#include "Vault.h"

#include <QBuffer>
#include <QCryptographicHash>
#include <QDataStream>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QObject>
#include <QRegularExpression>
#include <QSet>
#include <QStandardPaths>
#include <QStorageInfo>
#include <QUrl>
#include <algorithm>
#include <cstring>

#include "Platform.h"

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <windows.h>
#include <winioctl.h>
#include <string>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {

constexpr char kMagic[4] = {'S', 'S', 'V', '2'};      // cabecera
constexpr char kBlobMagic[4] = {'S', 'S', 'B', '1'};  // archivos cifrados
constexpr qint64 kChunk = 256 * 1024;                 // tamaño de bloque (acceso aleatorio para vídeo/audio)
constexpr int kBlobHdr = 4 + 16;                      // magic + prefijo de nonce
constexpr int kNonce = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr int kTag = crypto_aead_xchacha20poly1305_ietf_ABYTES;
constexpr int kSalt = crypto_pwhash_SALTBYTES;
constexpr int kKey = 32;
constexpr int kKcv = 16;                              // valor de comprobación de la llave
constexpr int kSaltOff = 4 + 8 + 8;
constexpr int kKcvOff = kSaltOff + kSalt;
constexpr int kHeadLen = kKcvOff + kKcv;              // autenticado como dato asociado
constexpr quint64 kOps = crypto_pwhash_OPSLIMIT_MODERATE;
constexpr quint64 kMem = crypto_pwhash_MEMLIMIT_MODERATE;
constexpr char kIndexCtx[] = "SSINDEX1";              // 8 bytes exactos

const QString kHeaderFile = QStringLiteral("cfg.bin");
const QString kIndexFile = QStringLiteral("ix.bin");
const QString kStateFile = QStringLiteral("st.bin");
const QString kTmpSuffix = QStringLiteral(".tmp");

bool fail(QString* e, const QString& msg) {
    if (e) *e = msg;
    return false;
}

const unsigned char* u8(const QByteArray& b) { return reinterpret_cast<const unsigned char*>(b.constData()); }
unsigned char* u8(QByteArray& b) { return reinterpret_cast<unsigned char*>(b.data()); }

struct Wipe {  // borra un buffer al salir del ámbito
    void* p;
    std::size_t n;
    ~Wipe() { sodium_memzero(p, n); }
};

void wipeBytes(QByteArray& b) {
    if (!b.isEmpty()) sodium_memzero(b.data(), std::size_t(b.size()));
}

void syncFile(QFile& f) {
    f.flush();
#ifdef Q_OS_WIN
    FlushFileBuffers(reinterpret_cast<HANDLE>(_get_osfhandle(f.handle())));
#elif defined(Q_OS_MACOS)
    if (::fcntl(f.handle(), F_FULLFSYNC) == -1) (void)::fsync(f.handle());  // fsync solo vacía hasta la caché del disco
#else
    (void)::fsync(f.handle());
#endif
}

QString randomId() {
    unsigned char b[16];
    randombytes_buf(b, sizeof b);
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(b), sizeof b).toHex());
}

QJsonObject toJson(const VaultSettings& s) {
    QJsonObject o;
    o["lockout"] = s.lockoutEnabled;
    o["max"] = s.maxAttempts;
    o["remaining"] = s.showRemaining;
    o["delay"] = s.progressiveDelay;
    o["passes"] = s.shredPasses;
    o["importOrig"] = s.importOriginal;
    o["autoLock"] = s.autoLockEnabled;
    o["autoLockMin"] = s.autoLockMinutes;
    o["lockMin"] = s.lockOnMinimize;
    o["capture"] = s.blockScreenCapture;
    o["confirmDel"] = s.confirmDelete;
    o["font"] = s.uiFontPx;
    return o;
}

VaultSettings fromJson(const QJsonObject& o) {
    VaultSettings s;
    s.lockoutEnabled = o.value("lockout").toBool(s.lockoutEnabled);
    s.maxAttempts = std::clamp(o.value("max").toInt(s.maxAttempts), 1, 99);
    s.showRemaining = o.value("remaining").toBool(s.showRemaining);
    s.progressiveDelay = o.value("delay").toBool(s.progressiveDelay);
    s.shredPasses = std::clamp(o.value("passes").toInt(s.shredPasses), 1, 35);
    s.importOriginal = std::clamp(o.value("importOrig").toInt(s.importOriginal), 0, 2);
    s.autoLockEnabled = o.value("autoLock").toBool(s.autoLockEnabled);
    s.autoLockMinutes = std::clamp(o.value("autoLockMin").toInt(s.autoLockMinutes), 1, 1440);
    s.lockOnMinimize = o.value("lockMin").toBool(s.lockOnMinimize);
    s.blockScreenCapture = o.value("capture").toBool(s.blockScreenCapture);
    s.confirmDelete = o.value("confirmDel").toBool(s.confirmDelete);
    s.uiFontPx = std::clamp(o.value("font").toInt(s.uiFontPx), 10, 20);
    return s;
}

// --- cifrado de archivos por bloques independientes -----------------------------------------------
// Blob = "SSB1" | prefijo(16) | n bloques. Bloque i: XChaCha20-Poly1305, nonce = prefijo||LE64(i),
// dato asociado = LE64(i)||[es_último]. Cada bloque se puede descifrar sin los demás (acceso aleatorio) y
// cualquier reordenación, truncado o ampliación se detecta.

qint64 chunkCount(qint64 size) { return size <= 0 ? 1 : (size + kChunk - 1) / kChunk; }

void makeNonce(unsigned char out[kNonce], const unsigned char* prefix, quint64 idx) {
    std::memcpy(out, prefix, 16);
    for (int i = 0; i < 8; ++i) out[16 + i] = static_cast<unsigned char>((idx >> (8 * i)) & 0xff);
}

void makeAd(unsigned char out[9], quint64 idx, bool last) {
    for (int i = 0; i < 8; ++i) out[i] = static_cast<unsigned char>((idx >> (8 * i)) & 0xff);
    out[8] = last ? 1 : 0;
}

qint64 readFully(QIODevice& d, char* buf, qint64 want) {
    qint64 got = 0;
    while (got < want) {
        const qint64 n = d.read(buf + got, want - got);
        if (n <= 0) break;
        got += n;
    }
    return got;
}

bool encryptBlob(QIODevice& in, QIODevice& out, const unsigned char* key, qint64 size, const Vault::Progress& prog,
                 crypto_generichash_state* hs) {
    unsigned char prefix[16];
    randombytes_buf(prefix, sizeof prefix);
    if (out.write(kBlobMagic, 4) != 4) return false;
    if (out.write(reinterpret_cast<const char*>(prefix), 16) != 16) return false;

    std::vector<unsigned char> plain(std::size_t(kChunk));
    std::vector<unsigned char> ct(std::size_t(kChunk) + kTag);
    Wipe w{plain.data(), plain.size()};

    const qint64 n = chunkCount(size);
    for (qint64 i = 0; i < n; ++i) {
        const bool last = i == n - 1;
        const qint64 want = last ? size - i * kChunk : kChunk;
        if (readFully(in, reinterpret_cast<char*>(plain.data()), want) != want) return false;
        if (hs) crypto_generichash_update(hs, plain.data(), static_cast<unsigned long long>(want));
        unsigned char nonce[kNonce], ad[9];
        makeNonce(nonce, prefix, quint64(i));
        makeAd(ad, quint64(i), last);
        unsigned long long clen = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &clen, plain.data(),
                                                   static_cast<unsigned long long>(want), ad, sizeof ad, nullptr,
                                                   nonce, key);
        if (out.write(reinterpret_cast<const char*>(ct.data()), qint64(clen)) != qint64(clen)) return false;
        if (prog && !prog(std::min(size, (i + 1) * kChunk), size)) return false;  // cancelado
    }
    char extra;
    if (in.read(&extra, 1) > 0) return false;  // el origen creció mientras se leía
    return true;
}

QString safeFileName(QString n) {
    for (QChar& c : n) {
        if (c == QLatin1Char('/') || c == QLatin1Char('\\') || c == QLatin1Char(':') || c == QLatin1Char('*') ||
            c == QLatin1Char('?') || c == QLatin1Char('"') || c == QLatin1Char('<') || c == QLatin1Char('>') ||
            c == QLatin1Char('|') || c.unicode() < 32)
            c = QLatin1Char('_');
    }
    return n.isEmpty() ? QStringLiteral("_") : n;
}

QString uniquePath(const QString& path) {
    if (!QFileInfo::exists(path)) return path;
    const QFileInfo fi(path);
    const QString suf = fi.suffix().isEmpty() ? QString() : QStringLiteral(".") + fi.suffix();
    for (int i = 2;; ++i) {
        const QString p = fi.dir().filePath(QStringLiteral("%1 (%2)%3").arg(fi.completeBaseName()).arg(i).arg(suf));
        if (!QFileInfo::exists(p)) return p;
    }
}

void computeKcv(const SecretKey& pepper, unsigned char out[kKcv]) {
    static const unsigned char msg[] = "SSKCV1";
    crypto_generichash(out, kKcv, msg, sizeof msg - 1, pepper.data(), SecretKey::kSize);
}

// KEK = BLAKE2b( Argon2id(contraseña), clave = llave ). Hacen falta las dos cosas.
bool deriveKek(const QByteArray& pw, const unsigned char* salt, quint64 ops, quint64 mem, const SecretKey& pepper,
               SecretKey& kek) {
    SecretKey pwKey;
    if (crypto_pwhash(pwKey.data(), kKey, pw.constData(), static_cast<unsigned long long>(pw.size()), salt, ops,
                      static_cast<std::size_t>(mem), crypto_pwhash_ALG_ARGON2ID13) != 0)
        return false;
    return crypto_generichash(kek.data(), kKey, pwKey.data(), SecretKey::kSize, pepper.data(), SecretKey::kSize) == 0;
}


// --- borrado profundo -------------------------------------------------------------------------------

qint64 roundUp(qint64 v, qint64 unit) { return unit <= 0 ? v : ((v + unit - 1) / unit) * unit; }

// Sobrescribe un archivo EN SU SITIO: `passes` pasadas aleatorias + 1 final a ceros. Cubre hasta el final del
// último clúster (la «cola» o slack, donde pueden quedar restos). Después lo deja vacío y con fechas neutras.
// Windows: escritura directa con WRITE_THROUGH (sin caché perezosa). true = todo se escribió.
bool overwritePath(const QString& path, int passes, qint64 cluster) {
    const int total = std::max(1, passes) + 1;
#ifdef Q_OS_WIN
    const std::wstring wpath = QDir::toNativeSeparators(path).toStdWString();
    SetFileAttributesW(wpath.c_str(), FILE_ATTRIBUTE_NORMAL);  // quita solo-lectura / oculto / sistema
    HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                           FILE_FLAG_WRITE_THROUGH | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) {
        CloseHandle(h);
        return false;
    }
    const qint64 span = roundUp(qint64(sz.QuadPart), cluster);
    std::vector<unsigned char> buf(std::size_t(std::max<qint64>(1, std::min<qint64>(span, kChunk))));
    bool ok = true;
    for (int p = 0; p < total && ok; ++p) {
        const bool zeroPass = p == total - 1;
        LARGE_INTEGER zero{};
        SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);
        qint64 left = span;
        while (left > 0) {
            const DWORD n = DWORD(std::min<qint64>(left, qint64(buf.size())));
            if (zeroPass)
                std::memset(buf.data(), 0, n);
            else
                randombytes_buf(buf.data(), n);
            DWORD wr = 0;
            if (!WriteFile(h, buf.data(), n, &wr, nullptr) || wr != n) {
                ok = false;
                break;
            }
            left -= n;
        }
        FlushFileBuffers(h);
    }
    ULARGE_INTEGER t;
    t.QuadPart = 125911584000000000ULL;  // 2000-01-01: borra las fechas reales de creación/uso/modificación
    FILETIME ft{t.LowPart, t.HighPart};
    SetFileTime(h, &ft, &ft, &ft);
    LARGE_INTEGER zero{};
    SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);
    SetEndOfFile(h);
    FlushFileBuffers(h);
    CloseHandle(h);
    sodium_memzero(buf.data(), buf.size());
    return ok;
#else
    QFile f(path);
    f.setPermissions(f.permissions() | QFileDevice::WriteOwner | QFileDevice::WriteUser);
    if (!f.open(QIODevice::ReadWrite)) return false;
    const qint64 size = f.size();
    const qint64 span = roundUp(size, cluster);
    QByteArray buf(int(std::max<qint64>(1, std::min<qint64>(span, kChunk))), '\0');
    bool ok = true;
    for (int p = 0; p < total && ok; ++p) {
        const bool zeroPass = p == total - 1;
        f.seek(0);
        qint64 left = span;
        while (left > 0) {
            const qint64 n = std::min<qint64>(left, buf.size());
            if (zeroPass)
                std::memset(buf.data(), 0, std::size_t(n));
            else
                randombytes_buf(buf.data(), std::size_t(n));
            if (f.write(buf.constData(), n) != n) {
                ok = false;
                break;
            }
            left -= n;
        }
        syncFile(f);
    }
    const QDateTime neutral = QDateTime::fromSecsSinceEpoch(946684800);  // 2000-01-01
    f.setFileTime(neutral, QFileDevice::FileModificationTime);
    f.setFileTime(neutral, QFileDevice::FileAccessTime);
    f.resize(0);
    syncFile(f);
    f.close();
    sodium_memzero(buf.data(), std::size_t(buf.size()));
    return ok;
#endif
}

// Renombra varias veces a nombres aleatorios de la misma longitud: sobrescribe el nombre original en la entrada
// del directorio / registro del sistema de archivos (MFT, inodo) en vez de dejarlo ahí.
QString scrubRename(const QString& path, int times, bool isDir) {
    QString cur = path;
    const QFileInfo fi(path);
    const QDir dir = fi.dir();
    const int len = std::max(12, int(fi.fileName().size()));
    for (int i = 0; i < times; ++i) {
        QString name = randomId();
        while (name.size() < len) name += randomId();
        name.truncate(len);
        const QString next = dir.filePath(name);
        if (QFileInfo::exists(next)) continue;
        const bool ok = isDir ? QDir().rename(cur, next) : QFile::rename(cur, next);
        if (!ok) break;
        cur = next;
    }
    return cur;
}

struct VolInfo {
    QString fs;           // sistema de archivos (minúsculas)
    qint64 cluster = 4096;
    int media = -1;       // 1 = disco giratorio, 0 = memoria flash (SSD / USB), -1 = desconocido
    bool network = false;
};

VolInfo volumeInfo(const QString& path) {
    VolInfo v;
    const QStorageInfo si(QFileInfo(path).absolutePath());
    v.fs = QString::fromLatin1(si.fileSystemType()).toLower();
    if (si.blockSize() > 0) v.cluster = std::max<qint64>(4096, si.blockSize());
    static const QSet<QString> net = {QStringLiteral("nfs"),  QStringLiteral("nfs4"), QStringLiteral("cifs"),
                                      QStringLiteral("smbfs"), QStringLiteral("smb3"), QStringLiteral("sshfs"),
                                      QStringLiteral("afpfs"), QStringLiteral("davfs"), QStringLiteral("9p"),
                                      QStringLiteral("fuse.sshfs")};
    v.network = net.contains(v.fs);
#ifdef Q_OS_WIN
    const QString root = QDir::toNativeSeparators(si.rootPath());  // "C:\"
    if (GetDriveTypeW(reinterpret_cast<LPCWSTR>(root.utf16())) == DRIVE_REMOTE) v.network = true;
    if (root.size() >= 2 && root[1] == QLatin1Char(':')) {
        const QString dev = QStringLiteral("\\\\.\\") + root.left(2);
        HANDLE h = CreateFileW(reinterpret_cast<LPCWSTR>(dev.utf16()), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            STORAGE_PROPERTY_QUERY q{};
            q.PropertyId = StorageDeviceSeekPenaltyProperty;
            q.QueryType = PropertyStandardQuery;
            DEVICE_SEEK_PENALTY_DESCRIPTOR d{};
            DWORD ret = 0;
            if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, &d, sizeof d, &ret, nullptr))
                v.media = d.IncursSeekPenalty ? 1 : 0;
            CloseHandle(h);
        }
    }
#elif defined(Q_OS_LINUX)
    QString name = QFileInfo(QString::fromLatin1(si.device())).fileName();  // sda1, nvme0n1p2, mmcblk0p1...
    QRegularExpressionMatch m =
        QRegularExpression(QStringLiteral("^(nvme\\d+n\\d+|mmcblk\\d+)p\\d+$")).match(name);
    if (m.hasMatch())
        name = m.captured(1);
    else if ((m = QRegularExpression(QStringLiteral("^([a-z]+)\\d+$")).match(name)).hasMatch())
        name = m.captured(1);
    QFile rot(QStringLiteral("/sys/block/%1/queue/rotational").arg(name));
    if (rot.open(QIODevice::ReadOnly)) {
        const QByteArray b = rot.readAll().trimmed();
        if (b == "1") v.media = 1;
        else if (b == "0") v.media = 0;
    }
#endif
    return v;
}

bool isCopyOnWrite(const QString& fs) {
    static const QSet<QString> cow = {QStringLiteral("btrfs"), QStringLiteral("zfs"), QStringLiteral("apfs"),
                                      QStringLiteral("refs"),  QStringLiteral("f2fs"), QStringLiteral("bcachefs")};
    return cow.contains(fs);
}


// Rastros que el sistema deja de un archivo concreto (lista de recientes, miniaturas) y que revelan su nombre
// o incluso su contenido (miniatura de una imagen).
void scrubTraces(const QString& absPath) {
#ifdef Q_OS_WIN
    const QFileInfo fi(absPath);
    const QString lnk = qEnvironmentVariable("APPDATA") + QStringLiteral("/Microsoft/Windows/Recent/") +
                        fi.fileName() + QStringLiteral(".lnk");
    if (QFile::exists(lnk)) Vault::shredFile(lnk, 1);
#elif defined(Q_OS_LINUX)
    const QByteArray uri = QUrl::fromLocalFile(absPath).toEncoded();
    const QString md5 = QString::fromLatin1(QCryptographicHash::hash(uri, QCryptographicHash::Md5).toHex());
    const QString thumbs =
        QStandardPaths::writableLocation(QStandardPaths::GenericCacheLocation) + QStringLiteral("/thumbnails");
    for (const char* sz : {"normal", "large", "x-large", "xx-large", "fail/gnome-thumbnail-factory"}) {
        const QString t = QStringLiteral("%1/%2/%3.png").arg(thumbs, QString::fromLatin1(sz), md5);
        if (QFile::exists(t)) Vault::shredFile(t, 1);
    }
    QFile f(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) +
            QStringLiteral("/recently-used.xbel"));
    if (f.open(QIODevice::ReadOnly)) {
        const QString text = QString::fromUtf8(f.readAll());
        f.close();
        const QRegularExpression re(QStringLiteral("\\s*<bookmark href=\"%1\"[^>]*>.*?</bookmark>")
                                        .arg(QRegularExpression::escape(QString::fromLatin1(uri))),
                                    QRegularExpression::DotMatchesEverythingOption);
        QString cleaned = text;
        cleaned.remove(re);
        if (cleaned != text && f.open(QIODevice::WriteOnly | QIODevice::Truncate)) f.write(cleaned.toUtf8());
    }
#else
    Q_UNUSED(absPath);
#endif
}

#ifdef Q_OS_WIN
// Flujos de datos alternativos de NTFS (archivo.txt:oculto): también pueden contener datos.
QStringList alternateStreams(const QString& path) {
    QStringList out;
    WIN32_FIND_STREAM_DATA fsd;
    HANDLE h = FindFirstStreamW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(path).utf16()),
                                FindStreamInfoStandard, &fsd, 0);
    if (h == INVALID_HANDLE_VALUE) return out;
    do {
        const QString name = QString::fromWCharArray(fsd.cStreamName);  // ":nombre:$DATA" o "::$DATA"
        if (name != QLatin1String("::$DATA")) out << name;
    } while (FindNextStreamW(h, &fsd));
    FindClose(h);
    return out;
}
#endif

}  // namespace

// ---------------------------------------------------------------------------------------------
// VaultFileDevice

VaultFileDevice::VaultFileDevice(const QString& blobPath, const unsigned char* key, qint64 plainSize)
    : file_(blobPath), size_(plainSize) {
    std::memcpy(key_.data(), key, SecretKey::kSize);
    plain_.resize(std::size_t(kChunk));
    ct_.resize(std::size_t(kChunk) + kTag);
}

VaultFileDevice::~VaultFileDevice() {
    if (isOpen()) close();
    sodium_memzero(plain_.data(), plain_.size());
}

bool VaultFileDevice::open(OpenMode mode) {
    if (mode & (WriteOnly | Append | Truncate)) return false;
    QMutexLocker lock(&mutex_);
    if (!file_.open(QIODevice::ReadOnly)) {
        setErrorString(file_.errorString());
        return false;
    }
    char hdr[kBlobHdr];
    if (file_.read(hdr, kBlobHdr) != kBlobHdr || std::memcmp(hdr, kBlobMagic, 4) != 0 ||
        file_.size() != kBlobHdr + size_ + chunkCount(size_) * kTag) {
        file_.close();
        setErrorString(QObject::tr("El archivo cifrado está dañado."));
        return false;
    }
    std::memcpy(prefix_, hdr + 4, 16);
    pos_ = 0;
    cachedIdx_ = -1;
    return QIODevice::open(QIODevice::ReadOnly);
}

void VaultFileDevice::close() {
    QMutexLocker lock(&mutex_);
    file_.close();
    cachedIdx_ = -1;
    sodium_memzero(plain_.data(), plain_.size());
    QIODevice::close();
}

bool VaultFileDevice::seek(qint64 p) {
    QMutexLocker lock(&mutex_);
    if (p < 0 || p > size_) return false;
    if (!QIODevice::seek(p)) return false;
    pos_ = p;
    return true;
}

qint64 VaultFileDevice::bytesAvailable() const {
    QMutexLocker lock(&mutex_);
    return std::max<qint64>(0, size_ - pos_) + QIODevice::bytesAvailable();
}

bool VaultFileDevice::loadChunk(qint64 idx) {
    const qint64 n = chunkCount(size_);
    if (idx < 0 || idx >= n) return false;
    const bool last = idx == n - 1;
    const qint64 plainLen = last ? size_ - idx * kChunk : kChunk;
    const qint64 ctLen = plainLen + kTag;
    if (!file_.seek(kBlobHdr + idx * (kChunk + kTag))) return false;
    if (file_.read(reinterpret_cast<char*>(ct_.data()), ctLen) != ctLen) return false;
    unsigned char nonce[kNonce], ad[9];
    makeNonce(nonce, prefix_, quint64(idx));
    makeAd(ad, quint64(idx), last);
    unsigned long long mlen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain_.data(), &mlen, nullptr, ct_.data(),
                                                   static_cast<unsigned long long>(ctLen), ad, sizeof ad, nonce,
                                                   key_.data()) != 0) {
        cachedIdx_ = -1;
        return false;  // manipulado o clave incorrecta
    }
    cachedIdx_ = idx;
    cachedLen_ = qint64(mlen);
    return true;
}

qint64 VaultFileDevice::readData(char* data, qint64 maxlen) {
    QMutexLocker lock(&mutex_);
    qint64 total = 0;
    while (total < maxlen && pos_ < size_) {
        const qint64 idx = pos_ / kChunk;
        if (idx != cachedIdx_ && !loadChunk(idx)) return total > 0 ? total : -1;
        const qint64 off = pos_ - idx * kChunk;
        const qint64 n = std::min(cachedLen_ - off, maxlen - total);
        if (n <= 0) return total > 0 ? total : -1;
        std::memcpy(data + total, plain_.data() + off, std::size_t(n));
        total += n;
        pos_ += n;
    }
    return total;
}

// ---------------------------------------------------------------------------------------------
// Vault

Vault::Vault(const QString& dir) : dir_(dir) {}
Vault::~Vault() { lock(); }

bool Vault::initCrypto() { return sodium_init() >= 0; }

QString Vault::pathIn(const QString& name) const { return QDir(dir_).filePath(name); }
QString Vault::headerPath() const { return pathIn(kHeaderFile); }
QString Vault::indexPath() const { return pathIn(kIndexFile); }
QString Vault::statePath() const { return pathIn(kStateFile); }
QString Vault::blobPath(const QString& blob) const { return pathIn(blob); }

bool Vault::exists() const { return QFile::exists(headerPath()) || QFile::exists(headerPath() + kTmpSuffix); }

int Vault::passes() const { return unlocked_ ? settings_.shredPasses : readState().shredPasses; }

// --- estado previo al desbloqueo ---------------------------------------------------------------

LockState Vault::readState() const {
    LockState s;
    QFile f(statePath());
    if (!f.open(QIODevice::ReadOnly)) return s;
    const QJsonObject o = QJsonDocument::fromJson(f.readAll()).object();
    s.fails = std::max(0, o.value("f").toInt(0));
    s.lastFail = o.value("t").toInteger(0);
    s.lockoutEnabled = o.value("e").toBool(false);
    s.maxAttempts = std::clamp(o.value("m").toInt(5), 1, 99);
    s.progressiveDelay = o.value("d").toBool(true);
    s.showRemaining = o.value("r").toBool(true);
    s.shredPasses = std::clamp(o.value("p").toInt(3), 1, 35);
    return s;
}

void Vault::writeState(const LockState& s) const {
    QJsonObject o;
    o["f"] = s.fails;
    o["t"] = s.lastFail;
    o["e"] = s.lockoutEnabled;
    o["m"] = s.maxAttempts;
    o["d"] = s.progressiveDelay;
    o["r"] = s.showRemaining;
    o["p"] = s.shredPasses;
    QDir().mkpath(dir_);
    QFile f(statePath());
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(QJsonDocument(o).toJson(QJsonDocument::Compact));
        syncFile(f);
    }
}

LockState Vault::stateFromSettings() const {
    LockState s;
    s.lockoutEnabled = settings_.lockoutEnabled;
    s.maxAttempts = settings_.maxAttempts;
    s.progressiveDelay = settings_.progressiveDelay;
    s.showRemaining = settings_.showRemaining;
    s.shredPasses = settings_.shredPasses;
    return s;
}

LockState Vault::lockState() const { return readState(); }

int Vault::retryDelaySeconds() const {
    const LockState st = readState();
    if (!st.progressiveDelay || st.fails < 3) return 0;
    const int delay = std::min(30, 1 << std::min(st.fails - 2, 5));  // 2, 4, 8, 16, 30 s
    const qint64 elapsed = QDateTime::currentSecsSinceEpoch() - st.lastFail;
    return int(std::max<qint64>(0, delay - elapsed));
}

// --- cabecera (contraseña + llave -> clave maestra) --------------------------------------------

bool Vault::headerKcvMatches(const SecretKey& key) const {
    QFile f(headerPath());
    if (!f.open(QIODevice::ReadOnly)) return false;
    const QByteArray raw = f.readAll();
    if (raw.size() != kHeadLen + kNonce + kKey + kTag) return false;
    unsigned char kcv[kKcv];
    computeKcv(key, kcv);
    return sodium_memcmp(kcv, u8(raw) + kKcvOff, kKcv) == 0;
}

Vault::HeaderResult Vault::openHeader(const QByteArray& pw, const SecretKey& key, SecretKey& vmkOut,
                                      QString* err) const {
    QFile f(headerPath());
    if (!f.open(QIODevice::ReadOnly)) {
        if (err) *err = QObject::tr("No se pudo leer la bóveda.");
        return HeaderResult::Bad;
    }
    const QByteArray raw = f.readAll();
    if (raw.size() != kHeadLen + kNonce + kKey + kTag || std::memcmp(raw.constData(), kMagic, 4) != 0) {
        if (err) *err = QObject::tr("La cabecera de la bóveda está dañada.");
        return HeaderResult::Bad;
    }
    QDataStream ds(raw);
    ds.skipRawData(4);
    quint64 ops = 0, mem = 0;
    ds >> ops >> mem;
    if (ops < 1 || ops > 64 || mem < (8ull << 20) || mem > (4ull << 30)) {
        if (err) *err = QObject::tr("Parámetros de cifrado no válidos.");
        return HeaderResult::Bad;
    }
    const unsigned char* base = u8(raw);
    SecretKey kek;
    if (!deriveKek(pw, base + kSaltOff, ops, mem, key, kek)) {
        if (err) *err = QObject::tr("No hay memoria suficiente para derivar la clave.");
        return HeaderResult::Bad;
    }
    const unsigned char* nonce = base + kHeadLen;
    const unsigned char* ct = nonce + kNonce;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(vmkOut.data(), nullptr, nullptr, ct, kKey + kTag, base, kHeadLen,
                                                   nonce, kek.data()) != 0) {
        vmkOut.clear();
        return HeaderResult::Wrong;
    }
    return HeaderResult::Ok;
}

bool Vault::writeHeader(const unsigned char* salt, quint64 ops, quint64 mem, const SecretKey& kek) {
    QByteArray blob;
    {
        QDataStream ds(&blob, QIODevice::WriteOnly);
        ds.writeRawData(kMagic, 4);
        ds << ops << mem;
        ds.writeRawData(reinterpret_cast<const char*>(salt), kSalt);
        unsigned char kcv[kKcv];
        computeKcv(pepper_, kcv);
        ds.writeRawData(reinterpret_cast<const char*>(kcv), kKcv);
    }
    unsigned char nonce[kNonce];
    randombytes_buf(nonce, sizeof nonce);
    QByteArray wrapped(kKey + kTag, '\0');
    crypto_aead_xchacha20poly1305_ietf_encrypt(u8(wrapped), nullptr, vmk_.data(), kKey, u8(blob),
                                               static_cast<unsigned long long>(blob.size()), nullptr, nonce,
                                               kek.data());
    blob.append(reinterpret_cast<const char*>(nonce), kNonce);
    blob.append(wrapped);
    return replaceFile(headerPath(), blob);
}

// --- índice cifrado ----------------------------------------------------------------------------

void Vault::deriveIndexKey() { crypto_kdf_derive_from_key(ixKey_.data(), kKey, 1, kIndexCtx, vmk_.data()); }

bool Vault::loadIndex() {
    QFile f(indexPath());
    if (!f.open(QIODevice::ReadOnly)) return false;
    const QByteArray raw = f.readAll();
    if (raw.size() < kNonce + kTag) return false;
    QByteArray plain(raw.size() - kNonce - kTag, '\0');
    unsigned long long plen = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(u8(plain), &plen, nullptr, u8(raw) + kNonce,
                                                   static_cast<unsigned long long>(raw.size() - kNonce), nullptr, 0,
                                                   u8(raw), ixKey_.data()) != 0)
        return false;
    plain.truncate(qsizetype(plen));
    const QJsonObject root = QJsonDocument::fromJson(plain).object();
    wipeBytes(plain);
    if (root.value("v").toInt() != 2) return false;

    settings_ = fromJson(root.value("settings").toObject());
    items_.clear();
    const QJsonArray arr = root.value("items").toArray();
    for (const QJsonValue& v : arr) {
        const QJsonObject o = v.toObject();
        VaultItem it;
        it.id = o.value("i").toString();
        it.parentId = o.value("p").toString();
        it.name = o.value("n").toString();
        it.isFolder = o.value("d").toBool();
        it.size = o.value("s").toInteger();
        it.modified = o.value("m").toInteger();
        if (it.id.isEmpty()) return false;
        if (!it.isFolder) {
            it.blob = o.value("b").toString();
            const QByteArray k = QByteArray::fromBase64(o.value("k").toString().toLatin1());
            if (it.blob.isEmpty() || k.size() != kKey) return false;
            std::memcpy(it.key.data(), k.constData(), kKey);
        }
        items_.push_back(it);
    }
    return true;
}

bool Vault::saveIndex() {
    QJsonArray arr;
    for (const VaultItem& it : items_) {
        QJsonObject o;
        o["i"] = it.id;
        o["p"] = it.parentId;
        o["n"] = it.name;
        o["d"] = it.isFolder;
        o["s"] = it.size;
        o["m"] = it.modified;
        if (!it.isFolder) {
            o["b"] = it.blob;
            o["k"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(it.key.data()), kKey).toBase64());
        }
        arr.append(o);
    }
    QJsonObject root;
    root["v"] = 2;
    root["settings"] = toJson(settings_);
    root["items"] = arr;

    QByteArray plain = QJsonDocument(root).toJson(QJsonDocument::Compact);
    plain.append(QByteArray((4096 - plain.size() % 4096) % 4096, ' '));  // relleno: oculta la cantidad de archivos

    unsigned char nonce[kNonce];
    randombytes_buf(nonce, sizeof nonce);
    QByteArray out(kNonce + plain.size() + kTag, '\0');
    std::memcpy(out.data(), nonce, kNonce);
    crypto_aead_xchacha20poly1305_ietf_encrypt(u8(out) + kNonce, nullptr, u8(plain),
                                               static_cast<unsigned long long>(plain.size()), nullptr, 0, nullptr,
                                               nonce, ixKey_.data());
    wipeBytes(plain);
    return replaceFile(indexPath(), out);
}

// Escritura "atómica": se escribe a .tmp, se destruye el antiguo y se renombra el nuevo.
bool Vault::replaceFile(const QString& path, const QByteArray& data) {
    const QString tmp = path + kTmpSuffix;
    {
        QFile f(tmp);
        if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
        if (f.write(data) != data.size()) return false;
        syncFile(f);
    }
    if (QFile::exists(path)) shredFile(path, passes());
    return QFile::rename(tmp, path);
}

void Vault::recoverTmp(const QString& path) const {
    if (!QFile::exists(path) && QFile::exists(path + kTmpSuffix)) QFile::rename(path + kTmpSuffix, path);
}

void Vault::purgeOrphans() {  // blobs que ya no figuran en el índice (p. ej. tras un corte de energía)
    static const QRegularExpression re(QStringLiteral("^[0-9a-f]{32}$"));
    QSet<QString> known;
    for (const VaultItem& it : items_)
        if (!it.blob.isEmpty()) known.insert(it.blob);
    const QStringList names = QDir(dir_).entryList(QDir::Files | QDir::Hidden);
    for (const QString& n : names)
        if (re.match(n).hasMatch() && !known.contains(n)) shredFile(pathIn(n), settings_.shredPasses);
}

// --- ciclo de vida -----------------------------------------------------------------------------

bool Vault::create(const QByteArray& pw, bool keyOnDevice, QString* err) {
    if (exists()) return fail(err, QObject::tr("Ya existe una bóveda."));
    if (!QDir().mkpath(dir_)) return fail(err, QObject::tr("No se pudo crear el directorio de la bóveda."));
#ifdef Q_OS_WIN
    SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(dir_).utf16()), FILE_ATTRIBUTE_HIDDEN);
#endif
    pepper_.randomize();
    DeviceKey::remove();  // nunca heredar la llave de una bóveda anterior
    if (keyOnDevice && !DeviceKey::save(pepper_)) {
        pepper_.clear();
        return fail(err, QObject::tr("No se pudo guardar la llave en este equipo."));
    }

    unsigned char salt[kSalt];
    randombytes_buf(salt, sizeof salt);
    SecretKey kek;
    if (!deriveKek(pw, salt, kOps, kMem, pepper_, kek)) {
        destroyEverything();
        return fail(err, QObject::tr("No hay memoria suficiente para derivar la clave."));
    }
    vmk_.randomize();
    deriveIndexKey();
    items_.clear();
    settings_ = VaultSettings();
    if (!writeHeader(salt, kOps, kMem, kek) || !saveIndex()) {
        destroyEverything();
        return fail(err, QObject::tr("No se pudo escribir la bóveda en el disco."));
    }
    writeState(stateFromSettings());
    unlocked_ = true;
    return true;
}

Vault::UnlockResult Vault::unlock(const QByteArray& pw, const QString& keyFile, QString* err) {
    if (unlocked_) return UnlockResult::Ok;
    recoverTmp(headerPath());
    recoverTmp(indexPath());
    if (!QFile::exists(headerPath())) {
        if (err) *err = QObject::tr("No existe ninguna bóveda.");
        return UnlockResult::Error;
    }

    // 1) Obtener la llave. Si falta o no corresponde NO cuenta como intento de contraseña.
    SecretKey key;
    QString e;
    if (!keyFile.isEmpty()) {
        if (!DeviceKey::readKeyFile(keyFile, key, &e)) {
            if (err) *err = e;
            return UnlockResult::NeedKey;
        }
    } else if (!DeviceKey::load(key)) {
        if (err) *err = QObject::tr("Esta bóveda necesita su archivo de llave (.sskey).");
        return UnlockResult::NeedKey;
    }
    if (!headerKcvMatches(key)) {
        if (err)
            *err = keyFile.isEmpty() ? QObject::tr("La llave guardada en este equipo no corresponde a esta bóveda. "
                                                   "Selecciona tu archivo de llave (.sskey).")
                                     : QObject::tr("Ese archivo de llave no corresponde a esta bóveda.");
        return UnlockResult::NeedKey;
    }

    // 2) El intento se cuenta ANTES de derivar la clave: si se mata el proceso a mitad, igualmente cuenta.
    const LockState before = readState();
    LockState st = before;
    st.fails += 1;
    st.lastFail = QDateTime::currentSecsSinceEpoch();
    writeState(st);

    const HeaderResult hr = openHeader(pw, key, vmk_, &e);
    if (hr == HeaderResult::Bad) {
        writeState(before);  // un error técnico no cuenta como intento
        if (err) *err = e;
        return UnlockResult::Error;
    }
    if (hr == HeaderResult::Wrong) {
        if (st.lockoutEnabled && st.fails >= st.maxAttempts) {
            destroyEverything();
            return UnlockResult::Destroyed;
        }
        return UnlockResult::WrongPassword;
    }

    std::memcpy(pepper_.data(), key.data(), SecretKey::kSize);
    deriveIndexKey();
    if (!loadIndex()) {
        lock();
        writeState(before);
        if (err) *err = QObject::tr("El índice está dañado o fue manipulado.");
        return UnlockResult::Error;
    }
    unlocked_ = true;
    purgeOrphans();
    writeState(stateFromSettings());  // fails = 0
    return UnlockResult::Ok;
}

void Vault::lock() {
    for (VaultItem& it : items_) sodium_memzero(it.key.data(), it.key.size());
    items_.clear();
    items_.shrink_to_fit();
    vmk_.clear();
    ixKey_.clear();
    pepper_.clear();
    unlocked_ = false;
}

bool Vault::changePassword(const QByteArray& current, const QByteArray& next, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    SecretKey tmp;
    QString e;
    if (openHeader(current, pepper_, tmp, &e) != HeaderResult::Ok)
        return fail(err, e.isEmpty() ? QObject::tr("La contraseña actual no es correcta.") : e);
    unsigned char salt[kSalt];
    randombytes_buf(salt, sizeof salt);
    SecretKey kek;
    if (!deriveKek(next, salt, kOps, kMem, pepper_, kek))
        return fail(err, QObject::tr("No hay memoria suficiente para derivar la clave."));
    if (!writeHeader(salt, kOps, kMem, kek)) return fail(err, QObject::tr("No se pudo guardar la nueva contraseña."));
    return true;
}

// --- llave ---------------------------------------------------------------------------------------

bool Vault::deviceKeyUsable() const {
    SecretKey key;
    return DeviceKey::load(key) && headerKcvMatches(key);
}

bool Vault::isKeyOnDevice() const { return DeviceKey::exists(); }

bool Vault::setKeyOnDevice(bool on, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    if (on) {
        if (!DeviceKey::save(pepper_)) return fail(err, QObject::tr("No se pudo guardar la llave en este equipo."));
    } else {
        DeviceKey::remove();
    }
    return true;
}

bool Vault::exportKeyFile(const QString& path, QString* err) const {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    return DeviceKey::writeKeyFile(path, pepper_, err);
}

bool Vault::saveSettings() {
    if (!unlocked_) return false;
    const bool ok = saveIndex();
    const LockState old = readState();
    LockState st = stateFromSettings();
    st.fails = old.fails;
    st.lastFail = old.lastFail;
    writeState(st);
    return ok;
}

void Vault::destroyEverything(const Progress& prog) {
    const int n = std::max(1, passes());
    lock();
    DeviceKey::remove();  // 0) la llave de este equipo
    const QDir d(dir_);

    // 1) Primero las claves (cabecera e índice): sin ellas el resto ya es ruido indescifrable.
    const QStringList keys = {kHeaderFile, kHeaderFile + kTmpSuffix, kIndexFile, kIndexFile + kTmpSuffix};
    for (const QString& k : keys) shredFile(d.filePath(k), n);

    // 2) Después todo lo demás (los archivos cifrados).
    const QStringList rest = d.entryList(QDir::Files | QDir::Hidden | QDir::System);
    const qint64 total = rest.size();
    qint64 done = 0;
    for (const QString& f : rest) {
        if (f == kStateFile) continue;
        shredFile(d.filePath(f), n);
        if (prog) prog(++done, total);
    }
    shredFile(statePath(), 1);
    QDir(dir_).removeRecursively();
    if (prog) prog(total, total);
}

// --- árbol de archivos -------------------------------------------------------------------------

int Vault::indexOf(const QString& id) const {
    for (std::size_t i = 0; i < items_.size(); ++i)
        if (items_[i].id == id) return int(i);
    return -1;
}

void Vault::collect(const QString& id, QStringList& out) const {
    out << id;
    for (const VaultItem& it : items_)
        if (it.parentId == id) collect(it.id, out);
}

QList<VaultEntry> Vault::children(const QString& parentId) const {
    QList<VaultEntry> out;
    for (const VaultItem& it : items_)
        if (it.parentId == parentId) out.append(static_cast<const VaultEntry&>(it));
    std::sort(out.begin(), out.end(), [](const VaultEntry& a, const VaultEntry& b) {
        if (a.isFolder != b.isFolder) return a.isFolder;
        return a.name.compare(b.name, Qt::CaseInsensitive) < 0;
    });
    return out;
}

bool Vault::entry(const QString& id, VaultEntry* out) const {
    const int i = indexOf(id);
    if (i < 0) return false;
    if (out) *out = static_cast<const VaultEntry&>(items_[std::size_t(i)]);
    return true;
}

QString Vault::pathOf(const QString& id) const {
    QStringList parts;
    QString cur = id;
    for (int guard = 0; !cur.isEmpty() && guard < 256; ++guard) {
        const int i = indexOf(cur);
        if (i < 0) break;
        parts.prepend(items_[std::size_t(i)].name);
        cur = items_[std::size_t(i)].parentId;
    }
    return parts.isEmpty() ? QString() : QStringLiteral("/") + parts.join(QLatin1Char('/'));
}

bool Vault::validName(const QString& n) {
    const QString t = n.trimmed();
    return !t.isEmpty() && t.size() <= 255 && t != QLatin1String(".") && t != QLatin1String("..") &&
           !t.contains(QLatin1Char('/')) && !t.contains(QLatin1Char('\\'));
}

QString Vault::uniqueName(const QString& parentId, const QString& name, const QString& ignoreId) const {
    auto taken = [&](const QString& cand) {
        for (const VaultItem& it : items_)
            if (it.parentId == parentId && it.id != ignoreId && it.name.compare(cand, Qt::CaseInsensitive) == 0)
                return true;
        return false;
    };
    if (!taken(name)) return name;
    const QFileInfo fi(name);
    const QString base = fi.completeBaseName().isEmpty() ? name : fi.completeBaseName();
    const QString suf = fi.suffix().isEmpty() ? QString() : QStringLiteral(".") + fi.suffix();
    for (int i = 2;; ++i) {
        const QString cand = QStringLiteral("%1 (%2)%3").arg(base).arg(i).arg(suf);
        if (!taken(cand)) return cand;
    }
}

QString Vault::createFolder(const QString& name, const QString& parentId, QString* err) {
    if (!unlocked_) {
        fail(err, QObject::tr("La bóveda está bloqueada."));
        return {};
    }
    if (!validName(name)) {
        fail(err, QObject::tr("Nombre no válido."));
        return {};
    }
    VaultItem it;
    it.id = randomId();
    it.parentId = parentId;
    it.name = uniqueName(parentId, name.trimmed(), QString());
    it.isFolder = true;
    it.modified = QDateTime::currentSecsSinceEpoch();
    items_.push_back(it);
    if (!saveIndex()) {
        items_.pop_back();
        fail(err, QObject::tr("No se pudo guardar el índice."));
        return {};
    }
    return it.id;
}

bool Vault::rename(const QString& id, const QString& newName, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    const int i = indexOf(id);
    if (i < 0) return fail(err, QObject::tr("Elemento inexistente."));
    if (!validName(newName)) return fail(err, QObject::tr("Nombre no válido."));
    VaultItem& it = items_[std::size_t(i)];
    it.name = uniqueName(it.parentId, newName.trimmed(), id);
    return saveIndex() || fail(err, QObject::tr("No se pudo guardar el índice."));
}

// --- escritura de contenido ----------------------------------------------------------------------

bool Vault::writeBlobFrom(QIODevice& in, qint64 size, const QString& blob, const unsigned char* key,
                          const Progress& prog, unsigned char* hashOut) const {
    QFile out(blobPath(blob));
    if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    crypto_generichash_state hs;
    if (hashOut) crypto_generichash_init(&hs, nullptr, 0, 32);
    const bool ok = encryptBlob(in, out, key, size, prog, hashOut ? &hs : nullptr);
    syncFile(out);
    out.close();
    if (ok && hashOut) crypto_generichash_final(&hs, hashOut, 32);
    return ok;
}

bool Vault::verifyBlob(const QString& blob, const unsigned char* key, qint64 size, const unsigned char* expected,
                       const Progress& prog) const {
    VaultFileDevice dev(blobPath(blob), key, size);
    if (!dev.open(QIODevice::ReadOnly)) return false;
    crypto_generichash_state hs;
    crypto_generichash_init(&hs, nullptr, 0, 32);
    std::vector<unsigned char> buf(std::size_t(1) << 20);
    Wipe w{buf.data(), buf.size()};
    qint64 total = 0;
    for (;;) {
        const qint64 n = dev.read(reinterpret_cast<char*>(buf.data()), qint64(buf.size()));
        if (n < 0) return false;
        if (n == 0) break;
        crypto_generichash_update(&hs, buf.data(), static_cast<unsigned long long>(n));
        total += n;
        if (prog && !prog(total, size)) return false;  // cancelado
    }
    unsigned char h[32];
    crypto_generichash_final(&hs, h, sizeof h);
    return total == size && sodium_memcmp(h, expected, 32) == 0;
}

bool Vault::importFile(const QString& src, const QString& parentId, const Progress& prog, QString* err,
                       bool verify) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    const QFileInfo fi(src);
    QFile in(src);
    if (!in.open(QIODevice::ReadOnly))
        return fail(err, QObject::tr("No se pudo leer «%1».").arg(fi.fileName()));

    VaultItem it;
    it.id = randomId();
    it.blob = randomId();
    it.parentId = parentId;
    it.name = uniqueName(parentId, fi.fileName(), QString());
    it.size = fi.size();
    it.modified = fi.lastModified().toSecsSinceEpoch();
    randombytes_buf(it.key.data(), it.key.size());

    // Con verificación el trabajo es doble (cifrar + releer): el progreso se reparte 50/50.
    Progress encProg = prog, verProg;
    if (verify && prog) {
        encProg = [&prog](qint64 d, qint64 t) { return prog(d, 2 * t); };
        verProg = [&prog](qint64 d, qint64 t) { return prog(t + d, 2 * t); };
    }
    unsigned char hash[32];
    bool ok = writeBlobFrom(in, it.size, it.blob, it.key.data(), encProg, verify ? hash : nullptr);
    if (ok && verify) ok = verifyBlob(it.blob, it.key.data(), it.size, hash, verProg);
    if (!ok) {
        shredFile(blobPath(it.blob), 1);
        sodium_memzero(it.key.data(), it.key.size());
        return fail(err, verify ? QObject::tr("La verificación de «%1» falló; el original no se ha tocado.")
                                      .arg(fi.fileName())
                                : QObject::tr("Error al cifrar «%1».").arg(fi.fileName()));
    }
    items_.push_back(it);
    if (!saveIndex()) {
        items_.pop_back();
        shredFile(blobPath(it.blob), 1);
        sodium_memzero(it.key.data(), it.key.size());
        return fail(err, QObject::tr("No se pudo guardar el índice."));
    }
    sodium_memzero(it.key.data(), it.key.size());
    return true;
}

QString Vault::createFileFromBytes(const QString& name, const QString& parentId, const QByteArray& data,
                                   QString* err) {
    if (!unlocked_) {
        fail(err, QObject::tr("La bóveda está bloqueada."));
        return {};
    }
    if (!validName(name)) {
        fail(err, QObject::tr("Nombre no válido."));
        return {};
    }
    VaultItem it;
    it.id = randomId();
    it.blob = randomId();
    it.parentId = parentId;
    it.name = uniqueName(parentId, name.trimmed(), QString());
    it.size = data.size();
    it.modified = QDateTime::currentSecsSinceEpoch();
    randombytes_buf(it.key.data(), it.key.size());

    QBuffer buf;
    buf.setData(data);
    buf.open(QIODevice::ReadOnly);
    if (!writeBlobFrom(buf, it.size, it.blob, it.key.data(), {}, nullptr)) {
        shredFile(blobPath(it.blob), 1);
        sodium_memzero(it.key.data(), it.key.size());
        fail(err, QObject::tr("Error al cifrar el archivo."));
        return {};
    }
    items_.push_back(it);
    if (!saveIndex()) {
        items_.pop_back();
        shredFile(blobPath(it.blob), 1);
        sodium_memzero(it.key.data(), it.key.size());
        fail(err, QObject::tr("No se pudo guardar el índice."));
        return {};
    }
    sodium_memzero(it.key.data(), it.key.size());
    return it.id;
}

// Reemplaza el contenido con un blob NUEVO (clave nueva) y destruye el anterior. Si algo falla a medias,
// el índice sigue apuntando a un blob válido; los huérfanos se purgan al desbloquear.
bool Vault::replaceContent(const QString& id, const QByteArray& data, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    const int i = indexOf(id);
    if (i < 0 || items_[std::size_t(i)].isFolder) return fail(err, QObject::tr("Elemento inexistente."));

    const QString newBlob = randomId();
    std::array<unsigned char, 32> newKey{};
    randombytes_buf(newKey.data(), newKey.size());
    QBuffer buf;
    buf.setData(data);
    buf.open(QIODevice::ReadOnly);
    if (!writeBlobFrom(buf, data.size(), newBlob, newKey.data(), {}, nullptr)) {
        shredFile(blobPath(newBlob), 1);
        sodium_memzero(newKey.data(), newKey.size());
        return fail(err, QObject::tr("Error al cifrar los cambios."));
    }

    VaultItem& it = items_[std::size_t(i)];
    VaultItem old = it;
    it.blob = newBlob;
    it.key = newKey;
    it.size = data.size();
    it.modified = QDateTime::currentSecsSinceEpoch();
    sodium_memzero(newKey.data(), newKey.size());
    if (!saveIndex()) {
        it = old;
        shredFile(blobPath(newBlob), 1);
        return fail(err, QObject::tr("No se pudo guardar el índice."));
    }
    shredFile(blobPath(old.blob), settings_.shredPasses);
    sodium_memzero(old.key.data(), old.key.size());
    return true;
}

// --- lectura de contenido (RAM) ------------------------------------------------------------------

std::unique_ptr<VaultFileDevice> Vault::openRead(const QString& id, QString* err) const {
    const int i = indexOf(id);
    if (!unlocked_ || i < 0 || items_[std::size_t(i)].isFolder) {
        fail(err, QObject::tr("No se puede abrir el elemento."));
        return nullptr;
    }
    const VaultItem& it = items_[std::size_t(i)];
    return std::make_unique<VaultFileDevice>(blobPath(it.blob), it.key.data(), it.size);
}

bool Vault::readAll(const QString& id, qint64 maxBytes, QByteArray* out, QString* err) const {
    VaultEntry e;
    if (!entry(id, &e) || e.isFolder) return fail(err, QObject::tr("Elemento inexistente."));
    if (e.size > maxBytes) return fail(err, QObject::tr("El archivo es demasiado grande para abrirlo aquí."));
    std::unique_ptr<VaultFileDevice> dev = openRead(id, err);
    if (!dev) return false;
    if (!dev->open(QIODevice::ReadOnly))
        return fail(err, dev->errorString().isEmpty() ? QObject::tr("No se pudo abrir el archivo.")
                                                      : dev->errorString());
    QByteArray b(qsizetype(e.size), '\0');
    if (readFully(*dev, b.data(), e.size) != e.size) {
        wipeBytes(b);
        return fail(err, QObject::tr("«%1» está dañado o fue manipulado.").arg(e.name));
    }
    *out = b;
    return true;
}

qint64 Vault::totalSize(const QString& id) const {
    const int i = indexOf(id);
    if (i < 0) return 0;
    if (!items_[std::size_t(i)].isFolder) return items_[std::size_t(i)].size;
    qint64 t = 0;
    for (const VaultItem& it : items_)
        if (it.parentId == id) t += totalSize(it.id);
    return t;
}

int Vault::countFiles(const QString& id) const {
    const int i = indexOf(id);
    if (i < 0) return 0;
    if (!items_[std::size_t(i)].isFolder) return 1;
    int n = 0;
    for (const VaultItem& it : items_)
        if (it.parentId == id) n += countFiles(it.id);
    return n;
}

bool Vault::exportItem(const QString& id, const QString& destDir, const Progress& prog, QString* err,
                       const std::function<void(const QString&, qint64)>& onFile) const {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    const int i = indexOf(id);
    if (i < 0) return fail(err, QObject::tr("Elemento inexistente."));
    const VaultItem& it = items_[std::size_t(i)];

    if (it.isFolder) {
        const QString sub = safeFileName(it.name);
        QDir d(destDir);
        if (!d.mkpath(sub)) return fail(err, QObject::tr("No se pudo crear la carpeta de destino."));
        const QString subPath = d.filePath(sub);
        for (const VaultEntry& c : children(id))
            if (!exportItem(c.id, subPath, prog, err, onFile)) return false;
        return true;
    }

    if (onFile) onFile(it.name, it.size);
    VaultFileDevice dev(blobPath(it.blob), it.key.data(), it.size);
    if (!dev.open(QIODevice::ReadOnly))
        return fail(err, QObject::tr("Falta el archivo cifrado de «%1» o está dañado.").arg(it.name));
    const QString outPath = uniquePath(QDir(destDir).filePath(safeFileName(it.name)));
    bool ok = false, cancelled = false;
    {
        QFile out(outPath);
        if (!out.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return fail(err, QObject::tr("No se pudo escribir en el destino."));
        std::vector<unsigned char> buf(std::size_t(1) << 20);
        Wipe w{buf.data(), buf.size()};
        qint64 total = 0;
        ok = true;
        for (;;) {
            const qint64 n = dev.read(reinterpret_cast<char*>(buf.data()), qint64(buf.size()));
            if (n < 0) {
                ok = false;
                break;
            }
            if (n == 0) break;
            if (out.write(reinterpret_cast<const char*>(buf.data()), n) != n) {
                ok = false;
                break;
            }
            total += n;
            if (prog && !prog(total, it.size)) {
                cancelled = true;
                ok = false;
                break;
            }
        }
        ok = ok && total == it.size;
    }
    if (!ok) {
        QFile::remove(outPath);
        return fail(err, cancelled ? QObject::tr("Operación cancelada.")
                                   : QObject::tr("«%1» está dañado o fue manipulado.").arg(it.name));
    }
    return true;
}

bool Vault::remove(const QString& id, const Progress& prog, QString* err) {
    if (!unlocked_) return fail(err, QObject::tr("La bóveda está bloqueada."));
    QStringList ids;
    collect(id, ids);
    QStringList blobs;
    for (const QString& x : ids) {
        const int i = indexOf(x);
        if (i < 0) continue;
        VaultItem& it = items_[std::size_t(i)];
        if (!it.isFolder) blobs << it.blob;
        sodium_memzero(it.key.data(), it.key.size());
        items_.erase(items_.begin() + i);
    }
    // 1) La clave de cada archivo desaparece con el índice nuevo; 2) después se destruyen los datos cifrados.
    if (!saveIndex()) return fail(err, QObject::tr("No se pudo actualizar el índice."));
    qint64 done = 0;
    for (const QString& b : blobs) {
        shredFile(blobPath(b), settings_.shredPasses);
        if (prog) prog(++done, blobs.size());
    }
    return true;
}

// --- borrado seguro ----------------------------------------------------------------------------

bool Vault::shredFile(const QString& path, int passes) {
    const QFileInfo fi(path);
    if (!fi.exists() && !fi.isSymLink()) return true;
    bool overwritten = true;  // los enlaces no tienen datos propios que sobrescribir
    if (fi.isFile() && !fi.isSymLink()) overwritten = overwritePath(path, passes, 4096);
    const QString target = scrubRename(path, 2, false);
    return overwritten && QFile::remove(target);
}

ShredReport Vault::shredExternal(const QString& path, int passes) {
    ShredReport rep;
    const QFileInfo fi(path);
    rep.folder = fi.absolutePath();
    if (!fi.exists() && !fi.isSymLink()) {
        rep.removed = true;
        return rep;
    }
    if (fi.isSymLink()) {  // nunca se toca el destino de un enlace: solo se quita el enlace
        rep.removed = fi.isDir() ? QDir().rmdir(path) : QFile::remove(path);
        return rep;
    }

    // 1) ¿Qué fiabilidad puede ofrecer esta unidad?
    const VolInfo vol = volumeInfo(path);
    int level = 2;
    bool special = false;
    auto lower = [&](int to, const QString& note) {
        level = std::min(level, to);
        if (!rep.notes.contains(note)) rep.notes << note;
    };
    if (vol.network)
        lower(0, QObject::tr("Es una unidad de red: el servidor puede conservar copias del archivo."));
    else if (isCopyOnWrite(vol.fs))
        lower(0, QObject::tr("El sistema de archivos (%1) escribe en bloques nuevos en lugar de sobrescribir: los datos "
                             "antiguos pueden seguir en el disco.")
                     .arg(vol.fs));
    else if (vol.media == 0)
        lower(1, QObject::tr("La unidad es de memoria flash (SSD/USB): su controlador puede conservar copias físicas de "
                             "los datos sobrescritos hasta que se reutilicen."));
    else if (vol.media < 0)
        lower(1, QObject::tr("No se pudo determinar el tipo de unidad; se asume memoria flash (SSD/USB)."));

    static const char* const kCloud[] = {"onedrive", "dropbox", "google drive", "googledrive", "icloud",
                                         "mobile documents", "pcloud", "nextcloud", "megasync", "box sync"};
    const QString low = QDir::fromNativeSeparators(fi.absoluteFilePath()).toLower();
    for (const char* c : kCloud)
        if (low.contains(QLatin1String(c))) {
            special = true;
            rep.notes << QObject::tr("La carpeta parece sincronizada con la nube: elimina también las copias y "
                                     "versiones anteriores en el servicio (y su papelera).");
            break;
        }

    bool hasLocalData = true;
#ifdef Q_OS_WIN
    {
        constexpr DWORD kRecallOnOpen = 0x00040000, kRecallOnData = 0x00400000;
        const std::wstring wp = QDir::toNativeSeparators(path).toStdWString();
        const DWORD at = GetFileAttributesW(wp.c_str());
        if (at != INVALID_FILE_ATTRIBUTES) {
            if (at & (kRecallOnOpen | kRecallOnData | FILE_ATTRIBUTE_OFFLINE)) {
                hasLocalData = false;  // marcador de nube sin datos locales: sobrescribirlo lo descargaría
                special = true;
                rep.notes << QObject::tr("El archivo solo estaba «en la nube» (sin datos locales): se ha quitado el "
                                         "marcador local; bórralo también del servicio.");
            }
            if (at & FILE_ATTRIBUTE_COMPRESSED)
                lower(0, QObject::tr("El archivo estaba comprimido por NTFS: el sistema reubica los datos al reescribir, "
                                     "así que pueden quedar restos."));
            if (at & FILE_ATTRIBUTE_ENCRYPTED)
                lower(1, QObject::tr("El archivo estaba cifrado con EFS: sus restos están cifrados con una clave de tu "
                                     "perfil de Windows."));
        }
    }
#endif

    // 2) Destruir: datos + cola del clúster (+ flujos alternos) y fechas; si no se puede sobrescribir, NO se borra.
    bool overwritten = true;
    if (hasLocalData && fi.isFile()) {
#ifdef Q_OS_WIN
        for (const QString& s : alternateStreams(path)) overwritePath(path + s, passes, vol.cluster);
#endif
        overwritten = overwritePath(path, passes, vol.cluster);
    }
    if (!overwritten) {
        rep.notes << QObject::tr("No se pudo sobrescribir «%1» (¿está en uso o protegido?): se ha dejado donde estaba.")
                         .arg(fi.fileName());
        rep.reliability = 0;
        rep.attention = true;
        return rep;  // removed = false
    }

    // 3) Destruir el nombre (varios renombrados) y eliminar sin pasar por la papelera.
#ifdef Q_OS_WIN
    constexpr int kRenames = 8;
#else
    constexpr int kRenames = 4;
#endif
    const QString finalPath = scrubRename(path, kRenames, false);
    rep.removed = QFile::remove(finalPath);
    if (rep.removed) scrubTraces(fi.absoluteFilePath());

    rep.reliability = level;
    rep.attention = level < 2 || special;
#ifdef Q_OS_WIN
    if (rep.attention)
        rep.notes << QObject::tr("Windows puede conservar versiones anteriores (Historial de archivos, Restaurar "
                                 "sistema) que Secure Space no puede borrar.");
#endif
    return rep;
}

bool Vault::removeDirScrubbed(const QString& dir) {
    const QDir d(dir);
    if (!d.entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System).isEmpty()) return false;
    const QString finalPath = scrubRename(dir, 6, true);
    return QDir().rmdir(finalPath);
}

bool Vault::shredTree(const QString& path, int passes, ShredSummary* sum,
                      const std::function<void(const QString&)>& onFile) {
    const QFileInfo fi(path);
    if (fi.isDir() && !fi.isSymLink()) {
        const QFileInfoList kids =
            QDir(path).entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System);
        bool ok = true;
        for (const QFileInfo& k : kids) ok = shredTree(k.absoluteFilePath(), passes, sum, onFile) && ok;
        return removeDirScrubbed(path) && ok;
    }
    if (onFile) onFile(path);
    const ShredReport r = shredExternal(path, passes);
    if (sum) sum->add(r);
    return r.removed;
}

bool Vault::wipeFreeSpace(const QString& folder, const std::function<bool(qint64, qint64)>& progress, QString* err) {
    QStorageInfo si(folder);
    if (!si.isValid() || !si.isReady() || si.isReadOnly())
        return fail(err, QObject::tr("No se puede escribir en esa unidad."));
    const qint64 start = si.bytesAvailable();
    const qint64 reserve = std::max<qint64>(1LL << 30, start / 50);  // se deja un margen para no ahogar al sistema
    const qint64 target = start - reserve;
    if (target <= 0) return fail(err, QObject::tr("No hay suficiente espacio libre para limpiar."));

    const QDir base(folder);
    const QString tmpName = QStringLiteral(".sswipe-") + randomId().left(8);
    if (!base.mkpath(tmpName)) return fail(err, QObject::tr("No se pudo crear la carpeta temporal."));
    const QDir tmp(base.filePath(tmpName));

    QByteArray buf(1 << 20, '\0');
    qint64 written = 0;
    bool cancelled = false, full = false;
    for (int fileNo = 0; written < target && !cancelled && !full; ++fileNo) {
        QFile f(tmp.filePath(QString::number(fileNo)));
        if (!f.open(QIODevice::WriteOnly)) break;
        qint64 inFile = 0;
        while (inFile < (512LL << 20) && written < target) {
            randombytes_buf(buf.data(), std::size_t(buf.size()));
            const qint64 n = f.write(buf);
            if (n != buf.size()) {
                full = true;
                break;
            }
            inFile += n;
            written += n;
            if (progress && !progress(written, target)) {
                cancelled = true;
                break;
            }
            if ((inFile & ((64LL << 20) - 1)) == 0) {
                si.refresh();
                if (si.bytesAvailable() <= reserve / 2) {
                    full = true;
                    break;
                }
            }
        }
        syncFile(f);
        f.close();
    }

    // Fase 2: inundar con archivos diminutos de nombre aleatorio. Reutiliza (y sobrescribe) los registros de archivos
    // ya borrados: entradas de la tabla de archivos (MFT / inodos), nombres y datos «residentes» de archivos pequeños.
    if (!cancelled) {
        const QString floodDir = tmp.filePath(QStringLiteral("f"));
        QDir().mkpath(floodDir);
        QByteArray tiny(600, '\0');
        QElapsedTimer timer;
        timer.start();
        for (int i = 0; i < 40000 && timer.elapsed() < 90000; ++i) {
            randombytes_buf(tiny.data(), std::size_t(tiny.size()));
            QFile f(QDir(floodDir).filePath(randomId().left(24)));
            if (!f.open(QIODevice::WriteOnly)) break;
            if (f.write(tiny) != tiny.size()) break;
            f.close();
            if ((i & 255) == 0 && progress && !progress(target, target)) {
                cancelled = true;
                break;
            }
        }
    }
    QDir(tmp.path()).removeRecursively();
    if (cancelled) return fail(err, QObject::tr("Operación cancelada."));
    return true;
}
