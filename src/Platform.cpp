#include "Platform.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QObject>
#include <QStandardPaths>
#include <QWidget>
#include <cstring>

#include "Vault.h"

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <shellapi.h>
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif
#endif

namespace {

QString storeFile() {
    return QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation) + QStringLiteral("/.sscfg/dk.bin");
}

void wipe(QByteArray& b) {
    if (!b.isEmpty()) sodium_memzero(b.data(), std::size_t(b.size()));
}

#ifdef Q_OS_WIN
const BYTE kEntropy[] = "SecureSpace-DeviceKey-v2";
#endif

}  // namespace

void Platform::setCaptureProtection(QWidget* w, bool on) {
#ifdef Q_OS_WIN
    if (!w) return;
    SetWindowDisplayAffinity(reinterpret_cast<HWND>(w->winId()), on ? WDA_EXCLUDEFROMCAPTURE : WDA_NONE);
#else
    Q_UNUSED(w);
    Q_UNUSED(on);
#endif
}

bool DeviceKey::exists() { return QFile::exists(storeFile()); }

bool DeviceKey::save(const SecretKey& key) {
    QByteArray raw(reinterpret_cast<const char*>(key.data()), int(SecretKey::kSize));
    QByteArray blob;
#ifdef Q_OS_WIN
    DATA_BLOB in{DWORD(raw.size()), reinterpret_cast<BYTE*>(raw.data())};
    DATA_BLOB ent{DWORD(sizeof kEntropy), const_cast<BYTE*>(kEntropy)};
    DATA_BLOB out{};
    const BOOL ok = CryptProtectData(&in, L"Secure Space", &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out);
    wipe(raw);
    if (!ok) return false;
    blob = QByteArray(reinterpret_cast<const char*>(out.pbData), int(out.cbData));
    LocalFree(out.pbData);
#else
    blob.swap(raw);  // la llave en claro vive solo en `blob` (se borra al final)
#endif
    const QString path = storeFile();
    const QString dir = QFileInfo(path).absolutePath();
    QDir().mkpath(dir);
#ifdef Q_OS_WIN
    SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(dir).utf16()), FILE_ATTRIBUTE_HIDDEN);
#endif
    bool ok2 = false;
    {
        QFile f(path);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
            ok2 = f.write(blob) == blob.size();
            f.flush();
        }
    }
#ifndef Q_OS_WIN
    wipe(blob);
#endif
    return ok2;
}

bool DeviceKey::load(SecretKey& out) {
    QFile f(storeFile());
    if (!f.open(QIODevice::ReadOnly)) return false;
    QByteArray blob = f.readAll();
    f.close();
#ifdef Q_OS_WIN
    DATA_BLOB in{DWORD(blob.size()), reinterpret_cast<BYTE*>(blob.data())};
    DATA_BLOB ent{DWORD(sizeof kEntropy), const_cast<BYTE*>(kEntropy)};
    DATA_BLOB res{};
    if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &res)) return false;
    const bool okSize = res.cbData == SecretKey::kSize;
    if (okSize) std::memcpy(out.data(), res.pbData, SecretKey::kSize);
    SecureZeroMemory(res.pbData, res.cbData);
    LocalFree(res.pbData);
    return okSize;
#else
    const bool okSize = blob.size() == int(SecretKey::kSize);
    if (okSize) std::memcpy(out.data(), blob.constData(), SecretKey::kSize);
    wipe(blob);
    return okSize;
#endif
}

void DeviceKey::remove() {
    const QString path = storeFile();
    if (QFile::exists(path)) Vault::shredFile(path, 3);
}

namespace {
constexpr char kKeyMagic[6] = {'S', 'S', 'K', 'E', 'Y', '1'};
constexpr int kKeyFileSize = 6 + 32 + 8;
}  // namespace

bool DeviceKey::writeKeyFile(const QString& path, const SecretKey& key, QString* err) {
    QByteArray b(kKeyMagic, 6);
    b.append(reinterpret_cast<const char*>(key.data()), int(SecretKey::kSize));
    unsigned char h[16];
    crypto_generichash(h, sizeof h, key.data(), SecretKey::kSize, nullptr, 0);
    b.append(reinterpret_cast<const char*>(h), 8);

    QFile f(path);
    bool ok = f.open(QIODevice::WriteOnly | QIODevice::Truncate) && f.write(b) == b.size();
    if (ok) {
        f.flush();
        f.close();
    }
    wipe(b);
    if (!ok && err) *err = QObject::tr("No se pudo escribir el archivo de llave en esa ubicación.");
    return ok;
}

bool DeviceKey::readKeyFile(const QString& path, SecretKey& out, QString* err) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (err) *err = QObject::tr("No se pudo leer el archivo de llave.");
        return false;
    }
    QByteArray b = f.readAll();
    f.close();
    bool ok = b.size() == kKeyFileSize && std::memcmp(b.constData(), kKeyMagic, 6) == 0;
    if (ok) {
        unsigned char h[16];
        crypto_generichash(h, sizeof h, reinterpret_cast<const unsigned char*>(b.constData()) + 6, SecretKey::kSize,
                           nullptr, 0);
        ok = sodium_memcmp(h, b.constData() + 6 + 32, 8) == 0;
    }
    if (ok) std::memcpy(out.data(), b.constData() + 6, SecretKey::kSize);
    wipe(b);
    if (!ok && err) *err = QObject::tr("El archivo no es una llave válida de Secure Space.");
    return ok;
}

// --- rastros del sistema ---------------------------------------------------------------------------

Platform::TraceResult Platform::clearSystemTraces() {
    TraceResult r;
    auto wipeFile = [&r](const QString& path) {
        if (Vault::shredFile(path, 1)) ++r.removed;
        else ++r.locked;
    };
    auto wipeDir = [&wipeFile](const QString& dir, const QStringList& filters) {
        const QFileInfoList list = QDir(dir).entryInfoList(filters, QDir::Files | QDir::Hidden | QDir::System);
        for (const QFileInfo& fi : list) wipeFile(fi.absoluteFilePath());
    };
#ifdef Q_OS_WIN
    const QString recent = qEnvironmentVariable("APPDATA") + QStringLiteral("/Microsoft/Windows/Recent");
    wipeDir(recent, {QStringLiteral("*.lnk")});
    wipeDir(recent + QStringLiteral("/AutomaticDestinations"), {QStringLiteral("*")});
    wipeDir(recent + QStringLiteral("/CustomDestinations"), {QStringLiteral("*")});
    const QString explorer = qEnvironmentVariable("LOCALAPPDATA") + QStringLiteral("/Microsoft/Windows/Explorer");
    wipeDir(explorer, {QStringLiteral("thumbcache_*.db"), QStringLiteral("iconcache_*.db")});
#elif defined(Q_OS_LINUX)
    const QString thumbs =
        QStandardPaths::writableLocation(QStandardPaths::GenericCacheLocation) + QStringLiteral("/thumbnails");
    QDirIterator it(thumbs, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) wipeFile(it.next());
    const QString xbel =
        QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QStringLiteral("/recently-used.xbel");
    if (QFile::exists(xbel)) {
        QFile f(xbel);
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xbel version=\"1.0\"/>\n");
            ++r.removed;
        }
    }
#else
    Q_UNUSED(wipeDir);
    r.supported = false;
#endif
    return r;
}

bool Platform::deleteShadowCopies(const QString& drive, QString* err) {
#ifdef Q_OS_WIN
    const std::wstring params = L"delete shadows /for=" + drive.toStdWString() + L" /all /quiet";
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";  // pide elevación (UAC)
    sei.lpFile = L"vssadmin.exe";
    sei.lpParameters = params.c_str();
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExW(&sei) || !sei.hProcess) {
        if (err) *err = QObject::tr("No se obtuvieron permisos de administrador.");
        return false;
    }
    while (WaitForSingleObject(sei.hProcess, 50) == WAIT_TIMEOUT) QCoreApplication::processEvents();
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    if (code != 0 && err) *err = QObject::tr("vssadmin terminó con el código %1 (puede que no hubiera copias).").arg(code);
    return code == 0;
#else
    Q_UNUSED(drive);
    if (err) *err = QObject::tr("Solo disponible en Windows.");
    return false;
#endif
}
