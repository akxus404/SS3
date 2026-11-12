#pragma once

#include <QFile>
#include <QIODevice>
#include <QList>
#include <QMutex>
#include <QString>
#include <QStringList>
#include <algorithm>
#include <array>
#include <functional>
#include <memory>
#include <vector>

#include "SecretKey.h"

// Ajustes del usuario. Se guardan DENTRO del índice cifrado.
struct VaultSettings {
    // Seguridad
    bool lockoutEnabled = false;   // destruir tras N contraseñas incorrectas
    int maxAttempts = 5;
    bool showRemaining = true;     // mostrar intentos restantes en el acceso
    bool progressiveDelay = true;  // retardo creciente entre intentos fallidos
    int shredPasses = 3;           // pasadas aleatorias de sobrescritura (+1 final a ceros)
    int importOriginal = 0;        // al importar: 0 = preguntar, 1 = dejar copia, 2 = destruir original
    // Privacidad
    bool autoLockEnabled = true;
    int autoLockMinutes = 5;
    bool lockOnMinimize = true;
    bool blockScreenCapture = true;  // solo Windows
    // General
    bool confirmDelete = true;
    int uiFontPx = 13;
};

// Estado necesario ANTES de desbloquear (contador de fallos y política). Va en claro en st.bin.
struct LockState {
    int fails = 0;
    qint64 lastFail = 0;
    bool lockoutEnabled = false;
    int maxAttempts = 5;
    bool progressiveDelay = true;
    bool showRemaining = true;
    int shredPasses = 3;
};

struct VaultEntry {  // lo que ve la interfaz (sin claves)
    QString id;
    QString parentId;  // vacío = raíz
    QString name;
    bool isFolder = false;
    qint64 size = 0;
    qint64 modified = 0;  // epoch en segundos
};

struct VaultItem : VaultEntry {
    QString blob;                         // nombre (aleatorio) del archivo cifrado en disco
    std::array<unsigned char, 32> key{};  // clave propia de cada archivo
};

// Resultado de destruir un archivo EXTERNO a la bóveda (un original). `reliability`: 2 = alta, 1 = media, 0 = baja.
struct ShredReport {
    bool removed = false;     // el archivo ya no existe
    int reliability = 2;      // fiabilidad del borrado físico según la unidad y el sistema de archivos
    bool attention = false;   // hay algo que el usuario debería saber (avisos en `notes`)
    QStringList notes;
    QString folder;           // carpeta de la unidad (para limpiar luego el espacio libre)
};

struct ShredSummary {
    int files = 0;
    int failed = 0;
    int reliability = 2;
    bool attention = false;
    QStringList notes;
    QString folder;
    void add(const ShredReport& r) {
        if (r.removed) ++files; else ++failed;
        reliability = std::min(reliability, r.reliability);
        attention = attention || r.attention;
        for (const QString& n : r.notes)
            if (!notes.contains(n)) notes << n;
        if (folder.isEmpty()) folder = r.folder;
    }
};

// Lectura con acceso aleatorio de un archivo cifrado: descifra por bloques en RAM, sin escribir nada en disco.
// Es lo que permite reproducir vídeo/audio con «saltos» sin descifrar el archivo entero.
class VaultFileDevice : public QIODevice {
public:
    VaultFileDevice(const QString& blobPath, const unsigned char* key, qint64 plainSize);
    ~VaultFileDevice() override;

    bool open(OpenMode mode) override;
    void close() override;
    bool isSequential() const override { return false; }
    qint64 size() const override { return size_; }
    bool seek(qint64 pos) override;
    qint64 bytesAvailable() const override;

protected:
    qint64 readData(char* data, qint64 maxlen) override;
    qint64 writeData(const char*, qint64) override { return -1; }

private:
    bool loadChunk(qint64 idx);

    mutable QMutex mutex_;
    QFile file_;
    SecretKey key_;
    unsigned char prefix_[16] = {};
    qint64 size_;
    qint64 pos_ = 0;
    qint64 cachedIdx_ = -1;
    qint64 cachedLen_ = 0;
    std::vector<unsigned char> plain_;
    std::vector<unsigned char> ct_;
};

class Vault {
public:
    enum class UnlockResult { Ok, WrongPassword, NeedKey, Destroyed, Error };
    using Progress = std::function<bool(qint64 done, qint64 total)>;  // devuelve false para cancelar

    explicit Vault(const QString& dir);
    ~Vault();
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    static bool initCrypto();

    // --- estado -------------------------------------------------------------------------------
    bool exists() const;
    bool isUnlocked() const { return unlocked_; }
    LockState lockState() const;
    int retryDelaySeconds() const;  // espera restante antes de poder reintentar

    // --- ciclo de vida ------------------------------------------------------------------------
    // La clave de la bóveda = Argon2id(contraseña) combinada con una llave aleatoria de 256 bits («llave»).
    // Sin la llave, una copia de la carpeta es inabordable por fuerza bruta, aunque la contraseña sea débil.
    bool create(const QByteArray& password, bool keyOnDevice, QString* error = nullptr);  // deja la bóveda abierta
    UnlockResult unlock(const QByteArray& password, const QString& keyFile = QString(), QString* error = nullptr);
    void lock();
    bool changePassword(const QByteArray& current, const QByteArray& next, QString* error = nullptr);
    void destroyEverything(const Progress& progress = {});  // destrucción total: vuelve al estado inicial

    // --- llave --------------------------------------------------------------------------------
    bool deviceKeyUsable() const;  // ¿hay en este equipo una llave que corresponda a esta bóveda?
    bool isKeyOnDevice() const;
    bool setKeyOnDevice(bool on, QString* error = nullptr);                // requiere bóveda abierta
    bool exportKeyFile(const QString& path, QString* error = nullptr) const;  // requiere bóveda abierta

    // --- ajustes ------------------------------------------------------------------------------
    VaultSettings& settings() { return settings_; }
    const VaultSettings& settings() const { return settings_; }
    bool saveSettings();

    // --- árbol de archivos --------------------------------------------------------------------
    QList<VaultEntry> children(const QString& parentId) const;
    bool entry(const QString& id, VaultEntry* out) const;
    QString pathOf(const QString& id) const;

    // verify = releer y comprobar la copia cifrada (hash) antes de dar la importación por buena.
    bool importFile(const QString& srcPath, const QString& parentId, const Progress& progress, QString* error,
                    bool verify = false);
    QString createFileFromBytes(const QString& name, const QString& parentId, const QByteArray& data, QString* error);
    QString createFolder(const QString& name, const QString& parentId, QString* error);
    bool rename(const QString& id, const QString& newName, QString* error);
    bool remove(const QString& id, const Progress& progress, QString* error);
    // onFile se llama antes de descifrar cada archivo (nombre, tamaño).
    bool exportItem(const QString& id, const QString& destDir, const Progress& progress, QString* error,
                    const std::function<void(const QString&, qint64)>& onFile = {}) const;
    qint64 totalSize(const QString& id) const;  // bytes de un archivo o de toda una carpeta
    int countFiles(const QString& id) const;

    // --- uso del contenido dentro de SS (todo en RAM) ------------------------------------------
    std::unique_ptr<VaultFileDevice> openRead(const QString& id, QString* error) const;
    bool readAll(const QString& id, qint64 maxBytes, QByteArray* out, QString* error) const;
    bool replaceContent(const QString& id, const QByteArray& data, QString* error);

    // --- borrado seguro -----------------------------------------------------------------------
    // Sobrescribe con aleatorios (+1 pasada a ceros), trunca, renombra al azar y elimina. true = ya no existe.
    static bool shredFile(const QString& path, int passes);

    // Destrucción PROFUNDA de archivos que están fuera de la bóveda (ver README, «Borrado definitivo»):
    // sobrescribe datos + cola del clúster + flujos alternos NTFS, neutraliza fechas, destruye el nombre con
    // varios renombrados y elimina sin pasar por la papelera. Informa de la fiabilidad real de la unidad.
    // Nunca elimina un archivo que no haya podido sobrescribir. Es seguro llamarla desde otro hilo.
    static ShredReport shredExternal(const QString& path, int passes);
    static bool removeDirScrubbed(const QString& dir);  // solo si está vacía: renombra al azar y elimina
    // Archivo o carpeta (recursivo, sin seguir enlaces). onFile se llama antes de cada archivo.
    static bool shredTree(const QString& path, int passes, ShredSummary* summary,
                          const std::function<void(const QString&)>& onFile = {});
    // Rellena el espacio libre de la unidad con datos aleatorios y lo libera (sobrescribe restos de archivos
    // borrados). progress devuelve false para cancelar.
    static bool wipeFreeSpace(const QString& folderOnVolume, const std::function<bool(qint64, qint64)>& progress,
                              QString* error);

private:
    enum class HeaderResult { Ok, Wrong, Bad };

    QString pathIn(const QString& name) const;
    QString headerPath() const;
    QString indexPath() const;
    QString statePath() const;
    QString blobPath(const QString& blob) const;

    LockState readState() const;
    void writeState(const LockState& s) const;
    LockState stateFromSettings() const;

    bool headerKcvMatches(const SecretKey& key) const;
    HeaderResult openHeader(const QByteArray& pw, const SecretKey& key, SecretKey& vmkOut, QString* err) const;
    bool writeHeader(const unsigned char* salt, quint64 ops, quint64 mem, const SecretKey& kek);
    void deriveIndexKey();
    bool loadIndex();
    bool saveIndex();
    bool replaceFile(const QString& path, const QByteArray& data);
    void recoverTmp(const QString& path) const;
    void purgeOrphans();
    int passes() const;
    int indexOf(const QString& id) const;
    void collect(const QString& id, QStringList& out) const;
    QString uniqueName(const QString& parentId, const QString& name, const QString& ignoreId) const;
    static bool validName(const QString& name);

    bool writeBlobFrom(QIODevice& in, qint64 size, const QString& blob, const unsigned char* key,
                       const Progress& prog, unsigned char* hashOut) const;
    bool verifyBlob(const QString& blob, const unsigned char* key, qint64 size, const unsigned char* expected,
                    const Progress& prog) const;

    QString dir_;
    bool unlocked_ = false;
    SecretKey vmk_;     // clave maestra de la bóveda (aleatoria, protegida por contraseña + llave)
    SecretKey ixKey_;   // clave del índice, derivada de vmk_
    SecretKey pepper_;  // la llave de 256 bits (en RAM solo mientras la bóveda está abierta)
    VaultSettings settings_;
    std::vector<VaultItem> items_;
};
