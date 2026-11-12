#include "SettingsDialog.h"

#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>
#include <algorithm>

#include "AuthDialogs.h"
#include "Theme.h"
#include "UiUtil.h"

namespace {
QWidget* indented(QWidget* inner) {
    auto* w = new QWidget;
    auto* l = new QHBoxLayout(w);
    l->setContentsMargins(26, 0, 0, 0);
    l->addWidget(inner);
    l->addStretch();
    return w;
}

QLabel* note(const QString& text, QRgb color = Theme::kDim) {
    auto* l = new QLabel(text);
    l->setWordWrap(true);
    l->setStyleSheet(QStringLiteral("color: %1;").arg(Theme::hex(color)));
    return l;
}
}  // namespace

SettingsDialog::SettingsDialog(Vault& vault, QWidget* parent) : QDialog(parent), vault_(vault) {
    setWindowTitle(tr("Configuración"));
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    setMinimumWidth(620);
    const VaultSettings& s = vault_.settings();

    auto* tabs = new QTabWidget;

    // ---- Seguridad -------------------------------------------------------------------------
    auto* sec = new QWidget;
    auto* secLay = new QVBoxLayout(sec);
    secLay->setSpacing(12);

    auto* g1 = new QGroupBox(tr("Intentos de acceso"));
    auto* g1l = new QVBoxLayout(g1);
    lockout_ = new QCheckBox(tr("Destruir la bóveda al superar un número de contraseñas incorrectas"));
    lockout_->setChecked(s.lockoutEnabled);
    auto* attRow = new QWidget;
    auto* attLay = new QHBoxLayout(attRow);
    attLay->setContentsMargins(0, 0, 0, 0);
    attLay->addWidget(new QLabel(tr("Intentos permitidos:")));
    attempts_ = new QSpinBox;
    attempts_->setRange(1, 99);
    attempts_->setValue(s.maxAttempts);
    attempts_->setEnabled(s.lockoutEnabled);
    attLay->addWidget(attempts_);
    connect(lockout_, &QCheckBox::toggled, attempts_, &QWidget::setEnabled);
    showRemaining_ = new QCheckBox(tr("Mostrar los intentos restantes en la pantalla de acceso"));
    showRemaining_->setChecked(s.showRemaining);
    delay_ = new QCheckBox(tr("Retardo progresivo entre intentos fallidos"));
    delay_->setChecked(s.progressiveDelay);
    g1l->addWidget(lockout_);
    g1l->addWidget(indented(attRow));
    g1l->addWidget(indented(note(tr("Al alcanzar el límite se borrarán TODOS los archivos de forma irrecuperable y "
                                    "Secure Space volverá a su estado inicial."),
                                 Theme::kWarn)));
    g1l->addWidget(showRemaining_);
    g1l->addWidget(delay_);
    secLay->addWidget(g1);

    auto* g2 = new QGroupBox(tr("Llave de la bóveda (segundo factor)"));
    auto* g2l = new QVBoxLayout(g2);
    g2l->addWidget(note(tr("La clave de la bóveda combina tu contraseña con una llave secreta de 256 bits. "
                           "Quien copie la carpeta sin la llave no puede abrirla, ni siquiera por fuerza bruta.")));
    keyOnDevice_ = new QCheckBox(tr("Guardar la llave en este equipo (no pedir el archivo en cada inicio)"));
    keyOnDevice_->setChecked(vault_.isKeyOnDevice());
    auto* exportBtn = new QPushButton(tr("Guardar copia de la llave…"));
    auto* exportRow = new QHBoxLayout;
    exportRow->addWidget(exportBtn);
    exportRow->addStretch();
    g2l->addWidget(keyOnDevice_);
    g2l->addLayout(exportRow);
    connect(exportBtn, &QPushButton::clicked, this, [this] { exportKey(); });
    secLay->addWidget(g2);

    auto* g3 = new QGroupBox(tr("Borrado seguro"));
    auto* g3l = new QVBoxLayout(g3);
    auto* passRow = new QHBoxLayout;
    passRow->addWidget(new QLabel(tr("Sobrescritura al eliminar:")));
    passes_ = new QComboBox;
    passes_->addItem(tr("1 pasada aleatoria (rápido)"), 1);
    passes_->addItem(tr("3 pasadas aleatorias (recomendado)"), 3);
    passes_->addItem(tr("7 pasadas aleatorias (máximo)"), 7);
    const int pi = passes_->findData(s.shredPasses);
    passes_->setCurrentIndex(pi >= 0 ? pi : 1);
    passRow->addWidget(passes_);
    passRow->addStretch();
    auto* impRow = new QHBoxLayout;
    impRow->addWidget(new QLabel(tr("Al importar un archivo:")));
    importMode_ = new QComboBox;
    importMode_->addItem(tr("Preguntar siempre"), 0);
    importMode_->addItem(tr("Dejar una copia sin cifrar fuera de la bóveda"), 1);
    importMode_->addItem(tr("Destruir de forma segura el original"), 2);
    importMode_->setCurrentIndex(std::clamp(s.importOriginal, 0, 2));
    impRow->addWidget(importMode_);
    impRow->addStretch();
    auto* wipeBtn = new QPushButton(tr("Limpiar espacio libre de una unidad…"));
    auto* wipeRow = new QHBoxLayout;
    wipeRow->addWidget(wipeBtn);
    wipeRow->addStretch();
    g3l->addLayout(passRow);
    g3l->addLayout(impRow);
    g3l->addLayout(wipeRow);
    g3l->addWidget(note(tr("Antes de destruir un original se comprueba que la copia cifrada se lee correctamente. "
                           "«Limpiar espacio libre» sobrescribe los restos de archivos borrados antes (en SSD ayuda a "
                           "rematar el borrado; es lento).")));
    connect(wipeBtn, &QPushButton::clicked, this, [this] { wipeFree(); });
    secLay->addWidget(g3);

    auto* g4 = new QGroupBox(tr("Contraseña maestra"));
    auto* g4l = new QHBoxLayout(g4);
    auto* changePw = new QPushButton(tr("Cambiar contraseña…"));
    g4l->addWidget(changePw);
    g4l->addStretch();
    connect(changePw, &QPushButton::clicked, this, [this] { ChangePasswordDialog(vault_, this).exec(); });
    secLay->addWidget(g4);
    secLay->addStretch();
    tabs->addTab(sec, tr("Seguridad"));

    // ---- Privacidad ------------------------------------------------------------------------
    auto* priv = new QWidget;
    auto* privLay = new QVBoxLayout(priv);
    privLay->setSpacing(14);
    auto* g5 = new QGroupBox(tr("Bloqueo"));
    auto* g5l = new QVBoxLayout(g5);
    autoLock_ = new QCheckBox(tr("Bloquear automáticamente por inactividad"));
    autoLock_->setChecked(s.autoLockEnabled);
    auto* idleRow = new QWidget;
    auto* idleLay = new QHBoxLayout(idleRow);
    idleLay->setContentsMargins(0, 0, 0, 0);
    idleLay->addWidget(new QLabel(tr("Tras")));
    autoLockMin_ = new QSpinBox;
    autoLockMin_->setRange(1, 1440);
    autoLockMin_->setSuffix(tr(" min"));
    autoLockMin_->setValue(s.autoLockMinutes);
    autoLockMin_->setEnabled(s.autoLockEnabled);
    idleLay->addWidget(autoLockMin_);
    connect(autoLock_, &QCheckBox::toggled, autoLockMin_, &QWidget::setEnabled);
    lockMinimize_ = new QCheckBox(tr("Bloquear al minimizar la ventana"));
    lockMinimize_->setChecked(s.lockOnMinimize);
    g5l->addWidget(autoLock_);
    g5l->addWidget(indented(idleRow));
    g5l->addWidget(lockMinimize_);
    g5l->addWidget(note(tr("Al bloquear se cierran los visores y se borran las claves de la memoria. Mientras un "
                           "vídeo se reproduce no se bloquea por inactividad.")));
    privLay->addWidget(g5);

    auto* g6 = new QGroupBox(tr("Pantalla"));
    auto* g6l = new QVBoxLayout(g6);
    capture_ = new QCheckBox(tr("Impedir capturas y grabación de pantalla de las ventanas de Secure Space"));
    capture_->setChecked(s.blockScreenCapture);
#ifndef Q_OS_WIN
    capture_->setEnabled(false);
    capture_->setToolTip(tr("Disponible solo en Windows."));
#endif
    g6l->addWidget(capture_);
    privLay->addWidget(g6);
    privLay->addStretch();
    tabs->addTab(priv, tr("Privacidad"));

    // ---- General ---------------------------------------------------------------------------
    auto* gen = new QWidget;
    auto* genLay = new QVBoxLayout(gen);
    genLay->setSpacing(14);
    auto* g7 = new QGroupBox(tr("Interfaz"));
    auto* g7l = new QVBoxLayout(g7);
    confirmDelete_ = new QCheckBox(tr("Pedir confirmación antes de eliminar"));
    confirmDelete_->setChecked(s.confirmDelete);
    auto* sizeRow = new QHBoxLayout;
    sizeRow->addWidget(new QLabel(tr("Tamaño de la interfaz:")));
    uiSize_ = new QComboBox;
    uiSize_->addItem(tr("Compacto"), 12);
    uiSize_->addItem(tr("Normal"), 13);
    uiSize_->addItem(tr("Grande"), 15);
    const int ui = uiSize_->findData(s.uiFontPx);
    uiSize_->setCurrentIndex(ui >= 0 ? ui : 1);
    sizeRow->addWidget(uiSize_);
    sizeRow->addStretch();
    g7l->addWidget(confirmDelete_);
    g7l->addLayout(sizeRow);
    genLay->addWidget(g7);
    auto* about = note(tr("Secure Space 0.2\nCifrado: Argon2id + llave de 256 bits · XChaCha20-Poly1305 (libsodium)"));
    genLay->addWidget(about);
    genLay->addStretch();
    tabs->addTab(gen, tr("General"));

    // ---- Botones ---------------------------------------------------------------------------
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Ok)->setText(tr("Guardar"));
    buttons->button(QDialogButtonBox::Ok)->setObjectName(QStringLiteral("primary"));
    buttons->button(QDialogButtonBox::Cancel)->setText(tr("Cancelar"));
    connect(buttons, &QDialogButtonBox::accepted, this, &SettingsDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(20, 18, 20, 16);
    root->addWidget(tabs);
    root->addWidget(buttons);
}

bool SettingsDialog::exportKey() {
    const QString path = QFileDialog::getSaveFileName(
        this, tr("Guardar copia de la llave (idealmente en un USB)"),
        QDir::homePath() + QStringLiteral("/SecureSpace.sskey"), tr("Llave de Secure Space (*.sskey)"));
    if (path.isEmpty()) return false;
    QString err;
    if (!vault_.exportKeyFile(path.endsWith(QLatin1String(".sskey"), Qt::CaseInsensitive)
                                  ? path
                                  : path + QStringLiteral(".sskey"),
                              &err)) {
        Dlg::error(this, tr("Llave"), err);
        return false;
    }
    keyExported_ = true;
    Dlg::info(this, tr("Llave"),
              tr("Copia guardada. Guárdala fuera de este equipo (USB) y no la dejes junto a la carpeta de la bóveda."));
    return true;
}

void SettingsDialog::wipeFree() {
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Elige una carpeta de la unidad que quieres limpiar"));
    if (dir.isEmpty()) return;
    if (!Dlg::confirm(this, QMessageBox::Warning, tr("Limpiar espacio libre"),
                      tr("Se llenará el espacio libre de esa unidad con datos aleatorios y se crearán miles de "
                         "archivos diminutos, para sobrescribir los restos de archivos borrados (datos, nombres y "
                         "registros del sistema de archivos). Después se liberará todo.\n\nPuede tardar mucho y la "
                         "unidad estará casi llena mientras tanto. Puedes cancelar en cualquier momento.\n\n"
                         "¿Continuar?"),
                      tr("Continuar"), tr("Cancelar")))
        return;
    Dlg::runFreeSpaceWipe(this, dir);
}

void SettingsDialog::accept() {
    if (lockout_->isChecked() && !vault_.settings().lockoutEnabled) {
        if (!Dlg::confirm(this, QMessageBox::Warning, tr("Destrucción automática"),
                          tr("Vas a activar la destrucción automática.\n\nTras %1 contraseña(s) incorrecta(s) se "
                             "borrará todo de forma irrecuperable.\n\n¿Activarla?")
                              .arg(attempts_->value()),
                          tr("Activar"), tr("Cancelar"), true))
            return;
    }

    // Quitar la llave de este equipo exige tener antes una copia en un archivo.
    if (!keyOnDevice_->isChecked() && vault_.isKeyOnDevice()) {
        if (!keyExported_ &&
            !Dlg::confirm(this, QMessageBox::Warning, tr("Llave solo en archivo"),
                          tr("A partir de ahora Secure Space pedirá el archivo de llave en cada inicio y no la "
                             "guardará en este equipo.\n\nAntes debes guardar una copia de la llave."),
                          tr("Guardar la llave…"), tr("Cancelar")))
            return;
        if (!keyExported_ && !exportKey()) return;
    }
    QString err;
    if (keyOnDevice_->isChecked() != vault_.isKeyOnDevice() && !vault_.setKeyOnDevice(keyOnDevice_->isChecked(), &err)) {
        Dlg::error(this, tr("Llave"), err);
        return;
    }

    VaultSettings& s = vault_.settings();
    s.lockoutEnabled = lockout_->isChecked();
    s.maxAttempts = attempts_->value();
    s.showRemaining = showRemaining_->isChecked();
    s.progressiveDelay = delay_->isChecked();
    s.shredPasses = passes_->currentData().toInt();
    s.importOriginal = importMode_->currentData().toInt();
    s.autoLockEnabled = autoLock_->isChecked();
    s.autoLockMinutes = autoLockMin_->value();
    s.lockOnMinimize = lockMinimize_->isChecked();
    s.blockScreenCapture = capture_->isChecked();
    s.confirmDelete = confirmDelete_->isChecked();
    s.uiFontPx = uiSize_->currentData().toInt();
    if (!vault_.saveSettings()) {
        Dlg::error(this, tr("Configuración"), tr("No se pudieron guardar los ajustes."));
        return;
    }
    QDialog::accept();
}
