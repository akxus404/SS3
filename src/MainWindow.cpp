#include "MainWindow.h"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QDateTime>
#include <QDir>
#include <QDirIterator>
#include <QDragEnterEvent>
#include <QDragLeaveEvent>
#include <QDropEvent>
#include <QEventLoop>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLocale>
#include <QMenu>
#include <QMimeData>
#include <QMutex>
#include <QPushButton>
#include <QResizeEvent>
#include <QShortcut>
#include <QStatusBar>
#include <QStorageInfo>
#include <QStyle>
#include <QThread>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>
#include <atomic>
#include <thread>

#include "DropOverlay.h"
#include "Platform.h"
#include "SettingsDialog.h"
#include "Theme.h"
#include "TransferPanel.h"
#include "UiUtil.h"
#include "Viewer.h"

namespace {
constexpr int kIdRole = Qt::UserRole;
constexpr int kFolderRole = Qt::UserRole + 1;

struct ScanResult {
    qint64 bytes = 0;
    int files = 0;
};

// Tamaño y número de archivos que se van a importar (mismos criterios que importOne: sin enlaces simbólicos).
ScanResult scanPaths(const QStringList& paths) {
    ScanResult r;
    for (const QString& p : paths) {
        const QFileInfo fi(p);
        if (fi.isDir()) {
            QDirIterator it(p, QDir::Files | QDir::Hidden | QDir::NoSymLinks, QDirIterator::Subdirectories);
            while (it.hasNext()) {
                it.next();
                r.bytes += it.fileInfo().size();
                ++r.files;
            }
        } else {
            r.bytes += fi.size();
            ++r.files;
        }
    }
    return r;
}

// Carpeta existente más cercana (la original puede haberse eliminado al destruir una carpeta entera).
QString existingAncestor(QString p) {
    while (!p.isEmpty() && !QFileInfo::exists(p)) {
        const QString up = QFileInfo(p).absolutePath();
        if (up == p) break;
        p = up;
    }
    return p;
}
}  // namespace

MainWindow::MainWindow(Vault& vault, QWidget* parent) : QMainWindow(parent), vault_(vault) {
    setWindowTitle(QStringLiteral("Secure Space"));
    resize(1040, 660);
    setAcceptDrops(true);

    auto* central = new QWidget(this);
    setCentralWidget(central);
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(20, 16, 20, 12);
    root->setSpacing(12);

    // Todo el contenido vive en `content_`: se desactiva mientras hay una operación en curso; el panel de
    // transferencia queda fuera para poder cancelar.
    content_ = new QWidget;
    auto* cl = new QVBoxLayout(content_);
    cl->setContentsMargins(0, 0, 0, 0);
    cl->setSpacing(12);
    root->addWidget(content_, 1);
    panel_ = new TransferPanel;
    root->addWidget(panel_);
    overlay_ = new DropOverlay(central);

    // Cabecera: logo, título y acciones globales
    auto* head = new QHBoxLayout;
    head->setSpacing(12);
    head->addWidget(new LogoWidget(46));
    auto* titles = new QVBoxLayout;
    titles->setSpacing(0);
    auto* title = new QLabel(QStringLiteral("Secure Space"));
    title->setObjectName(QStringLiteral("title"));
    pathLabel_ = new QLabel;
    pathLabel_->setObjectName(QStringLiteral("hint"));
    titles->addWidget(title);
    titles->addWidget(pathLabel_);
    head->addLayout(titles);
    head->addStretch();
    auto* lockBtn = new QPushButton(tr("Bloquear"));
    lockBtn->setToolTip(tr("Bloquear la bóveda (Ctrl+L)"));
    auto* settingsBtn = new QPushButton(tr("Configuración"));
    auto* destroyBtn = new QPushButton(tr("Destruir todo"));
    destroyBtn->setObjectName(QStringLiteral("danger"));
    destroyBtn->setToolTip(tr("Borra de forma permanente e irrecuperable todo el contenido"));
    head->addWidget(lockBtn);
    head->addWidget(settingsBtn);
    head->addWidget(destroyBtn);
    cl->addLayout(head);

    // Barra de acciones sobre archivos
    auto* row = new QHBoxLayout;
    row->setSpacing(8);
    upBtn_ = new QPushButton(tr("Subir"));
    openBtn_ = new QPushButton(tr("Abrir"));
    openBtn_->setToolTip(tr("Ver o editar dentro de la bóveda, sin descifrar nada en el disco"));

    auto* importBtn = new QPushButton(tr("Importar"));
    importBtn->setObjectName(QStringLiteral("primary"));
    auto* importMenu = new QMenu(importBtn);
    connect(importMenu->addAction(tr("Archivos…")), &QAction::triggered, this, &MainWindow::importFiles);
    connect(importMenu->addAction(tr("Carpeta…")), &QAction::triggered, this, &MainWindow::importFolder);
    importBtn->setMenu(importMenu);

    auto* newBtn = new QPushButton(tr("Nuevo"));
    auto* newMenu = new QMenu(newBtn);
    connect(newMenu->addAction(tr("Carpeta")), &QAction::triggered, this, &MainWindow::newFolder);
    connect(newMenu->addAction(tr("Documento de texto")), &QAction::triggered, this, &MainWindow::newTextFile);
    newBtn->setMenu(newMenu);

    exportBtn_ = new QPushButton(tr("Exportar"));
    renameBtn_ = new QPushButton(tr("Renombrar"));
    deleteBtn_ = new QPushButton(tr("Eliminar"));

    auto* toolsBtn = new QPushButton(tr("Herramientas"));
    auto* toolsMenu = new QMenu(toolsBtn);
    connect(toolsMenu->addAction(tr("Destruir archivos del equipo…")), &QAction::triggered, this,
            &MainWindow::shredExternalFiles);
    connect(toolsMenu->addAction(tr("Destruir carpeta del equipo…")), &QAction::triggered, this,
            &MainWindow::shredExternalFolder);
    toolsMenu->addSeparator();
    connect(toolsMenu->addAction(tr("Limpiar espacio libre de una unidad…")), &QAction::triggered, this,
            &MainWindow::wipeFreeSpaceTool);
    connect(toolsMenu->addAction(tr("Limpiar rastros del sistema (recientes, miniaturas)…")), &QAction::triggered, this,
            &MainWindow::clearTracesTool);
#ifdef Q_OS_WIN
    connect(toolsMenu->addAction(tr("Eliminar copias de volumen (Restaurar sistema)…")), &QAction::triggered, this,
            &MainWindow::deleteShadowCopiesTool);
#endif
    toolsBtn->setMenu(toolsMenu);
    for (QPushButton* b : {upBtn_, openBtn_, importBtn, newBtn, exportBtn_, renameBtn_, deleteBtn_, toolsBtn})
        row->addWidget(b);
    row->addStretch();
    cl->addLayout(row);

    // Lista de elementos
    tree_ = new QTreeWidget;
    tree_->setColumnCount(3);
    tree_->setHeaderLabels({tr("Nombre"), tr("Tamaño"), tr("Modificado")});
    tree_->setRootIsDecorated(false);
    tree_->setAlternatingRowColors(true);
    tree_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    tree_->setUniformRowHeights(true);
    tree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    tree_->header()->setStretchLastSection(false);
    tree_->setColumnWidth(1, 120);
    tree_->setColumnWidth(2, 160);
    cl->addWidget(tree_, 1);

    // Barra de estado
    statusLabel_ = new QLabel;
    statusBar()->addWidget(statusLabel_, 1);

    // Conexiones
    connect(lockBtn, &QPushButton::clicked, this, &MainWindow::lockNow);
    connect(settingsBtn, &QPushButton::clicked, this, &MainWindow::openSettings);
    connect(destroyBtn, &QPushButton::clicked, this, &MainWindow::destroyAll);
    connect(upBtn_, &QPushButton::clicked, this, &MainWindow::goUp);
    connect(openBtn_, &QPushButton::clicked, this, &MainWindow::openSelected);
    connect(exportBtn_, &QPushButton::clicked, this, &MainWindow::exportSelected);
    connect(renameBtn_, &QPushButton::clicked, this, &MainWindow::renameSelected);
    connect(deleteBtn_, &QPushButton::clicked, this, &MainWindow::deleteSelected);
    connect(tree_, &QTreeWidget::itemActivated, this, [this](QTreeWidgetItem* it, int) { openItem(it); });
    connect(tree_, &QTreeWidget::itemSelectionChanged, this, &MainWindow::updateButtons);

    auto bind = [this](const QKeySequence& k, auto slot) {
        connect(new QShortcut(k, this), &QShortcut::activated, this, slot);
    };
    bind(QKeySequence(QStringLiteral("Ctrl+L")), &MainWindow::lockNow);
    bind(QKeySequence(QStringLiteral("Ctrl+I")), &MainWindow::importFiles);
    bind(QKeySequence(QStringLiteral("Ctrl+N")), &MainWindow::newFolder);
    bind(QKeySequence(Qt::Key_F2), &MainWindow::renameSelected);
    bind(QKeySequence(Qt::Key_Delete), &MainWindow::deleteSelected);
    bind(QKeySequence(Qt::Key_Backspace), &MainWindow::goUp);

    idle_.setSingleShot(true);
    connect(&idle_, &QTimer::timeout, this, [this] {
        for (ViewerDialog* v : findChildren<ViewerDialog*>())  // viendo un vídeo no cuenta como inactividad
            if (v->isPlaying()) {
                idle_.start();
                return;
            }
        lockNow();
    });
    qApp->installEventFilter(this);

    refresh();
    applySettings();
}

MainWindow::~MainWindow() { qApp->removeEventFilter(this); }

// --- lista ---------------------------------------------------------------------------------------

void MainWindow::refresh() {
    tree_->clear();
    const QList<VaultEntry> entries = vault_.children(current_);
    for (const VaultEntry& e : entries) {
        auto* it = new QTreeWidgetItem(tree_);
        it->setText(0, e.name);
        it->setIcon(0, style()->standardIcon(e.isFolder ? QStyle::SP_DirIcon : QStyle::SP_FileIcon));
        it->setText(1, e.isFolder ? QString() : QLocale().formattedDataSize(e.size));
        it->setTextAlignment(1, Qt::AlignRight | Qt::AlignVCenter);
        it->setText(2, QDateTime::fromSecsSinceEpoch(e.modified).toString(QStringLiteral("dd/MM/yyyy HH:mm")));
        it->setData(0, kIdRole, e.id);
        it->setData(0, kFolderRole, e.isFolder);
    }
    pathLabel_->setText(tr("Bóveda") + vault_.pathOf(current_));
    upBtn_->setEnabled(!current_.isEmpty());
    statusLabel_->setText(entries.isEmpty() ? tr("Vacío — arrastra archivos aquí o usa «Importar»")
                                            : tr("%1 elemento(s)").arg(entries.size()));
    updateButtons();
}

void MainWindow::updateButtons() {
    const int n = int(tree_->selectedItems().size());
    openBtn_->setEnabled(n == 1);
    exportBtn_->setEnabled(n > 0);
    renameBtn_->setEnabled(n == 1);
    deleteBtn_->setEnabled(n > 0);
}

QStringList MainWindow::selectedIds() const {
    QStringList ids;
    for (QTreeWidgetItem* it : tree_->selectedItems()) ids << it->data(0, kIdRole).toString();
    return ids;
}

void MainWindow::openItem(QTreeWidgetItem* item) {
    if (!item || busy_ || done_) return;
    if (item->data(0, kFolderRole).toBool()) {
        current_ = item->data(0, kIdRole).toString();
        refresh();
        return;
    }
    VaultEntry e;
    if (!vault_.entry(item->data(0, kIdRole).toString(), &e)) return;
    if (ViewerDialog::kindFor(e.name) == ViewerDialog::Kind::None) {
        Dlg::info(this, QStringLiteral("Secure Space"),
                  tr("No hay vista previa para este tipo de archivo.\n\nPuedes exportarlo, o usar archivos de texto, "
                     "imágenes, audio y vídeo directamente dentro de la bóveda."));
        return;
    }
    ViewerDialog dlg(vault_, e, this);
    dlg.exec();
    if (!done_) refresh();  // por si se guardaron cambios (tamaño y fecha)
}

void MainWindow::openSelected() {
    const auto items = tree_->selectedItems();
    if (items.size() == 1) openItem(items.first());
}

void MainWindow::goUp() {
    VaultEntry e;
    if (!current_.isEmpty() && vault_.entry(current_, &e)) {
        current_ = e.parentId;
        refresh();
    }
}

// --- operaciones largas --------------------------------------------------------------------------

void MainWindow::beginBusy(const QString& title, qint64 units, int files, int scale, bool cancellable) {
    busy_ = true;
    idle_.stop();
    content_->setEnabled(false);
    panel_->begin(title, units, files, scale, cancellable);
}

void MainWindow::endBusy() {
    busy_ = false;
    panel_->end();
    content_->setEnabled(true);
    if (vault_.settings().autoLockEnabled) idle_.start(vault_.settings().autoLockMinutes * 60 * 1000);
    if (lockPending_) {
        lockPending_ = false;
        lockNow();
    }
}

Vault::Progress MainWindow::progressFn() {
    return [this](qint64 done, qint64 total) { return panel_->fileProgress(done, total); };
}

Vault::Progress MainWindow::overallFn() {
    return [this](qint64 done, qint64 total) { return panel_->overall(done, total); };
}

// --- importar / exportar -------------------------------------------------------------------------

int MainWindow::askImportAction() {
    int action = vault_.settings().importOriginal;
    if (action == 1 || action == 2) return action;

    QMessageBox box(QMessageBox::Question, tr("Importar a la bóveda"),
                    tr("¿Qué hacemos con los archivos originales?"), QMessageBox::NoButton, this);
    box.setInformativeText(
        tr("Dejar copia: el original sigue donde estaba, sin cifrar.\n\n"
           "Destruir original: se comprueba que la copia cifrada se lee correctamente y entonces el original se "
           "elimina de forma definitiva. Solo quedará el que está dentro de la bóveda."));
    QPushButton* keep = box.addButton(tr("Dejar copia sin cifrar"), QMessageBox::AcceptRole);
    QPushButton* shred = box.addButton(tr("Destruir original"), QMessageBox::DestructiveRole);
    QPushButton* cancel = box.addButton(tr("Cancelar"), QMessageBox::RejectRole);
    box.setDefaultButton(keep);
    box.setEscapeButton(cancel);
    auto* remember = new QCheckBox(tr("Recordar mi elección"));
    box.setCheckBox(remember);
    box.exec();

    if (box.clickedButton() == keep)
        action = 1;
    else if (box.clickedButton() == shred)
        action = 2;
    else
        return -1;
    if (remember->isChecked() && !done_) {
        vault_.settings().importOriginal = action;
        vault_.saveSettings();
    }
    return action;
}

void MainWindow::importFiles() {
    if (busy_ || done_) return;
    const QStringList files = QFileDialog::getOpenFileNames(this, tr("Importar archivos a la bóveda"));
    if (!files.isEmpty() && !done_) importPaths(files);
}

void MainWindow::importFolder() {
    if (busy_ || done_) return;
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Importar carpeta a la bóveda"));
    if (!dir.isEmpty() && !done_) importPaths({dir});
}

void MainWindow::importPaths(const QStringList& paths) {
    if (busy_ || done_) return;
    const int action = askImportAction();
    if (action < 0 || done_) return;
    const bool shred = action == 2;
    const ScanResult sc = scanPaths(paths);
    const int scale = shred ? 2 : 1;  // con «destruir original» se cifra y además se verifica (relee)

    int ok = 0, bad = 0;
    QString err;
    QStringList queue, dirs;  // originales ya verificados, listos para destruir
    beginBusy(shred ? tr("Cifrando y verificando") : tr("Cifrando y guardando en la bóveda"), sc.bytes * scale,
              sc.files, scale, true);
    for (const QString& p : paths) {
        if (panel_->cancelled()) break;
        importOne(p, current_, shred, ok, bad, queue, dirs, err);
    }
    const bool cancelled = panel_->cancelled();
    endBusy();
    if (done_) return;
    refresh();
    statusLabel_->setText(cancelled ? tr("Importación cancelada · %1 archivo(s) importado(s)").arg(ok)
                                    : tr("%1 archivo(s) importado(s)").arg(ok));
    if (cancelled) return;  // al cancelar, los originales no se tocan
    if (bad > 0)
        Dlg::warn(this, QStringLiteral("Secure Space"),
                  tr("%1 elemento(s) no se pudieron importar: %2\n\nSus originales no se han tocado.").arg(bad).arg(err));

    // Solo se destruyen los originales cuya copia cifrada se verificó, y en segundo plano (la interfaz sigue viva).
    if (shred && !queue.isEmpty()) {
        ShredSummary sum;
        shredInBackground(queue, false, sum);
        if (done_) return;
        for (const QString& d : dirs) Vault::removeDirScrubbed(d);  // hijos antes que padres
        reportShred(sum);
    }
}

void MainWindow::importOne(const QString& path, const QString& parentId, bool shredOriginal, int& ok, int& bad,
                           QStringList& queue, QStringList& dirs, QString& err) {
    if (panel_->cancelled()) return;
    const QFileInfo fi(path);
    if (fi.isDir()) {
        QString e;
        const QString id = vault_.createFolder(fi.fileName(), parentId, &e);
        if (id.isEmpty()) {
            ++bad;
            err = e;
            return;
        }
        const QFileInfoList kids =
            QDir(path).entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden | QDir::NoSymLinks);
        int childBad = 0;
        for (const QFileInfo& k : kids) {
            if (panel_->cancelled()) break;
            importOne(k.absoluteFilePath(), id, shredOriginal, ok, childBad, queue, dirs, err);
        }
        bad += childBad;
        if (shredOriginal && childBad == 0 && !panel_->cancelled()) dirs << path;
        return;
    }
    QString e;
    panel_->startFile(fi.fileName(), fi.size() * (shredOriginal ? 2 : 1));
    // Con «destruir original» se verifica la copia cifrada (hash) ANTES de dar el archivo por importado.
    if (vault_.importFile(path, parentId, progressFn(), &e, shredOriginal)) {
        ++ok;
        if (shredOriginal) queue << path;
    } else {
        ++bad;
        err = e;
    }
}

// --- destrucción definitiva de archivos externos -------------------------------------------------

void MainWindow::shredInBackground(const QStringList& paths, bool trees, ShredSummary& sum) {
    const int passes = vault_.settings().shredPasses;
    beginBusy(tr("Destruyendo de forma definitiva"), 0, 0, 1, false);
    panel_->setIndeterminate(tr("Preparando…"));
    QMutex mtx;
    QString current;
    std::atomic<bool> finishedFlag{false};
    std::thread worker([&] {
        for (const QString& p : paths) {
            if (trees) {
                Vault::shredTree(p, passes, &sum, [&](const QString& f) {
                    QMutexLocker l(&mtx);
                    current = f;
                });
            } else {
                {
                    QMutexLocker l(&mtx);
                    current = p;
                }
                sum.add(Vault::shredExternal(p, passes));
            }
        }
        finishedFlag = true;
    });
    while (!finishedFlag) {
        QString name;
        {
            QMutexLocker l(&mtx);
            name = QFileInfo(current).fileName();
        }
        panel_->setFileText(name);
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents);
        QThread::msleep(20);
    }
    worker.join();
    endBusy();
}

void MainWindow::reportShred(const ShredSummary& sum) {
    if (done_) return;
    statusLabel_->setText(tr("%1 archivo(s) destruido(s) de forma definitiva").arg(sum.files));
    if (!sum.attention && sum.failed == 0) return;

    QString text = tr("%1 archivo(s) destruido(s) de forma definitiva.").arg(sum.files);
    if (sum.failed > 0)
        text += QStringLiteral("\n") +
                tr("%1 no se pudieron destruir (¿en uso o protegidos?) y siguen donde estaban.").arg(sum.failed);
    if (!sum.notes.isEmpty())
        text += QStringLiteral("\n\n") + tr("Avisos:") + QStringLiteral("\n• ") + sum.notes.join(QStringLiteral("\n• "));

    if (sum.reliability < 2 && !sum.folder.isEmpty()) {
        text += QStringLiteral("\n\n") +
                tr("Para rematar el borrado en esta unidad se recomienda sobrescribir el espacio libre (puede tardar "
                   "bastante).");
        if (Dlg::confirm(this, QMessageBox::Warning, tr("Borrado definitivo"), text, tr("Limpiar espacio libre ahora"),
                         tr("Más tarde")) &&
            !done_)
            Dlg::runFreeSpaceWipe(this, existingAncestor(sum.folder));
    } else {
        Dlg::warn(this, tr("Borrado definitivo"), text);
    }
}

void MainWindow::confirmAndShred(const QStringList& paths) {
    if (paths.isEmpty() || busy_ || done_) return;
    if (!Dlg::confirm(this, QMessageBox::Warning, tr("Destruir de forma definitiva"),
                      tr("Se destruirán de forma DEFINITIVA %1 elemento(s) del equipo (no de la bóveda). No pasarán "
                         "por la papelera y no habrá forma de recuperarlos.\n\n%2")
                          .arg(paths.size())
                          .arg(paths.first()),
                      tr("Destruir"), tr("Cancelar"), true))
        return;
    ShredSummary sum;
    shredInBackground(paths, true, sum);
    reportShred(sum);
}

void MainWindow::shredExternalFiles() {
    if (busy_ || done_) return;
    const QStringList files = QFileDialog::getOpenFileNames(this, tr("Elige los archivos del equipo que quieres destruir"));
    if (!files.isEmpty() && !done_) confirmAndShred(files);
}

void MainWindow::shredExternalFolder() {
    if (busy_ || done_) return;
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Elige la carpeta del equipo que quieres destruir"));
    if (!dir.isEmpty() && !done_) confirmAndShred({dir});
}

void MainWindow::wipeFreeSpaceTool() {
    if (busy_ || done_) return;
    const QString dir = QFileDialog::getExistingDirectory(this, tr("Elige una carpeta de la unidad que quieres limpiar"));
    if (dir.isEmpty() || done_) return;
    if (!Dlg::confirm(this, QMessageBox::Warning, tr("Limpiar espacio libre"),
                      tr("Se llenará el espacio libre de esa unidad con datos aleatorios y se crearán miles de "
                         "archivos diminutos, para sobrescribir los restos de archivos borrados. Después se liberará "
                         "todo.\n\nPuede tardar mucho. Puedes cancelar en cualquier momento.\n\n¿Continuar?"),
                      tr("Continuar"), tr("Cancelar")))
        return;
    Dlg::runFreeSpaceWipe(this, dir);
}

void MainWindow::exportSelected() {
    const QStringList ids = selectedIds();
    if (ids.isEmpty() || busy_ || done_) return;
    if (!exportWarned_) {
        if (!Dlg::confirm(this, QMessageBox::Question, tr("Exportar"),
                          tr("Los archivos exportados quedarán SIN cifrar fuera de la bóveda.\n\n¿Continuar?"),
                          tr("Continuar"), tr("Cancelar")))
            return;
        exportWarned_ = true;
    }
    const QString dest = QFileDialog::getExistingDirectory(this, tr("Elige la carpeta de destino"));
    if (dest.isEmpty() || done_) return;

    qint64 bytes = 0;
    int files = 0;
    for (const QString& id : ids) {
        bytes += vault_.totalSize(id);
        files += vault_.countFiles(id);
    }
    QString err;
    bool ok = true;
    beginBusy(tr("Exportando (descifrando)"), bytes, files, 1, true);
    for (const QString& id : ids)
        if (!vault_.exportItem(id, dest, progressFn(), &err,
                               [this](const QString& name, qint64 size) { panel_->startFile(name, size); })) {
            ok = false;
            break;
        }
    const bool cancelled = panel_->cancelled();
    endBusy();
    if (done_) return;
    if (cancelled)
        statusLabel_->setText(tr("Exportación cancelada."));
    else if (ok)
        statusLabel_->setText(tr("Exportación completada."));
    else
        Dlg::warn(this, tr("Exportar"), err);
}

// --- carpetas, textos, renombrar, eliminar -------------------------------------------------------

void MainWindow::newFolder() {
    if (busy_ || done_) return;
    bool ok = false;
    const QString name = Dlg::askText(this, tr("Nueva carpeta"), tr("Nombre:"), QString(), &ok);
    if (!ok || done_) return;
    QString err;
    if (vault_.createFolder(name, current_, &err).isEmpty()) Dlg::warn(this, tr("Nueva carpeta"), err);
    refresh();
}

void MainWindow::newTextFile() {
    if (busy_ || done_) return;
    bool ok = false;
    const QString name = Dlg::askText(this, tr("Nuevo documento de texto"), tr("Nombre:"), tr("Nota.txt"), &ok);
    if (!ok || done_) return;
    QString err;
    const QString id = vault_.createFileFromBytes(name, current_, QByteArray(), &err);
    if (id.isEmpty()) {
        Dlg::warn(this, tr("Nuevo documento de texto"), err);
        return;
    }
    refresh();
    VaultEntry e;
    if (vault_.entry(id, &e) && ViewerDialog::kindFor(e.name) == ViewerDialog::Kind::Text) {
        ViewerDialog dlg(vault_, e, this);
        dlg.exec();
        if (!done_) refresh();
    }
}

void MainWindow::renameSelected() {
    const QStringList ids = selectedIds();
    VaultEntry e;
    if (ids.size() != 1 || busy_ || done_ || !vault_.entry(ids.first(), &e)) return;
    bool ok = false;
    const QString name = Dlg::askText(this, tr("Renombrar"), tr("Nuevo nombre:"), e.name, &ok);
    if (!ok || done_) return;
    QString err;
    if (!vault_.rename(e.id, name, &err)) Dlg::warn(this, tr("Renombrar"), err);
    refresh();
}

void MainWindow::deleteSelected() {
    const QStringList ids = selectedIds();
    if (ids.isEmpty() || busy_ || done_) return;
    if (vault_.settings().confirmDelete) {
        if (!Dlg::confirm(this, QMessageBox::Warning, tr("Eliminar"),
                          tr("Se destruirán de forma irrecuperable %1 elemento(s).\n\nEsta acción no se puede "
                             "deshacer.")
                              .arg(ids.size()),
                          tr("Eliminar"), tr("Cancelar"), true))
            return;
    }
    QString err;
    bool ok = true;
    beginBusy(tr("Destruyendo de forma segura"), 0, 0, 1, false);
    panel_->setIndeterminate(tr("Sobrescribiendo y eliminando…"));
    for (const QString& id : ids)
        if (!vault_.remove(id, overallFn(), &err)) {
            ok = false;
            break;
        }
    endBusy();
    if (done_) return;
    refresh();
    if (!ok) Dlg::warn(this, tr("Eliminar"), err);
}

// --- destrucción total ---------------------------------------------------------------------------

void MainWindow::destroyAll() {
    if (busy_ || done_) return;
    bool ok = false;
    const QString typed = Dlg::askText(
        this, tr("Destruir todo"),
        tr("Esto borrará de forma PERMANENTE e IRRECUPERABLE todos los archivos de la bóveda, la contraseña y la "
           "llave de este equipo. Secure Space volverá a su estado inicial.\n\nEscribe DESTRUIR para confirmar:"),
        QString(), &ok);
    if (!ok || typed.trimmed() != QLatin1String("DESTRUIR") || done_) return;

    beginBusy(tr("Destruyendo la bóveda"), 0, 0, 1, false);
    panel_->setIndeterminate(tr("Sobrescribiendo claves y archivos…"));
    vault_.destroyEverything(overallFn());
    busy_ = false;
    panel_->end();
    content_->setEnabled(true);
    Dlg::info(this, QStringLiteral("Secure Space"),
              tr("La bóveda fue destruida. Secure Space volverá a su estado inicial."));
    finish(Result::Destroyed);
}

void MainWindow::clearTracesTool() {
    if (busy_ || done_) return;
    if (!Dlg::confirm(this, QMessageBox::Question, tr("Limpiar rastros del sistema"),
                      tr("Se vaciarán los rastros que el sistema guarda de los archivos que has abierto: listas de "
                         "archivos recientes, listas de salto y cachés de miniaturas (que pueden contener una vista "
                         "previa de imágenes y vídeos).\n\nNo afecta a tus archivos. Las cachés que el sistema tenga "
                         "en uso quedarán para después de cerrar sesión.\n\n¿Continuar?"),
                      tr("Limpiar"), tr("Cancelar")))
        return;
    const Platform::TraceResult r = Platform::clearSystemTraces();
    if (!r.supported) {
        Dlg::info(this, tr("Limpiar rastros del sistema"), tr("Esta función aún no está disponible en este sistema."));
        return;
    }
    QString msg = tr("%1 rastro(s) eliminado(s).").arg(r.removed);
    if (r.locked > 0)
        msg += QStringLiteral("\n") +
               tr("%1 están en uso por el sistema: cierra sesión o reinicia y repite la limpieza.").arg(r.locked);
    Dlg::info(this, tr("Limpiar rastros del sistema"), msg);
}

#ifdef Q_OS_WIN
void MainWindow::deleteShadowCopiesTool() {
    if (busy_ || done_) return;
    const QString dir =
        QFileDialog::getExistingDirectory(this, tr("Elige una carpeta de la unidad cuyas copias de volumen quieres eliminar"));
    if (dir.isEmpty() || done_) return;
    const QString drive = QStorageInfo(dir).rootPath().left(2);  // "C:"
    if (!Dlg::confirm(this, QMessageBox::Warning, tr("Eliminar copias de volumen"),
                      tr("Se eliminarán TODAS las copias de volumen de la unidad %1: puntos de restauración y "
                         "versiones anteriores de archivos. Es la única forma de que no queden versiones antiguas de "
                         "archivos ya destruidos, pero ya no podrás restaurar el sistema a fechas anteriores.\n\n"
                         "Windows pedirá permisos de administrador.\n\n¿Continuar?")
                          .arg(drive),
                      tr("Eliminar copias"), tr("Cancelar"), true))
        return;
    QString err;
    if (Platform::deleteShadowCopies(drive, &err))
        Dlg::info(this, tr("Eliminar copias de volumen"), tr("Copias de volumen eliminadas."));
    else
        Dlg::warn(this, tr("Eliminar copias de volumen"), err);
}
#endif

// --- ajustes, bloqueo y ventana ------------------------------------------------------------------

void MainWindow::openSettings() {
    if (busy_ || done_) return;
    SettingsDialog dlg(vault_, this);
    if (dlg.exec() == QDialog::Accepted && !done_) applySettings();
}

void MainWindow::applySettings() {
    const VaultSettings& s = vault_.settings();
    idle_.stop();
    if (s.autoLockEnabled) idle_.start(s.autoLockMinutes * 60 * 1000);
    Platform::setCaptureProtection(this, s.blockScreenCapture);
    qApp->setStyleSheet(Theme::styleSheet(s.uiFontPx));
}

void MainWindow::lockNow() {
    if (done_) return;
    if (busy_) {
        lockPending_ = true;
        return;
    }
    finish(Result::Locked);
}

void MainWindow::finish(Result r) {
    if (done_) return;
    done_ = true;
    result_ = r;
    idle_.stop();
    // Cerrar visores y cuadros de diálogo abiertos (los visores guardan lo pendiente y liberan sus claves).
    const auto dialogs = findChildren<QDialog*>(QString(), Qt::FindDirectChildrenOnly);
    for (QDialog* d : dialogs) {
        if (auto* v = qobject_cast<ViewerDialog*>(d))
            v->forceClose();
        else
            d->reject();
    }
    vault_.lock();
    hide();
    emit finished();
}

void MainWindow::closeEvent(QCloseEvent* e) {
    if (busy_) {
        e->ignore();
        return;
    }
    finish(Result::Quit);
    e->accept();
}

void MainWindow::changeEvent(QEvent* e) {
    QMainWindow::changeEvent(e);
    if (e->type() == QEvent::WindowStateChange && isMinimized() && vault_.settings().lockOnMinimize)
        QTimer::singleShot(0, this, &MainWindow::lockNow);
}

void MainWindow::showEvent(QShowEvent* e) {
    QMainWindow::showEvent(e);
    Platform::setCaptureProtection(this, vault_.settings().blockScreenCapture);
}

void MainWindow::dragEnterEvent(QDragEnterEvent* e) {
    if (busy_ || done_ || !e->mimeData()->hasUrls()) return;
    int n = 0;
    for (const QUrl& u : e->mimeData()->urls())
        if (u.isLocalFile()) ++n;
    if (n == 0) return;
    e->acceptProposedAction();
    QString hint;
    switch (vault_.settings().importOriginal) {
        case 1: hint = tr("Los originales se conservarán sin cifrar"); break;
        case 2: hint = tr("Los originales se destruirán de forma segura tras verificar la copia"); break;
        default: hint = tr("Te preguntaremos qué hacer con los originales"); break;
    }
    overlay_->showFor(n, hint);
}

void MainWindow::dragLeaveEvent(QDragLeaveEvent* e) {
    overlay_->hideNow();
    QMainWindow::dragLeaveEvent(e);
}

void MainWindow::dropEvent(QDropEvent* e) {
    overlay_->hideNow();
    QStringList paths;
    for (const QUrl& u : e->mimeData()->urls())
        if (u.isLocalFile()) paths << u.toLocalFile();
    if (paths.isEmpty() || busy_ || done_) return;
    e->acceptProposedAction();
    // Se importa fuera del evento de soltar para no dejar «colgado» al programa de origen (Explorador, etc.).
    QTimer::singleShot(0, this, [this, paths] { importPaths(paths); });
}

void MainWindow::resizeEvent(QResizeEvent* e) {
    QMainWindow::resizeEvent(e);
    if (overlay_ && overlay_->isVisible()) overlay_->setGeometry(centralWidget()->rect());
}

bool MainWindow::eventFilter(QObject* obj, QEvent* e) {
    switch (e->type()) {  // cualquier actividad reinicia el temporizador de inactividad
        case QEvent::MouseMove:
        case QEvent::MouseButtonPress:
        case QEvent::KeyPress:
        case QEvent::Wheel:
            if (idle_.isActive()) idle_.start();
            break;
        default: break;
    }
    return QMainWindow::eventFilter(obj, e);
}
