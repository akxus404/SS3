#pragma once

#include <QMainWindow>
#include <QStringList>
#include <QTimer>

#include "Vault.h"

class DropOverlay;
class QLabel;
class QPushButton;
class TransferPanel;
class QTreeWidget;
class QTreeWidgetItem;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    enum class Result { Quit, Locked, Destroyed };

    explicit MainWindow(Vault& vault, QWidget* parent = nullptr);
    ~MainWindow() override;
    Result result() const { return result_; }

signals:
    void finished();  // la sesión terminó (cerrar, bloquear o destruir)

protected:
    void closeEvent(QCloseEvent* e) override;
    void changeEvent(QEvent* e) override;
    void showEvent(QShowEvent* e) override;
    void dragEnterEvent(QDragEnterEvent* e) override;
    void dragLeaveEvent(QDragLeaveEvent* e) override;
    void resizeEvent(QResizeEvent* e) override;
    void dropEvent(QDropEvent* e) override;
    bool eventFilter(QObject* obj, QEvent* e) override;

private:
    void refresh();
    void updateButtons();
    QStringList selectedIds() const;
    void openItem(QTreeWidgetItem* item);
    void openSelected();
    void goUp();
    int askImportAction();  // 1 = dejar copia, 2 = destruir original, -1 = cancelar
    void importFiles();
    void importFolder();
    void importPaths(const QStringList& paths);
    void importOne(const QString& path, const QString& parentId, bool shredOriginal, int& ok, int& bad,
                   QStringList& queue, QStringList& dirs, QString& err);
    void shredInBackground(const QStringList& paths, bool trees, ShredSummary& sum);
    void reportShred(const ShredSummary& sum);
    void confirmAndShred(const QStringList& paths);
    void shredExternalFiles();
    void shredExternalFolder();
    void wipeFreeSpaceTool();
    void clearTracesTool();
#ifdef Q_OS_WIN
    void deleteShadowCopiesTool();
#endif
    void newFolder();
    void newTextFile();
    void exportSelected();
    void renameSelected();
    void deleteSelected();
    void destroyAll();
    void openSettings();
    void applySettings();
    void lockNow();
    void finish(Result r);
    void beginBusy(const QString& title, qint64 units = 0, int files = 0, int scale = 1, bool cancellable = false);
    void endBusy();
    Vault::Progress progressFn();  // progreso por archivo (importar / exportar)
    Vault::Progress overallFn();   // progreso global (eliminar / destruir)

    Vault& vault_;
    QTreeWidget* tree_;
    QLabel* pathLabel_;
    QLabel* statusLabel_;
    QWidget* content_;
    TransferPanel* panel_;
    DropOverlay* overlay_;
    QPushButton* upBtn_;
    QPushButton* openBtn_;
    QPushButton* exportBtn_;
    QPushButton* renameBtn_;
    QPushButton* deleteBtn_;
    QTimer idle_;
    QString current_;  // carpeta actual (id); vacío = raíz
    Result result_ = Result::Quit;
    bool done_ = false;
    bool busy_ = false;
    bool lockPending_ = false;
    bool exportWarned_ = false;
};
