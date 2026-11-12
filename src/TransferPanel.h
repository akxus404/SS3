#pragma once

#include <QElapsedTimer>
#include <QFrame>

class QLabel;
class QProgressBar;
class QPushButton;

// Panel de progreso de operaciones largas: título, archivo actual, barra, tamaño, velocidad, tiempo restante y Cancelar.
class TransferPanel : public QFrame {
    Q_OBJECT
public:
    explicit TransferPanel(QWidget* parent = nullptr);

    // totalUnits = trabajo total (p. ej. bytes). scale = unidades por byte real (2 si se cifra y se verifica).
    void begin(const QString& title, qint64 totalUnits, int fileCount, int scale, bool cancellable);
    void end();
    void startFile(const QString& name, qint64 units);       // da por terminado el anterior
    bool fileProgress(qint64 done, qint64 total);            // progreso del archivo actual; false = cancelado
    bool overall(qint64 done, qint64 total);                 // progreso global directo (p. ej. elementos)
    void setIndeterminate(const QString& text);
    void setFileText(const QString& text);
    bool cancelled() const { return cancelled_; }

private:
    void refresh();

    QLabel* title_;
    QLabel* file_;
    QLabel* stats_;
    QProgressBar* bar_;
    QPushButton* cancel_;

    QString titleBase_;
    qint64 total_ = 0, base_ = 0, cur_ = 0, curUnits_ = 0, lastUnits_ = 0, lastMs_ = 0;
    int count_ = 0, index_ = 0, scale_ = 1;
    double speed_ = 0.0;
    QElapsedTimer clock_, tick_;
    bool cancelled_ = false;
};
