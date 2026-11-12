#pragma once

#include <QVariantAnimation>
#include <QWidget>

// Capa animada que aparece sobre la ventana cuando se arrastran archivos hacia Secure Space.
class DropOverlay : public QWidget {
    Q_OBJECT
public:
    explicit DropOverlay(QWidget* parent);
    void showFor(int count, const QString& hint);
    void hideNow();

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QVariantAnimation phase_;  // 0..1 en bucle: marco discontinuo, anillos, pulso
    QVariantAnimation fade_;   // 0..1: aparición / desaparición suave
    int count_ = 0;
    QString hint_;
};
