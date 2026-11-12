#pragma once

#ifdef SS_HAS_MEDIA

#include <QImage>
#include <QTimer>
#include <QVariantAnimation>
#include <QWidget>
#include <memory>
#include <QPainterPath>

#include "Vault.h"

class QAudioOutput;
class QFrame;
class QLabel;
class QMediaPlayer;
class QSlider;
class QToolButton;
class QVideoWidget;

// Escenario de audio: portada (o logo) con anillos que laten mientras suena, título y artista.
class AudioStage : public QWidget {
    Q_OBJECT
public:
    explicit AudioStage(QWidget* parent = nullptr);
    void setTexts(const QString& title, const QString& subtitle);
    void setCover(const QImage& img);
    void setPlaying(bool on);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QString title_, subtitle_;
    QImage cover_;
    QVariantAnimation anim_;
    bool playing_ = false;
};

// Reproductor profesional de audio/vídeo que lee el archivo cifrado directamente desde RAM.
// Atajos: Espacio/K pausa · ←/→ ±5 s · J/L ±10 s · ↑/↓ volumen · M silencio · F pantalla completa · Esc salir.
class MediaPlayerWidget : public QWidget {
    Q_OBJECT
public:
    MediaPlayerWidget(std::unique_ptr<VaultFileDevice> device, const QString& name, bool video,
                      QWidget* parent = nullptr);
    ~MediaPlayerWidget() override;

    bool isPlaying() const;
    void release();  // detiene, suelta el archivo y borra su clave de la memoria

protected:
    void keyPressEvent(QKeyEvent* e) override;
    bool eventFilter(QObject* obj, QEvent* e) override;

private:
    void togglePlay();
    void toggleFullscreen();
    void seekBy(qint64 deltaMs);
    void changeVolume(int delta);
    void updateVolumeIcon();
    void updateMeta();
    void updateTimes();
    void showControls();
    QToolButton* makeTool(const QString& tip, const char* objectName, int fixed);

    std::unique_ptr<VaultFileDevice> device_;
    QString name_;
    bool video_;

    QMediaPlayer* player_ = nullptr;
    QAudioOutput* audio_ = nullptr;
    QVideoWidget* videoWidget_ = nullptr;
    AudioStage* stage_ = nullptr;

    QWidget* header_ = nullptr;
    QLabel* titleLabel_ = nullptr;
    QLabel* infoLabel_ = nullptr;
    QLabel* errorLabel_ = nullptr;
    QFrame* bar_ = nullptr;
    QSlider* seek_ = nullptr;
    QSlider* vol_ = nullptr;
    QLabel* curLabel_ = nullptr;
    QLabel* durLabel_ = nullptr;
    QToolButton* back_ = nullptr;
    QToolButton* play_ = nullptr;
    QToolButton* fwd_ = nullptr;
    QToolButton* mute_ = nullptr;
    QToolButton* speed_ = nullptr;
    QToolButton* full_ = nullptr;
    QTimer hideTimer_;
    bool released_ = false;
};

#endif  // SS_HAS_MEDIA
