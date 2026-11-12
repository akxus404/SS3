#pragma once

#include <QDialog>
#include <QImage>
#include <memory>

#include "Vault.h"

class QLabel;
class QPlainTextEdit;
class QPushButton;
class QScrollArea;
class QSlider;
class QVBoxLayout;
#ifdef SS_HAS_MEDIA
class MediaPlayerWidget;
#endif

// Visor/editor interno: texto (editable), imágenes, audio y vídeo. Todo se descifra en RAM,
// nunca se escribe una copia temporal en disco.
class ViewerDialog : public QDialog {
    Q_OBJECT
public:
    enum class Kind { None, Text, Image, Audio, Video };
    static Kind kindFor(const QString& fileName);

    ViewerDialog(Vault& vault, const VaultEntry& entry, QWidget* parent);
    ~ViewerDialog() override;

    bool isPlaying() const;
    void forceClose();  // bloqueo de sesión: guarda los cambios pendientes y cierra sin preguntar

protected:
    void closeEvent(QCloseEvent* e) override;
    void resizeEvent(QResizeEvent* e) override;
    void showEvent(QShowEvent* e) override;

private:
    void showError(QVBoxLayout* lay, const QString& msg);
    void buildText(QVBoxLayout* lay);
    void buildImage(QVBoxLayout* lay);
    void buildMedia(QVBoxLayout* lay, bool video);
    bool saveText(bool interactive);
    void updateTitle();
    void updateImage();
    void releaseMedia();

    Vault& vault_;
    VaultEntry entry_;
    Kind kind_;

    // texto
    QPlainTextEdit* edit_ = nullptr;
    QPushButton* saveBtn_ = nullptr;
    bool dirty_ = false;
    bool crlf_ = false;

    // imagen
    QScrollArea* scroll_ = nullptr;
    QLabel* imgLabel_ = nullptr;
    QImage image_;
    bool fit_ = true;
    double zoom_ = 1.0;

#ifdef SS_HAS_MEDIA
    MediaPlayerWidget* media_ = nullptr;
#endif
};
