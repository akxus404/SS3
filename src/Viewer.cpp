#include "Viewer.h"

#include <QBuffer>
#include <QCloseEvent>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QImage>
#include <QImageReader>
#include <QLabel>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSet>
#include <QShortcut>
#include <QSlider>
#include <QStringDecoder>
#include <QUrl>
#include <QVBoxLayout>
#include <algorithm>

#ifdef SS_HAS_MEDIA
#include "MediaPlayer.h"
#endif

#include "Platform.h"
#include "Theme.h"
#include "UiUtil.h"

namespace {
constexpr qint64 kMaxText = 8LL << 20;     // 8 MiB
constexpr qint64 kMaxImage = 256LL << 20;  // 256 MiB

void wipe(QByteArray& b) {
    if (!b.isEmpty()) sodium_memzero(b.data(), std::size_t(b.size()));
}

}  // namespace

ViewerDialog::Kind ViewerDialog::kindFor(const QString& name) {
    static const QSet<QString> text = {QStringLiteral("txt"),  QStringLiteral("md"),   QStringLiteral("log"),
                                       QStringLiteral("json"), QStringLiteral("csv"),  QStringLiteral("xml"),
                                       QStringLiteral("ini"),  QStringLiteral("cfg"),  QStringLiteral("yaml"),
                                       QStringLiteral("yml"),  QStringLiteral("html"), QStringLiteral("css"),
                                       QStringLiteral("js"),   QStringLiteral("py"),   QStringLiteral("cpp"),
                                       QStringLiteral("h"),    QStringLiteral("c"),    QStringLiteral("java"),
                                       QStringLiteral("tex"),  QStringLiteral("sql"),  QStringLiteral("sh"),
                                       QStringLiteral("bat"),  QStringLiteral("toml")};
    static const QSet<QString> image = {QStringLiteral("png"),  QStringLiteral("jpg"), QStringLiteral("jpeg"),
                                        QStringLiteral("gif"),  QStringLiteral("bmp"), QStringLiteral("webp"),
                                        QStringLiteral("ico"),  QStringLiteral("tif"), QStringLiteral("tiff")};
    static const QSet<QString> audio = {QStringLiteral("mp3"), QStringLiteral("wav"),  QStringLiteral("flac"),
                                        QStringLiteral("ogg"), QStringLiteral("m4a"),  QStringLiteral("aac"),
                                        QStringLiteral("opus"), QStringLiteral("wma")};
    static const QSet<QString> video = {QStringLiteral("mp4"),  QStringLiteral("mov"),  QStringLiteral("mkv"),
                                        QStringLiteral("avi"),  QStringLiteral("webm"), QStringLiteral("m4v"),
                                        QStringLiteral("wmv"),  QStringLiteral("3gp"),  QStringLiteral("mpg"),
                                        QStringLiteral("mpeg")};
    const QString ext = QFileInfo(name).suffix().toLower();
    if (text.contains(ext)) return Kind::Text;
    if (image.contains(ext)) return Kind::Image;
    if (audio.contains(ext)) return Kind::Audio;
    if (video.contains(ext)) return Kind::Video;
    return Kind::None;
}

ViewerDialog::ViewerDialog(Vault& vault, const VaultEntry& entry, QWidget* parent)
    : QDialog(parent), vault_(vault), entry_(entry), kind_(kindFor(entry.name)) {
    setWindowTitle(entry.name);
    setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    setWindowFlag(Qt::WindowMaximizeButtonHint, true);
    resize(980, 700);

    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(14, 14, 14, 14);
    lay->setSpacing(10);
    switch (kind_) {
        case Kind::Text: buildText(lay); break;
        case Kind::Image: buildImage(lay); break;
        case Kind::Audio: buildMedia(lay, false); break;
        case Kind::Video: buildMedia(lay, true); break;
        case Kind::None: showError(lay, tr("No hay vista previa para este tipo de archivo.")); break;
    }
}

ViewerDialog::~ViewerDialog() { releaseMedia(); }

void ViewerDialog::showError(QVBoxLayout* lay, const QString& msg) {
    auto* l = new QLabel(msg);
    l->setObjectName(QStringLiteral("error"));
    l->setWordWrap(true);
    l->setAlignment(Qt::AlignCenter);
    lay->addWidget(l, 1);
}

// --- texto -----------------------------------------------------------------------------------------

void ViewerDialog::buildText(QVBoxLayout* lay) {
    QByteArray data;
    QString err;
    if (!vault_.readAll(entry_.id, kMaxText, &data, &err)) {
        showError(lay, err);
        return;
    }
    crlf_ = data.contains("\r\n");
    QStringDecoder dec(QStringDecoder::Utf8);
    QString text = dec(data);
    const bool unknownEncoding = dec.hasError();
    if (unknownEncoding) text = QString::fromLatin1(data);
    wipe(data);
    if (crlf_) text.replace(QStringLiteral("\r\n"), QStringLiteral("\n"));

    edit_ = new QPlainTextEdit;
    edit_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    edit_->setPlainText(text);
    edit_->setReadOnly(unknownEncoding);
    lay->addWidget(edit_, 1);

    auto* row = new QHBoxLayout;
    auto* hint = new QLabel(unknownEncoding ? tr("Solo lectura: codificación no reconocida.")
                                            : tr("Los cambios se guardan cifrados dentro de la bóveda (Ctrl+S)."));
    hint->setObjectName(QStringLiteral("hint"));
    saveBtn_ = new QPushButton(tr("Guardar"));
    saveBtn_->setObjectName(QStringLiteral("primary"));
    saveBtn_->setEnabled(false);
    saveBtn_->setVisible(!unknownEncoding);
    row->addWidget(hint);
    row->addStretch();
    row->addWidget(saveBtn_);
    lay->addLayout(row);

    connect(edit_, &QPlainTextEdit::textChanged, this, [this] {
        dirty_ = true;
        saveBtn_->setEnabled(true);
        updateTitle();
    });
    connect(saveBtn_, &QPushButton::clicked, this, [this] { saveText(true); });
    connect(new QShortcut(QKeySequence(QStringLiteral("Ctrl+S")), this), &QShortcut::activated, this,
            [this] { saveText(true); });
}

bool ViewerDialog::saveText(bool interactive) {
    if (!edit_ || edit_->isReadOnly() || !dirty_) return true;
    QString t = edit_->toPlainText();
    if (crlf_) t.replace(QLatin1Char('\n'), QStringLiteral("\r\n"));
    QByteArray bytes = t.toUtf8();
    QString err;
    const bool ok = vault_.replaceContent(entry_.id, bytes, &err);
    wipe(bytes);
    if (!ok) {
        if (interactive) Dlg::warn(this, tr("Guardar"), err);
        return false;
    }
    dirty_ = false;
    saveBtn_->setEnabled(false);
    updateTitle();
    return true;
}

void ViewerDialog::updateTitle() { setWindowTitle(dirty_ ? entry_.name + QStringLiteral(" *") : entry_.name); }

// --- imagen ------------------------------------------------------------------------------------------

void ViewerDialog::buildImage(QVBoxLayout* lay) {
    QByteArray data;
    QString err;
    if (!vault_.readAll(entry_.id, kMaxImage, &data, &err)) {
        showError(lay, err);
        return;
    }
    {
        QBuffer buf(&data);
        buf.open(QIODevice::ReadOnly);
        QImageReader reader(&buf);
        reader.setAutoTransform(true);
        image_ = reader.read();
        if (image_.isNull()) err = reader.errorString();
    }
    wipe(data);
    if (image_.isNull()) {
        showError(lay, tr("No se pudo abrir la imagen: %1").arg(err));
        return;
    }

    auto* bar = new QHBoxLayout;
    auto* fit = new QPushButton(tr("Ajustar"));
    auto* one = new QPushButton(tr("100 %"));
    auto* zin = new QPushButton(QStringLiteral("+"));
    auto* zout = new QPushButton(QStringLiteral("−"));
    auto* info = new QLabel(tr("%1 × %2 px").arg(image_.width()).arg(image_.height()));
    info->setObjectName(QStringLiteral("hint"));
    for (QPushButton* b : {fit, one, zin, zout}) bar->addWidget(b);
    bar->addStretch();
    bar->addWidget(info);
    lay->addLayout(bar);

    scroll_ = new QScrollArea;
    scroll_->setAlignment(Qt::AlignCenter);
    imgLabel_ = new QLabel;
    imgLabel_->setAlignment(Qt::AlignCenter);
    scroll_->setWidget(imgLabel_);
    lay->addWidget(scroll_, 1);

    connect(fit, &QPushButton::clicked, this, [this] { fit_ = true; updateImage(); });
    connect(one, &QPushButton::clicked, this, [this] { fit_ = false; zoom_ = 1.0; updateImage(); });
    connect(zin, &QPushButton::clicked, this, [this] { fit_ = false; zoom_ = std::min(8.0, zoom_ * 1.25); updateImage(); });
    connect(zout, &QPushButton::clicked, this, [this] { fit_ = false; zoom_ = std::max(0.05, zoom_ / 1.25); updateImage(); });
}

void ViewerDialog::updateImage() {
    if (image_.isNull() || !scroll_) return;
    QSize target;
    if (fit_) {
        const QSize avail = scroll_->viewport()->size() - QSize(4, 4);
        target = image_.size().scaled(avail, Qt::KeepAspectRatio);
        if (target.width() > image_.width() || target.height() > image_.height()) target = image_.size();
    } else {
        target = QSize(std::max(1, int(image_.width() * zoom_)), std::max(1, int(image_.height() * zoom_)));
    }
    imgLabel_->setPixmap(QPixmap::fromImage(image_.scaled(target, Qt::KeepAspectRatio, Qt::SmoothTransformation)));
    imgLabel_->adjustSize();
}

// --- audio / vídeo -----------------------------------------------------------------------------------

void ViewerDialog::buildMedia(QVBoxLayout* lay, bool video) {
#ifdef SS_HAS_MEDIA
    QString err;
    std::unique_ptr<VaultFileDevice> dev = vault_.openRead(entry_.id, &err);
    if (!dev || !dev->open(QIODevice::ReadOnly)) {
        showError(lay, dev && !dev->errorString().isEmpty() ? dev->errorString()
                                                            : (err.isEmpty() ? tr("No se pudo abrir el archivo.") : err));
        return;
    }
    media_ = new MediaPlayerWidget(std::move(dev), entry_.name, video);
    lay->addWidget(media_, 1);
    lay->setContentsMargins(video ? 10 : 14, 10, video ? 10 : 14, 12);
    resize(video ? 1120 : 760, video ? 760 : 620);
#else
    Q_UNUSED(video);
    showError(lay, tr("Esta compilación no incluye reproducción multimedia (Qt Multimedia)."));
#endif
}

bool ViewerDialog::isPlaying() const {
#ifdef SS_HAS_MEDIA
    return media_ && media_->isPlaying();
#else
    return false;
#endif
}

void ViewerDialog::releaseMedia() {
#ifdef SS_HAS_MEDIA
    if (media_) media_->release();  // detiene, cierra el archivo y borra su clave de la memoria
#endif
}

// --- ventana -----------------------------------------------------------------------------------------

void ViewerDialog::forceClose() {
    saveText(false);  // no perder el trabajo al bloquear por inactividad
    releaseMedia();
    if (edit_) edit_->clear();
    done(QDialog::Rejected);
}

void ViewerDialog::closeEvent(QCloseEvent* e) {
    if (dirty_) {
        QMessageBox box(QMessageBox::Question, tr("Guardar cambios"),
                        tr("«%1» tiene cambios sin guardar.").arg(entry_.name), QMessageBox::NoButton, this);
        QPushButton* save = box.addButton(tr("Guardar"), QMessageBox::AcceptRole);
        QPushButton* discard = box.addButton(tr("Descartar"), QMessageBox::DestructiveRole);
        QPushButton* cancel = box.addButton(tr("Cancelar"), QMessageBox::RejectRole);
        box.setDefaultButton(save);
        box.setEscapeButton(cancel);
        box.exec();
        if (box.clickedButton() == cancel || (box.clickedButton() == save && !saveText(true))) {
            e->ignore();
            return;
        }
        Q_UNUSED(discard);
    }
    releaseMedia();
    if (edit_) edit_->clear();
    e->accept();
}

void ViewerDialog::resizeEvent(QResizeEvent* e) {
    QDialog::resizeEvent(e);
    if (kind_ == Kind::Image && fit_) updateImage();
}

void ViewerDialog::showEvent(QShowEvent* e) {
    QDialog::showEvent(e);
    Platform::setCaptureProtection(this, vault_.settings().blockScreenCapture);
    if (kind_ == Kind::Image) updateImage();
#ifdef SS_HAS_MEDIA
    if (media_) media_->setFocus();
#endif
}
