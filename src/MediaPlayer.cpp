#ifdef SS_HAS_MEDIA

#include "MediaPlayer.h"

#include <QAction>
#include <QActionGroup>
#include <QAudioOutput>
#include <QFileInfo>
#include <QFontMetrics>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QMediaMetaData>
#include <QMediaPlayer>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QSlider>
#include <QStyle>
#include <QToolButton>
#include <QToolTip>
#include <QUrl>
#include <QVBoxLayout>
#include <QVideoWidget>
#include <algorithm>
#include <cmath>

#include "Icons.h"
#include "Theme.h"

namespace {
QString fmtTime(qint64 ms) {
    const qint64 s = std::max<qint64>(0, ms) / 1000;
    const qint64 h = s / 3600, m = (s / 60) % 60, sec = s % 60;
    return h > 0 ? QStringLiteral("%1:%2:%3").arg(h).arg(m, 2, 10, QLatin1Char('0')).arg(sec, 2, 10, QLatin1Char('0'))
                 : QStringLiteral("%1:%2").arg(m).arg(sec, 2, 10, QLatin1Char('0'));
}

// Barra de posición: un clic salta a ese punto, arrastrar hace «scrubbing» y el cursor muestra el tiempo.
class SeekSlider : public QSlider {
public:
    explicit SeekSlider(QWidget* parent = nullptr) : QSlider(Qt::Horizontal, parent) {
        setMouseTracking(true);
        setFixedHeight(22);
        setFocusPolicy(Qt::NoFocus);
    }

protected:
    int valueAt(double x) const {
        const int margin = 7;
        return QStyle::sliderValueFromPosition(minimum(), maximum(), int(x) - margin, std::max(1, width() - 2 * margin));
    }
    void mousePressEvent(QMouseEvent* e) override {
        if (e->button() == Qt::LeftButton && maximum() > 0) {
            setValue(valueAt(e->position().x()));
            emit sliderMoved(value());
        }
        QSlider::mousePressEvent(e);
    }
    void mouseMoveEvent(QMouseEvent* e) override {
        if (maximum() > 0)
            QToolTip::showText(e->globalPosition().toPoint(), fmtTime(valueAt(e->position().x())), this);
        QSlider::mouseMoveEvent(e);
    }
};
}  // namespace

// --- AudioStage -----------------------------------------------------------------------------------

AudioStage::AudioStage(QWidget* parent) : QWidget(parent) {
    setMinimumHeight(260);
    anim_.setStartValue(0.0);
    anim_.setEndValue(1.0);
    anim_.setDuration(2600);
    anim_.setLoopCount(-1);
    connect(&anim_, &QVariantAnimation::valueChanged, this, [this] {
        if (playing_) update();
    });
    anim_.start();
}

void AudioStage::setTexts(const QString& title, const QString& subtitle) {
    title_ = title;
    subtitle_ = subtitle;
    update();
}

void AudioStage::setCover(const QImage& img) {
    cover_ = img;
    update();
}

void AudioStage::setPlaying(bool on) {
    playing_ = on;
    update();
}

void AudioStage::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setRenderHint(QPainter::SmoothPixmapTransform, true);

    QLinearGradient bg(0, 0, 0, height());
    bg.setColorAt(0.0, QColor(Theme::kBase));
    bg.setColorAt(1.0, QColor(Theme::kBg0));
    p.fillRect(rect(), bg);

    const QPointF c(width() / 2.0, height() / 2.0 - 34);
    const double ph = anim_.currentValue().toDouble();

    if (playing_) {  // anillos que laten mientras suena
        p.setBrush(Qt::NoBrush);
        for (int k = 0; k < 3; ++k) {
            const double t = std::fmod(ph + k / 3.0, 1.0);
            QColor ring(Theme::kAccent);
            ring.setAlphaF((1.0 - t) * 0.35);
            p.setPen(QPen(ring, 2.0));
            const double r = 96.0 + t * 80.0;
            p.drawEllipse(c, r, r);
        }
    }

    const double size = 168.0;
    const QRectF box(c.x() - size / 2, c.y() - size / 2, size, size);
    if (!cover_.isNull()) {
        QPainterPath clip;
        clip.addRoundedRect(box, 22, 22);
        p.save();
        p.setClipPath(clip);
        const QImage scaled = cover_.scaled(box.size().toSize(), Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
        p.drawImage(box.topLeft() - QPointF((scaled.width() - size) / 2, (scaled.height() - size) / 2), scaled);
        p.restore();
    } else {
        Theme::paintLogo(p, box);
    }

    QFont tf = font();
    tf.setPixelSize(22);
    tf.setBold(true);
    p.setFont(tf);
    p.setPen(QColor(Theme::kText));
    const QFontMetrics tm(tf);
    p.drawText(QRectF(20, c.y() + size / 2 + 22, width() - 40, 32), Qt::AlignHCenter | Qt::AlignVCenter,
               tm.elidedText(title_, Qt::ElideRight, width() - 60));
    if (!subtitle_.isEmpty()) {
        QFont sf = font();
        sf.setPixelSize(14);
        p.setFont(sf);
        p.setPen(QColor(Theme::kDim));
        p.drawText(QRectF(20, c.y() + size / 2 + 56, width() - 40, 24), Qt::AlignHCenter | Qt::AlignVCenter,
                   QFontMetrics(sf).elidedText(subtitle_, Qt::ElideRight, width() - 60));
    }
}

// --- MediaPlayerWidget -----------------------------------------------------------------------------

QToolButton* MediaPlayerWidget::makeTool(const QString& tip, const char* objectName, int fixed) {
    auto* b = new QToolButton;
    b->setObjectName(QString::fromLatin1(objectName));
    b->setToolTip(tip);
    b->setFixedSize(fixed, fixed);
    b->setAutoRaise(true);
    b->setFocusPolicy(Qt::NoFocus);  // el teclado se queda en el reproductor (Espacio no «pulsa» botones)
    return b;
}

MediaPlayerWidget::MediaPlayerWidget(std::unique_ptr<VaultFileDevice> device, const QString& name, bool video,
                                     QWidget* parent)
    : QWidget(parent), device_(std::move(device)), name_(name), video_(video) {
    setFocusPolicy(Qt::StrongFocus);
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(0, 0, 0, 0);
    lay->setSpacing(10);

    player_ = new QMediaPlayer(this);
    audio_ = new QAudioOutput(this);
    audio_->setVolume(0.8f);
    player_->setAudioOutput(audio_);

    // Cabecera (solo vídeo): título e información técnica
    header_ = new QWidget;
    auto* hl = new QHBoxLayout(header_);
    hl->setContentsMargins(4, 0, 4, 0);
    titleLabel_ = new QLabel(QFileInfo(name_).completeBaseName());
    titleLabel_->setObjectName(QStringLiteral("panelTitle"));
    infoLabel_ = new QLabel;
    infoLabel_->setObjectName(QStringLiteral("hint"));
    hl->addWidget(titleLabel_, 1);
    hl->addWidget(infoLabel_);

    if (video_) {
        lay->addWidget(header_);
        videoWidget_ = new QVideoWidget;
        videoWidget_->setStyleSheet(QStringLiteral("background-color: black;"));
        videoWidget_->setMinimumHeight(260);
        videoWidget_->setMouseTracking(true);
        videoWidget_->installEventFilter(this);
        player_->setVideoOutput(videoWidget_);
        lay->addWidget(videoWidget_, 1);
    } else {
        header_->hide();
        stage_ = new AudioStage;
        stage_->setTexts(QFileInfo(name_).completeBaseName(), QString());
        lay->addWidget(stage_, 1);
    }

    errorLabel_ = new QLabel;
    errorLabel_->setObjectName(QStringLiteral("error"));
    errorLabel_->setWordWrap(true);
    errorLabel_->hide();
    lay->addWidget(errorLabel_);

    // Barra de control
    bar_ = new QFrame;
    bar_->setObjectName(QStringLiteral("playerBar"));
    auto* bl = new QVBoxLayout(bar_);
    bl->setContentsMargins(18, 10, 18, 12);
    bl->setSpacing(6);

    auto* r1 = new QHBoxLayout;
    r1->setSpacing(10);
    curLabel_ = new QLabel(QStringLiteral("0:00"));
    durLabel_ = new QLabel(QStringLiteral("0:00"));
    curLabel_->setObjectName(QStringLiteral("hint"));
    durLabel_->setObjectName(QStringLiteral("hint"));
    curLabel_->setMinimumWidth(46);
    curLabel_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    durLabel_->setMinimumWidth(46);
    seek_ = new SeekSlider;
    seek_->setRange(0, 0);
    r1->addWidget(curLabel_);
    r1->addWidget(seek_, 1);
    r1->addWidget(durLabel_);
    bl->addLayout(r1);

    back_ = makeTool(tr("Retroceder 10 s (J)"), "mediaBtn", 38);
    back_->setIcon(Icons::make(Icons::Id::Back10, 24));
    back_->setIconSize(QSize(24, 24));
    play_ = makeTool(tr("Reproducir / pausa (Espacio)"), "mediaPlay", 50);
    play_->setIcon(Icons::make(Icons::Id::Pause, 26, 0xffffff));
    play_->setIconSize(QSize(26, 26));
    fwd_ = makeTool(tr("Avanzar 10 s (L)"), "mediaBtn", 38);
    fwd_->setIcon(Icons::make(Icons::Id::Fwd10, 24));
    fwd_->setIconSize(QSize(24, 24));

    mute_ = makeTool(tr("Silenciar (M)"), "mediaBtn", 36);
    mute_->setIconSize(QSize(22, 22));
    vol_ = new QSlider(Qt::Horizontal);
    vol_->setRange(0, 100);
    vol_->setValue(80);
    vol_->setFixedWidth(96);
    vol_->setFocusPolicy(Qt::NoFocus);

    speed_ = new QToolButton;
    speed_->setObjectName(QStringLiteral("mediaSpeed"));
    speed_->setText(QStringLiteral("1×"));
    speed_->setToolTip(tr("Velocidad de reproducción"));
    speed_->setPopupMode(QToolButton::InstantPopup);
    speed_->setFocusPolicy(Qt::NoFocus);
    auto* menu = new QMenu(speed_);
    auto* group = new QActionGroup(menu);
    for (double rate : {0.5, 0.75, 1.0, 1.25, 1.5, 2.0}) {
        const QString label = QStringLiteral("%1×").arg(rate);
        QAction* a = menu->addAction(label);
        a->setCheckable(true);
        a->setChecked(rate == 1.0);
        group->addAction(a);
        connect(a, &QAction::triggered, this, [this, rate, label] {
            player_->setPlaybackRate(rate);
            speed_->setText(label);
        });
    }
    speed_->setMenu(menu);

    full_ = makeTool(tr("Pantalla completa (F)"), "mediaBtn", 36);
    full_->setIcon(Icons::make(Icons::Id::Fullscreen, 22));
    full_->setIconSize(QSize(22, 22));

    auto* grid = new QGridLayout;
    grid->setColumnStretch(0, 1);
    grid->setColumnStretch(1, 0);
    grid->setColumnStretch(2, 1);
    auto* left = new QHBoxLayout;
    left->setSpacing(6);
    left->addWidget(mute_);
    left->addWidget(vol_);
    left->addStretch();
    auto* center = new QHBoxLayout;
    center->setSpacing(14);
    center->addWidget(back_);
    center->addWidget(play_);
    center->addWidget(fwd_);
    auto* right = new QHBoxLayout;
    right->setSpacing(8);
    right->addStretch();
    right->addWidget(speed_);
    if (video_) right->addWidget(full_);
    else {
        full_->setParent(bar_);
        full_->hide();
    }
    grid->addLayout(left, 0, 0);
    grid->addLayout(center, 0, 1);
    grid->addLayout(right, 0, 2);
    bl->addLayout(grid);
    lay->addWidget(bar_);

    // Conexiones
    connect(play_, &QToolButton::clicked, this, &MediaPlayerWidget::togglePlay);
    connect(back_, &QToolButton::clicked, this, [this] { seekBy(-10000); });
    connect(fwd_, &QToolButton::clicked, this, [this] { seekBy(10000); });
    connect(mute_, &QToolButton::clicked, this, [this] { audio_->setMuted(!audio_->isMuted()); });
    connect(full_, &QToolButton::clicked, this, &MediaPlayerWidget::toggleFullscreen);
    connect(vol_, &QSlider::valueChanged, this, [this](int v) {
        audio_->setVolume(float(v) / 100.0f);
        if (v > 0 && audio_->isMuted()) audio_->setMuted(false);
        updateVolumeIcon();
    });
    connect(audio_, &QAudioOutput::mutedChanged, this, [this](bool) { updateVolumeIcon(); });
    connect(seek_, &QSlider::sliderMoved, this, [this](int v) { player_->setPosition(v); });
    connect(seek_, &QSlider::sliderReleased, this, [this] { player_->setPosition(seek_->value()); });
    connect(player_, &QMediaPlayer::durationChanged, this, [this](qint64 d) {
        seek_->setRange(0, int(d));
        updateTimes();
    });
    connect(player_, &QMediaPlayer::positionChanged, this, [this](qint64 pos) {
        if (!seek_->isSliderDown()) seek_->setValue(int(pos));
        updateTimes();
    });
    connect(player_, &QMediaPlayer::playbackStateChanged, this, [this](QMediaPlayer::PlaybackState s) {
        const bool playing = s == QMediaPlayer::PlayingState;
        play_->setIcon(Icons::make(playing ? Icons::Id::Pause : Icons::Id::Play, 26, 0xffffff));
        if (stage_) stage_->setPlaying(playing);
        showControls();
    });
    connect(player_, &QMediaPlayer::metaDataChanged, this, &MediaPlayerWidget::updateMeta);
    connect(player_, &QMediaPlayer::mediaStatusChanged, this, [this](QMediaPlayer::MediaStatus s) {
        if (s == QMediaPlayer::LoadedMedia) updateMeta();
    });
    connect(player_, &QMediaPlayer::errorOccurred, this, [this](QMediaPlayer::Error, const QString& msg) {
        errorLabel_->setText(tr("No se pudo reproducir: %1\n(Depende de los códecs del sistema; puedes exportar el archivo.)").arg(msg));
        errorLabel_->show();
    });

    hideTimer_.setSingleShot(true);
    hideTimer_.setInterval(2500);
    connect(&hideTimer_, &QTimer::timeout, this, [this] {
        if (video_ && window()->isFullScreen() && isPlaying()) {  // modo cine: se oculta todo
            bar_->hide();
            header_->hide();
            videoWidget_->setCursor(Qt::BlankCursor);
        }
    });

    updateVolumeIcon();
    player_->setSourceDevice(device_.get(), QUrl::fromLocalFile(QStringLiteral("/") + name_));
    player_->play();
}

MediaPlayerWidget::~MediaPlayerWidget() { release(); }

void MediaPlayerWidget::release() {
    if (released_) return;
    released_ = true;
    if (player_) {
        player_->stop();
        player_->setSourceDevice(nullptr);
    }
    device_.reset();  // cierra el archivo y borra la clave de la memoria
}

bool MediaPlayerWidget::isPlaying() const {
    return player_ && player_->playbackState() == QMediaPlayer::PlayingState;
}

void MediaPlayerWidget::togglePlay() {
    if (isPlaying()) player_->pause();
    else player_->play();
}

void MediaPlayerWidget::toggleFullscreen() {
    if (!video_) return;
    QWidget* w = window();
    if (w->isFullScreen()) w->showNormal();
    else w->showFullScreen();
    full_->setIcon(Icons::make(w->isFullScreen() ? Icons::Id::ExitFullscreen : Icons::Id::Fullscreen, 22));
    showControls();
    setFocus();
}

void MediaPlayerWidget::seekBy(qint64 deltaMs) {
    const qint64 dur = std::max<qint64>(0, player_->duration());
    player_->setPosition(std::clamp<qint64>(player_->position() + deltaMs, 0, dur));
}

void MediaPlayerWidget::changeVolume(int delta) { vol_->setValue(std::clamp(vol_->value() + delta, 0, 100)); }

void MediaPlayerWidget::updateVolumeIcon() {
    Icons::Id id = Icons::Id::VolumeHigh;
    if (audio_->isMuted() || vol_->value() == 0) id = Icons::Id::VolumeMute;
    else if (vol_->value() < 45) id = Icons::Id::VolumeLow;
    mute_->setIcon(Icons::make(id, 22));
}

void MediaPlayerWidget::updateTimes() {
    curLabel_->setText(fmtTime(player_->position()));
    durLabel_->setText(fmtTime(player_->duration()));
}

void MediaPlayerWidget::updateMeta() {
    const QMediaMetaData md = player_->metaData();
    QString title = md.stringValue(QMediaMetaData::Title);
    if (title.isEmpty()) title = QFileInfo(name_).completeBaseName();
    if (video_) {
        titleLabel_->setText(title);
        QString info;
        const QSize res = md.value(QMediaMetaData::Resolution).toSize();
        if (res.isValid()) info = QStringLiteral("%1 × %2").arg(res.width()).arg(res.height());
        const double fps = md.value(QMediaMetaData::VideoFrameRate).toDouble();
        if (fps > 0.0)
            info += (info.isEmpty() ? QString() : QStringLiteral("  ·  ")) +
                    QStringLiteral("%1 fps").arg(fps, 0, 'f', std::abs(fps - std::round(fps)) < 0.01 ? 0 : 2);
        infoLabel_->setText(info);
    } else {
        QString sub = md.stringValue(QMediaMetaData::ContributingArtist);
        const QString album = md.stringValue(QMediaMetaData::AlbumTitle);
        if (!album.isEmpty()) sub += (sub.isEmpty() ? QString() : QStringLiteral("  —  ")) + album;
        stage_->setTexts(title, sub);
        QImage cover = md.value(QMediaMetaData::ThumbnailImage).value<QImage>();
        if (cover.isNull()) cover = md.value(QMediaMetaData::CoverArtImage).value<QImage>();
        if (!cover.isNull()) stage_->setCover(cover);
    }
}

void MediaPlayerWidget::showControls() {
    bar_->show();
    if (video_) {
        header_->show();
        videoWidget_->unsetCursor();
        if (window()->isFullScreen()) hideTimer_.start();
    }
}

void MediaPlayerWidget::keyPressEvent(QKeyEvent* e) {
    switch (e->key()) {
        case Qt::Key_Space:
        case Qt::Key_K: togglePlay(); break;
        case Qt::Key_Left: seekBy(-5000); break;
        case Qt::Key_Right: seekBy(5000); break;
        case Qt::Key_J: seekBy(-10000); break;
        case Qt::Key_L: seekBy(10000); break;
        case Qt::Key_Up: changeVolume(5); break;
        case Qt::Key_Down: changeVolume(-5); break;
        case Qt::Key_M: audio_->setMuted(!audio_->isMuted()); break;
        case Qt::Key_F: toggleFullscreen(); break;
        case Qt::Key_Escape:
            if (video_ && window()->isFullScreen()) {
                toggleFullscreen();
                break;
            }
            QWidget::keyPressEvent(e);  // el diálogo se cierra
            return;
        default: QWidget::keyPressEvent(e); return;
    }
    showControls();
    e->accept();
}

bool MediaPlayerWidget::eventFilter(QObject* obj, QEvent* e) {
    if (obj == videoWidget_) {
        switch (e->type()) {
            case QEvent::MouseButtonRelease:
                if (static_cast<QMouseEvent*>(e)->button() == Qt::LeftButton) togglePlay();
                break;
            case QEvent::MouseButtonDblClick: toggleFullscreen(); break;
            case QEvent::MouseMove: showControls(); break;
            default: break;
        }
    }
    return QWidget::eventFilter(obj, e);
}

#endif  // SS_HAS_MEDIA
