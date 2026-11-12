#include "DropOverlay.h"

#include <QEasingCurve>
#include <QFont>
#include <QPainter>
#include <QPen>
#include <algorithm>
#include <cmath>

#include "Theme.h"

namespace {
constexpr double kPi = 3.14159265358979323846;
}

DropOverlay::DropOverlay(QWidget* parent) : QWidget(parent) {
    setAttribute(Qt::WA_TransparentForMouseEvents);
    hide();

    phase_.setStartValue(0.0);
    phase_.setEndValue(1.0);
    phase_.setDuration(2200);
    phase_.setLoopCount(-1);
    connect(&phase_, &QVariantAnimation::valueChanged, this, [this] { update(); });

    fade_.setDuration(180);
    fade_.setEasingCurve(QEasingCurve::OutCubic);
    connect(&fade_, &QVariantAnimation::valueChanged, this, [this] { update(); });
    connect(&fade_, &QVariantAnimation::finished, this, [this] {
        if (fade_.endValue().toDouble() <= 0.0) {
            hide();
            phase_.stop();
        }
    });
}

void DropOverlay::showFor(int count, const QString& hint) {
    count_ = count;
    hint_ = hint;
    if (parentWidget()) setGeometry(parentWidget()->rect());
    raise();
    show();
    const double cur = fade_.currentValue().toDouble();
    fade_.stop();
    fade_.setStartValue(cur);
    fade_.setEndValue(1.0);
    fade_.start();
    if (phase_.state() != QAbstractAnimation::Running) phase_.start();
}

void DropOverlay::hideNow() {
    if (!isVisible()) return;
    const double cur = fade_.currentValue().toDouble();
    fade_.stop();
    fade_.setStartValue(cur);
    fade_.setEndValue(0.0);
    fade_.start();
}

void DropOverlay::paintEvent(QPaintEvent*) {
    const double f = std::clamp(fade_.currentValue().toDouble(), 0.0, 1.0);
    const double ph = phase_.currentValue().toDouble();
    const double pulse = 0.5 + 0.5 * std::sin(2.0 * kPi * ph);

    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    // Velo oscuro
    QColor veil(Theme::kBg0);
    veil.setAlphaF(0.86 * f);
    p.fillRect(rect(), veil);

    // Marco discontinuo que «corre» alrededor
    const QRectF frame = QRectF(rect()).adjusted(24, 24, -24, -24);
    QColor accent(Theme::kAccent);
    accent.setAlphaF(f);
    QPen dash(accent, 3.0);
    dash.setStyle(Qt::CustomDashLine);
    dash.setDashPattern({4.0, 4.0});
    dash.setDashOffset(ph * 8.0);  // 8 = periodo del patrón → bucle sin saltos
    dash.setCapStyle(Qt::RoundCap);
    p.setPen(dash);
    p.setBrush(Qt::NoBrush);
    p.drawRoundedRect(frame, 26, 26);

    // Relleno suave del marco
    QColor fill(Theme::kAccent);
    fill.setAlphaF(0.05 * f + 0.04 * pulse * f);
    p.setPen(Qt::NoPen);
    p.setBrush(fill);
    p.drawRoundedRect(frame, 26, 26);

    const QPointF c(width() / 2.0, height() / 2.0 - 30);

    // Anillos que se expanden desde el logo
    p.setBrush(Qt::NoBrush);
    for (int k = 0; k < 2; ++k) {
        const double t = std::fmod(ph + k * 0.5, 1.0);
        QColor ring(Theme::kCyan);
        ring.setAlphaF((1.0 - t) * 0.40 * f);
        p.setPen(QPen(ring, 2.0));
        const double r = 70.0 + t * 120.0;
        p.drawEllipse(c, r, r);
    }

    // Logo con latido
    const double sz = 118.0 + 12.0 * pulse;
    p.setOpacity(f);
    Theme::paintLogo(p, QRectF(c.x() - sz / 2, c.y() - sz / 2, sz, sz));

    // Textos
    QFont title = font();
    title.setPixelSize(22);
    title.setBold(true);
    p.setFont(title);
    p.setPen(QColor(Theme::kText));
    const QRectF t1(0, c.y() + 90, width(), 34);
    p.drawText(t1, Qt::AlignHCenter | Qt::AlignVCenter, tr("Suelta para cifrar y guardar en la bóveda"));

    QFont sub = font();
    sub.setPixelSize(14);
    p.setFont(sub);
    p.setPen(QColor(Theme::kDim));
    const QString line =
        count_ == 1 ? tr("1 elemento") : tr("%1 elementos").arg(count_);
    p.drawText(QRectF(0, c.y() + 126, width(), 24), Qt::AlignHCenter | Qt::AlignVCenter, line);
    if (!hint_.isEmpty())
        p.drawText(QRectF(0, c.y() + 150, width(), 24), Qt::AlignHCenter | Qt::AlignVCenter, hint_);
}
