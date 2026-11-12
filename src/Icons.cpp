#include "Icons.h"

#include <QFont>
#include <QPainter>
#include <QPainterPath>
#include <QPixmap>
#include <QPolygonF>
#include <cmath>

namespace {
constexpr double kPi = 3.14159265358979323846;

QPointF onCircle(const QPointF& c, double r, double deg) {
    const double a = deg * kPi / 180.0;
    return QPointF(c.x() + r * std::cos(a), c.y() - r * std::sin(a));
}

// «Saltar 10 s»: arco casi completo con punta de flecha y el número 10 dentro.
void drawSkip(QPainter& p, bool forward, const QColor& c) {
    const QPointF ctr(12, 13);
    const double r = 7.5;
    p.save();
    if (!forward) {
        p.translate(24, 0);
        p.scale(-1, 1);
    }
    p.setBrush(Qt::NoBrush);
    p.setPen(QPen(c, 1.8, Qt::SolidLine, Qt::RoundCap));
    const QRectF rect(ctr.x() - r, ctr.y() - r, 2 * r, 2 * r);
    QPainterPath arc;
    arc.arcMoveTo(rect, 70);
    arc.arcTo(rect, 70, -300);
    p.drawPath(arc);

    const double endDeg = 70.0 - 300.0;
    const QPointF e = onCircle(ctr, r, endDeg);
    const double a = endDeg * kPi / 180.0;
    const QPointF dir(std::sin(a), std::cos(a));  // tangente en sentido horario
    const QPointF nrm(-dir.y(), dir.x());
    QPolygonF head;
    head << e + dir * 3.2 << e - dir * 1.0 + nrm * 3.0 << e - dir * 1.0 - nrm * 3.0;
    p.setPen(Qt::NoPen);
    p.setBrush(c);
    p.drawPolygon(head);
    p.restore();

    QFont f;
    f.setPixelSize(8);
    f.setBold(true);
    p.setFont(f);
    p.setPen(c);
    p.drawText(QRectF(4.5, 8.5, 15, 10), Qt::AlignCenter, QStringLiteral("10"));
}

void drawSpeaker(QPainter& p, const QColor& c) {
    p.setPen(Qt::NoPen);
    p.setBrush(c);
    QPolygonF sp;
    sp << QPointF(4, 9.5) << QPointF(8, 9.5) << QPointF(13, 5.5) << QPointF(13, 18.5) << QPointF(8, 14.5)
       << QPointF(4, 14.5);
    p.drawPolygon(sp);
}

void drawWave(QPainter& p, const QColor& c, double radius) {
    p.setBrush(Qt::NoBrush);
    p.setPen(QPen(c, 1.8, Qt::SolidLine, Qt::RoundCap));
    const QRectF rect(13 - radius, 12 - radius, 2 * radius, 2 * radius);
    QPainterPath w;
    w.arcMoveTo(rect, -45);
    w.arcTo(rect, -45, 90);
    p.drawPath(w);
}

void polyline(QPainter& p, std::initializer_list<QPointF> pts) {
    QPainterPath path;
    bool first = true;
    for (const QPointF& pt : pts) {
        if (first) path.moveTo(pt);
        else path.lineTo(pt);
        first = false;
    }
    p.drawPath(path);
}
}  // namespace

QIcon Icons::make(Id id, int size, QRgb color) {
    const int dpr = 2;
    QPixmap pm(size * dpr, size * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.scale(size / 24.0, size / 24.0);  // se dibuja sobre una rejilla de 24×24
    const QColor c(color);
    const QPen stroke(c, 2.0, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
    p.setPen(Qt::NoPen);
    p.setBrush(c);

    switch (id) {
        case Id::Play: {
            QPainterPath path;
            path.moveTo(8, 5);
            path.lineTo(19, 12);
            path.lineTo(8, 19);
            path.closeSubpath();
            p.drawPath(path);
            break;
        }
        case Id::Pause:
            p.drawRoundedRect(QRectF(6.5, 5, 4, 14), 1.2, 1.2);
            p.drawRoundedRect(QRectF(13.5, 5, 4, 14), 1.2, 1.2);
            break;
        case Id::Back10: drawSkip(p, false, c); break;
        case Id::Fwd10: drawSkip(p, true, c); break;
        case Id::VolumeHigh:
            drawSpeaker(p, c);
            drawWave(p, c, 4.0);
            drawWave(p, c, 7.0);
            break;
        case Id::VolumeLow:
            drawSpeaker(p, c);
            drawWave(p, c, 4.0);
            break;
        case Id::VolumeMute:
            drawSpeaker(p, c);
            p.setBrush(Qt::NoBrush);
            p.setPen(stroke);
            polyline(p, {QPointF(16.5, 9.5), QPointF(21.5, 14.5)});
            polyline(p, {QPointF(21.5, 9.5), QPointF(16.5, 14.5)});
            break;
        case Id::Fullscreen:
            p.setBrush(Qt::NoBrush);
            p.setPen(stroke);
            polyline(p, {QPointF(4, 9), QPointF(4, 4), QPointF(9, 4)});
            polyline(p, {QPointF(15, 4), QPointF(20, 4), QPointF(20, 9)});
            polyline(p, {QPointF(4, 15), QPointF(4, 20), QPointF(9, 20)});
            polyline(p, {QPointF(20, 15), QPointF(20, 20), QPointF(15, 20)});
            break;
        case Id::ExitFullscreen:
            p.setBrush(Qt::NoBrush);
            p.setPen(stroke);
            polyline(p, {QPointF(9, 4), QPointF(9, 9), QPointF(4, 9)});
            polyline(p, {QPointF(15, 4), QPointF(15, 9), QPointF(20, 9)});
            polyline(p, {QPointF(4, 15), QPointF(9, 15), QPointF(9, 20)});
            polyline(p, {QPointF(20, 15), QPointF(15, 15), QPointF(15, 20)});
            break;
    }
    p.end();
    return QIcon(pm);
}
