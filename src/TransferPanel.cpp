#include "TransferPanel.h"

#include <QCoreApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLocale>
#include <QProgressBar>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QVBoxLayout>
#include <algorithm>

namespace {
QString fmtDuration(qint64 secs) {
    if (secs < 60) return QObject::tr("%1 s").arg(std::max<qint64>(1, secs));
    if (secs < 3600) return QObject::tr("%1 min %2 s").arg(secs / 60).arg(secs % 60);
    return QObject::tr("%1 h %2 min").arg(secs / 3600).arg((secs / 60) % 60);
}
}  // namespace

TransferPanel::TransferPanel(QWidget* parent) : QFrame(parent) {
    setObjectName(QStringLiteral("panel"));
    auto* lay = new QVBoxLayout(this);
    lay->setContentsMargins(18, 14, 18, 14);
    lay->setSpacing(7);

    auto* top = new QHBoxLayout;
    title_ = new QLabel;
    title_->setObjectName(QStringLiteral("panelTitle"));
    cancel_ = new QPushButton(tr("Cancelar"));
    top->addWidget(title_, 1);
    top->addWidget(cancel_);
    lay->addLayout(top);

    file_ = new QLabel;
    file_->setObjectName(QStringLiteral("hint"));
    lay->addWidget(file_);

    bar_ = new QProgressBar;
    bar_->setObjectName(QStringLiteral("transfer"));
    bar_->setTextVisible(false);
    bar_->setRange(0, 1000);
    lay->addWidget(bar_);

    stats_ = new QLabel;
    stats_->setObjectName(QStringLiteral("hint"));
    lay->addWidget(stats_);

    connect(cancel_, &QPushButton::clicked, this, [this] {
        cancelled_ = true;
        cancel_->setEnabled(false);
        cancel_->setText(tr("Cancelando…"));
    });
    hide();
}

void TransferPanel::begin(const QString& title, qint64 totalUnits, int fileCount, int scale, bool cancellable) {
    titleBase_ = title;
    total_ = totalUnits;
    count_ = fileCount;
    scale_ = std::max(1, scale);
    base_ = cur_ = curUnits_ = lastUnits_ = lastMs_ = 0;
    index_ = 0;
    speed_ = 0.0;
    cancelled_ = false;
    clock_.start();
    tick_.start();

    title_->setText(title);
    file_->clear();
    stats_->clear();
    cancel_->setVisible(cancellable);
    cancel_->setEnabled(true);
    cancel_->setText(tr("Cancelar"));
    bar_->setRange(0, 1000);
    bar_->setValue(0);

    setMaximumHeight(0);
    show();
    auto* a = new QPropertyAnimation(this, "maximumHeight", this);
    a->setDuration(180);
    a->setStartValue(0);
    a->setEndValue(sizeHint().height());
    connect(a, &QPropertyAnimation::finished, this, [this] { setMaximumHeight(QWIDGETSIZE_MAX); });
    a->start(QAbstractAnimation::DeleteWhenStopped);
    QCoreApplication::processEvents();
}

void TransferPanel::end() { hide(); }

void TransferPanel::startFile(const QString& name, qint64 units) {
    base_ += curUnits_;
    cur_ = 0;
    curUnits_ = units;
    ++index_;
    file_->setText(fontMetrics().elidedText(name, Qt::ElideMiddle, std::max(200, width() - 60)));
    title_->setText(count_ > 1 ? tr("%1 · archivo %2 de %3").arg(titleBase_).arg(std::min(index_, count_)).arg(count_)
                               : titleBase_);
}

bool TransferPanel::fileProgress(qint64 done, qint64 total) {
    cur_ = total > 0 ? qint64(double(done) / double(total) * double(curUnits_)) : curUnits_;
    if (tick_.elapsed() >= 40) {
        tick_.restart();
        refresh();
        QCoreApplication::processEvents();  // permite pulsar «Cancelar»; el resto de la ventana está desactivado
    }
    return !cancelled_;
}

bool TransferPanel::overall(qint64 done, qint64 total) {
    if (bar_->maximum() == 0) bar_->setRange(0, 1000);
    bar_->setValue(total > 0 ? int(double(done) * 1000.0 / double(total)) : 0);
    stats_->setText(tr("%1 de %2").arg(done).arg(total));
    QCoreApplication::processEvents();
    return !cancelled_;
}

void TransferPanel::setIndeterminate(const QString& text) {
    bar_->setRange(0, 0);
    file_->setText(text);
    stats_->clear();
}

void TransferPanel::setFileText(const QString& text) {
    file_->setText(fontMetrics().elidedText(text, Qt::ElideMiddle, std::max(200, width() - 60)));
}

void TransferPanel::refresh() {
    const qint64 doneUnits = base_ + cur_;
    if (total_ > 0) bar_->setValue(int(std::min(1.0, double(doneUnits) / double(total_)) * 1000.0));

    const qint64 now = clock_.elapsed();
    if (now - lastMs_ >= 500) {  // velocidad suavizada
        const double inst = double(doneUnits - lastUnits_) / (double(now - lastMs_) / 1000.0);
        speed_ = speed_ <= 0.0 ? inst : 0.6 * speed_ + 0.4 * inst;
        lastUnits_ = doneUnits;
        lastMs_ = now;
    }
    const QLocale loc;
    QString s = tr("%1 de %2").arg(loc.formattedDataSize(doneUnits / scale_, 1), loc.formattedDataSize(total_ / scale_, 1));
    if (speed_ > 1.0) {
        s += QStringLiteral("  ·  ") + tr("%1/s").arg(loc.formattedDataSize(qint64(speed_ / scale_), 1));
        const qint64 remain = qint64(double(std::max<qint64>(0, total_ - doneUnits)) / speed_);
        s += QStringLiteral("  ·  ") + tr("%1 restantes").arg(fmtDuration(remain));
    }
    stats_->setText(s);
}
