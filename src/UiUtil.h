#pragma once

// Diálogos con botones en español (los estándar de Qt salen en inglés si no hay traducciones instaladas).

#include <QCoreApplication>
#include <QDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QObject>
#include <QPushButton>
#include <QProgressDialog>
#include <QString>

#include "Vault.h"

namespace Dlg {

inline void message(QWidget* parent, QMessageBox::Icon icon, const QString& title, const QString& text) {
    QMessageBox box(icon, title, text, QMessageBox::NoButton, parent);
    box.addButton(QObject::tr("Aceptar"), QMessageBox::AcceptRole);
    box.exec();
}

inline void info(QWidget* p, const QString& title, const QString& text) { message(p, QMessageBox::Information, title, text); }
inline void warn(QWidget* p, const QString& title, const QString& text) { message(p, QMessageBox::Warning, title, text); }
inline void error(QWidget* p, const QString& title, const QString& text) { message(p, QMessageBox::Critical, title, text); }

// Devuelve true si se pulsó «yes». El botón por defecto es siempre «no».
inline bool confirm(QWidget* parent, QMessageBox::Icon icon, const QString& title, const QString& text,
                    const QString& yes, const QString& no, bool dangerous = false) {
    QMessageBox box(icon, title, text, QMessageBox::NoButton, parent);
    QPushButton* y = box.addButton(yes, QMessageBox::AcceptRole);
    QPushButton* n = box.addButton(no, QMessageBox::RejectRole);
    if (dangerous) y->setObjectName(QStringLiteral("danger"));
    box.setDefaultButton(n);
    box.setEscapeButton(n);
    box.exec();
    return box.clickedButton() == y;
}

inline QString askText(QWidget* parent, const QString& title, const QString& label, const QString& initial, bool* ok) {
    QInputDialog dlg(parent);
    dlg.setWindowTitle(title);
    dlg.setLabelText(label);
    dlg.setTextValue(initial);
    dlg.setOkButtonText(QObject::tr("Aceptar"));
    dlg.setCancelButtonText(QObject::tr("Cancelar"));
    dlg.setWindowFlag(Qt::WindowContextHelpButtonHint, false);
    const bool accepted = dlg.exec() == QDialog::Accepted;
    if (ok) *ok = accepted;
    return accepted ? dlg.textValue() : QString();
}

// Sobrescribe el espacio libre de la unidad que contiene `folder` (con barra de progreso cancelable).
inline void runFreeSpaceWipe(QWidget* parent, const QString& folder) {
    QProgressDialog pd(QObject::tr("Limpiando espacio libre…"), QObject::tr("Cancelar"), 0, 100, parent);
    pd.setWindowModality(Qt::WindowModal);
    pd.setMinimumDuration(0);
    pd.setValue(0);
    QString err;
    const bool ok = Vault::wipeFreeSpace(
        folder,
        [&pd](qint64 done, qint64 total) {
            pd.setValue(total > 0 ? int(done * 100 / total) : 100);
            QCoreApplication::processEvents();
            return !pd.wasCanceled();
        },
        &err);
    pd.close();
    if (ok)
        info(parent, QObject::tr("Limpiar espacio libre"), QObject::tr("Espacio libre sobrescrito correctamente."));
    else
        warn(parent, QObject::tr("Limpiar espacio libre"), err);
}

}  // namespace Dlg
