#pragma once

#include <QString>

#include "SecretKey.h"

class QWidget;

namespace Platform {
// Windows: excluye la ventana de capturas de pantalla y grabaciones. Otras plataformas: sin efecto.
void setCaptureProtection(QWidget* w, bool on);

struct TraceResult {
    int removed = 0;
    int locked = 0;       // en uso por el sistema: se vacían al cerrar sesión / reiniciar
    bool supported = true;
};
// Vacía los rastros que el sistema guarda de los archivos que has abierto: listas de recientes, listas de
// salto y cachés de miniaturas (que pueden contener una vista previa del contenido).
TraceResult clearSystemTraces();

// Windows: elimina TODAS las copias de volumen (puntos de restauración, versiones anteriores) de una unidad.
// Pide permisos de administrador (UAC). drive = "C:".
bool deleteShadowCopies(const QString& drive, QString* err);
}  // namespace Platform

// Llave de dispositivo: el segundo factor, guardado FUERA de la carpeta de la bóveda.
//  - Windows: cifrada con DPAPI (ligada a tu cuenta de Windows; no se puede abrir en otro equipo ni usuario).
//  - Linux / macOS: archivo con permisos 0600 en la carpeta de configuración (ver README).
namespace DeviceKey {
bool exists();
bool load(SecretKey& out);
bool save(const SecretKey& key);
void remove();  // borrado seguro

// Archivo .sskey: copia de la llave para recuperación / modo «solo llave externa».
bool writeKeyFile(const QString& path, const SecretKey& key, QString* err);
bool readKeyFile(const QString& path, SecretKey& out, QString* err);
}  // namespace DeviceKey
