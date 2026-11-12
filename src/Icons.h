#pragma once

#include <QIcon>
#include <QRgb>

// Iconos vectoriales dibujados por código (nítidos en cualquier escala, sin archivos externos).
namespace Icons {
enum class Id { Play, Pause, Back10, Fwd10, VolumeHigh, VolumeLow, VolumeMute, Fullscreen, ExitFullscreen };
QIcon make(Id id, int size = 24, QRgb color = 0xe6e8f5);
}  // namespace Icons
