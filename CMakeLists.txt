cmake_minimum_required(VERSION 3.21)
project(SecureSpace VERSION 0.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
# Reproducción de audio/vídeo dentro de la bóveda (opcional pero recomendado)
find_package(Qt6 QUIET COMPONENTS Multimedia MultimediaWidgets)

# libsodium: pkg-config (Linux / macOS / MSYS2) o vcpkg (Windows)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(SODIUM IMPORTED_TARGET libsodium)
endif()
if(TARGET PkgConfig::SODIUM)
  set(SS_SODIUM_TARGET PkgConfig::SODIUM)
else()
  find_package(unofficial-sodium CONFIG REQUIRED)
  set(SS_SODIUM_TARGET unofficial-sodium::sodium)
endif()

add_executable(SecureSpace WIN32 MACOSX_BUNDLE
  src/main.cpp
  src/Theme.cpp
  src/Platform.cpp
  src/Vault.cpp
  src/AuthDialogs.cpp
  src/MainWindow.cpp
  src/SettingsDialog.cpp
  src/Viewer.cpp
  src/Icons.cpp
  src/DropOverlay.cpp
  src/TransferPanel.cpp
  src/MediaPlayer.cpp
)
target_include_directories(SecureSpace PRIVATE src)
target_link_libraries(SecureSpace PRIVATE Qt6::Widgets ${SS_SODIUM_TARGET})

if(TARGET Qt6::Multimedia AND TARGET Qt6::MultimediaWidgets)
  target_link_libraries(SecureSpace PRIVATE Qt6::Multimedia Qt6::MultimediaWidgets)
  target_compile_definitions(SecureSpace PRIVATE SS_HAS_MEDIA)
  message(STATUS "Secure Space: reproducción multimedia ACTIVADA")
else()
  message(WARNING "Qt Multimedia no encontrado: el visor no podrá reproducir audio/vídeo")
endif()

if(WIN32)
  target_link_libraries(SecureSpace PRIVATE crypt32 shell32)  # DPAPI (llave de dispositivo) y elevación (UAC)
endif()

if(MSVC)
  target_compile_options(SecureSpace PRIVATE /W4 /utf-8 /permissive-)
else()
  target_compile_options(SecureSpace PRIVATE -Wall -Wextra -Wpedantic -fstack-protector-strong)
endif()
