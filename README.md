# Secure Space (SS) 0.3

Bóveda de archivos cifrada en C++17 (Qt 6 + libsodium). Lo que entra se guarda cifrado con nombres aleatorios,
se puede **usar dentro de SS** (editar texto, ver imágenes, reproducir audio y vídeo) sin dejar copias
descifradas en el disco, y lo que se elimina se destruye de forma definitiva.

## Compilar

**Linux (Debian/Ubuntu)**
```
sudo apt install build-essential cmake pkg-config qt6-base-dev qt6-multimedia-dev libsodium-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/SecureSpace
```
**Windows (vcpkg)**: `vcpkg install qt6-base qt6-multimedia libsodium` y
`cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake`.
**macOS**: `brew install qt libsodium cmake pkg-config` (+ `-DCMAKE_PREFIX_PATH=$(brew --prefix qt)`).

Si Qt Multimedia no está instalado, el programa compila igualmente pero sin reproducción de audio/vídeo.

## Modelo de seguridad

**Contraseña + llave (dos factores).** La clave de la bóveda sale de `Argon2id(contraseña)` combinada con una
**llave aleatoria de 256 bits**. Quien copie la carpeta a otro equipo no tiene la llave, así que no hay
contraseña que probar: la fuerza bruta es inabordable aunque la contraseña sea débil.
- *Modo cómodo (por defecto):* la llave se guarda en este equipo, fuera de la carpeta de la bóveda
  (Windows: protegida con DPAPI, ligada a tu cuenta; Linux/macOS: archivo `0600` en `~/.config/.sscfg`).
- *Modo máxima protección:* la llave solo existe en un archivo `.sskey` (p. ej. en un USB) que se elige en cada inicio.
- En el primer inicio se guarda un **archivo `.sskey` de recuperación**. Sin contraseña **y** sin llave no hay
  forma de recuperar nada: es intencional.

**Archivos.** Cada archivo se cifra con su propia clave aleatoria, en bloques independientes de 256 KiB
(XChaCha20-Poly1305, con detección de manipulación, reordenación y truncado). Esto permite descifrar *solo el
trozo que se necesita*, en RAM: así el vídeo permite saltar a cualquier minuto sin descifrar el archivo entero.
Las claves de archivo, nombres, tamaños y ajustes viven en un índice cifrado con relleno.

**Uso dentro de SS.** El visor descifra a memoria; nunca escribe temporales. Texto: editable y se guarda
cifrado (clave nueva en cada guardado). Imágenes: zoom y ajuste. Audio/vídeo: reproductor con barra de
posición. Al bloquear (manual, inactividad o minimizar) se cierran los visores, se guardan los cambios pendientes
y se borran las claves de la memoria.

**Importar.** Por cada importación se elige (o se fija en Configuración):
- *Dejar una copia sin cifrar* fuera de la bóveda, o
- *Destruir de forma segura el original*: antes se **verifica** la copia cifrada (hash del contenido) y solo
  entonces se elimina el original; si la verificación falla, el original no se toca.

**Borrado definitivo (archivos fuera de la bóveda).** Borrar un archivo normalmente solo quita su entrada: los datos
siguen en el disco y los programas de recuperación los leen. SS ataca cada sitio donde esos programas buscan:

| Dónde buscan los programas de recuperación | Qué hace SS |
|---|---|
| Datos en clústeres «liberados» | Sobrescribe en su sitio: N pasadas aleatorias + 1 a ceros, con escritura directa (`WRITE_THROUGH` en Windows, `fsync`/`F_FULLFSYNC` en Linux/macOS) |
| «Cola» del último clúster (slack) | La sobrescritura llega hasta el final del clúster, no solo hasta el final del archivo |
| Nombre y fechas en la tabla de archivos (MFT / inodo / directorio) | Fechas neutras y varios renombrados aleatorios de la misma longitud antes de eliminar |
| Flujos de datos alternos de NTFS (`archivo:oculto`) | Se enumeran y se sobrescriben también |
| Papelera y accesos directos | Eliminación directa, sin papelera; de un enlace solo se quita el enlace |
| Archivos pequeños «residentes» dentro de la MFT y registros liberados | *Limpiar espacio libre* inunda la unidad con datos aleatorios y con miles de archivos diminutos de nombre aleatorio |
| Restos en el espacio libre | *Limpiar espacio libre* (se ofrece automáticamente cuando la unidad lo necesita) |
| Marcadores de nube sin datos locales | No se descargan (sobrescribirlos los descargaría) y se avisa |
| Listas de recientes y miniaturas del archivo | Se elimina su entrada: `.lnk` de Recientes (Windows); `recently-used.xbel` y miniatura exacta por URI/MD5 (Linux) |
| Rastros generales del sistema (listas de salto, cachés de miniaturas) | **Herramientas → Limpiar rastros del sistema** |
| Copias de volumen (Restaurar sistema, versiones anteriores) | **Herramientas → Eliminar copias de volumen** (Windows, pide administrador) |

Reglas de seguridad: **nunca se elimina un archivo que no se pudo sobrescribir**; al importar con «destruir original»,
primero se verifica la copia cifrada por hash. El proceso corre en segundo plano y la interfaz sigue viva.

**Fiabilidad honesta.** SS detecta el tipo de unidad (giratoria / flash), el sistema de archivos (btrfs, ZFS, APFS, ReFS,
F2FS, red), compresión/EFS de NTFS y carpetas de nube, y al terminar informa de la fiabilidad real del borrado con avisos
concretos. Si no es alta, ofrece rematar con *Limpiar espacio libre*. Disponible también como herramienta:
**Herramientas → Destruir archivos / carpeta del equipo**.

**Eliminar dentro de la bóveda / destruir todo.** La clave del archivo sale del índice, se sobrescribe el archivo cifrado,
se trunca, se renombra al azar y se borra. «Destruir todo» elimina primero la llave de este equipo, la cabecera y el
índice, y después todo lo demás; SS vuelve a la pantalla de primer inicio.

## Interfaz

- **Arrastrar y soltar:** al arrastrar archivos hacia la ventana aparece una capa animada (marco discontinuo en
  movimiento, anillos que se expanden, logo que late) con el número de elementos y lo que se hará con los originales.
  La importación se lanza después de soltar, para no dejar «colgado» al Explorador.
- **Panel de transferencia:** en importar, exportar, eliminar y destruir aparece un panel con la operación, el archivo
  actual («archivo 3 de 12»), barra de progreso, tamaño, **velocidad suavizada**, **tiempo restante** y **Cancelar**
  (importar y exportar). Al cancelar una importación los originales no se tocan. Mientras corre, el resto de la
  ventana queda desactivado para que nada interfiera.
- **Reproductor:** iconos vectoriales, botón de reproducir/pausa, ±10 s, barra con salto por clic y tiempo al pasar el
  cursor, volumen y silencio, **velocidad 0,5×–2×**, **pantalla completa con modo cine** (los controles y el cursor se
  ocultan solos), título, resolución y fps, y un escenario de audio con portada (o logo) y anillos que laten.
  Atajos: `Espacio`/`K` pausa · `←`/`→` ±5 s · `J`/`L` ±10 s · `↑`/`↓` volumen · `M` silencio · `F` pantalla completa ·
  `Esc` salir. Clic = pausa; doble clic = pantalla completa.

## Límites que conviene conocer

- En **SSD** el controlador reasigna bloques (desgaste/TRIM): una sobrescritura puede no tocar las celdas físicas
  antiguas, y en sistemas **copia-al-escribir** (btrfs, ZFS, APFS, ReFS) el dato viejo sigue en otro bloque. Ningún
  programa en espacio de usuario puede garantizarlo; por eso SS lo detecta, te lo dice y encadena *Limpiar espacio
  libre*. Lo único que lo cierra del todo es que el disco ya estuviera cifrado (BitLocker / LUKS / FileVault).
- **«Imposible» no es una promesa que un programa en espacio de usuario pueda hacer** en SSD o sistemas
  copia-al-escribir: ahí SS reduce la recuperación al mínimo posible, te dice con qué fiabilidad lo logró y te
  indica qué lo cierra del todo (cifrado de disco). Prometer más sería engañar a quien confía en SS.
- Quedan fuera de su alcance: **copias de volumen** (Restaurar sistema, Historial de archivos, instantáneas), el
  **diario del sistema de archivos / USN** (guardan nombres, no contenido; borrarlos exige administrador), las
  **copias en la nube** y las copias de seguridad que ya existieran. SS avisa cuando aplican.
- El archivo de **paginación / swap** del sistema puede guardar fragmentos de lo que se ve en pantalla. Con
  cifrado de disco completo (o swap cifrado) queda cubierto.
- El **límite de intentos** protege contra quien use el programa; no puede frenar a alguien que ya controla tu
  sesión del sistema operativo ni a malware con acceso a la memoria mientras la bóveda está abierta.
- En Linux/macOS la llave de dispositivo es un archivo `0600` (no hardware): protege contra copiar la carpeta de
  la bóveda, no contra copiar todo tu perfil. Para equipos robados usa el modo «solo llave externa» + cifrado de disco.
- Los archivos **exportados** quedan sin cifrar fuera de la bóveda.
- Primera versión: **no se ha compilado ni probado** en el entorno donde se escribió; es probable que haga falta
  corregir algún detalle menor de API al compilar con tu versión de Qt.

## Estructura

`Vault` (núcleo cifrado) · `Platform` (llave de dispositivo, DPAPI, anti-captura) · `Viewer` (visor/editor) ·
`MainWindow` · `AuthDialogs` · `SettingsDialog` · `Strength` · `Theme` (paleta `#1e223d`, logo "SS") · `UiUtil`.
