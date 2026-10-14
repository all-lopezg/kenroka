# Validación de la corrección SSH en Ubuntu 26.04

Fecha: 2026-10-14. Script validado: commit `133c65487bb3d873dca125186e25c5bb76ad10df`.
SHA256: `45d0a55d65b4a0c117255d5448fb2e95c40d8c827e8a64109c5925a8f72f867b`.

## Entorno y alcance

- Docker Desktop, daemon 29.7.2; arquitectura arm64 (`aarch64`).
- Imagen de pruebas Ubuntu 26.04.1 LTS, con systemd como PID 1.
- OpenSSH 10.2p1 Ubuntu-2ubuntu3.6, systemd 259.5-0ubuntu3.4,
  sudo-rs 0.2.13-0ubuntu1.2.
- Cliente y servidor separados: autenticación SSH real, UFW, Fail2ban y
  temporizadores de restauración reales. Cada escenario reinicia los contenedores.
- Se verificó el hash de `/opt/secure-vps.sh` dentro del servidor: corresponde
  exactamente al script del commit indicado, copiado por el runner.

Se ejecutaron todos los escenarios disponibles y una regresión adicional.
Docker no valida amd64, el reinicio de una VM/VPS ni una migración del sistema
operativo desde 24.04; esos alcances siguen pendientes.

## Resultados

Resultado agregado tras corregir dos pruebas obsoletas: **23/23 escenarios
aprobados, 377 comprobaciones externas**, más 19 comprobaciones internas del
escenario 20 y 15 del escenario 23. El instalador pasó sus 30 comprobaciones
locales con firma y checksum de prueba. Las 601 comprobaciones unitarias del
script habían pasado antes de subir el commit; en esta validación no se cambió
el código del script.

La primera corrida completa aprobó 20/22 escenarios. Los dos fallos estaban
en el arnés y se corrigieron sin cambiar `secure-vps.sh`:

- Escenario 17: al restaurar el último snapshot del cambio de puerto, debe
  conservarse `sshd_config` posterior al endurecimiento, incluido el Include
  inicial de Kenroka. La expectativa anterior lo comparaba con el archivo
  previo al endurecimiento. Se conserva la comparación byte a byte, usando
  el estado que corresponde al snapshot restaurado.
- Escenario 20: la prueba llamaba directamente a `hardening_set_ports`, pero
  omitía `install_hardening_include`. Se añadió el paso que ya ejecuta la fase
  7 real antes de recargar SSH.

Ambos escenarios se repitieron completos y aprobaron. Los demás escenarios
aprobados no se repitieron, pues el script no cambió.

Cobertura de la corrección:

- Escenario 05: directiva `PasswordAuthentication yes` previa al Include y
  drop-in `00-provider.conf` con contraseña/root permitidos. La guía completa
  termina, el administrador entra con clave, root y contraseñas quedan cerrados,
  UFW y Fail2ban funcionan.
- Escenarios 04 y 10: restauración temporizada real y restauración exacta de
  archivos sobre un servidor ya endurecido.
- Escenario 22: conexiones SSH reales y sudo en los tres checkpoints: antes del
  cierre, después del cierre y después de activar UFW.
- Nuevo escenario 23: migración de `99-hardening.conf`, preservación de puerto,
  idempotencia, rechazo de bloques Match del administrador/root y restauración
  exacta de `sshd_config` y archivo legado. El rollback retira el archivo nuevo,
  recupera la política anterior y conserva el acceso del administrador.

## Comandos ejecutados

```bash
bash tests/docker/run.sh --distro 26.04
bash tests/docker/run.sh --distro 26.04 --only 17
bash tests/docker/run.sh --distro 26.04 --only 20
bash tests/docker/run.sh --distro 26.04 --only 23
bash tests/install-local.sh
```

Sintaxis Bash de las pruebas cambiadas y `git diff --check`: sin errores.
Los runners retiraron sus contenedores al terminar; Docker Desktop sigue activo.

## Por qué la captura muestra otra vez el error anterior

La captura escribe `/etc/ssh/sshd_config.d/99-hardening.conf`. El commit
corregido escribe `/etc/ssh/secure-vps.conf`; por tanto, esa ejecución usó el
script anterior. La consulta de GitHub confirmó que `releases/latest` seguía
siendo la release estable `v1.4.11`, mientras la corrección estaba en `main`.
El instalador habitual descarga `releases/latest`, por lo que subir un commit
no actualiza el script que ese instalador entrega. En esa primera fase se publicó el cambio en main, sin actualizar la release
estable. La publicación y prueba del instalador se documentan a continuación.

## Release estable y prueba del comando público

Posteriormente se publicó **v1.5.1 como release estable y latest**, con el
script, checksum y firma de Kenroka. GitHub confirmó `draft=false` y
`prerelease=false`. El instalador permanece en su URL habitual y no requiere
variables ni una descarga manual del script.

Script publicado: SHA256
`56e948de47442e080de6e3781c16d386b6519daca53165177ddab254883604ff`.
Respecto al script validado inicialmente, solo cambia la versión declarada
(cabecera y SCRIPT_VERSION).

Se ejecutó el nuevo escenario 24 sobre Ubuntu 26.04.1 arm64 contra las URLs
públicas reales de GitHub, sin servidor local ni sustitución de claves:

```bash
bash tests/docker/run.sh --distro 26.04 --only 24
```

Resultado: **14 comprobaciones aprobadas, 0 fallos**.

- El comando exacto `curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash`
  descarga v1.5.1, verifica firma/checksum, pide sudo y selección de idioma,
  abre el menú y permite salir.
- Una segunda ejecución del mismo instalador, con flags de guía de laboratorio,
  descarga la misma release pública y completa el hardening pese a las opciones
  contradictorias del proveedor. En cada checkpoint se abre una conexión real
  desde el cliente y se comprueba sudo antes de confirmar.
- La salida incluye `/etc/ssh/secure-vps.conf` y `HARDENING DEL ACCESO COMPLETADO`.
  Root y contraseñas quedan cerrados, el administrador entra tras UFW, Fail2ban
  está activo y no hay protección temporizada pendiente.

El controlador se adaptó al prompt `[sudo: authenticate] Password:` de sudo-rs
(con la contraseña conocida de la cuenta de laboratorio) y a la selección
inicial de idioma. Esas respuestas no cambian el instalador ni sus controles.
Las 30 comprobaciones locales del instalador también se repitieron con v1.5.1
y aprobaron. Resultado conjunto de escenarios: 24 aprobados, 391 comprobaciones
externas, más las 34 internas de seguridad indicadas antes.

## Corrección de GNU awk en v1.5.2

Un VPS que ejecutaba v1.5.1 devolvió `gawk: fatal: cannot use gawk builtin
include as variable name`. La versión publicada era la correcta; esta vez la
causa era una incompatibilidad introducida por el helper de Include SSH.
Las pruebas anteriores usaban otra implementación de awk y no cubrían GNU awk.

Se reprodujo el mismo error en GNU awk 5.3.2 sobre Ubuntu 26.04.1. El helper
ahora usa `managed_line` en lugar de `include`. Se añadió gawk al servidor de
pruebas Docker, donde pasa a ser `/usr/bin/awk`, y el nuevo escenario 25 prueba
el helper con gawk y mawk, incluida la eliminación de un Include gestionado
previo, conservación de contenido/permisos e idempotencia.

Validaciones nuevas: 601 unitarias; 30 del instalador; escenario 25 (4 externas
+ 15 internas), escenario 23 (8 externas + 15 internas) y escenario 05 (19
externas) aprobados con GNU awk como implementación predeterminada. No se
repitieron los demás escenarios de la suite anterior.

SHA256 del script v1.5.2 firmado:
`606bab9a082c9987fb49d9c23f8ca59c264f34ec54d90a3b79b7558c0df6ca64`.

La release v1.5.2 se publicó como estable y latest, con los tres assets firmados.
Se repitió el escenario 24 contra las descargas públicas reales con GNU awk
por defecto: **14 comprobaciones aprobadas, 0 fallos**. El comando exacto abre
el menú de v1.5.2 y la guía desde esa release termina con los tres checkpoints
SSH/sudo reales aprobados, root/contraseñas cerrados, UFW y Fail2ban activos y
sin rollback pendiente. El formato de invocación del instalador no cambió.
