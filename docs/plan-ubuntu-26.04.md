# Plan de soporte para Ubuntu 26.04 LTS

Fecha: 2026-09-30. Base del proyecto: secure-vps v1.4.11.
Estado: adaptación mínima implementada; prerelease v1.5.0 con validación experimental en Docker arm64.

Docker Desktop ya está operativo. La ejecución nativa usa arm64. El intento
amd64 falló en el entorno de emulación antes de ejecutar Kenroka; incluso
`docker run --rm --platform linux/amd64 ubuntu:26.04 uname -m` devolvió
`exec format error`. No se considera evidencia de incompatibilidad de Kenroka
ni validación de amd64.

## Objetivo y base aceptada

Incluir Ubuntu 26.04 LTS con el recorrido guiado, verificación y recuperación
que ofrece Kenroka. El dueño considera correctas sus pruebas de Ubuntu 22.04 y
24.04; se conservan como versiones admitidas. Sus pruebas manuales no se
confunden con una nueva ejecución de la suite automatizada.

El primer alcance es Ubuntu Server 26.04 actualizado, instalación limpia en
amd64. La migración de un VPS endurecido con 24.04 se valida después y tendrá
un resultado separado. Se ha podido avanzar con arm64 en Docker; amd64 continúa como objetivo pendiente.
Versiones anteriores a 22.04 no forman parte de este incremento.

## Regla de implementación acordada

Conservar el comportamiento validado de 22.04 y 24.04. El alcance consiste en
reconocer 26.04 y aplicar únicamente lo necesario para que funcione, no en
reestructurar el script ni cambiar políticas, interfaz o flujos existentes.

- Mantener las rutas actuales de 22.04/24.04 y añadir las diferencias de 26.04.
- Reutilizar lo que ya funciona sin modificarlo.
- No hacer refactorizaciones, cambios de herramientas ni sustituciones de sudo
  por conveniencia. Primero probar el entorno predeterminado de 26.04.
- Cada ajuste debe corresponder a una incompatibilidad reproducida o a la
  incorporación explícita de 26.04 en detección/documentación/pruebas.
- Si un cambio en una función compartida es inevitable, mantener su resultado
  en 22.04/24.04 y comprobarlo con la regresión correspondiente.
- Implementar en incrementos pequeños; registrar archivo, motivo y prueba.

## 1. Caracterizar una instalación real de 26.04

Usar una VM o VPS desechable, con consola de recuperación y snapshot completo.
Registrar la imagen/proveedor, arquitectura, versión de Ubuntu y paquetes,
proveedor efectivo de sudo/visudo, unidades SSH y puertos a la escucha,
configuración cloud-init, logs disponibles y estado inicial de Fail2ban/UFW.
No ejecutar hardening sobre el VPS principal para investigar compatibilidad.

Entregable: ficha del entorno y lista de incompatibilidades reproducidas.
La ausencia previa de Docker local no impide preparar código, pero las pruebas
con systemd y red necesitan un entorno operativo antes de declarar soporte.

## 2. Preparar la matriz de pruebas

- Añadir 26.04 al selector de tests/docker/run.sh como objetivo de pruebas.
- Revisar Dockerfile.server y Dockerfile.client: instalar los paquetes necesarios
  sin sustituir inadvertidamente el sudo predeterminado de la imagen real.
- Revisar seed.sh: su condición actual activa ssh.socket únicamente para 24.04.
  Representar el comportamiento observado en 26.04; no asumir que usa el mismo.
- Cubrir servicio y socket si ambos modos están contemplados por Kenroka.
- Registrar paquetes/proveedores efectivos en los resultados para reproducirlos.

Entregable: entorno reproducible para ejecutar la suite con --distro 26.04.
Añadir la versión al arnés no la convierte todavía en soporte publicado.

## 3. Adaptar únicamente las diferencias confirmadas

Prioridad: conservar acceso administrativo y recuperación.

1. Sudo: comprobar visudo, validación de sudoers, contraseña obligatoria,
   NOPASSWD, sudo -l, sudo -k -n y ejecución desde runuser. Validar el proveedor
   predeterminado y la alternativa sudo.ws cuando esté instalada.
2. SSH: comprobar sshd -t/-T, configuración cloud-init, listener real,
   activación servicio/socket, autenticación por clave y cambio de puerto.
3. Fail2ban: comprobar backend journald/auth.log, jail sshd, instalación,
   servicio activo y arranque enabled después de reiniciar.
4. UFW: comprobar reglas IPv4/IPv6, servicios existentes y prueba externa
   posterior a la activación.
5. Actualizaciones: comprobar instalación de paquetes, unattended-upgrades,
   temporizadores, avisos de servicios/kernel y mensajes de reinicio.
6. Herramientas del sistema: comprobar las opciones de cp, stat, mktemp, sed,
   flock y comandos empleados en snapshots/restauración con el entorno real.

Conservar la detección actual de capacidades cuando ya funcione en 26.04.
Añadir una rama o ajuste específico para 26.04 solo donde exista una diferencia
comprobada. No reemplazar la lógica existente por un nuevo sistema de detección
ni cambiar políticas de seguridad solo para hacer pasar una prueba.

## 4. Criterios de aceptación para instalación limpia

- Guía completa con usuario nuevo y reutilización de un administrador existente.
- Entrada por clave desde otra terminal y sudo funcional antes/después del cierre.
- Clave inválida corregible; rechazo de la prueba previa detiene el recorrido.
- UFW permite el acceso esperado; clave, root y contraseña cumplen la política.
- Cambio de puerto: nuevo puerto funciona y el anterior deja de estar abierto
  tras confirmar; rechazo/timeout restaura acceso y reglas.
- Restauración explícita y temporizada funcionan, incluido estado de Fail2ban
  activo y habilitado/deshabilitado al arrancar.
- Reinicio real: SSH, UFW y Fail2ban conservan el estado esperado y permiten entrar.
- Segunda ejecución no destruye claves, usuario, reglas ni configuración válida.
- Auditoría no modifica el sistema y verificación 2.3 genera reporte coherente.
- Alias y comandos finales corresponden al puerto efectivo.
- Pruebas unitarias, instalador y suite de integración disponibles pasan.
- Regresión crítica de SSH, sudo y rollback en 22.04/24.04; aprovechar sus
  escenarios existentes sin repetir toda la revisión visual ya aceptada.

Docker con systemd cubre servicios, red y timers, pero no certifica el kernel ni
el arranque de una VM/VPS: el reinicio real se valida fuera de contenedores.

## 5. Validar migración 24.04 -> 26.04

En una copia desechable de un VPS 24.04 endurecido y con respaldo completo:
actualizar siguiendo Ubuntu, registrar decisiones sobre archivos de
configuración, reiniciar y probar SSH con clave, sudo, UFW, Fail2ban y servicios.
Reejecutar Kenroka y verificar idempotencia y diagnóstico.

Los snapshots de Kenroka restauran configuración; no revierten Ubuntu ni sus
paquetes. La vuelta a 24.04 depende del respaldo completo externo.
Si solo pasa instalación limpia, declarar ese alcance y mantener la migración
como pendiente, sin presentar ambos escenarios como equivalentes.

## 6. Publicar soporte

Solo después de cumplir la aceptación correspondiente: actualizar check_os,
texto de ayuda, auditoría y documentación ES/EN con la matriz y alcance reales.
Publicar release firmada y notas con pruebas ejecutadas, imagen, versiones de
paquetes y limitaciones. No cambiar el mensaje a «probado» antes de tener evidencia.

## Fuentes y evidencias

- [Notas oficiales de Ubuntu 26.04 para usuarios LTS](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/): cambios de OpenSSH y proveedor sudo.
- [Gestión de usuarios de Ubuntu Server](https://ubuntu.com/server/docs/security-users/): sudo-rs predeterminado desde 25.10 y alternativa sudo.ws.
- [Actualización de Ubuntu Server](https://ubuntu.com/server/docs/how-to/software/upgrade-your-release/): preparación de migraciones de versión.
- Revisión local: secure-vps.sh (check_os, sudo, SSH, snapshots y verificación),
  tests/docker/run.sh, tests/docker/seed.sh y Dockerfiles.

## Registro de implementación y validación

Entorno: Ubuntu 26.04.1 LTS, arm64 (`aarch64`), Docker Desktop 29.7.2,
OpenSSH 10.2p1, systemd 259.5 y sudo-rs 0.2.13-0ubuntu1.2.

Cambios limitados:

- Script: reconoce 26.04 como experimental, informa ese alcance en ayuda y
  auditoría, y muestra 26.04 en el diagnóstico de su generador SSH. Las ramas
  de 22.04/24.04 y las políticas de hardening no cambian.
- Arnés: acepta `--distro 26.04`, instala sudo-rs y prepara activación SSH por
  socket para esta versión. Las versiones anteriores conservan sus paquetes.
- Fixture 26.04: el paquete sudo-common deja `/etc/sudoers` con 0644 en la
  imagen mínima y `visudo-rs -c` lo rechaza. Se fija 0440 en el Dockerfile para
  preparar una instalación válida. El script sigue rechazando una política
  sudo inválida; no corrige esos permisos por su cuenta.
- Prueba de auditoría: espera 24022, el puerto sugerido que ya usaba el script,
  en lugar del antiguo 2222. No cambia la lógica de selección del puerto.

Primera ejecución: 19 de 22 escenarios aprobados. Los escenarios 20 y 21
fallaron por los permisos de la fixture; el 19 por la expectativa de puerto
obsoleta. Tras corregir sus causas, los tres pasan: 50, 6 y 36 comprobaciones
externas respectivamente (el escenario 20 además ejecuta 19 comprobaciones
internas con servicios reales). Resultado agregado: 22 de 22 escenarios
aprobados.

Validaciones locales: 484 comprobaciones unitarias y 30 del instalador
aprobadas; sintaxis Bash y `git diff --check` sin errores.

Regresión adicional en arm64: escenarios 06 (cambio de puerto y login real),
19 (auditoría sin escrituras) y 20 (snapshots, confirmación tardía y transición
sudo con contraseña) aprobados en ambas versiones:

| Ubuntu | Escenario 06 | Escenario 19 | Escenario 20 |
| --- | ---: | ---: | ---: |
| 22.04 | 10 | 50 | 6 + 19 internas |
| 24.04 | 14 | 50 | 6 + 19 internas |

Comandos ejecutados: `bash tests/run.sh unit`, `bash tests/install-local.sh`,
`bash tests/docker/run.sh --distro 26.04 --keep`; tras las correcciones de
fixtures, `--distro 26.04 --rebuild --only 19`, `--only 20` y `--only 21`.
Para 22.04 y 24.04: `--distro VERSION --only 06`, `--only 19` y `--only 20`.


Pendientes para declarar soporte completo: amd64 en entorno operativo,
reinicio real de VM/VPS y migración de 24.04 a 26.04. Docker comparte el kernel
del host Linux y no sustituye esas comprobaciones.

