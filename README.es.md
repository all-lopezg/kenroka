# secure-vps

<div align="center">

**Endurece un VPS Ubuntu sin dejarte fuera.**

**[ :gb: English ](README.md)** &nbsp;·&nbsp; :es: Español

```
 ██╗  ██╗███████╗███╗   ██╗██████╗  ██████╗  ██╗  ██╗ █████╗
 ██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██╔═══██╗ ██║ ██╔╝██╔══██╗
 █████╔╝ █████╗  ██╔██╗ ██║██████╔╝██║   ██║ █████╔╝ ███████║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██╔══██╗██║   ██║ ██╔═██╗ ██╔══██║
 ██║  ██╗███████╗██║ ╚████║██║  ██║╚██████╔╝ ██║  ██╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝
```

</div>

## Inicio rápido

```bash
curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
```

La URL no lleva versión a propósito: siempre resuelve la última release publicada.
El instalador verifica la firma de la release y te dice qué versión bajó antes de
ejecutar nada. Si entras con un administrador sin privilegios de root, solicita
`sudo` automáticamente. Puede pedir la contraseña local de ese usuario (no la
frase de tu clave SSH); al escribirla no se ven caracteres. Para repetirlo, usa
el mismo comando desde tu cuenta administradora.

Entre fases, la vista se limpia después de que hayas leído el resultado y
continuado. El historial de la terminal y `/var/log/secure-vps.log` siguen disponibles.
Al cambiar el puerto se sugiere **24022**, o el siguiente disponible hasta 24121,
comprobando escuchas TCP y UDP. Abre también ese puerto TCP en el cortafuegos de
tu proveedor si lo tiene. Cambiarlo es opcional y no sustituye una clave SSH.

Para fijar una versión concreta:

```bash
curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | KENROKA_VERSION=vX.Y.Z bash
```

Antes de empezar, ten disponible la consola web / de recuperación de tu proveedor y
prepara una segunda terminal en **tu computadora** para la prueba de acceso SSH. La
consola del proveedor sirve para recuperar el VPS; no demuestra que una conexión SSH
nueva desde Internet funcione.

El comando habitual abre el menú inicial con el arte ASCII de Kenroka. Desde él
puedes elegir la guía completa, revisar el estado o abrir las acciones avanzadas.
Para entrar directamente a la guía, añade `--run-all` al ejecutar el script.
También puedes descargarlo y abrir el mismo menú sin argumentos:

```bash
curl -fsSL -o secure-vps.sh \
  https://github.com/all-lopezg/kenroka/releases/latest/download/secure-vps.sh

less secure-vps.sh
sudo bash secure-vps.sh
```

En una ejecución guiada e interactiva, el asistente primero permite elegir español o
inglés. La elección describe a quien administra el VPS, no el locale del servidor.
Para fijarla y omitir esa pregunta, usa `--lang es` o `--lang en`:

```bash
sudo bash secure-vps.sh --lang es
```

¿Quieres el diagnóstico antes de que cambie algo? `--audit` es de solo lectura: quién
puede entrar, qué acepta realmente `sshd`, qué puertos están expuestos y qué falta endurecer. No
escribe ningún archivo y no hace ninguna petición saliente.

```bash
sudo bash secure-vps.sh --audit > auditoria.txt
```


### Interfaz de terminal

En una terminal interactiva, Kenroka presenta pantallas con servidor,
administrador, puerto y estado de la operación. El recorrido tiene **8 pasos**
(incluye las actualizaciones que internamente se llaman fase 2.5).

- El menú usa grupos consecutivos: `1` configuración, `2` revisión, `3`
  recuperación y `4` ayuda. Las acciones aparecen indentadas con subnúmeros:
  `1.1` administrador, `1.2` clave, hasta `1.8` puerto; `2.1` resultado,
  `2.2` auditoría, `2.3` verificación; `3.1` conservar y `3.2` restaurar.
  Escribe el número completo y pulsa Enter. `1` inicia toda la guía; `2` y `3`
  muestran solo su grupo, `b` vuelve al menú completo y `0` sale.
- Las confirmaciones aceptan `1`/`2` o las respuestas habituales `s`/`n`.
  `h` muestra ayuda en confirmaciones, pruebas de acceso y resultados.
- Cada fase muestra su resultado y espera Enter antes de limpiar la vista.
  “Confirmado para esta fase” no certifica el VPS completo. Las tareas parciales,
  la prueba pendiente, los cambios omitidos y las restauraciones se distinguen.
- En una prueba SSH, Enter y pedir ayuda **no confirman ni restauran**. El
  temporizador de protección continúa corriendo mientras decides.
- Los comandos para copiar aparecen en bloques separados, en verde y negrita,
  con la etiqueta “COPIAR Y EJECUTAR” y el lugar donde debes ejecutarlos.
  Copia solo las líneas del comando; no incluyen un prompt `$` o `>`.
- El ancho se recalcula al dibujar. En terminales de menos de 60 columnas se
  eliminan los marcos; los comandos se imprimen en una sola línea lógica, sin `\` añadidas.
  La terminal puede envolver visualmente esa línea según su ancho.
- `--audit`, `--verify`, `--non-interactive`, la salida redirigida y `TERM=dumb`
  conservan una presentación de texto sin pantallas ni marcos. `--experto`
  mantiene las explicaciones breves en la interfaz interactiva.

No hace falta instalar una biblioteca TUI. La presentación usa Bash y las
herramientas del sistema Ubuntu. Las operaciones siguen en el registro
`/var/log/secure-vps.log`; la verificación final guarda su propio reporte.

## Flujo guiado

Cada fase guiada empieza indicando qué cambiará, qué debes hacer ahora y qué
protección queda activa. El recorrido normal es:

1. **Fase 1 — Administrador y sudo:** crear o elegir el administrador no-root que conservará
   el acceso al VPS.
2. **Fase 2 — Clave SSH:** instalar una clave pública para ese administrador. El par se crea
   en tu computadora; al VPS llega solo la línea pública.
3. **Fase 2.5 — Actualizaciones pendientes:** revisar o aplicar actualizaciones mientras el
   acceso original todavía está disponible.
4. **Fase 3 — Hardening de SSH:** primero demostrar que la clave funciona en una sesión SSH
   nueva; después cerrar root y la autenticación por contraseña, y repetir la prueba.
5. **Fase 4 — UFW:** revisar los puertos TCP y UDP que escuchan, activar el cortafuegos y
   repetir la prueba SSH externa porque UFW cambió el camino de red.
6. **Fases 5 y 6 — Fail2ban y actualizaciones automáticas:** configurar las protecciones restantes.
7. **Fase 7 — Cambio opcional de puerto SSH:** conservar el puerto anterior, probar el nuevo
   y quitar el anterior solo después de que la prueba funcione.

### Clave SSH: qué debes entregar

Crea el par de claves en **tu computadora**, por ejemplo con `ssh-keygen -t ed25519`,
y pega el contenido completo del archivo `.pub` correspondiente. Una clave pública
empieza con un tipo como `ssh-ed25519`. Nunca pegues, subas ni copies el archivo
privado (`id_ed25519` sin `.pub`); se queda en tu computadora.

Una cuenta creada en la fase 1 no tiene contraseña SSH. Para esa cuenta nueva, pega
la clave pública cuando se solicite: `ssh-copy-id` normalmente no podrá entrar. Para
una cuenta **existente** cuya contraseña SSH conoces, `ssh-copy-id -p PUERTO
USUARIO@HOST` es una alternativa opcional. Si todavía no tienes una clave utilizable,
el asistente permite volver a ver las instrucciones, continuar con límites SSH no
restrictivos que dejan root y la autenticación por contraseña activos, o salir sin
cambiar el acceso SSH.

## Verificar el hardening aplicado

Al terminar todas las fases, el asistente ofrece una verificación opcional. También
puedes abrirla desde la opción **13** del menú o ejecutarla después:

```bash
sudo bash secure-vps.sh --verify --user miadmin
# Opcional: exigir el puerto y la política sudo elegidos.
sudo bash secure-vps.sh --verify --user miadmin --port 24022 --sudo prompt
```

Comprueba el administrador, la clave y sus permisos, la política sudo efectiva,
SSH y sus puertos de escucha, UFW, el jail y los puertos de Fail2ban, las
actualizaciones automáticas y las reversiones pendientes o fallidas. Cada ejecución
guarda un reporte con fecha, equipo, versión, contexto SSH y resultados en
`/var/lib/secure-vps/reports/`, accesible solo por root (directorio `700`, archivo `600`).
La verificación no aplica configuraciones ni cancela cuentas atrás.

Si todas las comprobaciones técnicas pasan, muestra el comando SSH exacto para abrir
en **otra terminal de tu computadora**. En esa sesión nueva, comprueba el usuario
esperado, ejecuta `whoami && sudo -v && sudo -l` y prueba los servicios que necesitas.
Al volver al asistente, elige `[s]` para marcar la prueba externa como confirmada o
`[n]` para dejar la verificación pendiente. Después de confirmar vuelve a comprobar
el estado técnico. La consola del proveedor es para recuperación y no cuenta como
esta prueba SSH externa. El reporte distingue la declaración de quien opera el VPS
de las comprobaciones del servidor.

| Resultado | Código de salida | Significado |
|---|---|---|
| EXITOSO | `0` | Comprobaciones técnicas aprobadas y prueba externa confirmada. |
| CON PENDIENTES | `2` | Falta la confirmación externa o hay puntos que revisar. |
| CON FALLOS | `1` | Se detectó un fallo o no se pudo completar la verificación. |

`--yes`, `--non-interactive` o una entrada sin terminal nunca confirman la prueba
externa: incluso con todas las comprobaciones técnicas aprobadas, el resultado será
pendiente. Las políticas personalizadas que no se puedan verificar se señalan para
revisión. El resultado corresponde al perfil y contexto SSH mostrados, no certifica
todos los posibles clientes ni la seguridad completa del servidor.

## Qué hace

- Crea un usuario administrador con sudo que sí funciona, con contraseña o NOPASSWD.
- Instala tu clave pública SSH y verifica que `sshd` la acepta, permisos incluidos.
- Revisa las actualizaciones de paquetes pendientes antes de hacer cambios que restrinjan el acceso.
- Aplica límites de SSH como `MaxAuthTries`, `MaxSessions` y `ClientAlive`.
- Desactiva el login de root y la autenticación por contraseña.
- Al cerrar SSH, limita el acceso al usuario administrador elegido (`AllowUsers`); las demás cuentas ya no podrán entrar por SSH.
- Muestra qué puertos TCP **y UDP** quedarían filtrados antes de activar UFW.
- Configura fail2ban y excluye de los bloqueos tu IP actual.
- Activa las actualizaciones automáticas de seguridad.
- Ofrece sacar SSH del puerto 22.
- Verifica la configuración efectiva de SSH antes del cierre definitivo.


### Entrar con un nombre corto

El resumen final y la opción **2.4** del menú explican cómo añadir un alias
`mi-vps` a la configuración SSH de tu computadora. Incluyen instrucciones para
macOS/Linux y Windows/PowerShell, el usuario y puerto efectivos, y el comando
`ssh mi-vps`. Conserva las entradas existentes del archivo `config`; el asistente
solo muestra instrucciones y no modifica archivos locales ni del VPS.


## La red de seguridad

La regla importante es simple:

> No cerrar el acceso SSH sin haber comprobado antes que la configuración nueva funciona.

- Antes de restringir el acceso, `secure-vps` comprueba la configuración efectiva de
  `sshd` y pide una **prueba previa**. Muestra el comando SSH exacto que debe usar
  solo la clave. Si la prueba previa no funciona o no se confirma, la guía se
  detiene antes de cambiar SSH o activar UFW y explica cómo revisar la clave.
  Siguen disponibles las opciones explícitas de endurecimiento parcial.
- Después de cerrar SSH, activar UFW o cambiar el puerto SSH, empieza una cuenta atrás
  de 10 minutos por defecto. Durante esa ventana:
  1. Mantén abierta la terminal original como respaldo.
  2. En otra terminal de **tu computadora**, ejecuta el comando exacto que muestra el asistente.
  3. Comprueba que entra como el administrador elegido; ejecuta
     `whoami && sudo -v && sudo -l` y prueba cada servicio que decidiste mantener público.
  4. Vuelve a la terminal original y elige `[s]` para conservar el cambio o `[n]`
     para restaurar el cambio de acceso.
- Pulsar Enter o escribir una respuesta no reconocida no restaura nada: el asistente
  vuelve a explicar la elección mientras la cuenta atrás sigue activa. Elegir
  restaurar, o no poder confirmar el acceso, restaura el cambio de acceso. Si dejas
  correr la cuenta atrás, también se restaura automáticamente al expirar.
- La cuenta atrás restaura solo SSH, UFW y Fail2ban al estado anterior a esa fase. El
  administrador, la clave pública instalada, sudo y las actualizaciones permanecen.
  Al conservar el cambio, la cuenta atrás se cancela automáticamente.
- Los cambios de SSH, UFW y Fail2ban dejan snapshots; el menú restaura el más reciente que aún no se haya revertido.

Si una cuenta atrás sigue pendiente al pasar a otra fase, su reversión restaura
el estado anterior a esa cuenta atrás, incluidos los cambios posteriores de SSH,
UFW y Fail2ban. Una confirmación que llega después de la reversión se rechaza.

## Requisitos

- Ubuntu **22.04** o **24.04**. Otras versiones de Ubuntu se detectan y se avisa, pero no están cubiertas por la suite de pruebas.
- Acceso root o un `sudo` que funcione.
- Una segunda terminal para probar el acceso SSH.
- Recomendado encarecidamente tener disponible la consola web / de recuperación de
  tu proveedor; úsala para recuperar el VPS, no como prueba SSH externa.

## Verifica la clave de firma

`install.sh` confía en dos claves públicas `ssh-ed25519`: la actual firma las releases
desde v1.3.0 y la anterior verifica las releases históricas.

```
Actual (v1.3.0+): SHA256:H8Dv+fd0O8i6yPVnTlS5WMMs+NuM1/y9YV9Mypf0GoY
Anterior:         SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg
```

No te fíes solo de la copia descargada de la huella: contrástala por un canal
independiente antes de fiarte de la verificación. Desde v1.1.2 las releases se verifican
con el principal `kenroka`; las anteriores usaban el nombre del dueño del repositorio, que
es solo una etiqueta. Si firmas tú las releases:

```bash
ssh-keygen -lf ~/.ssh/kenroka_sign.pub
```

## Lo que no hace

- No pipea el script principal en `bash`. El script necesita entrada interactiva, así que primero se descarga y se verifica.
- Revertir restaura la configuración de SSH, UFW y fail2ban. **No** deshace las actualizaciones de paquetes ni la creación de cuentas o cambios de contraseña, grupos y `sudoers`; tampoco elimina la clave pública instalada.
- `--audit` reporta la configuración tal como está. No es una auditoría de seguridad: si el servidor ya está comprometido, trátalo como comprometido — endurecerlo después no establece confianza.
- Nunca genera un par de claves en el servidor. La parte privada no debería existir ahí.

## Automatización

```bash
sudo bash secure-vps.sh --help
```

| Opción | Significado |
|---|---|
| `--non-interactive` | Para Ansible o CI. Al aplicar hardening exige `--user`, `--pubkey-file` y `--sudo`. |
| `--skip-lockdown` | Prepara el servidor sin el cierre de acceso definitivo. |
| `--allow-lockdown` | Cierra el acceso sin la confirmación humana. Úsalo entendiendo las implicaciones de recuperación. |
| `--upgrade` / `--no-upgrade` | Aplicar, o solo reportar, las actualizaciones pendientes. |
| `--lang es\|en` | Elige el idioma de la interfaz y omite la pregunta de idioma del asistente guiado. |
| `--audit` | Reporte de estado de solo lectura: qué está abierto, qué está expuesto y qué correr después. |
| `--verify --user NOMBRE` | Verificación posterior con reporte privado; códigos `0` exitoso, `2` pendiente, `1` fallo. |

> El cierre automatizado puede dejarte sin acceso SSH si la configuración resultante es incorrecta.

## Pruebas

La suite corre el script contra systemd real en contenedor, en Ubuntu 22.04 y 24.04.
Cubre el cierre y el rollback, la cuenta atrás disparando de verdad, el cambio de
puerto y sus conflictos, la idempotencia byte a byte, el flujo guiado de primera
vez con pruebas reales de acceso externo solo por clave, el aviso de puertos UDP,
el rescate desde el menú y la verificación final con confirmación humana, permisos
del reporte y detección de servicios caídos.

- **22** escenarios end-to-end
- **345** asertos unitarios
- **17** asertos del instalador, incluido rechazar un archivo manipulado y una firma de otra mano

```bash
./tests/run.sh unit
./tests/docker/run.sh --distro 24.04
./tests/docker/run.sh --distro 22.04
```

## Licencia

Pendiente de elegir. Hasta que se publique una licencia explícita, todos los derechos reservados.
