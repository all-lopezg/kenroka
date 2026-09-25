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
ejecutar nada.

Para fijar una versión concreta:

```bash
KENROKA_VERSION=vX.Y.Z curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
```

Antes de empezar: ten abierta la consola web de tu proveedor y prepara una segunda
terminal para la prueba de acceso SSH.

El one-liner lanza directo el asistente guiado. Si prefieres elegir fases sueltas, o
ver el estado sin cambiar nada, descarga el script y corrélo sin argumentos: el menú
ofrece las 12 acciones.

```bash
curl -fsSL -o secure-vps.sh \
  https://github.com/all-lopezg/kenroka/releases/latest/download/secure-vps.sh

less secure-vps.sh
sudo bash secure-vps.sh
```
¿Quieres el diagnóstico antes de que cambie algo? `--audit` es de solo lectura: quién
puede entrar, qué acepta realmente `sshd`, qué puertos están expuestos y qué falta endurecer. No
escribe ningún archivo y no hace ninguna petición saliente.

```bash
sudo bash secure-vps.sh --audit > auditoria.txt
```

## Qué hace

- Crea un usuario administrador con sudo que sí funciona, con contraseña o NOPASSWD.
- Instala tu clave pública SSH y verifica que `sshd` la acepta, permisos incluidos.
- Revisa las actualizaciones de paquetes pendientes antes de hacer cambios que restrinjan el acceso.
- Aplica límites de SSH como `MaxAuthTries`, `MaxSessions` y `ClientAlive`.
- Desactiva el login de root y la autenticación por contraseña.
- Muestra qué puertos TCP **y UDP** quedarían filtrados antes de activar UFW.
- Configura fail2ban y excluye de los bloqueos tu IP actual.
- Activa las actualizaciones automáticas de seguridad.
- Ofrece sacar SSH del puerto 22.
- Verifica la configuración efectiva de SSH antes del cierre definitivo.

## La red de seguridad

La regla importante es simple:

> No cerrar el acceso SSH sin haber comprobado antes que la configuración nueva funciona.

- Antes de restringir el acceso, `secure-vps` comprueba la configuración efectiva de `sshd`.
- Al empezar el cierre arranca una cuenta atrás: 10 minutos por defecto. Durante esa ventana:
  1. Abre una sesión SSH nueva desde otra terminal.
  2. Comprueba que puedes entrar con normalidad.
  3. Vuelve a la sesión original.
  4. Confirma el acceso nuevo escribiendo `acceso-ok`.
- Si la confirmación no llega antes de que expire la cuenta atrás, los cambios se revierten solos.
- Cada cambio deja un snapshot, y el menú tiene una opción para restaurar el último.

`acceso-ok` es el token literal en los dos idiomas: nunca se traduce, así que las
instrucciones siempre piden la misma palabra.

## Requisitos

- Ubuntu **22.04** o **24.04**. Otras versiones de Ubuntu se detectan y se avisa, pero no están cubiertas por la suite de pruebas.
- Acceso root o un `sudo` que funcione.
- Una segunda terminal para probar el acceso SSH.
- Recomendado encarecidamente tener disponible la consola web / de recuperación de tu proveedor.

## Verifica la clave de firma

`install.sh` lleva embebida una clave pública `ssh-ed25519` con la que se verifican las releases. Su huella:

```
256  SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg  kenroka-release (ED25519)
```

No te fíes solo de la copia descargada de la huella: contrástala por un canal
independiente antes de fiarte de la verificación. Si firmas tú las releases:

```bash
ssh-keygen -lf ~/.ssh/kenroka_sign.pub
```

## Lo que no hace

- No pipea el script principal en `bash`. El script necesita entrada interactiva, así que primero se descarga y se verifica.
- Revertir restaura la configuración de SSH, UFW y fail2ban. **No** deshace las actualizaciones de paquetes ni borra la clave pública que instaló.
- `--audit` reporta la configuración tal como está. No es una auditoría de seguridad: si el servidor ya está comprometido, trátalo como comprometido — endurecerlo después no establece confianza.
- Nunca genera un par de claves en el servidor. La parte privada no debería existir ahí.

## Automatización

```bash
sudo bash secure-vps.sh --help
```

| Opción | Significado |
|---|---|
| `--non-interactive` | Para Ansible o CI. Exige `--user`, `--pubkey-file` y `--sudo`. |
| `--skip-lockdown` | Prepara el servidor sin el cierre de acceso definitivo. |
| `--allow-lockdown` | Cierra el acceso sin la confirmación humana. Úsalo entendiendo las implicaciones de recuperación. |
| `--upgrade` / `--no-upgrade` | Aplicar, o solo reportar, las actualizaciones pendientes. |
| `--lang es\|en` | Fuerza el idioma detectado. |
| `--audit` | Reporte de estado de solo lectura: qué está abierto, qué está expuesto y qué correr después. |

> El cierre automatizado puede dejarte sin acceso SSH si la configuración resultante es incorrecta.

## Pruebas

La suite corre el script contra systemd real en contenedor, en Ubuntu 22.04 y 24.04.
Cubre el cierre y el rollback, la cuenta atrás disparando de verdad, el cambio de
puerto y sus conflictos, la idempotencia byte a byte, el flujo guiado de primera
vez, el aviso de puertos UDP y el rescate desde el menú.

- **19** escenarios end-to-end
- **213** asertos unitarios
- **9** asertos del instalador, incluido rechazar un archivo manipulado y una firma de otra mano

```bash
./tests/run.sh unit
./tests/docker/run.sh --distro 24.04
./tests/docker/run.sh --distro 22.04
```

## Licencia

Pendiente de elegir. Hasta que se publique una licencia explícita, todos los derechos reservados.
