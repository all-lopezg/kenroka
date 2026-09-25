# secure-vps

```
 ██╗  ██╗███████╗███╗   ██╗██████╗  ██████╗  ██╗  ██╗ █████╗
 ██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██╔═══██╗ ██║ ██╔╝██╔══██╗
 █████╔╝ █████╗  ██╔██╗ ██║██████╔╝██║   ██║ █████╔╝ ███████║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██╔══██╗██║   ██║ ██╔═██╗ ██╔══██║
 ██║  ██╗███████╗██║ ╚████║██║  ██║╚██████╔╝ ██║  ██╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝
```

**ES ·** Endurece un VPS Ubuntu sin que te quedes fuera del servidor.
**EN ·** Hardens an Ubuntu VPS without locking you out of it.

---

## Cómo se usa / Quickstart

```bash
curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
```

**ES ·** La URL no lleva versión: se baja siempre la última release publicada, y el
instalador te dice qué versión resolvió y que su firma es válida. Para congelar una
flota en una versión, añade `KENROKA_VERSION=vX.Y.Z` antes del `curl`.
Necesitas una terminal interactiva (el asistente te va pidiendo cosas) y conviene
tener abierta la consola web de tu proveedor en el navegador.

**ES ·** Ese one-liner entra **directo al asistente guiado**, fase por fase. Si
prefieres elegir tú qué fase correr, o ver el estado sin cambiar nada, baja el
script y córrelo sin argumentos: abre un menú con las 11 opciones.

**EN ·** That one-liner goes **straight to the guided assistant**, phase by phase.
To pick individual phases, or to see the state without changing anything, download
the script and run it with no arguments: it opens a menu with the 11 options.

**EN ·** The URL carries no version: it always fetches the latest published release,
and the installer tells you which version it resolved and that the signature is
valid. To pin a fleet, prefix `KENROKA_VERSION=vX.Y.Z`. You need an interactive
terminal (the assistant asks you things) and it helps to have your provider's web
console open in the browser.

**ES ·** `install.sh` descarga el script, verifica su firma contra la clave pública
publicada aquí, y entonces lo arranca. Puedes leer todo antes de ejecutarlo:

```bash
curl -fsSL -o secure-vps.sh https://github.com/all-lopezg/kenroka/releases/latest/download/secure-vps.sh
less secure-vps.sh            # léelo
sudo bash secure-vps.sh       # y entonces corre
```

**EN ·** `install.sh` downloads the script, verifies its signature against the public
key published here, and only then runs it. You can read everything first.

## Qué hace / What it does

**ES**
1. Crea un usuario administrador con sudo que sí funciona (contraseña o NOPASSWD).
2. Instala tu clave pública SSH y comprueba que sshd la acepta (permisos incluidos).
3. Dice al empezar cuántos paquetes faltan y, si aceptas, los aplica **antes** de cerrar
   el acceso: si un `apt upgrade` rompe algo, todavía puedes entrar con contraseña.
4. Aplica límites de seguridad (MaxAuthTries, MaxSessions, ClientAlive, etc.).
5. Desactiva el login de root y la autenticación por contraseña.
6. Activa UFW avisando antes qué puertos TCP y UDP quedarían filtrados.
7. Configura fail2ban con tu IP excluida del bloqueo.
8. Activa las actualizaciones automáticas de seguridad.
9. Recomienda sacar SSH del puerto 22 y, si aceptas, lo hace sin cortarte el acceso.

**EN**
1. Creates an admin user with sudo that actually works (password or NOPASSWD).
2. Installs your SSH public key and checks sshd accepts it (permissions included).
3. Reports up front how many packages are pending and, if you agree, applies them
   **before** locking down: if an `apt upgrade` breaks something, password access works.
4. Applies security limits (MaxAuthTries, MaxSessions, ClientAlive, etc.).
5. Disables root login and password authentication.
6. Enables UFW, warning which TCP and UDP ports would be filtered first.
7. Sets up fail2ban with your IP excluded from banning.
8. Turns on automatic security updates.
9. Recommends moving SSH off port 22 and, if you agree, does it without cutting you off.

## La red de seguridad / The safety net

**ES** Antes de cerrar el acceso se comprueba la configuración *efectiva* de sshd. Al
cerrarlo arranca una cuenta atrás (10 minutos por defecto): si no escribes `acceso-ok`
tras probar una conexión nueva desde otra sesión, **todo vuelve atrás solo**. Cada
cambio deja un snapshot, y el menú tiene una opción para revertir al último.

**EN** Before locking down, the *effective* sshd configuration is verified. Locking
down starts a countdown (10 minutes by default): unless you type `access-ok` after
testing a new connection from another session, **everything reverts on its own**.
Every change leaves a snapshot, and the menu can revert to the latest one.

## Requisitos / Requirements

- **ES ·** Ubuntu 22.04 o 24.04 (otras versiones: avisa, no las prueba). Root o `sudo`.
- **EN ·** Ubuntu 22.04 or 24.04 (other versions: it warns, it does not test them). Root or `sudo`.
- **ES ·** Una segunda terminal en tu computadora para la prueba de acceso.
- **EN ·** A second terminal on your computer for the access test.

## Verificar la clave de firma / Verifying the signing key

**ES ·** `install.sh` lleva embebida una clave pública `ssh-ed25519`. Su huella es:

```
256 SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg  kenroka-release (ED25519)
```

Contrástala por un canal distinto al de la descarga antes de fiarte de ninguna
verificación: `ssh-keygen -lf ~/.ssh/kenroka_sign.pub` en tu máquina si firmas tú
mismo las releases.

**EN ·** `install.sh` embeds an `ssh-ed25519` public key with the fingerprint above.
Compare it through a channel other than the download before trusting any verification.

## No hace / What it does not do

- **ES ·** No ejecuta `curl | bash` del script principal: necesita preguntarte cosas y
  por eso se descarga primero.
- **EN ·** It does not support piping the main script into bash: it must ask you things.
- **ES ·** Revertir deshace SSH, UFW y fail2ban; **no** deshace las actualizaciones
  automáticas ni borra la clave pública que instaló.
- **EN ·** Reverting undoes SSH, UFW and fail2ban; it does **not** undo automatic
  updates or remove the public key it installed.
- **ES ·** No es una auditoría ni reemplaza a las claves: un servidor ya comprometido
  sigue comprometido.
- **EN ·** It is not an audit and it is no substitute for keys: an already compromised
  server stays compromised.

## Opciones y automatización / Options and automation

`sudo bash secure-vps.sh --help` lista las opciones, incluido `--non-interactive` para
Ansible o CI. `--skip-lockdown` prepara todo sin cerrar el acceso; `--allow-lockdown`
lo cierra sin prueba humana y es lo que hay que usar sabiendo que puede dejarte fuera.

## Probar los cambios / Testing the changes

**ES ·** La suite corre el script contra systemd real en contenedor, en Ubuntu 22.04 y
24.04: 17 escenarios de extremo a extremo (cierre de acceso, cuenta atrás, cambio de
puerto, idempotencia, flujo de novato, rescate por el menú) y 101 asertos unitarios.

```bash
./tests/run.sh unit
./tests/docker/run.sh --distro 24.04
./tests/docker/run.sh --distro 22.04
```

**EN ·** The suite runs the script against real systemd in containers, on Ubuntu 22.04
and 24.04: 17 end-to-end scenarios and 101 unit assertions.

## Licencia / License

Pendiente de elegir. Hasta entonces, todos los derechos reservados.
To be chosen. Until then, all rights reserved.
