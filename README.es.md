<div align="center">

```
 ██╗  ██╗███████╗███╗   ██╗██████╗  ██████╗  ██╗  ██╗ █████╗
 ██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██╔═══██╗ ██║ ██╔╝██╔══██╗
 █████╔╝ █████╗  ██╔██╗ ██║██████╔╝██║   ██║ █████╔╝ ███████║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██╔══██╗██║   ██║ ██╔═██╗ ██╔══██║
 ██║  ██╗███████╗██║ ╚████║██║  ██║╚██████╔╝ ██║  ██╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Endurece un VPS Ubuntu sin dejarte fuera.**

[English](README.md) · **Español**

</div>

---

Compraste un VPS. Esto cierra las puertas que vienen abiertas por defecto —el
acceso por contraseña, el root, un cortafuegos sin reglas, sin fail2ban y sin
actualizaciones— y se niega a cerrar ninguna hasta tener prueba de que sigues
pudiendo entrar.

## Instalación

```bash
curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
```

La URL no lleva versión: baja siempre la última release publicada. `install.sh`
descarga el script, verifica la firma de su checksum contra la clave del
mantenedor, te dice qué versión resolvió y solo entonces lo ejecuta —con tu
terminal conectada, porque el asistente te va preguntando cosas.

¿Prefieres leerlo antes de correrlo?

```bash
curl -fsSL -o secure-vps.sh https://github.com/all-lopezg/kenroka/releases/latest/download/secure-vps.sh
less secure-vps.sh
sudo bash secure-vps.sh        # abre un menú con cada fase suelta
```

## Por qué no te va a dejar fuera

- **Tu clave se verifica, no se da por hecha.** Instala la pública, comprueba que
  `sshd` la acepta y corrige los permisos de `StrictModes` que suelen hacer que una
  clave correcta se ignore en silencio.
- **Nada se cierra hasta que confirmes desde una segunda sesión.** Imprime el
  comando `ssh` exacto; lo corres en otra ventana y escribes `acceso-ok`. Cualquier
  otra cosa revierte al instante.
- **Hay una cuenta atrás corriendo mientras pruebas.** Si te vas, o si la
  confirmación nunca llega, SSH, UFW y fail2ban vuelven atrás solos en 10 minutos.
- **Cada cambio deja un snapshot**, y el menú permite revertir al último.
- **Desde la consola web del proveedor no cierra el acceso.** Desde ahí no hay
  forma de probar una conexión SSH nueva, así que aplica todo menos el cierre y te
  dice qué correr después.

## Qué hace

1. Crea un usuario administrador con sudo que sí funciona (contraseña o NOPASSWD).
2. Instala y verifica tu clave pública SSH.
3. Reporta las actualizaciones pendientes y las aplica **antes** de cerrar el acceso.
4. Aplica límites de SSH (`MaxAuthTries`, `MaxSessions`, `ClientAliveInterval`…).
5. Desactiva el login de root y la autenticación por contraseña.
6. Activa UFW enseñando antes qué puertos TCP **y UDP** dejaría filtrados.
7. Configura fail2ban con la IP de tus sesiones abiertas excluida del bloqueo.
8. Activa las actualizaciones automáticas y recomienda sacar SSH del puerto 22.

Es idempotente: si lo corres dos veces, te dice qué encontró ya hecho.

## Requisitos

Ubuntu **22.04** o **24.04** · root o `sudo` · una segunda terminal en tu
computadora para la prueba de acceso · la consola web de tu proveedor abierta como
respaldo. Otras versiones de Ubuntu continúan con aviso explícito; otras
distribuciones no están soportadas.

## Opciones que importan

| | |
|---|---|
| `--user NOMBRE` | usuario administrador a crear o usar. Sin valor por defecto. |
| `--pubkey-file RUTA` | tu clave pública. Evita que aparezca en `ps`. |
| `--run-all` | corrida guiada, fase por fase. Es lo que hace el instalador. |
| `--skip-lockdown` | todo menos cerrar el acceso. |
| `--allow-lockdown` | cierra el acceso sin la prueba humana. Puedes quedarte fuera. |
| `--non-interactive` | para Ansible/CI; exige `--user`, `--pubkey-file`, `--sudo`. |
| `--upgrade` / `--no-upgrade` | aplicar, o solo reportar, lo pendiente. |
| `--lang es\|en` | fuerza el idioma detectado. |

`--help` lista todo.

## Lo que no hace

No sustituye a guardar bien tu clave privada, no es una auditoría y no rescata una
máquina ya comprometida. Revertir deshace SSH, UFW y fail2ban; **no** deshace las
actualizaciones de paquetes ni borra la clave pública que instaló. Nunca genera un
par de claves en el servidor: la parte privada no debería existir ahí.

## Verifica lo que bajaste

`install.sh` lleva embebida esta clave de firma. Contrasta su huella por un canal
distinto al de la descarga:

```
256  SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg  kenroka-release (ED25519)
```

```bash
ssh-keygen -Y verify -f allowed_signers -I all-lopezg -n file \
    -s SHA256SUMS.txt.sig < SHA256SUMS.txt
```

## Pruebas

Lo de arriba no es una promesa, es lo que comprueba la suite:

- **18 escenarios end-to-end** contra systemd real en contenedor, en Ubuntu 24.04
  y 22.04: cierre de acceso, la cuenta atrás disparando de verdad, cambio de puerto
  y conflictos, idempotencia y rollback byte a byte, los flujos de novato, el aviso
  de puertos UDP y el rescate desde el menú.
- **134 asertos unitarios** sobre la lógica pura y **9** sobre el instalador,
  incluido que rechaza un archivo manipulado y una firma de otra mano.

```bash
./tests/run.sh unit
./tests/docker/run.sh --distro 24.04
./tests/docker/run.sh --distro 22.04
```

## Licencia

Pendiente de elegir. Hasta entonces, todos los derechos reservados.
