# secure-vps

<div align="center">

**Harden an Ubuntu VPS without locking yourself out.**

:gb: English &nbsp;·&nbsp; **[ :es: Español ](README.es.md)**

```
 ██╗  ██╗███████╗███╗   ██╗██████╗  ██████╗  ██╗  ██╗ █████╗
 ██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██╔═══██╗ ██║ ██╔╝██╔══██╗
 █████╔╝ █████╗  ██╔██╗ ██║██████╔╝██║   ██║ █████╔╝ ███████║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██╔══██╗██║   ██║ ██╔═██╗ ██╔══██║
 ██║  ██╗███████╗██║ ╚████║██║  ██║╚██████╔╝ ██║  ██╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝
```

</div>

## Quickstart

```bash
curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
```

The URL is intentionally unversioned: it always resolves to the latest published
release. The installer verifies the release signature and tells you which version it
resolved before running anything.

To pin a specific version:

```bash
KENROKA_VERSION=vX.Y.Z curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
```

Before you start: keep your provider's web console open, and have a second terminal
ready for the SSH access test.

The one-liner launches the guided assistant directly. If you prefer to choose
individual phases, or to inspect the current state without making changes, download
the script and run it without arguments — the menu provides all 12 actions:

```bash
curl -fsSL -o secure-vps.sh \
  https://github.com/all-lopezg/kenroka/releases/latest/download/secure-vps.sh

less secure-vps.sh
sudo bash secure-vps.sh
```
Want the diagnosis before anything changes? `--audit` is read-only: who can log in,
what `sshd` actually accepts, which ports are exposed, what is still missing. It writes no
file and makes no outbound request.

```bash
sudo bash secure-vps.sh --audit > audit.txt
```

## What it does

- Creates a working administrative user with sudo, using either a password or NOPASSWD.
- Installs your SSH public key and verifies that `sshd` accepts it, including file permissions.
- Checks for pending package updates before making access-restricting changes.
- Applies SSH security limits such as `MaxAuthTries`, `MaxSessions` and `ClientAlive`.
- Disables root login and password authentication.
- Shows which TCP **and UDP** ports would be filtered before enabling UFW.
- Configures fail2ban and excludes your current IP from bans.
- Enables automatic security updates.
- Offers to move SSH away from port 22.
- Verifies the effective SSH configuration before applying the final lockdown.

## The safety net

The most important rule is simple:

> Never lock down SSH without first verifying that the new configuration works.

- Before restricting access, `secure-vps` checks the effective `sshd` configuration.
- Once lockdown begins, a countdown starts — 10 minutes by default. During that window:
  1. Open a new SSH session from another terminal.
  2. Verify that you can log in normally.
  3. Return to the original session.
  4. Confirm the new access by typing `acceso-ok`.
- If the confirmation never arrives before the countdown expires, the changes are reverted automatically.
- Every change creates a snapshot, and the menu includes an option to restore the latest one.

`acceso-ok` is the literal token in both languages: it is never translated, so the
instructions always ask for the same word.

## Requirements

- Ubuntu **22.04** or **24.04**. Other Ubuntu versions are detected and reported, but are not covered by the test suite.
- Root access or working `sudo`.
- A second terminal for testing SSH access.
- Keeping your provider's recovery / web console available is strongly recommended.

## Verify the signing key

`install.sh` contains an embedded `ssh-ed25519` public key used to verify releases. Its fingerprint is:

```
256  SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg  kenroka-release (ED25519)
```

Do not rely solely on the downloaded copy of the fingerprint: compare it through an
independent channel before trusting the verification. If you sign releases yourself:

```bash
ssh-keygen -lf ~/.ssh/kenroka_sign.pub
```

## What it does not do

- It does not pipe the main script into `bash`. The script needs interactive input, so it is downloaded and verified first.
- Reverting restores the SSH, UFW and fail2ban configuration. It does **not** undo package updates, and it does **not** remove the public key the tool installed.
- `--audit` reports the configuration as it stands. It is not a security audit: if the server is already compromised, treat it as compromised — hardening it afterwards does not establish trust.
- It never generates a key pair on the server. The private half should never exist there.

## Automation

```bash
sudo bash secure-vps.sh --help
```

| Option | Meaning |
|---|---|
| `--non-interactive` | For Ansible or CI. Requires `--user`, `--pubkey-file` and `--sudo`. |
| `--skip-lockdown` | Prepares the server without the final access lockdown. |
| `--allow-lockdown` | Locks down without the human confirmation. Understand the recovery implications first. |
| `--upgrade` / `--no-upgrade` | Apply, or only report, pending package updates. |
| `--lang es\|en` | Override the detected language. |
| `--audit` | Read-only state report: what is open, what is exposed, what to run next. |

> Automated lockdown can leave you without SSH access if the resulting configuration is wrong.

## Testing

The suite runs the script against real systemd inside containers, on Ubuntu 22.04 and
24.04. It covers lockdown and rollback, the access countdown firing for real, port
changes and conflicts, byte-exact idempotency, the guided first-run flow, UDP warnings,
recovery through the menu, and the read-only mode leaving no trace on disk.

- **19** end-to-end scenarios
- **213** unit assertions
- **9** installer assertions, including refusing a tampered file and a foreign signature

```bash
./tests/run.sh unit
./tests/docker/run.sh --distro 24.04
./tests/docker/run.sh --distro 22.04
```

## License

To be chosen. Until a license is explicitly published, all rights are reserved.
