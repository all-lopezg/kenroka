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
curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | KENROKA_VERSION=vX.Y.Z bash
```

Before you start, keep your provider's recovery / web console available and have a
second terminal on **your computer** ready for the SSH access test. The provider
console is a recovery path; it does not prove that a new SSH connection from the
Internet works.

The one-liner launches the guided assistant directly. If you prefer to choose
individual phases, or to inspect the current state without making changes, download
the script and run it without arguments — the menu provides all 13 actions:

```bash
curl -fsSL -o secure-vps.sh \
  https://github.com/all-lopezg/kenroka/releases/latest/download/secure-vps.sh

less secure-vps.sh
sudo bash secure-vps.sh
```

In an interactive guided run, the assistant first lets you choose Spanish or
English. The choice describes the person operating the VPS, not the server locale.
To select it explicitly and skip that question, use `--lang es` or `--lang en`:

```bash
sudo bash secure-vps.sh --lang en
```

Want the diagnosis before anything changes? `--audit` is read-only: who can log in,
what `sshd` actually accepts, which ports are exposed, what is still missing. It writes no
file and makes no outbound request.

```bash
sudo bash secure-vps.sh --audit > audit.txt
```

## Guided flow

Every guided phase starts by stating what will change, what you need to do now, and
which protection remains in place. The normal path is:

1. **Phase 1 — Administrator and sudo:** create or select the non-root administrator that
   will keep access to the VPS.
2. **Phase 2 — SSH key:** install a public key for that administrator. The key pair is made
   on your computer; the VPS receives only the public line.
3. **Phase 2.5 — Pending updates:** review or apply package updates while the original access
   is still available.
4. **Phase 3 — SSH hardening:** first prove the key works in a new SSH session, then close
   root and password authentication and repeat the same test.
5. **Phase 4 — UFW:** review the listening TCP and UDP ports, enable the firewall, and repeat
   the external SSH test because the firewall has changed the network path.
6. **Phase 5 and 6 — Fail2ban and automatic updates:** configure the remaining protections.
7. **Phase 7 — Optional SSH port change:** keep the old port open, test the new one, then
   remove the old port only after the test succeeds.

### SSH key: what to provide

Create the key pair on **your computer**, for example with `ssh-keygen -t ed25519`,
then paste the complete contents of the matching `.pub` file. A public key begins
with a type such as `ssh-ed25519`. Never paste, upload, or copy the private file
(`id_ed25519` without `.pub`); it stays on your computer.

An account created in phase 1 has no SSH password. For that new account, paste the
public key when prompted: `ssh-copy-id` normally cannot log in to it. For an
**existing** account whose SSH password you know, `ssh-copy-id -p PORT USER@HOST`
is an optional alternative. If you do not yet have a usable key, the guided prompt
lets you review the instructions, continue with non-restrictive SSH limits that
leave root and password authentication enabled, or stop without changing SSH access.

## Verify the applied hardening

After all phases finish, the assistant offers an optional verification. You can
also select menu option **13** or run it later:

```bash
sudo bash secure-vps.sh --verify --user myadmin
# Optional: require the chosen port and sudo policy.
sudo bash secure-vps.sh --verify --user myadmin --port 2222 --sudo prompt
```

It checks the administrator, key and permissions, effective sudo policy, SSH and
its listening ports, UFW, the Fail2ban jail and action ports, automatic updates,
and pending or failed rollbacks. Each run saves a report with the date, host,
version, SSH context and results in `/var/lib/secure-vps/reports/`, accessible only
to root (directory `700`, file `600`). Verification does not apply configuration
or cancel countdowns.

If all technical checks pass, it prints the exact SSH command to run in **another
terminal on your computer**. In that new session, verify the expected user and run
`whoami && sudo -v && sudo -l`, then check the services you need. Back in the
assistant, choose `[y]` to mark the external test confirmed or `[n]` to leave the
verification pending. It checks the technical state again after a confirmation.
The provider console is for recovery and does not count as this external SSH test.
The report distinguishes the operator's declaration from the server checks.

| Result | Exit code | Meaning |
|---|---|---|
| SUCCESSFUL | `0` | Technical checks passed and the external test was confirmed. |
| PENDING | `2` | External confirmation is missing or some items need review. |
| FAILED | `1` | A failure was detected or verification could not complete. |

`--yes`, `--non-interactive` or input without a terminal never confirm the external
test: even when all technical checks pass, the result remains pending. Custom
policies that cannot be verified are flagged for review. The result covers the
displayed profile and SSH context; it does not certify every possible client or
the server's overall security.

## What it does

- Creates a working administrative user with sudo, using either a password or NOPASSWD.
- Installs your SSH public key and verifies that `sshd` accepts it, including file permissions.
- Checks for pending package updates before making access-restricting changes.
- Applies SSH security limits such as `MaxAuthTries`, `MaxSessions` and `ClientAlive`.
- Disables root login and password authentication.
- When locking down SSH, restricts access to the selected admin user with `AllowUsers`; other accounts can no longer log in over SSH.
- Shows which TCP **and UDP** ports would be filtered before enabling UFW.
- Configures fail2ban and excludes your current IP from bans.
- Enables automatic security updates.
- Offers to move SSH away from port 22.
- Verifies the effective SSH configuration before applying the final lockdown.

## The safety net

The most important rule is simple:

> Never lock down SSH without first verifying that the new configuration works.

- Before restricting access, `secure-vps` checks the effective `sshd` configuration
  and asks for a **pre-check**. It prints the exact key-only SSH command. If the
  pre-check does not work, root and password authentication stay enabled and only
  non-restrictive SSH limits can be applied.
- After SSH is closed, UFW is enabled, or the SSH port changes, a 10-minute
  countdown starts by default. During that window:
  1. Keep the original terminal open as the backup.
  2. In another terminal on **your computer**, run the exact command shown by the assistant.
  3. Confirm that it logs in as the selected administrator, then run
     `whoami && sudo -v && sudo -l` and test any service you deliberately kept public.
  4. Return to the original terminal and choose `[y]` to keep the change or `[n]`
     to restore the access change.
- Pressing Enter or entering an unrecognised answer does not restore anything; the
  assistant explains the choice again while the countdown remains active. Choosing
  restore, or failing to confirm access, restores the access change. Leaving the
  countdown alone also restores it automatically when it expires.
- The countdown restores only SSH, UFW and Fail2ban to their state before that
  phase. The administrator, installed public key, sudo configuration and package
  updates remain in place. Keeping the change cancels the countdown automatically.
- SSH, UFW and Fail2ban changes create snapshots; the menu restores the latest one that has not already been reverted.

If a countdown is still pending when another phase runs, its rollback restores
the state from before that countdown, including later SSH, UFW and fail2ban
changes. A confirmation arriving after rollback is rejected.

## Requirements

- Ubuntu **22.04** or **24.04**. Other Ubuntu versions are detected and reported, but are not covered by the test suite.
- Root access or working `sudo`.
- A second terminal for testing SSH access.
- Keeping your provider's recovery / web console available is strongly recommended;
  use it to recover a VPS, not as the external SSH test.

## Verify the signing key

`install.sh` trusts two `ssh-ed25519` public keys: the current key signs releases
from v1.3.0 onward, and the previous key verifies historical releases.

```
Current (v1.3.0+): SHA256:H8Dv+fd0O8i6yPVnTlS5WMMs+NuM1/y9YV9Mypf0GoY
Previous:          SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg
```

Do not rely solely on the downloaded copy of the fingerprint: compare it through an
independent channel before trusting the verification. Releases from v1.1.2 up verify under
the principal `kenroka`; earlier ones used the repository owner, which is only a label.
If you sign releases yourself:

```bash
ssh-keygen -lf ~/.ssh/kenroka_sign.pub
```

## What it does not do

- It does not pipe the main script into `bash`. The script needs interactive input, so it is downloaded and verified first.
- Reverting restores the SSH, UFW and fail2ban configuration. It does **not** undo package updates or account creation, password, group or sudoers changes, and it does **not** remove the installed public key.
- `--audit` reports the configuration as it stands. It is not a security audit: if the server is already compromised, treat it as compromised — hardening it afterwards does not establish trust.
- It never generates a key pair on the server. The private half should never exist there.

## Automation

```bash
sudo bash secure-vps.sh --help
```

| Option | Meaning |
|---|---|
| `--non-interactive` | For Ansible or CI. Applying hardening requires `--user`, `--pubkey-file` and `--sudo`. |
| `--skip-lockdown` | Prepares the server without the final access lockdown. |
| `--allow-lockdown` | Locks down without the human confirmation. Understand the recovery implications first. |
| `--upgrade` / `--no-upgrade` | Apply, or only report, pending package updates. |
| `--lang es\|en` | Select the interface language explicitly and skip the guided language question. |
| `--audit` | Read-only state report: what is open, what is exposed, what to run next. |
| `--verify --user NAME` | Post-hardening verification with a private report; exit codes `0` successful, `2` pending, `1` failed. |

> Automated lockdown can leave you without SSH access if the resulting configuration is wrong.

## Testing

The suite runs the script against real systemd inside containers, on Ubuntu 22.04 and
24.04. It covers lockdown and rollback, the access countdown firing for real, port
changes and conflicts, byte-exact idempotency, the guided first-run flow including
real key-only external access checks, UDP warnings, recovery through the menu, the
read-only mode leaving no trace on disk, and final verification with human
confirmation, report permissions and stopped-service detection.

- **22** end-to-end scenarios
- **345** unit assertions
- **17** installer assertions, including refusing a tampered file and a foreign signature

```bash
./tests/run.sh unit
./tests/docker/run.sh --distro 24.04
./tests/docker/run.sh --distro 22.04
```

## License

To be chosen. Until a license is explicitly published, all rights are reserved.
