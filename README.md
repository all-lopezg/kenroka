<div align="center">

```
 ██╗  ██╗███████╗███╗   ██╗██████╗  ██████╗  ██╗  ██╗ █████╗
 ██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██╔═══██╗ ██║ ██╔╝██╔══██╗
 █████╔╝ █████╗  ██╔██╗ ██║██████╔╝██║   ██║ █████╔╝ ███████║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██╔══██╗██║   ██║ ██╔═██╗ ██╔══██║
 ██║  ██╗███████╗██║ ╚████║██║  ██║╚██████╔╝ ██║  ██╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Hardens an Ubuntu VPS without locking you out.**

English · **[Español](README.es.md)**

</div>

---

You bought a VPS. This closes the doors that are open by default — password
login, root, an unfiltered firewall, no fail2ban, no security updates — and it
refuses to close any of them until it has proof you can still get in.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash
```

The URL carries no version: it always fetches the latest published release.
`install.sh` downloads the script, verifies the signature of its checksum
against the maintainer key, prints the version it resolved, and only then runs
it — with your terminal attached, because the assistant asks you things.

Prefer to read before running?

```bash
curl -fsSL -o secure-vps.sh https://github.com/all-lopezg/kenroka/releases/latest/download/secure-vps.sh
less secure-vps.sh
sudo bash secure-vps.sh        # opens a menu of individual phases
```

## Why it won't lock you out

- **Your key is verified, not assumed.** It installs the public key, checks
  `sshd` accepts it, and fixes the `StrictModes` permissions that usually make a
  working key silently ignored.
- **Nothing closes until you confirm from a second session.** It prints the exact
  `ssh` command; you run it elsewhere and type `acceso-ok`. Anything else reverts
  immediately.
- **A countdown runs while you test.** If you walk away or the test never comes,
  SSH, UFW and fail2ban revert on their own after 10 minutes.
- **Every change leaves a snapshot**, and the menu can revert to the latest one.
- **On a provider web console it will not lock down.** There is no way to test a
  new SSH connection from there, so it applies everything except the lockdown and
  tells you what to run later.

## What it does

1. Creates an admin user with sudo that actually works (password or NOPASSWD).
2. Installs and verifies your SSH public key.
3. Reports pending package updates and applies them **before** closing access.
4. Applies SSH limits (`MaxAuthTries`, `MaxSessions`, `ClientAliveInterval`…).
5. Disables root login and password authentication.
6. Enables UFW, listing the TCP **and UDP** ports it would filter first.
7. Sets up fail2ban with the IP of your live sessions excluded.
8. Turns on unattended security updates, and recommends moving SSH off port 22.

It is idempotent: run it twice and it reports what is already in place.

## Requirements

Ubuntu **22.04** or **24.04** · root or `sudo` · a second terminal on your own
computer for the access test · your provider's web console open as a fallback.
Other Ubuntu releases continue with an explicit warning; other distributions are
not supported.

## Flags that matter

| | |
|---|---|
| `--user NAME` | admin user to create or use. No default. |
| `--pubkey-file PATH` | your public key. Keeps it out of `ps`. |
| `--run-all` | guided run, phase by phase. This is what the installer does. |
| `--skip-lockdown` | everything except closing access. |
| `--allow-lockdown` | close access without the human test. You can lose SSH. |
| `--non-interactive` | for Ansible/CI; requires `--user`, `--pubkey-file`, `--sudo`. |
| `--upgrade` / `--no-upgrade` | apply, or only report, pending updates. |
| `--lang es\|en` | override the detected language. |

`--help` lists everything.

## What it does not do

It is not a substitute for keeping your private key safe, not an audit, and not a
rescue for a machine that is already compromised. Reverting undoes SSH, UFW and
fail2ban; it does not undo package updates, and it does not remove the public key
it installed. It never generates a key pair on the server — the private half
should never exist there.

## Verify what you downloaded

`install.sh` embeds this signing key; check its fingerprint through a channel
other than the download:

```
256  SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg  kenroka-release (ED25519)
```

```bash
ssh-keygen -Y verify -f allowed_signers -I all-lopezg -n file \
    -s SHA256SUMS.txt.sig < SHA256SUMS.txt
```

## Tests

The behaviour above is not a claim, it is what the suite checks:

- **18 end-to-end scenarios** against real systemd in containers, on Ubuntu 24.04
  and 22.04: lockdown, the countdown firing for real, port changes and conflicts,
  byte-exact idempotency and rollback, the novice flows, UDP warnings, and rescue
  through the menu.
- **134 unit assertions** on the pure logic, and **9** on the installer, including
  that a tampered file and a foreign signature are both refused.

```bash
./tests/run.sh unit
./tests/docker/run.sh --distro 24.04
./tests/docker/run.sh --distro 22.04
```

## License

To be chosen. Until then, all rights reserved.
