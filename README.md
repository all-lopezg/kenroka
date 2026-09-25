secure-vps
Harden an Ubuntu VPS without locking yourself out.
🇪🇸 Español
 ██╗  ██╗███████╗███╗   ██╗██████╗  ██████╗  ██╗  ██╗ █████╗
 ██║ ██╔╝██╔════╝████╗  ██║██╔══██╗██╔═══██╗ ██║ ██╔╝██╔══██╗
 █████╔╝ █████╗  ██╔██╗ ██║██████╔╝██║   ██║ █████╔╝ ███████║
 ██╔═██╗ ██╔══╝  ██║╚██╗██║██╔══██╗██║   ██║ ██╔═██╗ ██╔══██║
 ██║  ██╗███████╗██║ ╚████║██║  ██║╚██████╔╝ ██║  ██╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═╝

Quickstart
curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash

The URL is intentionally unversioned: it always resolves to the latest published release.
The installer tells you which version it resolved and verifies its signature before running it.

To pin a specific version:

KENROKA_VERSION=vX.Y.Z curl -fsSL https://raw.githubusercontent.com/all-lopezg/kenroka/main/install.sh | bash

Before you start: keep your provider's web console open and have a second terminal ready for the SSH access test.
The one-liner launches the guided assistant directly.
If you prefer to choose individual phases or inspect the current state without making changes, download the script and run it without arguments:

curl -fsSL -o secure-vps.sh \
  https://github.com/all-lopezg/kenroka/releases/latest/download/secure-vps.sh

less secure-vps.sh
sudo bash secure-vps.sh

The menu provides all 11 available actions.
What it does
Creates a working administrative user with sudo, using either a password or NOPASSWD.
Installs your SSH public key and verifies that sshd accepts it, including file permissions.
Checks for pending package updates before making access-restricting changes.
Applies SSH security limits such as MaxAuthTries, MaxSessions, and ClientAlive.
Disables root login and password authentication.
Shows which TCP and UDP ports would be filtered before enabling UFW.
Configures fail2ban and excludes your current IP from bans.
Enables automatic security updates.
Offers to move SSH away from port 22.
Verifies the effective SSH configuration before applying the final lockdown.
The safety net
The most important rule is simple:
Never lock down SSH without first verifying that the new configuration works.

Before restricting access, secure-vps checks the effective sshd configuration.

Once lockdown begins, a countdown starts — 10 minutes by default.

During that window:

Open a new SSH session from another terminal.
Verify that you can log in normally.
Return to the original session.
Confirm the new access with:
access-ok

If the confirmation does not arrive before the countdown expires, the changes are automatically reverted.
Every change creates a snapshot, and the interactive menu includes an option to restore the latest snapshot manually.

Requirements
Ubuntu 22.04 or 24.04.
Root access or working sudo.
A second terminal for testing SSH access.
Keeping your VPS provider's recovery/web console available is strongly recommended.
Other Ubuntu versions are detected and reported, but are not covered by the test suite.
Verify the signing key
install.sh contains an embedded ssh-ed25519 public key used to verify releases.
Its fingerprint is:

256 SHA256:HHGNTv5xODpeL2dDmFZFCatrDfiFWHSzwbO3WjISAEg
kenroka-release (ED25519)

Do not rely solely on the downloaded copy of the fingerprint.
Compare the fingerprint through an independent channel before trusting the verification process.

For example:

ssh-keygen -lf ~/.ssh/kenroka_sign.pub

If you sign releases yourself, verify that the fingerprint matches your expected signing key.
What it does not do
It does not pipe the main script directly into bash. The main script must be downloaded first because it requires interactive input.
Reverting restores SSH, UFW, and fail2ban configuration.
Reverting does not undo automatic security updates.
Reverting does not remove the SSH public key installed by the tool.
It is not a security audit.
It cannot recover a server that has already been compromised.
If the server is already compromised, treat it as compromised. Hardening it afterwards does not establish trust.
Automation
sudo bash secure-vps.sh --help

Available options include:
--non-interactive
--skip-lockdown
--allow-lockdown

--non-interactive
Designed for automation through tools such as Ansible or CI.
--skip-lockdown
Prepares the server without applying the final access lockdown.
Useful when you want to review the resulting configuration before restricting access.

--allow-lockdown
Allows the final lockdown without requiring the human access confirmation.
Use this only when you understand the recovery implications.

Warning: automated lockdown can leave you without SSH access if the resulting configuration is incorrect.
Testing
The test suite runs the script against real systemd environments inside containers on Ubuntu 22.04 and 24.04.
It currently covers:

17 end-to-end scenarios.
101 unit assertions.
SSH lockdown and rollback.
Access countdown.
SSH port changes.
Idempotency.
Guided first-run flow.
Recovery through the interactive menu.
Run the unit tests:
./tests/run.sh unit

Test Ubuntu 24.04:
./tests/docker/run.sh --distro 24.04

Test Ubuntu 22.04:
./tests/docker/run.sh --distro 22.04

License
To be chosen.
Until a license is explicitly published, all rights are reserved.
