# Installing AuditLight

AuditLight is a single static binary. There is nothing to install alongside it, no runtime
to provision, and no database to create.

## Requirements

- Linux, amd64.
- Nothing else. The binary links no third-party library and makes no outbound connection of
  its own.

Tested on Ubuntu 24.04 LTS, Ubuntu 22.04 LTS and Debian 12. The RHEL family (Rocky, Alma,
RHEL 9) and Alpine are best-effort: the binary runs, but the optional external tools have
different package names.

## From a release

```sh
tar xzf auditlight-free-0.3.0-linux-amd64.tar.gz
cd auditlight-0.3.0
sha256sum -c SHA256SUMS
./auditlight
```

Open <http://127.0.0.1:8431>.

By default AuditLight listens on loopback only. To reach it from another machine, bind it
explicitly and put it behind something that authenticates:

```sh
./auditlight -listen 10.0.0.5:8431
```

AuditLight has no user accounts. Anyone who can reach the port can start an assessment, so
do not expose it to an untrusted network.

## From source

```sh
git clone https://github.com/nizartuanku/auditlight
cd auditlight
go build ./cmd/auditlight
./auditlight
```

Go 1.24 or later. No modules are fetched, so this works offline.

## Optional external tools

AuditLight completes an assessment on its own. These add depth if you install them; if they
are absent the report records which capabilities were unavailable.

```sh
# Debian / Ubuntu
sudo apt install -y testssl.sh lynis

# nuclei — see https://github.com/projectdiscovery/nuclei/releases
# nmap is NOT distributed with AuditLight; install it yourself if you want it
sudo apt install -y nmap
```

Check what the running instance can see under **What this installation can check** on the
dashboard, or at `GET /api/status`.

## Licence key

Paid editions are unlocked by an offline Ed25519 key. There is no activation server and no
callback.

```sh
export AUDITLIGHT_LICENSE='SNTL1-...'
./auditlight
```

or

```sh
./auditlight -license 'SNTL1-...'
```

The banner at startup states which tier is active. If a key is missing, expired or invalid,
AuditLight runs as Free and says exactly why — it never refuses to start.

## Recurring assessments and notifications

Saved assessments re-run on a schedule using an internal ticker; there is no cron entry to
add. Disable it with `-no-schedule`.

For e-mail notifications:

```sh
./auditlight \
  -smtp-host smtp.example.com -smtp-port 587 \
  -smtp-user audit@example.com -smtp-from audit@example.com \
  -console-url https://audit.example.internal
```

The password comes from `AUDITLIGHT_SMTP_PASS` rather than the command line, so it does not
appear in the process list. AuditLight refuses to send credentials to a remote host without
STARTTLS. Webhooks need no configuration here — the URL is set per assessment.

`-console-url` only affects the links inside notifications. Leave it unset and the
notification still arrives, just without a clickable report link.

## Data

Jobs, findings and saved assessments are written to `$HOME/.auditlight` by default. Change it with `-data`, or
keep everything in memory:

```sh
./auditlight -data /var/lib/auditlight
./auditlight -memory      # nothing is written to disk
```

## Running as a service

```ini
# /etc/systemd/system/auditlight.service
[Unit]
Description=AuditLight
After=network.target

[Service]
Type=simple
User=auditlight
Environment=AUDITLIGHT_LICENSE=SNTL1-...
ExecStart=/usr/local/bin/auditlight -listen 127.0.0.1:8431 -data /var/lib/auditlight
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/auditlight
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd -r -s /usr/sbin/nologin auditlight
sudo mkdir -p /var/lib/auditlight && sudo chown auditlight: /var/lib/auditlight
sudo systemctl enable --now auditlight
```

Note that the `hardening` profile audits the host AuditLight runs on, and `lynis` needs
privileges to read much of what it checks. Run that profile manually rather than granting
the service account broad access.

## Uninstall

```sh
sudo systemctl disable --now auditlight
sudo rm /usr/local/bin/auditlight
sudo rm -rf /var/lib/auditlight
```

Nothing else is left behind: no packages, no daemons, no registry of any kind.
