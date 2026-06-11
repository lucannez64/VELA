# Deploying VELA Server With systemd

This guide targets a Linux home server running VELA behind a local reverse proxy
or Cloudflare Tunnel. VELA stores encrypted vault data only; keep the data
directory and server identity environment file backed up.

## Layout

Recommended paths:

```text
/usr/local/bin/vela-server
/etc/vela/vela-server.env
/var/lib/vela
```

Create the runtime user and data directory:

```bash
sudo useradd --system --home /var/lib/vela --shell /usr/sbin/nologin vela
sudo install -d -o vela -g vela -m 0700 /var/lib/vela
sudo install -d -o root -g root -m 0755 /etc/vela
```

## Environment File

`/etc/vela/vela-server.env`:

```env
VELA_PRODUCTION=true
LISTEN_ADDR=127.0.0.1:8443
DATA_DIR=/var/lib/vela

WEBAUTHN_RP_ID=vault.example.com
WEBAUTHN_RP_ORIGIN=https://vault.example.com
WEBAUTHN_RP_NAME=VELA
CORS_ORIGINS=https://vault.example.com

PASETO_SECRET_KEY=<base64-64-byte-key>
```

`PASETO_SECRET_KEY` is part of the server identity. Losing it invalidates
existing sessions. Changing `WEBAUTHN_RP_ID` or `WEBAUTHN_RP_ORIGIN` can require
users to re-register recovery WebAuthn credentials.

## systemd Unit

`/etc/systemd/system/vela-server.service`:

```ini
[Unit]
Description=VELA Server
After=network-online.target
Wants=network-online.target

[Service]
User=vela
Group=vela
EnvironmentFile=/etc/vela/vela-server.env
ExecStart=/usr/local/bin/vela-server
Restart=on-failure
RestartSec=5s
WorkingDirectory=/var/lib/vela
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/vela

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vela-server
```

## Deploying Behind Cloudflare Tunnel

Cloudflare Tunnel is the recommended home-server edge for personal deployments.
VELA listens on loopback HTTP, and Cloudflare exposes your domain over HTTPS.
This avoids inbound firewall ports and local certificate management.

Use this VELA environment:

```env
VELA_PRODUCTION=true
LISTEN_ADDR=127.0.0.1:8443
DATA_DIR=/var/lib/vela

WEBAUTHN_RP_ID=vault.example.com
WEBAUTHN_RP_ORIGIN=https://vault.example.com
WEBAUTHN_RP_NAME=VELA
CORS_ORIGINS=https://vault.example.com

TRUST_PROXY_HEADERS=true
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128

PASETO_SECRET_KEY=<base64-64-byte-key>
```

Do not set `ALLOW_INSECURE_LAN=true` for this setup. Clients use
`https://vault.example.com`; only the local hop from `cloudflared` to VELA is
HTTP.

`/etc/cloudflared/config.yml`:

```yaml
tunnel: <tunnel-id>
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: vault.example.com
    service: http://127.0.0.1:8443
  - service: http_status:404
```

The server honors forwarded HTTPS headers only when `TRUST_PROXY_HEADERS=true`
and the request comes from `TRUSTED_PROXY_CIDRS`. For Cloudflare Tunnel on the
same machine, the default trusted CIDRs are loopback-only.

Make `cloudflared` start after VELA if you run it as a system service:

```ini
[Unit]
After=network-online.target vela-server.service
Wants=network-online.target vela-server.service
```

Validate through the public domain:

```bash
curl https://vault.example.com/health
```

## Migration Checklist With Cloudflare Tunnel

When moving to a new home server:

1. Stop VELA on the old server.

```bash
sudo systemctl stop vela-server
```

2. Export an encrypted VELA migration bundle:

```bash
vela-server migrate export \
  --out /tmp/vela-home.vela-migrate \
  --env-file /etc/vela/vela-server.env \
  --data-dir /var/lib/vela \
  --include-secrets \
  --passphrase
```

To include Cloudflare's non-secret tunnel routing file explicitly:

```bash
vela-server migrate export \
  --out /tmp/vela-home.vela-migrate \
  --env-file /etc/vela/vela-server.env \
  --data-dir /var/lib/vela \
  --include-secrets \
  --include-deployment-config /etc/cloudflared/config.yml \
  --passphrase
```

The bundle contains:

```text
data/vela.db
data/sled/
identity.env
manifest.json
checksums.json
```

The server identity values that must move with the data are:

```env
PASETO_SECRET_KEY
WEBAUTHN_RP_ID
WEBAUTHN_RP_ORIGIN
WEBAUTHN_RP_NAME
CORS_ORIGINS
TRUST_PROXY_HEADERS
TRUSTED_PROXY_CIDRS
```

3. Copy the bundle to the new server and import it:

```bash
vela-server migrate import \
  --bundle /tmp/vela-home.vela-migrate \
  --target-data-dir /var/lib/vela \
  --target-env-file /etc/vela/vela-server.env \
  --passphrase
```

Use `--replace` only when intentionally overwriting an existing restored data
directory.

4. Recreate Cloudflare Tunnel config on the new server:

```text
/etc/cloudflared/config.yml
/etc/cloudflared/<tunnel-id>.json
```

Cloudflare credentials are deployment config, not VELA vault data. They are not
included by default. Include config files only with `--include-deployment-config`.

5. Start VELA and `cloudflared` on the new server.

```bash
sudo systemctl start vela-server
sudo systemctl start cloudflared
```

6. Validate:

```bash
curl https://vault.example.com/health
```

Keep the same hostname when possible. Changing from `vault.example.com` to a new
domain changes the WebAuthn relying party origin and may require recovery
passkey re-registration.
