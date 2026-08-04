# PasarGuard Node — Multi-Backend

One node, four VPN backends in a single Docker image, all driven by the panel:

| Backend | Protocols | Notes |
| --- | --- | --- |
| **Xray** | VLESS / VMESS / Trojan / Shadowsocks | full xray-core |
| **OpenVPN** | OpenVPN (udp/tcp) | `.ovpn` per user, served by the panel |
| **WireGuard** | WireGuard | `.conf` + QR per user |

The panel assigns cores to the node over gRPC; the node starts/stops the
matching backends and reports per-protocol traffic and online IPs back to the
panel.

> **Private repo:** the source is private, but the container image on GHCR is
> public — servers can pull and run it without any GitHub credentials. Only
> fetching the scripts/source needs auth (see below).

## Install (Docker, recommended)

The installer runs the node as a Docker container: installs Docker if missing,
lets you toggle which backends run on this box, writes a `docker-compose.yml`
(pulling the prebuilt image — all backends baked in), brings it up, and prints
the **Server CA** + details to register the node in the panel.

Get `install.sh` onto the server first — pick one:

```bash
# a) from your machine (repo cloned locally)
scp scripts/install.sh root@SERVER:/root/ && ssh root@SERVER

# b) straight from GitHub with a personal access token (repo scope, read)
curl -fsSL -H "Authorization: token YOUR_PAT" \
  https://raw.githubusercontent.com/AlirezaNorouzzadeh9/pasarguardNode/main/scripts/install.sh -o install.sh
```

Then on the server:

```bash
# interactive menu (toggle backends, set node port + API key, install)
sudo bash install.sh
```

Non-interactive, e.g. an xray + wireguard node (OpenVPN disabled) with
your own API key:

```bash
sudo bash install.sh install --disable openvpn \
  --api-key <uuid> --service-port 62050 --yes
```

Day-2 management (all via `docker compose` under the hood):

```bash
sudo bash install.sh update      # pull the latest image + recreate
sudo bash install.sh restart | status | logs
sudo bash install.sh uninstall
```

Install options (skip the menu with `-y`): `--disable <list>`, `--api-key <uuid>`,
`--service-port <n>`, `--image <ref>`, `--build`, `--branch <name>`, `--repo <url>`.
See [`scripts/install.sh`](scripts/install.sh). `--build` clones this repo on the
server, so it needs a PAT (pass `--repo https://TOKEN@github.com/...`); the
default pull mode needs nothing.

## Docker compose (manual)

```bash
mkdir -p /opt/pg-node && cd /opt/pg-node
# copy docker-compose.yml from this repo (scp / PAT, same as above)
sed -i "s/REPLACE-WITH-A-UUID/$(cat /proc/sys/kernel/random/uuid)/" docker-compose.yml
docker compose up -d
cat /var/lib/pg-node/certs/ssl_cert.pem   # the Server CA to paste into the panel
```

The container runs with `network_mode: host` and `cap_add: [NET_ADMIN,
SYS_MODULE]` plus `/dev/net/tun` and `/lib/modules` so all four backends work.
The entrypoint generates the node TLS certificate on first run and prints the
**Server CA** to paste into the panel. Data (certs + generated configs) lives in
`/var/lib/pg-node`.

> Open the VPN ports on any **cloud** firewall too — host networking binds them
> on the host directly. OpenVPN/WireGuard ports are set in the panel's core
> config.

## Choosing which backends run

The node is panel-driven: it runs whatever cores the panel assigns. To keep a
backend off a box entirely, hard-disable it with an env var (it's then also
greyed out in the panel):

| Env | Effect |
| --- | --- |
| `PG_NODE_DISABLE_XRAY=1` | never run xray on this node |
| `PG_NODE_DISABLE_OPENVPN=1` | never run OpenVPN |
| `PG_NODE_DISABLE_WIREGUARD=1` | never run WireGuard |

## Development

```bash
make build                   # build the node binary
go test ./...                # run tests
docker build -t pg-node .    # build the full multi-backend image locally
```

CI (GitHub Actions) builds and pushes the image to GHCR on pushes to `main` and
`v*` tags (plus manual dispatch), and runs the Go tests. Releases attach
prebuilt binaries.

## Credits & license

Based on [PasarGuard/node](https://github.com/PasarGuard/node), extended with
multi-backend (OpenVPN / WireGuard) support, per-protocol stats, and the
Docker/installer stack. Licensed
under the [GPL-3.0](LICENSE).
