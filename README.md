# PasarGuard-Node
<p align="center">
    <a href="#">
        <img src="https://img.shields.io/github/actions/workflow/status/PasarGuard/node/docker-build.yml?style=flat-square" />
    </a>
    <a href="https://hub.docker.com/r/pasarguard/node" target="_blank">
        <img src="https://img.shields.io/docker/pulls/pasarguard/node?style=flat-square&logo=docker" />
    </a>
    <a href="#">
        <img src="https://img.shields.io/github/license/PasarGuard/node?style=flat-square" />
    </a>
    <a href="#">
        <img src="https://img.shields.io/github/stars/PasarGuard/node?style=social" />
    </a>
</p>

# Documentation
You can find a full guide in docs https://docs.pasarguard.org/en/node/

# One-Click Installation (Recommended)
The bundled installer runs this (multi-backend) node **as a Docker container**:
it installs Docker if missing, lets you toggle which backends run here, writes a
`docker-compose.yml` (pulling this fork's prebuilt image — all backends baked
in), brings the container up, and prints the Server CA + details to register the
node in the panel. No building on the node.

```bash
# interactive menu (toggle backends, set node port + API key, install)
sudo bash -c "$(curl -sL https://github.com/AlirezaNorouzzadeh9/pasarguardNode/raw/main/scripts/install.sh)"
```

Non-interactive, e.g. an xray + wireguard node (OpenVPN/IKEv2 disabled) with your
own API key:

```bash
sudo bash -c "$(curl -sL https://github.com/AlirezaNorouzzadeh9/pasarguardNode/raw/main/scripts/install.sh)" @ install \
  --disable openvpn,ikev2 --api-key <uuid> --service-port 62050 --yes
```

Command-driven management (all via `docker compose` under the hood):

```bash
sudo bash install.sh update      # pull the latest image (or rebuild) + recreate
sudo bash install.sh restart | status | logs
sudo bash install.sh uninstall
```

The interactive menu toggles the four **backends** (image ships all — off means
`PG_NODE_DISABLE_*`), and sets the **node (gRPC) port**, the **API key** (blank =
auto), and the **image source** (pull vs build from source). **VPN ports**
(OpenVPN / WireGuard) live in the panel's core config; IKEv2 is always 500/4500.

Install options (skip the menu with `-y`): `--disable <list>`, `--api-key <uuid>`,
`--service-port <n>`, `--image <ref>`, `--build`, `--branch <name>`, `--repo <url>`.
See [`scripts/install.sh`](scripts/install.sh).

> If the GHCR image can't be pulled (still private), the installer falls back to
> building it from source; or make the package public. Open the VPN ports on any
> **cloud** firewall too — host networking binds them on the host directly.

# Docker (compose)

Prefer Docker? A prebuilt multi-backend image is published to this fork's GHCR,
so you just drop a compose file and bring it up — no building on the node.

```bash
mkdir -p /opt/pg-node && cd /opt/pg-node
curl -fsSL https://github.com/AlirezaNorouzzadeh9/pasarguardNode/raw/main/docker-compose.yml -o docker-compose.yml
# set API_KEY to any UUID (the same one you enter for this node in the panel)
sed -i "s/REPLACE-WITH-A-UUID/$(cat /proc/sys/kernel/random/uuid)/" docker-compose.yml
docker compose up -d
docker compose logs | sed -n '/Server CA/,/====/p'   # copy the CA into the panel
```

The image bundles xray, OpenVPN, WireGuard and strongSwan/charon (IKEv2). The
container runs with `network_mode: host` and `cap_add: [NET_ADMIN, SYS_MODULE]`
plus `/dev/net/tun` and `/lib/modules` so all four backends work; the entrypoint
generates the node TLS certificate on first run and prints the **Server CA** to
paste into the panel. Data (certs + generated configs) lives in
`/var/lib/pg-node`.

> Still open the VPN ports on any **cloud** firewall (host networking binds them
> on the host directly).

### Choosing which backends run

The node is panel-driven: it runs whatever cores the panel assigns, and the image
ships all four backends. **Ports** (OpenVPN, WireGuard) are set in the panel's core
config / per-node override; **IKEv2** is always UDP 500 + 4500. To run only a
subset, either just don't assign a core to the node, or hard-disable a backend at
the node with an env var (it's then also greyed out in the panel):

| Env | Effect |
| --- | --- |
| `PG_NODE_DISABLE_XRAY=1` | never run xray on this node |
| `PG_NODE_DISABLE_OPENVPN=1` | never run OpenVPN |
| `PG_NODE_DISABLE_WIREGUARD=1` | never run WireGuard |
| `PG_NODE_DISABLE_IKEV2=1` | never run IKEv2 |

# Donation
You can help PasarGuard team with your donations, [Click Here](https://donate.pasarguard.org/)

# Contributors

We ❤️‍🔥 contributors! If you'd like to contribute, please check out our [Contributing Guidelines](CONTRIBUTING.md) and feel free to submit a pull request or open an issue. We also welcome you to join our [Telegram](https://t.me/Pasar_Guard) group for either support or contributing guidance.

Check [open issues](https://github.com/PasarGuard/node/issues) to help the progress of this project.

## Stargazers over time
[![Stargazers over time](https://starchart.cc/PasarGuard/node.svg?variant=adaptive)](https://starchart.cc/PasarGuard/node)
                    
<p align="center">
Thanks to the all contributors who have helped improve PasarGuard Node:
</p>
<p align="center">
<a href="https://github.com/PasarGuard/node/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=PasarGuard/node" />
</a>
</p>
<p align="center">
  Made with <a rel="noopener noreferrer" target="_blank" href="https://contrib.rocks">contrib.rocks</a>
</p>
