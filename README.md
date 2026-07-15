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
The bundled installer sets up this (multi-backend) node: it asks which backends
to run (xray is always installed; OpenVPN / WireGuard / IKEv2 are optional),
installs their OS deps, **opens the needed firewall ports**, builds the binary,
makes a TLS cert + API key, writes a systemd service, and prints the details to
register the node in the panel.

```bash
# interactive (asks which backends + ports)
sudo bash -c "$(curl -sL https://github.com/AlirezaNorouzzadeh9/pasarguardNode/raw/main/scripts/install.sh)"
```

Non-interactive, e.g. an OpenVPN + IKEv2 node with your own API key:

```bash
sudo bash -c "$(curl -sL https://github.com/AlirezaNorouzzadeh9/pasarguardNode/raw/main/scripts/install.sh)" @ install \
  --backends openvpn,ikev2 --api-key <uuid> --openvpn-port 1194 --yes
```

It is command-driven like the upstream installer:

```bash
sudo bash install.sh update      # rebuild from latest source + restart
sudo bash install.sh restart | status | logs
sudo bash install.sh uninstall
```

The interactive install asks, in order: **Xray version** (blank = latest),
which **backends** to run (strict y/n — Enter means no), their **ports**, the
**node port** + **API port**, and the **API key** (blank = auto). Each install
step then runs quietly with colored progress.

Install options (skip the matching prompt): `--backends <list>`,
`--xray-version <tag>`, `--api-key <uuid>`, `--service-port <n>`, `--api-port <n>`,
`--openvpn-port <n>`, `--wireguard-port <n>`, `--host <addr>`, `--branch <name>`,
`-y/--yes`. See [`scripts/install.sh`](scripts/install.sh).

> A cloud firewall (DigitalOcean/AWS/Hetzner) must be opened separately — the
> installer can only open the local `ufw`/`firewalld`.

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
