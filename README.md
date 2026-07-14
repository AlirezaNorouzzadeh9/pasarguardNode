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
The easiest way to install this (multi-backend) PasarGuard Node is the bundled
installer. It asks which backends to set up (xray is always installed;
OpenVPN / WireGuard / IKEv2 are optional), installs their OS-level
dependencies, builds the node binary, generates a TLS cert + API key, creates a
systemd service, and prints the details to register the node in the panel.

```bash
# interactive (asks which backends)
sudo bash -c "$(curl -sL https://github.com/AlirezaNorouzzadeh9/pasarguardNode/raw/main/scripts/install.sh)"
```

Non-interactive, e.g. an OpenVPN + IKEv2 node on port 62050:

```bash
sudo bash -c "$(curl -sL https://github.com/AlirezaNorouzzadeh9/pasarguardNode/raw/main/scripts/install.sh)" @ --backends openvpn,ikev2 --port 62050 --yes
```

Flags: `--backends <list>`, `--port <n>`, `--host <addr>`, `--branch <name>`,
`-y/--yes`, `--uninstall`. See [`scripts/install.sh`](scripts/install.sh).

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
