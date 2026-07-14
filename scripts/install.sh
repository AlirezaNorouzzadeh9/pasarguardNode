#!/usr/bin/env bash
#
# PasarGuard Node manager (multi-backend fork)
# ---------------------------------------------
# Builds this fork's multi-backend node binary and sets up only the backends you
# pick (xray always; openvpn / wireguard / ikev2 optional). Run with no argument
# for an interactive menu where you toggle each backend on/off and edit ports /
# version / keys, then install. It runs each step quietly with colored progress,
# sets up VPN routing (IP forwarding + NAT, persisted across reboots), opens the
# firewall, writes a systemd service, and prints the details to register the node.
#
#   sudo bash install.sh                                   # interactive menu
#   sudo bash install.sh install --backends openvpn,ikev2 \
#        --xray-version v25.3.6 --api-key <uuid> --yes     # scripted
#   sudo bash install.sh update | restart | status | logs | uninstall
#
set -euo pipefail

# ---- defaults (override via flags / env) -----------------------------------
REPO="${REPO:-https://github.com/AlirezaNorouzzadeh9/pasarguardNode.git}"
BRANCH="${BRANCH:-main}"
GO_VERSION="${GO_VERSION:-1.26.2}"

INSTALL_DIR="${INSTALL_DIR:-/opt/pg-node}"
SRC_DIR="$INSTALL_DIR/src"
BIN="$INSTALL_DIR/node_main"
DATA_DIR="${DATA_DIR:-/var/lib/pg-node}"
CERT_DIR="$DATA_DIR/certs"
SERVICE="${SERVICE:-pg-node}"
UNIT="/etc/systemd/system/${SERVICE}.service"
NAT_UNIT="/etc/systemd/system/${SERVICE}-nat.service"
NAT_SCRIPT="$INSTALL_DIR/pg-node-nat.sh"
SYSCTL_FILE="/etc/sysctl.d/99-${SERVICE}-forward.conf"
STEP_LOG="/tmp/pg-node-install.log"

SERVICE_PORT="${SERVICE_PORT:-62050}"
API_PORT="${API_PORT:-62051}"
NODE_HOST="${NODE_HOST:-0.0.0.0}"
XRAY_PATH="/usr/local/bin/xray"

XRAY_VERSION="${XRAY_VERSION:-}"   # blank -> latest
BACKENDS=""                         # comma list; empty -> none (xray only)
API_KEY=""                          # empty -> auto-generate
OPENVPN_PORT="${OPENVPN_PORT:-1194}"
WG_PORT="${WG_PORT:-51820}"
ASSUME_YES=0
PUBLIC_IP=""

# Per-backend toggles used by the interactive menu (seeded from --backends/env).
WG_ON=0; OVPN_ON=0; IKEV2_ON=0

# ---- colors / logging -------------------------------------------------------
if [ -t 1 ]; then
  c_grn='\033[0;32m'; c_yel='\033[0;33m'; c_red='\033[0;31m'
  c_cyn='\033[0;36m'; c_mag='\033[0;35m'; c_bld='\033[1m'; c_dim='\033[2m'; c_off='\033[0m'
else
  c_grn=''; c_yel=''; c_red=''; c_cyn=''; c_mag=''; c_bld=''; c_dim=''; c_off=''
fi
log()  { echo -e "${c_grn}[+]${c_off} $*"; }
warn() { echo -e "${c_yel}[!]${c_off} $*"; }
err()  { echo -e "${c_red}[x]${c_off} $*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { echo -e "${c_cyn}────────────────────────────────────────────────────────${c_off}"; }
has()  { command -v "$1" >/dev/null 2>&1; }

# Read that works even under `curl … | bash` (stdin is the script, not the user)
# by pulling from the controlling terminal when one exists. Never fails the
# script on EOF.
_read() {
  if [ -e /dev/tty ]; then read "$@" </dev/tty || true; else read "$@" || true; fi
}

# Run a step quietly: show a colored line, hide the command output (it goes to
# the log), and report success/failure.
run_step() {
  local msg="$1"; shift
  echo -ne "  ${c_cyn}▶${c_off} ${msg} ${c_dim}...${c_off} "
  if "$@" >>"$STEP_LOG" 2>&1; then
    echo -e "${c_grn}done${c_off}"
  else
    echo -e "${c_red}failed${c_off}"
    err "step failed: ${msg}"
    err "last lines of ${STEP_LOG}:"
    tail -n 8 "$STEP_LOG" >&2 || true
    exit 1
  fi
}

# ---- input prompts (strict) -------------------------------------------------
# Yes/No: only y/n accepted; empty = No; anything else is rejected and re-asked.
ask_yn() {
  local q="$1" ans
  while true; do
    _read -r -p "$(echo -e "${c_bld}${q}${c_off} (y/n, Enter = no): ")" ans
    case "${ans:-n}" in
      [Yy]|[Yy][Ee][Ss]) return 0 ;;
      [Nn]|[Nn][Oo])     return 1 ;;
      *) warn "Please type only 'y' (yes) or 'n' (no). Empty means no." ;;
    esac
  done
}

# Free text with a default.
ask_val() {
  local q="$1" def="$2" ans
  _read -r -p "$(echo -e "${c_bld}${q}${c_off}${def:+ [${def}]}: ")" ans
  echo "${ans:-$def}"
}

# Numeric (1-65535) with a default; rejects non-numbers / out-of-range.
ask_num() {
  local q="$1" def="$2" ans
  while true; do
    _read -r -p "$(echo -e "${c_bld}${q}${c_off} [${def}]: ")" ans
    ans="${ans:-$def}"
    if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le 65535 ]; then
      echo "$ans"; return
    fi
    warn "Please enter a port number between 1 and 65535."
  done
}

want() { echo ",$BACKENDS," | grep -qi ",$1,"; }

# ---- system helpers ---------------------------------------------------------
require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }

detect_pm() {
  if has apt-get; then PM=apt
  elif has dnf; then PM=dnf
  elif has yum; then PM=yum
  elif has pacman; then PM=pacman
  else die "unsupported distro (need apt/dnf/yum/pacman)"; fi
}
pm_install() {
  case "$PM" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf)    dnf install -y "$@" ;;
    yum)    yum install -y "$@" ;;
    pacman) pacman -Sy --noconfirm "$@" ;;
  esac
}
pm_update() { case "$PM" in apt) apt-get update -y ;; pacman) pacman -Sy --noconfirm ;; *) : ;; esac; }

detect_public_ip() {
  PUBLIC_IP="$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP="127.0.0.1"
}

# True when a backend that tunnels client traffic (and thus needs IP forwarding
# and NAT) is selected. Xray does its own egress, so it is not counted here.
needs_vpn_net() { want openvpn || want wireguard || want ikev2; }

# Keep the CSV (used by want/install steps) and the menu toggles in sync.
sync_toggles_from_backends() {
  want wireguard && WG_ON=1 || WG_ON=0
  want openvpn   && OVPN_ON=1 || OVPN_ON=0
  want ikev2     && IKEV2_ON=1 || IKEV2_ON=0
}
rebuild_backends_from_toggles() {
  BACKENDS=""
  [ "$OVPN_ON"  -eq 1 ] && BACKENDS="$BACKENDS,openvpn"
  [ "$WG_ON"    -eq 1 ] && BACKENDS="$BACKENDS,wireguard"
  [ "$IKEV2_ON" -eq 1 ] && BACKENDS="$BACKENDS,ikev2"
  BACKENDS="${BACKENDS#,}"
}

usage() {
  cat <<EOF
PasarGuard Node manager

Usage: sudo bash install.sh [command] [options]

Commands:
  (no command)        Open the interactive menu (toggle backends, then install)
  menu                Same as above
  install             Install / reinstall (menu unless -y or --backends given)
  update              Rebuild from the latest source and restart
  restart | status | logs
  uninstall           Remove the service, binary, routing and data

Install options (skip the menu when combined with -y):
  --backends <list>     openvpn,wireguard,ikev2  (xray always)
  --xray-version <tag>  e.g. v25.3.6  (default: latest)
  --api-key <uuid>      (default: auto-generate)
  --service-port <n>    gRPC port the panel connects to (default: ${SERVICE_PORT})
  --api-port <n>        API port for the panel form (default: ${API_PORT})
  --openvpn-port <n>    OpenVPN port to open in the firewall (default: ${OPENVPN_PORT})
  --wireguard-port <n>  WireGuard port to open (default: ${WG_PORT})
  --host <addr>         Listen address (default: ${NODE_HOST})
  --branch <name> | --repo <url>
  -y, --yes             Non-interactive (use flags/defaults; skip the menu)
  -h, --help
EOF
}

parse_install_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --backends) BACKENDS="$2"; shift 2 ;;
      --xray-version) XRAY_VERSION="$2"; shift 2 ;;
      --api-key) API_KEY="$2"; shift 2 ;;
      --service-port|--port) SERVICE_PORT="$2"; shift 2 ;;
      --api-port) API_PORT="$2"; shift 2 ;;
      --openvpn-port) OPENVPN_PORT="$2"; shift 2 ;;
      --wireguard-port) WG_PORT="$2"; shift 2 ;;
      --host) NODE_HOST="$2"; shift 2 ;;
      --branch) BRANCH="$2"; shift 2 ;;
      --repo) REPO="$2"; shift 2 ;;
      -y|--yes) ASSUME_YES=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done
}

gen_uuid() { [ -r /proc/sys/kernel/random/uuid ] && cat /proc/sys/kernel/random/uuid || (has uuidgen && uuidgen) || die "cannot generate a UUID"; }

# ---- interactive menu -------------------------------------------------------
onoff() {
  if [ "${1:-0}" -eq 1 ]; then echo -e "${c_grn}${c_bld}● ON${c_off}"; else echo -e "${c_dim}○ off${c_off}"; fi
}
press_enter() { echo; _read -r -p "$(echo -e "  ${c_dim}Press Enter to return to the menu…${c_off}")" _; }

banner() {
  clear 2>/dev/null || true
  echo
  echo -e "  ${c_cyn}${c_bld}╔══════════════════════════════════════════════════════╗${c_off}"
  echo -e "  ${c_cyn}${c_bld}║${c_off}          ${c_bld}PasarGuard Node${c_off}  ${c_dim}·${c_off}  ${c_mag}${c_bld}multi-backend${c_off}          ${c_cyn}${c_bld}║${c_off}"
  echo -e "  ${c_cyn}${c_bld}╚══════════════════════════════════════════════════════╝${c_off}"
  echo
}

menu_command() {
  require_root; detect_pm
  # The menu needs a terminal to read choices; without one (e.g. plain
  # `curl … | bash` in a non-interactive context) fall back to guidance instead
  # of spinning forever on empty reads.
  if [ ! -e /dev/tty ] && [ ! -t 0 ]; then
    die "no terminal for the interactive menu — run non-interactively, e.g.:
  sudo bash install.sh install --backends wireguard,openvpn,ikev2 -y   (see --help)"
  fi
  sync_toggles_from_backends
  local status="not installed"
  [ -x "$BIN" ] && status="installed ($(systemctl is-active "$SERVICE" 2>/dev/null || echo unknown))"

  while true; do
    rebuild_backends_from_toggles
    banner
    echo -e "  ${c_dim}State:${c_off} ${c_bld}${status}${c_off}"
    echo
    echo -e "  ${c_bld}Backends${c_off} ${c_dim}(xray is always installed)${c_off}"
    printf "    ${c_bld}1${c_off}  %-24s %b\n" "WireGuard"          "$(onoff "$WG_ON")"
    printf "    ${c_bld}2${c_off}  %-24s %b\n" "OpenVPN"            "$(onoff "$OVPN_ON")"
    printf "    ${c_bld}3${c_off}  %-24s %b\n" "IKEv2 (strongSwan)" "$(onoff "$IKEV2_ON")"
    echo
    echo -e "  ${c_bld}Settings${c_off}"
    printf "    ${c_bld}4${c_off}  %-24s ${c_cyn}%s${c_off}\n" "Xray version"      "${XRAY_VERSION:-latest}"
    [ "$WG_ON"   -eq 1 ] && printf "    ${c_bld}5${c_off}  %-24s ${c_cyn}%s${c_off}\n" "WireGuard port"  "$WG_PORT"
    [ "$OVPN_ON" -eq 1 ] && printf "    ${c_bld}6${c_off}  %-24s ${c_cyn}%s${c_off}\n" "OpenVPN port"    "$OPENVPN_PORT"
    printf "    ${c_bld}7${c_off}  %-24s ${c_cyn}%s${c_off}\n" "Node port (gRPC)"  "$SERVICE_PORT"
    printf "    ${c_bld}8${c_off}  %-24s ${c_cyn}%s${c_off}\n" "API port"          "$API_PORT"
    printf "    ${c_bld}9${c_off}  %-24s ${c_cyn}%s${c_off}\n" "API key"           "${API_KEY:-auto-generate}"
    echo
    echo -e "  ${c_bld}Actions${c_off}"
    echo -e "    ${c_grn}${c_bld}i${c_off}  Install / reinstall with the selection above"
    echo -e "    ${c_bld}u${c_off} Update   ${c_bld}s${c_off} Status   ${c_bld}l${c_off} Logs   ${c_bld}r${c_off} Restart   ${c_red}x${c_off} Uninstall"
    echo -e "    ${c_bld}q${c_off} Quit"
    echo
    local choice
    _read -r -p "$(echo -e "  ${c_bld}Select${c_off} ${c_dim}(number or letter)${c_off} ${c_cyn}❯${c_off} ")" choice
    case "$choice" in
      1) WG_ON=$((1 - WG_ON)) ;;
      2) OVPN_ON=$((1 - OVPN_ON)) ;;
      3) IKEV2_ON=$((1 - IKEV2_ON)) ;;
      4) XRAY_VERSION="$(ask_val "Xray-core version (e.g. v25.3.6, blank = latest)" "$XRAY_VERSION")" ;;
      5) WG_PORT="$(ask_num "WireGuard listen port (match the panel core)" "$WG_PORT")" ;;
      6) OPENVPN_PORT="$(ask_num "OpenVPN listen port (match the panel core)" "$OPENVPN_PORT")" ;;
      7) SERVICE_PORT="$(ask_num "Node port (gRPC connects here)" "$SERVICE_PORT")" ;;
      8) API_PORT="$(ask_num "API port (panel form; REST mode only)" "$API_PORT")" ;;
      9) API_KEY="$(ask_val "API key (blank = auto-generate)" "$API_KEY")" ;;
      i|I) rebuild_backends_from_toggles; echo; run_install; break ;;
      u|U) echo; update_command; press_enter ;;
      s|S) echo; status_command; press_enter ;;
      l|L) echo; logs_command ;;
      r|R) echo; restart_command; press_enter ;;
      x|X) echo; uninstall_command; press_enter; status="not installed" ;;
      q|Q) echo; exit 0 ;;
      "") : ;;
      *) warn "Unknown option: '${choice}'"; sleep 1 ;;
    esac
  done
}

# ---- install steps (each quiet; run via run_step) ---------------------------
install_base_deps() { pm_update || true; pm_install curl git ca-certificates openssl iptables; }

install_go() {
  if has go && go version 2>/dev/null | grep -q "go${GO_VERSION%.*}"; then
    export PATH="$PATH:$(go env GOPATH)/bin:/usr/local/go/bin"; return
  fi
  local arch; case "$(uname -m)" in
    x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;;
    *) die "unsupported CPU arch: $(uname -m)" ;;
  esac
  local tgz="/tmp/go${GO_VERSION}.tar.gz"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o "$tgz"
  rm -rf /usr/local/go && tar -C /usr/local -xzf "$tgz" && rm -f "$tgz"
  export PATH="/usr/local/go/bin:$PATH"; has go
}

install_xray() {
  if [ -x "$XRAY_PATH" ] && [ -z "$XRAY_VERSION" ]; then return 0; fi
  local args=""; [ -n "$XRAY_VERSION" ] && args="--tag $XRAY_VERSION"
  curl -fsSL https://github.com/PasarGuard/scripts/raw/main/install_core.sh | bash -s -- $args
}
install_openvpn()   { pm_install openvpn; }
install_wireguard() {
  case "$PM" in
    apt) pm_install wireguard || pm_install wireguard-tools ;;
    *)   pm_install wireguard-tools ;;
  esac
  # Load the module now and on every boot. (The node also triggers a load when it
  # creates the interface, but persisting it avoids a cold-boot race.)
  modprobe wireguard 2>/dev/null || true
  echo wireguard > /etc/modules-load.d/wireguard.conf 2>/dev/null || true
}
install_ikev2()     {
  case "$PM" in
    apt) pm_install strongswan strongswan-swanctl libcharon-extra-plugins ;;
    *)   pm_install strongswan ;;
  esac
  # The node spawns and manages its own charon; the distro service would fight it
  # over ports 500/4500, so keep it off.
  systemctl disable --now strongswan strongswan-starter 2>/dev/null || true
}

# VPN backends only forward client traffic to the internet if the kernel has IP
# forwarding on and the client pools are NAT'd (MASQUERADE) out the egress
# interface. Neither the node binary nor the distro sets these up, so we do —
# persisted across reboots via a sysctl drop-in and a oneshot systemd unit that
# re-applies the (idempotent) iptables rules on every boot.
configure_networking() {
  cat > "$SYSCTL_FILE" <<EOF
# PasarGuard Node — forward VPN client traffic
net.ipv4.ip_forward = 1
EOF
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

  cat > "$NAT_SCRIPT" <<'NAT'
#!/usr/bin/env bash
# Managed by the PasarGuard Node installer — VPN NAT + forwarding.
# Idempotent: safe to run repeatedly (checks each rule before adding).
set -u
# The private ranges every VPN client pool falls into. The panel decides the
# exact subnet per core; masquerading the whole private space covers any of them
# without the node needing to know the pool. The node's own public traffic keeps
# a public source address, so it never matches these rules.
RANGES="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
EGRESS="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || true)"
[ -n "$EGRESS" ] || EGRESS="$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')"

up() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  for r in $RANGES; do
    if [ -n "$EGRESS" ]; then
      iptables -t nat -C POSTROUTING -s "$r" -o "$EGRESS" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -s "$r" -o "$EGRESS" -j MASQUERADE
    else
      iptables -t nat -C POSTROUTING -s "$r" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -s "$r" -j MASQUERADE
    fi
    iptables -C FORWARD -s "$r" -j ACCEPT 2>/dev/null || iptables -A FORWARD -s "$r" -j ACCEPT
    iptables -C FORWARD -d "$r" -j ACCEPT 2>/dev/null || iptables -A FORWARD -d "$r" -j ACCEPT
  done
}
down() {
  for r in $RANGES; do
    if [ -n "$EGRESS" ]; then
      iptables -t nat -D POSTROUTING -s "$r" -o "$EGRESS" -j MASQUERADE 2>/dev/null || true
    else
      iptables -t nat -D POSTROUTING -s "$r" -j MASQUERADE 2>/dev/null || true
    fi
    iptables -D FORWARD -s "$r" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -d "$r" -j ACCEPT 2>/dev/null || true
  done
}
case "${1:-up}" in down) down ;; *) up ;; esac
NAT
  chmod +x "$NAT_SCRIPT"

  cat > "$NAT_UNIT" <<EOF
[Unit]
Description=PasarGuard Node VPN NAT and IP forwarding
After=network-online.target
Wants=network-online.target
Before=${SERVICE}.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${NAT_SCRIPT} up
ExecStop=${NAT_SCRIPT} down
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${SERVICE}-nat.service"
}

build_node() {
  mkdir -p "$INSTALL_DIR"
  if [ -d "$SRC_DIR/.git" ]; then
    git -C "$SRC_DIR" fetch --depth 1 origin "$BRANCH" && git -C "$SRC_DIR" reset --hard "origin/$BRANCH"
  else
    rm -rf "$SRC_DIR"; git clone --depth 1 --branch "$BRANCH" "$REPO" "$SRC_DIR"
  fi
  ( cd "$SRC_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/node )
  chmod +x "$BIN"
}

gen_cert() {
  mkdir -p "$CERT_DIR"
  if [ -s "$CERT_DIR/ssl_cert.pem" ] && [ -s "$CERT_DIR/ssl_key.pem" ]; then return 0; fi
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/ssl_key.pem" -out "$CERT_DIR/ssl_cert.pem" \
    -days 3650 -nodes -subj "/CN=${PUBLIC_IP}" \
    -addext "subjectAltName = IP:${PUBLIC_IP},IP:127.0.0.1,DNS:localhost"
  chmod 600 "$CERT_DIR/ssl_key.pem"
}

write_service() {
  mkdir -p "$DATA_DIR/generated"
  ( umask 077; echo "$API_KEY" > "$INSTALL_DIR/api_key" )
  cat > "$UNIT" <<EOF
[Unit]
Description=PasarGuard Node (multi-backend)
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=SERVICE_PORT=$SERVICE_PORT
Environment=NODE_HOST=$NODE_HOST
Environment=SERVICE_PROTOCOL=grpc
Environment=API_KEY=$API_KEY
Environment=SSL_CERT_FILE=$CERT_DIR/ssl_cert.pem
Environment=SSL_KEY_FILE=$CERT_DIR/ssl_key.pem
Environment=GENERATED_CONFIG_PATH=$DATA_DIR/generated/
Environment=XRAY_EXECUTABLE_PATH=$XRAY_PATH
Environment=DEBUG=false
ExecStart=$BIN
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1 || true
  # restart (not `enable --now`): on a reinstall the service is already running,
  # and `enable --now` would NOT reload the new unit — so a changed API key / env
  # would never take effect and the panel would report an api-key mismatch.
  systemctl restart "$SERVICE"
}

fw_allow() {
  local port="$1" proto="$2"
  if has ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then ufw allow "${port}/${proto}" || true; fi
  if has firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --permanent --add-port="${port}/${proto}" || true; fi
}
open_firewall() {
  fw_allow "$SERVICE_PORT" tcp
  if want openvpn;   then fw_allow "$OPENVPN_PORT" udp; fw_allow "$OPENVPN_PORT" tcp; fi
  if want wireguard; then fw_allow "$WG_PORT" udp; fi
  if want ikev2;     then fw_allow 500 udp; fw_allow 4500 udp; fi
  has firewall-cmd && firewall-cmd --reload >/dev/null 2>&1 || true
}

print_summary() {
  sleep 2
  echo; hr
  echo -e "  ${c_grn}${c_bld}PasarGuard Node installed${c_off}"
  hr
  echo -e "  Service     : ${SERVICE}.service ($(systemctl is-active "$SERVICE" 2>/dev/null))"
  echo -e "  Backends    : ${c_bld}xray${BACKENDS:+, $BACKENDS}${c_off}"
  echo -e "  Address     : ${c_bld}${PUBLIC_IP}${c_off}"
  echo -e "  Node port   : ${c_bld}${SERVICE_PORT}${c_off}   ${c_dim}(gRPC connects here; set as \"Node Port\" in the panel)${c_off}"
  echo -e "  API port    : ${API_PORT}   ${c_dim}(panel form; only used in REST mode)${c_off}"
  want openvpn   && echo -e "  OpenVPN port: ${OPENVPN_PORT}  ${c_dim}(set the same in the panel core/override)${c_off}"
  want wireguard && echo -e "  WG port     : ${WG_PORT}  ${c_dim}(set the same in the panel core/override)${c_off}"
  want ikev2     && echo -e "  IKEv2 ports : 500, 4500 (UDP, fixed)"
  needs_vpn_net  && echo -e "  Routing     : ${c_bld}IP forward + NAT on${c_off} ${c_dim}(persistent; ${SERVICE}-nat.service)${c_off}"
  echo -e "  ${c_yel}API key${c_off}     : ${c_bld}${API_KEY}${c_off}"
  echo
  echo -e "  Paste this ${c_yel}Server CA${c_off} into the node's \"Server CA\" field"
  echo -e "  ${c_dim}(copy exactly, including BEGIN/END, no leading spaces):${c_off}"
  echo
  cat "$CERT_DIR/ssl_cert.pem"
  echo
  echo -e "  ${c_dim}Logs:${c_off} journalctl -u ${SERVICE} -f"
  warn "If this server has a CLOUD firewall (DigitalOcean/AWS/Hetzner), open the"
  warn "same inbound ports there too — the script can only touch ufw/firewalld."
  hr
}

# Runs the actual install using the currently-set BACKENDS / ports / key. Both
# the menu and the scripted (-y) path call this.
run_install() {
  require_root; detect_pm
  : > "$STEP_LOG"
  [ -z "$API_KEY" ] && API_KEY="$(gen_uuid)"
  detect_public_ip
  echo -e "${c_bld}Installing${c_off} ${c_dim}(backends: xray${BACKENDS:+, $BACKENDS}; details hidden — full log: ${STEP_LOG})${c_off}"
  run_step "Installing base tools"          install_base_deps
  run_step "Installing Go ${GO_VERSION}"    install_go
  run_step "Installing Xray-core${XRAY_VERSION:+ ${XRAY_VERSION}}" install_xray
  want openvpn   && run_step "Installing OpenVPN"            install_openvpn
  want wireguard && run_step "Installing WireGuard"          install_wireguard
  want ikev2     && run_step "Installing strongSwan (IKEv2)" install_ikev2
  run_step "Building node binary (may take a few minutes)"   build_node
  run_step "Generating TLS certificate"     gen_cert
  needs_vpn_net && run_step "Configuring VPN routing (IP forward + NAT)" configure_networking
  run_step "Configuring systemd service"    write_service
  run_step "Opening firewall ports"         open_firewall
  print_summary
}

install_command() {
  parse_install_args "$@"
  # Scripted when -y is given (or a non-interactive shell with backends chosen);
  # otherwise fall through to the interactive menu, pre-seeded from any flags.
  if [ "$ASSUME_YES" -eq 1 ]; then
    run_install
  else
    menu_command
  fi
}

update_command() {
  require_root
  [ -d "$SRC_DIR/.git" ] || die "no install found at $SRC_DIR"
  : > "$STEP_LOG"
  echo -e "${c_bld}Updating${c_off}"
  run_step "Ensuring Go ${GO_VERSION}" install_go
  run_step "Rebuilding node binary"    build_node
  run_step "Restarting service"        _restart
  log "Updated ($(systemctl is-active "$SERVICE"))"
}
_restart() { systemctl restart "$SERVICE"; }

restart_command() { require_root; systemctl restart "$SERVICE"; log "restarted ($(systemctl is-active "$SERVICE"))"; }
status_command()  { systemctl status "$SERVICE" --no-pager || true; }
logs_command()    { journalctl -u "$SERVICE" -f; }
uninstall_command() {
  require_root
  warn "Removing PasarGuard Node"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"
  # Tear down VPN routing (remove NAT rules while the script still exists, then
  # drop the unit and the persistent forwarding drop-in).
  if [ -f "$NAT_UNIT" ]; then
    systemctl disable --now "${SERVICE}-nat.service" 2>/dev/null || true
    [ -x "$NAT_SCRIPT" ] && "$NAT_SCRIPT" down 2>/dev/null || true
    rm -f "$NAT_UNIT"
  fi
  rm -f "$SYSCTL_FILE"
  systemctl daemon-reload 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  if ask_yn "Also remove data/certs in $DATA_DIR?"; then rm -rf "$DATA_DIR"; fi
  log "Uninstalled"
}

main() {
  local cmd="menu"
  case "${1:-}" in
    menu) cmd="menu"; shift ;;
    install|update|uninstall|restart|status|logs) cmd="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    "") cmd="menu" ;;
    -*) cmd="install" ;;                 # flags with no subcommand => install
    *) die "unknown command: $1 (see --help)" ;;
  esac
  case "$cmd" in
    menu)      menu_command ;;
    install)   install_command "$@" ;;
    update)    update_command ;;
    uninstall) uninstall_command ;;
    restart)   restart_command ;;
    status)    status_command ;;
    logs)      logs_command ;;
  esac
}

main "$@"
