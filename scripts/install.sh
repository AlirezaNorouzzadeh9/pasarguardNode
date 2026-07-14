#!/usr/bin/env bash
#
# PasarGuard Node manager (multi-backend fork)
# ---------------------------------------------
# Command-driven, like the upstream pg-node.sh, but builds this fork's
# multi-backend binary and sets up only the backends you pick (xray always;
# openvpn / wireguard / ikev2 optional). It installs their OS deps, opens the
# needed firewall ports, builds the binary, makes a TLS cert + API key, writes a
# systemd service, and prints the details to register the node in the panel.
#
#   sudo bash install.sh                 # interactive install
#   sudo bash install.sh install --backends openvpn,ikev2 \
#        --api-key <uuid> --openvpn-port 1194 --yes
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

SERVICE_PORT="${SERVICE_PORT:-62050}"
NODE_HOST="${NODE_HOST:-0.0.0.0}"
XRAY_PATH="/usr/local/bin/xray"

BACKENDS=""            # comma list; empty -> ask
API_KEY=""             # empty -> ask / auto-generate
OPENVPN_PORT="${OPENVPN_PORT:-1194}"
WG_PORT="${WG_PORT:-51820}"
ASSUME_YES=0
PUBLIC_IP=""

# ---- helpers ----------------------------------------------------------------
c_grn='\033[0;32m'; c_yel='\033[0;33m'; c_red='\033[0;31m'; c_cyn='\033[0;36m'; c_off='\033[0m'
log()  { echo -e "${c_grn}[+]${c_off} $*"; }
warn() { echo -e "${c_yel}[!]${c_off} $*"; }
err()  { echo -e "${c_red}[x]${c_off} $*" >&2; }
die()  { err "$*"; exit 1; }
has()  { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<EOF
PasarGuard Node manager

Usage: sudo bash install.sh [command] [options]

Commands:
  install (default)   Install / reinstall the node
  update              Rebuild the binary from the latest source and restart
  restart             Restart the node service
  status              Show service + node info
  logs                Follow the service logs
  uninstall           Remove the service, binary and data

Install options:
  --backends <list>   openvpn,wireguard,ikev2  (xray always; default: none)
  --api-key <uuid>    Use a specific API key (default: auto-generate)
  --service-port <n>  gRPC control port the panel connects to (default: ${SERVICE_PORT})
  --openvpn-port <n>  OpenVPN listen port to open in the firewall (default: ${OPENVPN_PORT})
  --wireguard-port <n> WireGuard listen port to open (default: ${WG_PORT})
  --host <addr>       Listen address (default: ${NODE_HOST})
  --branch <name>     Git branch to build (default: ${BRANCH})
  --repo <url>        Git repo to build
  -y, --yes           Non-interactive (assume provided flags / all backends)
  -h, --help          This help
EOF
}

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

pm_update() {
  case "$PM" in
    apt) apt-get update -y ;;
    pacman) pacman -Sy --noconfirm ;;
    *) : ;;
  esac
}

ask_yn() { # ask_yn "question" default(y/n) ; default N unless stated
  local q="$1" def="${2:-n}" ans
  if [ "$ASSUME_YES" -eq 1 ]; then [ "$def" = y ]; return; fi
  read -r -p "$q [$( [ "$def" = y ] && echo Y/n || echo y/N )] " ans || true
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

ask_val() { # ask_val "prompt" "default" -> echoes chosen value
  local q="$1" def="$2" ans
  if [ "$ASSUME_YES" -eq 1 ]; then echo "$def"; return; fi
  read -r -p "$q [$def]: " ans || true
  echo "${ans:-$def}"
}

want() { echo ",$BACKENDS," | grep -qi ",$1,"; }

detect_public_ip() {
  PUBLIC_IP="$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP="127.0.0.1"
}

# ---- install steps ----------------------------------------------------------
parse_install_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --backends) BACKENDS="$2"; shift 2 ;;
      --api-key) API_KEY="$2"; shift 2 ;;
      --service-port) SERVICE_PORT="$2"; shift 2 ;;
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

choose_backends() {
  if [ -n "$BACKENDS" ]; then return; fi
  if [ "$ASSUME_YES" -eq 1 ]; then BACKENDS="openvpn,wireguard,ikev2"; return; fi
  echo "Which backends should this node run? (xray is always installed)"
  local sel=""
  ask_yn "  OpenVPN?"          n && sel="$sel,openvpn"
  ask_yn "  WireGuard?"        n && sel="$sel,wireguard"
  ask_yn "  IKEv2 (strongSwan)?" n && sel="$sel,ikev2"
  BACKENDS="${sel#,}"
}

choose_ports() {
  want openvpn   && OPENVPN_PORT="$(ask_val "  OpenVPN listen port (must match the panel core)" "$OPENVPN_PORT")"
  want wireguard && WG_PORT="$(ask_val "  WireGuard listen port (must match the panel core)" "$WG_PORT")"
  SERVICE_PORT="$(ask_val "  gRPC control port (panel connects here)" "$SERVICE_PORT")"
}

choose_apikey() {
  if [ -n "$API_KEY" ]; then return; fi
  if [ -s "$INSTALL_DIR/api_key" ]; then API_KEY="$(cat "$INSTALL_DIR/api_key")"; return; fi
  if [ "$ASSUME_YES" -eq 0 ]; then
    API_KEY="$(ask_val "  API key (blank = auto-generate)" "")"
  fi
  if [ -z "$API_KEY" ]; then
    API_KEY="$( [ -r /proc/sys/kernel/random/uuid ] && cat /proc/sys/kernel/random/uuid || (has uuidgen && uuidgen) )"
  fi
  [ -n "$API_KEY" ] || die "could not obtain an API key"
}

install_go() {
  if has go && go version 2>/dev/null | grep -q "go${GO_VERSION%.*}"; then
    export PATH="$PATH:$(go env GOPATH)/bin:/usr/local/go/bin"; log "Go present: $(go version)"; return
  fi
  local arch; case "$(uname -m)" in
    x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;;
    *) die "unsupported CPU arch: $(uname -m)" ;;
  esac
  log "Installing Go ${GO_VERSION} (${arch})"
  local tgz="/tmp/go${GO_VERSION}.tar.gz"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -o "$tgz"
  rm -rf /usr/local/go && tar -C /usr/local -xzf "$tgz" && rm -f "$tgz"
  export PATH="/usr/local/go/bin:$PATH"
  has go || die "Go install failed"
}

install_base_deps() {
  log "Installing base dependencies"
  pm_update || true
  pm_install curl git ca-certificates openssl iptables || true
}

install_backend_deps() {
  if [ ! -x "$XRAY_PATH" ]; then
    log "Installing xray-core"
    curl -fsSL https://github.com/PasarGuard/scripts/raw/main/install_core.sh | bash || \
      warn "xray-core install failed; install it manually to ${XRAY_PATH}"
  fi
  if want openvpn; then
    log "Installing OpenVPN"; pm_install openvpn
  fi
  if want wireguard; then
    log "Installing WireGuard"
    case "$PM" in apt) pm_install wireguard || pm_install wireguard-tools ;; *) pm_install wireguard-tools ;; esac
    modprobe wireguard 2>/dev/null || warn "wireguard kernel module will load on first use"
  fi
  if want ikev2; then
    log "Installing strongSwan (IKEv2)"
    case "$PM" in
      apt) pm_install strongswan strongswan-swanctl libcharon-extra-plugins ;;
      *)   pm_install strongswan ;;
    esac
    systemctl disable --now strongswan strongswan-starter 2>/dev/null || true
  fi
}

build_node() {
  log "Fetching node source ($BRANCH)"
  mkdir -p "$INSTALL_DIR"
  if [ -d "$SRC_DIR/.git" ]; then
    git -C "$SRC_DIR" fetch --depth 1 origin "$BRANCH" && git -C "$SRC_DIR" reset --hard "origin/$BRANCH"
  else
    rm -rf "$SRC_DIR"; git clone --depth 1 --branch "$BRANCH" "$REPO" "$SRC_DIR"
  fi
  log "Building node binary"
  ( cd "$SRC_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/node )
  chmod +x "$BIN"; log "Built $BIN"
}

gen_cert() {
  mkdir -p "$CERT_DIR"
  if [ -s "$CERT_DIR/ssl_cert.pem" ] && [ -s "$CERT_DIR/ssl_key.pem" ]; then log "TLS cert already present"; return; fi
  log "Generating self-signed TLS cert (SAN includes ${PUBLIC_IP})"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/ssl_key.pem" -out "$CERT_DIR/ssl_cert.pem" \
    -days 3650 -nodes -subj "/CN=${PUBLIC_IP}" \
    -addext "subjectAltName = IP:${PUBLIC_IP},IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1
  chmod 600 "$CERT_DIR/ssl_key.pem"
}

save_apikey() { ( umask 077; echo "$API_KEY" > "$INSTALL_DIR/api_key" ); }

write_service() {
  log "Writing systemd unit ($UNIT)"
  mkdir -p "$DATA_DIR/generated"
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
  systemctl enable --now "$SERVICE"
}

fw_allow() { # fw_allow <port> <proto>
  local port="$1" proto="$2"
  if has ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
  fi
  if has firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || true
  fi
}

open_firewall() {
  log "Opening firewall ports"
  fw_allow "$SERVICE_PORT" tcp                       # gRPC control (panel -> node)
  if want openvpn;   then fw_allow "$OPENVPN_PORT" udp; fw_allow "$OPENVPN_PORT" tcp; fi
  if want wireguard; then fw_allow "$WG_PORT" udp; fi
  if want ikev2;     then fw_allow 500 udp; fw_allow 4500 udp; fi
  has firewall-cmd && firewall-cmd --reload >/dev/null 2>&1 || true
  warn "If this server has a CLOUD firewall (DigitalOcean/AWS/Hetzner/etc.),"
  warn "allow the same inbound ports there too — the script can't do that."
}

print_summary() {
  sleep 2
  echo
  echo -e "${c_cyn}==================== PasarGuard Node installed ====================${c_off}"
  echo -e "  Service     : ${SERVICE}.service ($(systemctl is-active "$SERVICE" 2>/dev/null))"
  echo -e "  Backends    : xray${BACKENDS:+, $BACKENDS}"
  echo -e "  Address     : ${PUBLIC_IP}"
  echo -e "  gRPC port   : ${SERVICE_PORT}"
  want openvpn   && echo -e "  OpenVPN port: ${OPENVPN_PORT} (set the same in the panel core/override)"
  want wireguard && echo -e "  WG port     : ${WG_PORT} (set the same in the panel core/override)"
  want ikev2     && echo -e "  IKEv2 ports : 500, 4500 (UDP, fixed)"
  echo -e "  ${c_yel}API key${c_off}     : ${API_KEY}"
  echo
  echo -e "  Register this node in the panel, then paste the ${c_yel}Server CA${c_off} below"
  echo -e "  into the node's \"Server CA\" field (copy exactly, no leading spaces):"
  echo
  cat "$CERT_DIR/ssl_cert.pem"
  echo
  echo -e "  Logs: ${c_cyn}journalctl -u ${SERVICE} -f${c_off}"
  echo -e "${c_cyn}==================================================================${c_off}"
}

install_command() {
  parse_install_args "$@"
  require_root; detect_pm
  choose_backends
  choose_ports
  detect_public_ip
  install_base_deps
  install_backend_deps
  install_go
  build_node
  gen_cert
  choose_apikey
  save_apikey
  write_service
  open_firewall
  print_summary
}

update_command() {
  require_root
  [ -d "$SRC_DIR/.git" ] || die "no install found at $SRC_DIR"
  install_go
  log "Updating node source ($BRANCH)"
  git -C "$SRC_DIR" fetch --depth 1 origin "$BRANCH" && git -C "$SRC_DIR" reset --hard "origin/$BRANCH"
  ( cd "$SRC_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/node )
  systemctl restart "$SERVICE"
  log "Updated and restarted ($(systemctl is-active "$SERVICE"))"
}

restart_command() { require_root; systemctl restart "$SERVICE"; log "restarted ($(systemctl is-active "$SERVICE"))"; }
status_command()  { systemctl status "$SERVICE" --no-pager || true; }
logs_command()    { journalctl -u "$SERVICE" -f; }

uninstall_command() {
  require_root
  warn "Removing PasarGuard Node"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  read -r -p "Also remove data/certs in $DATA_DIR? [y/N] " a || true
  [[ "${a:-n}" =~ ^[Yy]$ ]] && rm -rf "$DATA_DIR"
  log "Uninstalled"
}

main() {
  local cmd="install"
  case "${1:-}" in
    install|update|uninstall|restart|status|logs) cmd="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
  esac
  case "$cmd" in
    install)   install_command "$@" ;;
    update)    update_command ;;
    uninstall) uninstall_command ;;
    restart)   restart_command ;;
    status)    status_command ;;
    logs)      logs_command ;;
  esac
}

main "$@"
