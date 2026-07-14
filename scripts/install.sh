#!/usr/bin/env bash
#
# PasarGuard Node installer (multi-backend fork)
# -----------------------------------------------
# Installs the node binary + a systemd service and the OS-level dependencies for
# the backends you choose (xray is always available; openvpn / wireguard / ikev2
# are optional). The panel then decides which cores each node actually runs, and
# greys out any backend this installer did not set up.
#
#   sudo bash install.sh                       # interactive
#   sudo bash install.sh --backends openvpn,ikev2 --port 62050 --yes
#   sudo bash install.sh --uninstall
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

BACKENDS=""        # comma list; empty -> ask
ASSUME_YES=0
DO_UNINSTALL=0
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
PasarGuard Node installer

  --backends <list>   Comma list of backends to install deps for:
                      openvpn,wireguard,ikev2  (xray is always included)
  --port <n>          gRPC service port (default: ${SERVICE_PORT})
  --host <addr>       Listen address (default: ${NODE_HOST})
  --branch <name>     Git branch to build (default: ${BRANCH})
  --repo <url>        Git repo to build (default: fork)
  -y, --yes           Non-interactive; assume defaults / provided flags
  --uninstall         Remove the service, binary and data
  -h, --help          This help
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --backends) BACKENDS="$2"; shift 2 ;;
      --port)     SERVICE_PORT="$2"; shift 2 ;;
      --host)     NODE_HOST="$2"; shift 2 ;;
      --branch)   BRANCH="$2"; shift 2 ;;
      --repo)     REPO="$2"; shift 2 ;;
      -y|--yes)   ASSUME_YES=1; shift ;;
      --uninstall) DO_UNINSTALL=1; shift ;;
      -h|--help)  usage; exit 0 ;;
      *) die "unknown argument: $1 (see --help)" ;;
    esac
  done
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
    dnf|yum) : ;;
    pacman) pacman -Sy --noconfirm ;;
  esac
}

ask_yn() { # ask_yn "question" default(y/n)
  local q="$1" def="${2:-y}" ans
  if [ "$ASSUME_YES" -eq 1 ]; then [ "$def" = y ]; return; fi
  read -r -p "$q [$( [ "$def" = y ] && echo Y/n || echo y/N )] " ans || true
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

want() { # want backend-name  -> is it in the selected list?
  echo ",$BACKENDS," | grep -qi ",$1,"
}

detect_public_ip() {
  PUBLIC_IP="$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP="127.0.0.1"
}

# ---- steps ------------------------------------------------------------------
choose_backends() {
  if [ -n "$BACKENDS" ]; then return; fi
  if [ "$ASSUME_YES" -eq 1 ]; then BACKENDS="openvpn,wireguard,ikev2"; return; fi
  echo "Which backends should this node be able to run? (xray is always installed)"
  local sel=""
  ask_yn "  OpenVPN?"          y && sel="$sel,openvpn"
  ask_yn "  WireGuard?"        y && sel="$sel,wireguard"
  ask_yn "  IKEv2 (strongSwan)?" y && sel="$sel,ikev2"
  BACKENDS="${sel#,}"
}

install_go() {
  if has go && go version 2>/dev/null | grep -q "go${GO_VERSION%.*}"; then
    log "Go present: $(go version)"; export PATH="$PATH:$(go env GOPATH)/bin:/usr/local/go/bin"; return
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
  log "Go installed: $(go version)"
}

install_base_deps() {
  log "Installing base dependencies"
  pm_update || true
  pm_install curl git ca-certificates openssl iptables || true
}

install_backend_deps() {
  # xray core (always)
  if [ ! -x "$XRAY_PATH" ]; then
    log "Installing xray-core"
    curl -fsSL https://github.com/PasarGuard/scripts/raw/main/install_core.sh | bash || \
      warn "xray-core install failed; install it manually to ${XRAY_PATH}"
  else
    log "xray-core already present"
  fi

  if want openvpn; then
    log "Installing OpenVPN"
    pm_install openvpn
  fi
  if want wireguard; then
    log "Installing WireGuard"
    case "$PM" in
      apt) pm_install wireguard || pm_install wireguard-tools ;;
      *)   pm_install wireguard-tools ;;
    esac
    modprobe wireguard 2>/dev/null || warn "could not load wireguard kernel module now (will load on use)"
  fi
  if want ikev2; then
    log "Installing strongSwan (IKEv2)"
    case "$PM" in
      apt) pm_install strongswan strongswan-swanctl libcharon-extra-plugins ;;
      dnf|yum) pm_install strongswan ;;
      pacman) pm_install strongswan ;;
    esac
    # The node supervises charon itself; don't let the distro unit hold the ports.
    systemctl disable --now strongswan strongswan-starter 2>/dev/null || true
  fi
}

build_node() {
  log "Fetching node source ($BRANCH)"
  mkdir -p "$INSTALL_DIR"
  if [ -d "$SRC_DIR/.git" ]; then
    git -C "$SRC_DIR" fetch --depth 1 origin "$BRANCH"
    git -C "$SRC_DIR" reset --hard "origin/$BRANCH"
  else
    rm -rf "$SRC_DIR"
    git clone --depth 1 --branch "$BRANCH" "$REPO" "$SRC_DIR"
  fi
  log "Building node binary"
  ( cd "$SRC_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$BIN" ./cmd/node )
  chmod +x "$BIN"
  log "Built $BIN"
}

gen_cert() {
  mkdir -p "$CERT_DIR"
  if [ -s "$CERT_DIR/ssl_cert.pem" ] && [ -s "$CERT_DIR/ssl_key.pem" ]; then
    log "TLS cert already present"; return
  fi
  log "Generating self-signed TLS cert (SAN includes ${PUBLIC_IP})"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/ssl_key.pem" -out "$CERT_DIR/ssl_cert.pem" \
    -days 3650 -nodes -subj "/CN=${PUBLIC_IP}" \
    -addext "subjectAltName = IP:${PUBLIC_IP},IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1
  chmod 600 "$CERT_DIR/ssl_key.pem"
}

gen_apikey() {
  if [ -s "$INSTALL_DIR/api_key" ]; then API_KEY="$(cat "$INSTALL_DIR/api_key")"; return; fi
  API_KEY="$( [ -r /proc/sys/kernel/random/uuid ] && cat /proc/sys/kernel/random/uuid || (has uuidgen && uuidgen) )"
  [ -n "$API_KEY" ] || die "could not generate API key"
  ( umask 077; echo "$API_KEY" > "$INSTALL_DIR/api_key" )
}

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

open_firewall() {
  local port="$SERVICE_PORT"
  if has ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
    ufw allow "${port}/tcp" >/dev/null 2>&1 && log "Opened ${port}/tcp in ufw"
  fi
  if has firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 && log "Opened ${port}/tcp in firewalld"
  fi
  warn "If this server has a CLOUD firewall (DigitalOcean/AWS/Hetzner/etc.),"
  warn "you must also allow inbound TCP ${port} in the provider's dashboard."
}

print_summary() {
  sleep 2
  echo
  echo -e "${c_cyn}==================== PasarGuard Node installed ====================${c_off}"
  echo -e "  Service     : ${SERVICE}.service ($(systemctl is-active "$SERVICE" 2>/dev/null))"
  echo -e "  Backends    : xray${BACKENDS:+, $BACKENDS}"
  echo -e "  Address     : ${PUBLIC_IP}"
  echo -e "  Port        : ${SERVICE_PORT}"
  echo -e "  Protocol    : grpc"
  echo -e "  ${c_yel}API key${c_off}     : ${API_KEY}"
  echo
  echo -e "  Register this node in the panel with the above, and paste the"
  echo -e "  ${c_yel}Server CA${c_off} below into the node's \"Server CA\" field"
  echo -e "  (copy exactly, including the BEGIN/END lines, no extra spaces):"
  echo
  cat "$CERT_DIR/ssl_cert.pem"
  echo
  echo -e "  Logs: ${c_cyn}journalctl -u ${SERVICE} -f${c_off}"
  echo -e "${c_cyn}==================================================================${c_off}"
}

uninstall() {
  warn "Removing PasarGuard Node"
  systemctl disable --now "$SERVICE" 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload 2>/dev/null || true
  rm -rf "$INSTALL_DIR"
  read -r -p "Also remove data/certs in $DATA_DIR? [y/N] " a || true
  [[ "${a:-n}" =~ ^[Yy]$ ]] && rm -rf "$DATA_DIR"
  log "Uninstalled"
}

main() {
  parse_args "$@"
  require_root
  detect_pm
  if [ "$DO_UNINSTALL" -eq 1 ]; then uninstall; exit 0; fi
  choose_backends
  detect_public_ip
  install_base_deps
  install_backend_deps
  install_go
  build_node
  gen_cert
  gen_apikey
  write_service
  open_firewall
  print_summary
}

main "$@"
