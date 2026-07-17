#!/usr/bin/env bash
#
# PasarGuard Node — Docker installer (multi-backend fork)
# -------------------------------------------------------
# Installs the node as a Docker container from this fork's prebuilt image (all
# backends baked in: xray / openvpn / wireguard / strongSwan-IKEv2). Run with no
# argument for an interactive menu: toggle which backends run here, set the node
# (gRPC) port + API key, then install. It installs Docker if missing, writes a
# docker-compose.yml, brings the container up, and prints the Server CA + details
# to register the node in the panel.
#
#   sudo bash install.sh                                    # interactive menu
#   sudo bash install.sh install --disable openvpn,ikev2 \
#        --api-key <uuid> --service-port 62050 --yes        # scripted
#   sudo bash install.sh update | restart | status | logs | uninstall
#
# VPN ports (OpenVPN/WireGuard) and IKEv2 (fixed 500/4500) are configured in the
# PANEL's core config, not here — host networking binds whatever the panel sets.
#
set -euo pipefail

# ---- defaults (override via flags / env) -----------------------------------
REPO="${REPO:-https://github.com/AlirezaNorouzzadeh9/pasarguardNode}"
IMAGE="${IMAGE:-ghcr.io/alirezanorouzzadeh9/pasarguardnode:latest}"
BRANCH="${BRANCH:-main}"

SERVICE="${SERVICE:-pg-node}"                 # container name + compose project
INSTALL_DIR="${INSTALL_DIR:-/opt/pg-node}"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
DATA_DIR="${DATA_DIR:-/var/lib/pg-node}"

SERVICE_PORT="${SERVICE_PORT:-62050}"
API_KEY=""                                    # empty -> auto-generate
BUILD_FROM_SOURCE=0                           # 1 -> compose builds the image locally
ASSUME_YES=0
QUIET="${QUIET:-0}"                           # 1 -> hide docker pull/build output

# Which backends run here (image ships all; off -> PG_NODE_DISABLE_*).
XRAY_ON=1; OVPN_ON=1; WG_ON=1; IKEV2_ON=1

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

# Read that works under `curl … | bash` too.
_read() { if [ -e /dev/tty ]; then read "$@" </dev/tty || true; else read "$@" || true; fi; }

# Quiet step with colored progress; output goes to the log file. Use this only
# for steps that finish instantly — anything that can take minutes should use
# run_step_live so the user can see it working instead of staring at a frozen
# line and assuming it hung.
STEP_LOG="/tmp/pg-node-docker.log"
run_step() {
  local msg="$1"; shift
  echo -ne "  ${c_cyn}▶${c_off} ${msg} ${c_dim}...${c_off} "
  if "$@" >>"$STEP_LOG" 2>&1; then
    echo -e "${c_grn}done${c_off}"
  else
    echo -e "${c_red}failed${c_off}"
    err "step failed: ${msg}"; err "last lines of ${STEP_LOG}:"; tail -n 12 "$STEP_LOG" >&2 || true
    exit 1
  fi
}

_rule() { echo -e "${c_dim}    ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄${c_off}"; }

# Runs "$@" with its output streamed to the terminal and appended to the log,
# and returns its exit status.
#
# It deliberately does NOT pipe ("$@" | tee): a pipeline runs the command in a
# subshell, so anything it sets is lost — install_docker calls detect_compose to
# set COMPOSE_CMD, and losing that left $COMPOSE_CMD empty and the next step
# running a bare `pull`/`up` ("pull: command not found"). Redirecting to a
# process substitution keeps the command in this shell. The fd is closed and the
# reader reaped before returning, so its output can't land after the result line.
_stream() {
  local fd rc
  exec {fd}> >(tee -a "$STEP_LOG" | sed "s/^/    /")
  "$@" >&"$fd" 2>&1
  rc=$?
  exec {fd}>&-
  wait 2>/dev/null || true
  return $rc
}

# Long step whose output the user should watch live (docker pull/build/up: layer
# downloads, build steps). QUIET=1 falls back to the silent behaviour.
run_step_live() {
  local msg="$1"; shift
  if [ "${QUIET:-0}" = "1" ]; then run_step "$msg" "$@"; return; fi
  echo -e "  ${c_cyn}▶${c_off} ${c_bld}${msg}${c_off}"
  _rule
  if _stream "$@"; then
    _rule; echo -e "  ${c_grn}✔${c_off} ${msg}"
  else
    _rule; echo -e "  ${c_red}✘${c_off} ${msg}"
    err "step failed: ${msg} (full log: ${STEP_LOG})"
    exit 1
  fi
}

# run_step_live variant that returns non-zero instead of exiting.
run_step_live_soft() {
  local msg="$1"; shift
  if [ "${QUIET:-0}" = "1" ]; then run_step_soft "$msg" "$@"; return; fi
  echo -e "  ${c_cyn}▶${c_off} ${c_bld}${msg}${c_off}"
  _rule
  if _stream "$@"; then
    echo -e "  ${c_grn}✔${c_off} ${msg}"; return 0
  else
    echo -e "  ${c_yel}▷${c_off} ${msg} — ${c_yel}skipped${c_off}"; return 1
  fi
}

# ---- input prompts (strict) -------------------------------------------------
ask_yn() {
  local q="$1" ans
  while true; do
    _read -r -p "$(echo -e "${c_bld}${q}${c_off} (y/n, Enter = no): ")" ans
    case "${ans:-n}" in
      [Yy]|[Yy][Ee][Ss]) return 0 ;;
      [Nn]|[Nn][Oo])     return 1 ;;
      *) warn "Please type only 'y' (yes) or 'n' (no)." ;;
    esac
  done
}
ask_val() {
  local q="$1" def="$2" ans
  _read -r -p "$(echo -e "${c_bld}${q}${c_off}${def:+ [${def}]}: ")" ans
  echo "${ans:-$def}"
}
ask_num() {
  local q="$1" def="$2" ans
  while true; do
    _read -r -p "$(echo -e "${c_bld}${q}${c_off} [${def}]: ")" ans
    ans="${ans:-$def}"
    if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le 65535 ]; then echo "$ans"; return; fi
    warn "Please enter a port between 1 and 65535."
  done
}

# ---- system helpers ---------------------------------------------------------
require_root() { [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"; }
gen_uuid() { [ -r /proc/sys/kernel/random/uuid ] && cat /proc/sys/kernel/random/uuid || (has uuidgen && uuidgen) || die "cannot generate a UUID"; }

# `docker compose` (v2 plugin) or the legacy `docker-compose`.
COMPOSE_CMD=""
detect_compose() {
  if docker compose version >/dev/null 2>&1; then COMPOSE_CMD="docker compose"
  elif has docker-compose; then COMPOSE_CMD="docker-compose"
  else return 1; fi
}
dc() { ( cd "$INSTALL_DIR" && $COMPOSE_CMD "$@" ); }

# Fresh VPS images kick off unattended-upgrades / apt-daily on first boot, which
# holds the dpkg lock for the first few minutes. get.docker.com then dies with
#   E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process N
# Wait it out instead of failing the install on a brand new server.
apt_busy() {
  local f
  for f in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
           /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
    [ -e "$f" ] || continue
    if has fuser && fuser "$f" >/dev/null 2>&1; then return 0; fi
  done
  # fuser isn't always installed; fall back to spotting the processes themselves.
  if has pgrep; then
    local p
    for p in apt apt-get dpkg; do
      pgrep -x "$p" >/dev/null 2>&1 && return 0
    done
    pgrep -f unattended-upgr >/dev/null 2>&1 && return 0
  fi
  return 1
}

wait_for_apt() {
  has apt-get || return 0            # not a debian-family box; nothing to wait on
  apt_busy || return 0               # already free — don't print anything
  local waited=0 max="${APT_LOCK_TIMEOUT:-300}"
  log "another apt/dpkg process is running (unattended-upgrades on a fresh VPS) — waiting up to ${max}s..."
  while apt_busy; do
    if [ "$waited" -ge "$max" ]; then
      warn "apt is still locked after ${max}s."
      warn "Wait for it to finish (or: systemctl stop unattended-upgrades) and re-run."
      return 1
    fi
    sleep 3; waited=$((waited + 3))
  done
  log "apt is free (waited ${waited}s) — continuing"
}

install_docker() {
  if ! has docker; then
    wait_for_apt || die "apt is locked by another process — see above"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker 2>/dev/null || true
  fi
  detect_compose || die "docker compose plugin not available after install"
}

usage() {
  cat <<EOF
PasarGuard Node — Docker installer

Usage: sudo bash install.sh [command] [options]

Commands:
  (no command) / menu   Interactive menu (toggle backends, then install)
  install               Install / reinstall the container
  update                Pull the latest image (or rebuild) and recreate
  restart | status | logs
  uninstall             Stop and remove the container (asks about data)

Install options (skip the menu with -y):
  --disable <list>      comma list of xray,openvpn,wireguard,ikev2 to NOT run here
  --api-key <uuid>      (default: auto-generate)
  --service-port <n>    gRPC port the panel connects to (default: ${SERVICE_PORT})
  --image <ref>         image to pull (default: ${IMAGE})
  --build               build the image from source instead of pulling
  --branch <name> | --repo <url>
  -y, --yes             non-interactive
  -q, --quiet           hide docker pull/build output (default: show it live)
  -h, --help

Docker pull/build/up stream their output so you can watch progress; the full
log is always kept at ${STEP_LOG}.
EOF
}

parse_install_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --disable)
        local d=",$2,"
        echo "$d" | grep -qi ",xray,"      && XRAY_ON=0
        echo "$d" | grep -qi ",openvpn,"   && OVPN_ON=0
        echo "$d" | grep -qi ",wireguard," && WG_ON=0
        echo "$d" | grep -qi ",ikev2,"     && IKEV2_ON=0
        shift 2 ;;
      --api-key) API_KEY="$2"; shift 2 ;;
      --service-port|--port) SERVICE_PORT="$2"; shift 2 ;;
      --image) IMAGE="$2"; shift 2 ;;
      --build) BUILD_FROM_SOURCE=1; shift ;;
      --branch) BRANCH="$2"; shift 2 ;;
      --repo) REPO="$2"; shift 2 ;;
      -y|--yes) ASSUME_YES=1; shift ;;
      -q|--quiet) QUIET=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1 (see --help)" ;;
    esac
  done
}

# ---- interactive menu -------------------------------------------------------
onoff() { if [ "${1:-0}" -eq 1 ]; then echo -e "${c_grn}${c_bld}● ON${c_off}"; else echo -e "${c_dim}○ off${c_off}"; fi; }
press_enter() { echo; _read -r -p "$(echo -e "  ${c_dim}Press Enter to return to the menu…${c_off}")" _; }

banner() {
  clear 2>/dev/null || true
  echo
  echo -e "  ${c_cyn}${c_bld}╔══════════════════════════════════════════════════════╗${c_off}"
  echo -e "  ${c_cyn}${c_bld}║${c_off}       ${c_bld}PasarGuard Node${c_off}  ${c_dim}·${c_off}  ${c_mag}${c_bld}Docker install${c_off}         ${c_cyn}${c_bld}║${c_off}"
  echo -e "  ${c_cyn}${c_bld}╚══════════════════════════════════════════════════════╝${c_off}"
  echo
}

menu_command() {
  require_root
  if [ ! -e /dev/tty ] && [ ! -t 0 ]; then
    die "no terminal for the menu — run non-interactively, e.g.:
  sudo bash install.sh install --disable wireguard -y   (see --help)"
  fi
  local status="not installed"
  has docker && docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$SERVICE" && \
    status="installed ($(docker inspect -f '{{.State.Status}}' "$SERVICE" 2>/dev/null))"

  while true; do
    banner
    echo -e "  ${c_dim}State:${c_off} ${c_bld}${status}${c_off}   ${c_dim}image:${c_off} $([ "$BUILD_FROM_SOURCE" = 1 ] && echo 'build from source' || echo "$IMAGE")"
    echo
    echo -e "  ${c_bld}Backends${c_off} ${c_dim}(image ships all — toggle what runs on this node)${c_off}"
    printf "    ${c_bld}1${c_off}  %-24s %b\n" "Xray"               "$(onoff "$XRAY_ON")"
    printf "    ${c_bld}2${c_off}  %-24s %b\n" "OpenVPN"            "$(onoff "$OVPN_ON")"
    printf "    ${c_bld}3${c_off}  %-24s %b\n" "WireGuard"          "$(onoff "$WG_ON")"
    printf "    ${c_bld}4${c_off}  %-24s %b\n" "IKEv2 (strongSwan)" "$(onoff "$IKEV2_ON")"
    echo
    echo -e "  ${c_bld}Settings${c_off}"
    printf "    ${c_bld}5${c_off}  %-24s ${c_cyn}%s${c_off}\n" "Node port (gRPC)" "$SERVICE_PORT"
    printf "    ${c_bld}6${c_off}  %-24s ${c_cyn}%s${c_off}\n" "API key"          "${API_KEY:-auto-generate}"
    printf "    ${c_bld}7${c_off}  %-24s ${c_cyn}%s${c_off}\n" "Image source"     "$([ "$BUILD_FROM_SOURCE" = 1 ] && echo 'build from source' || echo 'pull (ghcr)')"
    echo -e "    ${c_dim}VPN ports (OpenVPN/WireGuard) are set in the panel; IKEv2 is 500/4500.${c_off}"
    echo
    echo -e "  ${c_bld}Actions${c_off}"
    echo -e "    ${c_grn}${c_bld}i${c_off}  Install / reinstall with the selection above"
    echo -e "    ${c_bld}u${c_off} Update   ${c_bld}s${c_off} Status   ${c_bld}l${c_off} Logs   ${c_bld}r${c_off} Restart   ${c_red}x${c_off} Uninstall   ${c_bld}q${c_off} Quit"
    echo
    local choice
    _read -r -p "$(echo -e "  ${c_bld}Select${c_off} ${c_dim}(number or letter)${c_off} ${c_cyn}❯${c_off} ")" choice
    case "$choice" in
      1) XRAY_ON=$((1 - XRAY_ON)) ;;
      2) OVPN_ON=$((1 - OVPN_ON)) ;;
      3) WG_ON=$((1 - WG_ON)) ;;
      4) IKEV2_ON=$((1 - IKEV2_ON)) ;;
      5) SERVICE_PORT="$(ask_num "Node port (gRPC connects here)" "$SERVICE_PORT")" ;;
      6) API_KEY="$(ask_val "API key (blank = auto-generate)" "$API_KEY")" ;;
      7) BUILD_FROM_SOURCE=$((1 - BUILD_FROM_SOURCE)) ;;
      i|I) echo; run_install; break ;;
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

# ---- compose file -----------------------------------------------------------
write_compose() {
  mkdir -p "$INSTALL_DIR" "$DATA_DIR"
  {
    echo "services:"
    echo "  node:"
    if [ "$BUILD_FROM_SOURCE" = 1 ]; then
      echo "    build: ${REPO}.git#${BRANCH}"
    else
      echo "    image: ${IMAGE}"
    fi
    echo "    container_name: ${SERVICE}"
    echo "    restart: always"
    echo "    network_mode: host"
    echo "    cap_add:"
    echo "      - NET_ADMIN"
    echo "      - SYS_MODULE"
    echo "    devices:"
    echo "      - /dev/net/tun"
    echo "    environment:"
    echo "      API_KEY: \"${API_KEY}\""
    echo "      SERVICE_PORT: ${SERVICE_PORT}"
    echo "      SERVICE_PROTOCOL: \"grpc\""
    echo "      PG_NODE_WG_HOST_ROUTING: \"1\""
    [ "$XRAY_ON"  -eq 0 ] && echo "      PG_NODE_DISABLE_XRAY: \"1\""
    [ "$OVPN_ON"  -eq 0 ] && echo "      PG_NODE_DISABLE_OPENVPN: \"1\""
    [ "$WG_ON"    -eq 0 ] && echo "      PG_NODE_DISABLE_WIREGUARD: \"1\""
    [ "$IKEV2_ON" -eq 0 ] && echo "      PG_NODE_DISABLE_IKEV2: \"1\""
    echo "    volumes:"
    echo "      - /lib/modules:/lib/modules:ro"
    echo "      - ${DATA_DIR}:/var/lib/pg-node"
  } > "$COMPOSE_FILE"
}

compose_up()   { dc up -d $([ "$BUILD_FROM_SOURCE" = 1 ] && echo --build); }
pull_image()   { dc pull; }

print_summary() {
  # Read the CA straight from the mounted cert file (no `docker logs` prefix, so
  # it copy-pastes cleanly). Wait for the container to generate it on first run.
  local ca="" i cert_file="$DATA_DIR/certs/ssl_cert.pem"
  for i in $(seq 1 20); do
    [ -s "$cert_file" ] && { ca="$(cat "$cert_file")"; break; }
    sleep 1
  done
  local ip; ip="$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || echo '<server-ip>')"
  local backends=""
  [ "$XRAY_ON"  -eq 1 ] && backends="${backends} xray"
  [ "$OVPN_ON"  -eq 1 ] && backends="${backends} openvpn"
  [ "$WG_ON"    -eq 1 ] && backends="${backends} wireguard"
  [ "$IKEV2_ON" -eq 1 ] && backends="${backends} ikev2"

  echo; hr
  echo -e "  ${c_grn}${c_bld}PasarGuard Node running in Docker${c_off}"
  hr
  echo -e "  Container   : ${SERVICE} ($(docker inspect -f '{{.State.Status}}' "$SERVICE" 2>/dev/null))"
  echo -e "  Backends    : ${c_bld}${backends# }${c_off}"
  echo -e "  Address     : ${c_bld}${ip}${c_off}"
  echo -e "  Node port   : ${c_bld}${SERVICE_PORT}${c_off}   ${c_dim}(gRPC; set as \"Node Port\" in the panel)${c_off}"
  echo -e "  ${c_yel}API key${c_off}     : ${c_bld}${API_KEY}${c_off}"
  echo -e "  Compose     : ${COMPOSE_FILE}"
  echo
  if [ -n "$ca" ]; then
    echo -e "  Paste this ${c_yel}Server CA${c_off} into the node's \"Server CA\" field:"; echo
    echo "$ca"
  else
    warn "Couldn't read the Server CA yet — get it with:"
    echo -e "  ${c_dim}cat ${cert_file}${c_off}"
  fi
  echo
  echo -e "  ${c_dim}Logs:${c_off} ${COMPOSE_CMD} -f ${COMPOSE_FILE} logs -f"
  warn "VPN ports are set in the panel core config. Open the same ports on any"
  warn "CLOUD firewall (host networking binds them on the host directly)."
  hr
}

run_install() {
  require_root
  : > "$STEP_LOG"
  [ -z "$API_KEY" ] && API_KEY="$(gen_uuid)"
  # ${QUIET:+…} would fire on the literal "0" too, so test the value.
  local quiet_note=""; [ "${QUIET:-0}" = "1" ] && quiet_note=" — quiet mode"
  echo -e "${c_bld}Installing${c_off} ${c_dim}(full log: ${STEP_LOG}${quiet_note})${c_off}"
  run_step_live "Installing Docker"          install_docker
  run_step      "Writing docker-compose.yml" write_compose
  if [ "$BUILD_FROM_SOURCE" = 0 ]; then
    if ! run_step_live_soft "Pulling image ${IMAGE}" pull_image; then
      warn "image pull failed — falling back to building from source (this takes a few minutes)"
      BUILD_FROM_SOURCE=1
      run_step "Rewriting docker-compose.yml" write_compose
    fi
  fi
  run_step_live "Starting container"         compose_up
  print_summary
}

# run_step variant that returns non-zero instead of exiting (for the pull fallback).
run_step_soft() {
  local msg="$1"; shift
  echo -ne "  ${c_cyn}▶${c_off} ${msg} ${c_dim}...${c_off} "
  if "$@" >>"$STEP_LOG" 2>&1; then echo -e "${c_grn}done${c_off}"; return 0
  else echo -e "${c_yel}skipped${c_off}"; return 1; fi
}

install_command() {
  parse_install_args "$@"
  require_root
  if [ "$ASSUME_YES" -eq 1 ]; then run_install; else menu_command; fi
}

update_command() {
  require_root; detect_compose || install_docker
  [ -f "$COMPOSE_FILE" ] || die "no install found at $COMPOSE_FILE"
  : > "$STEP_LOG"
  echo -e "${c_bld}Updating${c_off}"
  if grep -q "build:" "$COMPOSE_FILE"; then
    run_step_live "Rebuilding image" bash -c "cd '$INSTALL_DIR' && $COMPOSE_CMD build --pull"
  else
    run_step_live "Pulling latest image" pull_image
  fi
  run_step_live "Recreating container" bash -c "cd '$INSTALL_DIR' && $COMPOSE_CMD up -d"
  log "Updated ($(docker inspect -f '{{.State.Status}}' "$SERVICE" 2>/dev/null))"
}

need_compose() { detect_compose || { warn "Docker / compose not found — install first."; return 1; }; [ -f "$COMPOSE_FILE" ] || { warn "no install found at $COMPOSE_FILE"; return 1; }; }
restart_command()  { require_root; need_compose || return 0; dc restart; log "restarted"; }
status_command()   { need_compose || return 0; dc ps; }
logs_command()     { need_compose || return 0; dc logs -f; }
uninstall_command() {
  require_root; detect_compose || true
  warn "Removing the PasarGuard Node container"
  [ -f "$COMPOSE_FILE" ] && dc down 2>/dev/null || docker rm -f "$SERVICE" 2>/dev/null || true
  rm -f "$COMPOSE_FILE"
  if ask_yn "Also remove data (certs + generated configs) in $DATA_DIR?"; then rm -rf "$DATA_DIR"; fi
  log "Uninstalled"
}

main() {
  local cmd="menu"
  case "${1:-}" in
    menu) cmd="menu"; shift ;;
    install|update|uninstall|restart|status|logs) cmd="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    "") cmd="menu" ;;
    -*) cmd="install" ;;
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
