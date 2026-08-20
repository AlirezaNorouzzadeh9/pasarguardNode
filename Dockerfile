FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk update && apk add --no-cache make

WORKDIR /src

COPY go* .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make NAME=main build
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} make install_xray

# sing-box is built from source rather than taken from a release, because the
# released binary cannot do what this node needs: stock sing-box can only be
# told its user set once, at startup, so every user change would restart the
# process and drop every live connection. singbox/*.patch adds the runtime user
# endpoint and makes the stats service count users created after startup.
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS singbox

ARG TARGETOS
ARG TARGETARCH
ARG SINGBOX_VERSION=v1.13.18

RUN apk update && apk add --no-cache git

WORKDIR /build
RUN git clone --depth 1 --branch ${SINGBOX_VERSION} https://github.com/SagerNet/sing-box.git .

COPY singbox/ /patches/
# git am needs an identity, and a rejected patch must fail the build rather
# than quietly produce a stock binary that looks fine until a user is added.
RUN git -c user.name=build -c user.email=build@local am /patches/*.patch

# with_v2ray_api is NOT in sing-box's default tag set and is required: without
# it there are no per-user counters at all, so every user's usage reads as zero
# while the core reports itself perfectly healthy.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -tags with_quic,with_clash_api,with_v2ray_api,with_utls,with_gvisor \
    -trimpath -ldflags "-s -w" \
    -o /out/sing-box ./cmd/sing-box

FROM alpine:latest

LABEL org.opencontainers.image.source="https://github.com/PasarGuard/node"

RUN apk update && apk add --no-cache wireguard-tools nftables iproute2 procps openvpn iptables \
      strongswan xl2tpd ppp

WORKDIR /app
COPY --from=builder /src/main /app/main
COPY --from=builder /usr/local/bin/xray /usr/local/bin/xray
COPY --from=builder /usr/local/share/xray /usr/local/share/xray
COPY --from=singbox /out/sing-box /usr/local/bin/sing-box

# Fail the build rather than ship an image whose cores die on startup: a missing
# runtime binary only shows up when a user tries to connect, long after the node
# has reported itself healthy.
RUN set -e; \
    for bin in wg nft ip openvpn iptables sing-box swanctl xl2tpd pppd; do \
        command -v "$bin" >/dev/null || { echo "missing runtime dependency: $bin" >&2; exit 1; }; \
    done; \
    # charon is a daemon, not on PATH; the backend probes these two locations.
    { test -x /usr/lib/strongswan/charon || test -x /usr/lib/ipsec/charon; } \
        || { echo "missing runtime dependency: charon" >&2; exit 1; }; \
    # EAP/CHAP crypto lives in plugins; without openssl among them every L2TP
    # auth fails at the MD4/DES step no matter the password.
    ls /usr/lib/strongswan/plugins/ 2>/dev/null | grep -q openssl \
        || ls /usr/lib/ipsec/plugins/ 2>/dev/null | grep -q openssl \
        || { echo "missing strongswan openssl plugin" >&2; exit 1; }; \
    openvpn --version | head -1; \
    sing-box version | head -1; \
    # The patched endpoint and the stats tag are the two things that make this
    # binary usable here, and both fail silently at runtime if they are absent.
    sing-box version | grep -q with_v2ray_api || { echo "sing-box built without with_v2ray_api: no per-user usage" >&2; exit 1; }; \
    sing-box version | grep -q with_clash_api || { echo "sing-box built without with_clash_api: users cannot be pushed" >&2; exit 1; }

ENTRYPOINT ["./main"]
