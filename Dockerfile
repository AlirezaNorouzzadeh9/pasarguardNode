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

FROM alpine:latest

LABEL org.opencontainers.image.source="https://github.com/PasarGuard/node"

RUN apk update && apk add --no-cache wireguard-tools nftables iproute2 procps openvpn iptables

# Fail the build rather than ship an image whose cores die on startup: a missing
# runtime binary only shows up when a user tries to connect, long after the node
# has reported itself healthy.
RUN set -e; \
    for bin in wg nft ip openvpn iptables; do \
        command -v "$bin" >/dev/null || { echo "missing runtime dependency: $bin" >&2; exit 1; }; \
    done; \
    openvpn --version | head -1

WORKDIR /app
COPY --from=builder /src/main /app/main
COPY --from=builder /usr/local/bin/xray /usr/local/bin/xray
COPY --from=builder /usr/local/share/xray /usr/local/share/xray

ENTRYPOINT ["./main"]
