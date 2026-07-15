FROM --platform=$BUILDPLATFORM golang:1.26.2-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

RUN apk update && apk add --no-cache make curl bash sudo

WORKDIR /src

COPY go* .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make NAME=main build
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} make install_xray

# Runtime is Debian (not Alpine) so the multi-backend fork's VPN deps —
# strongSwan/charon for IKEv2 and openvpn — match the packages the bare-metal
# installer uses and are known to work (EAP-MSCHAPv2 plugins included).
FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/AlirezaNorouzzadeh9/pasarguardNode"

# Don't let package postinst scripts try to start services during the build.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d && \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openvpn strongswan strongswan-swanctl libcharon-extra-plugins \
      wireguard-tools iptables iproute2 kmod openssl curl ca-certificates procps && \
    rm -rf /var/lib/apt/lists/* /usr/sbin/policy-rc.d

ENV SERVICE_PROTOCOL=grpc \
    NODE_HOST=0.0.0.0 \
    XRAY_EXECUTABLE_PATH=/usr/local/bin/xray \
    XRAY_ASSETS_PATH=/usr/local/share/xray

WORKDIR /app
COPY --from=builder /src/main /app/main
COPY --from=builder /usr/local/bin/xray /usr/local/bin/xray
COPY --from=builder /usr/local/share/xray /usr/local/share/xray
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
