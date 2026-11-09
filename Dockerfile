# Minimal runtime image: the release binary is statically linked (musl).
FROM scratch

ARG TARGETARCH=amd64
ARG VERSION=dev

LABEL org.opencontainers.image.title="fritzrecon" \
      org.opencontainers.image.description="FRITZ!Box / Pi-hole DNS reconciliation with selective device-memory cleanup" \
      org.opencontainers.image.url="https://github.com/zx97/fritzrecon" \
      org.opencontainers.image.source="https://github.com/zx97/fritzrecon" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}"

COPY dist/fritzrecon-linux-${TARGETARCH} /fritzrecon

ENTRYPOINT ["/fritzrecon"]
