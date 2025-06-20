# ───────────────
# Build-time ARG
# ───────────────
ARG VERSION=dev
ARG BIN_NAME=mdns-relay

# ───────────────
# Base Image
# ───────────────
FROM alpine:3.19

# Re-declare ARG so it's visible to the final image
ARG VERSION
ARG BIN_NAME

# ───────────────
# Install Dependencies
# ───────────────
RUN apk add --no-cache ca-certificates tzdata

# ───────────────
# Copy Binary
# ───────────────
COPY dist/${BIN_NAME} /usr/local/bin/mdns-relay

# ───────────────
# Image Metadata (OpenContainers labels)
# ───────────────
LABEL org.opencontainers.image.title="mdns-relay" \
      org.opencontainers.image.description="Multicast DNS relay written in Rust to bridge subnets for mDNS services." \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.url="https://github.com/engeloded/mdns-relay" \
      org.opencontainers.image.authors="Oded Engel <engeloded@gmail.com>" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/engeloded/mdns-relay" \
      mdns-relay.version="${VERSION}"

# ───────────────
# Entrypoint
# ───────────────
ENTRYPOINT ["/usr/local/bin/mdns-relay"]
