ARG SINGBOX_VERSION=v1.12.22

FROM ghcr.io/sagernet/sing-box:${SINGBOX_VERSION} AS sing-box

FROM alpine:latest
ARG TARGETARCH
LABEL maintainer="Anton Kudriavtsev <anidetrix@proton.me>"
RUN apk add --no-cache ca-certificates-bundle nftables runit
COPY --from=sing-box /usr/local/bin/sing-box /bin/sing-box
COPY --chown=0:0 --chmod=755 dns-gen-${TARGETARCH} /bin/dns-gen
COPY --chown=0:0 --chmod=755 entrypoint.sh /entrypoint.sh
COPY --chown=0:0 --chmod=755 service.sh /service/run
ENTRYPOINT ["/entrypoint.sh"]
