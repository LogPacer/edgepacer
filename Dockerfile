FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS staged-binaries

ARG TARGETARCH
COPY .docker-stage /docker-stage
RUN arch="${TARGETARCH:-$(uname -m)}" && \
    case "${arch}" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac && \
    mkdir -p /selected && \
    cp "/docker-stage/${arch}/edgepacer" /selected/edgepacer && \
    cp "/docker-stage/${arch}/edgepacer-manager" /selected/edgepacer-manager

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="EdgePacer" \
      org.opencontainers.image.description="EdgePacer node agent and manager for LogPacer" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.source="https://github.com/LogPacer/edgepacer" \
      org.opencontainers.image.vendor="Logpacer" \
      org.opencontainers.image.base.name="docker.io/library/alpine:3.22"

RUN apk add --no-cache ca-certificates cri-tools && \
    addgroup -S -g 65532 edgepacer && \
    adduser -S -D -H -u 65532 -G edgepacer edgepacer && \
    mkdir -p /app /var/lib/edgepacer && \
    chown -R 65532:65532 /app /var/lib/edgepacer

WORKDIR /app

COPY --from=staged-binaries --chown=65532:65532 /selected/edgepacer /app/edgepacer
COPY --from=staged-binaries --chown=65532:65532 /selected/edgepacer-manager /app/edgepacer-manager

RUN chmod 0555 /app/edgepacer /app/edgepacer-manager

ENV EDGEPACER_RAILS_URL=""
ENV EDGEPACER_LOG_LEVEL="info"
ENV EDGEPACER_STATE_DIR="/var/lib/edgepacer"
ENV XDG_CACHE_HOME="/var/lib"
ENV HOME="/var/lib/edgepacer"

USER 65532:65532
STOPSIGNAL SIGTERM

ENTRYPOINT ["/app/edgepacer-manager"]
