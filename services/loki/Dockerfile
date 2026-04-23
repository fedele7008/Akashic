FROM grafana/loki:3.5.5 AS upstream

# The official grafana/loki image is distroless -- no package manager.
# Rebase on debian-slim so we can install inotify-tools for cert-watcher.
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        inotify-tools openssl ca-certificates gosu wget && \
    rm -rf /var/lib/apt/lists/* && \
    useradd -u 10001 -r -s /sbin/nologin -M -d /loki loki && \
    mkdir -p /loki && chown loki:loki /loki

COPY --from=upstream /usr/bin/loki /usr/bin/loki

COPY config.yml config.tls.yml /etc/loki/
COPY docker-entrypoint-tls.sh cert-watcher.sh healthcheck.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh /usr/local/bin/cert-watcher.sh /usr/local/bin/healthcheck.sh

EXPOSE 3100 9096
ENTRYPOINT ["/usr/local/bin/docker-entrypoint-tls.sh"]
