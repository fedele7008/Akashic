FROM redis:7-alpine

RUN apk add --no-cache inotify-tools bash openssl

COPY docker-entrypoint-tls.sh cert-watcher.sh healthcheck.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh /usr/local/bin/cert-watcher.sh /usr/local/bin/healthcheck.sh

ENTRYPOINT ["docker-entrypoint-tls.sh"]
