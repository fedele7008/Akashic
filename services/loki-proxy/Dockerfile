FROM nginx:alpine

RUN apk add --no-cache inotify-tools openssl

# Two config variants; entrypoint picks one based on LOKI_TLS_MODE
COPY nginx.tls.conf nginx.plain.conf /etc/nginx/conf-variants/
COPY docker-entrypoint.sh cert-watcher.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/cert-watcher.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
