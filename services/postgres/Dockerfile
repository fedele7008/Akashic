FROM postgres:16-alpine

RUN apk add --no-cache inotify-tools

COPY docker-entrypoint-tls.sh cert-watcher.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh /usr/local/bin/cert-watcher.sh

ENTRYPOINT ["docker-entrypoint-tls.sh"]
CMD ["postgres"]
