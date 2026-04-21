FROM postgres:16-alpine

COPY docker-entrypoint-tls.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh

ENTRYPOINT ["docker-entrypoint-tls.sh"]
CMD ["postgres"]
