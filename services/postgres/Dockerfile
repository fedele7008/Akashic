FROM postgres:16-alpine

COPY docker-entrypoint-tls.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh

ENTRYPOINT ["docker-entrypoint-tls.sh"]
CMD ["postgres", \
     "-c", "ssl=on", \
     "-c", "ssl_cert_file=/certs/server.crt", \
     "-c", "ssl_key_file=/certs/server.key", \
     "-c", "ssl_ca_file=/certs/ca.crt"]
