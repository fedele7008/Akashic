FROM osixia/phpldapadmin:0.9.0

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint-tls.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint-tls.sh"]
CMD ["--copy-service"]
