FROM osixia/openldap:1.5.0

# Install inotify-tools for cert watcher. openssl, ldapmodify, ldapsearch are
# already in the image. The base is Debian Buster (EOL) so we rewrite sources
# to use archive.debian.org (active snapshots are gone).
RUN printf 'deb http://archive.debian.org/debian buster main\ndeb http://archive.debian.org/debian-security buster/updates main\n' > /etc/apt/sources.list && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends inotify-tools && \
    rm -rf /var/lib/apt/lists/*

COPY docker-entrypoint-tls.sh cert-watcher.sh healthcheck.sh apply-tls-state.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint-tls.sh /usr/local/bin/cert-watcher.sh /usr/local/bin/healthcheck.sh /usr/local/bin/apply-tls-state.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint-tls.sh"]
CMD ["--copy-service"]
