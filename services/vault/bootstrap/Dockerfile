FROM alpine:3.22.4

RUN apk add --no-cache openssl

COPY vault-bootstrap.sh /bootstrap/vault-bootstrap.sh
RUN chmod +x /bootstrap/vault-bootstrap.sh

ENTRYPOINT ["/bootstrap/vault-bootstrap.sh"]