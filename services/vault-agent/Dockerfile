FROM hashicorp/vault:1.20

COPY config.hcl /vault-agent/config.hcl
COPY templates/ /templates/

ENTRYPOINT ["vault", "agent", "-config=/vault-agent/config.hcl"]
