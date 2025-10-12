# Vault bootstrap

Vault bootstrap will configure vault-root-ca self-signed certificate,
vault secret key and vault certificate for TLS connection to vault service.

Note that vault-root-ca is different from akashic's root-ca.

vault-root-ca is created using script file, `vault-bootstrap.sh` using openssl for
initial connection setup for vault.

akashic's root-ca on the other hands, is created and managed by the vault after it
get initialized.

note that `vault_file` volume is mounted to change the owner of the directory to
comply with vault's permission.

output certificates will be located in mounted `./certs/vault` folder in local directory.
