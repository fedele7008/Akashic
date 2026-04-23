#!/usr/bin/env bash

set -e

current_dir_name="${PWD##*/}"
if [[ "$current_dir_name" != "Akashic" ]]; then
  echo "Current directory is ${current_dir_name}, Please run this script in the Akashic root directory."
fi

# Clean all certs and secrets — a Vault reset invalidates everything
# (the certs were signed by the old CA chain and can't be reused)
find ./certs -mindepth 1 ! -name '.gitignore' ! -name 'README.md' -exec rm -rf {} + 2>/dev/null || true
rm -rf ./.secrets/vault
rm -rf ./.secrets/vault-agent
docker compose ps | grep "akashic-vault" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "Stopping and removing Akashic Vault container..."
  docker compose down
fi
docker volume rm $(docker volume ls --format 'table {{.Name}}' | grep "vault")
docker volume rm akashic_redisinsight_data 2>/dev/null || true
# LDAP's cn=config stores TLS cert trust state tied to the old CA chain.
# A vault reset issues a new CA chain, so LDAP state must be wiped too.
docker volume rm akashic_ldap_data akashic_ldap_config 2>/dev/null || true