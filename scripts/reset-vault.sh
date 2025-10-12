#!/usr/bin/env bash

set -e

current_dir_name="${PWD##*/}"
if [[ "$current_dir_name" != "Akashic" ]]; then
  echo "Current directory is ${current_dir_name}, Please run this script in the Akashic root directory."
fi

rm -r ./certs/vault
docker compose ps | grep "akashic-vault" > /dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "Stopping and removing Akashic Vault container..."
  docker compose down
fi
docker volume rm $(docker volume ls --format 'table {{.Name}}' | grep "vault")