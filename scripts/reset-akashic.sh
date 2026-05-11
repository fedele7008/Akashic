#!/usr/bin/env bash

# parse arg
deep=false
for arg in "$@"; do
    case "$arg" in
        --deep)
            deep=true
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

current_dir_name="${PWD##*/}"
if [[ "$current_dir_name" != "Akashic" ]]; then
    echo "Current directory is '${current_dir_name}'. Please run this script from the Akashic project root."
    exit 1
fi

echo "Bringing the Akashic stack down (if running)..."
docker compose down --remove-orphans

echo "Wiping ./certs/..."
find ./certs -mindepth 1 ! -name '.gitignore' ! -name 'README.md' -exec rm -rf {} + 2>/dev/null || true

echo "Wiping ./logs/..."
find ./logs -mindepth 1 -type f ! -name '.gitkeep' -exec rm -rf {} + 2>/dev/null || true
find ./logs -mindepth 1 -type d -empty -exec rm -rf {} + 2>/dev/null || true

echo "Removing every akashic_* docker volume..."
project_vols=$(docker volume ls --format '{{.Name}}' | grep -E '^akashic_' || true)
if [[ -n "$project_vols" ]]; then
    docker volume rm $project_vols 2>&1 | sed 's/^/  /' || true
else
    echo "  (no akashic_* volumes found — nothing to remove)"
fi

if [[ "$deep" == "true" ]]; then
    echo ""
    echo "Deep clean: pruning Docker build cache + dangling images (host-wide)..."
    docker builder prune --all --force 2>&1 | sed 's/^/  /'
    docker image prune --all --force 2>&1 | sed 's/^/  /'
fi

sleep 1

echo ""
echo "Reset complete."