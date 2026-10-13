#!/usr/bin/env bash
# One-command update + redeploy for the pilot.
#   ./deploy.sh
# Pulls the latest code, stamps the running build so the Settings page can show
# the current commit, and rebuilds the containers.
set -euo pipefail

cd "$(dirname "$0")"

echo "→ Pulling latest code…"
git pull --ff-only

# Stamp build info so the Settings page shows what's actually running.
export GIT_COMMIT="$(git rev-parse --short HEAD)"
export GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
export GIT_COMMITTED_AT="$(git log -1 --format=%cI)"
echo "→ Building ${GIT_BRANCH}@${GIT_COMMIT}…"

docker compose up -d --build

echo "→ Done. Running ${GIT_BRANCH}@${GIT_COMMIT}."
docker compose ps
