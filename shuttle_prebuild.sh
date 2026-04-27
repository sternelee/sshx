#!/usr/bin/env bash
set -euo pipefail

if ! command -v npm >/dev/null 2>&1; then
  apt-get update
  apt-get install -y --no-install-recommends nodejs npm
fi

npm ci
npm run build
