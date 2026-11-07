#!/usr/bin/env bash
set -Eeuo pipefail
SUDO=""
if [[ $(id -u) -ne 0 ]]; then SUDO="sudo"; fi
$SUDO apt-get update
$SUDO apt-get install -y --no-install-recommends \
  build-essential pkg-config ca-certificates curl \
  libsqlite3-dev libmicrohttpd-dev libcjson-dev libssl-dev
echo "Build dependencies installed."
