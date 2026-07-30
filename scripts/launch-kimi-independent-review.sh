#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
if [ "$#" -lt 1 ] || [ ! -x "$1" ]; then
  exit 2
fi
NODE_EXECUTABLE=$1
shift

exec /usr/bin/env -i \
  PATH=/usr/bin:/bin \
  LANG=C \
  LC_ALL=C \
  ZB_KIMI_SANITIZED_LAUNCHER=1 \
  "$NODE_EXECUTABLE" \
  "$SCRIPT_DIR/bootstrap-kimi-independent-review.mjs" \
  "$@"
