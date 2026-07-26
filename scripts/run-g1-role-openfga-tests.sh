#!/bin/sh
set -eu

g1_role_version="1.18.1"
g1_role_verified_version="v1.18.1"
g1_role_expected_sha256="d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94"
g1_role_asset="openfga_${g1_role_version}_darwin_arm64.tar.gz"
g1_role_url="https://github.com/openfga/openfga/releases/download/v${g1_role_version}/${g1_role_asset}"
g1_role_root=$(mktemp -d /tmp/g1-role-openfga.XXXXXX)
g1_role_archive="$g1_role_root/$g1_role_asset"
g1_role_log="$g1_role_root/openfga.log"
g1_role_http_port=$((42000 + ($$ % 3000)))
g1_role_grpc_port=$((46000 + ($$ % 3000)))
g1_role_pid=""

cleanup_g1_role_openfga() {
  g1_role_exit_status=$?
  trap - EXIT HUP INT TERM

  if [ -n "$g1_role_pid" ]; then
    kill "$g1_role_pid" >/dev/null 2>&1 || true
    wait "$g1_role_pid" >/dev/null 2>&1 || true
  fi

  case "$g1_role_root" in
    /tmp/g1-role-openfga.*) rm -rf -- "$g1_role_root" ;;
    *)
      g1_role_exit_status=1
      printf '%s\n' "Refusing to remove unexpected G1 OpenFGA path." >&2
      ;;
  esac

  exit "$g1_role_exit_status"
}

trap cleanup_g1_role_openfga EXIT
trap 'exit 130' HUP INT TERM

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  printf '%s\n' "The frozen OpenFGA lock supports only Darwin arm64." >&2
  exit 1
fi

node --input-type=module - <<'NODE'
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const lock = JSON.parse(
  await readFile(
    "implementation/p1/c06/openfga/openfga-distribution.lock.json",
    "utf8",
  ),
);
assert.equal(lock.version, "v1.18.1");
assert.equal(
  lock.sha256,
  "d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94",
);
assert.equal(lock.platform, "darwin");
assert.equal(lock.architecture, "arm64");
NODE

curl \
  --proto '=https' \
  --tlsv1.2 \
  --fail \
  --location \
  --retry 3 \
  --silent \
  --show-error \
  "$g1_role_url" \
  --output "$g1_role_archive"

printf '%s  %s\n' "$g1_role_expected_sha256" "$g1_role_archive" |
  shasum -a 256 --check >/dev/null

tar -xzf "$g1_role_archive" -C "$g1_role_root"
if [ ! -x "$g1_role_root/openfga" ]; then
  printf '%s\n' "The locked OpenFGA archive did not contain an executable." >&2
  exit 1
fi

"$g1_role_root/openfga" run \
  --datastore-engine memory \
  --http-addr "127.0.0.1:$g1_role_http_port" \
  --grpc-addr "127.0.0.1:$g1_role_grpc_port" \
  --playground-enabled=false \
  >"$g1_role_log" 2>&1 &
g1_role_pid=$!

g1_role_ready=0
g1_role_attempt=0
while [ "$g1_role_attempt" -lt 100 ]; do
  if curl --fail --silent \
    "http://127.0.0.1:$g1_role_http_port/healthz" >/dev/null 2>&1; then
    g1_role_ready=1
    break
  fi
  if ! kill -0 "$g1_role_pid" >/dev/null 2>&1; then
    break
  fi
  g1_role_attempt=$((g1_role_attempt + 1))
  sleep 0.1
done

if [ "$g1_role_ready" -ne 1 ]; then
  printf '%s\n' "OpenFGA did not become ready. Log: $g1_role_log" >&2
  exit 1
fi

G1_ROLE_OPENFGA_EPHEMERAL=1 \
G1_ROLE_OPENFGA_BASE_URL="http://127.0.0.1:$g1_role_http_port" \
G1_ROLE_OPENFGA_VERIFIED_VERSION="$g1_role_verified_version" \
G1_ROLE_OPENFGA_VERIFIED_SHA256="$g1_role_expected_sha256" \
node --test --test-concurrency=1 \
  tests/integration/g1-role-openfga.test.mjs
