#!/bin/sh
set -eu

g1_matrix_pg_bin=${G1_MATRIX_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
g1_matrix_root=$(mktemp -d /tmp/g1-persistent-matrix.XXXXXX)
g1_matrix_data="$g1_matrix_root/data"
g1_matrix_socket="$g1_matrix_root/socket"
g1_matrix_pg_log="$g1_matrix_root/postgres.log"
g1_matrix_dump="$g1_matrix_root/source.dump"
g1_matrix_file_root="$g1_matrix_root/file"
g1_matrix_object_root="$g1_matrix_root/object"
g1_matrix_openfga_log="$g1_matrix_root/openfga.log"
g1_matrix_openfga_archive="$g1_matrix_root/openfga_1.18.1_darwin_arm64.tar.gz"
g1_matrix_pg_port=$((53000 + ($$ % 1000)))
g1_matrix_http_port=$((43000 + ($$ % 1000)))
g1_matrix_grpc_port=$((47000 + ($$ % 1000)))
g1_matrix_source="g1_matrix_source_$$"
g1_matrix_restore="g1_matrix_restore_$$"
g1_matrix_user=$(id -un)
g1_matrix_pg_started=0
g1_matrix_openfga_pid=""
g1_matrix_openfga_sha256="d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94"
g1_matrix_openfga_url="https://github.com/openfga/openfga/releases/download/v1.18.1/openfga_1.18.1_darwin_arm64.tar.gz"

cleanup_g1_persistent_matrix() {
  g1_matrix_status=$?
  g1_matrix_can_remove=1
  trap - EXIT HUP INT TERM

  if [ -n "$g1_matrix_openfga_pid" ]; then
    kill "$g1_matrix_openfga_pid" >/dev/null 2>&1 || true
    wait "$g1_matrix_openfga_pid" >/dev/null 2>&1 || true
  fi
  if [ "$g1_matrix_pg_started" -eq 1 ]; then
    if ! "$g1_matrix_pg_bin/pg_ctl" \
      -D "$g1_matrix_data" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      g1_matrix_can_remove=0
      g1_matrix_status=1
      printf '%s\n' \
        "G1 matrix PostgreSQL could not be stopped; preserving $g1_matrix_root." >&2
    fi
  fi
  if [ "$g1_matrix_can_remove" -eq 1 ]; then
    case "$g1_matrix_root" in
      /tmp/g1-persistent-matrix.*) rm -rf -- "$g1_matrix_root" ;;
      *)
        g1_matrix_status=1
        printf '%s\n' "Refusing to remove unexpected G1 matrix path." >&2
        ;;
    esac
  fi
  exit "$g1_matrix_status"
}

trap cleanup_g1_persistent_matrix EXIT
trap 'exit 130' HUP INT TERM

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  printf '%s\n' "The frozen G1 matrix dependencies support Darwin arm64." >&2
  exit 1
fi

for g1_matrix_binary in initdb pg_ctl createdb pg_dump pg_restore psql; do
  if [ ! -x "$g1_matrix_pg_bin/$g1_matrix_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $g1_matrix_binary" >&2
    exit 1
  fi
done

node --input-type=module - <<'NODE'
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const lock = JSON.parse(
  await readFile(
    "implementation/p1/c06/openfga/openfga-distribution.lock.json",
    "utf8",
  ),
);
assert.deepEqual(
  {
    version: lock.version,
    sha256: lock.sha256,
    platform: lock.platform,
    architecture: lock.architecture,
  },
  {
    version: "v1.18.1",
    sha256:
      "d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94",
    platform: "darwin",
    architecture: "arm64",
  },
);
NODE

mkdir "$g1_matrix_socket"
mkdir "$g1_matrix_file_root"
mkdir "$g1_matrix_object_root"

"$g1_matrix_pg_bin/initdb" \
  -D "$g1_matrix_data" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$g1_matrix_pg_bin/pg_ctl" \
  -D "$g1_matrix_data" \
  -l "$g1_matrix_pg_log" \
  -o "-c listen_addresses='' -c unix_socket_directories='$g1_matrix_socket' -p $g1_matrix_pg_port" \
  -t 30 \
  -w start >/dev/null
g1_matrix_pg_started=1

"$g1_matrix_pg_bin/createdb" \
  -h "$g1_matrix_socket" \
  -p "$g1_matrix_pg_port" \
  -U "$g1_matrix_user" \
  "$g1_matrix_source"

unset G1_MATRIX_PGPASSWORD

G1_MATRIX_EPHEMERAL=1 \
G1_MATRIX_PGHOST="$g1_matrix_socket" \
G1_MATRIX_PGPORT="$g1_matrix_pg_port" \
G1_MATRIX_SOURCE_DATABASE="$g1_matrix_source" \
G1_MATRIX_PGUSER="$g1_matrix_user" \
node tests/integration/g1-persistent-matrix-seed.mjs

"$g1_matrix_pg_bin/pg_dump" \
  -h "$g1_matrix_socket" \
  -p "$g1_matrix_pg_port" \
  -U "$g1_matrix_user" \
  -d "$g1_matrix_source" \
  --format=custom \
  --file="$g1_matrix_dump"

"$g1_matrix_pg_bin/createdb" \
  -h "$g1_matrix_socket" \
  -p "$g1_matrix_pg_port" \
  -U "$g1_matrix_user" \
  "$g1_matrix_restore"

"$g1_matrix_pg_bin/pg_restore" \
  -h "$g1_matrix_socket" \
  -p "$g1_matrix_pg_port" \
  -U "$g1_matrix_user" \
  -d "$g1_matrix_restore" \
  "$g1_matrix_dump"

"$g1_matrix_pg_bin/psql" \
  -h "$g1_matrix_socket" \
  -p "$g1_matrix_pg_port" \
  -U "$g1_matrix_user" \
  -d postgres \
  -v ON_ERROR_STOP=1 \
  -c "ALTER DATABASE \"$g1_matrix_restore\" SET default_transaction_read_only=on" \
  >/dev/null

curl \
  --proto '=https' \
  --tlsv1.2 \
  --fail \
  --location \
  --retry 3 \
  --silent \
  --show-error \
  "$g1_matrix_openfga_url" \
  --output "$g1_matrix_openfga_archive"

printf '%s  %s\n' \
  "$g1_matrix_openfga_sha256" \
  "$g1_matrix_openfga_archive" |
  shasum -a 256 --check >/dev/null

tar -xzf "$g1_matrix_openfga_archive" -C "$g1_matrix_root"
if [ ! -x "$g1_matrix_root/openfga" ]; then
  printf '%s\n' "The locked OpenFGA archive did not contain an executable." >&2
  exit 1
fi

"$g1_matrix_root/openfga" run \
  --datastore-engine memory \
  --http-addr "127.0.0.1:$g1_matrix_http_port" \
  --grpc-addr "127.0.0.1:$g1_matrix_grpc_port" \
  --playground-enabled=false \
  >"$g1_matrix_openfga_log" 2>&1 &
g1_matrix_openfga_pid=$!

g1_matrix_ready=0
g1_matrix_attempt=0
while [ "$g1_matrix_attempt" -lt 100 ]; do
  if curl --fail --silent \
    "http://127.0.0.1:$g1_matrix_http_port/healthz" >/dev/null 2>&1; then
    g1_matrix_ready=1
    break
  fi
  if ! kill -0 "$g1_matrix_openfga_pid" >/dev/null 2>&1; then
    break
  fi
  g1_matrix_attempt=$((g1_matrix_attempt + 1))
  sleep 0.1
done

if [ "$g1_matrix_ready" -ne 1 ]; then
  printf '%s\n' \
    "OpenFGA did not become ready. Log: $g1_matrix_openfga_log" >&2
  exit 1
fi

G1_MATRIX_EPHEMERAL=1 \
G1_MATRIX_PGHOST="$g1_matrix_socket" \
G1_MATRIX_PGPORT="$g1_matrix_pg_port" \
G1_MATRIX_SOURCE_DATABASE="$g1_matrix_source" \
G1_MATRIX_RESTORE_DATABASE="$g1_matrix_restore" \
G1_MATRIX_PGUSER="$g1_matrix_user" \
G1_MATRIX_FILE_ROOT="$g1_matrix_file_root" \
G1_MATRIX_OBJECT_ROOT="$g1_matrix_object_root" \
G1_MATRIX_OPENFGA_BASE_URL="http://127.0.0.1:$g1_matrix_http_port" \
G1_MATRIX_OPENFGA_VERSION="v1.18.1" \
G1_MATRIX_OPENFGA_SHA256="$g1_matrix_openfga_sha256" \
node --test --test-concurrency=1 \
  tests/integration/g1-persistent-matrix-postgres.test.mjs
