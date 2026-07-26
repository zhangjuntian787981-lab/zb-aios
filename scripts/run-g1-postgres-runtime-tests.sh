#!/bin/sh
set -eu

g1_pg_bin=${G1_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
g1_pg_root=$(mktemp -d /tmp/g1-runtime-pg.XXXXXX)
g1_data_dir="$g1_pg_root/data"
g1_socket_dir="$g1_pg_root/socket"
g1_file_root="$g1_pg_root/runtime-files"
g1_log_file="$g1_pg_root/postgres.log"
g1_port=$((56000 + ($$ % 1500)))
g1_database="g1_runtime_test_$$"
g1_user=$(id -un)
g1_started=0

cleanup_g1_postgres() {
  g1_exit_status=$?
  g1_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$g1_exit_status" -ne 0 ] && [ -f "$g1_log_file" ]; then
    tail -n 80 "$g1_log_file" >&2
  fi

  if [ "$g1_started" -eq 1 ]; then
    if ! "$g1_pg_bin/pg_ctl" \
      -D "$g1_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      g1_can_remove=0
      g1_exit_status=1
      printf '%s\n' \
        "G1 PostgreSQL could not stop; preserving $g1_pg_root and $g1_log_file." >&2
    fi
  fi

  if [ "$g1_can_remove" -eq 1 ]; then
    case "$g1_pg_root" in
      /tmp/g1-runtime-pg.*) rm -rf -- "$g1_pg_root" ;;
      *)
        g1_exit_status=1
        printf '%s\n' "Refusing unexpected G1 PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$g1_exit_status"
}

trap cleanup_g1_postgres EXIT
trap 'exit 130' HUP INT TERM

for g1_binary in initdb pg_ctl createdb pg_config; do
  if [ ! -x "$g1_pg_bin/$g1_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $g1_binary" >&2
    exit 1
  fi
done

g1_extension_dir=$("$g1_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$g1_extension_dir/vector.control" ]; then
  printf '%s\n' "G1 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$g1_socket_dir" "$g1_file_root"
"$g1_pg_bin/initdb" \
  -D "$g1_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$g1_pg_bin/pg_ctl" \
  -D "$g1_data_dir" \
  -l "$g1_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$g1_socket_dir' -p $g1_port" \
  -t 30 \
  -w start >/dev/null
g1_started=1

"$g1_pg_bin/createdb" \
  -h "$g1_socket_dir" \
  -p "$g1_port" \
  -U "$g1_user" \
  "$g1_database"

unset G1_TEST_PGPASSWORD

G1_TEST_EPHEMERAL=1 \
G1_TEST_PGHOST="$g1_socket_dir" \
G1_TEST_PGPORT="$g1_port" \
G1_TEST_PGDATABASE="$g1_database" \
G1_TEST_PGUSER="$g1_user" \
G1_TEST_FILE_ROOT="$g1_file_root" \
node --test --test-concurrency=1 \
  tests/integration/g1-postgres-runtime-restart.test.mjs
