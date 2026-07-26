#!/bin/sh
set -eu

c11_pg_bin=${C11_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c11_pg_root=$(mktemp -d /tmp/c11-pg.XXXXXX)
c11_data_dir="$c11_pg_root/data"
c11_socket_dir="$c11_pg_root/socket"
c11_log_file="$c11_pg_root/postgres.log"
c11_port=$((62000 + ($$ % 2000)))
c11_database="c11_test_$$"
c11_user=$(id -un)
c11_started=0

cleanup_c11_postgres() {
  c11_exit_status=$?
  c11_can_remove=1
  trap - EXIT HUP INT TERM
  if [ "$c11_started" -eq 1 ]; then
    if ! "$c11_pg_bin/pg_ctl" \
      -D "$c11_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c11_can_remove=0
      c11_exit_status=1
      printf '%s\n' \
        "C11 PostgreSQL could not stop; preserving $c11_pg_root." >&2
    fi
  fi
  if [ "$c11_can_remove" -eq 1 ]; then
    case "$c11_pg_root" in
      /tmp/c11-pg.*) rm -rf -- "$c11_pg_root" ;;
      *)
        c11_exit_status=1
        printf '%s\n' "Refusing unexpected C11 PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c11_exit_status"
}

trap cleanup_c11_postgres EXIT
trap 'exit 130' HUP INT TERM

for c11_binary in initdb pg_ctl createdb pg_config; do
  if [ ! -x "$c11_pg_bin/$c11_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c11_binary" >&2
    exit 1
  fi
done

c11_extension_dir=$("$c11_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c11_extension_dir/vector.control" ]; then
  printf '%s\n' "C11 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$c11_socket_dir"
"$c11_pg_bin/initdb" \
  -D "$c11_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c11_pg_bin/pg_ctl" \
  -D "$c11_data_dir" \
  -l "$c11_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c11_socket_dir' -p $c11_port" \
  -t 30 \
  -w start >/dev/null
c11_started=1

"$c11_pg_bin/createdb" \
  -h "$c11_socket_dir" \
  -p "$c11_port" \
  -U "$c11_user" \
  "$c11_database"

unset C11_TEST_PGPASSWORD

C11_TEST_EPHEMERAL=1 \
C11_TEST_PGHOST="$c11_socket_dir" \
C11_TEST_PGPORT="$c11_port" \
C11_TEST_PGDATABASE="$c11_database" \
C11_TEST_PGUSER="$c11_user" \
node --test --test-concurrency=1 \
  tests/integration/c11-postgres.test.mjs
