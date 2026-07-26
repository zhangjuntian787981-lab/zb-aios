#!/bin/sh
set -eu

c12_pg_bin=${C12_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c12_pg_root=$(mktemp -d /tmp/c12-pg.XXXXXX)
c12_data_dir="$c12_pg_root/data"
c12_socket_dir="$c12_pg_root/socket"
c12_log_file="$c12_pg_root/postgres.log"
c12_port=$((58000 + ($$ % 4000)))
c12_database="c12_test_$$"
c12_user=$(id -un)
c12_started=0

cleanup_c12_postgres() {
  c12_exit_status=$?
  c12_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c12_started" -eq 1 ]; then
    if ! "$c12_pg_bin/pg_ctl" \
      -D "$c12_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c12_can_remove=0
      c12_exit_status=1
      printf '%s\n' \
        "C12 PostgreSQL could not stop; preserving $c12_pg_root and $c12_log_file." >&2
    fi
  fi

  if [ "$c12_can_remove" -eq 1 ]; then
    case "$c12_pg_root" in
      /tmp/c12-pg.*) rm -rf -- "$c12_pg_root" ;;
      *)
        c12_exit_status=1
        printf '%s\n' "Refusing unexpected C12 PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c12_exit_status"
}

trap cleanup_c12_postgres EXIT
trap 'exit 130' HUP INT TERM

for c12_binary in initdb pg_ctl createdb pg_config; do
  if [ ! -x "$c12_pg_bin/$c12_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c12_binary" >&2
    exit 1
  fi
done

c12_extension_dir=$("$c12_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c12_extension_dir/vector.control" ]; then
  printf '%s\n' "C12 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$c12_socket_dir"
"$c12_pg_bin/initdb" \
  -D "$c12_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c12_pg_bin/pg_ctl" \
  -D "$c12_data_dir" \
  -l "$c12_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c12_socket_dir' -p $c12_port" \
  -t 30 \
  -w start >/dev/null
c12_started=1

"$c12_pg_bin/createdb" \
  -h "$c12_socket_dir" \
  -p "$c12_port" \
  -U "$c12_user" \
  "$c12_database"

unset C12_TEST_PGPASSWORD

C12_TEST_EPHEMERAL=1 \
C12_TEST_PGHOST="$c12_socket_dir" \
C12_TEST_PGPORT="$c12_port" \
C12_TEST_PGDATABASE="$c12_database" \
C12_TEST_PGUSER="$c12_user" \
node --test --test-concurrency=1 tests/integration/c12-postgres.test.mjs
