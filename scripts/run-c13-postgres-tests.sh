#!/bin/sh
set -eu

c13_pg_bin=${C13_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c13_pg_root=$(mktemp -d /tmp/c13-pg.XXXXXX)
c13_data_dir="$c13_pg_root/data"
c13_socket_dir="$c13_pg_root/socket"
c13_log_file="$c13_pg_root/postgres.log"
c13_port=$((61000 + ($$ % 3000)))
c13_database="c13_test_$$"
c13_user=$(id -un)
c13_started=0

cleanup_c13_postgres() {
  c13_exit_status=$?
  c13_can_remove=1
  trap - EXIT HUP INT TERM
  if [ "$c13_started" -eq 1 ]; then
    if ! "$c13_pg_bin/pg_ctl" -D "$c13_data_dir" -m immediate \
      -w stop >/dev/null 2>&1; then
      c13_can_remove=0
      c13_exit_status=1
      printf '%s\n' \
        "C13 PostgreSQL could not stop; preserving $c13_pg_root." >&2
    fi
  fi
  if [ "$c13_can_remove" -eq 1 ]; then
    case "$c13_pg_root" in
      /tmp/c13-pg.*) rm -rf -- "$c13_pg_root" ;;
      *) c13_exit_status=1 ;;
    esac
  fi
  exit "$c13_exit_status"
}

trap cleanup_c13_postgres EXIT
trap 'exit 130' HUP INT TERM

for c13_binary in initdb pg_ctl createdb pg_config; do
  if [ ! -x "$c13_pg_bin/$c13_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c13_binary" >&2
    exit 1
  fi
done
c13_extension_dir=$("$c13_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c13_extension_dir/vector.control" ]; then
  printf '%s\n' "C13 dependency pgvector is missing." >&2
  exit 1
fi

mkdir "$c13_socket_dir"
"$c13_pg_bin/initdb" -D "$c13_data_dir" --encoding=UTF8 --locale=C \
  --auth-local=trust --auth-host=reject --no-instructions >/dev/null
"$c13_pg_bin/pg_ctl" -D "$c13_data_dir" -l "$c13_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c13_socket_dir' -p $c13_port" \
  -t 30 -w start >/dev/null
c13_started=1
"$c13_pg_bin/createdb" -h "$c13_socket_dir" -p "$c13_port" \
  -U "$c13_user" "$c13_database"

unset C13_TEST_PGPASSWORD
C13_TEST_EPHEMERAL=1 \
C13_TEST_PGHOST="$c13_socket_dir" \
C13_TEST_PGPORT="$c13_port" \
C13_TEST_PGDATABASE="$c13_database" \
C13_TEST_PGUSER="$c13_user" \
node --test --test-concurrency=1 tests/integration/c13-postgres.test.mjs
