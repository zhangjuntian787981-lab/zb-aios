#!/bin/sh
set -eu

c19_pg_bin=${C19_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c19_pg_root=$(mktemp -d /tmp/c19-pg.XXXXXX)
c19_data_dir="$c19_pg_root/data"
c19_socket_dir="$c19_pg_root/socket"
c19_log_file="$c19_pg_root/postgres.log"
c19_port=$((64000 + ($$ % 1000)))
c19_database="c19_test_$$"
c19_user=$(id -un)
c19_started=0

cleanup_c19_postgres() {
  c19_exit_status=$?
  trap - EXIT HUP INT TERM
  if [ "$c19_started" -eq 1 ]; then
    "$c19_pg_bin/pg_ctl" -D "$c19_data_dir" -m immediate \
      -w stop >/dev/null 2>&1 || c19_exit_status=1
  fi
  case "$c19_pg_root" in
    /tmp/c19-pg.*) rm -rf -- "$c19_pg_root" ;;
    *) c19_exit_status=1 ;;
  esac
  exit "$c19_exit_status"
}

trap cleanup_c19_postgres EXIT
trap 'exit 130' HUP INT TERM

for c19_binary in initdb pg_ctl createdb pg_config
do
  if [ ! -x "$c19_pg_bin/$c19_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c19_binary" >&2
    exit 1
  fi
done
c19_extension_dir=$("$c19_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c19_extension_dir/vector.control" ]; then
  printf '%s\n' "C19 dependency pgvector is missing." >&2
  exit 1
fi

mkdir "$c19_socket_dir"
"$c19_pg_bin/initdb" -D "$c19_data_dir" --encoding=UTF8 --locale=C \
  --auth-local=trust --auth-host=reject --no-instructions >/dev/null
"$c19_pg_bin/pg_ctl" -D "$c19_data_dir" -l "$c19_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c19_socket_dir' -p $c19_port" \
  -t 30 -w start >/dev/null
c19_started=1
"$c19_pg_bin/createdb" -h "$c19_socket_dir" -p "$c19_port" \
  -U "$c19_user" "$c19_database"

unset C19_TEST_PGPASSWORD
C19_TEST_EPHEMERAL=1 \
C19_TEST_PGHOST="$c19_socket_dir" \
C19_TEST_PGPORT="$c19_port" \
C19_TEST_PGDATABASE="$c19_database" \
C19_TEST_PGUSER="$c19_user" \
node --test --test-concurrency=1 \
  tests/integration/c19-observability-postgres.test.mjs
