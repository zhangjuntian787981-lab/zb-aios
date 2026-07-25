#!/bin/sh
set -eu

c05_pg_bin=${C05_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c05_pg_root=$(mktemp -d /tmp/c05-pg.XXXXXX)
c05_data_dir="$c05_pg_root/data"
c05_socket_dir="$c05_pg_root/socket"
c05_log_file="$c05_pg_root/postgres.log"
c05_port=$((47000 + ($$ % 8000)))
c05_database="c05_test_$$"
c05_user=$(id -un)
c05_started=0

cleanup_c05_postgres() {
  c05_exit_status=$?
  c05_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c05_started" -eq 1 ]; then
    if ! "$c05_pg_bin/pg_ctl" \
      -D "$c05_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c05_can_remove=0
      c05_exit_status=1
      printf '%s\n' \
        "C05 PostgreSQL could not be stopped; preserving $c05_pg_root and $c05_log_file." >&2
    fi
  fi

  if [ "$c05_can_remove" -eq 1 ]; then
    case "$c05_pg_root" in
      /tmp/c05-pg.*) rm -rf -- "$c05_pg_root" ;;
      *)
        c05_exit_status=1
        printf '%s\n' "Refusing to remove unexpected C05 PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c05_exit_status"
}

trap cleanup_c05_postgres EXIT
trap 'exit 130' HUP INT TERM

for c05_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c05_pg_bin/$c05_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c05_binary" >&2
    exit 1
  fi
done

mkdir "$c05_socket_dir"

"$c05_pg_bin/initdb" \
  -D "$c05_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c05_pg_bin/pg_ctl" \
  -D "$c05_data_dir" \
  -l "$c05_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c05_socket_dir' -p $c05_port" \
  -t 30 \
  -w start >/dev/null
c05_started=1

"$c05_pg_bin/createdb" \
  -h "$c05_socket_dir" \
  -p "$c05_port" \
  -U "$c05_user" \
  "$c05_database"

unset C05_TEST_PGPASSWORD

C05_TEST_EPHEMERAL=1 \
C05_TEST_PGHOST="$c05_socket_dir" \
C05_TEST_PGPORT="$c05_port" \
C05_TEST_PGDATABASE="$c05_database" \
C05_TEST_PGUSER="$c05_user" \
node --test --test-concurrency=1 tests/integration/c05-postgres.test.mjs
