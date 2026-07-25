#!/bin/sh
set -eu

c03_pg_bin=${C03_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c03_pg_root=$(mktemp -d /tmp/c03-pg.XXXXXX)
c03_data_dir="$c03_pg_root/data"
c03_socket_dir="$c03_pg_root/socket"
c03_log_file="$c03_pg_root/postgres.log"
c03_port=$((55000 + ($$ % 8000)))
c03_database="c03_test_$$"
c03_user=$(id -un)
c03_started=0

cleanup_c03_postgres() {
  c03_exit_status=$?
  c03_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c03_started" -eq 1 ]; then
    if ! "$c03_pg_bin/pg_ctl" \
      -D "$c03_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c03_can_remove=0
      c03_exit_status=1
      printf '%s\n' \
        "C03 PostgreSQL could not be stopped; preserving $c03_pg_root and $c03_log_file." >&2
    fi
  fi

  if [ "$c03_can_remove" -eq 1 ]; then
    case "$c03_pg_root" in
      /tmp/c03-pg.*) rm -rf -- "$c03_pg_root" ;;
      *)
        c03_exit_status=1
        printf '%s\n' "Refusing to remove unexpected C03 PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c03_exit_status"
}

trap cleanup_c03_postgres EXIT
trap 'exit 130' HUP INT TERM

for c03_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c03_pg_bin/$c03_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c03_binary" >&2
    exit 1
  fi
done

mkdir "$c03_socket_dir"

"$c03_pg_bin/initdb" \
  -D "$c03_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c03_pg_bin/pg_ctl" \
  -D "$c03_data_dir" \
  -l "$c03_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c03_socket_dir' -p $c03_port" \
  -t 30 \
  -w start >/dev/null
c03_started=1

"$c03_pg_bin/createdb" \
  -h "$c03_socket_dir" \
  -p "$c03_port" \
  -U "$c03_user" \
  "$c03_database"

unset C03_TEST_DATABASE_URL C03_TEST_PGPASSWORD

C03_TEST_EPHEMERAL=1 \
C03_TEST_PGHOST="$c03_socket_dir" \
C03_TEST_PGPORT="$c03_port" \
C03_TEST_PGDATABASE="$c03_database" \
C03_TEST_PGUSER="$c03_user" \
node --test --test-concurrency=1 tests/integration/c03-postgres.test.mjs
