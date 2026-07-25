#!/bin/sh
set -eu

c04_outbox_pg_bin=${C04_OUTBOX_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c04_outbox_pg_root=$(mktemp -d /tmp/c04-outbox-pg.XXXXXX)
c04_outbox_data_dir="$c04_outbox_pg_root/data"
c04_outbox_socket_dir="$c04_outbox_pg_root/socket"
c04_outbox_log_file="$c04_outbox_pg_root/postgres.log"
c04_outbox_port=$((47000 + ($$ % 8000)))
c04_outbox_database="c04_outbox_test_$$"
c04_outbox_user=$(id -un)
c04_outbox_started=0

cleanup_c04_outbox_postgres() {
  c04_outbox_exit_status=$?
  c04_outbox_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c04_outbox_started" -eq 1 ]; then
    if ! "$c04_outbox_pg_bin/pg_ctl" \
      -D "$c04_outbox_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c04_outbox_can_remove=0
      c04_outbox_exit_status=1
      printf '%s\n' \
        "C04 Outbox PostgreSQL could not be stopped; preserving $c04_outbox_pg_root and $c04_outbox_log_file." >&2
    fi
  fi

  if [ "$c04_outbox_can_remove" -eq 1 ]; then
    case "$c04_outbox_pg_root" in
      /tmp/c04-outbox-pg.*) rm -rf -- "$c04_outbox_pg_root" ;;
      *)
        c04_outbox_exit_status=1
        printf '%s\n' "Refusing to remove unexpected C04 Outbox PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c04_outbox_exit_status"
}

trap cleanup_c04_outbox_postgres EXIT
trap 'exit 130' HUP INT TERM

for c04_outbox_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c04_outbox_pg_bin/$c04_outbox_binary" ]; then
    printf '%s\n' \
      "PostgreSQL 17 binary is missing: $c04_outbox_binary" >&2
    exit 1
  fi
done

mkdir "$c04_outbox_socket_dir"

"$c04_outbox_pg_bin/initdb" \
  -D "$c04_outbox_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c04_outbox_pg_bin/pg_ctl" \
  -D "$c04_outbox_data_dir" \
  -l "$c04_outbox_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c04_outbox_socket_dir' -p $c04_outbox_port" \
  -t 30 \
  -w start >/dev/null
c04_outbox_started=1

"$c04_outbox_pg_bin/createdb" \
  -h "$c04_outbox_socket_dir" \
  -p "$c04_outbox_port" \
  -U "$c04_outbox_user" \
  "$c04_outbox_database"

unset C04_OUTBOX_TEST_PGPASSWORD

C04_OUTBOX_TEST_EPHEMERAL=1 \
C04_OUTBOX_TEST_PGHOST="$c04_outbox_socket_dir" \
C04_OUTBOX_TEST_PGPORT="$c04_outbox_port" \
C04_OUTBOX_TEST_PGDATABASE="$c04_outbox_database" \
C04_OUTBOX_TEST_PGUSER="$c04_outbox_user" \
node --test --test-concurrency=1 \
  tests/integration/c04-outbox-postgres.test.mjs
