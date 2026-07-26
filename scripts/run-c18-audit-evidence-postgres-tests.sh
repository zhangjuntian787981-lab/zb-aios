#!/bin/sh
set -eu

c18_pg_bin=${C18_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c18_pg_root=$(mktemp -d /tmp/c18-pg.XXXXXX)
c18_data_dir="$c18_pg_root/data"
c18_socket_dir="$c18_pg_root/socket"
c18_log_file="$c18_pg_root/postgres.log"
c18_port=$((61000 + ($$ % 1500)))
c18_database="c18_test_$$"
c18_restore_pg_root=$(mktemp -d /tmp/c18-restore-pg.XXXXXX)
c18_restore_data_dir="$c18_restore_pg_root/data"
c18_restore_socket_dir="$c18_restore_pg_root/socket"
c18_restore_log_file="$c18_restore_pg_root/postgres.log"
c18_restore_port=$((c18_port + 2000))
c18_restore_database="c18_restore_test_$$"
c18_user=$(id -un)
c18_started=0
c18_restore_started=0

cleanup_c18_postgres() {
  c18_exit_status=$?
  c18_can_remove=1
  trap - EXIT HUP INT TERM
  if [ "$c18_started" -eq 1 ]; then
    if ! "$c18_pg_bin/pg_ctl" -D "$c18_data_dir" -m immediate \
      -w stop >/dev/null 2>&1; then
      c18_can_remove=0
      c18_exit_status=1
      printf '%s\n' \
        "C18 PostgreSQL could not stop; preserving $c18_pg_root." >&2
    fi
  fi
  if [ "$c18_restore_started" -eq 1 ]; then
    if ! "$c18_pg_bin/pg_ctl" -D "$c18_restore_data_dir" \
      -m immediate -w stop >/dev/null 2>&1; then
      c18_can_remove=0
      c18_exit_status=1
      printf '%s\n' \
        "C18 restore PostgreSQL could not stop; preserving $c18_restore_pg_root." >&2
    fi
  fi
  if [ "$c18_can_remove" -eq 1 ]; then
    case "$c18_pg_root" in
      /tmp/c18-pg.*) rm -rf -- "$c18_pg_root" ;;
      *) c18_exit_status=1 ;;
    esac
    case "$c18_restore_pg_root" in
      /tmp/c18-restore-pg.*) rm -rf -- "$c18_restore_pg_root" ;;
      *) c18_exit_status=1 ;;
    esac
  fi
  exit "$c18_exit_status"
}

trap cleanup_c18_postgres EXIT
trap 'exit 130' HUP INT TERM

for c18_binary in initdb pg_ctl createdb dropdb pg_config pg_dump pg_restore; do
  if [ ! -x "$c18_pg_bin/$c18_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c18_binary" >&2
    exit 1
  fi
done
c18_extension_dir=$("$c18_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c18_extension_dir/vector.control" ]; then
  printf '%s\n' "C18 dependency pgvector is missing." >&2
  exit 1
fi

mkdir "$c18_socket_dir" "$c18_restore_socket_dir"
"$c18_pg_bin/initdb" -D "$c18_data_dir" --encoding=UTF8 --locale=C \
  --auth-local=trust --auth-host=reject --no-instructions >/dev/null
"$c18_pg_bin/initdb" -D "$c18_restore_data_dir" --encoding=UTF8 \
  --locale=C --auth-local=trust --auth-host=reject \
  --no-instructions >/dev/null
"$c18_pg_bin/pg_ctl" -D "$c18_data_dir" -l "$c18_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c18_socket_dir' -p $c18_port" \
  -t 30 -w start >/dev/null
c18_started=1
"$c18_pg_bin/pg_ctl" -D "$c18_restore_data_dir" \
  -l "$c18_restore_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c18_restore_socket_dir' -p $c18_restore_port" \
  -t 30 -w start >/dev/null
c18_restore_started=1
"$c18_pg_bin/createdb" -h "$c18_socket_dir" -p "$c18_port" \
  -U "$c18_user" "$c18_database"
"$c18_pg_bin/createdb" -h "$c18_restore_socket_dir" \
  -p "$c18_restore_port" -U "$c18_user" "$c18_restore_database"

unset C18_TEST_PGPASSWORD
C18_TEST_EPHEMERAL=1 \
C18_TEST_PGHOST="$c18_socket_dir" \
C18_TEST_PGPORT="$c18_port" \
C18_TEST_PGDATABASE="$c18_database" \
C18_TEST_PGUSER="$c18_user" \
C18_TEST_PG_BIN="$c18_pg_bin" \
C18_RESTORE_TEST_PGHOST="$c18_restore_socket_dir" \
C18_RESTORE_TEST_PGPORT="$c18_restore_port" \
C18_RESTORE_TEST_PGDATABASE="$c18_restore_database" \
C18_RESTORE_TEST_PGUSER="$c18_user" \
node --test --test-concurrency=1 \
  tests/integration/c18-audit-evidence-postgres.test.mjs
