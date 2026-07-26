#!/bin/sh
set -eu

c07_restore_pg_bin=${C07_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c07_restore_root=$(mktemp -d /tmp/c07-restore-pg.XXXXXX)
c07_restore_data_dir="$c07_restore_root/data"
c07_restore_socket_dir="$c07_restore_root/socket"
c07_restore_log_file="$c07_restore_root/postgres.log"
c07_restore_dump_file="$c07_restore_root/c07.dump"
c07_restore_object_source="$c07_restore_root/object-source"
c07_restore_object_target="$c07_restore_root/object-target"
c07_restore_port=$((52000 + ($$ % 3000)))
c07_restore_source="c07_restore_source_$$"
c07_restore_target="c07_restore_target_$$"
c07_restore_user=$(id -un)
c07_restore_started=0

cleanup_c07_restore_postgres() {
  c07_restore_exit_status=$?
  c07_restore_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c07_restore_started" -eq 1 ]; then
    if ! "$c07_restore_pg_bin/pg_ctl" \
      -D "$c07_restore_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c07_restore_can_remove=0
      c07_restore_exit_status=1
      printf '%s\n' \
        "C07 restore PostgreSQL could not be stopped; preserving $c07_restore_root and $c07_restore_log_file." >&2
    fi
  fi

  if [ "$c07_restore_can_remove" -eq 1 ]; then
    case "$c07_restore_root" in
      /tmp/c07-restore-pg.*) rm -rf -- "$c07_restore_root" ;;
      *)
        c07_restore_exit_status=1
        printf '%s\n' \
          "Refusing to remove unexpected C07 restore path." >&2
        ;;
    esac
  fi

  exit "$c07_restore_exit_status"
}

trap cleanup_c07_restore_postgres EXIT
trap 'exit 130' HUP INT TERM

for c07_restore_binary in \
  initdb pg_ctl createdb pg_dump pg_restore psql; do
  if [ ! -x "$c07_restore_pg_bin/$c07_restore_binary" ]; then
    printf '%s\n' \
      "PostgreSQL 17 binary is missing: $c07_restore_binary" >&2
    exit 1
  fi
done

mkdir "$c07_restore_socket_dir"
mkdir "$c07_restore_object_source"
mkdir "$c07_restore_object_target"

"$c07_restore_pg_bin/initdb" \
  -D "$c07_restore_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c07_restore_pg_bin/pg_ctl" \
  -D "$c07_restore_data_dir" \
  -l "$c07_restore_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c07_restore_socket_dir' -p $c07_restore_port" \
  -t 30 \
  -w start >/dev/null
c07_restore_started=1

"$c07_restore_pg_bin/createdb" \
  -h "$c07_restore_socket_dir" \
  -p "$c07_restore_port" \
  -U "$c07_restore_user" \
  "$c07_restore_source"

unset C07_RESTORE_TEST_PGPASSWORD

C07_RESTORE_TEST_EPHEMERAL=1 \
C07_RESTORE_TEST_PGHOST="$c07_restore_socket_dir" \
C07_RESTORE_TEST_PGPORT="$c07_restore_port" \
C07_RESTORE_SOURCE_DATABASE="$c07_restore_source" \
C07_RESTORE_TEST_PGUSER="$c07_restore_user" \
C07_RESTORE_OBJECT_SOURCE="$c07_restore_object_source" \
node tests/integration/c07-restore-seed.mjs

"$c07_restore_pg_bin/pg_dump" \
  -h "$c07_restore_socket_dir" \
  -p "$c07_restore_port" \
  -U "$c07_restore_user" \
  -d "$c07_restore_source" \
  --format=custom \
  --exclude-table-data=aios_data.tenant_cache_record \
  --file="$c07_restore_dump_file"

"$c07_restore_pg_bin/createdb" \
  -h "$c07_restore_socket_dir" \
  -p "$c07_restore_port" \
  -U "$c07_restore_user" \
  "$c07_restore_target"

"$c07_restore_pg_bin/pg_restore" \
  -h "$c07_restore_socket_dir" \
  -p "$c07_restore_port" \
  -U "$c07_restore_user" \
  -d "$c07_restore_target" \
  "$c07_restore_dump_file"

cp -R "$c07_restore_object_source/." "$c07_restore_object_target/"

"$c07_restore_pg_bin/psql" \
  -h "$c07_restore_socket_dir" \
  -p "$c07_restore_port" \
  -U "$c07_restore_user" \
  -d postgres \
  -v ON_ERROR_STOP=1 \
  -c "ALTER DATABASE \"$c07_restore_target\" SET default_transaction_read_only = on" \
  >/dev/null

C07_RESTORE_TEST_EPHEMERAL=1 \
C07_RESTORE_TEST_PGHOST="$c07_restore_socket_dir" \
C07_RESTORE_TEST_PGPORT="$c07_restore_port" \
C07_RESTORE_TARGET_DATABASE="$c07_restore_target" \
C07_RESTORE_TEST_PGUSER="$c07_restore_user" \
C07_RESTORE_OBJECT_TARGET="$c07_restore_object_target" \
node --test --test-concurrency=1 \
  tests/integration/c07-restore-postgres.test.mjs
