#!/bin/sh
set -eu

c16_pg_bin=${C16_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c16_pg_root=$(mktemp -d /tmp/c16-pg.XXXXXX)
c16_data_dir="$c16_pg_root/data"
c16_socket_dir="$c16_pg_root/socket"
c16_log_file="$c16_pg_root/postgres.log"
c16_port=$((60000 + ($$ % 2000)))
c16_database="c16_test_$$"
c16_restore_root=$(mktemp -d /tmp/c16-restore-pg.XXXXXX)
c16_restore_data_dir="$c16_restore_root/data"
c16_restore_socket_dir="$c16_restore_root/socket"
c16_restore_log_file="$c16_restore_root/postgres.log"
c16_restore_port=$((62000 + ($$ % 2000)))
c16_restore_database="c16_restore_test_$$"
c16_user=$(id -un)
c16_started=0
c16_restore_started=0

cleanup_c16_postgres() {
  c16_exit_status=$?
  c16_can_remove=1
  trap - EXIT HUP INT TERM
  if [ "$c16_started" -eq 1 ]; then
    if ! "$c16_pg_bin/pg_ctl" \
      -D "$c16_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c16_can_remove=0
      c16_exit_status=1
      printf '%s\n' \
        "C16 PostgreSQL could not stop; preserving $c16_pg_root." >&2
    fi
  fi
  if [ "$c16_restore_started" -eq 1 ]; then
    if ! "$c16_pg_bin/pg_ctl" \
      -D "$c16_restore_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c16_can_remove=0
      c16_exit_status=1
      printf '%s\n' \
        "C16 restored PostgreSQL could not stop; preserving $c16_restore_root." >&2
    fi
  fi
  if [ "$c16_can_remove" -eq 1 ]; then
    case "$c16_pg_root" in
      /tmp/c16-pg.*) rm -rf -- "$c16_pg_root" ;;
      *)
        c16_exit_status=1
        printf '%s\n' "Refusing unexpected C16 PostgreSQL path." >&2
        ;;
    esac
    case "$c16_restore_root" in
      /tmp/c16-restore-pg.*) rm -rf -- "$c16_restore_root" ;;
      *)
        c16_exit_status=1
        printf '%s\n' \
          "Refusing unexpected C16 restore PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c16_exit_status"
}

trap cleanup_c16_postgres EXIT
trap 'exit 130' HUP INT TERM

for c16_binary in initdb pg_ctl createdb pg_config pg_dump pg_restore psql; do
  if [ ! -x "$c16_pg_bin/$c16_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c16_binary" >&2
    exit 1
  fi
done

c16_extension_dir=$("$c16_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c16_extension_dir/vector.control" ]; then
  printf '%s\n' "C16 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$c16_socket_dir"
"$c16_pg_bin/initdb" \
  -D "$c16_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c16_pg_bin/pg_ctl" \
  -D "$c16_data_dir" \
  -l "$c16_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c16_socket_dir' -p $c16_port" \
  -t 30 \
  -w start >/dev/null
c16_started=1

"$c16_pg_bin/createdb" \
  -h "$c16_socket_dir" \
  -p "$c16_port" \
  -U "$c16_user" \
  "$c16_database"

unset C16_TEST_PGPASSWORD

C16_TEST_EPHEMERAL=1 \
C16_TEST_PGHOST="$c16_socket_dir" \
C16_TEST_PGPORT="$c16_port" \
C16_TEST_PGDATABASE="$c16_database" \
C16_TEST_PGUSER="$c16_user" \
node --test --test-concurrency=1 \
  tests/integration/c16-postgres.test.mjs

c16_source_system_identifier=$(
  "$c16_pg_bin/psql" \
    -X \
    -At \
    -h "$c16_socket_dir" \
    -p "$c16_port" \
    -U "$c16_user" \
    -d "$c16_database" \
    -c "SELECT system_identifier FROM pg_control_system()"
)
c16_dump_file="$c16_pg_root/c16.dump"
"$c16_pg_bin/pg_dump" \
  -h "$c16_socket_dir" \
  -p "$c16_port" \
  -U "$c16_user" \
  --format=custom \
  --file="$c16_dump_file" \
  "$c16_database"

mkdir "$c16_restore_socket_dir"
"$c16_pg_bin/initdb" \
  -D "$c16_restore_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c16_pg_bin/pg_ctl" \
  -D "$c16_restore_data_dir" \
  -l "$c16_restore_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c16_restore_socket_dir' -p $c16_restore_port" \
  -t 30 \
  -w start >/dev/null
c16_restore_started=1

"$c16_pg_bin/createdb" \
  -h "$c16_restore_socket_dir" \
  -p "$c16_restore_port" \
  -U "$c16_user" \
  "$c16_restore_database"

"$c16_pg_bin/psql" \
  -X \
  -v ON_ERROR_STOP=1 \
  -h "$c16_restore_socket_dir" \
  -p "$c16_restore_port" \
  -U "$c16_user" \
  -d "$c16_restore_database" \
  -f implementation/p1/c16/postgresql/c16_restore_role_bootstrap.v1.sql \
  >/dev/null

"$c16_pg_bin/pg_restore" \
  -h "$c16_restore_socket_dir" \
  -p "$c16_restore_port" \
  -U "$c16_user" \
  -d "$c16_restore_database" \
  --exit-on-error \
  "$c16_dump_file"

c16_restore_system_identifier=$(
  "$c16_pg_bin/psql" \
    -X \
    -At \
    -h "$c16_restore_socket_dir" \
    -p "$c16_restore_port" \
    -U "$c16_user" \
    -d "$c16_restore_database" \
    -c "SELECT system_identifier FROM pg_control_system()"
)
if [ "$c16_source_system_identifier" = "$c16_restore_system_identifier" ]; then
  printf '%s\n' \
    "C16 restore must use a different PostgreSQL system identifier." >&2
  exit 1
fi

unset C16_RESTORE_PGPASSWORD

C16_RESTORE_EPHEMERAL=1 \
C16_RESTORE_PGHOST="$c16_restore_socket_dir" \
C16_RESTORE_PGPORT="$c16_restore_port" \
C16_RESTORE_PGDATABASE="$c16_restore_database" \
C16_RESTORE_PGUSER="$c16_user" \
C16_RESTORE_SOURCE_SYSTEM_IDENTIFIER="$c16_source_system_identifier" \
C16_RESTORE_TARGET_SYSTEM_IDENTIFIER="$c16_restore_system_identifier" \
node --test --test-concurrency=1 \
  tests/integration/c16-postgres-restore.test.mjs
