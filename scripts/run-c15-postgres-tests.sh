#!/bin/sh
set -eu

c15_pg_bin=${C15_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c15_pg_root=$(mktemp -d /tmp/c15-pg.XXXXXX)
c15_data_dir="$c15_pg_root/data"
c15_socket_dir="$c15_pg_root/socket"
c15_log_file="$c15_pg_root/postgres.log"
c15_port=$((59000 + ($$ % 3000)))
c15_database="c15_test_$$"
c15_restore_root=$(mktemp -d /tmp/c15-restore-pg.XXXXXX)
c15_restore_data_dir="$c15_restore_root/data"
c15_restore_socket_dir="$c15_restore_root/socket"
c15_restore_log_file="$c15_restore_root/postgres.log"
c15_restore_port=$((62000 + ($$ % 3000)))
c15_restore_database="c15_restore_test_$$"
c15_user=$(id -un)
c15_started=0
c15_restore_started=0

cleanup_c15_postgres() {
  c15_exit_status=$?
  c15_can_remove=1
  trap - EXIT HUP INT TERM
  if [ "$c15_started" -eq 1 ]; then
    if ! "$c15_pg_bin/pg_ctl" \
      -D "$c15_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c15_can_remove=0
      c15_exit_status=1
      printf '%s\n' \
        "C15 PostgreSQL could not stop; preserving $c15_pg_root." >&2
    fi
  fi
  if [ "$c15_restore_started" -eq 1 ]; then
    if ! "$c15_pg_bin/pg_ctl" \
      -D "$c15_restore_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c15_can_remove=0
      c15_exit_status=1
      printf '%s\n' \
        "C15 restored PostgreSQL could not stop; preserving $c15_restore_root." >&2
    fi
  fi
  if [ "$c15_can_remove" -eq 1 ]; then
    case "$c15_pg_root" in
      /tmp/c15-pg.*) rm -rf -- "$c15_pg_root" ;;
      *)
        c15_exit_status=1
        printf '%s\n' "Refusing unexpected C15 PostgreSQL path." >&2
        ;;
    esac
    case "$c15_restore_root" in
      /tmp/c15-restore-pg.*) rm -rf -- "$c15_restore_root" ;;
      *)
        c15_exit_status=1
        printf '%s\n' \
          "Refusing unexpected C15 restore PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c15_exit_status"
}

trap cleanup_c15_postgres EXIT
trap 'exit 130' HUP INT TERM

for c15_binary in initdb pg_ctl createdb pg_config pg_dump pg_restore psql; do
  if [ ! -x "$c15_pg_bin/$c15_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c15_binary" >&2
    exit 1
  fi
done

c15_extension_dir=$("$c15_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c15_extension_dir/vector.control" ]; then
  printf '%s\n' "C15 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$c15_socket_dir"
"$c15_pg_bin/initdb" \
  -D "$c15_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c15_pg_bin/pg_ctl" \
  -D "$c15_data_dir" \
  -l "$c15_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c15_socket_dir' -p $c15_port" \
  -t 30 \
  -w start >/dev/null
c15_started=1

"$c15_pg_bin/createdb" \
  -h "$c15_socket_dir" \
  -p "$c15_port" \
  -U "$c15_user" \
  "$c15_database"

unset C15_TEST_PGPASSWORD

C15_TEST_EPHEMERAL=1 \
C15_TEST_PGHOST="$c15_socket_dir" \
C15_TEST_PGPORT="$c15_port" \
C15_TEST_PGDATABASE="$c15_database" \
C15_TEST_PGUSER="$c15_user" \
node --test --test-concurrency=1 tests/integration/c15-postgres.test.mjs

c15_source_system_identifier=$(
  "$c15_pg_bin/psql" \
    -X \
    -At \
    -h "$c15_socket_dir" \
    -p "$c15_port" \
    -U "$c15_user" \
    -d "$c15_database" \
    -c "SELECT system_identifier FROM pg_control_system()"
)
c15_dump_file="$c15_pg_root/c15.dump"
"$c15_pg_bin/pg_dump" \
  -h "$c15_socket_dir" \
  -p "$c15_port" \
  -U "$c15_user" \
  --format=custom \
  --file="$c15_dump_file" \
  "$c15_database"

mkdir "$c15_restore_socket_dir"
"$c15_pg_bin/initdb" \
  -D "$c15_restore_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c15_pg_bin/pg_ctl" \
  -D "$c15_restore_data_dir" \
  -l "$c15_restore_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c15_restore_socket_dir' -p $c15_restore_port" \
  -t 30 \
  -w start >/dev/null
c15_restore_started=1

"$c15_pg_bin/createdb" \
  -h "$c15_restore_socket_dir" \
  -p "$c15_restore_port" \
  -U "$c15_user" \
  "$c15_restore_database"

"$c15_pg_bin/psql" \
  -X \
  -v ON_ERROR_STOP=1 \
  -h "$c15_restore_socket_dir" \
  -p "$c15_restore_port" \
  -U "$c15_user" \
  -d "$c15_restore_database" \
  -f implementation/p1/c15/postgresql/c15_restore_role_bootstrap.v1.sql \
  >/dev/null

"$c15_pg_bin/pg_restore" \
  -h "$c15_restore_socket_dir" \
  -p "$c15_restore_port" \
  -U "$c15_user" \
  -d "$c15_restore_database" \
  --exit-on-error \
  "$c15_dump_file"

c15_restore_system_identifier=$(
  "$c15_pg_bin/psql" \
    -X \
    -At \
    -h "$c15_restore_socket_dir" \
    -p "$c15_restore_port" \
    -U "$c15_user" \
    -d "$c15_restore_database" \
    -c "SELECT system_identifier FROM pg_control_system()"
)
if [ "$c15_source_system_identifier" = "$c15_restore_system_identifier" ]; then
  printf '%s\n' \
    "C15 restore must use a different PostgreSQL system identifier." >&2
  exit 1
fi

unset C15_RESTORE_PGPASSWORD

C15_RESTORE_EPHEMERAL=1 \
C15_RESTORE_PGHOST="$c15_restore_socket_dir" \
C15_RESTORE_PGPORT="$c15_restore_port" \
C15_RESTORE_PGDATABASE="$c15_restore_database" \
C15_RESTORE_PGUSER="$c15_user" \
C15_RESTORE_SOURCE_SYSTEM_IDENTIFIER="$c15_source_system_identifier" \
C15_RESTORE_TARGET_SYSTEM_IDENTIFIER="$c15_restore_system_identifier" \
node --test --test-concurrency=1 \
  tests/integration/c15-postgres-restore.test.mjs
