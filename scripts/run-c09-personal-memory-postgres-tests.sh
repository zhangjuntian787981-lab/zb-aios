#!/bin/sh
set -eu

c09_pg_bin=${C09_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c09_pg_root=$(mktemp -d /tmp/c09-pg.XXXXXX)
c09_source_data_dir="$c09_pg_root/source-data"
c09_source_socket_dir="$c09_pg_root/source-socket"
c09_source_log_file="$c09_pg_root/source-postgres.log"
c09_source_port=$((57000 + ($$ % 4000)))
c09_source_database="c09_test_$$"
c09_restore_data_dir="$c09_pg_root/restore-data"
c09_restore_socket_dir="$c09_pg_root/restore-socket"
c09_restore_log_file="$c09_pg_root/restore-postgres.log"
c09_restore_port=$((c09_source_port + 1))
c09_restore_database="c09_restore_test_$$"
c09_dump_file="$c09_pg_root/c09.dump"
c09_role_bootstrap="implementation/p1/c09/postgresql/c09_restore_role_bootstrap.v1.sql"
c09_user=$(id -un)
c09_source_started=0
c09_restore_started=0

cleanup_c09_postgres() {
  c09_exit_status=$?
  c09_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c09_restore_started" -eq 1 ]; then
    if ! "$c09_pg_bin/pg_ctl" \
      -D "$c09_restore_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c09_can_remove=0
      c09_exit_status=1
      printf '%s\n' \
        "C09 restore PostgreSQL could not stop; preserving $c09_pg_root." >&2
    fi
  fi
  if [ "$c09_source_started" -eq 1 ]; then
    if ! "$c09_pg_bin/pg_ctl" \
      -D "$c09_source_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c09_can_remove=0
      c09_exit_status=1
      printf '%s\n' \
        "C09 source PostgreSQL could not stop; preserving $c09_pg_root." >&2
    fi
  fi

  if [ "$c09_can_remove" -eq 1 ]; then
    case "$c09_pg_root" in
      /tmp/c09-pg.*) rm -rf -- "$c09_pg_root" ;;
      *)
        c09_exit_status=1
        printf '%s\n' "Refusing unexpected C09 PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c09_exit_status"
}

trap cleanup_c09_postgres EXIT
trap 'exit 130' HUP INT TERM

for c09_binary in \
  initdb pg_ctl createdb pg_config pg_dump pg_restore psql
do
  if [ ! -x "$c09_pg_bin/$c09_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c09_binary" >&2
    exit 1
  fi
done

if [ ! -f "$c09_role_bootstrap" ]; then
  printf '%s\n' "C09 restore role bootstrap is missing." >&2
  exit 1
fi

c09_extension_dir=$("$c09_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c09_extension_dir/vector.control" ]; then
  printf '%s\n' "C09 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$c09_source_socket_dir"
"$c09_pg_bin/initdb" \
  -D "$c09_source_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c09_pg_bin/pg_ctl" \
  -D "$c09_source_data_dir" \
  -l "$c09_source_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c09_source_socket_dir' -p $c09_source_port" \
  -t 30 \
  -w start >/dev/null
c09_source_started=1

"$c09_pg_bin/createdb" \
  -h "$c09_source_socket_dir" \
  -p "$c09_source_port" \
  -U "$c09_user" \
  "$c09_source_database"

unset C09_TEST_PGPASSWORD

C09_TEST_EPHEMERAL=1 \
C09_TEST_PGHOST="$c09_source_socket_dir" \
C09_TEST_PGPORT="$c09_source_port" \
C09_TEST_PGDATABASE="$c09_source_database" \
C09_TEST_PGUSER="$c09_user" \
node --test --test-concurrency=1 \
  tests/integration/c09-personal-memory-postgres.test.mjs

c09_source_system_identifier=$(
  "$c09_pg_bin/psql" \
    -h "$c09_source_socket_dir" \
    -p "$c09_source_port" \
    -U "$c09_user" \
    -d "$c09_source_database" \
    -Atc "SELECT system_identifier::text FROM pg_control_system()"
)

"$c09_pg_bin/pg_dump" \
  -h "$c09_source_socket_dir" \
  -p "$c09_source_port" \
  -U "$c09_user" \
  --format=custom \
  --file="$c09_dump_file" \
  "$c09_source_database"

"$c09_pg_bin/pg_ctl" \
  -D "$c09_source_data_dir" \
  -m fast \
  -w stop >/dev/null
c09_source_started=0

mkdir "$c09_restore_socket_dir"
"$c09_pg_bin/initdb" \
  -D "$c09_restore_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c09_pg_bin/pg_ctl" \
  -D "$c09_restore_data_dir" \
  -l "$c09_restore_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c09_restore_socket_dir' -p $c09_restore_port" \
  -t 30 \
  -w start >/dev/null
c09_restore_started=1

c09_restore_system_identifier=$(
  "$c09_pg_bin/psql" \
    -h "$c09_restore_socket_dir" \
    -p "$c09_restore_port" \
    -U "$c09_user" \
    -d postgres \
    -Atc "SELECT system_identifier::text FROM pg_control_system()"
)
if [ "$c09_source_system_identifier" = "$c09_restore_system_identifier" ]; then
  printf '%s\n' "C09 restore cluster is not fresh." >&2
  exit 1
fi

"$c09_pg_bin/psql" \
  -h "$c09_restore_socket_dir" \
  -p "$c09_restore_port" \
  -U "$c09_user" \
  -d postgres \
  -v ON_ERROR_STOP=1 \
  -f "$c09_role_bootstrap" >/dev/null

"$c09_pg_bin/createdb" \
  -h "$c09_restore_socket_dir" \
  -p "$c09_restore_port" \
  -U "$c09_user" \
  "$c09_restore_database"

"$c09_pg_bin/pg_restore" \
  -h "$c09_restore_socket_dir" \
  -p "$c09_restore_port" \
  -U "$c09_user" \
  --dbname="$c09_restore_database" \
  --exit-on-error \
  "$c09_dump_file"

C09_TEST_EPHEMERAL=1 \
C09_TEST_RESTORED=1 \
C09_TEST_SOURCE_SYSTEM_IDENTIFIER="$c09_source_system_identifier" \
C09_TEST_PGHOST="$c09_restore_socket_dir" \
C09_TEST_PGPORT="$c09_restore_port" \
C09_TEST_PGDATABASE="$c09_restore_database" \
C09_TEST_PGUSER="$c09_user" \
node --test --test-concurrency=1 \
  tests/integration/c09-personal-memory-postgres-restore.test.mjs
