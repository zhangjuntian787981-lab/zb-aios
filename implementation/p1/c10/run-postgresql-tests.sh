#!/bin/sh
set -eu

c10_pg_bin=${C10_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c10_pg_root=$(mktemp -d /tmp/c10-pg.XXXXXX)
c10_data_dir="$c10_pg_root/data"
c10_socket_dir="$c10_pg_root/socket"
c10_log_file="$c10_pg_root/postgres.log"
c10_port=$((61000 + ($$ % 3000)))
c10_database="c10_test_$$"
c10_user=$(id -un)
c10_started=0

cleanup_c10_postgres() {
  c10_exit_status=$?
  c10_can_remove=1
  trap - EXIT HUP INT TERM
  if [ "$c10_started" -eq 1 ]; then
    if ! "$c10_pg_bin/pg_ctl" \
      -D "$c10_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c10_can_remove=0
      c10_exit_status=1
      printf '%s\n' \
        "C10 PostgreSQL could not stop; preserving $c10_pg_root." >&2
    fi
  fi
  if [ "$c10_can_remove" -eq 1 ]; then
    case "$c10_pg_root" in
      /tmp/c10-pg.*) rm -rf -- "$c10_pg_root" ;;
      *)
        c10_exit_status=1
        printf '%s\n' "Refusing unexpected C10 PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c10_exit_status"
}

trap cleanup_c10_postgres EXIT
trap 'exit 130' HUP INT TERM

for c10_binary in initdb pg_ctl createdb pg_config psql; do
  if [ ! -x "$c10_pg_bin/$c10_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c10_binary" >&2
    exit 1
  fi
done

c10_extension_dir=$("$c10_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c10_extension_dir/vector.control" ]; then
  printf '%s\n' "C10 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$c10_socket_dir"
"$c10_pg_bin/initdb" \
  -D "$c10_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c10_pg_bin/pg_ctl" \
  -D "$c10_data_dir" \
  -l "$c10_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c10_socket_dir' -p $c10_port" \
  -t 30 \
  -w start >/dev/null
c10_started=1

"$c10_pg_bin/createdb" \
  -h "$c10_socket_dir" \
  -p "$c10_port" \
  -U "$c10_user" \
  "$c10_database"

unset C10_TEST_PGPASSWORD

C10_TEST_EPHEMERAL=1 \
C10_TEST_PGHOST="$c10_socket_dir" \
C10_TEST_PGPORT="$c10_port" \
C10_TEST_PGDATABASE="$c10_database" \
C10_TEST_PGUSER="$c10_user" \
node --test --test-concurrency=1 \
  tests/integration/c10-postgres.test.mjs

c10_before_restart_epoch=$(
  "$c10_pg_bin/psql" \
    -h "$c10_socket_dir" \
    -p "$c10_port" \
    -U "$c10_user" \
    -d "$c10_database" \
    -Atc "SELECT EXTRACT(EPOCH FROM pg_postmaster_start_time())"
)

"$c10_pg_bin/pg_ctl" \
  -D "$c10_data_dir" \
  -l "$c10_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c10_socket_dir' -p $c10_port" \
  -t 30 \
  -w restart >/dev/null

c10_after_restart_epoch=$(
  "$c10_pg_bin/psql" \
    -h "$c10_socket_dir" \
    -p "$c10_port" \
    -U "$c10_user" \
    -d "$c10_database" \
    -Atc "SELECT EXTRACT(EPOCH FROM pg_postmaster_start_time())"
)

if [ "$c10_before_restart_epoch" = "$c10_after_restart_epoch" ]; then
  printf '%s\n' "C10 PostgreSQL restart did not change postmaster start time." >&2
  exit 1
fi

C10_TEST_EPHEMERAL=1 \
C10_TEST_POSTGRES_RESTARTED=1 \
C10_TEST_PRE_RESTART_EPOCH="$c10_before_restart_epoch" \
C10_TEST_PGHOST="$c10_socket_dir" \
C10_TEST_PGPORT="$c10_port" \
C10_TEST_PGDATABASE="$c10_database" \
C10_TEST_PGUSER="$c10_user" \
node --test --test-concurrency=1 \
  tests/integration/c10-postgres-restart.test.mjs
