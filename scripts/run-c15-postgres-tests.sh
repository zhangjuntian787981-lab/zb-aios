#!/bin/sh
set -eu

c15_pg_bin=${C15_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c15_pg_root=$(mktemp -d /tmp/c15-pg.XXXXXX)
c15_data_dir="$c15_pg_root/data"
c15_socket_dir="$c15_pg_root/socket"
c15_log_file="$c15_pg_root/postgres.log"
c15_port=$((59000 + ($$ % 3000)))
c15_database="c15_test_$$"
c15_user=$(id -un)
c15_started=0

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
  if [ "$c15_can_remove" -eq 1 ]; then
    case "$c15_pg_root" in
      /tmp/c15-pg.*) rm -rf -- "$c15_pg_root" ;;
      *)
        c15_exit_status=1
        printf '%s\n' "Refusing unexpected C15 PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c15_exit_status"
}

trap cleanup_c15_postgres EXIT
trap 'exit 130' HUP INT TERM

for c15_binary in initdb pg_ctl createdb pg_config; do
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
