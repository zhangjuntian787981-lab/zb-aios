#!/bin/sh
set -eu

c14_pg_bin=${C14_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c14_pg_root=$(mktemp -d /tmp/c14-pg.XXXXXX)
c14_data_dir="$c14_pg_root/data"
c14_socket_dir="$c14_pg_root/socket"
c14_log_file="$c14_pg_root/postgres.log"
c14_port=$((58000 + ($$ % 4000)))
c14_database="c14_test_$$"
c14_user=$(id -un)
c14_started=0

cleanup_c14_postgres() {
  c14_exit_status=$?
  c14_can_remove=1
  trap - EXIT HUP INT TERM
  if [ "$c14_started" -eq 1 ]; then
    if ! "$c14_pg_bin/pg_ctl" \
      -D "$c14_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c14_can_remove=0
      c14_exit_status=1
      printf '%s\n' \
        "C14 PostgreSQL could not stop; preserving $c14_pg_root and $c14_log_file." >&2
    fi
  fi
  if [ "$c14_can_remove" -eq 1 ]; then
    case "$c14_pg_root" in
      /tmp/c14-pg.*) rm -rf -- "$c14_pg_root" ;;
      *)
        c14_exit_status=1
        printf '%s\n' "Refusing unexpected C14 PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c14_exit_status"
}

trap cleanup_c14_postgres EXIT
trap 'exit 130' HUP INT TERM

for c14_binary in initdb pg_ctl createdb pg_config; do
  if [ ! -x "$c14_pg_bin/$c14_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c14_binary" >&2
    exit 1
  fi
done

c14_extension_dir=$("$c14_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c14_extension_dir/vector.control" ]; then
  printf '%s\n' "C14 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$c14_socket_dir"
"$c14_pg_bin/initdb" \
  -D "$c14_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c14_pg_bin/pg_ctl" \
  -D "$c14_data_dir" \
  -l "$c14_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c14_socket_dir' -p $c14_port" \
  -t 30 \
  -w start >/dev/null
c14_started=1

"$c14_pg_bin/createdb" \
  -h "$c14_socket_dir" \
  -p "$c14_port" \
  -U "$c14_user" \
  "$c14_database"

unset C14_TEST_PGPASSWORD

C14_TEST_EPHEMERAL=1 \
C14_TEST_PGHOST="$c14_socket_dir" \
C14_TEST_PGPORT="$c14_port" \
C14_TEST_PGDATABASE="$c14_database" \
C14_TEST_PGUSER="$c14_user" \
node --test --test-concurrency=1 tests/integration/c14-postgres.test.mjs
