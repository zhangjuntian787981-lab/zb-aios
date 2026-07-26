#!/bin/sh
set -eu

c09_pg_bin=${C09_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c09_pg_root=$(mktemp -d /tmp/c09-pg.XXXXXX)
c09_data_dir="$c09_pg_root/data"
c09_socket_dir="$c09_pg_root/socket"
c09_log_file="$c09_pg_root/postgres.log"
c09_port=$((57000 + ($$ % 5000)))
c09_database="c09_test_$$"
c09_user=$(id -un)
c09_started=0

cleanup_c09_postgres() {
  c09_exit_status=$?
  c09_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c09_started" -eq 1 ]; then
    if ! "$c09_pg_bin/pg_ctl" \
      -D "$c09_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c09_can_remove=0
      c09_exit_status=1
      printf '%s\n' \
        "C09 PostgreSQL could not stop; preserving $c09_pg_root." >&2
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

for c09_binary in initdb pg_ctl createdb pg_config; do
  if [ ! -x "$c09_pg_bin/$c09_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c09_binary" >&2
    exit 1
  fi
done

c09_extension_dir=$("$c09_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c09_extension_dir/vector.control" ]; then
  printf '%s\n' "C09 dependency pgvector is missing for PostgreSQL 17." >&2
  exit 1
fi

mkdir "$c09_socket_dir"
"$c09_pg_bin/initdb" \
  -D "$c09_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c09_pg_bin/pg_ctl" \
  -D "$c09_data_dir" \
  -l "$c09_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c09_socket_dir' -p $c09_port" \
  -t 30 \
  -w start >/dev/null
c09_started=1

"$c09_pg_bin/createdb" \
  -h "$c09_socket_dir" \
  -p "$c09_port" \
  -U "$c09_user" \
  "$c09_database"

unset C09_TEST_PGPASSWORD

C09_TEST_EPHEMERAL=1 \
C09_TEST_PGHOST="$c09_socket_dir" \
C09_TEST_PGPORT="$c09_port" \
C09_TEST_PGDATABASE="$c09_database" \
C09_TEST_PGUSER="$c09_user" \
node --test --test-concurrency=1 \
  tests/integration/c09-personal-memory-postgres.test.mjs
