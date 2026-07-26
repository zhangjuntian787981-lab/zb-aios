#!/bin/sh
set -eu

c08_roles_pg_bin=${C08_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c08_roles_pg_root=$(mktemp -d /tmp/c08-roles-pg.XXXXXX)
c08_roles_data_dir="$c08_roles_pg_root/data"
c08_roles_socket_dir="$c08_roles_pg_root/socket"
c08_roles_log_file="$c08_roles_pg_root/postgres.log"
c08_roles_port=$((59000 + ($$ % 5000)))
c08_roles_database="c08_roles_test_$$"
c08_roles_user=$(id -un)
c08_roles_started=0

cleanup_c08_roles_postgres() {
  c08_roles_exit_status=$?
  c08_roles_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c08_roles_started" -eq 1 ]; then
    if ! "$c08_roles_pg_bin/pg_ctl" \
      -D "$c08_roles_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c08_roles_can_remove=0
      c08_roles_exit_status=1
      printf '%s\n' \
        "C08 roles PostgreSQL could not stop; preserving $c08_roles_pg_root and $c08_roles_log_file." >&2
    fi
  fi

  if [ "$c08_roles_can_remove" -eq 1 ]; then
    case "$c08_roles_pg_root" in
      /tmp/c08-roles-pg.*) rm -rf -- "$c08_roles_pg_root" ;;
      *)
        c08_roles_exit_status=1
        printf '%s\n' "Refusing unexpected C08 roles PostgreSQL path." >&2
        ;;
    esac
  fi
  exit "$c08_roles_exit_status"
}

trap cleanup_c08_roles_postgres EXIT
trap 'exit 130' HUP INT TERM

for c08_roles_binary in initdb pg_ctl createdb pg_config; do
  if [ ! -x "$c08_roles_pg_bin/$c08_roles_binary" ]; then
    printf '%s\n' \
      "PostgreSQL 17 binary is missing: $c08_roles_binary" >&2
    exit 1
  fi
done

c08_roles_extension_dir=$(
  "$c08_roles_pg_bin/pg_config" --sharedir
)/extension
if [ ! -f "$c08_roles_extension_dir/vector.control" ]; then
  printf '%s\n' "C08 roles dependency pgvector is missing." >&2
  exit 1
fi

mkdir "$c08_roles_socket_dir"
"$c08_roles_pg_bin/initdb" \
  -D "$c08_roles_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c08_roles_pg_bin/pg_ctl" \
  -D "$c08_roles_data_dir" \
  -l "$c08_roles_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c08_roles_socket_dir' -p $c08_roles_port" \
  -t 30 \
  -w start >/dev/null
c08_roles_started=1

"$c08_roles_pg_bin/createdb" \
  -h "$c08_roles_socket_dir" \
  -p "$c08_roles_port" \
  -U "$c08_roles_user" \
  "$c08_roles_database"

unset C08_ROLES_TEST_PGPASSWORD

C08_ROLES_TEST_EPHEMERAL=1 \
C08_ROLES_TEST_PGHOST="$c08_roles_socket_dir" \
C08_ROLES_TEST_PGPORT="$c08_roles_port" \
C08_ROLES_TEST_PGDATABASE="$c08_roles_database" \
C08_ROLES_TEST_PGUSER="$c08_roles_user" \
node --test --test-concurrency=1 \
  tests/integration/c08-roles-postgres.test.mjs
