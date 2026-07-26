#!/bin/sh
set -eu

c07_roles_pg_bin=${C07_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c07_roles_pg_root=$(mktemp -d /tmp/c07-roles-pg.XXXXXX)
c07_roles_data_dir="$c07_roles_pg_root/data"
c07_roles_socket_dir="$c07_roles_pg_root/socket"
c07_roles_log_file="$c07_roles_pg_root/postgres.log"
c07_roles_port=$((55000 + ($$ % 6000)))
c07_roles_database="c07_roles_test_$$"
c07_roles_user=$(id -un)
c07_roles_started=0

cleanup_c07_roles_postgres() {
  c07_roles_exit_status=$?
  c07_roles_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c07_roles_started" -eq 1 ]; then
    if ! "$c07_roles_pg_bin/pg_ctl" \
      -D "$c07_roles_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c07_roles_can_remove=0
      c07_roles_exit_status=1
      printf '%s\n' \
        "C07 roles PostgreSQL could not be stopped; preserving $c07_roles_pg_root and $c07_roles_log_file." >&2
    fi
  fi

  if [ "$c07_roles_can_remove" -eq 1 ]; then
    case "$c07_roles_pg_root" in
      /tmp/c07-roles-pg.*) rm -rf -- "$c07_roles_pg_root" ;;
      *)
        c07_roles_exit_status=1
        printf '%s\n' \
          "Refusing to remove unexpected C07 roles PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c07_roles_exit_status"
}

trap cleanup_c07_roles_postgres EXIT
trap 'exit 130' HUP INT TERM

for c07_roles_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c07_roles_pg_bin/$c07_roles_binary" ]; then
    printf '%s\n' \
      "PostgreSQL 17 binary is missing: $c07_roles_binary" >&2
    exit 1
  fi
done

mkdir "$c07_roles_socket_dir"

"$c07_roles_pg_bin/initdb" \
  -D "$c07_roles_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c07_roles_pg_bin/pg_ctl" \
  -D "$c07_roles_data_dir" \
  -l "$c07_roles_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c07_roles_socket_dir' -p $c07_roles_port" \
  -t 30 \
  -w start >/dev/null
c07_roles_started=1

"$c07_roles_pg_bin/createdb" \
  -h "$c07_roles_socket_dir" \
  -p "$c07_roles_port" \
  -U "$c07_roles_user" \
  "$c07_roles_database"

unset C07_ROLES_TEST_PGPASSWORD

C07_ROLES_TEST_EPHEMERAL=1 \
C07_ROLES_TEST_PGHOST="$c07_roles_socket_dir" \
C07_ROLES_TEST_PGPORT="$c07_roles_port" \
C07_ROLES_TEST_PGDATABASE="$c07_roles_database" \
C07_ROLES_TEST_PGUSER="$c07_roles_user" \
node --test --test-concurrency=1 \
  tests/integration/c07-roles-postgres.test.mjs
