#!/bin/sh
set -eu

c06_roles_pg_bin=${C06_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c06_roles_pg_root=$(mktemp -d /tmp/c06-roles-pg.XXXXXX)
c06_roles_data_dir="$c06_roles_pg_root/data"
c06_roles_socket_dir="$c06_roles_pg_root/socket"
c06_roles_log_file="$c06_roles_pg_root/postgres.log"
c06_roles_port=$((57000 + ($$ % 6000)))
c06_roles_database="c06_roles_test_$$"
c06_roles_user=$(id -un)
c06_roles_started=0

cleanup_c06_roles_postgres() {
  c06_roles_exit_status=$?
  c06_roles_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c06_roles_started" -eq 1 ]; then
    if ! "$c06_roles_pg_bin/pg_ctl" \
      -D "$c06_roles_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c06_roles_can_remove=0
      c06_roles_exit_status=1
      printf '%s\n' \
        "C06 roles PostgreSQL could not be stopped; preserving $c06_roles_pg_root and $c06_roles_log_file." >&2
    fi
  fi

  if [ "$c06_roles_can_remove" -eq 1 ]; then
    case "$c06_roles_pg_root" in
      /tmp/c06-roles-pg.*) rm -rf -- "$c06_roles_pg_root" ;;
      *)
        c06_roles_exit_status=1
        printf '%s\n' \
          "Refusing to remove unexpected C06 roles PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c06_roles_exit_status"
}

trap cleanup_c06_roles_postgres EXIT
trap 'exit 130' HUP INT TERM

for c06_roles_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c06_roles_pg_bin/$c06_roles_binary" ]; then
    printf '%s\n' \
      "PostgreSQL 17 binary is missing: $c06_roles_binary" >&2
    exit 1
  fi
done

mkdir "$c06_roles_socket_dir"

"$c06_roles_pg_bin/initdb" \
  -D "$c06_roles_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c06_roles_pg_bin/pg_ctl" \
  -D "$c06_roles_data_dir" \
  -l "$c06_roles_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c06_roles_socket_dir' -p $c06_roles_port" \
  -t 30 \
  -w start >/dev/null
c06_roles_started=1

"$c06_roles_pg_bin/createdb" \
  -h "$c06_roles_socket_dir" \
  -p "$c06_roles_port" \
  -U "$c06_roles_user" \
  "$c06_roles_database"

unset C06_ROLES_TEST_PGPASSWORD

C06_ROLES_TEST_EPHEMERAL=1 \
C06_ROLES_TEST_PGHOST="$c06_roles_socket_dir" \
C06_ROLES_TEST_PGPORT="$c06_roles_port" \
C06_ROLES_TEST_PGDATABASE="$c06_roles_database" \
C06_ROLES_TEST_PGUSER="$c06_roles_user" \
node --test --test-concurrency=1 \
  tests/integration/c06-roles-postgres.test.mjs
