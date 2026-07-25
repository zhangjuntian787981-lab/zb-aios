#!/bin/sh
set -eu

c05_roles_pg_bin=${C05_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c05_roles_pg_root=$(mktemp -d /tmp/c05-roles-pg.XXXXXX)
c05_roles_data_dir="$c05_roles_pg_root/data"
c05_roles_socket_dir="$c05_roles_pg_root/socket"
c05_roles_log_file="$c05_roles_pg_root/postgres.log"
c05_roles_port=$((58000 + ($$ % 5000)))
c05_roles_database="c05_roles_test_$$"
c05_roles_user=$(id -un)
c05_roles_started=0

cleanup_c05_roles_postgres() {
  c05_roles_exit_status=$?
  c05_roles_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c05_roles_started" -eq 1 ]; then
    if ! "$c05_roles_pg_bin/pg_ctl" \
      -D "$c05_roles_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c05_roles_can_remove=0
      c05_roles_exit_status=1
      printf '%s\n' \
        "C05 roles PostgreSQL could not be stopped; preserving $c05_roles_pg_root and $c05_roles_log_file." >&2
    fi
  fi

  if [ "$c05_roles_can_remove" -eq 1 ]; then
    case "$c05_roles_pg_root" in
      /tmp/c05-roles-pg.*) rm -rf -- "$c05_roles_pg_root" ;;
      *)
        c05_roles_exit_status=1
        printf '%s\n' \
          "Refusing to remove unexpected C05 roles PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c05_roles_exit_status"
}

trap cleanup_c05_roles_postgres EXIT
trap 'exit 130' HUP INT TERM

for c05_roles_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c05_roles_pg_bin/$c05_roles_binary" ]; then
    printf '%s\n' \
      "PostgreSQL 17 binary is missing: $c05_roles_binary" >&2
    exit 1
  fi
done

mkdir "$c05_roles_socket_dir"

"$c05_roles_pg_bin/initdb" \
  -D "$c05_roles_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c05_roles_pg_bin/pg_ctl" \
  -D "$c05_roles_data_dir" \
  -l "$c05_roles_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c05_roles_socket_dir' -p $c05_roles_port" \
  -t 30 \
  -w start >/dev/null
c05_roles_started=1

"$c05_roles_pg_bin/createdb" \
  -h "$c05_roles_socket_dir" \
  -p "$c05_roles_port" \
  -U "$c05_roles_user" \
  "$c05_roles_database"

unset C05_ROLES_TEST_PGPASSWORD

C05_ROLES_TEST_EPHEMERAL=1 \
C05_ROLES_TEST_PGHOST="$c05_roles_socket_dir" \
C05_ROLES_TEST_PGPORT="$c05_roles_port" \
C05_ROLES_TEST_PGDATABASE="$c05_roles_database" \
C05_ROLES_TEST_PGUSER="$c05_roles_user" \
node --test --test-concurrency=1 \
  tests/integration/c05-roles-postgres.test.mjs
