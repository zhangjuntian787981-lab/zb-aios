#!/bin/sh
set -eu

c04_roles_pg_bin=${C04_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c04_roles_pg_root=$(mktemp -d /tmp/c04-roles-pg.XXXXXX)
c04_roles_data_dir="$c04_roles_pg_root/data"
c04_roles_socket_dir="$c04_roles_pg_root/socket"
c04_roles_log_file="$c04_roles_pg_root/postgres.log"
c04_roles_port=$((57000 + ($$ % 6000)))
c04_roles_database="c04_roles_test_$$"
c04_roles_user=$(id -un)
c04_roles_started=0

cleanup_c04_roles_postgres() {
  c04_roles_exit_status=$?
  c04_roles_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c04_roles_started" -eq 1 ]; then
    if ! "$c04_roles_pg_bin/pg_ctl" \
      -D "$c04_roles_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c04_roles_can_remove=0
      c04_roles_exit_status=1
      printf '%s\n' \
        "C04 roles PostgreSQL could not be stopped; preserving $c04_roles_pg_root and $c04_roles_log_file." >&2
    fi
  fi

  if [ "$c04_roles_can_remove" -eq 1 ]; then
    case "$c04_roles_pg_root" in
      /tmp/c04-roles-pg.*) rm -rf -- "$c04_roles_pg_root" ;;
      *)
        c04_roles_exit_status=1
        printf '%s\n' \
          "Refusing to remove unexpected C04 roles PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c04_roles_exit_status"
}

trap cleanup_c04_roles_postgres EXIT
trap 'exit 130' HUP INT TERM

for c04_roles_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c04_roles_pg_bin/$c04_roles_binary" ]; then
    printf '%s\n' \
      "PostgreSQL 17 binary is missing: $c04_roles_binary" >&2
    exit 1
  fi
done

mkdir "$c04_roles_socket_dir"

"$c04_roles_pg_bin/initdb" \
  -D "$c04_roles_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c04_roles_pg_bin/pg_ctl" \
  -D "$c04_roles_data_dir" \
  -l "$c04_roles_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c04_roles_socket_dir' -p $c04_roles_port" \
  -t 30 \
  -w start >/dev/null
c04_roles_started=1

"$c04_roles_pg_bin/createdb" \
  -h "$c04_roles_socket_dir" \
  -p "$c04_roles_port" \
  -U "$c04_roles_user" \
  "$c04_roles_database"

unset C04_ROLES_TEST_PGPASSWORD

C04_ROLES_TEST_EPHEMERAL=1 \
C04_ROLES_TEST_PGHOST="$c04_roles_socket_dir" \
C04_ROLES_TEST_PGPORT="$c04_roles_port" \
C04_ROLES_TEST_PGDATABASE="$c04_roles_database" \
C04_ROLES_TEST_PGUSER="$c04_roles_user" \
node --test --test-concurrency=1 \
  tests/integration/c04-roles-postgres.test.mjs
