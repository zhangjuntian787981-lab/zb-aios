#!/bin/sh
set -eu

c04_scim_checkpoint_pg_bin=${C04_SCIM_CHECKPOINT_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c04_scim_checkpoint_pg_root=$(mktemp -d /tmp/c04-scim-checkpoint-pg.XXXXXX)
c04_scim_checkpoint_data_dir="$c04_scim_checkpoint_pg_root/data"
c04_scim_checkpoint_socket_dir="$c04_scim_checkpoint_pg_root/socket"
c04_scim_checkpoint_log_file="$c04_scim_checkpoint_pg_root/postgres.log"
c04_scim_checkpoint_port=$((47000 + ($$ % 8000)))
c04_scim_checkpoint_database="c04_scim_checkpoint_test_$$"
c04_scim_checkpoint_user=$(id -un)
c04_scim_checkpoint_started=0

cleanup_c04_scim_checkpoint_postgres() {
  c04_scim_checkpoint_exit_status=$?
  c04_scim_checkpoint_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c04_scim_checkpoint_started" -eq 1 ]; then
    if ! "$c04_scim_checkpoint_pg_bin/pg_ctl" \
      -D "$c04_scim_checkpoint_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c04_scim_checkpoint_can_remove=0
      c04_scim_checkpoint_exit_status=1
      printf '%s\n' \
        "C04 SCIM checkpoint PostgreSQL could not be stopped; preserving $c04_scim_checkpoint_pg_root and $c04_scim_checkpoint_log_file." >&2
    fi
  fi

  if [ "$c04_scim_checkpoint_can_remove" -eq 1 ]; then
    case "$c04_scim_checkpoint_pg_root" in
      /tmp/c04-scim-checkpoint-pg.*)
        rm -rf -- "$c04_scim_checkpoint_pg_root"
        ;;
      *)
        c04_scim_checkpoint_exit_status=1
        printf '%s\n' \
          "Refusing to remove unexpected C04 SCIM checkpoint PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c04_scim_checkpoint_exit_status"
}

trap cleanup_c04_scim_checkpoint_postgres EXIT
trap 'exit 130' HUP INT TERM

for c04_scim_checkpoint_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c04_scim_checkpoint_pg_bin/$c04_scim_checkpoint_binary" ]; then
    printf '%s\n' \
      "PostgreSQL 17 binary is missing: $c04_scim_checkpoint_binary" >&2
    exit 1
  fi
done

mkdir "$c04_scim_checkpoint_socket_dir"

"$c04_scim_checkpoint_pg_bin/initdb" \
  -D "$c04_scim_checkpoint_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c04_scim_checkpoint_pg_bin/pg_ctl" \
  -D "$c04_scim_checkpoint_data_dir" \
  -l "$c04_scim_checkpoint_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c04_scim_checkpoint_socket_dir' -p $c04_scim_checkpoint_port" \
  -t 30 \
  -w start >/dev/null
c04_scim_checkpoint_started=1

"$c04_scim_checkpoint_pg_bin/createdb" \
  -h "$c04_scim_checkpoint_socket_dir" \
  -p "$c04_scim_checkpoint_port" \
  -U "$c04_scim_checkpoint_user" \
  "$c04_scim_checkpoint_database"

unset C04_SCIM_CHECKPOINT_TEST_PGPASSWORD

C04_SCIM_CHECKPOINT_TEST_EPHEMERAL=1 \
C04_SCIM_CHECKPOINT_TEST_PGHOST="$c04_scim_checkpoint_socket_dir" \
C04_SCIM_CHECKPOINT_TEST_PGPORT="$c04_scim_checkpoint_port" \
C04_SCIM_CHECKPOINT_TEST_PGDATABASE="$c04_scim_checkpoint_database" \
C04_SCIM_CHECKPOINT_TEST_PGUSER="$c04_scim_checkpoint_user" \
node --test --test-concurrency=1 \
  tests/postgres-scim-checkpoint-contract.test.mjs \
  tests/integration/c04-scim-checkpoint-postgres.test.mjs
