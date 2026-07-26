#!/bin/sh
set -eu

c07_pg_bin=${C07_PG_BIN:-/opt/homebrew/opt/postgresql@17/bin}
c07_pg_root=$(mktemp -d /tmp/c07-pg.XXXXXX)
c07_data_dir="$c07_pg_root/data"
c07_socket_dir="$c07_pg_root/socket"
c07_log_file="$c07_pg_root/postgres.log"
c07_port=$((51000 + ($$ % 4000)))
c07_database="c07_test_$$"
c07_user=$(id -un)
c07_started=0

cleanup_c07_postgres() {
  c07_exit_status=$?
  c07_can_remove=1
  trap - EXIT HUP INT TERM

  if [ "$c07_started" -eq 1 ]; then
    if ! "$c07_pg_bin/pg_ctl" \
      -D "$c07_data_dir" \
      -m immediate \
      -w stop >/dev/null 2>&1; then
      c07_can_remove=0
      c07_exit_status=1
      printf '%s\n' \
        "C07 PostgreSQL could not be stopped; preserving $c07_pg_root and $c07_log_file." >&2
    fi
  fi

  if [ "$c07_can_remove" -eq 1 ]; then
    case "$c07_pg_root" in
      /tmp/c07-pg.*) rm -rf -- "$c07_pg_root" ;;
      *)
        c07_exit_status=1
        printf '%s\n' "Refusing to remove unexpected C07 PostgreSQL path." >&2
        ;;
    esac
  fi

  exit "$c07_exit_status"
}

trap cleanup_c07_postgres EXIT
trap 'exit 130' HUP INT TERM

for c07_binary in initdb pg_ctl createdb; do
  if [ ! -x "$c07_pg_bin/$c07_binary" ]; then
    printf '%s\n' "PostgreSQL 17 binary is missing: $c07_binary" >&2
    exit 1
  fi
done

c07_extension_dir=$("$c07_pg_bin/pg_config" --sharedir)/extension
if [ ! -f "$c07_extension_dir/vector.control" ]; then
  printf '%s\n' "pgvector control file is missing for PostgreSQL 17." >&2
  exit 1
fi
c07_expected_control_sha=$(node -e \
  "const lock = require('./implementation/p1/c07/pgvector/pgvector-distribution.lock.json'); process.stdout.write(lock.measuredControlFile.sha256.slice(7));")
c07_actual_control_sha=$(shasum -a 256 \
  "$c07_extension_dir/vector.control" | awk '{print $1}')
if [ "$c07_actual_control_sha" != "$c07_expected_control_sha" ]; then
  printf '%s\n' "pgvector control file hash does not match the C07 lock." >&2
  exit 1
fi

mkdir "$c07_socket_dir"

"$c07_pg_bin/initdb" \
  -D "$c07_data_dir" \
  --encoding=UTF8 \
  --locale=C \
  --auth-local=trust \
  --auth-host=reject \
  --no-instructions >/dev/null

"$c07_pg_bin/pg_ctl" \
  -D "$c07_data_dir" \
  -l "$c07_log_file" \
  -o "-c listen_addresses='' -c unix_socket_directories='$c07_socket_dir' -p $c07_port" \
  -t 30 \
  -w start >/dev/null
c07_started=1

"$c07_pg_bin/createdb" \
  -h "$c07_socket_dir" \
  -p "$c07_port" \
  -U "$c07_user" \
  "$c07_database"

unset C07_TEST_PGPASSWORD

C07_TEST_EPHEMERAL=1 \
C07_TEST_PGHOST="$c07_socket_dir" \
C07_TEST_PGPORT="$c07_port" \
C07_TEST_PGDATABASE="$c07_database" \
C07_TEST_PGUSER="$c07_user" \
node --test --test-concurrency=1 tests/integration/c07-postgres.test.mjs
