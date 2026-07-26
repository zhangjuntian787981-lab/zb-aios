#!/bin/sh
set -eu

c06_version="1.18.1"
c06_expected_sha256="d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94"
c06_asset="openfga_${c06_version}_darwin_arm64.tar.gz"
c06_url="https://github.com/openfga/openfga/releases/download/v${c06_version}/${c06_asset}"
c06_root=$(mktemp -d /tmp/c06-openfga.XXXXXX)
c06_archive="$c06_root/$c06_asset"
c06_log="$c06_root/openfga.log"
c06_http_port=$((41000 + ($$ % 4000)))
c06_grpc_port=$((45000 + ($$ % 4000)))
c06_unreachable_port=$((49000 + ($$ % 4000)))
c06_pid=""

cleanup_c06_openfga() {
  c06_exit_status=$?
  trap - EXIT HUP INT TERM

  if [ -n "$c06_pid" ]; then
    kill "$c06_pid" >/dev/null 2>&1 || true
    wait "$c06_pid" >/dev/null 2>&1 || true
  fi

  case "$c06_root" in
    /tmp/c06-openfga.*) rm -rf -- "$c06_root" ;;
    *)
      c06_exit_status=1
      printf '%s\n' "Refusing to remove unexpected C06 OpenFGA path." >&2
      ;;
  esac

  exit "$c06_exit_status"
}

trap cleanup_c06_openfga EXIT
trap 'exit 130' HUP INT TERM

if [ "$(uname -s)" != "Darwin" ] || [ "$(uname -m)" != "arm64" ]; then
  printf '%s\n' "C06 lock supports only Darwin arm64." >&2
  exit 1
fi

curl \
  --proto '=https' \
  --tlsv1.2 \
  --fail \
  --location \
  --retry 3 \
  --silent \
  --show-error \
  "$c06_url" \
  --output "$c06_archive"

printf '%s  %s\n' "$c06_expected_sha256" "$c06_archive" |
  shasum -a 256 --check >/dev/null

tar -xzf "$c06_archive" -C "$c06_root"
if [ ! -x "$c06_root/openfga" ]; then
  printf '%s\n' "The locked OpenFGA archive did not contain an executable." >&2
  exit 1
fi

"$c06_root/openfga" run \
  --datastore-engine memory \
  --http-addr "127.0.0.1:$c06_http_port" \
  --grpc-addr "127.0.0.1:$c06_grpc_port" \
  --playground-enabled=false \
  >"$c06_log" 2>&1 &
c06_pid=$!

c06_ready=0
c06_attempt=0
while [ "$c06_attempt" -lt 100 ]; do
  if curl --fail --silent \
    "http://127.0.0.1:$c06_http_port/healthz" >/dev/null 2>&1; then
    c06_ready=1
    break
  fi
  if ! kill -0 "$c06_pid" >/dev/null 2>&1; then
    break
  fi
  c06_attempt=$((c06_attempt + 1))
  sleep 0.1
done

if [ "$c06_ready" -ne 1 ]; then
  printf '%s\n' "OpenFGA did not become ready. Log: $c06_log" >&2
  exit 1
fi

C06_OPENFGA_EPHEMERAL=1 \
C06_OPENFGA_BASE_URL="http://127.0.0.1:$c06_http_port" \
C06_OPENFGA_UNREACHABLE_BASE_URL="http://127.0.0.1:$c06_unreachable_port" \
node --test --test-concurrency=1 tests/integration/c06-openfga.test.mjs
