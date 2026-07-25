#!/bin/sh
set -eu
set +x

c04_repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
c04_lock_file="$c04_repo_root/implementation/p1/c04/keycloak/keycloak-distribution.lock.json"
c04_java_home=${C04_KEYCLOAK_JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}
c04_cache_root=${C04_KEYCLOAK_CACHE_ROOT:-/tmp/c04-keycloak-cache}
c04_runtime_root=$(mktemp -d /tmp/c04-keycloak.XXXXXX)
c04_download_file="$c04_runtime_root/keycloak-download.tar.gz"
c04_cert_file="$c04_runtime_root/idp-cert.pem"
c04_key_file="$c04_runtime_root/idp-key.pem"
c04_log_file="$c04_runtime_root/keycloak.log"
c04_hostname="idp.c04-synthetic.example"
c04_started=0
c04_keycloak_pid=""

cleanup_c04_keycloak() {
  c04_exit_status=$?
  trap - EXIT HUP INT TERM

  if [ "$c04_started" -eq 1 ] && [ -n "$c04_keycloak_pid" ]; then
    if kill -0 "$c04_keycloak_pid" >/dev/null 2>&1; then
      kill -TERM "$c04_keycloak_pid" >/dev/null 2>&1 || true
      c04_stop_attempt=0
      while kill -0 "$c04_keycloak_pid" >/dev/null 2>&1; do
        c04_stop_attempt=$((c04_stop_attempt + 1))
        if [ "$c04_stop_attempt" -ge 40 ]; then
          kill -KILL "$c04_keycloak_pid" >/dev/null 2>&1 || true
          break
        fi
        sleep 0.25
      done
    fi
    wait "$c04_keycloak_pid" >/dev/null 2>&1 || true
  fi

  unset C04_KC_ADMIN_PASSWORD C04_KC_CLIENT_SECRET C04_KC_USER_PASSWORD
  case "$c04_runtime_root" in
    /tmp/c04-keycloak.*) rm -rf -- "$c04_runtime_root" ;;
    *)
      c04_exit_status=1
      printf '%s\n' "Refusing to remove unexpected C04 Keycloak path." >&2
      ;;
  esac
  exit "$c04_exit_status"
}

trap cleanup_c04_keycloak EXIT
trap 'exit 130' HUP INT TERM

for c04_binary in node curl shasum tar openssl lsof; do
  if ! command -v "$c04_binary" >/dev/null 2>&1; then
    printf '%s\n' "C04 Keycloak prerequisite is missing: $c04_binary" >&2
    exit 1
  fi
done
if [ ! -x "$c04_java_home/bin/java" ]; then
  printf '%s\n' "OpenJDK 21 is missing at the configured C04 path." >&2
  exit 1
fi
if [ ! -f "$c04_lock_file" ]; then
  printf '%s\n' "C04 Keycloak distribution lock is missing." >&2
  exit 1
fi

c04_version=$(node -e '
  const lock = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
  process.stdout.write(String(lock.version ?? ""));
' "$c04_lock_file")
c04_artifact_url=$(node -e '
  const lock = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
  process.stdout.write(String(lock.artifactUrl ?? ""));
' "$c04_lock_file")
c04_expected_sha=$(node -e '
  const lock = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
  process.stdout.write(String(lock.sha256 ?? ""));
' "$c04_lock_file")
c04_required_java=$(node -e '
  const lock = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
  process.stdout.write(String(lock.requiredJavaMajor ?? ""));
' "$c04_lock_file")

if [ "$c04_version" != "26.7.0" ]; then
  printf '%s\n' "Unexpected C04 Keycloak version lock." >&2
  exit 1
fi
if [ "$c04_artifact_url" != "https://github.com/keycloak/keycloak/releases/download/26.7.0/keycloak-26.7.0.tar.gz" ]; then
  printf '%s\n' "Unexpected C04 Keycloak artifact origin." >&2
  exit 1
fi
case "$c04_expected_sha" in
  *[!0-9a-f]*)
    printf '%s\n' "Invalid C04 Keycloak SHA-256 lock." >&2
    exit 1
    ;;
esac
if [ "${#c04_expected_sha}" -ne 64 ]; then
  printf '%s\n' "Invalid C04 Keycloak SHA-256 lock." >&2
  exit 1
fi
if [ "$c04_required_java" != "21" ]; then
  printf '%s\n' "Unexpected C04 Keycloak Java lock." >&2
  exit 1
fi

c04_cache_file="$c04_cache_root/keycloak-$c04_version.tar.gz"
c04_cache_valid=0
if [ -f "$c04_cache_file" ]; then
  c04_cache_sha=$(shasum -a 256 "$c04_cache_file" | awk '{print $1}')
  if [ "$c04_cache_sha" = "$c04_expected_sha" ]; then
    c04_cache_valid=1
  fi
fi
if [ "$c04_cache_valid" -ne 1 ]; then
  curl \
    --proto '=https' \
    --tlsv1.2 \
    --fail \
    --location \
    --retry 3 \
    --silent \
    --show-error \
    --output "$c04_download_file" \
    "$c04_artifact_url"
  c04_download_sha=$(shasum -a 256 "$c04_download_file" | awk '{print $1}')
  if [ "$c04_download_sha" != "$c04_expected_sha" ]; then
    printf '%s\n' "Downloaded C04 Keycloak artifact failed SHA-256 verification." >&2
    exit 1
  fi
  mkdir -p -- "$c04_cache_root"
  chmod 700 "$c04_cache_root"
  install -m 600 "$c04_download_file" "$c04_cache_file"
fi

c04_verified_sha=$(shasum -a 256 "$c04_cache_file" | awk '{print $1}')
if [ "$c04_verified_sha" != "$c04_expected_sha" ]; then
  printf '%s\n' "Cached C04 Keycloak artifact failed SHA-256 verification." >&2
  exit 1
fi

tar -xzf "$c04_cache_file" -C "$c04_runtime_root"
c04_keycloak_home="$c04_runtime_root/keycloak-$c04_version"
if [ ! -x "$c04_keycloak_home/bin/kc.sh" ]; then
  printf '%s\n' "Extracted C04 Keycloak launcher is missing." >&2
  exit 1
fi
if [ "$(sed -n '1p' "$c04_keycloak_home/version.txt")" != "Keycloak - Version $c04_version" ]; then
  printf '%s\n' "Extracted C04 Keycloak version does not match the lock." >&2
  exit 1
fi

c04_java_version=$("$c04_java_home/bin/java" -version 2>&1 | sed -n '1s/.*version "\([0-9][0-9]*\).*/\1/p')
if [ "$c04_java_version" != "$c04_required_java" ]; then
  printf '%s\n' "C04 Keycloak requires the locked Java major version." >&2
  exit 1
fi

umask 077
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -days 1 \
  -nodes \
  -keyout "$c04_key_file" \
  -out "$c04_cert_file" \
  -subj "/CN=$c04_hostname" \
  -addext "subjectAltName=DNS:$c04_hostname,IP:127.0.0.1" \
  >/dev/null 2>&1

c04_port=$(node -e '
  const net = require("node:net");
  const server = net.createServer();
  server.unref();
  server.listen(0, "127.0.0.1", () => {
    process.stdout.write(String(server.address().port));
    server.close();
  });
')
c04_origin="https://$c04_hostname:$c04_port"
C04_KC_ADMIN_PASSWORD=$(openssl rand -hex 32)
C04_KC_CLIENT_SECRET=$(openssl rand -hex 32)
C04_KC_USER_PASSWORD=$(openssl rand -hex 32)
c04_admin_username="c04-bootstrap-admin"
c04_test_username="synthetic-operator"

KC_BOOTSTRAP_ADMIN_USERNAME="$c04_admin_username" \
KC_BOOTSTRAP_ADMIN_PASSWORD="$C04_KC_ADMIN_PASSWORD" \
JAVA_HOME="$c04_java_home" \
PATH="$c04_java_home/bin:$PATH" \
"$c04_keycloak_home/bin/kc.sh" start \
  --db=dev-file \
  --cache=local \
  --http-enabled=false \
  --http-host=127.0.0.1 \
  --https-port="$c04_port" \
  --https-certificate-file="$c04_cert_file" \
  --https-certificate-key-file="$c04_key_file" \
  --hostname="$c04_origin" \
  --hostname-strict=true \
  >"$c04_log_file" 2>&1 &
c04_keycloak_pid=$!
c04_started=1

c04_ready=0
c04_start_attempt=0
while [ "$c04_start_attempt" -lt 180 ]; do
  c04_start_attempt=$((c04_start_attempt + 1))
  if ! kill -0 "$c04_keycloak_pid" >/dev/null 2>&1; then
    printf '%s\n' "C04 Keycloak exited before becoming ready." >&2
    exit 1
  fi
  if curl \
    --silent \
    --fail \
    --connect-timeout 1 \
    --max-time 2 \
    --cacert "$c04_cert_file" \
    --resolve "$c04_hostname:$c04_port:127.0.0.1" \
    "$c04_origin/realms/master/.well-known/openid-configuration" \
    >/dev/null 2>&1; then
    c04_ready=1
    break
  fi
  sleep 0.5
done
if [ "$c04_ready" -ne 1 ]; then
  printf '%s\n' "C04 Keycloak did not become ready within 90 seconds." >&2
  exit 1
fi

c04_listeners=$(lsof \
  -nP \
  -a \
  -p "$c04_keycloak_pid" \
  -iTCP \
  -sTCP:LISTEN \
  -Fn 2>/dev/null | sed -n 's/^n//p')
if ! printf '%s\n' "$c04_listeners" | grep -Fx "127.0.0.1:$c04_port" >/dev/null; then
  printf '%s\n' \
    "C04 Keycloak did not expose the expected loopback HTTPS listener." >&2
  exit 1
fi
if printf '%s\n' "$c04_listeners" | grep -Ev '^127\.0\.0\.1:[0-9]+$' >/dev/null; then
  printf '%s\n' \
    "C04 Keycloak exposed a non-loopback listener." >&2
  exit 1
fi

printf '%s\n' \
  "C04 Keycloak $c04_version artifact SHA-256 verified: $c04_verified_sha"
printf '%s\n' "C04 Keycloak listeners verified as IPv4 loopback only."

cd "$c04_repo_root"
C04_KEYCLOAK_EPHEMERAL=1 \
C04_KC_ORIGIN="$c04_origin" \
C04_KC_HOSTNAME="$c04_hostname" \
C04_KC_CA_FILE="$c04_cert_file" \
C04_KC_ADMIN_USERNAME="$c04_admin_username" \
C04_KC_ADMIN_PASSWORD="$C04_KC_ADMIN_PASSWORD" \
C04_KC_CLIENT_SECRET="$C04_KC_CLIENT_SECRET" \
C04_KC_TEST_USERNAME="$c04_test_username" \
C04_KC_USER_PASSWORD="$C04_KC_USER_PASSWORD" \
node --test --test-concurrency=1 tests/integration/c04-keycloak-oidc.test.mjs
