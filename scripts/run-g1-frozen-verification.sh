#!/bin/sh
set -eu

g1_frozen_mode=${1:-}
case "$g1_frozen_mode" in
  dependencies)
    g1_frozen_runner="npm ci --ignore-scripts --no-audit --no-fund"
    ;;
  build) g1_frozen_runner="npm run build" ;;
  c06) g1_frozen_runner="scripts/run-g1-role-openfga-tests.sh" ;;
  c15) g1_frozen_runner="scripts/run-c15-tests.sh" ;;
  runtime) g1_frozen_runner="scripts/run-g1-postgres-runtime-tests.sh" ;;
  isolation) g1_frozen_runner="scripts/run-g1-persistent-matrix-tests.sh" ;;
  full) g1_frozen_runner="npm test" ;;
  lint) g1_frozen_runner="npm run lint" ;;
  *)
    printf '%s\n' \
      "Usage: $0 dependencies|build|c06|c15|runtime|isolation|full|lint" >&2
    exit 64
    ;;
esac

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

file_sha256() {
  g1_sha_output=$(shasum -a 256 "$1") || return 1
  g1_sha_value=${g1_sha_output%% *}
  case "$g1_sha_value" in
    ''|*[!0-9a-f]*) return 1 ;;
  esac
  [ "${#g1_sha_value}" -eq 64 ] || return 1
  printf '%s\n' "$g1_sha_value"
}

g1_frozen_dependency_tree_file=""
cleanup() {
  if [ -n "$g1_frozen_dependency_tree_file" ]; then
    rm -f -- "$g1_frozen_dependency_tree_file"
  fi
}
trap cleanup EXIT HUP INT TERM

dependency_tree_sha256() {
  : "${TMPDIR:?TMPDIR must name the bounded verification scratch root.}"
  case "$TMPDIR" in
    /*) ;;
    *) return 1 ;;
  esac
  [ -d "$TMPDIR" ] || return 1
  g1_frozen_dependency_tree_file=$(mktemp "${TMPDIR%/}/g1-dependency-tree.XXXXXX")
  if ! npm ls --all --json >"$g1_frozen_dependency_tree_file"; then
    return 1
  fi
  g1_dependency_sha=$(file_sha256 "$g1_frozen_dependency_tree_file") ||
    return 1
  rm -f -- "$g1_frozen_dependency_tree_file"
  g1_frozen_dependency_tree_file=""
  printf '%s\n' "$g1_dependency_sha"
}

if ! git diff --quiet || ! git diff --cached --quiet; then
  fail "Tracked worktree changes are not allowed."
fi

[ ! -e node_modules ] ||
  fail "node_modules must be absent so this run starts with a fresh install."
if [ -n "$(git status --porcelain --untracked-files=all --ignored)" ]; then
  fail "Untracked or ignored worktree content is not allowed at run start."
fi

g1_frozen_commit=$(git rev-parse HEAD)
g1_frozen_tree=$(git rev-parse 'HEAD^{tree}')
g1_frozen_lock_sha=$(file_sha256 package-lock.json) ||
  fail "Could not compute a valid package-lock.json SHA-256."
g1_frozen_run_id=$(
  node --input-type=module -e \
    'import { randomUUID } from "node:crypto"; process.stdout.write(randomUUID())'
)
g1_frozen_npm_version=$(npm --version)
g1_frozen_started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
case "$g1_frozen_mode" in
  dependencies|build|full|lint) g1_frozen_command="$g1_frozen_runner" ;;
  *) g1_frozen_command="sh $g1_frozen_runner" ;;
esac
g1_frozen_install_command="npm ci --ignore-scripts --no-audit --no-fund"

emit_record() {
  G1_FROZEN_PHASE="$1" \
  G1_FROZEN_RUN_ID="$g1_frozen_run_id" \
  G1_FROZEN_MODE="$g1_frozen_mode" \
  G1_FROZEN_COMMAND="$g1_frozen_command" \
  G1_FROZEN_INSTALL_COMMAND="$g1_frozen_install_command" \
  G1_FROZEN_COMMIT="$g1_frozen_commit" \
  G1_FROZEN_TREE="$g1_frozen_tree" \
  G1_FROZEN_LOCK_SHA="$g1_frozen_lock_sha" \
  G1_FROZEN_DEPENDENCY_TREE_SHA="${2:-}" \
  G1_FROZEN_NPM_VERSION="$g1_frozen_npm_version" \
  G1_FROZEN_RECORDED_AT="$3" \
  node --input-type=module -e '
    const phase = process.env.G1_FROZEN_PHASE;
    const dependencyInstalled = phase !== "start";
    const record = {
      schemaVersion: `g1-frozen-verification-${phase}.v1`,
      runId: process.env.G1_FROZEN_RUN_ID,
      mode: process.env.G1_FROZEN_MODE,
      verificationCommand: process.env.G1_FROZEN_COMMAND,
      dependencyInstallCommand: process.env.G1_FROZEN_INSTALL_COMMAND,
      candidateCommit: process.env.G1_FROZEN_COMMIT,
      candidateTree: process.env.G1_FROZEN_TREE,
      trackedWorktreeClean: true,
      nodeModulesPresentAtStart: false,
      freshDependencyInstallCompleted: dependencyInstalled,
      packageLockSha256: `sha256:${process.env.G1_FROZEN_LOCK_SHA}`,
      npmDependencyTreeSha256: dependencyInstalled
        ? `sha256:${process.env.G1_FROZEN_DEPENDENCY_TREE_SHA}`
        : null,
      nodeVersion: process.version,
      npmVersion: process.env.G1_FROZEN_NPM_VERSION,
      operatingSystem: process.platform,
      architecture: process.arch,
      recordedAt: process.env.G1_FROZEN_RECORDED_AT,
    };
    if (phase === "complete") {
      record.exitCode = 0;
    }
    console.log(JSON.stringify(record));
  '
}

emit_record start "" "$g1_frozen_started_at"

npm ci --ignore-scripts --no-audit --no-fund

g1_frozen_lock_after_install=$(file_sha256 package-lock.json) ||
  fail "Could not recompute package-lock.json SHA-256 after npm ci."
[ "$g1_frozen_lock_after_install" = "$g1_frozen_lock_sha" ] ||
  fail "package-lock.json changed during npm ci."
if ! git diff --quiet || ! git diff --cached --quiet; then
  fail "npm ci changed tracked worktree content."
fi
g1_frozen_dependency_tree_sha=$(dependency_tree_sha256) ||
  fail "Could not compute the installed dependency tree SHA-256."
g1_frozen_dependencies_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
emit_record dependencies-complete \
  "$g1_frozen_dependency_tree_sha" \
  "$g1_frozen_dependencies_at"

case "$g1_frozen_mode" in
  dependencies) : ;;
  build) npm run build ;;
  full) npm test ;;
  lint) npm run lint ;;
  *) sh "$g1_frozen_runner" ;;
esac

if ! git diff --quiet || ! git diff --cached --quiet; then
  fail "Verification command changed tracked worktree content."
fi
[ "$(git rev-parse HEAD)" = "$g1_frozen_commit" ] ||
  fail "Candidate commit changed during verification."
[ "$(git rev-parse 'HEAD^{tree}')" = "$g1_frozen_tree" ] ||
  fail "Candidate tree changed during verification."
g1_frozen_lock_after_command=$(file_sha256 package-lock.json) ||
  fail "Could not recompute package-lock.json SHA-256 after verification."
[ "$g1_frozen_lock_after_command" = "$g1_frozen_lock_sha" ] ||
  fail "package-lock.json changed during verification."
g1_frozen_dependency_tree_after_command=$(dependency_tree_sha256) ||
  fail "Could not recompute the installed dependency tree SHA-256."
[ "$g1_frozen_dependency_tree_after_command" = \
  "$g1_frozen_dependency_tree_sha" ] ||
  fail "Installed dependency tree changed during verification."

g1_frozen_completed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
emit_record complete \
  "$g1_frozen_dependency_tree_sha" \
  "$g1_frozen_completed_at"
