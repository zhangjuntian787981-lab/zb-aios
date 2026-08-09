import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const rootUrl = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(rootUrl);
const evidenceUrl = new URL(
  "../implementation/p1/c07/c07-verification-evidence.v1.json",
  import.meta.url,
);
const verifiedSourceCommit = "b52ff7c5bd1e247745db48dad94b42d52daa888c";
const executableArtifactPaths = new Set([
  "scripts/run-c07-postgres-tests.sh",
  "scripts/run-c07-restore-postgres-tests.sh",
  "scripts/run-c07-roles-postgres-tests.sh",
  "scripts/run-c07-tests.sh",
]);

function git(arguments_, encoding = null) {
  try {
    return execFileSync("git", arguments_, {
      cwd: repositoryRoot,
      encoding,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch {
    throw new Error(`Git read failed: ${arguments_[0]}`);
  }
}

function assertSafeGitPath(path) {
  assert.equal(typeof path, "string", "Git artifact path must be a string");
  assert.notEqual(path, "", "Git artifact path must not be empty");
  assert.equal(path.startsWith("/"), false, "Git artifact path must be relative");
  assert.equal(path.startsWith(":"), false, "Git artifact path must be literal");
  assert.equal(
    /[\\\u0000-\u001f\u007f]/u.test(path),
    false,
    "Git artifact path contains an unsafe character",
  );
  assert.equal(
    path.split("/").every((segment) => segment !== "" && segment !== "." && segment !== ".."),
    true,
    "Git artifact path contains an unsafe segment",
  );
}

function assertVerifiedSourceCommit(commit) {
  assert.match(
    commit,
    /^[a-f0-9]{40}$/u,
    "verified_source_commit must be an exact 40-character commit",
  );
  assert.equal(commit, verifiedSourceCommit, "verified_source_commit mismatch");
  assert.equal(
    git(["cat-file", "-t", commit], "utf8").trim(),
    "commit",
    "verified_source_commit must identify a commit object",
  );
}

function readFrozenArtifact(commit, path) {
  assertSafeGitPath(path);
  const treeEntry = git(
    ["ls-tree", "-z", "-l", commit, "--", `:(literal)${path}`],
    "utf8",
  );
  const match = /^(100644|100755) blob [a-f0-9]{40,64} +([0-9]+)\t([^\0]+)\0$/u.exec(
    treeEntry,
  );
  assert.ok(match, `missing or ambiguous Git blob: ${commit}:${path}`);
  assert.equal(match[3], path, `Git tree path mismatch: ${path}`);

  const byteLength = Number(match[2]);
  assert.equal(Number.isSafeInteger(byteLength), true, `invalid Git blob size: ${path}`);
  const bytes = git(["cat-file", "blob", `${commit}:${path}`]);
  assert.ok(Buffer.isBuffer(bytes), `Git blob bytes unavailable: ${path}`);
  return { path: match[3], gitMode: match[1], byteLength, bytes };
}

function assertFrozenArtifactBinding(artifact, frozen) {
  assert.equal(frozen.path, artifact.path, `Git tree path mismatch: ${artifact.path}`);
  assert.equal(
    frozen.gitMode,
    executableArtifactPaths.has(artifact.path) ? "100755" : "100644",
    `Git mode mismatch: ${artifact.path}`,
  );
  assert.equal(
    frozen.byteLength,
    frozen.bytes.byteLength,
    `Git byteLength mismatch: ${artifact.path}`,
  );
  assert.equal(
    `sha256:${createHash("sha256").update(frozen.bytes).digest("hex")}`,
    artifact.sha256,
    `Git blob SHA-256 mismatch: ${artifact.path}`,
  );
}

test("C07 P1 synthetic verification evidence is intact", async () => {
  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));

  assert.equal(evidence.work_package_id, "C07");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(
    evidence.verified_source_commit,
    verifiedSourceCommit,
  );
  assertVerifiedSourceCommit(evidence.verified_source_commit);
  assert.equal(
    evidence.approved_g0_submission_sha256,
    "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07",
  );
  assert.equal(
    evidence.verification_results.full_test_suite,
    "307 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.c07_targeted_tests,
    "33 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.real_postgresql_isolation,
    "1 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.real_postgresql_runtime_roles,
    "1 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.real_postgresql_restore,
    "1 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.shared_object_lock_stress,
    "200 PASS, 0 FAIL",
  );
  assert.equal(evidence.independent_review.p0_findings, 0);
  assert.equal(evidence.independent_review.p1_findings, 0);
  assert.equal(evidence.independent_review.p2_findings, 1);
  assert.equal(evidence.artifacts.length, 22);
  assert.equal(
    new Set(evidence.artifacts.map(({ path }) => path)).size,
    evidence.artifacts.length,
  );
  assert.equal(evidence.dependency_evidence.length, 6);
  assert.equal(
    new Set(evidence.dependency_evidence.map(({ path }) => path)).size,
    evidence.dependency_evidence.length,
  );
  assert.equal(
    evidence.artifacts.some(({ path }) => path === evidence.evidence_ref),
    false,
  );

  const artifacts = [
    ...evidence.artifacts,
    ...evidence.dependency_evidence,
  ];
  for (const artifact of artifacts) {
    assertFrozenArtifactBinding(
      artifact,
      readFrozenArtifact(evidence.verified_source_commit, artifact.path),
    );
  }

  const referenceArtifact = artifacts[0];
  const referenceFrozen = readFrozenArtifact(
    evidence.verified_source_commit,
    referenceArtifact.path,
  );
  assert.throws(
    () => assertVerifiedSourceCommit("0".repeat(40)),
    /verified_source_commit mismatch/u,
  );
  assert.throws(
    () => git(["cat-file", "-t", "0".repeat(40)], "utf8"),
    /Git read failed/u,
  );
  assert.throws(
    () =>
      readFrozenArtifact(
        evidence.verified_source_commit,
        `${referenceArtifact.path}.missing`,
      ),
    /missing or ambiguous Git blob/u,
  );
  assert.throws(
    () =>
      assertFrozenArtifactBinding(referenceArtifact, {
        ...referenceFrozen,
        gitMode: referenceFrozen.gitMode === "100644" ? "100755" : "100644",
      }),
    /Git mode mismatch/u,
  );
  assert.throws(
    () =>
      assertFrozenArtifactBinding(referenceArtifact, {
        ...referenceFrozen,
        byteLength: referenceFrozen.byteLength + 1,
      }),
    /Git byteLength mismatch/u,
  );
  assert.throws(
    () =>
      assertFrozenArtifactBinding(
        { ...referenceArtifact, sha256: `sha256:${"0".repeat(64)}` },
        referenceFrozen,
      ),
    /Git blob SHA-256 mismatch/u,
  );

  const boundary = JSON.stringify({
    runtime: evidence.runtime_boundary,
    limitations: evidence.limitations,
  });
  for (const requiredBoundary of [
    "P1_SYNTHETIC_ONLY",
    "P3_REQUIRED",
    "C0_DISABLED",
    "NOT_VERIFIED",
    "LOCAL_FILE_ONLY",
    "PROCESS_LOCAL_LOCK_ONLY",
    "SAME_POSTMASTER_ONLY",
    "C02_C08_O01_O04_O05_PENDING",
    "capacity",
    "high_availability",
    "G1",
  ]) {
    assert.equal(boundary.includes(requiredBoundary), true);
  }
});
