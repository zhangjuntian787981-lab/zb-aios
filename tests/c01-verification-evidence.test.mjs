import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(root);
const evidencePath =
  "implementation/p1/c01/c01-verification-evidence.v1.json";

async function read(path) {
  return readFile(new URL(path, root));
}

async function json(path) {
  return JSON.parse(await read(path));
}

function sourceAtCommit(commit, path) {
  return execFileSync("git", ["show", `${commit}:${path}`], {
    cwd: repositoryRoot,
  });
}

function sourceManifestSha256(paths, commit) {
  const chunks = [];
  for (const path of [...paths].sort()) {
    const fileSha256 = createHash("sha256")
      .update(sourceAtCommit(commit, path))
      .digest("hex");
    chunks.push(`${path}\0${fileSha256}\n`);
  }
  return `sha256:${createHash("sha256")
    .update(chunks.join(""))
    .digest("hex")}`;
}

test("C01 verification evidence is source-bound and Synthetic-only", async () => {
  const evidence = await json(evidencePath);
  assert.equal(evidence.work_package_id, "C01");
  assert.equal(evidence.evidence_ref, evidencePath);
  assert.equal(
    evidence.verified_source_commit,
    "de8e025813f4e6c8e759837107f5198b65767185",
  );
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(evidence.enterprise_integration_status, "P3_REQUIRED");
  assert.equal(evidence.enterprise_connectors, "C0_DISABLED");
  assert.equal(evidence.review.p0_findings, 0);
  assert.equal(evidence.review.p1_findings, 0);
  assert.equal(evidence.review.p2_remaining, 0);
  assert.equal(evidence.source_artifacts.count, 15);
  assert.equal(
    evidence.source_artifacts.paths.includes(evidencePath),
    false,
  );
  assert.equal(
    sourceManifestSha256(
      evidence.source_artifacts.paths,
      evidence.verified_source_commit,
    ),
    evidence.source_artifacts.manifest_sha256,
  );
  for (const dependency of evidence.dependency_evidence) {
    assert.equal(
      `sha256:${createHash("sha256")
        .update(
          sourceAtCommit(
            evidence.verified_source_commit,
            dependency.path,
          ),
        )
        .digest("hex")}`,
      dependency.sha256,
      dependency.path,
    );
  }
  const matrix = await json(
    "implementation/p1/c01/verification-matrix.v1.json",
  );
  assert.equal(matrix.implementationStatus, "IMPLEMENTED");
  assert.equal(matrix.verificationStatus, "VERIFIED");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.deepEqual(matrix.openP1Items, []);
});
