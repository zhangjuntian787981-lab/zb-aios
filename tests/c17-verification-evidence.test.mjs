import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(root);
const evidencePath =
  "implementation/p1/c17/c17-verification-evidence.v1.json";

async function read(path) {
  return readFile(new URL(path, root));
}

async function json(path) {
  return JSON.parse(await read(path));
}

function readAtCommit(commit, path) {
  return execFileSync("git", ["show", `${commit}:${path}`], {
    cwd: repositoryRoot,
  });
}

function sourceManifestSha256(commit, paths) {
  const chunks = [];
  for (const path of [...paths].sort()) {
    const fileSha256 = createHash("sha256")
      .update(readAtCommit(commit, path))
      .digest("hex");
    chunks.push(`${path}\0${fileSha256}\n`);
  }
  return `sha256:${createHash("sha256")
    .update(chunks.join(""))
    .digest("hex")}`;
}

test("C17 verification evidence is source-bound and Synthetic-only", async () => {
  const evidence = await json(evidencePath);
  assert.equal(evidence.work_package_id, "C17");
  assert.equal(evidence.evidence_ref, evidencePath);
  assert.equal(
    evidence.verified_source_commit,
    "4204d28844b8474528778891fda997a80c37f969",
  );
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(evidence.enterprise_integration_status, "P3_REQUIRED");
  assert.equal(evidence.enterprise_connectors, "C0_DISABLED");
  assert.equal(evidence.review.p0_findings, 0);
  assert.equal(evidence.review.p1_findings, 0);
  assert.equal(evidence.review.p2_findings, 0);
  assert.equal(evidence.source_artifacts.count, 13);
  assert.equal(
    evidence.source_artifacts.paths.includes(evidencePath),
    false,
  );
  assert.equal(
    sourceManifestSha256(
      evidence.verified_source_commit,
      evidence.source_artifacts.paths,
    ),
    evidence.source_artifacts.manifest_sha256,
  );
  execFileSync(
    "git",
    [
      "merge-base",
      "--is-ancestor",
      evidence.verified_source_commit,
      "HEAD",
    ],
    { cwd: repositoryRoot },
  );
  for (const dependency of evidence.dependency_evidence) {
    assert.equal(
      `sha256:${createHash("sha256")
        .update(
          readAtCommit(
            evidence.verified_source_commit,
            dependency.path,
          ),
        )
        .digest("hex")}`,
      dependency.sha256,
      dependency.path,
    );
  }
  const matrix = JSON.parse(
    readAtCommit(
      evidence.verified_source_commit,
      "implementation/p1/c17/verification-matrix.v1.json",
    ),
  );
  assert.equal(matrix.implementationStatus, "IMPLEMENTED");
  assert.equal(matrix.verificationStatus, "VERIFIED");
  assert.deepEqual(matrix.openP1Items, []);
});
