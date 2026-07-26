import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const sourceCommit = "a1f34e0cffbb75e6642bd8eb8b82c7c7246d2bbd";
const approvedG0 =
  "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07";

const modules = [
  {
    id: "C09",
    evidence: "implementation/p1/c09/c09-verification-evidence.v1.json",
    matrix: "implementation/p1/c09/memory-matrix.v1.json",
  },
  {
    id: "C11",
    evidence: "implementation/p1/c11/c11-verification-evidence.v1.json",
    matrix: "implementation/p1/c11/acceptance-matrix.v1.json",
  },
  {
    id: "C15",
    evidence: "implementation/p1/c15/c15-verification-evidence.v1.json",
    matrix:
      "implementation/p1/c15/human-decision-verification-matrix.v1.json",
  },
  {
    id: "C16",
    evidence: "implementation/p1/c16/c16-verification-evidence.v1.json",
    matrix: "implementation/p1/c16/verification-matrix.v1.json",
  },
  {
    id: "C18",
    evidence: "implementation/p1/c18/c18-verification-evidence.v1.json",
    matrix: "implementation/p1/c18/audit-verification-matrix.v1.json",
  },
];

async function json(path) {
  return JSON.parse(await readFile(new URL(path, root), "utf8"));
}

async function artifactManifestSha256(paths) {
  const chunks = [];
  for (const path of [...paths].sort()) {
    const content = await readFile(new URL(path, root));
    const fileSha256 = createHash("sha256").update(content).digest("hex");
    chunks.push(`${path}\0${fileSha256}\n`);
  }
  return `sha256:${createHash("sha256")
    .update(chunks.join(""))
    .digest("hex")}`;
}

test("late P1 module evidence is source-bound and Synthetic-only", async () => {
  for (const entry of modules) {
    const evidence = await json(entry.evidence);
    assert.equal(evidence.work_package_id, entry.id);
    assert.equal(evidence.evidence_ref, entry.evidence);
    assert.equal(evidence.verified_source_commit, sourceCommit);
    assert.equal(evidence.implementation_status, "IMPLEMENTED");
    assert.equal(evidence.verification_status, "VERIFIED");
    assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
    assert.equal(
      evidence.production_verification_status,
      "NOT_VERIFIED",
    );
    assert.equal(evidence.enterprise_integration_status, "P3_REQUIRED");
    assert.equal(evidence.enterprise_connectors, "C0_DISABLED");
    assert.equal(evidence.approved_g0_submission_sha256, approvedG0);
    assert.equal(evidence.verification_results.full_build, "PASS");
    assert.equal(evidence.verification_results.full_eslint, "PASS");
    assert.equal(
      evidence.verification_results.verified_source_test_suite,
      "652 PASS, 0 FAIL",
    );
    assert.equal(
      evidence.verification_results.full_test_suite_with_evidence,
      "653 PASS, 0 FAIL",
    );
    assert.equal(
      evidence.source_artifacts.algorithm,
      "SHA256_UTF8_SORTED_PATH_NUL_FILE_SHA256_HEX_LF",
    );
    assert.equal(
      evidence.source_artifacts.paths.length,
      evidence.source_artifacts.count,
    );
    assert.equal(
      new Set(evidence.source_artifacts.paths).size,
      evidence.source_artifacts.count,
    );
    assert.equal(
      evidence.source_artifacts.paths.includes(entry.evidence),
      false,
    );
    assert.equal(
      await artifactManifestSha256(evidence.source_artifacts.paths),
      evidence.source_artifacts.manifest_sha256,
    );
    for (const dependency of evidence.dependency_evidence) {
      const content = await readFile(new URL(dependency.path, root));
      const actual = `sha256:${createHash("sha256")
        .update(content)
        .digest("hex")}`;
      assert.equal(actual, dependency.sha256, dependency.path);
    }
    const matrix = await json(entry.matrix);
    assert.equal(matrix.implementationStatus, "IMPLEMENTED");
    assert.equal(matrix.verificationStatus, "VERIFIED");
    assert.equal(
      matrix.productionVerificationStatus,
      "NOT_VERIFIED",
    );
  }
});
