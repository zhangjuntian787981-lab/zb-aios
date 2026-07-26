import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const rootUrl = new URL("../", import.meta.url);
const evidenceUrl = new URL(
  "../implementation/p1/c08/c08-verification-evidence.v1.json",
  import.meta.url,
);

test("C08 P1 synthetic verification evidence is intact", async () => {
  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));

  assert.equal(evidence.work_package_id, "C08");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(
    evidence.verified_source_commit,
    "9937a29d39f2f3eef6961af7f0d10d2fa8f8c816",
  );
  assert.equal(
    evidence.approved_g0_submission_sha256,
    "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07",
  );
  assert.equal(
    evidence.verification_results.full_test_suite,
    "354 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.c08_targeted_node_tests,
    "46 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.real_postgresql_state_core,
    "14 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.real_postgresql_runtime_roles,
    "1 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.frozen_replay_matrix_cases,
    47,
  );
  assert.equal(evidence.independent_review.reviewers, 2);
  assert.equal(evidence.independent_review.p0_findings, 0);
  assert.equal(evidence.independent_review.p1_findings, 0);
  assert.equal(evidence.independent_review.p2_findings, 0);
  assert.equal(evidence.artifacts.length, 25);
  assert.equal(
    new Set(evidence.artifacts.map(({ path }) => path)).size,
    evidence.artifacts.length,
  );
  assert.equal(evidence.dependency_evidence.length, 7);
  assert.equal(
    new Set(evidence.dependency_evidence.map(({ path }) => path)).size,
    evidence.dependency_evidence.length,
  );
  assert.equal(
    evidence.artifacts.some(({ path }) => path === evidence.evidence_ref),
    false,
  );

  for (const artifact of [
    ...evidence.artifacts,
    ...evidence.dependency_evidence,
  ]) {
    const content = await readFile(new URL(artifact.path, rootUrl));
    const actual = `sha256:${createHash("sha256")
      .update(content)
      .digest("hex")}`;
    assert.equal(actual, artifact.sha256, artifact.path);
  }

  const matrix = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c08/replay-matrix.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(matrix.implementationStatus, "IMPLEMENTED");
  assert.equal(matrix.verificationStatus, "VERIFIED");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(matrix.enterpriseConnectors, "C0_DISABLED");
  assert.equal(matrix.cases.length, 47);
  assert.equal(
    matrix.cases.every(
      ({ evidenceStatus }) =>
        evidenceStatus === "VERIFIED_P1_SYNTHETIC",
    ),
    true,
  );

  const api = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c08/aios-state-core.openapi.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(
    api["x-c08-boundary"].production_verification_status,
    "NOT_VERIFIED",
  );
  assert.equal(
    api["x-c08-boundary"].enterprise_integration_status,
    "P3_REQUIRED",
  );
  assert.equal(
    api["x-c08-boundary"].enterprise_connectors,
    "C0_DISABLED",
  );
});
