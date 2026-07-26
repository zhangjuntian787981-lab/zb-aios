import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const rootUrl = new URL("../", import.meta.url);
const evidenceUrl = new URL(
  "../implementation/p1/c06/c06-verification-evidence.v1.json",
  import.meta.url,
);

test("C06 P1 synthetic verification evidence is intact", async () => {
  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));

  assert.equal(evidence.work_package_id, "C06");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(
    evidence.verified_source_commit,
    "5b0bb2eae5d81956a80484dc04595e5c2c875cec",
  );
  assert.equal(
    evidence.approved_g0_submission_sha256,
    "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07",
  );
  assert.equal(evidence.verification_results.full_test_suite, "273 PASS, 0 FAIL");
  assert.equal(
    evidence.verification_results.c06_targeted_tests,
    "70 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.real_openfga,
    "4 PASS, 0 FAIL",
  );
  assert.match(
    evidence.verification_results.real_postgresql_core,
    /^19 PASS, 0 FAIL/,
  );
  assert.equal(
    evidence.verification_results.real_postgresql_runtime_roles,
    "1 PASS, 0 FAIL",
  );
  assert.equal(evidence.independent_review.p0_findings, 0);
  assert.equal(evidence.independent_review.p1_findings, 0);
  assert.equal(evidence.artifacts.length, 33);
  assert.equal(
    new Set(evidence.artifacts.map(({ path }) => path)).size,
    evidence.artifacts.length,
  );
  assert.equal(evidence.dependency_evidence.length, 5);
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

  const boundary = JSON.stringify({
    runtime: evidence.runtime_boundary,
    limitations: evidence.limitations,
  });
  for (const requiredBoundary of [
    "P1_SYNTHETIC_ONLY",
    "P3_REQUIRED",
    "C0_DISABLED",
    "NOT_VERIFIED",
    "C01_C02_C11_C16_O01_PENDING",
    "capacity",
    "high_availability",
    "Manifest",
  ]) {
    assert.equal(boundary.includes(requiredBoundary), true);
  }
});
