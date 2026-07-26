import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const rootUrl = new URL("../", import.meta.url);
const evidenceUrl = new URL(
  "../implementation/p1/c07/c07-verification-evidence.v1.json",
  import.meta.url,
);

test("C07 P1 synthetic verification evidence is intact", async () => {
  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));

  assert.equal(evidence.work_package_id, "C07");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(
    evidence.verified_source_commit,
    "b52ff7c5bd1e247745db48dad94b42d52daa888c",
  );
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
