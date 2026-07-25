import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const rootUrl = new URL("../", import.meta.url);
const evidenceUrl = new URL(
  "../implementation/p1/c05/c05-verification-evidence.v1.json",
  import.meta.url,
);

test("C05 P1 synthetic verification evidence is intact", async () => {
  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));

  assert.equal(evidence.work_package_id, "C05");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(
    evidence.verified_source_commit,
    "e7cc6dbc11274146079612f0fe0bf32095f8f5ae",
  );
  assert.equal(
    evidence.approved_g0_submission_sha256,
    "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07",
  );
  assert.equal(evidence.verification_results.full_test_suite, "202 PASS, 0 FAIL");
  assert.equal(
    evidence.verification_results.c05_targeted_tests,
    "55 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.real_postgresql_core,
    "13 PASS, 0 FAIL",
  );
  assert.equal(
    evidence.verification_results.real_postgresql_runtime_roles,
    "1 PASS, 0 FAIL",
  );
  assert.equal(evidence.artifacts.length, 16);
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
    "P3_REQUIRED",
    "C0_DISABLED",
    "NOT_EVALUATED",
    "C06",
    "C18",
    "pagination",
    "capacity",
  ]) {
    assert.equal(boundary.includes(requiredBoundary), true);
  }
});
