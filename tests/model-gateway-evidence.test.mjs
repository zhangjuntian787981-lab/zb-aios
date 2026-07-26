import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const evidenceUrl = new URL(
  "../implementation/p1/c14/c14-verification-evidence.v1.json",
  import.meta.url,
);

test("C14 P1 Synthetic evidence and referenced files are intact", async () => {
  const evidence = JSON.parse(await readFile(evidenceUrl, "utf8"));
  assert.equal(evidence.work_package_id, "C14");
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(
    evidence.verified_source_commit,
    "17f90947a2be376d62c1ced722a157bb8934df69",
  );
  assert.equal(evidence.verification_results.c14_targeted_node_tests, "32 PASS, 0 FAIL");
  assert.equal(evidence.verification_results.real_postgresql_tests, "7 PASS, 0 FAIL");
  assert.equal(evidence.verification_results.frozen_routing_matrix_cases, 34);
  assert.equal(evidence.verification_results.source_artifacts, 18);
  assert.equal(evidence.artifacts.length, 18);
  assert.equal(
    new Set(evidence.artifacts.map(({ path }) => path)).size,
    evidence.artifacts.length,
  );
  assert.equal(
    evidence.artifacts.some(({ path }) => path === evidence.evidence_ref),
    false,
  );

  for (const artifact of [
    ...evidence.artifacts,
    ...evidence.dependency_evidence,
  ]) {
    const content = await readFile(new URL(artifact.path, root));
    const actual = `sha256:${createHash("sha256")
      .update(content)
      .digest("hex")}`;
    assert.equal(actual, artifact.sha256, artifact.path);
  }
});
