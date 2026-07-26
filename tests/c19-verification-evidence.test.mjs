import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const evidencePath =
  "implementation/p1/c19/c19-verification-evidence.v2.json";

async function read(path) {
  return readFile(new URL(path, root));
}

async function json(path) {
  return JSON.parse(await read(path));
}

function digest(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

async function sourceManifestSha256(paths) {
  const records = [];
  for (const path of [...paths].sort()) {
    records.push(
      `${path}\0${createHash("sha256")
        .update(await read(path))
        .digest("hex")}\n`,
    );
  }
  return digest(records.join(""));
}

test("C19 v2 evidence preserves v1 and binds the current Synthetic source", async () => {
  const evidence = await json(evidencePath);
  const base = await json(evidence.supersedes.path);

  assert.equal(evidence.schema_version, "2.0.0");
  assert.equal(evidence.work_package_id, "C19");
  assert.equal(evidence.evidence_ref, evidencePath);
  assert.equal(
    evidence.verified_source_commit,
    "b0bdb6b60d46f5702b8d0d680d0de93aba611e17",
  );
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(evidence.enterprise_integration_status, "P3_REQUIRED");
  assert.equal(evidence.enterprise_connectors, "C0_DISABLED");
  assert.equal(
    digest(await read(evidence.supersedes.path)),
    evidence.supersedes.sha256,
  );
  assert.equal(
    evidence.source_artifact_catalog.count,
    base.source_artifacts.paths.length,
  );
  assert.equal(
    await sourceManifestSha256(base.source_artifacts.paths),
    evidence.source_artifact_catalog.current_manifest_sha256,
  );
  assert.equal(
    evidence.verification_results.full_test_suite_at_g1_freeze,
    "863 PASS, 0 FAIL",
  );
  const matrix = await json(
    "implementation/p1/c19/verification-matrix.v1.json",
  );
  assert.equal(matrix.implementationStatus, "IMPLEMENTED");
  assert.equal(matrix.verificationStatus, "VERIFIED");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.deepEqual(matrix.openP1Items, []);
});
