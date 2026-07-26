import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const evidencePath =
  "implementation/p1/c06/c06-verification-evidence.v2.json";

async function read(path) {
  return readFile(new URL(path, root));
}

async function json(path) {
  return JSON.parse(await read(path));
}

function digest(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

async function sourceManifestSha256(refs) {
  const records = [];
  for (const { path } of [...refs].sort((a, b) =>
    a.path.localeCompare(b.path)
  )) {
    records.push(
      `${path}\0${createHash("sha256")
        .update(await read(path))
        .digest("hex")}\n`,
    );
  }
  return digest(records.join(""));
}

test("C06 P1 synthetic v2 evidence preserves v1 and binds the G1 delta", async () => {
  const evidence = await json(evidencePath);
  const base = await json(evidence.supersedes.path);

  assert.equal(evidence.schema_version, "2.0.0");
  assert.equal(evidence.work_package_id, "C06");
  assert.equal(evidence.evidence_ref, evidencePath);
  assert.equal(
    evidence.verified_source_commit,
    "b0bdb6b60d46f5702b8d0d680d0de93aba611e17",
  );
  assert.equal(evidence.implementation_status, "IMPLEMENTED");
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(
    digest(await read(evidence.supersedes.path)),
    evidence.supersedes.sha256,
  );
  assert.equal(base.work_package_id, "C06");
  assert.equal(
    evidence.source_artifact_catalog.count,
    base.artifacts.length,
  );
  assert.equal(
    await sourceManifestSha256(base.artifacts),
    evidence.source_artifact_catalog.current_manifest_sha256,
  );
  assert.equal(
    new Set(
      evidence.supplemental_artifacts.map(({ path }) => path),
    ).size,
    evidence.supplemental_artifacts.length,
  );
  for (const artifact of evidence.supplemental_artifacts) {
    assert.equal(digest(await read(artifact.path)), artifact.sha256);
  }
  assert.equal(
    evidence.verification_results.full_test_suite_at_g1_freeze,
    "863 PASS, 0 FAIL",
  );
  assert.equal(evidence.runtime_boundary.enterprise_connectors, "C0_DISABLED");
  assert.equal(evidence.runtime_boundary.enterprise_data, "NOT_PRESENT");
});
