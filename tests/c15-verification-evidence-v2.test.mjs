import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = new URL("../", import.meta.url);
const repoPath = fileURLToPath(root);
const evidencePath =
  "implementation/p1/c15/c15-verification-evidence.v2.json";
const sourceCommit =
  "6a23e93ed37eabec1201ff3a7bb00a0d9231fc49";

async function read(path) {
  return readFile(new URL(path, root));
}

async function json(path) {
  return JSON.parse(await read(path));
}

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function source(path) {
  return execFileSync(
    "git",
    ["-C", repoPath, "show", `${sourceCommit}:${path}`],
    { maxBuffer: 10 * 1024 * 1024 },
  );
}

function sourceManifest(paths) {
  return sha256(
    [...paths]
      .sort()
      .map((path) => `${path}\0${sha256(source(path)).slice(7)}\n`)
      .join(""),
  );
}

async function assertRef(ref, { atSource = false } = {}) {
  const content = atSource ? source(ref.path) : await read(ref.path);
  assert.equal(sha256(content), ref.sha256, ref.path);
}

test("C15 v2 evidence binds atomic memory and transactional PostgreSQL paths", async () => {
  const evidence = await json(evidencePath);
  assert.deepEqual(Object.keys(evidence), [
    "schema_version",
    "work_package_id",
    "evidence_ref",
    "recorded_at",
    "verified_source_commit",
    "implementation_status",
    "verification_status",
    "verification_scope",
    "production_verification_status",
    "enterprise_integration_status",
    "enterprise_connectors",
    "approved_g0_submission_sha256",
    "supersedes",
    "source_artifact_catalog",
    "supplemental_artifacts",
    "run_receipt",
    "independent_reviews",
    "verification_results",
    "verified_assertions",
    "runtime_boundary",
    "limitations",
  ]);
  assert.equal(evidence.work_package_id, "C15");
  assert.equal(evidence.evidence_ref, evidencePath);
  assert.equal(evidence.verified_source_commit, sourceCommit);
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(evidence.enterprise_connectors, "C0_DISABLED");

  await assertRef(evidence.supersedes);
  const base = await json(evidence.source_artifact_catalog.path);
  assert.equal(
    sourceManifest(base.source_artifacts.paths),
    evidence.source_artifact_catalog.current_manifest_sha256,
  );
  for (const ref of evidence.supplemental_artifacts) {
    await assertRef(ref, { atSource: true });
  }

  await assertRef(evidence.run_receipt);
  const receipt = await json(evidence.run_receipt.path);
  assert.equal(receipt.candidate.commit, sourceCommit);
  for (const mode of evidence.run_receipt.required_modes) {
    assert.equal(
      receipt.runs.find((item) => item.mode === mode).exitCode,
      0,
    );
  }

  assert.equal(evidence.independent_reviews.length, 2);
  for (const ref of evidence.independent_reviews) {
    await assertRef(ref);
    const review = await json(ref.path);
    assert.equal(review.workPackageId, "C15");
    assert.equal(review.reviewedSourceCommit, sourceCommit);
    assert.equal(review.severityCounts.p0, 0);
    assert.equal(review.severityCounts.p1, 0);
    assert.equal(
      sourceManifest(review.reviewedPathsManifest.paths),
      review.reviewedPathsManifest.sha256,
    );
  }

  assert.deepEqual(evidence.verification_results, {
    build: "PASS",
    eslint: "PASS",
    targeted_node: "46 PASS, 0 FAIL",
    real_postgresql: "33 PASS, 0 FAIL",
    fresh_cluster_restore: "1 PASS, 0 FAIL",
    postgresql_version: "17.10",
  });
  assert.equal(evidence.runtime_boundary.external_effect_count, 0);
  assert.equal(evidence.runtime_boundary.enterprise_data, "NOT_PRESENT");
});
