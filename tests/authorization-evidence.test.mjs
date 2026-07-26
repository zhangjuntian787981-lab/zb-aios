import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = new URL("../", import.meta.url);
const repoPath = fileURLToPath(root);
const evidencePath =
  "implementation/p1/c06/c06-verification-evidence.v3.json";
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

test("C06 v3 evidence proves orthogonal wrong-user and wrong-role isolation", async () => {
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
    "independent_review",
    "verification_results",
    "orthogonal_negative_cases",
    "runtime_boundary",
    "limitations",
  ]);
  assert.equal(evidence.work_package_id, "C06");
  assert.equal(evidence.evidence_ref, evidencePath);
  assert.equal(evidence.verified_source_commit, sourceCommit);
  assert.equal(evidence.verification_status, "VERIFIED");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(evidence.enterprise_connectors, "C0_DISABLED");

  await assertRef(evidence.supersedes);
  const base = await json(evidence.source_artifact_catalog.path);
  const basePaths = base.artifacts.map(({ path }) => path);
  assert.equal(basePaths.length, evidence.source_artifact_catalog.count);
  assert.equal(
    sourceManifest(basePaths),
    evidence.source_artifact_catalog.current_manifest_sha256,
  );
  for (const ref of evidence.supplemental_artifacts) {
    await assertRef(ref, { atSource: true });
  }

  await assertRef(evidence.run_receipt);
  const receipt = await json(evidence.run_receipt.path);
  assert.equal(receipt.candidate.commit, sourceCommit);
  for (const mode of evidence.run_receipt.required_modes) {
    const run = receipt.runs.find((item) => item.mode === mode);
    assert.equal(run.exitCode, 0);
  }

  await assertRef(evidence.independent_review);
  const review = await json(evidence.independent_review.path);
  assert.equal(review.workPackageId, "C06");
  assert.equal(review.reviewedSourceCommit, sourceCommit);
  assert.equal(review.severityCounts.p0, 0);
  assert.equal(review.severityCounts.p1, 0);
  assert.equal(
    sourceManifest(review.reviewedPathsManifest.paths),
    review.reviewedPathsManifest.sha256,
  );

  assert.deepEqual(evidence.verification_results, {
    unit: "6 PASS, 0 FAIL",
    real_openfga: "1 PASS, 0 FAIL",
    persistent_matrix: "1 PASS, 0 FAIL",
    case_count: 288,
    allow_count: 72,
    deny_count: 216,
    negative_backend_touch_count: 0,
    observed_leak_count: 0,
    wrong_attribution_count: 0,
  });
  assert.deepEqual(evidence.orthogonal_negative_cases, {
    wrong_user_count: 72,
    wrong_user_semantics:
      "REQUIRED_ROLE_MATCHES_AND_OWNER_PRINCIPAL_DIFFERS",
    wrong_role_count: 72,
    wrong_role_semantics:
      "OWNER_PRINCIPAL_MATCHES_AND_AUTHORITATIVE_ROLE_DIFFERS_FROM_REQUIRED_ROLE",
  });
});
