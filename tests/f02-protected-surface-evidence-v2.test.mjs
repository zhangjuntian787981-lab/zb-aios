import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const evidence = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f02/f02-protected-surface-evidence.v2.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("P0-B04 evidence binds exact local gate artifacts while leaving hosted CI pending", async () => {
  assert.deepEqual(evidence.parent_work_package_ids, ["F02", "F04"]);
  assert.deepEqual(evidence.acceptance_item_ids, [
    "F02-AC03",
    "F02-AC04",
    "F02-AC05",
    "F04-AC05",
  ]);
  assert.equal(evidence.supplement_group_id, "P0-B04");
  assert.equal(
    evidence.evidence_status,
    "GIT_FROZEN_LOCAL_EXTERNAL_CI_PENDING",
  );
  assert.equal(evidence.local_verification_status, "PASS");
  assert.equal(evidence.hosted_ci_execution_status, "EXTERNAL_PENDING");
  assert.equal(evidence.overall_completion, "PARTIAL_EXTERNAL_CI_PENDING");

  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", evidence.source_commit, "HEAD"],
    { cwd: repositoryRoot },
  );
  for (const artifact of evidence.source_artifacts) {
    const contents = execFileSync(
      "git",
      ["show", `${evidence.source_commit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(sha256(contents), artifact.sha256, artifact.path);
    assert.equal(artifact.git_freeze_status, "GIT_FROZEN");
  }
  const reportContents = await readFile(
    new URL(`../${evidence.acceptance_report.path}`, import.meta.url),
  );
  assert.equal(
    sha256(reportContents),
    evidence.acceptance_report.sha256,
  );
  const report = JSON.parse(reportContents);
  assert.equal(report.source_commit, evidence.source_commit);
  assert.equal(report.local_verification_status, "PASS");
  assert.equal(report.hosted_ci.execution_status, "EXTERNAL_PENDING");
  assert.equal(report.surface_scan.surface_count, 7);
  assert.equal(report.surface_scan.findings.length, 0);
  assert.deepEqual(evidence.governance_boundary, {
    d1_written: false,
    historical_work_package_status_changed: false,
    historical_gate_submission_changed: false,
    historical_gate_decision_changed: false,
    manifest_changed: false,
    historical_evidence_changed: false,
    enterprise_data_used: false,
  });
});
