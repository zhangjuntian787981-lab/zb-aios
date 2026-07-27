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
      "../implementation/p1/c17/c17-ac05-reliability-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C17-AC05 reliability evidence binds the remediated source and current execution boundary", async () => {
  assert.equal(evidence.parent_work_package_id, "C17");
  assert.equal(evidence.acceptance_item_id, "C17-AC05");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(
    evidence.finding.status,
    "ACTUAL_FAILURE_REPRODUCED_AND_REMEDIATED",
  );
  assert.deepEqual(
    evidence.reliability_matrix.map(({ status }) => status),
    ["PASS", "PASS", "PASS", "PASS", "PASS"],
  );

  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", evidence.verified_source_commit, "HEAD"],
    { cwd: repositoryRoot },
  );
  for (const artifact of evidence.source_artifacts) {
    const contents = execFileSync(
      "git",
      ["show", `${evidence.verified_source_commit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(sha256(contents), artifact.sha256, artifact.path);
  }

  const boundary = await readFile(
    new URL(`../${evidence.execution_boundary.path}`, import.meta.url),
  );
  assert.equal(
    sha256(boundary),
    evidence.execution_boundary.sha256,
  );
  assert.equal(evidence.execution_boundary.connector_stage, "C0_DISABLED");
  assert.equal(evidence.execution_boundary.external_effect_count, 0);
  assert.deepEqual(evidence.governance_boundary, {
    d1_written: false,
    historical_work_package_status_changed: false,
    historical_gate_decision_changed: false,
    manifest_changed: false,
    enterprise_data_used: false,
  });
});
