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
      "../implementation/p0/f04/f04-architecture-threat-crosswalk-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("F04-AC01 crosswalk evidence resolves to exact Git-frozen architecture objects", () => {
  assert.equal(evidence.parent_work_package_id, "F04");
  assert.deepEqual(evidence.acceptance_item_ids, ["F04-AC01"]);
  assert.equal(evidence.evidence_status, "GIT_FROZEN");
  assert.equal(evidence.crosswalk_summary.unmapped_count, 0);
  assert.equal(
    evidence.approved_plan_baseline.sha256,
    "sha256:bae704aa9fc8cf4275b8d85f8593139f1d83f8913c03d330227690eea98d43f3",
  );

  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", evidence.source_commit, "HEAD"],
    { cwd: repositoryRoot },
  );
  for (const artifact of [
    ...evidence.source_artifacts,
    ...evidence.frozen_inputs,
  ]) {
    const contents = execFileSync(
      "git",
      ["show", `${evidence.source_commit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(sha256(contents), artifact.sha256, artifact.path);
  }
  assert.deepEqual(evidence.governance_boundary, {
    d1_written: false,
    historical_work_package_status_changed: false,
    historical_gate_submission_changed: false,
    historical_gate_decision_changed: false,
    manifest_changed: false,
    enterprise_data_used: false,
  });
});
