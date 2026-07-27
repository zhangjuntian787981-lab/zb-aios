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
      "../implementation/p1/c04/c04-c05-scim-identity-link-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C04-AC02 supplemental evidence resolves to its frozen C04-C05 integration source", async () => {
  assert.equal(evidence.parent_work_package_id, "C04");
  assert.deepEqual(evidence.acceptance_item_ids, ["C04-AC02"]);
  assert.equal(evidence.freeze_status, "GIT_FROZEN");
  assert.equal(evidence.verification_scope, "P1_SYNTHETIC_ONLY");
  assert.equal(
    evidence.synthetic_scenario.final_identity_link_count,
    1,
  );
  assert.equal(
    evidence.synthetic_scenario.identity_link_created_event_count,
    1,
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
  for (const dependency of evidence.dependency_evidence) {
    const contents = execFileSync(
      "git",
      ["show", `${evidence.verified_source_commit}:${dependency.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(sha256(contents), dependency.sha256, dependency.path);
  }
  assert.deepEqual(evidence.governance_boundary, {
    d1_written: false,
    historical_work_package_status_changed: false,
    historical_gate_decision_changed: false,
    manifest_changed: false,
    enterprise_data_used: false,
  });
});
