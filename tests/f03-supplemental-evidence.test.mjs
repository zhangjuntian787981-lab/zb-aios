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
      "../implementation/p0/f03/f03-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("F03 supplemental evidence binds exact source and preserves the hosted-CI limitation", () => {
  assert.equal(evidence.parent_work_package_id, "F03");
  assert.deepEqual(evidence.acceptance_item_ids, [
    "F03-AC01",
    "F03-AC05",
    "F03-AC06",
    "F03-AC07",
  ]);
  assert.deepEqual(
    evidence.acceptance_results.map(({ status }) => status),
    ["PASS", "PASS", "PARTIAL_EXTERNAL_CI_PENDING", "PASS"],
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
  assert.equal(evidence.verification_results.enterprise_endpoint_count, 0);
  assert.equal(evidence.verification_results.external_effect_count, 0);
  assert.deepEqual(evidence.governance_boundary, {
    d1_written: false,
    historical_work_package_status_changed: false,
    historical_gate_decision_changed: false,
    manifest_changed: false,
    enterprise_data_used: false,
  });
});
