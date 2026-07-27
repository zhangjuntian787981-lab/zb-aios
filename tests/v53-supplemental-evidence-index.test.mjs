import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(root);
const index = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/v5.3-supplemental-evidence-index.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

test("v5.3 supplemental index is a complete static 26-group catalog", () => {
  assert.equal(
    index.recordType,
    "STATIC_SUPPLEMENTAL_EVIDENCE_INDEX",
  );
  assert.equal(index.governanceDisclaimer.isProgressTracker, false);
  assert.equal(
    index.governanceDisclaimer.isWorkPackageOrGateStatusAuthority,
    false,
  );
  assert.equal(index.governanceDisclaimer.d1LedgerChanged, false);
  assert.equal(index.governanceDisclaimer.gateSubmissionChanged, false);
  assert.equal(index.governanceDisclaimer.gateDecisionChanged, false);
  assert.equal(index.governanceDisclaimer.manifestChanged, false);

  assert.equal(index.groups.length, 26);
  assert.equal(
    new Set(index.groups.map(({ groupId }) => groupId)).size,
    26,
  );
  assert.equal(
    index.groups.flatMap(({ criteria }) => criteria).length,
    29,
  );

  const counts = Object.groupBy(
    index.groups,
    ({ classification }) => classification,
  );
  for (const classification of [
    "GIT_FROZEN_PASS",
    "GIT_FROZEN_AFTER_REMEDIATION",
    "EXISTING_EVIDENCE_REUSED",
    "PARTIAL_EXTERNAL_EVIDENCE_PENDING",
    "BLOCKED_EXTERNAL_READ",
  ]) {
    assert.equal(
      counts[classification]?.length ?? 0,
      index.classificationSummary[classification],
      classification,
    );
  }
  assert.deepEqual(
    index.externalBlockers.map(({ groupId }) => groupId).sort(),
    ["P0-B04", "P0-B07", "P0-B11", "P1-B11"],
  );
});

test("every indexed evidence blob resolves at its exact Git freeze", () => {
  for (const group of index.groups) {
    execFileSync(
      "git",
      [
        "merge-base",
        "--is-ancestor",
        group.sourceCommit,
        group.evidenceFreezeCommit,
      ],
      { cwd: repositoryRoot },
    );
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", group.evidenceFreezeCommit, "HEAD"],
      { cwd: repositoryRoot },
    );
    const content = execFileSync(
      "git",
      [
        "show",
        `${group.evidenceFreezeCommit}:${group.evidence.path}`,
      ],
      { cwd: repositoryRoot },
    );
    assert.equal(sha256(content), group.evidence.sha256, group.groupId);
  }
});

test("v5.3 baselines and integrated regression are hash-bound", async () => {
  for (const baseline of Object.values(index.baselines)) {
    const content = await readFile(new URL(baseline.path, root));
    assert.equal(sha256(content), baseline.sha256, baseline.path);
  }
  execFileSync(
    "git",
    [
      "merge-base",
      "--is-ancestor",
      index.integratedRegression.sourceHead,
      "HEAD",
    ],
    { cwd: repositoryRoot },
  );
  assert.deepEqual(index.integratedRegression.tests, {
    command: "npm test",
    passed: 1018,
    failed: 0,
  });
  assert.deepEqual(index.integratedRegression.lint, {
    command: "npm run lint",
    result: "PASS",
  });
  assert.equal(index.integratedRegression.enterpriseDataUsed, false);
});
