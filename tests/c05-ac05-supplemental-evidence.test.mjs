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
      "../implementation/p1/c05/c05-ac05-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C05-AC05 supplemental evidence resolves to exact Git-frozen operation coverage", () => {
  assert.equal(evidence.workPackageId, "C05");
  assert.equal(evidence.acceptanceCriterionId, "C05-AC05");
  assert.equal(evidence.evidenceGroupId, "P1-B06");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.verificationStatus, "PASS_GIT_FROZEN");
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.deepEqual(evidence.coverageResults, {
    inventoryOperations: 18,
    coveredHumanDelegatedOperations: 13,
    policyExemptOperations: 5,
    unexplainedOperations: 0,
    requiredIdentityDimensions: [
      "human subject",
      "workload actor",
      "delegation chain",
    ],
    consumers: ["C08", "C15", "C18"],
    result: "PASS",
  });

  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", evidence.sourceCommit, "HEAD"],
    { cwd: repositoryRoot },
  );
  for (const artifact of evidence.artifacts) {
    const contents = execFileSync(
      "git",
      ["show", `${evidence.sourceCommit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(sha256(contents), artifact.sha256, artifact.path);
  }
  assert.deepEqual(evidence.governanceBoundary, {
    d1LedgerChanged: false,
    workPackageStatusChanged: false,
    gateSubmissionChanged: false,
    gateDecisionChanged: false,
    manifestChanged: false,
    historicalEvidenceChanged: false,
  });
  assert.equal(evidence.runtimeBoundary.enterpriseSystems, "NOT_CONNECTED");
  assert.equal(evidence.runtimeBoundary.enterpriseDataUsed, false);
  assert.equal(evidence.runtimeBoundary.productionVerificationStatus, "NOT_VERIFIED");
});
