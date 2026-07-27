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
      "../implementation/p1/c04/c04-ac04-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C04-AC04 supplemental evidence resolves to exact Git-frozen SLA artifacts", () => {
  assert.equal(evidence.workPackageId, "C04");
  assert.equal(evidence.acceptanceCriterionId, "C04-AC04");
  assert.equal(evidence.evidenceGroupId, "P1-B05");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.verificationStatus, "PASS_GIT_FROZEN");
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.equal(evidence.frozenSla.maximumPropagationMs, 1000);
  assert.equal(evidence.frozenSla.observedPropagationMs, 0);
  assert.equal(evidence.frozenSla.result, "PASS");
  assert.equal(evidence.surfaceResults.sessionCache.mode, "DISABLED");
  assert.equal(evidence.surfaceResults.sessionCache.observedCacheHits, 0);
  assert.equal(
    evidence.actualFailureAndRemediation.finalResult,
    "34 PASS, 0 FAIL",
  );

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
