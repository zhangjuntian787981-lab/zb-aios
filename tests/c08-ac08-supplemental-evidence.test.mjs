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
      "../implementation/p1/c08/c08-ac08-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C08-AC08 supplemental remediation resolves to exact Git-frozen artifacts", () => {
  assert.equal(evidence.workPackageId, "C08");
  assert.equal(evidence.acceptanceCriterionId, "C08-AC08");
  assert.equal(evidence.evidenceGroupId, "P1-B08");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(
    evidence.verificationStatus,
    "PASS_AFTER_REMEDIATION_GIT_FROZEN",
  );
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.equal(evidence.actualFailure.detected, true);
  assert.equal(evidence.remediation.errorCode, "STALE_SOURCE_REFERENCE");
  assert.deepEqual(evidence.factBoundary.storedKnowledgeKeys, [
    "evidenceRef",
    "version",
    "asOf",
    "sha256",
  ]);
  assert.equal(evidence.factBoundary.storedSourceFactBody, false);
  assert.equal(evidence.factBoundary.storedArbitraryPayload, false);
  assert.deepEqual(
    {
      tests: evidence.verificationResults.fullC08Total.tests,
      passed: evidence.verificationResults.fullC08Total.passed,
      failed: evidence.verificationResults.fullC08Total.failed,
    },
    { tests: 62, passed: 62, failed: 0 },
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
    gateRecordChanged: false,
    manifestChanged: false,
    historicalEvidenceChanged: false,
  });
  assert.equal(evidence.runtimeBoundary.enterpriseData, "NOT_PRESENT");
  assert.equal(
    evidence.runtimeBoundary.productionVerificationStatus,
    "NOT_VERIFIED",
  );
});
