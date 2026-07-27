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
      "../implementation/p1/c19/c19-ac09-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C19-AC09 supplemental evidence resolves to exact Git-frozen boundary artifacts", () => {
  assert.equal(evidence.workPackageId, "C19");
  assert.equal(evidence.acceptanceCriterionId, "C19-AC09");
  assert.equal(evidence.evidenceGroupId, "P1-B15");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.verificationStatus, "PASS_GIT_FROZEN");
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.equal(
    evidence.verificationResults.closedSchemaNegativeCases.count,
    24,
  );
  assert.equal(
    evidence.verificationResults.publicApiNegativeCases.count,
    24,
  );
  assert.equal(
    evidence.verificationResults.realPostgresqlInvalidColumnCases.count,
    6,
  );
  assert.equal(evidence.verificationResults.c19Runner.passed, 37);
  assert.equal(evidence.verificationResults.c19Runner.failed, 0);

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
