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
      "../implementation/p1/c01/c01-ac05-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C01-AC05 supplemental evidence resolves to the frozen citation chain", () => {
  assert.equal(evidence.workPackageId, "C01");
  assert.equal(evidence.acceptanceCriterionId, "C01-AC05");
  assert.equal(evidence.evidenceGroupId, "P1-B02");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.verificationStatus, "PASS_GIT_FROZEN");
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.equal(evidence.contractChange.effectivePlanBaseline, "v5.3");
  assert.equal(
    evidence.contractChange.historicalGateOrEvidenceRewritten,
    false,
  );
  assert.equal(
    evidence.sourceReconciliationCoverage.fieldMutationCases,
    15,
  );
  assert.equal(
    evidence.sourceReconciliationCoverage.exactFields.length,
    15,
  );
  assert.equal(
    evidence.sourceReconciliationCoverage
      .allFieldMutationCasesUnavailable,
    true,
  );
  assert.deepEqual(
    evidence.lifecycleAndAuthorizationCoverage.map(
      ({ case: caseName, observedStatus, reasonCode, oldLocatorReturned }) => ({
        case: caseName,
        observedStatus,
        reasonCode,
        oldLocatorReturned,
      }),
    ),
    [
      {
        case: "C10_WITHDRAWN",
        observedStatus: "UNAVAILABLE",
        reasonCode: "SOURCE_NOT_CURRENT",
        oldLocatorReturned: false,
      },
      {
        case: "C10_DELETED",
        observedStatus: "UNAVAILABLE",
        reasonCode: "SOURCE_NOT_CURRENT",
        oldLocatorReturned: false,
      },
      {
        case: "CURRENT_PRINCIPAL_WITHOUT_SOURCE_ACCESS",
        observedStatus: "UNAVAILABLE",
        reasonCode: "ACCESS_DENIED",
        oldLocatorReturned: false,
      },
    ],
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
    planBaseline: "v5.3",
    supplementOnly: true,
    d1LedgerChanged: false,
    gateRecordChanged: false,
    manifestChanged: false,
    historicalEvidenceChanged: false,
    g1ReopenedOrReapproved: false,
  });
  assert.equal(evidence.runtimeBoundary.enterpriseSystems, "NOT_CONNECTED");
  assert.equal(
    evidence.runtimeBoundary.productionVerificationStatus,
    "NOT_VERIFIED",
  );
  assert.equal(
    evidence.verificationResults.fullRepositoryRun.result,
    "NOT_CLAIMED",
  );
});
