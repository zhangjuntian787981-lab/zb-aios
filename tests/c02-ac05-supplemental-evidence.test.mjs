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
      "../implementation/p1/c02/c02-ac05-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const sourcePaths = [
  "lib/tenant-governance-bff.mjs",
  "scripts/run-c02-tests.sh",
  "tests/c02-c06-integration.test.mjs",
  "tests/c02-c18-high-risk-integration.test.mjs",
  "tests/c02-tenant-governance-bff.test.mjs",
  "tests/c02-verification-evidence.test.mjs",
];

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C02-AC05 supplemental evidence binds the exact six-file source freeze", () => {
  assert.equal(evidence.workPackageId, "C02");
  assert.equal(evidence.acceptanceCriterionId, "C02-AC05");
  assert.equal(evidence.evidenceGroupId, "P1-B03");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(
    evidence.verificationStatus,
    "TARGETED_PASS_SOURCE_GIT_FROZEN",
  );
  assert.equal(evidence.freezeStatus, "SOURCE_GIT_FROZEN");
  assert.match(evidence.sourceCommit, /^[a-f0-9]{40}$/);

  execFileSync(
    "git",
    ["merge-base", "--is-ancestor", evidence.sourceCommit, "HEAD"],
    { cwd: repositoryRoot },
  );
  const committedPaths = execFileSync(
    "git",
    [
      "diff-tree",
      "--no-commit-id",
      "--name-only",
      "-r",
      evidence.sourceCommit,
    ],
    { cwd: repositoryRoot, encoding: "utf8" },
  )
    .trim()
    .split("\n")
    .filter(Boolean)
    .sort();
  assert.deepEqual(committedPaths, [...sourcePaths].sort());
  assert.deepEqual(
    evidence.artifacts.map(({ path }) => path),
    sourcePaths,
  );
  for (const artifact of evidence.artifacts) {
    const contents = execFileSync(
      "git",
      ["show", `${evidence.sourceCommit}:${artifact.path}`],
      { cwd: repositoryRoot },
    );
    assert.equal(sha256(contents), artifact.sha256, artifact.path);
  }
});

test("C02-AC05 records a real same-Tenant C18 loop and fail-closed hash binding", () => {
  assert.deepEqual(
    evidence.actualGapAndRemediation.classification,
    "PRODUCT_MECHANISM_GAP_REMEDIATED",
  );
  assert.match(
    evidence.actualGapAndRemediation.priorGap,
    /namespace-only reference/,
  );
  assert.equal(
    evidence.actualGapAndRemediation.historicalGateAutomaticallyChanged,
    false,
  );
  assert.equal(
    evidence.actualGapAndRemediation.historicalEvidenceChanged,
    false,
  );

  const coverage = evidence.closedLoopCoverage;
  assert.equal(coverage.operationId, "QUOTA_CHANGE");
  assert.equal(coverage.logicalConfirmationConsumptionCount, 1);
  assert.equal(coverage.productCoreCommitCount, 1);
  assert.equal(coverage.c18AppendAttemptCount, 2);
  assert.equal(coverage.c18NewEventCount, 1);
  assert.equal(coverage.c18IdempotentReplayCount, 1);
  assert.equal(coverage.c18StoredEventCount, 1);
  assert.equal(coverage.c18StoredCommandReceiptCount, 1);
  assert.equal(coverage.sameTenantReadback, true);
  assert.equal(coverage.otherTenantEventCount, 0);
  assert.equal(coverage.returnedCopyMutationChangedStoredEvent, false);
  assert.equal(coverage.mutableUpdateApiExposed, false);
  assert.equal(coverage.mutableDeleteApiExposed, false);
  assert.equal(
    coverage.commandSha256,
    "sha256:050ada115b402ee8cc62da3096fd127ab8c30315c96b929ab9fda566f0b73f0c",
  );
  assert.equal(
    coverage.resultSha256,
    "sha256:ce7492fef3e108975385faee6c46dbd1dcc59e70854f8e2ff0e4a62e4b5b39be",
  );
  assert.deepEqual(
    coverage.negativeCases.map(
      ({ case: caseName, terminalCode, c02SuccessReturned }) => ({
        caseName,
        terminalCode,
        c02SuccessReturned,
      }),
    ),
    [
      {
        caseName: "C18_COMMAND_HASH_MISMATCH",
        terminalCode: "AUDIT_EVIDENCE_INVALID",
        c02SuccessReturned: false,
      },
      {
        caseName: "C18_RESULT_HASH_MISMATCH",
        terminalCode: "AUDIT_EVIDENCE_INVALID",
        c02SuccessReturned: false,
      },
    ],
  );
});

test("C02-AC05 keeps governance and full-regression claims bounded", () => {
  assert.deepEqual(evidence.governanceBoundary, {
    d1LedgerChanged: false,
    workPackageStatusChanged: false,
    gateRecordChanged: false,
    manifestChanged: false,
    historicalEvidenceChanged: false,
  });
  assert.equal(
    evidence.historicalEvidencePreservation.historicalEvidenceModified,
    false,
  );
  assert.equal(
    evidence.historicalEvidencePreservation.oldGateReopened,
    false,
  );
  assert.equal(
    evidence.historicalEvidencePreservation.oldGateReapproved,
    false,
  );
  assert.equal(
    evidence.runtimeBoundary.c18Store,
    "IN_PROCESS_MEMORY_AUDIT_EVIDENCE_STORE",
  );
  assert.equal(evidence.runtimeBoundary.enterpriseSystems, "NOT_CONNECTED");
  assert.equal(
    evidence.runtimeBoundary.productionVerificationStatus,
    "NOT_VERIFIED",
  );
  assert.deepEqual(
    evidence.verificationResults.fullRepositoryRegression,
    {
      status: "PENDING_MAIN_AGENT_FINAL_RUN",
      resultClaimed: false,
    },
  );
});
