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
      "../implementation/p1/c01/c01-ac04-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C01-AC04 supplemental evidence resolves to the exact stream lifecycle source", () => {
  assert.equal(evidence.workPackageId, "C01");
  assert.equal(evidence.acceptanceCriterionId, "C01-AC04");
  assert.equal(evidence.evidenceGroupId, "P1-B01");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.verificationStatus, "PASS_GIT_FROZEN");
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.deepEqual(
    evidence.faultInjectionCoverage.map(
      ({
        fault,
        terminalCode,
        downstreamAbortObserved,
        completedEventYielded,
        laterToolOrConnectorSideEffectCount,
      }) => ({
        fault,
        terminalCode,
        downstreamAbortObserved,
        completedEventYielded,
        laterToolOrConnectorSideEffectCount,
      }),
    ),
    [
      {
        fault: "EXPLICIT_CANCELLATION",
        terminalCode: "STREAM_CANCELLED",
        downstreamAbortObserved: true,
        completedEventYielded: false,
        laterToolOrConnectorSideEffectCount: 0,
      },
      {
        fault: "SERVER_TIMEOUT",
        terminalCode: "STREAM_TIMEOUT",
        downstreamAbortObserved: true,
        completedEventYielded: false,
        laterToolOrConnectorSideEffectCount: 0,
      },
      {
        fault: "CLIENT_DISCONNECT",
        terminalCode: "CLIENT_DISCONNECTED",
        downstreamAbortObserved: true,
        completedEventYielded: false,
        laterToolOrConnectorSideEffectCount: 0,
      },
    ],
  );
  assert.equal(
    evidence.terminalStateCoverage.terminalEventReleasedOnlyAfterSourceEnd,
    true,
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
  assert.equal(evidence.runtimeBoundary.enterpriseSystems, "NOT_CONNECTED");
  assert.equal(
    evidence.runtimeBoundary.productionVerificationStatus,
    "NOT_VERIFIED",
  );
});
