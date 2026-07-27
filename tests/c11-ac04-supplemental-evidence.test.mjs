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
      "../implementation/p1/c11/c11-ac04-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C11-AC04 supplemental evidence resolves to the frozen quality benchmark and PostgreSQL test", () => {
  assert.equal(evidence.workPackageId, "C11");
  assert.equal(evidence.acceptanceCriterionId, "C11-AC04");
  assert.equal(evidence.evidenceGroupId, "P1-B10");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.verificationStatus, "PASS_GIT_FROZEN");
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.equal(evidence.benchmark.positiveQueryCount, 6);
  assert.equal(evidence.benchmark.negativeQueryCount, 4);
  assert.equal(evidence.metrics.allThresholdsPassed, true);
  assert.equal(evidence.metrics.macroPrecisionAtK, 0.91666667);
  assert.equal(evidence.metrics.macroRecallAtK, 1);
  assert.equal(evidence.metrics.microPrecisionAtK, 0.85714286);
  assert.equal(evidence.metrics.microRecallAtK, 1);
  assert.equal(evidence.metrics.statusAccuracy, 1);
  assert.equal(evidence.metrics.negativeRefusalAccuracy, 1);
  assert.equal(evidence.perQueryResults.length, 10);

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
  assert.equal(
    evidence.preRunFreeze.sha256,
    evidence.artifacts[0].sha256,
  );
  assert.deepEqual(evidence.governanceBoundary, {
    d1LedgerChanged: false,
    gateRecordChanged: false,
    manifestChanged: false,
    historicalEvidenceChanged: false,
  });
  assert.equal(evidence.runtimeBoundary.enterpriseConnectors, "C0_DISABLED");
  assert.equal(evidence.runtimeBoundary.enterpriseData, "NOT_PRESENT");
  assert.equal(evidence.runtimeBoundary.productionVerificationStatus, "NOT_VERIFIED");
});
