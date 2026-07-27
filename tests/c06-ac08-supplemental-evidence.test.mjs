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
      "../implementation/p1/c06/c06-ac08-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C06-AC08 supplemental evidence resolves to the exact revocation profile and tests", () => {
  assert.equal(evidence.workPackageId, "C06");
  assert.equal(evidence.acceptanceCriterionId, "C06-AC08");
  assert.equal(evidence.evidenceGroupId, "P1-B07");
  assert.equal(evidence.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.verificationStatus, "PASS_GIT_FROZEN");
  assert.equal(evidence.freezeStatus, "GIT_FROZEN");
  assert.deepEqual(evidence.revocationSla, {
    maximumPropagationMs: 1000,
    measurementStart: "REVOCATION_COMMIT_RETURNED",
    measurementEnd: "FIRST_POST_COMMIT_ACTION_DENIED",
    implementedProductPepCount: 10,
    representativeSurfaceCount: 6,
    warmCachePathCount: 1,
    maximumObservedPropagationMs: 0,
    allMeasuredPathsPassed: true,
  });
  assert.equal(evidence.staleAllowCoverage.length, 2);
  assert.equal(
    evidence.staleAllowCoverage.every(
      (item) =>
        item.postRevocationAllowRecordCount === 0 ||
        item.postRevocationEffectWriteCount === 0,
    ),
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
