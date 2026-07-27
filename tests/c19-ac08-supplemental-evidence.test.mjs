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
      "../implementation/p1/c19/c19-ac08-supplemental-evidence.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function sha256(contents) {
  return `sha256:${createHash("sha256").update(contents).digest("hex")}`;
}

test("C19-AC08 supplemental evidence resolves to exact Git-frozen billing artifacts", () => {
  assert.equal(evidence.workPackageId, "C19");
  assert.equal(evidence.acceptanceId, "C19-AC08");
  assert.equal(evidence.supplementId, "P1-B14");
  assert.equal(evidence.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(evidence.evidenceStatus, "GIT_FROZEN");
  assert.deepEqual(evidence.coverage.dimensions, [
    "MODEL",
    "TOOL",
    "SANDBOX",
  ]);
  assert.equal(evidence.verificationResults.positiveCaseCount, 1);
  assert.equal(evidence.verificationResults.negativeCaseCount, 10);
  assert.equal(
    evidence.actualGapAndRemediation.classification,
    "PRODUCT_MECHANISM_GAP_REMEDIATED",
  );
  assert.equal(
    evidence.actualGapAndRemediation.historicalGateAutomaticallyChanged,
    false,
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
  assert.equal(evidence.dataScope, "SYNTHETIC_ONLY");
  assert.equal(evidence.enterpriseData, "NOT_PRESENT");
  assert.match(
    evidence.limitations.join("\n"),
    /does not change any D1 work-package or Gate state/,
  );
});
