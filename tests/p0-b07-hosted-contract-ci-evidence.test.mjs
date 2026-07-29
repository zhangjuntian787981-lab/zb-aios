import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { sha256ProjectValue } from "../lib/project-control.mjs";
import { findBreakingChanges } from "../scripts/f03-contract-lab.mjs";

const REPOSITORY_ROOT = new URL("..", import.meta.url);
const EVIDENCE_PATH =
  "implementation/p0/f03/f03-hosted-ci-supplemental-evidence.v1.json";
const SOURCE_COMMIT = "807172852044d4c86480f05845b358e5ed394e9e";
const SOURCE_PARENT = "96ccc8fd375cf895285c42971b76863184b320b0";
const SOURCE_TREE = "e3fa8e7ef495fa121942b1c9e063dd198990ecbf";
const CANARY_COMMIT = "96451b43eaf03cf7f52ce5f9c1f15a8cd09b77a8";
const CANARY_TREE = "aa0a8d7489aeb1c675f46cb549648f6d472c1a6a";
const CANARY_PATCH_SHA256 =
  "sha256:43bc7acedbb53a58844c5c58910b834fe2df4ccbc915276fee8b2c24ae58bcb1";
const AUDIT_CONTRACT_PATH =
  "implementation/p0/f03/contracts/audit.openapi.v1.json";
const AUDIT_BEFORE_SHA256 =
  "sha256:7173f5a3b23f00d730f3330827b80756248ae5d458365771bb97181bd353a07c";
const AUDIT_AFTER_SHA256 =
  "sha256:84ec525daf6f70a726fe9b9c8dfe30a7d379a2b8a82847a083580ea6097eedca";
const PRIOR_EVIDENCE_COMMIT =
  "6b86e5a55bf9cea6c31f0ba92597d2ea5d8ab817";
const PRIOR_EVIDENCE_PATH =
  "implementation/p0/f03/f03-supplemental-evidence.v1.json";
const PRIOR_EVIDENCE_SHA256 =
  "sha256:1c8865ea322444b708470dd17ef43388a4df2d921e868793e43437eab6b5e795";

const evidence = JSON.parse(
  await readFile(new URL(`../${EVIDENCE_PATH}`, import.meta.url), "utf8"),
);

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function gitBytes(commit, path) {
  return execFileSync("git", ["show", `${commit}:${path}`], {
    cwd: REPOSITORY_ROOT,
  });
}

function gitPatchBytes(parent, commit) {
  return execFileSync("git", ["diff", "--binary", parent, commit], {
    cwd: REPOSITORY_ROOT,
  });
}

function withoutSelfHash(value) {
  const copy = structuredClone(value);
  delete copy.evidenceSha256;
  return copy;
}

function assertExactKeys(value, expected) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}

test("P0-B07 evidence binds the prior pending evidence and exact source freeze", () => {
  assertExactKeys(evidence, [
    "schemaVersion",
    "evidenceId",
    "recordType",
    "groupId",
    "workPackageId",
    "acceptanceCriterionId",
    "classification",
    "status",
    "closureScope",
    "recordedAt",
    "priorLocalEvidenceFreeze",
    "sourceFreeze",
    "workflowTrustBoundary",
    "positiveControl",
    "negativeControl",
    "criterionResult",
    "acceptanceResult",
    "referenceReviewBoundary",
    "governanceBoundary",
    "limitations",
    "evidenceSha256",
  ]);
  assert.equal(
    evidence.schemaVersion,
    "p0-b07-hosted-contract-ci-evidence.v1",
  );
  assert.equal(evidence.groupId, "P0-B07");
  assert.equal(evidence.workPackageId, "F03");
  assert.equal(evidence.acceptanceCriterionId, "F03-AC06");
  assert.equal(evidence.status, "CLOSED");
  assert.equal(
    evidence.closureScope,
    "HOSTED_PR_BASE_COMPARISON_AND_SYNTHETIC_NEGATIVE_PROPAGATION",
  );

  assert.deepEqual(evidence.priorLocalEvidenceFreeze, {
    commit: PRIOR_EVIDENCE_COMMIT,
    path: PRIOR_EVIDENCE_PATH,
    sha256: PRIOR_EVIDENCE_SHA256,
    priorStatus: "PARTIAL_EXTERNAL_CI_PENDING",
  });
  assert.equal(
    sha256Bytes(gitBytes(PRIOR_EVIDENCE_COMMIT, PRIOR_EVIDENCE_PATH)),
    PRIOR_EVIDENCE_SHA256,
  );
  const prior = JSON.parse(
    gitBytes(PRIOR_EVIDENCE_COMMIT, PRIOR_EVIDENCE_PATH).toString("utf8"),
  );
  assert.equal(
    prior.acceptance_results.find(({ id }) => id === "F03-AC06").status,
    "PARTIAL_EXTERNAL_CI_PENDING",
  );

  execFileSync("git", ["cat-file", "-e", `${SOURCE_COMMIT}^{commit}`], {
    cwd: REPOSITORY_ROOT,
  });
  assert.equal(evidence.sourceFreeze.commit, SOURCE_COMMIT);
  assert.equal(evidence.sourceFreeze.parent, SOURCE_PARENT);
  assert.equal(evidence.sourceFreeze.tree, SOURCE_TREE);
  assert.equal(
    execFileSync("git", ["show", "-s", "--format=%P", SOURCE_COMMIT], {
      cwd: REPOSITORY_ROOT,
      encoding: "utf8",
    }).trim(),
    SOURCE_PARENT,
  );
  assert.equal(
    execFileSync("git", ["show", "-s", "--format=%T", SOURCE_COMMIT], {
      cwd: REPOSITORY_ROOT,
      encoding: "utf8",
    }).trim(),
    SOURCE_TREE,
  );
  for (const artifact of evidence.sourceFreeze.artifacts) {
    assertExactKeys(artifact, ["path", "sha256"]);
    assert.equal(
      sha256Bytes(gitBytes(SOURCE_COMMIT, artifact.path)),
      artifact.sha256,
      artifact.path,
    );
  }
});

test("P0-B07 positive control proves six exact-base comparisons and the hosted eight-category suite", () => {
  assert.deepEqual(evidence.positiveControl.pullRequest, {
    number: 4,
    url: "https://github.com/zhangjuntian787981-lab/zb-aios/pull/4",
    state: "OPEN",
    draft: true,
    merged: false,
    baseBranch: "main",
    baseSha: "3cca881e9f6bc89cba28fc7fc5a42663208c8a10",
    headBranch: "codex/p0-b07-hosted-ci",
    headSha: SOURCE_COMMIT,
    createdAt: "2026-07-29T22:36:42Z",
  });
  assert.deepEqual(evidence.positiveControl.run, {
    runId: 30496746458,
    runNumber: 1,
    runAttempt: 1,
    url: "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30496746458",
    event: "pull_request",
    workflowPath: ".github/workflows/f03-contract-compatibility-gate.yml",
    headBranch: "codex/p0-b07-hosted-ci",
    headSha: SOURCE_COMMIT,
    status: "completed",
    conclusion: "success",
    createdAt: "2026-07-29T22:36:45Z",
    updatedAt: "2026-07-29T22:37:17Z",
    jobId: 90727253457,
    jobUrl:
      "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30496746458/job/90727253457",
    startedAt: "2026-07-29T22:36:48Z",
    completedAt: "2026-07-29T22:37:16Z",
    runner: {
      runnerVersion: "2.336.0",
      provisionerVersion: "20260707.563",
      image: "ubuntu-24.04",
      imageVersion: "20260720.247.2",
      includedSoftwareUrl:
        "https://github.com/actions/runner-images/blob/ubuntu24/20260720.247/images/ubuntu/Ubuntu2404-Readme.md",
      imageReleaseUrl:
        "https://github.com/actions/runner-images/releases/tag/ubuntu24%2F20260720.247",
    },
    log: {
      byteLength: 32354,
      sha256:
        "sha256:d2a1998ea86864394b11631974ae184203fbf12c3b85eb2c7f682b92990c5d2f",
    },
  });
  assert.deepEqual(evidence.positiveControl.gateResult, {
    exactBaseContractComparisonCount: 6,
    exactBaseContractCompatibleCount: 6,
    frozenMutationCategoryCount: 8,
    frozenTestCount: 13,
    passedTestCount: 13,
    failedTestCount: 0,
  });
});

test("P0-B07 negative control is one closed unmerged synthetic response-removal canary", () => {
  assert.equal(evidence.negativeControl.canary.commit, CANARY_COMMIT);
  assert.equal(evidence.negativeControl.canary.parent, SOURCE_COMMIT);
  assert.equal(evidence.negativeControl.canary.tree, CANARY_TREE);
  assert.equal(
    evidence.negativeControl.canary.patchSha256,
    CANARY_PATCH_SHA256,
  );
  assert.equal(evidence.negativeControl.canary.path, AUDIT_CONTRACT_PATH);
  assert.equal(
    evidence.negativeControl.canary.beforeFileSha256,
    AUDIT_BEFORE_SHA256,
  );
  assert.equal(
    evidence.negativeControl.canary.afterFileSha256,
    AUDIT_AFTER_SHA256,
  );
  assert.equal(
    sha256Bytes(gitPatchBytes(SOURCE_COMMIT, CANARY_COMMIT)),
    CANARY_PATCH_SHA256,
  );
  assert.equal(
    sha256Bytes(gitBytes(SOURCE_COMMIT, AUDIT_CONTRACT_PATH)),
    AUDIT_BEFORE_SHA256,
  );
  assert.equal(
    sha256Bytes(gitBytes(CANARY_COMMIT, AUDIT_CONTRACT_PATH)),
    AUDIT_AFTER_SHA256,
  );

  const changes = findBreakingChanges(
    JSON.parse(gitBytes(SOURCE_COMMIT, AUDIT_CONTRACT_PATH).toString("utf8")),
    JSON.parse(gitBytes(CANARY_COMMIT, AUDIT_CONTRACT_PATH).toString("utf8")),
  );
  assert.deepEqual(changes, [
    {
      code: "RESPONSE_REMOVED",
      location: "POST /v1/audit-events default",
      message: "POST /v1/audit-events 移除了响应 default",
    },
  ]);

  assert.deepEqual(evidence.negativeControl.pullRequest, {
    number: 5,
    url: "https://github.com/zhangjuntian787981-lab/zb-aios/pull/5",
    state: "CLOSED",
    draft: true,
    merged: false,
    baseBranch: "main",
    baseSha: "3cca881e9f6bc89cba28fc7fc5a42663208c8a10",
    headBranch: "codex/p0-b07-negative-canary",
    headSha: CANARY_COMMIT,
    createdAt: "2026-07-29T22:38:43Z",
    closedAt: "2026-07-29T22:40:21Z",
  });
  assert.deepEqual(evidence.negativeControl.run, {
    runId: 30496859527,
    runNumber: 2,
    runAttempt: 1,
    url: "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30496859527",
    event: "pull_request",
    workflowPath: ".github/workflows/f03-contract-compatibility-gate.yml",
    headBranch: "codex/p0-b07-negative-canary",
    headSha: CANARY_COMMIT,
    status: "completed",
    conclusion: "failure",
    createdAt: "2026-07-29T22:38:47Z",
    updatedAt: "2026-07-29T22:39:15Z",
    jobId: 90727610863,
    jobUrl:
      "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30496859527/job/90727610863",
    startedAt: "2026-07-29T22:38:50Z",
    completedAt: "2026-07-29T22:39:14Z",
    runner: {
      runnerVersion: "2.336.0",
      provisionerVersion: "20260707.563",
      image: "ubuntu-24.04",
      imageVersion: "20260726.254.1",
      includedSoftwareUrl:
        "https://github.com/actions/runner-images/blob/ubuntu24/20260726.254/images/ubuntu/Ubuntu2404-Readme.md",
      imageReleaseUrl:
        "https://github.com/actions/runner-images/releases/tag/ubuntu24%2F20260726.254",
    },
    log: {
      byteLength: 27462,
      sha256:
        "sha256:2bad2109051bf8e7faf30f8bea0476aef3df10c370d2538f7898d3987311cb4b",
    },
  });
  assert.deepEqual(evidence.negativeControl.gateResult, {
    comparisonConclusion: "failure",
    detectedCodes: ["RESPONSE_REMOVED"],
    processExitCode: 1,
    compatibilitySuiteExecuted: false,
  });
});

test("P0-B07 closure remains scoped and creates no governance state", async () => {
  assert.deepEqual(evidence.criterionResult, {
    criterionId: "F03-AC06",
    status: "PASS",
    scope:
      "HOSTED_EIGHT_CATEGORY_DETECTION_WITH_ONE_REAL_RESPONSE_REMOVAL_FAILURE_PROPAGATION",
  });
  assert.equal(evidence.acceptanceResult.status, "PASS");
  assert.equal(evidence.acceptanceResult.positiveHostedRunProved, true);
  assert.equal(evidence.acceptanceResult.negativeHostedBlockProved, true);
  assert.equal(evidence.acceptanceResult.enterpriseDataUsed, false);
  assert.deepEqual(evidence.referenceReviewBoundary, {
    researchAndCandidateAdrFrozen: true,
    formalReceiptCreated: false,
    currentCatalogAndPolicyCoverF03: false,
    profileReadinessProved: false,
  });
  assert.deepEqual(evidence.governanceBoundary, {
    p0B07EvidenceClosed: true,
    supplementalEvidenceIndexUpdated: false,
    d1Written: false,
    workPackageStatusChanged: false,
    gateStatusChanged: false,
    manifestChanged: false,
    profileApproved: false,
    startAuthorized: false,
    positivePullRequestMerged: false,
    negativePullRequestMerged: false,
  });
  assert.ok(
    evidence.limitations.some((item) =>
      item.includes("does not prove branch protection"),
    ),
  );
  assert.ok(
    evidence.limitations.some((item) =>
      item.includes("not eight separate failing pull requests"),
    ),
  );
  assert.equal(
    evidence.evidenceSha256,
    await sha256ProjectValue(withoutSelfHash(evidence)),
  );
});

test("P0-B07 evidence hash fails closed after any semantic tamper", async () => {
  const tampered = structuredClone(evidence);
  tampered.negativeControl.gateResult.processExitCode = 0;
  assert.notEqual(
    evidence.evidenceSha256,
    await sha256ProjectValue(withoutSelfHash(tampered)),
  );
});
