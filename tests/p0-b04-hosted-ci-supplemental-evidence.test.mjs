import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const REPOSITORY_ROOT = new URL("..", import.meta.url);
const EVIDENCE_PATH =
  "implementation/p0/f02/f02-hosted-ci-supplemental-evidence.v1.json";
const SOURCE_COMMIT = "862adfd58c8ead48f4a18d84a72cdbc28c89bc5c";
const SOURCE_PARENT = "3cca881e9f6bc89cba28fc7fc5a42663208c8a10";
const SOURCE_TREE = "62c82d544ae585ca62b6a9a59005976a72bb7221";
const PRIOR_EVIDENCE_COMMIT = "7f0353c53756305b8a09bb0a7cf9aa5a01968390";
const PRIOR_EVIDENCE_PATH =
  "implementation/p0/f02/f02-protected-surface-evidence.v2.json";
const PRIOR_EVIDENCE_SHA256 =
  "sha256:61981f53f75f2869b834882d6aa6c358205213c3701de1d91c0ff8d3c9beba7e";
const PRIOR_REPORT_PATH =
  "implementation/p0/f02/reports/protected-surface-gate.v2.json";
const PRIOR_REPORT_SHA256 =
  "sha256:75f5ac92eaedd7478134a9f04fe5d42ac7490484acbf316f920891e234eb0df9";
const ENTERPRISE_NEGATIVE_COMMIT =
  "843df737e35518c9fe4fc47d52fcc7a632757bf2";
const ENTERPRISE_NEGATIVE_TREE =
  "5dfe71b999b0cc2ed020839811af2287005a8ed4";
const ENTERPRISE_PATCH_SHA256 =
  "sha256:1892456154344f4e6c3bd6c203d19eb49f6b081676f330699d4a06948c31bafe";
const CREDENTIAL_NEGATIVE_COMMIT =
  "8c6495feaac7b2e58077aa862c991d8d36622065";
const CREDENTIAL_NEGATIVE_TREE =
  "a79809c7200282d6a04737242b3ee993e2c43ed4";
const CREDENTIAL_PATCH_SHA256 =
  "sha256:a5656e70d52605c300fb2fcf93036ac22c478330da190ad8b6d868e0227d0c06";
const CANARY_BEFORE_FILE_SHA256 =
  "sha256:870f1adccecf3051cbcd9fd307cef51d7633cf510979c181a81f4b1797273493";
const ENTERPRISE_AFTER_FILE_SHA256 =
  "sha256:c7b5bbc2d9488d6a6918d52b717e2c0dbc60559fb3d37cf6c354c5cef4061ce0";
const CREDENTIAL_AFTER_FILE_SHA256 =
  "sha256:92953b8a2050bc1423954ecc92aa9e0310964a04768b754ceb729d8f3f5b5ad8";
const WORKFLOW_PATH = ".github/workflows/f02-protected-surface-gate.yml";
const WORKFLOW_SHA256 =
  "sha256:4ec641f0e4012f39469a2fe03caa018cdf641625313019d6902d8f041d297ec8";
const TEST_PATH = "tests/f02-protected-surface-gate.test.mjs";
const TEST_SHA256 =
  "sha256:348d01295e68755e200b4d1f1f56421809068eb6ad394ae7a7a6dc2a0ebe7ffa";
const POSITIVE_LOG_SHA256 =
  "sha256:41945bd82b551d26e6c4149b9d8d86bc777dbae40f16a0cf1c0bcc403e965b21";
const NEGATIVE_LOG_SHA256 =
  "sha256:8221e0def8e9099a5acfaeaa24731c92e44df776fa7384c162125fabc55818e8";
const CREDENTIAL_LOG_SHA256 =
  "sha256:da509aef42bd3ef1493befdcfb1957bc1f81637c6324fd5fd32d2099a6393726";

const evidence = JSON.parse(
  await readFile(new URL(`../${EVIDENCE_PATH}`, import.meta.url), "utf8"),
);

function clone(value) {
  return structuredClone(value);
}

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
  const copy = clone(value);
  delete copy.evidenceSha256;
  return copy;
}

function assertExactKeys(value, expected) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}

async function validateEvidence(value) {
  assertExactKeys(value, [
    "schemaVersion",
    "evidenceId",
    "recordType",
    "groupId",
    "workPackageIds",
    "acceptanceCriterionIds",
    "classification",
    "status",
    "closureScope",
    "recordedAt",
    "priorLocalEvidenceFreeze",
    "sourceFreeze",
    "repository",
    "workflowTrustBoundary",
    "positiveControl",
    "negativeControls",
    "criterionResults",
    "acceptanceResult",
    "referenceReviewBoundary",
    "governanceBoundary",
    "limitations",
    "evidenceSha256",
  ]);
  assert.equal(
    value.schemaVersion,
    "p0-b04-hosted-ci-supplemental-evidence.v1",
  );
  assert.equal(value.groupId, "P0-B04");
  assert.deepEqual(value.workPackageIds, ["F02", "F04"]);
  assert.deepEqual(value.acceptanceCriterionIds, [
    "F02-AC03",
    "F02-AC04",
    "F02-AC05",
    "F04-AC05",
  ]);
  assert.equal(value.status, "CLOSED");
  assert.equal(
    value.closureScope,
    "HOSTED_CI_POSITIVE_AND_SYNTHETIC_NEGATIVE_CONTROL",
  );
  assert.match(
    value.recordedAt,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
  );

  assertExactKeys(value.priorLocalEvidenceFreeze, [
    "commit",
    "evidence",
    "report",
    "priorStatus",
  ]);
  assertExactKeys(value.priorLocalEvidenceFreeze.evidence, ["path", "sha256"]);
  assertExactKeys(value.priorLocalEvidenceFreeze.report, ["path", "sha256"]);
  assert.deepEqual(value.priorLocalEvidenceFreeze, {
    commit: PRIOR_EVIDENCE_COMMIT,
    evidence: {
      path: PRIOR_EVIDENCE_PATH,
      sha256: PRIOR_EVIDENCE_SHA256,
    },
    report: {
      path: PRIOR_REPORT_PATH,
      sha256: PRIOR_REPORT_SHA256,
    },
    priorStatus: "PARTIAL_EXTERNAL_CI_PENDING",
  });
  assert.equal(
    sha256Bytes(gitBytes(PRIOR_EVIDENCE_COMMIT, PRIOR_EVIDENCE_PATH)),
    PRIOR_EVIDENCE_SHA256,
  );
  assert.equal(
    sha256Bytes(gitBytes(PRIOR_EVIDENCE_COMMIT, PRIOR_REPORT_PATH)),
    PRIOR_REPORT_SHA256,
  );
  const priorEvidence = JSON.parse(
    gitBytes(PRIOR_EVIDENCE_COMMIT, PRIOR_EVIDENCE_PATH).toString("utf8"),
  );
  assert.equal(priorEvidence.hosted_ci_execution_status, "EXTERNAL_PENDING");
  assert.equal(priorEvidence.overall_completion, "PARTIAL_EXTERNAL_CI_PENDING");

  assertExactKeys(value.sourceFreeze, [
    "commit",
    "parent",
    "tree",
    "artifacts",
  ]);
  for (const artifact of value.sourceFreeze.artifacts) {
    assertExactKeys(artifact, ["path", "sha256"]);
  }
  execFileSync("git", ["cat-file", "-e", `${value.sourceFreeze.commit}^{commit}`], {
    cwd: REPOSITORY_ROOT,
  });
  assert.equal(value.sourceFreeze.commit, SOURCE_COMMIT);
  assert.equal(value.sourceFreeze.parent, SOURCE_PARENT);
  assert.equal(value.sourceFreeze.tree, SOURCE_TREE);
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
  assert.deepEqual(value.sourceFreeze.artifacts, [
    { path: WORKFLOW_PATH, sha256: WORKFLOW_SHA256 },
    { path: TEST_PATH, sha256: TEST_SHA256 },
  ]);
  for (const artifact of value.sourceFreeze.artifacts) {
    assert.equal(sha256Bytes(gitBytes(SOURCE_COMMIT, artifact.path)), artifact.sha256);
  }

  assertExactKeys(value.repository, [
    "url",
    "visibility",
    "defaultBranch",
    "allowForking",
    "workflowDefaultPermission",
    "canApprovePullRequestReviews",
    "securityAndAnalysis",
  ]);
  assertExactKeys(value.repository.securityAndAnalysis, [
    "repositoryField",
    "secretScanning",
    "codeScanning",
  ]);
  for (const assessment of [
    value.repository.securityAndAnalysis.secretScanning,
    value.repository.securityAndAnalysis.codeScanning,
  ]) {
    assertExactKeys(assessment, [
      "status",
      "endpoint",
      "httpStatus",
      "stableMessage",
    ]);
  }
  assert.deepEqual(value.repository, {
    url: "https://github.com/zhangjuntian787981-lab/zb-aios",
    visibility: "private",
    defaultBranch: "main",
    allowForking: true,
    workflowDefaultPermission: "read",
    canApprovePullRequestReviews: false,
    securityAndAnalysis: {
      repositoryField: null,
      secretScanning: {
        status: "DISABLED",
        endpoint:
          "/repos/zhangjuntian787981-lab/zb-aios/secret-scanning/alerts",
        httpStatus: 404,
        stableMessage: "Secret scanning is disabled on this repository.",
      },
      codeScanning: {
        status: "NOT_ENABLED",
        endpoint:
          "/repos/zhangjuntian787981-lab/zb-aios/code-scanning/alerts",
        httpStatus: 403,
        stableMessage: "Code scanning is not enabled for this repository.",
      },
    },
  });

  assertExactKeys(value.workflowTrustBoundary, [
    "trigger",
    "pullRequestTargetEnabled",
    "permissions",
    "runnerLabel",
    "checkoutAction",
    "setupNodeAction",
    "dependencyCacheEnabled",
    "installCommand",
    "buildCommand",
    "selfHostedRunnerUsed",
  ]);
  assertExactKeys(value.workflowTrustBoundary.permissions, ["contents"]);
  assertExactKeys(value.workflowTrustBoundary.checkoutAction, [
    "repository",
    "commit",
    "persistCredentials",
  ]);
  assertExactKeys(value.workflowTrustBoundary.setupNodeAction, [
    "repository",
    "commit",
    "configuredNodeVersion",
  ]);
  assert.deepEqual(value.workflowTrustBoundary, {
    trigger: "pull_request",
    pullRequestTargetEnabled: false,
    permissions: { contents: "read" },
    runnerLabel: "ubuntu-24.04",
    checkoutAction: {
      repository: "actions/checkout",
      commit: "11d5960a326750d5838078e36cf38b85af677262",
      persistCredentials: false,
    },
    setupNodeAction: {
      repository: "actions/setup-node",
      commit: "49933ea5288caeca8642d1e84afbd3f7d6820020",
      configuredNodeVersion: "24",
    },
    dependencyCacheEnabled: false,
    installCommand: "npm ci --ignore-scripts --no-audit --no-fund",
    buildCommand: "npm run build",
    selfHostedRunnerUsed: false,
  });

  assertExactKeys(value.positiveControl, [
    "controlKind",
    "pullRequest",
    "run",
    "gateResult",
  ]);
  assertExactKeys(value.positiveControl.pullRequest, [
    "number",
    "url",
    "state",
    "draft",
    "merged",
    "baseBranch",
    "baseSha",
    "headBranch",
    "headSha",
    "createdAt",
    "updatedAt",
  ]);
  assertExactKeys(value.positiveControl.run, [
    "runId",
    "runNumber",
    "url",
    "event",
    "headBranch",
    "headSha",
    "status",
    "conclusion",
    "createdAt",
    "updatedAt",
    "jobId",
    "jobUrl",
    "startedAt",
    "completedAt",
    "runner",
    "log",
  ]);
  assertExactKeys(value.positiveControl.run.runner, [
    "runnerVersion",
    "provisionerVersion",
    "image",
    "imageVersion",
    "includedSoftwareUrl",
    "imageReleaseUrl",
  ]);
  assertExactKeys(value.positiveControl.run.log, ["byteLength", "sha256"]);
  assertExactKeys(value.positiveControl.gateResult, [
    "buildConclusion",
    "prebuildStatus",
    "prebuildFindingCount",
    "releaseStatus",
    "releaseFindingCount",
  ]);
  assert.equal(value.positiveControl.pullRequest.number, 1);
  assert.equal(value.positiveControl.pullRequest.state, "OPEN");
  assert.equal(value.positiveControl.pullRequest.draft, true);
  assert.equal(value.positiveControl.pullRequest.merged, false);
  assert.equal(value.positiveControl.pullRequest.baseSha, SOURCE_PARENT);
  assert.equal(value.positiveControl.pullRequest.headSha, SOURCE_COMMIT);
  assert.equal(value.positiveControl.run.runId, 30494004076);
  assert.equal(value.positiveControl.run.runNumber, 1);
  assert.equal(value.positiveControl.run.event, "pull_request");
  assert.equal(value.positiveControl.run.headSha, SOURCE_COMMIT);
  assert.equal(value.positiveControl.run.conclusion, "success");
  assert.equal(value.positiveControl.run.jobId, 90718468551);
  assert.equal(value.positiveControl.run.log.byteLength, 44921);
  assert.equal(value.positiveControl.run.log.sha256, POSITIVE_LOG_SHA256);
  assert.deepEqual(value.positiveControl.run.runner, {
    runnerVersion: "2.336.0",
    provisionerVersion: "20260707.563",
    image: "ubuntu-24.04",
    imageVersion: "20260720.247.2",
    includedSoftwareUrl:
      "https://github.com/actions/runner-images/blob/ubuntu24/20260720.247/images/ubuntu/Ubuntu2404-Readme.md",
    imageReleaseUrl:
      "https://github.com/actions/runner-images/releases/tag/ubuntu24%2F20260720.247",
  });
  assert.deepEqual(value.positiveControl.gateResult, {
    buildConclusion: "success",
    prebuildStatus: "PASS",
    prebuildFindingCount: 0,
    releaseStatus: "PASS",
    releaseFindingCount: 0,
  });

  assert.equal(value.negativeControls.length, 2);
  const [enterpriseControl, credentialControl] = value.negativeControls;
  for (const control of value.negativeControls) {
    assertExactKeys(control, [
      "controlKind",
      "canary",
      "pullRequest",
      "run",
      "gateResult",
    ]);
    assertExactKeys(control.canary, [
      "commit",
      "parent",
      "tree",
      "patchSha256",
      "path",
      "surfaceId",
      "beforeFileSha256",
      "afterFileSha256",
      "changedFileCount",
      "insertedLineCount",
      "rawCanaryPersistedInEvidence",
    ]);
    assertExactKeys(control.pullRequest, [
      "number",
      "url",
      "state",
      "draft",
      "merged",
      "baseBranch",
      "baseSha",
      "headBranch",
      "headSha",
      "createdAt",
      "closedAt",
    ]);
    assertExactKeys(control.run, [
      "runId",
      "runNumber",
      "url",
      "event",
      "headBranch",
      "headSha",
      "status",
      "conclusion",
      "createdAt",
      "updatedAt",
      "jobId",
      "jobUrl",
      "startedAt",
      "completedAt",
      "log",
    ]);
    assertExactKeys(control.run.log, ["byteLength", "sha256"]);
    assertExactKeys(control.gateResult, [
      "buildConclusion",
      "prebuildStatus",
      "findingCount",
      "ruleIds",
      "processExitCode",
      "releaseExecuted",
    ]);
  }

  execFileSync(
    "git",
    ["cat-file", "-e", `${ENTERPRISE_NEGATIVE_COMMIT}^{commit}`],
    { cwd: REPOSITORY_ROOT },
  );
  assert.equal(
    execFileSync(
      "git",
      ["show", "-s", "--format=%P", ENTERPRISE_NEGATIVE_COMMIT],
      { cwd: REPOSITORY_ROOT, encoding: "utf8" },
    ).trim(),
    SOURCE_COMMIT,
  );
  assert.equal(enterpriseControl.controlKind, "SYNTHETIC_ENTERPRISE_IDENTIFIER");
  assert.equal(enterpriseControl.canary.commit, ENTERPRISE_NEGATIVE_COMMIT);
  assert.equal(enterpriseControl.canary.tree, ENTERPRISE_NEGATIVE_TREE);
  assert.equal(enterpriseControl.canary.patchSha256, ENTERPRISE_PATCH_SHA256);
  assert.equal(
    sha256Bytes(gitPatchBytes(SOURCE_COMMIT, ENTERPRISE_NEGATIVE_COMMIT)),
    ENTERPRISE_PATCH_SHA256,
  );
  assert.equal(enterpriseControl.canary.path, "eslint.config.mjs");
  assert.equal(enterpriseControl.canary.surfaceId, "SOURCE_CODE");
  assert.equal(enterpriseControl.canary.rawCanaryPersistedInEvidence, false);
  assert.equal(
    enterpriseControl.canary.beforeFileSha256,
    CANARY_BEFORE_FILE_SHA256,
  );
  assert.equal(
    enterpriseControl.canary.afterFileSha256,
    ENTERPRISE_AFTER_FILE_SHA256,
  );
  assert.equal(
    sha256Bytes(gitBytes(ENTERPRISE_NEGATIVE_COMMIT, enterpriseControl.canary.path)),
    enterpriseControl.canary.afterFileSha256,
  );
  assert.equal(enterpriseControl.pullRequest.number, 2);
  assert.equal(enterpriseControl.pullRequest.state, "CLOSED");
  assert.equal(enterpriseControl.pullRequest.draft, true);
  assert.equal(enterpriseControl.pullRequest.merged, false);
  assert.equal(enterpriseControl.pullRequest.baseSha, SOURCE_PARENT);
  assert.equal(
    enterpriseControl.pullRequest.headSha,
    ENTERPRISE_NEGATIVE_COMMIT,
  );
  assert.equal(enterpriseControl.run.runId, 30494153685);
  assert.equal(enterpriseControl.run.runNumber, 2);
  assert.equal(enterpriseControl.run.event, "pull_request");
  assert.equal(enterpriseControl.run.headSha, ENTERPRISE_NEGATIVE_COMMIT);
  assert.equal(enterpriseControl.run.conclusion, "failure");
  assert.equal(enterpriseControl.run.jobId, 90718947248);
  assert.equal(enterpriseControl.run.log.byteLength, 35581);
  assert.equal(enterpriseControl.run.log.sha256, NEGATIVE_LOG_SHA256);
  assert.deepEqual(enterpriseControl.gateResult, {
    buildConclusion: "failure",
    prebuildStatus: "BLOCKED",
    findingCount: 1,
    ruleIds: ["ENTERPRISE_IDENTIFIER"],
    processExitCode: 1,
    releaseExecuted: false,
  });

  execFileSync(
    "git",
    ["cat-file", "-e", `${CREDENTIAL_NEGATIVE_COMMIT}^{commit}`],
    { cwd: REPOSITORY_ROOT },
  );
  assert.equal(
    execFileSync(
      "git",
      ["show", "-s", "--format=%P", CREDENTIAL_NEGATIVE_COMMIT],
      { cwd: REPOSITORY_ROOT, encoding: "utf8" },
    ).trim(),
    SOURCE_COMMIT,
  );
  assert.equal(credentialControl.controlKind, "SYNTHETIC_CREDENTIAL_PATTERNS");
  assert.equal(credentialControl.canary.commit, CREDENTIAL_NEGATIVE_COMMIT);
  assert.equal(credentialControl.canary.tree, CREDENTIAL_NEGATIVE_TREE);
  assert.equal(credentialControl.canary.patchSha256, CREDENTIAL_PATCH_SHA256);
  assert.equal(
    sha256Bytes(gitPatchBytes(SOURCE_COMMIT, CREDENTIAL_NEGATIVE_COMMIT)),
    CREDENTIAL_PATCH_SHA256,
  );
  assert.equal(credentialControl.canary.path, "eslint.config.mjs");
  assert.equal(credentialControl.canary.surfaceId, "SOURCE_CODE");
  assert.equal(credentialControl.canary.rawCanaryPersistedInEvidence, false);
  assert.equal(
    credentialControl.canary.beforeFileSha256,
    CANARY_BEFORE_FILE_SHA256,
  );
  assert.equal(
    credentialControl.canary.afterFileSha256,
    CREDENTIAL_AFTER_FILE_SHA256,
  );
  assert.equal(
    sha256Bytes(gitBytes(CREDENTIAL_NEGATIVE_COMMIT, credentialControl.canary.path)),
    credentialControl.canary.afterFileSha256,
  );
  assert.equal(credentialControl.pullRequest.number, 3);
  assert.equal(credentialControl.pullRequest.state, "CLOSED");
  assert.equal(credentialControl.pullRequest.draft, true);
  assert.equal(credentialControl.pullRequest.merged, false);
  assert.equal(credentialControl.pullRequest.baseSha, SOURCE_PARENT);
  assert.equal(
    credentialControl.pullRequest.headSha,
    CREDENTIAL_NEGATIVE_COMMIT,
  );
  assert.equal(credentialControl.run.runId, 30494769365);
  assert.equal(credentialControl.run.runNumber, 3);
  assert.equal(credentialControl.run.event, "pull_request");
  assert.equal(credentialControl.run.headSha, CREDENTIAL_NEGATIVE_COMMIT);
  assert.equal(credentialControl.run.conclusion, "failure");
  assert.equal(credentialControl.run.jobId, 90720899524);
  assert.equal(credentialControl.run.log.byteLength, 36738);
  assert.equal(credentialControl.run.log.sha256, CREDENTIAL_LOG_SHA256);
  assert.deepEqual(credentialControl.gateResult, {
    buildConclusion: "failure",
    prebuildStatus: "BLOCKED",
    findingCount: 3,
    ruleIds: ["CONNECTION_STRING", "PRIVATE_KEY", "TOKEN"],
    processExitCode: 1,
    releaseExecuted: false,
  });

  assert.deepEqual(value.criterionResults, [
    {
      criterionId: "F02-AC03",
      status: "PASS",
      scope: "REGISTERED_TEXT_SURFACES_ONLY",
    },
    {
      criterionId: "F02-AC04",
      status: "PASS",
      scope: "HOSTED_ENTERPRISE_IDENTIFIER_CANARY",
    },
    {
      criterionId: "F02-AC05",
      status: "PASS",
      scope:
        "LOCAL_ALL_SURFACE_CREDENTIAL_CANARIES_AND_HOSTED_REGISTERED_SOURCE_CONTROL",
    },
    {
      criterionId: "F04-AC05",
      status: "PASS",
      scope: "REGISTERED_TEXT_SURFACES_ONLY",
    },
  ]);

  for (const result of value.criterionResults) {
    assertExactKeys(result, ["criterionId", "status", "scope"]);
  }
  assertExactKeys(value.acceptanceResult, [
    "status",
    "statement",
    "positiveHostedRunProved",
    "negativeHostedBlockProved",
    "enterpriseDataUsed",
  ]);
  assert.deepEqual(value.acceptanceResult, {
    status: "PASS",
    statement:
      "P0-B04 hosted-CI execution is closed by one successful pull_request run of the frozen gate and two synthetic registered-surface canary runs that failed closed; no broader secret-scanning, fork, binary, or unregistered-path claim is made.",
    positiveHostedRunProved: true,
    negativeHostedBlockProved: true,
    enterpriseDataUsed: false,
  });
  assertExactKeys(value.referenceReviewBoundary, [
    "formalReceiptCreated",
    "currentCatalogAndPolicyCoverThisAdoption",
    "profileReadinessProved",
  ]);
  assert.deepEqual(value.referenceReviewBoundary, {
    formalReceiptCreated: false,
    currentCatalogAndPolicyCoverThisAdoption: false,
    profileReadinessProved: false,
  });
  assertExactKeys(value.governanceBoundary, [
    "p0B04EvidenceClosed",
    "supplementalEvidenceIndexUpdated",
    "d1Written",
    "workPackageStatusChanged",
    "gateStatusChanged",
    "manifestChanged",
    "profileApproved",
    "startAuthorized",
    "pullRequestsMerged",
  ]);
  assert.deepEqual(value.governanceBoundary, {
    p0B04EvidenceClosed: true,
    supplementalEvidenceIndexUpdated: false,
    d1Written: false,
    workPackageStatusChanged: false,
    gateStatusChanged: false,
    manifestChanged: false,
    profileApproved: false,
    startAuthorized: false,
    pullRequestsMerged: false,
  });
  assert.ok(
    value.limitations.some((item) =>
      item.includes("GitHub Secret Scanning is disabled"),
    ),
  );
  assert.ok(
    value.limitations.some((item) =>
      item.includes("fork-origin pull request was not exercised"),
    ),
  );
  assert.ok(
    value.limitations.some((item) =>
      item.includes("unknown secret formats, binary payloads, or unregistered paths"),
    ),
  );
  assert.equal(
    await sha256ProjectValue(withoutSelfHash(value)),
    value.evidenceSha256,
  );
}

test("P0-B04 hosted evidence freezes the exact positive and negative controls", async () => {
  await validateEvidence(evidence);
});

test("P0-B04 evidence cannot overclaim Secret Scanning, fork coverage, or a merge", () => {
  const serialized = JSON.stringify(evidence);
  assert.equal(
    evidence.repository.securityAndAnalysis.secretScanning.status,
    "DISABLED",
  );
  assert.equal(
    evidence.repository.securityAndAnalysis.codeScanning.status,
    "NOT_ENABLED",
  );
  assert.equal(evidence.positiveControl.pullRequest.merged, false);
  assert.ok(evidence.negativeControls.every((item) => item.pullRequest.merged === false));
  assert.equal(evidence.governanceBoundary.pullRequestsMerged, false);
  assert.doesNotMatch(serialized, /"secretScanningEnabled":true/);
  assert.doesNotMatch(serialized, /"forkPullRequestTested":true/);
  assert.equal(
    serialized.includes(["sk", "synthetic", "canary", "1234567890"].join("-")),
    false,
  );
  assert.equal(
    serialized.includes(["BEGIN", "PRIVATE", "KEY"].join(" ")),
    false,
  );
  assert.equal(serialized.includes(["postgresql", "://"].join("")), false);
});

test("P0-B04 evidence self-hash rejects a changed hosted result", async () => {
  const tampered = clone(evidence);
  tampered.negativeControls[1].gateResult.findingCount = 0;
  await assert.rejects(() => validateEvidence(tampered));
});

test("P0-B04 evidence remains supplemental and cannot change governance state", () => {
  assert.equal(evidence.governanceBoundary.d1Written, false);
  assert.equal(evidence.governanceBoundary.workPackageStatusChanged, false);
  assert.equal(evidence.governanceBoundary.gateStatusChanged, false);
  assert.equal(evidence.governanceBoundary.manifestChanged, false);
  assert.equal(evidence.governanceBoundary.profileApproved, false);
  assert.equal(evidence.governanceBoundary.startAuthorized, false);
  assert.equal(evidence.referenceReviewBoundary.formalReceiptCreated, false);
  assert.equal(evidence.referenceReviewBoundary.profileReadinessProved, false);
});
