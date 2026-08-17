import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "../lib/project-control.mjs";

const ROOT = new URL("..", import.meta.url);
const EVIDENCE_PATH =
  "implementation/p1/c13/p1-b11-protected-review-preparation-evidence.v1.json";
const CLOSURE_EVIDENCE_PATH =
  "implementation/p1/c13/p1-b11-model-only-protected-review-evidence.v1.json";
const SOURCE_COMMIT = "9e14804015e022ffae90696b04fdb37edd31e992";
const SOURCE_PARENT = "5d12201e984937a905ab8bae90a86a4b1763d899";
const SOURCE_TREE = "cfe2b281543bc354fe4cdda259d2acd6bf870927";
const SOURCE_PATCH_SHA256 =
  "sha256:382c30b8677785581f1eef6b298b82f9c6e9a4eba8b70c7410fcb7271cd216f7";
const EXPECTED_LIMITATIONS = [
  "The successful hosted checks prove execution of the frozen synthetic source-review boundary, not enforcement of a branch Ruleset.",
  "Zero CODEOWNERS parse errors prove that the branch policy parses; they do not prove that a second real human reviewer approved the change.",
  "The current private-repository plan returns HTTP 403 for Rulesets and classic branch protection.",
  "Only one write-capable human is present, so independent Code Owner review remains INCONCLUSIVE.",
  "No protected negative control has proved that an unapproved or failing change is denied at merge time; this evidence does not prove merge denial.",
  "Making the repository public is not authorized as a substitute for the missing private-repository capability.",
];
const REQUIRED_CHECKS = [
  "protected-surface-gate",
  "contract-compatibility-gate",
  "c13-source-review-gate",
  "independent-model-review",
];
const POSITIVE_HEAD = "fa9b353644314f70a1849d0def1396301e136240";
const POSITIVE_TREE = "ab913a2ec5c75e932eeff56429ed08329c4352e1";
const MISSING_HEAD = "eb9aabf016eabde1923fdac2c837f5017f22fa4b";
const MAIN_HEAD = "bcc314f65709aebb21dc5afa923753a224a6de4c";
const DIRECT_PUSH_COMMIT = "f162fb34302994ef0b2cc458cac26a8950e7f22b";
const GIT_ENV = {
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_ATTR_NOSYSTEM: "1",
  LANG: "C",
  LC_ALL: "C",
};

const evidence = JSON.parse(
  await readFile(new URL(`../${EVIDENCE_PATH}`, import.meta.url), "utf8"),
);
const closureEvidence = JSON.parse(
  await readFile(
    new URL(`../${CLOSURE_EVIDENCE_PATH}`, import.meta.url),
    "utf8",
  ),
);

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function gitBytes(commit, path) {
  return execFileSync("/usr/bin/git", ["show", `${commit}:${path}`], {
    cwd: ROOT,
    env: GIT_ENV,
  });
}

function gitValue(format, commit) {
  return execFileSync("/usr/bin/git", ["show", "-s", `--format=${format}`, commit], {
    cwd: ROOT,
    encoding: "utf8",
    env: GIT_ENV,
  }).trim();
}

function withoutSelfHash(value) {
  const copy = structuredClone(value);
  delete copy.evidenceSha256;
  return copy;
}

function assertExactKeys(value, expected) {
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort());
}

function assertNoSensitiveMaterial(value) {
  const forbiddenKey =
    /^(?:actorId|authorization|cookie|email|requestHeaders|secret|token)$/i;
  const forbiddenContent =
    /(?:[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|\b(?:Cookie|Set-Cookie)\s*:|\bAuthorization\s*:\s*(?:Basic|Bearer)\b|\bBasic\s+[A-Za-z0-9+/=]{8,}|\bBearer\s+[A-Za-z0-9._-]{8,}|gh[opsu]_[A-Za-z0-9]{8,}|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b|[?&](?:access_token|api_key|apikey|client_secret|password)=|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY)/i;
  const visit = (current) => {
    if (Array.isArray(current)) {
      current.forEach(visit);
      return;
    }
    if (current && typeof current === "object") {
      for (const [key, nested] of Object.entries(current)) {
        assert.doesNotMatch(key, forbiddenKey);
        visit(nested);
      }
      return;
    }
    if (typeof current === "string") {
      assert.doesNotMatch(current, forbiddenContent);
    }
  };
  visit(value);
}

async function validateEvidence(value) {
  assertExactKeys(value, [
    "schemaVersion",
    "evidenceId",
    "recordType",
    "groupId",
    "workPackageId",
    "acceptanceCriterionId",
    "classification",
    "status",
    "recordedAt",
    "sourceFreeze",
    "pullRequest",
    "hostedChecks",
    "codeownersReadback",
    "rulesetCandidate",
    "capabilityBoundary",
    "criterionAssessment",
    "governanceBoundary",
    "limitations",
    "evidenceSha256",
  ]);
  assertExactKeys(value.sourceFreeze, [
    "commit",
    "parent",
    "tree",
    "patchSha256",
    "branch",
    "artifacts",
  ]);
  assertExactKeys(value.pullRequest, [
    "number",
    "url",
    "state",
    "draft",
    "merged",
    "baseBranch",
    "baseSha",
    "headBranch",
    "headSha",
    "mergeStateStatus",
    "reviewDecision",
    "createdAt",
  ]);
  assertExactKeys(value.hostedChecks, [
    "integrationId",
    "requiredCandidateChecks",
    "c13SourceReview",
    "contractCompatibility",
    "protectedSurface",
  ]);
  assertExactKeys(value.hostedChecks.c13SourceReview, [
    "runId",
    "runNumber",
    "workflowId",
    "runUrl",
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
    "gateResult",
  ]);
  assertExactKeys(value.hostedChecks.c13SourceReview.runner, [
    "runnerVersion",
    "provisionerVersion",
    "image",
    "imageVersion",
    "nodeVersion",
    "npmVersion",
    "includedSoftwareUrl",
    "imageReleaseUrl",
  ]);
  assertExactKeys(value.hostedChecks.c13SourceReview.log, [
    "byteLength",
    "sha256",
  ]);
  assertExactKeys(value.hostedChecks.c13SourceReview.gateResult, [
    "testCount",
    "passedCount",
    "failedCount",
  ]);
  for (const check of [
    value.hostedChecks.contractCompatibility,
    value.hostedChecks.protectedSurface,
  ]) {
    assertExactKeys(check, [
      "runId",
      "runUrl",
      "headSha",
      "status",
      "conclusion",
      "createdAt",
      "updatedAt",
      "jobId",
    ]);
  }
  assertExactKeys(value.codeownersReadback, [
    "ref",
    "observedAt",
    "httpStatus",
    "errorCount",
    "errors",
  ]);
  assertExactKeys(value.rulesetCandidate, [
    "path",
    "fileSha256",
    "status",
    "target",
    "desiredEnforcement",
    "bypassActors",
    "remoteEnforcementProved",
  ]);
  assertExactKeys(value.capabilityBoundary, [
    "auditPath",
    "auditFileSha256",
    "auditSha256",
    "repositoryVisibility",
    "privateRepositoryRulesCapability",
    "rulesetProbeHttpStatus",
    "classicProtectionProbeHttpStatus",
    "writeCapableHumanCount",
    "independentHumanReviewer",
    "automaticPublicVisibilityChangeAuthorized",
  ]);
  assertExactKeys(value.criterionAssessment, [
    "codeownersSyntax",
    "hostedCheckExecution",
    "rulesetEnforcement",
    "independentCodeOwnerReview",
    "unapprovedMergeDenied",
    "overall",
  ]);
  assertExactKeys(value.governanceBoundary, [
    "d1EventCreated",
    "workPackageStateChanged",
    "gateChanged",
    "p1B11Closed",
    "profileApproved",
    "o02Authorized",
    "o03Authorized",
    "isProgressTracker",
  ]);
  assertNoSensitiveMaterial(value);
  assert.equal(value.schemaVersion, "p1-b11-protected-review-preparation-evidence.v1");
  assert.equal(value.groupId, "P1-B11");
  assert.equal(value.workPackageId, "C13");
  assert.equal(value.acceptanceCriterionId, "C13-AC02");
  assert.equal(value.classification, "CANDIDATE_PREPARATION");
  assert.equal(value.status, "PREPARED_NOT_ENFORCED");
  assert.equal(value.sourceFreeze.commit, SOURCE_COMMIT);
  assert.equal(value.sourceFreeze.parent, SOURCE_PARENT);
  assert.equal(value.sourceFreeze.tree, SOURCE_TREE);
  assert.equal(value.sourceFreeze.patchSha256, SOURCE_PATCH_SHA256);
  assert.equal(value.pullRequest.number, 6);
  assert.equal(
    value.pullRequest.url,
    "https://github.com/zhangjuntian787981-lab/zb-aios/pull/6",
  );
  assert.equal(value.pullRequest.draft, true);
  assert.equal(value.pullRequest.merged, false);
  assert.equal(value.pullRequest.headSha, SOURCE_COMMIT);
  assert.equal(value.hostedChecks.c13SourceReview.status, "completed");
  assert.equal(value.hostedChecks.c13SourceReview.conclusion, "success");
  assert.equal(
    value.hostedChecks.c13SourceReview.runUrl,
    "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30498992738",
  );
  assert.equal(
    value.hostedChecks.c13SourceReview.jobUrl,
    "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30498992738/job/90734205670",
  );
  assert.equal(
    value.hostedChecks.c13SourceReview.runner.includedSoftwareUrl,
    "https://github.com/actions/runner-images/blob/ubuntu24/20260726.254/images/ubuntu/Ubuntu2404-Readme.md",
  );
  assert.equal(
    value.hostedChecks.c13SourceReview.runner.imageReleaseUrl,
    "https://github.com/actions/runner-images/releases/tag/ubuntu24%2F20260726.254",
  );
  assert.equal(
    value.hostedChecks.contractCompatibility.runUrl,
    "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30498992695",
  );
  assert.equal(
    value.hostedChecks.protectedSurface.runUrl,
    "https://github.com/zhangjuntian787981-lab/zb-aios/actions/runs/30498992706",
  );
  assert.equal(value.hostedChecks.c13SourceReview.gateResult.testCount, 20);
  assert.equal(value.hostedChecks.c13SourceReview.gateResult.passedCount, 20);
  assert.equal(value.hostedChecks.c13SourceReview.gateResult.failedCount, 0);
  assert.equal(value.codeownersReadback.errorCount, 0);
  assert.deepEqual(value.codeownersReadback.errors, []);
  assert.equal(value.rulesetCandidate.status, "CANDIDATE_NOT_APPLIED");
  assert.equal(value.rulesetCandidate.remoteEnforcementProved, false);
  assert.deepEqual(value.rulesetCandidate.bypassActors, []);
  assert.equal(
    value.capabilityBoundary.privateRepositoryRulesCapability,
    "BLOCKED_BY_GITHUB_PLAN",
  );
  assert.equal(value.capabilityBoundary.independentHumanReviewer, "MISSING");
  assert.equal(value.criterionAssessment.codeownersSyntax, "PASS");
  assert.equal(value.criterionAssessment.hostedCheckExecution, "PASS");
  assert.equal(
    value.criterionAssessment.rulesetEnforcement,
    "BLOCKED_BY_GITHUB_PLAN",
  );
  assert.equal(value.criterionAssessment.independentCodeOwnerReview, "INCONCLUSIVE");
  assert.equal(value.criterionAssessment.unapprovedMergeDenied, "NOT_RUN_BLOCKED");
  assert.equal(value.criterionAssessment.overall, "INCONCLUSIVE");
  assert.equal(value.governanceBoundary.d1EventCreated, false);
  assert.equal(value.governanceBoundary.workPackageStateChanged, false);
  assert.equal(value.governanceBoundary.p1B11Closed, false);
  assert.equal(value.governanceBoundary.profileApproved, false);
  assert.equal(value.governanceBoundary.o02Authorized, false);
  assert.equal(value.governanceBoundary.o03Authorized, false);
  assert.deepEqual(value.limitations, EXPECTED_LIMITATIONS);
  assert.equal(
    value.evidenceSha256,
    await sha256ProjectValue(withoutSelfHash(value)),
  );
}

async function validateClosureEvidence(value) {
  assertExactKeys(value, [
    "schemaVersion",
    "evidenceId",
    "recordType",
    "groupId",
    "workPackageId",
    "acceptanceCriterionId",
    "classification",
    "status",
    "recordedAt",
    "evidenceSources",
    "rulesetEnforcement",
    "remoteExecutionEvidence",
    "localFailClosedContractEvidence",
    "criterionAssessment",
    "historicalPreservation",
    "freezeCommitRule",
    "governanceBoundary",
    "limitations",
    "evidenceSha256",
  ]);
  assert.equal(
    value.schemaVersion,
    "p1-b11-model-only-protected-review-evidence.v1",
  );
  assert.equal(value.recordType, "SUPPLEMENTAL_ACCEPTANCE_EVIDENCE");
  assert.equal(value.groupId, "P1-B11");
  assert.equal(value.workPackageId, "C13");
  assert.equal(value.acceptanceCriterionId, "C13-AC02");
  assert.equal(value.classification, "B_SUPPLEMENTAL_EVIDENCE");
  assert.equal(value.status, "CLOSED");
  assert.match(value.recordedAt, /^2026-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$/u);
  assertExactKeys(value.evidenceSources, [
    "activePolicy",
    "targetedReviewEvidence",
    "rulesetCandidate",
  ]);
  assertExactKeys(value.evidenceSources.activePolicy, [
    "path",
    "freezeCommit",
    "rawSha256",
  ]);
  assertExactKeys(value.evidenceSources.targetedReviewEvidence, [
    "path",
    "freezeCommit",
    "rawSha256",
  ]);
  assertExactKeys(value.evidenceSources.rulesetCandidate, [
    "path",
    "freezeCommit",
    "rawSha256",
    "payloadCanonicalSha256",
  ]);
  assert.deepEqual(value.evidenceSources, closureEvidence.evidenceSources);
  for (const binding of Object.values(value.evidenceSources)) {
    assert.match(binding.path, /^(?:implementation|tests|scripts)\//u);
    assert.match(binding.freezeCommit, /^[a-f0-9]{40}$/u);
    assert.match(binding.rawSha256, /^sha256:[a-f0-9]{64}$/u);
  }
  assert.equal(value.rulesetEnforcement.rulesetId, 20780723);
  assert.equal(value.rulesetEnforcement.rulesetVersion, 46398696);
  assertExactKeys(value.rulesetEnforcement, [
    "rulesetId",
    "rulesetVersion",
    "observedAt",
    "rulesetReadback",
    "effectiveMainRulesReadback",
  ]);
  for (const readback of [
    value.rulesetEnforcement.rulesetReadback,
    value.rulesetEnforcement.effectiveMainRulesReadback,
  ]) {
    assertExactKeys(readback, [
      "captureSource",
      "rawResponseArtifactCaptured",
      "canonicalResponse",
      "canonicalByteLength",
      "canonicalResponseSha256",
    ]);
    assert.equal(readback.captureSource, "LIVE_API_READBACK");
    assert.equal(readback.rawResponseArtifactCaptured, false);
    assert.equal(
      Buffer.byteLength(canonicalizeProjectJson(readback.canonicalResponse)),
      readback.canonicalByteLength,
    );
    assert.equal(
      await sha256ProjectValue(readback.canonicalResponse),
      readback.canonicalResponseSha256,
    );
  }
  const ruleset = value.rulesetEnforcement.rulesetReadback.canonicalResponse;
  assert.deepEqual(ruleset, closureEvidence.rulesetEnforcement.rulesetReadback.canonicalResponse);
  assert.deepEqual(
    value.rulesetEnforcement.effectiveMainRulesReadback.canonicalResponse,
    closureEvidence.rulesetEnforcement.effectiveMainRulesReadback.canonicalResponse,
  );

  const remote = value.remoteExecutionEvidence;
  assert.equal(remote.evidenceClass, "REMOTE_EXECUTION_EVIDENCE");
  assertExactKeys(remote, [
    "evidenceClass",
    "positiveControl",
    "missingAndStaleControl",
    "directPushControl",
    "priorFailureObservation",
  ]);
  for (const control of [
    remote.positiveControl,
    remote.missingAndStaleControl,
    remote.directPushControl,
  ]) {
    assert.equal(control.rawResponseArtifactCaptured, false);
    assert.equal(
      Buffer.byteLength(canonicalizeProjectJson(control.canonicalResponse)),
      control.canonicalByteLength,
    );
    assert.equal(
      await sha256ProjectValue(control.canonicalResponse),
      control.canonicalResponseSha256,
    );
  }
  assert.deepEqual(
    remote.positiveControl,
    closureEvidence.remoteExecutionEvidence.positiveControl,
  );
  assert.deepEqual(
    remote.missingAndStaleControl,
    closureEvidence.remoteExecutionEvidence.missingAndStaleControl,
  );
  assert.deepEqual(
    remote.directPushControl,
    closureEvidence.remoteExecutionEvidence.directPushControl,
  );
  assert.equal(remote.positiveControl.captureSource, "MAIN_THREAD_TOOL_OUTPUT");
  assert.equal(
    remote.positiveControl.canonicalResponse.pullRequest.headRefOid,
    POSITIVE_HEAD,
  );
  assert.equal(
    remote.positiveControl.canonicalResponse.pullRequest.headTree,
    POSITIVE_TREE,
  );
  assert.equal(
    remote.positiveControl.canonicalResponse.pullRequest.mergeStateStatus,
    "CLEAN",
  );
  assert.deepEqual(
    remote.positiveControl.canonicalResponse.requiredChecks.map(
      ({ context }) => context,
    ),
    REQUIRED_CHECKS,
  );
  for (const check of remote.positiveControl.canonicalResponse.requiredChecks) {
    assert.equal(check.headSha, POSITIVE_HEAD);
    assert.equal(check.status, "COMPLETED");
    assert.equal(check.conclusion, "SUCCESS");
    assert.equal(check.publisher, "GitHub Actions");
    assert.equal(check.integrationId, 15368);
    assert.equal(check.isRequired, true);
  }
  assert.equal(remote.positiveControl.modelReviewDecision, "CLEAR");
  assert.equal(
    remote.positiveControl.modelReviewConclusion,
    "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  );
  assert.equal(remote.missingAndStaleControl.captureSource, "LIVE_API_READBACK");
  assert.equal(remote.missingAndStaleControl.commit, MISSING_HEAD);
  assert.equal(remote.missingAndStaleControl.parent, POSITIVE_HEAD);
  assert.equal(remote.missingAndStaleControl.tree, POSITIVE_TREE);
  assert.match(remote.missingAndStaleControl.commitMessage, /\[skip ci\]$/u);
  assert.equal(
    remote.missingAndStaleControl.canonicalResponse.pullRequest.mergeStateStatus,
    "BLOCKED",
  );
  assert.deepEqual(remote.missingAndStaleControl.canonicalResponse.checkRuns, []);
  assert.deepEqual(
    remote.missingAndStaleControl.canonicalResponse.commitStatuses,
    [],
  );
  assert.deepEqual(
    remote.missingAndStaleControl.canonicalResponse.workflowRuns,
    [],
  );
  assert.equal(remote.missingAndStaleControl.oldHeadSuccessReusable, false);
  assert.equal(
    remote.missingAndStaleControl.result,
    "BLOCKED_REQUIRED_CHECKS_MISSING",
  );
  assert.equal(remote.directPushControl.captureSource, "LIVE_API_READBACK");
  assert.equal(remote.directPushControl.attemptedCommit, DIRECT_PUSH_COMMIT);
  assert.equal(remote.directPushControl.parent, MAIN_HEAD);
  assert.equal(
    remote.directPushControl.tree,
    "c13c3122779f107a649138c9dc0c89cb849ce4ff",
  );
  assert.equal(remote.directPushControl.canonicalResponse.id, 3663356883);
  assert.equal(remote.directPushControl.canonicalResponse.result, "FAIL");
  assert.equal(remote.directPushControl.result, "REJECTED_BY_RULESET");
  assert.equal(
    remote.directPushControl.remoteMainAfterAttempt,
    MAIN_HEAD,
  );
  assert.ok(
    remote.directPushControl.canonicalResponse.ruleEvaluations.some(
      ({ source, ruleType, result }) =>
        source === "RULESET_20780723" &&
        ruleType === "pull_request" &&
        result === "FAIL",
    ),
  );
  assert.deepEqual(remote.priorFailureObservation, {
    runId: 31659601178,
    classification: "PRE_RULESET_FAILURE_OBSERVATION_ONLY",
    remoteNegativeControlClaimed: false,
  });

  const local = value.localFailClosedContractEvidence;
  assertExactKeys(local, [
    "evidenceClass",
    "remoteExecutionClaimed",
    "sourceCommit",
    "controls",
  ]);
  assert.equal(local.evidenceClass, "LOCAL_FAIL_CLOSED_CONTRACT_EVIDENCE");
  assert.equal(local.remoteExecutionClaimed, false);
  assert.equal(local.sourceCommit, POSITIVE_HEAD);
  assert.deepEqual(
    local.controls.map(({ control }) => control),
    [
      "WRONG_INTEGRATION",
      "BLOCKED_MODEL_DECISION",
      "INCONCLUSIVE_MODEL_DECISION",
    ],
  );
  for (const control of local.controls) {
    assertExactKeys(control, ["control", "path", "rawSha256", "contract"]);
    assert.match(control.rawSha256, /^sha256:[a-f0-9]{64}$/u);
  }
  assert.deepEqual(value.criterionAssessment, {
    rulesetReadback: "PASS",
    effectiveMainRules: "PASS",
    positiveRequiredChecks: "PASS",
    staleCheckReplayDenied: "PASS",
    directPushDenied: "PASS",
    wrongIntegration: "LOCAL_FAIL_CLOSED_ONLY",
    blockedModelDecision: "LOCAL_FAIL_CLOSED_ONLY",
    inconclusiveModelDecision: "LOCAL_FAIL_CLOSED_ONLY",
    overall: "PASS",
  });
  assertExactKeys(value.criterionAssessment, [
    "rulesetReadback",
    "effectiveMainRules",
    "positiveRequiredChecks",
    "staleCheckReplayDenied",
    "directPushDenied",
    "wrongIntegration",
    "blockedModelDecision",
    "inconclusiveModelDecision",
    "overall",
  ]);
  assertExactKeys(value.historicalPreservation, [
    "preservedReasonCodes",
    "historicalArtifacts",
    "historicalRecordsReclassified",
  ]);
  for (const artifact of value.historicalPreservation.historicalArtifacts) {
    assertExactKeys(artifact, ["path", "freezeCommit", "rawSha256"]);
  }
  assert.deepEqual(
    value.historicalPreservation,
    closureEvidence.historicalPreservation,
  );
  assert.deepEqual(value.historicalPreservation.preservedReasonCodes, [
    "INCONCLUSIVE_INDEPENDENT_HUMAN_REVIEWER_MISSING",
    "INCONCLUSIVE_INDEPENDENT_REVIEWER_MISSING",
  ]);
  assert.equal(value.historicalPreservation.historicalRecordsReclassified, false);
  assert.deepEqual(value.freezeCommitRule, {
    mode: "BOUND_BY_SUBSEQUENT_INDEX_COMMIT",
    selfReferenceAllowed: false,
    evidenceFreezeCommitRecordedHere: false,
    requiredNextArtifactPath:
      "implementation/governance/v5.3-supplemental-evidence-index.v3.json",
    requiredGitMode: "100644",
    requiredBindings: [
      "evidence.path",
      "evidence.sha256",
      "evidenceFreezeCommit",
    ],
  });
  assert.equal(value.governanceBoundary.humanIndependentReviewSatisfied, false);
  assertExactKeys(value.governanceBoundary, [
    "humanIndependentReviewSatisfied",
    "modelReviewConclusion",
    "p1B11RemoteEvidenceCaptured",
    "closureEligibleForSupplementalIndex",
    "p1B11IndexClosed",
    "d1Written",
    "workPackageStatusChanged",
    "gateChanged",
    "profileApproved",
    "o02Authorized",
    "o03Authorized",
    "changeCounts",
    "governanceEffect",
    "isProgressTracker",
  ]);
  assert.equal(
    value.governanceBoundary.modelReviewConclusion,
    "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  );
  assert.equal(value.governanceBoundary.p1B11RemoteEvidenceCaptured, true);
  assert.equal(value.governanceBoundary.closureEligibleForSupplementalIndex, true);
  assert.equal(value.governanceBoundary.p1B11IndexClosed, false);
  for (const key of [
    "d1Written",
    "workPackageStatusChanged",
    "gateChanged",
    "profileApproved",
    "o02Authorized",
    "o03Authorized",
    "isProgressTracker",
  ]) {
    assert.equal(value.governanceBoundary[key], false);
  }
  assert.deepEqual(value.governanceBoundary.changeCounts, {
    d1Writes: 0,
    workPackageStateChanges: 0,
    gateChanges: 0,
    profileChanges: 0,
    o02Changes: 0,
    o03Changes: 0,
  });
  assert.equal(value.governanceBoundary.governanceEffect, "NONE");
  assertNoSensitiveMaterial(value);
  assert.equal(
    value.evidenceSha256,
    await sha256ProjectValue(withoutSelfHash(value)),
  );
}

test("P1-B11 preparation evidence binds the exact source commit and artifacts", async () => {
  await validateEvidence(evidence);
  await validateClosureEvidence(closureEvidence);
  execFileSync("/usr/bin/git", ["cat-file", "-e", `${SOURCE_COMMIT}^{commit}`], {
    cwd: ROOT,
    env: GIT_ENV,
  });
  execFileSync(
    "/usr/bin/git",
    ["merge-base", "--is-ancestor", SOURCE_COMMIT, "HEAD"],
    { cwd: ROOT, env: GIT_ENV },
  );
  assert.equal(gitValue("%P", SOURCE_COMMIT), SOURCE_PARENT);
  assert.equal(gitValue("%T", SOURCE_COMMIT), SOURCE_TREE);
  assert.equal(
    sha256Bytes(
      execFileSync(
        "/usr/bin/git",
        [
          "diff",
          "--binary",
          "--no-ext-diff",
          "--no-textconv",
          SOURCE_PARENT,
          SOURCE_COMMIT,
        ],
        { cwd: ROOT, env: GIT_ENV },
      ),
    ),
    SOURCE_PATCH_SHA256,
  );
  for (const artifact of evidence.sourceFreeze.artifacts) {
    assertExactKeys(artifact, ["path", "sha256"]);
    assert.equal(sha256Bytes(gitBytes(SOURCE_COMMIT, artifact.path)), artifact.sha256);
  }
  for (const binding of [
    ...Object.values(closureEvidence.evidenceSources),
    ...closureEvidence.historicalPreservation.historicalArtifacts,
  ]) {
    assert.equal(
      sha256Bytes(gitBytes(binding.freezeCommit, binding.path)),
      binding.rawSha256,
    );
    assert.equal(
      sha256Bytes(await readFile(new URL(`../${binding.path}`, import.meta.url))),
      binding.rawSha256,
    );
  }
  const candidate = JSON.parse(
    gitBytes(
      closureEvidence.evidenceSources.rulesetCandidate.freezeCommit,
      closureEvidence.evidenceSources.rulesetCandidate.path,
    ),
  );
  assert.equal(
    await sha256ProjectValue(candidate.payload),
    closureEvidence.evidenceSources.rulesetCandidate.payloadCanonicalSha256,
  );
  assert.equal(gitValue("%T", POSITIVE_HEAD), POSITIVE_TREE);
  assert.equal(gitValue("%P", MISSING_HEAD), POSITIVE_HEAD);
  assert.equal(gitValue("%T", MISSING_HEAD), POSITIVE_TREE);
  assert.equal(
    gitValue("%s", MISSING_HEAD),
    closureEvidence.remoteExecutionEvidence.missingAndStaleControl.commitMessage,
  );
  for (const control of closureEvidence.localFailClosedContractEvidence.controls) {
    assert.equal(
      sha256Bytes(
        gitBytes(
          closureEvidence.localFailClosedContractEvidence.sourceCommit,
          control.path,
        ),
      ),
      control.rawSha256,
    );
  }
});

test("hosted evidence is exact but cannot masquerade as protected independent review", () => {
  assert.deepEqual(evidence.hostedChecks.requiredCandidateChecks, [
    "protected-surface-gate",
    "contract-compatibility-gate",
    "c13-source-review-gate",
  ]);
  assert.equal(
    evidence.hostedChecks.c13SourceReview.log.sha256,
    "sha256:eb15d6ab82ce4195a223bedfc763275eab30dfbdf56b278116b52aa195b465af",
  );
  assert.equal(evidence.hostedChecks.c13SourceReview.log.byteLength, 19568);
  assert.equal(evidence.pullRequest.reviewDecision, "NONE");
  assert.equal(evidence.capabilityBoundary.writeCapableHumanCount, 1);
  assert.match(evidence.limitations.join("\n"), /second real human reviewer/i);
  assert.match(evidence.limitations.join("\n"), /does not prove merge denial/i);
  assert.equal(
    closureEvidence.remoteExecutionEvidence.evidenceClass,
    "REMOTE_EXECUTION_EVIDENCE",
  );
  assert.equal(
    closureEvidence.localFailClosedContractEvidence.evidenceClass,
    "LOCAL_FAIL_CLOSED_CONTRACT_EVIDENCE",
  );
  assert.equal(
    closureEvidence.localFailClosedContractEvidence.remoteExecutionClaimed,
    false,
  );
  assert.equal(
    closureEvidence.governanceBoundary.humanIndependentReviewSatisfied,
    false,
  );
  assert.match(closureEvidence.limitations.join("\n"), /not a human review/i);
  assert.match(
    closureEvidence.limitations.join("\n"),
    /not remote negative controls/i,
  );
  assert.match(
    closureEvidence.limitations.join("\n"),
    /only Supplemental Evidence Index v3 may close the gap/i,
  );
});

test("ruleset, reviewer, merge-denial, or completion overclaims fail closed", async () => {
  for (const mutate of [
    (copy) => {
      copy.status = "CLOSED";
    },
    (copy) => {
      copy.rulesetCandidate.status = "APPLIED";
    },
    (copy) => {
      copy.rulesetCandidate.remoteEnforcementProved = true;
    },
    (copy) => {
      copy.capabilityBoundary.independentHumanReviewer = "PRESENT";
    },
    (copy) => {
      copy.criterionAssessment.overall = "PASS";
    },
    (copy) => {
      copy.governanceBoundary.p1B11Closed = true;
    },
  ]) {
    const copy = structuredClone(evidence);
    mutate(copy);
    copy.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(copy));
    await assert.rejects(() => validateEvidence(copy));
  }
  for (const mutate of [
    (copy) => { copy.rulesetEnforcement.rulesetId = 1; },
    (copy) => { copy.rulesetEnforcement.rulesetVersion = 1; },
    (copy) => { copy.rulesetEnforcement.rulesetReadback.canonicalResponse.bypassActors.push({ id: 1 }); },
    (copy) => { copy.remoteExecutionEvidence.positiveControl.canonicalResponse.requiredChecks[0].headSha = "f".repeat(40); },
    (copy) => { copy.remoteExecutionEvidence.positiveControl.canonicalResponse.requiredChecks[0].isRequired = false; },
    (copy) => { copy.remoteExecutionEvidence.positiveControl.canonicalResponse.requiredChecks[0].integrationId = 1; },
    (copy) => { copy.remoteExecutionEvidence.missingAndStaleControl.canonicalResponse.checkRuns.push({ conclusion: "SUCCESS" }); },
    (copy) => { copy.remoteExecutionEvidence.missingAndStaleControl.oldHeadSuccessReusable = true; },
    (copy) => { copy.remoteExecutionEvidence.missingAndStaleControl.parent = "f".repeat(40); },
    (copy) => { copy.remoteExecutionEvidence.missingAndStaleControl.tree = "f".repeat(40); },
    (copy) => { copy.remoteExecutionEvidence.directPushControl.result = "ALLOWED"; },
    (copy) => { copy.remoteExecutionEvidence.directPushControl.attemptedCommit = "f".repeat(40); },
    (copy) => { copy.remoteExecutionEvidence.positiveControl.canonicalResponse.pullRequest.baseRefOid = "f".repeat(40); },
    (copy) => { copy.localFailClosedContractEvidence.evidenceClass = "REMOTE_EXECUTION_EVIDENCE"; },
    (copy) => { copy.localFailClosedContractEvidence.remoteExecutionClaimed = true; },
    (copy) => { copy.localFailClosedContractEvidence.sourceCommit = MISSING_HEAD; },
    (copy) => { copy.evidenceSources.activePolicy = structuredClone(copy.evidenceSources.targetedReviewEvidence); },
    (copy) => { copy.historicalPreservation.historicalArtifacts = []; },
    (copy) => { copy.freezeCommitRule.selfReferenceAllowed = true; },
    (copy) => { copy.governanceBoundary.changeCounts.d1Writes = 1; },
    (copy) => { copy.governanceBoundary.p1B11IndexClosed = true; },
    (copy) => { copy.governanceBoundary.humanIndependentReviewSatisfied = true; },
    (copy) => { copy.governanceBoundary.governanceEffect = "P1_B11_VERIFIED"; },
    (copy) => { copy.governanceBoundary.d1Written = true; },
  ]) {
    const copy = structuredClone(closureEvidence);
    mutate(copy);
    copy.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(copy));
    await assert.rejects(() => validateClosureEvidence(copy));
  }
});

test("self-hash and frozen source bytes fail closed on tampering", async () => {
  const selfHash = structuredClone(evidence);
  selfHash.evidenceSha256 = `sha256:${"f".repeat(64)}`;
  await assert.rejects(() => validateEvidence(selfHash));

  const source = structuredClone(evidence);
  source.sourceFreeze.artifacts[0].sha256 = `sha256:${"f".repeat(64)}`;
  source.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(source));
  await assert.rejects(async () => {
    await validateEvidence(source);
    for (const artifact of source.sourceFreeze.artifacts) {
      assert.equal(
        sha256Bytes(gitBytes(SOURCE_COMMIT, artifact.path)),
        artifact.sha256,
      );
    }
  });

  const closureSelfHash = structuredClone(closureEvidence);
  closureSelfHash.evidenceSha256 = `sha256:${"f".repeat(64)}`;
  await assert.rejects(() => validateClosureEvidence(closureSelfHash));

  for (const mutate of [
    (copy) => { copy.evidenceSources.activePolicy.rawSha256 = `sha256:${"f".repeat(64)}`; },
    (copy) => { copy.historicalPreservation.historicalArtifacts[0].rawSha256 = `sha256:${"f".repeat(64)}`; },
    (copy) => { copy.rulesetEnforcement.rulesetReadback.canonicalResponseSha256 = `sha256:${"f".repeat(64)}`; },
    (copy) => { copy.remoteExecutionEvidence.directPushControl.canonicalByteLength += 1; },
  ]) {
    const copy = structuredClone(closureEvidence);
    mutate(copy);
    copy.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(copy));
    await assert.rejects(async () => {
      await validateClosureEvidence(copy);
      for (const binding of [
        ...Object.values(copy.evidenceSources),
        ...copy.historicalPreservation.historicalArtifacts,
      ]) {
        assert.equal(
          sha256Bytes(gitBytes(binding.freezeCommit, binding.path)),
          binding.rawSha256,
        );
      }
    });
  }
});

test("unknown nested fields and sensitive material fail closed", async () => {
  const unknown = structuredClone(evidence);
  unknown.pullRequest.token = "not-a-real-token";
  unknown.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(unknown));
  await assert.rejects(() => validateEvidence(unknown));

  for (const content of [
    "person@example.com",
    "Cookie: session=synthetic",
    "Authorization: Basic c3ludGhldGlj",
    "eyJhbGciOiJIUzI1NiJ9.c3ludGhldGlj.c2lnbmF0dXJl",
    "https://github.com/example?access_token=synthetic",
    "https://github.com/example?api_key=synthetic",
  ]) {
    const sensitive = structuredClone(evidence);
    sensitive.limitations[0] = content;
    sensitive.evidenceSha256 =
      await sha256ProjectValue(withoutSelfHash(sensitive));
    await assert.rejects(() => validateEvidence(sensitive));
  }

  const closureUnknown = structuredClone(closureEvidence);
  closureUnknown.remoteExecutionEvidence.positiveControl.unexpected = false;
  closureUnknown.evidenceSha256 =
    await sha256ProjectValue(withoutSelfHash(closureUnknown));
  await assert.rejects(() => validateClosureEvidence(closureUnknown));

  for (const content of [
    "person@example.com",
    "Cookie: session=synthetic",
    "Authorization: Basic c3ludGhldGlj",
    "ghp_notarealtokenvalue",
  ]) {
    const sensitive = structuredClone(closureEvidence);
    sensitive.limitations[0] = content;
    sensitive.evidenceSha256 =
      await sha256ProjectValue(withoutSelfHash(sensitive));
    await assert.rejects(() => validateClosureEvidence(sensitive));
  }
});
