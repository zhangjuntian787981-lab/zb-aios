import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const REPOSITORY_ROOT = new URL("..", import.meta.url);
const EVIDENCE_PATH =
  "implementation/p0/evidence/p0-b11-f04-ac07-supplemental-evidence.v1.json";
const CANDIDATE_FREEZE_COMMIT =
  "a4741e3b03a78c4b8ad009ec169dcc0f4ec7c18b";
const CANDIDATE_FREEZE_TREE =
  "c129014936653270d0090d401cf83678951e55bc";
const DECISION_FREEZE_COMMIT =
  "127f7dac03aec2569af1c538d37c04670d2c2fbb";
const DECISION_FREEZE_TREE =
  "2240046516bb308b3ccb1be99b97273ae7d3fbe3";
const CANDIDATE_PATH =
  "implementation/p0/f04/f04-evaluation-binding.v1.json";
const DECISION_PATH =
  "implementation/p0/f04/f04-evaluation-binding-decision.v1.json";
const CANDIDATE_FILE_SHA256 =
  "sha256:d7678e1203ca442decb98aaffde8a58ac0489e03490e42d690902152e891c914";
const CANDIDATE_BINDING_SHA256 =
  "sha256:7317a516bdfaefed639f81e4699ffc2bb07f8619078fa81551f7d4ca303a21c6";
const DECISION_FILE_SHA256 =
  "sha256:237adb8841c8080bc68aaa93ab76a86f7d7782e0262472fd0a624e1d8d3313dc";
const DECISION_RECEIPT_SHA256 =
  "sha256:69f2725702130789317c9f56f8d9f72b3b071d67335328aa73159e5d17e0afc4";
const ONLINE_RESPONSE_SHA256 =
  "sha256:296a93a8cff7058c980769130fee9a6c2ea69bed0df00042a16a496d52fba8c7";
const HUMAN_BASELINE_SHA256 =
  "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0";

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
    "workPackageId",
    "acceptanceCriterionId",
    "classification",
    "status",
    "closureScope",
    "recordedAt",
    "candidateFreeze",
    "decisionFreeze",
    "onlineAuthority",
    "evaluationBaseline",
    "adjudication",
    "acceptanceResult",
    "referenceReviewBoundary",
    "governanceBoundary",
    "limitations",
    "evidenceSha256",
  ]);
  assert.equal(
    value.schemaVersion,
    "p0-b11-f04-ac07-supplemental-evidence.v1",
  );
  assert.equal(value.groupId, "P0-B11");
  assert.equal(value.workPackageId, "F04");
  assert.equal(value.acceptanceCriterionId, "F04-AC07");
  assert.equal(value.status, "CLOSED");
  assert.equal(
    value.closureScope,
    "NO_RUN_RETROSPECTIVE_BINDING_BEFORE_ANY_FUTURE_EVALUATION_RUN",
  );
  assert.match(value.recordedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);

  for (const freeze of [value.candidateFreeze, value.decisionFreeze]) {
    execFileSync("git", ["cat-file", "-e", `${freeze.commit}^{commit}`], {
      cwd: REPOSITORY_ROOT,
    });
    assert.equal(
      execFileSync("git", ["show", "-s", "--format=%T", freeze.commit], {
        cwd: REPOSITORY_ROOT,
        encoding: "utf8",
      }).trim(),
      freeze.tree,
    );
    assert.equal(sha256Bytes(gitBytes(freeze.commit, freeze.path)), freeze.fileSha256);
  }

  const candidate = JSON.parse(
    gitBytes(value.candidateFreeze.commit, value.candidateFreeze.path).toString(
      "utf8",
    ),
  );
  const decision = JSON.parse(
    gitBytes(value.decisionFreeze.commit, value.decisionFreeze.path).toString(
      "utf8",
    ),
  );
  assert.equal(candidate.bindingSha256, value.candidateFreeze.bindingSha256);
  assert.equal(decision.receiptSha256, value.decisionFreeze.receiptSha256);
  assert.equal(decision.candidate.freezeCommit, value.candidateFreeze.commit);
  assert.equal(decision.candidate.bindingSha256, candidate.bindingSha256);
  assert.equal(decision.decision, "APPROVE");

  assert.deepEqual(
    value.onlineAuthority.projection,
    candidate.humanBaseline.onlineProjection,
  );
  assert.equal(
    value.onlineAuthority.responseSha256,
    candidate.humanBaseline.onlineProjectionResponseSha256,
  );
  assert.equal(
    value.onlineAuthority.projection.f04HumanBaselineAuthority
      .evidenceHashes[1],
    HUMAN_BASELINE_SHA256,
  );
  assert.equal(
    value.onlineAuthority.projection.g0Submission.submissionId,
    value.onlineAuthority.projection.g0Decision.submissionId,
  );
  assert.equal(
    value.onlineAuthority.projection.g0Submission.packageHash,
    value.onlineAuthority.projection.g0Decision.packageHash,
  );
  assert.equal(
    value.onlineAuthority.projection.structuredAdjudicationPersisted,
    false,
  );

  assert.equal(
    value.evaluationBaseline.scenarioManifest,
    candidate.dataset.manifestKind,
  );
  assert.equal(
    value.evaluationBaseline.sampleCount,
    candidate.dataset.sampleCount,
  );
  assert.equal(
    value.evaluationBaseline.statisticalGeneralization,
    candidate.dataset.statisticalGeneralization,
  );
  assert.deepEqual(
    value.evaluationBaseline.thresholds,
    candidate.metric.thresholds,
  );
  assert.deepEqual(
    value.evaluationBaseline.zeroTolerance,
    candidate.zeroTolerance,
  );
  assert.equal(
    value.evaluationBaseline.humanBaselineCandidateSha256,
    candidate.humanBaseline.candidateSha256,
  );
  assert.equal(value.evaluationBaseline.evaluationRunExecuted, false);
  assert.equal(value.evaluationBaseline.evaluationOutcome, null);
  assert.deepEqual(
    value.evaluationBaseline.futureEvaluationRunRequiredBindings,
    decision.acceptedSemantics.futureEvaluationRunRequiredBindings,
  );

  assert.equal(value.adjudication.bindingDecision, "APPROVE");
  assert.equal(
    value.adjudication.adjudicationStatus,
    "CONFIRMED_NO_UNRESOLVED_DISPUTE",
  );
  assert.equal(
    value.adjudication.decisionReceiptSha256,
    decision.receiptSha256,
  );
  assert.equal(value.adjudication.decisionAt, decision.decisionAt);
  assert.deepEqual(value.adjudication.unresolvedDisputes, []);
  assert.equal(value.adjudication.automaticJudgeUsed, false);
  assert.equal(
    value.adjudication.automaticJudgeMaySubstituteHumanBaseline,
    false,
  );
  assert.equal(value.adjudication.zeroToleranceOverrideAllowed, false);

  assert.deepEqual(value.acceptanceResult, {
    status: "PASS",
    statement:
      "The v5.3 P0-B11 supplemental gap is closed by freezing the existing D1 human-baseline authority, exact candidate bytes, thresholds, zero-tolerance rules, G0 chain, and Product Owner adjudication; no actual evaluation run or retroactive timing claim is made.",
    evaluationRunExecuted: false,
    evaluationOutcome: null,
    statisticalGeneralizationClaimed: false,
  });
  assert.deepEqual(value.referenceReviewBoundary, {
    effect: "NONE",
    formalReceiptCreated: false,
    currentPolicyCoversF04RetrospectiveBackfill: false,
    futurePolicyProfileAndAttestationBindingRequired: true,
    profileReadinessProved: false,
  });
  assert.deepEqual(value.governanceBoundary, {
    p0B11EvidenceClosed: true,
    supplementalEvidenceIndexUpdated: false,
    referenceReviewReceiptCreated: false,
    d1Written: false,
    workPackageStatusChanged: false,
    gateStatusChanged: false,
    manifestChanged: false,
    profileApproved: false,
    startAuthorized: false,
    enterpriseDataUsed: false,
  });
  assert.equal(
    await sha256ProjectValue(withoutSelfHash(value)),
    value.evidenceSha256,
  );
}

test("P0-B11 supplemental evidence closes only the F04-AC07 baseline-freeze gap", async () => {
  await validateEvidence(evidence);
  assert.equal(evidence.candidateFreeze.commit, CANDIDATE_FREEZE_COMMIT);
  assert.equal(evidence.candidateFreeze.tree, CANDIDATE_FREEZE_TREE);
  assert.equal(evidence.candidateFreeze.path, CANDIDATE_PATH);
  assert.equal(evidence.candidateFreeze.fileSha256, CANDIDATE_FILE_SHA256);
  assert.equal(
    evidence.candidateFreeze.bindingSha256,
    CANDIDATE_BINDING_SHA256,
  );
  assert.equal(evidence.decisionFreeze.commit, DECISION_FREEZE_COMMIT);
  assert.equal(evidence.decisionFreeze.tree, DECISION_FREEZE_TREE);
  assert.equal(evidence.decisionFreeze.path, DECISION_PATH);
  assert.equal(evidence.decisionFreeze.fileSha256, DECISION_FILE_SHA256);
  assert.equal(
    evidence.decisionFreeze.receiptSha256,
    DECISION_RECEIPT_SHA256,
  );
  assert.equal(evidence.onlineAuthority.responseSha256, ONLINE_RESPONSE_SHA256);
});

test("the evidence binds the exact D1 F04 authority and G0 submission/decision chain", () => {
  const projection = evidence.onlineAuthority.projection;
  assert.equal(projection.currentRevision, 70);
  assert.equal(
    projection.f04HumanBaselineAuthority.eventId,
    "9e00fa42-313e-4c26-8441-cc4f3f3b2779",
  );
  assert.equal(projection.f04HumanBaselineAuthority.revision, 1);
  assert.equal(
    projection.f04HumanBaselineAuthority.recordedAt,
    "2026-07-25T18:10:29.111Z",
  );
  assert.equal(projection.g0Submission.revision, 69);
  assert.equal(projection.g0Decision.revision, 70);
  assert.equal(projection.g0Decision.decision, "APPROVE");
});

test("no-run and zero-tolerance boundaries cannot be widened", async () => {
  const falseRun = clone(evidence);
  falseRun.evaluationBaseline.evaluationRunExecuted = true;
  falseRun.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(falseRun));
  await assert.rejects(() => validateEvidence(falseRun));

  const falseOutcome = clone(evidence);
  falseOutcome.acceptanceResult.evaluationOutcome = "PASS";
  falseOutcome.evidenceSha256 =
    await sha256ProjectValue(withoutSelfHash(falseOutcome));
  await assert.rejects(() => validateEvidence(falseOutcome));

  const override = clone(evidence);
  override.adjudication.zeroToleranceOverrideAllowed = true;
  override.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(override));
  await assert.rejects(() => validateEvidence(override));

  const substitute = clone(evidence);
  substitute.adjudication.automaticJudgeMaySubstituteHumanBaseline = true;
  substitute.evidenceSha256 =
    await sha256ProjectValue(withoutSelfHash(substitute));
  await assert.rejects(() => validateEvidence(substitute));
});

test("Git, D1 projection, approval, and self-hash tampering fail closed", async () => {
  for (const mutate of [
    (value) => {
      value.candidateFreeze.fileSha256 = `sha256:${"0".repeat(64)}`;
    },
    (value) => {
      value.decisionFreeze.receiptSha256 = `sha256:${"1".repeat(64)}`;
    },
    (value) => {
      value.onlineAuthority.projection.f04HumanBaselineAuthority.eventId =
        "00000000-0000-4000-8000-000000000000";
    },
    (value) => {
      value.onlineAuthority.projection.g0Decision.packageHash =
        `sha256:${"2".repeat(64)}`;
    },
  ]) {
    const changed = clone(evidence);
    mutate(changed);
    changed.evidenceSha256 = await sha256ProjectValue(withoutSelfHash(changed));
    await assert.rejects(() => validateEvidence(changed));
  }

  const selfHash = clone(evidence);
  selfHash.evidenceSha256 = `sha256:${"f".repeat(64)}`;
  await assert.rejects(() => validateEvidence(selfHash));
});

test("the supplemental artifact is evidence-only and leaves governance truth unchanged", () => {
  assert.equal(evidence.governanceBoundary.d1Written, false);
  assert.equal(evidence.governanceBoundary.workPackageStatusChanged, false);
  assert.equal(evidence.governanceBoundary.gateStatusChanged, false);
  assert.equal(evidence.governanceBoundary.manifestChanged, false);
  assert.equal(evidence.governanceBoundary.profileApproved, false);
  assert.equal(evidence.governanceBoundary.startAuthorized, false);
  assert.equal(evidence.governanceBoundary.supplementalEvidenceIndexUpdated, false);
});
