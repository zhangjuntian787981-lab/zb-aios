import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const SOURCE_COMMIT = "66249330f990fa1c76c07eceb163a688b134395b";
const ONLINE_RESPONSE_SHA256 =
  "sha256:296a93a8cff7058c980769130fee9a6c2ea69bed0df00042a16a496d52fba8c7";
const CASE_IDS = Array.from(
  { length: 10 },
  (_, index) => `F04-E${String(index + 1).padStart(3, "0")}`,
);
const ZERO_TOLERANCE_RULE_IDS = Array.from(
  { length: 7 },
  (_, index) => `ZT-0${index + 1}`,
);

const schema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f04/schemas/f04-evaluation-binding.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const binding = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f04/f04-evaluation-binding.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const ajv = new Ajv2020({
  strict: true,
  allErrors: true,
  validateFormats: true,
});
addFormats(ajv);
const validateSchema = ajv.compile(schema);

function clone(value) {
  return structuredClone(value);
}

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function gitBytes(commit, path) {
  return execFileSync("git", ["show", `${commit}:${path}`], {
    cwd: new URL("..", import.meta.url),
  });
}

function gitJson(commit, path) {
  return JSON.parse(gitBytes(commit, path).toString("utf8"));
}

function bindingWithoutSelfHash(value) {
  const copy = clone(value);
  delete copy.bindingSha256;
  return copy;
}

async function validateFrozenReferences(value) {
  const references = [
    [value.dataset.artifactRef, value.dataset.artifactSha256],
    [value.metric.configRef, value.metric.configSha256],
    [value.metric.evaluatorRef, value.metric.evaluatorSha256],
    [value.zeroTolerance.artifactRef, value.zeroTolerance.artifactSha256],
    [
      value.humanBaseline.candidateRef,
      value.humanBaseline.candidateSha256,
    ],
  ];
  for (const [path, expectedSha256] of references) {
    assert.equal(sha256Bytes(gitBytes(value.sourceCommit, path)), expectedSha256);
  }
}

async function validateBinding(value) {
  assert.equal(validateSchema(value), true, ajv.errorsText(validateSchema.errors));
  execFileSync("git", ["cat-file", "-e", `${value.sourceCommit}^{commit}`], {
    cwd: new URL("..", import.meta.url),
  });
  await validateFrozenReferences(value);
  const projection = value.humanBaseline.onlineProjection;
  const projectionBytes = Buffer.from(JSON.stringify(projection), "utf8");
  assert.equal(
    sha256Bytes(projectionBytes),
    value.humanBaseline.onlineProjectionResponseSha256,
  );
  assert.equal(
    projection.g0Submission.submissionId,
    projection.g0Decision.submissionId,
  );
  assert.equal(
    projection.g0Submission.packageHash,
    projection.g0Decision.packageHash,
  );
  assert.ok(projection.g0Submission.revision < projection.g0Decision.revision);
  assert.ok(projection.g0Decision.revision <= projection.currentRevision);
  assert.equal(
    await sha256ProjectValue(bindingWithoutSelfHash(value)),
    value.bindingSha256,
  );
}

test("the F04 evaluation binding candidate passes its closed schema and frozen-byte checks", async () => {
  await validateBinding(binding);
});

test("the candidate is non-authorizing and defines no evaluation run", () => {
  assert.equal(binding.status, "CANDIDATE");
  assert.equal(binding.governanceEffect, "NONE");
  assert.equal(binding.scope, "BASELINE_DEFINITION_ONLY_NO_EVALUATION_RUN");
  assert.equal(binding.workPackageId, "F04");
  assert.equal(binding.acceptanceCriterionId, "F04-AC07");
  assert.equal(binding.enterpriseDataUsed, false);
  assert.equal(binding.sourceCommit, SOURCE_COMMIT);
});

test("the ten cases are a purposive synthetic scenario manifest, not a statistical dataset", () => {
  assert.equal(
    binding.dataset.manifestKind,
    "FROZEN_SYNTHETIC_SCENARIO_MANIFEST",
  );
  assert.equal(binding.dataset.sampleCount, 10);
  assert.equal(binding.dataset.coverageDenominator, 10);
  assert.equal(
    binding.dataset.samplingMethod,
    "PURPOSIVE_SECURITY_AND_QUALITY_COVERAGE",
  );
  assert.equal(binding.dataset.statisticalGeneralization, false);
  assert.deepEqual(binding.dataset.caseIds, CASE_IDS);

  const suite = gitJson(binding.sourceCommit, binding.dataset.artifactRef);
  assert.equal(suite.id, binding.dataset.suiteId);
  assert.deepEqual(
    suite.cases.map(({ id }) => id),
    binding.dataset.caseIds,
  );
});

test("metric thresholds and aggregation are bound to the frozen release-gate config", () => {
  const config = gitJson(binding.sourceCommit, binding.metric.configRef);
  assert.deepEqual(binding.metric.thresholds, {
    minimumCaseScore: config.thresholds.minimum_case_score,
    minimumOverallScore: config.thresholds.minimum_overall_score,
    minimumCategoryScores: {
      normal: config.thresholds.minimum_category_scores.normal,
      refusal: config.thresholds.minimum_category_scores.refusal,
    },
  });
  assert.deepEqual(
    binding.metric.aggregation.decisionPrecedence,
    config.decision_precedence,
  );
  assert.deepEqual(binding.metric.aggregation.missingOrInvalidResult, {
    zeroToleranceCase: "BLOCKED",
    nonZeroToleranceCase: "QUALITY_FAILURE",
  });
  assert.equal(binding.metric.caseScoreProducer, "NOT_DEFINED_IN_BASELINE");
  assert.equal(binding.metric.futureEvaluationRunMustBindScorer, true);
});

test("all seven zero-tolerance rules remain blocking and non-overridable", () => {
  const rules = gitJson(
    binding.sourceCommit,
    binding.zeroTolerance.artifactRef,
  );
  assert.deepEqual(binding.zeroTolerance.ruleIds, ZERO_TOLERANCE_RULE_IDS);
  assert.deepEqual(
    binding.zeroTolerance.ruleIds,
    rules.rules.map(({ id }) => id),
  );
  assert.equal(binding.zeroTolerance.decisionOnAnyFailure, "BLOCKED");
  assert.equal(binding.zeroTolerance.averageScoreMayOffset, false);
  assert.equal(binding.zeroTolerance.productOwnerExclusionMayOffset, false);
});

test("model, prompt, skill, and knowledge are only inapplicable to this no-run baseline definition", () => {
  assert.deepEqual(Object.keys(binding.evaluationInputs).sort(), [
    "knowledge",
    "model",
    "prompt",
    "skill",
  ]);
  for (const input of Object.values(binding.evaluationInputs)) {
    assert.equal(input.status, "NOT_APPLICABLE_TO_BASELINE_DEFINITION");
    assert.equal(input.digest, null);
    assert.equal(input.futureEvaluationRunMustBind, true);
    assert.match(input.reason, /baseline definition|基线定义/i);
  }
  assert.match(
    binding.evaluationInputs.knowledge.reason,
    /must bind one exact knowledge digest/i,
  );
  assert.doesNotMatch(
    binding.evaluationInputs.knowledge.reason,
    /separately justified|applicability decision/i,
  );
});

test("the online projection bytes bind the authority and current G0 chain without inventing a persisted role", () => {
  const projection = binding.humanBaseline.onlineProjection;
  const responseBytes = Buffer.from(JSON.stringify(projection), "utf8");
  assert.equal(responseBytes.byteLength, 1981);
  assert.equal(
    sha256Bytes(responseBytes),
    binding.humanBaseline.onlineProjectionResponseSha256,
  );
  assert.equal(
    binding.humanBaseline.onlineProjectionResponseSha256,
    ONLINE_RESPONSE_SHA256,
  );
  assert.equal(projection.schemaVersion, "p0-b11-evidence-projection.v1");
  assert.equal(
    projection.source,
    "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
  );
  assert.equal(projection.currentRevision, 70);
  assert.equal(projection.f04HumanBaselineAuthority.revision, 1);
  assert.equal(
    projection.f04HumanBaselineAuthority.eventId,
    "9e00fa42-313e-4c26-8441-cc4f3f3b2779",
  );
  assert.equal(
    projection.f04HumanBaselineAuthority.actorBinding.persistedRole,
    null,
  );
  assert.equal(projection.g0Submission.revision, 69);
  assert.equal(projection.g0Decision.revision, 70);
  assert.equal(projection.g0Decision.decision, "APPROVE");
  assert.equal(
    projection.g0Submission.submissionId,
    projection.g0Decision.submissionId,
  );
  assert.equal(
    projection.g0Submission.packageHash,
    projection.g0Decision.packageHash,
  );
});

test("structured adjudication remains pending human confirmation", () => {
  assert.equal(
    binding.humanBaseline.onlineProjection.structuredAdjudicationPersisted,
    false,
  );
  assert.equal(binding.adjudication.status, "PENDING_PRODUCT_OWNER_CONFIRMATION");
  assert.equal(binding.adjudication.decision, null);
  assert.equal(binding.adjudication.unresolvedDisputes, null);
  assert.equal(binding.adjudication.automaticJudgeMayDecide, false);
  assert.equal(binding.adjudication.zeroToleranceOverrideAllowed, false);
});

test("unknown fields and a false completed-adjudication claim are rejected", () => {
  const unknown = clone(binding);
  unknown.ready = true;
  assert.equal(validateSchema(unknown), false);

  const falseClaim = clone(binding);
  falseClaim.adjudication.status = "CONFIRMED";
  assert.equal(validateSchema(falseClaim), false);
});

test("tampered reference bytes or a stale self-hash fail closed", async () => {
  const referenceTamper = clone(binding);
  referenceTamper.dataset.artifactSha256 = `sha256:${"0".repeat(64)}`;
  await assert.rejects(() => validateBinding(referenceTamper));

  const selfHashTamper = clone(binding);
  selfHashTamper.bindingSha256 = `sha256:${"f".repeat(64)}`;
  await assert.rejects(() => validateBinding(selfHashTamper));
});

test("a rehashed projection with a mismatched G0 Submission and Decision fails closed", async () => {
  const mismatch = clone(binding);
  mismatch.humanBaseline.onlineProjection.g0Decision.submissionId =
    "00000000-0000-4000-8000-000000000000";
  mismatch.humanBaseline.onlineProjectionResponseSha256 = sha256Bytes(
    Buffer.from(
      JSON.stringify(mismatch.humanBaseline.onlineProjection),
      "utf8",
    ),
  );
  mismatch.bindingSha256 = await sha256ProjectValue(
    bindingWithoutSelfHash(mismatch),
  );

  await assert.rejects(() => validateBinding(mismatch));
});

test("the candidate does not alter any historical evidence or governance truth", () => {
  assert.deepEqual(binding.replacesArtifacts, []);
  assert.deepEqual(binding.governanceClaims, {
    p0B11Closed: false,
    workPackageStatusChanged: false,
    gateStatusChanged: false,
    profileApproved: false,
    startAuthorized: false,
  });
});
