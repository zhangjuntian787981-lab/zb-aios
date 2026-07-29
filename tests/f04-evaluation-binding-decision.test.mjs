import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const REPOSITORY_ROOT = new URL("..", import.meta.url);
const FREEZE_COMMIT = "a4741e3b03a78c4b8ad009ec169dcc0f4ec7c18b";
const FREEZE_TREE = "c129014936653270d0090d401cf83678951e55bc";
const CANDIDATE_PATH =
  "implementation/p0/f04/f04-evaluation-binding.v1.json";
const CANDIDATE_FILE_SHA256 =
  "sha256:d7678e1203ca442decb98aaffde8a58ac0489e03490e42d690902152e891c914";
const CANDIDATE_BINDING_SHA256 =
  "sha256:7317a516bdfaefed639f81e4699ffc2bb07f8619078fa81551f7d4ca303a21c6";
const HUMAN_BASELINE_SHA256 =
  "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0";
const STANDING_AUTHORIZATION_SHA256 =
  "sha256:bf5f48194395c9cf92c0fba2c79a15770ca7fe0da2791f99ca03c3298cc3a8e1";
const APPROVAL_MESSAGE_ID = "msg_019fafbd-f5e5-7740-bbb2-0fc65cc6a44b";
const APPROVAL_TURN_ID = "12341531-519f-41a6-9e4e-55c6995d2a8e";
const APPROVAL_RECORDED_AT = "2026-07-29T21:18:09.893Z";
const APPROVAL_MESSAGE_SHA256 =
  "sha256:cbe2686380833032e01a2590f4d871416e0623ed702d9021d0e451c8c4708c62";
const APPROVAL_MESSAGE =
  "APPROVE F04 EVALUATION BINDING\n\n" +
  "freezeCommit:\n" +
  "a4741e3b03a78c4b8ad009ec169dcc0f4ec7c18b\n\n" +
  "candidateBindingSha256:\n" +
  "sha256:7317a516bdfaefed639f81e4699ffc2bb07f8619078fa81551f7d4ca303a21c6\n\n" +
  "candidateFileSha256:\n" +
  "sha256:d7678e1203ca442decb98aaffde8a58ac0489e03490e42d690902152e891c914\n\n" +
  "我确认：\n\n" +
  "1. 这10条案例仅构成冻结的合成场景覆盖清单，不构成统计代表性Dataset，不支持统计泛化声明。\n" +
  "2. 当前制品只定义评测基线，不执行实际评测，因此不产生PASS、FAIL或BLOCKED结论。\n" +
  "3. Model、Prompt、Skill、Knowledge只对本次“无运行的基线定义”不适用；未来任何实际评测必须分别绑定准确Digest。\n" +
  "4. 接受D1权威事件所绑定的人工基线候选准确字节：\n" +
  "   sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0\n" +
  "5. 当前不存在尚待裁决的基线分歧。\n" +
  "6. 自动Judge不得代替真人基线或真人裁决。\n" +
  "7. 任何零容忍失败均不得被平均分或人工排除覆盖。\n";

const schema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f04/schemas/f04-evaluation-binding-decision.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const receipt = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f04/f04-evaluation-binding-decision.v1.json",
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
    cwd: REPOSITORY_ROOT,
  });
}

function withoutSelfHash(value) {
  const copy = clone(value);
  delete copy.receiptSha256;
  return copy;
}

async function validateReceipt(value) {
  assert.equal(validateSchema(value), true, ajv.errorsText(validateSchema.errors));
  execFileSync("git", ["cat-file", "-e", `${value.candidate.freezeCommit}^{commit}`], {
    cwd: REPOSITORY_ROOT,
  });
  assert.equal(
    execFileSync(
      "git",
      ["show", "-s", "--format=%T", value.candidate.freezeCommit],
      { cwd: REPOSITORY_ROOT, encoding: "utf8" },
    ).trim(),
    value.candidate.freezeTree,
  );
  assert.equal(
    sha256Bytes(gitBytes(value.candidate.freezeCommit, value.candidate.path)),
    value.candidate.fileSha256,
  );
  const candidate = JSON.parse(
    gitBytes(value.candidate.freezeCommit, value.candidate.path).toString(
      "utf8",
    ),
  );
  assert.equal(candidate.bindingSha256, value.candidate.bindingSha256);
  assert.equal(
    candidate.humanBaseline.candidateSha256,
    value.humanBaselineCandidateSha256,
  );
  assert.equal(
    candidate.dataset.manifestKind,
    value.acceptedSemantics.scenarioManifestKind,
  );
  assert.equal(candidate.dataset.sampleCount, value.acceptedSemantics.sampleCount);
  assert.equal(
    candidate.dataset.statisticalGeneralization,
    value.acceptedSemantics.statisticalGeneralization,
  );
  assert.equal(
    candidate.scope,
    "BASELINE_DEFINITION_ONLY_NO_EVALUATION_RUN",
  );
  const approvalBytes = Buffer.from(
    value.authorization.sourceMessage.text,
    "utf8",
  );
  assert.equal(
    approvalBytes.byteLength,
    value.authorization.sourceMessage.utf8ByteLength,
  );
  assert.equal(
    sha256Bytes(approvalBytes),
    value.authorization.sourceMessage.sha256,
  );
  assert.equal(value.decisionAt, value.authorization.sourceMessage.recordedAt);
  const freezeTime = Date.parse(
    execFileSync(
      "git",
      ["show", "-s", "--format=%cI", value.candidate.freezeCommit],
      { cwd: REPOSITORY_ROOT, encoding: "utf8" },
    ).trim(),
  );
  assert.ok(Date.parse(value.decisionAt) >= freezeTime);
  assert.equal(
    await sha256ProjectValue(withoutSelfHash(value)),
    value.receiptSha256,
  );
}

test("the F04 binding decision receipt validates and binds the frozen candidate bytes", async () => {
  await validateReceipt(receipt);
  assert.equal(receipt.schemaVersion, "f04-evaluation-binding-decision.v1");
  assert.equal(receipt.workPackageId, "F04");
  assert.equal(receipt.acceptanceCriterionId, "F04-AC07");
  assert.equal(receipt.decision, "APPROVE");
  assert.equal(receipt.candidate.freezeCommit, FREEZE_COMMIT);
  assert.equal(receipt.candidate.freezeTree, FREEZE_TREE);
  assert.equal(receipt.candidate.path, CANDIDATE_PATH);
  assert.equal(receipt.candidate.fileSha256, CANDIDATE_FILE_SHA256);
  assert.equal(receipt.candidate.bindingSha256, CANDIDATE_BINDING_SHA256);
  assert.equal(
    receipt.humanBaselineCandidateSha256,
    HUMAN_BASELINE_SHA256,
  );
  assert.equal(
    receipt.authorization.standingAuthorizationSha256,
    STANDING_AUTHORIZATION_SHA256,
  );
  assert.equal(receipt.decisionAt, APPROVAL_RECORDED_AT);
  assert.equal(receipt.authorization.sourceMessage.messageId, APPROVAL_MESSAGE_ID);
  assert.equal(receipt.authorization.sourceMessage.turnId, APPROVAL_TURN_ID);
  assert.equal(
    receipt.authorization.sourceMessage.recordedAt,
    APPROVAL_RECORDED_AT,
  );
  assert.equal(receipt.authorization.sourceMessage.text, APPROVAL_MESSAGE);
  assert.equal(
    Buffer.byteLength(receipt.authorization.sourceMessage.text, "utf8"),
    receipt.authorization.sourceMessage.utf8ByteLength,
  );
  assert.equal(receipt.authorization.sourceMessage.utf8ByteLength, 998);
  assert.equal(
    sha256Bytes(
      Buffer.from(receipt.authorization.sourceMessage.text, "utf8"),
    ),
    receipt.authorization.sourceMessage.sha256,
  );
  assert.equal(
    receipt.authorization.sourceMessage.sha256,
    APPROVAL_MESSAGE_SHA256,
  );
});

test("approval preserves the no-run, no-generalization, and future exact-digest boundaries", () => {
  assert.equal(
    receipt.acceptedSemantics.scenarioManifestKind,
    "FROZEN_SYNTHETIC_SCENARIO_MANIFEST",
  );
  assert.equal(receipt.acceptedSemantics.sampleCount, 10);
  assert.equal(receipt.acceptedSemantics.statisticalGeneralization, false);
  assert.equal(receipt.acceptedSemantics.evaluationRunExecuted, false);
  assert.equal(receipt.acceptedSemantics.evaluationOutcome, null);
  assert.deepEqual(receipt.acceptedSemantics.futureEvaluationRunRequiredBindings, {
    model: "EXACT_DIGEST_REQUIRED",
    prompt: "EXACT_DIGEST_REQUIRED",
    skill: "EXACT_DIGEST_REQUIRED",
    knowledge: "EXACT_DIGEST_REQUIRED",
  });
});

test("human adjudication cannot be replaced by an automatic judge or zero-tolerance override", () => {
  assert.deepEqual(receipt.adjudication.unresolvedDisputes, []);
  assert.equal(
    receipt.adjudication.status,
    "CONFIRMED_NO_UNRESOLVED_DISPUTE",
  );
  assert.equal(receipt.adjudication.automaticJudgeUsed, false);
  assert.equal(
    receipt.acceptedSemantics.automaticJudgeMaySubstituteHumanBaseline,
    false,
  );
  assert.equal(
    receipt.acceptedSemantics.zeroToleranceFailureMayBeOverridden,
    false,
  );
});

test("the receipt is evidence-only and does not close P0-B11 or create governance state", () => {
  assert.equal(receipt.enterpriseDataUsed, false);
  assert.equal(receipt.governanceEffect, "EVIDENCE_ONLY");
  assert.equal(receipt.isProgressTracker, false);
  assert.equal(receipt.d1EventCreated, false);
  assert.equal(receipt.p0B11Closed, false);
  assert.deepEqual(receipt.independentReview, {
    required: false,
    status: "NOT_REQUIRED_FOR_F04_AC07",
  });
});

test("unknown fields, false run outcomes, widened governance claims, and forged approval text fail closed", async () => {
  const unknown = clone(receipt);
  unknown.ready = true;
  assert.equal(validateSchema(unknown), false);

  const falseOutcome = clone(receipt);
  falseOutcome.acceptedSemantics.evaluationRunExecuted = true;
  assert.equal(validateSchema(falseOutcome), false);

  const falseClosure = clone(receipt);
  falseClosure.p0B11Closed = true;
  assert.equal(validateSchema(falseClosure), false);

  const falseAuthorization = clone(receipt);
  falseAuthorization.authorization.sourceMessage.text =
    "APPROVE F04 EVALUATION BINDING";
  falseAuthorization.receiptSha256 = await sha256ProjectValue(
    withoutSelfHash(falseAuthorization),
  );
  await assert.rejects(() => validateReceipt(falseAuthorization));
});

test("candidate-byte, human-baseline, and receipt-hash tampering fail closed", async () => {
  const candidateTamper = clone(receipt);
  candidateTamper.candidate.fileSha256 = `sha256:${"0".repeat(64)}`;
  await assert.rejects(() => validateReceipt(candidateTamper));

  const baselineTamper = clone(receipt);
  baselineTamper.humanBaselineCandidateSha256 = `sha256:${"1".repeat(64)}`;
  await assert.rejects(() => validateReceipt(baselineTamper));

  const receiptTamper = clone(receipt);
  receiptTamper.receiptSha256 = `sha256:${"f".repeat(64)}`;
  await assert.rejects(() => validateReceipt(receiptTamper));
});
