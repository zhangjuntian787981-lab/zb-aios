import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";

const ERROR_SCHEMA_VERSION = "g0-decision-error.v1";
const SOURCE = "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER";
const MAX_REQUEST_BYTES = 4 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024;
const UTF8_ENCODER = new TextEncoder();
const EVENT_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/;
const GOVERNED_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,159}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const JSON_CONTENT_TYPE =
  /^[\t ]*application\/json(?:[\t ]*;[\t ]*charset[\t ]*=[\t ]*utf-8)?[\t ]*$/i;
const ACTOR_CONTEXT = Object.freeze({
  actorId: "external_product_owner",
  roles: Object.freeze(["PRODUCT_OWNER"]),
});
const REMEDIATION_SUBMISSION_BINDING = Object.freeze({
  sourceRevision: 68,
  supersedes: "06531499-9cc4-4b09-b0c4-1f6d18e36fd6",
  idempotencyKey: "g0-remediation-20260729-001:05-G0-SUBMIT",
  commandHash:
    "sha256:06bcc209cb6b23597f71970a017324d17b2b1b60cfb530eb499cb981beec2ab5",
});
const DECISION_COMMAND_HASH =
  "sha256:5a3fadaf4167f19de9f5a5c3b8b6d6c6645a35df743d5383543861d166249a4e";

export const G0_DECISION_BINDING = Object.freeze({
  expectedRevision: 69,
  resultRevision: 70,
  submissionId: "be08e1d3-1e9c-43a0-aa2e-f93a800b5105",
  packageHash:
    "sha256:d4e449a305a6f496e24fb777d1d883d8c02f0d7e3165d00fc90561c1d14421b0",
  decision: "APPROVE",
  idempotencyKey: "g0-decision-be08e1d3-approve-20260729-001",
  confirmation: "CONFIRM_G0_DECISION",
});

class G0DecisionError extends Error {
  constructor(code, message, status = 503) {
    super(message);
    this.name = "G0DecisionError";
    this.code = code;
    this.status = status;
  }
}

function failure(code, message, status = 503) {
  return new G0DecisionError(code, message, status);
}

function fail(code, message, status) {
  throw failure(code, message, status);
}

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function base64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

async function json(body, status = 200) {
  const bodyBytes = UTF8_ENCODER.encode(JSON.stringify(body));
  if (bodyBytes.byteLength >= MAX_RESPONSE_BYTES) {
    throw new Error("G0 decision response exceeds the fixed size limit.");
  }
  const digestBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bodyBytes),
  );
  return new Response(bodyBytes, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "Content-Digest": `sha-256=:${base64(digestBytes)}:`,
      "X-Response-Body-SHA256": `sha256:${hex(digestBytes)}`,
      "X-Response-Body-Length": String(bodyBytes.byteLength),
    },
  });
}

function errorResponse(code, error, status) {
  return json(
    {
      schemaVersion: ERROR_SCHEMA_VERSION,
      code,
      error,
    },
    status,
  );
}

function same(left, right) {
  return JSON.stringify(Object.keys(left).sort()) ===
    JSON.stringify(Object.keys(right).sort());
}

function sameValue(left, right) {
  return canonicalizeProjectJson(left) === canonicalizeProjectJson(right);
}

function validUtc(value) {
  return (
    typeof value === "string" &&
    Number.isFinite(Date.parse(value)) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value)
  );
}

async function authorize({
  request,
  configuredProductOwner,
  isProductOwner,
}) {
  const actor =
    request.headers.get("oai-authenticated-user-email")?.trim() ?? "";
  if (!actor) {
    return errorResponse(
      "AUTHENTICATION_REQUIRED",
      "需要先通过工作区身份验证。",
      401,
    );
  }
  const productOwner = configuredProductOwner();
  if (typeof productOwner !== "string" || !productOwner.trim()) {
    return errorResponse(
      "PRODUCT_OWNER_NOT_CONFIGURED",
      "产品所有者身份尚未配置。",
      503,
    );
  }
  if (!isProductOwner(actor, productOwner)) {
    return errorResponse(
      "PRODUCT_OWNER_REQUIRED",
      "只有外部产品所有者可以使用 G0 Decision 通道。",
      403,
    );
  }
  return null;
}

function assertValidJournalProjection(snapshot) {
  if (
    !Number.isInteger(snapshot?.revision) ||
    snapshot.revision < 0 ||
    !Array.isArray(snapshot.events) ||
    snapshot.events.length !== snapshot.revision
  ) {
    fail(
      "ONLINE_D1_INVALID",
      "线上 D1 治理事件序列无效。",
    );
  }
  const eventIds = new Set();
  const submissions = new Set();
  const decisions = new Set();
  for (const [index, event] of snapshot.events.entries()) {
    if (
      !event ||
      event.revision !== index + 1 ||
      !EVENT_ID.test(event.id ?? "") ||
      eventIds.has(event.id)
    ) {
      fail(
        "ONLINE_D1_INVALID",
        "线上 D1 治理事件序列无效。",
      );
    }
    eventIds.add(event.id);
    if (event.type === "GATE_SUBMITTED") {
      const submissionId = event.payload?.submission_id;
      if (
        !GOVERNED_ID.test(submissionId ?? "") ||
        !SHA256.test(event.payload?.package_hash ?? "") ||
        submissions.has(submissionId)
      ) {
        fail(
          "ONLINE_D1_INVALID",
          "线上 D1 Gate Submission 序列无效。",
        );
      }
      submissions.add(submissionId);
    } else if (event.type === "GATE_DECIDED") {
      const submissionId = event.payload?.submission_id;
      if (
        !submissions.has(submissionId) ||
        decisions.has(submissionId) ||
        !GOVERNED_ID.test(event.payload?.decision_id ?? "") ||
        !SHA256.test(event.payload?.package_hash ?? "")
      ) {
        fail(
          "ONLINE_D1_INVALID",
          "线上 D1 Gate Decision 因果顺序无效。",
        );
      }
      decisions.add(submissionId);
    }
  }
}

async function fixedSubmissionProvenanceMatches({
  snapshot,
  g0,
  submissionEvent,
}) {
  const payload = submissionEvent?.payload;
  if (
    submissionEvent?.revision !== G0_DECISION_BINDING.expectedRevision ||
    submissionEvent.type !== "GATE_SUBMITTED" ||
    submissionEvent.actorId !== ACTOR_CONTEXT.actorId ||
    submissionEvent.idempotencyKey !==
      REMEDIATION_SUBMISSION_BINDING.idempotencyKey ||
    submissionEvent.commandHash !==
      REMEDIATION_SUBMISSION_BINDING.commandHash ||
    payload?.gate_id !== "G0" ||
    payload.submission_id !== G0_DECISION_BINDING.submissionId ||
    payload.package_hash !== G0_DECISION_BINDING.packageHash ||
    payload.submitted_by !== ACTOR_CONTEXT.actorId ||
    !validUtc(payload.submitted_at) ||
    payload.source_revision !==
      REMEDIATION_SUBMISSION_BINDING.sourceRevision ||
    payload.supersedes !== REMEDIATION_SUBMISSION_BINDING.supersedes ||
    !sameValue(payload.work_package_scope, g0?.workPackageScope) ||
    !sameValue(
      payload.evidence_refs,
      g0?.workPackageScope.flatMap(({ evidence_refs }) => evidence_refs),
    )
  ) {
    return false;
  }
  return (
    (await sha256ProjectValue({
      manifest_version: snapshot.manifestVersion,
      gate_id: "G0",
      source_revision: REMEDIATION_SUBMISSION_BINDING.sourceRevision,
      work_package_scope: payload.work_package_scope,
      evidence_refs: payload.evidence_refs,
    })) === G0_DECISION_BINDING.packageHash
  );
}

async function preview(snapshot, serverTime) {
  assertValidJournalProjection(snapshot);
  const p0Ids = new Set(["F01", "F02", "F03", "F04"]);
  const g0 = snapshot.gates.find(({ id }) => id === "G0");
  const g1 = snapshot.gates.find(({ id }) => id === "G1");
  const submission = g0?.latestSubmission;
  const submissionEvent = snapshot.events.find(
    ({ type, payload }) =>
      type === "GATE_SUBMITTED" &&
      payload?.submission_id === submission?.submission_id,
  );
  const allP0Verified = ["F01", "F02", "F03", "F04"].every(
    (id) =>
      snapshot.workPackages.find((item) => item.id === id)
        ?.verificationStatus === "VERIFIED",
  );
  const blockers = [];
  if (snapshot.revision !== G0_DECISION_BINDING.expectedRevision) {
    blockers.push("REVISION_MISMATCH");
  }
  if (g0?.status !== "AWAITING_DECISION") {
    blockers.push("G0_NOT_AWAITING_DECISION");
  }
  if (submission?.submission_id !== G0_DECISION_BINDING.submissionId) {
    blockers.push("SUBMISSION_ID_MISMATCH");
  }
  if (submission?.package_hash !== G0_DECISION_BINDING.packageHash) {
    blockers.push("PACKAGE_HASH_MISMATCH");
  }
  if (submissionEvent?.revision !== G0_DECISION_BINDING.expectedRevision) {
    blockers.push("SUBMISSION_REVISION_MISMATCH");
  }
  if (
    !(await fixedSubmissionProvenanceMatches({
      snapshot,
      g0,
      submissionEvent,
    }))
  ) {
    blockers.push("SUBMISSION_PROVENANCE_MISMATCH");
  }
  if (g0?.latestDecision) blockers.push("DECISION_ALREADY_EXISTS");
  if (!allP0Verified) blockers.push("P0_NOT_VERIFIED");
  if (
    snapshot.evidenceValidationIssues.some(({ workPackageId }) =>
      p0Ids.has(workPackageId),
    )
  ) {
    blockers.push("P0_EVIDENCE_NOT_FROZEN");
  }
  if (g1?.status !== "APPROVED") blockers.push("G1_NOT_APPROVED");
  if (snapshot.phaseEntry.P2) blockers.push("PHASE_ENTRY_P2_ALREADY_OPEN");
  if (
    snapshot.events.some(
      ({ type }) => type === "P2_ACCEPTANCE_PROFILE_APPROVED",
    )
  ) {
    blockers.push("P2_PROFILE_EVENT_PRESENT");
  }
  for (const workPackageId of ["O02", "O03"]) {
    if (
      snapshot.events.some(
        ({ type, payload }) =>
          type === "P2_WORK_PACKAGE_START_AUTHORIZED" &&
          payload?.work_package_id === workPackageId,
      )
    ) {
      blockers.push(`${workPackageId}_START_AUTHORIZATION_EVENT_PRESENT`);
    }
    const item = snapshot.workPackages.find(
      ({ id }) => id === workPackageId,
    );
    if (
      item?.allowedToStart === true ||
      item?.startAuthorization?.executionStatus !== "NOT_AUTHORIZED"
    ) {
      blockers.push(`${workPackageId}_START_BOUNDARY_MISMATCH`);
    }
  }

  return {
    schemaVersion: "g0-decision-preview.v1",
    source: SOURCE,
    revision: snapshot.revision,
    g0Status: g0?.status ?? "NOT_READY",
    latestSubmission: submission
      ? {
          submissionId: submission.submission_id,
          packageHash: submission.package_hash,
          revision: submissionEvent?.revision ?? null,
        }
      : null,
    latestDecisionExists: Boolean(g0?.latestDecision),
    allP0Verified,
    g1Status: g1?.status ?? "NOT_READY",
    phaseEntryP2: snapshot.phaseEntry.P2 === true,
    approveImpact: {
      decision: G0_DECISION_BINDING.decision,
      resultRevision: G0_DECISION_BINDING.resultRevision,
      g0Status: "APPROVED",
      phaseEntryP2: g1?.status === "APPROVED",
      profileApprovalChanges: 0,
      workPackageStatusChanges: 0,
      startAuthorizationChanges: 0,
    },
    canDecide: blockers.length === 0,
    blockers,
    serverTime,
  };
}

function assertNoQuery(request) {
  if (new URL(request.url).search) {
    fail(
      "QUERY_PARAMETERS_FORBIDDEN",
      "G0 Decision 通道不接受查询参数。",
      400,
    );
  }
}

function assertSameOriginMutation(request) {
  if (
    request.headers.get("origin") !== new URL(request.url).origin ||
    request.headers.get("sec-fetch-site") !== "same-origin"
  ) {
    fail(
      "CROSS_SITE_REQUEST_FORBIDDEN",
      "POST 必须来自当前应用的同源页面。",
      403,
    );
  }
}

async function parsePostBody(request) {
  if (!JSON_CONTENT_TYPE.test(request.headers.get("content-type") ?? "")) {
    fail("INVALID_REQUEST", "POST 必须使用 UTF-8 JSON 请求体。", 400);
  }
  const contentLength = request.headers.get("content-length");
  if (
    contentLength !== null &&
    (!/^(?:0|[1-9]\d*)$/.test(contentLength.trim()) ||
      Number(contentLength) > MAX_REQUEST_BYTES)
  ) {
    fail("INVALID_REQUEST", "POST 请求体大小声明无效。", 400);
  }
  const text = await request.text();
  if (UTF8_ENCODER.encode(text).byteLength > MAX_REQUEST_BYTES) {
    fail("INVALID_REQUEST", "POST 请求体超过固定大小限制。", 400);
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    fail("INVALID_REQUEST", "POST 请求体不是有效 JSON。", 400);
  }
  const expectedKeys = [
    "confirmation",
    "decision",
    "expectedRevision",
    "idempotencyKey",
    "packageHash",
    "submissionId",
  ];
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    !same(body, Object.fromEntries(expectedKeys.map((key) => [key, true])))
  ) {
    fail("INVALID_REQUEST", "POST 请求字段不完整或包含未知字段。", 400);
  }
  for (const key of expectedKeys) {
    if (body[key] !== G0_DECISION_BINDING[key]) {
      fail(
        {
          expectedRevision: "EXPECTED_REVISION_MISMATCH",
          submissionId: "SUBMISSION_ID_MISMATCH",
          packageHash: "PACKAGE_HASH_MISMATCH",
          decision: "DECISION_MISMATCH",
          idempotencyKey: "IDEMPOTENCY_KEY_MISMATCH",
          confirmation: "CONFIRMATION_MISMATCH",
        }[key],
        "POST 确认值与固定 G0 Decision 不匹配。",
        key === "idempotencyKey" || key === "confirmation" ? 400 : 409,
      );
    }
  }
  return body;
}

function command() {
  return {
    kind: "DECIDE_GATE",
    submissionId: G0_DECISION_BINDING.submissionId,
    expectedPackageHash: G0_DECISION_BINDING.packageHash,
    decision: G0_DECISION_BINDING.decision,
    acceptedExclusions: [],
    evidenceRefs: [
      `product-owner-decision:${G0_DECISION_BINDING.submissionId}:${G0_DECISION_BINDING.packageHash}:${G0_DECISION_BINDING.decision}`,
    ],
    expectedRevision: G0_DECISION_BINDING.expectedRevision,
    idempotencyKey: G0_DECISION_BINDING.idempotencyKey,
  };
}

function matchingDecisionEvent(snapshot) {
  const decisions = snapshot.events.filter(
    ({ type, payload }) =>
      type === "GATE_DECIDED" &&
      payload?.submission_id === G0_DECISION_BINDING.submissionId,
  );
  return decisions.length === 1 ? decisions[0] : null;
}

function hasMatchingCompletedDecision(snapshot) {
  const event = matchingDecisionEvent(snapshot);
  if (!event || snapshot.revision !== G0_DECISION_BINDING.resultRevision) {
    return false;
  }
  const payload = event.payload;
  return (
    event.revision === G0_DECISION_BINDING.resultRevision &&
    event.idempotencyKey === G0_DECISION_BINDING.idempotencyKey &&
    event.commandHash === DECISION_COMMAND_HASH &&
    event.actorId === ACTOR_CONTEXT.actorId &&
    validUtc(event.createdAt) &&
    GOVERNED_ID.test(payload.decision_id ?? "") &&
    payload.package_hash === G0_DECISION_BINDING.packageHash &&
    payload.decision === G0_DECISION_BINDING.decision &&
    payload.decided_by === ACTOR_CONTEXT.actorId &&
    validUtc(payload.decided_at) &&
    Array.isArray(payload.accepted_exclusions) &&
    payload.accepted_exclusions.length === 0 &&
    JSON.stringify(payload.evidence_refs) ===
      JSON.stringify(command().evidenceRefs)
  );
}

async function completedDecisionStateMatches(snapshot) {
  const p0Ids = new Set(["F01", "F02", "F03", "F04"]);
  const g0 = snapshot.gates.find(({ id }) => id === "G0");
  const g1 = snapshot.gates.find(({ id }) => id === "G1");
  const submissionEvent = snapshot.events.find(
    ({ type, payload }) =>
      type === "GATE_SUBMITTED" &&
      payload?.submission_id === G0_DECISION_BINDING.submissionId,
  );
  if (
    !hasMatchingCompletedDecision(snapshot) ||
    !(await fixedSubmissionProvenanceMatches({
      snapshot,
      g0,
      submissionEvent,
    })) ||
    g0?.status !== "APPROVED" ||
    g1?.status !== "APPROVED" ||
    snapshot.phaseEntry.P2 !== true ||
    !["F01", "F02", "F03", "F04"].every(
      (id) =>
        snapshot.workPackages.find((item) => item.id === id)
          ?.verificationStatus === "VERIFIED",
    ) ||
    snapshot.evidenceValidationIssues.some(({ workPackageId }) =>
      p0Ids.has(workPackageId),
    ) ||
    snapshot.events.some(
      ({ type }) => type === "P2_ACCEPTANCE_PROFILE_APPROVED",
    )
  ) {
    return false;
  }
  return ["O02", "O03"].every((workPackageId) => {
    const item = snapshot.workPackages.find(
      ({ id }) => id === workPackageId,
    );
    return (
      !snapshot.events.some(
        ({ type, payload }) =>
          type === "P2_WORK_PACKAGE_START_AUTHORIZED" &&
          payload?.work_package_id === workPackageId,
      ) &&
      item?.startAuthorization?.executionStatus === "NOT_AUTHORIZED" &&
      item.allowedToStart === false
    );
  });
}

async function executionBody(snapshot, receipt, serverTime) {
  assertValidJournalProjection(snapshot);
  const g0 = snapshot.gates.find(({ id }) => id === "G0");
  const decision = g0?.latestDecision;
  const event = matchingDecisionEvent(snapshot);
  const profileApproval =
    snapshot.events.find(
      ({ type }) => type === "P2_ACCEPTANCE_PROFILE_APPROVED",
    ) ?? null;
  const workPackage = (id) => {
    const item = snapshot.workPackages.find((candidate) => candidate.id === id);
    return {
      startAuthorizationStatus:
        item?.startAuthorization?.executionStatus ?? "NOT_AUTHORIZED",
      allowedToStart: item?.allowedToStart === true,
    };
  };
  if (
    !(await completedDecisionStateMatches(snapshot)) ||
    receipt?.revision !== G0_DECISION_BINDING.resultRevision ||
    receipt?.eventId !== event?.id ||
    typeof receipt?.duplicate !== "boolean" ||
    !sameValue(receipt?.output?.decision, event?.payload) ||
    decision?.submission_id !== G0_DECISION_BINDING.submissionId ||
    decision.package_hash !== G0_DECISION_BINDING.packageHash ||
    decision.decision !== G0_DECISION_BINDING.decision ||
    g0.status !== "APPROVED" ||
    snapshot.phaseEntry.P2 !== true ||
    profileApproval !== null ||
    workPackage("O02").startAuthorizationStatus !== "NOT_AUTHORIZED" ||
    workPackage("O02").allowedToStart ||
    workPackage("O03").startAuthorizationStatus !== "NOT_AUTHORIZED" ||
    workPackage("O03").allowedToStart
  ) {
    fail(
      "READBACK_MISMATCH",
      "G0 Decision 写入后的线上回读不匹配。",
    );
  }
  return {
    schemaVersion: "g0-decision-execution.v1",
    source: SOURCE,
    status: "COMPLETED",
    revision: snapshot.revision,
    decisionEvent: {
      eventId: event.id,
      revision: event.revision,
      decisionId: decision.decision_id,
      submissionId: decision.submission_id,
      packageHash: decision.package_hash,
      decision: decision.decision,
    },
    duplicate: receipt.duplicate,
    g0Status: g0.status,
    phaseEntryP2: true,
    profileApproval: null,
    workPackages: {
      O02: workPackage("O02"),
      O03: workPackage("O03"),
    },
    serverTime,
  };
}

function publicError(error) {
  if (error instanceof G0DecisionError) {
    return {
      code: error.code,
      message: error.message,
      status: error.status,
    };
  }
  if (
    [
      "DECISION_EXISTS",
      "EVIDENCE_NOT_FROZEN",
      "HASH_MISMATCH",
      "IDEMPOTENCY_CONFLICT",
      "STALE_REVISION",
      "STALE_SUBMISSION",
      "UNKNOWN_ID",
    ].includes(error?.code)
  ) {
    return {
      code: error.code,
      message: "线上 G0 Decision 状态已变化。",
      status: 409,
    };
  }
  return {
    code: "G0_DECISION_UNAVAILABLE",
    message: "线上 G0 Decision 通道暂时不可用。",
    status: 503,
  };
}

export function createG0DecisionHandlers({
  configuredProductOwner,
  isProductOwner,
  createRuntime,
  clock = () => new Date().toISOString(),
}) {
  async function GET(request) {
    try {
      const denied = await authorize({
        request,
        configuredProductOwner,
        isProductOwner,
      });
      if (denied) return denied;
      assertNoQuery(request);
      const runtime = await createRuntime({ readOnly: true });
      return json(await preview(await runtime.control.snapshot(), clock()));
    } catch (error) {
      const publicFailure = publicError(error);
      return errorResponse(
        publicFailure.code,
        publicFailure.message,
        publicFailure.status,
      );
    }
  }

  async function POST(request) {
    try {
      const denied = await authorize({
        request,
        configuredProductOwner,
        isProductOwner,
      });
      if (denied) return denied;
      assertSameOriginMutation(request);
      assertNoQuery(request);
      await parsePostBody(request);
      const runtime = await createRuntime({ readOnly: false });
      const beforeSnapshot = await runtime.control.snapshot();
      const before = await preview(beforeSnapshot, clock());
      if (
        !before.canDecide &&
        !(await completedDecisionStateMatches(beforeSnapshot))
      ) {
        fail(
          "G0_DECISION_NOT_ALLOWED",
          "当前线上投影不允许执行固定 G0 Decision。",
          409,
        );
      }
      const receipt = await runtime.control.execute(
        ACTOR_CONTEXT,
        command(),
      );
      const after = await runtime.control.snapshot();
      return json(await executionBody(after, receipt, clock()));
    } catch (error) {
      const publicFailure = publicError(error);
      return errorResponse(
        publicFailure.code,
        publicFailure.message,
        publicFailure.status,
      );
    }
  }

  return Object.freeze({ GET, POST });
}
