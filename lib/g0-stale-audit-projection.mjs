import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";

const ERROR_SCHEMA_VERSION = "g0-stale-audit-error.v1";
const P0_IDS = Object.freeze(["F01", "F02", "F03", "F04"]);
const IMPLEMENTATION_STATUSES = new Set([
  "NOT_STARTED",
  "IN_PROGRESS",
  "IMPLEMENTED",
]);
const VERIFICATION_STATUSES = new Set(["NOT_VERIFIED", "VERIFIED"]);
const GATE_STATUSES = new Set([
  "NOT_READY",
  "READY_TO_SUBMIT",
  "AWAITING_DECISION",
  "APPROVED",
  "RETURNED",
  "HELD",
  "STALE_SUBMISSION",
]);
const GATE_DECISIONS = new Set([
  "APPROVE",
  "APPROVE_WITH_EXCLUSIONS",
  "RETURN",
  "HOLD",
]);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const RFC3339_DATE_TIME =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const SENSITIVE_PUBLIC_TEXT =
  /@|secret|token|credential|cookie|authorization|password|api[_-]?key|private[_-]?key/i;
const PROGRESS_REQUEST_TIME = Date.parse("2026-07-28T19:26:27.404Z");
const PROGRESS_CORRELATION_WINDOW_MS = 5_000;
const MAX_RESPONSE_BYTES = 16 * 1024;
const UTF8_ENCODER = new TextEncoder();
const NO_STORE_HEADERS = Object.freeze({
  "Cache-Control": "no-store",
});

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function base64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

async function json(body, status) {
  const bodyBytes = UTF8_ENCODER.encode(JSON.stringify(body));
  if (bodyBytes.byteLength >= MAX_RESPONSE_BYTES) {
    throw new Error("G0 stale audit response exceeds the fixed size limit.");
  }
  const digestBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bodyBytes),
  );
  return new Response(bodyBytes, {
    status,
    headers: {
      ...NO_STORE_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Content-Digest": `sha-256=:${base64(digestBytes)}:`,
      "X-Response-Body-SHA256": `sha256:${hex(digestBytes)}`,
      "X-Response-Body-Length": String(bodyBytes.byteLength),
    },
  });
}

function fail(message) {
  throw new Error(message);
}

function validDateTime(value) {
  return (
    typeof value === "string" &&
    RFC3339_DATE_TIME.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function validIsoUtc(value) {
  return validDateTime(value) && new Date(value).toISOString() === value;
}

function requireNonEmptyId(value) {
  if (typeof value !== "string" || !value.trim()) {
    fail("Invalid governed identifier.");
  }
  return value;
}

function requireEventId(value) {
  return requireNonEmptyId(value);
}

function publicMetadataId(value) {
  requireNonEmptyId(value);
  if (SENSITIVE_PUBLIC_TEXT.test(value)) {
    fail("Sensitive text is not safe for public metadata.");
  }
  return value;
}

function requireSha256(value) {
  if (!SHA256.test(value ?? "")) fail("Invalid SHA-256.");
  return value;
}

function requireEvidenceRefs(value) {
  if (
    !Array.isArray(value) ||
    value.some(
      (item) => typeof item !== "string" || !item.trim(),
    )
  ) {
    fail("Invalid evidence references.");
  }
  return value;
}

function requireEvidenceHashes(value) {
  if (
    !Array.isArray(value) ||
    value.some((item) => !SHA256.test(item))
  ) {
    fail("Invalid evidence hashes.");
  }
  return value;
}

function validateScope(scope) {
  if (!Array.isArray(scope) || scope.length !== P0_IDS.length) {
    fail("Invalid G0 work-package scope.");
  }
  const seen = new Set();
  for (const item of scope) {
    if (
      !item ||
      !P0_IDS.includes(item.work_package_id) ||
      seen.has(item.work_package_id) ||
      item.applicability !== "REQUIRED" ||
      !IMPLEMENTATION_STATUSES.has(item.implementation_status) ||
      !VERIFICATION_STATUSES.has(item.verification_status)
    ) {
      fail("Invalid G0 work-package scope.");
    }
    requireEvidenceRefs(item.evidence_refs);
    requireEvidenceHashes(item.evidence_hashes);
    seen.add(item.work_package_id);
  }
  if (P0_IDS.some((id) => !seen.has(id))) {
    fail("Incomplete G0 work-package scope.");
  }
  return scope;
}

function validateJournalState(journalState) {
  if (
    !journalState ||
    !Number.isInteger(journalState.revision) ||
    journalState.revision < 0 ||
    !Array.isArray(journalState.events) ||
    journalState.events.length !== journalState.revision
  ) {
    fail("Invalid governance ledger projection.");
  }
  const eventIds = new Set();
  for (const [index, event] of journalState.events.entries()) {
    if (
      !event ||
      event.revision !== index + 1 ||
      typeof event.type !== "string" ||
      !event.type ||
      !validDateTime(event.createdAt) ||
      eventIds.has(event.id)
    ) {
      fail("Invalid governance event sequence.");
    }
    requireEventId(event.id);
    eventIds.add(event.id);
  }
}

function validateWorkPackageEvent(event) {
  const payload = event.payload;
  if (
    !payload ||
    !P0_IDS.includes(payload.workPackageId) ||
    !IMPLEMENTATION_STATUSES.has(payload.implementationStatus) ||
    !VERIFICATION_STATUSES.has(payload.verificationStatus)
  ) {
    fail("Invalid P0 work-package event.");
  }
  requireEvidenceRefs(payload.evidenceRefs);
  requireEvidenceHashes(payload.evidenceHashes);
  return event;
}

function validateSubmissionEvent(event) {
  const payload = event.payload;
  if (
    !payload ||
    payload.gate_id !== "G0" ||
    !Number.isInteger(payload.source_revision) ||
    payload.source_revision !== event.revision - 1 ||
    !validDateTime(payload.submitted_at)
  ) {
    fail("Invalid G0 submission event.");
  }
  requireNonEmptyId(payload.submission_id);
  requireSha256(payload.package_hash);
  requireEvidenceRefs(payload.evidence_refs);
  validateScope(payload.work_package_scope);
  if (payload.supersedes !== null) requireNonEmptyId(payload.supersedes);
  return event;
}

function validateDecisionEvent(event, submission) {
  const payload = event.payload;
  if (
    !payload ||
    !submission ||
    event.revision <= submission.revision ||
    payload.submission_id !== submission.payload.submission_id ||
    payload.package_hash !== submission.payload.package_hash ||
    !GATE_DECISIONS.has(payload.decision) ||
    !validDateTime(payload.decided_at)
  ) {
    fail("Invalid G0 decision event.");
  }
  requireNonEmptyId(payload.decision_id);
  requireEvidenceRefs(payload.evidence_refs);
  return event;
}

function summarizeWorkPackage(event) {
  if (!event) return null;
  return {
    eventId: publicMetadataId(event.id),
    revision: event.revision,
    implementationStatus: event.payload.implementationStatus,
    verificationStatus: event.payload.verificationStatus,
    evidenceHashes: [...event.payload.evidenceHashes],
    recordedAt: event.createdAt,
  };
}

function summarizeSubmission(event) {
  if (!event) return null;
  return {
    eventId: publicMetadataId(event.id),
    revision: event.revision,
    submissionId: publicMetadataId(event.payload.submission_id),
    sourceRevision: event.payload.source_revision,
    packageHash: event.payload.package_hash,
    recordedAt: event.createdAt,
  };
}

function summarizeDecision(event) {
  if (!event) return null;
  return {
    eventId: publicMetadataId(event.id),
    revision: event.revision,
    decisionId: publicMetadataId(event.payload.decision_id),
    submissionId: publicMetadataId(event.payload.submission_id),
    packageHash: event.payload.package_hash,
    decision: event.payload.decision,
    recordedAt: event.createdAt,
  };
}

function valueDiff(submitted, current) {
  return canonicalizeProjectJson(submitted) ===
    canonicalizeProjectJson(current)
    ? null
    : { submitted, current };
}

async function scopeDiff(submittedScope, currentScope) {
  if (!submittedScope) return [];
  const submittedById = new Map(
    submittedScope.map((item) => [item.work_package_id, item]),
  );
  const currentById = new Map(
    currentScope.map((item) => [item.work_package_id, item]),
  );
  const result = [];
  for (const workPackageId of P0_IDS) {
    const submitted = submittedById.get(workPackageId);
    const current = currentById.get(workPackageId);
    const fields = {};
    const applicability = valueDiff(
      submitted.applicability,
      current.applicability,
    );
    const implementationStatus = valueDiff(
      submitted.implementation_status,
      current.implementation_status,
    );
    const verificationStatus = valueDiff(
      submitted.verification_status,
      current.verification_status,
    );
    const evidenceHashes = valueDiff(
      submitted.evidence_hashes,
      current.evidence_hashes,
    );
    const evidenceRefsMatch =
      canonicalizeProjectJson(submitted.evidence_refs) ===
      canonicalizeProjectJson(current.evidence_refs);
    if (applicability) fields.applicability = applicability;
    if (implementationStatus) {
      fields.implementationStatus = implementationStatus;
    }
    if (verificationStatus) {
      fields.verificationStatus = verificationStatus;
    }
    if (evidenceHashes) fields.evidenceHashes = evidenceHashes;
    if (!evidenceRefsMatch) {
      fields.evidenceRefs = {
        submittedCount: submitted.evidence_refs.length,
        currentCount: current.evidence_refs.length,
        submittedSha256: await sha256ProjectValue(submitted.evidence_refs),
        currentSha256: await sha256ProjectValue(current.evidence_refs),
      };
    }
    if (Object.keys(fields).length > 0) {
      result.push({ workPackageId, fields });
    }
  }
  return result;
}

export async function projectG0StaleAudit({
  journalState,
  snapshot,
  serverTime,
}) {
  if (!validIsoUtc(serverTime)) fail("Invalid audit server time.");
  validateJournalState(journalState);
  const gate = snapshot?.gates?.find(({ id }) => id === "G0");
  if (
    snapshot?.revision !== journalState.revision ||
    !gate ||
    !GATE_STATUSES.has(gate.status)
  ) {
    throw new Error("Invalid G0 audit input.");
  }
  const currentScope = validateScope(gate.workPackageScope);
  const latestWorkPackageEvents = new Map();
  const submissions = [];
  for (const event of journalState.events) {
    if (
      event.type === "WORK_PACKAGE_RECORDED" &&
      P0_IDS.includes(event.payload?.workPackageId)
    ) {
      latestWorkPackageEvents.set(
        event.payload.workPackageId,
        validateWorkPackageEvent(event),
      );
    } else if (event.type === "GATE_SUBMITTED" && event.payload?.gate_id === "G0") {
      submissions.push(validateSubmissionEvent(event));
    }
  }
  const submissionIds = new Set();
  for (const [index, submission] of submissions.entries()) {
    const submissionId = submission.payload.submission_id;
    if (submissionIds.has(submissionId)) fail("Duplicate G0 submission ID.");
    submissionIds.add(submissionId);
    const prior = submissions[index - 1] ?? null;
    if (
      (prior === null && submission.payload.supersedes !== null) ||
      (prior !== null &&
        submission.payload.supersedes !== prior.payload.submission_id)
    ) {
      fail("Invalid G0 submission supersession.");
    }
  }
  const latestSubmissionEvent = submissions.at(-1) ?? null;
  const decisionIds = new Set();
  const decisionsBySubmission = new Map();
  for (const event of journalState.events) {
    if (
      event.type !== "GATE_DECIDED" ||
      !submissionIds.has(event.payload?.submission_id)
    ) {
      continue;
    }
    const submission = submissions.find(
      ({ payload }) =>
        payload.submission_id === event.payload.submission_id,
    );
    validateDecisionEvent(event, submission);
    if (
      decisionIds.has(event.payload.decision_id) ||
      decisionsBySubmission.has(event.payload.submission_id)
    ) {
      fail("Duplicate G0 decision.");
    }
    decisionIds.add(event.payload.decision_id);
    decisionsBySubmission.set(event.payload.submission_id, event);
  }
  const latestDecisionEvent = latestSubmissionEvent
    ? decisionsBySubmission.get(latestSubmissionEvent.payload.submission_id) ??
      null
    : null;
  const submittedScope =
    latestSubmissionEvent?.payload.work_package_scope ?? null;
  const scopeMatches =
    submittedScope === null
      ? null
      : canonicalizeProjectJson(submittedScope) ===
        canonicalizeProjectJson(currentScope);
  const allRequiredVerified = currentScope.every(
    ({ verification_status }) => verification_status === "VERIFIED",
  );
  const evaluatesToStale =
    latestSubmissionEvent !== null &&
    scopeMatches === false &&
    !(latestDecisionEvent && allRequiredVerified);
  if ((gate.status === "STALE_SUBMISSION") !== evaluatesToStale) {
    fail("G0 stale projection mismatch.");
  }
  let staleReasonCode = null;
  if (evaluatesToStale) {
    staleReasonCode = allRequiredVerified
      ? "CURRENT_SCOPE_MISMATCH_WITHOUT_DECISION"
      : "CURRENT_SCOPE_MISMATCH_REQUIRED_NOT_VERIFIED";
  }
  const progressRequestGovernanceEventRevisions = journalState.events
    .filter(
      ({ createdAt }) =>
        Math.abs(Date.parse(createdAt) - PROGRESS_REQUEST_TIME) <=
        PROGRESS_CORRELATION_WINDOW_MS,
    )
    .map(({ revision }) => revision);
  return {
    schemaVersion: "g0-stale-audit.v1",
    source: "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
    revision: journalState.revision,
    g0: {
      status: gate.status,
      staleReasonCode,
      staleCondition: {
        latestSubmissionExists: latestSubmissionEvent !== null,
        latestDecisionExists: latestDecisionEvent !== null,
        scopeMismatch: scopeMatches === false,
        requiredNotVerified: !allRequiredVerified,
        evaluatesToStale,
      },
    },
    latestSubmission: summarizeSubmission(latestSubmissionEvent),
    latestDecision: summarizeDecision(latestDecisionEvent),
    workPackages: Object.fromEntries(
      P0_IDS.map((id) => [id, summarizeWorkPackage(latestWorkPackageEvents.get(id))]),
    ),
    scopeDiff: await scopeDiff(submittedScope, currentScope),
    scopeMatch: scopeMatches,
    allRequiredVerified,
    hasSupersession: submissions.some(
      ({ payload }) => payload.supersedes !== null,
    ),
    progressRequestGovernanceEventRevisions,
    governanceEventsWriteAssessment: "UNPROVABLE",
    serverTime,
  };
}

export function createG0StaleAuditGet({
  configuredProductOwner,
  isProductOwner,
  loadAuditInput,
  clock,
}) {
  void loadAuditInput;
  void clock;
  return async function GET(request) {
    const actor = request.headers.get("oai-authenticated-user-email");
    if (!actor) {
      return json(
        {
          schemaVersion: ERROR_SCHEMA_VERSION,
          code: "AUTHENTICATION_REQUIRED",
          error: "需要先通过工作区身份验证。",
        },
        401,
      );
    }
    const productOwner = configuredProductOwner();
    if (typeof productOwner !== "string" || !productOwner.trim()) {
      return json(
        {
          schemaVersion: ERROR_SCHEMA_VERSION,
          code: "PRODUCT_OWNER_NOT_CONFIGURED",
          error: "产品所有者身份尚未配置。",
        },
        503,
      );
    }
    if (!isProductOwner(actor, productOwner)) {
      return json(
        {
          schemaVersion: ERROR_SCHEMA_VERSION,
          code: "PRODUCT_OWNER_REQUIRED",
          error: "只有外部产品所有者可以读取 G0 stale 审计。",
        },
        403,
      );
    }
    if (new URL(request.url).search) {
      return json(
        {
          schemaVersion: ERROR_SCHEMA_VERSION,
          code: "QUERY_PARAMETERS_NOT_ALLOWED",
          error: "该只读端点不接受查询参数。",
        },
        400,
      );
    }
    try {
      const auditInput = await loadAuditInput();
      return await json(
        await projectG0StaleAudit({
          ...auditInput,
          serverTime: clock(),
        }),
        200,
      );
    } catch {
      return json(
        {
          schemaVersion: ERROR_SCHEMA_VERSION,
          code: "G0_STALE_AUDIT_UNAVAILABLE",
          error: "线上 G0 stale 审计暂时不可用。",
        },
        503,
      );
    }
  };
}
