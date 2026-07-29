import {
  F04_HISTORICAL_AUTHORITY_BINDING,
  assertUniqueF04HistoricalAuthority,
} from "./f04-historical-authority.mjs";
import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";

const ERROR_SCHEMA_VERSION = "p0-b11-evidence-error.v1";
const SOURCE = "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER";
const P0_IDS = Object.freeze(["F01", "F02", "F03", "F04"]);
const PROJECT_ID = "generic-multi-enterprise-ai-platform-v5";
const MANIFEST_VERSION = "1.0.0";
const ACTOR_ID = "external_product_owner";
const REMEDIATION_ROOT_KEY = "g0-remediation-20260729-001";
const RECORD_NOTE =
  "G0 remediation from the frozen P0 evidence catalog.";
const F04_RECORD_NOTE =
  `G0 remediation preserves F04 human-baseline authority from online D1 revision 1 (${F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256}).`;
const CURRENT_G0 = Object.freeze({
  submissionRevision: 69,
  decisionRevision: 70,
  submissionId: "be08e1d3-1e9c-43a0-aa2e-f93a800b5105",
  sourceRevision: 68,
  packageHash:
    "sha256:d4e449a305a6f496e24fb777d1d883d8c02f0d7e3165d00fc90561c1d14421b0",
  decision: "APPROVE",
  submissionIdempotencyKey:
    "g0-remediation-20260729-001:05-G0-SUBMIT",
  submissionCommandHash:
    "sha256:06bcc209cb6b23597f71970a017324d17b2b1b60cfb530eb499cb981beec2ab5",
  decisionIdempotencyKey:
    "g0-decision-be08e1d3-approve-20260729-001",
  decisionCommandHash:
    "sha256:5a3fadaf4167f19de9f5a5c3b8b6d6c6645a35df743d5383543861d166249a4e",
});
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const PUBLIC_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$/;
const SENSITIVE_TEXT =
  /@|secret|token|credential|cookie|authorization|password|api[_-]?key|private[_-]?key/i;
const EVIDENCE_REF =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._\-/\u4e00-\u9fff]{1,240}$/u;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const MAX_RESPONSE_BYTES = 16 * 1024;
const UTF8_ENCODER = new TextEncoder();

class P0B11EvidenceError extends Error {
  constructor(code, message, status = 503) {
    super(message);
    this.name = "P0B11EvidenceError";
    this.code = code;
    this.status = status;
  }
}

function fail(code, message, status = 503) {
  throw new P0B11EvidenceError(code, message, status);
}

function same(left, right) {
  return canonicalizeProjectJson(left) === canonicalizeProjectJson(right);
}

function validTime(value) {
  return (
    typeof value === "string" &&
    RFC3339.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function requirePublicId(value) {
  if (
    !PUBLIC_ID.test(value ?? "") ||
    SENSITIVE_TEXT.test(value)
  ) {
    fail("ONLINE_D1_INVALID", "线上 D1 包含不安全的治理标识符。");
  }
  return value;
}

function requireSha256(value) {
  if (!SHA256.test(value ?? "")) {
    fail("ONLINE_D1_INVALID", "线上 D1 包含无效的 SHA-256。");
  }
  return value;
}

function requireEvidenceRefs(value) {
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.length > 16 ||
    value.some((item) => !EVIDENCE_REF.test(item ?? ""))
  ) {
    fail("ONLINE_D1_INVALID", "F04 证据引用超出固定安全边界。");
  }
  return value;
}

function validateJournalState(journalState) {
  if (
    !journalState ||
    !Number.isInteger(journalState.revision) ||
    journalState.revision < CURRENT_G0.decisionRevision ||
    !Array.isArray(journalState.events) ||
    journalState.events.length !== journalState.revision
  ) {
    fail("ONLINE_D1_INVALID", "线上 D1 治理事件序列无效。");
  }
  const ids = new Set();
  for (const [index, event] of journalState.events.entries()) {
    if (
      !event ||
      event.revision !== index + 1 ||
      typeof event.type !== "string" ||
      !event.type ||
      typeof event.id !== "string" ||
      !event.id ||
      ids.has(event.id) ||
      !validTime(event.createdAt)
    ) {
      fail("ONLINE_D1_INVALID", "线上 D1 治理事件序列无效。");
    }
    ids.add(event.id);
  }
}

function manifestP0Definitions(manifest) {
  const g0 = manifest?.gates?.find(({ id }) => id === "G0");
  if (
    manifest?.project_id !== PROJECT_ID ||
    manifest.manifest_version !== MANIFEST_VERSION ||
    !Array.isArray(manifest.work_packages) ||
    !g0 ||
    !same(g0.required_work_packages, P0_IDS)
  ) {
    fail(
      "CURRENT_G0_CONFIRMATION_MISMATCH",
      "当前 G0 确认链与服务器 Manifest 不匹配。",
    );
  }
  return P0_IDS.map((workPackageId) => {
    const definition = manifest.work_packages.find(
      ({ id }) => id === workPackageId,
    );
    if (
      definition?.phase !== "P0" ||
      definition.applicability !== "REQUIRED"
    ) {
      fail(
        "CURRENT_G0_CONFIRMATION_MISMATCH",
        "当前 G0 确认链与服务器 Manifest 不匹配。",
      );
    }
    return definition;
  });
}

async function currentP0Scope(journalState, catalog, manifest) {
  const definitions = manifestP0Definitions(manifest);
  const scope = [];
  for (const [index, workPackageId] of P0_IDS.entries()) {
    const revision = 65 + index;
    const event = journalState.events[revision - 1];
    const record = catalog?.records?.find(
      (item) => item.workPackageId === workPackageId,
    );
    const idempotencyKey =
      `${REMEDIATION_ROOT_KEY}:${String(index + 1).padStart(2, "0")}-${workPackageId}`;
    const note =
      workPackageId === "F04" ? F04_RECORD_NOTE : RECORD_NOTE;
    const commandHash = record
      ? await sha256ProjectValue({
          actorId: ACTOR_ID,
          command: {
            kind: "RECORD_WORK_PACKAGE",
            workPackageId,
            implementationStatus: "IMPLEMENTED",
            verificationStatus: "VERIFIED",
            evidenceRefs: [...record.evidenceRefs],
            evidenceHashes: [...record.evidenceHashes],
            note,
            expectedRevision: revision - 1,
            idempotencyKey,
          },
        })
      : null;
    if (
      event?.revision !== revision ||
      event.type !== "WORK_PACKAGE_RECORDED" ||
      event.actorId !== ACTOR_ID ||
      event.idempotencyKey !== idempotencyKey ||
      event.commandHash !== commandHash ||
      event.payload?.workPackageId !== workPackageId ||
      event.payload?.implementationStatus !== "IMPLEMENTED" ||
      event.payload?.verificationStatus !== "VERIFIED" ||
      event.payload?.note !== note ||
      !record ||
      !same(event.payload?.evidenceRefs, record.evidenceRefs) ||
      !same(event.payload?.evidenceHashes, record.evidenceHashes)
    ) {
      fail(
        "CURRENT_G0_CONFIRMATION_MISMATCH",
        "当前 G0 工作包确认链与冻结证据不匹配。",
      );
    }
    scope.push({
      work_package_id: workPackageId,
      applicability: definitions[index].applicability,
      implementation_status: "IMPLEMENTED",
      verification_status: "VERIFIED",
      evidence_refs: [...event.payload.evidenceRefs],
      evidence_hashes: [...event.payload.evidenceHashes],
    });
  }
  return scope;
}

async function currentG0Confirmation(journalState, catalog, manifest) {
  const scope = await currentP0Scope(journalState, catalog, manifest);
  const evidenceRefs = scope.flatMap((item) => item.evidence_refs);
  const submissions = journalState.events.filter(
    ({ type, payload }) =>
      type === "GATE_SUBMITTED" && payload?.gate_id === "G0",
  );
  const submission = submissions.at(-1);
  if (
    submission?.revision !== CURRENT_G0.submissionRevision ||
    submission.actorId !== ACTOR_ID ||
    submission.idempotencyKey !== CURRENT_G0.submissionIdempotencyKey ||
    submission.commandHash !== CURRENT_G0.submissionCommandHash ||
    submission.payload?.submission_id !== CURRENT_G0.submissionId ||
    submission.payload?.source_revision !== CURRENT_G0.sourceRevision ||
    submission.payload?.package_hash !== CURRENT_G0.packageHash ||
    submission.payload?.supersedes !==
      F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId ||
    submission.payload?.submitted_by !== ACTOR_ID ||
    !validTime(submission.payload?.submitted_at) ||
    !same(submission.payload?.work_package_scope, scope) ||
    !same(submission.payload?.evidence_refs, evidenceRefs)
  ) {
    fail(
      "CURRENT_G0_CONFIRMATION_MISMATCH",
      "当前 G0 Submission 与冻结工作包 scope 不匹配。",
    );
  }
  const recomputedPackageHash = await sha256ProjectValue({
    manifest_version: manifest.manifest_version,
    gate_id: "G0",
    source_revision: CURRENT_G0.sourceRevision,
    work_package_scope: scope,
    evidence_refs: evidenceRefs,
  });
  const submissionCommandHash = await sha256ProjectValue({
    actorId: ACTOR_ID,
    command: {
      kind: "SUBMIT_GATE",
      expectedRevision: CURRENT_G0.sourceRevision,
      idempotencyKey: CURRENT_G0.submissionIdempotencyKey,
      gateId: "G0",
      evidenceRefs,
      supersedes: F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
    },
  });
  if (
    recomputedPackageHash !== CURRENT_G0.packageHash ||
    submissionCommandHash !== CURRENT_G0.submissionCommandHash
  ) {
    fail(
      "CURRENT_G0_CONFIRMATION_MISMATCH",
      "当前 G0 Submission packageHash 重算不匹配。",
    );
  }

  const decisions = journalState.events.filter(
    ({ type, payload }) =>
      type === "GATE_DECIDED" &&
      payload?.submission_id === CURRENT_G0.submissionId,
  );
  const decision = decisions[0];
  const decisionEvidenceRefs = [
    `product-owner-decision:${CURRENT_G0.submissionId}:${CURRENT_G0.packageHash}:${CURRENT_G0.decision}`,
  ];
  if (
    decisions.length !== 1 ||
    decision.revision !== CURRENT_G0.decisionRevision ||
    decision.actorId !== ACTOR_ID ||
    decision.idempotencyKey !== CURRENT_G0.decisionIdempotencyKey ||
    decision.commandHash !== CURRENT_G0.decisionCommandHash ||
    decision.payload?.package_hash !== CURRENT_G0.packageHash ||
    decision.payload?.decision !== CURRENT_G0.decision ||
    decision.payload?.decided_by !== ACTOR_ID ||
    !validTime(decision.payload?.decided_at) ||
    !Array.isArray(decision.payload?.accepted_exclusions) ||
    decision.payload.accepted_exclusions.length !== 0 ||
    !same(decision.payload?.evidence_refs, decisionEvidenceRefs)
  ) {
    fail(
      "CURRENT_G0_CONFIRMATION_MISMATCH",
      "当前 G0 Decision 与 Submission 不匹配。",
    );
  }
  const decisionCommandHash = await sha256ProjectValue({
    actorId: ACTOR_ID,
    command: {
      kind: "DECIDE_GATE",
      submissionId: CURRENT_G0.submissionId,
      expectedPackageHash: CURRENT_G0.packageHash,
      decision: CURRENT_G0.decision,
      acceptedExclusions: [],
      evidenceRefs: decisionEvidenceRefs,
      expectedRevision: CURRENT_G0.submissionRevision,
      idempotencyKey: CURRENT_G0.decisionIdempotencyKey,
    },
  });
  if (decisionCommandHash !== CURRENT_G0.decisionCommandHash) {
    fail(
      "CURRENT_G0_CONFIRMATION_MISMATCH",
      "当前 G0 Decision 命令来源不匹配。",
    );
  }
  return { submission, decision };
}

async function sha256Text(value) {
  const bytes = UTF8_ENCODER.encode(value);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes),
  );
  return `sha256:${Array.from(
    digest,
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

export async function projectP0B11Evidence({
  journalState,
  catalog,
  manifest,
  serverTime,
}) {
  validateJournalState(journalState);
  if (!validTime(serverTime)) {
    fail("INVALID_SERVER_TIME", "服务器时间无效。");
  }
  const { f04Event } = await assertUniqueF04HistoricalAuthority({
    journalState,
    catalog,
  });
  const { submission, decision } = await currentG0Confirmation(
    journalState,
    catalog,
    manifest,
  );
  requirePublicId(f04Event.id);
  requirePublicId(submission.id);
  requirePublicId(submission.payload.submission_id);
  requirePublicId(decision.id);
  requirePublicId(decision.payload.decision_id);
  requireEvidenceRefs(f04Event.payload.evidenceRefs);
  for (const hash of f04Event.payload.evidenceHashes) requireSha256(hash);
  requireSha256(f04Event.commandHash);
  requireSha256(submission.payload.package_hash);
  requireSha256(decision.payload.package_hash);
  if (
    typeof f04Event.actorId !== "string" ||
    !f04Event.actorId ||
    typeof f04Event.idempotencyKey !== "string" ||
    !f04Event.idempotencyKey
  ) {
    fail(
      "F04_HUMAN_AUTHORITY_UNPROVEN",
      "F04 真人基线缺少 actor 或幂等绑定。",
    );
  }

  return {
    schemaVersion: "p0-b11-evidence-projection.v1",
    source: SOURCE,
    currentRevision: journalState.revision,
    f04HumanBaselineAuthority: {
      eventId: f04Event.id,
      revision: f04Event.revision,
      recordedAt: f04Event.createdAt,
      workPackageId: "F04",
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [...f04Event.payload.evidenceRefs],
      evidenceHashes: [...f04Event.payload.evidenceHashes],
      commandHash: f04Event.commandHash,
      actorBinding: {
        actorIdSha256: await sha256Text(f04Event.actorId),
        persistedRole: null,
        authorizationPath: "PRODUCT_OWNER_ONLY",
      },
      idempotencyKeySha256: await sha256Text(f04Event.idempotencyKey),
    },
    g0Submission: {
      eventId: submission.id,
      revision: submission.revision,
      submissionId: submission.payload.submission_id,
      sourceRevision: submission.payload.source_revision,
      packageHash: submission.payload.package_hash,
      recordedAt: submission.createdAt,
    },
    g0Decision: {
      eventId: decision.id,
      revision: decision.revision,
      decisionId: decision.payload.decision_id,
      submissionId: decision.payload.submission_id,
      packageHash: decision.payload.package_hash,
      decision: decision.payload.decision,
      recordedAt: decision.createdAt,
    },
    structuredAdjudicationPersisted: false,
    serverTime,
  };
}

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
    throw new Error("P0-B11 evidence response exceeds the fixed size limit.");
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

export function createP0B11EvidenceGet({
  configuredProductOwner,
  isProductOwner,
  loadJournalState,
  catalog,
  manifest,
  clock,
}) {
  return async function GET(request) {
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
    if (
      typeof productOwner !== "string" ||
      !productOwner.trim()
    ) {
      return errorResponse(
        "PRODUCT_OWNER_NOT_CONFIGURED",
        "产品所有者身份尚未配置。",
        503,
      );
    }
    if (!isProductOwner(actor, productOwner)) {
      return errorResponse(
        "PRODUCT_OWNER_REQUIRED",
        "只有外部产品所有者可以读取 P0-B11 历史证据。",
        403,
      );
    }
    if (new URL(request.url).search) {
      return errorResponse(
        "QUERY_PARAMETERS_NOT_ALLOWED",
        "该只读端点不接受查询参数。",
        400,
      );
    }

    try {
      const journalState = await loadJournalState();
      return await json(
        await projectP0B11Evidence({
          journalState,
          catalog,
          manifest,
          serverTime: clock(),
        }),
        200,
      );
    } catch {
      return errorResponse(
        "P0_B11_EVIDENCE_UNAVAILABLE",
        "线上 P0-B11 历史证据暂时不可用。",
        503,
      );
    }
  };
}
