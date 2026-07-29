import { createFrozenEvidenceVerifier } from "./frozen-evidence.mjs";
import {
  F04_HISTORICAL_AUTHORITY_BINDING,
  assertF04HistoricalAuthority,
} from "./f04-historical-authority.mjs";
import {
  createMemoryJournal,
  createProjectControl,
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";

const ERROR_SCHEMA_VERSION = "g0-remediation-error.v1";
const PREVIEW_SCHEMA_VERSION = "g0-remediation-preview.v1";
const EXECUTION_SCHEMA_VERSION = "g0-remediation-execution.v1";
const SOURCE = "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER";
const P0_IDS = Object.freeze(["F01", "F02", "F03", "F04"]);
const BASE_REVISION = 64;
const FINAL_REVISION = 69;
const OLD_SUBMISSION_ID =
  F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId;
const OLD_PACKAGE_HASH =
  F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash;
const OLD_F04_ENGINEERING_HASH =
  F04_HISTORICAL_AUTHORITY_BINDING.engineeringEvidenceSha256;
const HUMAN_F04_HASH =
  F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256;
const EXPECTED_SCOPE_DIGEST =
  "sha256:e3cb5c88f21492200d30841010be4b738eca952309dbafdc66c96100b1e80b0f";
const EXPECTED_PACKAGE_HASH =
  "sha256:d4e449a305a6f496e24fb777d1d883d8c02f0d7e3165d00fc90561c1d14421b0";
const EXPECTED_CATALOG_CANONICAL_SHA256 =
  "sha256:954631d8bf6150c3fe993c4c0510b27e21d49ca951ce0bb176a534d0f2f4ac43";
const ACTOR_CONTEXT = Object.freeze({
  actorId: "external_product_owner",
  roles: Object.freeze(["PRODUCT_OWNER"]),
});
const RECORD_NOTE =
  "G0 remediation from the frozen P0 evidence catalog.";
const F04_RECORD_NOTE =
  `G0 remediation preserves F04 human-baseline authority from online D1 revision 1 (${HUMAN_F04_HASH}).`;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_OBJECT = /^[a-f0-9]{40}$/;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const IDEMPOTENCY_KEY =
  /^g0-remediation-[a-z0-9][a-z0-9._-]{7,55}$/;
const JSON_CONTENT_TYPE =
  /^[\t ]*application\/json(?:[\t ]*;[\t ]*charset[\t ]*=[\t ]*utf-8)?[\t ]*$/i;
const MAX_REQUEST_BYTES = 4 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024;
const UTF8_ENCODER = new TextEncoder();
const denyReferenceReviewReadiness = async () => false;

export const G0_REMEDIATION_CONFIRMATION =
  "CONFIRM_G0_REMEDIATION_PLAN";

export const G0_REMEDIATION_BUILD_BINDING = Object.freeze({
  schemaVersion: "g0-remediation-build-binding.v1",
  sourceCommit: "4e9867875f00eb7c35efa8fbe7c76a0146deeda7",
  tree: "288172a3e49636c4f45ec999114dcc6d35126de7",
  frozenEvidenceIndexPath:
    "implementation/governance/p0-frozen-evidence-index.v1.json",
  frozenEvidenceIndexSha256:
    "sha256:9d7c7d37279d2c24ff97f9bbea42ff2adc935dbd10be30ea504552c53c8b9aa8",
  frozenEvidenceIndexCanonicalSha256:
    EXPECTED_CATALOG_CANONICAL_SHA256,
  verifierVersion: "g0-remediation-frozen-catalog-verifier.v1",
});

function failure(code, message, status = 503) {
  return Object.assign(new Error(message), { code, status });
}

function fail(code, message, status) {
  throw failure(code, message, status);
}

function validUtc(value) {
  return (
    typeof value === "string" &&
    RFC3339.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function same(left, right) {
  return canonicalizeProjectJson(left) === canonicalizeProjectJson(right);
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
    throw failure(
      "RESPONSE_TOO_LARGE",
      "G0 remediation response exceeds the fixed size limit.",
      503,
    );
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

async function errorResponse(code, message, status) {
  return json(
    {
      schemaVersion: ERROR_SCHEMA_VERSION,
      code,
      error: message,
    },
    status,
  );
}

function authenticatedActor(request) {
  return request.headers.get("oai-authenticated-user-email")?.trim() ?? "";
}

async function authorize({
  request,
  configuredProductOwner,
  isProductOwner,
}) {
  const actor = authenticatedActor(request);
  if (!actor) {
    return errorResponse(
      "AUTHENTICATION_REQUIRED",
      "需要先通过工作区身份验证。",
      401,
    );
  }
  const owner = configuredProductOwner();
  if (!owner) {
    return errorResponse(
      "PRODUCT_OWNER_NOT_CONFIGURED",
      "产品所有者身份尚未配置。",
      503,
    );
  }
  if (!isProductOwner(actor, owner)) {
    return errorResponse(
      "PRODUCT_OWNER_REQUIRED",
      "只有外部产品所有者可以使用 G0 整改通道。",
      403,
    );
  }
  return null;
}

function assertNoQuery(request) {
  if ([...new URL(request.url).searchParams].length > 0) {
    fail(
      "QUERY_PARAMETERS_FORBIDDEN",
      "G0 整改通道不接受查询参数。",
      400,
    );
  }
}

function assertSameOriginMutation(request) {
  const requestOrigin = new URL(request.url).origin;
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (origin !== requestOrigin || fetchSite !== "same-origin") {
    fail(
      "CROSS_SITE_REQUEST_FORBIDDEN",
      "POST 必须来自当前应用的同源页面。",
      403,
    );
  }
}

function validateBuildBinding(binding) {
  if (
    !same(binding, G0_REMEDIATION_BUILD_BINDING) ||
    !GIT_OBJECT.test(binding.sourceCommit ?? "") ||
    !GIT_OBJECT.test(binding.tree ?? "") ||
    !SHA256.test(binding.frozenEvidenceIndexSha256 ?? "") ||
    !SHA256.test(binding.frozenEvidenceIndexCanonicalSha256 ?? "")
  ) {
    fail(
      "FROZEN_CATALOG_MISMATCH",
      "冻结证据目录与构建证明不匹配。",
    );
  }
}

export async function verifyG0RemediationFrozenCatalog({
  catalog,
  binding = G0_REMEDIATION_BUILD_BINDING,
}) {
  try {
    validateBuildBinding(binding);
    if (
      catalog?.schemaVersion !== "frozen-evidence-catalog.v1" ||
      !Array.isArray(catalog.records) ||
      !same(
        catalog.records.map(({ workPackageId }) => workPackageId),
        P0_IDS,
      )
    ) {
      return false;
    }
    const catalogDigest = await sha256ProjectValue(catalog);
    if (catalogDigest !== binding.frozenEvidenceIndexCanonicalSha256) {
      return false;
    }
    for (const record of catalog.records) {
      if (
        !Array.isArray(record.evidenceRefs) ||
        record.evidenceRefs.length === 0 ||
        record.evidenceRefs.some(
          (item) => typeof item !== "string" || !item,
        ) ||
        !Array.isArray(record.evidenceHashes) ||
        record.evidenceHashes.length === 0 ||
        record.evidenceHashes.some((item) => !SHA256.test(item)) ||
        !Array.isArray(record.hashedObjects) ||
        !same(
          record.hashedObjects.map(({ sha256 }) => sha256),
          record.evidenceHashes,
        ) ||
        record.hashedObjects.some(
          ({ path, sha256 }) =>
            typeof path !== "string" ||
            !record.evidenceRefs.includes(path) ||
            !SHA256.test(sha256 ?? ""),
        )
      ) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

function recordById(catalog, workPackageId) {
  return catalog.records.find(
    (record) => record.workPackageId === workPackageId,
  );
}

function targetScope({ manifest, catalog }) {
  return P0_IDS.map((workPackageId) => {
    const definition = manifest.work_packages.find(
      (item) => item.id === workPackageId,
    );
    const record = recordById(catalog, workPackageId);
    if (!definition || !record) {
      fail("MANIFEST_MISMATCH", "P0 工作包定义或冻结证据缺失。");
    }
    return {
      work_package_id: workPackageId,
      applicability: definition.applicability,
      implementation_status: "IMPLEMENTED",
      verification_status: "VERIFIED",
      evidence_refs: [...record.evidenceRefs],
      evidence_hashes: [...record.evidenceHashes],
    };
  });
}

function targetGateEvidence(catalog) {
  return catalog.records.flatMap((record) => record.evidenceRefs);
}

function stepDefinitions({ manifest, catalog }) {
  const scope = targetScope({ manifest, catalog });
  const gateEvidenceRefs = targetGateEvidence(catalog);
  return [
    ...P0_IDS.map((workPackageId, index) => ({
      position: index + 1,
      kind: "RECORD_WORK_PACKAGE",
      workPackageId,
      gateId: null,
      expectedRevision: BASE_REVISION + index,
      resultRevision: BASE_REVISION + index + 1,
      evidenceRefs: [...recordById(catalog, workPackageId).evidenceRefs],
      evidenceHashes: [
        ...recordById(catalog, workPackageId).evidenceHashes,
      ],
      note:
        workPackageId === "F04"
          ? F04_RECORD_NOTE
          : RECORD_NOTE,
    })),
    {
      position: 5,
      kind: "SUBMIT_GATE",
      workPackageId: null,
      gateId: "G0",
      expectedRevision: BASE_REVISION + 4,
      resultRevision: FINAL_REVISION,
      evidenceRefs: gateEvidenceRefs,
      evidenceHashes: [],
      note: null,
      workPackageScope: scope,
      supersedes: OLD_SUBMISSION_ID,
    },
  ];
}

async function fixedPlan({ manifest, catalog, buildBinding }) {
  validateBuildBinding(buildBinding);
  if (
    !(await verifyG0RemediationFrozenCatalog({
      catalog,
      binding: buildBinding,
    }))
  ) {
    fail(
      "FROZEN_CATALOG_MISMATCH",
      "冻结证据目录与构建证明不匹配。",
    );
  }
  if (
    manifest?.manifest_version !== "1.0.0" ||
    manifest?.project_id !== "generic-multi-enterprise-ai-platform-v5"
  ) {
    fail("MANIFEST_MISMATCH", "工作包定义基线不匹配。");
  }
  const g0 = manifest.gates.find(({ id }) => id === "G0");
  if (
    !g0 ||
    !same(g0.required_work_packages, P0_IDS)
  ) {
    fail("MANIFEST_MISMATCH", "G0 工作包定义基线不匹配。");
  }
  const workPackageScope = targetScope({ manifest, catalog });
  const scopeDigest = await sha256ProjectValue(workPackageScope);
  if (scopeDigest !== EXPECTED_SCOPE_DIGEST) {
    fail("SCOPE_MISMATCH", "G0 目标 scope 与批准的摘要不匹配。");
  }
  const evidenceRefs = targetGateEvidence(catalog);
  const frozenPackage = {
    manifest_version: manifest.manifest_version,
    gate_id: "G0",
    source_revision: BASE_REVISION + 4,
    work_package_scope: workPackageScope,
    evidence_refs: evidenceRefs,
  };
  const packageHash = await sha256ProjectValue(frozenPackage);
  if (packageHash !== EXPECTED_PACKAGE_HASH) {
    fail(
      "PACKAGE_HASH_MISMATCH",
      "G0 目标提交摘要与批准的摘要不匹配。",
    );
  }
  const steps = stepDefinitions({ manifest, catalog });
  const planCore = {
    schemaVersion: "g0-remediation-plan.v1",
    projectId: manifest.project_id,
    manifestVersion: manifest.manifest_version,
    baseRevision: BASE_REVISION,
    buildProof: buildBinding,
    historicalAnchor: {
      f04HumanAuthority: {
        revision: 1,
        eventType: "WORK_PACKAGE_RECORDED",
        actorId: ACTOR_CONTEXT.actorId,
        workPackageId: "F04",
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        engineeringEvidenceSha256: OLD_F04_ENGINEERING_HASH,
        humanEvidenceSha256: HUMAN_F04_HASH,
      },
      g0SubmissionRevision: 2,
      g0SubmissionId: OLD_SUBMISSION_ID,
      g0PackageHash: OLD_PACKAGE_HASH,
      g0DecisionRevision: 3,
      g0Decision: "APPROVE",
    },
    target: {
      workPackageScope,
      scopeDigest,
      sourceRevision: BASE_REVISION + 4,
      evidenceRefs,
      packageHash,
      supersedes: OLD_SUBMISSION_ID,
    },
    orderedSteps: steps.map((step) => ({
      position: step.position,
      kind: step.kind,
      workPackageId: step.workPackageId,
      gateId: step.gateId,
      expectedRevision: step.expectedRevision,
      resultRevision: step.resultRevision,
      evidenceRefs: step.evidenceRefs,
      evidenceHashes: step.evidenceHashes,
      note: step.note,
      supersedes: step.supersedes ?? null,
    })),
  };
  return {
    ...planCore,
    planDigest: await sha256ProjectValue(planCore),
    steps,
  };
}

function validateJournalState(journalState) {
  if (
    !journalState ||
    !Number.isInteger(journalState.revision) ||
    journalState.revision < BASE_REVISION ||
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
      typeof event.id !== "string" ||
      !event.id ||
      ids.has(event.id) ||
      typeof event.type !== "string" ||
      !event.type ||
      !validUtc(event.createdAt)
    ) {
      fail("ONLINE_D1_INVALID", "线上 D1 治理事件序列无效。");
    }
    ids.add(event.id);
  }
}

async function validateHistoricalBaseScope(journalState, catalog) {
  await assertF04HistoricalAuthority({
    journalState,
    catalog,
  });
  for (const event of journalState.events.slice(3, BASE_REVISION)) {
    if (
      event.type === "WORK_PACKAGE_RECORDED" &&
      P0_IDS.includes(event.payload?.workPackageId)
    ) {
      fail(
        "G0_BASE_SCOPE_MISMATCH",
        "revision 64 前出现了未纳入批准计划的 P0 工作包事件。",
        409,
      );
    }
    if (
      event.type === "GATE_SUBMITTED" &&
      event.payload?.gate_id === "G0"
    ) {
      fail(
        "G0_BASE_SCOPE_MISMATCH",
        "revision 64 前出现了未纳入批准计划的 G0 Submission。",
        409,
      );
    }
  }
}

function commandForStep(step, idempotencyKey) {
  const stepId =
    step.kind === "RECORD_WORK_PACKAGE"
      ? `${String(step.position).padStart(2, "0")}-${step.workPackageId}`
      : "05-G0-SUBMIT";
  const command = {
    kind: step.kind,
    expectedRevision: step.expectedRevision,
    idempotencyKey: `${idempotencyKey}:${stepId}`,
  };
  if (step.kind === "RECORD_WORK_PACKAGE") {
    return {
      ...command,
      workPackageId: step.workPackageId,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [...step.evidenceRefs],
      evidenceHashes: [...step.evidenceHashes],
      note: step.note,
    };
  }
  return {
    ...command,
    gateId: "G0",
    evidenceRefs: [...step.evidenceRefs],
    supersedes: OLD_SUBMISSION_ID,
  };
}

async function commandHash(command) {
  return sha256ProjectValue({
    actorId: ACTOR_CONTEXT.actorId,
    command,
  });
}

function rootKeyFromFirstPrefixEvent(event) {
  const suffix = ":01-F01";
  if (
    typeof event?.idempotencyKey !== "string" ||
    !event.idempotencyKey.endsWith(suffix)
  ) {
    return null;
  }
  const root = event.idempotencyKey.slice(0, -suffix.length);
  return IDEMPOTENCY_KEY.test(root) ? root : null;
}

async function eventMatchesStep({ event, step, rootKey, plan }) {
  const command = commandForStep(step, rootKey);
  if (
    !event ||
    event.revision !== step.resultRevision ||
    event.idempotencyKey !== command.idempotencyKey ||
    event.commandHash !== (await commandHash(command)) ||
    event.actorId !== ACTOR_CONTEXT.actorId ||
    typeof event.id !== "string" ||
    !event.id ||
    !validUtc(event.createdAt)
  ) {
    return false;
  }
  if (step.kind === "RECORD_WORK_PACKAGE") {
    return (
      event.type === "WORK_PACKAGE_RECORDED" &&
      same(event.payload, {
        workPackageId: step.workPackageId,
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: step.evidenceRefs,
        evidenceHashes: step.evidenceHashes,
        note: step.note,
      })
    );
  }
  const payload = event.payload;
  return (
    event.type === "GATE_SUBMITTED" &&
    payload?.gate_id === "G0" &&
    typeof payload.submission_id === "string" &&
    payload.submission_id.length > 0 &&
    payload.package_hash === plan.target.packageHash &&
    validUtc(payload.submitted_at) &&
    payload.submitted_by === ACTOR_CONTEXT.actorId &&
    payload.source_revision === BASE_REVISION + 4 &&
    same(payload.work_package_scope, plan.target.workPackageScope) &&
    same(payload.evidence_refs, plan.target.evidenceRefs) &&
    payload.supersedes === OLD_SUBMISSION_ID
  );
}

async function inspectPrefix({ journalState, plan, rootKey = null }) {
  const observedCount = Math.min(
    Math.max(journalState.revision - BASE_REVISION, 0),
    plan.steps.length,
  );
  if (observedCount === 0) {
    return {
      prefixLength: 0,
      rootKey: null,
      complete: false,
      current: true,
    };
  }
  const effectiveRoot =
    rootKey ??
    rootKeyFromFirstPrefixEvent(journalState.events[BASE_REVISION]);
  if (!effectiveRoot) {
    fail(
      "REMEDIATION_PREFIX_MISMATCH",
      "线上 revision 64 之后不是已批准整改计划的可恢复前缀。",
      409,
    );
  }
  for (let index = 0; index < observedCount; index += 1) {
    if (
      !(await eventMatchesStep({
        event: journalState.events[BASE_REVISION + index],
        step: plan.steps[index],
        rootKey: effectiveRoot,
        plan,
      }))
    ) {
      fail(
        "REMEDIATION_PREFIX_MISMATCH",
        "线上 revision 64 之后不是已批准整改计划的可恢复前缀。",
        409,
      );
    }
  }
  if (
    journalState.revision > BASE_REVISION + observedCount &&
    observedCount < plan.steps.length
  ) {
    fail(
      "REMEDIATION_PREFIX_MISMATCH",
      "整改计划前缀后存在未批准的插队事件。",
      409,
    );
  }
  const complete = observedCount === plan.steps.length;
  let current = true;
  if (complete) {
    const latestSubmission = journalState.events
      .filter(
        (event) =>
          event.type === "GATE_SUBMITTED" &&
          event.payload?.gate_id === "G0",
      )
      .at(-1);
    current =
      latestSubmission?.revision === FINAL_REVISION &&
      latestSubmission.payload.package_hash === plan.target.packageHash;
  }
  return {
    prefixLength: observedCount,
    rootKey: effectiveRoot,
    complete,
    current,
  };
}

function snapshotProjection(snapshot) {
  const g0 = snapshot.gates.find(({ id }) => id === "G0");
  if (!g0) {
    fail("ONLINE_D1_INVALID", "线上 D1 缺少 G0 投影。");
  }
  const workPackages = Object.fromEntries(
    P0_IDS.map((id) => {
      const item = snapshot.workPackages.find(
        (workPackage) => workPackage.id === id,
      );
      if (!item) {
        fail("ONLINE_D1_INVALID", `线上 D1 缺少 ${id} 投影。`);
      }
      return [
        id,
        {
          implementationStatus: item.implementationStatus,
          verificationStatus: item.verificationStatus,
        },
      ];
    }),
  );
  return { g0, workPackages };
}

async function loadState(runtime, projectId) {
  if (!runtime?.journal?.load || !runtime?.control?.snapshot) {
    fail("ONLINE_D1_UNAVAILABLE", "线上 D1 只追加治理账本暂不可用。");
  }
  const journalState = await runtime.journal.load(projectId);
  const snapshot = await runtime.control.snapshot();
  if (snapshot.revision !== journalState.revision) {
    fail("ONLINE_D1_CHANGED_DURING_READ", "线上 D1 在读取期间发生变化。", 409);
  }
  return { journalState, snapshot };
}

async function computeCurrent({
  runtime,
  manifest,
  catalog,
  buildBinding,
  rootKey = null,
}) {
  const plan = await fixedPlan({ manifest, catalog, buildBinding });
  const { journalState, snapshot } = await loadState(
    runtime,
    manifest.project_id,
  );
  validateJournalState(journalState);
  await validateHistoricalBaseScope(journalState, catalog);
  const prefix = await inspectPrefix({
    journalState,
    plan,
    rootKey,
  });
  const projection = snapshotProjection(snapshot);
  if (prefix.complete) {
    const completedSubmission =
      journalState.events[FINAL_REVISION - 1]?.payload;
    prefix.current =
      prefix.current &&
      projection.g0.latestSubmission?.submission_id ===
        completedSubmission?.submission_id &&
      projection.g0.latestSubmission?.package_hash ===
        plan.target.packageHash &&
      same(
        projection.g0.workPackageScope,
        plan.target.workPackageScope,
      );
  }
  return {
    plan,
    journalState,
    snapshot,
    prefix,
    ...projection,
  };
}

function publicSteps(steps) {
  return steps.map((step) => ({
    position: step.position,
    kind: step.kind,
    workPackageId: step.workPackageId,
    gateId: step.gateId,
    expectedRevision: step.expectedRevision,
    resultRevision: step.resultRevision,
  }));
}

async function previewBody(current, serverTime) {
  const blockers = [];
  if (current.prefix.complete) {
    blockers.push(
      current.prefix.current
        ? "PLAN_ALREADY_COMPLETED"
        : "COMPLETED_PLAN_NOT_CURRENT",
    );
  } else if (
    current.prefix.prefixLength === 0 &&
    current.g0.status !== "STALE_SUBMISSION"
  ) {
    blockers.push("G0_NOT_STALE_SUBMISSION");
  }
  return {
    schemaVersion: PREVIEW_SCHEMA_VERSION,
    source: SOURCE,
    revision: current.journalState.revision,
    g0Status: current.g0.status,
    workPackages: current.workPackages,
    steps: publicSteps(current.plan.steps),
    sourceCommit: current.plan.buildProof.sourceCommit,
    tree: current.plan.buildProof.tree,
    frozenEvidenceIndexSha256:
      current.plan.buildProof.frozenEvidenceIndexSha256,
    scopeDigest: current.plan.target.scopeDigest,
    packageHash: current.plan.target.packageHash,
    planDigest: current.plan.planDigest,
    canExecute: blockers.length === 0,
    blockers,
    serverTime,
  };
}

async function parsePostBody(request) {
  if (!JSON_CONTENT_TYPE.test(request.headers.get("content-type") ?? "")) {
    fail("INVALID_REQUEST", "POST 必须使用 JSON 请求体。", 400);
  }
  const declaredLength = Number(
    request.headers.get("content-length") ?? "0",
  );
  if (
    Number.isFinite(declaredLength) &&
    declaredLength > MAX_REQUEST_BYTES
  ) {
    fail("INVALID_REQUEST", "POST 请求体超过固定大小限制。", 400);
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
    "expectedRevision",
    "idempotencyKey",
    "planDigest",
  ];
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    !same(Object.keys(body).sort(), expectedKeys)
  ) {
    fail("INVALID_REQUEST", "POST 请求字段不完整或包含未知字段。", 400);
  }
  if (
    !Number.isInteger(body.expectedRevision) ||
    !SHA256.test(body.planDigest ?? "") ||
    !IDEMPOTENCY_KEY.test(body.idempotencyKey ?? "") ||
    body.confirmation !== G0_REMEDIATION_CONFIRMATION
  ) {
    fail("INVALID_REQUEST", "POST 确认字段无效。", 400);
  }
  return body;
}

async function preflight({
  journalState,
  manifest,
  catalog,
  plan,
  rootKey,
  referenceReviewPolicy,
  verifyReferenceReviewReadiness,
}) {
  const memory = createMemoryJournal(journalState.events);
  const control = createProjectControl({
    manifest,
    journal: memory,
    verifyFrozenEvidence: createFrozenEvidenceVerifier(catalog),
    referenceReviewPolicy,
    verifyReferenceReviewReadiness,
    clock: () => "2026-07-29T00:00:00.000Z",
    idFactory: (() => {
      let id = 0;
      return () => `g0-remediation-preflight-${++id}`;
    })(),
  });
  for (const step of plan.steps) {
    if (step.kind === "SUBMIT_GATE") {
      const snapshot = await control.snapshot();
      const gate = snapshot.gates.find(({ id }) => id === "G0");
      if (gate?.status !== "READY_TO_SUBMIT") {
        fail(
          "G0_NOT_READY_TO_SUBMIT",
          "四个工作包事件完成后 G0 仍未达到 READY_TO_SUBMIT。",
          409,
        );
      }
    }
    await control.execute(
      ACTOR_CONTEXT,
      commandForStep(step, rootKey),
    );
  }
  const snapshot = await control.snapshot();
  if (
    snapshot.revision !== FINAL_REVISION ||
    snapshot.gates.find(({ id }) => id === "G0")?.status !==
      "AWAITING_DECISION"
  ) {
    fail(
      "PREFLIGHT_RESULT_MISMATCH",
      "整改预演未停在新的 G0 Submission。",
      409,
    );
  }
}

function executionResult(current, {
  appendedCount,
  duplicateCount,
  serverTime,
}) {
  const submission = current.journalState.events[FINAL_REVISION - 1];
  return {
    schemaVersion: EXECUTION_SCHEMA_VERSION,
    source: SOURCE,
    status: "COMPLETED",
    baseRevision: BASE_REVISION,
    revision: current.journalState.revision,
    planDigest: current.plan.planDigest,
    packageHash: current.plan.target.packageHash,
    submissionId: submission?.payload?.submission_id ?? null,
    appendedCount,
    duplicateCount,
    serverTime,
  };
}

function publicError(error) {
  if (!Number.isInteger(error?.status)) {
    if (error?.code === "REFERENCE_REVIEW_NOT_PROVED") {
      return {
        code: "REFERENCE_REVIEW_NOT_PROVED",
        message:
          "G0 整改需要服务器持有且经 Git 冻结的 Reference Review 证明。",
        status: 409,
      };
    }
    if (error?.code === "STORE_UNAVAILABLE") {
      return {
        code: "ONLINE_D1_UNAVAILABLE",
        message: "线上 D1 只追加治理账本暂不可用。",
        status: 503,
      };
    }
    return {
      code: "G0_REMEDIATION_UNAVAILABLE",
      message: "G0 整改通道暂不可用。",
      status: 503,
    };
  }
  const code = error.code;
  const knownMessage = {
    EXECUTION_INTERRUPTED:
      "整改执行已停止；已追加的合法前缀保留，需使用同一确认值安全重试。",
    ONLINE_D1_UNAVAILABLE: "线上 D1 只追加治理账本暂不可用。",
    G0_REMEDIATION_UNAVAILABLE: "G0 整改通道暂不可用。",
    REFERENCE_REVIEW_NOT_PROVED:
      "G0 整改需要服务器持有且经 Git 冻结的 Reference Review 证明。",
  }[code];
  return {
    code,
    message:
      knownMessage ??
      (typeof error?.message === "string"
        ? error.message
        : "G0 整改通道暂不可用。"),
    status: error.status,
  };
}

export function createG0RemediationHandlers({
  configuredProductOwner,
  isProductOwner,
  createRuntime,
  manifest,
  catalog,
  buildBinding = G0_REMEDIATION_BUILD_BINDING,
  clock = () => new Date().toISOString(),
  onReadback = () => {},
  referenceReviewPolicy = null,
  verifyReferenceReviewReadiness =
    denyReferenceReviewReadiness,
}) {
  async function GET(request) {
    const denied = await authorize({
      request,
      configuredProductOwner,
      isProductOwner,
    });
    if (denied) return denied;
    try {
      assertNoQuery(request);
      const runtime = await createRuntime({ readOnly: true });
      const current = await computeCurrent({
        runtime,
        manifest,
        catalog,
        buildBinding,
      });
      return json(await previewBody(current, clock()), 200);
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
    const denied = await authorize({
      request,
      configuredProductOwner,
      isProductOwner,
    });
    if (denied) return denied;
    let body;
    try {
      assertNoQuery(request);
      assertSameOriginMutation(request);
      body = await parsePostBody(request);
      const runtime = await createRuntime({ readOnly: false });
      let current = await computeCurrent({
        runtime,
        manifest,
        catalog,
        buildBinding,
        rootKey: body.idempotencyKey,
      });
      if (body.expectedRevision !== BASE_REVISION) {
        fail(
          "EXPECTED_REVISION_MISMATCH",
          "expectedRevision 与批准的整改基线不匹配。",
          409,
        );
      }
      if (body.planDigest !== current.plan.planDigest) {
        fail(
          "PLAN_DIGEST_MISMATCH",
          "planDigest 与服务器重算结果不匹配。",
          409,
        );
      }
      if (current.prefix.complete) {
        if (!current.prefix.current) {
          fail(
            "COMPLETED_PLAN_NOT_CURRENT",
            "整改前缀已完成，但新的 G0 Submission 已不是当前版本。",
            409,
          );
        }
        return json(
          executionResult(current, {
            appendedCount: 0,
            duplicateCount: 5,
            serverTime: clock(),
          }),
          200,
        );
      }
      if (
        current.prefix.prefixLength === 0 &&
        current.journalState.revision !== body.expectedRevision
      ) {
        fail(
          "EXPECTED_REVISION_MISMATCH",
          "线上 revision 已漂移且不是可恢复的整改前缀。",
          409,
        );
      }
      if (
        current.prefix.prefixLength === 0 &&
        current.g0.status !== "STALE_SUBMISSION"
      ) {
        fail(
          "G0_NOT_STALE_SUBMISSION",
          "G0 当前状态不允许执行该整改计划。",
          409,
        );
      }
      await preflight({
        journalState: current.journalState,
        manifest,
        catalog,
        plan: current.plan,
        rootKey: body.idempotencyKey,
        referenceReviewPolicy,
        verifyReferenceReviewReadiness,
      });
      const initialPrefixLength = current.prefix.prefixLength;
      let appendedCount = 0;
      let duplicateCount = initialPrefixLength;
      for (
        let index = initialPrefixLength;
        index < current.plan.steps.length;
      ) {
        const step = current.plan.steps[index];
        if (step.kind === "SUBMIT_GATE") {
          const snapshot = await runtime.control.snapshot();
          const gate = snapshot.gates.find(({ id }) => id === "G0");
          if (gate?.status !== "READY_TO_SUBMIT") {
            current = await computeCurrent({
              runtime,
              manifest,
              catalog,
              buildBinding,
              rootKey: body.idempotencyKey,
            });
            if (current.prefix.complete && current.prefix.current) {
              duplicateCount += current.plan.steps.length - index;
              break;
            }
            fail(
              "G0_NOT_READY_TO_SUBMIT",
              "G0 未达到 READY_TO_SUBMIT，拒绝创建新 Submission。",
              409,
            );
          }
        }
        let receipt;
        try {
          receipt = await runtime.control.execute(
            ACTOR_CONTEXT,
            commandForStep(step, body.idempotencyKey),
          );
        } catch {
          try {
            await computeCurrent({
              runtime,
              manifest,
              catalog,
              buildBinding,
              rootKey: body.idempotencyKey,
            });
          } catch {
            fail(
              "EXECUTION_OUTCOME_UNKNOWN",
              "整改步骤失败后无法确认线上结果。",
            );
          }
          throw failure(
            "EXECUTION_INTERRUPTED",
            "整改步骤已停止，合法前缀保持不变。",
            503,
          );
        }
        if (receipt.duplicate) {
          duplicateCount += 1;
        } else {
          appendedCount += 1;
        }
        current = await computeCurrent({
          runtime,
          manifest,
          catalog,
          buildBinding,
          rootKey: body.idempotencyKey,
        });
        onReadback({
          step: {
            position: step.position,
            kind: step.kind,
            workPackageId: step.workPackageId,
            gateId: step.gateId,
          },
          revision: current.journalState.revision,
        });
        if (current.prefix.prefixLength < index + 1) {
          fail(
            "READBACK_MISMATCH",
            "追加后的线上回读与整改计划不一致。",
          );
        }
        duplicateCount += current.prefix.prefixLength - (index + 1);
        index = current.prefix.prefixLength;
      }
      if (!current.prefix.complete || !current.prefix.current) {
        fail(
          "READBACK_MISMATCH",
          "整改完成回读与固定计划不一致。",
        );
      }
      return json(
        executionResult(current, {
          appendedCount,
          duplicateCount,
          serverTime: clock(),
        }),
        200,
      );
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
