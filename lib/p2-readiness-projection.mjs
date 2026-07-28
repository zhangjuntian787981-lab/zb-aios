const ERROR_SCHEMA_VERSION = "p2-readiness-error.v1";
const MAX_RESPONSE_BYTES = 16 * 1024;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const GOVERNED_ID = /^[a-z0-9][a-z0-9_-]{0,159}$/;
const GATE_DECISIONS = new Set([
  "APPROVE",
  "APPROVE_WITH_EXCLUSIONS",
  "RETURN",
  "HOLD",
]);
const GATE_STATUSES = new Set([
  "NOT_READY",
  "READY_TO_SUBMIT",
  "AWAITING_DECISION",
  "APPROVED",
  "RETURNED",
  "HELD",
  "STALE_SUBMISSION",
]);
const IMPLEMENTATION_STATUSES = new Set([
  "NOT_STARTED",
  "IN_PROGRESS",
  "IMPLEMENTED",
]);
const VERIFICATION_STATUSES = new Set(["NOT_VERIFIED", "VERIFIED"]);
const START_AUTHORIZATION_STATUSES = new Set([
  "NOT_AUTHORIZED",
  "INVALID",
  "STALE",
  "REVOKED",
  "AUTHORIZED",
]);
const BLOCKER = /^[A-Z0-9_|]{1,96}$/;
const NO_STORE_HEADERS = Object.freeze({
  "Cache-Control": "no-store",
});
const UTF8_ENCODER = new TextEncoder();

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
    throw new Error("P2 readiness response exceeds the fixed size limit.");
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

function gateSummary(snapshot, gateId) {
  const gate = snapshot.gates.find(({ id }) => id === gateId);
  if (!GATE_STATUSES.has(gate?.status)) {
    throw new Error("Invalid bounded Gate projection.");
  }
  const submissionId = gate?.latestSubmission?.submission_id;
  const decision = gate?.latestDecision?.decision;
  return {
    status: gate.status,
    decision: GATE_DECISIONS.has(decision) ? decision : null,
    submissionId: GOVERNED_ID.test(submissionId ?? "") ? submissionId : null,
  };
}

function currentProfileApproval(snapshot) {
  const authorization = snapshot.workPackages
    .find(({ id }) => id === "O02")
    ?.startAuthorization;
  if (
    authorization?.profileStatus !== "APPROVED" ||
    !GOVERNED_ID.test(authorization.profileApprovalId ?? "")
  ) {
    return null;
  }
  const event = snapshot.events
    .filter(({ type }) => type === "P2_ACCEPTANCE_PROFILE_APPROVED")
    .at(-1);
  const payload = event?.payload;
  if (
    !event ||
    !GOVERNED_ID.test(event.id ?? "") ||
    !Number.isInteger(event.revision) ||
    event.revision <= 0 ||
    payload?.profile_approval_id !== authorization.profileApprovalId ||
    !SHA256.test(payload.profile_sha256 ?? "") ||
    payload.execution_baseline_digest !==
      authorization.executionBaselineDigest ||
    !GIT_COMMIT.test(payload.source_commit ?? "")
  ) {
    return null;
  }
  return {
    eventId: event.id,
    revision: event.revision,
    profileApprovalId: payload.profile_approval_id,
    profileSha256: payload.profile_sha256,
    executionBaselineDigest: payload.execution_baseline_digest,
    sourceCommit: payload.source_commit,
  };
}

function currentAuthorizationId(snapshot, item) {
  if (item?.startAuthorization?.authorized !== true) return null;
  const event = snapshot.events
    .filter(
      ({ type, payload }) =>
        type === "P2_WORK_PACKAGE_START_AUTHORIZED" &&
        payload?.work_package_id === item.id,
    )
    .at(-1);
  if (
    event?.payload?.authorization_status !== "AUTHORIZED" ||
    event.payload.profile_approval_id !==
      item.startAuthorization.profileApprovalId ||
    event.payload.execution_baseline_digest !==
      item.startAuthorization.executionBaselineDigest ||
    !GOVERNED_ID.test(event.payload.authorization_id ?? "")
  ) {
    return null;
  }
  return event.payload.authorization_id;
}

function workPackageSummary(snapshot, workPackageId) {
  const item = snapshot.workPackages.find(({ id }) => id === workPackageId);
  const blockers = item?.blockers;
  if (
    !item ||
    !IMPLEMENTATION_STATUSES.has(item.implementationStatus) ||
    !VERIFICATION_STATUSES.has(item.verificationStatus) ||
    !START_AUTHORIZATION_STATUSES.has(
      item.startAuthorization?.executionStatus,
    ) ||
    typeof item.structuralReady !== "boolean" ||
    typeof item.allowedToStart !== "boolean" ||
    !Array.isArray(blockers) ||
    blockers.length > 16 ||
    blockers.some((blocker) => !BLOCKER.test(blocker))
  ) {
    throw new Error("Invalid bounded work-package projection.");
  }
  return {
    implementationStatus: item.implementationStatus,
    verificationStatus: item.verificationStatus,
    structuralReady: item.structuralReady,
    allowedToStart: item.allowedToStart,
    startAuthorizationStatus: item.startAuthorization.executionStatus,
    authorizationId: currentAuthorizationId(snapshot, item),
    blockers: [...blockers],
  };
}

export function projectP2Readiness(snapshot, serverTime) {
  return {
    schemaVersion: "p2-readiness-projection.v1",
    source: "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
    revision: snapshot.revision,
    phaseEntryP2: snapshot.phaseEntry.P2 === true,
    gates: {
      G0: gateSummary(snapshot, "G0"),
      G1: gateSummary(snapshot, "G1"),
    },
    profileApproval: currentProfileApproval(snapshot),
    workPackages: {
      O02: workPackageSummary(snapshot, "O02"),
      O03: workPackageSummary(snapshot, "O03"),
    },
    serverTime,
  };
}

export function createP2ReadinessGet({
  configuredProductOwner,
  isProductOwner,
  loadSnapshot,
  clock,
}) {
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
          error: "只有外部产品所有者可以读取 P2 准备度。",
        },
        403,
      );
    }

    try {
      const snapshot = await loadSnapshot();
      return await json(projectP2Readiness(snapshot, clock()));
    } catch {
      return json(
        {
          schemaVersion: ERROR_SCHEMA_VERSION,
          code: "P2_READINESS_UNAVAILABLE",
          error: "线上 P2 治理投影暂时不可用。",
        },
        503,
      );
    }
  };
}
