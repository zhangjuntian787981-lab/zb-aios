import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";

const AUTHORITY_ERROR_STATUS = 503;
const AUTHORITY_ACTOR_ID = "external_product_owner";
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const P0_IDS = Object.freeze(["F01", "F02", "F03", "F04"]);

export const F04_HISTORICAL_AUTHORITY_BINDING = Object.freeze({
  actorId: AUTHORITY_ACTOR_ID,
  workPackageId: "F04",
  implementationStatus: "IMPLEMENTED",
  verificationStatus: "VERIFIED",
  engineeringEvidenceSha256:
    "sha256:851851fcec6d961efaf17f6a0ced172c12dad2dced6746c9c9b805a205c95f62",
  humanEvidenceSha256:
    "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0",
  evidenceRefs: Object.freeze([
    "implementation/p0/f04/README.md",
    "implementation/p0/f04/threat-model.v1.md",
    "implementation/p0/f04/frozen-evaluation-cases.v1.json",
    "implementation/p0/f04/human-baseline-candidate.v1.json",
    "implementation/p0/f04/zero-tolerance.v1.json",
    "implementation/p0/f04/release-gate.config.v1.json",
    "scripts/f04-release-gate.mjs",
    "tests/f04-release-gate.test.mjs",
    "implementation/p0/evidence/f04-evidence.v1.json",
  ]),
  g0SubmissionRevision: 2,
  g0SubmissionId: "06531499-9cc4-4b09-b0c4-1f6d18e36fd6",
  g0PackageHash:
    "sha256:77d8707a602a83729b557c028bd6cf87c5a0e5d921145b9dc3a5a1e79bf32a07",
  g0DecisionRevision: 3,
  g0Decision: "APPROVE",
});

function authorityFailure(code, message) {
  return Object.assign(new Error(message), {
    code,
    status: AUTHORITY_ERROR_STATUS,
  });
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

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    same(Object.keys(value).sort(), [...expected].sort())
  );
}

function nonEmptyStrings(value) {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((item) => typeof item === "string" && item.length > 0)
  );
}

function frozenCatalogMatches(catalog) {
  const record = catalog?.records?.find(
    ({ workPackageId }) => workPackageId === "F04",
  );
  return (
    record?.workPackageId === "F04" &&
    same(record.evidenceRefs, F04_HISTORICAL_AUTHORITY_BINDING.evidenceRefs) &&
    Array.isArray(record.evidenceHashes) &&
    record.evidenceHashes.includes(
      F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256,
    )
  );
}

async function authorityCommandHash(event) {
  return sha256ProjectValue({
    actorId: AUTHORITY_ACTOR_ID,
    command: {
      kind: "RECORD_WORK_PACKAGE",
      workPackageId: "F04",
      implementationStatus: event.payload?.implementationStatus,
      verificationStatus: event.payload?.verificationStatus,
      evidenceRefs: event.payload?.evidenceRefs,
      evidenceHashes: event.payload?.evidenceHashes,
      note: event.payload?.note ?? "",
      expectedRevision: event.revision - 1,
      idempotencyKey: event.idempotencyKey,
    },
  });
}

async function isAuthorityCandidate(event) {
  if (
    event?.type !== "WORK_PACKAGE_RECORDED" ||
    typeof event.id !== "string" ||
    !event.id ||
    event.actorId !== AUTHORITY_ACTOR_ID ||
    event.payload?.workPackageId !== "F04" ||
    event.payload?.implementationStatus !== "IMPLEMENTED" ||
    event.payload?.verificationStatus !== "VERIFIED" ||
    !same(
      event.payload?.evidenceRefs,
      F04_HISTORICAL_AUTHORITY_BINDING.evidenceRefs,
    ) ||
    !same(event.payload?.evidenceHashes, [
      F04_HISTORICAL_AUTHORITY_BINDING.engineeringEvidenceSha256,
      F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256,
    ]) ||
    typeof event.idempotencyKey !== "string" ||
    !event.idempotencyKey ||
    !SHA256.test(event.commandHash ?? "")
  ) {
    return false;
  }
  return event.commandHash === (await authorityCommandHash(event));
}

function expectedHistoricalScope(catalog) {
  return P0_IDS.map((workPackageId) => {
    const record = catalog.records.find(
      (item) => item.workPackageId === workPackageId,
    );
    return {
      work_package_id: workPackageId,
      applicability: "REQUIRED",
      implementation_status: "IMPLEMENTED",
      verification_status: "VERIFIED",
      evidence_refs: [...record.evidenceRefs],
      evidence_hashes:
        workPackageId === "F04"
          ? [
              F04_HISTORICAL_AUTHORITY_BINDING.engineeringEvidenceSha256,
              F04_HISTORICAL_AUTHORITY_BINDING.humanEvidenceSha256,
            ]
          : [...record.evidenceHashes],
    };
  });
}

async function historicalSubmissionMatches(submission, catalog) {
  const scope = expectedHistoricalScope(catalog);
  const evidenceRefs = scope.flatMap((item) => item.evidence_refs);
  const payload = submission?.payload;
  if (
    submission?.revision !==
      F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionRevision ||
    submission.type !== "GATE_SUBMITTED" ||
    submission.actorId !== AUTHORITY_ACTOR_ID ||
    typeof submission.id !== "string" ||
    !submission.id ||
    typeof submission.idempotencyKey !== "string" ||
    !submission.idempotencyKey ||
    !SHA256.test(submission.commandHash ?? "") ||
    !validTime(submission.createdAt) ||
    !exactKeys(payload, [
      "evidence_refs",
      "gate_id",
      "package_hash",
      "source_revision",
      "submission_id",
      "submitted_at",
      "submitted_by",
      "supersedes",
      "work_package_scope",
    ]) ||
    payload.gate_id !== "G0" ||
    payload.submission_id !==
      F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId ||
    payload.package_hash !==
      F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash ||
    payload.source_revision !== 1 ||
    payload.submitted_by !== AUTHORITY_ACTOR_ID ||
    !validTime(payload.submitted_at) ||
    payload.supersedes !== null ||
    !same(payload.work_package_scope, scope) ||
    !same(payload.evidence_refs, evidenceRefs)
  ) {
    return false;
  }
  const packageHash = await sha256ProjectValue({
    manifest_version: "1.0.0",
    gate_id: "G0",
    source_revision: 1,
    work_package_scope: scope,
    evidence_refs: evidenceRefs,
  });
  const commandHash = await sha256ProjectValue({
    actorId: AUTHORITY_ACTOR_ID,
    command: {
      kind: "SUBMIT_GATE",
      gateId: "G0",
      evidenceRefs,
      supersedes: null,
      expectedRevision: 1,
      idempotencyKey: submission.idempotencyKey,
    },
  });
  return (
    packageHash === F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash &&
    commandHash === submission.commandHash
  );
}

async function historicalDecisionMatches(decision) {
  const payload = decision?.payload;
  if (
    decision?.revision !==
      F04_HISTORICAL_AUTHORITY_BINDING.g0DecisionRevision ||
    decision.type !== "GATE_DECIDED" ||
    decision.actorId !== AUTHORITY_ACTOR_ID ||
    typeof decision.id !== "string" ||
    !decision.id ||
    typeof decision.idempotencyKey !== "string" ||
    !decision.idempotencyKey ||
    !SHA256.test(decision.commandHash ?? "") ||
    !validTime(decision.createdAt) ||
    !exactKeys(payload, [
      "accepted_exclusions",
      "decided_at",
      "decided_by",
      "decision",
      "decision_id",
      "evidence_refs",
      "package_hash",
      "submission_id",
    ]) ||
    typeof payload.decision_id !== "string" ||
    !payload.decision_id ||
    payload.submission_id !==
      F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId ||
    payload.package_hash !==
      F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash ||
    payload.decision !== F04_HISTORICAL_AUTHORITY_BINDING.g0Decision ||
    payload.decided_by !== AUTHORITY_ACTOR_ID ||
    !validTime(payload.decided_at) ||
    !Array.isArray(payload.accepted_exclusions) ||
    payload.accepted_exclusions.length !== 0 ||
    !nonEmptyStrings(payload.evidence_refs)
  ) {
    return false;
  }
  return (
    decision.commandHash ===
    (await sha256ProjectValue({
      actorId: AUTHORITY_ACTOR_ID,
      command: {
        kind: "DECIDE_GATE",
        submissionId:
          F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
        expectedPackageHash:
          F04_HISTORICAL_AUTHORITY_BINDING.g0PackageHash,
        decision: F04_HISTORICAL_AUTHORITY_BINDING.g0Decision,
        acceptedExclusions: [],
        evidenceRefs: payload.evidence_refs,
        expectedRevision: 2,
        idempotencyKey: decision.idempotencyKey,
      },
    }))
  );
}

function historicalSubmission(journalState) {
  return journalState.events.filter(
    ({ type, payload }) =>
      type === "GATE_SUBMITTED" &&
      payload?.gate_id === "G0" &&
      payload?.submission_id ===
        F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
  );
}

function historicalDecision(journalState) {
  return journalState.events.filter(
    ({ type, payload }) =>
      type === "GATE_DECIDED" &&
      payload?.submission_id ===
        F04_HISTORICAL_AUTHORITY_BINDING.g0SubmissionId,
  );
}

export async function assertUniqueF04HistoricalAuthority({
  journalState,
  catalog,
}) {
  const authority = await assertF04HistoricalAuthority({
    journalState,
    catalog,
  });
  const candidates = [];
  for (const event of journalState.events) {
    if (await isAuthorityCandidate(event)) candidates.push(event);
  }
  if (candidates.length !== 1) {
    throw authorityFailure(
      "F04_HUMAN_AUTHORITY_AMBIGUOUS",
      "线上 D1 存在多个符合条件的 F04 真人基线权威事件。",
    );
  }
  if (
    historicalSubmission(journalState).length !== 1 ||
    historicalDecision(journalState).length !== 1
  ) {
    throw authorityFailure(
      "G0_HISTORICAL_ANCHOR_MISMATCH",
      "历史 G0 Submission 或 Decision 锚点不唯一。",
    );
  }
  return authority;
}

export async function assertF04HistoricalAuthority({
  journalState,
  catalog,
}) {
  if (!Array.isArray(journalState?.events) || !frozenCatalogMatches(catalog)) {
    throw authorityFailure(
      "F04_HUMAN_AUTHORITY_UNPROVEN",
      "F04 真人基线未绑定到线上 D1 revision 1 的权威事件。",
    );
  }

  const f04Event = journalState.events[0];
  if (!(await isAuthorityCandidate(f04Event)) || f04Event.revision !== 1) {
    throw authorityFailure(
      "F04_HUMAN_AUTHORITY_UNPROVEN",
      "F04 真人基线未绑定到线上 D1 revision 1 的权威事件。",
    );
  }

  const submission = journalState.events[1];
  if (!(await historicalSubmissionMatches(submission, catalog))) {
    throw authorityFailure(
      "G0_HISTORICAL_ANCHOR_MISMATCH",
      "历史 G0 Submission 锚点不匹配。",
    );
  }

  const decision = journalState.events[2];
  if (!(await historicalDecisionMatches(decision))) {
    throw authorityFailure(
      "G0_HISTORICAL_ANCHOR_MISMATCH",
      "历史 G0 Decision 锚点不匹配。",
    );
  }

  return {
    f04Event,
    historicalSubmission: submission,
    historicalDecision: decision,
  };
}
