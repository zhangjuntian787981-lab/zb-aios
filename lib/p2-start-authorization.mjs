const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const PROTECTED_WORK_PACKAGES = Object.freeze(["O02", "O03"]);
const PROFILE_APPROVAL_ID = /^p2pa_[a-z0-9][a-z0-9_-]{7,127}$/;
const START_AUTHORIZATION_ID = /^p2wpa_[a-z0-9][a-z0-9_-]{7,127}$/;
export const P2_V2_CANDIDATE_START_POLICY = Object.freeze({
  protectedWorkPackages: Object.freeze(["O02", "O03"]),
  profile: Object.freeze({
    path: "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
    schemaVersion: "p2-acceptance-profile.v2",
    sha256:
      "sha256:34c6932cb6040d92512370d2b6f00b835a9e7f5ab816c1eb2dc7a4fcdf93ac3a",
  }),
  receiptSchema: Object.freeze({
    path: "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
    version: "p2-acceptance-receipt.v2",
    sha256:
      "sha256:f995310688c620b24c42b058fb6305b00876e0dfa0b8a755f41f827bfcb700bf",
  }),
  validator: Object.freeze({
    path: "lib/p2-acceptance-receipt-validator.mjs",
    version: "p2-acceptance-validator.v2",
    sha256:
      "sha256:1c31fd405a57237ef90a0c25154443a2e6ece473663ed270ffad7b85d728cf95",
  }),
});
const PROFILE_PAYLOAD_KEYS = [
  "approved_at",
  "approved_by",
  "execution_baseline_digest",
  "profile_approval_id",
  "profile_path",
  "profile_schema_version",
  "profile_sha256",
  "receipt_schema_path",
  "receipt_schema_sha256",
  "receipt_schema_version",
  "source_commit",
  "source_revision",
  "supersedes",
  "validator_path",
  "validator_sha256",
  "validator_version",
];
const START_PAYLOAD_KEYS = [
  "authorization_id",
  "authorization_status",
  "execution_baseline_digest",
  "profile_approval_id",
  "profile_sha256",
  "recorded_at",
  "recorded_by",
  "revokes_authorization_id",
  "source_revision",
  "work_package_id",
];

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort())
  );
}

function policyValid(policy) {
  return (
    Array.isArray(policy?.protectedWorkPackages) &&
    policy.protectedWorkPackages.length ===
      PROTECTED_WORK_PACKAGES.length &&
    new Set(policy.protectedWorkPackages).size ===
      PROTECTED_WORK_PACKAGES.length &&
    PROTECTED_WORK_PACKAGES.every((id) =>
      policy.protectedWorkPackages.includes(id),
    ) &&
    typeof policy.profile?.path === "string" &&
    policy.profile.schemaVersion === "p2-acceptance-profile.v2" &&
    SHA256.test(policy.profile.sha256 ?? "") &&
    typeof policy.receiptSchema?.path === "string" &&
    policy.receiptSchema.version === "p2-acceptance-receipt.v2" &&
    SHA256.test(policy.receiptSchema.sha256 ?? "") &&
    typeof policy.validator?.path === "string" &&
    policy.validator.version === "p2-acceptance-validator.v2" &&
    SHA256.test(policy.validator.sha256 ?? "")
  );
}

function profileEventValid(event, policy) {
  const payload = event?.payload;
  return (
    event?.type === "P2_ACCEPTANCE_PROFILE_APPROVED" &&
    Number.isInteger(event.revision) &&
    event.revision > 0 &&
    exactKeys(payload, PROFILE_PAYLOAD_KEYS) &&
    PROFILE_APPROVAL_ID.test(payload.profile_approval_id ?? "") &&
    payload.profile_path === policy.profile.path &&
    payload.profile_sha256 === policy.profile.sha256 &&
    payload.profile_schema_version === policy.profile.schemaVersion &&
    payload.receipt_schema_path === policy.receiptSchema.path &&
    payload.receipt_schema_sha256 === policy.receiptSchema.sha256 &&
    payload.receipt_schema_version === policy.receiptSchema.version &&
    payload.validator_path === policy.validator.path &&
    payload.validator_sha256 === policy.validator.sha256 &&
    payload.validator_version === policy.validator.version &&
    SHA256.test(payload.execution_baseline_digest ?? "") &&
    GIT_COMMIT.test(payload.source_commit ?? "") &&
    payload.approved_by === event.actorId &&
    payload.approved_at === event.createdAt &&
    payload.source_revision === event.revision - 1 &&
    (payload.supersedes === null ||
      PROFILE_APPROVAL_ID.test(payload.supersedes ?? ""))
  );
}

function startEventValid(event) {
  const payload = event?.payload;
  return (
    event?.type === "P2_WORK_PACKAGE_START_AUTHORIZED" &&
    Number.isInteger(event.revision) &&
    event.revision > 0 &&
    exactKeys(payload, START_PAYLOAD_KEYS) &&
    START_AUTHORIZATION_ID.test(payload.authorization_id ?? "") &&
    ["O02", "O03"].includes(payload.work_package_id) &&
    PROFILE_APPROVAL_ID.test(payload.profile_approval_id ?? "") &&
    SHA256.test(payload.profile_sha256 ?? "") &&
    SHA256.test(payload.execution_baseline_digest ?? "") &&
    ["AUTHORIZED", "REVOKED"].includes(payload.authorization_status) &&
    payload.recorded_by === event.actorId &&
    payload.recorded_at === event.createdAt &&
    payload.source_revision === event.revision - 1 &&
    ((payload.authorization_status === "AUTHORIZED" &&
      payload.revokes_authorization_id === null) ||
      (payload.authorization_status === "REVOKED" &&
        START_AUTHORIZATION_ID.test(payload.revokes_authorization_id ?? "")))
  );
}

function denied({
  profileStatus,
  executionStatus,
  reasonCode,
  profileApprovalId = null,
  executionBaselineDigest = null,
}) {
  return {
    required: true,
    profileStatus,
    executionStatus,
    authorized: false,
    profileApprovalId,
    executionBaselineDigest,
    reasonCodes: [reasonCode],
  };
}

export function evaluateP2StartAuthorization({
  workPackageId,
  governanceEvents,
  policy,
}) {
  if (!PROTECTED_WORK_PACKAGES.includes(workPackageId)) {
    return {
      required: false,
      profileStatus: "NOT_REQUIRED",
      executionStatus: "NOT_REQUIRED",
      authorized: true,
      profileApprovalId: null,
      executionBaselineDigest: null,
      reasonCodes: [],
    };
  }
  if (!policyValid(policy)) {
    return denied({
      profileStatus: "INVALID",
      executionStatus: "NOT_AUTHORIZED",
      reasonCode: "P2_START_POLICY_INVALID",
    });
  }
  if (!Array.isArray(governanceEvents)) {
    return denied({
      profileStatus: "INVALID",
      executionStatus: "NOT_AUTHORIZED",
      reasonCode: "P2_GOVERNANCE_EVENT_INVALID",
    });
  }

  const ordered = [...governanceEvents].sort(
    (left, right) => left.revision - right.revision,
  );
  const profileEvents = ordered.filter(
    ({ type }) => type === "P2_ACCEPTANCE_PROFILE_APPROVED",
  );
  if (profileEvents.length === 0) {
    return denied({
      profileStatus: "NOT_APPROVED",
      executionStatus: "NOT_AUTHORIZED",
      reasonCode: "P2_PROFILE_NOT_APPROVED",
    });
  }

  let previousProfileApprovalId = null;
  for (const event of profileEvents) {
    if (
      !profileEventValid(event, policy) ||
      event.payload.supersedes !== previousProfileApprovalId
    ) {
      return denied({
        profileStatus: "INVALID",
        executionStatus: "NOT_AUTHORIZED",
        reasonCode: "P2_GOVERNANCE_EVENT_INVALID",
      });
    }
    previousProfileApprovalId = event.payload.profile_approval_id;
  }
  const activeProfileEvent = profileEvents.at(-1);
  const activeProfile = activeProfileEvent.payload;

  const allStartEvents = ordered.filter(
    ({ type }) => type === "P2_WORK_PACKAGE_START_AUTHORIZED",
  );
  if (allStartEvents.some((event) => !startEventValid(event))) {
    return denied({
      profileStatus: "APPROVED",
      executionStatus: "INVALID",
      reasonCode: "P2_GOVERNANCE_EVENT_INVALID",
      profileApprovalId: activeProfile.profile_approval_id,
      executionBaselineDigest: activeProfile.execution_baseline_digest,
    });
  }
  const workPackageEvents = allStartEvents.filter(
    ({ payload }) => payload.work_package_id === workPackageId,
  );
  if (workPackageEvents.length === 0) {
    return denied({
      profileStatus: "APPROVED",
      executionStatus: "NOT_AUTHORIZED",
      reasonCode: "P2_START_AUTHORIZATION_MISSING",
      profileApprovalId: activeProfile.profile_approval_id,
      executionBaselineDigest: activeProfile.execution_baseline_digest,
    });
  }

  let previousAuthorizationId = null;
  let previousAuthorizationStatus = null;
  for (const event of workPackageEvents) {
    const payload = event.payload;
    if (
      (payload.authorization_status === "AUTHORIZED" &&
        previousAuthorizationStatus === "AUTHORIZED") ||
      (payload.authorization_status === "REVOKED" &&
        (previousAuthorizationStatus !== "AUTHORIZED" ||
          payload.revokes_authorization_id !== previousAuthorizationId))
    ) {
      return denied({
        profileStatus: "APPROVED",
        executionStatus: "INVALID",
        reasonCode: "P2_GOVERNANCE_EVENT_INVALID",
        profileApprovalId: activeProfile.profile_approval_id,
        executionBaselineDigest: activeProfile.execution_baseline_digest,
      });
    }
    previousAuthorizationId = payload.authorization_id;
    previousAuthorizationStatus = payload.authorization_status;
  }

  const latest = workPackageEvents.at(-1).payload;
  if (
    latest.profile_approval_id !== activeProfile.profile_approval_id ||
    latest.profile_sha256 !== activeProfile.profile_sha256 ||
    latest.execution_baseline_digest !==
      activeProfile.execution_baseline_digest
  ) {
    return denied({
      profileStatus: "APPROVED",
      executionStatus: "STALE",
      reasonCode: "P2_START_AUTHORIZATION_STALE",
      profileApprovalId: activeProfile.profile_approval_id,
      executionBaselineDigest: activeProfile.execution_baseline_digest,
    });
  }
  if (latest.authorization_status === "REVOKED") {
    return denied({
      profileStatus: "APPROVED",
      executionStatus: "REVOKED",
      reasonCode: "P2_START_AUTHORIZATION_REVOKED",
      profileApprovalId: activeProfile.profile_approval_id,
      executionBaselineDigest: activeProfile.execution_baseline_digest,
    });
  }
  return {
    required: true,
    profileStatus: "APPROVED",
    executionStatus: "AUTHORIZED",
    authorized: true,
    profileApprovalId: activeProfile.profile_approval_id,
    executionBaselineDigest: activeProfile.execution_baseline_digest,
    reasonCodes: [],
  };
}
