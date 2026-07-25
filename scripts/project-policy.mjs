const PHASE_ENTRY_GATES = {
  P1: "v4-p0-09-stage-approval",
  P2: "v4-p1-03-stage-approval",
  P3: "v4-p2-02-stage-approval",
};

const STAGE_GATE_REQUIREMENTS = {
  "v4-p0-09-stage-approval": [
    "v4-p0-01-engineering-plan",
    "v4-p0-02-beginner-plan",
    "v4-p0-03-progress-center",
    "v4-p0-04-product-owner",
    "v4-p0-05-synthetic-boundary",
    "v4-p0-06-tenant-boundary",
    "v4-p0-07-public-context",
    "v4-p0-08-technical-gates",
  ],
  "v4-p1-03-stage-approval": [
    "v4-p1-01-core",
    "v4-p1-02-synthetic-validation",
  ],
  "v4-p2-02-stage-approval": ["v4-p2-01-product-hardening"],
  "v4-p3-02-stage-approval": ["v4-p3-01-enterprise-onboarding"],
};

const STAGE_APPROVAL_TASKS = new Set(Object.keys(STAGE_GATE_REQUIREMENTS));
const SHA256_EVIDENCE = /(?:^|\s)sha256:[a-f0-9]{64}(?:\s|$)/i;
const ENTERPRISE_AUTHORIZATION =
  /(?:^|\s)enterprise-authorization:[a-z0-9._:-]{3,160}(?:\s|$)/i;

function normalized(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function isProductOwner(actor, configuredOwner) {
  const normalizedActor = normalized(actor);
  const normalizedOwner = normalized(configuredOwner);
  return Boolean(normalizedActor && normalizedActor === normalizedOwner);
}

export function canStartPhase(phase, statuses) {
  const gateId = PHASE_ENTRY_GATES[phase];
  return !gateId || statuses[gateId] === "accepted";
}

export function canAcceptStageGate(taskId, statuses) {
  const requirements = STAGE_GATE_REQUIREMENTS[taskId] ?? [];
  return requirements.every((id) => statuses[id] === "accepted");
}

export function canAdvanceConnector(statuses) {
  return statuses["v4-p2-02-stage-approval"] === "accepted";
}

export function isStageApprovalTask(taskId) {
  return STAGE_APPROVAL_TASKS.has(taskId);
}

export function isValidStageApprovalEvidence(taskId, evidence) {
  return !isStageApprovalTask(taskId) || SHA256_EVIDENCE.test(evidence);
}

export function isValidConnectorAdvanceEvidence(
  currentStage,
  nextStage,
  evidence,
) {
  const stages = ["C0", "C1", "C2", "C3"];
  const currentIndex = stages.indexOf(currentStage);
  const nextIndex = stages.indexOf(nextStage);
  if (currentIndex < 0 || nextIndex <= currentIndex) return true;
  if (!SHA256_EVIDENCE.test(evidence)) return false;
  return (
    currentStage !== "C0" ||
    nextStage !== "C1" ||
    ENTERPRISE_AUTHORIZATION.test(evidence)
  );
}
