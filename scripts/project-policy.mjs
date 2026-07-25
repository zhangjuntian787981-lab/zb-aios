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

export function isValidConnectorAdvanceEvidence(
  currentStage,
  nextStage,
  evidence,
) {
  const stages = ["C0", "C1", "C2", "C3"];
  const currentIndex = stages.indexOf(currentStage);
  const nextIndex = stages.indexOf(nextStage);
  if (currentIndex < 0 || nextIndex < 0) return false;
  if (nextIndex <= currentIndex) return true;
  if (!SHA256_EVIDENCE.test(evidence)) return false;
  return (
    currentStage !== "C0" ||
    nextStage !== "C1" ||
    ENTERPRISE_AUTHORIZATION.test(evidence)
  );
}
