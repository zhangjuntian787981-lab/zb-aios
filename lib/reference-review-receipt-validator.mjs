import receiptSchema from "../implementation/governance/schemas/reference-review-receipt.v1.schema.json" with { type: "json" };
import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const NON_EMPTY = (value) =>
  typeof value === "string" && value.trim().length > 0;
const RECEIPT_KEYS = Object.freeze([
  "adrRef",
  "alternativePath",
  "alternativesCompared",
  "applicableReferenceSetDigest",
  "capabilityGap",
  "currentImplementation",
  "decision",
  "decisionReason",
  "evidenceHashes",
  "evidenceRefs",
  "governanceEffect",
  "isProgressTracker",
  "licenseAndRedistributionAssessment",
  "maintenanceAndExitAssessment",
  "notApplicableReason",
  "officialSources",
  "ownerRole",
  "pocRequired",
  "pocResult",
  "productionAdoptionClaim",
  "profileSha256",
  "receiptId",
  "receiptSha256",
  "referenceCatalogSha256",
  "referenceId",
  "referenceKind",
  "referenceName",
  "referencePolicySha256",
  "reReviewTrigger",
  "reviewBoundary",
  "reviewMode",
  "reviewedAt",
  "reviewedMaterials",
  "reviewedSections",
  "schemaVersion",
  "securityAndDataFlowAssessment",
  "selfAuthorizing",
  "sourceCommit",
  "supersedesReceiptId",
  "workPackageId",
]);

function resolveLocalSchemaReference(rootSchema, reference) {
  if (
    typeof reference !== "string" ||
    !reference.startsWith("#/")
  ) {
    return null;
  }
  return reference
    .slice(2)
    .split("/")
    .map((part) =>
      part.replaceAll("~1", "/").replaceAll("~0", "~"),
    )
    .reduce(
      (current, part) =>
        current &&
        typeof current === "object" &&
        Object.hasOwn(current, part)
          ? current[part]
          : null,
      rootSchema,
    );
}

function matchesSchemaType(type, value) {
  if (type === "object") {
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value)
    );
  }
  if (type === "array") return Array.isArray(value);
  if (type === "null") return value === null;
  return typeof value === type;
}

function matchesSchemaFormat(format, value) {
  if (format === "uri") {
    try {
      return new URL(value).href.length > 0;
    } catch {
      return false;
    }
  }
  if (format === "date-time") {
    return (
      /^\d{4}-\d{2}-\d{2}T/u.test(value) &&
      !Number.isNaN(Date.parse(value))
    );
  }
  return false;
}

function matchesClosedSchema(schema, value, rootSchema) {
  if (!schema || typeof schema !== "object") return false;
  if (schema.$ref) {
    const target = resolveLocalSchemaReference(
      rootSchema,
      schema.$ref,
    );
    return (
      target !== null &&
      matchesClosedSchema(target, value, rootSchema)
    );
  }
  if (
    Array.isArray(schema.anyOf) &&
    !schema.anyOf.some((candidate) =>
      matchesClosedSchema(candidate, value, rootSchema),
    )
  ) {
    return false;
  }
  if (
    Object.hasOwn(schema, "const") &&
    JSON.stringify(value) !== JSON.stringify(schema.const)
  ) {
    return false;
  }
  if (
    Array.isArray(schema.enum) &&
    !schema.enum.some(
      (candidate) =>
        JSON.stringify(value) === JSON.stringify(candidate),
    )
  ) {
    return false;
  }
  if (schema.type && !matchesSchemaType(schema.type, value)) {
    return false;
  }
  if (
    typeof value === "string" &&
    ((Number.isInteger(schema.minLength) &&
      value.length < schema.minLength) ||
      (schema.pattern &&
        !new RegExp(schema.pattern, "u").test(value)) ||
      (schema.format &&
        !matchesSchemaFormat(schema.format, value)))
  ) {
    return false;
  }
  if (Array.isArray(value)) {
    if (
      (Number.isInteger(schema.minItems) &&
        value.length < schema.minItems) ||
      (Number.isInteger(schema.maxItems) &&
        value.length > schema.maxItems) ||
      (schema.uniqueItems === true &&
        new Set(value.map((item) => JSON.stringify(item))).size !==
          value.length)
    ) {
      return false;
    }
    if (
      schema.items &&
      value.some(
        (item) =>
          !matchesClosedSchema(schema.items, item, rootSchema),
      )
    ) {
      return false;
    }
  }
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    schema.type === "object"
  ) {
    const properties = schema.properties ?? {};
    if (
      (schema.required ?? []).some(
        (key) => !Object.hasOwn(value, key),
      ) ||
      (schema.additionalProperties === false &&
        Object.keys(value).some(
          (key) => !Object.hasOwn(properties, key),
        ))
    ) {
      return false;
    }
    for (const [key, propertySchema] of Object.entries(properties)) {
      if (
        Object.hasOwn(value, key) &&
        !matchesClosedSchema(
          propertySchema,
          value[key],
          rootSchema,
        )
      ) {
        return false;
      }
    }
  }
  return true;
}

export function validateReferenceReviewSchema(schema, value) {
  return matchesClosedSchema(schema, value, schema);
}

const validateReceiptSchema = (value) =>
  validateReferenceReviewSchema(receiptSchema, value);

function keysExactly(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

async function receiptDigest(receipt) {
  return sha256ProjectValue(withoutField(receipt, "receiptSha256"));
}

function materialHasExactPin(material) {
  return (
    NON_EMPTY(material?.documentationVersion) ||
    GIT_COMMIT.test(material?.sourceCommit ?? "") ||
    NON_EMPTY(material?.release) ||
    SHA256.test(material?.imageDigest ?? "") ||
    SHA256.test(material?.artifactDigest ?? "")
  );
}

function sourceIsOfficial(source) {
  return (
    NON_EMPTY(source?.sourceId) &&
    typeof source?.uri === "string" &&
    source.uri.startsWith("https://") &&
    NON_EMPTY(source?.authority) &&
    typeof source?.sourceKind === "string" &&
    source.sourceKind.startsWith("OFFICIAL_") &&
    NON_EMPTY(source?.contentEvidenceRef) &&
    SHA256.test(source?.contentSha256 ?? "")
  );
}

function matchingStringAndHashArrays(refs, hashes) {
  return (
    Array.isArray(refs) &&
    Array.isArray(hashes) &&
    refs.length === hashes.length &&
    refs.every(NON_EMPTY) &&
    hashes.every((hash) => SHA256.test(hash))
  );
}

function baseReasonCodes(receipt) {
  const reasons = [];
  if (
    !receipt ||
    typeof receipt !== "object" ||
    Array.isArray(receipt)
  ) {
    return ["REFERENCE_RECEIPT_INVALID"];
  }
  if (!keysExactly(receipt, RECEIPT_KEYS)) {
    reasons.push("REFERENCE_RECEIPT_SCHEMA_CLOSED");
  }
  if (!validateReceiptSchema(receipt)) {
    reasons.push("REFERENCE_RECEIPT_SCHEMA_INVALID");
  }
  if (
    receipt.governanceEffect !== "NONE" ||
    receipt.isProgressTracker !== false ||
    receipt.selfAuthorizing !== false
  ) {
    reasons.push("REFERENCE_RECEIPT_CANNOT_AUTHORIZE");
  }
  if (receipt.productionAdoptionClaim !== false) {
    reasons.push("REFERENCE_PRODUCTION_ADOPTION_CLAIM_FORBIDDEN");
  }
  if (
    !Array.isArray(receipt.officialSources) ||
    receipt.officialSources.length === 0 ||
    receipt.officialSources.some((source) => !sourceIsOfficial(source))
  ) {
    reasons.push("REFERENCE_OFFICIAL_SOURCE_NOT_PROVED");
  }
  const sourceIds = new Set(
    (receipt.officialSources ?? []).map(({ sourceId }) => sourceId),
  );
  if (
    !Array.isArray(receipt.reviewedMaterials) ||
    receipt.reviewedMaterials.length === 0 ||
    receipt.reviewedMaterials.some(
      (material) =>
        !sourceIds.has(material?.sourceId) ||
        !materialHasExactPin(material),
    )
  ) {
    reasons.push("REFERENCE_VERSION_NOT_PINNED");
  }
  if (
    !Array.isArray(receipt.reviewedSections) ||
    receipt.reviewedSections.length === 0 ||
    receipt.reviewedSections.some(
      (section) =>
        !sourceIds.has(section?.sourceId) ||
        !NON_EMPTY(section?.locator) ||
        !NON_EMPTY(section?.topic) ||
        !NON_EMPTY(section?.notesRef) ||
        !SHA256.test(section?.notesDigest ?? ""),
    )
  ) {
    reasons.push("REFERENCE_REVIEWED_SECTIONS_MISSING");
  }
  if (
    !NON_EMPTY(receipt.capabilityGap?.summary) ||
    !NON_EMPTY(receipt.capabilityGap?.currentMeasure) ||
    !NON_EMPTY(receipt.capabilityGap?.targetMeasure) ||
    !NON_EMPTY(receipt.capabilityGap?.evidenceRef) ||
    !SHA256.test(receipt.capabilityGap?.evidenceHash ?? "") ||
    !NON_EMPTY(receipt.currentImplementation?.summary) ||
    !matchingStringAndHashArrays(
      receipt.currentImplementation?.evidenceRefs,
      receipt.currentImplementation?.evidenceHashes,
    ) ||
    receipt.currentImplementation.evidenceRefs.length === 0 ||
    !Array.isArray(receipt.alternativesCompared) ||
    receipt.alternativesCompared.length < 2 ||
    new Set(
      (receipt.alternativesCompared ?? []).map(
        ({ alternativeId }) => alternativeId,
      ),
    ).size !== receipt.alternativesCompared.length ||
    receipt.alternativesCompared.filter(
      ({ disposition }) => disposition === "SELECTED",
    ).length !== 1 ||
    !NON_EMPTY(receipt.decisionReason)
  ) {
    reasons.push("REFERENCE_COMPARISON_INCOMPLETE");
  }
  if (
    !matchingStringAndHashArrays(
      receipt.evidenceRefs,
      receipt.evidenceHashes,
    ) ||
    receipt.evidenceRefs.length === 0
  ) {
    reasons.push("REFERENCE_EVIDENCE_INCOMPLETE");
  }
  if (!GIT_COMMIT.test(receipt.sourceCommit ?? "")) {
    reasons.push("REFERENCE_SOURCE_COMMIT_INVALID");
  }
  if (
    receipt.reviewMode === "RETROSPECTIVE_BACKFILL" &&
    receipt.governanceEffect !== "NONE"
  ) {
    reasons.push("REFERENCE_BACKFILL_CANNOT_CHANGE_HISTORY");
  }
  return reasons;
}

function adoptReasonCodes(receipt) {
  const reasons = [];
  const license = receipt.licenseAndRedistributionAssessment;
  const security = receipt.securityAndDataFlowAssessment;
  const maintenance = receipt.maintenanceAndExitAssessment;
  const sourceIds = new Set(
    (receipt.officialSources ?? []).map(({ sourceId }) => sourceId),
  );
  const reviewedPins = new Set(
    (receipt.reviewedMaterials ?? []).flatMap((material) =>
      [
        material.documentationVersion,
        material.sourceCommit,
        material.release,
        material.imageDigest,
        material.artifactDigest,
      ].filter(
        (value) => typeof value === "string" && value.length > 0,
      ),
    ),
  );
  if (
    !NON_EMPTY(license?.licenseId) ||
    !sourceIds.has(license?.licenseSourceId) ||
    !NON_EMPTY(license?.reviewedVersion) ||
    !reviewedPins.has(license?.reviewedVersion) ||
    !NON_EMPTY(license?.usageMode) ||
    !NON_EMPTY(license?.distributionMode) ||
    !NON_EMPTY(license?.rationale) ||
    license?.conclusion !== "ACCEPTABLE"
  ) {
    reasons.push("REFERENCE_ADOPT_LICENSE_INCOMPLETE");
  }
  if (
    !NON_EMPTY(security?.rationale) ||
    security?.conclusion !== "ACCEPTABLE" ||
    ![
      security?.dataClasses,
      security?.ingress,
      security?.egress,
      security?.storage,
      security?.networkAccess,
      security?.privileges,
      security?.secretHandling,
      security?.trustBoundaries,
      security?.knownRisks,
    ].every(
      (values) =>
        Array.isArray(values) &&
        values.length > 0 &&
        values.every(NON_EMPTY),
    )
  ) {
    reasons.push("REFERENCE_ADOPT_SECURITY_DATA_FLOW_INCOMPLETE");
  }
  if (
    !NON_EMPTY(maintenance?.operationalOwnerRole) ||
    !NON_EMPTY(maintenance?.upgradeCadence) ||
    !NON_EMPTY(maintenance?.onCallResponsibility) ||
    !NON_EMPTY(maintenance?.exitPlan) ||
    !NON_EMPTY(maintenance?.migrationTarget) ||
    !NON_EMPTY(maintenance?.stopMaintenanceTrigger) ||
    maintenance?.exitPlanStatus !== "DEFINED"
  ) {
    reasons.push("REFERENCE_ADOPT_MAINTENANCE_EXIT_INCOMPLETE");
  }
  if (!NON_EMPTY(receipt.adrRef)) {
    reasons.push("REFERENCE_ADOPT_ADR_MISSING");
  }
  if (
    receipt.pocRequired === true &&
    (receipt.pocResult?.status !== "PASS" ||
      !matchingStringAndHashArrays(
        receipt.pocResult?.evidenceRefs,
        receipt.pocResult?.evidenceHashes,
      ) ||
      receipt.pocResult.evidenceRefs.length === 0)
  ) {
    reasons.push("REFERENCE_ADOPT_POC_NOT_PASSED");
  }
  return reasons;
}

function decisionReasonCodes(receipt) {
  const candidateSelected = (
    receipt.alternativesCompared ?? []
  ).some(
    ({ name, kind, disposition }) =>
      name === receipt.referenceName &&
      kind === receipt.referenceKind &&
      disposition === "SELECTED",
  );
  if (receipt.decision === "ADOPT") {
    return [
      ...adoptReasonCodes(receipt),
      ...(candidateSelected
        ? []
        : ["REFERENCE_ADOPT_COMPARISON_INCOMPLETE"]),
    ];
  }
  if (candidateSelected) {
    return ["REFERENCE_NON_ADOPT_CANDIDATE_SELECTED"];
  }
  if (receipt.decision === "REJECT") {
    return NON_EMPTY(receipt.decisionReason) &&
      NON_EMPTY(receipt.alternativePath)
      ? []
      : ["REFERENCE_REJECT_PATH_MISSING"];
  }
  if (receipt.decision === "DEFER") {
    return NON_EMPTY(receipt.decisionReason) &&
      NON_EMPTY(receipt.reReviewTrigger?.condition) &&
      NON_EMPTY(receipt.reReviewTrigger?.beforeBoundary)
      ? []
      : ["REFERENCE_DEFER_TRIGGER_MISSING"];
  }
  if (receipt.decision === "NOT_APPLICABLE") {
    return NON_EMPTY(receipt.decisionReason) &&
      NON_EMPTY(receipt.notApplicableReason)
      ? []
      : ["REFERENCE_NOT_APPLICABLE_REASON_MISSING"];
  }
  return ["REFERENCE_DECISION_INVALID"];
}

export const referenceReviewDigests = Object.freeze({
  receipt: receiptDigest,
  value: sha256ProjectValue,
  canonicalize: canonicalizeProjectJson,
});

export async function validateReferenceReviewReceipt(receipt) {
  const reasonCodes = [
    ...baseReasonCodes(receipt),
    ...decisionReasonCodes(receipt ?? {}),
  ];
  if (
    receipt &&
    SHA256.test(receipt.receiptSha256 ?? "") &&
    (await receiptDigest(receipt)) !== receipt.receiptSha256
  ) {
    reasonCodes.push("REFERENCE_RECEIPT_HASH_MISMATCH");
  } else if (!SHA256.test(receipt?.receiptSha256 ?? "")) {
    reasonCodes.push("REFERENCE_RECEIPT_HASH_MISMATCH");
  }
  const uniqueReasonCodes = [...new Set(reasonCodes)];
  return uniqueReasonCodes.length === 0
    ? { ok: true, status: "VALID", reasonCodes: [] }
    : { ok: false, status: "INVALID", reasonCodes: uniqueReasonCodes };
}
