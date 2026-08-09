import { createHash, randomBytes } from "node:crypto";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7}$`);
const ARTIFACT_ID = new RegExp(`^dar_${UUID_V7}$`);
const DECISION_ID = new RegExp(`^std_${UUID_V7}$`);
const EFFECT_ID = new RegExp(`^hef_${UUID_V7}$`);
const AUDIT_INTENT_ID = new RegExp(`^hai_${UUID_V7}$`);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|synthetic|test):\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const MAX_LEASE_SECONDS = 300;
const MAX_RETRY_SECONDS = 3600;
const FORBIDDEN_KEYS = new Set([
  "accesskey",
  "apikey",
  "authorizationheader",
  "body",
  "cookie",
  "credential",
  "password",
  "privatekey",
  "secret",
  "sessiontoken",
  "token",
]);
const SECRET_VALUE =
  /(?:basic\s+[a-z0-9+/=]+|bearer\s+[a-z0-9._~-]+|sk-[a-z0-9_-]{8,}|aiza[a-z0-9_-]{8,}|akia[a-z0-9]{16}|gh[pousr]_[a-z0-9]{8,}|-----BEGIN [A-Z ]+PRIVATE KEY-----|(?:api[_-]?key|access[_-]?key|client[_-]?secret|password|secret|token)\s*[:=])/i;

export class HumanDecisionWorkflowError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "HumanDecisionWorkflowError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new HumanDecisionWorkflowError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactKeys(value, allowed, field, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  const keys = Object.keys(value);
  if (
    keys.some((key) => !allowed.includes(key)) ||
    required.some((key) => !keys.includes(key))
  ) {
    fail("INVALID_INPUT", `${field} has an invalid shape.`);
  }
}

function nonEmpty(value, field, max = 256) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > max
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function identifier(value, expression, field) {
  nonEmpty(value, field, 128);
  if (!expression.test(value)) fail("INVALID_INPUT", `${field} is invalid.`);
}

function reference(value, field) {
  nonEmpty(value, field, 1024);
  if (!REFERENCE.test(value)) {
    fail("P3_REQUIRED", `${field} is not a P1 Synthetic reference.`);
  }
}

function version(value, field) {
  nonEmpty(value, field, 128);
  if (!VERSION.test(value)) fail("INVALID_INPUT", `${field} is invalid.`);
}

function canonicalInstant(value, field) {
  if (
    typeof value !== "string" ||
    !INSTANT.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${field} must be a canonical UTC instant.`);
  }
  return value;
}

function positiveInteger(value, field, { allowZero = false } = {}) {
  if (
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1)
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function validateUnicode(value) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail("INVALID_JSON", "RFC 8785 rejects unpaired surrogates.");
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      fail("INVALID_JSON", "RFC 8785 rejects unpaired surrogates.");
    }
  }
}

function canonicalize(value, ancestors) {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    validateUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("INVALID_JSON", "RFC 8785 accepts only finite numbers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) fail("INVALID_JSON", "JSON cannot be cyclic.");
    const next = new Set(ancestors).add(value);
    const items = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        fail("INVALID_JSON", "Sparse arrays are not JSON.");
      }
      items.push(canonicalize(value[index], next));
    }
    return `[${items.join(",")}]`;
  }
  if (value && typeof value === "object") {
    if (
      Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null
    ) {
      fail("INVALID_JSON", "Only plain JSON objects are supported.");
    }
    if (ancestors.has(value)) fail("INVALID_JSON", "JSON cannot be cyclic.");
    const next = new Set(ancestors).add(value);
    return `{${Object.keys(value)
      .sort()
      .map((key) => {
        validateUnicode(key);
        return `${JSON.stringify(key)}:${canonicalize(value[key], next)}`;
      })
      .join(",")}}`;
  }
  fail("INVALID_JSON", "Value is not JSON.");
}

export function canonicalizeHumanDecisionJson(value) {
  return canonicalize(value, new Set());
}

export function humanDecisionSha256(value) {
  const input =
    typeof value === "string"
      ? value
      : canonicalizeHumanDecisionJson(value);
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}

function uuidV7() {
  const bytes = randomBytes(16);
  let milliseconds = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(milliseconds & 0xffn);
    milliseconds >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

function generatedId(prefix, expression, idFactory, field) {
  const value = `${prefix}${idFactory()}`;
  identifier(value, expression, field);
  return value;
}

function assertNoSecretsOrNetwork(value, field = "candidate") {
  if (typeof value === "string") {
    if (/https?:\/\//i.test(value) || SECRET_VALUE.test(value)) {
      fail(
        "SYNTHETIC_BOUNDARY_VIOLATION",
        `${field} contains a network or credential value.`,
      );
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      assertNoSecretsOrNetwork(item, `${field}[${index}]`),
    );
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      const normalized = key.toLowerCase().replaceAll(/[_-]/g, "");
      if (FORBIDDEN_KEYS.has(normalized)) {
        fail(
          "SYNTHETIC_BOUNDARY_VIOLATION",
          `${field}.${key} is forbidden.`,
        );
      }
      assertNoSecretsOrNetwork(nested, `${field}.${key}`);
    }
  }
}

export function assertSyntheticHumanDecisionPayload(value) {
  assertNoSecretsOrNetwork(value);
  canonicalizeHumanDecisionJson(value);
}

function validateBinding(value, field) {
  exactKeys(value, ["ref", "version", "sha256"], field);
  reference(value.ref, `${field}.ref`);
  version(value.version, `${field}.version`);
  if (!SHA256.test(value.sha256 ?? "")) {
    fail("INVALID_INPUT", `${field}.sha256 is invalid.`);
  }
}

function validateCandidate(candidate, workflow) {
  exactKeys(
    candidate,
    [
      "operationId",
      "recipients",
      "attachments",
      "rules",
      "fields",
      "model",
      "skill",
      "knowledge",
    ],
    "candidate",
  );
  if (candidate.operationId !== "SYNTHETIC_PREVIEW_EFFECT") {
    fail(
      "P3_REQUIRED",
      "P1 C15 accepts only SYNTHETIC_PREVIEW_EFFECT.",
    );
  }
  for (const field of ["recipients", "attachments", "rules", "knowledge"]) {
    if (!Array.isArray(candidate[field])) {
      fail("INVALID_INPUT", `candidate.${field} must be an array.`);
    }
  }
  if (
    candidate.recipients.length < 1 ||
    candidate.recipients.length > 10 ||
    candidate.attachments.length > 10 ||
    candidate.rules.length < 1 ||
    candidate.rules.length > 20 ||
    candidate.knowledge.length < 1 ||
    candidate.knowledge.length > 20
  ) {
    fail("INVALID_INPUT", "Candidate collection size is invalid.");
  }
  candidate.recipients.forEach((item, index) => {
    exactKeys(item, ["recipientRef", "role"], `recipients[${index}]`);
    reference(item.recipientRef, `recipients[${index}].recipientRef`);
    nonEmpty(item.role, `recipients[${index}].role`, 64);
  });
  candidate.attachments.forEach((item, index) => {
    exactKeys(item, ["artifactRef", "sha256"], `attachments[${index}]`);
    reference(item.artifactRef, `attachments[${index}].artifactRef`);
    if (!SHA256.test(item.sha256 ?? "")) {
      fail("INVALID_INPUT", `attachments[${index}].sha256 is invalid.`);
    }
  });
  candidate.rules.forEach((item, index) =>
    validateBinding(item, `rules[${index}]`),
  );
  validateBinding(candidate.model, "candidate.model");
  validateBinding(candidate.skill, "candidate.skill");
  candidate.knowledge.forEach((item, index) =>
    validateBinding(item, `knowledge[${index}]`),
  );
  if (
    !candidate.fields ||
    typeof candidate.fields !== "object" ||
    Array.isArray(candidate.fields)
  ) {
    fail("INVALID_INPUT", "candidate.fields must be an object.");
  }
  const fieldNames = Object.keys(candidate.fields).sort();
  if (
    fieldNames.length < 1 ||
    fieldNames.some((name) => !workflow.allowedFields.includes(name))
  ) {
    fail("INVALID_INPUT", "Candidate fields are not allowed.");
  }
  if (
    (Object.hasOwn(candidate.fields, "amount") &&
      (typeof candidate.fields.amount !== "number" ||
        !Number.isFinite(candidate.fields.amount))) ||
    (Object.hasOwn(candidate.fields, "subject") &&
      (typeof candidate.fields.subject !== "string" ||
        !candidate.fields.subject ||
        candidate.fields.subject.length > 256))
  ) {
    fail("INVALID_INPUT", "Candidate field value is invalid.");
  }
  const unique = (values) => new Set(values).size === values.length;
  if (
    !unique(candidate.recipients.map((item) => item.recipientRef)) ||
    !unique(candidate.attachments.map((item) => item.artifactRef)) ||
    !unique(candidate.rules.map((item) => item.ref)) ||
    !unique(candidate.knowledge.map((item) => item.ref))
  ) {
    fail("INVALID_INPUT", "Candidate references must be unique.");
  }
  const sorted = (values) => [...values].sort();
  for (const values of [
    candidate.recipients.map((item) => item.recipientRef),
    candidate.attachments.map((item) => item.artifactRef),
    candidate.rules.map((item) => item.ref),
    candidate.knowledge.map((item) => item.ref),
  ]) {
    if (canonicalizeHumanDecisionJson(values) !==
      canonicalizeHumanDecisionJson(sorted(values))) {
      fail("INVALID_INPUT", "Candidate references must be sorted.");
    }
  }
  const allowed = workflow.allowedBindings;
  const matches = (binding, values) =>
    values.some(
      (value) =>
        canonicalizeHumanDecisionJson(value) ===
        canonicalizeHumanDecisionJson(binding),
    );
  if (
    candidate.recipients.some(
      (item) => !allowed.recipientRefs.includes(item.recipientRef),
    ) ||
    candidate.attachments.some(
      (item) =>
        !allowed.attachments.some(
          (value) =>
            value.artifactRef === item.artifactRef &&
            value.sha256 === item.sha256,
        ),
    ) ||
    candidate.rules.some((item) => !matches(item, allowed.rules)) ||
    !matches(candidate.model, allowed.models) ||
    !matches(candidate.skill, allowed.skills) ||
    candidate.knowledge.some(
      (item) => !matches(item, allowed.knowledge),
    )
  ) {
    fail("ARTIFACT_BINDING_INVALID", "Candidate binding is not frozen.");
  }
  assertNoSecretsOrNetwork(candidate);
  canonicalizeHumanDecisionJson(candidate);
}

function validateCatalogDocument(document) {
  exactKeys(
    document,
    ["schemaVersion", "scope", "workflows"],
    "Synthetic workflow catalog",
  );
  if (
    document.schemaVersion !== "c15-synthetic-workflow-catalog.v1" ||
    document.scope !== "P1_SYNTHETIC_ONLY" ||
    !Array.isArray(document.workflows) ||
    document.workflows.length !== 3
  ) {
    fail("INVALID_CATALOG", "C15 Synthetic catalog shape is invalid.");
  }
}

export function createSyntheticHumanDecisionCatalog(document) {
  validateCatalogDocument(document);
  const workflows = new Map();
  const tenantIds = new Set();
  for (const [index, raw] of document.workflows.entries()) {
    exactKeys(
      raw,
      [
        "tenantId",
        "tenantKind",
        "workflowRef",
        "version",
        "resourcePrefix",
        "decisionTtlSeconds",
        "allowedFields",
        "baseline",
        "allowedBindings",
      ],
      `workflows[${index}]`,
    );
    identifier(raw.tenantId, SYNTHETIC_TENANT_ID, "tenantId");
    if (raw.tenantKind !== "SYNTHETIC") {
      fail("INVALID_CATALOG", "C15 catalog must be Synthetic.");
    }
    reference(raw.workflowRef, "workflowRef");
    version(raw.version, "workflow.version");
    nonEmpty(raw.resourcePrefix, "resourcePrefix", 128);
    positiveInteger(raw.decisionTtlSeconds, "decisionTtlSeconds");
    if (
      raw.decisionTtlSeconds > 86400 ||
      !Array.isArray(raw.allowedFields) ||
      raw.allowedFields.length < 1 ||
      raw.allowedFields.some(
        (field) =>
          typeof field !== "string" ||
          !["amount", "subject"].includes(field),
      ) ||
      new Set(raw.allowedFields).size !== raw.allowedFields.length
    ) {
      fail("INVALID_CATALOG", "C15 catalog policy is invalid.");
    }
    exactKeys(
      raw.allowedBindings,
      [
        "recipientRefs",
        "attachments",
        "rules",
        "models",
        "skills",
        "knowledge",
      ],
      "allowedBindings",
    );
    if (
      !Array.isArray(raw.allowedBindings.recipientRefs) ||
      !Array.isArray(raw.allowedBindings.attachments) ||
      !Array.isArray(raw.allowedBindings.rules) ||
      !Array.isArray(raw.allowedBindings.models) ||
      !Array.isArray(raw.allowedBindings.skills) ||
      !Array.isArray(raw.allowedBindings.knowledge)
    ) {
      fail("INVALID_CATALOG", "C15 allowed bindings are invalid.");
    }
    const workflow = clone(raw);
    validateCandidate(workflow.baseline, workflow);
    const key = `${workflow.tenantId}\u0000${workflow.workflowRef}`;
    if (workflows.has(key) || tenantIds.has(workflow.tenantId)) {
      fail("INVALID_CATALOG", "C15 catalog duplicates a Tenant workflow.");
    }
    workflow.catalogBindingSha256 = humanDecisionSha256(raw);
    workflows.set(key, deepFreeze(workflow));
    tenantIds.add(workflow.tenantId);
  }
  return Object.freeze({
    resolve(tenantId, workflowRef) {
      identifier(tenantId, SYNTHETIC_TENANT_ID, "tenantId");
      reference(workflowRef, "workflowRef");
      const value = workflows.get(`${tenantId}\u0000${workflowRef}`);
      if (!value) fail("WORKFLOW_NOT_FOUND", "Synthetic workflow was not found.");
      return value;
    },
    assertCurrent(artifact) {
      const value = workflows.get(
        `${artifact.tenantId}\u0000${artifact.workflowRef}`,
      );
      if (
        !value ||
        value.version !== artifact.workflowVersion ||
        value.catalogBindingSha256 !== artifact.bindingSha256
      ) {
        fail(
          "ARTIFACT_BINDING_CHANGED",
          "A frozen workflow binding changed after the decision.",
        );
      }
      validateCandidate(artifact.candidate, value);
      return value;
    },
    tenantIds: Object.freeze([...tenantIds].sort()),
  });
}

function diffValues(before, after, path = "$") {
  const leftValue = before === undefined ? null : before;
  const rightValue = after === undefined ? null : after;
  if (
    canonicalizeHumanDecisionJson(leftValue) ===
    canonicalizeHumanDecisionJson(rightValue)
  ) {
    return [];
  }
  if (
    before &&
    after &&
    typeof before === "object" &&
    typeof after === "object" &&
    !Array.isArray(before) &&
    !Array.isArray(after)
  ) {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])]
      .sort();
    return keys.flatMap((key) =>
      diffValues(before[key], after[key], `${path}.${key}`),
    );
  }
  return [
    {
      path,
      beforeSha256: humanDecisionSha256(leftValue),
      afterSha256: humanDecisionSha256(rightValue),
    },
  ];
}

function artifactDisplay(workflow, candidate) {
  const differences = diffValues(workflow.baseline, candidate);
  const sources = [
    {
      kind: "WORKFLOW",
      ref: workflow.workflowRef,
      version: workflow.version,
      sha256: workflow.catalogBindingSha256,
    },
    ...candidate.rules.map((item) => ({ kind: "RULE", ...clone(item) })),
    ...candidate.attachments.map((item) => ({
      kind: "ATTACHMENT",
      ref: item.artifactRef,
      version: "content-addressed",
      sha256: item.sha256,
    })),
    { kind: "MODEL", ...clone(candidate.model) },
    { kind: "SKILL", ...clone(candidate.skill) },
    ...candidate.knowledge.map((item) => ({
      kind: "KNOWLEDGE",
      ...clone(item),
    })),
  ].sort((left, right) =>
    compareStrings(
      `${left.kind}\u0000${left.ref}`,
      `${right.kind}\u0000${right.ref}`,
    ),
  );
  const changedPaths = differences.map((item) => item.path);
  const risks = [];
  const addRisk = (code, severity) => risks.push({ code, severity });
  if (changedPaths.some((path) => path.startsWith("$.recipients"))) {
    addRisk("RECIPIENT_CHANGED", "HIGH");
  }
  if (candidate.attachments.length > 0) {
    addRisk("ATTACHMENT_PRESENT", "HIGH");
  }
  if (changedPaths.some((path) => path.startsWith("$.fields"))) {
    addRisk("APPROVED_FIELD_CHANGED", "MEDIUM");
  }
  for (const [path, code] of [
    ["$.rules", "RULE_BINDING_CHANGED"],
    ["$.model", "MODEL_BINDING_CHANGED"],
    ["$.skill", "SKILL_BINDING_CHANGED"],
    ["$.knowledge", "KNOWLEDGE_BINDING_CHANGED"],
  ]) {
    if (changedPaths.some((value) => value.startsWith(path))) {
      addRisk(code, "HIGH");
    }
  }
  if (risks.length === 0) addRisk("NO_BASELINE_DIFFERENCE", "LOW");
  return deepFreeze({
    differences,
    sources,
    risks: risks.sort((left, right) =>
      compareStrings(left.code, right.code),
    ),
  });
}

function validateServerContext(context) {
  exactKeys(
    context,
    [
      "synthetic",
      "routeTrustSource",
      "tenantId",
      "workloadTrustSource",
      "workloadActorPrincipalId",
    ],
    "serverContext",
  );
  if (
    context.synthetic !== true ||
    context.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR" ||
    context.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT"
  ) {
    fail("UNTRUSTED_ROUTE", "C15 server route is not trusted.");
  }
  identifier(context.tenantId, SYNTHETIC_TENANT_ID, "tenantId");
  identifier(
    context.workloadActorPrincipalId,
    PRINCIPAL_ID,
    "workloadActorPrincipalId",
  );
}

function validateEnvelope(request, fields) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "idempotencyKey",
      "correlationId",
      ...fields,
    ],
    "request",
  );
  nonEmpty(request.sessionToken, "sessionToken", 4096);
  identifier(request.delegationId, DELEGATION_ID, "delegationId");
  nonEmpty(request.idempotencyKey, "idempotencyKey", 128);
  nonEmpty(request.correlationId, "correlationId", 128);
}

function identityBinding(identity) {
  const leaf = identity.delegationChain[identity.delegationChain.length - 1];
  return deepFreeze({
    humanPrincipalId: identity.humanSubject.principalId,
    humanLifecycleVersion: identity.humanSubject.lifecycleVersion,
    humanSecurityEpoch: identity.humanSubject.securityEpoch,
    workloadActorPrincipalId: identity.workloadActor.principalId,
    workloadActorLifecycleVersion:
      identity.workloadActor.lifecycleVersion,
    workloadActorSecurityEpoch: identity.workloadActor.securityEpoch,
    leafDelegationId: leaf.delegationId,
    delegationChainSha256: humanDecisionSha256(identity.delegationChain),
    purposeRef: identity.purposeRef,
  });
}

function validateIdentity(identity, context, request) {
  const leaf =
    Array.isArray(identity?.delegationChain) &&
    identity.delegationChain.length > 0
      ? identity.delegationChain[identity.delegationChain.length - 1]
      : null;
  if (
    identity?.tenantId !== context.tenantId ||
    identity?.tenantKind !== "SYNTHETIC" ||
    identity?.trustSource !==
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT" ||
    identity?.humanSubject?.principalType !== "HUMAN" ||
    identity?.workloadActor?.principalId !==
      context.workloadActorPrincipalId ||
    !["AGENT", "SERVICE"].includes(identity?.workloadActor?.principalType) ||
    !Number.isSafeInteger(identity?.humanSubject?.lifecycleVersion) ||
    identity.humanSubject.lifecycleVersion < 1 ||
    !Number.isSafeInteger(identity?.humanSubject?.securityEpoch) ||
    identity.humanSubject.securityEpoch < 1 ||
    !Number.isSafeInteger(identity?.workloadActor?.lifecycleVersion) ||
    identity.workloadActor.lifecycleVersion < 1 ||
    !Number.isSafeInteger(identity?.workloadActor?.securityEpoch) ||
    identity.workloadActor.securityEpoch < 1 ||
    leaf?.delegationId !== request.delegationId ||
    leaf?.delegatePrincipalId !== context.workloadActorPrincipalId
  ) {
    fail("ACTION_IDENTITY_INVALID", "C05 action identity is invalid.");
  }
  identifier(identity.humanSubject.principalId, PRINCIPAL_ID, "humanPrincipal");
  return identityBinding(identity);
}

function sameBinding(left, right) {
  return (
    canonicalizeHumanDecisionJson(left) ===
    canonicalizeHumanDecisionJson(right)
  );
}

function sameAuthority(left, right) {
  return (
    left?.humanPrincipalId === right?.humanPrincipalId &&
    left?.humanLifecycleVersion === right?.humanLifecycleVersion &&
    left?.humanSecurityEpoch === right?.humanSecurityEpoch &&
    left?.workloadActorPrincipalId ===
      right?.workloadActorPrincipalId &&
    left?.workloadActorLifecycleVersion ===
      right?.workloadActorLifecycleVersion &&
    left?.workloadActorSecurityEpoch ===
      right?.workloadActorSecurityEpoch
  );
}

function validateAuthorization(value, binding, context, descriptor) {
  exactKeys(
    value,
    [
      "trustSource",
      "operationId",
      "decisionId",
      "evidenceRef",
      "policyVersion",
      "tenantId",
      "surface",
      "resourceId",
      "humanPrincipalId",
      "humanSecurityEpoch",
      "workloadActorPrincipalId",
      "workloadActorSecurityEpoch",
      "leafDelegationId",
      "delegationChainSha256",
      "purposeRef",
    ],
    "authorization evidence",
  );
  if (
    value?.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    value?.operationId !== descriptor.operationId ||
    value?.tenantId !== context.tenantId ||
    value?.surface !== descriptor.surface ||
    value?.resourceId !== descriptor.resourceId ||
    value?.humanPrincipalId !== binding.humanPrincipalId ||
    value?.humanSecurityEpoch !== binding.humanSecurityEpoch ||
    value?.workloadActorPrincipalId !==
      binding.workloadActorPrincipalId ||
    value?.workloadActorSecurityEpoch !==
      binding.workloadActorSecurityEpoch ||
    value?.leafDelegationId !== binding.leafDelegationId ||
    value?.delegationChainSha256 !== binding.delegationChainSha256 ||
    value?.purposeRef !== binding.purposeRef ||
    typeof value?.decisionId !== "string" ||
    typeof value?.evidenceRef !== "string" ||
    typeof value?.policyVersion !== "string"
  ) {
    fail(
      "AUTHORIZATION_BINDING_INVALID",
      "C06 decision is not bound to the C15 action.",
    );
  }
  return deepFreeze({
    trustSource: value.trustSource,
    operationId: value.operationId,
    decisionId: value.decisionId,
    evidenceRef: value.evidenceRef,
    policyVersion: value.policyVersion,
    tenantId: value.tenantId,
    surface: value.surface,
    resourceId: value.resourceId,
    humanPrincipalId: value.humanPrincipalId,
    humanSecurityEpoch: value.humanSecurityEpoch,
    workloadActorPrincipalId: value.workloadActorPrincipalId,
    workloadActorSecurityEpoch: value.workloadActorSecurityEpoch,
    leafDelegationId: value.leafDelegationId,
    delegationChainSha256: value.delegationChainSha256,
    purposeRef: value.purposeRef,
  });
}

function validateTenant(tenant, context) {
  if (
    tenant?.tenantId !== context.tenantId ||
    tenant?.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(tenant?.lifecycleVersion) ||
    tenant.lifecycleVersion < 1
  ) {
    fail("TENANT_NOT_ACTIVE", "C03 Tenant admission failed.");
  }
}

function tenantScope(tenant, authorization, correlationId) {
  return deepFreeze({
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: tenant.tenantId,
    tenantKind: tenant.tenantKind,
    lifecycleVersion: tenant.lifecycleVersion,
    correlationId,
    decisionId: authorization.decisionId,
    evidenceRef: authorization.evidenceRef,
    policyVersion: authorization.policyVersion,
  });
}

async function authorizeAction(
  dependencies,
  context,
  request,
  descriptor,
) {
  const pre = validateIdentity(
    await dependencies.stablePrincipalRegistry.resolveActionIdentity(
      context,
      request,
    ),
    context,
    request,
  );
  const authorization = await dependencies.authorizer.enforce(
    context,
    {
      sessionToken: request.sessionToken,
      delegationId: request.delegationId,
      correlationId: request.correlationId,
      resourceId: descriptor.resourceId,
    },
    {
      operationId: descriptor.operationId,
      surface: descriptor.surface,
      path: "human-decision",
      mode: "WRITE",
    },
  );
  const boundAuthorization = validateAuthorization(
    authorization,
    pre,
    context,
    descriptor,
  );
  const post = validateIdentity(
    await dependencies.stablePrincipalRegistry.resolveActionIdentity(
      context,
      request,
    ),
    context,
    request,
  );
  if (!sameBinding(pre, post)) {
    fail(
      "ACTION_IDENTITY_CHANGED",
      "C05 identity changed during the C15 action.",
    );
  }
  const tenant =
    await dependencies.tenantRegistry.admitNewRequest(context);
  validateTenant(tenant, context);
  return {
    identityBinding: pre,
    authorization: boundAuthorization,
    tenant,
    scope: tenantScope(
      tenant,
      boundAuthorization,
      request.correlationId,
    ),
  };
}

function auditMetadata({
  intentId,
  tenantId,
  eventType,
  subjectId,
  subjectSha256,
  artifactId,
  artifactSha256,
  decisionId = null,
  decisionSha256 = null,
  effectId = null,
  effectKey = null,
  identityBinding: identity,
  authorization,
  correlationId,
  occurredAt,
}) {
  const value = {
    schemaVersion: "c15-audit-intent.v1",
    intentId,
    tenantId,
    tenantKind: "SYNTHETIC",
    eventType,
    subjectId,
    subjectSha256,
    artifactId,
    artifactSha256,
    decisionId,
    decisionSha256,
    effectId,
    effectKey,
    humanPrincipalId: identity.humanPrincipalId,
    workloadActorPrincipalId: identity.workloadActorPrincipalId,
    leafDelegationId: identity.leafDelegationId,
    authorizationDecisionId: authorization.decisionId,
    authorizationEvidenceRef: authorization.evidenceRef,
    authorizationPolicyVersion: authorization.policyVersion,
    correlationId,
    occurredAt,
  };
  assertAuditIntentMetadataOnly(value);
  return deepFreeze(value);
}

export function assertAuditIntentMetadataOnly(value) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "intentId",
      "tenantId",
      "tenantKind",
      "eventType",
      "subjectId",
      "subjectSha256",
      "artifactId",
      "artifactSha256",
      "decisionId",
      "decisionSha256",
      "effectId",
      "effectKey",
      "humanPrincipalId",
      "workloadActorPrincipalId",
      "leafDelegationId",
      "authorizationDecisionId",
      "authorizationEvidenceRef",
      "authorizationPolicyVersion",
      "correlationId",
      "occurredAt",
    ],
    "audit intent",
  );
  if (
    value.schemaVersion !== "c15-audit-intent.v1" ||
    value.tenantKind !== "SYNTHETIC" ||
    !CODE.test(value.eventType ?? "") ||
    !SHA256.test(value.subjectSha256 ?? "") ||
    !SHA256.test(value.artifactSha256 ?? "")
  ) {
    fail("AUDIT_INTENT_INVALID", "C15 audit intent is invalid.");
  }
  assertNoSecretsOrNetwork(value, "auditIntent");
  canonicalizeHumanDecisionJson(value);
}

function requestHash(operation, value) {
  return humanDecisionSha256({ operation, ...value });
}

function viewArtifact(record, replayed = false) {
  return deepFreeze({ ...clone(record), replayed });
}

function viewDecision(record, replayed = false) {
  return deepFreeze({ ...clone(record), replayed });
}

function viewEffect(record, replayed = false) {
  return deepFreeze({ ...clone(record), replayed });
}

function effectReadbackSha256(tenantId, effectKey, artifactSha256) {
  return humanDecisionSha256({
    schemaVersion: "c15-synthetic-readback.v1",
    tenantId,
    effectKey,
    artifactSha256,
    state: "APPLIED",
  });
}

function withoutField(value, field) {
  const body = clone(value);
  delete body[field];
  return body;
}

function validateMemoryCommand(command, operation) {
  if (
    command?.operation !== operation ||
    command?.tenantId !== command?.auditIntent?.tenantId ||
    typeof command?.idempotencyKey !== "string" ||
    !command.idempotencyKey ||
    command.idempotencyKey.length > 128 ||
    !SHA256.test(command?.requestHash ?? "")
  ) {
    fail("INVALID_INPUT", "C15 Store command metadata is invalid.");
  }
  assertAuditIntentMetadataOnly(command.auditIntent);
}

function validateMemoryArtifactCommand(command) {
  validateMemoryCommand(command, "PREPARE");
  const value = command.artifact;
  if (
    value?.tenantId !== command.tenantId ||
    value?.tenantKind !== "SYNTHETIC" ||
    value?.schemaVersion !== "c15-draft-artifact.v1" ||
    value?.artifactKind !== "SYNTHETIC_DRAFT" ||
    value?.candidate?.operationId !== "SYNTHETIC_PREVIEW_EFFECT" ||
    humanDecisionSha256(withoutField(value, "artifactSha256")) !==
      value?.artifactSha256
  ) {
    fail("INTEGRITY_VIOLATION", "C15 Store rejected DraftArtifact.");
  }
  assertSyntheticHumanDecisionPayload(value);
}

function validateMemoryDecisionCommand(command) {
  validateMemoryCommand(command, "DECIDE");
  const value = command.decision;
  if (
    value?.tenantId !== command.tenantId ||
    value?.tenantKind !== "SYNTHETIC" ||
    value?.schemaVersion !== "c15-synthetic-test-decision.v1" ||
    value?.decisionType !== "SYNTHETIC_TEST_DECISION" ||
    value?.outcome !== "APPROVE" ||
    value?.status !== "ACTIVE" ||
    value?.productionReusable !== false ||
    value?.externalEffectCount !== 0 ||
    humanDecisionSha256(withoutField(value, "decisionSha256")) !==
      value?.decisionSha256
  ) {
    fail(
      "INTEGRITY_VIOLATION",
      "C15 Store rejected Synthetic Test Decision.",
    );
  }
  assertSyntheticHumanDecisionPayload(value);
}

function validateMemoryEffectCommand(command) {
  validateMemoryCommand(command, "EXECUTE");
  const value = command.effect;
  if (
    value?.tenantId !== command.tenantId ||
    value?.tenantKind !== "SYNTHETIC" ||
    value?.schemaVersion !== "c15-synthetic-effect.v1" ||
    value?.operationId !== "SYNTHETIC_PREVIEW_EFFECT" ||
    value?.status !== "QUEUED" ||
    value?.externalEffectCount !== 0 ||
    humanDecisionSha256(withoutField(value, "effectSha256")) !==
      value?.effectSha256
  ) {
    fail("INTEGRITY_VIOLATION", "C15 Store rejected Synthetic effect.");
  }
  assertSyntheticHumanDecisionPayload(value);
}

export function assertC15EffectCompletion(effect, input) {
  assertAuditIntentMetadataOnly(input.auditIntent);
  if (
    !["SUCCEEDED", "COMPENSATED", "COMPENSATION_FAILED"].includes(
      input.terminalStatus,
    ) ||
    input.auditIntent.tenantId !== effect.tenantId ||
    input.auditIntent.eventType !==
      `SYNTHETIC_EFFECT_${input.terminalStatus}` ||
    input.auditIntent.subjectId !== effect.effectId ||
    input.auditIntent.subjectSha256 !== effect.effectSha256 ||
    input.auditIntent.artifactId !== effect.artifactId ||
    input.auditIntent.artifactSha256 !== effect.artifactSha256 ||
    input.auditIntent.decisionId !== effect.decisionId ||
    input.auditIntent.decisionSha256 !== effect.decisionSha256 ||
    input.auditIntent.effectId !== effect.effectId ||
    input.auditIntent.effectKey !== effect.effectKey ||
    input.auditIntent.humanPrincipalId !==
      effect.executionIdentity.humanPrincipalId ||
    input.auditIntent.workloadActorPrincipalId !==
      effect.executionIdentity.workloadActorPrincipalId ||
    input.auditIntent.leafDelegationId !==
      effect.executionIdentity.leafDelegationId ||
    input.auditIntent.authorizationDecisionId !==
      effect.executionAuthorization.decisionId
  ) {
    fail(
      "AUDIT_INTENT_INVALID",
      "C15 effect outcome Audit Intent is not bound.",
    );
  }
  const exactReceipt = (receipt, fields) =>
    receipt &&
    typeof receipt === "object" &&
    !Array.isArray(receipt) &&
    Object.keys(receipt).length === fields.length &&
    fields.every((field) => Object.hasOwn(receipt, field));
  const commit = input.commitReceipt;
  if (
    !exactReceipt(commit, [
      "schemaVersion",
      "tenantId",
      "effectKey",
      "operationId",
      "committed",
      "externalEffectCount",
    ]) ||
    commit.schemaVersion !== "c15-synthetic-commit-receipt.v1" ||
    commit.tenantId !== effect.tenantId ||
    commit.effectKey !== effect.effectKey ||
    commit.operationId !== effect.operationId ||
    commit.committed !== true ||
    commit.externalEffectCount !== 0
  ) {
    fail("INTEGRITY_VIOLATION", "C15 commitReceipt is invalid.");
  }
  assertSyntheticHumanDecisionPayload(commit);
  const readback = input.readbackReceipt;
  if (
    !exactReceipt(readback, [
      "schemaVersion",
      "tenantId",
      "effectKey",
      "observedState",
      "readbackSha256",
      "externalEffectCount",
    ]) ||
    readback.schemaVersion !== "c15-synthetic-readback-receipt.v1" ||
    readback.tenantId !== effect.tenantId ||
    readback.effectKey !== effect.effectKey ||
    !SHA256.test(readback.readbackSha256 ?? "") ||
    readback.externalEffectCount !== 0
  ) {
    fail("INTEGRITY_VIOLATION", "C15 readbackReceipt is invalid.");
  }
  assertSyntheticHumanDecisionPayload(readback);
  const observedReadbackSha256 = humanDecisionSha256({
    schemaVersion: "c15-synthetic-readback.v1",
    tenantId: effect.tenantId,
    effectKey: effect.effectKey,
    artifactSha256: effect.artifactSha256,
    state: readback.observedState,
  });
  if (readback.readbackSha256 !== observedReadbackSha256) {
    fail(
      "READBACK_STATE_INVALID",
      "C15 readback hash does not bind the observed state.",
    );
  }
  const matches =
    readback.readbackSha256 === effect.expectedReadbackSha256;
  const succeeded = input.terminalStatus === "SUCCEEDED";
  const observedStates = succeeded
    ? ["APPLIED"]
    : input.terminalStatus === "COMPENSATED"
      ? ["COMPENSATED"]
      : ["MISMATCH"];
  if (
    !observedStates.includes(readback.observedState) ||
    matches !== succeeded
  ) {
    fail(
      "READBACK_STATE_INVALID",
      "C15 terminal state does not match readback.",
    );
  }
  if (succeeded) {
    if (input.compensationReceipt !== null) {
      fail(
        "INTEGRITY_VIOLATION",
        "Successful C15 effect cannot have compensation.",
      );
    }
    return;
  }
  const receipt = input.compensationReceipt;
  if (input.terminalStatus === "COMPENSATED") {
    if (
      !exactReceipt(receipt, [
        "schemaVersion",
        "tenantId",
        "effectKey",
        "compensated",
        "externalEffectCount",
      ]) ||
      receipt.schemaVersion !==
        "c15-synthetic-compensation-receipt.v1" ||
      receipt.tenantId !== effect.tenantId ||
      receipt.effectKey !== effect.effectKey ||
      receipt.compensated !== true ||
      receipt.externalEffectCount !== 0
    ) {
      fail(
        "INTEGRITY_VIOLATION",
        "C15 compensation receipt is invalid.",
      );
    }
  } else if (
    !exactReceipt(receipt, [
      "schemaVersion",
      "tenantId",
      "effectKey",
      "errorCode",
      "externalEffectCount",
    ]) ||
    receipt.schemaVersion !== "c15-compensation-failure.v1" ||
    receipt.tenantId !== effect.tenantId ||
    receipt.effectKey !== effect.effectKey ||
    !CODE.test(receipt.errorCode ?? "") ||
    receipt.externalEffectCount !== 0
  ) {
    fail(
      "INTEGRITY_VIOLATION",
      "C15 compensation failure receipt is invalid.",
    );
  }
  assertSyntheticHumanDecisionPayload(receipt);
}

function validateStoreScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope?.tenantKind !== "SYNTHETIC" ||
    !SYNTHETIC_TENANT_ID.test(scope?.tenantId ?? "") ||
    !Number.isSafeInteger(scope?.lifecycleVersion) ||
    scope.lifecycleVersion < 1 ||
    typeof scope?.correlationId !== "string" ||
    !scope.correlationId ||
    typeof scope?.decisionId !== "string" ||
    !scope.decisionId ||
    typeof scope?.evidenceRef !== "string" ||
    !scope.evidenceRef ||
    typeof scope?.policyVersion !== "string" ||
    !scope.policyVersion
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C15 requires a C07 Tenant scope.");
  }
  return scope;
}

function emptyMemoryState() {
  return {
    artifacts: new Map(),
    decisions: new Map(),
    withdrawals: new Map(),
    effects: new Map(),
    effectOutbox: new Map(),
    auditIntents: new Map(),
    auditOutbox: new Map(),
    receipts: new Map(),
  };
}

function memoryBody(tenantId, state) {
  const sorted = (map, key) =>
    [...map.values()]
      .map(clone)
      .sort((left, right) => compareStrings(left[key], right[key]));
  return {
    schemaVersion: "c15-memory-recovery.v1",
    tenantId,
    tenantKind: "SYNTHETIC",
    artifacts: sorted(state.artifacts, "artifactId"),
    decisions: sorted(state.decisions, "decisionId"),
    withdrawals: sorted(state.withdrawals, "decisionId"),
    effects: sorted(state.effects, "effectId"),
    effectOutbox: sorted(state.effectOutbox, "effectId"),
    auditIntents: sorted(state.auditIntents, "intentId"),
    auditOutbox: sorted(state.auditOutbox, "intentId"),
    receipts: sorted(state.receipts, "idempotencyKey"),
  };
}

export function createMemoryHumanDecisionStore({
  clock = () => new Date().toISOString(),
  recoveryBundles = [],
} = {}) {
  const states = new Map();
  const stateFor = (tenantId) => {
    if (!states.has(tenantId)) states.set(tenantId, emptyMemoryState());
    return states.get(tenantId);
  };
  for (const document of recoveryBundles) {
    exactKeys(
      document,
      [
        "schemaVersion",
        "tenantId",
        "tenantKind",
        "artifacts",
        "decisions",
        "withdrawals",
        "effects",
        "effectOutbox",
        "auditIntents",
        "auditOutbox",
        "receipts",
        "recoverySha256",
      ],
      "memory recovery",
    );
    const body = { ...clone(document) };
    delete body.recoverySha256;
    if (
      document.schemaVersion !== "c15-memory-recovery.v1" ||
      document.tenantKind !== "SYNTHETIC" ||
      !SYNTHETIC_TENANT_ID.test(document.tenantId ?? "") ||
      humanDecisionSha256(body) !== document.recoverySha256
    ) {
      fail("RECOVERY_TAMPERED", "C15 Memory recovery is invalid.");
    }
    const state = emptyMemoryState();
    for (const [field, key] of [
      ["artifacts", "artifactId"],
      ["decisions", "decisionId"],
      ["withdrawals", "decisionId"],
      ["effects", "effectId"],
      ["effectOutbox", "effectId"],
      ["auditIntents", "intentId"],
      ["auditOutbox", "intentId"],
      ["receipts", "idempotencyKey"],
    ]) {
      if (!Array.isArray(document[field])) {
        fail("RECOVERY_TAMPERED", "C15 recovery collection is invalid.");
      }
      for (const value of document[field]) {
        if (state[field].has(value[key])) {
          fail("RECOVERY_TAMPERED", "C15 recovery duplicates a record.");
        }
        state[field].set(value[key], clone(value));
      }
    }
    for (const decision of state.decisions.values()) {
      if (
        decision.status !== "ACTIVE" ||
        humanDecisionSha256(
          withoutField(decision, "decisionSha256"),
        ) !== decision.decisionSha256
      ) {
        fail("RECOVERY_TAMPERED", "C15 recovery changed a Decision.");
      }
    }
    for (const withdrawal of state.withdrawals.values()) {
      const decision = state.decisions.get(withdrawal.decisionId);
      if (
        withdrawal.tenantId !== document.tenantId ||
        withdrawal.tenantKind !== "SYNTHETIC" ||
        !decision ||
        withdrawal.decisionSha256 !== decision.decisionSha256
      ) {
        fail("RECOVERY_TAMPERED", "C15 recovery changed a Withdrawal.");
      }
    }
    states.set(document.tenantId, state);
  }

  function decisionView(state, decision, replayed = false) {
    const withdrawal = state.withdrawals.get(decision.decisionId);
    if (!withdrawal) return viewDecision(decision, replayed);
    return viewDecision(
      {
        ...clone(decision),
        status: "WITHDRAWN",
        withdrawnAt: withdrawal.withdrawnAt,
        withdrawalAuthorization: clone(
          withdrawal.withdrawalAuthorization,
        ),
      },
      replayed,
    );
  }

  function replay(state, command) {
    const receipt = state.receipts.get(command.idempotencyKey);
    if (!receipt) return null;
    if (
      receipt.operation !== command.operation ||
      receipt.requestHash !== command.requestHash
    ) {
      fail("IDEMPOTENCY_CONFLICT", "C15 idempotency key was reused.");
    }
    return clone(receipt.response);
  }

  function assertAuditAvailable(state, audit) {
    if (
      state.auditIntents.has(audit.intentId) ||
      state.auditOutbox.has(audit.intentId)
    ) {
      fail("ID_COLLISION", "C15 audit intent ID collided.");
    }
  }

  function prepareAudit(state, audit, now) {
    assertAuditAvailable(state, audit);
    const intent = {
      ...clone(audit),
      intentSha256: humanDecisionSha256(audit),
      createdAt: now,
    };
    return {
      intent,
      outbox: {
        tenantId: intent.tenantId,
        tenantKind: "SYNTHETIC",
        intentId: intent.intentId,
        status: "PENDING",
        attemptCount: 0,
        leaseVersion: 0,
        leasedBy: null,
        leaseUntil: null,
        leaseProofSha256: null,
        availableAt: now,
        publishedAt: null,
        lastErrorCode: null,
        c18CommandReceiptKey: null,
        c18EventId: null,
        c18EventHash: null,
        createdAt: now,
      },
    };
  }

  function addAudit(state, prepared) {
    state.auditIntents.set(prepared.intent.intentId, prepared.intent);
    state.auditOutbox.set(prepared.outbox.intentId, prepared.outbox);
  }

  function prepareReceipt(command, response, now) {
    return {
      tenantId: command.tenantId,
      tenantKind: "SYNTHETIC",
      idempotencyKey: command.idempotencyKey,
      operation: command.operation,
      requestHash: command.requestHash,
      response: clone(response),
      createdAt: now,
    };
  }

  function addReceipt(state, prepared) {
    state.receipts.set(prepared.idempotencyKey, prepared);
  }

  async function createArtifact(scope, command) {
    const trusted = validateStoreScope(scope);
    validateMemoryArtifactCommand(command);
    if (command.tenantId !== trusted.tenantId) {
      fail("TENANT_SCOPE_VIOLATION", "C15 command escaped Tenant scope.");
    }
    const state = stateFor(trusted.tenantId);
    const prior = replay(state, command);
    if (prior) return viewArtifact(prior, true);
    if (state.artifacts.has(command.artifact.artifactId)) {
      fail("ID_COLLISION", "C15 Artifact ID collided.");
    }
    const now = canonicalInstant(clock(), "clock");
    const audit = prepareAudit(state, command.auditIntent, now);
    const commandReceipt = prepareReceipt(
      command,
      command.artifact,
      now,
    );
    state.artifacts.set(command.artifact.artifactId, clone(command.artifact));
    addAudit(state, audit);
    addReceipt(state, commandReceipt);
    return viewArtifact(command.artifact);
  }

  async function getArtifact(scope, artifactId) {
    const trusted = validateStoreScope(scope);
    const value = stateFor(trusted.tenantId).artifacts.get(artifactId);
    return value ? viewArtifact(value) : null;
  }

  async function createDecision(scope, command) {
    const trusted = validateStoreScope(scope);
    validateMemoryDecisionCommand(command);
    if (command.tenantId !== trusted.tenantId) {
      fail("TENANT_SCOPE_VIOLATION", "C15 command escaped Tenant scope.");
    }
    const state = stateFor(trusted.tenantId);
    const prior = replay(state, command);
    if (prior) return viewDecision(prior, true);
    const artifact = state.artifacts.get(command.decision.artifactId);
    if (
      !artifact ||
      artifact.artifactSha256 !== command.decision.artifactSha256 ||
      state.decisions.has(command.decision.decisionId)
    ) {
      fail("INTEGRITY_VIOLATION", "C15 decision binding is invalid.");
    }
    const now = canonicalInstant(clock(), "clock");
    const audit = prepareAudit(state, command.auditIntent, now);
    const commandReceipt = prepareReceipt(
      command,
      command.decision,
      now,
    );
    state.decisions.set(command.decision.decisionId, clone(command.decision));
    addAudit(state, audit);
    addReceipt(state, commandReceipt);
    return decisionView(state, command.decision);
  }

  async function getDecision(scope, decisionId) {
    const trusted = validateStoreScope(scope);
    const state = stateFor(trusted.tenantId);
    const value = state.decisions.get(decisionId);
    return value ? decisionView(state, value) : null;
  }

  async function withdrawDecision(scope, command) {
    const trusted = validateStoreScope(scope);
    validateMemoryCommand(command, "WITHDRAW");
    if (command.tenantId !== trusted.tenantId) {
      fail("TENANT_SCOPE_VIOLATION", "C15 command escaped Tenant scope.");
    }
    const state = stateFor(trusted.tenantId);
    const prior = replay(state, command);
    if (prior) return viewDecision(prior, true);
    const current = state.decisions.get(command.decisionId);
    if (!current) fail("DECISION_NOT_FOUND", "C15 decision was not found.");
    if (
      command.decisionSha256 !== current.decisionSha256 ||
      command.auditIntent.decisionSha256 !== current.decisionSha256
    ) {
      fail("DECISION_TAMPERED", "C15 withdrawal decision hash changed.");
    }
    if (
      current.status !== "ACTIVE" ||
      state.withdrawals.has(current.decisionId)
    ) {
      fail("DECISION_NOT_ACTIVE", "C15 decision is not active.");
    }
    if (
      [...state.effects.values()].some(
        (effect) =>
          effect.decisionId === current.decisionId &&
          state.effectOutbox.get(effect.effectId)?.executionStartedAt != null,
      )
    ) {
      fail(
        "DECISION_ALREADY_EXECUTING",
        "C15 cannot withdraw a decision after execution started.",
      );
    }
    const withdrawal = {
      tenantId: trusted.tenantId,
      tenantKind: "SYNTHETIC",
      decisionId: current.decisionId,
      decisionSha256: current.decisionSha256,
      withdrawalAuthorization: clone(command.withdrawalAuthorization),
      createdByIdempotencyKey: command.idempotencyKey,
      auditIntentId: command.auditIntent.intentId,
      withdrawnAt: command.withdrawnAt,
    };
    const now = canonicalInstant(clock(), "clock");
    const audit = prepareAudit(state, command.auditIntent, now);
    const updated = viewDecision({
      ...clone(current),
      status: "WITHDRAWN",
      withdrawnAt: withdrawal.withdrawnAt,
      withdrawalAuthorization: clone(
        withdrawal.withdrawalAuthorization,
      ),
    });
    const commandReceipt = prepareReceipt(command, updated, now);
    state.withdrawals.set(current.decisionId, withdrawal);
    addAudit(state, audit);
    addReceipt(state, commandReceipt);
    return updated;
  }

  async function queueEffect(scope, command) {
    const trusted = validateStoreScope(scope);
    validateMemoryEffectCommand(command);
    if (command.tenantId !== trusted.tenantId) {
      fail("TENANT_SCOPE_VIOLATION", "C15 command escaped Tenant scope.");
    }
    const state = stateFor(trusted.tenantId);
    const prior = replay(state, command);
    if (prior) return viewEffect(prior, true);
    const decision = state.decisions.get(command.effect.decisionId);
    const artifact = state.artifacts.get(command.effect.artifactId);
    if (
      !decision ||
      decision.status !== "ACTIVE" ||
      state.withdrawals.has(decision.decisionId) ||
      decision.outcome !== "APPROVE" ||
      decision.decisionSha256 !== command.effect.decisionSha256 ||
      decision.artifactId !== command.effect.artifactId ||
      decision.artifactSha256 !== command.effect.artifactSha256 ||
      !artifact ||
      artifact.artifactSha256 !== command.effect.artifactSha256 ||
      !sameAuthority(
        decision.identityBinding,
        command.effect.executionIdentity,
      ) ||
      Date.parse(decision.expiresAt) <= Date.parse(clock())
    ) {
      fail("DECISION_NOT_ACTIVE", "C15 decision cannot authorize execution.");
    }
    if (
      [...state.effects.values()].some(
        (item) => item.effectKey === command.effect.effectKey,
      )
    ) {
      fail("EFFECT_KEY_CONFLICT", "C15 effect key already exists.");
    }
    if (
      state.effects.has(command.effect.effectId) ||
      state.effectOutbox.has(command.effect.effectId)
    ) {
      fail("ID_COLLISION", "C15 Effect ID collided.");
    }
    const now = canonicalInstant(clock(), "clock");
    const audit = prepareAudit(state, command.auditIntent, now);
    const commandReceipt = prepareReceipt(
      command,
      command.effect,
      now,
    );
    state.effects.set(command.effect.effectId, clone(command.effect));
    state.effectOutbox.set(command.effect.effectId, {
      tenantId: trusted.tenantId,
      tenantKind: "SYNTHETIC",
      effectId: command.effect.effectId,
      status: "PENDING",
      attemptCount: 0,
      leaseVersion: 0,
      leasedBy: null,
      leaseUntil: null,
      leaseProofSha256: null,
      executionStartedAt: null,
      availableAt: now,
      publishedAt: null,
      lastErrorCode: null,
      createdAt: now,
    });
    addAudit(state, audit);
    addReceipt(state, commandReceipt);
    return viewEffect(command.effect);
  }

  async function getEffect(scope, effectId) {
    const trusted = validateStoreScope(scope);
    const value = stateFor(trusted.tenantId).effects.get(effectId);
    return value ? viewEffect(value) : null;
  }

  function validateLease(input) {
    exactKeys(input, ["workerId", "limit", "leaseDurationSeconds"], "lease");
    nonEmpty(input.workerId, "workerId", 128);
    positiveInteger(input.limit, "limit");
    positiveInteger(input.leaseDurationSeconds, "leaseDurationSeconds");
    if (input.limit > 100 || input.leaseDurationSeconds > MAX_LEASE_SECONDS) {
      fail("INVALID_INPUT", "C15 lease is out of range.");
    }
  }

  function assertActiveEffectDecision(state, effect, now) {
    const decision = state.decisions.get(effect?.decisionId);
    if (
      !effect ||
      !decision ||
      decision.status !== "ACTIVE" ||
      decision.outcome !== "APPROVE" ||
      state.withdrawals.has(decision.decisionId) ||
      decision.decisionSha256 !== effect.decisionSha256 ||
      decision.artifactId !== effect.artifactId ||
      decision.artifactSha256 !== effect.artifactSha256 ||
      !sameAuthority(decision.identityBinding, effect.executionIdentity) ||
      Date.parse(decision.expiresAt) <= now
    ) {
      fail("DECISION_NOT_ACTIVE", "C15 decision cannot authorize execution.");
    }
  }

  function claim(map, trusted, input, key, assertCandidate) {
    validateLease(input);
    const now = Date.parse(canonicalInstant(clock(), "clock"));
    const candidates = [...map.values()]
      .filter(
        (item) =>
          item.tenantId === trusted.tenantId &&
          ((["PENDING", "FAILED"].includes(item.status) &&
            Date.parse(item.availableAt) <= now) ||
            (item.status === "PROCESSING" &&
              Date.parse(item.leaseUntil) <= now)),
      )
      .sort((left, right) =>
        compareStrings(
          `${left.createdAt}\u0000${left[key]}`,
          `${right.createdAt}\u0000${right[key]}`,
        ),
      )
      .slice(0, input.limit);
    for (const item of candidates) assertCandidate?.(item, now);
    return candidates.map((item) => {
      const leaseToken = randomBytes(32).toString("hex");
      Object.assign(item, {
        status: "PROCESSING",
        attemptCount: item.attemptCount + 1,
        leaseVersion: item.leaseVersion + 1,
        leasedBy: input.workerId,
        leaseUntil: new Date(
          now + input.leaseDurationSeconds * 1000,
        ).toISOString(),
        leaseProofSha256: humanDecisionSha256(leaseToken),
        lastErrorCode: null,
      });
      const claimed = clone(item);
      delete claimed.leaseProofSha256;
      claimed.leaseToken = leaseToken;
      return claimed;
    });
  }

  async function claimEffects(scope, input) {
    const trusted = validateStoreScope(scope);
    const state = stateFor(trusted.tenantId);
    return claim(
      state.effectOutbox,
      trusted,
      input,
      "effectId",
      (outbox, now) => {
        if (outbox.executionStartedAt == null) {
          assertActiveEffectDecision(
            state,
            state.effects.get(outbox.effectId),
            now,
          );
        }
      },
    ).map(
      (outbox) => ({
        ...outbox,
        effect: clone(state.effects.get(outbox.effectId)),
      }),
    );
  }

  function activeLease(item, input, now = Date.parse(clock())) {
    return (
      item?.status === "PROCESSING" &&
      item.leasedBy === input.workerId &&
      item.leaseVersion === input.leaseVersion &&
      item.leaseProofSha256 ===
        humanDecisionSha256(input.leaseToken) &&
      Date.parse(item.leaseUntil) > now
    );
  }

  function assertExecutable(state, trusted, input) {
    const outbox = state.effectOutbox.get(input.effectId);
    const effect = state.effects.get(input.effectId);
    const now = Date.parse(canonicalInstant(clock(), "clock"));
    if (!effect || !activeLease(outbox, input, now)) {
      fail("STALE_OUTBOX_LEASE", "C15 effect lease is stale.");
    }
    if (
      effect.tenantId !== trusted.tenantId ||
      effect.effectSha256 !== input.effectSha256
    ) {
      fail("INTEGRITY_VIOLATION", "C15 claimed effect binding changed.");
    }
    if (outbox.executionStartedAt == null) {
      assertActiveEffectDecision(state, effect, now);
    }
    return { effect, outbox, now };
  }

  async function assertEffectExecutable(scope, input) {
    const trusted = validateStoreScope(scope);
    exactKeys(
      input,
      [
        "effectId",
        "effectSha256",
        "workerId",
        "leaseVersion",
        "leaseToken",
      ],
      "effect execution authorization",
    );
    nonEmpty(input.effectId, "effectId", 128);
    if (!SHA256.test(input.effectSha256 ?? "")) {
      fail("INVALID_INPUT", "C15 Effect hash is invalid.");
    }
    nonEmpty(input.workerId, "workerId", 128);
    positiveInteger(input.leaseVersion, "leaseVersion");
    nonEmpty(input.leaseToken, "leaseToken", 128);
    const { outbox, now } = assertExecutable(
      stateFor(trusted.tenantId),
      trusted,
      input,
    );
    if (outbox.executionStartedAt == null) {
      outbox.executionStartedAt = new Date(now).toISOString();
    }
    return true;
  }

  async function completeEffect(scope, input) {
    const trusted = validateStoreScope(scope);
    exactKeys(
      input,
      [
        "effect",
        "effectId",
        "workerId",
        "leaseVersion",
        "leaseToken",
        "terminalStatus",
        "commitReceipt",
        "readbackReceipt",
        "compensationReceipt",
        "auditIntent",
      ],
      "effect completion",
    );
    const state = stateFor(trusted.tenantId);
    const outbox = state.effectOutbox.get(input.effectId);
    const effect = state.effects.get(input.effectId);
    if (!effect || !activeLease(outbox, input)) {
      fail("STALE_OUTBOX_LEASE", "C15 effect lease is stale.");
    }
    if (
      input.effect?.tenantId !== trusted.tenantId ||
      input.effect?.effectId !== input.effectId ||
      input.effect?.effectSha256 !== effect.effectSha256
    ) {
      fail("INTEGRITY_VIOLATION", "C15 claimed effect binding changed.");
    }
    if (outbox.executionStartedAt == null) {
      fail("STALE_EFFECT", "C15 effect execution has not started.");
    }
    if (
      !["SUCCEEDED", "COMPENSATED", "COMPENSATION_FAILED"].includes(
        input.terminalStatus,
      )
    ) {
      fail("INVALID_INPUT", "C15 effect terminal status is invalid.");
    }
    assertC15EffectCompletion(effect, input);
    const updatedAt = canonicalInstant(clock(), "clock");
    const audit = prepareAudit(state, input.auditIntent, updatedAt);
    Object.assign(effect, {
      status: input.terminalStatus,
      commitReceipt: clone(input.commitReceipt),
      readbackReceipt: clone(input.readbackReceipt),
      compensationReceipt: clone(input.compensationReceipt),
      updatedAt,
    });
    Object.assign(outbox, {
      status: "PUBLISHED",
      leasedBy: null,
      leaseUntil: null,
      leaseProofSha256: null,
      publishedAt: effect.updatedAt,
      lastErrorCode: null,
    });
    addAudit(state, audit);
    return viewEffect(effect);
  }

  async function failEffect(scope, input) {
    const trusted = validateStoreScope(scope);
    exactKeys(
      input,
      [
        "effectId",
        "workerId",
        "leaseVersion",
        "leaseToken",
        "retryDelaySeconds",
        "errorCode",
      ],
      "effect failure",
    );
    positiveInteger(input.retryDelaySeconds, "retryDelaySeconds", {
      allowZero: true,
    });
    if (
      input.retryDelaySeconds > MAX_RETRY_SECONDS ||
      !CODE.test(input.errorCode ?? "")
    ) {
      fail("INVALID_INPUT", "C15 retry is invalid.");
    }
    const outbox = stateFor(trusted.tenantId).effectOutbox.get(
      input.effectId,
    );
    if (!activeLease(outbox, input)) {
      fail("STALE_OUTBOX_LEASE", "C15 effect lease is stale.");
    }
    const now = Date.parse(canonicalInstant(clock(), "clock"));
    Object.assign(outbox, {
      status: "FAILED",
      leasedBy: null,
      leaseUntil: null,
      leaseProofSha256: null,
      availableAt: new Date(
        now + input.retryDelaySeconds * 1000,
      ).toISOString(),
      lastErrorCode: input.errorCode,
    });
    return clone(outbox);
  }

  async function claimAudit(scope, input) {
    const trusted = validateStoreScope(scope);
    const state = stateFor(trusted.tenantId);
    return claim(state.auditOutbox, trusted, input, "intentId").map(
      (outbox) => ({
        ...outbox,
        intent: clone(state.auditIntents.get(outbox.intentId)),
      }),
    );
  }

  async function completeAudit(scope, input) {
    const trusted = validateStoreScope(scope);
    exactKeys(
      input,
      ["intentId", "workerId", "leaseVersion", "leaseToken", "ack"],
      "audit completion",
    );
    const ack = input.ack;
    if (
      ack?.schemaVersion !== "c15-c18-audit-ack.v1" ||
      ack?.tenantId !== trusted.tenantId ||
      ack?.intentId !== input.intentId ||
      ack?.c18CommandReceiptKey !== input.intentId ||
      !/^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        ack?.c18EventId ?? "",
      ) ||
      !SHA256.test(ack?.c18EventHash ?? "") ||
      !SHA256.test(ack?.c18PayloadSha256 ?? "") ||
      typeof ack?.duplicate !== "boolean"
    ) {
      fail("AUDIT_ACK_MISMATCH", "C18 audit ACK did not match the intent.");
    }
    const outbox = stateFor(trusted.tenantId).auditOutbox.get(
      input.intentId,
    );
    if (!activeLease(outbox, input)) {
      fail("STALE_OUTBOX_LEASE", "C15 audit lease is stale.");
    }
    Object.assign(outbox, {
      status: "PUBLISHED",
      leasedBy: null,
      leaseUntil: null,
      leaseProofSha256: null,
      publishedAt: canonicalInstant(clock(), "clock"),
      lastErrorCode: null,
      c18CommandReceiptKey: ack.c18CommandReceiptKey,
      c18EventId: ack.c18EventId,
      c18EventHash: ack.c18EventHash,
    });
    return clone(outbox);
  }

  async function failAudit(scope, input) {
    const trusted = validateStoreScope(scope);
    exactKeys(
      input,
      [
        "intentId",
        "workerId",
        "leaseVersion",
        "leaseToken",
        "retryDelaySeconds",
        "errorCode",
      ],
      "audit failure",
    );
    positiveInteger(input.retryDelaySeconds, "retryDelaySeconds", {
      allowZero: true,
    });
    if (
      input.retryDelaySeconds > MAX_RETRY_SECONDS ||
      !CODE.test(input.errorCode ?? "")
    ) {
      fail("INVALID_INPUT", "C15 audit retry is invalid.");
    }
    const outbox = stateFor(trusted.tenantId).auditOutbox.get(
      input.intentId,
    );
    if (!activeLease(outbox, input)) {
      fail("STALE_OUTBOX_LEASE", "C15 audit lease is stale.");
    }
    const now = Date.parse(canonicalInstant(clock(), "clock"));
    Object.assign(outbox, {
      status: "FAILED",
      leasedBy: null,
      leaseUntil: null,
      leaseProofSha256: null,
      availableAt: new Date(
        now + input.retryDelaySeconds * 1000,
      ).toISOString(),
      lastErrorCode: input.errorCode,
    });
    return clone(outbox);
  }

  async function exportRecovery(scope) {
    const trusted = validateStoreScope(scope);
    const body = memoryBody(
      trusted.tenantId,
      stateFor(trusted.tenantId),
    );
    return {
      ...body,
      recoverySha256: humanDecisionSha256(body),
    };
  }

  async function inspect(scope) {
    const trusted = validateStoreScope(scope);
    const state = stateFor(trusted.tenantId);
    return clone({
      artifacts: [...state.artifacts.values()],
      decisions: [...state.decisions.values()],
      withdrawals: [...state.withdrawals.values()],
      effects: [...state.effects.values()],
      effectOutbox: [...state.effectOutbox.values()],
      auditIntents: [...state.auditIntents.values()],
      auditOutbox: [...state.auditOutbox.values()],
      receipts: [...state.receipts.values()],
    });
  }

  return Object.freeze({
    createArtifact,
    getArtifact,
    createDecision,
    getDecision,
    withdrawDecision,
    queueEffect,
    getEffect,
    claimEffects,
    assertEffectExecutable,
    completeEffect,
    failEffect,
    claimAudit,
    completeAudit,
    failAudit,
    exportRecovery,
    inspect,
  });
}

export function createHumanDecisionWorkflow({
  tenantRegistry,
  stablePrincipalRegistry,
  authorizer,
  decisionCeremony,
  catalog,
  store,
  clock = () => new Date().toISOString(),
  idFactory = uuidV7,
}) {
  if (
    typeof tenantRegistry?.admitNewRequest !== "function" ||
    typeof stablePrincipalRegistry?.resolveActionIdentity !== "function" ||
    typeof authorizer?.enforce !== "function" ||
    typeof decisionCeremony?.verify !== "function" ||
    typeof catalog?.resolve !== "function" ||
    typeof catalog?.assertCurrent !== "function" ||
    typeof store?.createArtifact !== "function" ||
    typeof store?.createDecision !== "function" ||
    typeof store?.withdrawDecision !== "function" ||
    typeof store?.queueEffect !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C15 workflow dependencies are invalid.");
  }
  const dependencies = {
    tenantRegistry,
    stablePrincipalRegistry,
    authorizer,
  };

  async function prepare(context, request) {
    context = deepFreeze(clone(context));
    request = deepFreeze(clone(request));
    validateServerContext(context);
    validateEnvelope(request, ["workflowRef", "candidate"]);
    reference(request.workflowRef, "workflowRef");
    const workflow = catalog.resolve(context.tenantId, request.workflowRef);
    validateCandidate(request.candidate, workflow);
    const resourceId = `${workflow.resourcePrefix}--decision-prepare`;
    const access = await authorizeAction(
      dependencies,
      context,
      request,
      {
        operationId: "C15_PREPARE_DRAFT",
        surface: "MANAGE",
        resourceId,
      },
    );
    const createdAt = canonicalInstant(clock(), "clock");
    const artifactId = generatedId(
      "dar_",
      ARTIFACT_ID,
      idFactory,
      "artifactId",
    );
    const body = {
      schemaVersion: "c15-draft-artifact.v1",
      tenantId: context.tenantId,
      tenantKind: "SYNTHETIC",
      artifactId,
      artifactKind: "SYNTHETIC_DRAFT",
      workflowRef: workflow.workflowRef,
      workflowVersion: workflow.version,
      bindingSha256: workflow.catalogBindingSha256,
      candidate: clone(request.candidate),
      display: artifactDisplay(workflow, request.candidate),
      preparedBy: access.identityBinding,
      preparedAuthorization: access.authorization,
      createdAt,
    };
    const artifact = deepFreeze({
      ...body,
      artifactSha256: humanDecisionSha256(body),
    });
    const intentId = generatedId(
      "hai_",
      AUDIT_INTENT_ID,
      idFactory,
      "intentId",
    );
    const auditIntent = auditMetadata({
      intentId,
      tenantId: context.tenantId,
      eventType: "DRAFT_ARTIFACT_PREPARED",
      subjectId: artifactId,
      subjectSha256: artifact.artifactSha256,
      artifactId,
      artifactSha256: artifact.artifactSha256,
      identityBinding: access.identityBinding,
      authorization: access.authorization,
      correlationId: request.correlationId,
      occurredAt: createdAt,
    });
    return store.createArtifact(access.scope, {
      tenantId: context.tenantId,
      operation: "PREPARE",
      idempotencyKey: request.idempotencyKey,
      requestHash: requestHash("PREPARE", {
        tenantId: context.tenantId,
        workflowRef: request.workflowRef,
        candidate: request.candidate,
        delegationId: request.delegationId,
      }),
      artifact,
      auditIntent,
    });
  }

  async function decide(context, request) {
    context = deepFreeze(clone(context));
    request = deepFreeze(clone(request));
    validateServerContext(context);
    validateEnvelope(request, [
      "artifactId",
      "artifactSha256",
      "outcome",
      "ceremonyProofRef",
    ]);
    identifier(request.artifactId, ARTIFACT_ID, "artifactId");
    if (!SHA256.test(request.artifactSha256 ?? "")) {
      fail("INVALID_INPUT", "artifactSha256 is invalid.");
    }
    if (request.outcome !== "APPROVE") {
      fail(
        "P3_REQUIRED",
        "P1 C15 only creates approved Synthetic Test Decisions.",
      );
    }
    reference(request.ceremonyProofRef, "ceremonyProofRef");
    const access = await authorizeAction(
      dependencies,
      context,
      request,
      {
        operationId: "C15_APPROVE_SYNTHETIC_TEST_DECISION",
        surface: "MANAGE",
        resourceId: `${request.artifactId}--decision-approve`,
      },
    );
    const artifact = await store.getArtifact(
      access.scope,
      request.artifactId,
    );
    if (!artifact) fail("ARTIFACT_NOT_FOUND", "DraftArtifact was not found.");
    if (artifact.artifactSha256 !== request.artifactSha256) {
      fail("ARTIFACT_TAMPERED", "DraftArtifact hash does not match.");
    }
    catalog.assertCurrent(artifact);
    const proof = await decisionCeremony.verify({
      tenantId: context.tenantId,
      proofRef: request.ceremonyProofRef,
      artifactId: artifact.artifactId,
      artifactSha256: artifact.artifactSha256,
      displaySha256: humanDecisionSha256(artifact.display),
      identityBinding: access.identityBinding,
    });
    if (
      proof?.trustSource !== "C15_DEDICATED_DECISION_CEREMONY" ||
      proof?.proofRef !== request.ceremonyProofRef ||
      proof?.artifactSha256 !== artifact.artifactSha256 ||
      proof?.displaySha256 !== humanDecisionSha256(artifact.display) ||
      proof?.humanPrincipalId !==
        access.identityBinding.humanPrincipalId ||
      proof?.leafDelegationId !==
        access.identityBinding.leafDelegationId ||
      !SHA256.test(proof?.proofSha256 ?? "") ||
      Date.parse(canonicalInstant(proof?.expiresAt, "ceremony.expiresAt")) <=
        Date.parse(clock())
    ) {
      fail(
        "DECISION_CEREMONY_INVALID",
        "Chat, stage approval, or an ordinary button is not a decision.",
      );
    }
    const workflow = catalog.resolve(
      context.tenantId,
      artifact.workflowRef,
    );
    const decidedAt = canonicalInstant(clock(), "clock");
    const decisionId = generatedId(
      "std_",
      DECISION_ID,
      idFactory,
      "decisionId",
    );
    const body = {
      schemaVersion: "c15-synthetic-test-decision.v1",
      tenantId: context.tenantId,
      tenantKind: "SYNTHETIC",
      decisionId,
      decisionType: "SYNTHETIC_TEST_DECISION",
      outcome: "APPROVE",
      status: "ACTIVE",
      artifactId: artifact.artifactId,
      artifactSha256: artifact.artifactSha256,
      displaySha256: humanDecisionSha256(artifact.display),
      identityBinding: access.identityBinding,
      authorizationEvidence: access.authorization,
      ceremonyProof: {
        proofRef: proof.proofRef,
        proofSha256: proof.proofSha256,
      },
      decidedAt,
      expiresAt: new Date(
        Date.parse(decidedAt) + workflow.decisionTtlSeconds * 1000,
      ).toISOString(),
      withdrawnAt: null,
      withdrawalAuthorization: null,
      productionReusable: false,
      externalEffectCount: 0,
    };
    const decision = deepFreeze({
      ...body,
      decisionSha256: humanDecisionSha256(body),
    });
    const auditIntent = auditMetadata({
      intentId: generatedId(
        "hai_",
        AUDIT_INTENT_ID,
        idFactory,
        "intentId",
      ),
      tenantId: context.tenantId,
      eventType: "SYNTHETIC_TEST_DECISION_APPROVED",
      subjectId: decisionId,
      subjectSha256: decision.decisionSha256,
      artifactId: artifact.artifactId,
      artifactSha256: artifact.artifactSha256,
      decisionId,
      decisionSha256: decision.decisionSha256,
      identityBinding: access.identityBinding,
      authorization: access.authorization,
      correlationId: request.correlationId,
      occurredAt: decidedAt,
    });
    return store.createDecision(access.scope, {
      tenantId: context.tenantId,
      operation: "DECIDE",
      idempotencyKey: request.idempotencyKey,
      requestHash: requestHash("DECIDE", {
        tenantId: context.tenantId,
        artifactId: request.artifactId,
        artifactSha256: request.artifactSha256,
        outcome: request.outcome,
        ceremonyProofRef: request.ceremonyProofRef,
        delegationId: request.delegationId,
      }),
      decision,
      auditIntent,
    });
  }

  async function withdraw(context, request) {
    context = deepFreeze(clone(context));
    request = deepFreeze(clone(request));
    validateServerContext(context);
    validateEnvelope(request, ["decisionId", "decisionSha256"]);
    identifier(request.decisionId, DECISION_ID, "decisionId");
    if (!SHA256.test(request.decisionSha256 ?? "")) {
      fail("INVALID_INPUT", "decisionSha256 is invalid.");
    }
    const access = await authorizeAction(
      dependencies,
      context,
      request,
      {
        operationId: "C15_WITHDRAW_SYNTHETIC_TEST_DECISION",
        surface: "MANAGE",
        resourceId: `${request.decisionId}--decision-withdraw`,
      },
    );
    const decision = await store.getDecision(
      access.scope,
      request.decisionId,
    );
    if (!decision) fail("DECISION_NOT_FOUND", "Decision was not found.");
    if (
      decision.decisionSha256 !== request.decisionSha256 ||
      decision.identityBinding.humanPrincipalId !==
        access.identityBinding.humanPrincipalId
    ) {
      fail("DECISION_TAMPERED", "Decision binding does not match.");
    }
    const withdrawnAt = canonicalInstant(clock(), "clock");
    const auditIntent = auditMetadata({
      intentId: generatedId(
        "hai_",
        AUDIT_INTENT_ID,
        idFactory,
        "intentId",
      ),
      tenantId: context.tenantId,
      eventType: "SYNTHETIC_TEST_DECISION_WITHDRAWN",
      subjectId: decision.decisionId,
      subjectSha256: decision.decisionSha256,
      artifactId: decision.artifactId,
      artifactSha256: decision.artifactSha256,
      decisionId: decision.decisionId,
      decisionSha256: decision.decisionSha256,
      identityBinding: access.identityBinding,
      authorization: access.authorization,
      correlationId: request.correlationId,
      occurredAt: withdrawnAt,
    });
    return store.withdrawDecision(access.scope, {
      tenantId: context.tenantId,
      operation: "WITHDRAW",
      idempotencyKey: request.idempotencyKey,
      requestHash: requestHash("WITHDRAW", {
        tenantId: context.tenantId,
        decisionId: request.decisionId,
        decisionSha256: request.decisionSha256,
        delegationId: request.delegationId,
      }),
      decisionId: request.decisionId,
      decisionSha256: request.decisionSha256,
      withdrawnAt,
      withdrawalAuthorization: access.authorization,
      auditIntent,
    });
  }

  async function execute(context, request) {
    context = deepFreeze(clone(context));
    request = deepFreeze(clone(request));
    validateServerContext(context);
    validateEnvelope(request, [
      "decisionId",
      "decisionSha256",
      "artifactId",
      "artifactSha256",
    ]);
    identifier(request.decisionId, DECISION_ID, "decisionId");
    identifier(request.artifactId, ARTIFACT_ID, "artifactId");
    if (
      !SHA256.test(request.decisionSha256 ?? "") ||
      !SHA256.test(request.artifactSha256 ?? "")
    ) {
      fail("INVALID_INPUT", "C15 execution hashes are invalid.");
    }
    const access = await authorizeAction(
      dependencies,
      context,
      request,
      {
        operationId: "C15_EXECUTE_SYNTHETIC_PREVIEW",
        surface: "TOOL_CALL",
        resourceId: `${request.decisionId}--decision-execute`,
      },
    );
    const [decision, artifact] = await Promise.all([
      store.getDecision(access.scope, request.decisionId),
      store.getArtifact(access.scope, request.artifactId),
    ]);
    if (!decision || !artifact) {
      fail("DECISION_NOT_FOUND", "C15 execution binding was not found.");
    }
    const now = canonicalInstant(clock(), "clock");
    if (
      decision.decisionType !== "SYNTHETIC_TEST_DECISION" ||
      decision.productionReusable !== false ||
      decision.externalEffectCount !== 0 ||
      decision.status !== "ACTIVE" ||
      decision.outcome !== "APPROVE" ||
      decision.decisionSha256 !== request.decisionSha256 ||
      decision.artifactId !== artifact.artifactId ||
      decision.artifactSha256 !== artifact.artifactSha256 ||
      artifact.artifactSha256 !== request.artifactSha256 ||
      Date.parse(decision.expiresAt) <= Date.parse(now)
    ) {
      fail(
        "DECISION_NOT_ACTIVE",
        "C15 decision is expired, withdrawn, or tampered.",
      );
    }
    if (
      !sameAuthority(
        decision.identityBinding,
        access.identityBinding,
      )
    ) {
      fail(
        "DECISION_AUTHORITY_REVOKED",
        "C15 decision authority or leaf delegation changed.",
      );
    }
    catalog.assertCurrent(artifact);
    const effectId = generatedId(
      "hef_",
      EFFECT_ID,
      idFactory,
      "effectId",
    );
    const effectKey = humanDecisionSha256({
      tenantId: context.tenantId,
      decisionId: decision.decisionId,
      decisionSha256: decision.decisionSha256,
      artifactId: artifact.artifactId,
      artifactSha256: artifact.artifactSha256,
      operationId: artifact.candidate.operationId,
    });
    const body = {
      schemaVersion: "c15-synthetic-effect.v1",
      tenantId: context.tenantId,
      tenantKind: "SYNTHETIC",
      effectId,
      effectKey,
      status: "QUEUED",
      operationId: "SYNTHETIC_PREVIEW_EFFECT",
      decisionId: decision.decisionId,
      decisionSha256: decision.decisionSha256,
      artifactId: artifact.artifactId,
      artifactSha256: artifact.artifactSha256,
      expectedReadbackSha256: effectReadbackSha256(
        context.tenantId,
        effectKey,
        artifact.artifactSha256,
      ),
      executionIdentity: access.identityBinding,
      executionAuthorization: access.authorization,
      externalEffectCount: 0,
      commitReceipt: null,
      readbackReceipt: null,
      compensationReceipt: null,
      createdAt: now,
      updatedAt: now,
    };
    const effect = deepFreeze({
      ...body,
      effectSha256: humanDecisionSha256(body),
    });
    const auditIntent = auditMetadata({
      intentId: generatedId(
        "hai_",
        AUDIT_INTENT_ID,
        idFactory,
        "intentId",
      ),
      tenantId: context.tenantId,
      eventType: "SYNTHETIC_EFFECT_QUEUED",
      subjectId: effectId,
      subjectSha256: effect.effectSha256,
      artifactId: artifact.artifactId,
      artifactSha256: artifact.artifactSha256,
      decisionId: decision.decisionId,
      decisionSha256: decision.decisionSha256,
      effectId,
      effectKey,
      identityBinding: access.identityBinding,
      authorization: access.authorization,
      correlationId: request.correlationId,
      occurredAt: now,
    });
    return store.queueEffect(access.scope, {
      tenantId: context.tenantId,
      operation: "EXECUTE",
      idempotencyKey: request.idempotencyKey,
      requestHash: requestHash("EXECUTE", {
        tenantId: context.tenantId,
        decisionId: request.decisionId,
        decisionSha256: request.decisionSha256,
        artifactId: request.artifactId,
        artifactSha256: request.artifactSha256,
        delegationId: request.delegationId,
      }),
      now,
      effect,
      auditIntent,
    });
  }

  return Object.freeze({ prepare, decide, withdraw, execute });
}

export function createC15EffectOutcomeAuditIntent({
  effect,
  terminalStatus,
  identityBinding: identity,
  authorization,
  correlationId,
  occurredAt,
  idFactory = uuidV7,
}) {
  if (
    !["SUCCEEDED", "COMPENSATED", "COMPENSATION_FAILED"].includes(
      terminalStatus,
    )
  ) {
    fail("INVALID_INPUT", "C15 effect outcome is invalid.");
  }
  return auditMetadata({
    intentId: generatedId(
      "hai_",
      AUDIT_INTENT_ID,
      idFactory,
      "intentId",
    ),
    tenantId: effect.tenantId,
    eventType: `SYNTHETIC_EFFECT_${terminalStatus}`,
    subjectId: effect.effectId,
    subjectSha256: effect.effectSha256,
    artifactId: effect.artifactId,
    artifactSha256: effect.artifactSha256,
    decisionId: effect.decisionId,
    decisionSha256: effect.decisionSha256,
    effectId: effect.effectId,
    effectKey: effect.effectKey,
    identityBinding: identity,
    authorization,
    correlationId,
    occurredAt,
  });
}
