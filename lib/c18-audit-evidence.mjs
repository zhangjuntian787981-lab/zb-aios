import { createHash, randomBytes } from "node:crypto";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7}$`);
const AUDIT_EVENT_ID = new RegExp(`^aev_${UUID_V7}$`);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|profile|prov|synthetic|test):\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const CORRELATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const UTC_MILLISECOND_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const AUDIT_TYPE = /^[A-Z][A-Z0-9_]{0,63}$/;
const SUMMARY_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const RETENTION_CLASSES = new Set(["AUDIT_7Y"]);
const MAX_OUTBOX_LEASE_SECONDS = 300;
const MAX_OUTBOX_RETRY_SECONDS = 3600;
const EVIDENCE_TYPES = new Set([
  "AUTHORIZATION",
  "MODEL",
  "KNOWLEDGE",
  "SKILL",
  "TOOL",
  "HUMAN_DECISION",
  "RESULT",
  "C08_STATE",
]);
const AUDIT_RECORD_SCHEMA_VERSION = "c18-audit-record.v1";
const GENESIS_HASH =
  "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const FORBIDDEN_KEYS = new Set([
  "authorizationheader",
  "accesskey",
  "apikey",
  "body",
  "bytes",
  "content",
  "cookie",
  "clientsecret",
  "credential",
  "filebytes",
  "input",
  "message",
  "modelinput",
  "modeloutput",
  "output",
  "password",
  "privatekey",
  "prompt",
  "prompttext",
  "raw",
  "secret",
  "text",
  "token",
  "toolarguments",
]);
const SECRET_VALUE =
  /(?:basic\s+[a-z0-9+/=]+|bearer\s+[a-z0-9._~-]+|sk-[a-z0-9_-]{8,}|aiza[a-z0-9_-]{8,}|akia[a-z0-9]{16}|gh[pousr]_[a-z0-9]{8,}|-----BEGIN [A-Z ]+PRIVATE KEY-----|(?:api[_-]?key|access[_-]?key|client[_-]?secret|password|secret|token)\s*[:=])/i;

export const C18_GENESIS_HASH = GENESIS_HASH;

export class AuditEvidenceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AuditEvidenceError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new AuditEvidenceError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
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

function nonEmptyString(value, field, maxLength = 256) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maxLength
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function positiveInteger(value, field, { allowZero = false } = {}) {
  if (
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1)
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function identifier(value, pattern, field) {
  nonEmptyString(value, field, 128);
  if (!pattern.test(value)) fail("INVALID_INPUT", `${field} is invalid.`);
}

function reference(value, field) {
  nonEmptyString(value, field, 1024);
  if (!REFERENCE.test(value)) {
    fail("P3_REQUIRED", `${field} is not an approved P1 reference.`);
  }
}

function version(value, field) {
  nonEmptyString(value, field, 128);
  if (!VERSION.test(value)) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function canonicalInstant(value, field) {
  if (
    typeof value !== "string" ||
    !UTC_MILLISECOND_INSTANT.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${field} must be a canonical UTC instant.`);
  }
  return value;
}

function addSeconds(value, seconds) {
  return new Date(Date.parse(value) + seconds * 1000).toISOString();
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
      fail("INVALID_JSON", "RFC 8785 accepts only finite JSON numbers.");
    }
    return JSON.stringify(value);
  }
  if (!value || typeof value !== "object") {
    fail("INVALID_JSON", "RFC 8785 accepts only JSON values.");
  }
  if (ancestors.has(value)) {
    fail("INVALID_JSON", "RFC 8785 rejects cyclic values.");
  }
  ancestors.add(value);
  let result;
  if (Array.isArray(value)) {
    const entries = [];
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.hasOwn(value, index)) {
        fail("INVALID_JSON", "RFC 8785 rejects sparse arrays.");
      }
      entries.push(canonicalize(value[index], ancestors));
    }
    result = `[${entries.join(",")}]`;
  } else {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail("INVALID_JSON", "RFC 8785 accepts plain JSON objects only.");
    }
    const keys = Object.keys(value).sort();
    for (const key of keys) validateUnicode(key);
    result = `{${keys
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalize(value[key], ancestors)}`,
      )
      .join(",")}}`;
  }
  ancestors.delete(value);
  return result;
}

export function canonicalizeAuditJson(value) {
  return canonicalize(value, new WeakSet());
}

export function auditEvidenceSha256(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalizeAuditJson(value), "utf8")
    .digest("hex")}`;
}

function normalizedKey(key) {
  return key.toLowerCase().replace(/[_-]/g, "");
}

export function assertAuditMetadataOnly(value) {
  const visit = (current, path) => {
    if (typeof current === "string") {
      validateUnicode(current);
      if (current.length > 2048 || SECRET_VALUE.test(current)) {
        fail(
          "PROHIBITED_AUDIT_BODY",
          `Audit metadata at ${path} contains prohibited material.`,
        );
      }
      return;
    }
    if (
      current === null ||
      typeof current === "boolean" ||
      typeof current === "number"
    ) {
      return;
    }
    if (!current || typeof current !== "object") {
      fail("PROHIBITED_AUDIT_BODY", "Audit payload is not JSON metadata.");
    }
    if (Array.isArray(current)) {
      current.forEach((entry, index) => visit(entry, `${path}[${index}]`));
      return;
    }
    for (const [key, entry] of Object.entries(current)) {
      const keyName = normalizedKey(key);
      if (
        FORBIDDEN_KEYS.has(keyName) ||
        (keyName === "authorization" &&
          (entry === null ||
            typeof entry !== "object" ||
            Array.isArray(entry)))
      ) {
        fail(
          "PROHIBITED_AUDIT_BODY",
          `Audit field ${key} is prohibited.`,
        );
      }
      visit(entry, `${path}.${key}`);
    }
  };
  visit(value, "$");
  return true;
}

function commonEvidence(value, field) {
  exactKeys(value, ["evidenceRef", "version", "sha256"], field);
  reference(value.evidenceRef, `${field}.evidenceRef`);
  version(value.version, `${field}.version`);
  if (!SHA256.test(value.sha256 ?? "")) {
    fail("INVALID_CATALOG", `${field}.sha256 is invalid.`);
  }
  return clone(value);
}

function authorizationEvidence(value) {
  exactKeys(
    value,
    ["decisionId", "evidenceRef", "version", "sha256"],
    "authorization",
  );
  nonEmptyString(value.decisionId, "authorization.decisionId", 256);
  const evidence = commonEvidence(
    {
      evidenceRef: value.evidenceRef,
      version: value.version,
      sha256: value.sha256,
    },
    "authorization",
  );
  return { decisionId: value.decisionId, ...evidence };
}

function validateTenantId(value) {
  if (!SYNTHETIC_TENANT_ID.test(value ?? "")) {
    fail("P3_REQUIRED", "C18 accepts only Synthetic Tenant IDs before P3.");
  }
}

function catalogBundle(value) {
  exactKeys(
    value,
    [
      "bundleRef",
      "auditType",
      "summaryCode",
      "retentionClass",
      "authorization",
      "model",
      "knowledge",
      "skill",
      "tool",
      "humanDecision",
      "result",
      "c08State",
    ],
    "evidence bundle",
  );
  reference(value.bundleRef, "bundleRef");
  if (!AUDIT_TYPE.test(value.auditType ?? "")) {
    fail("INVALID_CATALOG", "auditType is invalid.");
  }
  if (!SUMMARY_CODE.test(value.summaryCode ?? "")) {
    fail("INVALID_CATALOG", "summaryCode is invalid.");
  }
  if (!RETENTION_CLASSES.has(value.retentionClass)) {
    fail("INVALID_CATALOG", "retentionClass is invalid.");
  }
  if (!Array.isArray(value.knowledge) || value.knowledge.length === 0) {
    fail("INVALID_CATALOG", "At least one knowledge evidence is required.");
  }
  const bundle = {
    bundleRef: value.bundleRef,
    auditType: value.auditType,
    summaryCode: value.summaryCode,
    retentionClass: value.retentionClass,
    authorization: authorizationEvidence(value.authorization),
    model: commonEvidence(value.model, "model"),
    knowledge: value.knowledge.map((item, index) =>
      commonEvidence(item, `knowledge[${index}]`),
    ),
    skill: commonEvidence(value.skill, "skill"),
    tool: commonEvidence(value.tool, "tool"),
    humanDecision: commonEvidence(
      value.humanDecision,
      "humanDecision",
    ),
    result: commonEvidence(value.result, "result"),
    c08State: commonEvidence(value.c08State, "c08State"),
  };
  assertAuditMetadataOnly(bundle);
  return Object.freeze(bundle);
}

export function createSyntheticAuditEvidenceRegistry(document) {
  exactKeys(
    document,
    ["schemaVersion", "status", "entries"],
    "evidence registry",
  );
  if (
    document.schemaVersion !== "c18-synthetic-evidence-registry.v1" ||
    document.status !== "SYNTHETIC_ONLY" ||
    !Array.isArray(document.entries) ||
    document.entries.length !== 24
  ) {
    fail("INVALID_EVIDENCE_REGISTRY", "Evidence registry is invalid.");
  }
  const entries = new Map();
  for (const entry of document.entries) {
    exactKeys(
      entry,
      [
        "tenantId",
        "evidenceType",
        "evidenceRef",
        "version",
        "sha256",
        "artifact",
      ],
      "evidence registry entry",
    );
    validateTenantId(entry.tenantId);
    if (!EVIDENCE_TYPES.has(entry.evidenceType)) {
      fail("INVALID_EVIDENCE_REGISTRY", "Evidence type is invalid.");
    }
    reference(entry.evidenceRef, "evidenceRef");
    version(entry.version, "version");
    if (!SHA256.test(entry.sha256 ?? "")) {
      fail("INVALID_EVIDENCE_REGISTRY", "Evidence digest is invalid.");
    }
    exactKeys(
      entry.artifact,
      [
        "schemaVersion",
        "tenantId",
        "evidenceType",
        "artifactId",
        "sourceWorkPackage",
        "summaryCode",
      ],
      "Synthetic evidence artifact",
    );
    if (
      entry.artifact.schemaVersion !==
        "c18-synthetic-evidence-artifact.v1" ||
      entry.artifact.tenantId !== entry.tenantId ||
      entry.artifact.evidenceType !== entry.evidenceType ||
      !/^[A-Z][0-9]{2}$/.test(entry.artifact.sourceWorkPackage ?? "") ||
      !SUMMARY_CODE.test(entry.artifact.summaryCode ?? "")
    ) {
      fail(
        "INVALID_EVIDENCE_REGISTRY",
        "Synthetic evidence artifact is invalid.",
      );
    }
    version(entry.artifact.artifactId, "artifactId");
    assertAuditMetadataOnly(entry.artifact);
    if (auditEvidenceSha256(entry.artifact) !== entry.sha256) {
      fail(
        "EVIDENCE_DIGEST_MISMATCH",
        "Synthetic evidence artifact digest does not match.",
      );
    }
    const key = `${entry.tenantId}\u0000${entry.evidenceRef}`;
    if (entries.has(key)) {
      fail("INVALID_EVIDENCE_REGISTRY", "Duplicate EvidenceRef.");
    }
    entries.set(key, clone(entry));
  }

  return Object.freeze({
    resolve(expected) {
      exactKeys(
        expected,
        [
          "tenantId",
          "evidenceType",
          "evidenceRef",
          "version",
          "sha256",
        ],
        "evidence resolution",
      );
      const entry = entries.get(
        `${expected.tenantId}\u0000${expected.evidenceRef}`,
      );
      if (
        !entry ||
        entry.evidenceType !== expected.evidenceType ||
        entry.version !== expected.version ||
        entry.sha256 !== expected.sha256 ||
        auditEvidenceSha256(entry.artifact) !== expected.sha256
      ) {
        fail(
          "EVIDENCE_DIGEST_MISMATCH",
          "Frozen Synthetic evidence did not resolve.",
        );
      }
      return clone(entry.artifact);
    },
  });
}

function bundleEvidence(bundle) {
  return [
    ["AUTHORIZATION", bundle.authorization],
    ["MODEL", bundle.model],
    ...bundle.knowledge.map((item) => ["KNOWLEDGE", item]),
    ["SKILL", bundle.skill],
    ["TOOL", bundle.tool],
    ["HUMAN_DECISION", bundle.humanDecision],
    ["RESULT", bundle.result],
    ["C08_STATE", bundle.c08State],
  ];
}

function verifyBundleEvidence(evidenceRegistry, tenantId, bundle) {
  for (const [evidenceType, evidence] of bundleEvidence(bundle)) {
    evidenceRegistry.resolve({
      tenantId,
      evidenceType,
      evidenceRef: evidence.evidenceRef,
      version: evidence.version,
      sha256: evidence.sha256,
    });
  }
}

export function createSyntheticAuditEvidenceCatalog(
  document,
  { evidenceRegistry } = {},
) {
  if (typeof evidenceRegistry?.resolve !== "function") {
    fail(
      "INVALID_CONFIGURATION",
      "A frozen Synthetic evidence registry is required.",
    );
  }
  exactKeys(
    document,
    ["schemaVersion", "status", "tenants"],
    "catalog",
  );
  if (
    document.schemaVersion !== "c18-synthetic-evidence-catalog.v1" ||
    document.status !== "SYNTHETIC_ONLY" ||
    !Array.isArray(document.tenants) ||
    document.tenants.length !== 3
  ) {
    fail("INVALID_CATALOG", "C18 requires three Synthetic Tenants.");
  }
  const tenants = new Map();
  for (const tenant of document.tenants) {
    exactKeys(tenant, ["tenantId", "fixtureId", "bundles"], "tenant");
    validateTenantId(tenant.tenantId);
    nonEmptyString(tenant.fixtureId, "fixtureId", 128);
    if (
      tenants.has(tenant.tenantId) ||
      !Array.isArray(tenant.bundles) ||
      tenant.bundles.length === 0
    ) {
      fail("INVALID_CATALOG", "Catalog Tenant is invalid.");
    }
    const bundles = new Map();
    for (const raw of tenant.bundles) {
      const bundle = catalogBundle(raw);
      verifyBundleEvidence(evidenceRegistry, tenant.tenantId, bundle);
      if (bundles.has(bundle.bundleRef)) {
        fail("INVALID_CATALOG", "Duplicate bundleRef.");
      }
      bundles.set(bundle.bundleRef, bundle);
    }
    tenants.set(
      tenant.tenantId,
      Object.freeze({ fixtureId: tenant.fixtureId, bundles }),
    );
  }
  return Object.freeze({
    resolve(tenantId, bundleRef) {
      validateTenantId(tenantId);
      reference(bundleRef, "evidenceBundleRef");
      const bundle = tenants.get(tenantId)?.bundles.get(bundleRef);
      if (!bundle) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "Evidence Bundle is not frozen for this Synthetic Tenant.",
        );
      }
      verifyBundleEvidence(evidenceRegistry, tenantId, bundle);
      return clone(bundle);
    },
    tenantIds() {
      return [...tenants.keys()];
    },
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
    "trusted server context",
  );
  if (
    context.synthetic !== true ||
    context.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR" ||
    context.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT"
  ) {
    fail("UNTRUSTED_ROUTE", "C18 route or workload context is untrusted.");
  }
  validateTenantId(context.tenantId);
  identifier(
    context.workloadActorPrincipalId,
    PRINCIPAL_ID,
    "workloadActorPrincipalId",
  );
}

function validateRequest(request) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "idempotencyKey",
      "correlationId",
      "evidenceBundleRef",
    ],
    "request",
  );
  nonEmptyString(request.sessionToken, "sessionToken", 256);
  identifier(request.delegationId, DELEGATION_ID, "delegationId");
  if (!IDEMPOTENCY_KEY.test(request.idempotencyKey ?? "")) {
    fail("INVALID_INPUT", "idempotencyKey is invalid.");
  }
  if (!CORRELATION_ID.test(request.correlationId ?? "")) {
    fail("INVALID_INPUT", "correlationId is invalid.");
  }
  reference(request.evidenceBundleRef, "evidenceBundleRef");
}

function validateIdentity(identity, context, delegationId) {
  if (
    identity?.tenantId !== context.tenantId ||
    identity?.tenantKind !== "SYNTHETIC" ||
    identity?.trustSource !==
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT" ||
    identity?.humanSubject?.principalType !== "HUMAN" ||
    !["AGENT", "SERVICE"].includes(
      identity?.workloadActor?.principalType,
    ) ||
    identity.workloadActor.principalId !==
      context.workloadActorPrincipalId ||
    !Array.isArray(identity.delegationChain) ||
    identity.delegationChain.length === 0
  ) {
    fail("IDENTITY_BINDING_INVALID", "C05 identity binding is invalid.");
  }
  identifier(
    identity.humanSubject.principalId,
    PRINCIPAL_ID,
    "humanSubject.principalId",
  );
  identifier(
    identity.workloadActor.principalId,
    PRINCIPAL_ID,
    "workloadActor.principalId",
  );
  for (const [field, value] of [
    ["identityAccountId", identity.identityAccountId],
    ["identityLinkId", identity.identityLinkId],
    ["sessionId", identity.sessionId],
  ]) {
    nonEmptyString(value, field, 256);
  }
  reference(identity.purposeRef, "purposeRef");
  for (const [field, value] of [
    ["humanSubject.lifecycleVersion", identity.humanSubject.lifecycleVersion],
    ["humanSubject.securityEpoch", identity.humanSubject.securityEpoch],
    [
      "workloadActor.lifecycleVersion",
      identity.workloadActor.lifecycleVersion,
    ],
    ["workloadActor.securityEpoch", identity.workloadActor.securityEpoch],
  ]) {
    positiveInteger(value, field);
  }
  for (const [index, delegation] of identity.delegationChain.entries()) {
    identifier(
      delegation?.delegationId,
      DELEGATION_ID,
      `delegationChain[${index}].delegationId`,
    );
    identifier(
      delegation.delegatorPrincipalId,
      PRINCIPAL_ID,
      `delegationChain[${index}].delegatorPrincipalId`,
    );
    identifier(
      delegation.delegatePrincipalId,
      PRINCIPAL_ID,
      `delegationChain[${index}].delegatePrincipalId`,
    );
    positiveInteger(
      delegation.lifecycleVersion,
      `delegationChain[${index}].lifecycleVersion`,
    );
    reference(
      delegation.purposeRef,
      `delegationChain[${index}].purposeRef`,
    );
    canonicalInstant(
      delegation.expiresAt,
      `delegationChain[${index}].expiresAt`,
    );
    const expectedDelegator =
      index === 0
        ? identity.humanSubject.principalId
        : identity.delegationChain[index - 1].delegatePrincipalId;
    if (delegation.delegatorPrincipalId !== expectedDelegator) {
      fail("IDENTITY_BINDING_INVALID", "C05 delegation chain is invalid.");
    }
  }
  const leaf = identity.delegationChain.at(-1);
  if (
    leaf?.delegationId !== delegationId ||
    leaf.delegatePrincipalId !== identity.workloadActor.principalId
  ) {
    fail("IDENTITY_BINDING_INVALID", "C05 delegation binding is invalid.");
  }
  return clone(identity);
}

function actionIdentitySnapshot(identity) {
  return {
    tenantId: identity.tenantId,
    tenantKind: identity.tenantKind,
    identityAccountId: identity.identityAccountId,
    identityLinkId: identity.identityLinkId,
    sessionId: identity.sessionId,
    purposeRef: identity.purposeRef,
    humanSubject: {
      principalId: identity.humanSubject.principalId,
      lifecycleVersion: identity.humanSubject.lifecycleVersion,
      securityEpoch: identity.humanSubject.securityEpoch,
    },
    workloadActor: {
      principalId: identity.workloadActor.principalId,
      principalType: identity.workloadActor.principalType,
      lifecycleVersion: identity.workloadActor.lifecycleVersion,
      securityEpoch: identity.workloadActor.securityEpoch,
    },
    delegationChain: identity.delegationChain.map((entry) => ({
      delegationId: entry.delegationId,
      delegatorPrincipalId: entry.delegatorPrincipalId,
      delegatePrincipalId: entry.delegatePrincipalId,
      purposeRef: entry.purposeRef,
      lifecycleVersion: entry.lifecycleVersion,
      expiresAt: entry.expiresAt,
    })),
    trustSource: identity.trustSource,
  };
}

function sameActionIdentity(left, right) {
  return (
    canonicalizeAuditJson(actionIdentitySnapshot(left)) ===
    canonicalizeAuditJson(actionIdentitySnapshot(right))
  );
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

function generatedEventId(idFactory) {
  const value = `aev_${idFactory()}`;
  identifier(value, AUDIT_EVENT_ID, "auditEventId");
  return value;
}

function identityEvidence(identity, eventId) {
  const snapshot = actionIdentitySnapshot(identity);
  const leaf = snapshot.delegationChain.at(-1);
  return {
    evidenceRef: `evidence://c18/action-identities/${eventId}`,
    version: "c05-action-identity-v1",
    sha256: auditEvidenceSha256(snapshot),
    humanPrincipalRef:
      `evidence://c05/principals/${snapshot.humanSubject.principalId}`,
    workloadPrincipalRef:
      `evidence://c05/principals/${snapshot.workloadActor.principalId}`,
    delegationRef: `evidence://c05/delegations/${leaf.delegationId}`,
  };
}

function evidenceEntity(evidence, type) {
  return {
    id: evidence.evidenceRef,
    type,
    version: evidence.version,
    sha256: evidence.sha256,
  };
}

function provenanceGraph(eventId, occurredAt, identity, bundle) {
  const activityId = `prov://c18/activities/${eventId}`;
  const entities = [
    evidenceEntity(identity, "aios:IdentityEvidence"),
    evidenceEntity(bundle.authorization, "aios:AuthorizationEvidence"),
    evidenceEntity(bundle.model, "aios:ModelEvidence"),
    ...bundle.knowledge.map((item) =>
      evidenceEntity(item, "aios:KnowledgeEvidence"),
    ),
    evidenceEntity(bundle.skill, "aios:SkillEvidence"),
    evidenceEntity(bundle.tool, "aios:ToolEvidence"),
    evidenceEntity(bundle.humanDecision, "aios:HumanDecisionEvidence"),
    evidenceEntity(bundle.result, "aios:ResultEvidence"),
    evidenceEntity(bundle.c08State, "aios:C08StateEvidence"),
  ];
  const used = entities
    .filter((entity) => entity.id !== bundle.result.evidenceRef)
    .map((entity) => ({
      type: "prov:used",
      activity: activityId,
      entity: entity.id,
    }));
  return {
    profileVersion: "c18-w3c-prov-profile.v1",
    activities: [
      {
        id: activityId,
        type: "aios:AuditedAction",
        occurredAt,
      },
    ],
    agents: [
      {
        id: identity.humanPrincipalRef,
        type: "prov:Person",
      },
      {
        id: identity.workloadPrincipalRef,
        type: "prov:SoftwareAgent",
      },
    ],
    entities,
    relations: [
      {
        type: "prov:wasAssociatedWith",
        activity: activityId,
        agent: identity.humanPrincipalRef,
      },
      {
        type: "prov:wasAssociatedWith",
        activity: activityId,
        agent: identity.workloadPrincipalRef,
      },
      {
        type: "prov:actedOnBehalfOf",
        delegate: identity.workloadPrincipalRef,
        responsible: identity.humanPrincipalRef,
      },
      ...used,
      {
        type: "prov:wasGeneratedBy",
        entity: bundle.result.evidenceRef,
        activity: activityId,
      },
      {
        type: "prov:wasDerivedFrom",
        generatedEntity: bundle.result.evidenceRef,
        usedEntity: bundle.c08State.evidenceRef,
      },
    ],
  };
}

function payloadFor({
  eventId,
  tenantId,
  correlationId,
  occurredAt,
  identity,
  bundle,
}) {
  const identityItem = identityEvidence(identity, eventId);
  const provenance = provenanceGraph(
    eventId,
    occurredAt,
    identityItem,
    bundle,
  );
  const payload = {
    schemaVersion: "c18-audit-event.v1",
    auditType: bundle.auditType,
    tenantId,
    tenantKind: "SYNTHETIC",
    occurredAt,
    correlationId,
    summaryCode: bundle.summaryCode,
    retentionClass: bundle.retentionClass,
    identity: identityItem,
    authorization: clone(bundle.authorization),
    model: clone(bundle.model),
    knowledge: clone(bundle.knowledge),
    skill: clone(bundle.skill),
    tool: clone(bundle.tool),
    humanDecision: clone(bundle.humanDecision),
    result: clone(bundle.result),
    c08State: clone(bundle.c08State),
    provenance,
    provenanceSha256: auditEvidenceSha256(provenance),
  };
  assertValidAuditPayload(payload, {
    eventId,
    tenantId,
    correlationId,
    createdAt: occurredAt,
  });
  return payload;
}

function validateIdentityEvidence(value, eventId) {
  exactKeys(
    value,
    [
      "evidenceRef",
      "version",
      "sha256",
      "humanPrincipalRef",
      "workloadPrincipalRef",
      "delegationRef",
    ],
    "payload.identity",
  );
  const evidence = commonEvidence(
    {
      evidenceRef: value.evidenceRef,
      version: value.version,
      sha256: value.sha256,
    },
    "payload.identity",
  );
  if (
    evidence.version !== "c05-action-identity-v1" ||
    evidence.evidenceRef !==
      `evidence://c18/action-identities/${eventId}`
  ) {
    fail("INVALID_AUDIT_PAYLOAD", "Identity evidence is not event-bound.");
  }
  for (const [field, item] of [
    ["humanPrincipalRef", value.humanPrincipalRef],
    ["workloadPrincipalRef", value.workloadPrincipalRef],
    ["delegationRef", value.delegationRef],
  ]) {
    reference(item, `payload.identity.${field}`);
  }
  if (
    !/^evidence:\/\/c05\/principals\/prn_/.test(value.humanPrincipalRef) ||
    !/^evidence:\/\/c05\/principals\/prn_/.test(
      value.workloadPrincipalRef,
    ) ||
    !/^evidence:\/\/c05\/delegations\/dlg_/.test(value.delegationRef)
  ) {
    fail("INVALID_AUDIT_PAYLOAD", "Identity references are invalid.");
  }
  return clone(value);
}

function validateAuditPayload(value, expected) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "auditType",
      "tenantId",
      "tenantKind",
      "occurredAt",
      "correlationId",
      "summaryCode",
      "retentionClass",
      "identity",
      "authorization",
      "model",
      "knowledge",
      "skill",
      "tool",
      "humanDecision",
      "result",
      "c08State",
      "provenance",
      "provenanceSha256",
    ],
    "Audit payload",
  );
  if (
    value.schemaVersion !== "c18-audit-event.v1" ||
    value.tenantKind !== "SYNTHETIC" ||
    !AUDIT_TYPE.test(value.auditType ?? "") ||
    !SUMMARY_CODE.test(value.summaryCode ?? "") ||
    !RETENTION_CLASSES.has(value.retentionClass)
  ) {
    fail("INVALID_AUDIT_PAYLOAD", "Audit payload constants are invalid.");
  }
  validateTenantId(value.tenantId);
  canonicalInstant(value.occurredAt, "payload.occurredAt");
  if (!CORRELATION_ID.test(value.correlationId ?? "")) {
    fail("INVALID_AUDIT_PAYLOAD", "Audit correlationId is invalid.");
  }
  if (
    value.tenantId !== expected.tenantId ||
    value.correlationId !== expected.correlationId ||
    value.occurredAt !== expected.createdAt
  ) {
    fail("INVALID_AUDIT_PAYLOAD", "Audit payload escaped its record.");
  }
  const identity = validateIdentityEvidence(value.identity, expected.eventId);
  const authorization = authorizationEvidence(value.authorization);
  const model = commonEvidence(value.model, "payload.model");
  if (!Array.isArray(value.knowledge) || value.knowledge.length === 0) {
    fail("INVALID_AUDIT_PAYLOAD", "Knowledge evidence is required.");
  }
  const knowledge = value.knowledge.map((item, index) =>
    commonEvidence(item, `payload.knowledge[${index}]`),
  );
  const skill = commonEvidence(value.skill, "payload.skill");
  const tool = commonEvidence(value.tool, "payload.tool");
  const humanDecision = commonEvidence(
    value.humanDecision,
    "payload.humanDecision",
  );
  const result = commonEvidence(value.result, "payload.result");
  const c08State = commonEvidence(value.c08State, "payload.c08State");
  if (!SHA256.test(value.provenanceSha256 ?? "")) {
    fail("INVALID_AUDIT_PAYLOAD", "provenanceSha256 is invalid.");
  }
  const provenance = provenanceGraph(
    expected.eventId,
    value.occurredAt,
    identity,
    {
      authorization,
      model,
      knowledge,
      skill,
      tool,
      humanDecision,
      result,
      c08State,
    },
  );
  if (
    canonicalizeAuditJson(value.provenance) !==
      canonicalizeAuditJson(provenance) ||
    auditEvidenceSha256(value.provenance) !== value.provenanceSha256
  ) {
    fail("INVALID_AUDIT_PAYLOAD", "W3C PROV evidence is invalid.");
  }
  assertAuditMetadataOnly(value);
  return true;
}

export function assertValidAuditPayload(value, expected) {
  try {
    return validateAuditPayload(value, expected);
  } catch (error) {
    if (
      error instanceof AuditEvidenceError &&
      ["INVALID_AUDIT_PAYLOAD", "PROHIBITED_AUDIT_BODY"].includes(
        error.code,
      )
    ) {
      throw error;
    }
    fail("INVALID_AUDIT_PAYLOAD", "Audit payload is invalid.");
  }
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope.tenantKind !== "SYNTHETIC"
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C18 Tenant scope is invalid.");
  }
  validateTenantId(scope.tenantId);
  positiveInteger(scope.lifecycleVersion, "scope.lifecycleVersion");
  if (!CORRELATION_ID.test(scope.correlationId ?? "")) {
    fail("TENANT_SCOPE_VIOLATION", "C18 correlation scope is invalid.");
  }
  nonEmptyString(scope.decisionId, "scope.decisionId", 256);
  reference(scope.evidenceRef, "scope.evidenceRef");
  nonEmptyString(scope.policyVersion, "scope.policyVersion", 128);
  return clone(scope);
}

export function computeAuditEventHash(record) {
  return auditEvidenceSha256({
    schemaVersion: AUDIT_RECORD_SCHEMA_VERSION,
    eventId: record.eventId,
    tenantId: record.tenantId,
    tenantKind: record.tenantKind,
    sequence: record.sequence,
    previousEventHash: record.previousEventHash,
    payloadSha256: record.payloadSha256,
    createdAt: record.createdAt,
  });
}

export function createAuditCloudEvent(record) {
  return {
    specversion: "1.0",
    id: record.eventId,
    source: "/aios-core/audit-evidence",
    type: "product.aios.audit-evidence-recorded.v1",
    time: record.createdAt,
    datacontenttype: "application/json",
    subject: record.tenantId,
    dataschema: "synthetic://c18/schemas/audit-event.v1",
    tenantkind: "SYNTHETIC",
    correlationid: record.payload.correlationId,
    synthetic: true,
    data: {
      tenant_id: record.tenantId,
      audit_event_id: record.eventId,
      sequence: record.sequence,
      previous_event_hash: record.previousEventHash,
      event_hash: record.eventHash,
      payload_sha256: record.payloadSha256,
      provenance_sha256: record.payload.provenanceSha256,
      audit_type: record.payload.auditType,
      retention_class: record.payload.retentionClass,
    },
  };
}

function recordView(record, duplicate = false) {
  return Object.freeze({
    tenantId: record.tenantId,
    tenantKind: "SYNTHETIC",
    eventId: record.eventId,
    sequence: record.sequence,
    previousEventHash: record.previousEventHash,
    eventHash: record.eventHash,
    payloadSha256: record.payloadSha256,
    provenanceSha256: record.payload.provenanceSha256,
    auditType: record.payload.auditType,
    retentionClass: record.payload.retentionClass,
    createdAt: record.createdAt,
    duplicate,
  });
}

function tenantState() {
  return {
    events: [],
    receipts: new Map(),
    outbox: new Map(),
  };
}

function validateAppendInput(input) {
  exactKeys(
    input,
    [
      "eventId",
      "idempotencyKey",
      "requestHash",
      "payload",
      "createdAt",
    ],
    "append input",
  );
  identifier(input.eventId, AUDIT_EVENT_ID, "eventId");
  if (!IDEMPOTENCY_KEY.test(input.idempotencyKey ?? "")) {
    fail("INVALID_INPUT", "idempotencyKey is invalid.");
  }
  if (!SHA256.test(input.requestHash ?? "")) {
    fail("INVALID_INPUT", "requestHash is invalid.");
  }
  canonicalInstant(input.createdAt, "createdAt");
  assertValidAuditPayload(input.payload, {
    eventId: input.eventId,
    tenantId: input.payload?.tenantId,
    correlationId: input.payload?.correlationId,
    createdAt: input.createdAt,
  });
}

function validateQuery(query) {
  exactKeys(
    query,
    [
      "fromSequence",
      "toSequence",
      "fromOccurredAt",
      "toOccurredAt",
      "limit",
    ],
    "query",
  );
  positiveInteger(query.fromSequence, "fromSequence");
  positiveInteger(query.toSequence, "toSequence");
  if (query.fromSequence > query.toSequence) {
    fail("INVALID_INPUT", "Sequence range is invalid.");
  }
  canonicalInstant(query.fromOccurredAt, "fromOccurredAt");
  canonicalInstant(query.toOccurredAt, "toOccurredAt");
  if (
    Date.parse(query.fromOccurredAt) > Date.parse(query.toOccurredAt)
  ) {
    fail("INVALID_INPUT", "Time range is invalid.");
  }
  positiveInteger(query.limit, "limit");
  if (query.limit > 500) fail("INVALID_INPUT", "limit exceeds 500.");
}

function validateLease(input) {
  exactKeys(
    input,
    ["workerId", "leaseDurationSeconds", "limit"],
    "lease",
  );
  nonEmptyString(input.workerId, "workerId", 128);
  positiveInteger(input.leaseDurationSeconds, "leaseDurationSeconds");
  positiveInteger(input.limit, "limit");
  if (
    input.limit > 100 ||
    input.leaseDurationSeconds > MAX_OUTBOX_LEASE_SECONDS
  ) {
    fail("INVALID_INPUT", "Outbox lease is invalid.");
  }
}

function validateLeaseReceipt(input, failure = false) {
  const fields = [
    "eventId",
    "workerId",
    "leaseVersion",
    ...(failure ? ["retryDelaySeconds", "errorCode"] : []),
  ];
  exactKeys(input, fields, "lease receipt");
  identifier(input.eventId, AUDIT_EVENT_ID, "eventId");
  nonEmptyString(input.workerId, "workerId", 128);
  positiveInteger(input.leaseVersion, "leaseVersion");
  if (failure) {
    positiveInteger(input.retryDelaySeconds, "retryDelaySeconds");
    nonEmptyString(input.errorCode, "errorCode", 64);
    if (input.retryDelaySeconds > MAX_OUTBOX_RETRY_SECONDS) {
      fail("INVALID_INPUT", "retryDelaySeconds is invalid.");
    }
  }
}

function outboxView(entry) {
  return Object.freeze({
    eventId: entry.eventId,
    event: clone(entry.event),
    status: entry.status,
    attemptCount: entry.attemptCount,
    leaseVersion: entry.leaseVersion,
    workerId: entry.workerId,
    leaseExpiresAt: entry.leaseExpiresAt,
    availableAt: entry.availableAt,
    publishedAt: entry.publishedAt,
    lastErrorCode: entry.lastErrorCode,
  });
}

function receiptView(entry) {
  return Object.freeze({
    idempotencyKey: entry.idempotencyKey,
    requestHash: entry.requestHash,
    eventId: entry.eventId,
    createdAt: entry.createdAt,
  });
}

function recoveryBody({ tenantId, events, receipts, outbox }) {
  return {
    schemaVersion: "c18-audit-recovery.v1",
    tenantId,
    tenantKind: "SYNTHETIC",
    events,
    receipts,
    outbox,
  };
}

function recoveryDocument(tenantId, state) {
  const body = recoveryBody({
    tenantId,
    events: state.events,
    receipts: [...state.receipts.values()].map(receiptView),
    outbox: [...state.outbox.values()]
      .filter((entry) => entry.status !== "PUBLISHED")
      .map(outboxView),
  });
  return {
    ...body,
    recoverySha256: auditEvidenceSha256(body),
  };
}

export function verifyAuditExport(document) {
  exactKeys(
    document,
    [
      "schemaVersion",
      "tenantId",
      "tenantKind",
      "events",
      "receipts",
      "outbox",
      "recoverySha256",
    ],
    "audit recovery bundle",
  );
  if (
    document.schemaVersion !== "c18-audit-recovery.v1" ||
    document.tenantKind !== "SYNTHETIC" ||
    !Array.isArray(document.events) ||
    !Array.isArray(document.receipts) ||
    !Array.isArray(document.outbox) ||
    !SHA256.test(document.recoverySha256 ?? "")
  ) {
    fail("INVALID_EXPORT", "Audit recovery bundle shape is invalid.");
  }
  validateTenantId(document.tenantId);
  let previous = GENESIS_HASH;
  const eventsById = new Map();
  for (let index = 0; index < document.events.length; index += 1) {
    const record = document.events[index];
    exactKeys(
      record,
      [
        "tenantId",
        "tenantKind",
        "eventId",
        "sequence",
        "previousEventHash",
        "eventHash",
        "payloadSha256",
        "payload",
        "createdAt",
      ],
      `events[${index}]`,
    );
    if (
      record.tenantId !== document.tenantId ||
      record.tenantKind !== "SYNTHETIC" ||
      record.sequence !== index + 1 ||
      record.previousEventHash !== previous ||
      auditEvidenceSha256(record.payload) !== record.payloadSha256 ||
      computeAuditEventHash(record) !== record.eventHash
    ) {
      fail("AUDIT_CHAIN_TAMPERED", "Audit export chain is invalid.");
    }
    identifier(record.eventId, AUDIT_EVENT_ID, "eventId");
    canonicalInstant(record.createdAt, "createdAt");
    assertValidAuditPayload(record.payload, {
      eventId: record.eventId,
      tenantId: record.tenantId,
      correlationId: record.payload?.correlationId,
      createdAt: record.createdAt,
    });
    if (eventsById.has(record.eventId)) {
      fail("AUDIT_CHAIN_TAMPERED", "Duplicate AuditEvent ID.");
    }
    eventsById.set(record.eventId, record);
    previous = record.eventHash;
  }
  const receiptKeys = new Set();
  const receiptEvents = new Set();
  for (const [index, receipt] of document.receipts.entries()) {
    exactKeys(
      receipt,
      ["idempotencyKey", "requestHash", "eventId", "createdAt"],
      `receipts[${index}]`,
    );
    if (
      !IDEMPOTENCY_KEY.test(receipt.idempotencyKey ?? "") ||
      !SHA256.test(receipt.requestHash ?? "") ||
      !eventsById.has(receipt.eventId) ||
      receiptKeys.has(receipt.idempotencyKey) ||
      receiptEvents.has(receipt.eventId)
    ) {
      fail("AUDIT_RECOVERY_TAMPERED", "Audit receipt is invalid.");
    }
    identifier(receipt.eventId, AUDIT_EVENT_ID, "receipt.eventId");
    canonicalInstant(receipt.createdAt, "receipt.createdAt");
    if (eventsById.get(receipt.eventId).createdAt !== receipt.createdAt) {
      fail("AUDIT_RECOVERY_TAMPERED", "Audit receipt time is invalid.");
    }
    receiptKeys.add(receipt.idempotencyKey);
    receiptEvents.add(receipt.eventId);
  }
  if (receiptEvents.size !== document.events.length) {
    fail("AUDIT_RECOVERY_TAMPERED", "Audit receipts are incomplete.");
  }

  const outboxEvents = new Set();
  for (const [index, entry] of document.outbox.entries()) {
    exactKeys(
      entry,
      [
        "eventId",
        "event",
        "status",
        "attemptCount",
        "leaseVersion",
        "workerId",
        "leaseExpiresAt",
        "availableAt",
        "publishedAt",
        "lastErrorCode",
      ],
      `outbox[${index}]`,
    );
    const event = eventsById.get(entry.eventId);
    if (
      !event ||
      outboxEvents.has(entry.eventId) ||
      !["PENDING", "FAILED", "PROCESSING"].includes(entry.status) ||
      !Number.isSafeInteger(entry.attemptCount) ||
      entry.attemptCount < 0 ||
      !Number.isSafeInteger(entry.leaseVersion) ||
      entry.leaseVersion < 0 ||
      canonicalizeAuditJson(entry.event) !==
        canonicalizeAuditJson(createAuditCloudEvent(event))
    ) {
      fail("AUDIT_RECOVERY_TAMPERED", "Recoverable Outbox is invalid.");
    }
    canonicalInstant(entry.availableAt, "outbox.availableAt");
    if (entry.publishedAt !== null) {
      fail("AUDIT_RECOVERY_TAMPERED", "Published Outbox is not recoverable.");
    }
    if (entry.status === "PROCESSING") {
      nonEmptyString(entry.workerId, "outbox.workerId", 128);
      canonicalInstant(entry.leaseExpiresAt, "outbox.leaseExpiresAt");
      if (entry.lastErrorCode !== null) {
        fail("AUDIT_RECOVERY_TAMPERED", "Processing Outbox is invalid.");
      }
    } else if (
      entry.workerId !== null ||
      entry.leaseExpiresAt !== null ||
      (entry.status === "PENDING" && entry.lastErrorCode !== null) ||
      (entry.status === "FAILED" &&
        (typeof entry.lastErrorCode !== "string" ||
          !entry.lastErrorCode))
    ) {
      fail("AUDIT_RECOVERY_TAMPERED", "Recoverable Outbox state is invalid.");
    }
    assertAuditMetadataOnly(entry.event);
    outboxEvents.add(entry.eventId);
  }
  const body = recoveryBody({
    tenantId: document.tenantId,
    events: document.events,
    receipts: document.receipts,
    outbox: document.outbox,
  });
  if (auditEvidenceSha256(body) !== document.recoverySha256) {
    fail("AUDIT_RECOVERY_TAMPERED", "Recovery bundle digest is invalid.");
  }
  return Object.freeze({
    tenantId: document.tenantId,
    eventCount: document.events.length,
    receiptCount: document.receipts.length,
    recoverableOutboxCount: document.outbox.length,
    headEventHash: previous,
  });
}

export function createMemoryAuditEvidenceStore({
  restoredExports = [],
  clock = () => new Date().toISOString(),
} = {}) {
  if (!Array.isArray(restoredExports) || typeof clock !== "function") {
    fail("INVALID_CONFIGURATION", "restoredExports must be an array.");
  }
  const tenants = new Map();
  let queue = Promise.resolve();

  for (const document of restoredExports) {
    verifyAuditExport(document);
    if (tenants.has(document.tenantId)) {
      fail("INVALID_EXPORT", "Duplicate restored Tenant.");
    }
    const state = tenantState();
    state.events = clone(document.events);
    const records = new Map(
      state.events.map((record) => [record.eventId, record]),
    );
    for (const receipt of document.receipts) {
      state.receipts.set(receipt.idempotencyKey, {
        ...clone(receipt),
        record: records.get(receipt.eventId),
      });
    }
    for (const raw of document.outbox) {
      const entry = clone(raw);
      if (entry.status === "PROCESSING") {
        entry.status = "FAILED";
        entry.workerId = null;
        entry.leaseExpiresAt = null;
        entry.lastErrorCode = "RECOVERY_REQUEUE";
      }
      state.outbox.set(entry.eventId, entry);
    }
    tenants.set(document.tenantId, state);
  }

  function stateFor(tenantId) {
    let state = tenants.get(tenantId);
    if (!state) {
      state = tenantState();
      tenants.set(tenantId, state);
    }
    return state;
  }

  async function locked(reducer) {
    const previous = queue;
    let release;
    queue = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await reducer();
    } finally {
      release();
    }
  }

  async function append(scope, input) {
    const trusted = validateScope(scope);
    validateAppendInput(input);
    if (
      input.payload.tenantId !== trusted.tenantId ||
      input.payload.tenantKind !== "SYNTHETIC" ||
      input.payload.correlationId !== trusted.correlationId
    ) {
      fail("TENANT_SCOPE_VIOLATION", "Audit payload escaped Tenant scope.");
    }
    return locked(async () => {
      const state = stateFor(trusted.tenantId);
      const existing = state.receipts.get(input.idempotencyKey);
      if (existing) {
        if (existing.requestHash !== input.requestHash) {
          fail("IDEMPOTENCY_CONFLICT", "Idempotency key was reused.");
        }
        return recordView(existing.record, true);
      }
      if (
        state.events.some((event) => event.eventId === input.eventId)
      ) {
        fail("ID_COLLISION", "Generated AuditEvent ID already exists.");
      }
      const previous = state.events.at(-1);
      const record = {
        tenantId: trusted.tenantId,
        tenantKind: "SYNTHETIC",
        eventId: input.eventId,
        sequence: state.events.length + 1,
        previousEventHash: previous?.eventHash ?? GENESIS_HASH,
        eventHash: null,
        payloadSha256: auditEvidenceSha256(input.payload),
        payload: clone(input.payload),
        createdAt: input.createdAt,
      };
      record.eventHash = computeAuditEventHash(record);
      const outbox = {
        eventId: record.eventId,
        event: createAuditCloudEvent(record),
        status: "PENDING",
        attemptCount: 0,
        leaseVersion: 0,
        workerId: null,
        leaseExpiresAt: null,
        availableAt: record.createdAt,
        publishedAt: null,
        lastErrorCode: null,
      };
      state.events.push(record);
      state.outbox.set(record.eventId, outbox);
      state.receipts.set(input.idempotencyKey, {
        idempotencyKey: input.idempotencyKey,
        requestHash: input.requestHash,
        eventId: record.eventId,
        createdAt: record.createdAt,
        record,
      });
      return recordView(record);
    });
  }

  async function query(scope, input) {
    const trusted = validateScope(scope);
    validateQuery(input);
    const state = stateFor(trusted.tenantId);
    return Object.freeze(
      state.events
        .filter(
          (event) =>
            event.sequence >= input.fromSequence &&
            event.sequence <= input.toSequence &&
            Date.parse(event.payload.occurredAt) >=
              Date.parse(input.fromOccurredAt) &&
            Date.parse(event.payload.occurredAt) <=
              Date.parse(input.toOccurredAt),
        )
        .slice(0, input.limit)
        .map((event) => clone(event)),
    );
  }

  async function exportChain(scope) {
    const trusted = validateScope(scope);
    return clone(recoveryDocument(
      trusted.tenantId,
      stateFor(trusted.tenantId),
    ));
  }

  async function claimOutbox(scope, input) {
    const trusted = validateScope(scope);
    validateLease(input);
    return locked(async () => {
      const now = canonicalInstant(clock(), "store clock");
      const leaseExpiresAt = addSeconds(
        now,
        input.leaseDurationSeconds,
      );
      const claimed = [];
      for (const entry of stateFor(trusted.tenantId).outbox.values()) {
        if (claimed.length >= input.limit) break;
        const available =
          (["PENDING", "FAILED"].includes(entry.status) &&
            Date.parse(entry.availableAt) <= Date.parse(now)) ||
          (entry.status === "PROCESSING" &&
            Date.parse(entry.leaseExpiresAt) <= Date.parse(now));
        if (!available) continue;
        entry.status = "PROCESSING";
        entry.attemptCount += 1;
        entry.leaseVersion += 1;
        entry.workerId = input.workerId;
        entry.leaseExpiresAt = leaseExpiresAt;
        entry.lastErrorCode = null;
        claimed.push(outboxView(entry));
      }
      return Object.freeze(claimed);
    });
  }

  async function completeOutbox(scope, input) {
    const trusted = validateScope(scope);
    validateLeaseReceipt(input);
    return locked(async () => {
      const now = canonicalInstant(clock(), "store clock");
      const entry = stateFor(trusted.tenantId).outbox.get(input.eventId);
      if (
        !entry ||
        entry.status !== "PROCESSING" ||
        entry.workerId !== input.workerId ||
        entry.leaseVersion !== input.leaseVersion ||
        Date.parse(entry.leaseExpiresAt) < Date.parse(now)
      ) {
        fail("STALE_OUTBOX_LEASE", "C18 Outbox lease is stale.");
      }
      entry.status = "PUBLISHED";
      entry.workerId = null;
      entry.leaseExpiresAt = null;
      entry.publishedAt = now;
      entry.lastErrorCode = null;
      return outboxView(entry);
    });
  }

  async function failOutbox(scope, input) {
    const trusted = validateScope(scope);
    validateLeaseReceipt(input, true);
    return locked(async () => {
      const now = canonicalInstant(clock(), "store clock");
      const entry = stateFor(trusted.tenantId).outbox.get(input.eventId);
      if (
        !entry ||
        entry.status !== "PROCESSING" ||
        entry.workerId !== input.workerId ||
        entry.leaseVersion !== input.leaseVersion ||
        Date.parse(entry.leaseExpiresAt) < Date.parse(now)
      ) {
        fail("STALE_OUTBOX_LEASE", "C18 Outbox lease is stale.");
      }
      entry.status = "FAILED";
      entry.workerId = null;
      entry.leaseExpiresAt = null;
      entry.availableAt = addSeconds(now, input.retryDelaySeconds);
      entry.publishedAt = null;
      entry.lastErrorCode = input.errorCode;
      return outboxView(entry);
    });
  }

  async function snapshot(scope) {
    const trusted = validateScope(scope);
    const state = stateFor(trusted.tenantId);
    return clone({
      events: state.events,
      outbox: [...state.outbox.values()].map(outboxView),
      receiptCount: state.receipts.size,
    });
  }

  return Object.freeze({
    append,
    query,
    exportChain,
    claimOutbox,
    completeOutbox,
    failOutbox,
    snapshot,
  });
}

function validateDependencies(dependencies) {
  if (
    typeof dependencies?.tenantRegistry?.admitNewRequest !== "function" ||
    typeof dependencies?.stablePrincipalRegistry?.resolveActionIdentity !==
      "function" ||
    typeof dependencies?.catalog?.resolve !== "function" ||
    typeof dependencies?.store?.append !== "function" ||
    typeof dependencies?.tenantScopeFactory !== "function" ||
    typeof dependencies?.clock !== "function" ||
    typeof dependencies?.idFactory !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C18 dependencies are incomplete.");
  }
}

export function createAuditEvidenceService({
  tenantRegistry,
  stablePrincipalRegistry,
  catalog,
  store,
  tenantScopeFactory,
  clock = () => new Date().toISOString(),
  idFactory = uuidV7,
}) {
  const dependencies = {
    tenantRegistry,
    stablePrincipalRegistry,
    catalog,
    store,
    tenantScopeFactory,
    clock,
    idFactory,
  };
  validateDependencies(dependencies);

  async function append(serverContext, request) {
    validateServerContext(serverContext);
    validateRequest(request);
    const identityRequest = {
      sessionToken: request.sessionToken,
      expectedTenantId: serverContext.tenantId,
      delegationId: request.delegationId,
    };
    const firstIdentity = validateIdentity(
      await stablePrincipalRegistry.resolveActionIdentity(
        serverContext,
        identityRequest,
      ),
      serverContext,
      request.delegationId,
    );
    const bundle = catalog.resolve(
      serverContext.tenantId,
      request.evidenceBundleRef,
    );
    const finalIdentity = validateIdentity(
      await stablePrincipalRegistry.resolveActionIdentity(
        serverContext,
        identityRequest,
      ),
      serverContext,
      request.delegationId,
    );
    if (!sameActionIdentity(firstIdentity, finalIdentity)) {
      fail(
        "ACTION_IDENTITY_CHANGED",
        "C05 action identity changed before C18 persistence.",
      );
    }
    const tenant = await tenantRegistry.admitNewRequest({
      tenantId: serverContext.tenantId,
      expectedTenantKind: "SYNTHETIC",
    });
    if (
      tenant?.tenantId !== serverContext.tenantId ||
      tenant?.tenantKind !== "SYNTHETIC"
    ) {
      fail("TENANT_SCOPE_VIOLATION", "C03 Tenant admission is invalid.");
    }
    positiveInteger(tenant.lifecycleVersion, "tenant.lifecycleVersion");
    const scope = validateScope(
      tenantScopeFactory({
        tenant,
        authorization: bundle.authorization,
        correlationId: request.correlationId,
      }),
    );
    if (
      scope.tenantId !== serverContext.tenantId ||
      scope.correlationId !== request.correlationId ||
      scope.decisionId !== bundle.authorization.decisionId ||
      scope.evidenceRef !== bundle.authorization.evidenceRef ||
      scope.policyVersion !== bundle.authorization.version
    ) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C18 scope is not bound to authorization evidence.",
      );
    }
    const createdAt = canonicalInstant(clock(), "clock");
    const eventId = generatedEventId(idFactory);
    const payload = payloadFor({
      eventId,
      tenantId: serverContext.tenantId,
      correlationId: request.correlationId,
      occurredAt: createdAt,
      identity: finalIdentity,
      bundle,
    });
    const requestHash = auditEvidenceSha256({
      tenantId: serverContext.tenantId,
      correlationId: request.correlationId,
      evidenceBundleRef: request.evidenceBundleRef,
      identitySha256: payload.identity.sha256,
    });
    return store.append(scope, {
      eventId,
      idempotencyKey: request.idempotencyKey,
      requestHash,
      payload,
      createdAt,
    });
  }

  return Object.freeze({ append });
}
