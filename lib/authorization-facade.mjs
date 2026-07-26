import { createHash } from "node:crypto";

const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SYNTHETIC_TENANT_ID = new RegExp(
  `^stn_${UUID_V7.source.slice(1, -1)}$`,
);
const POLICY_RELEASE_ID = new RegExp(
  `^azr_${UUID_V7.source.slice(1, -1)}$`,
);
const ACTIVATION_ID = new RegExp(
  `^aza_${UUID_V7.source.slice(1, -1)}$`,
);
const DECISION_ID = new RegExp(
  `^azd_${UUID_V7.source.slice(1, -1)}$`,
);
const OPENFGA_ID = /^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{26}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|profile|synthetic|test):\/\/\S+$/;
const RESOURCE_ID = /^[A-Za-z0-9._-]{1,128}$/;
const SURFACES = Object.freeze([
  "READ",
  "RETRIEVE",
  "DOWNLOAD",
  "MANAGE",
  "TOOL_CALL",
  "SANDBOX_RUN",
]);
const COMMAND_CAPABILITIES = Object.freeze({
  STAGE_SYNTHETIC_POLICY_RELEASE: "AUTHORIZATION_POLICY_STAGE",
  RECORD_POLICY_PROJECTION: "AUTHORIZATION_POLICY_PROJECT",
  ACTIVATE_POLICY_RELEASE: "AUTHORIZATION_POLICY_ACTIVATE",
  ROLLBACK_POLICY_RELEASE: "AUTHORIZATION_POLICY_ROLLBACK",
});

export class AuthorizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AuthorizationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new AuthorizationError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function exactKeys(value, allowed, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    fail("INVALID_INPUT", `${field} has unsupported fields.`);
  }
}

function nonEmptyString(value, field, maxLength = 256) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function positiveInteger(value, field, { allowZero = false } = {}) {
  const minimum = allowZero ? 0 : 1;
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function syntheticTenantId(value) {
  nonEmptyString(value, "tenantId", 80);
  if (!SYNTHETIC_TENANT_ID.test(value)) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "C06 accepts only Synthetic Tenant IDs before P3.",
    );
  }
}

function reference(value, field) {
  nonEmptyString(value, field, 512);
  if (!REFERENCE.test(value)) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      `${field} must be an approved P1 reference.`,
    );
  }
}

function sha256String(value, field) {
  if (!SHA256.test(value ?? "")) {
    fail("INVALID_INPUT", `${field} must be a SHA-256 reference.`);
  }
}

function identifier(value, expression, field) {
  nonEmptyString(value, field, 128);
  if (!expression.test(value)) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("INVALID_INPUT", "Only finite JSON numbers are supported.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("INVALID_INPUT", "Only JSON values are supported.");
}

function sha256(value) {
  return `sha256:${createHash("sha256")
    .update(typeof value === "string" ? value : canonicalize(value))
    .digest("hex")}`;
}

function uuidV7() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let milliseconds = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(milliseconds & 0xffn);
    milliseconds >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
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

function canonicalInstant(value, field) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${field} must be a canonical UTC instant.`);
  }
  return value;
}

function operationMap(document) {
  if (
    document?.schema_version !== "1.0.0" ||
    document?.data_classification !== "SYNTHETIC_ONLY" ||
    !Array.isArray(document.operations) ||
    document.operations.length !== SURFACES.length
  ) {
    fail("INVALID_POLICY_CATALOG", "Protected operation catalog is invalid.");
  }
  const result = new Map();
  for (const operation of document.operations) {
    exactKeys(
      operation,
      [
        "surface",
        "resource_type",
        "human_relation",
        "actor_relation",
        "purpose_relation",
        "purpose_ref",
      ],
      "protected operation",
    );
    if (
      !SURFACES.includes(operation.surface) ||
      result.has(operation.surface)
    ) {
      fail("INVALID_POLICY_CATALOG", "Protected surfaces are not exact.");
    }
    for (const field of [
      "resource_type",
      "human_relation",
      "actor_relation",
      "purpose_relation",
    ]) {
      if (!/^[a-z][a-z0-9_]{0,63}$/.test(operation[field] ?? "")) {
        fail("INVALID_POLICY_CATALOG", "OpenFGA relation is invalid.");
      }
    }
    reference(operation.purpose_ref, "purpose_ref");
    result.set(operation.surface, Object.freeze(clone(operation)));
  }
  if (SURFACES.some((surface) => !result.has(surface))) {
    fail("INVALID_POLICY_CATALOG", "A protected surface is missing.");
  }
  return result;
}

export function createSyntheticAuthorizationCatalog({
  policyCatalog,
  protectedOperations,
  fixtures,
  model,
}) {
  const operations = operationMap(protectedOperations);
  if (
    policyCatalog?.schema_version !== "1.0.0" ||
    policyCatalog?.data_classification !== "SYNTHETIC_ONLY" ||
    policyCatalog?.enterprise_connectors !== "C0_DISABLED" ||
    policyCatalog?.policy_bundle_hash_semantics !==
      "FROZEN_TEMPLATE_DEFINITION" ||
    policyCatalog?.tuple_bundle_hash_semantics !==
      "TENANT_PROJECTED_OPENFGA_TUPLE_SET" ||
    !Array.isArray(policyCatalog.release_templates) ||
    policyCatalog.release_templates.length < 2
  ) {
    fail("INVALID_POLICY_CATALOG", "Synthetic policy catalog is invalid.");
  }
  if (
    fixtures?.schema_version !== "1.0.0" ||
    fixtures?.data_classification !== "SYNTHETIC_ONLY" ||
    fixtures?.fixture_case_count !== 60 ||
    fixtures.operations?.length * fixtures.scenarios?.length !== 60
  ) {
    fail("INVALID_POLICY_CATALOG", "C06 fixture matrix must freeze 60 cases.");
  }
  if (
    model?.schema_version !== "1.1" ||
    !Array.isArray(model.type_definitions) ||
    model.type_definitions.length === 0
  ) {
    fail("INVALID_POLICY_CATALOG", "OpenFGA model is invalid.");
  }
  if (
    policyCatalog.model?.sha256 !== sha256(JSON.stringify(model, null, 2) + "\n") ||
    policyCatalog.model?.canonical_sha256 !== sha256(model) ||
    policyCatalog.protected_operations?.sha256 !==
      sha256(JSON.stringify(protectedOperations, null, 2) + "\n") ||
    policyCatalog.facade_fixtures?.sha256 !==
      sha256(JSON.stringify(fixtures, null, 2) + "\n")
  ) {
    fail("INVALID_POLICY_CATALOG", "Catalog artifact hash is invalid.");
  }

  const templates = new Map();
  let previousSequence = 0;
  for (const template of policyCatalog.release_templates) {
    exactKeys(
      template,
      [
        "template_ref",
        "sequence",
        "tuple_set_variant",
        "bundle_sha256",
        "pdp_fixture_case_count",
        "facade_fixture_case_count",
        "migration_expectation",
        "additional_relationships",
      ],
      "policy release template",
    );
    reference(template.template_ref, "template_ref");
    positiveInteger(template.sequence, "sequence");
    sha256String(template.bundle_sha256, "bundle_sha256");
    if (
      template.sequence !== previousSequence + 1 ||
      !["BASELINE", "NOAH_READ_ADDED"].includes(
        template.tuple_set_variant,
      ) ||
      template.pdp_fixture_case_count !== 30 ||
      template.facade_fixture_case_count !== 60 ||
      !["ALLOW", "DENY"].includes(template.migration_expectation) ||
      templates.has(template.template_ref)
    ) {
      fail("INVALID_POLICY_CATALOG", "Policy template sequence is invalid.");
    }
    const expectedBundleSha256 = sha256({
      schemaVersion: "c06-policy-template-bundle-v1",
      templateRef: template.template_ref,
      sequence: template.sequence,
      tupleSetVariant: template.tuple_set_variant,
      modelSha256: policyCatalog.model.canonical_sha256,
      protectedOperationsSha256:
        policyCatalog.protected_operations.sha256,
      facadeFixturesSha256: policyCatalog.facade_fixtures.sha256,
      pdpFixtureCaseCount: template.pdp_fixture_case_count,
      facadeFixtureCaseCount: template.facade_fixture_case_count,
      migrationExpectation: template.migration_expectation,
      additionalRelationships: template.additional_relationships ?? [],
    });
    if (template.bundle_sha256 !== expectedBundleSha256) {
      fail(
        "INVALID_POLICY_CATALOG",
        "Policy template bundle hash is invalid.",
      );
    }
    if (
      template.tuple_set_variant === "BASELINE" &&
      template.additional_relationships !== undefined
    ) {
      fail("INVALID_POLICY_CATALOG", "Baseline cannot add relationships.");
    }
    templates.set(
      template.template_ref,
      Object.freeze({
        ...clone(template),
        model: clone(model),
        modelSha256: policyCatalog.model.canonical_sha256,
        operationCatalogVersion: protectedOperations.catalog_version,
        fixtureVersion: fixtures.fixture_version,
      }),
    );
    previousSequence = template.sequence;
  }

  return Object.freeze({
    operation(surface) {
      const value = operations.get(surface);
      if (!value) fail("UNKNOWN_SURFACE", "Protected surface is unknown.");
      return value;
    },
    template(templateRef) {
      const value = templates.get(templateRef);
      if (!value) {
        fail(
          "SYNTHETIC_BOUNDARY_VIOLATION",
          "Policy release template is not frozen.",
        );
      }
      return clone(value);
    },
    fixtures() {
      return clone(fixtures);
    },
    listTemplates() {
      return clone(Array.from(templates.values()));
    },
  });
}

function fixturePrincipalRef(fixtureId, suffix) {
  return `fixture://${fixtureId}${suffix}`;
}

function objectId(fixtureId, surface) {
  return `${fixtureId}--${surface.toLowerCase().replaceAll("_", "-")}`;
}

export function buildSyntheticPolicyTuples({
  catalog,
  templateRef,
  fixtureId,
  principalIdsByFixtureRef,
}) {
  nonEmptyString(fixtureId, "fixtureId", 128);
  if (!principalIdsByFixtureRef || typeof principalIdsByFixtureRef !== "object") {
    fail("INVALID_INPUT", "Principal fixture mapping is required.");
  }
  const template = catalog.template(templateRef);
  const tuples = [];
  for (const surface of SURFACES) {
    const operation = catalog.operation(surface);
    const humanRef = fixturePrincipalRef(
      fixtureId,
      "/principals/ava",
    );
    const actorRef = fixturePrincipalRef(
      fixtureId,
      "/principals/assistant-agent",
    );
    const humanId = principalIdsByFixtureRef[humanRef];
    const actorId = principalIdsByFixtureRef[actorRef];
    identifier(humanId, /^prn_[0-9a-f-]{36}$/, "human principal");
    identifier(actorId, /^prn_[0-9a-f-]{36}$/, "actor principal");
    const object = `${operation.resource_type}:${objectId(
      fixtureId,
      surface,
    )}`;
    tuples.push(
      {
        user: `human:${humanId}`,
        relation: operation.human_relation,
        object,
      },
      {
        user: `workload:${actorId}`,
        relation: operation.actor_relation,
        object,
      },
      {
        user: `purpose_scope:${sha256(operation.purpose_ref).slice(7)}`,
        relation: operation.purpose_relation,
        object,
      },
    );
  }
  for (const addition of template.additional_relationships ?? []) {
    const operation = catalog.operation(addition.surface);
    const principalRef = fixturePrincipalRef(
      fixtureId,
      addition.subject_fixture_principal_suffix,
    );
    const principalId = principalIdsByFixtureRef[principalRef];
    identifier(principalId, /^prn_[0-9a-f-]{36}$/, "additional principal");
    if (addition.factor !== "HUMAN") {
      fail("INVALID_POLICY_CATALOG", "Additional factor is invalid.");
    }
    tuples.push({
      user: `human:${principalId}`,
      relation: operation.human_relation,
      object: `${operation.resource_type}:${objectId(
        fixtureId,
        addition.surface,
      )}`,
    });
  }
  return Object.freeze(tuples.map((tuple) => Object.freeze(tuple)));
}

export function hashSyntheticPolicyTuples(tuples) {
  if (!Array.isArray(tuples) || tuples.length < 1 || tuples.length > 100) {
    fail("INVALID_INPUT", "Synthetic Policy Tuple bundle is invalid.");
  }
  const normalized = tuples
    .map((tuple) => {
      exactKeys(tuple, ["user", "relation", "object"], "policy tuple");
      for (const field of ["user", "relation", "object"]) {
        nonEmptyString(tuple[field], `policy tuple ${field}`, 512);
      }
      return {
        user: tuple.user,
        relation: tuple.relation,
        object: tuple.object,
      };
    })
    .sort((left, right) =>
      canonicalize(left).localeCompare(canonicalize(right)),
    );
  return sha256(normalized);
}

function eventRecord({
  idFactory,
  clock,
  type,
  subject,
  tenantId,
  correlationId,
  data,
}) {
  const event = {
    specversion: "1.0",
    id: `evt_${idFactory()}`,
    source: "/product-core/authorization",
    type,
    subject,
    time: canonicalInstant(clock(), "clock"),
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: correlationId,
    synthetic: true,
    data: {
      tenant_id: tenantId,
      ...clone(data),
    },
  };
  identifier(event.id, new RegExp(`^evt_${UUID_V7.source.slice(1, -1)}$`), "eventId");
  return event;
}

function receiptKey(tenantId, idempotencyKey) {
  return `${tenantId}\u0000${idempotencyKey}`;
}

function transaction(draft) {
  return Object.freeze({
    findReleaseByTemplate(tenantId, templateRef) {
      return clone(
        draft.releases.find(
          (release) =>
            release.tenantId === tenantId &&
            release.templateRef === templateRef &&
            release.state !== "FAILED",
        ) ?? null,
      );
    },
    findRelease(releaseId) {
      return clone(
        draft.releases.find(
          (release) => release.policyReleaseId === releaseId,
        ) ?? null,
      );
    },
    listReleases(tenantId) {
      return clone(
        draft.releases.filter((release) => release.tenantId === tenantId),
      );
    },
    insertRelease(release) {
      const matchingTemplateOrSequence = draft.releases.filter(
        (value) =>
          value.tenantId === release.tenantId &&
          (value.templateRef === release.templateRef ||
            value.templateSequence === release.templateSequence),
      );
      if (
        draft.releases.some(
          (value) => value.policyReleaseId === release.policyReleaseId,
        ) ||
        matchingTemplateOrSequence.some(
          (value) =>
            value.state !== "FAILED" ||
            value.tenantKind !== release.tenantKind ||
            value.templateRef !== release.templateRef ||
            value.templateSequence !== release.templateSequence ||
            value.fixtureId !== release.fixtureId ||
            value.bundleSha256 !== release.bundleSha256 ||
            value.modelSha256 !== release.modelSha256 ||
            value.operationCatalogVersion !==
              release.operationCatalogVersion ||
            value.fixtureVersion !== release.fixtureVersion,
        )
      ) {
        fail("RELEASE_CONFLICT", "Policy Release already exists.");
      }
      draft.releases.push(clone(release));
    },
    putRelease(release) {
      const index = draft.releases.findIndex(
        (value) => value.policyReleaseId === release.policyReleaseId,
      );
      if (index === -1) fail("RELEASE_NOT_FOUND", "Policy Release not found.");
      const current = draft.releases[index];
      for (const field of [
        "policyReleaseId",
        "tenantId",
        "tenantKind",
        "fixtureId",
        "templateRef",
        "templateSequence",
        "bundleSha256",
        "modelSha256",
        "createdAt",
      ]) {
        if (current[field] !== release[field]) {
          fail("RELEASE_IMMUTABLE", "Policy Release identity is immutable.");
        }
      }
      draft.releases[index] = clone(release);
    },
    activePolicy(tenantId) {
      return clone(draft.activePolicies[tenantId] ?? null);
    },
    activate(value) {
      const current = draft.activePolicies[value.tenantId];
      if (
        (current?.activationVersion ?? 0) + 1 !== value.activationVersion
      ) {
        fail("ACTIVATION_CONFLICT", "Policy activation version changed.");
      }
      draft.activePolicies[value.tenantId] = clone(value);
      draft.activations.push(clone(value));
    },
    appendEvent(event) {
      if (draft.events.some(({ id }) => id === event.id)) {
        fail("ID_COLLISION", "Authorization event already exists.");
      }
      draft.events.push(clone(event));
      draft.outbox.push(clone(event));
    },
  });
}

export function createMemoryAuthorizationStore() {
  let state = {
    releases: [],
    activePolicies: {},
    activations: [],
    decisions: [],
    events: [],
    outbox: [],
    receipts: {},
  };
  let queue = Promise.resolve();

  function serial(work) {
    const result = queue.then(work, work);
    queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  return Object.freeze({
    async readCommandReceipt({
      tenantId,
      idempotencyKey,
      commandHash,
    }) {
      await queue;
      const receipt = state.receipts[
        receiptKey(tenantId, idempotencyKey)
      ];
      if (!receipt) return null;
      if (receipt.commandHash !== commandHash) {
        fail(
          "IDEMPOTENCY_CONFLICT",
          "Idempotency key was used for another C06 command.",
        );
      }
      return clone(receipt.value);
    },
    async readPolicyRelease(policyReleaseId) {
      await queue;
      return clone(
        state.releases.find(
          (release) => release.policyReleaseId === policyReleaseId,
        ) ?? null,
      );
    },
    runCommand({ tenantId, idempotencyKey, commandHash }, reducer) {
      return serial(async () => {
        const key = receiptKey(tenantId, idempotencyKey);
        const receipt = state.receipts[key];
        if (receipt) {
          if (receipt.commandHash !== commandHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Idempotency key was used for another C06 command.",
            );
          }
          return { duplicate: true, value: clone(receipt.value) };
        }
        const draft = structuredClone(state);
        const value = await reducer(transaction(draft));
        draft.receipts[key] = {
          tenantId,
          idempotencyKey,
          commandHash,
          value: clone(value),
        };
        state = draft;
        return { duplicate: false, value: clone(value) };
      });
    },
    async readActiveRelease(tenantId) {
      await queue;
      const active = state.activePolicies[tenantId];
      if (!active) return null;
      const release = state.releases.find(
        (value) => value.policyReleaseId === active.policyReleaseId,
      );
      return clone({ active, release });
    },
    recordDecision({
      tenantId,
      expectedPolicyReleaseId,
      expectedActivationVersion,
      decision,
      event,
    }) {
      return serial(async () => {
        const existing = state.decisions.find(
          (value) => value.decisionId === decision.decisionId,
        );
        if (existing) {
          const storedEvent = state.events.find(
            (value) =>
              value.type ===
                "product.authorization.decision-recorded.v1" &&
              value.subject === decision.decisionId,
          );
          const storedOutbox = state.outbox.find(
            (value) => value.id === storedEvent?.id,
          );
          if (
            existing.tenantId !== tenantId ||
            existing.policyReleaseId !== expectedPolicyReleaseId ||
            existing.activationVersion !== expectedActivationVersion ||
            !storedEvent ||
            !storedOutbox ||
            canonicalize(existing) !== canonicalize(decision) ||
            canonicalize(storedEvent) !== canonicalize(event) ||
            canonicalize(storedOutbox) !== canonicalize(event)
          ) {
            fail("ID_COLLISION", "Authorization decision already exists.");
          }
          return clone(existing);
        }
        const active = state.activePolicies[tenantId];
        if (
          !active ||
          active.policyReleaseId !== expectedPolicyReleaseId ||
          active.activationVersion !== expectedActivationVersion
        ) {
          fail(
            "AUTHORIZATION_CHANGED",
            "Active policy changed during authorization.",
          );
        }
        const draft = structuredClone(state);
        draft.decisions.push(clone(decision));
        draft.events.push(clone(event));
        draft.outbox.push(clone(event));
        state = draft;
        return clone(decision);
      });
    },
    async readDecision(decisionId) {
      await queue;
      return clone(
        state.decisions.find(
          (decision) => decision.decisionId === decisionId,
        ) ?? null,
      );
    },
    async readTenantSnapshot(tenantId) {
      await queue;
      return clone({
        releases: state.releases.filter(
          (release) => release.tenantId === tenantId,
        ),
        activePolicy: state.activePolicies[tenantId] ?? null,
        activations: state.activations.filter(
          (activation) => activation.tenantId === tenantId,
        ),
        decisions: state.decisions.filter(
          (decision) => decision.tenantId === tenantId,
        ),
        events: state.events.filter(
          (event) => event.data?.tenant_id === tenantId,
        ),
        outbox: state.outbox.filter(
          (event) => event.data?.tenant_id === tenantId,
        ),
      });
    },
  });
}

function validateCommand(command) {
  exactKeys(
    command,
    Object.keys(command ?? {}),
    "authorization command",
  );
  const common = ["kind", "tenantId", "idempotencyKey", "correlationId"];
  if (!Object.hasOwn(COMMAND_CAPABILITIES, command.kind)) {
    fail("INVALID_COMMAND", "Unknown authorization command.");
  }
  syntheticTenantId(command.tenantId);
  nonEmptyString(command.idempotencyKey, "idempotencyKey", 128);
  nonEmptyString(command.correlationId, "correlationId", 128);
  if (command.kind === "STAGE_SYNTHETIC_POLICY_RELEASE") {
    exactKeys(command, [...common, "templateRef"], "stage command");
    reference(command.templateRef, "templateRef");
    return;
  }
  if (command.kind === "RECORD_POLICY_PROJECTION") {
    exactKeys(
      command,
      [
        ...common,
        "policyReleaseId",
        "projectionOperationId",
        "outcome",
        "openFgaStoreId",
        "authorizationModelId",
        "tupleBundleSha256",
        "fixtureReportRef",
        "fixtureReportSha256",
        "fixturePassCount",
        "fixtureFailCount",
        "reasonRef",
      ],
      "projection command",
    );
    identifier(command.policyReleaseId, POLICY_RELEASE_ID, "policyReleaseId");
    nonEmptyString(
      command.projectionOperationId,
      "projectionOperationId",
      128,
    );
    if (!["READY", "FAILED"].includes(command.outcome)) {
      fail("INVALID_COMMAND", "Projection outcome is invalid.");
    }
    if (command.outcome === "READY") {
      identifier(command.openFgaStoreId, OPENFGA_ID, "openFgaStoreId");
      identifier(
        command.authorizationModelId,
        OPENFGA_ID,
        "authorizationModelId",
      );
      sha256String(command.tupleBundleSha256, "tupleBundleSha256");
      reference(command.fixtureReportRef, "fixtureReportRef");
      sha256String(command.fixtureReportSha256, "fixtureReportSha256");
      positiveInteger(command.fixturePassCount, "fixturePassCount");
      positiveInteger(command.fixtureFailCount, "fixtureFailCount", {
        allowZero: true,
      });
      if (command.reasonRef !== null) {
        fail("INVALID_COMMAND", "READY projection cannot have a reason.");
      }
    } else {
      reference(command.reasonRef, "reasonRef");
      for (const field of [
        "openFgaStoreId",
        "authorizationModelId",
        "tupleBundleSha256",
        "fixtureReportRef",
        "fixtureReportSha256",
        "fixturePassCount",
        "fixtureFailCount",
      ]) {
        if (command[field] !== null) {
          fail("INVALID_COMMAND", "FAILED projection fields must be null.");
        }
      }
    }
    return;
  }
  if (command.kind === "ACTIVATE_POLICY_RELEASE") {
    exactKeys(
      command,
      [
        ...common,
        "policyReleaseId",
        "expectedActivationVersion",
        "reasonRef",
      ],
      "activation command",
    );
  } else {
    exactKeys(
      command,
      [
        ...common,
        "targetPolicyReleaseId",
        "expectedActivationVersion",
        "reasonRef",
      ],
      "rollback command",
    );
    command.policyReleaseId = command.targetPolicyReleaseId;
  }
  identifier(command.policyReleaseId, POLICY_RELEASE_ID, "policyReleaseId");
  positiveInteger(
    command.expectedActivationVersion,
    "expectedActivationVersion",
    { allowZero: true },
  );
  reference(command.reasonRef, "reasonRef");
}

function safeProjection(command, template) {
  if (command.outcome === "FAILED") {
    return {
      state: "FAILED",
      projectionOperationId: command.projectionOperationId,
      projectionReasonRef: command.reasonRef,
    };
  }
  if (
    command.fixturePassCount !== template.pdp_fixture_case_count ||
    command.fixtureFailCount !== 0
  ) {
    fail(
      "PROJECTION_EVIDENCE_INVALID",
      "Projection result does not match the frozen Policy Release.",
    );
  }
  return {
    state: "READY",
    projectionOperationId: command.projectionOperationId,
    openFgaStoreId: command.openFgaStoreId,
    authorizationModelId: command.authorizationModelId,
    tupleBundleSha256: command.tupleBundleSha256,
    fixtureReportRef: command.fixtureReportRef,
    fixtureReportSha256: command.fixtureReportSha256,
    fixturePassCount: command.fixturePassCount,
    fixtureFailCount: command.fixtureFailCount,
  };
}

function assertVerifiedPolicyRelease(release, verification) {
  if (
    verification?.passed !== true ||
    verification.fixturePassCount !== release.fixturePassCount ||
    verification.fixtureFailCount !== 0 ||
    verification.policyBundleSha256 !== release.bundleSha256 ||
    verification.tupleBundleSha256 !== release.tupleBundleSha256 ||
    verification.fixtureReportSha256 !== release.fixtureReportSha256 ||
    verification.modelSha256 !== release.modelSha256 ||
    verification.openFgaStoreId !== release.openFgaStoreId ||
    verification.authorizationModelId !== release.authorizationModelId
  ) {
    fail(
      "POLICY_REPLAY_FAILED",
      "Policy Release replay did not match frozen evidence.",
    );
  }
}

function compareIdentity(first, second) {
  return canonicalize(first) === canonicalize(second);
}

function validateIdentity(identity, tenantId) {
  if (
    identity?.tenantId !== tenantId ||
    identity?.tenantKind !== "SYNTHETIC" ||
    identity?.authorizationStatus !== "NOT_EVALUATED" ||
    identity?.humanSubject?.principalType !== "HUMAN" ||
    !["AGENT", "SERVICE"].includes(
      identity?.workloadActor?.principalType,
    ) ||
    !Array.isArray(identity?.delegationChain) ||
    identity.delegationChain.length === 0 ||
    identity.delegationChain.length > 8 ||
    typeof identity.purposeRef !== "string"
  ) {
    fail("IDENTITY_UNVERIFIED", "Stable Principal context is invalid.");
  }
}

function validateResource(resource, operation, tenantId, resourceId) {
  if (
    resource?.tenantId !== tenantId ||
    resource?.tenantKind !== "SYNTHETIC"
  ) {
    fail(
      "RESOURCE_TENANT_MISMATCH",
      "Protected resource does not belong to the trusted Tenant.",
    );
  }
  if (
    !resource ||
    resource.resourceType !== operation.resource_type ||
    resource.resourceId !== resourceId ||
    resource.state !== "ACTIVE" ||
    !Number.isSafeInteger(resource.authorizationVersion) ||
    resource.authorizationVersion < 1 ||
    resource.trustSource !== "VERIFIED_RESOURCE_CONTEXT"
  ) {
    fail("RESOURCE_UNVERIFIED", "Protected resource context is invalid.");
  }
}

function checkTuple(operation, resource, identity, factor) {
  const object = `${operation.resource_type}:${resource.resourceId}`;
  if (factor === "HUMAN") {
    return {
      user: `human:${identity.humanSubject.principalId}`,
      relation: operation.human_relation,
      object,
    };
  }
  if (factor === "ACTOR") {
    return {
      user: `workload:${identity.workloadActor.principalId}`,
      relation: operation.actor_relation,
      object,
    };
  }
  return {
    user: `purpose_scope:${sha256(identity.purposeRef).slice(7)}`,
    relation: operation.purpose_relation,
    object,
  };
}

function decisionReason(results) {
  if (!results.human) return "HUMAN_DENIED";
  if (!results.actor) return "ACTOR_DENIED";
  if (!results.purpose) return "PURPOSE_DENIED";
  return "ALL_FACTORS_ALLOWED";
}

export function createAuthorizationFacade({
  store,
  tenantRegistry,
  stablePrincipalRegistry,
  policyCatalog,
  resolveTenantFixture,
  resolveResource,
  pdpFactory,
  verifyPolicyRelease,
  authorizeControl,
  clock = () => new Date().toISOString(),
  idFactory = uuidV7,
}) {
  if (
    !store?.runCommand ||
    !store?.readCommandReceipt ||
    !store?.readPolicyRelease ||
    !store?.readActiveRelease ||
    !store?.recordDecision ||
    !store?.readDecision ||
    !store?.readTenantSnapshot ||
    !tenantRegistry?.admitNewRequest ||
    !stablePrincipalRegistry?.resolveActionIdentity ||
    !policyCatalog?.template ||
    !policyCatalog?.operation ||
    typeof resolveTenantFixture !== "function" ||
    typeof resolveResource !== "function" ||
    typeof pdpFactory !== "function" ||
    typeof verifyPolicyRelease !== "function" ||
    typeof authorizeControl !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C06 dependencies are incomplete.");
  }

  async function controlAllowed(context, capability) {
    try {
      return (await authorizeControl(context, capability)) === true;
    } catch {
      return false;
    }
  }

  function newReleaseId() {
    return generatedId("azr_", POLICY_RELEASE_ID, idFactory, "policyReleaseId");
  }

  function newActivationId() {
    return generatedId("aza_", ACTIVATION_ID, idFactory, "activationId");
  }

  function newDecisionId() {
    return generatedId("azd_", DECISION_ID, idFactory, "decisionId");
  }

  async function execute(context, originalCommand) {
    const command = clone(originalCommand);
    validateCommand(command);
    const capability = COMMAND_CAPABILITIES[command.kind];
    if (!(await controlAllowed(context, capability))) {
      fail("UNAUTHORIZED", "Authorization control command is not authorized.");
    }
    if (
      command.kind === "RECORD_POLICY_PROJECTION" &&
      context?.projectionTrustSource !== "VERIFIED_PROJECTION_WORKER"
    ) {
      fail("UNAUTHORIZED", "Projection result source is not verified.");
    }
    const commandHash = sha256({
      actorId: context?.actorId,
      command,
    });
    const replay = await store.readCommandReceipt?.({
      tenantId: command.tenantId,
      idempotencyKey: command.idempotencyKey,
      commandHash,
    });
    if (replay) return { ...replay, duplicate: true };

    const admission = await tenantRegistry.admitNewRequest({
      tenantId: command.tenantId,
      expectedTenantKind: "SYNTHETIC",
    });
    const prepared = { admission };
    if (command.kind === "STAGE_SYNTHETIC_POLICY_RELEASE") {
      prepared.fixture = await resolveTenantFixture(command.tenantId);
    }
    if (
      command.kind === "RECORD_POLICY_PROJECTION" &&
      command.outcome === "READY"
    ) {
      const release = await store.readPolicyRelease(
        command.policyReleaseId,
      );
      if (
        !release ||
        release.tenantId !== command.tenantId ||
        release.state !== "STAGED"
      ) {
        fail("RELEASE_NOT_READY", "Policy Release is not staged.");
      }
      const candidate = {
        ...release,
        ...safeProjection(
          command,
          policyCatalog.template(release.templateRef),
        ),
      };
      try {
        assertVerifiedPolicyRelease(
          candidate,
          await verifyPolicyRelease(clone(candidate)),
        );
      } catch (error) {
        if (error instanceof AuthorizationError) throw error;
        fail(
          "POLICY_REPLAY_FAILED",
          "Policy Release projection replay did not complete.",
        );
      }
    }
    if (
      command.kind === "ACTIVATE_POLICY_RELEASE" ||
      command.kind === "ROLLBACK_POLICY_RELEASE"
    ) {
      const targetId =
        command.kind === "ROLLBACK_POLICY_RELEASE"
          ? command.targetPolicyReleaseId
          : command.policyReleaseId;
      const release = await store.readPolicyRelease?.(targetId);
      if (
        !release ||
        release.tenantId !== command.tenantId ||
        release.state !== "READY"
      ) {
        fail("RELEASE_NOT_READY", "Policy Release is not ready.");
      }
      try {
        assertVerifiedPolicyRelease(
          release,
          await verifyPolicyRelease(clone(release)),
        );
      } catch (error) {
        if (error instanceof AuthorizationError) throw error;
        fail(
          "POLICY_REPLAY_FAILED",
          "Policy Release replay did not complete.",
        );
      }
      prepared.verifiedRelease = release;
    }

    const result = await store.runCommand(
      {
        tenantId: command.tenantId,
        idempotencyKey: command.idempotencyKey,
        commandHash,
      },
      async (tx) => {
        if (command.kind === "STAGE_SYNTHETIC_POLICY_RELEASE") {
          const existing = await tx.findReleaseByTemplate(
            command.tenantId,
            command.templateRef,
          );
          if (existing) return { ...existing, duplicate: true };
          const template = policyCatalog.template(command.templateRef);
          const fixture = prepared.fixture;
          if (
            fixture?.tenantId !== command.tenantId ||
            typeof fixture.fixtureId !== "string" ||
            fixture.tenantKind !== "SYNTHETIC"
          ) {
            fail(
              "SYNTHETIC_BOUNDARY_VIOLATION",
              "Tenant fixture mapping is invalid.",
            );
          }
          const releases = await tx.listReleases(command.tenantId);
          const sameSequence = releases.filter(
            (release) =>
              release.templateSequence === template.sequence,
          );
          const retryingFailedTemplate =
            sameSequence.length > 0 &&
            sameSequence.every(
              (release) =>
                release.state === "FAILED" &&
                release.templateRef === template.template_ref &&
                release.fixtureId === fixture.fixtureId &&
                release.bundleSha256 === template.bundle_sha256 &&
                release.modelSha256 === template.modelSha256 &&
                release.operationCatalogVersion ===
                  template.operationCatalogVersion &&
                release.fixtureVersion === template.fixtureVersion,
            );
          const seenSequences = new Set(
            releases.map((release) => release.templateSequence),
          );
          const stagingNextTemplate =
            sameSequence.length === 0 &&
            Array.from(
              { length: template.sequence - 1 },
              (_, index) => index + 1,
            ).every((sequence) => seenSequences.has(sequence)) &&
            releases.every(
              (release) =>
                release.templateSequence < template.sequence,
            );
          if (!retryingFailedTemplate && !stagingNextTemplate) {
            fail(
              "RELEASE_SEQUENCE_INVALID",
              "Policy Release templates must be staged in order.",
            );
          }
          const now = canonicalInstant(clock(), "clock");
          const release = {
            policyReleaseId: newReleaseId(),
            tenantId: command.tenantId,
            tenantKind: "SYNTHETIC",
            tenantLifecycleVersion: prepared.admission.lifecycleVersion,
            fixtureId: fixture.fixtureId,
            templateRef: template.template_ref,
            templateSequence: template.sequence,
            bundleSha256: template.bundle_sha256,
            modelSha256: template.modelSha256,
            operationCatalogVersion: template.operationCatalogVersion,
            fixtureVersion: template.fixtureVersion,
            state: "STAGED",
            createdAt: now,
            updatedAt: now,
          };
          await tx.insertRelease(release);
          const event = eventRecord({
            idFactory,
            clock,
            type: "product.authorization.policy-release-staged.v1",
            subject: release.policyReleaseId,
            tenantId: command.tenantId,
            correlationId: command.correlationId,
            data: {
              policy_release_id: release.policyReleaseId,
              template_ref: release.templateRef,
              bundle_sha256: release.bundleSha256,
            },
          });
          await tx.appendEvent(event);
          return clone(release);
        }

        if (command.kind === "RECORD_POLICY_PROJECTION") {
          const release = await tx.findRelease(command.policyReleaseId);
          if (!release || release.tenantId !== command.tenantId) {
            fail("RELEASE_NOT_FOUND", "Policy Release was not found.");
          }
          if (release.state !== "STAGED") {
            fail(
              "RELEASE_TERMINAL",
              "Projection result is already terminal.",
            );
          }
          const template = policyCatalog.template(release.templateRef);
          const projection = safeProjection(command, template);
          const updated = {
            ...release,
            ...projection,
            updatedAt: canonicalInstant(clock(), "clock"),
          };
          await tx.putRelease(updated);
          const event = eventRecord({
            idFactory,
            clock,
            type: "product.authorization.policy-projection-recorded.v1",
            subject: release.policyReleaseId,
            tenantId: command.tenantId,
            correlationId: command.correlationId,
            data: {
              policy_release_id: release.policyReleaseId,
              projection_outcome: command.outcome,
              bundle_sha256: release.bundleSha256,
            },
          });
          await tx.appendEvent(event);
          return clone(updated);
        }

        const targetId =
          command.kind === "ROLLBACK_POLICY_RELEASE"
            ? command.targetPolicyReleaseId
            : command.policyReleaseId;
        const release = await tx.findRelease(targetId);
        if (
          !release ||
          release.tenantId !== command.tenantId ||
          release.state !== "READY"
        ) {
          fail("RELEASE_NOT_READY", "Policy Release is not ready.");
        }
        const current = await tx.activePolicy(command.tenantId);
        const currentVersion = current?.activationVersion ?? 0;
        if (currentVersion !== command.expectedActivationVersion) {
          fail("ACTIVATION_CONFLICT", "Policy activation version changed.");
        }
        if (
          command.kind === "ACTIVATE_POLICY_RELEASE" &&
          ((current && release.templateSequence <= current.templateSequence) ||
            (!current && release.templateSequence !== 1))
        ) {
          fail(
            "ACTIVATION_INVALID",
            "Activation must move to the next verified release.",
          );
        }
        if (
          command.kind === "ROLLBACK_POLICY_RELEASE" &&
          (!current ||
            release.templateSequence >= current.templateSequence ||
            release.policyReleaseId === current.policyReleaseId)
        ) {
          fail(
            "ROLLBACK_INVALID",
            "Rollback must target an older verified release.",
          );
        }
        const activation = {
          activationId: newActivationId(),
          tenantId: command.tenantId,
          tenantKind: "SYNTHETIC",
          policyReleaseId: release.policyReleaseId,
          previousPolicyReleaseId: current?.policyReleaseId ?? null,
          templateSequence: release.templateSequence,
          activationVersion: currentVersion + 1,
          activationKind:
            command.kind === "ROLLBACK_POLICY_RELEASE"
              ? "ROLLBACK"
              : "ACTIVATE",
          reasonRef: command.reasonRef,
          activatedAt: canonicalInstant(clock(), "clock"),
        };
        await tx.activate(activation);
        const event = eventRecord({
          idFactory,
          clock,
          type:
            command.kind === "ROLLBACK_POLICY_RELEASE"
              ? "product.authorization.policy-rolled-back.v1"
              : "product.authorization.policy-activated.v1",
          subject: activation.activationId,
          tenantId: command.tenantId,
          correlationId: command.correlationId,
          data: {
            policy_release_id: release.policyReleaseId,
            previous_policy_release_id:
              activation.previousPolicyReleaseId,
            activation_version: activation.activationVersion,
          },
        });
        await tx.appendEvent(event);
        return {
          ...activation,
          openFgaStoreId: release.openFgaStoreId,
          authorizationModelId: release.authorizationModelId,
        };
      },
    );
    return {
      ...result.value,
      duplicate: result.duplicate || result.value.duplicate === true,
    };
  }

  async function resolveTrustedInputs(serverContext, request, operation) {
    const admission = await tenantRegistry.admitNewRequest({
      tenantId: serverContext.tenantId,
      expectedTenantKind: "SYNTHETIC",
    });
    const identity = await stablePrincipalRegistry.resolveActionIdentity(
      {
        synthetic: true,
        workloadTrustSource: serverContext.workloadTrustSource,
        workloadActorPrincipalId:
          serverContext.workloadActorPrincipalId,
      },
      {
        sessionToken: request.sessionToken,
        expectedTenantId: serverContext.tenantId,
        delegationId: request.delegationId,
      },
    );
    validateIdentity(identity, serverContext.tenantId);
    const resource = await resolveResource({
      tenantId: serverContext.tenantId,
      tenantKind: "SYNTHETIC",
      surface: serverContext.surface,
      resourceId: request.resourceId,
    });
    validateResource(
      resource,
      operation,
      serverContext.tenantId,
      request.resourceId,
    );
    return { admission, identity, resource };
  }

  async function decideOnce(serverContext, request) {
    const operation = policyCatalog.operation(serverContext.surface);
    const first = await resolveTrustedInputs(
      serverContext,
      request,
      operation,
    );
    const activeValue = await store.readActiveRelease(
      serverContext.tenantId,
    );
    if (
      !activeValue?.active ||
      !activeValue?.release ||
      activeValue.release.state !== "READY"
    ) {
      fail("POLICY_NOT_ACTIVE", "No active Policy Release is available.");
    }
    const { active, release } = activeValue;
    try {
      assertVerifiedPolicyRelease(
        release,
        await verifyPolicyRelease(clone(release)),
      );
    } catch (error) {
      if (error instanceof AuthorizationError) throw error;
      fail(
        "POLICY_REPLAY_FAILED",
        "Active Policy Release integrity verification did not complete.",
      );
    }
    const pdp = pdpFactory({
      storeId: release.openFgaStoreId,
      authorizationModelId: release.authorizationModelId,
    });
    if (!pdp?.check) {
      fail("PDP_UNAVAILABLE", "Policy Decision Point is unavailable.");
    }

    let results = { human: false, actor: false, purpose: false };
    let infrastructureReason = null;
    if (first.identity.purposeRef !== operation.purpose_ref) {
      infrastructureReason = "PURPOSE_MISMATCH";
    } else {
      const factors = ["HUMAN", "ACTOR", "PURPOSE"];
      try {
        const values = await Promise.all(
          factors.map((factor) =>
            pdp.check({
              authorizationModelId: release.authorizationModelId,
              tupleKey: checkTuple(
                operation,
                first.resource,
                first.identity,
                factor,
              ),
            }),
          ),
        );
        for (let index = 0; index < values.length; index += 1) {
          const value = values[index];
          if (
            typeof value?.allowed !== "boolean" ||
            value.storeId !== release.openFgaStoreId ||
            value.authorizationModelId !==
              release.authorizationModelId ||
            value.consistency !== "HIGHER_CONSISTENCY"
          ) {
            fail("PDP_INVALID_RESPONSE", "PDP response is invalid.");
          }
          results[factors[index].toLowerCase()] = value.allowed;
        }
      } catch (error) {
        infrastructureReason =
          ["OPENFGA_INVALID_RESPONSE", "PDP_INVALID_RESPONSE"].includes(
            error?.code,
          )
            ? "PDP_INVALID_RESPONSE"
            : "PDP_UNAVAILABLE";
        results = { human: false, actor: false, purpose: false };
      }
    }

    const second = await resolveTrustedInputs(
      serverContext,
      request,
      operation,
    );
    if (
      first.admission.lifecycleVersion !==
        second.admission.lifecycleVersion ||
      !compareIdentity(first.identity, second.identity) ||
      !compareIdentity(first.resource, second.resource)
    ) {
      fail(
        "AUTHORIZATION_CHANGED",
        "Trusted authorization inputs changed during evaluation.",
      );
    }
    const effect =
      !infrastructureReason &&
      results.human &&
      results.actor &&
      results.purpose
        ? "ALLOW"
        : "DENY";
    const reasonCode =
      infrastructureReason ?? decisionReason(results);
    const decisionId = newDecisionId();
    const evaluatedAt = canonicalInstant(clock(), "clock");
    const checkTuples = {
      human: checkTuple(
        operation,
        first.resource,
        first.identity,
        "HUMAN",
      ),
      actor: checkTuple(
        operation,
        first.resource,
        first.identity,
        "ACTOR",
      ),
      purpose: checkTuple(
        operation,
        first.resource,
        first.identity,
        "PURPOSE",
      ),
    };
    const delegationChainSha256 = sha256(
      first.identity.delegationChain,
    );
    const inputHash = sha256({
      tenantId: serverContext.tenantId,
      surface: serverContext.surface,
      resource: first.resource,
      humanSubject: first.identity.humanSubject,
      workloadActor: first.identity.workloadActor,
      delegationChainSha256,
      purposeRef: first.identity.purposeRef,
      policyReleaseId: release.policyReleaseId,
      policyBundleSha256: release.bundleSha256,
      tupleBundleSha256: release.tupleBundleSha256,
      openFgaStoreId: release.openFgaStoreId,
      authorizationModelId: release.authorizationModelId,
      activationVersion: active.activationVersion,
    });
    const decision = {
      decisionId,
      tenantId: serverContext.tenantId,
      tenantKind: "SYNTHETIC",
      correlationId: request.correlationId,
      surface: serverContext.surface,
      resourceType: first.resource.resourceType,
      resourceId: first.resource.resourceId,
      resourceAuthorizationVersion:
        first.resource.authorizationVersion,
      humanPrincipalId: first.identity.humanSubject.principalId,
      humanSecurityEpoch: first.identity.humanSubject.securityEpoch,
      workloadActorPrincipalId:
        first.identity.workloadActor.principalId,
      workloadActorSecurityEpoch:
        first.identity.workloadActor.securityEpoch,
      leafDelegationId:
        first.identity.delegationChain.at(-1).delegationId,
      delegationChainSha256,
      purposeRef: first.identity.purposeRef,
      policyReleaseId: release.policyReleaseId,
      bundleSha256: release.bundleSha256,
      tupleBundleSha256: release.tupleBundleSha256,
      openFgaStoreId: release.openFgaStoreId,
      authorizationModelId: release.authorizationModelId,
      activationVersion: active.activationVersion,
      consistency: "HIGHER_CONSISTENCY",
      effect,
      authorizationStatus: effect === "ALLOW" ? "ALLOWED" : "DENIED",
      reasonCode,
      inputSha256: inputHash,
      checkTuples,
      checkResults: results,
      checkResultSha256: sha256(results),
      evaluatedAt,
      evidenceRef: `evidence://c06/decisions/${decisionId}`,
    };
    const event = eventRecord({
      idFactory,
      clock,
      type: "product.authorization.decision-recorded.v1",
      subject: decisionId,
      tenantId: serverContext.tenantId,
      correlationId: request.correlationId,
      data: {
        decision_id: decisionId,
        policy_release_id: release.policyReleaseId,
        tuple_bundle_sha256: release.tupleBundleSha256,
        authorization_model_id: release.authorizationModelId,
        activation_version: active.activationVersion,
        effect,
        reason_code: reasonCode,
        input_sha256: inputHash,
      },
    });
    return store.recordDecision({
      tenantId: serverContext.tenantId,
      expectedPolicyReleaseId: release.policyReleaseId,
      expectedActivationVersion: active.activationVersion,
      decision,
      event,
    });
  }

  async function decide(serverContext, request) {
    exactKeys(
      serverContext,
      [
        "synthetic",
        "routeTrustSource",
        "tenantId",
        "surface",
        "workloadTrustSource",
        "workloadActorPrincipalId",
      ],
      "trusted server context",
    );
    exactKeys(
      request,
      [
        "sessionToken",
        "delegationId",
        "resourceId",
        "correlationId",
      ],
      "authorization request",
    );
    if (
      serverContext.synthetic !== true ||
      serverContext.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR"
    ) {
      fail("UNTRUSTED_ROUTE", "Protected route context is not verified.");
    }
    syntheticTenantId(serverContext.tenantId);
    if (!SURFACES.includes(serverContext.surface)) {
      fail("UNKNOWN_SURFACE", "Protected surface is unknown.");
    }
    nonEmptyString(request.sessionToken, "sessionToken", 128);
    identifier(
      request.delegationId,
      /^dlg_[0-9a-f-]{36}$/,
      "delegationId",
    );
    identifier(request.resourceId, RESOURCE_ID, "resourceId");
    nonEmptyString(request.correlationId, "correlationId", 128);
    identifier(
      serverContext.workloadActorPrincipalId,
      /^prn_[0-9a-f-]{36}$/,
      "workloadActorPrincipalId",
    );
    if (
      serverContext.workloadTrustSource !==
      "VERIFIED_WORKLOAD_CONTEXT"
    ) {
      fail("IDENTITY_UNVERIFIED", "Workload context is not verified.");
    }

    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return await decideOnce(serverContext, request);
      } catch (error) {
        if (
          error?.code === "AUTHORIZATION_CHANGED" &&
          attempt === 0
        ) {
          continue;
        }
        throw error;
      }
    }
    fail(
      "AUTHORIZATION_CHANGED",
      "Authorization inputs did not stabilize.",
    );
  }

  async function replay(context, query) {
    exactKeys(query, ["decisionId"], "replay query");
    identifier(query.decisionId, DECISION_ID, "decisionId");
    if (!(await controlAllowed(context, "AUTHORIZATION_DECISION_REPLAY"))) {
      fail("UNAUTHORIZED", "Authorization replay is not authorized.");
    }
    const decision = await store.readDecision(query.decisionId);
    if (!decision) {
      fail("DECISION_NOT_FOUND", "Authorization decision was not found.");
    }
    const release = await store.readPolicyRelease(decision.policyReleaseId);
    if (
      !release ||
      release.tenantId !== decision.tenantId ||
      release.state !== "READY" ||
      release.openFgaStoreId !== decision.openFgaStoreId ||
      release.authorizationModelId !== decision.authorizationModelId ||
      release.bundleSha256 !== decision.bundleSha256 ||
      release.tupleBundleSha256 !== decision.tupleBundleSha256
    ) {
      fail(
        "POLICY_REPLAY_FAILED",
        "Historical Policy Release evidence is unavailable.",
      );
    }
    try {
      assertVerifiedPolicyRelease(
        release,
        await verifyPolicyRelease(clone(release)),
      );
    } catch (error) {
      if (error instanceof AuthorizationError) throw error;
      fail(
        "POLICY_REPLAY_FAILED",
        "Historical Policy Release integrity verification did not complete.",
      );
    }
    const pdp = pdpFactory({
      storeId: decision.openFgaStoreId,
      authorizationModelId: decision.authorizationModelId,
    });
    const factorNames = ["human", "actor", "purpose"];
    let replayed;
    try {
      const values = await Promise.all(
        factorNames.map((factor) =>
          pdp.check({
            authorizationModelId: decision.authorizationModelId,
            tupleKey: decision.checkTuples[factor],
          }),
        ),
      );
      for (const value of values) {
        if (
          typeof value?.allowed !== "boolean" ||
          value.storeId !== decision.openFgaStoreId ||
          value.authorizationModelId !== decision.authorizationModelId ||
          value.consistency !== "HIGHER_CONSISTENCY"
        ) {
          fail("PDP_INVALID_RESPONSE", "Historical PDP response is invalid.");
        }
      }
      replayed = Object.fromEntries(
        factorNames.map((factor, index) => [
          factor,
          values[index].allowed,
        ]),
      );
    } catch {
      fail("PDP_UNAVAILABLE", "Historical Policy Release is unavailable.");
    }
    const effect =
      replayed.human && replayed.actor && replayed.purpose
        ? "ALLOW"
        : "DENY";
    return Object.freeze({
      decisionId: decision.decisionId,
      policyReleaseId: decision.policyReleaseId,
      openFgaStoreId: decision.openFgaStoreId,
      authorizationModelId: decision.authorizationModelId,
      originalEffect: decision.effect,
      replayedEffect: effect,
      originalCheckResultSha256: decision.checkResultSha256,
      replayedCheckResultSha256: sha256(replayed),
      matches:
        effect === decision.effect &&
        sha256(replayed) === decision.checkResultSha256,
      authorizationStatus: "NOT_AUTHORIZATION",
    });
  }

  async function snapshot(context, query) {
    exactKeys(query, ["tenantId"], "snapshot query");
    syntheticTenantId(query.tenantId);
    if (!(await controlAllowed(context, "AUTHORIZATION_GOVERNANCE_READ"))) {
      fail("UNAUTHORIZED", "Authorization governance read is not allowed.");
    }
    const value = await store.readTenantSnapshot(query.tenantId);
    return Object.freeze({
      tenantId: query.tenantId,
      tenantKind: "SYNTHETIC",
      releases: value.releases,
      activePolicy: value.activePolicy,
      activations: value.activations,
      decisions: value.decisions,
      events: value.events,
      outbox: value.outbox,
      productionVerificationStatus: "NOT_VERIFIED",
    });
  }

  return Object.freeze({ execute, decide, replay, snapshot });
}

export class PepDeniedError extends Error {
  constructor(code = "ACCESS_DENIED") {
    super("Protected operation was denied.");
    this.name = "PepDeniedError";
    this.code = code;
  }
}

export function createPepSdk({ authorizationFacade }) {
  if (!authorizationFacade?.decide) {
    fail("INVALID_CONFIGURATION", "Authorization Facade is required.");
  }
  return Object.freeze({
    async enforce(serverContext, request) {
      let decision;
      try {
        decision = await authorizationFacade.decide(
          serverContext,
          request,
        );
      } catch {
        throw new PepDeniedError("AUTHORIZATION_UNAVAILABLE");
      }
      if (
        decision?.effect !== "ALLOW" ||
        decision?.authorizationStatus !== "ALLOWED"
      ) {
        throw new PepDeniedError("ACCESS_DENIED");
      }
      return Object.freeze({
        decisionId: decision.decisionId,
        evidenceRef: decision.evidenceRef,
        policyVersion: decision.authorizationModelId,
      });
    },
  });
}
