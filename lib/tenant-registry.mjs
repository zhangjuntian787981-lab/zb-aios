const SHA256 = /^sha256:[a-f0-9]{64}$/;
const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7.source.slice(1, -1)}$`);
const P1_REFERENCE =
  /^(?:evidence|fixture|policy|profile|secret-ref|synthetic|test):\/\/\S+$/;
const PROJECTIONS = Object.freeze([
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
]);
const PROJECTION_OUTCOMES = ["SUCCEEDED", "FAILED"];
const MANAGE = "TENANT_LIFECYCLE_MANAGE";
const REPORT_PROJECTION = "TENANT_PROJECTION_REPORT";
const RECONCILE = "TENANT_RECONCILE";
const READ = "TENANT_LIFECYCLE_READ";

export class TenantRegistryError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TenantRegistryError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new TenantRegistryError(code, message);
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("INVALID_COMMAND", "Invalid number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("INVALID_COMMAND", "Only JSON command values are supported.");
}

async function sha256(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalize(value)),
  );
  return `sha256:${Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
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

function nonEmptyString(value, field, maxLength = 256) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maxLength
  ) {
    fail("INVALID_COMMAND", `${field} is invalid.`);
  }
}

function reference(value, field) {
  nonEmptyString(value, field, 512);
  if (!P1_REFERENCE.test(value)) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      `${field} must use an approved P1 reference scheme.`,
    );
  }
}

function exactKeys(value, allowed, field = "command") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_COMMAND", `${field} must be an object.`);
  }
  const extras = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extras.length > 0) {
    fail("INVALID_COMMAND", `${field} has unsupported fields.`);
  }
}

function expectedVersion(value) {
  if (!Number.isInteger(value) || value < 1) {
    fail("INVALID_COMMAND", "expectedVersion must be a positive integer.");
  }
}

function tenantId(value) {
  nonEmptyString(value, "tenantId", 80);
  if (!SYNTHETIC_TENANT_ID.test(value)) {
    fail("SYNTHETIC_BOUNDARY_VIOLATION", "Synthetic Tenant ID is invalid.");
  }
}

function validateFixtureRef(value) {
  exactKeys(value, ["fixtureId", "sha256"], "fixtureRef");
  nonEmptyString(value.fixtureId, "fixtureRef.fixtureId", 128);
  if (!SHA256.test(value.sha256 ?? "")) {
    fail("INVALID_COMMAND", "fixtureRef.sha256 is invalid.");
  }
}

function validateCommon(command) {
  nonEmptyString(command.idempotencyKey, "idempotencyKey", 128);
  nonEmptyString(command.correlationId, "correlationId", 128);
}

function validateCommand(command) {
  if (command.kind === "CREATE_SYNTHETIC_TENANT") {
    exactKeys(command, [
      "kind",
      "idempotencyKey",
      "creationKey",
      "fixtureRef",
      "configRefs",
      "correlationId",
    ]);
    validateCommon(command);
    nonEmptyString(command.creationKey, "creationKey", 128);
    validateFixtureRef(command.fixtureRef);
    if (
      !Array.isArray(command.configRefs) ||
      command.configRefs.length > 32
    ) {
      fail("INVALID_COMMAND", "configRefs must contain at most 32 references.");
    }
    for (const [index, item] of command.configRefs.entries()) {
      reference(item, `configRefs[${index}]`);
    }
    return;
  }
  if (command.kind === "SUSPEND_TENANT") {
    exactKeys(command, [
      "kind",
      "idempotencyKey",
      "tenantId",
      "expectedVersion",
      "reasonRef",
      "correlationId",
    ]);
    validateCommon(command);
    tenantId(command.tenantId);
    expectedVersion(command.expectedVersion);
    reference(command.reasonRef, "reasonRef");
    return;
  }
  if (command.kind === "RESUME_TENANT") {
    exactKeys(command, [
      "kind",
      "idempotencyKey",
      "tenantId",
      "expectedVersion",
      "correlationId",
    ]);
    validateCommon(command);
    tenantId(command.tenantId);
    expectedVersion(command.expectedVersion);
    return;
  }
  if (command.kind === "REQUEST_TENANT_DELETION") {
    exactKeys(command, [
      "kind",
      "idempotencyKey",
      "tenantId",
      "expectedVersion",
      "reasonRef",
      "correlationId",
    ]);
    validateCommon(command);
    tenantId(command.tenantId);
    expectedVersion(command.expectedVersion);
    reference(command.reasonRef, "reasonRef");
    return;
  }
  if (command.kind === "RECORD_PROJECTION_RESULT") {
    exactKeys(command, [
      "kind",
      "idempotencyKey",
      "tenantId",
      "generation",
      "operationId",
      "projection",
      "outcome",
      "attempt",
      "sourceEventId",
      "errorCode",
      "correlationId",
    ]);
    validateCommon(command);
    tenantId(command.tenantId);
    if (!Number.isInteger(command.generation) || command.generation < 0) {
      fail("INVALID_COMMAND", "generation must be a non-negative integer.");
    }
    nonEmptyString(command.operationId, "operationId", 80);
    if (!PROJECTIONS.includes(command.projection)) {
      fail("INVALID_COMMAND", "Unknown projection.");
    }
    if (!PROJECTION_OUTCOMES.includes(command.outcome)) {
      fail("INVALID_COMMAND", "Unknown projection outcome.");
    }
    if (!Number.isInteger(command.attempt) || command.attempt < 1) {
      fail("INVALID_COMMAND", "attempt must be a positive integer.");
    }
    nonEmptyString(command.sourceEventId, "sourceEventId", 128);
    if (command.outcome === "FAILED") {
      nonEmptyString(command.errorCode, "errorCode", 128);
    } else if (command.errorCode !== undefined) {
      fail("INVALID_COMMAND", "Successful results cannot contain an error code.");
    }
    return;
  }
  if (command.kind === "RECONCILE_TENANT") {
    exactKeys(command, [
      "kind",
      "idempotencyKey",
      "tenantId",
      "correlationId",
    ]);
    validateCommon(command);
    tenantId(command.tenantId);
    return;
  }
  fail("INVALID_COMMAND", "Unknown Tenant Registry command.");
}

function createMemoryTransaction(draft) {
  return Object.freeze({
    findTenantByCreationKey(creationKey) {
      const id = draft.creationIndex.get(creationKey);
      return id ? structuredClone(draft.tenants.get(id)) : null;
    },
    findTenantByOrigin(fixtureRef) {
      const key = `${fixtureRef.fixtureId}:${fixtureRef.sha256}`;
      const id = draft.originIndex.get(key);
      return id ? structuredClone(draft.tenants.get(id)) : null;
    },
    loadTenantForUpdate(id) {
      const value = draft.tenants.get(id);
      return value ? structuredClone(value) : null;
    },
    insertTenant(value) {
      if (
        draft.tenants.has(value.tenantId) ||
        draft.creationIndex.has(value.creationKey) ||
        draft.originIndex.has(
          `${value.fixtureRef.fixtureId}:${value.fixtureRef.sha256}`,
        )
      ) {
        fail("TENANT_ALREADY_EXISTS", "Tenant identity is already reserved.");
      }
      draft.tenants.set(value.tenantId, structuredClone(value));
      draft.creationIndex.set(value.creationKey, value.tenantId);
      draft.originIndex.set(
        `${value.fixtureRef.fixtureId}:${value.fixtureRef.sha256}`,
        value.tenantId,
      );
    },
    updateTenant(value, previousVersion) {
      const current = draft.tenants.get(value.tenantId);
      if (!current) fail("TENANT_NOT_FOUND", "Tenant was not found.");
      if (current.lifecycleVersion !== previousVersion) {
        fail("STALE_VERSION", "Tenant state changed; reload before retrying.");
      }
      if (
        current.tenantId !== value.tenantId ||
        current.tenantKind !== value.tenantKind ||
        current.creationKey !== value.creationKey ||
        current.resourceNamespaceId !== value.resourceNamespaceId ||
        canonicalize(current.fixtureRef) !== canonicalize(value.fixtureRef)
      ) {
        fail(
          "SYNTHETIC_BOUNDARY_VIOLATION",
          "Tenant identity and origin are immutable.",
        );
      }
      draft.tenants.set(value.tenantId, structuredClone(value));
    },
    loadProjections(id, generation) {
      return structuredClone(
        draft.projections.get(`${id}:${generation}`) ?? [],
      );
    },
    replaceProjections(id, generation, values) {
      draft.projections.set(`${id}:${generation}`, structuredClone(values));
    },
    appendLifecycleEvent(event) {
      if (draft.lifecycleEvents.some(({ id }) => id === event.id)) {
        fail("ID_COLLISION", "Lifecycle event ID already exists.");
      }
      draft.lifecycleEvents.push(structuredClone(event));
    },
    appendOutbox(event) {
      if (draft.outbox.some(({ id }) => id === event.id)) {
        fail("ID_COLLISION", "Outbox event ID already exists.");
      }
      draft.outbox.push(structuredClone(event));
    },
  });
}

export function createMemoryTenantStore() {
  let state = {
    tenants: new Map(),
    creationIndex: new Map(),
    originIndex: new Map(),
    projections: new Map(),
    lifecycleEvents: [],
    outbox: [],
    receipts: new Map(),
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
    runCommand({ idempotencyKey, commandHash }, reducer) {
      return serial(async () => {
        const existing = state.receipts.get(idempotencyKey);
        if (existing) {
          if (existing.commandHash !== commandHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "The idempotency key was used for another command.",
            );
          }
          return {
            duplicate: true,
            value: structuredClone(existing.value),
          };
        }

        const draft = structuredClone(state);
        const value = await reducer(createMemoryTransaction(draft));
        draft.receipts.set(idempotencyKey, {
          commandHash,
          value: structuredClone(value),
        });
        state = draft;
        return { duplicate: false, value: structuredClone(value) };
      });
    },
    async readTenantSnapshot(id) {
      await queue;
      const tenant = state.tenants.get(id);
      if (!tenant) return null;
      return structuredClone({
        tenant,
        projections:
          state.projections.get(`${id}:${tenant.generation}`) ?? [],
        lifecycleEvents: state.lifecycleEvents.filter(
          ({ subject }) => subject === id,
        ),
        outbox: state.outbox.filter(({ subject }) => subject === id),
      });
    },
  });
}

export function createSyntheticFixtureCatalog(fixtures) {
  if (!Array.isArray(fixtures) || fixtures.length === 0) {
    fail("INVALID_FIXTURE_CATALOG", "At least one synthetic fixture is required.");
  }
  const entries = new Map();
  for (const item of fixtures) {
    exactKeys(
      item,
      ["fixtureId", "sha256", "allowedConfigRefs"],
      "fixtureCatalog entry",
    );
    validateFixtureRef({
      fixtureId: item.fixtureId,
      sha256: item.sha256,
    });
    if (
      !Array.isArray(item.allowedConfigRefs) ||
      item.allowedConfigRefs.length > 32
    ) {
      fail(
        "INVALID_FIXTURE_CATALOG",
        "Fixture config references must be a bounded array.",
      );
    }
    for (const [index, configRef] of item.allowedConfigRefs.entries()) {
      reference(configRef, `fixtureCatalog.allowedConfigRefs[${index}]`);
    }
    if (entries.has(item.fixtureId)) {
      fail("INVALID_FIXTURE_CATALOG", "Fixture IDs must be unique.");
    }
    entries.set(item.fixtureId, {
      sha256: item.sha256,
      allowedConfigRefs: new Set(item.allowedConfigRefs),
    });
  }
  return Object.freeze({
    assertKnown(item, configRefs = []) {
      validateFixtureRef(item);
      const entry = entries.get(item.fixtureId);
      if (entry?.sha256 !== item.sha256) {
        fail(
          "UNKNOWN_SYNTHETIC_FIXTURE",
          "Synthetic fixture is not in the frozen catalog.",
        );
      }
      if (configRefs.some((configRef) => !entry.allowedConfigRefs.has(configRef))) {
        fail(
          "UNKNOWN_SYNTHETIC_CONFIG_REF",
          "Config reference is not in the frozen synthetic catalog.",
        );
      }
    },
  });
}

function resultFor(tenant) {
  return {
    tenantId: tenant.tenantId,
    tenantKind: tenant.tenantKind,
    state: tenant.state,
    lifecycleVersion: tenant.lifecycleVersion,
    generation: tenant.generation,
    operationId: tenant.operationId,
  };
}

function sameCreationIntent(tenant, command) {
  return (
    tenant.creationKey === command.creationKey &&
    canonicalize(tenant.fixtureRef) === canonicalize(command.fixtureRef) &&
    canonicalize(tenant.configRefs) === canonicalize(command.configRefs)
  );
}

function deletionProgress(projections) {
  return {
    completed: projections.filter(({ status }) => status === "DELETED").length,
    failed: projections.filter(({ status }) => status === "FAILED").length,
    pending: projections.filter(({ status }) => status === "PENDING").length,
    total: projections.length,
  };
}

function safeSnapshot(value) {
  const { tenant, projections, lifecycleEvents, outbox } = value;
  return {
    ...resultFor(tenant),
    synthetic: true,
    creationKey: tenant.creationKey,
    fixtureRef: structuredClone(tenant.fixtureRef),
    configRefs: structuredClone(tenant.configRefs),
    resourceNamespaceId: tenant.resourceNamespaceId,
    projections: structuredClone(projections).sort((left, right) =>
      left.projection.localeCompare(right.projection),
    ),
    deletionProgress:
      tenant.state === "DELETING" || tenant.state === "DELETED"
        ? deletionProgress(projections)
        : null,
    lifecycleEvents: structuredClone(lifecycleEvents),
    outbox: structuredClone(outbox),
    createdAt: tenant.createdAt,
    updatedAt: tenant.updatedAt,
  };
}

export function createTenantRegistry({
  store,
  fixtureCatalog,
  authorize,
  clock = () => new Date().toISOString(),
  idFactory = uuidV7,
}) {
  if (!store?.runCommand || !store?.readTenantSnapshot) {
    fail("INVALID_STORE", "Tenant Store is required.");
  }
  if (!fixtureCatalog?.assertKnown) {
    fail("INVALID_FIXTURE_CATALOG", "Synthetic fixture catalog is required.");
  }
  if (typeof authorize !== "function") {
    fail("INVALID_AUTHORIZER", "A fail-closed authorizer is required.");
  }

  async function isAuthorized(context, capability) {
    try {
      return (await authorize(context, capability)) === true;
    } catch {
      return false;
    }
  }

  function newUuid() {
    const value = idFactory();
    if (!UUID_V7.test(value)) {
      fail("INVALID_ID_FACTORY", "ID factory must return a UUIDv7.");
    }
    return value;
  }

  function event(tenant, command, actorId, type, data) {
    return {
      specversion: "1.0",
      id: `evt_${newUuid()}`,
      source: "/aios-core/tenant-registry",
      type,
      subject: tenant.tenantId,
      time: clock(),
      datacontenttype: "application/json",
      tenantkind: tenant.tenantKind,
      correlationid: command.correlationId,
      synthetic: true,
      data: {
        tenant_id: tenant.tenantId,
        lifecycle_version: tenant.lifecycleVersion,
        generation: tenant.generation,
        operation_id: tenant.operationId,
        state: tenant.state,
        actor_id: actorId,
        ...data,
      },
    };
  }

  function projectionPlan(tenant, desiredAction) {
    return PROJECTIONS.map((projection) => ({
      tenantId: tenant.tenantId,
      generation: tenant.generation,
      projection,
      desiredAction,
      status: "PENDING",
      attemptCount: 0,
      lastErrorCode: null,
      sourceEventId: null,
      updatedAt: tenant.updatedAt,
    }));
  }

  function ensureVersion(tenantValue, version) {
    if (tenantValue.lifecycleVersion !== version) {
      fail("STALE_VERSION", "Tenant state changed; reload before retrying.");
    }
  }

  function ensureTenant(value) {
    if (!value) fail("TENANT_NOT_FOUND", "Tenant was not found.");
    if (
      value.tenantKind !== "SYNTHETIC" ||
      !SYNTHETIC_TENANT_ID.test(value.tenantId) ||
      !value.resourceNamespaceId.startsWith("sns_")
    ) {
      fail(
        "SYNTHETIC_BOUNDARY_VIOLATION",
        "Tenant kind and namespace are inconsistent.",
      );
    }
    return value;
  }

  async function createSyntheticTenant(tx, command, actorId) {
    fixtureCatalog.assertKnown(command.fixtureRef, command.configRefs);
    const existing = await tx.findTenantByCreationKey(command.creationKey);
    if (existing) {
      if (!sameCreationIntent(existing, command)) {
        fail(
          "CREATION_CONFLICT",
          "Creation key is bound to another frozen Tenant intent.",
        );
      }
      return { ...resultFor(ensureTenant(existing)), duplicate: true };
    }
    const existingOrigin = await tx.findTenantByOrigin(command.fixtureRef);
    if (existingOrigin) {
      fail(
        "CREATION_CONFLICT",
        "Synthetic fixture origin is already bound to another Tenant.",
      );
    }

    const now = clock();
    const tenantValue = {
      tenantId: `stn_${newUuid()}`,
      tenantKind: "SYNTHETIC",
      state: "PROVISIONING",
      lifecycleVersion: 1,
      generation: 1,
      creationKey: command.creationKey,
      fixtureRef: structuredClone(command.fixtureRef),
      configRefs: structuredClone(command.configRefs),
      resourceNamespaceId: `sns_${newUuid()}`,
      operationId: `op_${newUuid()}`,
      createdAt: now,
      updatedAt: now,
    };
    const projections = projectionPlan(tenantValue, "PROVISION");
    const createdEvent = event(
      tenantValue,
      command,
      actorId,
      "product.tenant.provisioning-requested.v1",
      {
        operation_id: tenantValue.operationId,
        resource_namespace_id: tenantValue.resourceNamespaceId,
        fixture_ref: tenantValue.fixtureRef,
        projection_targets: PROJECTIONS,
      },
    );
    await tx.insertTenant(tenantValue);
    await tx.replaceProjections(
      tenantValue.tenantId,
      tenantValue.generation,
      projections,
    );
    await tx.appendLifecycleEvent(createdEvent);
    await tx.appendOutbox(createdEvent);
    return resultFor(tenantValue);
  }

  async function suspendTenant(tx, command, actorId) {
    const current = ensureTenant(
      await tx.loadTenantForUpdate(command.tenantId),
    );
    ensureVersion(current, command.expectedVersion);
    if (!["PROVISIONING", "ACTIVE"].includes(current.state)) {
      fail("INVALID_TRANSITION", "Tenant cannot be suspended from this state.");
    }
    const updated = {
      ...current,
      state: "SUSPENDED",
      lifecycleVersion: current.lifecycleVersion + 1,
      updatedAt: clock(),
    };
    const lifecycleEvent = event(
      updated,
      command,
      actorId,
      "product.tenant.suspended.v1",
      { reason_ref: command.reasonRef },
    );
    await tx.updateTenant(updated, current.lifecycleVersion);
    await tx.appendLifecycleEvent(lifecycleEvent);
    await tx.appendOutbox(lifecycleEvent);
    return resultFor(updated);
  }

  async function resumeTenant(tx, command, actorId) {
    const current = ensureTenant(
      await tx.loadTenantForUpdate(command.tenantId),
    );
    ensureVersion(current, command.expectedVersion);
    if (current.state !== "SUSPENDED") {
      fail("INVALID_TRANSITION", "Only a suspended Tenant can resume.");
    }
    const updated = {
      ...current,
      state: "PROVISIONING",
      lifecycleVersion: current.lifecycleVersion + 1,
      generation: current.generation + 1,
      operationId: `op_${newUuid()}`,
      updatedAt: clock(),
    };
    const projections = projectionPlan(updated, "PROVISION");
    const lifecycleEvent = event(
      updated,
      command,
      actorId,
      "product.tenant.resume-requested.v1",
      {
        operation_id: updated.operationId,
        projection_targets: PROJECTIONS,
      },
    );
    await tx.updateTenant(updated, current.lifecycleVersion);
    await tx.replaceProjections(
      updated.tenantId,
      updated.generation,
      projections,
    );
    await tx.appendLifecycleEvent(lifecycleEvent);
    await tx.appendOutbox(lifecycleEvent);
    return resultFor(updated);
  }

  async function requestDeletion(tx, command, actorId) {
    const current = ensureTenant(
      await tx.loadTenantForUpdate(command.tenantId),
    );
    ensureVersion(current, command.expectedVersion);
    if (["DELETING", "DELETED"].includes(current.state)) {
      fail("INVALID_TRANSITION", "Tenant deletion is already finalizing.");
    }
    const updated = {
      ...current,
      state: "DELETING",
      lifecycleVersion: current.lifecycleVersion + 1,
      generation: current.generation + 1,
      operationId: `op_${newUuid()}`,
      updatedAt: clock(),
    };
    const projections = projectionPlan(updated, "DELETE");
    const lifecycleEvent = event(
      updated,
      command,
      actorId,
      "product.tenant.deletion-requested.v1",
      {
        operation_id: updated.operationId,
        reason_ref: command.reasonRef,
        projection_targets: PROJECTIONS,
      },
    );
    await tx.updateTenant(updated, current.lifecycleVersion);
    await tx.replaceProjections(
      updated.tenantId,
      updated.generation,
      projections,
    );
    await tx.appendLifecycleEvent(lifecycleEvent);
    await tx.appendOutbox(lifecycleEvent);
    return resultFor(updated);
  }

  async function recordProjectionResult(tx, command, actorId) {
    const current = ensureTenant(
      await tx.loadTenantForUpdate(command.tenantId),
    );
    if (command.generation !== current.generation) {
      fail(
        "STALE_PROJECTION_GENERATION",
        "Projection result belongs to another generation.",
      );
    }
    if (command.operationId !== current.operationId) {
      fail(
        "STALE_PROJECTION_OPERATION",
        "Projection result belongs to another lifecycle operation.",
      );
    }
    if (current.state === "DELETED") {
      fail("TENANT_DELETED", "Deleted Tenant is a permanent tombstone.");
    }
    if (!["PROVISIONING", "SUSPENDED", "DELETING"].includes(current.state)) {
      fail(
        "INVALID_TRANSITION",
        "Projection result is not valid for this state.",
      );
    }
    const projections = await tx.loadProjections(
      current.tenantId,
      current.generation,
    );
    const selected = projections.find(
      ({ projection }) => projection === command.projection,
    );
    if (!selected) fail("INVALID_COMMAND", "Projection is not in the plan.");
    const nextStatus =
      command.outcome === "FAILED"
        ? "FAILED"
        : selected.desiredAction === "DELETE"
          ? "DELETED"
          : "READY";
    const nextErrorCode =
      command.outcome === "FAILED" ? command.errorCode : null;
    if (command.attempt <= selected.attemptCount) {
      if (
        command.attempt === selected.attemptCount &&
        selected.sourceEventId === command.sourceEventId &&
        selected.status === nextStatus &&
        selected.lastErrorCode === nextErrorCode
      ) {
        return {
          ...resultFor(current),
          projection: command.projection,
          projectionStatus: selected.status,
          duplicate: true,
        };
      }
      fail(
        "STALE_PROJECTION_RESULT",
        "Projection result is older than the recorded attempt.",
      );
    }
    if (command.attempt !== selected.attemptCount + 1) {
      fail(
        "PROJECTION_RESULT_GAP",
        "Projection result skipped an expected attempt.",
      );
    }
    if (["READY", "DELETED"].includes(selected.status)) {
      fail(
        "PROJECTION_ALREADY_FINAL",
        "A successful projection cannot regress in the same generation.",
      );
    }
    selected.status = nextStatus;
    selected.attemptCount = command.attempt;
    selected.lastErrorCode = nextErrorCode;
    selected.sourceEventId = command.sourceEventId;
    selected.updatedAt = clock();
    const lifecycleEvent = event(
      current,
      command,
      actorId,
      command.outcome === "FAILED"
        ? "product.tenant.projection-failed.v1"
        : "product.tenant.projection-applied.v1",
      {
        projection: command.projection,
        desired_action: selected.desiredAction,
        projection_status: selected.status,
        error_code: selected.lastErrorCode,
        source_event_id: command.sourceEventId,
      },
    );
    await tx.replaceProjections(
      current.tenantId,
      current.generation,
      projections,
    );
    await tx.appendLifecycleEvent(lifecycleEvent);
    return {
      ...resultFor(current),
      projection: command.projection,
      projectionStatus: selected.status,
    };
  }

  async function reconcileTenant(tx, command, actorId) {
    const current = ensureTenant(
      await tx.loadTenantForUpdate(command.tenantId),
    );
    const projections = await tx.loadProjections(
      current.tenantId,
      current.generation,
    );
    let nextState = current.state;
    let eventType = null;
    if (
      current.state === "PROVISIONING" &&
      projections.length === PROJECTIONS.length &&
      projections.every(({ status }) => status === "READY")
    ) {
      nextState = "ACTIVE";
      eventType = "product.tenant.activated.v1";
    } else if (
      current.state === "DELETING" &&
      projections.length === PROJECTIONS.length &&
      projections.every(({ status }) => status === "DELETED")
    ) {
      nextState = "DELETED";
      eventType = "product.tenant.deleted.v1";
    } else if (!["PROVISIONING", "DELETING"].includes(current.state)) {
      fail("INVALID_TRANSITION", "Tenant cannot reconcile from this state.");
    }

    if (!eventType) {
      const retryEvent = event(
        current,
        command,
        actorId,
        "product.tenant.reconcile-requested.v1",
        {
          incomplete_projections: projections
            .filter(({ status }) => !["READY", "DELETED"].includes(status))
            .map(({ projection, status }) => ({ projection, status })),
        },
      );
      await tx.appendOutbox(retryEvent);
      return resultFor(current);
    }

    const updated = {
      ...current,
      state: nextState,
      lifecycleVersion: current.lifecycleVersion + 1,
      updatedAt: clock(),
    };
    const lifecycleEvent = event(updated, command, actorId, eventType, {});
    await tx.updateTenant(updated, current.lifecycleVersion);
    await tx.appendLifecycleEvent(lifecycleEvent);
    await tx.appendOutbox(lifecycleEvent);
    return resultFor(updated);
  }

  async function execute(context, command) {
    if (!command || typeof command !== "object" || Array.isArray(command)) {
      fail("INVALID_COMMAND", "Command must be an object.");
    }
    const capability =
      command.kind === "RECORD_PROJECTION_RESULT"
        ? REPORT_PROJECTION
        : command.kind === "RECONCILE_TENANT"
          ? RECONCILE
          : MANAGE;
    if (!(await isAuthorized(context, capability))) {
      fail("UNAUTHORIZED", "Tenant Registry operation is not authorized.");
    }
    if (command.kind === "CREATE_ENTERPRISE_TENANT") {
      fail(
        "P3_REQUIRED",
        "Enterprise Tenant creation is disabled before Enterprise Onboarding.",
      );
    }
    validateCommand(command);
    nonEmptyString(context?.actorId, "context.actorId", 128);
    const commandHash = await sha256({
      actorId: context.actorId,
      command,
    });
    const stored = await store.runCommand(
      {
        idempotencyKey: command.idempotencyKey,
        commandHash,
      },
      async (tx) => {
        if (command.kind === "CREATE_SYNTHETIC_TENANT") {
          return createSyntheticTenant(tx, command, context.actorId);
        }
        if (command.kind === "SUSPEND_TENANT") {
          return suspendTenant(tx, command, context.actorId);
        }
        if (command.kind === "RESUME_TENANT") {
          return resumeTenant(tx, command, context.actorId);
        }
        if (command.kind === "REQUEST_TENANT_DELETION") {
          return requestDeletion(tx, command, context.actorId);
        }
        if (command.kind === "RECORD_PROJECTION_RESULT") {
          return recordProjectionResult(tx, command, context.actorId);
        }
        return reconcileTenant(tx, command, context.actorId);
      },
    );
    return {
      ...stored.value,
      duplicate: stored.duplicate || stored.value.duplicate === true,
    };
  }

  async function snapshot(context, id) {
    if (!(await isAuthorized(context, READ))) {
      fail("UNAUTHORIZED", "Tenant lifecycle read is not authorized.");
    }
    tenantId(id);
    const value = await store.readTenantSnapshot(id);
    if (!value) fail("TENANT_NOT_FOUND", "Tenant was not found.");
    ensureTenant(value.tenant);
    return safeSnapshot(value);
  }

  async function admitNewRequest({ tenantId: id, expectedTenantKind }) {
    tenantId(id);
    if (expectedTenantKind !== "SYNTHETIC") {
      fail("TENANT_KIND_MISMATCH", "Tenant kind does not match server context.");
    }
    let value;
    try {
      value = await store.readTenantSnapshot(id);
    } catch {
      fail("STORE_UNAVAILABLE", "Tenant lifecycle state is unavailable.");
    }
    if (!value) fail("TENANT_NOT_FOUND", "Tenant was not found.");
    const current = ensureTenant(value.tenant);
    if (current.state === "DELETED") {
      fail("TENANT_DELETED", "Deleted Tenant is a permanent tombstone.");
    }
    if (current.state !== "ACTIVE") {
      fail("TENANT_NOT_ACTIVE", "Tenant is not accepting new requests.");
    }
    return Object.freeze({
      tenantId: current.tenantId,
      tenantKind: current.tenantKind,
      lifecycleVersion: current.lifecycleVersion,
      trustSource: "VERIFIED_SERVER_CONTEXT",
    });
  }

  return Object.freeze({ execute, snapshot, admitNewRequest });
}
