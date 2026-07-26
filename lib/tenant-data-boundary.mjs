import { createHash } from "node:crypto";
import { createPepSdk } from "./authorization-facade.mjs";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7}$`);
const DELEGATION_ID = new RegExp(`^dlg_${UUID_V7}$`);
const RESOURCE_ID = /^[a-z][a-z0-9_-]{0,127}$/;
const LIFECYCLE_TYPES = new Set([
  "product.tenant.provisioning-requested.v1",
  "product.tenant.activated.v1",
  "product.tenant.suspended.v1",
  "product.tenant.resume-requested.v1",
  "product.tenant.deletion-requested.v1",
  "product.tenant.deleted.v1",
]);

export class TenantDataIsolationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TenantDataIsolationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new TenantDataIsolationError(code, message);
}

function exactKeys(value, allowed, field, required = allowed) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_INPUT", `${field} must be an object.`);
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.includes(key))) {
    fail("INVALID_INPUT", `${field} contains unsupported fields.`);
  }
  if (required.some((key) => !keys.includes(key))) {
    fail("INVALID_INPUT", `${field} is incomplete.`);
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

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("INVALID_INPUT", "Number is invalid.");
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
    .update(canonicalize(value))
    .digest("hex")}`;
}

function validateServerContext(context) {
  exactKeys(
    context,
    [
      "synthetic",
      "routeTrustSource",
      "tenantId",
      "operationId",
      "workloadTrustSource",
      "workloadActorPrincipalId",
    ],
    "trusted server context",
  );
  if (
    context.synthetic !== true ||
    context.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR"
  ) {
    fail("UNTRUSTED_ROUTE", "Storage route is not server verified.");
  }
  if (!SYNTHETIC_TENANT_ID.test(context.tenantId ?? "")) {
    fail(
      "P3_REQUIRED",
      "Only Synthetic Tenant storage is available in P1.",
    );
  }
  nonEmptyString(context.operationId, "operationId", 64);
  if (
    context.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT" ||
    !PRINCIPAL_ID.test(context.workloadActorPrincipalId ?? "")
  ) {
    fail("UNTRUSTED_ROUTE", "Workload identity is not server verified.");
  }
}

function validateRequest(request, descriptor) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "resourceId",
      "correlationId",
      "input",
    ],
    "storage request",
  );
  nonEmptyString(request.sessionToken, "sessionToken", 128);
  if (!DELEGATION_ID.test(request.delegationId ?? "")) {
    fail("INVALID_INPUT", "delegationId is invalid.");
  }
  if (!RESOURCE_ID.test(request.resourceId ?? "")) {
    fail("INVALID_INPUT", "resourceId is invalid.");
  }
  nonEmptyString(request.correlationId, "correlationId", 128);
  exactKeys(
    request.input,
    descriptor.inputKeys,
    "storage request input",
    descriptor.inputKeys,
  );
  if (
    Object.hasOwn(request.input, "resourceId") &&
    request.input.resourceId !== request.resourceId
  ) {
    fail("INVALID_INPUT", "resourceId values do not match.");
  }
}

function validateAdmission(admission, context) {
  if (
    admission?.tenantId !== context.tenantId ||
    admission?.tenantKind !== "SYNTHETIC" ||
    admission?.trustSource !== "VERIFIED_SERVER_CONTEXT" ||
    !Number.isSafeInteger(admission?.lifecycleVersion) ||
    admission.lifecycleVersion < 1
  ) {
    fail("TENANT_SCOPE_VIOLATION", "Tenant admission is inconsistent.");
  }
}

function normalizeDependency(error, fallback) {
  if (error instanceof TenantDataIsolationError) return error;
  if (
    ["TENANT_NOT_ACTIVE", "TENANT_DELETED", "TENANT_NOT_FOUND"].includes(
      error?.code,
    )
  ) {
    return new TenantDataIsolationError(
      "TENANT_NOT_ACTIVE",
      "Synthetic Tenant is not accepting data requests.",
    );
  }
  return new TenantDataIsolationError(fallback, "Dependency failed closed.");
}

function validateLifecycleEvent(event) {
  exactKeys(
    event,
    [
      "specversion",
      "id",
      "source",
      "type",
      "subject",
      "time",
      "datacontenttype",
      "tenantkind",
      "correlationid",
      "synthetic",
      "data",
    ],
    "lifecycle event",
  );
  if (
    event.specversion !== "1.0" ||
    event.source !== "/aios-core/tenant-registry" ||
    !LIFECYCLE_TYPES.has(event.type) ||
    event.datacontenttype !== "application/json" ||
    event.tenantkind !== "SYNTHETIC" ||
    event.synthetic !== true ||
    !SYNTHETIC_TENANT_ID.test(event.subject ?? "")
  ) {
    fail("INVALID_LIFECYCLE_EVENT", "Lifecycle event is not trusted.");
  }
  nonEmptyString(event.id, "event.id", 128);
  nonEmptyString(event.correlationid, "event.correlationid", 128);
  nonEmptyString(event.time, "event.time", 64);
  exactKeys(
    event.data,
    [
      "tenant_id",
      "lifecycle_version",
      "generation",
      "operation_id",
      "state",
      "actor_id",
      "reason_ref",
      "resource_namespace_id",
      "fixture_ref",
      "projection_targets",
    ],
    "lifecycle event data",
    [
      "tenant_id",
      "lifecycle_version",
      "generation",
      "operation_id",
      "state",
      "actor_id",
    ],
  );
  if (
    event.data.tenant_id !== event.subject ||
    !Number.isSafeInteger(event.data.lifecycle_version) ||
    event.data.lifecycle_version < 1 ||
    !Number.isSafeInteger(event.data.generation) ||
    event.data.generation < 1
  ) {
    fail("INVALID_LIFECYCLE_EVENT", "Lifecycle event scope is invalid.");
  }
  nonEmptyString(event.data.operation_id, "event.data.operation_id", 80);
  nonEmptyString(event.data.actor_id, "event.data.actor_id", 80);
}

function adapterMap(adapters) {
  const entries =
    adapters instanceof Map ? [...adapters.entries()] : Object.entries(adapters);
  const result = new Map(entries);
  for (const [id, adapter] of result) {
    if (
      typeof id !== "string" ||
      typeof adapter?.execute !== "function" ||
      typeof adapter?.project !== "function" ||
      typeof adapter?.snapshot !== "function"
    ) {
      fail("INVALID_CONFIGURATION", "C07 Adapter is incomplete.");
    }
  }
  return result;
}

export function createC06TenantDataAuthorizer({ authorizationFacade }) {
  const pep = createPepSdk({ authorizationFacade });
  return Object.freeze({
    async enforce(serverContext, request, descriptor) {
      return pep.enforce(
        Object.freeze({
          synthetic: true,
          routeTrustSource: serverContext.routeTrustSource,
          tenantId: serverContext.tenantId,
          surface: descriptor.surface,
          workloadTrustSource: serverContext.workloadTrustSource,
          workloadActorPrincipalId:
            serverContext.workloadActorPrincipalId,
        }),
        Object.freeze({
          sessionToken: request.sessionToken,
          delegationId: request.delegationId,
          resourceId: request.resourceId,
          correlationId: request.correlationId,
        }),
      );
    },
  });
}

export function createC03TenantLifecycleVerifier({ tenantStore }) {
  if (typeof tenantStore?.readTenantSnapshot !== "function") {
    fail(
      "INVALID_CONFIGURATION",
      "C03 Tenant lifecycle store is required.",
    );
  }
  return Object.freeze({
    async verify(event) {
      let snapshot;
      try {
        snapshot = await tenantStore.readTenantSnapshot(event.subject);
      } catch {
        fail(
          "DEPENDENCY_UNAVAILABLE",
          "C03 lifecycle evidence is unavailable.",
        );
      }
      const expectedHash = sha256(event);
      const lifecycleEvent = snapshot?.lifecycleEvents?.find(
        ({ id }) => id === event.id,
      );
      const outboxEvent = snapshot?.outbox?.find(
        ({ id }) => id === event.id,
      );
      if (
        !lifecycleEvent ||
        !outboxEvent ||
        sha256(lifecycleEvent) !== expectedHash ||
        sha256(outboxEvent) !== expectedHash
      ) {
        fail(
          "UNTRUSTED_LIFECYCLE_EVENT",
          "Lifecycle event is not an exact C03 event/outbox pair.",
        );
      }
      return Object.freeze({
        source: "C03_EVENT_OUTBOX_PAIR",
        tenantId: event.subject,
        eventId: event.id,
        eventSha256: expectedHash,
      });
    },
  });
}

export function createTenantDataBoundary({
  tenantRegistry,
  authorizer,
  lifecycleSource,
  operationCatalog,
  adapters,
  controlAuthorize = async () => false,
}) {
  if (
    typeof tenantRegistry?.admitNewRequest !== "function" ||
    typeof authorizer?.enforce !== "function" ||
    typeof lifecycleSource?.verify !== "function" ||
    typeof operationCatalog?.resolve !== "function" ||
    typeof operationCatalog?.list !== "function" ||
    typeof controlAuthorize !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C07 dependencies are incomplete.");
  }
  const stores = adapterMap(adapters);
  for (const descriptor of operationCatalog.list()) {
    if (!stores.has(descriptor.adapterId)) {
      fail(
        "INVALID_CONFIGURATION",
        "Frozen operation references an unavailable Adapter.",
      );
    }
  }

  const eventReceipts = new Map();

  async function execute(serverContext, request) {
    validateServerContext(serverContext);
    let descriptor;
    try {
      descriptor = operationCatalog.resolve(serverContext.operationId);
    } catch {
      fail("UNKNOWN_OPERATION", "Storage operation is not registered.");
    }
    validateRequest(request, descriptor);

    let authorization;
    try {
      authorization = await authorizer.enforce(
        Object.freeze({ ...serverContext }),
        Object.freeze(structuredClone(request)),
        descriptor,
      );
    } catch (error) {
      const code =
        error?.code === "AUTHORIZATION_UNAVAILABLE"
          ? "AUTHORIZATION_UNAVAILABLE"
          : "ACCESS_DENIED";
      throw new TenantDataIsolationError(
        code,
        "Storage operation was denied.",
      );
    }
    if (
      typeof authorization?.decisionId !== "string" ||
      typeof authorization?.evidenceRef !== "string" ||
      typeof authorization?.policyVersion !== "string"
    ) {
      fail("AUTHORIZATION_UNAVAILABLE", "Authorization evidence is invalid.");
    }

    let firstAdmission;
    try {
      firstAdmission = await tenantRegistry.admitNewRequest({
        tenantId: serverContext.tenantId,
        expectedTenantKind: "SYNTHETIC",
      });
    } catch (error) {
      throw normalizeDependency(error, "DEPENDENCY_UNAVAILABLE");
    }
    validateAdmission(firstAdmission, serverContext);

    const scope = Object.freeze({
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId: firstAdmission.tenantId,
      tenantKind: firstAdmission.tenantKind,
      lifecycleVersion: firstAdmission.lifecycleVersion,
      operationId: descriptor.operationId,
      storagePath: descriptor.path,
      correlationId: request.correlationId,
      decisionId: authorization.decisionId,
      evidenceRef: authorization.evidenceRef,
      policyVersion: authorization.policyVersion,
    });
    const adapter = stores.get(descriptor.adapterId);
    let value;
    try {
      value = await adapter.execute(
        scope,
        Object.freeze({
          ...descriptor,
          resourceId: request.resourceId,
          input: structuredClone(request.input),
        }),
      );
    } catch (error) {
      throw normalizeDependency(error, "STORE_UNAVAILABLE");
    }

    return Object.freeze({
      operationId: descriptor.operationId,
      value,
      authorization: Object.freeze({ ...authorization }),
      tenantLifecycleVersion: firstAdmission.lifecycleVersion,
    });
  }

  async function project(workerContext, event) {
    exactKeys(
      workerContext,
      ["synthetic", "trustSource"],
      "storage worker context",
    );
    if (
      workerContext.synthetic !== true ||
      workerContext.trustSource !== "VERIFIED_C03_OUTBOX"
    ) {
      fail("UNTRUSTED_WORKER", "Lifecycle worker is not trusted.");
    }
    validateLifecycleEvent(event);
    const eventHash = sha256(event);
    let sourceEvidence;
    try {
      sourceEvidence = await lifecycleSource.verify(
        structuredClone(event),
      );
    } catch (error) {
      throw normalizeDependency(
        error,
        "UNTRUSTED_LIFECYCLE_EVENT",
      );
    }
    if (
      sourceEvidence?.source !== "C03_EVENT_OUTBOX_PAIR" ||
      sourceEvidence?.tenantId !== event.subject ||
      sourceEvidence?.eventId !== event.id ||
      sourceEvidence?.eventSha256 !== eventHash
    ) {
      fail(
        "UNTRUSTED_LIFECYCLE_EVENT",
        "Lifecycle source evidence is invalid.",
      );
    }
    const existing = eventReceipts.get(event.id);
    if (existing) {
      if (existing.eventHash !== eventHash) {
        fail("LIFECYCLE_EVENT_CONFLICT", "Lifecycle event ID was reused.");
      }
      return Object.freeze({ ...existing.result, duplicate: true });
    }

    const receipts = [];
    for (const [adapterId, adapter] of stores) {
      let receipt;
      try {
        receipt = await adapter.project(structuredClone(event));
      } catch (error) {
        throw normalizeDependency(error, "PROJECTION_INCOMPLETE");
      }
      if (
        receipt?.tenantId !== event.subject ||
        receipt?.eventId !== event.id ||
        receipt?.status !== "SUCCEEDED"
      ) {
        fail(
          "PROJECTION_INCOMPLETE",
          "Storage Adapter did not prove lifecycle completion.",
        );
      }
      receipts.push(Object.freeze({ adapterId, ...receipt }));
    }
    const result = Object.freeze({
      tenantId: event.subject,
      eventId: event.id,
      lifecycleVersion: event.data.lifecycle_version,
      generation: event.data.generation,
      operationId: event.data.operation_id,
      state: event.data.state,
      status: "SUCCEEDED",
      receipts: Object.freeze(receipts),
      verificationScope: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
      duplicate: false,
    });
    eventReceipts.set(event.id, { eventHash, result });
    return result;
  }

  async function snapshot(controlContext, query) {
    exactKeys(query, ["tenantId"], "snapshot query");
    if (!SYNTHETIC_TENANT_ID.test(query.tenantId ?? "")) {
      fail("INVALID_INPUT", "Snapshot Tenant is invalid.");
    }
    let allowed = false;
    try {
      allowed =
        (await controlAuthorize(
          controlContext,
          "TENANT_DATA_ISOLATION_READ",
          Object.freeze({
            tenantId: query.tenantId,
            tenantKind: "SYNTHETIC",
          }),
        )) === true;
    } catch {
      allowed = false;
    }
    if (!allowed) fail("ACCESS_DENIED", "Isolation snapshot was denied.");

    const adapterSnapshots = [];
    for (const [adapterId, adapter] of stores) {
      const value = await adapter.snapshot({ tenantId: query.tenantId });
      adapterSnapshots.push(Object.freeze({ adapterId, ...value }));
    }
    return Object.freeze({
      tenantId: query.tenantId,
      adapters: Object.freeze(adapterSnapshots),
      verificationScope: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
    });
  }

  return Object.freeze({ execute, project, snapshot });
}
