import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createC03TenantLifecycleVerifier,
  createC06TenantDataAuthorizer,
  createTenantDataBoundary,
} from "../lib/tenant-data-boundary.mjs";
import { createC07OperationCatalog } from "../lib/c07-operation-catalog.mjs";

const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c07/operation-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const operationCatalog = createC07OperationCatalog(catalogDocument);

const TENANT_A = "stn_01984910-0000-7000-8000-000000000001";
const PRINCIPAL = "prn_01984910-0000-7000-8000-000000000002";
const DELEGATION = "dlg_01984910-0000-7000-8000-000000000003";

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

function sha256(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value))
    .digest("hex")}`;
}

function context(operationId = "SQL_GET") {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT_A,
    operationId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: PRINCIPAL,
  };
}

function request(input = { resourceId: "doc_synthetic_a" }) {
  return {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    resourceId: "doc_synthetic_a",
    correlationId: "c07-correlation",
    input,
  };
}

function event({
  id = "evt-c07-1",
  type = "product.tenant.provisioning-requested.v1",
  lifecycleVersion = 1,
  generation = 1,
  state = "PROVISIONING",
  operationId = "op_01984910-0000-7000-8000-000000000004",
} = {}) {
  return {
    specversion: "1.0",
    id,
    source: "/aios-core/tenant-registry",
    type,
    subject: TENANT_A,
    time: "2026-07-26T09:00:00.000Z",
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: "c07-lifecycle",
    synthetic: true,
    data: {
      tenant_id: TENANT_A,
      lifecycle_version: lifecycleVersion,
      generation,
      operation_id: operationId,
      state,
      actor_id: PRINCIPAL,
    },
  };
}

function fixture({
  authorization = "ALLOW",
  admissions = [2],
  controlAllowed = true,
  onAdapterExecute = async () => {},
} = {}) {
  const calls = [];
  const versions = [...admissions];
  const adapter = {
    async execute(scope, operation) {
      calls.push(["adapter", scope, operation]);
      await onAdapterExecute();
      return { found: true, tenantId: scope.tenantId };
    },
    async project(lifecycleEvent) {
      calls.push(["project", lifecycleEvent.id]);
      return {
        tenantId: lifecycleEvent.subject,
        eventId: lifecycleEvent.id,
        status: "SUCCEEDED",
      };
    },
    async snapshot({ tenantId }) {
      calls.push(["snapshot", tenantId]);
      return { state: "ACTIVE", recordCount: 1 };
    },
  };
  const tenantRegistry = {
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      calls.push(["admit", tenantId, expectedTenantKind]);
      const lifecycleVersion = versions.shift() ?? admissions.at(-1);
      if (lifecycleVersion === "DENY") {
        const error = new Error("not active");
        error.code = "TENANT_NOT_ACTIVE";
        throw error;
      }
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const authorizer = {
    async enforce(serverContext, storageRequest, descriptor) {
      calls.push([
        "authorize",
        serverContext.tenantId,
        storageRequest.resourceId,
        descriptor.surface,
      ]);
      if (authorization !== "ALLOW") {
        const error = new Error("denied");
        error.code = authorization;
        throw error;
      }
      return {
        decisionId: "azd_synthetic",
        evidenceRef: "evidence://c06/decisions/azd_synthetic",
        policyVersion: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
      };
    },
  };
  const boundary = createTenantDataBoundary({
    tenantRegistry,
    authorizer,
    lifecycleSource: {
      async verify(value) {
        return {
          source: "C03_EVENT_OUTBOX_PAIR",
          tenantId: value.subject,
          eventId: value.id,
          eventSha256: sha256(value),
        };
      },
    },
    operationCatalog,
    adapters: {
      "c07.postgres": adapter,
      "c07.object-storage": adapter,
    },
    controlAuthorize: async (controlContext, action, target) => {
      calls.push(["controlAuthorize", controlContext, action, target]);
      return controlAllowed;
    },
  });
  return { adapter, boundary, calls };
}

test("C07 executes only after authorization and active admission", async () => {
  const { boundary, calls } = fixture();
  const result = await boundary.execute(context(), request());

  assert.equal(result.operationId, "SQL_GET");
  assert.equal(result.value.tenantId, TENANT_A);
  assert.equal(result.tenantLifecycleVersion, 2);
  assert.deepEqual(
    calls.map(([kind]) => kind),
    ["authorize", "admit", "adapter"],
  );
  assert.equal(calls[2][1].trustSource, "C07_VERIFIED_TENANT_SCOPE");
  assert.equal(calls[2][1].tenantId, TENANT_A);
  assert.equal(calls[2][2].surface, "READ");
});

test("C07 rejects caller supplied routing fields before dependencies", async () => {
  for (const injected of [
    { tenantId: TENANT_A },
    { surface: "READ" },
    { adapterId: "c07.postgres" },
    { path: "records" },
  ]) {
    const { boundary, calls } = fixture();
    await assert.rejects(
      boundary.execute(context(), {
        ...request(),
        ...injected,
      }),
      { code: "INVALID_INPUT" },
    );
    assert.equal(calls.length, 0);
  }
  for (const field of ["sql", "bucket", "prefix"]) {
    const { boundary, calls } = fixture();
    await assert.rejects(
      boundary.execute(
        context(),
        request({
          resourceId: "doc_synthetic_a",
          [field]: "caller-controlled",
        }),
      ),
      { code: "INVALID_INPUT" },
    );
    assert.equal(calls.length, 0);
  }
});

test("C07 rejects untrusted routes and Enterprise Tenant IDs", async () => {
  const untrusted = fixture();
  await assert.rejects(
    untrusted.boundary.execute(
      { ...context(), routeTrustSource: "CLIENT_REQUEST" },
      request(),
    ),
    { code: "UNTRUSTED_ROUTE" },
  );
  await assert.rejects(
    untrusted.boundary.execute(
      {
        ...context(),
        tenantId: "etn_01984910-0000-7000-8000-000000000001",
      },
      request(),
    ),
    { code: "P3_REQUIRED" },
  );
  assert.equal(untrusted.calls.length, 0);
});

test("C07 fails closed before any Adapter access on deny or outage", async () => {
  for (const code of ["ACCESS_DENIED", "AUTHORIZATION_UNAVAILABLE"]) {
    const { boundary, calls } = fixture({ authorization: code });
    await assert.rejects(boundary.execute(context(), request()), {
      code,
    });
    assert.deepEqual(calls.map(([kind]) => kind), ["authorize"]);
  }
});

test("C07 reauthorizes every cache request, including a denied hit", async () => {
  let allow = true;
  const calls = [];
  const adapter = {
    async execute() {
      calls.push("cache");
      return { hit: true, value: "synthetic" };
    },
    async project(value) {
      return {
        tenantId: value.subject,
        eventId: value.id,
        status: "SUCCEEDED",
      };
    },
    async snapshot() {
      return { cacheCount: 1 };
    },
  };
  const boundary = createTenantDataBoundary({
    tenantRegistry: {
      async admitNewRequest({ tenantId }) {
        calls.push("admit");
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
          trustSource: "VERIFIED_SERVER_CONTEXT",
        };
      },
    },
    authorizer: {
      async enforce() {
        calls.push("authorize");
        if (!allow) {
          const error = new Error("denied");
          error.code = "ACCESS_DENIED";
          throw error;
        }
        return {
          decisionId: `azd_${calls.length}`,
          evidenceRef: "evidence://c06/cache",
          policyVersion: "model-cache",
        };
      },
    },
    lifecycleSource: {
      async verify() {
        throw new Error("not used");
      },
    },
    operationCatalog,
    adapters: {
      "c07.postgres": adapter,
      "c07.object-storage": adapter,
    },
  });
  const cacheRequest = request({ cacheKey: "answer" });

  await boundary.execute(context("CACHE_GET"), cacheRequest);
  await boundary.execute(context("CACHE_GET"), cacheRequest);
  allow = false;
  await assert.rejects(
    boundary.execute(context("CACHE_GET"), cacheRequest),
    { code: "ACCESS_DENIED" },
  );

  assert.equal(calls.filter((value) => value === "authorize").length, 3);
  assert.equal(calls.filter((value) => value === "cache").length, 2);
});

test("LIFECYCLE-SUSPENDED-01 blocks a warm cache before Adapter access", async () => {
  const { boundary, calls } = fixture({ admissions: [2, "DENY"] });
  const cacheRequest = request({ cacheKey: "warm-answer" });

  await boundary.execute(context("CACHE_GET"), cacheRequest);
  await assert.rejects(
    boundary.execute(context("CACHE_GET"), cacheRequest),
    { code: "TENANT_NOT_ACTIVE" },
  );

  assert.equal(calls.filter(([kind]) => kind === "adapter").length, 1);
  assert.deepEqual(
    calls.map(([kind]) => kind),
    ["authorize", "admit", "adapter", "authorize", "admit"],
  );
});

test("C07 lets an admitted request finish but rejects the next request", async () => {
  let releaseAdapter;
  let markAdapterStarted;
  const adapterStarted = new Promise((resolve) => {
    markAdapterStarted = resolve;
  });
  const adapterGate = new Promise((resolve) => {
    releaseAdapter = resolve;
  });
  const { boundary, calls } = fixture({
    admissions: [2, "DENY"],
    async onAdapterExecute() {
      markAdapterStarted();
      await adapterGate;
    },
  });
  const inFlight = boundary.execute(context(), request());
  await adapterStarted;
  const nextRequest = assert.rejects(
    boundary.execute(context(), request()),
    { code: "TENANT_NOT_ACTIVE" },
  );
  releaseAdapter();

  const admitted = await inFlight;
  await nextRequest;
  assert.equal(admitted.tenantLifecycleVersion, 2);
  assert.equal(calls.filter(([kind]) => kind === "adapter").length, 1);
});

test("C07 normalizes inactive Tenant admission without touching storage", async () => {
  const { boundary, calls } = fixture({ admissions: ["DENY"] });
  await assert.rejects(boundary.execute(context(), request()), {
    code: "TENANT_NOT_ACTIVE",
  });
  assert.deepEqual(
    calls.map(([kind]) => kind),
    ["authorize", "admit"],
  );
});

test("the C06 authorizer fixes the surface from the operation catalog", async () => {
  let captured;
  const authorizer = createC06TenantDataAuthorizer({
    authorizationFacade: {
      async decide(serverContext, authorizationRequest) {
        captured = { serverContext, authorizationRequest };
        return {
          effect: "ALLOW",
          authorizationStatus: "ALLOWED",
          decisionId: "azd_catalog_surface",
          evidenceRef: "evidence://c06/catalog-surface",
          authorizationModelId: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
        };
      },
    },
  });
  const result = await authorizer.enforce(
    context("VECTOR_SEARCH"),
    request({ embedding: [1, 0, 0], limit: 5 }),
    operationCatalog.resolve("VECTOR_SEARCH"),
  );

  assert.equal(captured.serverContext.surface, "RETRIEVE");
  assert.equal(Object.hasOwn(captured.authorizationRequest, "surface"), false);
  assert.equal(result.decisionId, "azd_catalog_surface");
});

test("C07 projects every Adapter and freezes an exact duplicate", async () => {
  const { boundary, calls } = fixture();
  const lifecycleEvent = event();
  const first = await boundary.project(
    { synthetic: true, trustSource: "VERIFIED_C03_OUTBOX" },
    lifecycleEvent,
  );
  const second = await boundary.project(
    { synthetic: true, trustSource: "VERIFIED_C03_OUTBOX" },
    lifecycleEvent,
  );

  assert.equal(first.status, "SUCCEEDED");
  assert.equal(first.receipts.length, 2);
  assert.equal(first.duplicate, false);
  assert.equal(second.duplicate, true);
  assert.equal(calls.filter(([kind]) => kind === "project").length, 2);
});

test("C07 reports lifecycle success only after every Adapter converges", async () => {
  const lifecycleEvent = event();
  const projectCalls = [];
  let failSecond = true;
  const adapter = (id) => ({
    async execute() {
      return null;
    },
    async project(value) {
      projectCalls.push(id);
      if (id === "second" && failSecond) {
        failSecond = false;
        throw new Error("synthetic projection failure");
      }
      return {
        tenantId: value.subject,
        eventId: value.id,
        status: "SUCCEEDED",
      };
    },
    async snapshot() {
      return {};
    },
  });
  const boundary = createTenantDataBoundary({
    tenantRegistry: {
      async admitNewRequest() {
        throw new Error("not used");
      },
    },
    authorizer: {
      async enforce() {
        throw new Error("not used");
      },
    },
    lifecycleSource: {
      async verify(value) {
        return {
          source: "C03_EVENT_OUTBOX_PAIR",
          tenantId: value.subject,
          eventId: value.id,
          eventSha256: sha256(value),
        };
      },
    },
    operationCatalog,
    adapters: {
      "c07.postgres": adapter("first"),
      "c07.object-storage": adapter("second"),
    },
  });

  await assert.rejects(
    boundary.project(
      { synthetic: true, trustSource: "VERIFIED_C03_OUTBOX" },
      lifecycleEvent,
    ),
    { code: "PROJECTION_INCOMPLETE" },
  );
  const retried = await boundary.project(
    { synthetic: true, trustSource: "VERIFIED_C03_OUTBOX" },
    lifecycleEvent,
  );
  assert.equal(retried.status, "SUCCEEDED");
  assert.deepEqual(projectCalls, ["first", "second", "first", "second"]);
});

test("LIFECYCLE-DELETING-01 denies reads while storage projection is incomplete", async () => {
  let releaseProjection;
  let markProjectionStarted;
  let gateFirstProjection = true;
  let failObjectProjection = true;
  let executeCalls = 0;
  const projectionStarted = new Promise((resolve) => {
    markProjectionStarted = resolve;
  });
  const projectionGate = new Promise((resolve) => {
    releaseProjection = resolve;
  });
  const adapter = (id) => ({
    async execute() {
      executeCalls += 1;
      return [];
    },
    async project(value) {
      if (id === "postgres" && gateFirstProjection) {
        gateFirstProjection = false;
        markProjectionStarted();
        await projectionGate;
      }
      if (id === "object" && failObjectProjection) {
        failObjectProjection = false;
        throw new Error("synthetic purge incomplete");
      }
      return {
        tenantId: value.subject,
        eventId: value.id,
        status: "SUCCEEDED",
      };
    },
    async snapshot() {
      return {};
    },
  });
  const boundary = createTenantDataBoundary({
    tenantRegistry: {
      async admitNewRequest() {
        const error = new Error("deleting");
        error.code = "TENANT_NOT_ACTIVE";
        throw error;
      },
    },
    authorizer: {
      async enforce() {
        return {
          decisionId: "azd_c07_deleting",
          evidenceRef: "evidence://c07/deleting",
          policyVersion: "c07-deleting-policy-v1",
        };
      },
    },
    lifecycleSource: {
      async verify(value) {
        return {
          source: "C03_EVENT_OUTBOX_PAIR",
          tenantId: value.subject,
          eventId: value.id,
          eventSha256: sha256(value),
        };
      },
    },
    operationCatalog,
    adapters: {
      "c07.postgres": adapter("postgres"),
      "c07.object-storage": adapter("object"),
    },
  });
  const deletionEvent = event({
    id: "evt-c07-deleting-incomplete",
    type: "product.tenant.deletion-requested.v1",
    lifecycleVersion: 3,
    generation: 2,
    state: "DELETING",
    operationId: "op_01984910-0000-7000-8000-000000000014",
  });
  let projectionSettled = false;
  const projection = boundary.project(
    { synthetic: true, trustSource: "VERIFIED_C03_OUTBOX" },
    deletionEvent,
  );
  projection.then(
    () => {
      projectionSettled = true;
    },
    () => {
      projectionSettled = true;
    },
  );

  await projectionStarted;
  assert.equal(projectionSettled, false);
  await assert.rejects(
    boundary.execute(
      context("VECTOR_SEARCH"),
      request({ embedding: [1, 0, 0], limit: 5 }),
    ),
    { code: "TENANT_NOT_ACTIVE" },
  );
  assert.equal(executeCalls, 0);

  releaseProjection();
  await assert.rejects(projection, { code: "PROJECTION_INCOMPLETE" });
  const retried = await boundary.project(
    { synthetic: true, trustSource: "VERIFIED_C03_OUTBOX" },
    deletionEvent,
  );
  assert.equal(retried.status, "SUCCEEDED");
});

test("C07 rejects conflicting or untrusted lifecycle delivery", async () => {
  const { boundary } = fixture();
  const lifecycleEvent = event();
  await assert.rejects(
    boundary.project(
      { synthetic: true, trustSource: "CLIENT_EVENT" },
      lifecycleEvent,
    ),
    { code: "UNTRUSTED_WORKER" },
  );
  await boundary.project(
    { synthetic: true, trustSource: "VERIFIED_C03_OUTBOX" },
    lifecycleEvent,
  );
  await assert.rejects(
    boundary.project(
      { synthetic: true, trustSource: "VERIFIED_C03_OUTBOX" },
      {
        ...lifecycleEvent,
        data: { ...lifecycleEvent.data, generation: 2 },
      },
    ),
    { code: "LIFECYCLE_EVENT_CONFLICT" },
  );
});

test("C07 snapshot exposes counts only after control authorization", async () => {
  const denied = fixture({ controlAllowed: false });
  await assert.rejects(
    denied.boundary.snapshot({}, { tenantId: TENANT_A }),
    { code: "ACCESS_DENIED" },
  );

  const allowed = fixture();
  const value = await allowed.boundary.snapshot(
    { actorId: PRINCIPAL },
    { tenantId: TENANT_A },
  );
  assert.equal(value.adapters.length, 2);
  assert.equal(value.adapters[0].recordCount, 1);
  assert.equal(JSON.stringify(value).includes("synthetic-session"), false);
  const authorization = allowed.calls.find(
    ([kind]) => kind === "controlAuthorize",
  );
  assert.deepEqual(authorization[3], {
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
  });
});

test("C03 lifecycle verifier requires an exact event/outbox pair", async () => {
  const lifecycleEvent = event();
  const verifier = createC03TenantLifecycleVerifier({
    tenantStore: {
      async readTenantSnapshot() {
        return {
          lifecycleEvents: [structuredClone(lifecycleEvent)],
          outbox: [structuredClone(lifecycleEvent)],
        };
      },
    },
  });
  const evidence = await verifier.verify(lifecycleEvent);
  assert.equal(evidence.source, "C03_EVENT_OUTBOX_PAIR");
  assert.equal(evidence.eventId, lifecycleEvent.id);

  const tampered = createC03TenantLifecycleVerifier({
    tenantStore: {
      async readTenantSnapshot() {
        return {
          lifecycleEvents: [structuredClone(lifecycleEvent)],
          outbox: [
            {
              ...lifecycleEvent,
              data: { ...lifecycleEvent.data, state: "SUSPENDED" },
            },
          ],
        };
      },
    },
  });
  await assert.rejects(
    tampered.verify(lifecycleEvent),
    { code: "UNTRUSTED_LIFECYCLE_EVENT" },
  );
});
