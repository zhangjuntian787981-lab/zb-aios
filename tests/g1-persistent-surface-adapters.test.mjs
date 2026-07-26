import assert from "node:assert/strict";
import test from "node:test";
import { createG1SyntheticRuntime } from "../lib/g1-synthetic-runtime.mjs";
import { createG1PersistentSurfaceAdapters } from "./integration/g1-persistent-surface-adapters.mjs";

const SURFACES = [
  "SQL",
  "VECTOR",
  "FILE",
  "OBJECT",
  "SEARCH",
  "CACHE",
  "TOOL",
  "RESTORE_REPLICA",
];

function backendObservations(instanceId, { readOnly = false } = {}) {
  return {
    backendKind: "NON_GATE_TEST_DOUBLE",
    backendInstanceId: instanceId,
    persistent: false,
    readOnly,
    negativeStorageTouchCount: 0,
  };
}

function createRecordingC07(instanceId, { readOnly = false } = {}) {
  const calls = [];
  const records = new Map();

  return {
    backend: {
      async execute(scope, operation) {
        calls.push({
          scope: structuredClone(scope),
          operation: structuredClone(operation),
        });
        const key = `${scope.tenantId}|${operation.resourceId}`;
        if (operation.kind === "SQL_PUT") {
          records.set(key, { value: operation.input.value });
          return { resourceId: operation.resourceId };
        }
        if (operation.kind === "SQL_GET") {
          return records.get(key) ?? null;
        }
        if (operation.kind === "VECTOR_UPSERT") {
          records.set(key, { metadata: operation.input.metadata });
          return { resourceId: operation.resourceId };
        }
        if (operation.kind === "VECTOR_SEARCH") {
          return [...records.entries()]
            .filter(([recordKey]) =>
              recordKey.startsWith(`${scope.tenantId}|`),
            )
            .map(([recordKey, record]) => ({
              resourceId: recordKey.split("|")[1],
              metadata: record.metadata,
              distance: 0,
            }));
        }
        if (operation.kind === "SEARCH_INDEX") {
          records.set(key, {
            metadata: operation.input.metadata,
            text: operation.input.text,
          });
          return { resourceId: operation.resourceId };
        }
        if (operation.kind === "SEARCH_QUERY") {
          return [...records.entries()]
            .filter(
              ([recordKey, record]) =>
                recordKey.startsWith(`${scope.tenantId}|`) &&
                record.text?.includes(operation.input.query),
            )
            .map(([recordKey, record]) => ({
              resourceId: recordKey.split("|")[1],
              metadata: record.metadata,
              rank: 1,
            }));
        }
        if (operation.kind === "CACHE_PUT") {
          records.set(
            `${scope.tenantId}|${operation.input.cacheKey}`,
            { value: operation.input.value },
          );
          return { cacheKey: operation.input.cacheKey };
        }
        if (operation.kind === "CACHE_GET") {
          return (
            records.get(
              `${scope.tenantId}|${operation.input.cacheKey}`,
            ) ?? null
          );
        }
        throw new Error(`Unexpected C07 operation: ${operation.kind}`);
      },
      observations() {
        return backendObservations(instanceId, { readOnly });
      },
    },
    calls,
    records,
  };
}

function createRecordingFileStore() {
  const calls = [];
  const records = new Map();
  return {
    backend: {
      async put(input) {
        calls.push({ method: "put", input: structuredClone(input) });
        records.set(input.quarantineRef, Buffer.from(input.content));
        return input.quarantineRef;
      },
      async read(input) {
        calls.push({ method: "read", input: structuredClone(input) });
        return Buffer.from(records.get(input.quarantineRef));
      },
      observations() {
        return backendObservations("recording-c10-file");
      },
    },
    calls,
  };
}

function createRecordingObjectStore() {
  const calls = [];
  const records = new Map();
  return {
    backend: {
      async execute(scope, operation) {
        calls.push({
          scope: structuredClone(scope),
          operation: structuredClone(operation),
        });
        const key = `${scope.tenantId}|${operation.input.objectKey}`;
        if (operation.kind === "OBJECT_PUT") {
          records.set(key, {
            tenantId: scope.tenantId,
            resourceId: operation.resourceId,
            objectKey: operation.input.objectKey,
            contentType: operation.input.contentType,
            body: operation.input.body,
          });
          return { resourceId: operation.resourceId };
        }
        if (operation.kind === "OBJECT_GET") {
          return records.get(key) ?? null;
        }
        throw new Error(`Unexpected object operation: ${operation.kind}`);
      },
      observations() {
        return backendObservations("recording-object-root");
      },
    },
    calls,
  };
}

function createRecordingC16Gateway() {
  const calls = [];
  return {
    backend: {
      async confirmBound(input) {
        calls.push({ method: "confirmBound", input: structuredClone(input) });
        return {
          confirmationId: `confirmation-${calls.length}`,
          tenantId: input.tenantId,
          confirmationSha256: "sha256:" + "a".repeat(64),
          normalizedParamSha256: "sha256:" + "b".repeat(64),
        };
      },
      async executeBound(input) {
        calls.push({ method: "executeBound", input: structuredClone(input) });
        return {
          tenantId: input.tenantId,
          status: "SUCCEEDED",
          result: { synthetic: true },
          receipt: {
            networkRequestCount: 0,
            externalEffectCount: 0,
          },
        };
      },
      observations() {
        return backendObservations("recording-c16-gateway");
      },
    },
    calls,
  };
}

function createRestoreVerifier() {
  const calls = [];
  return {
    verifier: {
      async verify(input) {
        calls.push(structuredClone(input));
        return {
          restoreId: "recording-restore-1",
          sourceBackendInstanceId: "recording-c07-source",
          replicaBackendInstanceId: "recording-c07-restore",
          sourceSha256: "sha256:" + "c".repeat(64),
          replicaSha256: "sha256:" + "c".repeat(64),
          verified: true,
        };
      },
    },
    calls,
  };
}

async function harness() {
  const deployment = await (await createG1SyntheticRuntime()).deploy();
  const c07Source = createRecordingC07("recording-c07-source");
  const c07Restore = createRecordingC07(
    "recording-c07-restore",
    { readOnly: true },
  );
  const fileStore = createRecordingFileStore();
  const objectStore = createRecordingObjectStore();
  const c16Gateway = createRecordingC16Gateway();
  const restore = createRestoreVerifier();
  const lifecycleVersionByTenant = Object.fromEntries(
    deployment.tenants.map(({ tenantId }) => [tenantId, 2]),
  );
  const adapters = createG1PersistentSurfaceAdapters({
    c07Source: c07Source.backend,
    c07Restore: c07Restore.backend,
    fileStore: fileStore.backend,
    objectStore: objectStore.backend,
    c16Gateway: c16Gateway.backend,
    deployment,
    lifecycleVersionByTenant,
    restoreVerifier: restore.verifier,
  });
  return {
    deployment,
    adapters,
    c07Source,
    c07Restore,
    fileStore,
    objectStore,
    c16Gateway,
    restore,
  };
}

function inputs(tenant, owner, surface) {
  const resourceId =
    `${owner.fixtureUserId}-${surface.toLowerCase().replaceAll("_", "-")}`;
  const authorization = {
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    c06BoundaryEntered: true,
    tenantId: tenant.tenantId,
    surface,
    resourceId,
    sessionId: owner.sessionId,
    principalId: owner.principalId,
    authoritativeRole: owner.role,
    storeId: `store-${tenant.tenantId}`,
    authorizationModelId: "g1-role-model-v2",
    consistency: "HIGHER_CONSISTENCY",
  };
  const attribution = {
    tenantId: tenant.tenantId,
    userId: owner.fixtureUserId,
    role: owner.role,
    principalId: owner.principalId,
  };
  return {
    seed: {
      caseId: `case-${surface.toLowerCase()}`,
      tenantId: tenant.tenantId,
      surface,
      resourceId,
      attribution,
      authorization,
    },
    read: {
      caseId: `case-${surface.toLowerCase()}`,
      tenantId: tenant.tenantId,
      surface,
      resourceId,
      caller: attribution,
      authorization,
    },
  };
}

test("maps all eight surfaces to their required backend operations", async () => {
  const value = await harness();
  const tenant = value.deployment.tenants[0];
  const owner = tenant.users[0];

  assert.deepEqual(Object.keys(value.adapters), SURFACES);
  for (const surface of SURFACES) {
    const input = inputs(tenant, owner, surface);
    if (surface === "RESTORE_REPLICA") {
      value.c07Restore.records.set(
        `${tenant.tenantId}|${input.read.resourceId}`,
        {
          value: {
            attribution: input.read.caller,
            marker: `RESTORE_REPLICA:${input.read.caseId}`,
          },
        },
      );
    }
    await value.adapters[surface].seed(input.seed);
    const output = await value.adapters[surface].read(input.read);
    assert.deepEqual(output.attribution, input.read.caller);
    assert.deepEqual(value.adapters[surface].observations(), {
      backendKind: "NON_GATE_TEST_DOUBLE",
      backendInstanceId:
        surface === "RESTORE_REPLICA"
          ? "recording-c07-restore"
          : ["SQL", "VECTOR", "SEARCH", "CACHE"].includes(surface)
            ? "recording-c07-source"
            : surface === "FILE"
              ? "recording-c10-file"
              : surface === "OBJECT"
                ? "recording-object-root"
                : "recording-c16-gateway",
      persistent: false,
      seedCount: 1,
      readCount: 1,
      touchCount: 2,
      negativeStorageTouchCount: 0,
    });
  }

  assert.deepEqual(
    value.c07Source.calls.map(({ operation }) => operation.kind),
    [
      "SQL_PUT",
      "SQL_GET",
      "VECTOR_UPSERT",
      "VECTOR_SEARCH",
      "SEARCH_INDEX",
      "SEARCH_QUERY",
      "CACHE_PUT",
      "CACHE_GET",
    ],
  );
  assert.deepEqual(
    value.fileStore.calls.map(({ method }) => method),
    ["put", "read"],
  );
  assert.deepEqual(
    value.objectStore.calls.map(({ operation }) => operation.kind),
    ["OBJECT_PUT", "OBJECT_GET"],
  );
  assert.deepEqual(
    value.c16Gateway.calls.map(({ method }) => method),
    ["confirmBound", "executeBound"],
  );
  assert.equal(
    value.c16Gateway.calls.every(
      ({ input }) => input.authorization === undefined ||
        input.authorization.c06BoundaryEntered === true,
    ),
    true,
  );
  assert.equal(value.restore.calls.length, 1);
  assert.deepEqual(
    value.c07Restore.calls.map(({ operation }) => operation.kind),
    ["SQL_GET"],
  );
});

test("fails closed before every backend when the outer C06 decision is denied", async () => {
  const value = await harness();
  const tenant = value.deployment.tenants[0];
  const owner = tenant.users[0];
  const before = {
    c07: value.c07Source.calls.length,
    restore: value.c07Restore.calls.length,
    file: value.fileStore.calls.length,
    object: value.objectStore.calls.length,
    tool: value.c16Gateway.calls.length,
    verifier: value.restore.calls.length,
  };

  for (const surface of SURFACES) {
    const input = inputs(tenant, owner, surface);
    input.seed.authorization.effect = "DENY";
    input.seed.authorization.authorizationStatus = "DENIED";
    input.read.authorization.effect = "DENY";
    input.read.authorization.authorizationStatus = "DENIED";
    await assert.rejects(
      value.adapters[surface].seed(input.seed),
      (error) => error.code === "G1_SURFACE_ACCESS_DENIED",
    );
    await assert.rejects(
      value.adapters[surface].read(input.read),
      (error) => error.code === "G1_SURFACE_ACCESS_DENIED",
    );
    assert.equal(
      value.adapters[surface].observations()
        .negativeStorageTouchCount,
      0,
    );
  }

  assert.deepEqual(
    {
      c07: value.c07Source.calls.length,
      restore: value.c07Restore.calls.length,
      file: value.fileStore.calls.length,
      object: value.objectStore.calls.length,
      tool: value.c16Gateway.calls.length,
      verifier: value.restore.calls.length,
    },
    before,
  );
});
