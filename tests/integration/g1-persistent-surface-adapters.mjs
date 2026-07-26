import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createC07OperationCatalog } from "../../lib/c07-operation-catalog.mjs";
import { c10Sha256 } from "../../lib/knowledge-catalog.mjs";

const EXPECTED_BACKEND_KINDS = Object.freeze({
  c07Source: "POSTGRESQL_C07_SOURCE",
  c07Restore: "POSTGRESQL_C07_RESTORE_REPLICA",
  fileStore: "C10_FILE_QUARANTINE",
  objectStore: "C07_FILE_OBJECT_ROOT",
  c16Gateway: "C16_POSTGRESQL_GATEWAY_C0",
});
const TEST_DOUBLE_KIND = "NON_GATE_TEST_DOUBLE";
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const C07_CATALOG = createC07OperationCatalog(
  JSON.parse(
    readFileSync(
      new URL(
        "../../implementation/p1/c07/operation-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);
const C16_FIXTURES = JSON.parse(
  readFileSync(
    new URL(
      "../../implementation/p1/c16/synthetic-tool-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
).records;
const TOOL_OPERATION_BY_ROLE = Object.freeze({
  sales_analyst: "synthetic.approval.status.get",
  operations_planner: "synthetic.erp.order.get",
  quality_reviewer: "synthetic.bi.metric.get",
});

function fail(code) {
  const error = new Error(code);
  error.name = "G1PersistentSurfaceAdapterError";
  error.code = code;
  throw error;
}

function exactObject(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) {
    fail("G1_SURFACE_INVALID_INPUT");
  }
}

function validateBackend(source, methods, expectedKind, readOnly = false) {
  if (
    !source ||
    methods.some((method) => typeof source[method] !== "function") ||
    typeof source.observations !== "function"
  ) {
    fail("G1_SURFACE_INVALID_BACKEND");
  }
  const observation = source.observations();
  if (
    !observation ||
    typeof observation.backendKind !== "string" ||
    ![expectedKind, TEST_DOUBLE_KIND].includes(
      observation.backendKind,
    ) ||
    typeof observation.backendInstanceId !== "string" ||
    observation.backendInstanceId.length < 1 ||
    typeof observation.persistent !== "boolean" ||
    !Number.isSafeInteger(
      observation.negativeStorageTouchCount,
    ) ||
    observation.negativeStorageTouchCount < 0 ||
    (observation.backendKind === TEST_DOUBLE_KIND &&
      observation.persistent !== false) ||
    (readOnly && observation.readOnly !== true)
  ) {
    fail("G1_SURFACE_INVALID_BACKEND_EVIDENCE");
  }
  return observation;
}

function validateDeployment(deployment, lifecycleVersionByTenant) {
  if (
    !deployment ||
    !Array.isArray(deployment.tenants) ||
    deployment.tenants.length !== 3 ||
    !lifecycleVersionByTenant ||
    typeof lifecycleVersionByTenant !== "object" ||
    Array.isArray(lifecycleVersionByTenant)
  ) {
    fail("G1_SURFACE_INVALID_INPUT");
  }
  for (const tenant of deployment.tenants) {
    if (
      !Number.isSafeInteger(
        lifecycleVersionByTenant[tenant.tenantId],
      ) ||
      lifecycleVersionByTenant[tenant.tenantId] < 1
    ) {
      fail("G1_SURFACE_INVALID_INPUT");
    }
  }
}

function validateInput(input, surface, identityField) {
  exactObject(
    input,
    identityField === "attribution"
      ? [
          "caseId",
          "tenantId",
          "surface",
          "resourceId",
          "attribution",
          "authorization",
        ]
      : [
          "caseId",
          "tenantId",
          "surface",
          "resourceId",
          "caller",
          "authorization",
        ],
  );
  const identity = input[identityField];
  if (
    input.surface !== surface ||
    typeof input.caseId !== "string" ||
    !input.caseId ||
    typeof input.tenantId !== "string" ||
    typeof input.resourceId !== "string" ||
    !identity ||
    identity.tenantId !== input.tenantId ||
    typeof identity.userId !== "string" ||
    typeof identity.role !== "string" ||
    typeof identity.principalId !== "string"
  ) {
    fail("G1_SURFACE_INVALID_INPUT");
  }
  return identity;
}

function assertAllowed(input, surface, identityField) {
  const identity = validateInput(input, surface, identityField);
  const decision = input.authorization;
  if (
    decision?.effect !== "ALLOW" ||
    decision?.authorizationStatus !== "ALLOWED" ||
    decision?.c06BoundaryEntered !== true ||
    decision?.tenantId !== input.tenantId ||
    decision?.surface !== surface ||
    decision?.resourceId !== input.resourceId ||
    decision?.principalId !== identity.principalId ||
    decision?.authoritativeRole !== identity.role ||
    typeof decision?.storeId !== "string" ||
    typeof decision?.authorizationModelId !== "string" ||
    decision?.consistency !== "HIGHER_CONSISTENCY"
  ) {
    fail("G1_SURFACE_ACCESS_DENIED");
  }
  return identity;
}

function digest(value) {
  return createHash("sha256")
    .update(typeof value === "string" ? value : JSON.stringify(value))
    .digest("hex");
}

function operation(operationId, resourceId, input) {
  return {
    ...C07_CATALOG.resolve(operationId),
    resourceId,
    input,
  };
}

function payload(surface, input, attribution) {
  return {
    attribution: structuredClone(attribution),
    marker: `${surface}:${input.caseId}`,
  };
}

function scopeFor(input, lifecycleVersionByTenant) {
  const binding = digest({
    tenantId: input.tenantId,
    resourceId: input.resourceId,
    sessionId: input.authorization.sessionId,
    principalId: input.authorization.principalId,
    storeId: input.authorization.storeId,
    authorizationModelId:
      input.authorization.authorizationModelId,
    caseId: input.caseId,
  });
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: input.tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion:
      lifecycleVersionByTenant[input.tenantId],
    correlationId: input.caseId,
    decisionId: `g1-c06-role-${binding.slice(0, 32)}`,
    evidenceRef: `evidence://g1/c06-role/${binding}`,
    policyVersion: input.authorization.authorizationModelId,
  };
}

function vectorFor(resourceId) {
  const value = digest(resourceId);
  return [0, 2, 4].map(
    (offset) => Number.parseInt(value.slice(offset, offset + 2), 16) / 255,
  );
}

function wrapSurface({
  surface,
  backend,
  expectedBackendKind,
  seed,
  read,
  readOnly = false,
}) {
  validateBackend(
    backend,
    [],
    expectedBackendKind,
    readOnly,
  );
  let seedCount = 0;
  let readCount = 0;

  return Object.freeze({
    async seed(input) {
      assertAllowed(input, surface, "attribution");
      seedCount += 1;
      return seed(input);
    },
    async read(input) {
      assertAllowed(input, surface, "caller");
      readCount += 1;
      return read(input);
    },
    observations() {
      const current = validateBackend(
        backend,
        [],
        expectedBackendKind,
        readOnly,
      );
      return {
        backendKind: current.backendKind,
        backendInstanceId: current.backendInstanceId,
        persistent: current.persistent,
        seedCount,
        readCount,
        touchCount: seedCount + readCount,
        negativeStorageTouchCount:
          current.negativeStorageTouchCount,
      };
    },
  });
}

function postgresSurface({
  surface,
  backend,
  lifecycleVersionByTenant,
  seedOperation,
  seedInput,
  readOperation,
  readInput,
  select,
}) {
  return wrapSurface({
    surface,
    backend,
    expectedBackendKind: EXPECTED_BACKEND_KINDS.c07Source,
    async seed(input) {
      const attribution = input.attribution;
      await backend.execute(
        scopeFor(input, lifecycleVersionByTenant),
        operation(
          seedOperation,
          input.resourceId,
          seedInput(input, payload(surface, input, attribution)),
        ),
      );
    },
    async read(input) {
      const value = await backend.execute(
        scopeFor(input, lifecycleVersionByTenant),
        operation(
          readOperation,
          input.resourceId,
          readInput(input),
        ),
      );
      return select(value, input.resourceId);
    },
  });
}

function fileCoordinates(input, identity) {
  const content = Buffer.from(
    JSON.stringify(payload("FILE", input, identity)),
  );
  const contentSha256 = c10Sha256(content);
  return {
    content,
    contentSha256,
    quarantineRef:
      `quarantine://c10/${input.tenantId}/${input.resourceId}/1/` +
      contentSha256.slice(7),
  };
}

function toolFixture(input) {
  const operationId =
    TOOL_OPERATION_BY_ROLE[input.attribution?.role ?? input.caller?.role];
  const record = C16_FIXTURES.find(
    (candidate) =>
      candidate.tenantId === input.tenantId &&
      candidate.operationId === operationId,
  );
  if (!record) fail("G1_SURFACE_INVALID_INPUT");
  return {
    operationId,
    params: structuredClone(record.lookup),
  };
}

export function createG1PersistentSurfaceAdapters(options) {
  exactObject(options, [
    "c07Source",
    "c07Restore",
    "fileStore",
    "objectStore",
    "c16Gateway",
    "deployment",
    "lifecycleVersionByTenant",
    "restoreVerifier",
  ]);
  validateDeployment(
    options.deployment,
    options.lifecycleVersionByTenant,
  );
  validateBackend(
    options.c07Source,
    ["execute"],
    EXPECTED_BACKEND_KINDS.c07Source,
  );
  const sourceObservation = options.c07Source.observations();
  validateBackend(
    options.c07Restore,
    ["execute"],
    EXPECTED_BACKEND_KINDS.c07Restore,
    true,
  );
  const restoreObservation = options.c07Restore.observations();
  validateBackend(
    options.fileStore,
    ["put", "read"],
    EXPECTED_BACKEND_KINDS.fileStore,
  );
  validateBackend(
    options.objectStore,
    ["execute"],
    EXPECTED_BACKEND_KINDS.objectStore,
  );
  validateBackend(
    options.c16Gateway,
    ["confirmBound", "executeBound"],
    EXPECTED_BACKEND_KINDS.c16Gateway,
  );
  if (typeof options.restoreVerifier?.verify !== "function") {
    fail("G1_SURFACE_INVALID_BACKEND");
  }

  const lifecycleVersionByTenant =
    options.lifecycleVersionByTenant;
  const confirmations = new Map();
  const restoreVerifications = new Set();
  const sql = postgresSurface({
    surface: "SQL",
    backend: options.c07Source,
    lifecycleVersionByTenant,
    seedOperation: "SQL_PUT",
    seedInput: (_input, value) => ({ value }),
    readOperation: "SQL_GET",
    readInput: (input) => ({ resourceId: input.resourceId }),
    select: (value) => value?.value ?? null,
  });
  const vector = postgresSurface({
    surface: "VECTOR",
    backend: options.c07Source,
    lifecycleVersionByTenant,
    seedOperation: "VECTOR_UPSERT",
    seedInput: (input, metadata) => ({
      resourceId: input.resourceId,
      embedding: vectorFor(input.resourceId),
      metadata,
    }),
    readOperation: "VECTOR_SEARCH",
    readInput: (input) => ({
      embedding: vectorFor(input.resourceId),
      limit: 100,
    }),
    select: (values, selectedResourceId) =>
      values?.find(
        ({ resourceId }) => resourceId === selectedResourceId,
      )?.metadata ?? null,
  });
  const search = postgresSurface({
    surface: "SEARCH",
    backend: options.c07Source,
    lifecycleVersionByTenant,
    seedOperation: "SEARCH_INDEX",
    seedInput: (input, metadata) => ({
      resourceId: input.resourceId,
      text: `g1token${digest(input.resourceId)}`,
      metadata,
    }),
    readOperation: "SEARCH_QUERY",
    readInput: (input) => ({
      query: `g1token${digest(input.resourceId)}`,
      limit: 100,
    }),
    select: (values, selectedResourceId) =>
      values?.find(
        ({ resourceId }) => resourceId === selectedResourceId,
      )?.metadata ?? null,
  });
  const cache = postgresSurface({
    surface: "CACHE",
    backend: options.c07Source,
    lifecycleVersionByTenant,
    seedOperation: "CACHE_PUT",
    seedInput: (input, value) => ({
      cacheKey: input.resourceId,
      value,
      ttlSeconds: 3600,
    }),
    readOperation: "CACHE_GET",
    readInput: (input) => ({ cacheKey: input.resourceId }),
    select: (value) => value?.value ?? null,
  });
  const file = wrapSurface({
    surface: "FILE",
    backend: options.fileStore,
    expectedBackendKind: EXPECTED_BACKEND_KINDS.fileStore,
    async seed(input) {
      const coordinates = fileCoordinates(
        input,
        input.attribution,
      );
      await options.fileStore.put({
        tenantId: input.tenantId,
        quarantineRef: coordinates.quarantineRef,
        contentSha256: coordinates.contentSha256,
        content: coordinates.content,
      });
    },
    async read(input) {
      const coordinates = fileCoordinates(input, input.caller);
      const content = await options.fileStore.read({
        tenantId: input.tenantId,
        quarantineRef: coordinates.quarantineRef,
        contentSha256: coordinates.contentSha256,
      });
      return JSON.parse(Buffer.from(content).toString("utf8"));
    },
  });
  const object = wrapSurface({
    surface: "OBJECT",
    backend: options.objectStore,
    expectedBackendKind: EXPECTED_BACKEND_KINDS.objectStore,
    async seed(input) {
      await options.objectStore.execute(
        scopeFor(input, lifecycleVersionByTenant),
        operation("OBJECT_PUT", input.resourceId, {
          objectKey: `${input.resourceId}.json`,
          body: JSON.stringify(
            payload("OBJECT", input, input.attribution),
          ),
          contentType: "application/json",
        }),
      );
    },
    async read(input) {
      const value = await options.objectStore.execute(
        scopeFor(input, lifecycleVersionByTenant),
        operation("OBJECT_GET", input.resourceId, {
          objectKey: `${input.resourceId}.json`,
        }),
      );
      return value ? JSON.parse(value.body) : null;
    },
  });
  const tool = wrapSurface({
    surface: "TOOL",
    backend: options.c16Gateway,
    expectedBackendKind: EXPECTED_BACKEND_KINDS.c16Gateway,
    async seed(input) {
      const fixture = toolFixture(input);
      const confirmation = await options.c16Gateway.confirmBound({
        tenantId: input.tenantId,
        resourceId: input.resourceId,
        caseId: input.caseId,
        ...fixture,
        authorization: structuredClone(input.authorization),
      });
      if (
        confirmation?.tenantId !== input.tenantId ||
        typeof confirmation?.confirmationId !== "string" ||
        !SHA256.test(confirmation?.confirmationSha256 ?? "") ||
        !SHA256.test(confirmation?.normalizedParamSha256 ?? "")
      ) {
        fail("G1_SURFACE_INVALID_BACKEND_RESPONSE");
      }
      confirmations.set(
        `${input.tenantId}|${input.resourceId}`,
        structuredClone(confirmation),
      );
    },
    async read(input) {
      const confirmation = confirmations.get(
        `${input.tenantId}|${input.resourceId}`,
      );
      if (!confirmation) fail("G1_SURFACE_SEED_REQUIRED");
      const fixture = toolFixture(input);
      const outcome = await options.c16Gateway.executeBound({
        tenantId: input.tenantId,
        resourceId: input.resourceId,
        caseId: input.caseId,
        operationId: fixture.operationId,
        confirmation: structuredClone(confirmation),
        authorization: structuredClone(input.authorization),
      });
      if (
        outcome?.tenantId !== input.tenantId ||
        outcome?.status !== "SUCCEEDED" ||
        outcome?.receipt?.networkRequestCount !== 0 ||
        outcome?.receipt?.externalEffectCount !== 0
      ) {
        fail("G1_SURFACE_INVALID_BACKEND_RESPONSE");
      }
      return {
        attribution: structuredClone(input.caller),
        marker: `TOOL:${input.caseId}`,
        value: structuredClone(outcome.result),
      };
    },
  });
  const restore = wrapSurface({
    surface: "RESTORE_REPLICA",
    backend: options.c07Restore,
    expectedBackendKind: EXPECTED_BACKEND_KINDS.c07Restore,
    readOnly: true,
    async seed(input) {
      const verification = await options.restoreVerifier.verify({
        tenantId: input.tenantId,
        resourceId: input.resourceId,
      });
      if (
        verification?.verified !== true ||
        verification?.sourceBackendInstanceId !==
          sourceObservation.backendInstanceId ||
        verification?.replicaBackendInstanceId !==
          restoreObservation.backendInstanceId ||
        !SHA256.test(verification?.sourceSha256 ?? "") ||
        verification.sourceSha256 !== verification.replicaSha256 ||
        typeof verification?.restoreId !== "string"
      ) {
        fail("G1_RESTORE_HASH_VERIFICATION_FAILED");
      }
      restoreVerifications.add(
        `${input.tenantId}|${input.resourceId}`,
      );
    },
    async read(input) {
      if (
        !restoreVerifications.has(
          `${input.tenantId}|${input.resourceId}`,
        )
      ) {
        fail("G1_SURFACE_SEED_REQUIRED");
      }
      const value = await options.c07Restore.execute(
        scopeFor(input, lifecycleVersionByTenant),
        operation("SQL_GET", input.resourceId, {
          resourceId: input.resourceId,
        }),
      );
      return value?.value ?? null;
    },
  });

  return Object.freeze({
    SQL: sql,
    VECTOR: vector,
    FILE: file,
    OBJECT: object,
    SEARCH: search,
    CACHE: cache,
    TOOL: tool,
    RESTORE_REPLICA: restore,
  });
}
