import { createHash } from "node:crypto";
import { cp, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createC07OperationCatalog } from "./c07-operation-catalog.mjs";
import { createFileTenantObjectAdapter } from "./file-tenant-object-adapter.mjs";
import { createG1SyntheticRuntime } from "./g1-synthetic-runtime.mjs";
import {
  c10Sha256,
  createC10SyntheticBenchmark,
  createKnowledgeCatalog,
  createMemoryC10QuarantineStore,
  createMemoryKnowledgeCatalogStore,
} from "./knowledge-catalog.mjs";
import {
  c11DeterministicEmbedding,
  c11Sha256,
  createMemoryPermissionAwareRagStore,
  createPermissionAwareRag,
} from "./permission-aware-rag.mjs";
import {
  TenantDataIsolationError,
  createTenantDataBoundary,
} from "./tenant-data-boundary.mjs";
import {
  createC17CredentialBroker,
  createC17ConnectorSdk,
} from "./c17-connector-sdk.mjs";
import { createC17MockLab } from "./c17-mock-lab.mjs";

const NOW = "2026-07-26T12:00:00.000Z";
const CASE_TYPES = Object.freeze([
  "POSITIVE",
  "SAME_TENANT_WRONG_USER",
  "SAME_TENANT_WRONG_ROLE",
  "CROSS_TENANT",
]);
const SURFACE_ACCESS = Object.freeze({
  SQL: "READ",
  VECTOR: "RETRIEVE",
  FILE: "READ",
  OBJECT: "DOWNLOAD",
  SEARCH: "RETRIEVE",
  CACHE: "RETRIEVE",
  TOOL: "TOOL_CALL",
  RESTORE_REPLICA: "READ",
});

async function loadJson(relativePath) {
  return JSON.parse(
    await readFile(new URL(relativePath, import.meta.url), "utf8"),
  );
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
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
    .update(typeof value === "string" ? value : canonicalize(value))
    .digest("hex")}`;
}

function accessDenied() {
  return Object.assign(new Error("G1 matrix access denied."), {
    code: "ACCESS_DENIED",
  });
}

function resourceId(surface, owner) {
  return `g1-${surface.toLowerCase().replaceAll("_", "-")}-${owner.id}`;
}

async function loadFixtures(deployment) {
  const names = [
    "blue-harbor-tools",
    "cedar-field-components",
    "northstar-fasteners",
  ];
  const documents = await Promise.all(
    names.map((name) =>
      loadJson(
        `../implementation/p0/f02/generated/synthetic-tenant-${name}.json`,
      )
    ),
  );
  return documents.map((document) => {
    const deployedTenant = deployment.tenants.find((tenant) =>
      tenant.users.some(
        ({ id }) => id === document.records.users[0].id,
      )
    );
    if (!deployedTenant) {
      throw new Error("G1 runtime omitted an F02 Synthetic Tenant.");
    }
    return {
      fixtureId: document.fixture_id,
      fixtureTenantId: document.tenant.id,
      runtimeTenantId: deployedTenant.tenantId,
      workloadActorPrincipalId: null,
      users: document.records.users.map((record) => {
        const deployed = deployedTenant.users.find(
          ({ id }) => id === record.id,
        );
        if (!deployed) {
          throw new Error("G1 runtime omitted an F02 user.");
        }
        return {
          id: record.id,
          fixtureUserId: deployed.fixtureUserId,
          role: record.role,
          tenantId: record.tenant_id,
          runtimeTenantId: deployedTenant.tenantId,
          principalId: deployed.principalId,
          delegationIds: deployed.delegationIds,
        };
      }),
    };
  });
}

function decisionEvidence(decision) {
  return Object.freeze({
    trustSource: "C06_BOUND_DECISION_EVIDENCE",
    decisionId: decision.decisionId,
    evidenceRef: decision.evidenceRef,
    policyVersion: decision.authorizationModelId,
    tenantId: decision.tenantId,
    surface: decision.surface,
    resourceId: decision.resourceId,
    humanPrincipalId: decision.humanPrincipalId,
    humanSecurityEpoch: decision.humanSecurityEpoch,
    workloadActorPrincipalId: decision.workloadActorPrincipalId,
    workloadActorSecurityEpoch: decision.workloadActorSecurityEpoch,
    leafDelegationId: decision.leafDelegationId,
    delegationChainSha256: decision.delegationChainSha256,
    purposeRef: decision.purposeRef,
  });
}

function createRoleBoundGate(fixtures, runtime) {
  const users = new Map(
    fixtures.flatMap((fixture) =>
      fixture.users.map((user) => [user.id, { fixture, user }])
    ),
  );
  const registrations = new Map();
  const grants = new Map();
  const decisionIds = new Set();
  let grantSequence = 0;
  let allowCount = 0;
  let denyCount = 0;
  let crossTenantDenyCount = 0;

  function registrationKey(tenantId, surface, id) {
    return `${tenantId}\u0000${surface}\u0000${id}`;
  }

  function grantKey(token, tenantId, surface, id) {
    return `${token}\u0000${tenantId}\u0000${surface}\u0000${id}`;
  }

  async function register(fixture, owner, surface, id) {
    const key = registrationKey(
      fixture.runtimeTenantId,
      surface,
      id,
    );
    const current = registrations.get(key);
    if (current && current.owner.id !== owner.id) {
      throw new Error("Role-bound resource owner changed.");
    }
    if (!current) {
      const registered = runtime.registerRoleBoundResource({
        tenantId: fixture.runtimeTenantId,
        ownerFixtureUserId: owner.fixtureUserId,
        surface,
        resourceId: id,
      });
      registrations.set(key, { fixture, owner, registered });
    }
    if (!fixture.workloadActorPrincipalId) {
      const warm = await runtime.authorizeRoleBoundResource({
        targetTenantId: fixture.runtimeTenantId,
        callerTenantId: fixture.runtimeTenantId,
        callerFixtureUserId: owner.fixtureUserId,
        surface,
        resourceId: id,
      });
      if (warm.decision.effect !== "ALLOW") {
        throw new Error("Trusted role-bound registration did not authorize.");
      }
      fixture.workloadActorPrincipalId =
        warm.decision.workloadActorPrincipalId;
      decisionIds.add(warm.decision.decisionId);
      allowCount += 1;
    }
  }

  function issue({
    targetFixture,
    owner,
    callerUserId,
    claimedRole,
    surface,
    id,
  }) {
    const caller = users.get(callerUserId);
    const registration = registrations.get(
      registrationKey(
        targetFixture.runtimeTenantId,
        surface,
        id,
      ),
    );
    if (
      !caller ||
      caller.user.role !== claimedRole ||
      !registration ||
      registration.owner.id !== owner.id
    ) {
      throw accessDenied();
    }
    grantSequence += 1;
    const token = `g1-role-bound-grant-${grantSequence}`;
    const grant = {
      token,
      targetFixture,
      owner,
      callerFixture: caller.fixture,
      caller: caller.user,
      surface,
      resourceId: id,
      delegationId: caller.user.delegationIds[surface],
    };
    grants.set(
      grantKey(
        token,
        targetFixture.runtimeTenantId,
        surface,
        id,
      ),
      grant,
    );
    return grant;
  }

  async function authorize(grant) {
    let result;
    try {
      result = await runtime.authorizeRoleBoundResource({
        targetTenantId: grant.targetFixture.runtimeTenantId,
        callerTenantId: grant.callerFixture.runtimeTenantId,
        callerFixtureUserId: grant.caller.fixtureUserId,
        surface: grant.surface,
        resourceId: grant.resourceId,
      });
    } catch (error) {
      if (error?.code === "CROSS_TENANT_DENIED") {
        crossTenantDenyCount += 1;
      }
      throw accessDenied();
    }
    decisionIds.add(result.decision.decisionId);
    if (
      result.decision.effect !== "ALLOW" ||
      result.decision.authorizationStatus !== "ALLOWED"
    ) {
      denyCount += 1;
      throw accessDenied();
    }
    allowCount += 1;
    return result;
  }

  const authorizer = Object.freeze({
    async enforce(serverContext, request, descriptor) {
      const grant = grants.get(
        grantKey(
          request.sessionToken,
          serverContext.tenantId,
          descriptor.surface,
          request.resourceId,
        ),
      );
      if (
        !grant ||
        request.delegationId !== grant.delegationId ||
        serverContext.workloadActorPrincipalId !==
          grant.targetFixture.workloadActorPrincipalId
      ) {
        throw accessDenied();
      }
      const result = await authorize(grant);
      return decisionEvidence(result.decision);
    },
  });

  return Object.freeze({
    register,
    issue,
    authorizeDirect: authorize,
    authorizer,
    observations() {
      return {
        syntheticC04SessionCount: fixtures.reduce(
          (count, fixture) => count + fixture.users.length,
          0,
        ),
        syntheticC05PrincipalCount: new Set(
          fixtures.flatMap((fixture) =>
            fixture.users.map(({ principalId }) => principalId)
          ),
        ).size,
        syntheticC06AllowCount: allowCount,
        syntheticC06DenyCount: denyCount,
        crossTenantIdentityDenyCount: crossTenantDenyCount,
        distinctDecisionCount: decisionIds.size,
      };
    },
  });
}

function counted(target, counter, names) {
  return Object.freeze(
    Object.fromEntries(
      Object.entries(target).map(([name, member]) => [
        name,
        typeof member !== "function" || !names.has(name)
          ? member
          : (...args) => {
              counter.count += 1;
              return member(...args);
            },
      ]),
    ),
  );
}

function createSyntheticMemoryDataAdapter({
  snapshot = [],
  readOnly = false,
} = {}) {
  const records = new Map(snapshot);
  let executeCount = 0;

  function key(scope, id) {
    return `${scope.tenantId}\u0000${id}`;
  }

  return Object.freeze({
    id: "g1.synthetic-memory",
    paths: Object.freeze(["SQL_TEST_SEAM"]),
    async execute(scope, operation) {
      executeCount += 1;
      if (operation.kind === "SQL_PUT") {
        if (readOnly) {
          throw new TenantDataIsolationError(
            "STORE_UNAVAILABLE",
            "Restored Synthetic SQL seam is read-only.",
          );
        }
        const record = {
          tenantId: scope.tenantId,
          resourceId: operation.resourceId,
          value: structuredClone(operation.input.value),
        };
        records.set(key(scope, operation.resourceId), record);
        return structuredClone(record);
      }
      if (operation.kind === "SQL_GET") {
        return structuredClone(
          records.get(key(scope, operation.resourceId)) ?? null,
        );
      }
      throw new TenantDataIsolationError(
        "UNKNOWN_OPERATION",
        "G1 Synthetic memory Adapter accepts only SQL test-seam operations.",
      );
    },
    async project(event) {
      if (readOnly) {
        throw new TenantDataIsolationError(
          "STORE_UNAVAILABLE",
          "Restored Synthetic SQL seam is read-only.",
        );
      }
      return {
        tenantId: event.subject,
        eventId: event.id,
        status: "SUCCEEDED",
      };
    },
    async snapshot({ tenantId }) {
      return {
        state: "ACTIVE",
        recordCount: [...records.values()].filter(
          (record) => record.tenantId === tenantId,
        ).length,
      };
    },
    inspect() {
      return {
        executeCount,
        snapshot: structuredClone([...records.entries()]),
      };
    },
  });
}

function wrapObjectAdapter(adapter, counter) {
  return Object.freeze({
    id: adapter.id,
    paths: adapter.paths,
    async execute(...args) {
      counter.count += 1;
      return adapter.execute(...args);
    },
    project: (...args) => adapter.project(...args),
    snapshot: (...args) => adapter.snapshot(...args),
  });
}

function lifecycleEvent(fixture, version, state, type) {
  return {
    specversion: "1.0",
    id: `evt-g1-${fixture.fixtureId}-${version}`,
    source: "/aios-core/tenant-registry",
    type,
    subject: fixture.runtimeTenantId,
    time: `2026-07-26T10:0${version}:00.000Z`,
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: `g1-${fixture.fixtureId}-${version}`,
    synthetic: true,
    data: {
      tenant_id: fixture.runtimeTenantId,
      lifecycle_version: version,
      generation: 1,
      operation_id: `g1-${fixture.fixtureId}`,
      state,
      actor_id: fixture.users[0].principalId,
    },
  };
}

function createC07Boundary(
  operationCatalog,
  authorizer,
  dataAdapter,
  objectAdapter,
) {
  return createTenantDataBoundary({
    tenantRegistry: {
      async admitNewRequest({ tenantId }) {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
          trustSource: "VERIFIED_SERVER_CONTEXT",
        };
      },
    },
    authorizer,
    lifecycleSource: {
      async verify(event) {
        return {
          source: "C03_EVENT_OUTBOX_PAIR",
          tenantId: event.subject,
          eventId: event.id,
          eventSha256: sha256(event),
        };
      },
    },
    operationCatalog,
    adapters: {
      "c07.postgres": dataAdapter,
      "c07.object-storage": objectAdapter,
    },
  });
}

function c07Context(fixture, operationId) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: fixture.runtimeTenantId,
    operationId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: fixture.workloadActorPrincipalId,
  };
}

function c07Request(grant, id, input) {
  return {
    sessionToken: grant.token,
    delegationId: grant.delegationId,
    resourceId: id,
    correlationId: `g1-${id}`,
    input,
  };
}

function knowledgeContext(fixture, grant) {
  return {
    tenantScope: {
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId: fixture.runtimeTenantId,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: 2,
      correlationId: `g1-knowledge-${grant.resourceId}`,
      decisionId: `g1-knowledge-${grant.resourceId}`,
      evidenceRef: `evidence://g1/knowledge/${grant.resourceId}`,
      policyVersion: "g1-role-bound-policy-v1",
    },
    c06ServerContext: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId: fixture.runtimeTenantId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: fixture.workloadActorPrincipalId,
    },
    authorizationRequest: {
      sessionToken: grant.token,
      delegationId: grant.delegationId,
      correlationId: `g1-knowledge-${grant.resourceId}`,
    },
  };
}

function publication(documentId, owner) {
  return {
    ownerPrincipalId: owner.principalId,
    sourceRef: `fixture://g1/c11/${documentId}`,
    version: "2026.1",
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil: "2027-01-01T00:00:00.000Z",
    classification: "INTERNAL",
    acl: {
      resourceId: documentId,
      readPrincipalRefs: [`human:${owner.principalId}`],
      managePrincipalRefs: [`human:${owner.principalId}`],
    },
  };
}

function chainFor(node, nodesById) {
  const chain = {
    original: null,
    page: null,
    section: null,
    table: null,
  };
  let current = node.parentNodeId
    ? nodesById.get(node.parentNodeId)
    : null;
  while (current) {
    if (current.nodeType === "ORIGINAL") chain.original = current;
    if (current.nodeType === "PAGE") chain.page = current;
    if (current.nodeType === "SECTION") chain.section = current;
    if (current.nodeType === "TABLE") chain.table = current;
    current = current.parentNodeId
      ? nodesById.get(current.parentNodeId)
      : null;
  }
  if (!chain.original || !chain.page) {
    throw new Error("G1 C10 provenance chain is incomplete.");
  }
  return chain;
}

function createG1C11Benchmark(searchResourceId, frozenChunks) {
  const chunksByOrdinal = new Map(
    frozenChunks.map((chunk) => [chunk.ordinal, chunk]),
  );
  return Object.freeze({
    embeddingModel: "g1-c11-deterministic-hash-embedding-v1",
    embeddingDimensions: 8,
    minimumScore: 0.05,
    minimumEvidenceCount: 1,
    searchResourceId,
    projectCatalogDocument(document) {
      if (
        document?.state !== "PUBLISHED" ||
        document?.tenantKind !== "SYNTHETIC" ||
        document?.metadata?.acl?.resourceId !== document.documentId ||
        document.metadata.acl.readPrincipalRefs.length !== 1 ||
        !document.metadata.acl.readPrincipalRefs[0].startsWith("human:")
      ) {
        throw new Error("G1 C11 role-bound document is invalid.");
      }
      const nodesById = new Map(
        document.nodes.map((node) => [node.nodeId, node]),
      );
      const chunks = document.nodes
        .filter((node) => node.nodeType === "CHUNK")
        .map((node) => {
          const frozen = chunksByOrdinal.get(node.ordinal);
          if (
            !frozen ||
            node.textSha256 !== frozen.text_sha256 ||
            node.sourceSha256 !== document.contentSha256 ||
            node.availabilityState !== "PUBLISHED"
          ) {
            throw new Error("G1 C11 Chunk is not frozen C10 content.");
          }
          const chain = chainFor(node, nodesById);
          return Object.freeze({
            chunkId: node.nodeId,
            ordinal: node.ordinal,
            text: frozen.text,
            textSha256: frozen.text_sha256,
            sourceSha256: node.sourceSha256,
            embedding: c11DeterministicEmbedding(frozen.text, 8),
            originalNodeId: chain.original.nodeId,
            pageNodeId: chain.page.nodeId,
            sectionNodeId: chain.section?.nodeId ?? null,
            tableNodeId: chain.table?.nodeId ?? null,
            location: structuredClone(node.location),
          });
        });
      return Object.freeze({
        tenantId: document.tenantId,
        tenantKind: "SYNTHETIC",
        documentId: document.documentId,
        documentVersion: document.documentVersion,
        catalogRevision: document.revision,
        state: document.state,
        contentSha256: document.contentSha256,
        parseSha256: document.parseSha256,
        metadata: structuredClone(document.metadata),
        chunks: Object.freeze(chunks),
      });
    },
  });
}

function principalResolver() {
  return Object.freeze({
    async resolve({ tenantScope, authorizationEvidence }) {
      const principalRefs = [
        `human:${authorizationEvidence.humanPrincipalId}`,
      ];
      return {
        trustSource: "C06_HUMAN_AND_SERVER_GROUP_RESOLUTION",
        tenantId: tenantScope.tenantId,
        humanPrincipalId: authorizationEvidence.humanPrincipalId,
        humanSecurityEpoch: authorizationEvidence.humanSecurityEpoch,
        principalRefs,
        principalScopeHash: c11Sha256(principalRefs),
      };
    },
  });
}

function positiveSignals(overrides = {}) {
  return {
    body: true,
    metadata: true,
    existenceSignal: true,
    cache: false,
    toolExternalEffect: false,
    ...overrides,
  };
}

function deniedSignals() {
  return {
    body: false,
    metadata: false,
    existenceSignal: false,
    cache: false,
    toolExternalEffect: false,
  };
}

function observedSignals(output, signals) {
  return {
    body: Boolean(signals?.body || output !== null),
    metadata: Boolean(
      signals?.metadata ||
        (output !== null && Object.hasOwn(output, "metadataSha256")),
    ),
    existenceSignal: Boolean(
      signals?.existenceSignal || output !== null,
    ),
    cache: Boolean(
      signals?.cache ||
        (output !== null && Object.hasOwn(output, "cacheHit")),
    ),
    toolExternalEffect: Boolean(
      signals?.toolExternalEffect ||
        (output !== null &&
          (Object.hasOwn(output, "externalEffectCount") ||
            Object.hasOwn(output, "networkRequestCount"))),
    ),
  };
}

function credentialsFor(fixtures, fixtureIndex, ownerIndex, caseType) {
  const fixture = fixtures[fixtureIndex];
  const owner = fixture.users[ownerIndex];
  if (caseType === "POSITIVE") {
    return { userId: owner.id, role: owner.role };
  }
  if (caseType === "SAME_TENANT_WRONG_USER") {
    const caller = fixture.users[(ownerIndex + 1) % fixture.users.length];
    return { userId: caller.id, role: caller.role };
  }
  if (caseType === "SAME_TENANT_WRONG_ROLE") {
    const wrong = fixture.users[(ownerIndex + 1) % fixture.users.length];
    return { userId: owner.id, role: wrong.role };
  }
  const other = fixtures[(fixtureIndex + 1) % fixtures.length];
  const caller = other.users.find(({ role }) => role === owner.role);
  return { userId: caller.id, role: caller.role };
}

async function runSurfaceCases({
  surface,
  fixtures,
  gate,
  touchCount,
  invoke,
  resolveResourceId = (owner) => resourceId(surface, owner),
}) {
  const cases = [];
  let observedLeakCount = 0;
  const accessSurface = SURFACE_ACCESS[surface];
  for (const [fixtureIndex, fixture] of fixtures.entries()) {
    for (const [ownerIndex, owner] of fixture.users.entries()) {
      const id = resolveResourceId(owner);
      for (const caseType of CASE_TYPES) {
        const credentials = credentialsFor(
          fixtures,
          fixtureIndex,
          ownerIndex,
          caseType,
        );
        const before = touchCount();
        let grant = null;
        let moduleBoundaryEntered = false;
        let output = null;
        let signals = deniedSignals();
        let errorCode = null;
        try {
          grant = gate.issue({
            targetFixture: fixture,
            owner,
            callerUserId: credentials.userId,
            claimedRole: credentials.role,
            surface: accessSurface,
            id,
          });
          moduleBoundaryEntered = true;
          const value = await invoke({
            fixture,
            owner,
            grant,
            resourceId: id,
          });
          output = value.output;
          signals = value.signals;
        } catch (error) {
          errorCode =
            error?.code === "ACCESS_DENIED"
              ? "ACCESS_DENIED"
              : error?.code ?? "UNEXPECTED_ERROR";
        }
        const lowerTouchDelta = touchCount() - before;
        const expectedAllowed = caseType === "POSITIVE";
        const actualAllowed =
          errorCode === null && moduleBoundaryEntered;
        const actualSignals = observedSignals(output, signals);
        const casePassed = expectedAllowed
          ? actualAllowed && lowerTouchDelta > 0 && output !== null
          : !actualAllowed &&
            errorCode === "ACCESS_DENIED" &&
            lowerTouchDelta === 0 &&
            output === null &&
            Object.values(actualSignals).every((value) => !value);
        if (!casePassed) {
          observedLeakCount += 1;
        }
        cases.push({
          fixtureId: fixture.fixtureId,
          ownerUserId: owner.id,
          ownerRole: owner.role,
          callerUserId: credentials.userId,
          callerRole: credentials.role,
          caseType,
          expectedAllowed,
          actualAllowed,
          allowed: actualAllowed,
          casePassed,
          moduleBoundaryEntered,
          errorCode,
          lowerTouchDelta,
          attribution:
            actualAllowed ||
            lowerTouchDelta > 0 ||
            Object.values(actualSignals).some(Boolean)
            ? {
                fixtureId: fixture.fixtureId,
                userId: owner.id,
                role: owner.role,
                principalId: owner.principalId,
              }
            : null,
          signals: actualSignals,
          output,
        });
      }
    }
  }
  return { surface, cases, observedLeakCount };
}

function exactSurfaceCoverage(surfaceResult, fixtures) {
  const expected = new Set();
  for (const [fixtureIndex, fixture] of fixtures.entries()) {
    for (const [ownerIndex, owner] of fixture.users.entries()) {
      for (const caseType of CASE_TYPES) {
        const caller = credentialsFor(
          fixtures,
          fixtureIndex,
          ownerIndex,
          caseType,
        );
        expected.add(
          [
            fixture.fixtureId,
            owner.id,
            owner.role,
            caller.userId,
            caller.role,
            caseType,
          ].join("\u0000"),
        );
      }
    }
  }
  const actual = new Set(
    surfaceResult.cases.map((item) =>
      [
        item.fixtureId,
        item.ownerUserId,
        item.ownerRole,
        item.callerUserId,
        item.callerRole,
        item.caseType,
      ].join("\u0000")
    ),
  );
  return (
    Object.hasOwn(SURFACE_ACCESS, surfaceResult.surface) &&
    surfaceResult.cases.length === expected.size &&
    actual.size === expected.size &&
    [...actual].every((key) => expected.has(key))
  );
}

function aggregateWrongAttributionCounts(surfaces) {
  const counts = {
    body: 0,
    metadata: 0,
    existenceSignal: 0,
    cache: 0,
    toolExternalEffect: 0,
  };
  for (const item of surfaces.flatMap(({ cases }) => cases)) {
    if (item.expectedAllowed) continue;
    for (const signal of Object.keys(counts)) {
      if (item.signals[signal]) counts[signal] += 1;
    }
  }
  return counts;
}

function connectorContext(fixture, owner, callIndex) {
  return {
    tenantId: fixture.runtimeTenantId,
    tenantKind: "SYNTHETIC",
    principalId: owner.principalId,
    callId:
      `tcl_018f3000-0000-7000-8000-${String(callIndex).padStart(12, "0")}`,
    connectorStage: "C0_DISABLED",
  };
}

function connectorEnvelope(owner, operationId, parameters, traceIndex) {
  return {
    document_status: "GENERIC_PRODUCT_TEMPLATE",
    contract_version: 1,
    message_type: "REQUEST",
    operation_id: operationId,
    trace_id: `trace-g1-tool-${traceIndex}`,
    principal_id: owner.principalId,
    purpose: "Read one fictitious role-bound record.",
    request: {
      parameters,
      requested_as_of: null,
    },
  };
}

export async function runG1IsolationMatrix() {
  const runtime = await createG1SyntheticRuntime();
  const deployment = await runtime.deploy();
  const fixtures = await loadFixtures(deployment);
  const gate = createRoleBoundGate(fixtures, runtime);
  const operationCatalog = createC07OperationCatalog(
    await loadJson(
      "../implementation/p1/c07/operation-catalog.v1.json",
    ),
  );
  const temporaryRoot = await mkdtemp(
    join(tmpdir(), "g1-isolation-matrix-"),
  );
  const objectRoot = join(temporaryRoot, "objects");
  const restoreRoot = join(temporaryRoot, "restore-objects");

  try {
    const dataAdapter = createSyntheticMemoryDataAdapter();
    const objectCounter = { count: 0 };
    const rawObjectAdapter = createFileTenantObjectAdapter({
      rootDir: objectRoot,
    });
    for (const fixture of fixtures) {
      await rawObjectAdapter.project(
        lifecycleEvent(
          fixture,
          1,
          "PROVISIONING",
          "product.tenant.provisioning-requested.v1",
        ),
      );
      await rawObjectAdapter.project(
        lifecycleEvent(
          fixture,
          2,
          "ACTIVE",
          "product.tenant.activated.v1",
        ),
      );
    }
    const objectAdapter = wrapObjectAdapter(
      rawObjectAdapter,
      objectCounter,
    );
    const onlineBoundary = createC07Boundary(
      operationCatalog,
      gate.authorizer,
      dataAdapter,
      objectAdapter,
    );

    const c10Counter = { count: 0 };
    const rawCatalogStore = createMemoryKnowledgeCatalogStore();
    const rawQuarantineStore = createMemoryC10QuarantineStore();
    const catalogStore = counted(
      rawCatalogStore,
      c10Counter,
      new Set(["readAsOf"]),
    );
    const quarantineStore = counted(
      rawQuarantineStore,
      c10Counter,
      new Set(["read"]),
    );
    const c10Benchmark = createC10SyntheticBenchmark(
      await loadJson(
        "../implementation/p1/c10/synthetic-document-benchmark.v1.json",
      ),
    );
    const catalog = createKnowledgeCatalog({
      store: catalogStore,
      quarantineStore,
      c06Authorizer: gate.authorizer,
      benchmark: c10Benchmark,
      clock: () => NOW,
    });
    const c11Document = await loadJson(
      "../implementation/p1/c11/synthetic-rag-benchmark.v1.json",
    );
    const frozenChunks = c11Document.documents.find(
      ({ document_id: documentId }) => documentId === "sales-guide",
    ).chunks;
    const c11Counter = { count: 0 };
    const ragStore = counted(
      createMemoryPermissionAwareRagStore(),
      c11Counter,
      new Set([
        "applyProjection",
        "search",
        "readCache",
        "writeCache",
        "recordAudit",
      ]),
    );
    const rags = new Map();

    for (const fixture of fixtures) {
      for (const owner of fixture.users) {
        const sqlId = resourceId("SQL", owner);
        const objectId = resourceId("OBJECT", owner);
        const documentId = resourceId("FILE", owner);
        await gate.register(fixture, owner, "MANAGE", sqlId);
        await gate.register(fixture, owner, "READ", sqlId);
        await gate.register(fixture, owner, "MANAGE", objectId);
        await gate.register(fixture, owner, "DOWNLOAD", objectId);
        await gate.register(fixture, owner, "MANAGE", documentId);
        await gate.register(fixture, owner, "READ", documentId);
        for (const surface of ["VECTOR", "SEARCH", "CACHE"]) {
          await gate.register(
            fixture,
            owner,
            "RETRIEVE",
            resourceId(surface, owner),
          );
          const benchmark = createG1C11Benchmark(
            resourceId(surface, owner),
            frozenChunks,
          );
          rags.set(
            `${surface}\u0000${owner.id}`,
            createPermissionAwareRag({
              store: ragStore,
              catalogReader: catalogStore,
              c06Authorizer: gate.authorizer,
              principalResolver: principalResolver(),
              benchmark,
              clock: () => NOW,
            }),
          );
        }
        await gate.register(
          fixture,
          owner,
          "TOOL_CALL",
          resourceId("TOOL", owner),
        );

        const sqlGrant = gate.issue({
          targetFixture: fixture,
          owner,
          callerUserId: owner.id,
          claimedRole: owner.role,
          surface: "MANAGE",
          id: sqlId,
        });
        await onlineBoundary.execute(
          c07Context(fixture, "SQL_PUT"),
          c07Request(sqlGrant, sqlId, {
            resourceId: sqlId,
            value: {
              ownerUserId: owner.id,
              ownerRole: owner.role,
              body: `synthetic-body-${owner.id}`,
            },
          }),
        );

        const objectGrant = gate.issue({
          targetFixture: fixture,
          owner,
          callerUserId: owner.id,
          claimedRole: owner.role,
          surface: "MANAGE",
          id: objectId,
        });
        await onlineBoundary.execute(
          c07Context(fixture, "OBJECT_PUT"),
          c07Request(objectGrant, objectId, {
            objectKey: `${owner.id}/isolation.json`,
            body: JSON.stringify({
              ownerUserId: owner.id,
              ownerRole: owner.role,
            }),
            contentType: "application/json",
          }),
        );

        const documentGrant = gate.issue({
          targetFixture: fixture,
          owner,
          callerUserId: owner.id,
          claimedRole: owner.role,
          surface: "MANAGE",
          id: documentId,
        });
        const context = knowledgeContext(fixture, documentGrant);
        const prefix = `g1-${owner.id}`;
        await catalog.upload(context, {
          idempotencyKey: `${prefix}-upload`,
          documentId,
          documentVersion: 1,
          expectedRevision: 0,
          fixtureRef: "fixture://c10/clean-markdown",
          filename: `${documentId}.md`,
          declaredMediaType: "text/markdown",
          sourceRef: `fixture://g1/c10/${documentId}`,
        });
        await catalog.inspect(context, {
          idempotencyKey: `${prefix}-inspect`,
          documentId,
          documentVersion: 1,
          expectedRevision: 1,
        });
        await catalog.parse(context, {
          idempotencyKey: `${prefix}-parse`,
          documentId,
          documentVersion: 1,
          expectedRevision: 2,
        });
        await catalog.publish(context, {
          idempotencyKey: `${prefix}-publish`,
          documentId,
          documentVersion: 1,
          expectedRevision: 3,
          metadata: publication(documentId, owner),
        });
        await rags.get(`VECTOR\u0000${owner.id}`).synchronize(
          context,
          {
            idempotencyKey: `${prefix}-synchronize`,
            documentId,
            documentVersion: 1,
            expectedProjectionVersion: 0,
          },
        );
      }
    }

    const connectorTemplates = await loadJson(
      "../implementation/p1/c17/connector-templates.v1.json",
    );
    const connectorFixtures = await loadJson(
      "../implementation/p1/c17/synthetic-connector-fixtures.v1.json",
    );
    const connectorBroker = createC17CredentialBroker(NOW);
    const connectorLab = createC17MockLab({
      templateDocument: connectorTemplates,
      fixtureDocument: connectorFixtures,
      observedAt: NOW,
    });
    const connector = createC17ConnectorSdk({
      templateDocument: connectorTemplates,
      credentialBroker: connectorBroker,
      adapter: connectorLab,
      timeoutMs: 100,
    });

    const surfaces = [];
    surfaces.push(
      await runSurfaceCases({
        surface: "SQL",
        fixtures,
        gate,
        touchCount: () => dataAdapter.inspect().executeCount,
        async invoke({ fixture, grant, resourceId: id }) {
          const result = await onlineBoundary.execute(
            c07Context(fixture, "SQL_GET"),
            c07Request(grant, id, { resourceId: id }),
          );
          return {
            output: {
              bodySha256: sha256(result.value.value),
              metadataSha256: sha256({
                tenantId: result.value.tenantId,
                resourceId: result.value.resourceId,
              }),
              exists: result.value !== null,
            },
            signals: positiveSignals(),
          };
        },
      }),
    );
    surfaces.push(
      await runSurfaceCases({
        surface: "VECTOR",
        fixtures,
        gate,
        touchCount: () => c11Counter.count,
        async invoke({ fixture, owner, grant }) {
          const result = await rags
            .get(`VECTOR\u0000${owner.id}`)
            .search(knowledgeContext(fixture, grant), {
              requestId: `g1-vector-${owner.id}`,
              query: "owner ACL publication",
              limit: 10,
            });
          if (
            !result.evidence.some(
              ({ documentId }) =>
                documentId === resourceId("FILE", owner),
            )
          ) {
            throw new Error("C11 omitted the owner's direct-Human ACL.");
          }
          return {
            output: {
              bodySha256: c11Sha256(result.modelContext),
              metadataSha256: c11Sha256(result.evidence),
              cacheHit: result.cacheHit,
              evidenceCount: result.evidence.length,
            },
            signals: positiveSignals(),
          };
        },
      }),
    );
    surfaces.push(
      await runSurfaceCases({
        surface: "FILE",
        fixtures,
        gate,
        touchCount: () => c10Counter.count,
        async invoke({ fixture, owner, grant }) {
          const documentId = resourceId("FILE", owner);
          const record = await catalog.readAsOf(
            knowledgeContext(fixture, grant),
            {
              documentId,
              documentVersion: 1,
              asOf: NOW,
            },
          );
          const body = await quarantineStore.read({
            tenantId: fixture.runtimeTenantId,
            quarantineRef: record.quarantineRef,
            contentSha256: record.contentSha256,
          });
          return {
            output: {
              bodySha256: c10Sha256(body),
              metadataSha256: sha256(record.metadata),
              exists: record !== null,
            },
            signals: positiveSignals(),
          };
        },
      }),
    );
    surfaces.push(
      await runSurfaceCases({
        surface: "OBJECT",
        fixtures,
        gate,
        touchCount: () => objectCounter.count,
        async invoke({ fixture, owner, grant, resourceId: id }) {
          const result = await onlineBoundary.execute(
            c07Context(fixture, "OBJECT_GET"),
            c07Request(grant, id, {
              objectKey: `${owner.id}/isolation.json`,
            }),
          );
          return {
            output: {
              bodySha256: sha256(result.value.body),
              metadataSha256: sha256({
                tenantId: result.value.tenantId,
                objectKey: result.value.objectKey,
                contentType: result.value.contentType,
              }),
              exists: result.value !== null,
            },
            signals: positiveSignals(),
          };
        },
      }),
    );
    surfaces.push(
      await runSurfaceCases({
        surface: "SEARCH",
        fixtures,
        gate,
        touchCount: () => c11Counter.count,
        async invoke({ fixture, owner, grant }) {
          const result = await rags
            .get(`SEARCH\u0000${owner.id}`)
            .search(knowledgeContext(fixture, grant), {
              requestId: `g1-search-${owner.id}`,
              query: "Only synthetic records are allowed",
              limit: 10,
            });
          return {
            output: {
              bodySha256: c11Sha256(result.modelContext),
              metadataSha256: c11Sha256(result.evidence),
              cacheHit: result.cacheHit,
              evidenceCount: result.evidence.length,
            },
            signals: positiveSignals(),
          };
        },
      }),
    );
    surfaces.push(
      await runSurfaceCases({
        surface: "CACHE",
        fixtures,
        gate,
        touchCount: () => c11Counter.count,
        async invoke({ fixture, owner, grant }) {
          const result = await rags
            .get(`CACHE\u0000${owner.id}`)
            .search(knowledgeContext(fixture, grant), {
              requestId: `g1-cache-${owner.id}`,
              query: "Only synthetic records are allowed",
              limit: 10,
            });
          if (!result.cacheHit) {
            throw Object.assign(new Error("C11 cache was not reused."), {
              code: "CACHE_MISS",
            });
          }
          return {
            output: {
              bodySha256: c11Sha256(result.modelContext),
              metadataSha256: c11Sha256(result.evidence),
              cacheHit: true,
              evidenceCount: result.evidence.length,
            },
            signals: positiveSignals({ cache: true }),
          };
        },
      }),
    );

    const toolOperations = Object.freeze({
      sales_analyst: "synthetic.approval.status.get",
      operations_planner: "synthetic.erp.order.get",
      quality_reviewer: "synthetic.bi.metric.get",
    });
    let connectorCallIndex = 0;
    surfaces.push(
      await runSurfaceCases({
        surface: "TOOL",
        fixtures,
        gate,
        touchCount: () => connectorLab.snapshot().invocationCount,
        async invoke({ fixture, owner, grant }) {
          await gate.authorizeDirect(grant);
          const operationId = toolOperations[owner.role];
          const record = connectorFixtures.records.find(
            (candidate) =>
              candidate.tenantId === fixture.runtimeTenantId &&
              candidate.operationId === operationId,
          );
          if (!record) throw new Error("C17 role fixture is missing.");
          connectorCallIndex += 1;
          const serverContext = connectorContext(
            fixture,
            owner,
            connectorCallIndex,
          );
          const template = connectorTemplates.templates.find(
            (candidate) => candidate.operationId === operationId,
          );
          const capability = connectorBroker.issue({
            tenantId: fixture.runtimeTenantId,
            operationId,
            callId: serverContext.callId,
            audience: template.audience,
          });
          const result = await connector.execute(
            serverContext,
            connectorEnvelope(
              owner,
              operationId,
              record.lookup,
              connectorCallIndex,
            ),
            capability,
          );
          const snapshot = connectorLab.snapshot();
          return {
            output: {
              bodySha256: sha256(result.result.data),
              metadataSha256: sha256(result.result.provenance),
              networkRequestCount: snapshot.networkRequestCount,
              externalEffectCount: snapshot.externalEffectCount,
            },
            signals: positiveSignals({
              toolExternalEffect: true,
            }),
          };
        },
      }),
    );

    await cp(objectRoot, restoreRoot, { recursive: true });
    const restoreData = createSyntheticMemoryDataAdapter({
      snapshot: dataAdapter.inspect().snapshot,
      readOnly: true,
    });
    const restoreObjectCounter = { count: 0 };
    const restoreObject = wrapObjectAdapter(
      createFileTenantObjectAdapter({
        rootDir: restoreRoot,
        readOnly: true,
      }),
      restoreObjectCounter,
    );
    const restoreBoundary = createC07Boundary(
      operationCatalog,
      gate.authorizer,
      restoreData,
      restoreObject,
    );
    surfaces.push(
      await runSurfaceCases({
        surface: "RESTORE_REPLICA",
        fixtures,
        gate,
        touchCount: () => restoreData.inspect().executeCount,
        resolveResourceId: (owner) => resourceId("SQL", owner),
        async invoke({ fixture, owner, grant }) {
          const id = resourceId("SQL", owner);
          const sql = await restoreBoundary.execute(
            c07Context(fixture, "SQL_GET"),
            c07Request(grant, id, { resourceId: id }),
          );
          const manageGrant = gate.issue({
            targetFixture: fixture,
            owner,
            callerUserId: owner.id,
            claimedRole: owner.role,
            surface: "MANAGE",
            id,
          });
          let writeRejected = false;
          try {
            await restoreBoundary.execute(
              c07Context(fixture, "SQL_PUT"),
              c07Request(manageGrant, id, {
                resourceId: id,
                value: { forbidden: true },
              }),
            );
          } catch (error) {
            writeRejected = error?.code === "STORE_UNAVAILABLE";
          }
          if (!writeRejected) {
            throw Object.assign(
              new Error("Restore endpoint accepted a write."),
              { code: "RESTORE_WRITE_ACCEPTED" },
            );
          }
          return {
            output: {
              bodySha256: sha256(sql.value.value),
              metadataSha256: sha256({
                tenantId: sql.value.tenantId,
                resourceId: sql.value.resourceId,
              }),
              readOnly: true,
              writeRejected,
            },
            signals: positiveSignals(),
          };
        },
      }),
    );

    const observedLeakCount = surfaces.reduce(
      (sum, surface) => sum + surface.observedLeakCount,
      0,
    );
    const wrongAttributionCounts =
      aggregateWrongAttributionCounts(surfaces);
    const passedPositiveIdentities = surfaces.map(
      ({ cases }) =>
        new Set(
          cases
            .filter(
              (item) =>
                item.expectedAllowed &&
                item.casePassed &&
                item.attribution,
            )
            .map((item) =>
              [
                item.fixtureId,
                item.ownerUserId,
                item.ownerRole,
                item.attribution.principalId,
              ].join("\u0000")
            ),
        ),
    );
    const identitiesPassingEverySurface = new Set(
      [...passedPositiveIdentities[0]].filter((identity) =>
        passedPositiveIdentities
          .slice(1)
          .every((surface) => surface.has(identity))
      ),
    );
    const observedPositiveIdentitiesPerTenant = Math.min(
      ...fixtures.map(
        (fixture) =>
          [...identitiesPassingEverySurface].filter((identity) =>
            identity.startsWith(`${fixture.fixtureId}\u0000`)
          ).length,
      ),
    );
    const observedCasesPerSurface = Math.min(
      ...surfaces.map(({ cases }) => cases.length),
    );
    const expectedSurfaces = Object.keys(SURFACE_ACCESS);
    const exhaustive =
      observedLeakCount === 0 &&
      Object.values(wrongAttributionCounts).every(
        (count) => count === 0,
      ) &&
      surfaces.length === expectedSurfaces.length &&
      new Set(surfaces.map(({ surface }) => surface)).size ===
        expectedSurfaces.length &&
      expectedSurfaces.every((surface) =>
        surfaces.some((candidate) => candidate.surface === surface)
      ) &&
      surfaces.every((surface) =>
        exactSurfaceCoverage(surface, fixtures)
      );
    return {
      schemaVersion: "g1-isolation-matrix-result.v1",
      phase: "P1_SYNTHETIC_ONLY",
      productionVerificationStatus: "NOT_VERIFIED",
      gateConditionStatus: "NOT_SATISFIED",
      exhaustive,
      observedLeakCount,
      wrongAttributionCounts,
      modulesUsed: [
        "C03",
        "C04",
        "C05",
        "C06",
        "C07",
        "C10",
        "C11",
        "C17",
      ],
      executionTiers: {
        SQL:
          "C07_REAL_BOUNDARY_WITH_SYNTHETIC_MEMORY_ADAPTER_AND_FROZEN_POSTGRESQL_ANCHOR",
        TOOL:
          "C17_C0_MOCK_EXECUTION_WITH_C16_FROZEN_DATABASE_ANCHOR_ONLY",
      },
      coverage: {
        observedPositiveIdentitiesPerTenant,
        requiredPositiveIdentitiesPerTenant: 3,
        observedCasesPerSurface,
        requiredCasesPerSurface: 36,
      },
      authorizationObservations: gate.observations(),
      remainingGaps: [
        "WRONG_ROLE_NOT_EVALUATED_BY_C06",
        "COMBINED_PERSISTENT_MATRIX_NOT_EXECUTED",
        "FILE_BODY_PERSISTENCE_NOT_EXECUTED",
        "TOOL_GATEWAY_POSTGRES_NOT_IN_COMBINED_PATH",
        "RESTORE_REPLICA_IS_MEMORY_SNAPSHOT",
      ],
      fixtures: fixtures.map(
        ({ fixtureId, runtimeTenantId, users }) => ({
          fixtureId,
          runtimeTenantId,
          users: users.map(({ id, role, principalId }) => ({
            id,
            role,
            principalId,
          })),
        }),
      ),
      surfaces,
    };
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}
