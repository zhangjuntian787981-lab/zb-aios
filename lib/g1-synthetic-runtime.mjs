import { readFile } from "node:fs/promises";
import {
  createIdentityFederation,
  createMemoryIdentityStore,
  createSyntheticIdentityCatalog,
} from "./identity-federation.mjs";
import {
  createMemoryTenantStore,
  createSyntheticFixtureCatalog,
  createTenantRegistry,
} from "./tenant-registry.mjs";
import {
  createMemoryPrincipalStore,
  createStablePrincipalRegistry,
  createSyntheticPrincipalCatalog,
} from "./stable-principal.mjs";
import {
  buildSyntheticPolicyTuples,
  createAuthorizationFacade,
  createMemoryAuthorizationStore,
  createSyntheticAuthorizationCatalog,
  hashSyntheticPolicyTuples,
} from "./authorization-facade.mjs";
import {
  createC10SyntheticBenchmark,
  createKnowledgeCatalog,
  createMemoryC10QuarantineStore,
  createMemoryKnowledgeCatalogStore,
} from "./knowledge-catalog.mjs";
import {
  c11Sha256,
  createC11SyntheticBenchmark,
  createMemoryPermissionAwareRagStore,
  createPermissionAwareRag,
} from "./permission-aware-rag.mjs";
import { createC10C06Authorizer } from "./c10-c06-authorizer.mjs";
import { createC11C06Authorizer } from "./c11-c06-authorizer.mjs";
import {
  createMemoryModelGatewayStore,
  createModelGateway,
  createSyntheticModelCatalog,
} from "./model-gateway.mjs";
import { createC14C06Authorizer } from "./c14-c06-authorizer.mjs";
import { createC14SyntheticModelProvider } from "./c14-synthetic-model-provider.mjs";
import {
  createMemoryToolGatewayStore,
  createSyntheticToolCatalog,
  createToolGateway,
  toolGatewaySha256,
} from "./tool-gateway.mjs";
import { createC16C06Authorizer } from "./c16-c06-authorizer.mjs";
import { createC16EphemeralCredentialBroker } from "./c16-ephemeral-credential-broker.mjs";
import { createC16SyntheticToolAdapter } from "./c16-synthetic-tool-adapter.mjs";
import {
  createHumanDecisionWorkflow,
  createMemoryHumanDecisionStore,
  createSyntheticHumanDecisionCatalog,
  humanDecisionSha256,
} from "./human-decision-workflow.mjs";
import { createC15C06Authorizer } from "./c15-c06-authorizer.mjs";
import {
  c12Sha256,
  createAgentOrchestrator,
  createMemoryC12StatePort,
  createSyntheticOrchestrationCatalog,
} from "./agent-orchestrator.mjs";
import {
  createAiosStateCore,
  createMemoryAiosStateStore,
} from "./aios-state-core.mjs";
import { createC08C06Authorizer } from "./c08-c06-authorizer.mjs";
import { createC08C0MockToolReceipts } from "./c08-c0-mock-tool-receipts.mjs";
import {
  auditEvidenceSha256,
  createAuditEvidenceService,
  createMemoryAuditEvidenceStore,
  verifyAuditExport,
} from "./c18-audit-evidence.mjs";
import {
  createMemoryObservabilityStore,
  createObservabilityService,
  observabilitySha256,
  parseTraceContext,
} from "./c19-observability.mjs";

export const G1_SYNTHETIC_TENANT_IDS = Object.freeze([
  "stn_018f0000-0000-7000-8000-000000000010",
  "stn_018f0000-0000-7000-8000-000000000011",
  "stn_018f0000-0000-7000-8000-000000000012",
]);

const NOW = "2026-07-26T12:00:00.000Z";
const PROJECTIONS = Object.freeze([
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
]);

const TENANT_OPERATOR = Object.freeze({
  actorId: "syn_prn_g1_tenant_operator",
  capabilities: ["TENANT_LIFECYCLE_MANAGE"],
  synthetic: true,
});
const TENANT_PROJECTION_WORKER = Object.freeze({
  actorId: "syn_svc_g1_projection_worker",
  capabilities: ["TENANT_PROJECTION_REPORT"],
  synthetic: true,
});
const TENANT_RECONCILER = Object.freeze({
  actorId: "syn_svc_g1_tenant_reconciler",
  capabilities: ["TENANT_RECONCILE"],
  synthetic: true,
});
const TENANT_READER = Object.freeze({
  actorId: "syn_svc_g1_tenant_reader",
  capabilities: ["TENANT_LIFECYCLE_READ"],
  synthetic: true,
});
const IDENTITY_PROJECTION_WORKER = Object.freeze({
  actorId: "syn_svc_g1_identity_projection",
  capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
  synthetic: true,
});
const IDENTITY_PROVISIONING_WORKER = Object.freeze({
  actorId: "syn_svc_g1_identity_provisioning",
  capabilities: ["IDENTITY_PROVISIONING_APPLY"],
  synthetic: true,
});
const PORTAL_CONTEXT = Object.freeze({
  actorId: "syn_svc_g1_portal",
  synthetic: true,
});
const PRINCIPAL_OPERATOR = Object.freeze({
  actorId: "syn_svc_g1_principal_operator",
  synthetic: true,
  capabilities: [
    "PRINCIPAL_PROVISION",
    "PRINCIPAL_LINK_MANAGE",
    "PRINCIPAL_LIFECYCLE_APPLY",
    "DELEGATION_MANAGE",
    "PRINCIPAL_READ",
  ],
});
const C06_TEMPLATE_REF = "fixture://c06/policy-release/baseline-v1";
const G1_STORAGE_KEYS = Object.freeze([
  "tenantStore",
  "tenantDataAdapter",
  "identityStore",
  "principalStore",
  "authorizationStore",
  "knowledgeCatalogStore",
  "knowledgeQuarantineStore",
  "ragStore",
  "modelDraftStore",
  "modelReviewStore",
  "modelProvider",
  "toolStore",
  "decisionStore",
  "c12StatePortFactory",
  "c08StateStore",
  "c08Receipts",
  "auditStore",
  "observabilityStore",
]);

function failStorageConfiguration(message) {
  const error = new Error(message);
  error.code = "INVALID_G1_STORAGE_CONFIGURATION";
  throw error;
}

function exactObject(value, keys, name) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) {
    failStorageConfiguration(`${name} is invalid.`);
  }
}

function requireMethods(value, methods, name) {
  if (
    !value ||
    methods.some((method) => typeof value[method] !== "function")
  ) {
    failStorageConfiguration(`${name} is incomplete.`);
  }
}

function validateStorage(storage) {
  exactObject(storage, G1_STORAGE_KEYS, "G1 storage");
  for (const [name, methods] of [
    ["tenantStore", ["runCommand", "readTenantSnapshot"]],
    ["tenantDataAdapter", ["project"]],
    [
      "identityStore",
      [
        "runCommand",
        "transact",
        "readTenantSnapshot",
        "readSessionSnapshot",
      ],
    ],
    [
      "principalStore",
      ["runCommand", "readTenantSnapshot", "readActionSnapshot"],
    ],
    [
      "authorizationStore",
      [
        "runCommand",
        "readCommandReceipt",
        "readPolicyRelease",
        "readActiveRelease",
        "recordDecision",
        "readDecision",
        "readTenantSnapshot",
      ],
    ],
    [
      "knowledgeCatalogStore",
      [
        "apply",
        "readReceipt",
        "prepareStorageEffect",
        "completeStorageEffect",
        "listPendingStorageEffects",
        "readCurrent",
        "readAsOf",
      ],
    ],
    ["knowledgeQuarantineStore", ["put", "read", "erase"]],
    [
      "ragStore",
      [
        "applyProjection",
        "search",
        "readCache",
        "writeCache",
        "recordAudit",
      ],
    ],
    [
      "modelDraftStore",
      ["prepareRoute", "completeRoute", "failRoute", "readRoute"],
    ],
    [
      "modelReviewStore",
      ["prepareRoute", "completeRoute", "failRoute", "readRoute"],
    ],
    ["modelProvider", ["invoke"]],
    [
      "toolStore",
      [
        "saveConfirmation",
        "getConfirmation",
        "beginExecution",
        "completeExecution",
        "failExecution",
      ],
    ],
    [
      "decisionStore",
      [
        "createArtifact",
        "createDecision",
        "withdrawDecision",
        "queueEffect",
      ],
    ],
    [
      "c08StateStore",
      ["runCommand", "readRun", "readTenantSnapshot"],
    ],
    ["auditStore", ["append", "exportChain"]],
    [
      "observabilityStore",
      [
        "appendSignal",
        "querySignals",
        "reserve",
        "release",
        "settle",
        "queryUsage",
        "queryQuota",
      ],
    ],
  ]) {
    requireMethods(storage[name], methods, name);
  }
  if (typeof storage.c12StatePortFactory !== "function") {
    failStorageConfiguration("c12StatePortFactory is incomplete.");
  }
  requireMethods(storage.c08Receipts?.executor, ["accept"], "c08Receipts.executor");
  requireMethods(storage.c08Receipts?.verifier, ["resolve"], "c08Receipts.verifier");
  return storage;
}

function validateC12StatePort(statePort) {
  requireMethods(
    statePort,
    ["replay", "create", "get", "transact"],
    "c12StatePortFactory result",
  );
  return statePort;
}

function createDiagnosticTenantDataAdapter() {
  const receipts = new Map();
  return Object.freeze({
    async project(event) {
      const serialized = JSON.stringify(event);
      const prior = receipts.get(event.id);
      if (prior && prior !== serialized) {
        failStorageConfiguration("Diagnostic lifecycle event changed.");
      }
      receipts.set(event.id, serialized);
      return Object.freeze({
        tenantId: event.subject,
        eventId: event.id,
        status: "SUCCEEDED",
        duplicate: Boolean(prior),
      });
    },
  });
}

function createMemoryG1Storage() {
  return Object.freeze({
    tenantStore: createMemoryTenantStore(),
    tenantDataAdapter: createDiagnosticTenantDataAdapter(),
    identityStore: createMemoryIdentityStore(),
    principalStore: createMemoryPrincipalStore(),
    authorizationStore: createMemoryAuthorizationStore(),
    knowledgeCatalogStore: createMemoryKnowledgeCatalogStore(),
    knowledgeQuarantineStore: createMemoryC10QuarantineStore(),
    ragStore: createMemoryPermissionAwareRagStore(),
    modelDraftStore: createMemoryModelGatewayStore(),
    modelReviewStore: createMemoryModelGatewayStore(),
    modelProvider: createC14SyntheticModelProvider(),
    toolStore: createMemoryToolGatewayStore({ clock: () => NOW }),
    decisionStore: createMemoryHumanDecisionStore({
      clock: () => NOW,
    }),
    c12StatePortFactory: () => createMemoryC12StatePort(),
    c08StateStore: createMemoryAiosStateStore(),
    c08Receipts: createC08C0MockToolReceipts(),
    auditStore: createMemoryAuditEvidenceStore({
      clock: () => NOW,
    }),
    observabilityStore: createMemoryObservabilityStore(),
  });
}

async function loadJson(relativePath) {
  return JSON.parse(
    await readFile(new URL(relativePath, import.meta.url), "utf8"),
  );
}

function c03UuidFactory() {
  const tenantUuids = new Map([
    [1, G1_SYNTHETIC_TENANT_IDS[0].slice(4)],
    [11, G1_SYNTHETIC_TENANT_IDS[1].slice(4)],
    [21, G1_SYNTHETIC_TENANT_IDS[2].slice(4)],
  ]);
  let call = 0;
  return () => {
    call += 1;
    return (
      tenantUuids.get(call) ??
      `018f1000-0000-7000-8000-${call.toString(16).padStart(12, "0")}`
    );
  };
}

function uuidFactory(prefix) {
  let call = 0;
  return () => {
    call += 1;
    return `01985000-${prefix}-7000-8000-${call
      .toString(16)
      .padStart(12, "0")}`;
  };
}

function secretFactory(prefix = "") {
  let call = 0;
  return () => {
    call += 1;
    return (
      prefix +
      call
        .toString(16)
        .padStart(64 - prefix.length, "0")
    );
  };
}

function fixtureSeed(index) {
  return `fixture://SYNTHETIC-SEED-${String(index + 1).padStart(3, "0")}`;
}

async function createIdentityPlatform({
  tenantStore,
  tenantDataAdapter,
  identityStore,
  identityInstancePrefix,
  identitySecretPrefix,
}) {
  const identityCatalogDocument = await loadJson(
    "../implementation/p1/c04/synthetic-identity-catalog.v1.json",
  );
  const f02Documents = await Promise.all([
    loadJson(
      "../implementation/p0/f02/generated/synthetic-tenant-northstar-fasteners.json",
    ),
    loadJson(
      "../implementation/p0/f02/generated/synthetic-tenant-blue-harbor-tools.json",
    ),
    loadJson(
      "../implementation/p0/f02/generated/synthetic-tenant-cedar-field-components.json",
    ),
  ]);
  const tenantRegistry = createTenantRegistry({
    store: tenantStore,
    fixtureCatalog: createSyntheticFixtureCatalog(
      identityCatalogDocument.map((entry, index) => ({
        fixtureId: entry.fixtureId,
        sha256: entry.sha256,
        allowedConfigRefs: [fixtureSeed(index)],
      })),
    ),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock: () => NOW,
    idFactory: c03UuidFactory(),
  });

  const authorizationRequests = new Map();
  const entryByIssuer = new Map(
    identityCatalogDocument.map((entry) => [entry.provider.issuer, entry]),
  );
  const federationBroker = {
    async startAuthorization(request) {
      authorizationRequests.set(request.issuer, structuredClone(request));
      return {
        authorizationUrl: `${request.issuer}/protocol/openid-connect/auth`,
      };
    },
    async exchangeAndVerify(request) {
      const authorization = authorizationRequests.get(request.issuer);
      const entry = entryByIssuer.get(request.issuer);
      if (!authorization || !entry) {
        throw new Error("Synthetic OIDC transaction is unknown.");
      }
      const userIndex = Number.parseInt(
        request.authorizationCode.split("-").at(-1),
        10,
      );
      const user = entry.users[userIndex - 1];
      if (!user) {
        throw new Error("Synthetic OIDC user is unknown.");
      }
      return {
        protocol: "OIDC",
        signatureVerified: true,
        synthetic: true,
        issuer: request.issuer,
        audience: [request.clientId],
        authorizedParty: request.clientId,
        subject: user.loginSubject,
        nonce: authorization.nonce,
        issuedAt: NOW,
        notBefore: NOW,
        expiresAt: "2026-07-26T13:00:00.000Z",
        authenticationTime: NOW,
        authenticationMethods: ["pwd", "mfa"],
        algorithm: "RS256",
        keyId: entry.provider.allowedKeyIds[0],
        configurationVersion: entry.provider.configurationVersion,
      };
    },
  };
  const identityFederation = createIdentityFederation({
    store: identityStore,
    tenantRegistry,
    tenantRegistryContext: TENANT_READER,
    identityCatalog: createSyntheticIdentityCatalog(
      identityCatalogDocument,
    ),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    federationBroker,
    clock: () => NOW,
    idFactory: uuidFactory(identityInstancePrefix),
    secretFactory: secretFactory(identitySecretPrefix),
  });

  const tenantStates = [];
  for (const [index, catalogEntry] of identityCatalogDocument.entries()) {
    const f02 = f02Documents[index];
    const created = await tenantRegistry.execute(TENANT_OPERATOR, {
      kind: "CREATE_SYNTHETIC_TENANT",
      idempotencyKey: `g1-create-tenant-${index + 1}`,
      creationKey: `g1:${catalogEntry.fixtureId}`,
      fixtureRef: {
        fixtureId: catalogEntry.fixtureId,
        sha256: catalogEntry.sha256,
      },
      configRefs: [fixtureSeed(index)],
      correlationId: `g1-create-tenant-${index + 1}`,
    });
    const provisioning = await tenantRegistry.snapshot(
      TENANT_READER,
      created.tenantId,
    );
    const event = provisioning.outbox.find(
      ({ type }) => type === "product.tenant.provisioning-requested.v1",
    );
    await tenantDataAdapter.project(event);
    const projected = await identityFederation.execute(
      IDENTITY_PROJECTION_WORKER,
      {
        kind: "APPLY_TENANT_LIFECYCLE_EVENT",
        idempotencyKey: `g1-project-identity-${index + 1}`,
        tenantId: created.tenantId,
        sourceEventId: event.id,
        sourceLifecycleVersion: event.data.lifecycle_version,
        sourceGeneration: event.data.generation,
        sourceOperationId: event.data.operation_id,
        sourceState: event.data.state,
        correlationId: event.correlationid,
      },
    );
    const identitySnapshot = await identityFederation.snapshot(
      IDENTITY_PROJECTION_WORKER,
      { tenantId: created.tenantId },
    );
    const readyEvent = identitySnapshot.outbox.find(
      ({ type }) =>
        type === "product.identity.tenant-projection-ready.v1",
    );
    for (const [projectionIndex, projection] of PROJECTIONS.entries()) {
      await tenantRegistry.execute(TENANT_PROJECTION_WORKER, {
        kind: "RECORD_PROJECTION_RESULT",
        idempotencyKey: `g1-ready-${index + 1}-${projection}`,
        tenantId: created.tenantId,
        generation: created.generation,
        operationId: created.operationId,
        projection,
        outcome: "SUCCEEDED",
        attempt: 1,
        sourceEventId:
          projection === "IDENTITY"
            ? readyEvent.id
            : `g1-projection-${index + 1}-${projectionIndex + 1}`,
        correlationId: `g1-provision-${index + 1}`,
      });
    }
    await tenantRegistry.execute(TENANT_RECONCILER, {
      kind: "RECONCILE_TENANT",
      idempotencyKey: `g1-reconcile-${index + 1}`,
      tenantId: created.tenantId,
      correlationId: `g1-reconcile-${index + 1}`,
    });
    const active = await tenantRegistry.snapshot(
      TENANT_READER,
      created.tenantId,
    );
    const activeEvent = active.outbox.find(
      ({ type }) => type === "product.tenant.activated.v1",
    );
    await tenantDataAdapter.project(activeEvent);
    const accounts = [];
    for (const [userIndex, user] of catalogEntry.users.entries()) {
      accounts.push(
        await identityFederation.execute(IDENTITY_PROVISIONING_WORKER, {
          kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
          idempotencyKey: `g1-account-${index + 1}-${userIndex + 1}`,
          tenantId: created.tenantId,
          providerConnectionId: projected.providerConnectionId,
          fixtureUserId: user.fixtureUserId,
          sourceEventId: `g1-account-source-${index + 1}-${userIndex + 1}`,
          sourceRevision: 1,
          desiredState: "ACTIVE",
          correlationId: `g1-account-${index + 1}-${userIndex + 1}`,
        }),
      );
    }
    const sessions = [];
    for (const [userIndex, user] of catalogEntry.users.entries()) {
      const started = await identityFederation.startLogin(PORTAL_CONTEXT, {
        tenantId: created.tenantId,
        providerConnectionId: projected.providerConnectionId,
        returnRoute: "PORTAL_HOME",
      });
      const completed = await identityFederation.completeLogin(
        PORTAL_CONTEXT,
        {
          transactionId: started.transactionId,
          state: started.state,
          authorizationCode: `synthetic-code-${index + 1}-${userIndex + 1}`,
          codeVerifier: started.codeVerifier,
        },
      );
      const resolved = await identityFederation.resolveSession(
        PORTAL_CONTEXT,
        {
          sessionToken: completed.sessionToken,
          expectedTenantId: created.tenantId,
        },
      );
      sessions.push({
        fixtureUserId: user.fixtureUserId,
        profileRef: user.profileRef,
        sessionToken: completed.sessionToken,
        sessionId: resolved.sessionId,
        accountId: resolved.identityAccountId,
        trustSource: resolved.trustSource,
      });
    }
    tenantStates.push({
      tenantId: created.tenantId,
      fixtureId: catalogEntry.fixtureId,
      catalogEntry,
      f02,
      accounts,
      sessions,
      sessionToken: sessions[0].sessionToken,
      login: {
        module: "C04",
        tenantId: created.tenantId,
        identityAccountId: sessions[0].accountId,
        sessionId: sessions[0].sessionId,
        trustSource: sessions[0].trustSource,
        selectedForChain: true,
      },
    });
  }
  return { tenantRegistry, identityFederation, tenantStates };
}

async function createPrincipalPlatform(identityPlatform, store) {
  const principalCatalogDocument = await loadJson(
    "../implementation/p1/c05/synthetic-principal-catalog.v1.json",
  );
  const registry = createStablePrincipalRegistry({
    store,
    tenantRegistry: identityPlatform.tenantRegistry,
    tenantRegistryContext: TENANT_READER,
    identityFederation: identityPlatform.identityFederation,
    identityFederationReadContext: IDENTITY_PROJECTION_WORKER,
    identityFederationServerContext: PORTAL_CONTEXT,
    principalCatalog: createSyntheticPrincipalCatalog(
      principalCatalogDocument,
    ),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock: () => NOW,
    idFactory: uuidFactory("2000"),
  });
  const purposes = Object.freeze({
    MANAGE: "synthetic://c06/purpose/manage",
    READ: "synthetic://c06/purpose/read",
    RETRIEVE: "synthetic://c06/purpose/retrieve",
    DOWNLOAD: "synthetic://c06/purpose/download",
    TOOL_CALL: "synthetic://c06/purpose/tool-call",
  });
  for (const [tenantIndex, tenant] of identityPlatform.tenantStates.entries()) {
    const catalogEntry = principalCatalogDocument.find(
      ({ fixtureId }) => fixtureId === tenant.fixtureId,
    );
    const principals = new Map();
    for (const [index, fixture] of catalogEntry.principals.entries()) {
      const created = await registry.execute(PRINCIPAL_OPERATOR, {
        kind: "CREATE_SYNTHETIC_PRINCIPAL",
        idempotencyKey: `g1-principal-${tenantIndex + 1}-${index + 1}`,
        tenantId: tenant.tenantId,
        fixturePrincipalRef: fixture.fixturePrincipalRef,
        correlationId: `g1-principal-${tenantIndex + 1}-${index + 1}`,
      });
      principals.set(fixture.fixturePrincipalRef, created.principal);
    }
    for (let userIndex = 0; userIndex < 3; userIndex += 1) {
      const principalFixture = catalogEntry.principals[userIndex];
      const principal = principals.get(
        principalFixture.fixturePrincipalRef,
      );
      await registry.execute(PRINCIPAL_OPERATOR, {
        kind: "LINK_IDENTITY_ACCOUNT",
        idempotencyKey: `g1-link-${tenantIndex + 1}-${userIndex + 1}`,
        tenantId: tenant.tenantId,
        principalId: principal.principalId,
        identityAccountId: tenant.sessions[userIndex].accountId,
        linkEvidenceRef:
          `synthetic://g1/identity-link/${tenantIndex + 1}/${userIndex + 1}`,
        correlationId: `g1-link-${tenantIndex + 1}-${userIndex + 1}`,
      });
    }
    const actorFixture = catalogEntry.principals.find(
      ({ principalType }) => principalType === "AGENT",
    );
    const actor = principals.get(actorFixture.fixturePrincipalRef);
    const serverContext = {
      synthetic: true,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: actor.principalId,
    };
    const userBindings = [];
    for (let userIndex = 0; userIndex < 3; userIndex += 1) {
      const principalFixture = catalogEntry.principals[userIndex];
      const human = principals.get(
        principalFixture.fixturePrincipalRef,
      );
      const delegations = {};
      for (const [surface, purposeRef] of Object.entries(purposes)) {
        const suffix =
          `${tenantIndex + 1}-${userIndex + 1}-${surface.toLowerCase()}`;
        const value = await registry.execute(PRINCIPAL_OPERATOR, {
          kind: "CREATE_DELEGATION",
          idempotencyKey: `g1-delegation-${suffix}`,
          tenantId: tenant.tenantId,
          humanSubjectPrincipalId: human.principalId,
          delegatorPrincipalId: human.principalId,
          delegatePrincipalId: actor.principalId,
          expiresAt: "2026-07-27T00:00:00.000Z",
          purposeRef,
          correlationId: `g1-delegation-${suffix}`,
        });
        delegations[surface] = value.delegation;
      }
      const actionIdentity = await registry.resolveActionIdentity(
        serverContext,
        {
          sessionToken: tenant.sessions[userIndex].sessionToken,
          expectedTenantId: tenant.tenantId,
          delegationId: delegations.MANAGE.delegationId,
        },
      );
      userBindings.push({
        f02UserId: tenant.f02.records.users[userIndex].id,
        fixtureUserId: tenant.sessions[userIndex].fixtureUserId,
        role: tenant.f02.records.users[userIndex].role,
        sessionToken: tenant.sessions[userIndex].sessionToken,
        accountId: tenant.sessions[userIndex].accountId,
        human,
        actor,
        delegations,
        actionIdentity,
      });
    }
    const selected = userBindings[0];
    Object.assign(tenant, {
      principals,
      userBindings,
      human: selected.human,
      actor,
      delegations: selected.delegations,
      actionIdentity: selected.actionIdentity,
    });
  }
  return { registry };
}

function tupleKey(tuple) {
  return `${tuple.user}|${tuple.relation}|${tuple.object}`;
}

function c06StoreId(index) {
  return `01J00000000000000000000${String(index + 10).padStart(3, "0")}`;
}

function c06ModelId(index) {
  return `01J00000000000000000000${String(index + 20).padStart(3, "0")}`;
}

async function createAuthorizationPlatform(
  identityPlatform,
  principalPlatform,
  store,
  idPrefix,
) {
  const catalog = createSyntheticAuthorizationCatalog({
    policyCatalog: await loadJson(
      "../implementation/p1/c06/synthetic-policy-catalog.v1.json",
    ),
    protectedOperations: await loadJson(
      "../implementation/p1/c06/protected-operations.v1.json",
    ),
    fixtures: await loadJson(
      "../implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
    ),
    model: await loadJson(
      "../implementation/p1/c06/openfga/authorization-model.v1.json",
    ),
  });
  const policyByTenant = new Map();
  const roleBoundResources = new Map();
  for (const [index, tenant] of identityPlatform.tenantStates.entries()) {
    const principalIdsByFixtureRef = Object.fromEntries(
      [...tenant.principals.entries()].map(([reference, principal]) => [
        reference,
        principal.principalId,
      ]),
    );
    const tupleBundle = buildSyntheticPolicyTuples({
      catalog,
      templateRef: C06_TEMPLATE_REF,
      fixtureId: tenant.fixtureId,
      principalIdsByFixtureRef,
    });
    policyByTenant.set(tenant.tenantId, {
      tupleBundle,
      activeTuples: new Set(tupleBundle.map(tupleKey)),
      storeId: c06StoreId(index),
      modelId: c06ModelId(index),
    });
  }
  const facade = createAuthorizationFacade({
    store,
    tenantRegistry: identityPlatform.tenantRegistry,
    stablePrincipalRegistry: principalPlatform.registry,
    policyCatalog: catalog,
    async resolveTenantFixture(tenantId) {
      const tenant = identityPlatform.tenantStates.find(
        (value) => value.tenantId === tenantId,
      );
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        fixtureId: tenant.fixtureId,
      };
    },
    async resolveResource({ tenantId, tenantKind, surface, resourceId }) {
      const policy = policyByTenant.get(tenantId);
      const operation = catalog.operation(surface);
      const binding = roleBoundResources.get(
        `${tenantId}|${surface}|${resourceId}`,
      );
      const sourceTuples = policy.tupleBundle.filter((tuple) =>
        [
          operation.human_relation,
          operation.actor_relation,
          operation.purpose_relation,
        ].includes(tuple.relation),
      );
      for (const tuple of sourceTuples) {
        if (
          binding &&
          tuple.relation === operation.human_relation
        ) {
          policy.activeTuples.add(
            tupleKey({
              ...tuple,
              user: `human:${binding.ownerPrincipalId}`,
              object: `${operation.resource_type}:${resourceId}`,
            }),
          );
        } else if (
          !binding ||
          tuple.relation !== operation.human_relation
        ) {
          policy.activeTuples.add(
            tupleKey({
              ...tuple,
              object: `${operation.resource_type}:${resourceId}`,
            }),
          );
        }
      }
      return {
        tenantId,
        tenantKind,
        resourceType: operation.resource_type,
        resourceId,
        state: "ACTIVE",
        authorizationVersion: 1,
        trustSource: "VERIFIED_RESOURCE_CONTEXT",
      };
    },
    pdpFactory({ storeId, authorizationModelId }) {
      const policy = [...policyByTenant.values()].find(
        (value) => value.storeId === storeId,
      );
      return {
        async check({ authorizationModelId: requestedModel, tupleKey: key }) {
          return {
            allowed: policy.activeTuples.has(tupleKey(key)),
            storeId,
            authorizationModelId:
              requestedModel === authorizationModelId
                ? authorizationModelId
                : "mismatch",
            consistency: "HIGHER_CONSISTENCY",
          };
        },
      };
    },
    async verifyPolicyRelease(release) {
      return {
        passed: true,
        fixturePassCount: release.fixturePassCount,
        fixtureFailCount: 0,
        policyBundleSha256: release.bundleSha256,
        tupleBundleSha256: release.tupleBundleSha256,
        fixtureReportSha256: release.fixtureReportSha256,
        modelSha256: release.modelSha256,
        openFgaStoreId: release.openFgaStoreId,
        authorizationModelId: release.authorizationModelId,
      };
    },
    authorizeControl: () => true,
    clock: () => NOW,
    idFactory: uuidFactory(idPrefix),
  });
  const control = {
    actorId: "syn_svc_g1_authorization_admin",
    projectionTrustSource: "VERIFIED_PROJECTION_WORKER",
  };
  for (const [index, tenant] of identityPlatform.tenantStates.entries()) {
    const policy = policyByTenant.get(tenant.tenantId);
    const staged = await facade.execute(control, {
      kind: "STAGE_SYNTHETIC_POLICY_RELEASE",
      tenantId: tenant.tenantId,
      templateRef: C06_TEMPLATE_REF,
      idempotencyKey: `g1-c06-stage-${index + 1}`,
      correlationId: `g1-c06-stage-${index + 1}`,
    });
    const ready = await facade.execute(control, {
      kind: "RECORD_POLICY_PROJECTION",
      tenantId: tenant.tenantId,
      policyReleaseId: staged.policyReleaseId,
      projectionOperationId: `g1-c06-project-operation-${index + 1}`,
      outcome: "READY",
      openFgaStoreId: policy.storeId,
      authorizationModelId: policy.modelId,
      tupleBundleSha256: hashSyntheticPolicyTuples(policy.tupleBundle),
      fixtureReportRef: `evidence://g1/c06/fixture-report/${index + 1}`,
      fixtureReportSha256:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      fixturePassCount: 30,
      fixtureFailCount: 0,
      reasonRef: null,
      idempotencyKey: `g1-c06-project-${index + 1}`,
      correlationId: `g1-c06-project-${index + 1}`,
    });
    await facade.execute(control, {
      kind: "ACTIVATE_POLICY_RELEASE",
      tenantId: tenant.tenantId,
      policyReleaseId: ready.policyReleaseId,
      expectedActivationVersion: 0,
      reasonRef: `policy://g1/c06/activate/${index + 1}`,
      idempotencyKey: `g1-c06-activate-${index + 1}`,
      correlationId: `g1-c06-activate-${index + 1}`,
    });
  }
  return {
    facade,
    catalog,
    policyByTenant,
    registerRoleBoundResource({
      tenantId,
      surface,
      resourceId,
      ownerPrincipalId,
    }) {
      const key = `${tenantId}|${surface}|${resourceId}`;
      const existing = roleBoundResources.get(key);
      if (
        existing &&
        existing.ownerPrincipalId !== ownerPrincipalId
      ) {
        throw new Error(
          "G1 role-bound resource owner is immutable.",
        );
      }
      if (!existing) {
        roleBoundResources.set(key, { ownerPrincipalId });
      }
      return Object.freeze({ tenantId, surface, resourceId, ownerPrincipalId });
    },
    resolveRoleBoundResource({ tenantId, surface, resourceId }) {
      return roleBoundResources.get(
        `${tenantId}|${surface}|${resourceId}`,
      ) ?? null;
    },
  };
}

function surfaceSuffix(surface) {
  return surface.toLowerCase().replaceAll("_", "-");
}

async function c07Context(
  identityPlatform,
  authorizationPlatform,
  tenant,
  surface,
  correlationId,
) {
  const delegation = tenant.delegations[surface];
  const serverContext = {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: tenant.tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: tenant.actor.principalId,
  };
  const authorizationRequest = {
    sessionToken: tenant.sessionToken,
    delegationId: delegation.delegationId,
    correlationId,
  };
  const decision = await authorizationPlatform.facade.decide(
    { ...serverContext, surface },
    {
      ...authorizationRequest,
      resourceId: `${tenant.fixtureId}--${surfaceSuffix(surface)}`,
    },
  );
  const admission = await identityPlatform.tenantRegistry.admitNewRequest({
    tenantId: tenant.tenantId,
    expectedTenantKind: "SYNTHETIC",
  });
  return {
    tenantScope: {
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId: tenant.tenantId,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: admission.lifecycleVersion,
      correlationId,
      decisionId: decision.decisionId,
      evidenceRef: decision.evidenceRef,
      policyVersion: decision.authorizationModelId,
    },
    c06ServerContext: serverContext,
    authorizationRequest,
  };
}

function c11Publication(fixture) {
  return {
    ownerPrincipalId: fixture.publication.owner_principal_id,
    sourceRef: fixture.publication.source_ref,
    version: fixture.publication.version,
    validFrom: fixture.publication.valid_from,
    validUntil: fixture.publication.valid_until,
    classification: fixture.publication.classification,
    acl: structuredClone(fixture.publication.acl),
  };
}

async function createKnowledgePlatform(
  identityPlatform,
  authorizationPlatform,
  {
    knowledgeCatalogStore,
    knowledgeQuarantineStore,
    ragStore,
  },
) {
  const c10Benchmark = createC10SyntheticBenchmark(
    await loadJson(
      "../implementation/p1/c10/synthetic-document-benchmark.v1.json",
    ),
  );
  const c11Document = await loadJson(
    "../implementation/p1/c11/synthetic-rag-benchmark.v1.json",
  );
  const c11Benchmark = createC11SyntheticBenchmark(c11Document);
  const catalogStore = knowledgeCatalogStore;
  const catalog = createKnowledgeCatalog({
    store: catalogStore,
    quarantineStore: knowledgeQuarantineStore,
    c06Authorizer: createC10C06Authorizer({
      authorizationFacade: authorizationPlatform.facade,
    }),
    benchmark: c10Benchmark,
    clock: () => NOW,
  });
  const rag = createPermissionAwareRag({
    store: ragStore,
    catalogReader: catalogStore,
    c06Authorizer: createC11C06Authorizer({
      authorizationFacade: authorizationPlatform.facade,
    }),
    principalResolver: {
      async resolve({ tenantScope, authorizationEvidence }) {
        const principalRefs = [
          `human:${authorizationEvidence.humanPrincipalId}`,
          "group:synthetic-sales",
          "group:synthetic-knowledge-owners",
        ].sort();
        return {
          trustSource: "C06_HUMAN_AND_SERVER_GROUP_RESOLUTION",
          tenantId: tenantScope.tenantId,
          humanPrincipalId: authorizationEvidence.humanPrincipalId,
          humanSecurityEpoch: authorizationEvidence.humanSecurityEpoch,
          principalRefs,
          principalScopeHash: c11Sha256(principalRefs),
        };
      },
    },
    benchmark: c11Benchmark,
    clock: () => NOW,
  });
  const fixture = c11Document.documents.find(
    ({ document_id: documentId }) => documentId === "sales-guide",
  );
  for (const [index, tenant] of identityPlatform.tenantStates.entries()) {
    const context = await c07Context(
      identityPlatform,
      authorizationPlatform,
      tenant,
      "MANAGE",
      `g1-c11-project-${index + 1}`,
    );
    const prefix = `g1-${index + 1}-sales-guide`;
    await catalog.upload(context, {
      idempotencyKey: `${prefix}-upload`,
      documentId: "sales-guide",
      documentVersion: 1,
      expectedRevision: 0,
      fixtureRef: fixture.fixture_ref,
      filename: "sales-guide.md",
      declaredMediaType: "text/markdown",
      sourceRef: fixture.publication.source_ref,
    });
    await catalog.inspect(context, {
      idempotencyKey: `${prefix}-inspect`,
      documentId: "sales-guide",
      documentVersion: 1,
      expectedRevision: 1,
    });
    await catalog.parse(context, {
      idempotencyKey: `${prefix}-parse`,
      documentId: "sales-guide",
      documentVersion: 1,
      expectedRevision: 2,
    });
    await catalog.publish(context, {
      idempotencyKey: `${prefix}-publish`,
      documentId: "sales-guide",
      documentVersion: 1,
      expectedRevision: 3,
      metadata: c11Publication(fixture),
    });
    await rag.synchronize(context, {
      idempotencyKey: `${prefix}-synchronize`,
      documentId: "sales-guide",
      documentVersion: 1,
      expectedProjectionVersion: 0,
    });
  }
  return { rag };
}

async function createModelPlatform(
  identityPlatform,
  principalPlatform,
  authorizationPlatform,
  { modelDraftStore, modelReviewStore, modelProvider },
) {
  const draftCatalogDocument = await loadJson(
    "../implementation/p1/c14/synthetic-model-catalog.v1.json",
  );
  const reviewCatalogDocument = structuredClone(draftCatalogDocument);
  for (const policy of draftCatalogDocument.tenantPolicies) {
    policy.canaryPercent = 0;
  }
  for (const policy of reviewCatalogDocument.tenantPolicies) {
    policy.canaryPercent = 100;
  }
  const provider = modelProvider;
  const dataPolicyResolver = {
    async resolve({ inputRef, inputSha256 }) {
      if (
        !inputRef.startsWith("synthetic://g1/") ||
        !/^sha256:[a-f0-9]{64}$/.test(inputSha256)
      ) {
        throw new Error("G1 Synthetic model input is not bound.");
      }
      return {
        trustSource: "C14_SYNTHETIC_DATA_POLICY",
        inputRef,
        inputSha256,
        dataClassification: "CONFIDENTIAL",
        inputTokens: 256,
        requiredPlane: "LOCAL_ONLY",
      };
    },
  };
  function gateway(catalogDocument, idPrefix, store) {
    return createModelGateway({
      tenantRegistry: identityPlatform.tenantRegistry,
      stablePrincipalRegistry: principalPlatform.registry,
      authorizer: createC14C06Authorizer({
        authorizationFacade: authorizationPlatform.facade,
      }),
      catalog: createSyntheticModelCatalog(catalogDocument),
      store,
      dataPolicyResolver,
      providerInvoker: provider,
      clock: () => NOW,
      idFactory: uuidFactory(idPrefix),
    });
  }
  return {
    gateway: gateway(draftCatalogDocument, "4000", modelDraftStore),
    reviewGateway: gateway(
      reviewCatalogDocument,
      "4100",
      modelReviewStore,
    ),
    provider,
  };
}

async function createToolPlatform(
  identityPlatform,
  principalPlatform,
  authorizationPlatform,
  store,
  clock,
) {
  const catalog = createSyntheticToolCatalog(
    await loadJson(
      "../implementation/p1/c16/operation-catalog.v1.json",
    ),
  );
  const fixtureDocument = await loadJson(
    "../implementation/p1/c16/synthetic-tool-fixtures.v1.json",
  );
  const credentialBroker = createC16EphemeralCredentialBroker({
    clock,
    idFactory: uuidFactory("5000"),
  });
  const adapter = createC16SyntheticToolAdapter({
    credentialBroker,
    fixtureDocument,
  });
  const gateway = createToolGateway({
    tenantRegistry: identityPlatform.tenantRegistry,
    stablePrincipalRegistry: principalPlatform.registry,
    authorizer: createC16C06Authorizer({
      authorizationFacade: authorizationPlatform.facade,
    }),
    catalog,
    store,
    credentialBroker,
    adapter,
    clock,
    idFactory: uuidFactory("6000"),
  });
  return { gateway, adapter, catalog };
}

async function createDecisionPlatform(
  identityPlatform,
  principalPlatform,
  authorizationPlatform,
  store,
) {
  const catalogDocument = await loadJson(
    "../implementation/p1/c15/synthetic-workflow-fixtures.v1.json",
  );
  const catalog = createSyntheticHumanDecisionCatalog(catalogDocument);
  const workflow = createHumanDecisionWorkflow({
    tenantRegistry: {
      admitNewRequest(context) {
        return identityPlatform.tenantRegistry.admitNewRequest({
          tenantId: context.tenantId,
          expectedTenantKind: "SYNTHETIC",
        });
      },
    },
    stablePrincipalRegistry: {
      resolveActionIdentity(context, request) {
        return principalPlatform.registry.resolveActionIdentity(context, {
          sessionToken: request.sessionToken,
          expectedTenantId: context.tenantId,
          delegationId: request.delegationId,
        });
      },
    },
    authorizer: createC15C06Authorizer({
      authorizationFacade: authorizationPlatform.facade,
    }),
    decisionCeremony: {
      async verify(input) {
        return {
          trustSource: "C15_DEDICATED_DECISION_CEREMONY",
          proofRef: input.proofRef,
          proofSha256: humanDecisionSha256({
            proofRef: input.proofRef,
            artifactSha256: input.artifactSha256,
          }),
          artifactSha256: input.artifactSha256,
          displaySha256: input.displaySha256,
          humanPrincipalId: input.identityBinding.humanPrincipalId,
          leafDelegationId: input.identityBinding.leafDelegationId,
          expiresAt: "2026-07-26T12:05:00.000Z",
        };
      },
    },
    catalog,
    store,
    clock: () => NOW,
    idFactory: uuidFactory("7000"),
  });
  return { workflow, store, catalogDocument };
}

function c12Clock(tenantIndex) {
  let tick = tenantIndex * 100;
  return () =>
    new Date(Date.UTC(2026, 6, 26, 12, 0, tick++)).toISOString();
}

function c12IdFactory(tenantIndex) {
  let value = tenantIndex * 100 + 1;
  return () =>
    `00000000-0000-4000-8000-${String(value++).padStart(12, "0")}`;
}

function g1ServerContext(tenant) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: tenant.tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: tenant.actor.principalId,
  };
}

function c12Authorization(authorizationPlatform) {
  return {
    async enforce(serverContext, request, descriptor) {
      const c06ResourceId =
        `c12-${c12Sha256(request.resourceId).slice(7, 39)}`;
      const decision = await authorizationPlatform.facade.decide(
        { ...serverContext, surface: descriptor.surface },
        {
          sessionToken: request.sessionToken,
          delegationId: request.delegationId,
          resourceId: c06ResourceId,
          correlationId: request.correlationId,
        },
      );
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        tenantId: decision.tenantId,
        humanPrincipalId: decision.humanPrincipalId,
        workloadActorPrincipalId:
          decision.workloadActorPrincipalId,
        decisionId: decision.decisionId,
        evidenceRef: decision.evidenceRef,
        policyVersion: decision.authorizationModelId,
        resourceId: request.resourceId,
        operationId: descriptor.operationId,
      };
    },
  };
}

async function createOrchestrationPlatform({
  identityPlatform,
  authorizationPlatform,
  knowledgePlatform,
  modelPlatform,
  toolPlatform,
  decisionPlatform,
  statePort,
}) {
  const catalogDocument = await loadJson(
    "../implementation/p1/c12/synthetic-task-catalog.v1.json",
  );
  const graphDocument = await loadJson(
    "../implementation/p1/c12/orchestration-graph.v1.json",
  );
  const catalog = createSyntheticOrchestrationCatalog({
    catalog: catalogDocument,
    graph: graphDocument,
  });
  const executions = new Map();

  function instanceFor(tenant) {
    const prior = executions.get(tenant.tenantId);
    if (prior) return prior;
    const tenantIndex = identityPlatform.tenantStates.indexOf(tenant);
    const observed = {
      c11: null,
      c14: null,
      c14Review: null,
      c16: null,
      c15: null,
    };
    const orchestrator = createAgentOrchestrator({
      authorizer: c12Authorization(authorizationPlatform),
      statePort,
      catalog,
      policyGate: {
        async evaluate(input) {
          return {
            schemaVersion: "c12-policy-gate.v1",
            tenantId: input.tenantId,
            taskId: input.taskId,
            effectKey: input.effectKey,
            effect: "ALLOW",
            reasonCode: "C06_BASELINE_AND_SYNTHETIC_BOUNDARY_PASS",
            policyRef: input.policy.ref,
            policyVersion: input.policy.version,
            policySha256: input.policy.sha256,
            budgetSha256: c12Sha256(input.budget),
            dataClass: input.dataClass,
            riskClass: input.riskClass,
          };
        },
      },
      ragPort: {
        async retrieve(input) {
          const context = await c07Context(
            identityPlatform,
            authorizationPlatform,
            tenant,
            "RETRIEVE",
            `g1-c12-c11-${input.effectKey.slice(7, 23)}`,
          );
          const retrieval = await knowledgePlatform.rag.search(
            context,
            {
              requestId:
                `g1-c12-c11-${input.effectKey.slice(7, 39)}`,
              query: "owner ACL publication",
              limit: 5,
            },
          );
          observed.c11 = retrieval;
          return {
            schemaVersion: "c12-rag-result.v1",
            tenantId: input.tenantId,
            taskId: input.taskId,
            effectKey: input.effectKey,
            inputRef: input.inputRef,
            inputSha256: input.inputSha256,
            status:
              retrieval.status === "ANSWERABLE"
                ? "EVIDENCE_READY"
                : "REFUSED",
            resultRef:
              `evidence://c11/results/${input.effectKey.slice(7)}`,
            resultSha256: c11Sha256(retrieval),
            knowledgeRef: input.knowledge.ref,
            knowledgeVersion: input.knowledge.version,
            knowledgeSha256: input.knowledge.sha256,
            evidenceRefs: retrieval.evidence.map(
              ({ evidenceId }) => `evidence://c11/${evidenceId}`,
            ),
          };
        },
      },
      toolPort: {
        async execute(_context, input) {
          const context = g1ServerContext(tenant);
          const operation =
            toolPlatform.catalog.operation(input.operationId);
          const authorization = await authorizationPlatform.facade.decide(
            { ...context, surface: "TOOL_CALL" },
            {
              sessionToken: tenant.sessionToken,
              delegationId:
                tenant.delegations.TOOL_CALL.delegationId,
              resourceId:
                `c16-${operation.authorizationResourceSuffix}`,
              correlationId: input.correlationId,
            },
          );
          const confirmation = await toolPlatform.gateway.confirm(
            context,
            {
              sessionToken: tenant.sessionToken,
              delegationId:
                tenant.delegations.TOOL_CALL.delegationId,
              correlationId: input.correlationId,
              operationId: input.operationId,
              idempotencyKey: `${input.effectKey}-confirm`,
              params: input.parameters,
            },
          );
          const result = await toolPlatform.gateway.execute(
            context,
            {
              sessionToken: tenant.sessionToken,
              delegationId:
                tenant.delegations.TOOL_CALL.delegationId,
              correlationId: input.correlationId,
              operationId: input.operationId,
              idempotencyKey: `${input.effectKey}-execute`,
              confirmationId: confirmation.confirmationId,
              confirmationSha256:
                confirmation.confirmationSha256,
              expectedParamSha256:
                confirmation.normalizedParamSha256,
            },
          );
          observed.c16 = { authorization, confirmation, result };
          return {
            schemaVersion: "c12-tool-result.v1",
            tenantId: input.tenantId,
            taskId: input.taskId,
            effectKey: input.effectKey,
            operationId: input.operationId,
            catalogVersion: input.catalogVersion,
            authorizationTrustSource:
              "C16_REAUTHORIZED_TOOL_CALL",
            authorizationDecisionRef: authorization.evidenceRef,
            authorizationDecisionSha256:
              toolGatewaySha256(authorization),
            identitySha256: confirmation.identitySha256,
            parameterSha256: input.parameterSha256,
            confirmationSha256:
              confirmation.confirmationSha256,
            humanPrincipalId: input.humanPrincipalId,
            workloadActorPrincipalId:
              input.workloadActorPrincipalId,
            resultRef:
              `evidence://c16/results/${result.receipt.receiptSha256.slice(7)}`,
            resultSha256: toolGatewaySha256(result.result),
            receiptSha256: result.receipt.receiptSha256,
            networkRequestCount:
              result.receipt.networkRequestCount,
            externalEffectCount:
              result.receipt.externalEffectCount,
          };
        },
      },
      modelPort: {
        async route(input) {
          const routed = await modelPlatform.gateway.route(
            g1ServerContext(tenant),
            {
              sessionToken: tenant.sessionToken,
              delegationId: tenant.delegations.MANAGE.delegationId,
              idempotencyKey:
                `g1-c12-draft-${input.effectKey.slice(7, 39)}`,
              correlationId:
                `g1-c12-draft-${input.effectKey.slice(7, 23)}`,
              taskRef: input.modelTask.ref,
              inputRef:
                `synthetic://g1/c12/draft/${input.taskId}`,
              inputSha256: input.contextSha256,
            },
          );
          const route = routed.route;
          observed.c14 = route;
          return {
            schemaVersion: "c12-model-result.v1",
            tenantId: input.tenantId,
            taskId: input.taskId,
            effectKey: input.effectKey,
            outputRef: route.responseRef,
            outputSha256: route.responseSha256,
            modelRef: route.selectedModel.modelRef,
            modelVersion: route.selectedModel.modelVersion,
            modelSha256: route.selectedModel.modelSha256,
            modelTaskRef: input.modelTask.ref,
            modelTaskVersion: input.modelTask.version,
            modelTaskSha256: input.modelTask.sha256,
            skillRef: input.skill.ref,
            skillVersion: input.skill.version,
            skillSha256: input.skill.sha256,
            contextSha256: input.contextSha256,
            inputTokens: route.usage.inputTokens,
            outputTokens: route.usage.outputTokens,
            totalTokens: route.usage.totalTokens,
            costMicrousd: route.costMicrousd,
          };
        },
      },
      validator: {
        async validate(input) {
          return {
            schemaVersion: "c12-validation-result.v1",
            tenantId: input.tenantId,
            taskId: input.taskId,
            effectKey: input.effectKey,
            artifactRef: input.artifactRef,
            artifactSha256: input.artifactSha256,
            outcome: "PASS",
            resultRef:
              `evidence://c12/validation/${input.effectKey.slice(7)}`,
            resultSha256: c12Sha256({
              artifactSha256: input.artifactSha256,
              outcome: "PASS",
            }),
            ruleRef: "policy://c12/g1-synthetic-draft-rules",
            ruleVersion: "1.0.0",
            ruleSha256: c12Sha256({
              ruleRef: "policy://c12/g1-synthetic-draft-rules",
              version: "1.0.0",
            }),
          };
        },
      },
      reviewer: {
        async review(input) {
          const routed = await modelPlatform.reviewGateway.route(
            g1ServerContext(tenant),
            {
              sessionToken: tenant.sessionToken,
              delegationId: tenant.delegations.MANAGE.delegationId,
              idempotencyKey:
                `g1-c12-review-${input.effectKey.slice(7, 39)}`,
              correlationId:
                `g1-c12-review-${input.effectKey.slice(7, 23)}`,
              taskRef: "synthetic://c14/tasks/structured-analysis",
              inputRef:
                `synthetic://g1/c12/review/${input.taskId}`,
              inputSha256: input.artifactSha256,
            },
          );
          const route = routed.route;
          observed.c14Review = route;
          return {
            schemaVersion: "c12-review-result.v1",
            tenantId: input.tenantId,
            taskId: input.taskId,
            effectKey: input.effectKey,
            artifactRef: input.artifactRef,
            artifactSha256: input.artifactSha256,
            outcome: "PASS",
            resultRef: route.responseRef,
            resultSha256: route.responseSha256,
            reviewerRef: "synthetic://c14/reviewers/independent",
            reviewerVersion: "1.0.0",
            reviewerSha256: c12Sha256({
              routeId: route.routeId,
              model: route.selectedModel,
            }),
            draftModelRef: input.draftModel.ref,
            draftModelVersion: input.draftModel.version,
            draftModelSha256: input.draftModel.sha256,
            reviewModelRef: route.selectedModel.modelRef,
            reviewModelVersion: route.selectedModel.modelVersion,
            reviewModelSha256: route.selectedModel.modelSha256,
            inputTokens: route.usage.inputTokens,
            outputTokens: route.usage.outputTokens,
            totalTokens: route.usage.totalTokens,
            costMicrousd: route.costMicrousd,
          };
        },
      },
      humanDecisionPort: {
        async verify(input) {
          const decision = observed.c15;
          if (
            !decision ||
            input.decisionRef !==
              `evidence://c15/decision/${decision.decisionId}` ||
            input.decisionSha256 !== decision.decisionSha256
          ) {
            throw new Error("C15 decision is not bound.");
          }
          return {
            schemaVersion: "c12-synthetic-human-decision.v1",
            tenantId: input.tenantId,
            taskId: input.taskId,
            effectKey: input.effectKey,
            expectedStateSha256: input.expectedStateSha256,
            decisionRef: input.decisionRef,
            decisionSha256: input.decisionSha256,
            outcome: decision.outcome,
            productionReusable: decision.productionReusable,
            externalEffectCount: decision.externalEffectCount,
            decidedByHumanPrincipalId: input.humanPrincipalId,
          };
        },
      },
      clock: c12Clock(tenantIndex),
      idFactory: c12IdFactory(tenantIndex),
    });
    const created = { orchestrator, observed, taskId: null };
    executions.set(tenant.tenantId, created);
    return created;
  }

  async function createHumanDecision(tenant, task, waiting, observed) {
    const tenantIndex = identityPlatform.tenantStates.indexOf(tenant);
    const fixture = decisionPlatform.catalogDocument.workflows.find(
      (value) => value.tenantId === tenant.tenantId,
    );
    const candidate = structuredClone(fixture.baseline);
    candidate.fields.subject = `G1 C12 ${waiting.taskId}`;
    const context = g1ServerContext(tenant);
    const artifact = await decisionPlatform.workflow.prepare(context, {
      sessionToken: tenant.sessionToken,
      delegationId: tenant.delegations.MANAGE.delegationId,
      idempotencyKey: `g1-c12-c15-prepare-${tenantIndex + 1}`,
      correlationId: `g1-c12-c15-prepare-${tenantIndex + 1}`,
      workflowRef: fixture.workflowRef,
      candidate,
    });
    const decision = await decisionPlatform.workflow.decide(context, {
      sessionToken: tenant.sessionToken,
      delegationId: tenant.delegations.MANAGE.delegationId,
      idempotencyKey: `g1-c12-c15-decide-${tenantIndex + 1}`,
      correlationId: `g1-c12-c15-decide-${tenantIndex + 1}`,
      artifactId: artifact.artifactId,
      artifactSha256: artifact.artifactSha256,
      outcome: "APPROVE",
      ceremonyProofRef:
        `fixture://g1/c12/c15/ceremonies/${tenantIndex + 1}`,
    });
    observed.c15 = decision;
    return decision;
  }

  async function rehydrateObserved(
    tenant,
    task,
    taskState,
    observed,
  ) {
    const record = (nodeId) =>
      taskState.nodeRecords.find((item) => item.nodeId === nodeId);
    if (!observed.c11) {
      const retrieval = record("RETRIEVE");
      const context = await c07Context(
        identityPlatform,
        authorizationPlatform,
        tenant,
        "RETRIEVE",
        `g1-c12-c11-${retrieval.effectKey.slice(7, 23)}`,
      );
      observed.c11 = await knowledgePlatform.rag.search(context, {
        requestId:
          `g1-c12-c11-${retrieval.effectKey.slice(7, 39)}`,
        query: "owner ACL publication",
        limit: 5,
      });
    }
    if (!observed.c16) {
      const tool = record("TOOL");
      const context = g1ServerContext(tenant);
      const operation = toolPlatform.catalog.operation(
        tool.binding.operationId,
      );
      const correlationId =
        `g1-c12-advance-${tenant.tenantId.slice(-3)}-4`;
      const authorization = await authorizationPlatform.facade.decide(
        { ...context, surface: "TOOL_CALL" },
        {
          sessionToken: tenant.sessionToken,
          delegationId:
            tenant.delegations.TOOL_CALL.delegationId,
          resourceId:
            `c16-${operation.authorizationResourceSuffix}`,
          correlationId,
        },
      );
      const confirmation = await toolPlatform.gateway.confirm(
        context,
        {
          sessionToken: tenant.sessionToken,
          delegationId:
            tenant.delegations.TOOL_CALL.delegationId,
          correlationId,
          operationId: tool.binding.operationId,
          idempotencyKey: `${tool.effectKey}-confirm`,
          params: task.toolInvocation.parameters,
        },
      );
      const result = await toolPlatform.gateway.execute(context, {
        sessionToken: tenant.sessionToken,
        delegationId: tenant.delegations.TOOL_CALL.delegationId,
        correlationId,
        operationId: tool.binding.operationId,
        idempotencyKey: `${tool.effectKey}-execute`,
        confirmationId: confirmation.confirmationId,
        confirmationSha256: confirmation.confirmationSha256,
        expectedParamSha256: confirmation.normalizedParamSha256,
      });
      observed.c16 = { authorization, confirmation, result };
    }
    if (!observed.c14) {
      const draft = record("DRAFT");
      const routed = await modelPlatform.gateway.route(
        g1ServerContext(tenant),
        {
          sessionToken: tenant.sessionToken,
          delegationId: tenant.delegations.MANAGE.delegationId,
          idempotencyKey:
            `g1-c12-draft-${draft.effectKey.slice(7, 39)}`,
          correlationId:
            `g1-c12-draft-${draft.effectKey.slice(7, 23)}`,
          taskRef: draft.binding.modelTaskRef,
          inputRef:
            `synthetic://g1/c12/draft/${taskState.taskId}`,
          inputSha256: draft.binding.contextSha256,
        },
      );
      observed.c14 = routed.route;
    }
    if (!observed.c14Review) {
      const review = record("INDEPENDENT_REVIEW");
      const routed = await modelPlatform.reviewGateway.route(
        g1ServerContext(tenant),
        {
          sessionToken: tenant.sessionToken,
          delegationId: tenant.delegations.MANAGE.delegationId,
          idempotencyKey:
            `g1-c12-review-${review.effectKey.slice(7, 39)}`,
          correlationId:
            `g1-c12-review-${review.effectKey.slice(7, 23)}`,
          taskRef: "synthetic://c14/tasks/structured-analysis",
          inputRef:
            `synthetic://g1/c12/review/${taskState.taskId}`,
          inputSha256: review.binding.artifactSha256,
        },
      );
      observed.c14Review = routed.route;
    }
    if (!observed.c15) {
      await createHumanDecision(
        tenant,
        task,
        taskState,
        observed,
      );
    }
  }

  return {
    catalogDocument,
    async run(tenant) {
      const task = catalogDocument.tasks.find(
        (value) => value.tenantId === tenant.tenantId,
      );
      const execution = instanceFor(tenant);
      const { orchestrator, observed } = execution;
      const context = g1ServerContext(tenant);
      if (execution.taskId) {
        const inspected = await orchestrator.inspect(context, {
          sessionToken: tenant.sessionToken,
          delegationId: tenant.delegations.READ.delegationId,
          correlationId:
            `g1-c12-inspect-${tenant.tenantId.slice(-3)}`,
          taskId: execution.taskId,
        });
        await rehydrateObserved(
          tenant,
          task,
          inspected,
          observed,
        );
        return { task: inspected, observed, replayed: true };
      }
      const envelope = {
        sessionToken: tenant.sessionToken,
        delegationId: tenant.delegations.MANAGE.delegationId,
      };
      let view = await orchestrator.start(context, {
        ...envelope,
        idempotencyKey: `g1-c12-start-${tenant.tenantId.slice(-3)}`,
        correlationId: `g1-c12-start-${tenant.tenantId.slice(-3)}`,
        taskRef: task.taskRef,
        inputRef: task.inputRef,
        inputSha256: task.inputSha256,
      });
      let step = 0;
      while (view.task.status === "RUNNING") {
        step += 1;
        view = await orchestrator.advance(context, {
          ...envelope,
          idempotencyKey:
            `g1-c12-advance-${tenant.tenantId.slice(-3)}-${step}`,
          correlationId:
            `g1-c12-advance-${tenant.tenantId.slice(-3)}-${step}`,
          taskId: view.task.taskId,
          expectedVersion: view.task.version,
        });
      }
      if (view.task.status !== "WAITING_FOR_HUMAN") {
        throw new Error("C12 did not reach its Human gate.");
      }
      const decision = await createHumanDecision(
        tenant,
        task,
        view.task,
        observed,
      );
      view = await orchestrator.resumeWithHumanDecision(context, {
        ...envelope,
        idempotencyKey:
          `g1-c12-resume-${tenant.tenantId.slice(-3)}`,
        correlationId:
          `g1-c12-resume-${tenant.tenantId.slice(-3)}`,
        taskId: view.task.taskId,
        expectedVersion: view.task.version,
        expectedStateSha256: view.task.stateSha256,
        decisionRef:
          `evidence://c15/decision/${decision.decisionId}`,
        decisionSha256: decision.decisionSha256,
      });
      view = await orchestrator.advance(context, {
        ...envelope,
        idempotencyKey:
          `g1-c12-complete-${tenant.tenantId.slice(-3)}`,
        correlationId:
          `g1-c12-complete-${tenant.tenantId.slice(-3)}`,
        taskId: view.task.taskId,
        expectedVersion: view.task.version,
      });
      execution.taskId = view.task.taskId;
      await rehydrateObserved(
        tenant,
        task,
        view.task,
        observed,
      );
      return {
        task: view.task,
        observed,
        replayed: view.replayed === true,
      };
    },
  };
}

function c08ReferenceCatalog(tenant, task) {
  const entries = new Set();
  const key = ({ kind, ref, version, sha256, asOf }) =>
    JSON.stringify([kind, ref, version, sha256, asOf]);
  const add = (entry) => entries.add(key(entry));
  add({
    kind: "GOAL",
    ref: "synthetic://g1/c08/goals/order-summary",
    version: null,
    sha256: null,
    asOf: null,
  });
  add({
    kind: "PURPOSE",
    ref: "policy://g1/c08/purpose/order-summary",
    version: null,
    sha256: null,
    asOf: null,
  });
  add({
    kind: "ARTIFACT_CONTENT",
    ref: task.inputRef,
    version: "1",
    sha256: task.inputSha256,
    asOf: null,
  });
  add({
    kind: "MODEL",
    ref: "synthetic://c14/models/local-secure",
    version: "1.0.0",
    sha256:
      "sha256:7d50c3c6467cde455d351fa158e3bdf841616ddf46f6f310321c4a54076a24c4",
    asOf: null,
  });
  const promptSha256 = c12Sha256({
    ref: "synthetic://g1/c13/prompts/order-summary",
    version: "1.0.0",
  });
  add({
    kind: "PROMPT",
    ref: "synthetic://g1/c13/prompts/order-summary",
    version: "1.0.0",
    sha256: promptSha256,
    asOf: null,
  });
  add({
    kind: "SKILL",
    ref: task.bindings.skill.ref,
    version: task.bindings.skill.version,
    sha256: task.bindings.skill.sha256,
    asOf: null,
  });
  add({
    kind: "KNOWLEDGE",
    ref: task.bindings.knowledge.ref,
    version: task.bindings.knowledge.version,
    sha256: task.bindings.knowledge.sha256,
    asOf: NOW,
  });
  add({
    kind: "TRACE",
    ref: `test://g1/c08/traces/${tenant.tenantId.slice(-3)}`,
    version: null,
    sha256: null,
    asOf: null,
  });
  add({
    kind: "TOOL_OPERATION",
    ref: "synthetic://c16/operations/synthetic.erp.order.get",
    version: task.bindings.tool.catalogVersion,
    sha256: null,
    asOf: null,
  });
  add({
    kind: "COMPENSATION",
    ref: "test://g1/c16/compensations/noop",
    version: null,
    sha256: null,
    asOf: null,
  });
  return {
    promptSha256,
    registerResult(ref, sha256) {
      add({
        kind: "ARTIFACT_CONTENT",
        ref,
        version: "1",
        sha256,
        asOf: null,
      });
    },
    verify(query) {
      if (!entries.has(key(query))) {
        const error = new Error("G1 C08 reference is not bound.");
        error.code = "SYNTHETIC_REFERENCE_UNVERIFIED";
        throw error;
      }
      return Object.freeze({ ...query });
    },
    authorizationResources(tenantId) {
      if (tenantId !== tenant.tenantId) {
        throw new Error("G1 C08 Tenant scope mismatch.");
      }
      return {
        READ: `${tenant.fixtureId}--read`,
        MANAGE: `${tenant.fixtureId}--manage`,
        TOOL_CALL: `${tenant.fixtureId}--tool-call`,
      };
    },
  };
}

async function startC08Run({
  tenant,
  task,
  identityPlatform,
  principalPlatform,
  authorizationPlatform,
  stateStore,
  receipts,
  idFactory,
}) {
  const references = c08ReferenceCatalog(tenant, task);
  const controlDecision = await authorizationPlatform.facade.decide(
    { ...g1ServerContext(tenant), surface: "MANAGE" },
    {
      sessionToken: tenant.sessionToken,
      delegationId: tenant.delegations.MANAGE.delegationId,
      resourceId: `${tenant.fixtureId}--manage`,
      correlationId: `g1-c08-control-${tenant.tenantId.slice(-3)}`,
    },
  );
  const core = createAiosStateCore({
    tenantRegistry: identityPlatform.tenantRegistry,
    stablePrincipalRegistry: principalPlatform.registry,
    authorizer: createC08C06Authorizer({
      authorizationFacade: authorizationPlatform.facade,
    }),
    store: stateStore,
    referenceCatalog: references,
    toolReceiptVerifier: receipts.verifier,
    controlAuthorize: async () => ({
      allowed: true,
      decisionId: controlDecision.decisionId,
      evidenceRef: controlDecision.evidenceRef,
      policyVersion: controlDecision.authorizationModelId,
    }),
    idFactory,
    clock: () => NOW,
  });
  const context = g1ServerContext(tenant);
  const execute = (idempotencyKey, command, surface = "MANAGE") =>
    core.execute(context, {
      sessionToken: tenant.sessionToken,
      delegationId: tenant.delegations[surface].delegationId,
      idempotencyKey,
      correlationId: `corr-${idempotencyKey}`,
      command,
    });
  const tenantSuffix = tenant.tenantId.slice(-3);
  const createdCase = await execute(`g1-c08-case-${tenantSuffix}`, {
    kind: "CREATE_CASE",
    goalRef: "synthetic://g1/c08/goals/order-summary",
  });
  const openedThread = await execute(`g1-c08-thread-${tenantSuffix}`, {
    kind: "OPEN_THREAD",
    caseId: createdCase.caseId,
    purposeRef: "policy://g1/c08/purpose/order-summary",
  });
  const inputArtifact = await execute(`g1-c08-input-${tenantSuffix}`, {
    kind: "RECORD_ARTIFACT_VERSION",
    artifactId: null,
    caseId: createdCase.caseId,
    threadId: openedThread.threadId,
    expectedArtifactVersion: 0,
    artifactKind: "INPUT",
    contentRef: task.inputRef,
    contentSha256: task.inputSha256,
  });
  const started = await execute(`g1-c08-start-${tenantSuffix}`, {
    kind: "START_RUN",
    threadId: openedThread.threadId,
    manifest: {
      inputArtifact: {
        artifactId: inputArtifact.artifactId,
        artifactVersion: inputArtifact.artifactVersion,
        contentSha256: inputArtifact.contentSha256,
      },
      model: {
        ref: "synthetic://c14/models/local-secure",
        version: "1.0.0",
        sha256:
          "sha256:7d50c3c6467cde455d351fa158e3bdf841616ddf46f6f310321c4a54076a24c4",
      },
      prompt: {
        ref: "synthetic://g1/c13/prompts/order-summary",
        version: "1.0.0",
        sha256: references.promptSha256,
      },
      skill: {
        ref: task.bindings.skill.ref,
        version: task.bindings.skill.version,
        sha256: task.bindings.skill.sha256,
      },
      knowledge: [
        {
          evidenceRef: task.bindings.knowledge.ref,
          version: task.bindings.knowledge.version,
          asOf: NOW,
          sha256: task.bindings.knowledge.sha256,
        },
      ],
      traceRef: `test://g1/c08/traces/${tenantSuffix}`,
    },
  });
  const prepared = await execute(
    `g1-c08-prepare-tool-${tenantSuffix}`,
    {
      kind: "PREPARE_TOOL_CALL",
      runId: started.runId,
      expectedRunVersion: 1,
      operationRef:
        "synthetic://c16/operations/synthetic.erp.order.get",
      operationVersion: task.bindings.tool.catalogVersion,
      requestHash: task.toolInvocation.parameterSha256,
      compensationRef: "test://g1/c16/compensations/noop",
    },
    "TOOL_CALL",
  );
  return {
    core,
    receipts,
    references,
    context,
    execute,
    createdCase,
    openedThread,
    started,
    prepared,
    initialReplayed: [
      createdCase,
      openedThread,
      inputArtifact,
      started,
      prepared,
    ].every((result) => result.duplicate === true),
  };
}

async function finishC08Run(state, tenant, c12Result) {
  const tenantSuffix = tenant.tenantId.slice(-3);
  const accepted = await state.receipts.executor.accept({
    tenantId: tenant.tenantId,
    runId: state.started.runId,
    toolCallId: state.prepared.toolCallId,
    effectKey: state.prepared.effectKey,
    requestHash: state.prepared.requestHash,
    operationRef:
      "synthetic://c16/operations/synthetic.erp.order.get",
    operationVersion:
      c12Result.task.bindings.tool.catalogVersion,
    outcome: "SUCCEEDED",
  });
  const recordedToolResult = await state.core.recordToolCallResult(
    {
      synthetic: true,
      routeTrustSource: "VERIFIED_TOOL_RESULT_ROUTE_DESCRIPTOR",
      tenantId: tenant.tenantId,
      workerTrustSource: "VERIFIED_C0_MOCK_TOOL_WORKER",
      workerPrincipalId: tenant.actor.principalId,
    },
    {
      idempotencyKey: `g1-c08-tool-result-${tenantSuffix}`,
      correlationId: `g1-c08-tool-result-${tenantSuffix}`,
      command: {
        kind: "RECORD_TOOL_CALL_RESULT",
        runId: state.started.runId,
        expectedRunVersion: 2,
        toolCallId: state.prepared.toolCallId,
        expectedToolCallVersion: 1,
        receiptId: accepted.receiptId,
      },
    },
  );
  const resultRef =
    `synthetic://g1/c12/results/${c12Result.task.taskId}`;
  state.references.registerResult(
    resultRef,
    c12Result.task.stateSha256,
  );
  const resultArtifact = await state.execute(
    `g1-c08-result-${tenantSuffix}`,
    {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: state.createdCase.caseId,
      threadId: state.openedThread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "RESULT",
      contentRef: resultRef,
      contentSha256: c12Result.task.stateSha256,
    },
  );
  const finished = await state.execute(`g1-c08-finish-${tenantSuffix}`, {
    kind: "FINISH_RUN",
    runId: state.started.runId,
    expectedRunVersion: 3,
    outcome: "SUCCEEDED",
    resultArtifact: {
      artifactId: resultArtifact.artifactId,
      artifactVersion: resultArtifact.artifactVersion,
      contentSha256: resultArtifact.contentSha256,
    },
  });
  const reconstructed = await state.core.reconstructRun(
    state.context,
    {
      sessionToken: tenant.sessionToken,
      delegationId: tenant.delegations.READ.delegationId,
      correlationId: `g1-c08-reconstruct-${tenantSuffix}`,
      runId: state.started.runId,
    },
  );
  const inspected = await state.core.inspectRun(state.context, {
    sessionToken: tenant.sessionToken,
    delegationId: tenant.delegations.READ.delegationId,
    correlationId: `g1-c08-inspect-${tenantSuffix}`,
    runId: state.started.runId,
  });
  return {
    reconstructed,
    inspected,
    resultArtifact,
    replayed:
      state.initialReplayed &&
      accepted.duplicate === true &&
      recordedToolResult.duplicate === true &&
      resultArtifact.duplicate === true &&
      finished.duplicate === true,
  };
}

async function readC08Run(state, tenant) {
  const tenantSuffix = tenant.tenantId.slice(-3);
  const reconstructed = await state.core.reconstructRun(
    state.context,
    {
      sessionToken: tenant.sessionToken,
      delegationId: tenant.delegations.READ.delegationId,
      correlationId: `g1-c08-reconstruct-replay-${tenantSuffix}`,
      runId: state.started.runId,
    },
  );
  const inspected = await state.core.inspectRun(state.context, {
    sessionToken: tenant.sessionToken,
    delegationId: tenant.delegations.READ.delegationId,
    correlationId: `g1-c08-inspect-replay-${tenantSuffix}`,
    runId: state.started.runId,
  });
  if (!state.completedResult?.resultArtifact) {
    throw new Error("G1 C08 completed result is unavailable.");
  }
  return {
    reconstructed,
    inspected,
    resultArtifact: state.completedResult.resultArtifact,
    replayed: true,
  };
}

function createAuditPlatform(
  identityPlatform,
  principalPlatform,
  store,
) {
  const bundles = new Map();
  const catalog = {
    resolve(tenantId, bundleRef) {
      const value = bundles.get(`${tenantId}|${bundleRef}`);
      if (!value) throw new Error("G1 C18 bundle is not registered.");
      return structuredClone(value);
    },
    resolveIdentityArtifact(tenantId, artifact) {
      if (artifact.tenantId !== tenantId) {
        throw new Error("G1 C18 identity escaped Tenant scope.");
      }
      return {
        tenantId,
        evidenceType: "IDENTITY",
        evidenceRef:
          `evidence://c05/action-identities/${tenantId}`,
        version: "c18-action-identity-artifact-v1",
        sha256: auditEvidenceSha256(artifact),
        artifact: structuredClone(artifact),
      };
    },
  };
  const service = createAuditEvidenceService({
    tenantRegistry: identityPlatform.tenantRegistry,
    stablePrincipalRegistry: {
      resolveActionIdentity(context, request) {
        return principalPlatform.registry.resolveActionIdentity(
          {
            synthetic: true,
            workloadTrustSource: context.workloadTrustSource,
            workloadActorPrincipalId:
              context.workloadActorPrincipalId,
          },
          request,
        );
      },
    },
    catalog,
    store,
    tenantScopeFactory({ tenant, authorization, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: tenant.tenantKind,
        lifecycleVersion: tenant.lifecycleVersion,
        correlationId,
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.version,
      };
    },
    clock: () => NOW,
    idFactory: uuidFactory("9000"),
  });

  return {
    async append({
      tenant,
      decision,
      c12Result,
      c08Result,
    }) {
      const task = c12Result.task;
      const observed = c12Result.observed;
      const bundleRef =
        `fixture://g1/c18/bundles/${tenant.tenantId.slice(-3)}`;
      const bundle = {
        bundleRef,
        auditType: "AIOS_ACTION_COMPLETED",
        summaryCode: "G1_SYNTHETIC_CHAIN_COMPLETED",
        retentionClass: "AUDIT_7Y",
        authorization: {
          decisionId: decision.decisionId,
          evidenceRef: decision.evidenceRef,
          version: decision.authorizationModelId,
          sha256: auditEvidenceSha256(decision),
        },
        model: {
          evidenceRef:
            `evidence://c14/routes/${observed.c14.routeId}`,
          version: observed.c14.catalogVersion,
          sha256: auditEvidenceSha256(observed.c14),
        },
        knowledge: [
          {
            evidenceRef:
              `evidence://c11/results/${task.taskId}`,
            version: "c11-runtime-v1",
            sha256: c11Sha256(observed.c11),
          },
        ],
        skill: {
          evidenceRef: task.bindings.skill.ref,
          version: task.bindings.skill.version,
          sha256: task.bindings.skill.sha256,
        },
        tool: {
          evidenceRef:
            `evidence://c16/receipts/${observed.c16.result.receipt.receiptSha256.slice(7)}`,
          version: task.bindings.tool.catalogVersion,
          sha256: observed.c16.result.receipt.receiptSha256,
        },
        humanDecision: {
          evidenceRef:
            `evidence://c15/decisions/${observed.c15.decisionId}`,
          version: "c15-synthetic-test-decision-v1",
          sha256: observed.c15.decisionSha256,
        },
        result: {
          evidenceRef:
            `evidence://c12/results/${task.taskId}`,
          version: task.graphVersion,
          sha256: task.stateSha256,
        },
        c08State: {
          evidenceRef:
            `evidence://c08/runs/${c08Result.reconstructed.runId}`,
          version: String(c08Result.reconstructed.version),
          sha256: c08Result.reconstructed.reconstructionHash,
        },
      };
      bundles.set(`${tenant.tenantId}|${bundleRef}`, bundle);
      const correlationId =
        `g1-c18-${tenant.tenantId.slice(-3)}`;
      const idempotencyKey =
        `g1-c18-append-${tenant.tenantId.slice(-3)}`;
      const admission =
        await identityPlatform.tenantRegistry.admitNewRequest({
          tenantId: tenant.tenantId,
          expectedTenantKind: "SYNTHETIC",
        });
      const scope = {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: admission.lifecycleVersion,
        correlationId,
        decisionId: bundle.authorization.decisionId,
        evidenceRef: bundle.authorization.evidenceRef,
        policyVersion: bundle.authorization.version,
      };
      const priorExport = await store.exportChain(scope);
      const priorReceipt = priorExport.receipts.find(
        (receipt) => receipt.idempotencyKey === idempotencyKey,
      );
      if (priorReceipt) {
        const record = priorExport.events.find(
          (event) => event.eventId === priorReceipt.eventId,
        );
        if (!record) {
          throw new Error("G1 C18 replay receipt is incomplete.");
        }
        return {
          appended: {
            tenantId: record.tenantId,
            tenantKind: "SYNTHETIC",
            eventId: record.eventId,
            sequence: record.sequence,
            previousEventHash: record.previousEventHash,
            eventHash: record.eventHash,
            payloadSha256: record.payloadSha256,
            provenanceSha256:
              record.payload.provenanceSha256,
            auditType: record.payload.auditType,
            retentionClass: record.payload.retentionClass,
            createdAt: record.createdAt,
            duplicate: true,
          },
          verification: verifyAuditExport(priorExport),
        };
      }
      const appended = await service.append(
        g1ServerContext(tenant),
        {
          sessionToken: tenant.sessionToken,
          delegationId: tenant.delegations.MANAGE.delegationId,
          idempotencyKey,
          correlationId,
          evidenceBundleRef: bundleRef,
        },
      );
      const exported = await store.exportChain(scope);
      return {
        appended,
        verification: verifyAuditExport(exported),
      };
    },
  };
}

function createObservabilityPlatform(identityPlatform, store) {
  const tenantConfigs = new Map();
  const plans = new Map();
  const receipts = new Map();
  const catalog = {
    catalogVersion: "g1-c19-runtime-v1",
    catalogSha256: observabilitySha256({
      schemaVersion: "g1-c19-runtime-catalog.v1",
      tenants: G1_SYNTHETIC_TENANT_IDS,
    }),
    resolveTelemetryOperation(operation) {
      const moduleId = {
        "c14.model.route": "C14",
        "c16.tool.execute": "C16",
        "c18.audit.append": "C18",
        "c19.usage.settle": "C19",
      }[operation];
      if (!moduleId) throw new Error("Unknown G1 telemetry operation.");
      return { operation, module: moduleId };
    },
    resolveTenant(tenantId) {
      const config = tenantConfigs.get(tenantId);
      if (!config) throw new Error("G1 C19 Tenant is not registered.");
      return structuredClone(config);
    },
    resolvePrincipalQuota(tenantId, principalId) {
      const config = tenantConfigs.get(tenantId);
      if (config?.principalId !== principalId) {
        throw new Error("G1 C19 Principal is not registered.");
      }
      return {
        principalId,
        quotaLimitMicros: 1_000_000,
        quotaThresholdBasisPoints: 9000,
      };
    },
    resolvePlan(tenantId, planRef) {
      const value = plans.get(`${tenantId}|${planRef}`);
      if (!value) throw new Error("G1 C19 plan is not registered.");
      return structuredClone(value);
    },
    resolveReceipt(tenantId, receiptRef) {
      const value = receipts.get(`${tenantId}|${receiptRef}`);
      if (!value) throw new Error("G1 C19 receipt is not registered.");
      return structuredClone(value);
    },
  };
  let span = 0x2000000000000000n;
  const service = createObservabilityService({
    tenantRegistry: identityPlatform.tenantRegistry,
    catalog,
    store,
    tenantScopeFactory({ tenant, scopeEvidence, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: tenant.tenantKind,
        lifecycleVersion: tenant.lifecycleVersion,
        correlationId,
        decisionId: scopeEvidence.decisionId,
        evidenceRef: scopeEvidence.evidenceRef,
        policyVersion: scopeEvidence.policyVersion,
      };
    },
    principalResolver: {
      async resolveActionIdentity({ tenantId, identityContextRef }) {
        const tenant = identityPlatform.tenantStates.find(
          (value) => value.tenantId === tenantId,
        );
        if (
          !tenant ||
          identityContextRef !==
            `fixture://g1/c19/identity/${tenantId.slice(-3)}`
        ) {
          throw new Error("G1 C19 identity context is untrusted.");
        }
        return tenant.actionIdentity;
      },
    },
    clock: () => NOW,
    idFactory: uuidFactory("a000"),
    spanIdFactory: () => {
      span += 1n;
      return span.toString(16);
    },
  });

  return {
    async record({
      tenant,
      c12Result,
      c18Result,
    }) {
      const suffix = tenant.tenantId.slice(-3);
      const c19TaskRef =
        `tsk_01985000-a100-7000-8000-${String(
          identityPlatform.tenantStates.indexOf(tenant) + 1,
        ).padStart(12, "0")}`;
      const identityContextRef =
        `fixture://g1/c19/identity/${suffix}`;
      tenantConfigs.set(tenant.tenantId, {
        fixtureId: tenant.fixtureId,
        quotaPeriod: "2026-07",
        quotaLimitMicros: 1_000_000,
        quotaThresholdBasisPoints: 9000,
        principalId: tenant.human.principalId,
        scopeEvidence: {
          decisionId: c18Result.appended.eventId,
          evidenceRef:
            `fixture://g1/c18/audit/${suffix}`,
          policyVersion: "g1-c19-policy-v1",
        },
      });
      const modelPlanRef =
        `fixture://g1/c19/${suffix}/plans/model`;
      const toolPlanRef =
        `fixture://g1/c19/${suffix}/plans/tool`;
      const modelReceiptRef =
        `fixture://g1/c19/${suffix}/receipts/model`;
      const toolReceiptRef =
        `fixture://g1/c19/${suffix}/receipts/tool`;
      const modelUsage = c12Result.observed.c14.usage;
      const modelPlan = {
        planRef: modelPlanRef,
        taskRef: c19TaskRef,
        dimensionType: "MODEL",
        resourceRef: "model://g1/local-secure/v1",
        meterType: "MODEL_TOKEN",
        unit: "TOKEN",
        maxQuantity: modelUsage.totalTokens,
        rateVersion: "g1-rates-2026-07-v1",
        unitRateMicros: 1,
        reservedCostMicros: modelUsage.totalTokens,
        sourceModule: "C14",
        sourceEvidenceRef: "model://g1/c14/route/v1",
        sourceEvidenceSha256:
          auditEvidenceSha256(c12Result.observed.c14),
        auditEvidenceRef: `fixture://g1/c18/audit/${suffix}`,
        auditEvidenceSha256: c18Result.appended.eventHash,
      };
      const toolPlan = {
        planRef: toolPlanRef,
        taskRef: c19TaskRef,
        dimensionType: "TOOL",
        resourceRef: "tool://g1/c16/order-get/v1",
        meterType: "TOOL_CALL",
        unit: "CALL",
        maxQuantity: 1,
        rateVersion: "g1-rates-2026-07-v1",
        unitRateMicros: 1,
        reservedCostMicros: 1,
        sourceModule: "C16",
        sourceEvidenceRef: "tool://g1/c16/order-get/v1",
        sourceEvidenceSha256:
          c12Result.observed.c16.result.receipt.receiptSha256,
        auditEvidenceRef: `fixture://g1/c18/audit/${suffix}`,
        auditEvidenceSha256: c18Result.appended.eventHash,
      };
      plans.set(`${tenant.tenantId}|${modelPlanRef}`, modelPlan);
      plans.set(`${tenant.tenantId}|${toolPlanRef}`, toolPlan);
      receipts.set(`${tenant.tenantId}|${modelReceiptRef}`, {
        receiptRef: modelReceiptRef,
        planRef: modelPlanRef,
        meterKey: `meter-g1-${suffix}-model`,
        quantity: modelUsage.totalTokens,
        bookedCostMicros: modelUsage.totalTokens,
        supplierCostMicros:
          c12Result.observed.c14.costMicrousd,
        occurredAt: NOW,
      });
      receipts.set(`${tenant.tenantId}|${toolReceiptRef}`, {
        receiptRef: toolReceiptRef,
        planRef: toolPlanRef,
        meterKey: `meter-g1-${suffix}-tool`,
        quantity: 1,
        bookedCostMicros: 1,
        supplierCostMicros: 0,
        occurredAt: NOW,
      });
      const serverContext = {
        synthetic: true,
        routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
        tenantId: tenant.tenantId,
        identityContextRef,
      };
      const traceId = observabilitySha256({
        tenantId: tenant.tenantId,
        taskId: c12Result.task.taskId,
      }).slice(7, 39);
      let traceContext = {
        traceparent:
          `00-${traceId}-1000000000000001-01`,
        tracestate: "g1=synthetic",
      };
      const duplicateEvidence = [];
      for (const [index, [signalType, operation, durationMs]] of [
        ["TRACE", "c14.model.route", 8],
        ["SPAN", "c16.tool.execute", 13],
        ["SPAN", "c18.audit.append", 5],
        ["LOG", "c19.usage.settle", null],
      ].entries()) {
        const result = await service.recordSignal(serverContext, {
          idempotencyKey: `g1-c19-signal-${suffix}-${index}`,
          traceparent: traceContext.traceparent,
          tracestate: traceContext.tracestate,
          signalType,
          operation,
          taskRef: c19TaskRef,
          status: "OK",
          durationMs,
          errorCode: null,
        });
        duplicateEvidence.push(result.duplicate === true);
        traceContext = result.traceContext;
      }
      const modelReservation = await service.reserve(serverContext, {
        idempotencyKey: `g1-c19-reserve-${suffix}-model`,
        planRef: modelPlanRef,
        traceparent: traceContext.traceparent,
        tracestate: traceContext.tracestate,
      });
      duplicateEvidence.push(modelReservation.duplicate === true);
      traceContext = modelReservation.traceContext;
      const toolReservation = await service.reserve(serverContext, {
        idempotencyKey: `g1-c19-reserve-${suffix}-tool`,
        planRef: toolPlanRef,
        traceparent: traceContext.traceparent,
        tracestate: traceContext.tracestate,
      });
      duplicateEvidence.push(toolReservation.duplicate === true);
      traceContext = toolReservation.traceContext;
      const modelSettlement = await service.settle(serverContext, {
        idempotencyKey: `g1-c19-settle-${suffix}-model`,
        reservationId:
          modelReservation.reservation.reservationId,
        receiptRef: modelReceiptRef,
        traceparent: traceContext.traceparent,
        tracestate: traceContext.tracestate,
      });
      duplicateEvidence.push(modelSettlement.duplicate === true);
      traceContext = modelSettlement.traceContext;
      const toolSettlement = await service.settle(serverContext, {
        idempotencyKey: `g1-c19-settle-${suffix}-tool`,
        reservationId:
          toolReservation.reservation.reservationId,
        receiptRef: toolReceiptRef,
        traceparent: traceContext.traceparent,
        tracestate: traceContext.tracestate,
      });
      duplicateEvidence.push(toolSettlement.duplicate === true);
      const telemetry = await service.telemetryReport(
        serverContext,
        {
          fromOccurredAt: "2026-07-26T00:00:00.000Z",
          toOccurredAt: "2026-07-27T00:00:00.000Z",
        },
      );
      const cost = await service.costVarianceReport(
        serverContext,
        {
          fromOccurredAt: "2026-07-26T00:00:00.000Z",
          toOccurredAt: "2026-07-27T00:00:00.000Z",
        },
      );
      const result = {
        c19TaskRef,
        traceId:
          parseTraceContext(toolSettlement.traceContext).traceId,
        modelSettlement,
        toolSettlement,
        telemetry,
        cost,
      };
      return {
        ...result,
        replayed: duplicateEvidence.every(Boolean),
      };
    },
  };
}

function deploymentView(tenantStates) {
  return Object.freeze({
    tenants: tenantStates.map((tenant) => {
      const users = tenant.f02.records.users.map((user, index) =>
        Object.freeze({
          id: user.id,
          fixtureUserId: tenant.sessions[index].fixtureUserId,
          role: user.role,
          accountId: tenant.sessions[index].accountId,
          profileRef: tenant.sessions[index].profileRef,
          sessionId: tenant.sessions[index].sessionId,
          trustSource: tenant.sessions[index].trustSource,
          principalId:
            tenant.userBindings[index].human.principalId,
          delegationIds: Object.freeze(
            Object.fromEntries(
              Object.entries(
                tenant.userBindings[index].delegations,
              ).map(([surface, delegation]) => [
                surface,
                delegation.delegationId,
              ]),
            ),
          ),
        }),
      );
      return Object.freeze({
        tenantId: tenant.tenantId,
        tenantKind: "SYNTHETIC",
        users,
        roles: users.map(({ role }) => Object.freeze({ role })),
        chainActorLogin: Object.freeze({ ...tenant.login }),
      });
    }),
  });
}

export async function createG1SyntheticRuntime(options) {
  let identityInstancePrefix = "1000";
  let identitySecretPrefix = "";
  let authorizationIdPrefix = "3000";
  let toolClock = () => NOW;
  let storage;
  if (options === undefined) {
    storage = validateStorage(createMemoryG1Storage());
  } else {
    exactObject(
      options,
      ["storage", "identityInstancePrefix"],
      "G1 runtime options",
    );
    if (
      typeof options.identityInstancePrefix !== "string" ||
      !/^[0-9a-f]{4}$/.test(options.identityInstancePrefix)
    ) {
      failStorageConfiguration(
        "identityInstancePrefix must be four lowercase hex characters.",
      );
    }
    identityInstancePrefix = options.identityInstancePrefix;
    identitySecretPrefix = identityInstancePrefix;
    authorizationIdPrefix = identityInstancePrefix;
    toolClock = () => new Date().toISOString();
    storage = validateStorage(options.storage);
  }
  const identityPlatform = await createIdentityPlatform({
    tenantStore: storage.tenantStore,
    tenantDataAdapter: storage.tenantDataAdapter,
    identityStore: storage.identityStore,
    identityInstancePrefix,
    identitySecretPrefix,
  });
  const c12StatePort = validateC12StatePort(
    storage.c12StatePortFactory(identityPlatform.tenantRegistry),
  );
  const principalPlatform = await createPrincipalPlatform(
    identityPlatform,
    storage.principalStore,
  );
  const authorizationPlatform = await createAuthorizationPlatform(
    identityPlatform,
    principalPlatform,
    storage.authorizationStore,
    authorizationIdPrefix,
  );
  const knowledgePlatform = await createKnowledgePlatform(
    identityPlatform,
    authorizationPlatform,
    storage,
  );
  const modelPlatform = await createModelPlatform(
    identityPlatform,
    principalPlatform,
    authorizationPlatform,
    storage,
  );
  const toolPlatform = await createToolPlatform(
    identityPlatform,
    principalPlatform,
    authorizationPlatform,
    storage.toolStore,
    toolClock,
  );
  const decisionPlatform = await createDecisionPlatform(
    identityPlatform,
    principalPlatform,
    authorizationPlatform,
    storage.decisionStore,
  );
  const orchestrationPlatform = await createOrchestrationPlatform({
    identityPlatform,
    authorizationPlatform,
    knowledgePlatform,
    modelPlatform,
    toolPlatform,
    decisionPlatform,
    statePort: c12StatePort,
  });
  const auditPlatform = createAuditPlatform(
    identityPlatform,
    principalPlatform,
    storage.auditStore,
  );
  const observabilityPlatform = createObservabilityPlatform(
    identityPlatform,
    storage.observabilityStore,
  );
  const c08Runs = new Map();
  const c08IdFactory = uuidFactory("8000");
  return Object.freeze({
    async deploy() {
      return deploymentView(identityPlatform.tenantStates);
    },
    async verifySessionIsolation(input) {
      const expected = ["sourceTenantId", "targetTenantId"];
      if (
        !input ||
        Object.keys(input).length !== expected.length ||
        Object.keys(input).some((key) => !expected.includes(key))
      ) {
        throw new Error("Invalid G1 session isolation probe.");
      }
      const source = identityPlatform.tenantStates.find(
        (value) => value.tenantId === input.sourceTenantId,
      );
      if (!source) throw new Error("Unknown G1 source Tenant.");
      return identityPlatform.identityFederation.resolveSession(
        PORTAL_CONTEXT,
        {
          sessionToken: source.sessionToken,
          expectedTenantId: input.targetTenantId,
        },
      );
    },
    registerRoleBoundResource(input) {
      const expected = [
        "tenantId",
        "ownerFixtureUserId",
        "surface",
        "resourceId",
      ];
      if (
        !input ||
        Object.keys(input).length !== expected.length ||
        Object.keys(input).some((key) => !expected.includes(key))
      ) {
        throw new Error("Invalid G1 role-bound registration.");
      }
      const {
        tenantId,
        ownerFixtureUserId,
        surface,
        resourceId,
      } = input;
      const tenant = identityPlatform.tenantStates.find(
        (value) => value.tenantId === tenantId,
      );
      const owner = tenant?.userBindings.find(
        (value) =>
          value.fixtureUserId === ownerFixtureUserId,
      );
      if (!tenant || !owner || !owner.delegations[surface]) {
        throw new Error("Unknown G1 role-bound registration input.");
      }
      const registered =
        authorizationPlatform.registerRoleBoundResource({
          tenantId,
          surface,
          resourceId,
          ownerPrincipalId: owner.human.principalId,
        });
      return Object.freeze({
        tenantId: registered.tenantId,
        surface: registered.surface,
        resourceId: registered.resourceId,
        owner: Object.freeze({
          fixtureUserId: owner.fixtureUserId,
          f02UserId: owner.f02UserId,
          role: owner.role,
          principalId: owner.human.principalId,
        }),
      });
    },
    async authorizeRoleBoundResource(input) {
      const expected = [
        "targetTenantId",
        "callerTenantId",
        "callerFixtureUserId",
        "surface",
        "resourceId",
      ];
      if (
        !input ||
        Object.keys(input).length !== expected.length ||
        Object.keys(input).some((key) => !expected.includes(key))
      ) {
        throw new Error("Invalid G1 role-bound authorization.");
      }
      const {
        targetTenantId,
        callerTenantId,
        callerFixtureUserId,
        surface,
        resourceId,
      } = input;
      const targetTenant = identityPlatform.tenantStates.find(
        (value) => value.tenantId === targetTenantId,
      );
      const callerTenant = identityPlatform.tenantStates.find(
        (value) => value.tenantId === callerTenantId,
      );
      const caller = callerTenant?.userBindings.find(
        (value) =>
          value.fixtureUserId === callerFixtureUserId,
      );
      const binding =
        authorizationPlatform.resolveRoleBoundResource({
          tenantId: targetTenantId,
          surface,
          resourceId,
        });
      const owner = targetTenant?.userBindings.find(
        (value) =>
          value.human.principalId === binding?.ownerPrincipalId,
      );
      if (
        !targetTenant ||
        !callerTenant ||
        !caller ||
        !owner ||
        !caller.delegations[surface]
      ) {
        throw new Error("Unknown G1 role-bound authorization input.");
      }
      let decision;
      try {
        decision = await authorizationPlatform.facade.decide(
          {
            ...g1ServerContext(targetTenant),
            surface,
          },
          {
            sessionToken: caller.sessionToken,
            delegationId:
              caller.delegations[surface].delegationId,
            resourceId,
            correlationId:
              `g1-role-bound-${surface.toLowerCase()}-${caller.fixtureUserId}`,
          },
        );
      } catch (error) {
        if (callerTenantId !== targetTenantId) {
          const denied = new Error(
            "Cross-Tenant authorization is denied.",
          );
          denied.code = "CROSS_TENANT_DENIED";
          throw denied;
        }
        throw error;
      }
      return Object.freeze({
        decision,
        caller: Object.freeze({
          fixtureUserId: caller.fixtureUserId,
          f02UserId: caller.f02UserId,
          role: caller.role,
          principalId: caller.human.principalId,
          delegationId:
            caller.delegations[surface].delegationId,
        }),
        owner: Object.freeze({
          fixtureUserId: owner.fixtureUserId,
          f02UserId: owner.f02UserId,
          role: owner.role,
          principalId: owner.human.principalId,
        }),
      });
    },
    async runTenant(tenantId) {
      const tenant = identityPlatform.tenantStates.find(
        (value) => value.tenantId === tenantId,
      );
      if (!tenant) throw new Error("Unknown G1 Synthetic Tenant.");
      const task = orchestrationPlatform.catalogDocument.tasks.find(
        (value) => value.tenantId === tenantId,
      );
      let c08State = c08Runs.get(tenantId);
      const replayingC08 = Boolean(c08State);
      if (!c08State) {
        c08State = await startC08Run({
          tenant,
          task,
          identityPlatform,
          principalPlatform,
          authorizationPlatform,
          stateStore: storage.c08StateStore,
          receipts: storage.c08Receipts,
          idFactory: c08IdFactory,
        });
        c08Runs.set(tenantId, c08State);
      }
      const c12Result = await orchestrationPlatform.run(tenant);
      const c08Result = replayingC08
        ? await readC08Run(c08State, tenant)
        : await finishC08Run(c08State, tenant, c12Result);
      if (!replayingC08) c08State.completedResult = c08Result;
      const decision = await authorizationPlatform.facade.decide(
        {
          synthetic: true,
          routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
          tenantId,
          surface: "MANAGE",
          workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
          workloadActorPrincipalId: tenant.actor.principalId,
        },
        {
          sessionToken: tenant.sessionToken,
          delegationId: tenant.delegations.MANAGE.delegationId,
          resourceId: `${tenant.fixtureId}--manage`,
          correlationId: `g1-run-${tenantId}`,
        },
      );
      const retrieval = c12Result.observed.c11;
      const modelRoute = c12Result.observed.c14;
      const toolResult = c12Result.observed.c16.result;
      const humanDecision = c12Result.observed.c15;
      const c18Result = await auditPlatform.append({
        tenant,
        decision,
        c12Result,
        c08Result,
      });
      const c19Result = await observabilityPlatform.record({
        tenant,
        c12Result,
        c18Result,
      });
      return Object.freeze({
        tenantId,
        modules: Object.freeze({
          C05: Object.freeze({
            trustSource: tenant.actionIdentity.trustSource,
            humanPrincipalId:
              tenant.actionIdentity.humanSubject.principalId,
            workloadActorPrincipalId:
              tenant.actionIdentity.workloadActor.principalId,
          }),
          C06: Object.freeze({
            effect: decision.effect,
            authorizationStatus: decision.authorizationStatus,
            surface: decision.surface,
            decisionId: decision.decisionId,
          }),
          C11: Object.freeze({
            status: retrieval.status,
            evidenceCount: retrieval.evidence.length,
            resultSha256: c11Sha256(retrieval),
          }),
          C14: Object.freeze({
            status: modelRoute.status,
            modelRef: modelRoute.selectedModel.modelRef,
            responseSha256: modelRoute.responseSha256,
          }),
          C16: Object.freeze({
            status: toolResult.status,
            networkRequestCount: toolResult.receipt.networkRequestCount,
            externalEffectCount: toolResult.receipt.externalEffectCount,
            receiptSha256: toolResult.receipt.receiptSha256,
            adapterNewExecutionCount:
              toolPlatform.adapter.snapshot().newExecutionCount,
          }),
          C15: Object.freeze({
            decisionType: humanDecision.decisionType,
            outcome: humanDecision.outcome,
            externalEffectCount: humanDecision.externalEffectCount,
            decisionSha256: humanDecision.decisionSha256,
            effectExecuted: false,
          }),
          C12: Object.freeze({
            status: c12Result.task.status,
            taskId: c12Result.task.taskId,
            stateSha256: c12Result.task.stateSha256,
            nodeOrder: c12Result.task.nodeRecords.map(
              ({ nodeId }) => nodeId,
            ),
            nodeCount: c12Result.task.nodeRecords.length,
            toolExternalEffectCount:
              c12Result.observed.c16.result.receipt.externalEffectCount,
            humanDecisionProductionReusable:
              c12Result.task.humanDecision.productionReusable,
            replayed: c12Result.replayed,
          }),
          C08: Object.freeze({
            runId: c08Result.reconstructed.runId,
            state: c08Result.reconstructed.state,
            recoveryStatus: c08Result.inspected.recoveryStatus,
            reconstructionHash:
              c08Result.reconstructed.reconstructionHash,
            resultContentSha256:
              c08Result.resultArtifact.contentSha256,
            replayed: c08Result.replayed,
          }),
          C18: Object.freeze({
            sequence: c18Result.appended.sequence,
            eventHash: c18Result.appended.eventHash,
            eventCount: c18Result.verification.eventCount,
            chainVerified:
              c18Result.verification.headEventHash ===
              c18Result.appended.eventHash,
            replayed: c18Result.appended.duplicate === true,
          }),
          C19: Object.freeze({
            c12TaskId: c12Result.task.taskId,
            taskRef: c19Result.c19TaskRef,
            traceId: c19Result.traceId,
            totalSignals:
              c19Result.telemetry.sli.totalSignals,
            traceCount: c19Result.telemetry.traceCount,
            modelSettlementState:
              c19Result.modelSettlement.settlement.state,
            toolSettlementState:
              c19Result.toolSettlement.settlement.state,
            bookedCostMicros:
              c19Result.cost.totals.bookedCostMicros,
            supplierCostMicros:
              c19Result.cost.totals.supplierCostMicros,
            replayed: c19Result.replayed,
          }),
        }),
      });
    },
  });
}
