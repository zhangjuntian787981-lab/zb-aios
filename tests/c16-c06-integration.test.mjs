import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  buildSyntheticPolicyTuples,
  createAuthorizationFacade,
  createMemoryAuthorizationStore,
  createSyntheticAuthorizationCatalog,
  hashSyntheticPolicyTuples,
} from "../lib/authorization-facade.mjs";
import {
  createC16C06Authorizer,
} from "../lib/c16-c06-authorizer.mjs";
import {
  createC16EphemeralCredentialBroker,
} from "../lib/c16-ephemeral-credential-broker.mjs";
import {
  createC16SyntheticToolAdapter,
} from "../lib/c16-synthetic-tool-adapter.mjs";
import {
  ToolGatewayError,
  createMemoryToolGatewayStore,
  createSyntheticToolCatalog,
  createToolGateway,
} from "../lib/tool-gateway.mjs";

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const HUMAN_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_ID =
  "dlg_018f0000-0000-7000-8000-000000000020";
const STORE_ID = "01J00000000000000000000000";
const MODEL_ID = "01J00000000000000000000001";
const TEMPLATE_REF = "fixture://c06/policy-release/baseline-v1";
const RESOURCE_ID = "c16-approval-status-get";
const NOW = "2026-07-26T10:00:00.000Z";

async function load(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

const C06_CATALOG = createSyntheticAuthorizationCatalog({
  policyCatalog: await load(
    "implementation/p1/c06/synthetic-policy-catalog.v1.json",
  ),
  protectedOperations: await load(
    "implementation/p1/c06/protected-operations.v1.json",
  ),
  fixtures: await load(
    "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
  ),
  model: await load(
    "implementation/p1/c06/openfga/authorization-model.v1.json",
  ),
});
const C16_CATALOG = createSyntheticToolCatalog(
  await load("implementation/p1/c16/operation-catalog.v1.json"),
);
const C16_FIXTURES = await load(
  "implementation/p1/c16/synthetic-tool-fixtures.v1.json",
);

function deterministicIds(start) {
  let current = start;
  return () => {
    current += 1;
    return `018f0000-0000-7000-8000-${String(current).padStart(12, "0")}`;
  };
}

function tupleKey(tuple) {
  return `${tuple.user}|${tuple.relation}|${tuple.object}`;
}

function identity() {
  return {
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId: "session-synthetic",
    humanSubject: {
      principalId: HUMAN_ID,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: ACTOR_ID,
      principalType: "AGENT",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c06/purpose/tool-call",
    delegationChain: [
      {
        delegationId: DELEGATION_ID,
        delegatorPrincipalId: HUMAN_ID,
        delegatePrincipalId: ACTOR_ID,
        purposeRef: "synthetic://c06/purpose/tool-call",
        lifecycleVersion: 1,
        expiresAt: "2026-07-27T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
  };
}

async function createHarness() {
  const log = [];
  const tenantRegistry = {
    async admitNewRequest({ tenantId }) {
      log.push("C03");
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 2,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const stablePrincipalRegistry = {
    async resolveActionIdentity() {
      log.push("C05");
      return identity();
    },
  };
  const tupleBundle = buildSyntheticPolicyTuples({
    catalog: C06_CATALOG,
    templateRef: TEMPLATE_REF,
    fixtureId: FIXTURE_ID,
    principalIdsByFixtureRef: {
      [`fixture://${FIXTURE_ID}/principals/ava`]: HUMAN_ID,
      [`fixture://${FIXTURE_ID}/principals/assistant-agent`]: ACTOR_ID,
    },
  });
  const activeTuples = new Set(tupleBundle.map(tupleKey));
  function resourceTupleKeys(resourceId) {
    const operation = C06_CATALOG.operation("TOOL_CALL");
    return tupleBundle
      .filter(({ object }) => object.endsWith("--tool-call"))
      .map((tuple) =>
        tupleKey({
          ...tuple,
          object: `${operation.resource_type}:${resourceId}`,
        }),
      );
  }
  function allowResource(resourceId) {
    for (const key of resourceTupleKeys(resourceId)) {
      activeTuples.add(key);
    }
  }
  function denyResource(resourceId) {
    for (const key of resourceTupleKeys(resourceId)) {
      activeTuples.delete(key);
    }
  }
  const authorizationFacade = createAuthorizationFacade({
    store: createMemoryAuthorizationStore(),
    tenantRegistry,
    stablePrincipalRegistry,
    policyCatalog: C06_CATALOG,
    async resolveTenantFixture(tenantId) {
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        fixtureId: FIXTURE_ID,
      };
    },
    async resolveResource({
      tenantId,
      tenantKind,
      surface,
      resourceId,
    }) {
      log.push(`C06:${surface}:${resourceId}`);
      return {
        tenantId,
        tenantKind,
        resourceType: C06_CATALOG.operation(surface).resource_type,
        resourceId,
        state: "ACTIVE",
        authorizationVersion: 1,
        trustSource: "VERIFIED_RESOURCE_CONTEXT",
      };
    },
    pdpFactory() {
      return {
        async check({ tupleKey: key }) {
          return {
            allowed: activeTuples.has(tupleKey(key)),
            storeId: STORE_ID,
            authorizationModelId: MODEL_ID,
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
    idFactory: deterministicIds(100),
  });
  const control = {
    actorId: "synthetic-authorization-admin",
    projectionTrustSource: "VERIFIED_PROJECTION_WORKER",
  };
  const staged = await authorizationFacade.execute(control, {
    kind: "STAGE_SYNTHETIC_POLICY_RELEASE",
    tenantId: TENANT_ID,
    templateRef: TEMPLATE_REF,
    idempotencyKey: "c16-c06-stage",
    correlationId: "c16-c06-stage",
  });
  const ready = await authorizationFacade.execute(control, {
    kind: "RECORD_POLICY_PROJECTION",
    tenantId: TENANT_ID,
    policyReleaseId: staged.policyReleaseId,
    projectionOperationId: "c16-c06-project-operation",
    outcome: "READY",
    openFgaStoreId: STORE_ID,
    authorizationModelId: MODEL_ID,
    tupleBundleSha256: hashSyntheticPolicyTuples(tupleBundle),
    fixtureReportRef: "evidence://c06/c16-integration",
    fixtureReportSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    fixturePassCount: 30,
    fixtureFailCount: 0,
    reasonRef: null,
    idempotencyKey: "c16-c06-project",
    correlationId: "c16-c06-project",
  });
  await authorizationFacade.execute(control, {
    kind: "ACTIVATE_POLICY_RELEASE",
    tenantId: TENANT_ID,
    policyReleaseId: ready.policyReleaseId,
    expectedActivationVersion: 0,
    reasonRef: "policy://c06/c16-integration/activate",
    idempotencyKey: "c16-c06-activate",
    correlationId: "c16-c06-activate",
  });

  const memory = createMemoryToolGatewayStore();
  let confirmationWrites = 0;
  let executionWrites = 0;
  const store = {
    ...memory,
    async saveConfirmation(...args) {
      confirmationWrites += 1;
      return memory.saveConfirmation(...args);
    },
    async beginExecution(...args) {
      executionWrites += 1;
      return memory.beginExecution(...args);
    },
  };
  const broker = createC16EphemeralCredentialBroker({
    clock: () => NOW,
    idFactory: deterministicIds(600),
  });
  const adapter = createC16SyntheticToolAdapter({
    credentialBroker: broker,
    fixtureDocument: C16_FIXTURES,
  });
  let c06DecisionCount = 0;
  const c06Facade = {
    async decide(...args) {
      c06DecisionCount += 1;
      return authorizationFacade.decide(...args);
    },
  };
  const gateway = createToolGateway({
    tenantRegistry,
    stablePrincipalRegistry,
    authorizer: createC16C06Authorizer({
      authorizationFacade: c06Facade,
    }),
    catalog: C16_CATALOG,
    store,
    credentialBroker: broker,
    adapter,
    clock: () => NOW,
    idFactory: deterministicIds(800),
  });
  log.length = 0;
  return {
    adapter,
    allowResource,
    denyResource,
    gateway,
    log,
    c06DecisionCount: () => c06DecisionCount,
    writes: () => ({ confirmationWrites, executionWrites }),
  };
}

function serverContext() {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT_ID,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR_ID,
  };
}

function envelope(overrides = {}) {
  return {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION_ID,
    correlationId: "c16-c06-correlation",
    operationId: "synthetic.approval.status.get",
    ...overrides,
  };
}

test("C16 discover, confirm and execute each pass through the real C06 facade", async () => {
  const harness = await createHarness();
  harness.allowResource(RESOURCE_ID);
  const discovered = await harness.gateway.discover(
    serverContext(),
    envelope(),
  );
  assert.equal(discovered.authorizationGranted, false);
  const confirmation = await harness.gateway.confirm(
    serverContext(),
    envelope({
      idempotencyKey: "c16-c06-confirm",
      params: { approvalRef: "SYN-APR-0001" },
    }),
  );
  const result = await harness.gateway.execute(
    serverContext(),
    envelope({
      idempotencyKey: "c16-c06-execute",
      confirmationId: confirmation.confirmationId,
      confirmationSha256: confirmation.confirmationSha256,
      expectedParamSha256: confirmation.normalizedParamSha256,
    }),
  );
  assert.equal(result.status, "SUCCEEDED");
  assert.deepEqual(harness.writes(), {
    confirmationWrites: 1,
    executionWrites: 1,
  });
  assert.equal(harness.adapter.snapshot().newExecutionCount, 1);
  assert.equal(harness.c06DecisionCount(), 3);
  assert.equal(
    harness.log.filter((entry) =>
      entry === `C06:TOOL_CALL:${RESOURCE_ID}`,
    ).length,
    6,
  );
});

test("C16 reauthorizes execution and a real C06 deny prevents adapter use", async () => {
  const harness = await createHarness();
  harness.allowResource(RESOURCE_ID);
  const confirmation = await harness.gateway.confirm(
    serverContext(),
    envelope({
      idempotencyKey: "c16-c06-deny-confirm",
      params: { approvalRef: "SYN-APR-0001" },
    }),
  );
  harness.denyResource(RESOURCE_ID);
  await assert.rejects(
    harness.gateway.execute(
      serverContext(),
      envelope({
        idempotencyKey: "c16-c06-deny-execute",
        confirmationId: confirmation.confirmationId,
        confirmationSha256: confirmation.confirmationSha256,
        expectedParamSha256: confirmation.normalizedParamSha256,
      }),
    ),
    (error) =>
      error instanceof ToolGatewayError &&
      error.code === "ACCESS_DENIED",
  );
  assert.deepEqual(harness.writes(), {
    confirmationWrites: 1,
    executionWrites: 0,
  });
  assert.equal(harness.adapter.snapshot().newExecutionCount, 0);
});
