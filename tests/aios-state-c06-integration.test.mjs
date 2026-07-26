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
  createAiosStateCore,
  createMemoryAiosStateStore,
} from "../lib/aios-state-core.mjs";
import { createC08C06Authorizer } from "../lib/c08-c06-authorizer.mjs";
import { createC08C0MockToolReceipts } from "../lib/c08-c0-mock-tool-receipts.mjs";
import { createC08SyntheticReferenceCatalog } from "../lib/c08-synthetic-reference-catalog.mjs";

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const HUMAN_ID = "prn_018f0000-0000-7000-8000-000000000001";
const HUMAN_B = "prn_018f0000-0000-7000-8000-000000000003";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_ID = "dlg_018f0000-0000-7000-8000-000000000020";
const STORE_ID = "01J00000000000000000000000";
const MODEL_ID = "01J00000000000000000000001";
const TEMPLATE_REF = "fixture://c06/policy-release/baseline-v1";
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
const C08_CATALOG = createC08SyntheticReferenceCatalog(
  await load(
    "implementation/p1/c08/synthetic-reference-catalog.v1.json",
  ),
);

function deterministicIds(start) {
  let counter = start;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function tupleKey(tuple) {
  return `${tuple.user}|${tuple.relation}|${tuple.object}`;
}

function identity(purposeRef, humanPrincipalId = HUMAN_ID) {
  return {
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_018f0000-0000-7000-8000-000000000030",
    identityLinkId: "lnk_018f0000-0000-7000-8000-000000000031",
    sessionId: "ses_018f0000-0000-7000-8000-000000000032",
    humanSubject: {
      principalId: humanPrincipalId,
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
    purposeRef,
    delegationChain: [
      {
        delegationId: DELEGATION_ID,
        delegatorPrincipalId: humanPrincipalId,
        delegatePrincipalId: ACTOR_ID,
        purposeRef,
        lifecycleVersion: 1,
        expiresAt: "2026-07-27T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
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

async function createHarness({
  identityPrincipals = null,
  policyHumanId = HUMAN_ID,
} = {}) {
  const log = [];
  let identityCall = 0;
  const resources = C08_CATALOG.authorizationResources(TENANT_ID);
  const tupleBundle = buildSyntheticPolicyTuples({
    catalog: C06_CATALOG,
    templateRef: TEMPLATE_REF,
    fixtureId: FIXTURE_ID,
    principalIdsByFixtureRef: {
      [`fixture://${FIXTURE_ID}/principals/ava`]: policyHumanId,
      [`fixture://${FIXTURE_ID}/principals/assistant-agent`]: ACTOR_ID,
    },
  });
  const activeTuples = new Set(tupleBundle.map(tupleKey));
  const mutable = {
    purposeRef: "synthetic://c06/purpose/manage",
    c08RunCommands: 0,
    c08ReadRuns: 0,
  };
  const tenantRegistry = {
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      log.push("admit");
      assert.equal(tenantId, TENANT_ID);
      assert.equal(expectedTenantKind, "SYNTHETIC");
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 1,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const stablePrincipalRegistry = {
    async resolveActionIdentity(context, request) {
      log.push("identity");
      assert.deepEqual(context, {
        synthetic: true,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
        workloadActorPrincipalId: ACTOR_ID,
      });
      assert.deepEqual(request, {
        sessionToken: "synthetic-session-token",
        expectedTenantId: TENANT_ID,
        delegationId: DELEGATION_ID,
      });
      const humanPrincipalId =
        identityPrincipals?.[identityCall] ?? HUMAN_ID;
      identityCall += 1;
      return identity(mutable.purposeRef, humanPrincipalId);
    },
  };
  const authorizationStore = createMemoryAuthorizationStore();
  const authorizationFacade = createAuthorizationFacade({
    store: authorizationStore,
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
      log.push(`resource:${surface}:${resourceId}`);
      assert.equal(resourceId, resources[surface]);
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
    pdpFactory({ storeId, authorizationModelId }) {
      assert.equal(storeId, STORE_ID);
      assert.equal(authorizationModelId, MODEL_ID);
      return {
        async check({ authorizationModelId: requestedModelId, tupleKey: key }) {
          assert.equal(requestedModelId, MODEL_ID);
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
    idempotencyKey: "c08-c06-stage",
    correlationId: "c08-c06-stage",
  });
  const ready = await authorizationFacade.execute(control, {
    kind: "RECORD_POLICY_PROJECTION",
    tenantId: TENANT_ID,
    policyReleaseId: staged.policyReleaseId,
    projectionOperationId: "c08-c06-project-operation",
    outcome: "READY",
    openFgaStoreId: STORE_ID,
    authorizationModelId: MODEL_ID,
    tupleBundleSha256: hashSyntheticPolicyTuples(tupleBundle),
    fixtureReportRef: "evidence://c06/c08-integration",
    fixtureReportSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    fixturePassCount: 30,
    fixtureFailCount: 0,
    reasonRef: null,
    idempotencyKey: "c08-c06-project",
    correlationId: "c08-c06-project",
  });
  await authorizationFacade.execute(control, {
    kind: "ACTIVATE_POLICY_RELEASE",
    tenantId: TENANT_ID,
    policyReleaseId: ready.policyReleaseId,
    expectedActivationVersion: 0,
    reasonRef: "policy://c06/c08-integration/activate",
    idempotencyKey: "c08-c06-activate",
    correlationId: "c08-c06-activate",
  });

  const baseStateStore = createMemoryAiosStateStore();
  const stateStore = {
    ...baseStateStore,
    async runCommand(...args) {
      mutable.c08RunCommands += 1;
      log.push("c08-store:runCommand");
      return baseStateStore.runCommand(...args);
    },
    async readRun(...args) {
      mutable.c08ReadRuns += 1;
      log.push("c08-store:readRun");
      return baseStateStore.readRun(...args);
    },
  };
  const mockToolReceipts = createC08C0MockToolReceipts();
  const core = createAiosStateCore({
    tenantRegistry,
    stablePrincipalRegistry,
    authorizer: createC08C06Authorizer({
      authorizationFacade,
    }),
    store: stateStore,
    referenceCatalog: C08_CATALOG,
    toolReceiptVerifier: mockToolReceipts.verifier,
    idFactory: deterministicIds(500),
    clock: () => NOW,
  });
  log.length = 0;
  return {
    activeTuples,
    core,
    log,
    mutable,
    resources,
  };
}

function filteredOrder(log) {
  return log.filter(
    (entry) =>
      entry === "admit" ||
      entry === "identity" ||
      entry.startsWith("resource:") ||
      entry.startsWith("c08-store:"),
  );
}

test("C08 passes catalog-fixed MANAGE and READ resources through the real C06 facade in order", async () => {
  const harness = await createHarness();
  assert.deepEqual(harness.resources, {
    READ: `${FIXTURE_ID}--read`,
    MANAGE: `${FIXTURE_ID}--manage`,
    TOOL_CALL: `${FIXTURE_ID}--tool-call`,
  });

  const created = await harness.core.execute(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_ID,
    idempotencyKey: "c08-c06-create-case",
    correlationId: "c08-c06-create-case",
    command: {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/safe",
    },
  });
  assert.equal(created.state, "OPEN");
  assert.deepEqual(filteredOrder(harness.log), [
    "identity",
    "admit",
    "identity",
    `resource:MANAGE:${harness.resources.MANAGE}`,
    "admit",
    "identity",
    `resource:MANAGE:${harness.resources.MANAGE}`,
    "identity",
    "admit",
    "c08-store:runCommand",
  ]);

  const thread = await harness.core.execute(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_ID,
    idempotencyKey: "c08-c06-open-thread",
    correlationId: "c08-c06-open-thread",
    command: {
      kind: "OPEN_THREAD",
      caseId: created.caseId,
      purposeRef: "policy://c08/purpose/analyze-order",
    },
  });
  const input = await harness.core.execute(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_ID,
    idempotencyKey: "c08-c06-input",
    correlationId: "c08-c06-input",
    command: {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: created.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "INPUT",
      contentRef: "synthetic://c08/artifacts/input-order",
      contentSha256:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  });
  const run = await harness.core.execute(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_ID,
    idempotencyKey: "c08-c06-start-run",
    correlationId: "c08-c06-start-run",
    command: {
      kind: "START_RUN",
      threadId: thread.threadId,
      manifest: {
        inputArtifact: {
          artifactId: input.artifactId,
          artifactVersion: input.artifactVersion,
          contentSha256: input.contentSha256,
        },
        model: {
          ref: "synthetic://c08/models/assistant",
          version: "model-1",
          sha256:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
        prompt: {
          ref: "synthetic://c08/prompts/run",
          version: "prompt-1",
          sha256:
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        },
        skill: {
          ref: "synthetic://c08/skills/analyze",
          version: "skill-1",
          sha256:
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        },
        knowledge: [
          {
            evidenceRef:
              "evidence://c08/knowledge/synthetic-handbook",
            version: "knowledge-1",
            asOf: "2026-07-26T09:59:00.000Z",
            sha256:
              "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          },
        ],
        traceRef: "test://c08/traces/run-1",
      },
    },
  });
  harness.log.length = 0;
  harness.mutable.purposeRef = "synthetic://c06/purpose/tool-call";
  const prepared = await harness.core.execute(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_ID,
    idempotencyKey: "c08-c06-prepare-tool",
    correlationId: "c08-c06-prepare-tool",
    command: {
      kind: "PREPARE_TOOL_CALL",
      runId: run.runId,
      expectedRunVersion: 1,
      operationRef: "synthetic://c08/tools/catalog-read",
      operationVersion: "tool-1",
      requestHash:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      compensationRef: "test://c08/compensations/noop",
    },
  });
  assert.equal(prepared.state, "PREPARED");
  assert.deepEqual(filteredOrder(harness.log), [
    "identity",
    "admit",
    "identity",
    `resource:TOOL_CALL:${harness.resources.TOOL_CALL}`,
    "admit",
    "identity",
    `resource:TOOL_CALL:${harness.resources.TOOL_CALL}`,
    "identity",
    "admit",
    "c08-store:runCommand",
  ]);

  harness.log.length = 0;
  harness.mutable.purposeRef = "synthetic://c06/purpose/read";
  await assert.rejects(
    harness.core.reconstructRun(serverContext(), {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION_ID,
      runId: run.runId,
      correlationId: "c08-c06-reconstruct",
    }),
    { code: "RUN_NOT_RECONSTRUCTABLE" },
  );
  assert.deepEqual(filteredOrder(harness.log), [
    "identity",
    "admit",
    "identity",
    `resource:READ:${harness.resources.READ}`,
    "admit",
    "identity",
    `resource:READ:${harness.resources.READ}`,
    "identity",
    "admit",
    "c08-store:readRun",
  ]);
});

test("a missing C06 tuple fails closed before final C08 admission and state storage", async () => {
  const harness = await createHarness();
  const missingTuple = [
    `human:${HUMAN_ID}`,
    "human_can_manage",
    `protected_resource:${harness.resources.MANAGE}`,
  ].join("|");
  assert.equal(harness.activeTuples.delete(missingTuple), true);
  harness.log.length = 0;

  await assert.rejects(
    harness.core.execute(serverContext(), {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION_ID,
      idempotencyKey: "c08-c06-denied-case",
      correlationId: "c08-c06-denied-case",
      command: {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/safe",
      },
    }),
    { code: "ACCESS_DENIED" },
  );

  assert.deepEqual(filteredOrder(harness.log), [
    "identity",
    "admit",
    "identity",
    `resource:MANAGE:${harness.resources.MANAGE}`,
    "admit",
    "identity",
    `resource:MANAGE:${harness.resources.MANAGE}`,
  ]);
  assert.equal(harness.mutable.c08RunCommands, 0);
  assert.equal(harness.mutable.c08ReadRuns, 0);
});

test("a C06 decision for another Human cannot pass an A-B-B-A identity sequence", async () => {
  const harness = await createHarness({
    identityPrincipals: [HUMAN_ID, HUMAN_B, HUMAN_B, HUMAN_ID],
    policyHumanId: HUMAN_B,
  });
  harness.log.length = 0;

  await assert.rejects(
    harness.core.execute(serverContext(), {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION_ID,
      idempotencyKey: "c08-c06-aba-case",
      correlationId: "c08-c06-aba-case",
      command: {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/safe",
      },
    }),
    { code: "AUTHORIZATION_BINDING_MISMATCH" },
  );

  assert.deepEqual(filteredOrder(harness.log), [
    "identity",
    "admit",
    "identity",
    `resource:MANAGE:${harness.resources.MANAGE}`,
    "admit",
    "identity",
    `resource:MANAGE:${harness.resources.MANAGE}`,
  ]);
  assert.equal(harness.mutable.c08RunCommands, 0);
});
