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
  C15C06AuthorizationError,
  createC15C06Authorizer,
} from "../lib/c15-c06-authorizer.mjs";
import {
  createHumanDecisionWorkflow,
  createMemoryHumanDecisionStore,
  createSyntheticHumanDecisionCatalog,
  humanDecisionSha256,
} from "../lib/human-decision-workflow.mjs";

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const HUMAN_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const MANAGE_DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const TOOL_DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000021";
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
const C15_DOCUMENT = await load(
  "implementation/p1/c15/synthetic-workflow-fixtures.v1.json",
);
const C15_CATALOG =
  createSyntheticHumanDecisionCatalog(C15_DOCUMENT);

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

function purposeForDelegation(delegationId) {
  return delegationId === TOOL_DELEGATION
    ? "synthetic://c06/purpose/tool-call"
    : "synthetic://c06/purpose/manage";
}

function identity(delegationId) {
  const purposeRef = purposeForDelegation(delegationId);
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
    purposeRef,
    delegationChain: [
      {
        delegationId,
        delegatorPrincipalId: HUMAN_ID,
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
    async resolveActionIdentity(_context, request) {
      log.push("C05");
      return identity(request.delegationId);
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
  function allowResource(surface, resourceId) {
    const suffix = `--${surface.toLowerCase().replaceAll("_", "-")}`;
    for (const tuple of tupleBundle.filter(({ object }) =>
      object.endsWith(suffix),
    )) {
      activeTuples.add(
        tupleKey({
          ...tuple,
          object:
            `${C06_CATALOG.operation(surface).resource_type}:${resourceId}`,
        }),
      );
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
    idempotencyKey: "c15-c06-stage",
    correlationId: "c15-c06-stage",
  });
  const ready = await authorizationFacade.execute(control, {
    kind: "RECORD_POLICY_PROJECTION",
    tenantId: TENANT_ID,
    policyReleaseId: staged.policyReleaseId,
    projectionOperationId: "c15-c06-project-operation",
    outcome: "READY",
    openFgaStoreId: STORE_ID,
    authorizationModelId: MODEL_ID,
    tupleBundleSha256: hashSyntheticPolicyTuples(tupleBundle),
    fixtureReportRef: "evidence://c06/c15-integration",
    fixtureReportSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    fixturePassCount: 30,
    fixtureFailCount: 0,
    reasonRef: null,
    idempotencyKey: "c15-c06-project",
    correlationId: "c15-c06-project",
  });
  await authorizationFacade.execute(control, {
    kind: "ACTIVATE_POLICY_RELEASE",
    tenantId: TENANT_ID,
    policyReleaseId: ready.policyReleaseId,
    expectedActivationVersion: 0,
    reasonRef: "policy://c06/c15-integration/activate",
    idempotencyKey: "c15-c06-activate",
    correlationId: "c15-c06-activate",
  });
  const memory = createMemoryHumanDecisionStore({
    clock: () => NOW,
  });
  let artifactWrites = 0;
  let effectWrites = 0;
  const store = {
    ...memory,
    async createArtifact(...args) {
      artifactWrites += 1;
      return memory.createArtifact(...args);
    },
    async queueEffect(...args) {
      effectWrites += 1;
      return memory.queueEffect(...args);
    },
  };
  const workflow = createHumanDecisionWorkflow({
    tenantRegistry,
    stablePrincipalRegistry,
    authorizer: createC15C06Authorizer({ authorizationFacade }),
    decisionCeremony: {
      async verify(input) {
        return {
          trustSource: "C15_DEDICATED_DECISION_CEREMONY",
          proofRef: input.proofRef,
          proofSha256: humanDecisionSha256(input),
          artifactSha256: input.artifactSha256,
          displaySha256: input.displaySha256,
          humanPrincipalId: HUMAN_ID,
          leafDelegationId: input.identityBinding.leafDelegationId,
          expiresAt: "2026-07-26T10:05:00.000Z",
        };
      },
    },
    catalog: C15_CATALOG,
    store,
    clock: () => NOW,
    idFactory: deterministicIds(500),
  });
  log.length = 0;
  return {
    allowResource,
    workflow,
    log,
    writes: () => ({ artifactWrites, effectWrites }),
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

function envelope(delegationId, idempotencyKey) {
  return {
    sessionToken: "synthetic-session",
    delegationId,
    idempotencyKey,
    correlationId: idempotencyKey,
  };
}

test("C15 reaches each state change only after a real C06 allow", async () => {
  const harness = await createHarness();
  const fixture = C15_DOCUMENT.workflows[0];
  harness.allowResource(
    "MANAGE",
    `${fixture.resourcePrefix}--decision-prepare`,
  );
  const artifact = await harness.workflow.prepare(serverContext(), {
    ...envelope(MANAGE_DELEGATION, "c15-real-prepare"),
    workflowRef: fixture.workflowRef,
    candidate: structuredClone(fixture.baseline),
  });
  harness.allowResource(
    "MANAGE",
    `${artifact.artifactId}--decision-approve`,
  );
  const decision = await harness.workflow.decide(serverContext(), {
    ...envelope(MANAGE_DELEGATION, "c15-real-decide"),
    artifactId: artifact.artifactId,
    artifactSha256: artifact.artifactSha256,
    outcome: "APPROVE",
    ceremonyProofRef:
      `fixture://c15/ceremonies/${artifact.artifactId}`,
  });
  harness.allowResource(
    "TOOL_CALL",
    `${decision.decisionId}--decision-execute`,
  );
  const effect = await harness.workflow.execute(serverContext(), {
    ...envelope(TOOL_DELEGATION, "c15-real-execute"),
    decisionId: decision.decisionId,
    decisionSha256: decision.decisionSha256,
    artifactId: artifact.artifactId,
    artifactSha256: artifact.artifactSha256,
  });
  assert.equal(effect.externalEffectCount, 0);
  assert.deepEqual(harness.writes(), {
    artifactWrites: 1,
    effectWrites: 1,
  });
  assert.equal(
    harness.log.some((entry) =>
      entry.startsWith("C06:MANAGE:"),
    ),
    true,
  );
  assert.equal(
    harness.log.some((entry) =>
      entry.startsWith("C06:TOOL_CALL:"),
    ),
    true,
  );
  assert.notEqual(
    decision.identityBinding.leafDelegationId,
    effect.executionIdentity.leafDelegationId,
  );
});

test("a real C06 deny occurs before C15 effect storage", async () => {
  const harness = await createHarness();
  const fixture = C15_DOCUMENT.workflows[0];
  harness.allowResource(
    "MANAGE",
    `${fixture.resourcePrefix}--decision-prepare`,
  );
  const artifact = await harness.workflow.prepare(serverContext(), {
    ...envelope(MANAGE_DELEGATION, "c15-deny-prepare"),
    workflowRef: fixture.workflowRef,
    candidate: structuredClone(fixture.baseline),
  });
  harness.allowResource(
    "MANAGE",
    `${artifact.artifactId}--decision-approve`,
  );
  const decision = await harness.workflow.decide(serverContext(), {
    ...envelope(MANAGE_DELEGATION, "c15-deny-decide"),
    artifactId: artifact.artifactId,
    artifactSha256: artifact.artifactSha256,
    outcome: "APPROVE",
    ceremonyProofRef:
      `fixture://c15/ceremonies/${artifact.artifactId}`,
  });
  await assert.rejects(
    harness.workflow.execute(serverContext(), {
      ...envelope(TOOL_DELEGATION, "c15-denied-execute"),
      decisionId: decision.decisionId,
      decisionSha256: decision.decisionSha256,
      artifactId: artifact.artifactId,
      artifactSha256: artifact.artifactSha256,
    }),
    (error) =>
      error instanceof C15C06AuthorizationError &&
      error.code === "ACCESS_DENIED",
  );
  assert.deepEqual(harness.writes(), {
    artifactWrites: 1,
    effectWrites: 0,
  });
});
