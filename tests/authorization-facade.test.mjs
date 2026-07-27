import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  AuthorizationError,
  PepDeniedError,
  buildSyntheticPolicyTuples,
  createAuthorizationFacade,
  createMemoryAuthorizationStore,
  createPepSdk,
  createSyntheticAuthorizationCatalog,
  hashSyntheticPolicyTuples,
} from "../lib/authorization-facade.mjs";

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const AVA_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const NOAH_ID = "prn_018f0000-0000-7000-8000-000000000003";
const DELEGATION_ID = "dlg_018f0000-0000-7000-8000-000000000020";
const STORE_V1 = "01J00000000000000000000000";
const MODEL_V1 = "01J00000000000000000000001";
const STORE_V2 = "01J00000000000000000000002";
const MODEL_V2 = "01J00000000000000000000003";
const TEMPLATE_V1 = "fixture://c06/policy-release/baseline-v1";
const TEMPLATE_V2 = "fixture://c06/policy-release/noah-read-v2";

async function load(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

async function loadCatalog() {
  return createSyntheticAuthorizationCatalog({
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
}

function deterministicIds() {
  let counter = 100;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function tupleKey(tuple) {
  return `${tuple.user}|${tuple.relation}|${tuple.object}`;
}

async function harness() {
  const catalog = await loadCatalog();
  const store = createMemoryAuthorizationStore();
  const principals = {
    [`fixture://${FIXTURE_ID}/principals/ava`]: AVA_ID,
    [`fixture://${FIXTURE_ID}/principals/assistant-agent`]: ACTOR_ID,
    [`fixture://${FIXTURE_ID}/principals/noah`]: NOAH_ID,
  };
  const tupleBundles = {
    [STORE_V1]: buildSyntheticPolicyTuples({
        catalog,
        templateRef: TEMPLATE_V1,
        fixtureId: FIXTURE_ID,
        principalIdsByFixtureRef: principals,
      }),
    [STORE_V2]: buildSyntheticPolicyTuples({
        catalog,
        templateRef: TEMPLATE_V2,
        fixtureId: FIXTURE_ID,
        principalIdsByFixtureRef: principals,
      }),
  };
  const tuples = {
    [STORE_V1]: new Set(tupleBundles[STORE_V1].map(tupleKey)),
    [STORE_V2]: new Set(tupleBundles[STORE_V2].map(tupleKey)),
  };
  const mutable = {
    now: "2026-07-26T00:00:00.000Z",
    tenantLifecycleVersion: 1,
    humanPrincipalId: AVA_ID,
    purposeRef: "synthetic://c06/purpose/read",
    resourceAuthorizationVersion: 1,
    pdpFailure: null,
    pdpHook: null,
    pdpResponseOverride: null,
    decisionCalls: 0,
    verifyRelease: true,
  };
  const tenantRegistry = {
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      assert.equal(tenantId, TENANT_ID);
      assert.equal(expectedTenantKind, "SYNTHETIC");
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: mutable.tenantLifecycleVersion,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const stablePrincipalRegistry = {
    async resolveActionIdentity(serverContext, request) {
      assert.deepEqual(serverContext, {
        synthetic: true,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
        workloadActorPrincipalId: ACTOR_ID,
      });
      assert.deepEqual(request, {
        sessionToken: "synthetic-session-token",
        expectedTenantId: TENANT_ID,
        delegationId: DELEGATION_ID,
      });
      return {
        tenantId: TENANT_ID,
        tenantKind: "SYNTHETIC",
        identityAccountId:
          "sia_018f0000-0000-7000-8000-000000000030",
        identityLinkId: "lnk_018f0000-0000-7000-8000-000000000031",
        sessionId: "ses_018f0000-0000-7000-8000-000000000032",
        humanSubject: {
          principalId: mutable.humanPrincipalId,
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
        purposeRef: mutable.purposeRef,
        delegationChain: [
          {
            delegationId: DELEGATION_ID,
            delegatorPrincipalId: mutable.humanPrincipalId,
            delegatePrincipalId: ACTOR_ID,
            purposeRef: mutable.purposeRef,
            lifecycleVersion: 1,
            expiresAt: "2026-07-27T00:00:00.000Z",
          },
        ],
        trustSource:
          "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
        authorizationStatus: "NOT_EVALUATED",
      };
    },
  };
  const pdpFactory = ({ storeId, authorizationModelId }) => ({
    async check({ authorizationModelId: requestedModelId, tupleKey: key }) {
      mutable.decisionCalls += 1;
      if (mutable.pdpHook) await mutable.pdpHook();
      if (mutable.pdpFailure) throw Object.assign(new Error("hidden"), {
        code: mutable.pdpFailure,
      });
      if (mutable.pdpResponseOverride) {
        return mutable.pdpResponseOverride({
          storeId,
          requestedModelId,
        });
      }
      return {
        allowed: tuples[storeId]?.has(tupleKey(key)) === true,
        storeId,
        authorizationModelId:
          requestedModelId === authorizationModelId
            ? authorizationModelId
            : "mismatch",
        consistency: "HIGHER_CONSISTENCY",
      };
    },
  });
  const facade = createAuthorizationFacade({
    store,
    tenantRegistry,
    stablePrincipalRegistry,
    policyCatalog: catalog,
    async resolveTenantFixture(tenantId) {
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        fixtureId: FIXTURE_ID,
      };
    },
    async resolveResource({ tenantId, tenantKind, surface, resourceId }) {
      return {
        tenantId,
        tenantKind,
        resourceType: catalog.operation(surface).resource_type,
        resourceId,
        state: "ACTIVE",
        authorizationVersion: mutable.resourceAuthorizationVersion,
        trustSource: "VERIFIED_RESOURCE_CONTEXT",
      };
    },
    pdpFactory,
    async verifyPolicyRelease(release) {
      return {
        passed: mutable.verifyRelease,
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
    authorizeControl: (context, capability) =>
      context?.capabilities?.includes(capability) === true,
    clock: () => mutable.now,
    idFactory: deterministicIds(),
  });
  const control = {
    actorId: "synthetic-authorization-admin",
    projectionTrustSource: "VERIFIED_PROJECTION_WORKER",
    capabilities: [
      "AUTHORIZATION_POLICY_STAGE",
      "AUTHORIZATION_POLICY_PROJECT",
      "AUTHORIZATION_POLICY_ACTIVATE",
      "AUTHORIZATION_POLICY_ROLLBACK",
      "AUTHORIZATION_DECISION_REPLAY",
      "AUTHORIZATION_GOVERNANCE_READ",
    ],
  };
  const serverContext = {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT_ID,
    surface: "READ",
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR_ID,
  };
  const request = {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_ID,
    resourceId: `${FIXTURE_ID}--read`,
    correlationId: "c06-test-correlation",
  };

  async function stage(templateRef, idempotencyKey) {
    return facade.execute(control, {
      kind: "STAGE_SYNTHETIC_POLICY_RELEASE",
      tenantId: TENANT_ID,
      templateRef,
      idempotencyKey,
      correlationId: `${idempotencyKey}-correlation`,
    });
  }

  async function project(release, storeId, modelId, idempotencyKey) {
    return facade.execute(control, {
      kind: "RECORD_POLICY_PROJECTION",
      tenantId: TENANT_ID,
      policyReleaseId: release.policyReleaseId,
      projectionOperationId: `${idempotencyKey}-operation`,
      outcome: "READY",
      openFgaStoreId: storeId,
      authorizationModelId: modelId,
      tupleBundleSha256: hashSyntheticPolicyTuples(
        tupleBundles[storeId],
      ),
      fixtureReportRef: `evidence://c06/${idempotencyKey}`,
      fixtureReportSha256:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      fixturePassCount: 30,
      fixtureFailCount: 0,
      reasonRef: null,
      idempotencyKey,
      correlationId: `${idempotencyKey}-correlation`,
    });
  }

  async function activate(release, expectedActivationVersion, idempotencyKey) {
    return facade.execute(control, {
      kind: "ACTIVATE_POLICY_RELEASE",
      tenantId: TENANT_ID,
      policyReleaseId: release.policyReleaseId,
      expectedActivationVersion,
      reasonRef: `policy://c06/${idempotencyKey}`,
      idempotencyKey,
      correlationId: `${idempotencyKey}-correlation`,
    });
  }

  async function rollback(release, expectedActivationVersion, idempotencyKey) {
    return facade.execute(control, {
      kind: "ROLLBACK_POLICY_RELEASE",
      tenantId: TENANT_ID,
      targetPolicyReleaseId: release.policyReleaseId,
      expectedActivationVersion,
      reasonRef: `policy://c06/${idempotencyKey}`,
      idempotencyKey,
      correlationId: `${idempotencyKey}-correlation`,
    });
  }

  async function prepareV1() {
    const staged = await stage(TEMPLATE_V1, "stage-v1");
    const ready = await project(staged, STORE_V1, MODEL_V1, "project-v1");
    await activate(ready, 0, "activate-v1");
    return ready;
  }

  async function prepareV2() {
    const staged = await stage(TEMPLATE_V2, "stage-v2");
    const ready = await project(staged, STORE_V2, MODEL_V2, "project-v2");
    return ready;
  }

  return {
    catalog,
    store,
    facade,
    control,
    serverContext,
    request,
    mutable,
    stage,
    project,
    activate,
    rollback,
    prepareV1,
    prepareV2,
  };
}

test("one C06 decision requires Human, Actor and purpose checks pinned to one release", async () => {
  const value = await harness();
  const release = await value.prepareV1();
  const decision = await value.facade.decide(
    value.serverContext,
    value.request,
  );

  assert.equal(decision.effect, "ALLOW");
  assert.equal(decision.authorizationStatus, "ALLOWED");
  assert.equal(decision.reasonCode, "ALL_FACTORS_ALLOWED");
  assert.equal(decision.policyReleaseId, release.policyReleaseId);
  assert.equal(decision.openFgaStoreId, STORE_V1);
  assert.equal(decision.authorizationModelId, MODEL_V1);
  assert.equal(decision.activationVersion, 1);
  assert.equal(decision.consistency, "HIGHER_CONSISTENCY");
  assert.notEqual(decision.tupleBundleSha256, decision.bundleSha256);
  assert.equal(value.mutable.decisionCalls, 3);
  assert.equal("sessionToken" in decision, false);
  assert.equal("password" in decision, false);
  assert.equal("claims" in decision, false);
});

test("missing factors, wrong purpose and PDP failures all fail closed", async () => {
  const value = await harness();
  await value.prepareV1();

  const missing = await value.facade.decide(value.serverContext, {
    ...value.request,
    resourceId: "unassigned-resource",
    correlationId: "missing-all",
  });
  assert.equal(missing.effect, "DENY");
  assert.equal(missing.reasonCode, "HUMAN_DENIED");

  value.mutable.purposeRef = "synthetic://c06/purpose/manage";
  const purpose = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "wrong-purpose",
  });
  assert.equal(purpose.effect, "DENY");
  assert.equal(purpose.reasonCode, "PURPOSE_MISMATCH");

  value.mutable.purposeRef = "synthetic://c06/purpose/read";
  value.mutable.pdpFailure = "OPENFGA_TIMEOUT";
  const unavailable = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "pdp-timeout",
  });
  assert.equal(unavailable.effect, "DENY");
  assert.equal(unavailable.reasonCode, "PDP_UNAVAILABLE");
});

test("an unverified real projection cannot become READY", async () => {
  const value = await harness();
  const staged = await value.stage(TEMPLATE_V1, "stage-unverified");
  value.mutable.verifyRelease = false;

  await assert.rejects(
    value.project(staged, STORE_V1, MODEL_V1, "project-unverified"),
    { code: "POLICY_REPLAY_FAILED" },
  );
  const snapshot = await value.facade.snapshot(value.control, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.releases[0].state, "STAGED");
  assert.equal(snapshot.activations.length, 0);
});

test("the caller cannot inject Principal, Tenant, model, relation or an Allow", async () => {
  const value = await harness();
  await value.prepareV1();
  for (const injected of [
    { principalId: AVA_ID },
    { tenantId: TENANT_ID },
    { authorizationModelId: MODEL_V1 },
    { relation: "human_can_read" },
    { allowed: true },
  ]) {
    await assert.rejects(
      value.facade.decide(value.serverContext, {
        ...value.request,
        ...injected,
      }),
      (error) =>
        error instanceof AuthorizationError &&
        error.code === "INVALID_INPUT",
    );
  }
  await assert.rejects(
    value.facade.decide(
      { ...value.serverContext, routeTrustSource: "CLIENT_ASSERTED" },
      value.request,
    ),
    { code: "UNTRUSTED_ROUTE" },
  );
});

test("activation and rollback change the next request while old decisions replay exactly", async () => {
  const value = await harness();
  const releaseV1 = await value.prepareV1();
  value.mutable.humanPrincipalId = NOAH_ID;
  const deniedV1 = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "noah-v1",
  });
  assert.equal(deniedV1.effect, "DENY");

  const releaseV2 = await value.prepareV2();
  await value.activate(releaseV2, 1, "activate-v2");
  const allowedV2 = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "noah-v2",
  });
  assert.equal(allowedV2.effect, "ALLOW");
  assert.equal(allowedV2.activationVersion, 2);

  await value.rollback(releaseV1, 2, "rollback-v1");
  const deniedAgain = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "noah-rollback",
  });
  assert.equal(deniedAgain.effect, "DENY");
  assert.equal(deniedAgain.activationVersion, 3);

  const replayed = await value.facade.replay(value.control, {
    decisionId: allowedV2.decisionId,
  });
  assert.equal(replayed.originalEffect, "ALLOW");
  assert.equal(replayed.replayedEffect, "ALLOW");
  assert.equal(replayed.matches, true);
  assert.equal(replayed.authorizationStatus, "NOT_AUTHORIZATION");
});

test("live decisions and historical replay reject a mismatched PDP response", async () => {
  const value = await harness();
  await value.prepareV1();
  value.mutable.pdpResponseOverride = ({ requestedModelId }) => ({
    allowed: true,
    storeId: "01J00000000000000000000009",
    authorizationModelId: requestedModelId,
    consistency: "HIGHER_CONSISTENCY",
  });

  const denied = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "mismatched-live-response",
  });
  assert.equal(denied.effect, "DENY");
  assert.equal(denied.reasonCode, "PDP_INVALID_RESPONSE");

  value.mutable.pdpResponseOverride = null;
  const original = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "valid-before-replay",
  });
  value.mutable.pdpResponseOverride = ({ storeId, requestedModelId }) => ({
    allowed: true,
    storeId,
    authorizationModelId: requestedModelId,
    consistency: "MINIMIZE_LATENCY",
  });
  await assert.rejects(
    value.facade.replay(value.control, {
      decisionId: original.decisionId,
    }),
    { code: "PDP_UNAVAILABLE" },
  );
});

test("an activation race cannot commit a stale Allow", async () => {
  const value = await harness();
  await value.prepareV1();
  const releaseV2 = await value.prepareV2();
  let switched = false;
  value.mutable.pdpHook = async () => {
    if (switched) return;
    switched = true;
    await value.activate(releaseV2, 1, "race-activate-v2");
  };

  const decision = await value.facade.decide(
    value.serverContext,
    value.request,
  );
  assert.equal(decision.effect, "ALLOW");
  assert.equal(decision.policyReleaseId, releaseV2.policyReleaseId);
  assert.equal(decision.activationVersion, 2);
  assert.equal(value.mutable.decisionCalls, 6);

  const snapshot = await value.facade.snapshot(value.control, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.decisions.length, 1);
  assert.equal(snapshot.decisions[0].policyReleaseId, releaseV2.policyReleaseId);
});

test("a rollback race cannot record the revoked release's old Allow", async () => {
  const value = await harness();
  const releaseV1 = await value.prepareV1();
  const releaseV2 = await value.prepareV2();
  await value.activate(releaseV2, 1, "activate-v2");
  value.mutable.humanPrincipalId = NOAH_ID;
  value.mutable.now = "2026-07-26T00:00:00.250Z";
  let switched = false;
  let revocation;
  value.mutable.pdpHook = async () => {
    if (switched) return;
    switched = true;
    revocation = await value.rollback(
      releaseV1,
      2,
      "race-rollback-v1",
    );
  };

  const decision = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "revoked-allow-cannot-commit",
  });

  assert.equal(decision.effect, "DENY");
  assert.equal(decision.policyReleaseId, releaseV1.policyReleaseId);
  assert.equal(decision.activationVersion, 3);
  assert.equal(
    Date.parse(decision.evaluatedAt) - Date.parse(revocation.activatedAt),
    0,
  );
  const snapshot = await value.facade.snapshot(value.control, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.decisions.length, 1);
  assert.equal(snapshot.decisions[0].effect, "DENY");
  assert.equal(
    snapshot.decisions.some(
      ({ policyReleaseId, effect }) =>
        policyReleaseId === releaseV2.policyReleaseId &&
        effect === "ALLOW",
    ),
    false,
  );
});

test("exact idempotency replays without revalidating an unavailable PDP", async () => {
  const value = await harness();
  const release = await value.prepareV1();
  value.mutable.verifyRelease = false;
  const replay = await value.activate(release, 0, "activate-v1");
  assert.equal(replay.duplicate, true);
  assert.equal(replay.activationVersion, 1);

  await assert.rejects(
    value.facade.execute(value.control, {
      kind: "ACTIVATE_POLICY_RELEASE",
      tenantId: TENANT_ID,
      policyReleaseId: release.policyReleaseId,
      expectedActivationVersion: 1,
      reasonRef: "policy://c06/different-content",
      idempotencyKey: "activate-v1",
      correlationId: "different-content",
    }),
    { code: "IDEMPOTENCY_CONFLICT" },
  );
});

test("the PEP exposes only evidence for Allow and collapses every other result", async () => {
  const value = await harness();
  await value.prepareV1();
  const pep = createPepSdk({ authorizationFacade: value.facade });
  const allowed = await pep.enforce(value.serverContext, value.request);
  assert.deepEqual(Object.keys(allowed).sort(), [
    "decisionId",
    "evidenceRef",
    "policyVersion",
  ]);

  await assert.rejects(
    pep.enforce(value.serverContext, {
      ...value.request,
      resourceId: "unassigned-resource",
      correlationId: "pep-deny",
    }),
    (error) =>
      error instanceof PepDeniedError && error.code === "ACCESS_DENIED",
  );
  await assert.rejects(
    pep.enforce(
      { ...value.serverContext, routeTrustSource: "CLIENT_ASSERTED" },
      value.request,
    ),
    (error) =>
      error instanceof PepDeniedError &&
      error.code === "AUTHORIZATION_UNAVAILABLE",
  );
});
