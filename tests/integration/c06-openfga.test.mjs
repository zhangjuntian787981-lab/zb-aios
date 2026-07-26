import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  buildSyntheticPolicyTuples,
  createAuthorizationFacade,
  createMemoryAuthorizationStore,
  createSyntheticAuthorizationCatalog,
} from "../../lib/authorization-facade.mjs";
import {
  createOpenFgaPdp,
  createOpenFgaRuntimePdp,
} from "../../lib/openfga-pdp.mjs";
import { createOpenFgaPolicyVerifier } from "../../lib/openfga-policy-verifier.mjs";

if (process.env.C06_OPENFGA_EPHEMERAL !== "1") {
  throw new Error("C06_OPENFGA_EPHEMERAL=1 is required.");
}
if (!process.env.C06_OPENFGA_BASE_URL) {
  throw new Error("C06_OPENFGA_BASE_URL is required.");
}
if (!process.env.C06_OPENFGA_UNREACHABLE_BASE_URL) {
  throw new Error("C06_OPENFGA_UNREACHABLE_BASE_URL is required.");
}

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const AVA_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const NOAH_ID = "prn_018f0000-0000-7000-8000-000000000003";
const OUTSIDER_ID = "prn_018f0000-0000-7000-8000-000000000099";
const DELEGATION_ID = "dlg_018f0000-0000-7000-8000-000000000020";
const TEMPLATE_V1 = "fixture://c06/policy-release/baseline-v1";
const TEMPLATE_V2 = "fixture://c06/policy-release/noah-read-v2";

async function load(path) {
  return JSON.parse(
    await readFile(new URL(`../../${path}`, import.meta.url), "utf8"),
  );
}

const model = await load(
  "implementation/p1/c06/openfga/authorization-model.v1.json",
);
const policyCatalog = createSyntheticAuthorizationCatalog({
  policyCatalog: await load(
    "implementation/p1/c06/synthetic-policy-catalog.v1.json",
  ),
  protectedOperations: await load(
    "implementation/p1/c06/protected-operations.v1.json",
  ),
  fixtures: await load(
    "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
  ),
  model,
});
const principalIdsByFixtureRef = {
  [`fixture://${FIXTURE_ID}/principals/ava`]: AVA_ID,
  [`fixture://${FIXTURE_ID}/principals/assistant-agent`]: ACTOR_ID,
  [`fixture://${FIXTURE_ID}/principals/noah`]: NOAH_ID,
};

function deterministicIds() {
  let counter = 700;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function createRealHarness() {
  const store = createMemoryAuthorizationStore();
  const mutable = {
    humanPrincipalId: AVA_ID,
    purposeRef: "synthetic://c06/purpose/read",
  };
  const pdpFactory = ({ storeId }) =>
    createOpenFgaRuntimePdp({
      baseUrl: process.env.C06_OPENFGA_BASE_URL,
      storeId,
    });
  const verifier = createOpenFgaPolicyVerifier({
    policyCatalog,
    pdpFactory,
    async resolvePrincipalIds(input) {
      assert.deepEqual(input, {
        tenantId: TENANT_ID,
        fixtureId: FIXTURE_ID,
      });
      return {
        principalIdsByFixtureRef,
        unauthorizedHumanPrincipalId: OUTSIDER_ID,
        trustSource: "VERIFIED_SYNTHETIC_PRINCIPAL_MAPPING",
      };
    },
  });
  const tenantRegistry = {
    async admitNewRequest({ tenantId, expectedTenantKind }) {
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
  const facade = createAuthorizationFacade({
    store,
    tenantRegistry,
    stablePrincipalRegistry,
    policyCatalog,
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
        resourceType: policyCatalog.operation(surface).resource_type,
        resourceId,
        state: "ACTIVE",
        authorizationVersion: 1,
        trustSource: "VERIFIED_RESOURCE_CONTEXT",
      };
    },
    pdpFactory,
    verifyPolicyRelease: verifier.verifyPolicyRelease,
    authorizeControl: (context, capability) =>
      context?.capabilities?.includes(capability) === true,
    clock: () => "2026-07-26T00:00:00.000Z",
    idFactory: deterministicIds(),
  });
  const control = {
    actorId: "synthetic-c06-openfga-admin",
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
    correlationId: "c06-real-openfga-decision",
  };

  async function stage(templateRef, label) {
    return facade.execute(control, {
      kind: "STAGE_SYNTHETIC_POLICY_RELEASE",
      tenantId: TENANT_ID,
      templateRef,
      idempotencyKey: `stage-${label}`,
      correlationId: `stage-${label}`,
    });
  }

  async function project(
    staged,
    label,
    fixtureReportSha256,
    { beforeRecord, modelOverride } = {},
  ) {
    const pdp = createOpenFgaPdp({
      baseUrl: process.env.C06_OPENFGA_BASE_URL,
    });
    const { storeId } = await pdp.provisionStore({
      name: `c06-${label}`,
    });
    const published = await pdp.publishModel(modelOverride ?? model);
    const tupleKeys = buildSyntheticPolicyTuples({
      catalog: policyCatalog,
      templateRef: staged.templateRef,
      fixtureId: FIXTURE_ID,
      principalIdsByFixtureRef,
    });
    await pdp.writeTuples({
      authorizationModelId: published.authorizationModelId,
      tupleKeys,
    });
    const report = await verifier.evaluateProjection({
      ...staged,
      openFgaStoreId: storeId,
      authorizationModelId: published.authorizationModelId,
    });
    if (beforeRecord) {
      await beforeRecord({
        pdp,
        authorizationModelId: published.authorizationModelId,
      });
    }
    const ready = await facade.execute(control, {
      kind: "RECORD_POLICY_PROJECTION",
      tenantId: TENANT_ID,
      policyReleaseId: staged.policyReleaseId,
      projectionOperationId: `project-${label}`,
      outcome: "READY",
      openFgaStoreId: storeId,
      authorizationModelId: published.authorizationModelId,
      tupleBundleSha256: report.tupleBundleSha256,
      fixtureReportRef: `evidence://c06/openfga/${label}`,
      fixtureReportSha256:
        fixtureReportSha256 ?? report.fixtureReportSha256,
      fixturePassCount: report.fixturePassCount,
      fixtureFailCount: report.fixtureFailCount,
      reasonRef: null,
      idempotencyKey: `project-${label}`,
      correlationId: `project-${label}`,
    });
    return { ready, report, projector: pdp };
  }

  async function activate(release, expectedActivationVersion, label) {
    return facade.execute(control, {
      kind: "ACTIVATE_POLICY_RELEASE",
      tenantId: TENANT_ID,
      policyReleaseId: release.policyReleaseId,
      expectedActivationVersion,
      reasonRef: `policy://c06/openfga/${label}`,
      idempotencyKey: `activate-${label}`,
      correlationId: `activate-${label}`,
    });
  }

  async function rollback(release, expectedActivationVersion, label) {
    return facade.execute(control, {
      kind: "ROLLBACK_POLICY_RELEASE",
      tenantId: TENANT_ID,
      targetPolicyReleaseId: release.policyReleaseId,
      expectedActivationVersion,
      reasonRef: `policy://c06/openfga/${label}`,
      idempotencyKey: `rollback-${label}`,
      correlationId: `rollback-${label}`,
    });
  }

  return {
    facade,
    control,
    mutable,
    serverContext,
    request,
    stage,
    project,
    activate,
    rollback,
    pdpFactory,
  };
}

test("real OpenFGA verifies 30 cases before projection, activation and rollback", async () => {
  const value = createRealHarness();
  const stagedV1 = await value.stage(TEMPLATE_V1, "v1");
  const { ready: readyV1, report: reportV1 } = await value.project(
    stagedV1,
    "v1",
  );
  assert.equal(reportV1.fixturePassCount, 30);
  assert.equal(reportV1.fixtureFailCount, 0);
  assert.notEqual(reportV1.policyBundleSha256, reportV1.tupleBundleSha256);
  await value.activate(readyV1, 0, "v1");

  const avaV1 = await value.facade.decide(
    value.serverContext,
    value.request,
  );
  assert.equal(avaV1.effect, "ALLOW");

  value.mutable.humanPrincipalId = NOAH_ID;
  const noahV1 = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "c06-real-openfga-noah-v1",
  });
  assert.equal(noahV1.effect, "DENY");

  const stagedV2 = await value.stage(TEMPLATE_V2, "v2");
  const { ready: readyV2, report: reportV2 } = await value.project(
    stagedV2,
    "v2",
  );
  assert.equal(reportV2.fixturePassCount, 30);
  assert.notEqual(
    reportV1.tupleBundleSha256,
    reportV2.tupleBundleSha256,
  );
  await value.activate(readyV2, 1, "v2");

  const noahV2 = await value.facade.decide(value.serverContext, {
    ...value.request,
    correlationId: "c06-real-openfga-noah-v2",
  });
  assert.equal(noahV2.effect, "ALLOW");

  await value.rollback(readyV1, 2, "v1");
  const noahAfterRollback = await value.facade.decide(
    value.serverContext,
    {
      ...value.request,
      correlationId: "c06-real-openfga-noah-rollback",
    },
  );
  assert.equal(noahAfterRollback.effect, "DENY");

  const replayed = await value.facade.replay(value.control, {
    decisionId: noahV2.decisionId,
  });
  assert.equal(replayed.originalEffect, "ALLOW");
  assert.equal(replayed.replayedEffect, "ALLOW");
  assert.equal(replayed.matches, true);
  assert.equal(replayed.authorizationStatus, "NOT_AUTHORIZATION");
});

test("a tampered fixture report cannot be projected or activated", async () => {
  const value = createRealHarness();
  const staged = await value.stage(TEMPLATE_V1, "tampered");

  await assert.rejects(
    value.project(
      staged,
      "tampered",
      `sha256:${"f".repeat(64)}`,
    ),
    { code: "POLICY_REPLAY_FAILED" },
  );
  await assert.rejects(
    value.activate(staged, 0, "tampered"),
    { code: "RELEASE_NOT_READY" },
  );
  const snapshot = await value.facade.snapshot(value.control, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.activePolicy, null);
  assert.equal(snapshot.releases[0].state, "STAGED");
});

test("an unreachable OpenFGA fails closed with a stable error", async () => {
  const pdp = createOpenFgaPdp({
    baseUrl: process.env.C06_OPENFGA_UNREACHABLE_BASE_URL,
    storeId: "01J00000000000000000000000",
    timeoutMs: 500,
  });

  await assert.rejects(
    pdp.check({
      authorizationModelId: "01J00000000000000000000001",
      tupleKey: {
        user: `human:${AVA_ID}`,
        relation: "human_can_read",
        object: `protected_resource:${FIXTURE_ID}--read`,
      },
    }),
    (error) => {
      assert.equal(
        ["OPENFGA_UNAVAILABLE", "OPENFGA_TIMEOUT"].includes(error.code),
        true,
      );
      assert.equal("allowed" in error, false);
      return true;
    },
  );
});

test("remote model or tuple drift blocks projection, activation and live decisions", async () => {
  const extraTuples = [
    {
      user: `human:${OUTSIDER_ID}`,
      relation: "human_can_read",
      object: `protected_resource:${FIXTURE_ID}--unapproved-read`,
    },
    {
      user: `workload:${ACTOR_ID}`,
      relation: "actor_can_read",
      object: `protected_resource:${FIXTURE_ID}--unapproved-read`,
    },
    {
      user: "purpose_scope:unapproved",
      relation: "scope_can_read",
      object: `protected_resource:${FIXTURE_ID}--unapproved-read`,
    },
  ];

  const changedModel = createRealHarness();
  const changedModelRelease = await changedModel.stage(
    TEMPLATE_V1,
    "changed-model",
  );
  await assert.rejects(
    changedModel.project(
      changedModelRelease,
      "changed-model",
      undefined,
      {
        modelOverride: {
          ...model,
          type_definitions: [
            ...model.type_definitions,
            { type: "unapproved" },
          ],
        },
      },
    ),
    { code: "POLICY_VERIFICATION_PROJECTION_MISMATCH" },
  );

  const beforeRecord = createRealHarness();
  const beforeRecordRelease = await beforeRecord.stage(
    TEMPLATE_V1,
    "before-record",
  );
  await assert.rejects(
    beforeRecord.project(
      beforeRecordRelease,
      "before-record",
      undefined,
      {
        beforeRecord: ({ pdp, authorizationModelId }) =>
          pdp.writeTuples({
            authorizationModelId,
            tupleKeys: extraTuples,
          }),
      },
    ),
    { code: "POLICY_REPLAY_FAILED" },
  );

  const afterReady = createRealHarness();
  const afterReadyRelease = await afterReady.stage(
    TEMPLATE_V1,
    "after-ready",
  );
  const {
    ready: readyAfterReady,
    projector: afterReadyProjector,
  } = await afterReady.project(afterReadyRelease, "after-ready");
  assert.equal(
    "writeTuples" in
      afterReady.pdpFactory({
        storeId: readyAfterReady.openFgaStoreId,
      }),
    false,
  );
  await afterReadyProjector.writeTuples({
    authorizationModelId: readyAfterReady.authorizationModelId,
    tupleKeys: extraTuples,
  });
  await assert.rejects(
    afterReady.activate(readyAfterReady, 0, "after-ready"),
    { code: "POLICY_REPLAY_FAILED" },
  );

  const afterActivation = createRealHarness();
  const afterActivationRelease = await afterActivation.stage(
    TEMPLATE_V1,
    "after-activation",
  );
  const {
    ready: readyAfterActivation,
    projector: afterActivationProjector,
  } = await afterActivation.project(
    afterActivationRelease,
    "after-activation",
  );
  await afterActivation.activate(
    readyAfterActivation,
    0,
    "after-activation",
  );
  const decisionBeforeDrift = await afterActivation.facade.decide(
    afterActivation.serverContext,
    afterActivation.request,
  );
  await afterActivationProjector.writeTuples({
    authorizationModelId: readyAfterActivation.authorizationModelId,
    tupleKeys: extraTuples,
  });
  await assert.rejects(
    afterActivation.facade.decide(
      afterActivation.serverContext,
      afterActivation.request,
    ),
    { code: "POLICY_REPLAY_FAILED" },
  );
  await assert.rejects(
    afterActivation.facade.replay(afterActivation.control, {
      decisionId: decisionBeforeDrift.decisionId,
    }),
    { code: "POLICY_REPLAY_FAILED" },
  );
});
