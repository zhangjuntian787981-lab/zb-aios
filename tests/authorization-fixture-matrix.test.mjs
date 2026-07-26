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

const HUMAN_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_ID = "dlg_018f0000-0000-7000-8000-000000000020";
const STORE_ID = "01J00000000000000000000000";
const MODEL_ID = "01J00000000000000000000001";
const TEMPLATE_REF = "fixture://c06/policy-release/baseline-v1";
const TENANT_IDS = Object.freeze({
  "synthetic-tenant-northstar-fasteners":
    "stn_018f0000-0000-7000-8000-000000000010",
  "synthetic-tenant-blue-harbor-tools":
    "stn_018f0000-0000-7000-8000-000000000011",
  "synthetic-tenant-cedar-field-components":
    "stn_018f0000-0000-7000-8000-000000000012",
});

async function load(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

const fixtures = await load(
  "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
);
const catalog = createSyntheticAuthorizationCatalog({
  policyCatalog: await load(
    "implementation/p1/c06/synthetic-policy-catalog.v1.json",
  ),
  protectedOperations: await load(
    "implementation/p1/c06/protected-operations.v1.json",
  ),
  fixtures,
  model: await load(
    "implementation/p1/c06/openfga/authorization-model.v1.json",
  ),
});

function deterministicIds() {
  let counter = 500;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function otherTenantId(tenantId) {
  return Object.values(TENANT_IDS).find((value) => value !== tenantId);
}

async function createSurfaceHarness(operationFixture) {
  const tenantId = TENANT_IDS[operationFixture.tenant_fixture_id];
  const operation = catalog.operation(operationFixture.surface);
  const tupleBundleSha256 = hashSyntheticPolicyTuples(
    buildSyntheticPolicyTuples({
      catalog,
      templateRef: TEMPLATE_REF,
      fixtureId: operationFixture.tenant_fixture_id,
      principalIdsByFixtureRef: {
        [`fixture://${operationFixture.tenant_fixture_id}/principals/ava`]:
          HUMAN_ID,
        [`fixture://${operationFixture.tenant_fixture_id}/principals/assistant-agent`]:
          ACTOR_ID,
      },
    }),
  );
  const resourceId = `${operationFixture.tenant_fixture_id}--${operationFixture.surface
    .toLowerCase()
    .replaceAll("_", "-")}`;
  const mutable = { scenario: "ALL_FACTORS_VALID" };
  const store = createMemoryAuthorizationStore();
  const tenantRegistry = {
    async admitNewRequest() {
      if (mutable.scenario === "TENANT_SUSPENDED") {
        throw Object.assign(new Error("Synthetic Tenant is not active."), {
          code: "TENANT_NOT_ACTIVE",
        });
      }
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 1,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const stablePrincipalRegistry = {
    async resolveActionIdentity() {
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        authorizationStatus:
          mutable.scenario === "IDENTITY_INVALIDATED"
            ? "INVALIDATED"
            : "NOT_EVALUATED",
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
        purposeRef:
          mutable.scenario === "WRONG_PURPOSE_FOR_SURFACE"
            ? operation.purpose_ref === "synthetic://c06/purpose/read"
              ? "synthetic://c06/purpose/manage"
              : "synthetic://c06/purpose/read"
            : operation.purpose_ref,
        delegationChain: [
          {
            delegationId: DELEGATION_ID,
            delegatorPrincipalId: HUMAN_ID,
            delegatePrincipalId: ACTOR_ID,
            purposeRef: operation.purpose_ref,
            lifecycleVersion: 1,
          },
        ],
      };
    },
  };
  const facade = createAuthorizationFacade({
    store,
    tenantRegistry,
    stablePrincipalRegistry,
    policyCatalog: catalog,
    async resolveTenantFixture() {
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        fixtureId: operationFixture.tenant_fixture_id,
      };
    },
    async resolveResource() {
      return {
        tenantId:
          mutable.scenario === "RESOURCE_OTHER_TENANT"
            ? otherTenantId(tenantId)
            : tenantId,
        tenantKind: "SYNTHETIC",
        resourceType: operation.resource_type,
        resourceId,
        state: "ACTIVE",
        authorizationVersion: 1,
        trustSource: "VERIFIED_RESOURCE_CONTEXT",
      };
    },
    pdpFactory() {
      return {
        async check({ tupleKey }) {
          if (mutable.scenario === "PDP_UNAVAILABLE") {
            throw Object.assign(new Error("Synthetic PDP timeout."), {
              code: "OPENFGA_TIMEOUT",
            });
          }
          const missing =
            (mutable.scenario === "HUMAN_RELATION_MISSING" &&
              tupleKey.relation === operation.human_relation) ||
            (mutable.scenario === "ACTOR_RELATION_MISSING" &&
              tupleKey.relation === operation.actor_relation) ||
            (mutable.scenario === "PURPOSE_RELATION_MISSING" &&
              tupleKey.relation === operation.purpose_relation);
          return {
            allowed: !missing,
            storeId:
              mutable.scenario === "MODEL_OR_STORE_MISMATCH"
                ? "01J00000000000000000000009"
                : STORE_ID,
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
    clock: () => "2026-07-26T00:00:00.000Z",
    idFactory: deterministicIds(),
  });
  const control = {
    actorId: "synthetic-authorization-admin",
    projectionTrustSource: "VERIFIED_PROJECTION_WORKER",
  };
  const staged = await facade.execute(control, {
    kind: "STAGE_SYNTHETIC_POLICY_RELEASE",
    tenantId,
    templateRef: TEMPLATE_REF,
    idempotencyKey: `stage-${operationFixture.surface}`,
    correlationId: `stage-${operationFixture.surface}`,
  });
  const ready = await facade.execute(control, {
    kind: "RECORD_POLICY_PROJECTION",
    tenantId,
    policyReleaseId: staged.policyReleaseId,
    projectionOperationId: `project-${operationFixture.surface}`,
    outcome: "READY",
    openFgaStoreId: STORE_ID,
    authorizationModelId: MODEL_ID,
    tupleBundleSha256,
    fixtureReportRef: `evidence://c06/matrix/${operationFixture.surface}`,
    fixtureReportSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    fixturePassCount: 30,
    fixtureFailCount: 0,
    reasonRef: null,
    idempotencyKey: `project-${operationFixture.surface}`,
    correlationId: `project-${operationFixture.surface}`,
  });
  await facade.execute(control, {
    kind: "ACTIVATE_POLICY_RELEASE",
    tenantId,
    policyReleaseId: ready.policyReleaseId,
    expectedActivationVersion: 0,
    reasonRef: "policy://c06/matrix/initial-activation",
    idempotencyKey: `activate-${operationFixture.surface}`,
    correlationId: `activate-${operationFixture.surface}`,
  });

  return {
    facade,
    mutable,
    serverContext: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId,
      surface: operationFixture.surface,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: ACTOR_ID,
    },
    request: {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION_ID,
      resourceId,
      correlationId: `matrix-${operationFixture.surface}`,
    },
  };
}

test("all 60 frozen C06 Allow/Deny fixtures execute with their expected outcome", async () => {
  const actual = [];
  for (const operationFixture of fixtures.operations) {
    const harness = await createSurfaceHarness(operationFixture);
    for (const scenario of fixtures.scenarios) {
      harness.mutable.scenario = scenario.scenario;
      try {
        const decision = await harness.facade.decide(
          harness.serverContext,
          {
            ...harness.request,
            correlationId: `${harness.request.correlationId}-${scenario.scenario}`,
          },
        );
        actual.push({
          surface: operationFixture.surface,
          scenario: scenario.scenario,
          effect: decision.effect,
          reasonCode: decision.reasonCode,
        });
      } catch (error) {
        actual.push({
          surface: operationFixture.surface,
          scenario: scenario.scenario,
          effect: "DENY",
          reasonCode: error.code,
        });
      }
    }
  }

  assert.equal(actual.length, 60);
  for (const result of actual) {
    const expected = fixtures.scenarios.find(
      ({ scenario }) => scenario === result.scenario,
    );
    assert.equal(
      result.effect,
      expected.expected,
      `${result.surface}/${result.scenario} effect`,
    );
    assert.equal(
      result.reasonCode,
      expected.reason_code,
      `${result.surface}/${result.scenario} reason`,
    );
  }
});
