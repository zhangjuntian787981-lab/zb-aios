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
  createC02C06Authorizer,
} from "../lib/c02-c06-authorizer.mjs";
import {
  createTenantGovernanceBff,
} from "../lib/tenant-governance-bff.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const FIXTURE = "synthetic-tenant-northstar-fasteners";
const HUMAN =
  "prn_018f0000-0000-7000-8000-000000000001";
const UNAUTHORIZED_HUMAN =
  "prn_018f0000-0000-7000-8000-000000000003";
const WORKLOAD =
  "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const STORE_ID = "01J00000000000000000000000";
const MODEL_ID = "01J00000000000000000000001";
const TEMPLATE_REF = "fixture://c06/policy-release/baseline-v1";
const RESOURCE = "c02-tenant-config-general";
const MUTATION_RESOURCE = "c02-quota-model-token";
const NOW = "2026-07-26T16:00:00.000Z";

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

function identity(humanPrincipalId) {
  return {
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    identityAccountId:
      "sia_018f0000-0000-7000-8000-000000000030",
    identityLinkId:
      "lnk_018f0000-0000-7000-8000-000000000031",
    sessionId: "ses_018f0000-0000-7000-8000-000000000032",
    humanSubject: {
      principalId: humanPrincipalId,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: WORKLOAD,
      principalType: "AGENT",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c06/purpose/manage",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: humanPrincipalId,
        delegatePrincipalId: WORKLOAD,
        purposeRef: "synthetic://c06/purpose/manage",
        lifecycleVersion: 1,
        expiresAt: "2026-07-27T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
  };
}

async function createHarness(humanPrincipalId) {
  const tenantRegistry = {
    async admitNewRequest({ tenantId }) {
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
      return identity(humanPrincipalId);
    },
  };
  const tupleBundle = buildSyntheticPolicyTuples({
    catalog: C06_CATALOG,
    templateRef: TEMPLATE_REF,
    fixtureId: FIXTURE,
    principalIdsByFixtureRef: {
      [`fixture://${FIXTURE}/principals/ava`]: HUMAN,
      [`fixture://${FIXTURE}/principals/assistant-agent`]: WORKLOAD,
    },
  });
  const activeTuples = new Set(tupleBundle.map(tupleKey));
  for (const resourceId of [RESOURCE, MUTATION_RESOURCE]) {
    for (const tuple of tupleBundle.filter(({ object }) =>
      object.endsWith("--manage")
    )) {
      activeTuples.add(
        tupleKey({
          ...tuple,
          object: `protected_resource:${resourceId}`,
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
        fixtureId: FIXTURE,
      };
    },
    async resolveResource({ tenantId, tenantKind, surface, resourceId }) {
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
    tenantId: TENANT,
    templateRef: TEMPLATE_REF,
    idempotencyKey: "c02-c06-stage",
    correlationId: "c02-c06-stage",
  });
  const ready = await authorizationFacade.execute(control, {
    kind: "RECORD_POLICY_PROJECTION",
    tenantId: TENANT,
    policyReleaseId: staged.policyReleaseId,
    projectionOperationId: "c02-c06-project",
    outcome: "READY",
    openFgaStoreId: STORE_ID,
    authorizationModelId: MODEL_ID,
    tupleBundleSha256: hashSyntheticPolicyTuples(tupleBundle),
    fixtureReportRef: "evidence://c06/c02-integration",
    fixtureReportSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    fixturePassCount: 30,
    fixtureFailCount: 0,
    reasonRef: null,
    idempotencyKey: "c02-c06-project",
    correlationId: "c02-c06-project",
  });
  await authorizationFacade.execute(control, {
    kind: "ACTIVATE_POLICY_RELEASE",
    tenantId: TENANT,
    policyReleaseId: ready.policyReleaseId,
    expectedActivationVersion: 0,
    reasonRef: "policy://c06/c02-integration/activate",
    idempotencyKey: "c02-c06-activate",
    correlationId: "c02-c06-activate",
  });
  let coreCalls = 0;
  const authorizer = createC02C06Authorizer({ authorizationFacade });
  const bff = createTenantGovernanceBff({
    authorizer,
    confirmationVerifier: {
      async consume(scope, input) {
        return {
          trustSource: "TRUSTED_CONFIRMATION_CONSUMPTION",
          tenantId: scope.tenantId,
          humanPrincipalId: scope.humanPrincipalId,
          operationId: input.operationId,
          resourceId: input.resourceId,
          expectedVersion: input.expectedVersion,
          candidateRef: input.candidateRef,
          candidateSha256: input.candidateSha256,
          confirmationRef: input.confirmationRef,
          confirmationSha256: input.confirmationSha256,
          consumptionId: "c02-c06-confirmation-consumption",
          consumedAt: "2026-07-26T16:00:00.000Z",
          evidenceRef:
            "evidence://product-core/confirmation-consumption/c02-c06",
          expiresAt: "2026-07-26T16:05:00.000Z",
          singleUse: true,
          status: "CONSUMED",
        };
      },
    },
    auditVerifier: {
      async verify(scope, input) {
        return {
          trustSource: "C18_IMMUTABLE_EVENT_READBACK",
          tenantId: scope.tenantId,
          auditRef: input.auditRef,
          eventId: "aev_synthetic_c02_c06",
          sequence: 1,
          eventHash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          payloadSha256:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          commandSha256: input.commandSha256,
          resultSha256: input.resultSha256,
        };
      },
    },
    corePort: {
      async read(scope, command) {
        coreCalls += 1;
        return {
          schemaVersion: "c02-governance-view.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: 1,
          items: [
            {
              settingRef: "synthetic://tenant/config/general",
              status: "ACTIVE",
              version: 1,
            },
          ],
          evidenceRefs: ["evidence://c03/tenant/config/1"],
          allowedActions: ["TENANT_CONFIG_VIEW"],
        };
      },
      async mutate(scope, command) {
        coreCalls += 1;
        return {
          schemaVersion: "c02-governance-mutation-receipt.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: command.expectedVersion + 1,
          candidateRef: command.candidateRef,
          candidateSha256: command.candidateSha256,
          status: "COMMITTED",
          auditRef: "evidence://c18/event/c02-c06-mutation",
          evidenceRefs: [
            command.confirmationVerification.evidenceRef,
          ],
        };
      },
    },
  });
  return {
    bff,
    coreCalls: () => coreCalls,
  };
}

const serverContext = {
  synthetic: true,
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: WORKLOAD,
};

const request = {
  sessionToken: "synthetic-session",
  delegationId: DELEGATION,
  correlationId: "corr-c02-real-c06",
  operationId: "TENANT_CONFIG_VIEW",
  resourceId: RESOURCE,
};
const mutationRequest = {
  sessionToken: "synthetic-session",
  delegationId: DELEGATION,
  correlationId: "corr-c02-real-c06-mutation",
  idempotencyKey: "idem-c02-real-c06-mutation",
  operationId: "QUOTA_CHANGE",
  resourceId: MUTATION_RESOURCE,
  expectedVersion: 3,
  candidateRef: "synthetic://c02/candidate/quota-4",
  candidateSha256:
    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
  confirmation: {
    confirmationRef: "evidence://c02/confirmation/quota-4",
    confirmationSha256:
      "sha256:265fda051a361885335a7bbe52e3e213d2ae099fb29b0551c793602d69c8db3c",
    confirmedByHumanPrincipalId: HUMAN,
    evidenceRefs: ["evidence://c02/review/quota-4"],
  },
};

test("C02 reaches Product Core only after a real C06 MANAGE allow", async () => {
  const harness = await createHarness(HUMAN);
  const result = await harness.bff.read(serverContext, request);
  assert.equal(result.authorityOwner, "PRODUCT_CORE");
  assert.match(
    result.authorizationEvidenceRef,
    /^evidence:\/\/c06\//,
  );
  assert.equal(harness.coreCalls(), 1);
});

test("a real C06 denial stops C02 before Product Core", async () => {
  const harness = await createHarness(UNAUTHORIZED_HUMAN);
  await assert.rejects(
    harness.bff.read(serverContext, request),
    (error) => error.code === "ACCESS_DENIED",
  );
  assert.equal(harness.coreCalls(), 0);
});

test("a C02 write reaches Product Core only after a fresh real C06 allow", async () => {
  const harness = await createHarness(HUMAN);
  const result = await harness.bff.mutate(
    serverContext,
    mutationRequest,
  );
  assert.equal(result.status, "COMMITTED");
  assert.equal(result.auditRef, "evidence://c18/event/c02-c06-mutation");
  assert.equal(harness.coreCalls(), 1);
});
