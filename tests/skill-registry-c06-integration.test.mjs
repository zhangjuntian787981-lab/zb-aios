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
import { createC13C06Authorizer } from "../lib/c13-c06-authorizer.mjs";
import {
  createC13SyntheticSkillCatalog,
} from "../lib/c13-synthetic-skill-catalog.mjs";
import {
  createMemorySkillRegistryStore,
  createSkillRegistry,
} from "../lib/skill-registry.mjs";

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const HUMAN_ID = "prn_018f0000-0000-7000-8000-000000000001";
const HUMAN_B = "prn_018f0000-0000-7000-8000-000000000003";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_ID = "dlg_018f0000-0000-7000-8000-000000000020";
const STORE_ID = "01J00000000000000000000000";
const MODEL_ID = "01J00000000000000000000001";
const TEMPLATE_REF = "fixture://c06/policy-release/baseline-v1";
const NOW = "2026-07-26T15:30:00.000Z";

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
const C13_RAW = await load(
  "implementation/p1/c13/synthetic-skill-catalog.v1.json",
);
const C13_REPORT_BUNDLE_BYTES = await readFile(
  new URL(
    "../implementation/p1/c13/synthetic-evaluation-reports.v1.json",
    import.meta.url,
  ),
);
const C13_CATALOG = createC13SyntheticSkillCatalog(
  C13_RAW,
  C13_REPORT_BUNDLE_BYTES,
);

function deterministicIds(start) {
  let value = start;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

function tupleKey(tuple) {
  return `${tuple.user}|${tuple.relation}|${tuple.object}`;
}

function identity(humanPrincipalId) {
  const purposeRef = "synthetic://c06/purpose/manage";
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

async function harness(
  humanPrincipalId,
  allowedResourceFields = Object.keys(
    C13_RAW.tenants[0].authorizationResources,
  ),
) {
  const log = [];
  const tenantRegistry = {
    async admitNewRequest({ tenantId }) {
      log.push("admit");
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
      log.push("identity");
      return identity(humanPrincipalId);
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
  const resources = C13_RAW.tenants[0].authorizationResources;
  const manageTuples = tupleBundle.filter(({ object }) =>
    object.endsWith("--manage"),
  );
  const readTuples = tupleBundle.filter(({ object }) =>
    object.endsWith("--read"),
  );
  for (const field of allowedResourceFields) {
    const surfaceTuples =
      field === "resolveResourceId" ? readTuples : manageTuples;
    for (const tuple of surfaceTuples) {
      activeTuples.add(
        tupleKey({
          ...tuple,
          object: `protected_resource:${resources[field]}`,
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
    async resolveResource({ tenantId, tenantKind, surface, resourceId }) {
      log.push(`resource:${surface}:${resourceId}`);
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
    idempotencyKey: "c13-c06-stage",
    correlationId: "c13-c06-stage",
  });
  const ready = await authorizationFacade.execute(control, {
    kind: "RECORD_POLICY_PROJECTION",
    tenantId: TENANT_ID,
    policyReleaseId: staged.policyReleaseId,
    projectionOperationId: "c13-c06-project-operation",
    outcome: "READY",
    openFgaStoreId: STORE_ID,
    authorizationModelId: MODEL_ID,
    tupleBundleSha256: hashSyntheticPolicyTuples(tupleBundle),
    fixtureReportRef: "evidence://c06/c13-integration",
    fixtureReportSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    fixturePassCount: 30,
    fixtureFailCount: 0,
    reasonRef: null,
    idempotencyKey: "c13-c06-project",
    correlationId: "c13-c06-project",
  });
  await authorizationFacade.execute(control, {
    kind: "ACTIVATE_POLICY_RELEASE",
    tenantId: TENANT_ID,
    policyReleaseId: ready.policyReleaseId,
    expectedActivationVersion: 0,
    reasonRef: "policy://c06/c13-integration/activate",
    idempotencyKey: "c13-c06-activate",
    correlationId: "c13-c06-activate",
  });
  const memory = createMemorySkillRegistryStore();
  let writeCount = 0;
  const store = {
    ...memory,
    async runCommand(...args) {
      writeCount += 1;
      return memory.runCommand(...args);
    },
  };
  const registry = createSkillRegistry({
    tenantRegistry,
    stablePrincipalRegistry,
    authorizer: createC13C06Authorizer({ authorizationFacade }),
    store,
    catalog: C13_CATALOG,
    idFactory: deterministicIds(500),
    clock: () => NOW,
  });
  log.length = 0;
  return {
    log,
    registry,
    writes: () => writeCount,
  };
}

function request(release) {
  return {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_ID,
    idempotencyKey: "c13-real-c06-submit",
    correlationId: "c13-real-c06-submit",
    command: {
      kind: "SUBMIT_RELEASE",
      skillId: null,
      expectedLatestSequence: 0,
      manifest: release.manifest,
      contentSha256: release.contentSha256,
      sourceReviewRef: release.sourceReviewRef,
      sourceReviewSha256: release.sourceReviewSha256,
    },
  };
}

const serverContext = {
  synthetic: true,
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT_ID,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: ACTOR_ID,
};

test("C13 reaches storage only after a real C06 MANAGE allow", async () => {
  const value = await harness(HUMAN_ID);
  const result = await value.registry.execute(
    serverContext,
    request(C13_RAW.tenants[0].releases[0]),
  );
  assert.equal(result.lifecycleState, "SUBMITTED");
  assert.equal(value.writes(), 1);
  assert.equal(
    value.log.includes(
      "resource:MANAGE:synthetic-tenant-northstar-fasteners--skill-submit",
    ),
    true,
  );
  assert.deepEqual(
    value.log.filter((entry) => entry === "identity" || entry === "admit"),
    [
      "identity",
      "admit",
      "identity",
      "admit",
      "identity",
      "identity",
      "admit",
    ],
  );
});

test("a C06 submit grant cannot authorize C13 approval or publication", async () => {
  const value = await harness(HUMAN_ID, ["submitResourceId"]);
  const submitted = await value.registry.execute(
    serverContext,
    request(C13_RAW.tenants[0].releases[0]),
  );
  const common = {
    releaseId: submitted.releaseId,
    expectedReleaseVersion: submitted.releaseVersion,
  };
  for (const command of [
    {
      kind: "APPROVE_RELEASE",
      ...common,
      approvedContentSha256: submitted.contentSha256,
      approvedEvaluationReportRef:
        "test://c13/not-reached/evaluation",
      approvedEvaluationReportSha256:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      approvedHumanBaselineDecisionRef:
        "test://c13/not-reached/human-baseline",
      approvedHumanBaselineDecisionSha256:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    },
    {
      kind: "PUBLISH_RELEASE",
      ...common,
      channel: "PILOT",
      expectedChannelGeneration: 0,
      expectedCurrentReleaseId: null,
    },
  ]) {
    await assert.rejects(
      value.registry.execute(serverContext, {
        sessionToken: "synthetic-session-token",
        delegationId: DELEGATION_ID,
        idempotencyKey: `c13-submit-only-${command.kind}`,
        correlationId: `c13-submit-only-${command.kind}`,
        command,
      }),
      { code: "ACCESS_DENIED" },
    );
  }
  assert.equal(value.writes(), 1);
});

test("C13 real C06 denial occurs before Skill storage", async () => {
  const value = await harness(HUMAN_B);
  await assert.rejects(
    value.registry.execute(
      serverContext,
      request(C13_RAW.tenants[0].releases[0]),
    ),
    { code: "ACCESS_DENIED" },
  );
  assert.equal(value.writes(), 0);
});
