import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  ModelGatewayError,
  createMemoryModelGatewayStore,
  createModelGateway,
  createSyntheticModelCatalog,
  modelGatewaySha256,
} from "../lib/model-gateway.mjs";
import { createC14SyntheticDataPolicyResolver } from "../lib/c14-synthetic-data-policy.mjs";
import { createC14SyntheticModelProvider } from "../lib/c14-synthetic-model-provider.mjs";

const TENANT_NORTHSTAR =
  "stn_018f0000-0000-7000-8000-000000000010";
const TENANT_BLUE_HARBOR =
  "stn_018f0000-0000-7000-8000-000000000011";
const HUMAN_A = "prn_018f0000-0000-7000-8000-000000000001";
const HUMAN_B = "prn_018f0000-0000-7000-8000-000000000003";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const NOW = "2026-07-26T12:00:00.000Z";

const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c14/synthetic-model-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const dataPolicyDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c14/synthetic-data-policy-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function withoutCanary(document = catalogDocument) {
  const clone = structuredClone(document);
  for (const policy of clone.tenantPolicies) {
    policy.canaryPercent = 0;
  }
  return clone;
}

function deterministicIds() {
  let counter = 100;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function identity(tenantId, humanPrincipalId = HUMAN_A) {
  return {
    tenantId,
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
      principalId: ACTOR,
      principalType: "AGENT",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c06/purpose/manage",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: humanPrincipalId,
        delegatePrincipalId: ACTOR,
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

function serverContext(tenantId = TENANT_BLUE_HARBOR) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
}

function request(overrides = {}) {
  return {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION,
    idempotencyKey: "c14-route-1",
    correlationId: "c14-correlation-1",
    taskRef: "synthetic://c14/tasks/chat",
    inputRef: "synthetic://c14/inputs/public-summary",
    inputSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ...overrides,
  };
}

function createHarness({
  tenantId = TENANT_BLUE_HARBOR,
  identityPrincipals = [HUMAN_A, HUMAN_A],
  authorizationHuman = null,
  failedProviderIds = [],
  catalogDocument: customCatalog = withoutCanary(),
  providerInvoker = null,
  store = null,
  dataPolicyResolver = null,
} = {}) {
  const log = [];
  let identityCall = 0;
  let latestIdentity = null;
  const catalog = createSyntheticModelCatalog(customCatalog);
  const provider =
    providerInvoker ??
    createC14SyntheticModelProvider({ failedProviderIds });
  const tenantRegistry = {
    async admitNewRequest({ tenantId: requested, expectedTenantKind }) {
      log.push("admit");
      assert.equal(requested, tenantId);
      assert.equal(expectedTenantKind, "SYNTHETIC");
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 2,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const stablePrincipalRegistry = {
    async resolveActionIdentity(context, value) {
      log.push("identity");
      assert.equal(context.workloadActorPrincipalId, ACTOR);
      assert.equal(value.expectedTenantId, tenantId);
      latestIdentity = identity(
        tenantId,
        identityPrincipals[
          Math.min(identityCall, identityPrincipals.length - 1)
        ],
      );
      identityCall += 1;
      return latestIdentity;
    },
  };
  const authorizer = {
    async enforce(context, value, descriptor) {
      log.push("authorize");
      assert.equal(context.tenantId, tenantId);
      assert.equal(descriptor.surface, "MANAGE");
      const bound = identity(
        tenantId,
        authorizationHuman ?? latestIdentity.humanSubject.principalId,
      );
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        decisionId: "decision-c14",
        evidenceRef: "evidence://c14/decision",
        policyVersion: "c06-model-1",
        tenantId,
        surface: "MANAGE",
        resourceId: value.resourceId,
        humanPrincipalId: bound.humanSubject.principalId,
        humanSecurityEpoch: bound.humanSubject.securityEpoch,
        workloadActorPrincipalId: ACTOR,
        workloadActorSecurityEpoch: 1,
        leafDelegationId: DELEGATION,
        delegationChainSha256: modelGatewaySha256(
          bound.delegationChain,
        ),
        purposeRef: bound.purposeRef,
      };
    },
  };
  const gateway = createModelGateway({
    tenantRegistry,
    stablePrincipalRegistry,
    authorizer,
    catalog,
    dataPolicyResolver:
      dataPolicyResolver ??
      createC14SyntheticDataPolicyResolver(dataPolicyDocument),
    providerInvoker: provider,
    store: store ?? createMemoryModelGatewayStore(),
    idFactory: deterministicIds(),
    clock: () => NOW,
  });
  return { gateway, provider, log, catalog };
}

test("C14 selects the highest-quality policy-allowed regional model", async () => {
  const { gateway, provider } = createHarness();
  const result = await gateway.route(
    serverContext(),
    request(),
  );
  assert.equal(
    result.route.selectedModel.modelRef,
    "synthetic://c14/models/cloud-eu-quality",
  );
  assert.equal(result.route.selectedModel.plane, "CLOUD");
  assert.equal(result.route.status, "SUCCEEDED");
  assert.equal(result.route.version, 2);
  assert.equal(result.route.attemptReceipts.length, 1);
  assert.equal(provider.calls.length, 1);
  assert.equal(
    Object.hasOwn(provider.calls[0], "prompt"),
    false,
  );
  assert.equal(
    Object.hasOwn(provider.calls[0], "inputBody"),
    false,
  );
  assert.match(result.route.responseSha256, /^sha256:[0-9a-f]{64}$/);
  assert.ok(result.route.costMicrousd >= 0);
});

test("C14 authorization and trusted identity precede Tenant admission and provider use", async () => {
  const { gateway, provider, log } = createHarness();
  await gateway.route(serverContext(), request());
  assert.deepEqual(log, [
    "identity",
    "authorize",
    "identity",
    "admit",
  ]);
  assert.equal(provider.calls.length, 1);
});

test("C14 confidential input stays local and cannot silently fall back to cloud", async () => {
  const { gateway, provider } = createHarness();
  const result = await gateway.route(
    serverContext(),
    request({
      inputRef: "synthetic://c14/inputs/confidential-analysis",
      inputSha256:
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    }),
  );
  assert.equal(result.route.requiredPlane, "LOCAL_ONLY");
  assert.equal(result.route.selectedModel.plane, "LOCAL");
  assert.ok(
    result.route.evaluatedCandidates
      .filter((entry) => entry.plane === "CLOUD")
      .every(
        (entry) =>
          !entry.allowed && entry.reasons.includes("LOCAL_ONLY"),
      ),
  );
  assert.ok(provider.calls.every((call) => !call.providerId.includes("cloud")));
});

test("C14 fallback remains inside the already-filtered allowed set", async () => {
  const { gateway, provider } = createHarness({
    failedProviderIds: ["c14-mock-cloud-eu"],
  });
  const result = await gateway.route(
    serverContext(),
    request(),
  );
  assert.deepEqual(
    result.route.attemptReceipts.map((entry) => entry.outcome),
    ["FAILED", "SUCCEEDED"],
  );
  assert.equal(
    result.route.selectedModel.modelRef,
    "synthetic://c14/models/local-secure",
  );
  const allowed = new Set(
    result.route.evaluatedCandidates
      .filter((entry) => entry.allowed)
      .map((entry) => entry.modelRef),
  );
  assert.ok(
    provider.calls.every((call) => allowed.has(call.modelRef)),
  );
});

test("C14 local-only exhaustion never invokes a cloud provider", async () => {
  const { gateway, provider } = createHarness({
    failedProviderIds: [
      "c14-mock-local-secure",
      "c14-mock-local-fast",
      "c14-mock-local-long",
      "c14-mock-local-canary",
    ],
  });
  await assert.rejects(
    gateway.route(
      serverContext(),
      request({
        inputRef: "synthetic://c14/inputs/confidential-analysis",
        inputSha256:
          "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      }),
    ),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "ALLOWED_MODELS_EXHAUSTED",
  );
  assert.ok(provider.calls.length > 0);
  assert.ok(provider.calls.every((call) => !call.providerId.includes("cloud")));
});

test("C14 fails before provider use when hard filters leave no model", async () => {
  const customCatalog = withoutCanary();
  const policy = customCatalog.tenantPolicies.find(
    (entry) => entry.tenantId === TENANT_BLUE_HARBOR,
  );
  policy.allowedModelRefs = [
    "synthetic://c14/models/cloud-eu-quality",
  ];
  const { gateway, provider } = createHarness({
    catalogDocument: customCatalog,
  });
  await assert.rejects(
    gateway.route(
      serverContext(),
      request({
        inputRef: "synthetic://c14/inputs/confidential-analysis",
        inputSha256:
          "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      }),
    ),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "NO_ALLOWED_MODEL",
  );
  assert.equal(provider.calls.length, 0);
});

test("C14 long-context hard filter runs before invocation", async () => {
  const { gateway, provider } = createHarness({
    tenantId: TENANT_NORTHSTAR,
  });
  const result = await gateway.route(
    serverContext(TENANT_NORTHSTAR),
    request({
      taskRef: "synthetic://c14/tasks/long-context",
      inputRef: "synthetic://c14/inputs/long-handbook",
      inputSha256:
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    }),
  );
  assert.equal(
    result.route.selectedModel.modelRef,
    "synthetic://c14/models/local-long-context",
  );
  assert.deepEqual(
    provider.calls.map((call) => call.modelRef),
    ["synthetic://c14/models/local-long-context"],
  );
  const secure = result.route.evaluatedCandidates.find(
    (entry) =>
      entry.modelRef === "synthetic://c14/models/local-secure",
  );
  assert.ok(secure.reasons.includes("CONTEXT_TOO_SMALL"));
});

test("C14 canary selection is deterministic and still policy-filtered", async () => {
  const customCatalog = structuredClone(catalogDocument);
  for (const policy of customCatalog.tenantPolicies) {
    policy.canaryPercent = 100;
  }
  const firstHarness = createHarness({
    catalogDocument: customCatalog,
  });
  const secondHarness = createHarness({
    catalogDocument: customCatalog,
  });
  const first = await firstHarness.gateway.route(
    serverContext(),
    request(),
  );
  const second = await secondHarness.gateway.route(
    serverContext(),
    request(),
  );
  assert.equal(
    first.route.selectedModel.modelRef,
    "synthetic://c14/models/local-canary",
  );
  assert.equal(
    second.route.selectedModel.modelRef,
    first.route.selectedModel.modelRef,
  );
  assert.equal(
    first.route.evaluatedCandidates.find(
      (entry) =>
        entry.modelRef ===
        "synthetic://c14/models/cloud-us-quality",
    ),
    undefined,
  );
});

test("C14 retry returns one route and one provider side effect", async () => {
  const { gateway, provider } = createHarness();
  const first = await gateway.route(serverContext(), request());
  const second = await gateway.route(serverContext(), request());
  assert.equal(second.duplicate, true);
  assert.equal(second.route.routeId, first.route.routeId);
  assert.equal(second.route.responseSha256, first.route.responseSha256);
  assert.equal(provider.calls.length, 1);
});

test("C14 idempotency key cannot be reused for another request", async () => {
  const { gateway } = createHarness();
  await gateway.route(serverContext(), request());
  await assert.rejects(
    gateway.route(
      serverContext(),
      request({
        inputRef: "synthetic://c14/inputs/internal-analysis",
        inputSha256:
          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      }),
    ),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("C14 fails closed on C05 identity switch and never invokes a provider", async () => {
  const { gateway, provider } = createHarness({
    identityPrincipals: [HUMAN_A, HUMAN_B],
  });
  await assert.rejects(
    gateway.route(serverContext(), request()),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "ACTION_IDENTITY_CHANGED",
  );
  assert.equal(provider.calls.length, 0);
});

test("C14 rejects a C06 decision bound to another Human", async () => {
  const { gateway, provider } = createHarness({
    authorizationHuman: HUMAN_B,
  });
  await assert.rejects(
    gateway.route(serverContext(), request()),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "AUTHORIZATION_BINDING_MISMATCH",
  );
  assert.equal(provider.calls.length, 0);
});

test("C14 rejects unknown inputs before provider invocation", async () => {
  const { gateway, provider } = createHarness();
  await assert.rejects(
    gateway.route(
      serverContext(),
      request({
        inputRef: "synthetic://c14/inputs/not-registered",
      }),
    ),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "DATA_POLICY_UNAVAILABLE",
  );
  assert.equal(provider.calls.length, 0);
});

test("C14 rejects caller-selected provider and data classification fields", async () => {
  const { gateway, provider } = createHarness();
  await assert.rejects(
    gateway.route(serverContext(), {
      ...request(),
      providerId: "c14-mock-cloud-us",
      dataClassification: "PUBLIC",
    }),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "INVALID_INPUT",
  );
  assert.equal(provider.calls.length, 0);
});

test("C14 validates provider receipt binding before persistence", async () => {
  const provider = {
    calls: [],
    async invoke(value) {
      this.calls.push(value);
      return {
        trustSource: "C14_C0_MOCK_PROVIDER_RECEIPT",
        effectKey: value.effectKey,
        providerId: "c14-mock-cloud-us",
        modelRef: value.modelRef,
        modelVersion: value.modelVersion,
        outcome: "SUCCEEDED",
        responseRef: "test://c14/provider-results/forged",
        responseSha256:
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        inputTokens: 1,
        outputTokens: 1,
        providerRequestId: "forged",
      };
    },
  };
  const { gateway } = createHarness({ providerInvoker: provider });
  await assert.rejects(
    gateway.route(serverContext(), request()),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "PROVIDER_RECEIPT_INVALID",
  );
});

test("C14 rejects provider usage above the frozen reservation", async () => {
  const provider = {
    async invoke(value) {
      return {
        trustSource: "C14_C0_MOCK_PROVIDER_RECEIPT",
        effectKey: value.effectKey,
        providerId: value.providerId,
        modelRef: value.modelRef,
        modelVersion: value.modelVersion,
        outcome: "SUCCEEDED",
        responseRef: "test://c14/provider-results/oversized",
        responseSha256:
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        inputTokens: 999999,
        outputTokens: 1,
        providerRequestId: "oversized",
      };
    },
  };
  const { gateway } = createHarness({ providerInvoker: provider });
  await assert.rejects(
    gateway.route(serverContext(), request()),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "PROVIDER_RECEIPT_INVALID",
  );
});

test("C14 concurrent quota reservation admits at most one oversized route", async () => {
  const customCatalog = withoutCanary();
  customCatalog.tenantPolicies.find(
    (policy) => policy.tenantId === TENANT_BLUE_HARBOR,
  ).dailyTokenLimit = 900;
  const { gateway } = createHarness({
    catalogDocument: customCatalog,
  });
  const outcomes = await Promise.allSettled([
    gateway.route(
      serverContext(),
      request({ idempotencyKey: "quota-route-a" }),
    ),
    gateway.route(
      serverContext(),
      request({
        idempotencyKey: "quota-route-b",
        correlationId: "quota-b",
      }),
    ),
  ]);
  assert.equal(
    outcomes.filter((entry) => entry.status === "fulfilled").length,
    1,
  );
  const rejection = outcomes.find(
    (entry) => entry.status === "rejected",
  );
  assert.equal(rejection.reason.code, "QUOTA_EXCEEDED");
});

test("C14 catalog rejects unknown tenant model bindings and duplicate tasks", () => {
  const unknown = withoutCanary();
  unknown.tenantPolicies[0].allowedModelRefs.push(
    "synthetic://c14/models/missing",
  );
  assert.throws(
    () => createSyntheticModelCatalog(unknown),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "INVALID_CATALOG",
  );

  const duplicate = withoutCanary();
  duplicate.tasks.push(structuredClone(duplicate.tasks[0]));
  assert.throws(
    () => createSyntheticModelCatalog(duplicate),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "INVALID_CATALOG",
  );

  const driftedModel = withoutCanary();
  driftedModel.models[0].qualityScore += 1;
  assert.throws(
    () => createSyntheticModelCatalog(driftedModel),
    (error) =>
      error instanceof ModelGatewayError &&
      error.code === "INVALID_CATALOG",
  );
});

test("C14 catalog digest is deterministic and changes with a policy change", () => {
  const first = createSyntheticModelCatalog(withoutCanary());
  const second = createSyntheticModelCatalog(withoutCanary());
  assert.equal(first.digest, second.digest);
  const changed = withoutCanary();
  changed.tenantPolicies[0].dailyTokenLimit += 1;
  assert.notEqual(
    first.digest,
    createSyntheticModelCatalog(changed).digest,
  );
});
