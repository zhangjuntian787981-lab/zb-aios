import assert from "node:assert/strict";
import test from "node:test";
import {
  createTenantGovernanceBff,
} from "../lib/tenant-governance-bff.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const HUMAN =
  "prn_018f0000-0000-7000-8000-000000000001";
const WORKLOAD =
  "prn_018f0000-0000-7000-8000-000000000002";

function context(overrides = {}) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: WORKLOAD,
    ...overrides,
  };
}

function request(overrides = {}) {
  return {
    sessionToken: "synthetic-session",
    delegationId: "synthetic-delegation",
    correlationId: "corr-c02-1",
    operationId: "TENANT_CONFIG_VIEW",
    resourceId: "c02-tenant-config-general",
    ...overrides,
  };
}

function mutationRequest(overrides = {}) {
  return {
    sessionToken: "synthetic-session",
    delegationId: "synthetic-delegation",
    correlationId: "corr-c02-mutate-1",
    idempotencyKey: "idem-c02-quota-4",
    operationId: "QUOTA_CHANGE",
    resourceId: "c02-quota-model-token",
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
    ...overrides,
  };
}

function authorization(serverContext, input, descriptor) {
  return {
    trustSource: "C06_BOUND_DECISION_EVIDENCE",
    tenantId: serverContext.tenantId,
    humanPrincipalId: HUMAN,
    workloadActorPrincipalId:
      serverContext.workloadActorPrincipalId,
    decisionId: "dec-c02-1",
    evidenceRef: "evidence://c06/decision/c02-1",
    policyVersion: "c06-policy-1",
    resourceId: input.resourceId,
    operationId: descriptor.operationId,
  };
}

function trustedConfirmationVerifier(overrides = {}) {
  return {
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
        consumptionId: "c02-confirmation-consumption-1",
        consumedAt: "2026-07-26T12:00:00.000Z",
        evidenceRef:
          "evidence://product-core/confirmation-consumption/c02-1",
        expiresAt: "2026-07-26T12:05:00.000Z",
        singleUse: true,
        status: "CONSUMED",
        ...overrides,
      };
    },
  };
}

test("C02 rejects a missing trusted confirmation verifier at startup", () => {
  assert.throws(
    () =>
      createTenantGovernanceBff({
        authorizer: { async enforce() {} },
        corePort: {
          async read() {},
          async mutate() {},
        },
      }),
    (error) => error.code === "INVALID_CONFIGURATION",
  );
});

test("authorized Tenant administrator sees only the Core-approved view", async () => {
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: trustedConfirmationVerifier(),
    corePort: {
      async read(scope, command) {
        return {
          schemaVersion: "c02-governance-view.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: 3,
          items: [
            {
              settingRef: "synthetic://tenant/config/general",
              status: "ACTIVE",
              version: 3,
            },
          ],
          evidenceRefs: ["evidence://c03/tenant/config/3"],
          allowedActions: [
            "TENANT_CONFIG_VIEW",
            "TENANT_CONFIG_CHANGE",
          ],
        };
      },
      async mutate() {
        throw new Error("not used");
      },
    },
  });

  const result = await bff.read(context(), request());

  assert.equal(result.tenantId, TENANT);
  assert.equal(result.operationId, "TENANT_CONFIG_VIEW");
  assert.equal(result.authorityOwner, "PRODUCT_CORE");
  assert.equal(
    result.authorizationEvidenceRef,
    "evidence://c06/decision/c02-1",
  );
  assert.deepEqual(result.allowedActions, [
    "TENANT_CONFIG_VIEW",
    "TENANT_CONFIG_CHANGE",
  ]);
  assert.deepEqual(result.items, [
    {
      settingRef: "synthetic://tenant/config/general",
      status: "ACTIVE",
      version: 3,
    },
  ]);
  assert.equal(Object.isFrozen(result), true);
});

test("every frozen management view is returned only through the Core seam", async () => {
  const cases = [
    [
      "PRINCIPAL_ROLE_VIEW",
      {
        principalRef: "synthetic://c05/principal/1",
        principalType: "HUMAN",
        status: "ACTIVE",
        roleRef: "synthetic://c06/role/tenant-admin",
      },
    ],
    [
      "KNOWLEDGE_RELEASE_VIEW",
      {
        knowledgeRef: "synthetic://c10/knowledge/1",
        status: "PUBLISHED",
        version: 2,
      },
    ],
    [
      "SKILL_RELEASE_VIEW",
      {
        skillRef: "synthetic://c13/skill/1",
        releaseChannel: "PILOT",
        status: "PUBLISHED",
        contentSha256:
          "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      },
    ],
    [
      "QUOTA_VIEW",
      {
        quotaRef: "synthetic://c19/quota/model-token",
        metric: "MODEL_TOKENS",
        limit: 1000,
        used: 25,
        unit: "TOKENS",
      },
    ],
    [
      "FORMAL_ARTIFACT_VIEW",
      {
        artifactRef: "synthetic://c08/artifact/1",
        artifactSha256:
          "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        status: "APPROVED",
        decisionRef: "evidence://c15/decision/1",
      },
    ],
    [
      "AUDIT_VIEW",
      {
        auditRef: "evidence://c18/event/1",
        eventType: "SYNTHETIC_CONFIG_CHANGED",
        occurredAt: "2026-07-26T12:00:00.000Z",
        traceId: "trace-c02-audit-1",
      },
    ],
    [
      "CONNECTOR_STAGE_VIEW",
      {
        connectorRef: "synthetic://c17/template/erp",
        templateRef: "synthetic://c17/template/erp",
        stage: "C0_DISABLED",
        status: "DISABLED",
      },
    ],
    [
      "OBSERVABILITY_VIEW",
      {
        metricRef: "synthetic://c19/metric/error-rate",
        value: 0,
        unit: "PERCENT",
        status: "HEALTHY",
      },
    ],
  ];
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: trustedConfirmationVerifier(),
    corePort: {
      async read(scope, command) {
        const item = cases.find(([operationId]) =>
          operationId === command.operationId
        )?.[1];
        return {
          schemaVersion: "c02-governance-view.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: 1,
          items: [item],
          evidenceRefs: ["evidence://c02/view/1"],
          allowedActions: [command.operationId],
        };
      },
      async mutate() {
        throw new Error("not used");
      },
    },
  });

  for (const [operationId, item] of cases) {
    const result = await bff.read(
      context(),
      request({
        operationId,
        resourceId: `c02-view-${operationId.toLowerCase().replaceAll("_", "-")}`,
      }),
    );
    assert.deepEqual(result.items, [item]);
    assert.equal(result.authorityOwner, "PRODUCT_CORE");
  }
});

test("a high-risk change needs a bound second confirmation before Core commit", async () => {
  let receivedCommand;
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        assert.equal(descriptor.mode, "WRITE");
        assert.equal(descriptor.operationId, "C02_QUOTA_CHANGE");
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: trustedConfirmationVerifier(),
    corePort: {
      async read() {
        throw new Error("not used");
      },
      async mutate(scope, command) {
        receivedCommand = command;
        return {
          schemaVersion: "c02-governance-mutation-receipt.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: 4,
          candidateRef: command.candidateRef,
          candidateSha256: command.candidateSha256,
          status: "COMMITTED",
          auditRef: "evidence://c18/event/quota-4",
          evidenceRefs: [
            command.confirmation.confirmationRef,
            command.confirmationVerification.evidenceRef,
            "evidence://c19/quota/4",
          ],
        };
      },
    },
  });

  const result = await bff.mutate(context(), mutationRequest());

  assert.deepEqual(receivedCommand, {
    idempotencyKey: "idem-c02-quota-4",
    operationId: "QUOTA_CHANGE",
    resourceId: "c02-quota-model-token",
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
    confirmationVerification: {
      trustSource: "TRUSTED_CONFIRMATION_CONSUMPTION",
      tenantId: TENANT,
      humanPrincipalId: HUMAN,
      operationId: "QUOTA_CHANGE",
      resourceId: "c02-quota-model-token",
      expectedVersion: 3,
      candidateRef: "synthetic://c02/candidate/quota-4",
      candidateSha256:
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      confirmationRef: "evidence://c02/confirmation/quota-4",
      confirmationSha256:
        "sha256:265fda051a361885335a7bbe52e3e213d2ae099fb29b0551c793602d69c8db3c",
      consumptionId: "c02-confirmation-consumption-1",
      consumedAt: "2026-07-26T12:00:00.000Z",
      evidenceRef:
        "evidence://product-core/confirmation-consumption/c02-1",
      expiresAt: "2026-07-26T12:05:00.000Z",
      singleUse: true,
      status: "CONSUMED",
    },
  });
  assert.equal(result.status, "COMMITTED");
  assert.equal(result.resourceVersion, 4);
  assert.equal(result.auditRef, "evidence://c18/event/quota-4");
  assert.equal(result.authorityOwner, "PRODUCT_CORE");
  assert.equal(
    result.authorizationEvidenceRef,
    "evidence://c06/decision/c02-1",
  );
});

test("the frozen mutation catalog covers only governed management changes", async () => {
  const confirmationHashes = {
    TENANT_CONFIG_CHANGE:
      "sha256:2671d2b99d951ea1fe715c8d2e7ab3ab5f7ec2869b1b255b11a7a4b58b1ef1d9",
    PRINCIPAL_ROLE_CHANGE:
      "sha256:49148d48fdbb38ced1fba74f328f7bf7b7db3e4837207a3c2a8f852ee6686cd7",
    KNOWLEDGE_RELEASE_CHANGE:
      "sha256:088fd82b837d82632de267d67cb18ab23cb96111634fb079a3ebecc4505caf92",
    SKILL_RELEASE_CHANGE:
      "sha256:e2606a44edd4c0f4bbf28fd1011432b436bf47c3d1c772ec74141cc0dec535c3",
    QUOTA_CHANGE:
      "sha256:38be1c6bfe33ef7d4019b1a4dd47d9f449b6090ebe83956479a3db7c7a794eca",
    FORMAL_ARTIFACT_PUBLISH:
      "sha256:19a9766d4f0ec8a68a56716b299b9b7a8136c3277ed04ef7dc97239cf4094249",
    CONNECTOR_STAGE_CHANGE:
      "sha256:89b62c52089697256154b7482ac9a4f81308b9b766978554dfa0d47b924f6326",
  };
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: trustedConfirmationVerifier(),
    corePort: {
      async read() {
        throw new Error("not used");
      },
      async mutate(scope, command) {
        return {
          schemaVersion: "c02-governance-mutation-receipt.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: 4,
          candidateRef: command.candidateRef,
          candidateSha256: command.candidateSha256,
          status: "COMMITTED",
          auditRef: "evidence://c18/event/1",
          evidenceRefs: [
            command.confirmationVerification.evidenceRef,
          ],
        };
      },
    },
  });

  for (const [operationId, confirmationSha256] of Object.entries(
    confirmationHashes,
  )) {
    const result = await bff.mutate(
      context(),
      mutationRequest({
        operationId,
        resourceId: "c02-resource-1",
        candidateRef: "synthetic://c02/candidate/1",
        candidateSha256:
          "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        confirmation: {
          confirmationRef: "evidence://c02/confirmation/1",
          confirmationSha256,
          confirmedByHumanPrincipalId: HUMAN,
          evidenceRefs: ["evidence://c02/review/1"],
        },
      }),
    );
    assert.equal(result.operationId, operationId);
  }
});

test("incomplete server authorization evidence never reaches Product Core", async () => {
  for (const authorizationOverride of [
    { decisionId: "" },
    { policyVersion: "" },
  ]) {
    let coreCalls = 0;
    const bff = createTenantGovernanceBff({
      authorizer: {
        async enforce(serverContext, input, descriptor) {
          return {
            ...authorization(serverContext, input, descriptor),
            ...authorizationOverride,
          };
        },
      },
      confirmationVerifier: trustedConfirmationVerifier(),
      corePort: {
        async read() {
          coreCalls += 1;
          throw new Error("must not run");
        },
        async mutate() {
          coreCalls += 1;
          throw new Error("must not run");
        },
      },
    });

    await assert.rejects(
      bff.read(context(), request()),
      (error) => error.code === "ACCESS_DENIED",
    );
    assert.equal(coreCalls, 0);
  }
});

test("cross-Tenant authorization evidence never reaches Product Core", async () => {
  let coreCalls = 0;
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return {
          ...authorization(serverContext, input, descriptor),
          tenantId:
            "stn_018f0000-0000-7000-8000-000000000099",
        };
      },
    },
    confirmationVerifier: trustedConfirmationVerifier(),
    corePort: {
      async read() {
        coreCalls += 1;
        throw new Error("must not run");
      },
      async mutate() {
        coreCalls += 1;
        throw new Error("must not run");
      },
    },
  });

  await assert.rejects(
    bff.read(context(), request()),
    (error) => error.code === "ACCESS_DENIED",
  );
  assert.equal(coreCalls, 0);
});

test("a tampered confirmed candidate never reaches Product Core", async () => {
  let coreCalls = 0;
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: trustedConfirmationVerifier(),
    corePort: {
      async read() {
        throw new Error("not used");
      },
      async mutate() {
        coreCalls += 1;
        throw new Error("must not run");
      },
    },
  });

  await assert.rejects(
    bff.mutate(
      context(),
      mutationRequest({
        candidateRef: "synthetic://c02/candidate/tampered",
      }),
    ),
    (error) => error.code === "CONFIRMATION_INVALID",
  );
  assert.equal(coreCalls, 0);
});

test("a correct caller hash cannot replace a trusted confirmation record", async () => {
  let coreCalls = 0;
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: {
      async consume() {
        throw new Error("confirmation record not found");
      },
    },
    corePort: {
      async read() {
        throw new Error("not used");
      },
      async mutate() {
        coreCalls += 1;
        throw new Error("must not run");
      },
    },
  });

  await assert.rejects(
    bff.mutate(
      context(),
      mutationRequest({
        confirmation: {
          confirmationRef:
            "evidence://untrusted-caller/self-asserted-confirmation",
          confirmationSha256:
            "sha256:ba18ac7d727370c0dec4904a9dcdab2fbe3433f0da549e1055196f19b71896f3",
          confirmedByHumanPrincipalId: HUMAN,
          evidenceRefs: [
            "evidence://untrusted-caller/self-reviewed",
          ],
        },
      }),
    ),
    (error) => error.code === "CONFIRMATION_INVALID",
  );
  assert.equal(coreCalls, 0);
});

test("trusted confirmation consumption is one-time and must be unexpired", async () => {
  let consumed = false;
  let coreCalls = 0;
  const oneTimeVerifier = {
    async consume(scope, input) {
      if (consumed) throw new Error("already consumed");
      consumed = true;
      return trustedConfirmationVerifier().consume(scope, input);
    },
  };
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: oneTimeVerifier,
    corePort: {
      async read() {
        throw new Error("not used");
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
          auditRef: "evidence://c18/event/one-time",
          evidenceRefs: [
            command.confirmationVerification.evidenceRef,
          ],
        };
      },
    },
  });

  assert.equal(
    (await bff.mutate(context(), mutationRequest())).status,
    "COMMITTED",
  );
  await assert.rejects(
    bff.mutate(context(), mutationRequest()),
    (error) => error.code === "CONFIRMATION_INVALID",
  );
  assert.equal(coreCalls, 1);

  const expired = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: trustedConfirmationVerifier({
      consumedAt: "2026-07-26T12:05:00.000Z",
      expiresAt: "2026-07-26T12:00:00.000Z",
    }),
    corePort: {
      async read() {
        throw new Error("not used");
      },
      async mutate() {
        coreCalls += 1;
        throw new Error("must not run");
      },
    },
  });
  await assert.rejects(
    expired.mutate(context(), mutationRequest()),
    (error) => error.code === "CONFIRMATION_INVALID",
  );
  assert.equal(coreCalls, 1);
});

test("evidence-free or private employee data cannot enter an administrator view", async () => {
  let coreCalls = 0;
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: trustedConfirmationVerifier(),
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
          evidenceRefs: [],
          allowedActions: [command.operationId],
        };
      },
      async mutate() {
        throw new Error("not used");
      },
    },
  });

  await assert.rejects(
    bff.read(context(), request()),
    (error) => error.code === "CORE_RESULT_INVALID",
  );
  for (const operationId of [
    "PRIVATE_SESSION_VIEW",
    "PRIVATE_MEMORY_VIEW",
    "AUDIT_CHANGE",
  ]) {
    await assert.rejects(
      bff.read(context(), request({ operationId })),
      (error) => error.code === "OPERATION_NOT_ALLOWED",
    );
  }
  assert.equal(coreCalls, 1);
});

test("a mutation receipt without a C18-namespaced audit reference is rejected", async () => {
  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(serverContext, input, descriptor);
      },
    },
    confirmationVerifier: trustedConfirmationVerifier(),
    corePort: {
      async read() {
        throw new Error("not used");
      },
      async mutate(scope, command) {
        return {
          schemaVersion: "c02-governance-mutation-receipt.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: 4,
          candidateRef: command.candidateRef,
          candidateSha256: command.candidateSha256,
          status: "COMMITTED",
          auditRef: "synthetic://c02/audit/not-immutable",
          evidenceRefs: [
            command.confirmationVerification.evidenceRef,
          ],
        };
      },
    },
  });

  await assert.rejects(
    bff.mutate(context(), mutationRequest()),
    (error) => error.code === "CORE_RESULT_INVALID",
  );
});
