import assert from "node:assert/strict";
import test from "node:test";
import {
  ToolGatewayError,
  createMemoryToolGatewayStore,
  createSyntheticToolCatalog,
  createToolGateway,
  toolGatewaySha256,
} from "../lib/tool-gateway.mjs";
import {
  createC16EphemeralCredentialBroker,
} from "../lib/c16-ephemeral-credential-broker.mjs";
import {
  createC16SyntheticToolAdapter,
} from "../lib/c16-synthetic-tool-adapter.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const OTHER_TENANT =
  "stn_018f0000-0000-7000-8000-000000000011";
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const NOW = "2026-07-26T12:00:00.000Z";

const catalogDocument = {
  schemaVersion: "1.0.0",
  catalogVersion: "c16-synthetic-tools-v1",
  phase: "P1_SYNTHETIC_ONLY",
  dataClassification: "SYNTHETIC_ONLY",
  connectorStage: "C0_MOCK",
  networkAccess: "DISABLED",
  operations: [
    {
      operationId: "synthetic.approval.status.get",
      title: "Synthetic approval status",
      purpose: "Read one fictitious approval status.",
      mode: "READ_ONLY",
      adapterVersion: "c0-approval-v1",
      authorizationResourceSuffix: "approval-status-get",
      audience: "c16-c0-approval",
      parameterSchema: {
        type: "object",
        additionalProperties: false,
        required: ["approvalRef"],
        properties: {
          approvalRef: {
            type: "string",
            pattern: "^SYN-APR-[0-9]{4}$",
            maxLength: 12,
          },
        },
      },
    },
    {
      operationId: "synthetic.erp.order.get",
      title: "Synthetic ERP order",
      purpose: "Read one fictitious order.",
      mode: "READ_ONLY",
      adapterVersion: "c0-erp-v1",
      authorizationResourceSuffix: "erp-order-get",
      audience: "c16-c0-erp",
      parameterSchema: {
        type: "object",
        additionalProperties: false,
        required: ["orderRef"],
        properties: {
          orderRef: {
            type: "string",
            pattern: "^SYN-ORD-[0-9]{4}$",
            maxLength: 12,
          },
        },
      },
    },
    {
      operationId: "synthetic.bi.metric.get",
      title: "Synthetic BI metric",
      purpose: "Read one fictitious metric.",
      mode: "READ_ONLY",
      adapterVersion: "c0-bi-v1",
      authorizationResourceSuffix: "bi-metric-get",
      audience: "c16-c0-bi",
      parameterSchema: {
        type: "object",
        additionalProperties: false,
        required: ["metricCode", "period"],
        properties: {
          metricCode: {
            type: "string",
            enum: ["on_time_delivery_rate", "open_order_count"],
            maxLength: 32,
          },
          period: {
            type: "string",
            enum: ["2026-Q1", "2026-Q2"],
            maxLength: 7,
          },
        },
      },
    },
  ],
};

const fixtureDocument = {
  schemaVersion: "1.0.0",
  fixtureVersion: "c16-synthetic-tool-fixtures-v1",
  phase: "P1_SYNTHETIC_ONLY",
  dataClassification: "SYNTHETIC_ONLY",
  networkAccess: "DISABLED",
  records: [
    {
      tenantId: TENANT,
      operationId: "synthetic.approval.status.get",
      lookup: { approvalRef: "SYN-APR-0001" },
      result: {
        approvalRef: "SYN-APR-0001",
        status: "PENDING_SYNTHETIC_REVIEW",
      },
    },
    {
      tenantId: TENANT,
      operationId: "synthetic.erp.order.get",
      lookup: { orderRef: "SYN-ORD-0001" },
      result: {
        orderRef: "SYN-ORD-0001",
        state: "SYNTHETIC_OPEN",
      },
    },
    {
      tenantId: TENANT,
      operationId: "synthetic.bi.metric.get",
      lookup: {
        metricCode: "on_time_delivery_rate",
        period: "2026-Q1",
      },
      result: {
        metricCode: "on_time_delivery_rate",
        period: "2026-Q1",
        value: 96.5,
        unit: "PERCENT",
      },
    },
  ],
};

function deterministicIds() {
  let value = 100;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

function identity({
  tenantId = TENANT,
  humanEpoch = 1,
  actorId = ACTOR,
  actorEpoch = 1,
  delegationId = DELEGATION,
} = {}) {
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId: "ses_synthetic",
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: humanEpoch,
    },
    workloadActor: {
      principalId: actorId,
      principalType: "AGENT",
      lifecycleVersion: 1,
      securityEpoch: actorEpoch,
    },
    purposeRef: "synthetic://c06/purpose/tool-call",
    delegationChain: [
      {
        delegationId,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: actorId,
        purposeRef: "synthetic://c06/purpose/tool-call",
        lifecycleVersion: 1,
        expiresAt: "2031-01-01T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
  };
}

function context(tenantId = TENANT, actorId = ACTOR) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: actorId,
  };
}

function envelope(overrides = {}) {
  return {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    correlationId: "c16-correlation",
    operationId: "synthetic.approval.status.get",
    ...overrides,
  };
}

function createHarness({
  identities = [identity(), identity()],
  store = null,
  adapter = null,
  broker = null,
} = {}) {
  const log = [];
  let identityIndex = 0;
  let currentIdentity = null;
  const mutable = { now: NOW };
  const catalog = createSyntheticToolCatalog(catalogDocument);
  const selectedStore = store ?? createMemoryToolGatewayStore();
  const selectedBroker =
    broker ??
    createC16EphemeralCredentialBroker({
      idFactory: deterministicIds(),
      clock: () => mutable.now,
    });
  const selectedAdapter =
    adapter ??
    createC16SyntheticToolAdapter({
      credentialBroker: selectedBroker,
      fixtureDocument,
    });
  const gateway = createToolGateway({
    tenantRegistry: {
      async admitNewRequest(value) {
        log.push("admit");
        return {
          tenantId: value.tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
          trustSource: "VERIFIED_SERVER_CONTEXT",
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity(_serverContext, request) {
        log.push("identity");
        assert.equal(request.expectedTenantId, TENANT);
        currentIdentity =
          identities[Math.min(identityIndex, identities.length - 1)];
        identityIndex += 1;
        return structuredClone(currentIdentity);
      },
    },
    authorizer: {
      async enforce(serverContext, request, descriptor) {
        log.push("authorize");
        assert.equal(descriptor.surface, "TOOL_CALL");
        assert.equal(descriptor.path, "tool-gateway");
        const binding = {
          humanPrincipalId: currentIdentity.humanSubject.principalId,
          humanSecurityEpoch: currentIdentity.humanSubject.securityEpoch,
          workloadActorPrincipalId:
            currentIdentity.workloadActor.principalId,
          workloadActorSecurityEpoch:
            currentIdentity.workloadActor.securityEpoch,
          leafDelegationId:
            currentIdentity.delegationChain.at(-1).delegationId,
          delegationChainSha256: toolGatewaySha256(
            currentIdentity.delegationChain,
          ),
          purposeRef: currentIdentity.purposeRef,
        };
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          operationId: descriptor.operationId,
          decisionId: `decision-${descriptor.operationId}`,
          evidenceRef: `evidence://c16/${descriptor.operationId}`,
          policyVersion: "c06-v1",
          tenantId: serverContext.tenantId,
          surface: "TOOL_CALL",
          resourceId: request.resourceId,
          ...binding,
        };
      },
    },
    catalog,
    store: selectedStore,
    credentialBroker: selectedBroker,
    adapter: selectedAdapter,
    idFactory: deterministicIds(),
    clock: () => mutable.now,
  });
  return {
    gateway,
    catalog,
    store: selectedStore,
    broker: selectedBroker,
    adapter: selectedAdapter,
    log,
    mutable,
  };
}

test("discover reauthorizes a named closed-catalog operation", async () => {
  const { gateway, log } = createHarness();
  const result = await gateway.discover(context(), envelope());
  assert.equal(
    result.operation.operationId,
    "synthetic.approval.status.get",
  );
  assert.equal(result.operation.mode, "READ_ONLY");
  assert.equal(result.authorizationGranted, false);
  assert.deepEqual(log, ["identity", "authorize", "identity", "admit"]);
});

test("confirm canonicalizes only the operation's declared parameters", async () => {
  const { gateway, log } = createHarness();
  const result = await gateway.confirm(
    context(),
    envelope({
      idempotencyKey: "confirm-approval-1",
      params: { approvalRef: "SYN-APR-0001" },
    }),
  );
  assert.match(
    result.confirmationId,
    /^tcf_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
  );
  assert.equal(result.operationId, "synthetic.approval.status.get");
  assert.match(result.normalizedParamSha256, /^sha256:[a-f0-9]{64}$/);
  assert.equal(result.expiresAt, "2026-07-26T12:02:00.000Z");
  assert.equal(Object.hasOwn(result, "params"), false);
  assert.equal(Object.hasOwn(result, "authorization"), false);
  assert.deepEqual(log, ["identity", "authorize", "identity", "admit"]);

  const replay = await gateway.confirm(
    context(),
    envelope({
      idempotencyKey: "confirm-approval-1",
      params: { approvalRef: "SYN-APR-0001" },
    }),
  );
  assert.equal(replay.confirmationId, result.confirmationId);
  assert.equal(replay.replayed, true);
});

test("confirm rejects undeclared execution surfaces and unsafe objects", async () => {
  const { gateway } = createHarness();
  for (const request of [
    envelope({
      idempotencyKey: "unsafe-1",
      params: {
        approvalRef: "SYN-APR-0001",
        url: "synthetic.invalid",
      },
    }),
    envelope({
      idempotencyKey: "unsafe-2",
      params: { approvalRef: "SYN-APR-0001", sql: "SELECT 1" },
    }),
    envelope({
      idempotencyKey: "unsafe-3",
      params: { approvalRef: "SYN-APR-0001", command: "whoami" },
    }),
    envelope({
      idempotencyKey: "unsafe-4",
      params: JSON.parse(
        '{"approvalRef":"SYN-APR-0001","__proto__":{"admin":true}}',
      ),
    }),
    envelope({
      idempotencyKey: "unsafe-5",
      params: { approvalRef: "SYN-APR-0001" },
      stageToken: "not-authority",
    }),
  ]) {
    await assert.rejects(
      gateway.confirm(context(), request),
      (error) =>
        error instanceof ToolGatewayError &&
        error.code === "INVALID_INPUT",
    );
  }
});

test("a C05 identity change during confirm fails before persistence", async () => {
  const { gateway, store } = createHarness({
    identities: [
      identity(),
      identity({ humanEpoch: 2 }),
    ],
  });
  await assert.rejects(
    gateway.confirm(
      context(),
      envelope({
        idempotencyKey: "changed-identity",
        params: { approvalRef: "SYN-APR-0001" },
      }),
    ),
    (error) =>
      error instanceof ToolGatewayError &&
      error.code === "ACTION_IDENTITY_CHANGED",
  );
  assert.equal(store.snapshot().confirmations.length, 0);
});

async function confirmedApproval(harness, overrides = {}) {
  return harness.gateway.confirm(
    context(),
    envelope({
      idempotencyKey: "confirm-for-execution",
      params: { approvalRef: "SYN-APR-0001" },
      ...overrides,
    }),
  );
}

function executeRequest(confirmation, overrides = {}) {
  return envelope({
    idempotencyKey: "execute-approval-1",
    confirmationId: confirmation.confirmationId,
    confirmationSha256: confirmation.confirmationSha256,
    expectedParamSha256: confirmation.normalizedParamSha256,
    ...overrides,
  });
}

test("execute binds current authority and returns one deterministic C0 receipt", async () => {
  const harness = createHarness();
  const confirmation = await confirmedApproval(harness);
  const result = await harness.gateway.execute(
    context(),
    executeRequest(confirmation),
  );
  assert.equal(result.status, "SUCCEEDED");
  assert.deepEqual(result.result, {
    approvalRef: "SYN-APR-0001",
    status: "PENDING_SYNTHETIC_REVIEW",
  });
  assert.equal(result.receipt.networkRequestCount, 0);
  assert.equal(result.receipt.externalEffectCount, 0);
  assert.match(result.receipt.receiptSha256, /^sha256:[a-f0-9]{64}$/);
  assert.equal(harness.adapter.snapshot().newExecutionCount, 1);
  assert.equal(harness.broker.snapshot().activeCapabilityCount, 0);

  const replay = await harness.gateway.execute(
    context(),
    executeRequest(confirmation),
  );
  assert.deepEqual(replay.result, result.result);
  assert.equal(replay.callId, result.callId);
  assert.equal(replay.replayed, true);
  assert.equal(harness.adapter.snapshot().newExecutionCount, 1);
});

test("execute rejects changed identity, Tenant, hashes, expiry, and confirmation replay before Adapter use", async () => {
  const changed = createHarness({
    identities: [
      identity(),
      identity(),
      identity({ actorEpoch: 2 }),
      identity({ actorEpoch: 2 }),
    ],
  });
  const changedConfirmation = await confirmedApproval(changed);
  await assert.rejects(
    changed.gateway.execute(
      context(),
      executeRequest(changedConfirmation),
    ),
    (error) =>
      error instanceof ToolGatewayError &&
      error.code === "CONFIRMATION_AUTHORITY_CHANGED",
  );
  assert.equal(changed.adapter.snapshot().newExecutionCount, 0);

  const harness = createHarness();
  const confirmation = await confirmedApproval(harness);
  for (const request of [
    executeRequest(confirmation, {
      confirmationSha256:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }),
    executeRequest(confirmation, {
      expectedParamSha256:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    }),
  ]) {
    await assert.rejects(
      harness.gateway.execute(context(), request),
      (error) =>
        error instanceof ToolGatewayError &&
        error.code === "CONFIRMATION_TAMPERED",
    );
  }
  await assert.rejects(
    harness.gateway.execute(
      context(OTHER_TENANT),
      {
        ...executeRequest(confirmation),
        correlationId: "other-tenant",
      },
    ),
    (error) =>
      error instanceof ToolGatewayError &&
      ["ACTION_IDENTITY_INVALID", "CONFIRMATION_NOT_FOUND"].includes(
        error.code,
      ),
  );
  harness.mutable.now = "2026-07-26T12:02:01.000Z";
  await assert.rejects(
    harness.gateway.execute(
      context(),
      executeRequest(confirmation, { correlationId: "expired" }),
    ),
    (error) =>
      error instanceof ToolGatewayError &&
      error.code === "CONFIRMATION_EXPIRED",
  );
  assert.equal(harness.adapter.snapshot().newExecutionCount, 0);

  const replayHarness = createHarness();
  const replayConfirmation = await confirmedApproval(replayHarness);
  await replayHarness.gateway.execute(
    context(),
    executeRequest(replayConfirmation),
  );
  await assert.rejects(
    replayHarness.gateway.execute(
      context(),
      executeRequest(replayConfirmation, {
        idempotencyKey: "different-execution-key",
      }),
    ),
    (error) =>
      error instanceof ToolGatewayError &&
      error.code === "CONFIRMATION_REPLAYED",
  );
  assert.equal(replayHarness.adapter.snapshot().newExecutionCount, 1);
});

test("execute uses request idempotency and never returns the private capability", async () => {
  const harness = createHarness();
  const confirmation = await confirmedApproval(harness);
  const first = await harness.gateway.execute(
    context(),
    executeRequest(confirmation),
  );
  await assert.rejects(
    harness.gateway.execute(
      context(),
      executeRequest(confirmation, {
        operationId: "synthetic.erp.order.get",
      }),
    ),
    (error) =>
      error instanceof ToolGatewayError &&
      ["CONFIRMATION_TAMPERED", "IDEMPOTENCY_CONFLICT"].includes(
        error.code,
      ),
  );
  const serialized = JSON.stringify({
    response: first,
    store: harness.store.snapshot(),
    adapter: harness.adapter.snapshot(),
    broker: harness.broker.snapshot(),
  });
  assert.equal(serialized.includes("cap_"), false);
  assert.equal(serialized.includes("opaque"), false);
});

test("a lost completion ACK retries without a second Adapter execution", async () => {
  const memory = createMemoryToolGatewayStore();
  let loseAck = true;
  const store = {
    ...memory,
    async completeExecution(...args) {
      const result = await memory.completeExecution(...args);
      if (loseAck) {
        loseAck = false;
        throw new Error("synthetic completion ACK loss");
      }
      return result;
    },
  };
  const harness = createHarness({ store });
  const confirmation = await confirmedApproval(harness);
  await assert.rejects(
    harness.gateway.execute(
      context(),
      executeRequest(confirmation),
    ),
    (error) =>
      error instanceof ToolGatewayError &&
      error.code === "STORE_UNAVAILABLE",
  );
  assert.equal(harness.adapter.snapshot().newExecutionCount, 1);

  const replay = await harness.gateway.execute(
    context(),
    executeRequest(confirmation),
  );
  assert.equal(replay.status, "SUCCEEDED");
  assert.equal(replay.replayed, true);
  assert.equal(harness.adapter.snapshot().newExecutionCount, 1);
});
