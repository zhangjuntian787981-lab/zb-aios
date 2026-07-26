import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createMemoryObservabilityStore,
  createObservabilityService,
  createSyntheticObservabilityCatalog,
  parseTraceContext,
} from "../lib/c19-observability.mjs";
import {
  C19UpstreamEmitterError,
  createC19SyntheticUpstreamEmitter,
  createC19UpstreamBindingCatalog,
} from "../lib/c19-upstream-emitter.mjs";
import {
  createMemoryModelGatewayStore,
  createModelGateway,
  createSyntheticModelCatalog,
  modelGatewaySha256,
} from "../lib/model-gateway.mjs";
import {
  createC14SyntheticDataPolicyResolver,
} from "../lib/c14-synthetic-data-policy.mjs";
import {
  createC14SyntheticModelProvider,
} from "../lib/c14-synthetic-model-provider.mjs";
import {
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
import {
  createAuditEvidenceService,
  createMemoryAuditEvidenceStore,
  createSyntheticAuditEvidenceCatalog,
  createSyntheticAuditEvidenceRegistry,
} from "../lib/c18-audit-evidence.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const IDENTITY_CONTEXT =
  "fixture://c19/northstar/identity-context/ava";
const NOW = "2026-07-26T12:00:00.000Z";
const TRACE =
  "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

async function json(path) {
  return JSON.parse(await readFile(new URL(path, import.meta.url), "utf8"));
}

const modelCatalogDocument = await json(
  "../implementation/p1/c14/synthetic-model-catalog.v1.json",
);
const modelDataPolicyDocument = await json(
  "../implementation/p1/c14/synthetic-data-policy-fixtures.v1.json",
);
const toolCatalogDocument = await json(
  "../implementation/p1/c16/operation-catalog.v1.json",
);
const toolFixtureDocument = await json(
  "../implementation/p1/c16/synthetic-tool-fixtures.v1.json",
);
const auditCatalogDocument = await json(
  "../implementation/p1/c18/synthetic-evidence-catalog.v1.json",
);
const auditRegistryDocument = await json(
  "../implementation/p1/c18/synthetic-evidence-registry.v1.json",
);
const observabilityCatalogDocument = await json(
  "../implementation/p1/c19/synthetic-observability-catalog.v1.json",
);
const bindingDocument = await json(
  "../implementation/p1/c19/upstream-artifact-bindings.v1.json",
);

function ids(start) {
  let value = start;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

function upstreamContext() {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
}

function c19Context() {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT,
    identityContextRef: IDENTITY_CONTEXT,
  };
}

function request() {
  return {
    traceparent: TRACE,
    tracestate: "vendor=synth",
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    correlationId: "c19-upstream",
    idempotencyPrefix: "c19-upstream",
    model: {
      taskRef: "synthetic://c14/tasks/chat",
      inputRef: "synthetic://c14/inputs/public-summary",
      inputSha256:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    tool: {
      operationId: "synthetic.approval.status.get",
      params: { approvalRef: "SYN-APR-0001" },
    },
  };
}

function actionIdentity({ purposeRef, actorType }) {
  return {
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId:
      actorType === "SERVICE"
        ? "session-synthetic"
        : "ses_synthetic",
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: actorType,
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef,
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: ACTOR,
        purposeRef,
        lifecycleVersion: 1,
        expiresAt:
          actorType === "SERVICE"
            ? "2027-07-26T00:00:00.000Z"
            : "2031-01-01T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    ...(actorType === "SERVICE"
      ? {}
      : { authorizationStatus: "NOT_EVALUATED" }),
  };
}

function tenantAdmission() {
  return {
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    trustSource: "VERIFIED_SERVER_CONTEXT",
  };
}

function createModelHarness() {
  const catalog = createSyntheticModelCatalog(modelCatalogDocument);
  const provider = createC14SyntheticModelProvider();
  let currentIdentity;
  const gateway = createModelGateway({
    tenantRegistry: {
      async admitNewRequest() {
        return tenantAdmission();
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        currentIdentity = actionIdentity({
          purposeRef: "synthetic://c06/purpose/manage",
          actorType: "AGENT",
        });
        return currentIdentity;
      },
    },
    authorizer: {
      async enforce(_context, value) {
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          decisionId: "d",
          evidenceRef: "e",
          policyVersion: "p",
          tenantId: TENANT,
          surface: "MANAGE",
          resourceId: value.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: ACTOR,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: DELEGATION,
          delegationChainSha256: modelGatewaySha256(
            currentIdentity.delegationChain,
          ),
          purposeRef: currentIdentity.purposeRef,
        };
      },
    },
    catalog,
    dataPolicyResolver: createC14SyntheticDataPolicyResolver(
      modelDataPolicyDocument,
    ),
    providerInvoker: provider,
    store: createMemoryModelGatewayStore(),
    idFactory: ids(0),
    clock: () => NOW,
  });
  return { gateway, provider };
}

function createToolHarness() {
  const catalog = createSyntheticToolCatalog(toolCatalogDocument);
  const store = createMemoryToolGatewayStore();
  const broker = createC16EphemeralCredentialBroker({
    idFactory: ids(100),
    clock: () => NOW,
  });
  const adapter = createC16SyntheticToolAdapter({
    credentialBroker: broker,
    fixtureDocument: toolFixtureDocument,
  });
  let currentIdentity;
  const gateway = createToolGateway({
    tenantRegistry: {
      async admitNewRequest() {
        return tenantAdmission();
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        currentIdentity = actionIdentity({
          purposeRef: "synthetic://c06/purpose/tool-call",
          actorType: "AGENT",
        });
        return currentIdentity;
      },
    },
    authorizer: {
      async enforce(serverContext, value, descriptor) {
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          operationId: descriptor.operationId,
          decisionId: `decision-${descriptor.operationId}`,
          evidenceRef: `evidence://c16/${descriptor.operationId}`,
          policyVersion: "c06-v1",
          tenantId: serverContext.tenantId,
          surface: "TOOL_CALL",
          resourceId: value.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: ACTOR,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: DELEGATION,
          delegationChainSha256: toolGatewaySha256(
            currentIdentity.delegationChain,
          ),
          purposeRef: currentIdentity.purposeRef,
        };
      },
    },
    catalog,
    store,
    credentialBroker: broker,
    adapter,
    idFactory: ids(100),
    clock: () => NOW,
  });
  return { gateway, adapter };
}

function createAuditHarness() {
  const registry = createSyntheticAuditEvidenceRegistry(
    auditRegistryDocument,
  );
  const catalog = createSyntheticAuditEvidenceCatalog(
    auditCatalogDocument,
    { evidenceRegistry: registry },
  );
  const store = createMemoryAuditEvidenceStore({ clock: () => NOW });
  const service = createAuditEvidenceService({
    tenantRegistry: {
      async admitNewRequest() {
        return tenantAdmission();
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return actionIdentity({
          purposeRef: "synthetic://c18/purpose/audit",
          actorType: "SERVICE",
        });
      },
    },
    catalog,
    store,
    tenantScopeFactory({ tenant, authorization, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: tenant.tenantKind,
        lifecycleVersion: tenant.lifecycleVersion,
        correlationId,
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.version,
      };
    },
    clock: () => NOW,
    idFactory: ids(800),
  });
  return { service, store };
}

function createObservabilityHarness() {
  const catalog = createSyntheticObservabilityCatalog(
    observabilityCatalogDocument,
  );
  const store = createMemoryObservabilityStore();
  let span = 0x7000000000000000n;
  const service = createObservabilityService({
    catalog,
    store,
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId: TENANT,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    tenantScopeFactory({ tenant, scopeEvidence, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: tenant.tenantKind,
        lifecycleVersion: tenant.lifecycleVersion,
        correlationId,
        decisionId: scopeEvidence.decisionId,
        evidenceRef: scopeEvidence.evidenceRef,
        policyVersion: scopeEvidence.policyVersion,
      };
    },
    principalResolver: {
      async resolveActionIdentity({ tenantId, identityContextRef }) {
        assert.equal(tenantId, TENANT);
        assert.equal(identityContextRef, IDENTITY_CONTEXT);
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          trustSource:
            "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
          humanSubject: {
            principalId: HUMAN,
            principalType: "HUMAN",
            lifecycleVersion: 1,
            securityEpoch: 1,
          },
        };
      },
    },
    clock: () => NOW,
    idFactory: ids(900),
    spanIdFactory: () => {
      span += 1n;
      return span.toString(16);
    },
  });
  return { service, store };
}

function createHarness({
  readArtifact,
  modelTransform,
  toolTransform,
  auditTransform,
  rejectToolReservation = false,
} = {}) {
  const model = createModelHarness();
  const tool = createToolHarness();
  const audit = createAuditHarness();
  const observability = createObservabilityHarness();
  const bindingCatalog = createC19UpstreamBindingCatalog(
    bindingDocument,
    {
      rootDir: ROOT,
      ...(readArtifact ? { readArtifact } : {}),
    },
  );
  let tick = 0;
  const modelGateway = modelTransform
    ? {
        async route(...args) {
          return modelTransform(await model.gateway.route(...args));
        },
      }
    : model.gateway;
  const toolGateway = toolTransform
    ? {
        confirm: tool.gateway.confirm,
        async execute(...args) {
          return toolTransform(await tool.gateway.execute(...args));
        },
    }
    : tool.gateway;
  const auditEvidenceService = auditTransform
    ? {
        async append(...args) {
          return auditTransform(await audit.service.append(...args));
        },
      }
    : audit.service;
  const observabilityService = rejectToolReservation
    ? {
        ...observability.service,
        async reserve(context, value) {
          if (value.planRef.endsWith("/plans/tool")) {
            throw new Error("synthetic Tool reservation rejected");
          }
          return observability.service.reserve(context, value);
        },
      }
    : observability.service;
  const emitter = createC19SyntheticUpstreamEmitter({
    modelGateway,
    toolGateway,
    auditEvidenceService,
    observabilityService,
    bindingCatalog,
    monotonicClock: () => {
      tick += 1;
      return tick;
    },
  });
  return { emitter, model, tool, audit, observability };
}

async function costReport(service) {
  return service.costVarianceReport(c19Context(), {
    fromOccurredAt: "2026-07-26T00:00:00.000Z",
    toOccurredAt: "2026-07-27T00:00:00.000Z",
  });
}

test("real C14, C16 and C18 outputs drive one traced C19 settlement", async () => {
  const harness = createHarness();
  const first = await harness.emitter.run(
    upstreamContext(),
    request(),
  );

  assert.equal(
    first.settlements.model.settlement.quantity,
    first.model.route.usage.totalTokens,
  );
  assert.equal(
    first.settlements.model.settlement.supplierCostMicros,
    first.model.route.costMicrousd,
  );
  assert.equal(
    first.settlements.model.settlement.resourceRef,
    "model://c14/local-secure/v1",
  );
  assert.equal(first.settlements.tool.settlement.quantity, 1);
  assert.equal(first.settlements.tool.settlement.supplierCostMicros, 0);
  assert.equal(
    first.projections.tool.receiptSha256,
    first.tool.result.receipt.receiptSha256,
  );
  assert.equal(
    first.projections.audit.eventHash,
    first.audit.eventHash,
  );
  assert.equal(harness.model.provider.calls.length, 1);
  assert.equal(harness.tool.adapter.snapshot().newExecutionCount, 1);

  const telemetry = await harness.observability.service.telemetryReport(
    c19Context(),
    {
      fromOccurredAt: "2026-07-26T00:00:00.000Z",
      toOccurredAt: "2026-07-27T00:00:00.000Z",
    },
  );
  assert.deepEqual(
    telemetry.records.map((row) => row.operation),
    [
      "c14.model.route",
      "c16.tool.execute",
      "c18.audit.append",
      "c19.usage.settle",
    ],
  );
  for (let index = 1; index < telemetry.records.length; index += 1) {
    assert.equal(
      telemetry.records[index].parentSpanId,
      telemetry.records[index - 1].spanId,
    );
  }
  assert.equal(
    telemetry.records.every(
      (row) =>
        row.traceId ===
        parseTraceContext({ traceparent: TRACE }).traceId,
    ),
    true,
  );

  const cost = await costReport(harness.observability.service);
  assert.deepEqual(cost.totals, {
    bookedCostMicros: 380,
    supplierCostMicros: 25,
    varianceMicros: -355,
  });
  assert.equal(cost.byPrincipal[0].principalId, HUMAN);
  assert.equal(
    JSON.stringify({ telemetry, cost }).includes("synthetic-session"),
    false,
  );
  assert.equal(
    JSON.stringify({ telemetry, cost }).includes(
      "PENDING_SYNTHETIC_REVIEW",
    ),
    false,
  );

  const replay = await harness.emitter.run(
    upstreamContext(),
    request(),
  );
  assert.equal(replay.model.duplicate, true);
  assert.equal(replay.tool.result.replayed, true);
  assert.equal(replay.audit.duplicate, true);
  assert.equal(replay.audit.eventId, first.audit.eventId);
  assert.equal(harness.model.provider.calls.length, 1);
  assert.equal(harness.tool.adapter.snapshot().newExecutionCount, 1);
  assert.equal((await costReport(harness.observability.service)).ledgerEvents.length, 4);
});

test("artifact drift fails before upstream or C19 effects", async () => {
  const harness = createHarness({
    async readArtifact(path) {
      const bytes = await readFile(path);
      return path.endsWith("/lib/c14-synthetic-model-provider.mjs")
        ? Buffer.concat([bytes, Buffer.from("\n")])
        : bytes;
    },
  });
  await assert.rejects(
    harness.emitter.run(upstreamContext(), request()),
    (error) =>
      error instanceof C19UpstreamEmitterError &&
      error.code === "UPSTREAM_ARTIFACT_MISMATCH",
  );
  assert.equal(harness.model.provider.calls.length, 0);
  assert.equal(harness.tool.adapter.snapshot().newExecutionCount, 0);
  assert.equal(
    (await costReport(harness.observability.service)).ledgerEvents.length,
    0,
  );
});

test("the frozen one-run fixture rejects another idempotency prefix before effects", async () => {
  const harness = createHarness();
  await assert.rejects(
    harness.emitter.run(upstreamContext(), {
      ...request(),
      idempotencyPrefix: "c19-another-run",
    }),
    (error) =>
      error instanceof C19UpstreamEmitterError &&
      error.code === "SYNTHETIC_FIXTURE_MISMATCH",
  );
  assert.equal(harness.model.provider.calls.length, 0);
  assert.equal(harness.tool.adapter.snapshot().newExecutionCount, 0);
  assert.equal(
    (await costReport(harness.observability.service)).ledgerEvents.length,
    0,
  );
});

test("a rejected second reservation releases the first before upstream effects", async () => {
  const harness = createHarness({ rejectToolReservation: true });
  await assert.rejects(
    harness.emitter.run(upstreamContext(), request()),
    /synthetic Tool reservation rejected/,
  );
  assert.equal(harness.model.provider.calls.length, 0);
  assert.equal(harness.tool.adapter.snapshot().newExecutionCount, 0);
  const cost = await costReport(harness.observability.service);
  assert.deepEqual(
    cost.ledgerEvents.map((event) => event.eventType),
    ["QUOTA_RESERVED", "QUOTA_RELEASED"],
  );
  const quota = await harness.observability.service.quotaStatus(
    c19Context(),
  );
  assert.equal(
    quota.accounts.every(
      (account) =>
        account.reservedMicros === 0 &&
        account.consumedMicros === 0,
    ),
    true,
  );
});

test("tampered C14, C16 or C18 output cannot reach C19 settlement", async (t) => {
  await t.test("C14 cost", async () => {
    const harness = createHarness({
      modelTransform(output) {
        return {
          ...output,
          route: {
            ...output.route,
            costMicrousd: output.route.costMicrousd + 1,
          },
        };
      },
    });
    await assert.rejects(
      harness.emitter.run(upstreamContext(), request()),
      (error) =>
        error instanceof C19UpstreamEmitterError &&
        error.code === "UPSTREAM_EVIDENCE_MISMATCH",
    );
    const cost = await costReport(harness.observability.service);
    assert.equal(
      cost.ledgerEvents.some(
        (event) => event.eventType === "USAGE_SETTLED",
      ),
      false,
    );
    assert.equal(
      cost.ledgerEvents.filter(
        (event) => event.eventType === "QUOTA_RELEASED",
      ).length,
      2,
    );
    const quota = await harness.observability.service.quotaStatus(
      c19Context(),
    );
    assert.equal(
      quota.accounts.every(
        (account) =>
          account.reservedMicros === 0 &&
          account.consumedMicros === 0,
      ),
      true,
    );
  });

  await t.test("C16 receipt", async () => {
    const harness = createHarness({
      toolTransform(output) {
        return {
          ...output,
          receipt: {
            ...output.receipt,
            receiptSha256:
              "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          },
        };
      },
    });
    await assert.rejects(
      harness.emitter.run(upstreamContext(), request()),
      (error) =>
        error instanceof C19UpstreamEmitterError &&
        error.code === "UPSTREAM_EVIDENCE_MISMATCH",
    );
    const cost = await costReport(harness.observability.service);
    assert.equal(
      cost.ledgerEvents.filter(
        (event) => event.eventType === "USAGE_SETTLED",
      ).length,
      0,
    );
    assert.equal(
      cost.ledgerEvents.filter(
        (event) => event.eventType === "QUOTA_RELEASED",
      ).length,
      2,
    );
    const quota = await harness.observability.service.quotaStatus(
      c19Context(),
    );
    assert.deepEqual(
      quota.accounts.map((account) => [
        account.quotaScope,
        account.reservedMicros,
        account.consumedMicros,
      ]),
      [
        ["PRINCIPAL", 0, 0],
        ["TENANT", 0, 0],
      ],
    );
  });

  await t.test("C18 event", async () => {
    const harness = createHarness({
      auditTransform(output) {
        return {
          ...output,
          eventHash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        };
      },
    });
    await assert.rejects(
      harness.emitter.run(upstreamContext(), request()),
      (error) =>
        error instanceof C19UpstreamEmitterError &&
        error.code === "UPSTREAM_EVIDENCE_MISMATCH",
    );
    const cost = await costReport(harness.observability.service);
    assert.equal(
      cost.ledgerEvents.filter(
        (event) => event.eventType === "USAGE_SETTLED",
      ).length,
      0,
    );
    assert.equal(
      cost.ledgerEvents.filter(
        (event) => event.eventType === "QUOTA_RELEASED",
      ).length,
      2,
    );
  });
});
