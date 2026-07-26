import assert from "node:assert/strict";
import test from "node:test";
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
  createC16AuditOutboxWorker,
} from "../lib/c16-outbox-worker.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const NOW = "2026-07-26T12:00:00.000Z";

function ids(start = 300) {
  let value = start;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

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

const fixtures = {
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
      result: { approvalRef: "SYN-APR-0001", status: "SYNTHETIC_PENDING" },
    },
    {
      tenantId: TENANT,
      operationId: "synthetic.erp.order.get",
      lookup: { orderRef: "SYN-ORD-0001" },
      result: { orderRef: "SYN-ORD-0001", state: "SYNTHETIC_OPEN" },
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

function scope(correlationId = "c16-audit") {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId,
    decisionId: "decision-c16",
    evidenceRef: "evidence://c16/audit",
    policyVersion: "c06-v1",
  };
}

async function completedStore(mutable) {
  const store = createMemoryToolGatewayStore({
    clock: () => mutable.now,
  });
  const broker = createC16EphemeralCredentialBroker({
    clock: () => mutable.now,
    idFactory: ids(400),
  });
  const adapter = createC16SyntheticToolAdapter({
    credentialBroker: broker,
    fixtureDocument: fixtures,
  });
  const identity = {
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: "AGENT",
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c06/purpose/tool-call",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatePrincipalId: ACTOR,
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
  };
  let currentIdentity = identity;
  const gateway = createToolGateway({
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId: TENANT,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return structuredClone(currentIdentity);
      },
    },
    authorizer: {
      async enforce(_context, request, descriptor) {
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          operationId: descriptor.operationId,
          decisionId: "decision-c16",
          evidenceRef: "evidence://c16/audit",
          policyVersion: "c06-v1",
          tenantId: TENANT,
          surface: "TOOL_CALL",
          resourceId: request.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: 1,
          workloadActorPrincipalId: ACTOR,
          workloadActorSecurityEpoch: 1,
          leafDelegationId: DELEGATION,
          delegationChainSha256: toolGatewaySha256(
            identity.delegationChain,
          ),
          purposeRef: identity.purposeRef,
        };
      },
    },
    catalog: createSyntheticToolCatalog(catalogDocument),
    store,
    credentialBroker: broker,
    adapter,
    idFactory: ids(500),
    clock: () => mutable.now,
  });
  const context = {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
  const confirmation = await gateway.confirm(context, {
    sessionToken: "session",
    delegationId: DELEGATION,
    correlationId: "confirm",
    operationId: "synthetic.approval.status.get",
    idempotencyKey: "confirm",
    params: { approvalRef: "SYN-APR-0001" },
  });
  await gateway.execute(context, {
    sessionToken: "session",
    delegationId: DELEGATION,
    correlationId: "execute",
    operationId: "synthetic.approval.status.get",
    idempotencyKey: "execute",
    confirmationId: confirmation.confirmationId,
    confirmationSha256: confirmation.confirmationSha256,
    expectedParamSha256: confirmation.normalizedParamSha256,
  });
  currentIdentity = identity;
  return store;
}

test("C18 publisher ACK loss retries the same metadata-only intent idempotently", async () => {
  const mutable = { now: NOW };
  const store = await completedStore(mutable);
  const published = new Map();
  let attempts = 0;
  const worker = createC16AuditOutboxWorker({
    store,
    workerId: "c16-audit-worker",
    c18Publisher: {
      async publish(intent) {
        attempts += 1;
        published.set(intent.intentId, structuredClone(intent));
        if (attempts === 1) throw new Error("ACK lost");
        return { intentId: intent.intentId };
      },
    },
  });
  await assert.rejects(worker.runOnce(scope("first")));
  mutable.now = "2026-07-26T12:00:01.000Z";
  const recovered = await worker.runOnce(scope("retry"));
  assert.equal(recovered.status, "PUBLISHED");
  assert.equal(attempts, 2);
  assert.equal(published.size, 1);
  const intent = [...published.values()][0];
  assert.equal(intent.metadataOnly, true);
  const serialized = JSON.stringify(intent);
  assert.equal(serialized.includes("normalizedParams"), false);
  assert.equal(serialized.includes('"result":'), false);
  assert.equal(serialized.includes("resultBody"), false);
  assert.equal(serialized.includes("cap_"), false);
});
