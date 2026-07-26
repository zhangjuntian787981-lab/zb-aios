import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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

const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c16/operation-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const fixtures = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c16/synthetic-tool-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

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
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: "AGENT",
      lifecycleVersion: 1,
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
