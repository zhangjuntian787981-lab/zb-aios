import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createAuditEvidenceService,
  createMemoryAuditEvidenceStore,
  createSyntheticAuditEvidenceCatalog,
  createSyntheticAuditEvidenceRegistry,
} from "../lib/c18-audit-evidence.mjs";
import {
  createC15C18AuditPublisher,
} from "../lib/c15-c18-audit-publisher.mjs";

const TENANT = "stn_018f0000-0000-7000-8000-000000000010";
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const BUNDLE =
  "fixture://c18/northstar/bundles/completed-analysis-v1";
const NOW = "2026-07-26T10:00:00.000Z";
const registry = createSyntheticAuditEvidenceRegistry(
  JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c18/synthetic-evidence-registry.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);
const catalog = createSyntheticAuditEvidenceCatalog(
  JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c18/synthetic-evidence-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
  { evidenceRegistry: registry },
);

function identity() {
  return {
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId: "session-synthetic",
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: "SERVICE",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c18/purpose/audit",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: ACTOR,
        purposeRef: "synthetic://c18/purpose/audit",
        lifecycleVersion: 1,
        expiresAt: "2027-07-26T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
  };
}

test("registered C15 publisher persists one idempotent C18 event", async () => {
  const store = createMemoryAuditEvidenceStore({ clock: () => NOW });
  const authorization = catalog.resolve(TENANT, BUNDLE).authorization;
  let nextId = 7000;
  const service = createAuditEvidenceService({
    store,
    catalog,
    clock: () => NOW,
    idFactory() {
      nextId += 1;
      return `018f0000-0000-7000-8000-${String(nextId).padStart(12, "0")}`;
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return identity();
      },
    },
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId: TENANT,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    tenantScopeFactory({ tenant, correlationId }) {
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
  });
  const publisher = createC15C18AuditPublisher({
    auditEvidenceService: service,
    async resolveBinding() {
      return {
        serverContext: {
          synthetic: true,
          routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
          tenantId: TENANT,
          workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
          workloadActorPrincipalId: ACTOR,
        },
        sessionToken: "synthetic-session",
        evidenceBundleRef: BUNDLE,
      };
    },
  });
  const intent = {
    schemaVersion: "c15-audit-intent.v1",
    intentId: "hai_018f0000-0000-7000-8000-000000007100",
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    eventType: "SYNTHETIC_DRAFT_PREPARED",
    subjectId: "dar_018f0000-0000-7000-8000-000000007101",
    subjectSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    artifactId: "dar_018f0000-0000-7000-8000-000000007101",
    artifactSha256:
      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    decisionId: null,
    decisionSha256: null,
    effectId: null,
    effectKey: null,
    humanPrincipalId: HUMAN,
    workloadActorPrincipalId: ACTOR,
    leafDelegationId: DELEGATION,
    authorizationDecisionId: "c06-c15-test",
    authorizationEvidenceRef: "evidence://c06/c15/test",
    authorizationPolicyVersion: "c06-v1",
    correlationId: "c15-c18-bridge",
    occurredAt: NOW,
  };
  const first = await publisher.publish(intent);
  const replay = await publisher.publish(intent);
  assert.equal(first.intentId, intent.intentId);
  assert.equal(first.c18CommandReceiptKey, intent.intentId);
  assert.equal(first.duplicate, false);
  assert.equal(replay.duplicate, true);
  assert.equal(replay.c18EventId, first.c18EventId);
  const exported = await store.exportChain({
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: intent.correlationId,
    decisionId: authorization.decisionId,
    evidenceRef: authorization.evidenceRef,
    policyVersion: authorization.version,
  });
  assert.equal(exported.events.length, 1);
  assert.equal(exported.receipts.length, 1);
  assert.equal(exported.receipts[0].idempotencyKey, intent.intentId);
});
