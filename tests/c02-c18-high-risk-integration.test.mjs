import assert from "node:assert/strict";
import test from "node:test";
import {
  c02GovernanceCommandSha256,
  c02GovernanceResultSha256,
  createTenantGovernanceBff,
} from "../lib/tenant-governance-bff.mjs";
import {
  auditEvidenceSha256,
  createAuditEvidenceService,
  createMemoryAuditEvidenceStore,
  verifyAuditExport,
} from "../lib/c18-audit-evidence.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const OTHER_TENANT =
  "stn_01984910-3000-7000-8000-000000000002";
const HUMAN =
  "prn_018f0000-0000-7000-8000-000000000001";
const WORKLOAD =
  "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const NOW = "2026-07-27T20:00:00.000Z";
const EXPECTED_COMMAND_SHA256 =
  "sha256:050ada115b402ee8cc62da3096fd127ab8c30315c96b929ab9fda566f0b73f0c";
const EXPECTED_RESULT_SHA256 =
  "sha256:ce7492fef3e108975385faee6c46dbd1dcc59e70854f8e2ff0e4a62e4b5b39be";

const serverContext = Object.freeze({
  synthetic: true,
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: WORKLOAD,
});

const highRiskRequest = Object.freeze({
  sessionToken: "synthetic-session",
  delegationId: DELEGATION,
  correlationId: "corr-c02-c18-quota-change",
  idempotencyKey: "idem-c02-c18-quota-change",
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
});

function actionIdentity() {
  return {
    tenantId: TENANT,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic_c02",
    identityLinkId: "lnk_synthetic_c02",
    sessionId: "session-synthetic-c02",
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    workloadActor: {
      principalId: WORKLOAD,
      principalType: "SERVICE",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c02/purpose/manage",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: WORKLOAD,
        purposeRef: "synthetic://c02/purpose/manage",
        lifecycleVersion: 1,
        expiresAt: "2027-07-27T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
  };
}

function auditScope(scope, tenantId = scope.tenantId) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 1,
    correlationId: scope.correlationId,
    decisionId: scope.decisionId,
    evidenceRef: scope.evidenceRef,
    policyVersion: scope.policyVersion,
  };
}

function evidence(evidenceRef, version, artifact) {
  return {
    evidenceRef,
    version,
    sha256: auditEvidenceSha256(artifact),
  };
}

function createHarness({
  auditCommandSha256,
  mutateReceiptAfterAudit = false,
} = {}) {
  const store = createMemoryAuditEvidenceStore({ clock: () => NOW });
  const bundles = new Map();
  const auditAppendAcks = [];
  const readbackProofs = [];
  const confirmationConsumptions = new Map();
  const coreReceipts = new Map();
  let coreCommitCount = 0;
  let nextEventId = 9100;

  const catalog = {
    resolve(tenantId, bundleRef) {
      const bundle = bundles.get(`${tenantId}|${bundleRef}`);
      if (!bundle) throw new Error("C02 C18 bundle is not registered.");
      return structuredClone(bundle);
    },
    resolveIdentityArtifact(tenantId, artifact) {
      if (artifact.tenantId !== tenantId) {
        throw new Error("C02 action identity escaped Tenant scope.");
      }
      return {
        tenantId,
        evidenceType: "IDENTITY",
        evidenceRef: `evidence://c05/action-identities/${tenantId}`,
        version: "c18-action-identity-artifact-v1",
        sha256: auditEvidenceSha256(artifact),
        artifact: structuredClone(artifact),
      };
    },
  };

  const auditService = createAuditEvidenceService({
    tenantRegistry: {
      async admitNewRequest({ tenantId }) {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 1,
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return actionIdentity();
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
    idFactory() {
      nextEventId += 1;
      return `018f0000-0000-7000-8000-${String(nextEventId).padStart(12, "0")}`;
    },
  });

  const auditVerifier = {
    async verify(scope, input) {
      const match =
        /^evidence:\/\/c18\/events\/(aev_[a-z0-9_-]+)$/.exec(
          input.auditRef,
        );
      if (!match) throw new Error("C18 audit reference is invalid.");
      const exported = await store.exportChain(auditScope(scope));
      verifyAuditExport(exported);
      const record = exported.events.find(
        ({ eventId }) => eventId === match[1],
      );
      const receipt = exported.receipts.find(
        ({ idempotencyKey }) =>
          idempotencyKey === `c02:${input.idempotencyKey}`,
      );
      if (
        !record ||
        !receipt ||
        receipt.eventId !== record.eventId ||
        record.tenantId !== scope.tenantId ||
        record.payload.correlationId !== input.correlationId ||
        record.payload.tool.sha256 !== input.commandSha256 ||
        record.payload.result.sha256 !== input.resultSha256
      ) {
        throw new Error("C18 audit event is not bound to C02.");
      }
      const proof = {
        trustSource: "C18_IMMUTABLE_EVENT_READBACK",
        tenantId: record.tenantId,
        auditRef: input.auditRef,
        eventId: record.eventId,
        sequence: record.sequence,
        eventHash: record.eventHash,
        payloadSha256: record.payloadSha256,
        commandSha256: record.payload.tool.sha256,
        resultSha256: record.payload.result.sha256,
      };
      readbackProofs.push(structuredClone(proof));
      return proof;
    },
  };

  const bff = createTenantGovernanceBff({
    authorizer: {
      async enforce(context, input, descriptor) {
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          tenantId: context.tenantId,
          humanPrincipalId: HUMAN,
          workloadActorPrincipalId:
            context.workloadActorPrincipalId,
          decisionId: "dec-c02-c18-quota-change",
          evidenceRef: "evidence://c06/decisions/c02-c18-quota-change",
          policyVersion: "c06-policy-c02-c18-v1",
          resourceId: input.resourceId,
          operationId: descriptor.operationId,
        };
      },
    },
    confirmationVerifier: {
      async consume(scope, input) {
        const key = input.confirmationRef;
        const existing = confirmationConsumptions.get(key);
        if (existing) return structuredClone(existing);
        const consumed = {
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
          consumptionId: "c02-c18-confirmation-consumption",
          consumedAt: NOW,
          evidenceRef:
            "evidence://product-core/confirmation-consumption/c02-c18",
          expiresAt: "2026-07-27T20:05:00.000Z",
          singleUse: true,
          status: "CONSUMED",
        };
        confirmationConsumptions.set(key, structuredClone(consumed));
        return consumed;
      },
    },
    auditVerifier,
    corePort: {
      async read() {
        throw new Error("not used");
      },
      async mutate(scope, command) {
        const commandSha256 = c02GovernanceCommandSha256(
          scope,
          command,
        );
        const existing = coreReceipts.get(command.idempotencyKey);
        if (
          existing &&
          existing.commandSha256 !== commandSha256
        ) {
          throw new Error("Product Core idempotency conflict.");
        }
        const baseReceipt =
          existing?.receipt ?? {
            schemaVersion: "c02-governance-mutation-receipt.v1",
            tenantId: scope.tenantId,
            operationId: command.operationId,
            resourceId: command.resourceId,
            resourceVersion: command.expectedVersion + 1,
            candidateRef: command.candidateRef,
            candidateSha256: command.candidateSha256,
            status: "COMMITTED",
            evidenceRefs: [
              command.confirmationVerification.evidenceRef,
            ],
          };
        if (!existing) {
          coreCommitCount += 1;
          coreReceipts.set(command.idempotencyKey, {
            commandSha256,
            receipt: structuredClone(baseReceipt),
          });
        }
        const resultSha256 =
          c02GovernanceResultSha256(baseReceipt);
        const recordedCommandSha256 =
          auditCommandSha256 ?? commandSha256;
        const bundleRef =
          `fixture://c02/c18/bundles/${recordedCommandSha256.slice(7)}/${resultSha256.slice(7)}`;
        const bundle = {
          auditType: "C02_HIGH_RISK_CHANGE_COMMITTED",
          summaryCode: "SYNTHETIC_QUOTA_CHANGE_COMMITTED",
          retentionClass: "AUDIT_7Y",
          authorization: {
            decisionId: scope.decisionId,
            ...evidence(
              scope.evidenceRef,
              scope.policyVersion,
              {
                decisionId: scope.decisionId,
                resourceId: command.resourceId,
              },
            ),
          },
          model: evidence(
            "evidence://c14/routes/c02-management-v1",
            "c14-synthetic-v1",
            { route: "NO_MODEL_REQUIRED" },
          ),
          knowledge: [
            evidence(
              "evidence://c10/knowledge/c02-management-policy-v1",
              "c10-synthetic-v1",
              { policy: "SYNTHETIC_MANAGEMENT_POLICY" },
            ),
          ],
          skill: evidence(
            "evidence://c13/skills/c02-governance-v1",
            "c13-synthetic-v1",
            { skill: "C02_GOVERNANCE" },
          ),
          tool: {
            evidenceRef:
              `evidence://c02/commands/${recordedCommandSha256.slice(7)}`,
            version: "c02-governance-command-evidence-v1",
            sha256: recordedCommandSha256,
          },
          humanDecision: evidence(
            command.confirmationVerification.evidenceRef,
            "c02-confirmation-consumption-v1",
            command.confirmationVerification,
          ),
          result: {
            evidenceRef:
              `evidence://c02/core-receipts/${resultSha256.slice(7)}`,
            version: "c02-governance-result-evidence-v1",
            sha256: resultSha256,
          },
          c08State: evidence(
            `evidence://c08/runs/c02-${resultSha256.slice(7)}`,
            "c08-synthetic-state-v1",
            {
              state: "COMMITTED",
              resultSha256,
            },
          ),
        };
        bundles.set(`${scope.tenantId}|${bundleRef}`, bundle);
        const appended = await auditService.append(serverContext, {
          sessionToken: highRiskRequest.sessionToken,
          delegationId: highRiskRequest.delegationId,
          idempotencyKey: `c02:${command.idempotencyKey}`,
          correlationId: scope.correlationId,
          evidenceBundleRef: bundleRef,
        });
        auditAppendAcks.push(structuredClone(appended));
        const receipt = {
          ...structuredClone(baseReceipt),
          auditRef:
            `evidence://c18/events/${appended.eventId}`,
        };
        if (mutateReceiptAfterAudit) {
          receipt.evidenceRefs.push(
            "evidence://c02/core-receipts/unbound-extra-reference",
          );
        }
        return receipt;
      },
    },
  });

  return {
    bff,
    store,
    auditAppendAcks,
    readbackProofs,
    confirmationConsumptions,
    coreCommitCount: () => coreCommitCount,
  };
}

test("one Synthetic high-risk C02 command closes the confirmation, Core receipt and real C18 loop", async () => {
  const harness = createHarness();

  const first = await harness.bff.mutate(
    serverContext,
    highRiskRequest,
  );
  const replay = await harness.bff.mutate(
    serverContext,
    highRiskRequest,
  );

  assert.deepEqual(replay, first);
  assert.equal(harness.confirmationConsumptions.size, 1);
  assert.equal(harness.coreCommitCount(), 1);
  assert.deepEqual(
    harness.auditAppendAcks.map(({ duplicate }) => duplicate),
    [false, true],
  );
  assert.equal(
    harness.auditAppendAcks[1].eventId,
    harness.auditAppendAcks[0].eventId,
  );
  assert.equal(harness.readbackProofs.length, 2);
  assert.equal(
    harness.readbackProofs[0].eventId,
    harness.readbackProofs[1].eventId,
  );
  assert.equal(
    harness.readbackProofs[0].commandSha256,
    EXPECTED_COMMAND_SHA256,
  );
  assert.equal(
    harness.readbackProofs[0].resultSha256,
    EXPECTED_RESULT_SHA256,
  );

  const scope = {
    tenantId: TENANT,
    correlationId: highRiskRequest.correlationId,
    decisionId: "dec-c02-c18-quota-change",
    evidenceRef: "evidence://c06/decisions/c02-c18-quota-change",
    policyVersion: "c06-policy-c02-c18-v1",
  };
  const exported = await harness.store.exportChain(auditScope(scope));
  const verification = verifyAuditExport(exported);
  assert.equal(verification.eventCount, 1);
  assert.equal(exported.receipts.length, 1);
  assert.equal(
    exported.events[0].payload.tool.sha256,
    harness.readbackProofs[0].commandSha256,
  );
  assert.equal(
    exported.events[0].payload.result.sha256,
    harness.readbackProofs[0].resultSha256,
  );
  assert.equal(
    exported.events[0].payload.humanDecision.evidenceRef,
    "evidence://product-core/confirmation-consumption/c02-c18",
  );
  assert.equal(
    first.auditRef,
    `evidence://c18/events/${exported.events[0].eventId}`,
  );

  const returnedCopy = await harness.store.exportChain(
    auditScope(scope),
  );
  returnedCopy.events[0].payload.tool.sha256 =
    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  const immutableReadback = await harness.store.exportChain(
    auditScope(scope),
  );
  assert.equal(
    immutableReadback.events[0].payload.tool.sha256,
    harness.readbackProofs[0].commandSha256,
  );
  assert.equal(typeof harness.store.update, "undefined");
  assert.equal(typeof harness.store.delete, "undefined");

  const otherTenant = await harness.store.exportChain(
    auditScope(scope, OTHER_TENANT),
  );
  assert.equal(otherTenant.events.length, 0);
});

test("C02 fails closed when the real C18 event does not bind the exact command or Product Core result", async (t) => {
  await t.test("command hash mismatch", async () => {
    const harness = createHarness({
      auditCommandSha256:
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    });
    await assert.rejects(
      harness.bff.mutate(serverContext, highRiskRequest),
      (error) => error.code === "AUDIT_EVIDENCE_INVALID",
    );
  });

  await t.test("result hash mismatch", async () => {
    const harness = createHarness({
      mutateReceiptAfterAudit: true,
    });
    await assert.rejects(
      harness.bff.mutate(serverContext, highRiskRequest),
      (error) => error.code === "AUDIT_EVIDENCE_INVALID",
    );
  });
});
