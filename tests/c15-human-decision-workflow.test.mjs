import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  HumanDecisionWorkflowError,
  canonicalizeHumanDecisionJson,
  createHumanDecisionWorkflow,
  createMemoryHumanDecisionStore,
  createSyntheticHumanDecisionCatalog,
  humanDecisionSha256,
} from "../lib/human-decision-workflow.mjs";
import {
  createC15AuditOutboxWorker,
  createC15EffectOutboxWorker,
} from "../lib/c15-outbox-worker.mjs";
import {
  createC15SyntheticEffectAdapter,
} from "../lib/c15-synthetic-effect-adapter.mjs";

const fixtureDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c15/synthetic-workflow-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TENANTS = fixtureDocument.workflows.map((item) => item.tenantId);
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const NOW = "2026-07-26T10:00:00.000Z";

function deterministicIds(start = 1000) {
  let current = start;
  return () => {
    current += 1;
    return `018f0000-0000-7000-8000-${String(current).padStart(12, "0")}`;
  };
}

function identity(tenantId, overrides = {}) {
  const human = {
    principalId: HUMAN,
    principalType: "HUMAN",
    lifecycleVersion: 1,
    securityEpoch: 1,
    ...overrides.humanSubject,
  };
  const actor = {
    principalId: ACTOR,
    principalType: "AGENT",
    lifecycleVersion: 1,
    securityEpoch: 1,
    ...overrides.workloadActor,
  };
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId: "session-synthetic",
    humanSubject: human,
    workloadActor: actor,
    purposeRef: "synthetic://c15/purpose/decision",
    delegationChain: [
      {
        delegationId: overrides.delegationId ?? DELEGATION,
        delegatorPrincipalId: human.principalId,
        delegatePrincipalId: actor.principalId,
        purposeRef: "synthetic://c15/purpose/decision",
        lifecycleVersion: 1,
        expiresAt: "2027-07-26T00:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
  };
}

function context(tenantId) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
}

function scope(tenantId, suffix = "worker") {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: `c15-${suffix}`,
    decisionId: `decision-${suffix}`,
    evidenceRef: `evidence://c15/${suffix}`,
    policyVersion: "c06-v1",
  };
}

function createHarness({
  tenantId = TENANTS[0],
  catalogDocument = fixtureDocument,
  store,
  idStart = 1000,
} = {}) {
  const mutable = {
    now: NOW,
    tenantActive: true,
    nextIdentity: [],
    ceremonyValid: true,
  };
  const calls = [];
  const catalog = createSyntheticHumanDecisionCatalog(catalogDocument);
  const selectedStore =
    store ?? createMemoryHumanDecisionStore({ clock: () => mutable.now });
  const workflowFixture = catalogDocument.workflows.find(
    (item) => item.tenantId === tenantId,
  );
  const workflow = createHumanDecisionWorkflow({
    tenantRegistry: {
      async admitNewRequest() {
        calls.push("C03");
        if (!mutable.tenantActive) {
          const error = new Error("inactive");
          error.code = "TENANT_NOT_ACTIVE";
          throw error;
        }
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        calls.push("C05");
        return (
          mutable.nextIdentity.shift() ?? identity(tenantId)
        );
      },
    },
    authorizer: {
      async enforce(_serverContext, request, descriptor) {
        calls.push(`C06:${descriptor.operationId}`);
        const current = identity(tenantId);
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          operationId: descriptor.operationId,
          decisionId: `c06-${descriptor.operationId}`,
          evidenceRef: `evidence://c15/${descriptor.operationId}`,
          policyVersion: "c06-v1",
          tenantId,
          surface: descriptor.surface,
          resourceId: request.resourceId,
          humanPrincipalId: current.humanSubject.principalId,
          humanSecurityEpoch: current.humanSubject.securityEpoch,
          workloadActorPrincipalId: current.workloadActor.principalId,
          workloadActorSecurityEpoch: current.workloadActor.securityEpoch,
          leafDelegationId: DELEGATION,
          delegationChainSha256: humanDecisionSha256(
            current.delegationChain,
          ),
          purposeRef: current.purposeRef,
        };
      },
    },
    decisionCeremony: {
      async verify(input) {
        calls.push("CEREMONY");
        if (!mutable.ceremonyValid) return null;
        return {
          trustSource: "C15_DEDICATED_DECISION_CEREMONY",
          proofRef: input.proofRef,
          proofSha256: humanDecisionSha256({
            proofRef: input.proofRef,
            artifactSha256: input.artifactSha256,
          }),
          artifactSha256: input.artifactSha256,
          displaySha256: input.displaySha256,
          humanPrincipalId: input.identityBinding.humanPrincipalId,
          leafDelegationId: input.identityBinding.leafDelegationId,
          expiresAt: new Date(
            Date.parse(mutable.now) + 300000,
          ).toISOString(),
        };
      },
    },
    catalog,
    store: selectedStore,
    clock: () => mutable.now,
    idFactory: deterministicIds(idStart),
  });
  let sequence = 0;
  return {
    workflow,
    store: selectedStore,
    mutable,
    calls,
    catalog,
    fixture: workflowFixture,
    context: () => context(tenantId),
    prepareRequest(overrides = {}) {
      sequence += 1;
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey: `c15-prepare-${sequence}`,
        correlationId: `c15-prepare-correlation-${sequence}`,
        workflowRef: workflowFixture.workflowRef,
        candidate: structuredClone(workflowFixture.baseline),
        ...overrides,
      };
    },
    decideRequest(artifact, overrides = {}) {
      sequence += 1;
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey: `c15-decide-${sequence}`,
        correlationId: `c15-decide-correlation-${sequence}`,
        artifactId: artifact.artifactId,
        artifactSha256: artifact.artifactSha256,
        outcome: "APPROVE",
        ceremonyProofRef:
          `fixture://c15/ceremonies/${artifact.artifactId}`,
        ...overrides,
      };
    },
    executeRequest(artifact, decision, overrides = {}) {
      sequence += 1;
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey: `c15-execute-${sequence}`,
        correlationId: `c15-execute-correlation-${sequence}`,
        decisionId: decision.decisionId,
        decisionSha256: decision.decisionSha256,
        artifactId: artifact.artifactId,
        artifactSha256: artifact.artifactSha256,
        ...overrides,
      };
    },
    withdrawRequest(decision, overrides = {}) {
      sequence += 1;
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey: `c15-withdraw-${sequence}`,
        correlationId: `c15-withdraw-correlation-${sequence}`,
        decisionId: decision.decisionId,
        decisionSha256: decision.decisionSha256,
        ...overrides,
      };
    },
  };
}

function code(expected) {
  return (error) =>
    error instanceof HumanDecisionWorkflowError &&
    error.code === expected;
}

test("C15 uses deterministic RFC 8785 canonicalization", () => {
  assert.equal(
    canonicalizeHumanDecisionJson({ z: -0, a: [3, true, "x"] }),
    '{"a":[3,true,"x"],"z":0}',
  );
  assert.equal(
    humanDecisionSha256({ b: 1, a: 2 }),
    humanDecisionSha256({ a: 2, b: 1 }),
  );
  assert.throws(
    () => canonicalizeHumanDecisionJson({ invalid: Number.NaN }),
    code("INVALID_JSON"),
  );
  assert.throws(
    () => canonicalizeHumanDecisionJson({ invalid: "\ud800" }),
    code("INVALID_JSON"),
  );
});

test("three Synthetic Tenants complete isolated decision workflows", async () => {
  const artifacts = [];
  for (const [index, tenantId] of TENANTS.entries()) {
    const harness = createHarness({ tenantId, idStart: 1200 + index * 100 });
    const artifact = await harness.workflow.prepare(
      harness.context(),
      harness.prepareRequest(),
    );
    const decision = await harness.workflow.decide(
      harness.context(),
      harness.decideRequest(artifact),
    );
    const effect = await harness.workflow.execute(
      harness.context(),
      harness.executeRequest(artifact, decision),
    );
    assert.equal(decision.decisionType, "SYNTHETIC_TEST_DECISION");
    assert.equal(decision.productionReusable, false);
    assert.equal(effect.externalEffectCount, 0);
    assert.deepEqual(
      harness.calls.slice(0, 4),
      ["C05", "C06:C15_PREPARE_DRAFT", "C05", "C03"],
    );
    artifacts.push(artifact.artifactSha256);
  }
  assert.equal(new Set(artifacts).size, 3);
});

test("server computes complete differences, sources and risks", async () => {
  const harness = createHarness();
  const changed = structuredClone(harness.fixture.baseline);
  changed.recipients = [
    {
      recipientRef:
        "fixture://c15/northstar/recipients/reviewer-b",
      role: "REVIEWER",
    },
  ];
  changed.attachments = [
    {
      artifactRef:
        "fixture://c15/northstar/attachments/summary",
      sha256:
        "sha256:5555555555555555555555555555555555555555555555555555555555555555",
    },
  ];
  changed.rules[0] = structuredClone(
    harness.fixture.allowedBindings.rules[1],
  );
  changed.fields.amount = 125;
  changed.model = structuredClone(
    harness.fixture.allowedBindings.models[1],
  );
  changed.skill = structuredClone(
    harness.fixture.allowedBindings.skills[1],
  );
  changed.knowledge[0] = structuredClone(
    harness.fixture.allowedBindings.knowledge[1],
  );
  const artifact = await harness.workflow.prepare(
    harness.context(),
    harness.prepareRequest({ candidate: changed }),
  );
  assert.deepEqual(
    artifact.display.risks.map((item) => item.code),
    [
      "APPROVED_FIELD_CHANGED",
      "ATTACHMENT_PRESENT",
      "KNOWLEDGE_BINDING_CHANGED",
      "MODEL_BINDING_CHANGED",
      "RECIPIENT_CHANGED",
      "RULE_BINDING_CHANGED",
      "SKILL_BINDING_CHANGED",
    ],
  );
  assert.ok(artifact.display.differences.length >= 7);
  assert.ok(
    artifact.display.sources.every(
      (item) => item.ref && item.version && item.sha256,
    ),
  );
  assert.throws(
    () => {
      artifact.candidate.fields.amount = 999;
    },
    TypeError,
  );
});

test("object and catalog binding changes invalidate an old decision", async () => {
  const harness = createHarness({ idStart: 1450 });
  const original = await harness.workflow.prepare(
    harness.context(),
    harness.prepareRequest(),
  );
  const decision = await harness.workflow.decide(
    harness.context(),
    harness.decideRequest(original),
  );
  const candidate = structuredClone(harness.fixture.baseline);
  candidate.recipients = [
    {
      recipientRef:
        "fixture://c15/northstar/recipients/reviewer-b",
      role: "REVIEWER",
    },
  ];
  const changed = await harness.workflow.prepare(
    harness.context(),
    harness.prepareRequest({ candidate }),
  );
  assert.notEqual(changed.artifactSha256, original.artifactSha256);
  await assert.rejects(
    harness.workflow.execute(
      harness.context(),
      harness.executeRequest(changed, decision),
    ),
    code("DECISION_NOT_ACTIVE"),
  );

  const updatedCatalog = structuredClone(fixtureDocument);
  updatedCatalog.workflows[0].version = "northstar-preview-v2";
  const restarted = createHarness({
    catalogDocument: updatedCatalog,
    store: harness.store,
    idStart: 1500,
  });
  await assert.rejects(
    restarted.workflow.execute(
      restarted.context(),
      restarted.executeRequest(original, decision),
    ),
    code("ARTIFACT_BINDING_CHANGED"),
  );
});

test("chat consent, stage approval and ordinary button values are rejected", async () => {
  const harness = createHarness();
  const artifact = await harness.workflow.prepare(
    harness.context(),
    harness.prepareRequest(),
  );
  await assert.rejects(
    harness.workflow.decide(
      harness.context(),
      {
        ...harness.decideRequest(artifact),
        outcome: "同意",
      },
    ),
    code("P3_REQUIRED"),
  );
  for (const invalid of [
    { stageApprovalHash: "sha256:".padEnd(71, "a") },
    { ordinaryButton: true },
  ]) {
    await assert.rejects(
      harness.workflow.decide(
        harness.context(),
        { ...harness.decideRequest(artifact), ...invalid },
      ),
      code("INVALID_INPUT"),
    );
  }
  harness.mutable.ceremonyValid = false;
  await assert.rejects(
    harness.workflow.decide(
      harness.context(),
      harness.decideRequest(artifact),
    ),
    code("DECISION_CEREMONY_INVALID"),
  );
});

test("expiry, withdrawal, identity revocation and hash tampering fail closed", async () => {
  const expired = createHarness();
  const artifact = await expired.workflow.prepare(
    expired.context(),
    expired.prepareRequest(),
  );
  const decision = await expired.workflow.decide(
    expired.context(),
    expired.decideRequest(artifact),
  );
  expired.mutable.now = decision.expiresAt;
  await assert.rejects(
    expired.workflow.execute(
      expired.context(),
      expired.executeRequest(artifact, decision),
    ),
    code("DECISION_NOT_ACTIVE"),
  );

  const withdrawn = createHarness({ idStart: 1600 });
  const artifact2 = await withdrawn.workflow.prepare(
    withdrawn.context(),
    withdrawn.prepareRequest(),
  );
  const decision2 = await withdrawn.workflow.decide(
    withdrawn.context(),
    withdrawn.decideRequest(artifact2),
  );
  await withdrawn.workflow.withdraw(
    withdrawn.context(),
    withdrawn.withdrawRequest(decision2),
  );
  await assert.rejects(
    withdrawn.workflow.execute(
      withdrawn.context(),
      withdrawn.executeRequest(artifact2, decision2),
    ),
    code("DECISION_NOT_ACTIVE"),
  );

  const executing = createHarness({ idStart: 1700 });
  const artifactExecuting = await executing.workflow.prepare(
    executing.context(),
    executing.prepareRequest(),
  );
  const decisionExecuting = await executing.workflow.decide(
    executing.context(),
    executing.decideRequest(artifactExecuting),
  );
  await executing.workflow.execute(
    executing.context(),
    executing.executeRequest(artifactExecuting, decisionExecuting),
  );
  await assert.rejects(
    executing.workflow.withdraw(
      executing.context(),
      executing.withdrawRequest(decisionExecuting),
    ),
    code("DECISION_ALREADY_EXECUTING"),
  );

  const revoked = createHarness({ idStart: 1800 });
  const artifact3 = await revoked.workflow.prepare(
    revoked.context(),
    revoked.prepareRequest(),
  );
  const decision3 = await revoked.workflow.decide(
    revoked.context(),
    revoked.decideRequest(artifact3),
  );
  revoked.mutable.nextIdentity.push(
    identity(TENANTS[0], {
      humanSubject: { securityEpoch: 2 },
    }),
  );
  await assert.rejects(
    revoked.workflow.execute(
      revoked.context(),
      revoked.executeRequest(artifact3, decision3),
    ),
    code("AUTHORIZATION_BINDING_INVALID"),
  );
  await assert.rejects(
    revoked.workflow.execute(
      revoked.context(),
      revoked.executeRequest(artifact3, decision3, {
        artifactSha256:
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      }),
    ),
    code("DECISION_NOT_ACTIVE"),
  );
});

test("idempotency, effect readback, compensation and ACK loss are safe", async () => {
  const harness = createHarness({ idStart: 2000 });
  const prepareRequest = harness.prepareRequest();
  const [artifactA, artifactB] = await Promise.all([
    harness.workflow.prepare(harness.context(), prepareRequest),
    harness.workflow.prepare(harness.context(), prepareRequest),
  ]);
  assert.equal(artifactA.artifactId, artifactB.artifactId);
  assert.equal([artifactA.replayed, artifactB.replayed].filter(Boolean).length, 1);
  const decision = await harness.workflow.decide(
    harness.context(),
    harness.decideRequest(artifactA),
  );
  const executeRequest = harness.executeRequest(artifactA, decision);
  const [effectA, effectB] = await Promise.all([
    harness.workflow.execute(harness.context(), executeRequest),
    harness.workflow.execute(harness.context(), executeRequest),
  ]);
  assert.equal(effectA.effectId, effectB.effectId);
  await assert.rejects(
    harness.workflow.execute(
      harness.context(),
      harness.executeRequest(artifactA, decision),
    ),
    code("EFFECT_KEY_CONFLICT"),
  );

  const adapter = createC15SyntheticEffectAdapter();
  let firstCompletion = true;
  const storeWithAckLoss = {
    claimEffects: (...args) => harness.store.claimEffects(...args),
    failEffect: (...args) => harness.store.failEffect(...args),
    async completeEffect(...args) {
      if (firstCompletion) {
        firstCompletion = false;
        throw Object.assign(new Error("ack lost"), {
          code: "ACK_LOST",
        });
      }
      return harness.store.completeEffect(...args);
    },
  };
  const effectWorker = createC15EffectOutboxWorker({
    store: storeWithAckLoss,
    adapter,
    workerId: "c15-effect-worker",
    leaseDurationSeconds: 30,
    retryDelaySeconds: 0,
    clock: () => harness.mutable.now,
    idFactory: deterministicIds(2500),
  });
  await assert.rejects(
    effectWorker.runOnce(scope(TENANTS[0], "effect")),
    /ack lost/,
  );
  const completed = await effectWorker.runOnce(
    scope(TENANTS[0], "effect"),
  );
  assert.equal(completed.status, "SUCCEEDED");
  assert.equal(
    adapter.snapshot().commitCounts[effectA.effectKey],
    1,
  );
  assert.equal(adapter.snapshot().externalEffectCount, 0);

  const mismatchHarness = createHarness({ idStart: 2700 });
  const mismatchArtifact = await mismatchHarness.workflow.prepare(
    mismatchHarness.context(),
    mismatchHarness.prepareRequest(),
  );
  const mismatchDecision = await mismatchHarness.workflow.decide(
    mismatchHarness.context(),
    mismatchHarness.decideRequest(mismatchArtifact),
  );
  const mismatchEffect = await mismatchHarness.workflow.execute(
    mismatchHarness.context(),
    mismatchHarness.executeRequest(
      mismatchArtifact,
      mismatchDecision,
    ),
  );
  const mismatchAdapter = createC15SyntheticEffectAdapter({
    mismatchEffectKeys: new Set([mismatchEffect.effectKey]),
  });
  const mismatchWorker = createC15EffectOutboxWorker({
    store: mismatchHarness.store,
    adapter: mismatchAdapter,
    workerId: "c15-mismatch-worker",
    clock: () => mismatchHarness.mutable.now,
    idFactory: deterministicIds(2900),
  });
  const compensated = await mismatchWorker.runOnce(
    scope(TENANTS[0], "mismatch"),
  );
  assert.equal(compensated.status, "COMPENSATED");
  assert.deepEqual(
    mismatchAdapter.snapshot().compensatedEffectKeys,
    [mismatchEffect.effectKey],
  );

  const failedHarness = createHarness({ idStart: 2950 });
  const failedArtifact = await failedHarness.workflow.prepare(
    failedHarness.context(),
    failedHarness.prepareRequest(),
  );
  const failedDecision = await failedHarness.workflow.decide(
    failedHarness.context(),
    failedHarness.decideRequest(failedArtifact),
  );
  const failedEffect = await failedHarness.workflow.execute(
    failedHarness.context(),
    failedHarness.executeRequest(failedArtifact, failedDecision),
  );
  const failedAdapter = createC15SyntheticEffectAdapter({
    mismatchEffectKeys: new Set([failedEffect.effectKey]),
    compensationFailureEffectKeys: new Set([failedEffect.effectKey]),
  });
  const failedWorker = createC15EffectOutboxWorker({
    store: failedHarness.store,
    adapter: failedAdapter,
    workerId: "c15-compensation-failure-worker",
    clock: () => failedHarness.mutable.now,
    idFactory: deterministicIds(3000),
  });
  const failed = await failedWorker.runOnce(
    scope(TENANTS[0], "compensation-failure"),
  );
  assert.equal(failed.status, "COMPENSATION_FAILED");
});

test("metadata-only audit Outbox is recoverable and C18 publishing is idempotent", async () => {
  const harness = createHarness({ idStart: 3100 });
  const artifact = await harness.workflow.prepare(
    harness.context(),
    harness.prepareRequest(),
  );
  const published = new Set();
  let dropAck = true;
  const worker = createC15AuditOutboxWorker({
    store: harness.store,
    c18Publisher: {
      async publish(intent) {
        assert.equal(Object.hasOwn(intent, "candidate"), false);
        assert.equal(Object.hasOwn(intent, "display"), false);
        published.add(intent.intentId);
        if (dropAck) {
          dropAck = false;
          throw Object.assign(new Error("ack lost"), {
            code: "ACK_LOST",
          });
        }
        return { intentId: intent.intentId };
      },
    },
    workerId: "c15-audit-worker",
    retryDelaySeconds: 0,
  });
  await assert.rejects(
    worker.runOnce(scope(TENANTS[0], "audit")),
    /ack lost/,
  );
  await worker.runOnce(scope(TENANTS[0], "audit"));
  assert.equal(published.size, 1);

  const recovery = await harness.store.exportRecovery(
    scope(TENANTS[0], "recovery"),
  );
  const restored = createMemoryHumanDecisionStore({
    clock: () => harness.mutable.now,
    recoveryBundles: [recovery],
  });
  const restoredArtifact = await restored.getArtifact(
    scope(TENANTS[0], "restore"),
    artifact.artifactId,
  );
  assert.equal(restoredArtifact.artifactSha256, artifact.artifactSha256);
  const tampered = structuredClone(recovery);
  tampered.artifacts[0].candidate.fields.amount = 999;
  assert.throws(
    () =>
      createMemoryHumanDecisionStore({
        recoveryBundles: [tampered],
      }),
    code("RECOVERY_TAMPERED"),
  );
});
