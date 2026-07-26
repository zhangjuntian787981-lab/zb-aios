import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  HumanDecisionWorkflowError,
  assertC15EffectCompletion,
  canonicalizeHumanDecisionJson,
  createC15EffectOutcomeAuditIntent,
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
  for (const invalidFields of [
    { amount: "125" },
    { subject: "" },
    { subject: "x".repeat(257) },
  ]) {
    const invalidCandidate = structuredClone(harness.fixture.baseline);
    invalidCandidate.fields = invalidFields;
    await assert.rejects(
      harness.workflow.prepare(
        harness.context(),
        harness.prepareRequest({ candidate: invalidCandidate }),
      ),
      code("INVALID_INPUT"),
    );
  }
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
  const withdrawalRecovery = await withdrawn.store.exportRecovery(
    scope(TENANTS[0], "withdrawal-recovery"),
  );
  assert.equal(withdrawalRecovery.withdrawals.length, 1);
  assert.equal(withdrawalRecovery.decisions[0].status, "ACTIVE");
  const frozenDecisionBody = structuredClone(
    withdrawalRecovery.decisions[0],
  );
  delete frozenDecisionBody.decisionSha256;
  assert.equal(
    humanDecisionSha256(frozenDecisionBody),
    withdrawalRecovery.decisions[0].decisionSha256,
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

test("identity lifecycle versions are validated and revoke old decisions", async (t) => {
  for (const entry of [
    { name: "Human", field: "humanSubject" },
    { name: "Workload", field: "workloadActor" },
  ]) {
    await t.test(`${entry.name} lifecycle must be positive`, async () => {
      const harness = createHarness({ idStart: 1900 });
      harness.mutable.nextIdentity.push(
        identity(TENANTS[0], {
          [entry.field]: { lifecycleVersion: 0 },
        }),
      );
      await assert.rejects(
        harness.workflow.prepare(
          harness.context(),
          harness.prepareRequest(),
        ),
        code("ACTION_IDENTITY_INVALID"),
      );
    });

    await t.test(`${entry.name} lifecycle change revokes`, async () => {
      const harness = createHarness({ idStart: 1950 });
      const artifact = await harness.workflow.prepare(
        harness.context(),
        harness.prepareRequest(),
      );
      const decision = await harness.workflow.decide(
        harness.context(),
        harness.decideRequest(artifact),
      );
      const changed = identity(TENANTS[0], {
        [entry.field]: { lifecycleVersion: 2 },
      });
      harness.mutable.nextIdentity.push(changed, changed);
      await assert.rejects(
        harness.workflow.execute(
          harness.context(),
          harness.executeRequest(artifact, decision),
        ),
        code("DECISION_AUTHORITY_REVOKED"),
      );
    });
  }
});

test("effect completion receipts have closed terminal-specific semantics", async (t) => {
  const harness = createHarness({ idStart: 1975 });
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
  const auditIntent = (terminalStatus, idStart) =>
    createC15EffectOutcomeAuditIntent({
      effect,
      terminalStatus,
      identityBinding: effect.executionIdentity,
      authorization: effect.executionAuthorization,
      correlationId: `c15-${terminalStatus.toLowerCase()}`,
      occurredAt: NOW,
      idFactory: deterministicIds(idStart),
    });
  const adapter = createC15SyntheticEffectAdapter();
  const commitReceipt = await adapter.commit(effect);
  const readbackReceipt = await adapter.readback(effect);
  const success = {
    terminalStatus: "SUCCEEDED",
    commitReceipt,
    readbackReceipt,
    compensationReceipt: null,
    auditIntent: auditIntent("SUCCEEDED", 1980),
  };
  assert.doesNotThrow(() => assertC15EffectCompletion(effect, success));

  const invalidSuccesses = [
    {
      name: "commit extra field",
      value: {
        ...success,
        commitReceipt: { ...commitReceipt, unexpected: true },
      },
    },
    {
      name: "commit false",
      value: {
        ...success,
        commitReceipt: { ...commitReceipt, committed: false },
      },
    },
    {
      name: "commit operation mismatch",
      value: {
        ...success,
        commitReceipt: {
          ...commitReceipt,
          operationId: "SYNTHETIC_OTHER_EFFECT",
        },
      },
    },
    {
      name: "commit and readback swapped",
      value: { ...success, commitReceipt: readbackReceipt },
    },
    {
      name: "readback extra field",
      value: {
        ...success,
        readbackReceipt: { ...readbackReceipt, unexpected: true },
      },
    },
    {
      name: "successful observed state mismatch",
      value: {
        ...success,
        readbackReceipt: {
          ...readbackReceipt,
          observedState: "MISMATCH",
        },
      },
    },
    {
      name: "successful readback hash mismatch",
      value: {
        ...success,
        readbackReceipt: {
          ...readbackReceipt,
          readbackSha256:
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        },
      },
    },
  ];
  for (const entry of invalidSuccesses) {
    await t.test(entry.name, () => {
      assert.throws(
        () => assertC15EffectCompletion(effect, entry.value),
        (error) => error instanceof HumanDecisionWorkflowError,
      );
    });
  }

  const mismatchAdapter = createC15SyntheticEffectAdapter({
    mismatchEffectKeys: new Set([effect.effectKey]),
  });
  const mismatchCommit = await mismatchAdapter.commit(effect);
  const mismatchReadback = await mismatchAdapter.readback(effect);
  const compensationReceipt = await mismatchAdapter.compensate(effect);
  const compensatedReadback = await mismatchAdapter.readback(effect);
  const compensated = {
    terminalStatus: "COMPENSATED",
    commitReceipt: mismatchCommit,
    readbackReceipt: compensatedReadback,
    compensationReceipt,
    auditIntent: auditIntent("COMPENSATED", 1990),
  };
  assert.doesNotThrow(
    () => assertC15EffectCompletion(effect, compensated),
  );

  const compensationFailure = {
    schemaVersion: "c15-compensation-failure.v1",
    tenantId: effect.tenantId,
    effectKey: effect.effectKey,
    errorCode: "COMPENSATION_FAILED",
    externalEffectCount: 0,
  };
  const failed = {
    terminalStatus: "COMPENSATION_FAILED",
    commitReceipt: mismatchCommit,
    readbackReceipt: mismatchReadback,
    compensationReceipt: compensationFailure,
    auditIntent: auditIntent("COMPENSATION_FAILED", 1995),
  };
  assert.doesNotThrow(() => assertC15EffectCompletion(effect, failed));

  for (const entry of [
    {
      name: "compensated rejects a still-mismatched final readback",
      value: { ...compensated, readbackReceipt: mismatchReadback },
    },
    {
      name: "compensated rejects failure receipt",
      value: { ...compensated, compensationReceipt: compensationFailure },
    },
    {
      name: "compensated flag must be true",
      value: {
        ...compensated,
        compensationReceipt: {
          ...compensationReceipt,
          compensated: false,
        },
      },
    },
    {
      name: "failed rejects success receipt",
      value: { ...failed, compensationReceipt },
    },
    {
      name: "failure error code is required",
      value: {
        ...failed,
        compensationReceipt: {
          ...compensationFailure,
          errorCode: "",
        },
      },
    },
    {
      name: "failure receipt rejects extra fields",
      value: {
        ...failed,
        compensationReceipt: {
          ...compensationFailure,
          unexpected: true,
        },
      },
    },
    {
      name: "non-success readback cannot claim applied",
      value: {
        ...compensated,
        readbackReceipt,
      },
    },
    {
      name: "non-success hash must bind observed state",
      value: {
        ...compensated,
        readbackReceipt: {
          ...mismatchReadback,
          readbackSha256:
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        },
      },
    },
    {
      name: "compensated observation requires compensated hash",
      value: {
        ...compensated,
        readbackReceipt: {
          ...mismatchReadback,
          observedState: "COMPENSATED",
        },
      },
    },
  ]) {
    await t.test(entry.name, () => {
      assert.throws(
        () => assertC15EffectCompletion(effect, entry.value),
        (error) => error instanceof HumanDecisionWorkflowError,
      );
    });
  }
});

test("idempotency, effect readback, compensation and request loss are safe", async () => {
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
  let firstCompletionRequestLost = true;
  const storeWithRequestLoss = {
    claimEffects: (...args) => harness.store.claimEffects(...args),
    failEffect: (...args) => harness.store.failEffect(...args),
    async completeEffect(...args) {
      if (firstCompletionRequestLost) {
        firstCompletionRequestLost = false;
        throw Object.assign(
          new Error("completion request lost before persistence"),
          { code: "REQUEST_LOST" },
        );
      }
      return harness.store.completeEffect(...args);
    },
  };
  const effectWorker = createC15EffectOutboxWorker({
    store: storeWithRequestLoss,
    adapter,
    workerId: "c15-effect-worker",
    leaseDurationSeconds: 30,
    retryDelaySeconds: 0,
    clock: () => harness.mutable.now,
    idFactory: deterministicIds(2500),
  });
  await assert.rejects(
    effectWorker.runOnce(scope(TENANTS[0], "effect")),
    /completion request lost before persistence/,
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
  const mismatchDelegate = createC15SyntheticEffectAdapter({
    mismatchEffectKeys: new Set([mismatchEffect.effectKey]),
  });
  let mismatchReadbackCount = 0;
  const mismatchAdapter = {
    ...mismatchDelegate,
    async readback(effect) {
      mismatchReadbackCount += 1;
      return mismatchDelegate.readback(effect);
    },
  };
  let mismatchCompletionRequestLost = true;
  const mismatchStoreWithRequestLoss = {
    claimEffects: (...args) => mismatchHarness.store.claimEffects(...args),
    failEffect: (...args) => mismatchHarness.store.failEffect(...args),
    async completeEffect(...args) {
      if (mismatchCompletionRequestLost) {
        mismatchCompletionRequestLost = false;
        throw Object.assign(
          new Error("compensation completion request lost before persistence"),
          { code: "REQUEST_LOST" },
        );
      }
      return mismatchHarness.store.completeEffect(...args);
    },
  };
  const mismatchWorker = createC15EffectOutboxWorker({
    store: mismatchStoreWithRequestLoss,
    adapter: mismatchAdapter,
    workerId: "c15-mismatch-worker",
    retryDelaySeconds: 0,
    clock: () => mismatchHarness.mutable.now,
    idFactory: deterministicIds(2900),
  });
  await assert.rejects(
    mismatchWorker.runOnce(scope(TENANTS[0], "mismatch-request-loss")),
    /compensation completion request lost before persistence/,
  );
  const compensated = await mismatchWorker.runOnce(
    scope(TENANTS[0], "mismatch-retry"),
  );
  assert.equal(compensated.status, "COMPENSATED");
  assert.deepEqual(
    mismatchDelegate.snapshot().compensatedEffectKeys,
    [mismatchEffect.effectKey],
  );
  assert.equal(mismatchReadbackCount, 4);

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

test("compensation remains terminal when completeEffect commits before its ACK is lost", async () => {
  const harness = createHarness({ idStart: 3050 });
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
  const adapter = createC15SyntheticEffectAdapter({
    mismatchEffectKeys: new Set([effect.effectKey]),
  });
  let dropCompletionAck = true;
  const storeWithPostCommitAckLoss = {
    claimEffects: (...args) => harness.store.claimEffects(...args),
    failEffect: (...args) => harness.store.failEffect(...args),
    async completeEffect(...args) {
      const completed = await harness.store.completeEffect(...args);
      if (dropCompletionAck) {
        dropCompletionAck = false;
        throw Object.assign(new Error("completion ack lost after commit"), {
          code: "ACK_LOST",
        });
      }
      return completed;
    },
  };
  const worker = createC15EffectOutboxWorker({
    store: storeWithPostCommitAckLoss,
    adapter,
    workerId: "c15-post-commit-ack-loss-worker",
    retryDelaySeconds: 0,
    clock: () => harness.mutable.now,
    idFactory: deterministicIds(3075),
  });

  await assert.rejects(
    worker.runOnce(scope(TENANTS[0], "post-commit-ack-loss")),
    code("STALE_OUTBOX_LEASE"),
  );
  assert.equal(
    (
      await harness.store.getEffect(
        scope(TENANTS[0], "post-commit-read"),
        effect.effectId,
      )
    ).status,
    "COMPENSATED",
  );
  assert.equal(
    await worker.runOnce(scope(TENANTS[0], "post-commit-retry")),
    null,
  );
  assert.equal(adapter.snapshot().commitCounts[effect.effectKey], 1);
  assert.deepEqual(adapter.snapshot().compensatedEffectKeys, [
    effect.effectKey,
  ]);
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
        return {
          schemaVersion: "c15-c18-audit-ack.v1",
          tenantId: intent.tenantId,
          intentId: intent.intentId,
          c18CommandReceiptKey: intent.intentId,
          c18EventId:
            "aev_018f0000-0000-7000-8000-000000003200",
          c18EventHash:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          c18PayloadSha256:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          duplicate: false,
        };
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
