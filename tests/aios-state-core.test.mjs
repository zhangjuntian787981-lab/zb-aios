import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createAiosStateCore,
  createMemoryAiosStateStore,
} from "../lib/aios-state-core.mjs";
import {
  createC08C0MockToolReceipts,
  createFileC08MockReceiptStore,
} from "../lib/c08-c0-mock-tool-receipts.mjs";
import { createC08SyntheticReferenceCatalog } from "../lib/c08-synthetic-reference-catalog.mjs";

const TENANT_A = "stn_018f0000-0000-7000-8000-000000000010";
const TENANT_B = "stn_018f0000-0000-7000-8000-000000000011";
const HUMAN = "prn_01985000-0000-7000-8000-000000000003";
const HUMAN_B = "prn_01985000-0000-7000-8000-000000000004";
const ACTOR = "prn_01985000-0000-7000-8000-000000000005";
const DELEGATION = "dlg_01985000-0000-7000-8000-000000000006";
const DELEGATION_B = "dlg_01985000-0000-7000-8000-000000000009";
const DELEGATION_NEXT = "dlg_01985000-0000-7000-8000-000000000010";
const HASH_A =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B =
  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C =
  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D =
  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const HASH_E =
  "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const NOW = "2026-07-26T10:00:00.000Z";
const REFERENCE_CATALOG = createC08SyntheticReferenceCatalog(
  JSON.parse(
    await readFile(
      new URL(
        "../implementation/p1/c08/synthetic-reference-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    typeof value === "number"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

function digest(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalize(value))
    .digest("hex")}`;
}

function deterministicUuidFactory() {
  let counter = 100;
  return () => {
    counter += 1;
    return `01985000-0000-7000-8000-${counter
      .toString(16)
      .padStart(12, "0")}`;
  };
}

function serverContext(tenantId = TENANT_A) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
}

function toolResultWorkerContext(tenantId = TENANT_A) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_TOOL_RESULT_ROUTE_DESCRIPTOR",
    tenantId,
    workerTrustSource: "VERIFIED_C0_MOCK_TOOL_WORKER",
    workerPrincipalId: ACTOR,
  };
}

function stateScope(tenantId = TENANT_A) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 7,
    operationId: "C08_OUTBOX_TEST",
    storagePath: "aios-state-core",
    correlationId: "corr-c08-outbox-test",
    decisionId: "azd_c08_outbox_test",
    evidenceRef: "evidence://c06/decisions/c08-outbox-test",
    policyVersion: "policy-c08-v1",
  };
}

function request(idempotencyKey, command, overrides = {}) {
  return {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION,
    idempotencyKey,
    correlationId: `corr-${idempotencyKey}`,
    command,
    ...overrides,
  };
}

function runManifest(inputArtifact) {
  return {
    inputArtifact: {
      artifactId: inputArtifact.artifactId,
      artifactVersion: inputArtifact.artifactVersion,
      contentSha256: inputArtifact.contentSha256,
    },
    model: {
      ref: "synthetic://c08/models/assistant",
      version: "model-1",
      sha256: HASH_B,
    },
    prompt: {
      ref: "synthetic://c08/prompts/run",
      version: "prompt-1",
      sha256: HASH_C,
    },
    skill: {
      ref: "synthetic://c08/skills/analyze",
      version: "skill-1",
      sha256: HASH_D,
    },
    knowledge: [
      {
        evidenceRef: "evidence://c08/knowledge/synthetic-handbook",
        version: "knowledge-1",
        asOf: "2026-07-26T09:59:00.000Z",
        sha256: HASH_E,
      },
    ],
    traceRef: "test://c08/traces/run-1",
  };
}

function identity(
  humanPrincipalId = HUMAN,
  tenantId = TENANT_A,
  sessionId = "ses_synthetic",
  delegationId = humanPrincipalId === HUMAN_B
    ? DELEGATION_B
    : DELEGATION,
) {
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_01985000-0000-7000-8000-000000000007",
    identityLinkId: "lnk_01985000-0000-7000-8000-000000000008",
    sessionId,
    humanSubject: {
      principalId: humanPrincipalId,
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
    purposeRef: "policy://c08/purpose/manage-state",
    delegationChain: [
      {
        delegationId,
        delegatorPrincipalId: humanPrincipalId,
        delegatePrincipalId: ACTOR,
        purposeRef: "policy://c08/purpose/manage-state",
        lifecycleVersion: 1,
        expiresAt: "2026-07-26T11:00:00.000Z",
      },
    ],
    trustSource:
      "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
    authorizationStatus: "NOT_EVALUATED",
  };
}

function createHarness({
  store = createMemoryAiosStateStore(),
  identityError = null,
  authorization = "ALLOW",
  admission = "ACTIVE",
  controlAllowed = true,
  authorizationMutatesHuman = false,
  mockToolReceipts = createC08C0MockToolReceipts(),
} = {}) {
  const calls = [];
  let currentHuman = HUMAN;
  let currentSession = "ses_synthetic";
  let currentDelegation = null;
  const tenantRegistry = {
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      calls.push(["admit", tenantId, expectedTenantKind]);
      if (admission !== "ACTIVE") {
        const error = new Error("not active");
        error.code = "TENANT_NOT_ACTIVE";
        throw error;
      }
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 7,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const stablePrincipalRegistry = {
    async resolveActionIdentity(_context, actionRequest) {
      calls.push(["identity", actionRequest.expectedTenantId]);
      if (identityError) throw identityError;
      return identity(
        currentHuman,
        actionRequest.expectedTenantId,
        currentSession,
        currentDelegation ?? undefined,
      );
    },
  };
  const authorizer = {
    async enforce(context, authorizationRequest, descriptor) {
      const decisionIdentity = identity(
        currentHuman,
        context.tenantId,
        currentSession,
        currentDelegation ?? undefined,
      );
      calls.push([
        "authorize",
        context.tenantId,
        authorizationRequest.resourceId,
        descriptor.surface,
      ]);
      if (authorization !== "ALLOW") {
        const error = new Error("denied");
        error.code = authorization;
        throw error;
      }
      if (authorizationMutatesHuman) currentHuman = HUMAN_B;
      const decisionSuffix = descriptor.surface
        .toLowerCase()
        .replace("_", "-");
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        decisionId: `azd_synthetic_c08_${decisionSuffix}`,
        evidenceRef: `evidence://c06/decisions/c08-${decisionSuffix}`,
        policyVersion: "policy-c08-v1",
        tenantId: context.tenantId,
        surface: descriptor.surface,
        resourceId: authorizationRequest.resourceId,
        humanPrincipalId:
          decisionIdentity.humanSubject.principalId,
        humanSecurityEpoch:
          decisionIdentity.humanSubject.securityEpoch,
        workloadActorPrincipalId:
          decisionIdentity.workloadActor.principalId,
        workloadActorSecurityEpoch:
          decisionIdentity.workloadActor.securityEpoch,
        leafDelegationId:
          decisionIdentity.delegationChain.at(-1).delegationId,
        delegationChainSha256: digest(
          decisionIdentity.delegationChain,
        ),
        purposeRef: decisionIdentity.purposeRef,
      };
    },
  };
  const core = createAiosStateCore({
    tenantRegistry,
    stablePrincipalRegistry,
    authorizer,
    store,
    referenceCatalog: REFERENCE_CATALOG,
    toolReceiptVerifier: mockToolReceipts.verifier,
    controlAuthorize: async () =>
      controlAllowed
        ? {
            allowed: true,
            decisionId: "azd_c08_control",
            evidenceRef: "evidence://c06/decisions/c08-control",
            policyVersion: "policy-c08-v1",
          }
        : { allowed: false },
    idFactory: deterministicUuidFactory(),
    clock: () => NOW,
  });
  return {
    calls,
    core,
    mockToolReceipts,
    store,
    setHuman(value) {
      currentHuman = value;
    },
    setSession(value) {
      currentSession = value;
    },
    setDelegation(value) {
      currentDelegation = value;
    },
  };
}

async function buildStartedRun(harness) {
  const createdCase = await harness.core.execute(
    serverContext(),
    request("create-case", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/analyze-order",
    }),
  );
  const openedThread = await harness.core.execute(
    serverContext(),
    request("open-thread", {
      kind: "OPEN_THREAD",
      caseId: createdCase.caseId,
      purposeRef: "policy://c08/purpose/analyze-order",
    }),
  );
  const inputArtifact = await harness.core.execute(
    serverContext(),
    request("input-artifact", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: openedThread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "INPUT",
      contentRef: "synthetic://c08/artifacts/input-order",
      contentSha256: HASH_A,
    }),
  );
  const manifest = runManifest(inputArtifact);
  const startedRun = await harness.core.execute(
    serverContext(),
    request("start-run", {
      kind: "START_RUN",
      threadId: openedThread.threadId,
      manifest,
    }),
  );
  return {
    createdCase,
    openedThread,
    inputArtifact,
    manifest,
    startedRun,
  };
}

async function buildPreparedRun(harness) {
  const started = await buildStartedRun(harness);
  const {
    createdCase,
    openedThread,
    inputArtifact,
    manifest,
    startedRun,
  } = started;
  const preparedTool = await harness.core.execute(
    serverContext(),
    request("prepare-tool", {
      kind: "PREPARE_TOOL_CALL",
      runId: startedRun.runId,
      expectedRunVersion: 1,
      operationRef: "synthetic://c08/tools/catalog-read",
      operationVersion: "tool-1",
      requestHash: HASH_B,
      compensationRef: "test://c08/compensations/noop",
    }),
  );
  return {
    createdCase,
    openedThread,
    inputArtifact,
    manifest,
    startedRun,
    preparedTool,
  };
}

async function buildCompleteRun(harness) {
  const prepared = await buildPreparedRun(harness);
  const {
    createdCase,
    openedThread,
    inputArtifact,
    manifest,
    startedRun,
    preparedTool,
  } = prepared;
  const acceptedReceipt = await harness.mockToolReceipts.executor.accept({
    tenantId: TENANT_A,
    runId: startedRun.runId,
    toolCallId: preparedTool.toolCallId,
    effectKey: preparedTool.effectKey,
    requestHash: preparedTool.requestHash,
    operationRef: "synthetic://c08/tools/catalog-read",
    operationVersion: "tool-1",
    outcome: "SUCCEEDED",
  });
  const toolResult = await harness.core.recordToolCallResult(
    toolResultWorkerContext(),
    {
      idempotencyKey: "tool-result",
      correlationId: "corr-tool-result",
      command: {
      kind: "RECORD_TOOL_CALL_RESULT",
      runId: startedRun.runId,
      expectedRunVersion: 2,
      toolCallId: preparedTool.toolCallId,
      expectedToolCallVersion: 1,
        receiptId: acceptedReceipt.receiptId,
      },
    },
  );
  const resultArtifact = await harness.core.execute(
    serverContext(),
    request("result-artifact", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: openedThread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "RESULT",
      contentRef: "synthetic://c08/artifacts/result-analysis",
      contentSha256: HASH_D,
    }),
  );
  const finishedRun = await harness.core.execute(
    serverContext(),
    request("finish-run", {
      kind: "FINISH_RUN",
      runId: startedRun.runId,
      expectedRunVersion: 3,
      outcome: "SUCCEEDED",
      resultArtifact: {
        artifactId: resultArtifact.artifactId,
        artifactVersion: resultArtifact.artifactVersion,
        contentSha256: resultArtifact.contentSha256,
      },
    }),
  );
  return {
    createdCase,
    openedThread,
    inputArtifact,
    manifest,
    startedRun,
    preparedTool,
    toolResult,
    resultArtifact,
    finishedRun,
  };
}

test("C08 exposes separate employee and Tool result Worker surfaces", () => {
  const { core } = createHarness();
  assert.deepEqual(Object.keys(core), [
    "execute",
    "recordToolCallResult",
    "inspectRun",
    "reconstructRun",
    "snapshot",
  ]);
});

test("a running Run exposes recoverable input, version, state and pending effect", async () => {
  const harness = createHarness();
  const flow = await buildPreparedRun(harness);

  const inspected = await harness.core.inspectRun(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION,
    runId: flow.startedRun.runId,
    correlationId: "corr-inspect-running",
  });

  assert.equal(inspected.state, "RUNNING");
  assert.equal(inspected.version, 2);
  assert.equal(inspected.recoveryStatus, "IN_PROGRESS");
  assert.deepEqual(inspected.snapshot.case, {
    caseId: flow.createdCase.caseId,
    state: "OPEN",
    version: 1,
    goalRef: "synthetic://c08/goals/analyze-order",
  });
  assert.deepEqual(inspected.snapshot.thread, {
    threadId: flow.openedThread.threadId,
    caseId: flow.createdCase.caseId,
    state: "OPEN",
    version: 1,
    purposeRef: "policy://c08/purpose/analyze-order",
  });
  assert.deepEqual(inspected.snapshot.input, {
    artifactId: flow.inputArtifact.artifactId,
    artifactVersion: 1,
    contentRef: "synthetic://c08/artifacts/input-order",
    contentSha256: HASH_A,
  });
  assert.deepEqual(inspected.snapshot.model, flow.manifest.model);
  assert.equal(inspected.snapshot.result, null);
  assert.equal(inspected.snapshot.reconstructionHash, null);
  assert.deepEqual(inspected.snapshot.tools, [
    {
      toolCallId: flow.preparedTool.toolCallId,
      state: "PREPARED",
      version: 1,
      operationRef: "synthetic://c08/tools/catalog-read",
      operationVersion: "tool-1",
      requestHash: HASH_B,
      effectKey: flow.preparedTool.effectKey,
      compensationRef: "test://c08/compensations/noop",
      policy: {
        decisionId: "azd_synthetic_c08_tool-call",
        evidenceRef: "evidence://c06/decisions/c08-tool-call",
        policyVersion: "policy-c08-v1",
      },
      outcome: null,
      receiptRef: null,
      receiptHash: null,
    },
  ]);
  assert.equal(inspected.verificationScope, "P1_SYNTHETIC_ONLY");
  assert.equal(inspected.productionVerificationStatus, "NOT_VERIFIED");
});

test("a Run permits only one prepared ToolCall at a time", async () => {
  const harness = createHarness();
  const flow = await buildPreparedRun(harness);

  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request("prepare-second-tool", {
        kind: "PREPARE_TOOL_CALL",
        runId: flow.startedRun.runId,
        expectedRunVersion: 2,
        operationRef: "synthetic://c08/tools/catalog-read",
        operationVersion: "tool-1",
        requestHash: HASH_C,
        compensationRef: "test://c08/compensations/noop",
      }),
    ),
    { code: "TOOL_CALL_IN_FLIGHT" },
  );
  const inspected = await harness.core.inspectRun(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION,
    runId: flow.startedRun.runId,
    correlationId: "corr-inspect-one-prepared",
  });
  assert.equal(inspected.version, 2);
  assert.equal(inspected.snapshot.tools.length, 1);
  assert.equal(inspected.snapshot.tools[0].toolCallId, flow.preparedTool.toolCallId);
});

test("another authorized Human cannot mutate an owned Run but may inspect it", async () => {
  const harness = createHarness();
  const flow = await buildStartedRun(harness);
  harness.setHuman(HUMAN_B);

  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request(
        "human-b-prepare",
        {
          kind: "PREPARE_TOOL_CALL",
          runId: flow.startedRun.runId,
          expectedRunVersion: 1,
          operationRef: "synthetic://c08/tools/catalog-read",
          operationVersion: "tool-1",
          requestHash: HASH_B,
          compensationRef: "test://c08/compensations/noop",
        },
        { delegationId: DELEGATION_B },
      ),
    ),
    { code: "RUN_ACTION_IDENTITY_MISMATCH" },
  );
  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request(
        "human-b-finish",
        {
          kind: "FINISH_RUN",
          runId: flow.startedRun.runId,
          expectedRunVersion: 1,
          outcome: "FAILED",
          resultArtifact: {
            artifactId: flow.inputArtifact.artifactId,
            artifactVersion: flow.inputArtifact.artifactVersion,
            contentSha256: flow.inputArtifact.contentSha256,
          },
        },
        { delegationId: DELEGATION_B },
      ),
    ),
    { code: "RUN_ACTION_IDENTITY_MISMATCH" },
  );
  const managerView = await harness.core.inspectRun(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION_B,
    runId: flow.startedRun.runId,
    correlationId: "corr-human-b-inspect",
  });
  assert.equal(managerView.version, 1);
  assert.equal(
    managerView.snapshot.actor.humanSubject.principalId,
    HUMAN,
  );
  harness.setHuman(HUMAN);
  const inspected = await harness.core.inspectRun(serverContext(), {
    sessionToken: "synthetic-session-token",
    delegationId: DELEGATION,
    runId: flow.startedRun.runId,
    correlationId: "corr-human-a-inspect",
  });
  assert.equal(inspected.version, 1);
  assert.equal(inspected.snapshot.tools.length, 0);
  assert.equal(
    inspected.snapshot.actor.humanSubject.principalId,
    HUMAN,
  );
});

test("the same Human can continue an owned Run after Session and Delegation renewal", async () => {
  const harness = createHarness();
  const flow = await buildStartedRun(harness);
  harness.setSession("ses_synthetic_after_restart");
  harness.setDelegation(DELEGATION_NEXT);

  const prepared = await harness.core.execute(
    serverContext(),
    request(
      "same-human-after-restart",
      {
        kind: "PREPARE_TOOL_CALL",
        runId: flow.startedRun.runId,
        expectedRunVersion: 1,
        operationRef: "synthetic://c08/tools/catalog-read",
        operationVersion: "tool-1",
        requestHash: HASH_B,
        compensationRef: "test://c08/compensations/noop",
      },
      {
        sessionToken: "synthetic-session-token-after-restart",
        delegationId: DELEGATION_NEXT,
      },
    ),
  );

  assert.equal(prepared.runId, flow.startedRun.runId);
  assert.equal(prepared.runVersion, 2);
});

test("ordinary execute and an untrusted Worker cannot record Tool results", async () => {
  const harness = createHarness();
  const command = {
    kind: "RECORD_TOOL_CALL_RESULT",
    runId: "run_018f0000-0000-7000-8000-000000000021",
    expectedRunVersion: 1,
    toolCallId: "tcl_018f0000-0000-7000-8000-000000000022",
    expectedToolCallVersion: 1,
    receiptId:
      "mrc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  };
  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request("ordinary-tool-result", command),
    ),
    { code: "UNKNOWN_COMMAND" },
  );
  await assert.rejects(
    harness.core.recordToolCallResult(
      {
        ...toolResultWorkerContext(),
        workerTrustSource: "CLIENT_ASSERTED",
      },
      {
        idempotencyKey: "untrusted-tool-result",
        correlationId: "corr-untrusted-tool-result",
        command,
      },
    ),
    { code: "UNTRUSTED_TOOL_RESULT_ROUTE" },
  );
  assert.equal(harness.calls.length, 0);
});

test("one completed Run reconstructs every frozen version and provenance", async () => {
  const harness = createHarness();
  const flow = await buildCompleteRun(harness);

  const reconstructed = await harness.core.reconstructRun(
    serverContext(),
    {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION,
      runId: flow.startedRun.runId,
      correlationId: "corr-reconstruct",
    },
  );

  assert.equal(reconstructed.state, "SUCCEEDED");
  assert.equal(reconstructed.version, 4);
  assert.equal(
    reconstructed.reconstructionHash,
    flow.finishedRun.reconstructionHash,
  );
  assert.deepEqual(reconstructed.manifest.input, {
    artifactId: flow.inputArtifact.artifactId,
    artifactVersion: 1,
    contentRef: "synthetic://c08/artifacts/input-order",
    contentSha256: HASH_A,
  });
  assert.deepEqual(reconstructed.manifest.model, flow.manifest.model);
  assert.deepEqual(reconstructed.manifest.prompt, flow.manifest.prompt);
  assert.deepEqual(reconstructed.manifest.skill, flow.manifest.skill);
  assert.deepEqual(reconstructed.manifest.knowledge, flow.manifest.knowledge);
  assert.deepEqual(reconstructed.manifest.policy, {
    decisionId: "azd_synthetic_c08_manage",
    evidenceRef: "evidence://c06/decisions/c08-manage",
    policyVersion: "policy-c08-v1",
  });
  assert.equal(reconstructed.manifest.tools.length, 1);
  assert.deepEqual(reconstructed.manifest.tools[0], {
    toolCallId: flow.preparedTool.toolCallId,
    operationRef: "synthetic://c08/tools/catalog-read",
    operationVersion: "tool-1",
    requestHash: HASH_B,
    effectKey: flow.preparedTool.effectKey,
    compensationRef: "test://c08/compensations/noop",
    policy: {
      decisionId: "azd_synthetic_c08_tool-call",
      evidenceRef: "evidence://c06/decisions/c08-tool-call",
      policyVersion: "policy-c08-v1",
    },
    outcome: "SUCCEEDED",
    receiptRef: flow.toolResult.receiptRef,
    receiptHash: flow.toolResult.receiptHash,
  });
  assert.equal(reconstructed.manifest.result.contentSha256, HASH_D);
  assert.equal(reconstructed.manifest.tenantLifecycleVersion, 7);
  assert.equal(
    reconstructed.manifest.actor.humanSubject.principalId,
    HUMAN,
  );
  assert.equal(
    reconstructed.manifest.dependentPackageStatus,
    "PENDING_DEPENDENT_PACKAGE",
  );
  assert.equal(reconstructed.verificationScope, "P1_SYNTHETIC_ONLY");
  assert.equal(reconstructed.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(
    harness.calls.some(
      ([kind, , resourceId, surface]) =>
        kind === "authorize" &&
        resourceId ===
          "synthetic-tenant-northstar-fasteners--tool-call" &&
        surface === "TOOL_CALL",
    ),
    true,
  );

  const snapshot = await harness.core.snapshot(
    { actorId: "synthetic-control" },
    { tenantId: TENANT_A },
  );
  assert.deepEqual(snapshot.counts, {
    cases: 1,
    threads: 1,
    runs: 1,
    artifacts: 2,
    toolCalls: 1,
    events: 8,
    outbox: 8,
    receipts: 8,
  });
  assert.deepEqual(snapshot.runStates, { SUCCEEDED: 1 });
  assert.deepEqual(snapshot.toolCallStates, { SUCCEEDED: 1 });
  assert.deepEqual(snapshot.outboxStates, { PENDING: 8 });
});

test("C08 rejects routing, identity and Enterprise injection before dependencies", async () => {
  for (const injected of [
    { tenantId: TENANT_A },
    { principalId: HUMAN },
    { actorId: ACTOR },
    { authorization: "ALLOW" },
    { adapterId: "postgres" },
    { endpoint: "https://erp.example" },
  ]) {
    const harness = createHarness();
    await assert.rejects(
      harness.core.execute(serverContext(), {
        ...request("inject", {
          kind: "CREATE_CASE",
          goalRef: "synthetic://c08/goals/safe",
        }),
        ...injected,
      }),
      { code: "INVALID_INPUT" },
    );
    assert.equal(harness.calls.length, 0);
  }

  for (const injected of [
    { tenantId: TENANT_A },
    { actorId: ACTOR },
    { policyVersion: "forged" },
    { connectorInstanceId: "oa-prod" },
    { body: "enterprise record" },
  ]) {
    const harness = createHarness();
    await assert.rejects(
      harness.core.execute(
        serverContext(),
        request("inject-command", {
          kind: "CREATE_CASE",
          goalRef: "synthetic://c08/goals/safe",
          ...injected,
        }),
      ),
      { code: "INVALID_INPUT" },
    );
    assert.equal(harness.calls.length, 0);
  }

  const enterpriseHarness = createHarness();
  await assert.rejects(
    enterpriseHarness.core.execute(
      serverContext("enterprise_001"),
      request("enterprise", {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/safe",
      }),
    ),
    { code: "P3_REQUIRED" },
  );
  assert.equal(enterpriseHarness.calls.length, 0);

  const externalRefHarness = createHarness();
  await assert.rejects(
    externalRefHarness.core.execute(
      serverContext(),
      request("external-ref", {
        kind: "CREATE_CASE",
        goalRef: "https://oa.example/case/1",
      }),
    ),
    { code: "P3_REQUIRED" },
  );
  assert.equal(externalRefHarness.calls.length, 0);

  const unfrozenRefHarness = createHarness();
  await assert.rejects(
    unfrozenRefHarness.core.execute(
      serverContext(),
      request("unfrozen-ref", {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/not-frozen",
      }),
    ),
    { code: "SYNTHETIC_REFERENCE_UNVERIFIED" },
  );
  assert.equal(unfrozenRefHarness.calls.length, 0);
});

test("identity, authorization and final Tenant admission all fail closed", async () => {
  const identityHarness = createHarness({
    identityError: new Error("identity unavailable"),
  });
  await assert.rejects(
    identityHarness.core.execute(
      serverContext(),
      request("identity-deny", {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/safe",
      }),
    ),
    { code: "ACTION_IDENTITY_INVALID" },
  );
  assert.deepEqual(
    identityHarness.calls.map(([kind]) => kind),
    ["identity"],
  );

  const authorizationHarness = createHarness({
    authorization: "ACCESS_DENIED",
  });
  await assert.rejects(
    authorizationHarness.core.execute(
      serverContext(),
      request("authorization-deny", {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/safe",
      }),
    ),
    { code: "ACCESS_DENIED" },
  );
  assert.deepEqual(
    authorizationHarness.calls.map(([kind]) => kind),
    ["identity", "authorize"],
  );

  const admissionHarness = createHarness({ admission: "SUSPENDED" });
  await assert.rejects(
    admissionHarness.core.execute(
      serverContext(),
      request("admission-deny", {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/safe",
      }),
    ),
    { code: "TENANT_NOT_ACTIVE" },
  );
  assert.deepEqual(
    admissionHarness.calls.map(([kind]) => kind),
    ["identity", "authorize", "identity", "admit"],
  );
});

test("C08 rejects an identity change during authorization before admission", async () => {
  const harness = createHarness({ authorizationMutatesHuman: true });
  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request("identity-change", {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/safe",
      }),
    ),
    { code: "ACTION_IDENTITY_CHANGED" },
  );
  assert.deepEqual(
    harness.calls.map(([kind]) => kind),
    ["identity", "authorize", "identity"],
  );

  const snapshot = await harness.core.snapshot(
    { actorId: "synthetic-control" },
    { tenantId: TENANT_A },
  );
  assert.equal(snapshot.counts.cases, 0);
});

test("32 concurrent identical commands commit one state, event and Outbox", async () => {
  const harness = createHarness();
  const commandRequest = request("parallel-case", {
    kind: "CREATE_CASE",
    goalRef: "synthetic://c08/goals/safe",
  });
  const results = await Promise.all(
    Array.from({ length: 32 }, () =>
      harness.core.execute(serverContext(), commandRequest),
    ),
  );

  assert.equal(new Set(results.map(({ caseId }) => caseId)).size, 1);
  assert.equal(new Set(results.map(({ eventId }) => eventId)).size, 1);
  assert.equal(results.filter(({ duplicate }) => !duplicate).length, 1);
  assert.equal(results.filter(({ duplicate }) => duplicate).length, 31);

  const snapshot = await harness.core.snapshot(
    { actorId: "synthetic-control" },
    { tenantId: TENANT_A },
  );
  assert.deepEqual(snapshot.counts, {
    cases: 1,
    threads: 0,
    runs: 0,
    artifacts: 0,
    toolCalls: 0,
    events: 1,
    outbox: 1,
    receipts: 1,
  });
});

test("idempotency is bound to exact command and resolved Human identity", async () => {
  const harness = createHarness();
  const first = request("identity-bound", {
    kind: "CREATE_CASE",
    goalRef: "synthetic://c08/goals/safe",
  });
  await harness.core.execute(serverContext(), first);

  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request("identity-bound", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/alternate",
      }),
    ),
    { code: "IDEMPOTENCY_CONFLICT" },
  );

  harness.setHuman(HUMAN_B);
  await assert.rejects(
    harness.core.execute(serverContext(), first),
    { code: "IDEMPOTENCY_CONFLICT" },
  );
});

test("Artifact versions keep one ID and advance from the expected version", async () => {
  const harness = createHarness();
  const createdCase = await harness.core.execute(
    serverContext(),
    request("artifact-chain-case", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/safe",
    }),
  );
  const thread = await harness.core.execute(
    serverContext(),
    request("artifact-chain-thread", {
      kind: "OPEN_THREAD",
      caseId: createdCase.caseId,
      purposeRef: "policy://c08/purpose/analyze-order",
    }),
  );
  const first = await harness.core.execute(
    serverContext(),
    request("artifact-chain-v1", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "INPUT",
      contentRef: "synthetic://c08/artifacts/input-order",
      contentSha256: HASH_A,
    }),
  );
  const second = await harness.core.execute(
    serverContext(),
    request("artifact-chain-v2", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: first.artifactId,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 1,
      artifactKind: "INPUT",
      contentRef: "synthetic://c08/artifacts/input-order-v2",
      contentSha256: HASH_B,
    }),
  );
  assert.equal(second.artifactId, first.artifactId);
  assert.equal(second.artifactVersion, 2);

  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request("artifact-chain-stale", {
        kind: "RECORD_ARTIFACT_VERSION",
        artifactId: first.artifactId,
        caseId: createdCase.caseId,
        threadId: thread.threadId,
        expectedArtifactVersion: 1,
        artifactKind: "INPUT",
        contentRef: "synthetic://c08/artifacts/input-order-v2",
        contentSha256: HASH_B,
      }),
    ),
    { code: "STALE_VERSION" },
  );
});

test("FAILED Run reconstructs an empty Tool list without a fabricated call", async () => {
  const harness = createHarness();
  const createdCase = await harness.core.execute(
    serverContext(),
    request("failed-no-tool-case", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/safe",
    }),
  );
  const thread = await harness.core.execute(
    serverContext(),
    request("failed-no-tool-thread", {
      kind: "OPEN_THREAD",
      caseId: createdCase.caseId,
      purposeRef: "policy://c08/purpose/analyze-order",
    }),
  );
  const input = await harness.core.execute(
    serverContext(),
    request("failed-no-tool-input", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "INPUT",
      contentRef: "synthetic://c08/artifacts/input-order",
      contentSha256: HASH_A,
    }),
  );
  const result = await harness.core.execute(
    serverContext(),
    request("failed-no-tool-result", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "RESULT",
      contentRef: "synthetic://c08/artifacts/failure",
      contentSha256: HASH_E,
    }),
  );
  const run = await harness.core.execute(
    serverContext(),
    request("failed-no-tool-run", {
      kind: "START_RUN",
      threadId: thread.threadId,
      manifest: runManifest(input),
    }),
  );
  await harness.core.execute(
    serverContext(),
    request("failed-no-tool-finish", {
      kind: "FINISH_RUN",
      runId: run.runId,
      expectedRunVersion: 1,
      outcome: "FAILED",
      resultArtifact: {
        artifactId: result.artifactId,
        artifactVersion: result.artifactVersion,
        contentSha256: result.contentSha256,
      },
    }),
  );
  const reconstructed = await harness.core.reconstructRun(
    serverContext(),
    {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION,
      runId: run.runId,
      correlationId: "corr-failed-no-tool",
    },
  );
  assert.equal(reconstructed.state, "FAILED");
  assert.deepEqual(reconstructed.manifest.tools, []);
});

test("stable PostgreSQL Store conflicts remain stable at the Core boundary", async () => {
  const base = createMemoryAiosStateStore();
  const store = {
    ...base,
    async runCommand() {
      throw Object.assign(new Error("hidden database detail"), {
        name: "AiosStateStoreError",
        code: "IDEMPOTENCY_CONFLICT",
      });
    },
  };
  const harness = createHarness({ store });
  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request("stable-store-error", {
        kind: "CREATE_CASE",
        goalRef: "synthetic://c08/goals/safe",
      }),
    ),
    (error) =>
      error.name === "AiosStateError" &&
      error.code === "IDEMPOTENCY_CONFLICT" &&
      !error.message.includes("hidden database detail"),
  );
});

test("Memory Store refuses a command without one exact Event and Outbox pair", async () => {
  const store = createMemoryAiosStateStore();
  await assert.rejects(
    store.runCommand(
      stateScope(),
      {
        idempotencyKey: "memory-missing-evidence",
        requestHash: HASH_A,
        commandKind: "CREATE_CASE",
        correlationId: "corr-memory-missing-evidence",
      },
      async () => ({ caseId: "not-committed" }),
    ),
    { code: "EVIDENCE_PAIR_INVALID" },
  );
});

test("stale Run versions and unverified Tool receipts cannot advance state", async () => {
  const harness = createHarness();
  const createdCase = await harness.core.execute(
    serverContext(),
    request("case-stale", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/safe",
    }),
  );
  const thread = await harness.core.execute(
    serverContext(),
    request("thread-stale", {
      kind: "OPEN_THREAD",
      caseId: createdCase.caseId,
      purposeRef: "policy://c08/purpose/analyze-order",
    }),
  );
  const input = await harness.core.execute(
    serverContext(),
    request("input-stale", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "INPUT",
      contentRef: "synthetic://c08/artifacts/input-order",
      contentSha256: HASH_A,
    }),
  );
  const run = await harness.core.execute(
    serverContext(),
    request("run-stale", {
      kind: "START_RUN",
      threadId: thread.threadId,
      manifest: runManifest(input),
    }),
  );

  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request("prepare-stale", {
        kind: "PREPARE_TOOL_CALL",
        runId: run.runId,
        expectedRunVersion: 2,
        operationRef: "synthetic://c08/tools/catalog-read",
        operationVersion: "tool-1",
        requestHash: HASH_B,
        compensationRef: null,
      }),
    ),
    { code: "STALE_VERSION" },
  );

  const prepared = await harness.core.execute(
    serverContext(),
    request("prepare-valid", {
      kind: "PREPARE_TOOL_CALL",
      runId: run.runId,
      expectedRunVersion: 1,
      operationRef: "synthetic://c08/tools/catalog-read",
      operationVersion: "tool-1",
      requestHash: HASH_B,
      compensationRef: null,
    }),
  );
  await assert.rejects(
    harness.core.recordToolCallResult(
      toolResultWorkerContext(),
      {
        idempotencyKey: "receipt-mismatch",
        correlationId: "corr-receipt-mismatch",
        command: {
        kind: "RECORD_TOOL_CALL_RESULT",
        runId: run.runId,
        expectedRunVersion: 2,
        toolCallId: prepared.toolCallId,
        expectedToolCallVersion: 1,
          receiptId:
            "mrc_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        },
      },
    ),
    { code: "TOOL_RECEIPT_UNVERIFIED" },
  );
});

test("a Run cannot finish or reconstruct without result and terminal Tool evidence", async () => {
  const harness = createHarness();
  const createdCase = await harness.core.execute(
    serverContext(),
    request("case-incomplete", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/safe",
    }),
  );
  const thread = await harness.core.execute(
    serverContext(),
    request("thread-incomplete", {
      kind: "OPEN_THREAD",
      caseId: createdCase.caseId,
      purposeRef: "policy://c08/purpose/analyze-order",
    }),
  );
  const input = await harness.core.execute(
    serverContext(),
    request("input-incomplete", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "INPUT",
      contentRef: "synthetic://c08/artifacts/input-order",
      contentSha256: HASH_A,
    }),
  );
  const result = await harness.core.execute(
    serverContext(),
    request("result-incomplete", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "RESULT",
      contentRef: "synthetic://c08/artifacts/result-analysis",
      contentSha256: HASH_D,
    }),
  );
  const run = await harness.core.execute(
    serverContext(),
    request("run-incomplete", {
      kind: "START_RUN",
      threadId: thread.threadId,
      manifest: runManifest(input),
    }),
  );

  await assert.rejects(
    harness.core.execute(
      serverContext(),
      request("finish-incomplete", {
        kind: "FINISH_RUN",
        runId: run.runId,
        expectedRunVersion: 1,
        outcome: "SUCCEEDED",
        resultArtifact: {
          artifactId: result.artifactId,
          artifactVersion: result.artifactVersion,
          contentSha256: result.contentSha256,
        },
      }),
    ),
    { code: "RUN_NOT_RECONSTRUCTABLE" },
  );
  await assert.rejects(
    harness.core.reconstructRun(serverContext(), {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION,
      runId: run.runId,
      correlationId: "corr-incomplete",
    }),
    { code: "RUN_NOT_RECONSTRUCTABLE" },
  );
});

test("stored Run references remain frozen after caller mutation", async () => {
  const harness = createHarness();
  const flow = await buildCompleteRun(harness);
  flow.manifest.model.version = "forged-model";
  flow.manifest.knowledge[0].evidenceRef =
    "synthetic://c08/knowledge/forged";

  const reconstructed = await harness.core.reconstructRun(
    serverContext(),
    {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION,
      runId: flow.startedRun.runId,
      correlationId: "corr-frozen",
    },
  );
  assert.equal(reconstructed.manifest.model.version, "model-1");
  assert.equal(
    reconstructed.manifest.knowledge[0].evidenceRef,
    "evidence://c08/knowledge/synthetic-handbook",
  );
});

test("reconstruction fails closed when persisted evidence is altered", async () => {
  const baseStore = createMemoryAiosStateStore();
  const writerHarness = createHarness({ store: baseStore });
  const flow = await buildCompleteRun(writerHarness);
  const tamperingStore = {
    ...baseStore,
    async readRun(scope, query) {
      const value = await baseStore.readRun(scope, query);
      value.run.baseManifest.model.version = "tampered-model";
      return value;
    },
  };
  const readerHarness = createHarness({ store: tamperingStore });
  await assert.rejects(
    readerHarness.core.reconstructRun(serverContext(), {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION,
      runId: flow.startedRun.runId,
      correlationId: "corr-tamper",
    }),
    { code: "RECONSTRUCTION_MISMATCH" },
  );
});

test("reconstruction hash detects altered Tool authorization evidence", async () => {
  const baseStore = createMemoryAiosStateStore();
  const writerHarness = createHarness({ store: baseStore });
  const flow = await buildCompleteRun(writerHarness);
  const tamperingStore = {
    ...baseStore,
    async readRun(scope, query) {
      const value = await baseStore.readRun(scope, query);
      value.toolCalls[0].authorization.policyVersion =
        "tampered-policy";
      return value;
    },
  };
  const readerHarness = createHarness({ store: tamperingStore });

  await assert.rejects(
    readerHarness.core.reconstructRun(serverContext(), {
      sessionToken: "synthetic-session-token",
      delegationId: DELEGATION,
      runId: flow.startedRun.runId,
      correlationId: "corr-tool-policy-tamper",
    }),
    { code: "RECONSTRUCTION_MISMATCH" },
  );
});

test("Outbox retry reuses one effectKey after Mock accepted then worker crashed", async (t) => {
  const rootDir = await mkdtemp(join(tmpdir(), "c08-outbox-mock-"));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  const deliveryMock = createC08C0MockToolReceipts({
    store: createFileC08MockReceiptStore({ rootDir }),
  });
  const harness = createHarness({ mockToolReceipts: deliveryMock });
  const flow = await buildPreparedRun(harness);
  async function acceptMock(mock, event) {
    const { effect_key: key, request_hash: requestHash } = event.event.data;
    return mock.executor.accept({
      tenantId: TENANT_A,
      runId: flow.startedRun.runId,
      toolCallId: flow.preparedTool.toolCallId,
      effectKey: key,
      requestHash,
      operationRef: "synthetic://c08/tools/catalog-read",
      operationVersion: "tool-1",
      outcome: "SUCCEEDED",
    });
  }

  const firstClaims = await harness.store.claimOutbox(stateScope(), {
    workerId: "worker-a",
    now: "2026-07-26T10:00:00.000Z",
    leaseExpiresAt: "2026-07-26T10:01:00.000Z",
  });
  const firstToolClaim = firstClaims.find(
    ({ event }) => event.type === "product.aios.tool-call-prepared.v1",
  );
  assert.equal(firstToolClaim.event.data.effect_key, flow.preparedTool.effectKey);
  const firstAccepted = await acceptMock(deliveryMock, firstToolClaim);
  assert.equal(firstAccepted.duplicate, false);

  const restartedMock = createC08C0MockToolReceipts({
    store: createFileC08MockReceiptStore({ rootDir }),
  });
  const secondClaims = await harness.store.claimOutbox(stateScope(), {
    workerId: "worker-b",
    now: "2026-07-26T10:02:00.000Z",
    leaseExpiresAt: "2026-07-26T10:03:00.000Z",
    limit: 100,
  });
  const secondToolClaim = secondClaims.find(
    ({ event }) => event.type === "product.aios.tool-call-prepared.v1",
  );
  assert.equal(secondToolClaim.eventId, firstToolClaim.eventId);
  assert.equal(secondToolClaim.leaseVersion, firstToolClaim.leaseVersion + 1);
  assert.deepEqual(await acceptMock(restartedMock, secondToolClaim), {
    receiptId: firstAccepted.receiptId,
    duplicate: true,
  });

  const toolResult = await harness.core.recordToolCallResult(
    toolResultWorkerContext(),
    {
      idempotencyKey: "crash-recovery-tool-result",
      correlationId: "corr-crash-recovery-tool-result",
      command: {
        kind: "RECORD_TOOL_CALL_RESULT",
        runId: flow.startedRun.runId,
        expectedRunVersion: 2,
        toolCallId: flow.preparedTool.toolCallId,
        expectedToolCallVersion: 1,
        receiptId: firstAccepted.receiptId,
      },
    },
  );
  assert.equal(toolResult.state, "SUCCEEDED");
  await harness.store.completeOutbox(stateScope(), {
    eventId: secondToolClaim.eventId,
    workerId: "worker-b",
    leaseVersion: secondToolClaim.leaseVersion,
    now: "2026-07-26T10:02:30.000Z",
  });
  await assert.rejects(
    harness.store.completeOutbox(stateScope(), {
      eventId: firstToolClaim.eventId,
      workerId: "worker-a",
      leaseVersion: firstToolClaim.leaseVersion,
      now: "2026-07-26T10:00:30.000Z",
    }),
    { code: "STALE_OUTBOX_LEASE" },
  );
  const snapshot = await harness.core.snapshot(
    { actorId: "synthetic-control" },
    { tenantId: TENANT_A },
  );
  assert.deepEqual(snapshot.toolCallStates, { SUCCEEDED: 1 });
  assert.equal(snapshot.outboxStates.PUBLISHED, 1);
});

test("Tenant-scoped memory state does not cross between Synthetic Tenants", async () => {
  const store = createMemoryAiosStateStore();
  const harness = createHarness({ store });
  await harness.core.execute(
    serverContext(TENANT_A),
    request("tenant-a-case", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/safe",
    }),
  );
  await harness.core.execute(
    serverContext(TENANT_B),
    request("tenant-b-case", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/safe",
    }),
  );

  const snapshotA = await harness.core.snapshot(
    { actorId: "synthetic-control" },
    { tenantId: TENANT_A },
  );
  const snapshotB = await harness.core.snapshot(
    { actorId: "synthetic-control" },
    { tenantId: TENANT_B },
  );
  assert.equal(snapshotA.counts.cases, 1);
  assert.equal(snapshotB.counts.cases, 1);
  assert.equal(snapshotA.counts.events, 1);
  assert.equal(snapshotB.counts.events, 1);
});

test("snapshot requires explicit control authorization", async () => {
  const harness = createHarness({ controlAllowed: false });
  await assert.rejects(
    harness.core.snapshot(
      { actorId: "synthetic-control" },
      { tenantId: TENANT_A },
    ),
    { code: "ACCESS_DENIED" },
  );
});
