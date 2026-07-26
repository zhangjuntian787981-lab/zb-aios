import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  AgentOrchestratorError,
  c12Sha256,
  createAgentOrchestrator,
  createMemoryC12StatePort,
  createSyntheticOrchestrationCatalog,
} from "../lib/agent-orchestrator.mjs";

const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c12/synthetic-task-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const graphDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c12/orchestration-graph.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const catalog = createSyntheticOrchestrationCatalog({
  catalog: catalogDocument,
  graph: graphDocument,
});

function clock() {
  let tick = 0;
  return () =>
    new Date(Date.UTC(2026, 6, 26, 12, 0, tick++)).toISOString();
}

function ids() {
  let value = 1;
  return () =>
    `00000000-0000-4000-8000-${String(value++).padStart(12, "0")}`;
}

function context(tenantId) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: `prn_workload_${tenantId.slice(-3)}`,
  };
}

function baseRequest(overrides = {}) {
  return {
    sessionToken: "synthetic-session",
    delegationId: "synthetic-delegation",
    idempotencyKey: "idem-1",
    correlationId: "corr-1",
    ...overrides,
  };
}

function inspectRequest(overrides = {}) {
  return {
    sessionToken: "synthetic-session",
    delegationId: "synthetic-delegation",
    correlationId: "corr-inspect",
    ...overrides,
  };
}

function resealState(state) {
  const body = structuredClone(state);
  delete body.stateSha256;
  return {
    ...body,
    stateSha256: c12Sha256(body),
  };
}

function proxyStatePort(base, transform) {
  return {
    create: (...args) => base.create(...args),
    replay: (...args) => base.replay(...args),
    transact: (...args) => base.transact(...args),
    snapshot: (...args) => base.snapshot(...args),
    async get(...args) {
      const value = await base.get(...args);
      return value ? transform(structuredClone(value)) : value;
    },
  };
}

function createHarness(options = {}) {
  const calls = {
    authorization: [],
    policy: [],
    rag: [],
    tool: [],
    model: [],
    validation: [],
    review: [],
    human: [],
  };
  const effects = {
    tool: new Set(),
    model: new Set(),
  };
  const baseStatePort =
    options.statePort ?? createMemoryC12StatePort();
  let lostAck = options.loseToolCheckpointAck === true;
  let failBeforeCommit =
    options.failToolCheckpointBeforeCommit === true;
  const statePort = lostAck || failBeforeCommit
    ? {
        create: (...args) => baseStatePort.create(...args),
        replay: (...args) => baseStatePort.replay(...args),
        get: (...args) => baseStatePort.get(...args),
        snapshot: (...args) => baseStatePort.snapshot(...args),
        async transact(...args) {
          if (failBeforeCommit) {
            const current = await baseStatePort.get(
              args[0],
              args[1].taskId,
            );
            if (current?.nextNodeId === "TOOL") {
              failBeforeCommit = false;
              throw new Error("crash before checkpoint");
            }
          }
          const result = await baseStatePort.transact(...args);
          if (
            lostAck &&
            result.task.nodeRecords.at(-1)?.nodeId === "TOOL"
          ) {
            lostAck = false;
            throw new Error("lost checkpoint ACK");
          }
          return result;
        },
      }
    : baseStatePort;
  const ports = {
    authorizer: {
      async enforce(serverContext, request, descriptor) {
        calls.authorization.push({
          tenantId: serverContext.tenantId,
          operationId: descriptor.operationId,
          resourceId: request.resourceId,
        });
        if (options.authorizationDenied) {
          throw new Error("denied");
        }
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          tenantId: serverContext.tenantId,
          humanPrincipalId:
            request.sessionToken === "other-session"
              ? "prn_other_human"
              : `prn_human_${serverContext.tenantId.slice(-3)}`,
          workloadActorPrincipalId:
            serverContext.workloadActorPrincipalId,
          decisionId: `dec-${descriptor.operationId}`,
          evidenceRef: `evidence://c06/${descriptor.operationId}`,
          policyVersion: "c06-policy-1",
          resourceId: request.resourceId,
          operationId: descriptor.operationId,
        };
      },
    },
    policyGate: {
      async evaluate(input) {
        calls.policy.push(input);
        const effect = options.policyEffect ?? "ALLOW";
        const result = {
          schemaVersion: "c12-policy-gate.v1",
          tenantId: input.tenantId,
          taskId: input.taskId,
          effectKey: input.effectKey,
          effect,
          reasonCode: effect === "ALLOW" ? "GATES_PASS" : "RISK_BLOCKED",
          policyRef: input.policy.ref,
          policyVersion: input.policy.version,
          policySha256: input.policy.sha256,
          budgetSha256: c12Sha256(input.budget),
          dataClass: input.dataClass,
          riskClass: input.riskClass,
        };
        if (options.policyUnbound) {
          result.effectKey =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        }
        return result;
      },
    },
    ragPort: {
      async retrieve(input) {
        calls.rag.push(input);
        const status = options.ragStatus ?? "EVIDENCE_READY";
        const result = {
          schemaVersion: "c12-rag-result.v1",
          tenantId: input.tenantId,
          taskId: input.taskId,
          effectKey: input.effectKey,
          inputRef: input.inputRef,
          inputSha256: input.inputSha256,
          status,
          resultRef: `evidence://c11/result/${input.effectKey.slice(7)}`,
          resultSha256: c12Sha256({
            taskId: input.taskId,
            status,
          }),
          knowledgeRef: input.knowledge.ref,
          knowledgeVersion: input.knowledge.version,
          knowledgeSha256: input.knowledge.sha256,
          evidenceRefs:
            status === "EVIDENCE_READY" &&
            options.ragEmptyEvidence !== true
              ? [`evidence://c11/chunk/${input.taskId}`]
              : [],
        };
        if (options.ragUnbound) {
          result.effectKey =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
          result.inputRef = "fixture://c12/forged/input";
          result.inputSha256 =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        }
        return result;
      },
    },
    toolPort: {
      async execute(...args) {
        const input = args.at(-1);
        calls.tool.push({
          argsCount: args.length,
          serverContext: args.length === 2 ? args[0] : null,
          input,
        });
        if (options.toolFailure) throw new Error("tool secret");
        effects.tool.add(input.effectKey);
        const result = {
          schemaVersion: "c12-tool-result.v1",
          tenantId: input.tenantId,
          taskId: input.taskId,
          effectKey: input.effectKey,
          operationId: input.operationId,
          catalogVersion: input.catalogVersion,
          resultRef: `evidence://c16/result/${input.effectKey.slice(7)}`,
          resultSha256: c12Sha256({
            taskId: input.taskId,
            operationId: input.operationId,
          }),
          receiptSha256: c12Sha256({
            effectKey: input.effectKey,
            externalEffectCount: 0,
          }),
          networkRequestCount: 0,
          externalEffectCount: 0,
        };
        if (options.toolMissingReauthorization !== true) {
          Object.assign(result, {
            authorizationTrustSource:
              "C16_REAUTHORIZED_TOOL_CALL",
            authorizationDecisionRef:
              `evidence://c16/authorization/${input.effectKey.slice(7)}`,
            authorizationDecisionSha256: c12Sha256({
              tenantId: input.tenantId,
              operationId: input.operationId,
              humanPrincipalId: input.humanPrincipalId,
            }),
            identitySha256: c12Sha256({
              humanPrincipalId: input.humanPrincipalId,
              workloadActorPrincipalId:
                input.workloadActorPrincipalId,
            }),
            parameterSha256: input.parameterSha256,
            confirmationSha256: c12Sha256({
              effectKey: input.effectKey,
              parameterSha256: input.parameterSha256,
            }),
            humanPrincipalId: input.humanPrincipalId,
            workloadActorPrincipalId:
              input.workloadActorPrincipalId,
          });
        }
        return result;
      },
    },
    modelPort: {
      async route(input) {
        calls.model.push(input);
        effects.model.add(input.effectKey);
        const inputTokens = options.modelInputTokens ?? 200;
        const outputTokens = options.modelOutputTokens ?? 100;
        const result = {
          schemaVersion: "c12-model-result.v1",
          tenantId: input.tenantId,
          taskId: input.taskId,
          effectKey: input.effectKey,
          outputRef: `evidence://c14/draft/${input.effectKey.slice(7)}`,
          outputSha256: c12Sha256({
            taskId: input.taskId,
            effectKey: input.effectKey,
          }),
          modelRef:
            options.draftModelRef ??
            "synthetic://c14/models/local-secure",
          modelVersion: options.draftModelVersion ?? "1.0.0",
          modelSha256:
            options.draftModelSha256 ??
            "sha256:7d50c3c6467cde455d351fa158e3bdf841616ddf46f6f310321c4a54076a24c4",
          modelTaskRef: input.modelTask.ref,
          modelTaskVersion: input.modelTask.version,
          modelTaskSha256: input.modelTask.sha256,
          skillRef: input.skill.ref,
          skillVersion: input.skill.version,
          skillSha256: input.skill.sha256,
          contextSha256: input.contextSha256,
          inputTokens,
          outputTokens,
          totalTokens: inputTokens + outputTokens,
          costMicrousd: options.modelCostMicrousd ?? 1000,
        };
        if (options.modelExtraField) result.prompt = "forbidden";
        return result;
      },
    },
    validator: {
      async validate(input) {
        calls.validation.push(input);
        const outcome = options.validationOutcome ?? "PASS";
        const result = {
          schemaVersion: "c12-validation-result.v1",
          tenantId: input.tenantId,
          taskId: input.taskId,
          effectKey: input.effectKey,
          artifactRef: input.artifactRef,
          artifactSha256: input.artifactSha256,
          outcome,
          resultRef: `evidence://c12/validation/${input.effectKey.slice(7)}`,
          resultSha256: c12Sha256({ taskId: input.taskId, outcome }),
          ruleRef: "policy://c12/draft-rules",
          ruleVersion: "1.0.0",
          ruleSha256:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        };
        if (options.validationUnbound) {
          result.effectKey = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
          result.artifactRef = "evidence://c14/draft/stale";
          result.artifactSha256 =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        }
        return result;
      },
    },
    reviewer: {
      async review(input) {
        calls.review.push(input);
        const outcome = options.reviewOutcome ?? "PASS";
        const inputTokens = options.reviewInputTokens ?? 100;
        const outputTokens = options.reviewOutputTokens ?? 50;
        const result = {
          schemaVersion: "c12-review-result.v1",
          tenantId: input.tenantId,
          taskId: input.taskId,
          effectKey: input.effectKey,
          artifactRef: input.artifactRef,
          artifactSha256: input.artifactSha256,
          outcome,
          resultRef: `evidence://c12/review/${input.effectKey.slice(7)}`,
          resultSha256: c12Sha256({ taskId: input.taskId, outcome }),
          reviewerRef: "policy://c12/independent-reviewer",
          reviewerVersion: "1.0.0",
          reviewerSha256:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          draftModelRef: input.draftModel.ref,
          draftModelVersion: input.draftModel.version,
          draftModelSha256: input.draftModel.sha256,
          reviewModelRef: input.reviewModel.ref,
          reviewModelVersion: input.reviewModel.version,
          reviewModelSha256: input.reviewModel.sha256,
          inputTokens,
          outputTokens,
          totalTokens:
            options.reviewTotalTokens ?? inputTokens + outputTokens,
          costMicrousd: options.reviewCostMicrousd ?? 500,
        };
        if (options.reviewUnbound) {
          result.effectKey = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
          result.artifactRef = "evidence://c14/draft/stale";
          result.artifactSha256 =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        }
        if (options.reviewModelUnbound) {
          result.reviewModelSha256 =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        }
        if (options.reviewSelfReportedIndependent) {
          result.modelIndependent = true;
        }
        return result;
      },
    },
    humanDecisionPort: {
      async verify(input) {
        calls.human.push(input);
        return {
          schemaVersion: "c12-synthetic-human-decision.v1",
          tenantId: input.tenantId,
          taskId: input.taskId,
          effectKey: input.effectKey,
          expectedStateSha256: input.expectedStateSha256,
          decisionRef: input.decisionRef,
          decisionSha256: input.decisionSha256,
          outcome: options.humanOutcome ?? "APPROVE",
          productionReusable: options.productionReusable ?? false,
          externalEffectCount: 0,
          decidedByHumanPrincipalId: input.humanPrincipalId,
        };
      },
    },
  };
  return {
    calls,
    effects,
    baseStatePort,
    orchestrator: createAgentOrchestrator({
      ...ports,
      statePort,
      catalog,
      clock: options.clock ?? clock(),
      idFactory: ids(),
    }),
  };
}

async function start(orchestrator, task, suffix = "1") {
  return orchestrator.start(
    context(task.tenantId),
    baseRequest({
      idempotencyKey: `start-${suffix}`,
      correlationId: `corr-start-${suffix}`,
      taskRef: task.taskRef,
      inputRef: task.inputRef,
      inputSha256: task.inputSha256,
    }),
  );
}

async function advance(orchestrator, task, state, suffix) {
  return orchestrator.advance(
    context(task.tenantId),
    baseRequest({
      idempotencyKey: `advance-${suffix}`,
      correlationId: `corr-advance-${suffix}`,
      taskId: state.taskId,
      expectedVersion: state.version,
    }),
  );
}

async function runToWaiting(orchestrator, task, initial) {
  let result = initial;
  let step = 1;
  while (result.task.status === "RUNNING") {
    result = await advance(orchestrator, task, result.task, step++);
  }
  return result;
}

test("three Synthetic Tenants complete the same explicit governed graph", async () => {
  const harness = createHarness();
  for (const [index, task] of catalogDocument.tasks.entries()) {
    let result = await start(harness.orchestrator, task, index);
    result = await runToWaiting(harness.orchestrator, task, result);
    assert.equal(result.task.status, "WAITING_FOR_HUMAN");
    assert.equal(result.task.nodeRecords.length, 7);
    const waiting = result.task;
    result = await harness.orchestrator.resumeWithHumanDecision(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: `human-${index}`,
        correlationId: `corr-human-${index}`,
        taskId: waiting.taskId,
        expectedVersion: waiting.version,
        expectedStateSha256: waiting.stateSha256,
        decisionRef: `evidence://c15/decision/${waiting.taskId}`,
        decisionSha256: c12Sha256({
          tenantId: task.tenantId,
          taskId: waiting.taskId,
        }),
      }),
    );
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      `complete-${index}`,
    );
    assert.equal(result.task.status, "COMPLETED");
    assert.equal(result.task.nextNodeId, null);
    assert.deepEqual(
      result.task.nodeRecords.map(({ nodeId }) => nodeId),
      graphDocument.nodes.map(({ nodeId }) => nodeId),
    );
    assert.equal(result.task.budget.usage.toolCalls, 1);
    assert.equal(result.task.budget.usage.inputTokens, 300);
    assert.equal(result.task.budget.usage.outputTokens, 150);
    assert.equal(result.task.budget.usage.totalTokens, 450);
    assert.equal(result.task.budget.usage.costMicrousd, 1500);
    assert.equal(result.task.humanDecision.productionReusable, false);
  }
  assert.equal(harness.calls.human.length, 3);
  assert.equal(harness.effects.tool.size, 3);
  assert.equal(harness.effects.model.size, 3);
});

test("hard-gate denial is terminal before RAG, Tool, or model access", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ policyEffect: "DENY" });
  let result = await start(harness.orchestrator, task);
  result = await advance(harness.orchestrator, task, result.task, "classify");
  result = await advance(harness.orchestrator, task, result.task, "gate");
  assert.equal(result.task.status, "BLOCKED");
  assert.equal(harness.calls.policy.length, 1);
  assert.equal(harness.calls.rag.length, 0);
  assert.equal(harness.calls.tool.length, 0);
  assert.equal(harness.calls.model.length, 0);
});

test("hard-gate result must bind the current node effect", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ policyUnbound: true });
  let result = await start(harness.orchestrator, task);
  result = await advance(harness.orchestrator, task, result.task, "classify");
  await assert.rejects(
    advance(harness.orchestrator, task, result.task, "gate-unbound"),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "POLICY_RESULT_INVALID",
  );
});

test("insufficient C11 evidence refuses before Tool and model access", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ ragStatus: "REFUSED" });
  let result = await start(harness.orchestrator, task);
  result = await advance(harness.orchestrator, task, result.task, "classify");
  result = await advance(harness.orchestrator, task, result.task, "gate");
  result = await advance(harness.orchestrator, task, result.task, "rag");
  assert.equal(result.task.status, "REFUSED");
  assert.equal(harness.calls.tool.length, 0);
  assert.equal(harness.calls.model.length, 0);
});

test("C11 cannot mark an empty evidence set ready", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ ragEmptyEvidence: true });
  let result = await start(harness.orchestrator, task);
  result = await advance(harness.orchestrator, task, result.task, "classify");
  result = await advance(harness.orchestrator, task, result.task, "gate");
  await assert.rejects(
    advance(harness.orchestrator, task, result.task, "rag-empty"),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "RAG_RESULT_INVALID",
  );
  assert.equal(harness.calls.tool.length, 0);
  assert.equal(harness.calls.model.length, 0);
});

test("C11 result must bind the current effect and frozen input", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ ragUnbound: true });
  let result = await start(harness.orchestrator, task);
  result = await advance(harness.orchestrator, task, result.task, "classify");
  result = await advance(harness.orchestrator, task, result.task, "gate");
  await assert.rejects(
    advance(harness.orchestrator, task, result.task, "rag-unbound"),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "RAG_RESULT_INVALID",
  );
});

test("Tool receives the trusted identity envelope for C16 reauthorization", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  let result = await start(harness.orchestrator, task);
  for (const suffix of ["classify", "gate", "rag", "tool"]) {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      suffix,
    );
  }
  const call = harness.calls.tool[0];
  assert.equal(call.argsCount, 2);
  assert.deepEqual(call.serverContext, context(task.tenantId));
  assert.equal(call.input.sessionToken, "synthetic-session");
  assert.equal(call.input.delegationId, "synthetic-delegation");
  assert.equal(call.input.operationId, "synthetic.erp.order.get");
  assert.deepEqual(call.input.parameters, { orderRef: "SYN-ORD-0001" });
  assert.equal(call.input.humanPrincipalId, "prn_human_010");
});

test("Tool result without C16 reauthorization evidence fails closed", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({
    toolMissingReauthorization: true,
  });
  let result = await start(harness.orchestrator, task);
  for (const suffix of ["classify", "gate", "rag"]) {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      suffix,
    );
  }
  await assert.rejects(
    advance(harness.orchestrator, task, result.task, "tool"),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "TOOL_RESULT_INVALID",
  );
});

test("DRAFT is bound to the C11 evidence and C16 Tool result", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  let result = await start(harness.orchestrator, task);
  for (const suffix of ["classify", "gate", "rag", "tool", "draft"]) {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      suffix,
    );
  }
  const modelInput = harness.calls.model[0];
  assert.equal(
    modelInput.evidenceContext.retrievalResultRef.startsWith(
      "evidence://c11/result/",
    ),
    true,
  );
  assert.equal(modelInput.evidenceContext.evidenceRefs.length, 1);
  assert.equal(
    modelInput.evidenceContext.toolResultRef.startsWith(
      "evidence://c16/result/",
    ),
    true,
  );
  assert.equal(modelInput.evidenceContext.toolEvidenceRefs.length, 2);
  assert.equal(
    modelInput.contextSha256,
    c12Sha256(modelInput.evidenceContext),
  );
  const draft = result.task.nodeRecords.find(
    ({ nodeId }) => nodeId === "DRAFT",
  );
  assert.equal(draft.binding.contextSha256, modelInput.contextSha256);
  assert.deepEqual(
    draft.evidenceRefs,
    [
      ...modelInput.evidenceContext.evidenceRefs,
      ...modelInput.evidenceContext.toolEvidenceRefs,
    ].sort(),
  );
});

test("model budget overage leaves the DRAFT checkpoint unadvanced", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ modelCostMicrousd: 5001 });
  let result = await start(harness.orchestrator, task);
  for (const suffix of ["classify", "gate", "rag", "tool"]) {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      suffix,
    );
  }
  const before = result.task;
  await assert.rejects(
    advance(harness.orchestrator, task, before, "draft-over"),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "BUDGET_EXCEEDED",
  );
  const current = await harness.orchestrator.inspect(
    context(task.tenantId),
    inspectRequest({
      correlationId: "inspect-budget",
      taskId: before.taskId,
    }),
  );
  assert.equal(current.version, before.version);
  assert.equal(current.nextNodeId, "DRAFT");
});

test("review model budget overage leaves the review checkpoint unadvanced", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ reviewCostMicrousd: 4500 });
  let result = await start(harness.orchestrator, task);
  while (result.task.nextNodeId !== "INDEPENDENT_REVIEW") {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      `review-budget-${result.task.version}`,
    );
  }
  const before = result.task;

  await assert.rejects(
    advance(
      harness.orchestrator,
      task,
      before,
      "review-budget-over",
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "BUDGET_EXCEEDED",
  );
  const current = await harness.orchestrator.inspect(
    context(task.tenantId),
    inspectRequest({
      correlationId: "inspect-review-budget",
      taskId: before.taskId,
    }),
  );
  assert.equal(current.version, before.version);
  assert.equal(current.nextNodeId, "INDEPENDENT_REVIEW");
  assert.equal(harness.calls.review.length, 1);
});

test("review usage must be non-negative and internally consistent", async () => {
  const task = catalogDocument.tasks[0];
  for (const [options, expectedCode] of [
    [{ reviewInputTokens: -1 }, "INVALID_INPUT"],
    [{ reviewTotalTokens: 999 }, "REVIEW_RESULT_INVALID"],
  ]) {
    const harness = createHarness(options);
    let result = await start(
      harness.orchestrator,
      task,
      expectedCode,
    );
    while (result.task.nextNodeId !== "INDEPENDENT_REVIEW") {
      result = await advance(
        harness.orchestrator,
        task,
        result.task,
        `${expectedCode}-${result.task.version}`,
      );
    }
    const before = result.task;
    await assert.rejects(
      advance(
        harness.orchestrator,
        task,
        before,
        `${expectedCode}-review-usage`,
      ),
      (error) =>
        error instanceof AgentOrchestratorError &&
        error.code === expectedCode,
    );
    const current = await harness.baseStatePort.get(
      {
        trustSource: "C12_AUTHORIZED_SCOPE",
        tenantId: task.tenantId,
        humanPrincipalId: before.ownerHumanPrincipalId,
        workloadActorPrincipalId: before.workloadActorPrincipalId,
        decisionId: "test",
        evidenceRef: "evidence://c06/test",
        policyVersion: "test",
        correlationId: "test",
      },
      before.taskId,
    );
    assert.equal(current.version, before.version);
  }
});

test("validation and independent review failures cannot reach HumanDecision", async () => {
  for (const [options, terminal] of [
    [{ validationOutcome: "FAIL" }, "INVALID"],
    [{ reviewOutcome: "FAIL" }, "REJECTED"],
  ]) {
    const task = catalogDocument.tasks[0];
    const harness = createHarness(options);
    const initial = await start(harness.orchestrator, task, terminal);
    const result = await runToWaiting(
      harness.orchestrator,
      task,
      initial,
    );
    assert.equal(result.task.status, terminal);
    assert.equal(harness.calls.human.length, 0);
  }
});

test("validation and review cannot reuse a result for another artifact", async () => {
  for (const [options, expectedCode] of [
    [{ validationUnbound: true }, "VALIDATION_RESULT_INVALID"],
    [{ reviewUnbound: true }, "REVIEW_RESULT_INVALID"],
  ]) {
    const task = catalogDocument.tasks[0];
    const harness = createHarness(options);
    let result = await start(
      harness.orchestrator,
      task,
      expectedCode,
    );
    const stopNode =
      expectedCode === "VALIDATION_RESULT_INVALID"
        ? "VALIDATE"
        : "INDEPENDENT_REVIEW";
    while (result.task.nextNodeId !== stopNode) {
      result = await advance(
        harness.orchestrator,
        task,
        result.task,
        `${expectedCode}-${result.task.version}`,
      );
    }
    await assert.rejects(
      advance(
        harness.orchestrator,
        task,
        result.task,
        `${expectedCode}-unbound`,
      ),
      (error) =>
        error instanceof AgentOrchestratorError &&
        error.code === expectedCode,
    );
  }
});

test("independent review is bound to distinct server-owned model identities", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  let result = await start(harness.orchestrator, task);
  while (result.task.nextNodeId !== "INDEPENDENT_REVIEW") {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      `review-ready-${result.task.version}`,
    );
  }
  const reviewReady = result.task;

  result = await advance(
    harness.orchestrator,
    task,
    result.task,
    "independent-review",
  );

  const call = harness.calls.review[0];
  assert.deepEqual(call.draftModel, {
    ref: "synthetic://c14/models/local-secure",
    version: "1.0.0",
    sha256:
      "sha256:7d50c3c6467cde455d351fa158e3bdf841616ddf46f6f310321c4a54076a24c4",
  });
  assert.deepEqual(call.reviewModel, task.bindings.reviewModel);
  assert.deepEqual(call.budget, reviewReady.budget);
  const record = result.task.nodeRecords.at(-1);
  assert.equal(record.binding.draftModelRef, call.draftModel.ref);
  assert.equal(record.binding.reviewModelRef, call.reviewModel.ref);
  assert.equal(record.binding.modelIndependent, true);
  assert.equal(record.binding.inputTokens, 100);
  assert.equal(record.binding.outputTokens, 50);
  assert.equal(record.binding.totalTokens, 150);
  assert.equal(record.binding.costMicrousd, 500);
});

test("same draft and review model is rejected before reviewer access", async () => {
  const task = catalogDocument.tasks[0];
  for (const options of [
    {
      draftModelRef: task.bindings.reviewModel.ref,
      draftModelSha256:
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    },
    {
      draftModelRef: "synthetic://c14/models/another",
      draftModelSha256: task.bindings.reviewModel.sha256,
    },
  ]) {
    const harness = createHarness(options);
    let result = await start(
      harness.orchestrator,
      task,
      options.draftModelRef,
    );
    while (result.task.nextNodeId !== "INDEPENDENT_REVIEW") {
      result = await advance(
        harness.orchestrator,
        task,
        result.task,
        `same-review-${result.task.version}`,
      );
    }

    await assert.rejects(
      advance(
        harness.orchestrator,
        task,
        result.task,
        `same-review-reject-${result.task.version}`,
      ),
      (error) =>
        error instanceof AgentOrchestratorError &&
        error.code === "REVIEW_MODEL_NOT_INDEPENDENT",
    );
    assert.equal(harness.calls.review.length, 0);
  }
});

test("reviewer cannot forge model identity or self-assert independence", async () => {
  const task = catalogDocument.tasks[0];
  for (const [options, expectedCode] of [
    [{ reviewModelUnbound: true }, "REVIEW_RESULT_INVALID"],
    [{ reviewSelfReportedIndependent: true }, "INVALID_INPUT"],
  ]) {
    const harness = createHarness(options);
    let result = await start(
      harness.orchestrator,
      task,
      expectedCode,
    );
    while (result.task.nextNodeId !== "INDEPENDENT_REVIEW") {
      result = await advance(
        harness.orchestrator,
        task,
        result.task,
        `review-forge-${result.task.version}`,
      );
    }
    const before = result.task;

    await assert.rejects(
      advance(
        harness.orchestrator,
        task,
        result.task,
        `review-forge-reject-${result.task.version}`,
      ),
      (error) =>
        error instanceof AgentOrchestratorError &&
        error.code === expectedCode,
    );
    const current = await harness.baseStatePort.get(
      {
        trustSource: "C12_AUTHORIZED_SCOPE",
        tenantId: task.tenantId,
        humanPrincipalId: before.ownerHumanPrincipalId,
        workloadActorPrincipalId: before.workloadActorPrincipalId,
        decisionId: "test",
        evidenceRef: "evidence://c06/test",
        policyVersion: "test",
        correlationId: "test",
      },
      before.taskId,
    );
    assert.equal(current.version, before.version);
  }
});

test("Human gate rejects production-reusable or unbound decisions", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ productionReusable: true });
  let result = await start(harness.orchestrator, task);
  result = await runToWaiting(harness.orchestrator, task, result);
  const waiting = result.task;
  await assert.rejects(
    harness.orchestrator.resumeWithHumanDecision(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: "bad-human",
        correlationId: "corr-bad-human",
        taskId: waiting.taskId,
        expectedVersion: waiting.version,
        expectedStateSha256: waiting.stateSha256,
        decisionRef: `evidence://c15/decision/${waiting.taskId}`,
        decisionSha256: c12Sha256(waiting.taskId),
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "HUMAN_DECISION_INVALID",
  );
  assert.deepEqual(
    harness.calls.authorization.find(
      ({ operationId }) =>
        operationId === "C12_RESUME_HUMAN_DECISION",
    ),
    {
      tenantId: task.tenantId,
      operationId: "C12_RESUME_HUMAN_DECISION",
      resourceId: waiting.taskId,
    },
  );
  const current = await harness.orchestrator.inspect(
    context(task.tenantId),
    inspectRequest({
      correlationId: "inspect-human",
      taskId: waiting.taskId,
    }),
  );
  assert.equal(current.stateSha256, waiting.stateSha256);
});

test("an exact retry after checkpoint ACK loss does not call C16 twice", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ loseToolCheckpointAck: true });
  let result = await start(harness.orchestrator, task);
  for (const suffix of ["classify", "gate", "rag"]) {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      suffix,
    );
  }
  const request = baseRequest({
    idempotencyKey: "tool-lost-ack",
    correlationId: "corr-tool-lost-ack",
    taskId: result.task.taskId,
    expectedVersion: result.task.version,
  });
  await assert.rejects(
    harness.orchestrator.advance(context(task.tenantId), request),
    /lost checkpoint ACK/,
  );
  const replay = await harness.orchestrator.advance(
    context(task.tenantId),
    request,
  );
  assert.equal(replay.replayed, true);
  assert.equal(replay.task.nextNodeId, "DRAFT");
  assert.equal(harness.calls.tool.length, 1);
  assert.equal(harness.effects.tool.size, 1);
});

test("a crash before checkpoint reuses one C16 effect key", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({
    failToolCheckpointBeforeCommit: true,
  });
  let result = await start(harness.orchestrator, task);
  for (const suffix of ["classify", "gate", "rag"]) {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      suffix,
    );
  }
  const request = baseRequest({
    idempotencyKey: "tool-before-checkpoint",
    correlationId: "corr-tool-before-checkpoint",
    taskId: result.task.taskId,
    expectedVersion: result.task.version,
  });
  await assert.rejects(
    harness.orchestrator.advance(context(task.tenantId), request),
    /crash before checkpoint/,
  );
  const retried = await harness.orchestrator.advance(
    context(task.tenantId),
    request,
  );
  assert.equal(retried.task.nextNodeId, "DRAFT");
  assert.equal(harness.calls.tool.length, 2);
  assert.equal(harness.effects.tool.size, 1);
  assert.equal(
    harness.calls.tool[0].input.effectKey,
    harness.calls.tool[1].input.effectKey,
  );
});

test("concurrent advances commit once and share one downstream effect key", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  let result = await start(harness.orchestrator, task);
  for (const suffix of ["classify", "gate", "rag"]) {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      suffix,
    );
  }
  const requests = ["concurrent-a", "concurrent-b"].map((suffix) =>
    harness.orchestrator.advance(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: suffix,
        correlationId: suffix,
        taskId: result.task.taskId,
        expectedVersion: result.task.version,
      }),
    ),
  );
  const outcomes = await Promise.allSettled(requests);
  assert.equal(
    outcomes.filter(({ status }) => status === "fulfilled").length,
    1,
  );
  assert.equal(
    outcomes.some(
      (outcome) =>
        outcome.status === "rejected" &&
        outcome.reason instanceof AgentOrchestratorError &&
        outcome.reason.code === "VERSION_CONFLICT",
    ),
    true,
  );
  assert.equal(harness.calls.tool.length, 2);
  assert.equal(harness.effects.tool.size, 1);
  assert.equal(
    harness.calls.tool[0].input.effectKey,
    harness.calls.tool[1].input.effectKey,
  );
});

test("concurrent exact START requests collapse to one receipt", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  const request = baseRequest({
    idempotencyKey: "concurrent-start-same-key",
    correlationId: "concurrent-start-same-key",
    taskRef: task.taskRef,
    inputRef: task.inputRef,
    inputSha256: task.inputSha256,
  });
  const results = await Promise.all([
    harness.orchestrator.start(context(task.tenantId), request),
    harness.orchestrator.start(context(task.tenantId), request),
  ]);

  assert.deepEqual(
    results.map(({ replayed }) => replayed).sort(),
    [false, true],
  );
  assert.deepEqual(results[0].task, results[1].task);
});

test("concurrent exact ADVANCE requests collapse to one receipt", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  const started = await start(harness.orchestrator, task);
  const request = baseRequest({
    idempotencyKey: "concurrent-advance-same-key",
    correlationId: "concurrent-advance-same-key",
    taskId: started.task.taskId,
    expectedVersion: started.task.version,
  });
  const results = await Promise.all([
    harness.orchestrator.advance(context(task.tenantId), request),
    harness.orchestrator.advance(context(task.tenantId), request),
  ]);

  assert.deepEqual(
    results.map(({ replayed }) => replayed).sort(),
    [false, true],
  );
  assert.deepEqual(results[0].task, results[1].task);
  assert.equal(results[0].task.version, started.task.version + 1);
});

test("concurrent exact RESUME requests collapse to one receipt", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  const started = await start(harness.orchestrator, task);
  const waiting = await runToWaiting(
    harness.orchestrator,
    task,
    started,
  );
  const request = baseRequest({
    idempotencyKey: "concurrent-resume-same-key",
    correlationId: "concurrent-resume-same-key",
    taskId: waiting.task.taskId,
    expectedVersion: waiting.task.version,
    expectedStateSha256: waiting.task.stateSha256,
    decisionRef: `evidence://c15/decision/${waiting.task.taskId}`,
    decisionSha256: c12Sha256(waiting.task.taskId),
  });
  const results = await Promise.all([
    harness.orchestrator.resumeWithHumanDecision(
      context(task.tenantId),
      request,
    ),
    harness.orchestrator.resumeWithHumanDecision(
      context(task.tenantId),
      request,
    ),
  ]);

  assert.deepEqual(
    results.map(({ replayed }) => replayed).sort(),
    [false, true],
  );
  assert.deepEqual(results[0].task, results[1].task);
  assert.equal(results[0].task.version, waiting.task.version + 1);
});

test("checkpoint snapshot resumes after service reconstruction", async () => {
  const task = catalogDocument.tasks[0];
  const sharedClock = clock();
  const first = createHarness({ clock: sharedClock });
  let result = await start(first.orchestrator, task);
  result = await advance(first.orchestrator, task, result.task, "classify");
  const restoredPort = createMemoryC12StatePort({
    snapshot: first.baseStatePort.snapshot(),
  });
  const second = createHarness({
    statePort: restoredPort,
    clock: sharedClock,
  });
  result = await advance(second.orchestrator, task, result.task, "gate");
  assert.equal(result.task.nextNodeId, "RETRIEVE");
  assert.equal(result.task.nodeRecords.length, 2);
});

test("stale versions fail before the next dependency and exact retries replay", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  const initial = await start(harness.orchestrator, task);
  const request = baseRequest({
    idempotencyKey: "advance-replay",
    correlationId: "corr-advance-replay",
    taskId: initial.task.taskId,
    expectedVersion: initial.task.version,
  });
  const first = await harness.orchestrator.advance(
    context(task.tenantId),
    request,
  );
  const replay = await harness.orchestrator.advance(
    context(task.tenantId),
    request,
  );
  assert.equal(replay.replayed, true);
  assert.deepEqual(replay.task, first.task);
  await assert.rejects(
    harness.orchestrator.advance(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: "advance-stale",
        correlationId: "corr-advance-stale",
        taskId: initial.task.taskId,
        expectedVersion: initial.task.version,
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "VERSION_CONFLICT",
  );
  assert.equal(harness.calls.policy.length, 0);
});

test("idempotency receipts are scoped by Tenant, human, and workload", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  const request = baseRequest({
    idempotencyKey: "shared-key",
    correlationId: "shared-key",
    taskRef: task.taskRef,
    inputRef: task.inputRef,
    inputSha256: task.inputSha256,
  });
  const first = await harness.orchestrator.start(
    context(task.tenantId),
    request,
  );
  const second = await harness.orchestrator.start(
    context(task.tenantId),
    {
      ...request,
      sessionToken: "other-session",
    },
  );
  const otherWorkload = context(task.tenantId);
  otherWorkload.workloadActorPrincipalId = "prn_workload_other";
  const third = await harness.orchestrator.start(otherWorkload, request);
  assert.notEqual(first.task.taskId, second.task.taskId);
  assert.notEqual(first.task.taskId, third.task.taskId);
  assert.notEqual(
    first.task.ownerHumanPrincipalId,
    second.task.ownerHumanPrincipalId,
  );
  assert.notEqual(
    first.task.workloadActorPrincipalId,
    third.task.workloadActorPrincipalId,
  );
});

test("recovery rejects a rehashed skipped node and catalog drift", async () => {
  const task = catalogDocument.tasks[0];
  const sharedClock = clock();
  const first = createHarness({ clock: sharedClock });
  let result = await start(first.orchestrator, task);
  result = await advance(first.orchestrator, task, result.task, "classify");
  const skipped = structuredClone(first.baseStatePort.snapshot());
  skipped.states[0] = resealState({
    ...skipped.states[0],
    nextNodeId: "COMPLETE",
  });
  assert.throws(
    () => createMemoryC12StatePort({ snapshot: skipped }),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );

  const drifted = structuredClone(first.baseStatePort.snapshot());
  drifted.states[0] = resealState({
    ...drifted.states[0],
    inputRef: "fixture://c12/forged/input",
  });
  const restoredPort = createMemoryC12StatePort({ snapshot: drifted });
  const second = createHarness({
    statePort: restoredPort,
    clock: sharedClock,
  });
  await assert.rejects(
    second.orchestrator.inspect(
      context(task.tenantId),
      inspectRequest({ taskId: result.task.taskId }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "TASK_BINDING_CHANGED",
  );
});

test("every loaded-state entry point fully validates checkpoint integrity", async () => {
  const task = catalogDocument.tasks[0];
  const first = createHarness();
  const started = await start(first.orchestrator, task);
  const corruptedBudgetPort = proxyStatePort(
    first.baseStatePort,
    (state) =>
      resealState({
        ...state,
        budget: {
          ...state.budget,
          usage: {
            ...state.budget.usage,
            forged: 1,
          },
        },
      }),
  );
  const second = createHarness({ statePort: corruptedBudgetPort });
  for (const operation of [
    () =>
      second.orchestrator.inspect(
        context(task.tenantId),
        inspectRequest({ taskId: started.task.taskId }),
      ),
    () =>
      second.orchestrator.advance(
        context(task.tenantId),
        baseRequest({
          idempotencyKey: "corrupt-advance",
          correlationId: "corrupt-advance",
          taskId: started.task.taskId,
          expectedVersion: started.task.version,
        }),
      ),
  ]) {
    await assert.rejects(
      operation,
      (error) =>
        error instanceof AgentOrchestratorError &&
        error.code === "INVALID_INPUT",
    );
  }
  assert.equal(second.calls.policy.length, 0);

  let waiting = await runToWaiting(
    first.orchestrator,
    task,
    started,
  );
  const third = createHarness({
    statePort: proxyStatePort(first.baseStatePort, (state) =>
      resealState({
        ...state,
        budget: {
          ...state.budget,
          usage: {
            ...state.budget.usage,
            forged: 1,
          },
        },
      })),
  });
  await assert.rejects(
    third.orchestrator.resumeWithHumanDecision(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: "corrupt-resume",
        correlationId: "corrupt-resume",
        taskId: waiting.task.taskId,
        expectedVersion: waiting.task.version,
        expectedStateSha256: waiting.task.stateSha256,
        decisionRef: `evidence://c15/decision/${waiting.task.taskId}`,
        decisionSha256: c12Sha256(waiting.task.taskId),
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INVALID_INPUT",
  );
  assert.equal(third.calls.human.length, 0);
});

test("advance and resume validate replayed State Port views before disclosure", async () => {
  const task = catalogDocument.tasks[0];
  const first = createHarness();
  const started = await start(first.orchestrator, task);
  let getCalls = 0;
  const crossTenantReplay = {
    create: (...args) => first.baseStatePort.create(...args),
    async replay() {
      return {
        task: resealState({
          ...started.task,
          tenantId: catalogDocument.tasks[1].tenantId,
        }),
        replayed: true,
      };
    },
    async get() {
      getCalls += 1;
      return null;
    },
    transact: (...args) => first.baseStatePort.transact(...args),
  };
  const second = createHarness({ statePort: crossTenantReplay });
  await assert.rejects(
    second.orchestrator.advance(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: "forged-advance-replay",
        correlationId: "forged-advance-replay",
        taskId: started.task.taskId,
        expectedVersion: started.task.version,
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );
  assert.equal(getCalls, 0);
  assert.equal(second.calls.policy.length, 0);

  const waiting = await runToWaiting(
    first.orchestrator,
    task,
    started,
  );
  const staleResumeReplay = {
    create: (...args) => first.baseStatePort.create(...args),
    async replay() {
      return {
        task: waiting.task,
        replayed: true,
      };
    },
    get: (...args) => first.baseStatePort.get(...args),
    transact: (...args) => first.baseStatePort.transact(...args),
  };
  const third = createHarness({ statePort: staleResumeReplay });
  await assert.rejects(
    third.orchestrator.resumeWithHumanDecision(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: "forged-resume-replay",
        correlationId: "forged-resume-replay",
        taskId: waiting.task.taskId,
        expectedVersion: waiting.task.version,
        expectedStateSha256: waiting.task.stateSha256,
        decisionRef: `evidence://c15/decision/${waiting.task.taskId}`,
        decisionSha256: c12Sha256(waiting.task.taskId),
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );
  assert.equal(third.calls.human.length, 0);

  const noOpResumePort = {
    create: (...args) => first.baseStatePort.create(...args),
    async replay() {
      return null;
    },
    get: (...args) => first.baseStatePort.get(...args),
    async transact(scope, command) {
      return {
        task: await first.baseStatePort.get(scope, command.taskId),
        replayed: false,
      };
    },
  };
  const fourth = createHarness({ statePort: noOpResumePort });
  await assert.rejects(
    fourth.orchestrator.resumeWithHumanDecision(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: "noop-resume-transact",
        correlationId: "noop-resume-transact",
        taskId: waiting.task.taskId,
        expectedVersion: waiting.task.version,
        expectedStateSha256: waiting.task.stateSha256,
        decisionRef: `evidence://c15/decision/${waiting.task.taskId}`,
        decisionSha256: c12Sha256(waiting.task.taskId),
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );
  assert.equal(fourth.calls.human.length, 1);
});

test("create and transact validate State Port views before disclosure", async () => {
  const task = catalogDocument.tasks[0];
  const forgedCreatePort = {
    async create(_scope, command) {
      return {
        task: resealState({
          ...command.state,
          taskId:
            "tsk_00000000-0000-4000-8000-000000000099",
        }),
        replayed: false,
      };
    },
    async replay() {
      return null;
    },
    async get() {
      return null;
    },
    async transact() {
      throw new Error("unexpected transact");
    },
  };
  const first = createHarness({ statePort: forgedCreatePort });
  await assert.rejects(
    start(first.orchestrator, task, "forged-create"),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );

  const second = createHarness();
  const started = await start(second.orchestrator, task);
  const forgedTransactPort = {
    create: (...args) => second.baseStatePort.create(...args),
    replay: (...args) => second.baseStatePort.replay(...args),
    get: (...args) => second.baseStatePort.get(...args),
    async transact(scope, command) {
      return {
        task: await second.baseStatePort.get(scope, command.taskId),
        replayed: false,
      };
    },
  };
  const third = createHarness({ statePort: forgedTransactPort });
  await assert.rejects(
    advance(
      third.orchestrator,
      task,
      started.task,
      "forged-transact",
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );
});

test("advance rejects a replayed legal pre-state that did not commit", async () => {
  const task = catalogDocument.tasks[0];
  const first = createHarness();
  const started = await start(first.orchestrator, task);
  const staleReplayPort = {
    create: (...args) => first.baseStatePort.create(...args),
    async replay() {
      return {
        task: started.task,
        replayed: true,
      };
    },
    get: (...args) => first.baseStatePort.get(...args),
    transact: (...args) => first.baseStatePort.transact(...args),
  };
  const second = createHarness({ statePort: staleReplayPort });

  await assert.rejects(
    advance(
      second.orchestrator,
      task,
      started.task,
      "stale-legal-replay",
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );
  assert.equal(second.calls.policy.length, 0);
});

test("START rejects a replay flag whose receipt does not bind the returned task", async () => {
  const task = catalogDocument.tasks[0];
  const baseStatePort = createMemoryC12StatePort();
  const forgedPort = {
    async create(scope, command) {
      const view = await baseStatePort.create(scope, command);
      return {
        ...view,
        task: resealState({
          ...view.task,
          taskId: "tsk_00000000-0000-4000-8000-000000000099",
        }),
        replayed: true,
      };
    },
    replay: (...args) => baseStatePort.replay(...args),
    get: (...args) => baseStatePort.get(...args),
    transact: (...args) => baseStatePort.transact(...args),
  };
  const harness = createHarness({ statePort: forgedPort });

  await assert.rejects(
    start(harness.orchestrator, task, "forged-start-receipt"),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );
});

test("ADVANCE rejects a replay flag whose receipt does not bind the command result", async () => {
  const task = catalogDocument.tasks[0];
  const baseStatePort = createMemoryC12StatePort();
  const first = createHarness({ statePort: baseStatePort });
  const started = await start(first.orchestrator, task);
  const forgedPort = {
    create: (...args) => baseStatePort.create(...args),
    replay: (...args) => baseStatePort.replay(...args),
    get: (...args) => baseStatePort.get(...args),
    async transact(scope, command) {
      const view = await baseStatePort.transact(scope, command);
      const nodeRecords = structuredClone(view.task.nodeRecords);
      nodeRecords[0].outputSha256 =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      return {
        ...view,
        task: resealState({ ...view.task, nodeRecords }),
        replayed: true,
      };
    },
  };
  const second = createHarness({ statePort: forgedPort });

  await assert.rejects(
    advance(
      second.orchestrator,
      task,
      started.task,
      "forged-advance-receipt",
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );
});

test("RESUME rejects a replay flag whose receipt does not bind the full command result", async () => {
  const task = catalogDocument.tasks[0];
  const baseStatePort = createMemoryC12StatePort();
  const sharedClock = clock();
  const first = createHarness({
    statePort: baseStatePort,
    clock: sharedClock,
  });
  const started = await start(first.orchestrator, task);
  const waiting = await runToWaiting(
    first.orchestrator,
    task,
    started,
  );
  const forgedPort = {
    create: (...args) => baseStatePort.create(...args),
    replay: (...args) => baseStatePort.replay(...args),
    get: (...args) => baseStatePort.get(...args),
    async transact(scope, command) {
      const view = await baseStatePort.transact(scope, command);
      const nodeRecords = structuredClone(view.task.nodeRecords);
      nodeRecords[0].outputSha256 =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      return {
        ...view,
        task: resealState({ ...view.task, nodeRecords }),
        replayed: true,
      };
    },
  };
  const second = createHarness({
    statePort: forgedPort,
    clock: sharedClock,
  });

  await assert.rejects(
    second.orchestrator.resumeWithHumanDecision(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: "forged-resume-receipt",
        correlationId: "forged-resume-receipt",
        taskId: waiting.task.taskId,
        expectedVersion: waiting.task.version,
        expectedStateSha256: waiting.task.stateSha256,
        decisionRef: `evidence://c15/decision/${waiting.task.taskId}`,
        decisionSha256: c12Sha256(waiting.task.taskId),
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INTEGRITY_VIOLATION",
  );
});

test("an exact START retry returns only the receipt-bound original task", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  const request = baseRequest({
    idempotencyKey: "start-exact-retry",
    correlationId: "start-exact-retry",
    taskRef: task.taskRef,
    inputRef: task.inputRef,
    inputSha256: task.inputSha256,
  });
  const first = await harness.orchestrator.start(
    context(task.tenantId),
    request,
  );
  const replay = await harness.orchestrator.start(
    context(task.tenantId),
    request,
  );
  assert.equal(replay.replayed, true);
  assert.equal(replay.task.taskId, first.task.taskId);
  assert.deepEqual(replay.task, first.task);
});

test("a rehashed node binding with an undeclared field is rejected", async () => {
  const task = catalogDocument.tasks[0];
  const first = createHarness();
  let result = await start(first.orchestrator, task);
  result = await advance(
    first.orchestrator,
    task,
    result.task,
    "binding-classify",
  );
  const statePort = proxyStatePort(first.baseStatePort, (state) => {
    const nodeRecords = structuredClone(state.nodeRecords);
    nodeRecords[0].binding.forged = "synthetic://c12/forged";
    nodeRecords[0].bindingSha256 = c12Sha256(
      nodeRecords[0].binding,
    );
    return resealState({ ...state, nodeRecords });
  });
  const second = createHarness({ statePort });

  await assert.rejects(
    second.orchestrator.inspect(
      context(task.tenantId),
      inspectRequest({ taskId: result.task.taskId }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INVALID_INPUT",
  );
});

test("direct authorization bypass, cross-owner read, and extra inputs fail closed", async () => {
  const task = catalogDocument.tasks[0];
  const denied = createHarness({ authorizationDenied: true });
  await assert.rejects(
    start(denied.orchestrator, task),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "AUTHORIZATION_UNAVAILABLE",
  );

  const harness = createHarness();
  const result = await start(harness.orchestrator, task);
  await assert.rejects(
    harness.orchestrator.inspect(
      context(task.tenantId),
      inspectRequest({
        sessionToken: "other-session",
        correlationId: "other-inspect",
        taskId: result.task.taskId,
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "ACCESS_DENIED",
  );
  const otherWorkload = context(task.tenantId);
  otherWorkload.workloadActorPrincipalId = "prn_workload_other";
  await assert.rejects(
    harness.orchestrator.inspect(
      otherWorkload,
      inspectRequest({
        taskId: result.task.taskId,
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "ACCESS_DENIED",
  );
  await assert.rejects(
    harness.orchestrator.start(
      context(task.tenantId),
      baseRequest({
        idempotencyKey: "forged",
        correlationId: "forged",
        taskRef: task.taskRef,
        inputRef: task.inputRef,
        inputSha256: task.inputSha256,
        approval: true,
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INVALID_INPUT",
  );
});

test("another Tenant cannot inspect or advance a task identifier", async () => {
  const task = catalogDocument.tasks[0];
  const otherTenant = catalogDocument.tasks[1].tenantId;
  const harness = createHarness();
  const result = await start(harness.orchestrator, task);
  await assert.rejects(
    harness.orchestrator.inspect(
      context(otherTenant),
      inspectRequest({ taskId: result.task.taskId }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "TASK_NOT_FOUND",
  );
  await assert.rejects(
    harness.orchestrator.advance(
      context(otherTenant),
      baseRequest({
        idempotencyKey: "cross-tenant-advance",
        correlationId: "cross-tenant-advance",
        taskId: result.task.taskId,
        expectedVersion: result.task.version,
      }),
    ),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "TASK_NOT_FOUND",
  );
  assert.equal(harness.calls.policy.length, 0);
  assert.equal(harness.calls.rag.length, 0);
  assert.equal(harness.calls.tool.length, 0);
  assert.equal(harness.calls.model.length, 0);
});

test("malformed dependency output cannot enter a checkpoint", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness({ modelExtraField: true });
  let result = await start(harness.orchestrator, task);
  for (const suffix of ["classify", "gate", "rag", "tool"]) {
    result = await advance(
      harness.orchestrator,
      task,
      result.task,
      suffix,
    );
  }
  const before = result.task;
  await assert.rejects(
    advance(harness.orchestrator, task, before, "bad-model"),
    (error) =>
      error instanceof AgentOrchestratorError &&
      error.code === "INVALID_INPUT",
  );
  const current = await harness.orchestrator.inspect(
    context(task.tenantId),
    inspectRequest({
      correlationId: "inspect-malformed",
      taskId: before.taskId,
    }),
  );
  assert.equal(current.version, before.version);
});

test("checkpoint state is metadata-only and never stores session or bodies", async () => {
  const task = catalogDocument.tasks[0];
  const harness = createHarness();
  let result = await start(harness.orchestrator, task);
  result = await runToWaiting(harness.orchestrator, task, result);
  const serialized = JSON.stringify(result.task);
  for (const forbidden of [
    "synthetic-session",
    "\"prompt\"",
    "\"body\"",
    "\"content\"",
    "\"toolArguments\"",
    "\"modelInput\"",
    "\"modelOutput\"",
    "\"credential\"",
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
});
