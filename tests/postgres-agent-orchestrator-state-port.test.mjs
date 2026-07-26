import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { c12Sha256 } from "../lib/agent-orchestrator.mjs";
import {
  createPostgresAgentOrchestratorStatePort,
} from "../lib/postgres-agent-orchestrator-state-port.mjs";

const TENANT_ID = "stn_01984910-1200-7000-8000-000000000001";
const TASK_ID = "tsk_00000000-0000-4000-8000-000000000001";
const HASH_A =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SCOPE = Object.freeze({
  trustSource: "C12_AUTHORIZED_SCOPE",
  tenantId: TENANT_ID,
  humanPrincipalId: "prn_c12_human",
  workloadActorPrincipalId: "prn_c12_workload",
  decisionId: "decision-c12-postgres-unit",
  evidenceRef: "evidence://c12/postgres/unit",
  policyVersion: "c12-postgres-policy-v1",
  correlationId: "c12-postgres-unit",
});

function state(overrides = {}) {
  const value = {
    schemaVersion: "c12-task-state.v1",
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    taskId: TASK_ID,
    taskRef: "synthetic://c12/task/unit",
    inputRef: "synthetic://c12/input/unit",
    inputSha256: HASH_A,
    graphRef: "synthetic://c12/graph/unit",
    graphVersion: "v1",
    graphSha256: HASH_A,
    catalogBindingSha256: HASH_A,
    ownerHumanPrincipalId: SCOPE.humanPrincipalId,
    workloadActorPrincipalId: SCOPE.workloadActorPrincipalId,
    status: "RUNNING",
    nextNodeId: "CLASSIFY",
    version: 1,
    budget: {
      limits: {
        maxInputTokens: 100,
        maxOutputTokens: 100,
        maxTotalTokens: 200,
        maxCostMicrousd: 1000,
        maxToolCalls: 1,
      },
      usage: {
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        costMicrousd: 0,
        toolCalls: 0,
      },
    },
    bindings: {},
    nodeRecords: [],
    humanDecision: null,
    createdAt: "2026-07-27T00:00:00.000Z",
    updatedAt: "2026-07-27T00:00:00.000Z",
    ...overrides,
  };
  value.stateSha256 = c12Sha256(value);
  return value;
}

function pool(onConnect = () => {
  throw new Error("PostgreSQL must not be reached.");
}) {
  return {
    async connect() {
      return onConnect();
    },
  };
}

function tenantRegistry(onAdmission = () => ({
  trustSource: "VERIFIED_SERVER_CONTEXT",
  tenantId: TENANT_ID,
  tenantKind: "SYNTHETIC",
  lifecycleVersion: 2,
})) {
  return {
    async admitNewRequest(input) {
      return onAdmission(input);
    },
  };
}

test("C12 PostgreSQL State Port rejects unsafe construction", () => {
  const sharedPool = pool();
  assert.throws(
    () =>
      createPostgresAgentOrchestratorStatePort({
        runtimePool: sharedPool,
        scopePool: sharedPool,
        tenantRegistry: tenantRegistry(),
      }),
    (error) => error?.code === "INVALID_CONFIGURATION",
  );
  assert.throws(
    () =>
      createPostgresAgentOrchestratorStatePort({
        runtimePool: pool(),
        scopePool: pool(),
        tenantRegistry: {},
      }),
    (error) => error?.code === "INVALID_CONFIGURATION",
  );
});

test("C12 PostgreSQL State Port rejects forged scope before admission", async () => {
  let admissions = 0;
  const port = createPostgresAgentOrchestratorStatePort({
    runtimePool: pool(),
    scopePool: pool(),
    tenantRegistry: tenantRegistry(() => {
      admissions += 1;
      throw new Error("must not admit forged scope");
    }),
  });

  await assert.rejects(
    port.get({ ...SCOPE, injectedTenantKind: "ENTERPRISE" }, TASK_ID),
    (error) => error?.code === "AUTHORIZATION_REQUIRED",
  );
  assert.equal(admissions, 0);
});

test("C12 PostgreSQL State Port rejects state owner escape before SQL", async () => {
  let connections = 0;
  const countingPool = pool(() => {
    connections += 1;
    throw new Error("must not connect");
  });
  const port = createPostgresAgentOrchestratorStatePort({
    runtimePool: countingPool,
    scopePool: pool(),
    tenantRegistry: tenantRegistry(),
  });

  await assert.rejects(
    port.create(SCOPE, {
      operation: "START",
      idempotencyKey: "unit-owner-escape",
      requestSha256: HASH_A,
      state: state({ ownerHumanPrincipalId: "prn_other_human" }),
    }),
    (error) => error?.code === "TENANT_SCOPE_VIOLATION",
  );
  assert.equal(connections, 0);
});

test("C12 PostgreSQL migrations force RLS and least-privilege roles", async () => {
  const [stateSql, rolesSql] = await Promise.all([
    readFile(
      new URL(
        "../implementation/p1/c12/postgresql/0031_agent_orchestrator_state.sql",
        import.meta.url,
      ),
      "utf8",
    ),
    readFile(
      new URL(
        "../implementation/p1/c12/postgresql/0032_agent_orchestrator_runtime_roles.sql",
        import.meta.url,
      ),
      "utf8",
    ),
  ]);

  assert.match(stateSql, /CREATE TABLE aios_orchestration\.task_state/);
  assert.match(
    stateSql,
    /CREATE TABLE aios_orchestration\.command_receipt/,
  );
  assert.match(stateSql, /reject_command_receipt_mutation/);
  assert.equal(
    [...stateSql.matchAll(/FORCE ROW LEVEL SECURITY/g)].length,
    2,
  );
  assert.match(rolesSql, /CREATE ROLE aios_c12_owner/);
  assert.match(rolesSql, /CREATE ROLE aios_c12_runtime/);
  assert.match(
    rolesSql,
    /runtime_scope_allows\(tenant_id, tenant_kind\)/,
  );
  assert.match(
    rolesSql,
    /GRANT SELECT, INSERT, UPDATE ON TABLE\s+aios_orchestration\.task_state/s,
  );
  assert.doesNotMatch(rolesSql, /GRANT .+ TO PUBLIC/);
});
