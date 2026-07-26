import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import { c12Sha256 } from "../../lib/agent-orchestrator.mjs";
import {
  createPostgresAgentOrchestratorStatePort,
} from "../../lib/postgres-agent-orchestrator-state-port.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c12/postgresql/0031_agent_orchestrator_state.sql",
    "../../implementation/p1/c12/postgresql/0032_agent_orchestrator_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);

const RUNTIME_LOGIN = "c12_test_runtime_login";
const SCOPE_LOGIN = "c12_test_scope_login";
const UNSAFE_LOGIN = "c12_test_unsafe_login";
const HASH_A =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B =
  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TENANTS = [
  {
    tenantId: "stn_01984910-1200-7000-8000-000000000001",
    namespaceId: "sns_01984910-1200-7000-8000-000000000011",
    operationId: "op_01984910-1200-7000-8000-000000000021",
    fixtureId: "north",
  },
  {
    tenantId: "stn_01984910-1200-7000-8000-000000000002",
    namespaceId: "sns_01984910-1200-7000-8000-000000000012",
    operationId: "op_01984910-1200-7000-8000-000000000022",
    fixtureId: "south",
  },
];
const UNKNOWN_TENANT =
  "stn_01984910-1200-7000-8000-000000000099";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function config(user = process.env.C12_TEST_PGUSER, max = 50) {
  if (process.env.C12_TEST_EPHEMERAL !== "1") {
    throw new Error("C12_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C12_TEST_PGHOST",
    "C12_TEST_PGPORT",
    "C12_TEST_PGDATABASE",
    "C12_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C12_TEST_PGHOST,
    port: Number(process.env.C12_TEST_PGPORT),
    database: process.env.C12_TEST_PGDATABASE,
    user,
    max,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function scope(
  tenant = TENANTS[0],
  {
    humanPrincipalId = "prn_c12_human",
    workloadActorPrincipalId = "prn_c12_workload",
    correlationId = `c12-${tenant.fixtureId}`,
  } = {},
) {
  return {
    trustSource: "C12_AUTHORIZED_SCOPE",
    tenantId: tenant.tenantId,
    humanPrincipalId,
    workloadActorPrincipalId,
    decisionId: `decision-c12-${tenant.fixtureId}`,
    evidenceRef: `evidence://c12/${tenant.fixtureId}`,
    policyVersion: "c12-postgres-policy-v1",
    correlationId,
  };
}

function taskId(suffix) {
  return `tsk_00000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`;
}

function taskState({
  authorizedScope = scope(),
  id = taskId(1),
  version = 1,
  status = "RUNNING",
  nextNodeId = "CLASSIFY",
  createdAt = "2026-07-27T00:00:00.000Z",
  updatedAt = createdAt,
  marker = "initial",
} = {}) {
  const value = {
    schemaVersion: "c12-task-state.v1",
    tenantId: authorizedScope.tenantId,
    tenantKind: "SYNTHETIC",
    taskId: id,
    taskRef: `synthetic://c12/task/${marker}`,
    inputRef: `synthetic://c12/input/${marker}`,
    inputSha256: digest(`input-${marker}`),
    graphRef: "synthetic://c12/graph/postgres",
    graphVersion: "v1",
    graphSha256: HASH_A,
    catalogBindingSha256: HASH_B,
    ownerHumanPrincipalId: authorizedScope.humanPrincipalId,
    workloadActorPrincipalId:
      authorizedScope.workloadActorPrincipalId,
    status,
    nextNodeId,
    version,
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
    bindings: { marker },
    nodeRecords: [],
    humanDecision: null,
    createdAt,
    updatedAt,
  };
  value.stateSha256 = c12Sha256(value);
  return value;
}

function nextState(current, marker = "advanced") {
  const value = structuredClone(current);
  value.version += 1;
  value.bindings = { marker };
  value.updatedAt = new Date(
    Date.parse(current.updatedAt) + 1000,
  ).toISOString();
  delete value.stateSha256;
  value.stateSha256 = c12Sha256(value);
  return value;
}

function command(operation, idempotencyKey, requestSeed, extra = {}) {
  return {
    operation,
    idempotencyKey,
    requestSha256: digest(requestSeed),
    ...extra,
  };
}

function rejectReceiptInsert(pool, idempotencyKey) {
  return {
    async connect() {
      const client = await pool.connect();
      return new Proxy(client, {
        get(target, property) {
          if (property === "query") {
            return async (...arguments_) => {
              const query = arguments_[0];
              const text =
                typeof query === "string" ? query : query?.text;
              const parameters = arguments_[1];
              if (
                text?.includes('INSERT INTO "aios_orchestration"."command_receipt"') &&
                parameters?.[3] === idempotencyKey
              ) {
                const error = new Error(
                  "Synthetic receipt persistence failure.",
                );
                error.code = "23514";
                error.constraint = "synthetic_receipt_failure";
                throw error;
              }
              return target.query(...arguments_);
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === "function"
            ? value.bind(target)
            : value;
        },
      });
    },
  };
}

async function seedTenant(adminPool, tenant, index) {
  const createdAt = `2026-07-27T00:0${index}:00.000Z`;
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id, tenant_kind, state, lifecycle_version, generation,
       creation_key, origin_ref, origin_hash, config_refs,
       resource_namespace_id, operation_id, created_at, updated_at
     ) VALUES (
       $1, 'SYNTHETIC', 'PROVISIONING', 1, 1, $2, $3, $4,
       '[]'::jsonb, $5, $6, $7, $7
     )`,
    [
      tenant.tenantId,
      `c12-creation-${tenant.fixtureId}`,
      `fixture://c12/${tenant.fixtureId}`,
      digest(`origin-${tenant.fixtureId}`),
      tenant.namespaceId,
      tenant.operationId,
      createdAt,
    ],
  );
  for (const projection of PROJECTIONS) {
    await adminPool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id, generation, projection, desired_action, status,
         attempt_count, source_event_id, updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [
        tenant.tenantId,
        projection,
        `c12-${tenant.fixtureId}-${projection.toLowerCase()}`,
        createdAt,
      ],
    );
  }
  const activeAt = `2026-07-27T00:1${index}:00.000Z`;
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE', lifecycle_version=2, updated_at=$2
      WHERE tenant_id=$1`,
    [tenant.tenantId, activeAt],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id, tenant_kind, lifecycle_version, generation,
       operation_id, state, last_event_id, updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4)`,
    [
      tenant.tenantId,
      tenant.operationId,
      `c12-active-${tenant.fixtureId}`,
      activeAt,
    ],
  );
}

test("C12 PostgreSQL State Port is durable, isolated and atomic", async (t) => {
  const adminPool = new Pool(config());
  let runtimePool;
  let scopePool;
  let unsafePool;
  t.after(async () => {
    await Promise.all(
      [runtimePool, scopePool, unsafePool]
        .filter(Boolean)
        .map((pool) => pool.end()),
    );
    await adminPool.end();
  });

  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_orchestration') AS state_schema`,
  );
  assert.match(safety.rows[0].database, /^c12_test_[0-9]+$/);
  assert.equal(safety.rows[0].state_schema, null);

  for (const migration of migrations) await adminPool.query(migration);
  await adminPool.query(`CREATE ROLE ${RUNTIME_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${SCOPE_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${UNSAFE_LOGIN} LOGIN`);
  await adminPool.query(
    `GRANT aios_c12_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};
     GRANT aios_c12_runtime, aios_c12_owner TO ${UNSAFE_LOGIN};`,
  );
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(adminPool, tenant, index);
  }

  runtimePool = new Pool(config(RUNTIME_LOGIN));
  scopePool = new Pool(config(SCOPE_LOGIN));
  unsafePool = new Pool(config(UNSAFE_LOGIN));
  const admissionByTenant = new Map(
    TENANTS.map((tenant) => [
      tenant.tenantId,
      {
        trustSource: "VERIFIED_SERVER_CONTEXT",
        tenantId: tenant.tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 2,
      },
    ]),
  );
  const tenantRegistry = {
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      const admission = admissionByTenant.get(tenantId);
      if (!admission || expectedTenantKind !== "SYNTHETIC") {
        const error = new Error("Tenant admission denied.");
        error.code = "TENANT_NOT_FOUND";
        throw error;
      }
      return admission;
    },
  };
  const port = createPostgresAgentOrchestratorStatePort({
    runtimePool,
    scopePool,
    tenantRegistry,
  });

  await t.test(
    "create, get and replay preserve historical command state",
    async () => {
      const authorizedScope = scope();
      const initial = taskState({
        authorizedScope,
        id: taskId(1),
        marker: "history-initial",
      });
      const start = command(
        "START",
        "history-start",
        "history-start",
        { state: initial },
      );
      const created = await port.create(authorizedScope, start);
      assert.equal(created.replayed, false);
      assert.deepEqual(created.task, initial);
      assert.equal(
        created.receipt.receiptSha256,
        c12Sha256({
          schemaVersion: "c12-state-port-receipt.v1",
          tenantId: authorizedScope.tenantId,
          humanPrincipalId: authorizedScope.humanPrincipalId,
          workloadActorPrincipalId:
            authorizedScope.workloadActorPrincipalId,
          taskId: initial.taskId,
          operation: "START",
          idempotencyKey: "history-start",
          requestSha256: start.requestSha256,
          resultVersion: 1,
          resultStateSha256: initial.stateSha256,
        }),
      );
      assert.deepEqual(
        await port.get(authorizedScope, initial.taskId),
        initial,
      );

      const advanced = await port.transact(
        authorizedScope,
        command("ADVANCE", "history-advance", "history-advance", {
          taskId: initial.taskId,
          expectedVersion: 1,
          reduce: (current) => nextState(current, "history-advanced"),
        }),
      );
      assert.equal(advanced.task.version, 2);
      assert.equal(advanced.replayed, false);

      const replayedStart = await port.replay(authorizedScope, {
        operation: "START",
        idempotencyKey: "history-start",
        requestSha256: start.requestSha256,
      });
      assert.equal(replayedStart.replayed, true);
      assert.deepEqual(replayedStart.task, initial);
      assert.deepEqual(
        await port.get(authorizedScope, initial.taskId),
        advanced.task,
      );
    },
  );

  await t.test("idempotency reuse with changed input is rejected", async () => {
    await assert.rejects(
      port.replay(scope(), {
        operation: "START",
        idempotencyKey: "history-start",
        requestSha256: digest("changed-history-start"),
      }),
      (error) => error?.code === "IDEMPOTENCY_CONFLICT",
    );
  });

  await t.test(
    "16 identical concurrent transitions have one durable result",
    async () => {
      const authorizedScope = scope();
      const initial = taskState({
        authorizedScope,
        id: taskId(2),
        marker: "parallel-identical",
      });
      await port.create(
        authorizedScope,
        command("START", "parallel-start", "parallel-start", {
          state: initial,
        }),
      );
      let reducerCalls = 0;
      const run = () =>
        port.transact(
          authorizedScope,
          command("ADVANCE", "parallel-advance", "parallel-advance", {
            taskId: initial.taskId,
            expectedVersion: 1,
            reduce(current) {
              reducerCalls += 1;
              return nextState(current, "parallel-result");
            },
          }),
        );
      const results = await Promise.all(
        Array.from({ length: 16 }, () => run()),
      );
      assert.equal(results.filter((value) => !value.replayed).length, 1);
      assert.equal(results.filter((value) => value.replayed).length, 15);
      assert.equal(reducerCalls, 1);
      assert.equal(
        results.every((value) => value.task.version === 2),
        true,
      );
      const counts = await adminPool.query(
        `SELECT
           (SELECT count(*)::integer
              FROM aios_orchestration.task_state
             WHERE tenant_id=$1 AND task_id=$2) AS tasks,
           (SELECT count(*)::integer
              FROM aios_orchestration.command_receipt
             WHERE tenant_id=$1 AND idempotency_key=$3) AS receipts`,
        [authorizedScope.tenantId, initial.taskId, "parallel-advance"],
      );
      assert.deepEqual(counts.rows[0], { tasks: 1, receipts: 1 });
    },
  );

  await t.test("different commands use row-lock version CAS", async () => {
    const authorizedScope = scope();
    const initial = taskState({
      authorizedScope,
      id: taskId(3),
      marker: "cas-initial",
    });
    await port.create(
      authorizedScope,
      command("START", "cas-start", "cas-start", { state: initial }),
    );
    const runs = await Promise.allSettled(
      ["left", "right"].map((side) =>
        port.transact(
          authorizedScope,
          command("ADVANCE", `cas-${side}`, `cas-${side}`, {
            taskId: initial.taskId,
            expectedVersion: 1,
            reduce: (current) => nextState(current, `cas-${side}`),
          }),
        ),
      ),
    );
    assert.equal(
      runs.filter((result) => result.status === "fulfilled").length,
      1,
    );
    const rejected = runs.find((result) => result.status === "rejected");
    assert.equal(rejected.reason.code, "VERSION_CONFLICT");
    assert.equal(
      (await port.get(authorizedScope, initial.taskId)).version,
      2,
    );
  });

  await t.test(
    "Tenant, Human and Workload boundaries cannot cross",
    async () => {
      const ownerScope = scope();
      const ownerTask = await port.get(ownerScope, taskId(1));
      assert.ok(ownerTask);
      await assert.rejects(
        port.get(
          scope(TENANTS[0], {
            humanPrincipalId: "prn_c12_other_human",
          }),
          taskId(1),
        ),
        (error) => error?.code === "ACCESS_DENIED",
      );
      await assert.rejects(
        port.get(
          scope(TENANTS[0], {
            workloadActorPrincipalId: "prn_c12_other_workload",
          }),
          taskId(1),
        ),
        (error) => error?.code === "ACCESS_DENIED",
      );
      assert.equal(await port.get(scope(TENANTS[1]), taskId(1)), null);
      assert.equal(
        await port.replay(
          scope(TENANTS[0], {
            humanPrincipalId: "prn_c12_other_human",
          }),
          {
            operation: "START",
            idempotencyKey: "history-start",
            requestSha256: digest("history-start"),
          },
        ),
        null,
      );
      await assert.rejects(
        port.create(
          ownerScope,
          command("START", "scope-escape", "scope-escape", {
            state: taskState({
              authorizedScope: scope(TENANTS[1]),
              id: taskId(4),
              marker: "scope-escape",
            }),
          }),
        ),
        (error) => error?.code === "TENANT_SCOPE_VIOLATION",
      );
      await assert.rejects(
        port.get(
          {
            ...ownerScope,
            tenantId: UNKNOWN_TENANT,
            correlationId: "c12-unknown-tenant",
          },
          taskId(1),
        ),
        (error) => error?.code === "TENANT_SCOPE_VIOLATION",
      );
    },
  );

  await t.test(
    "failed or asynchronous reducers roll back state and receipt",
    async () => {
      const authorizedScope = scope();
      const initial = taskState({
        authorizedScope,
        id: taskId(5),
        marker: "rollback-initial",
      });
      await port.create(
        authorizedScope,
        command("START", "rollback-start", "rollback-start", {
          state: initial,
        }),
      );
      await assert.rejects(
        port.transact(
          authorizedScope,
          command(
            "ADVANCE",
            "rollback-async",
            "rollback-async",
            {
              taskId: initial.taskId,
              expectedVersion: 1,
              reduce: async (current) =>
                nextState(current, "must-not-commit"),
            },
          ),
        ),
        (error) => error?.code === "INVALID_INPUT",
      );
      assert.deepEqual(
        await port.get(authorizedScope, initial.taskId),
        initial,
      );
      const receipt = await adminPool.query(
        `SELECT count(*)::integer AS count
           FROM aios_orchestration.command_receipt
          WHERE tenant_id=$1 AND idempotency_key='rollback-async'`,
        [authorizedScope.tenantId],
      );
      assert.equal(receipt.rows[0].count, 0);

      const atomicInitial = taskState({
        authorizedScope,
        id: taskId(6),
        marker: "atomic-receipt-initial",
      });
      await port.create(
        authorizedScope,
        command(
          "START",
          "atomic-receipt-start",
          "atomic-receipt-start",
          { state: atomicInitial },
        ),
      );
      const failingPort = createPostgresAgentOrchestratorStatePort({
        runtimePool: rejectReceiptInsert(
          runtimePool,
          "atomic-receipt-failure",
        ),
        scopePool,
        tenantRegistry,
      });
      await assert.rejects(
        failingPort.transact(
          authorizedScope,
          command(
            "ADVANCE",
            "atomic-receipt-failure",
            "atomic-receipt-failure",
            {
              taskId: atomicInitial.taskId,
              expectedVersion: 1,
              reduce: (current) =>
                nextState(current, "must-roll-back-with-receipt"),
            },
          ),
        ),
        (error) => error?.code === "INTEGRITY_VIOLATION",
      );
      assert.deepEqual(
        await port.get(authorizedScope, atomicInitial.taskId),
        atomicInitial,
      );
      const atomicReceipt = await adminPool.query(
        `SELECT count(*)::integer AS count
           FROM aios_orchestration.command_receipt
          WHERE tenant_id=$1
            AND idempotency_key='atomic-receipt-failure'`,
        [authorizedScope.tenantId],
      );
      assert.equal(atomicReceipt.rows[0].count, 0);
    },
  );

  await t.test("RLS and exact roles fail closed", async () => {
    const invisible = await runtimePool.query(
      `SELECT count(*)::integer AS count
         FROM aios_orchestration.task_state`,
    );
    assert.equal(invisible.rows[0].count, 0);
    await assert.rejects(
      runtimePool.query(
        `INSERT INTO aios_orchestration.task_state (
           tenant_id,tenant_kind,task_id,human_principal_id,
           workload_actor_principal_id,version,state_sha256,task,
           created_at,updated_at
         ) VALUES (
           $1,'SYNTHETIC',$2,'prn_x','prn_y',1,$3,'{}'::jsonb,now(),now()
         )`,
        [TENANTS[0].tenantId, taskId(99), HASH_A],
      ),
      (error) => error?.code === "42501",
    );

    const unsafePort = createPostgresAgentOrchestratorStatePort({
      runtimePool: unsafePool,
      scopePool,
      tenantRegistry,
    });
    await assert.rejects(
      unsafePort.get(scope(), taskId(1)),
      (error) => error?.code === "INVALID_CONFIGURATION",
    );
  });
});
