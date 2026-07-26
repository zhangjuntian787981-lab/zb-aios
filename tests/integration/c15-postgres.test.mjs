import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createHumanDecisionWorkflow,
  createSyntheticHumanDecisionCatalog,
  humanDecisionSha256,
} from "../../lib/human-decision-workflow.mjs";
import {
  createC15AuditOutboxWorker,
  createC15EffectOutboxWorker,
} from "../../lib/c15-outbox-worker.mjs";
import {
  createC15SyntheticEffectAdapter,
} from "../../lib/c15-synthetic-effect-adapter.mjs";
import {
  PostgresHumanDecisionStoreError,
  createPostgresHumanDecisionStore,
} from "../../lib/postgres-human-decision-store.mjs";

const { Pool } = pg;
const migrationPaths = [
  "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
  "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
  "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
  "../../implementation/p1/c18/postgresql/0023_audit_evidence.sql",
  "../../implementation/p1/c18/postgresql/0024_audit_evidence_runtime_roles.sql",
  "../../implementation/p1/c15/postgresql/0027_human_decision.sql",
  "../../implementation/p1/c15/postgresql/0028_human_decision_runtime_roles.sql",
];
const migrations = await Promise.all(
  migrationPaths.map((path) =>
    readFile(new URL(path, import.meta.url), "utf8"),
  ),
);
const fixtureDocument = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c15/synthetic-workflow-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TENANTS = fixtureDocument.workflows.map((item, index) => ({
  ...item,
  namespaceId:
    `sns_01984910-3000-7000-8000-${String(index + 71).padStart(12, "0")}`,
  tenantOperationId:
    `op_01984910-3000-7000-8000-${String(index + 81).padStart(12, "0")}`,
}));
const HUMAN = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const NOW = new Date().toISOString();
const RUNTIME_LOGIN = "c15_test_runtime_login";
const EFFECT_LOGIN = "c15_test_effect_login";
const AUDIT_LOGIN = "c15_test_audit_login";
const RECOVERY_LOGIN = "c15_test_recovery_login";
const SCOPE_LOGIN = "c15_test_scope_login";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

function config(user = process.env.C15_TEST_PGUSER, max = 30) {
  if (process.env.C15_TEST_EPHEMERAL !== "1") {
    throw new Error("C15_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C15_TEST_PGHOST",
    "C15_TEST_PGPORT",
    "C15_TEST_PGDATABASE",
    "C15_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C15_TEST_PGHOST,
    port: Number(process.env.C15_TEST_PGPORT),
    database: process.env.C15_TEST_PGDATABASE,
    user,
    max,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deterministicIds(start) {
  let current = start;
  return () => {
    current += 1;
    return `018f0000-0000-7000-8000-${String(current).padStart(12, "0")}`;
  };
}

function identity(tenantId, epoch = 1) {
  return {
    tenantId,
    tenantKind: "SYNTHETIC",
    identityAccountId: "sia_synthetic",
    identityLinkId: "lnk_synthetic",
    sessionId: "session-synthetic",
    humanSubject: {
      principalId: HUMAN,
      principalType: "HUMAN",
      lifecycleVersion: 1,
      securityEpoch: epoch,
    },
    workloadActor: {
      principalId: ACTOR,
      principalType: "AGENT",
      lifecycleVersion: 1,
      securityEpoch: 1,
    },
    purposeRef: "synthetic://c15/purpose/decision",
    delegationChain: [
      {
        delegationId: DELEGATION,
        delegatorPrincipalId: HUMAN,
        delegatePrincipalId: ACTOR,
        purposeRef: "synthetic://c15/purpose/decision",
        lifecycleVersion: 1,
        expiresAt: "2031-01-01T00:00:00.000Z",
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

function scope(tenantId, suffix) {
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

async function seedTenant(adminPool, tenant, index) {
  const createdAt = `2026-07-26T08:0${index}:00.000Z`;
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id,tenant_kind,state,lifecycle_version,generation,
       creation_key,origin_ref,origin_hash,config_refs,
       resource_namespace_id,operation_id,created_at,updated_at
     ) VALUES (
       $1,'SYNTHETIC','PROVISIONING',1,1,$2,$3,$4,'[]'::jsonb,
       $5,$6,$7,$7
     )`,
    [
      tenant.tenantId,
      `c15-creation-${index}`,
      `fixture://c15/tenants/${index}`,
      digest(`c15-origin-${index}`),
      tenant.namespaceId,
      tenant.tenantOperationId,
      createdAt,
    ],
  );
  await adminPool.query(
    `INSERT INTO aios_core.tenant_projection (
       tenant_id,generation,projection,desired_action,status,
       attempt_count,source_event_id,updated_at
     )
     SELECT $1,1,projection,'PROVISION','READY',1,
            'c15-ready-' || lower(projection),$2::timestamptz
       FROM unnest($3::text[]) AS projection`,
    [tenant.tenantId, createdAt, PROJECTIONS],
  );
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,
            updated_at='2026-07-26T09:00:00.000Z'
      WHERE tenant_id=$1`,
    [tenant.tenantId],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,
       operation_id,state,last_event_id,updated_at
     ) VALUES (
       $1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,
       '2026-07-26T09:00:00.000Z'
     )`,
    [
      tenant.tenantId,
      tenant.tenantOperationId,
      `c15-active-${index}`,
    ],
  );
}

function createStore(pools) {
  return createPostgresHumanDecisionStore({
    runtimePool: pools.runtime,
    effectWorkerPool: pools.effect,
    auditWorkerPool: pools.audit,
    recoveryPool: pools.recovery,
    scopePool: pools.scope,
  });
}

function createHarness(store, tenant, idStart) {
  const catalog = createSyntheticHumanDecisionCatalog(fixtureDocument);
  const mutable = { now: NOW, epoch: 1 };
  const workflow = createHumanDecisionWorkflow({
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId: tenant.tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return identity(tenant.tenantId, mutable.epoch);
      },
    },
    authorizer: {
      async enforce(_context, request, descriptor) {
        const current = identity(tenant.tenantId, mutable.epoch);
        return {
          trustSource: "C06_BOUND_DECISION_EVIDENCE",
          operationId: descriptor.operationId,
          decisionId: `c06-${descriptor.operationId}`,
          evidenceRef: `evidence://c15/${descriptor.operationId}`,
          policyVersion: "c06-v1",
          tenantId: tenant.tenantId,
          surface: descriptor.surface,
          resourceId: request.resourceId,
          humanPrincipalId: HUMAN,
          humanSecurityEpoch: mutable.epoch,
          workloadActorPrincipalId: ACTOR,
          workloadActorSecurityEpoch: 1,
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
        return {
          trustSource: "C15_DEDICATED_DECISION_CEREMONY",
          proofRef: input.proofRef,
          proofSha256: humanDecisionSha256(input),
          artifactSha256: input.artifactSha256,
          displaySha256: input.displaySha256,
          humanPrincipalId: HUMAN,
          leafDelegationId: DELEGATION,
        expiresAt: new Date(
          Date.parse(mutable.now) + 300000,
        ).toISOString(),
        };
      },
    },
    catalog,
    store,
    clock: () => mutable.now,
    idFactory: deterministicIds(idStart),
  });
  let sequence = 0;
  return {
    workflow,
    mutable,
    context: () => context(tenant.tenantId),
    prepare() {
      sequence += 1;
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey:
          `c15-pg-prepare-${tenant.resourcePrefix}-${idStart}-${sequence}`,
        correlationId: `c15-pg-prepare-${sequence}`,
        workflowRef: tenant.workflowRef,
        candidate: structuredClone(tenant.baseline),
      };
    },
    decide(artifact) {
      sequence += 1;
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey:
          `c15-pg-decide-${tenant.resourcePrefix}-${idStart}-${sequence}`,
        correlationId: `c15-pg-decide-${sequence}`,
        artifactId: artifact.artifactId,
        artifactSha256: artifact.artifactSha256,
        outcome: "APPROVE",
        ceremonyProofRef:
          `fixture://c15/ceremonies/${artifact.artifactId}`,
      };
    },
    execute(artifact, decision) {
      sequence += 1;
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey:
          `c15-pg-execute-${tenant.resourcePrefix}-${idStart}-${sequence}`,
        correlationId: `c15-pg-execute-${sequence}`,
        decisionId: decision.decisionId,
        decisionSha256: decision.decisionSha256,
        artifactId: artifact.artifactId,
        artifactSha256: artifact.artifactSha256,
      };
    },
    withdraw(decision) {
      sequence += 1;
      return {
        sessionToken: "synthetic-session",
        delegationId: DELEGATION,
        idempotencyKey:
          `c15-pg-withdraw-${tenant.resourcePrefix}-${idStart}-${sequence}`,
        correlationId: `c15-pg-withdraw-${sequence}`,
        decisionId: decision.decisionId,
        decisionSha256: decision.decisionSha256,
      };
    },
  };
}

test("C15 PostgreSQL state, Outboxes, roles, RLS and recovery are real", async (t) => {
  const adminPool = new Pool(config());
  const pools = {
    runtime: new Pool(config(RUNTIME_LOGIN)),
    effect: new Pool(config(EFFECT_LOGIN)),
    audit: new Pool(config(AUDIT_LOGIN)),
    recovery: new Pool(config(RECOVERY_LOGIN)),
    scope: new Pool(config(SCOPE_LOGIN)),
  };
  t.after(async () => {
    await Promise.all(Object.values(pools).map((pool) => pool.end()));
    await adminPool.end();
  });

  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_decision') AS decision_schema`,
  );
  assert.match(safety.rows[0].database, /^c15_test_[0-9]+$/);
  assert.equal(safety.rows[0].decision_schema, null);

  for (const migration of migrations) await adminPool.query(migration);
  for (const login of [
    RUNTIME_LOGIN,
    EFFECT_LOGIN,
    AUDIT_LOGIN,
    RECOVERY_LOGIN,
    SCOPE_LOGIN,
  ]) {
    await adminPool.query(`CREATE ROLE ${login} LOGIN`);
  }
  await adminPool.query(
    `GRANT aios_c15_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c15_effect_worker TO ${EFFECT_LOGIN};
     GRANT aios_c15_audit_worker TO ${AUDIT_LOGIN};
     GRANT aios_c15_recovery_reader TO ${RECOVERY_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(adminPool, tenant, index);
  }

  const store = createStore(pools);
  const records = [];

  await t.test("three Tenants persist isolated complete decisions", async () => {
    for (const [index, tenant] of TENANTS.entries()) {
      const harness = createHarness(store, tenant, 4000 + index * 200);
      const prepareRequest = harness.prepare();
      const [artifactA, artifactB] = await Promise.all([
        harness.workflow.prepare(harness.context(), prepareRequest),
        harness.workflow.prepare(harness.context(), prepareRequest),
      ]);
      assert.equal(artifactA.artifactId, artifactB.artifactId);
      const decision = await harness.workflow.decide(
        harness.context(),
        harness.decide(artifactA),
      );
      const effect = await harness.workflow.execute(
        harness.context(),
        harness.execute(artifactA, decision),
      );
      assert.equal(effect.externalEffectCount, 0);
      records.push({ harness, artifact: artifactA, decision, effect });
    }
    assert.equal(new Set(records.map((item) => item.artifact.artifactId)).size, 3);
    const tenantCounts = await adminPool.query(
      `SELECT tenant_id,count(*)::int AS count
         FROM aios_decision.draft_artifact
        GROUP BY tenant_id ORDER BY tenant_id`,
    );
    assert.deepEqual(
      tenantCounts.rows.map((row) => row.count),
      [1, 1, 1],
    );
    assert.equal(
      await store.getArtifact(
        scope(TENANTS[1].tenantId, "cross-tenant"),
        records[0].artifact.artifactId,
      ),
      null,
    );
    const cleared = await pools.runtime.query(
      `SELECT current_setting('aios.tenant_id', true) AS tenant_id,
              current_setting('aios.scope_signature', true)
                AS scope_signature`,
    );
    assert.ok(
      Object.values(cleared.rows[0]).every(
        (value) => value === null || value === "",
      ),
    );
  });

  await t.test("expired Effect and Audit leases are reclaimed after a worker restart", async () => {
    const tenantId = TENANTS[0].tenantId;
    const firstEffectLease = await store.claimEffects(
      scope(tenantId, "effect-lease-1"),
      {
        workerId: "c15-pg-expired-effect-worker",
        limit: 1,
        leaseDurationSeconds: 1,
      },
    );
    const firstAuditLease = await store.claimAudit(
      scope(tenantId, "audit-lease-1"),
      {
        workerId: "c15-pg-expired-audit-worker",
        limit: 1,
        leaseDurationSeconds: 1,
      },
    );
    assert.equal(firstEffectLease.length, 1);
    assert.equal(firstAuditLease.length, 1);

    await new Promise((resolve) => setTimeout(resolve, 1100));

    const reclaimedEffect = await store.claimEffects(
      scope(tenantId, "effect-lease-2"),
      {
        workerId: "c15-pg-restarted-effect-worker",
        limit: 1,
        leaseDurationSeconds: 30,
      },
    );
    const reclaimedAudit = await store.claimAudit(
      scope(tenantId, "audit-lease-2"),
      {
        workerId: "c15-pg-restarted-audit-worker",
        limit: 1,
        leaseDurationSeconds: 30,
      },
    );
    assert.equal(
      reclaimedEffect[0].leaseVersion,
      firstEffectLease[0].leaseVersion + 1,
    );
    assert.equal(
      reclaimedAudit[0].leaseVersion,
      firstAuditLease[0].leaseVersion + 1,
    );
    await store.failEffect(scope(tenantId, "effect-lease-release"), {
      effectId: reclaimedEffect[0].effectId,
      workerId: "c15-pg-restarted-effect-worker",
      leaseVersion: reclaimedEffect[0].leaseVersion,
      retryDelaySeconds: 0,
      errorCode: "REVIEW_RETRY",
    });
    await store.failAudit(scope(tenantId, "audit-lease-release"), {
      intentId: reclaimedAudit[0].intentId,
      workerId: "c15-pg-restarted-audit-worker",
      leaseVersion: reclaimedAudit[0].leaseVersion,
      retryDelaySeconds: 0,
      errorCode: "REVIEW_RETRY",
    });
  });

  await t.test("restart, effect idempotency and readback compensation hold", async () => {
    const restarted = createStore(pools);
    const first = records[0];
    const loaded = await restarted.getDecision(
      scope(TENANTS[0].tenantId, "restart"),
      first.decision.decisionId,
    );
    assert.equal(loaded.decisionSha256, first.decision.decisionSha256);
    await assert.rejects(
      first.harness.workflow.execute(
        first.harness.context(),
        first.harness.execute(first.artifact, first.decision),
      ),
      (error) =>
        error instanceof PostgresHumanDecisionStoreError &&
        error.code === "EFFECT_KEY_CONFLICT",
    );

    const adapter = createC15SyntheticEffectAdapter();
    const worker = createC15EffectOutboxWorker({
      store: restarted,
      adapter,
      workerId: "c15-pg-effect-worker",
      clock: () => NOW,
      idFactory: deterministicIds(4800),
    });
    const completed = await worker.runOnce(
      scope(TENANTS[0].tenantId, "effect"),
    );
    assert.equal(completed.status, "SUCCEEDED");
    assert.equal(
      adapter.snapshot().commitCounts[first.effect.effectKey],
      1,
    );
    assert.equal(
      await worker.runOnce(scope(TENANTS[0].tenantId, "effect-empty")),
      null,
    );

    const second = records[1];
    const mismatch = createC15SyntheticEffectAdapter({
      mismatchEffectKeys: new Set([second.effect.effectKey]),
    });
    const mismatchWorker = createC15EffectOutboxWorker({
      store: restarted,
      adapter: mismatch,
      workerId: "c15-pg-mismatch-worker",
      clock: () => NOW,
      idFactory: deterministicIds(4900),
    });
    const compensated = await mismatchWorker.runOnce(
      scope(TENANTS[1].tenantId, "mismatch"),
    );
    assert.equal(compensated.status, "COMPENSATED");
    assert.equal(mismatch.snapshot().externalEffectCount, 0);
  });

  await t.test("withdrawal is atomic with execution queueing", async () => {
    await assert.rejects(
      records[0].harness.workflow.withdraw(
        records[0].harness.context(),
        records[0].harness.withdraw(records[0].decision),
      ),
      (error) => error.code === "DECISION_ALREADY_EXECUTING",
    );

    const tenant = TENANTS[2];
    const harness = createHarness(store, tenant, 4950);
    const artifact = await harness.workflow.prepare(
      harness.context(),
      harness.prepare(),
    );
    const decision = await harness.workflow.decide(
      harness.context(),
      harness.decide(artifact),
    );
    const withdrawn = await harness.workflow.withdraw(
      harness.context(),
      harness.withdraw(decision),
    );
    assert.equal(withdrawn.status, "WITHDRAWN");
    await assert.rejects(
      harness.workflow.execute(
        harness.context(),
        harness.execute(artifact, decision),
      ),
      (error) => error.code === "DECISION_NOT_ACTIVE",
    );

    const raceHarness = createHarness(store, tenant, 4975);
    const raceArtifact = await raceHarness.workflow.prepare(
      raceHarness.context(),
      raceHarness.prepare(),
    );
    const raceDecision = await raceHarness.workflow.decide(
      raceHarness.context(),
      raceHarness.decide(raceArtifact),
    );
    const race = await Promise.allSettled([
      raceHarness.workflow.execute(
        raceHarness.context(),
        raceHarness.execute(raceArtifact, raceDecision),
      ),
      raceHarness.workflow.withdraw(
        raceHarness.context(),
        raceHarness.withdraw(raceDecision),
      ),
    ]);
    const fulfilled = race.filter((result) => result.status === "fulfilled");
    const rejected = race.filter((result) => result.status === "rejected");
    assert.equal(fulfilled.length, 1);
    assert.equal(rejected.length, 1);
    assert.ok(
      ["DECISION_ALREADY_EXECUTING", "DECISION_NOT_ACTIVE"].includes(
        rejected[0].reason?.code,
      ),
    );
  });

  await t.test("metadata-only C18 seam survives ACK loss", async () => {
    const published = new Set();
    let ackLoss = true;
    const worker = createC15AuditOutboxWorker({
      store,
      c18Publisher: {
        async publish(intent) {
          assert.equal(Object.hasOwn(intent, "candidate"), false);
          assert.equal(Object.hasOwn(intent, "display"), false);
          published.add(intent.intentId);
          if (ackLoss) {
            ackLoss = false;
            throw Object.assign(new Error("ack loss"), {
              code: "ACK_LOST",
            });
          }
          return { intentId: intent.intentId };
        },
      },
      workerId: "c15-pg-audit-worker",
      retryDelaySeconds: 0,
    });
    await assert.rejects(
      worker.runOnce(scope(TENANTS[0].tenantId, "audit-1")),
      /ack loss/,
    );
    await worker.runOnce(scope(TENANTS[0].tenantId, "audit-2"));
    assert.equal(published.size, 1);
  });

  await t.test("RLS, least privilege and append-only guards fail closed", async () => {
    const runtime = await pools.runtime.connect();
    const effect = await pools.effect.connect();
    const audit = await pools.audit.connect();
    const recovery = await pools.recovery.connect();
    try {
      await assert.rejects(
        runtime.query("SELECT * FROM aios_decision.audit_intent"),
        (error) => error.code === "42501",
      );
      await assert.rejects(
        effect.query("SELECT * FROM aios_decision.draft_artifact"),
        (error) => error.code === "42501",
      );
      await assert.rejects(
        audit.query("SELECT * FROM aios_decision.workflow_effect"),
        (error) => error.code === "42501",
      );
      await assert.rejects(
        recovery.query(
          "DELETE FROM aios_decision.command_receipt",
        ),
        (error) => error.code === "42501",
      );
    } finally {
      runtime.release();
      effect.release();
      audit.release();
      recovery.release();
    }
    await assert.rejects(
      adminPool.query(
        `UPDATE aios_decision.draft_artifact
            SET artifact_sha256=$3
          WHERE tenant_id=$1 AND artifact_id=$2`,
        [
          TENANTS[0].tenantId,
          records[0].artifact.artifactId,
          "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ],
      ),
      (error) => error.constraint === "c15_append_only_guard",
    );
    const rls = await adminPool.query(
      `SELECT relname,relrowsecurity,relforcerowsecurity
         FROM pg_class
        WHERE relnamespace='aios_decision'::regnamespace
          AND relkind='r'
        ORDER BY relname`,
    );
    assert.equal(rls.rowCount, 8);
    assert.ok(
      rls.rows.every(
        (row) => row.relrowsecurity && row.relforcerowsecurity,
      ),
    );
    const existingIntent = await adminPool.query(
      `SELECT metadata
         FROM aios_decision.audit_intent
        WHERE tenant_id=$1
        ORDER BY created_at,intent_id
        LIMIT 1`,
      [TENANTS[0].tenantId],
    );
    const bodyBearing = {
      ...existingIntent.rows[0].metadata,
      intentId: "hai_018f0000-0000-7000-8000-000000009999",
      content: "forbidden audit body",
    };
    await assert.rejects(
      adminPool.query(
        `INSERT INTO aios_decision.audit_intent (
           tenant_id,tenant_kind,intent_id,event_type,subject_id,
           subject_sha256,intent_sha256,metadata,created_at
         ) VALUES (
           $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7::jsonb,
           statement_timestamp()
         )`,
        [
          TENANTS[0].tenantId,
          bodyBearing.intentId,
          bodyBearing.eventType,
          bodyBearing.subjectId,
          bodyBearing.subjectSha256,
          digest("body-bearing-audit"),
          JSON.stringify(bodyBearing),
        ],
      ),
      (error) =>
        error.constraint === "c15_audit_intent_metadata_only",
    );
  });

  await t.test("recovery is stable and unpaired writes roll back", async () => {
    const recovery = await store.exportRecovery(
      scope(TENANTS[0].tenantId, "recovery"),
    );
    assert.equal(recovery.schemaVersion, "c15-postgres-recovery.v1");
    assert.equal(
      recovery.recoverySha256,
      humanDecisionSha256({
        schemaVersion: recovery.schemaVersion,
        tenantId: recovery.tenantId,
        tenantKind: recovery.tenantKind,
        collections: recovery.collections,
      }),
    );
    await assert.rejects(
      adminPool.query(
        `BEGIN;
         INSERT INTO aios_decision.command_receipt (
           tenant_id,tenant_kind,idempotency_key,operation,request_hash,
           subject_id,audit_intent_id,response,created_at
         ) VALUES (
           $1,'SYNTHETIC','unpaired','PREPARE',$2,'missing',$3,
           '{}'::jsonb,statement_timestamp()
         );
         COMMIT;`,
        [
          TENANTS[0].tenantId,
          "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          recovery.collections.audit_intent[0].intent_id,
        ],
      ),
    );
    const count = await adminPool.query(
      `SELECT count(*)::int AS count
         FROM aios_decision.command_receipt
        WHERE idempotency_key='unpaired'`,
    );
    assert.equal(count.rows[0].count, 0);
  });

  await t.test("unsafe pool role is rejected and discarded", async () => {
    await adminPool.query(
      `CREATE ROLE c15_test_unsafe_login LOGIN;
       GRANT aios_c15_runtime TO c15_test_unsafe_login;
       GRANT aios_c15_audit_worker TO c15_test_unsafe_login;`,
    );
    const unsafe = new Pool(config("c15_test_unsafe_login"));
    t.after(() => unsafe.end());
    const unsafeStore = createPostgresHumanDecisionStore({
      runtimePool: unsafe,
      effectWorkerPool: pools.effect,
      auditWorkerPool: pools.audit,
      recoveryPool: pools.recovery,
      scopePool: pools.scope,
    });
    await assert.rejects(
      unsafeStore.getArtifact(
        scope(TENANTS[0].tenantId, "unsafe"),
        records[0].artifact.artifactId,
      ),
      (error) =>
        error instanceof PostgresHumanDecisionStoreError &&
        error.code === "INVALID_CONFIGURATION",
    );
  });
});
