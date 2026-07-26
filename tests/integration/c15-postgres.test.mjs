import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createC15EffectOutcomeAuditIntent,
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
  createC15C18AuditPublisher,
} from "../../lib/c15-c18-audit-publisher.mjs";
import {
  createAuditEvidenceService,
  createSyntheticAuditEvidenceCatalog,
  createSyntheticAuditEvidenceRegistry,
} from "../../lib/c18-audit-evidence.mjs";
import {
  createPostgresAuditEvidenceStore,
} from "../../lib/c18-audit-evidence-postgres-store.mjs";
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
const c18Registry = createSyntheticAuditEvidenceRegistry(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c18/synthetic-evidence-registry.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);
const c18Catalog = createSyntheticAuditEvidenceCatalog(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c18/synthetic-evidence-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
  { evidenceRegistry: c18Registry },
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
const C18_WRITER_LOGIN = "c15_c18_writer_login";
const C18_READER_LOGIN = "c15_c18_reader_login";
const C18_OUTBOX_LOGIN = "c15_c18_outbox_login";
const C18_RECOVERY_LOGIN = "c15_c18_recovery_login";
const C18_RESTORE_LOGIN = "c15_c18_restore_login";
const C18_RETENTION_LOGIN = "c15_c18_retention_login";
const C18_SCOPE_LOGIN = "c15_c18_scope_login";
const C18_BUNDLE =
  "fixture://c18/northstar/bundles/completed-analysis-v1";
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

function c18Identity(tenantId) {
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
    c18Writer: new Pool(config(C18_WRITER_LOGIN)),
    c18Reader: new Pool(config(C18_READER_LOGIN)),
    c18Outbox: new Pool(config(C18_OUTBOX_LOGIN)),
    c18Recovery: new Pool(config(C18_RECOVERY_LOGIN)),
    c18Restore: new Pool(config(C18_RESTORE_LOGIN)),
    c18Retention: new Pool(config(C18_RETENTION_LOGIN)),
    c18Scope: new Pool(config(C18_SCOPE_LOGIN)),
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
    C18_WRITER_LOGIN,
    C18_READER_LOGIN,
    C18_OUTBOX_LOGIN,
    C18_RECOVERY_LOGIN,
    C18_RESTORE_LOGIN,
    C18_RETENTION_LOGIN,
    C18_SCOPE_LOGIN,
  ]) {
    await adminPool.query(`CREATE ROLE ${login} LOGIN`);
  }
  await adminPool.query(
    `GRANT aios_c15_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c15_effect_worker TO ${EFFECT_LOGIN};
     GRANT aios_c15_audit_worker TO ${AUDIT_LOGIN};
     GRANT aios_c15_recovery_reader TO ${RECOVERY_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};
     GRANT aios_c18_writer TO ${C18_WRITER_LOGIN};
     GRANT aios_c18_reader TO ${C18_READER_LOGIN};
     GRANT aios_c18_outbox_worker TO ${C18_OUTBOX_LOGIN};
     GRANT aios_c18_recovery_reader TO ${C18_RECOVERY_LOGIN};
     GRANT aios_c18_recovery_writer TO ${C18_RESTORE_LOGIN};
     GRANT aios_c18_retention_worker TO ${C18_RETENTION_LOGIN};
     GRANT aios_c07_scope_runtime TO ${C18_SCOPE_LOGIN};`,
  );
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(adminPool, tenant, index);
  }

  const store = createStore(pools);
  const c18Store = createPostgresAuditEvidenceStore({
    writerPool: pools.c18Writer,
    readerPool: pools.c18Reader,
    outboxPool: pools.c18Outbox,
    recoveryPool: pools.c18Recovery,
    restorePool: pools.c18Restore,
    retentionPool: pools.c18Retention,
    scopePool: pools.c18Scope,
  });
  const c18Service = createAuditEvidenceService({
    store: c18Store,
    catalog: c18Catalog,
    clock: () => NOW,
    idFactory: deterministicIds(5200),
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return c18Identity(TENANTS[0].tenantId);
      },
    },
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId: TENANTS[0].tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
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
  });
  const c15C18Publisher = createC15C18AuditPublisher({
    auditEvidenceService: c18Service,
    async resolveBinding(intent) {
      assert.equal(intent.tenantId, TENANTS[0].tenantId);
      return {
        serverContext: context(intent.tenantId),
        sessionToken: "synthetic-session",
        evidenceBundleRef: C18_BUNDLE,
      };
    },
  });
  const records = [];

  await t.test("invalid worker input is rejected before SQL", async () => {
    await assert.rejects(
      store.claimEffects(scope(TENANTS[0].tenantId, "invalid-worker"), {
        workerId: "x".repeat(129),
        limit: 1,
        leaseDurationSeconds: 30,
      }),
      (error) =>
        error instanceof PostgresHumanDecisionStoreError &&
        error.code === "INVALID_INPUT",
    );
    await assert.rejects(
      store.failEffect(scope(TENANTS[0].tenantId, "invalid-effect"), {
        effectId: "",
        workerId: "worker",
        leaseVersion: 1,
        leaseToken: "lease-token",
        retryDelaySeconds: 0,
        errorCode: "REVIEW_RETRY",
      }),
      (error) =>
        error instanceof PostgresHumanDecisionStoreError &&
        error.code === "INVALID_INPUT",
    );
  });

  await t.test("three Tenants persist isolated complete decisions", async () => {
    for (const [index, tenant] of TENANTS.entries()) {
      const harness = createHarness(store, tenant, 4000 + index * 200);
      const prepareRequest = harness.prepare();
      const [artifactA, artifactB] = await Promise.all([
        harness.workflow.prepare(harness.context(), prepareRequest),
        harness.workflow.prepare(harness.context(), prepareRequest),
      ]);
      assert.equal(artifactA.artifactId, artifactB.artifactId);
      const decideRequest = harness.decide(artifactA);
      const [decisionA, decisionB] = await Promise.all([
        harness.workflow.decide(harness.context(), decideRequest),
        harness.workflow.decide(harness.context(), decideRequest),
      ]);
      assert.equal(decisionA.decisionId, decisionB.decisionId);
      assert.equal(
        [decisionA.replayed, decisionB.replayed].filter(Boolean).length,
        1,
      );
      const decision = decisionA;
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

  await t.test("PostgreSQL queue rejects lifecycle tampering", async () => {
    const guardedStore = {
      ...store,
      async queueEffect(tenantScope, command) {
        const body = structuredClone(command.effect);
        body.executionIdentity.humanLifecycleVersion += 1;
        delete body.effectSha256;
        const effect = {
          ...body,
          effectSha256: humanDecisionSha256(body),
        };
        return store.queueEffect(tenantScope, {
          ...command,
          effect,
        });
      },
    };
    const harness = createHarness(guardedStore, TENANTS[0], 4550);
    const artifact = await harness.workflow.prepare(
      harness.context(),
      harness.prepare(),
    );
    const decision = await harness.workflow.decide(
      harness.context(),
      harness.decide(artifact),
    );
    await assert.rejects(
      harness.workflow.execute(
        harness.context(),
        harness.execute(artifact, decision),
      ),
      (error) =>
        error instanceof PostgresHumanDecisionStoreError &&
        error.code === "DECISION_AUTHORITY_REVOKED",
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
    await assert.rejects(
      store.failEffect(scope(tenantId, "stale-effect-lease"), {
        effectId: firstEffectLease[0].effectId,
        workerId: "c15-pg-expired-effect-worker",
        leaseVersion: firstEffectLease[0].leaseVersion,
        leaseToken: firstEffectLease[0].leaseToken,
        retryDelaySeconds: 0,
        errorCode: "STALE_WORKER_RETRY",
      }),
      (error) =>
        error instanceof PostgresHumanDecisionStoreError &&
        error.code === "STALE_OUTBOX_LEASE",
    );
    await assert.rejects(
      store.failAudit(scope(tenantId, "stale-audit-lease"), {
        intentId: firstAuditLease[0].intentId,
        workerId: "c15-pg-expired-audit-worker",
        leaseVersion: firstAuditLease[0].leaseVersion,
        leaseToken: firstAuditLease[0].leaseToken,
        retryDelaySeconds: 0,
        errorCode: "STALE_WORKER_RETRY",
      }),
      (error) =>
        error instanceof PostgresHumanDecisionStoreError &&
        error.code === "STALE_OUTBOX_LEASE",
    );
    const releasedEffect = await store.failEffect(
      scope(tenantId, "effect-lease-release"),
      {
        effectId: reclaimedEffect[0].effectId,
        workerId: "c15-pg-restarted-effect-worker",
        leaseVersion: reclaimedEffect[0].leaseVersion,
        leaseToken: reclaimedEffect[0].leaseToken,
        retryDelaySeconds: 0,
        errorCode: "REVIEW_RETRY",
      },
    );
    const releasedAudit = await store.failAudit(
      scope(tenantId, "audit-lease-release"),
      {
        intentId: reclaimedAudit[0].intentId,
        workerId: "c15-pg-restarted-audit-worker",
        leaseVersion: reclaimedAudit[0].leaseVersion,
        leaseToken: reclaimedAudit[0].leaseToken,
        retryDelaySeconds: 0,
        errorCode: "REVIEW_RETRY",
      },
    );
    assert.equal(releasedEffect.status, "FAILED");
    assert.equal(
      releasedEffect.leaseVersion,
      reclaimedEffect[0].leaseVersion,
    );
    assert.equal(releasedAudit.status, "FAILED");
    assert.equal(
      releasedAudit.leaseVersion,
      reclaimedAudit[0].leaseVersion,
    );
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
    const mismatchDelegate = createC15SyntheticEffectAdapter({
      mismatchEffectKeys: new Set([second.effect.effectKey]),
    });
    let mismatchReadbackCount = 0;
    const mismatch = {
      ...mismatchDelegate,
      async readback(effect) {
        mismatchReadbackCount += 1;
        return mismatchDelegate.readback(effect);
      },
    };
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
    assert.equal(mismatchDelegate.snapshot().externalEffectCount, 0);
    assert.equal(mismatchReadbackCount, 2);
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

  await t.test("persisted C18 receipt survives C15 ACK loss", async () => {
    const preflight = await store.claimAudit(
      scope(TENANTS[0].tenantId, "audit-preflight"),
      {
        workerId: "c15-pg-audit-preflight",
        limit: 1,
        leaseDurationSeconds: 30,
      },
    );
    assert.equal(preflight.length, 1);
    await assert.rejects(
      store.completeAudit(
        scope(TENANTS[0].tenantId, "audit-preflight-complete"),
        {
          intentId: preflight[0].intentId,
          workerId: "c15-pg-audit-preflight",
          leaseVersion: preflight[0].leaseVersion,
          leaseToken: preflight[0].leaseToken,
          ack: {
            schemaVersion: "c15-c18-audit-ack.v1",
            tenantId: TENANTS[0].tenantId,
            intentId: preflight[0].intentId,
            c18CommandReceiptKey: preflight[0].intentId,
            c18EventId:
              "aev_018f0000-0000-7000-8000-000000005199",
            c18EventHash:
              "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            c18PayloadSha256:
              "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            duplicate: false,
          },
        },
      ),
      (error) =>
        error instanceof PostgresHumanDecisionStoreError &&
        error.code === "AUDIT_ACK_NOT_PERSISTED",
    );
    await store.failAudit(
      scope(TENANTS[0].tenantId, "audit-preflight-release"),
      {
        intentId: preflight[0].intentId,
        workerId: "c15-pg-audit-preflight",
        leaseVersion: preflight[0].leaseVersion,
        leaseToken: preflight[0].leaseToken,
        retryDelaySeconds: 0,
        errorCode: "REVIEW_RETRY",
      },
    );
    let persistedIntentId;
    let loseC15Ack = true;
    const worker = createC15AuditOutboxWorker({
      store,
      c18Publisher: {
        async publish(intent) {
          assert.equal(Object.hasOwn(intent, "candidate"), false);
          assert.equal(Object.hasOwn(intent, "display"), false);
          persistedIntentId = intent.intentId;
          const ack = await c15C18Publisher.publish(intent);
          if (loseC15Ack) {
            loseC15Ack = false;
            throw Object.assign(new Error("C15 ack loss"), {
              code: "ACK_LOST",
            });
          }
          assert.equal(ack.duplicate, true);
          return ack;
        },
      },
      workerId: "c15-pg-audit-worker",
      retryDelaySeconds: 0,
    });
    await assert.rejects(
      worker.runOnce(scope(TENANTS[0].tenantId, "audit-1")),
      /C15 ack loss/,
    );
    await worker.runOnce(scope(TENANTS[0].tenantId, "audit-2"));
    const binding = await adminPool.query(
      `SELECT outbox.status,
              outbox.c18_receipt_key,
              outbox.c18_event_id,
              outbox.c18_event_hash,
              receipt.event_id AS receipt_event_id,
              event.event_hash AS persisted_event_hash,
              (
                SELECT count(*)::int
                  FROM aios_audit.audit_event AS counted
                 WHERE counted.tenant_id=outbox.tenant_id
                   AND counted.event_id=outbox.c18_event_id
              ) AS event_count,
              (
                SELECT count(*)::int
                  FROM aios_audit.audit_command_receipt AS counted
                 WHERE counted.tenant_id=outbox.tenant_id
                   AND counted.idempotency_key=outbox.intent_id
              ) AS receipt_count
         FROM aios_decision.audit_outbox AS outbox
         JOIN aios_audit.audit_command_receipt AS receipt
           ON receipt.tenant_id=outbox.tenant_id
          AND receipt.idempotency_key=outbox.c18_receipt_key
         JOIN aios_audit.audit_event AS event
           ON event.tenant_id=receipt.tenant_id
          AND event.event_id=receipt.event_id
        WHERE outbox.tenant_id=$1 AND outbox.intent_id=$2`,
      [TENANTS[0].tenantId, persistedIntentId],
    );
    assert.deepEqual(binding.rows[0], {
      status: "PUBLISHED",
      c18_receipt_key: persistedIntentId,
      c18_event_id: binding.rows[0].receipt_event_id,
      c18_event_hash: binding.rows[0].persisted_event_hash,
      receipt_event_id: binding.rows[0].receipt_event_id,
      persisted_event_hash: binding.rows[0].persisted_event_hash,
      event_count: 1,
      receipt_count: 1,
    });
  });

  await t.test("RLS, least privilege and append-only guards fail closed", async () => {
    const runtime = await pools.runtime.connect();
    const effect = await pools.effect.connect();
    const audit = await pools.audit.connect();
    const recovery = await pools.recovery.connect();
    try {
      const workerPrivileges = await adminPool.query(
        `SELECT
           has_table_privilege(
             'aios_c15_effect_worker',
             'aios_decision.effect_outbox',
             'UPDATE'
           ) AS effect_update,
           has_table_privilege(
             'aios_c15_effect_worker',
             'aios_decision.workflow_effect',
             'UPDATE'
           ) AS workflow_update,
           has_table_privilege(
             'aios_c15_audit_worker',
             'aios_decision.audit_outbox',
             'UPDATE'
           ) AS audit_update`,
      );
      assert.deepEqual(workerPrivileges.rows[0], {
        effect_update: false,
        workflow_update: false,
        audit_update: false,
      });
      const workerFunctions = await adminPool.query(
        `SELECT p.proname,p.prosecdef,p.proconfig
           FROM pg_proc AS p
           JOIN pg_namespace AS n ON n.oid=p.pronamespace
          WHERE n.nspname='aios_decision'
            AND p.proname=ANY($1::text[])
          ORDER BY p.proname`,
        [[
          "claim_effect_outbox",
          "complete_effect",
          "fail_effect_outbox",
          "claim_audit_outbox",
          "publish_audit_outbox",
          "fail_audit_outbox",
        ]],
      );
      assert.equal(workerFunctions.rowCount, 6);
      for (const row of workerFunctions.rows) {
        assert.equal(row.prosecdef, true, row.proname);
        assert.deepEqual(
          row.proconfig,
          ["search_path=pg_catalog"],
          row.proname,
        );
      }
      await assert.rejects(
        effect.query(
          "UPDATE aios_decision.effect_outbox SET status=status",
        ),
        (error) => error.code === "42501",
      );
      await assert.rejects(
        audit.query(
          "UPDATE aios_decision.audit_outbox SET status=status",
        ),
        (error) => error.code === "42501",
      );
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
    const terminalGuardLease = await store.claimEffects(
      scope(TENANTS[2].tenantId, "terminal-guard"),
      {
        workerId: "c15-terminal-guard-worker",
        limit: 1,
        leaseDurationSeconds: 30,
      },
    );
    assert.equal(terminalGuardLease.length, 1);
    const forgedAudit = createC15EffectOutcomeAuditIntent({
      effect: terminalGuardLease[0].effect,
      terminalStatus: "SUCCEEDED",
      identityBinding:
        terminalGuardLease[0].effect.executionIdentity,
      authorization:
        terminalGuardLease[0].effect.executionAuthorization,
      correlationId: "c15-forged-completion",
      occurredAt: NOW,
      idFactory: deterministicIds(5150),
    });
    await assert.rejects(
      store.completeEffect(
        scope(TENANTS[2].tenantId, "forged-completion"),
        {
          effect: terminalGuardLease[0].effect,
          effectId: terminalGuardLease[0].effectId,
          workerId: "c15-terminal-guard-worker",
          leaseVersion: terminalGuardLease[0].leaseVersion,
          leaseToken: terminalGuardLease[0].leaseToken,
          terminalStatus: "SUCCEEDED",
          commitReceipt: {},
          readbackReceipt: {},
          compensationReceipt: null,
          auditIntent: forgedAudit,
        },
      ),
      (error) => error.code === "INTEGRITY_VIOLATION",
    );
    const completionGuard = await adminPool.connect();
    try {
      await completionGuard.query("BEGIN");
      await completionGuard.query(
        `INSERT INTO aios_decision.audit_intent (
           tenant_id,tenant_kind,intent_id,event_type,subject_id,
           subject_sha256,intent_sha256,metadata,created_at
         ) VALUES (
           $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7::jsonb,$8::timestamptz
         )`,
        [
          forgedAudit.tenantId,
          forgedAudit.intentId,
          forgedAudit.eventType,
          forgedAudit.subjectId,
          forgedAudit.subjectSha256,
          humanDecisionSha256(forgedAudit),
          JSON.stringify(forgedAudit),
          forgedAudit.occurredAt,
        ],
      );
      await assert.rejects(
        completionGuard.query(
          `UPDATE aios_decision.workflow_effect
              SET status='SUCCEEDED',
                  commit_receipt='{}'::jsonb,
                  readback_receipt='{}'::jsonb,
                  compensation_receipt=NULL,
                  terminal_audit_intent_id=$3,
                  updated_at=statement_timestamp()
            WHERE tenant_id=$1 AND effect_id=$2`,
          [
            TENANTS[2].tenantId,
            terminalGuardLease[0].effectId,
            forgedAudit.intentId,
          ],
        ),
        (error) =>
          error.constraint === "c15_effect_completion_guard",
      );
    } finally {
      await completionGuard.query("ROLLBACK");
      completionGuard.release();
    }
    await adminPool.query("BEGIN");
    try {
      await assert.rejects(
        adminPool.query(
          `UPDATE aios_decision.effect_outbox
              SET status='PUBLISHED',
                  leased_by=NULL,
                  lease_until=NULL,
                  published_at=statement_timestamp(),
                  last_error_code=NULL
            WHERE tenant_id=$1 AND effect_id=$2`,
          [
            TENANTS[2].tenantId,
            terminalGuardLease[0].effectId,
          ],
        ),
        (error) =>
          error.constraint === "c15_effect_terminal_before_publish",
      );
    } finally {
      await adminPool.query("ROLLBACK");
    }
    await store.failEffect(
      scope(TENANTS[2].tenantId, "terminal-guard-release"),
      {
        effectId: terminalGuardLease[0].effectId,
        workerId: "c15-terminal-guard-worker",
        leaseVersion: terminalGuardLease[0].leaseVersion,
        leaseToken: terminalGuardLease[0].leaseToken,
        retryDelaySeconds: 0,
        errorCode: "REVIEW_RETRY",
      },
    );
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
    const legalMetadata = existingIntent.rows[0].metadata;
    for (const [name, metadata, expected] of [
      ["legal", legalMetadata, true],
      ["extra", { ...legalMetadata, unexpected: true }, false],
      ["body", { ...legalMetadata, body: "forbidden" }, false],
      ["unknown content", {
        ...legalMetadata,
        candidate: { field: "forbidden" },
      }, false],
    ]) {
      const validation = await adminPool.query(
        `SELECT aios_decision.valid_audit_intent($1::jsonb)
           AS valid`,
        [JSON.stringify(metadata)],
      );
      assert.equal(validation.rows[0].valid, expected, name);
    }
    const bodyBearing = {
      ...legalMetadata,
      intentId: "hai_018f0000-0000-7000-8000-000000009999",
      body: "forbidden audit body",
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

  await t.test("unsafe role closure, attributes and direct grants fail closed", async (roleTest) => {
    const cases = [
      {
        name: "required role with admin option",
        login: "c15_bad_admin_option",
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_admin_option WITH ADMIN OPTION",
        ],
      },
      {
        name: "mixed owner",
        login: "c15_bad_owner",
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_owner",
          "GRANT aios_c15_owner TO c15_bad_owner",
        ],
      },
      {
        name: "adjacent runtime",
        login: "c15_bad_adjacent",
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_adjacent",
          "GRANT aios_c07_data_runtime TO c15_bad_adjacent",
        ],
      },
      {
        name: "indirect arbitrary role",
        login: "c15_bad_indirect",
        setup: [
          "CREATE ROLE aios_c15_test_bridge NOLOGIN",
          "GRANT aios_c15_runtime TO aios_c15_test_bridge",
        ],
        grants: [
          "GRANT aios_c15_test_bridge TO c15_bad_indirect",
        ],
        cleanupRoles: ["aios_c15_test_bridge"],
      },
      {
        name: "built-in read-all",
        login: "c15_bad_read_all",
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_read_all",
          "GRANT pg_read_all_data TO c15_bad_read_all",
        ],
      },
      {
        name: "direct schema privilege",
        login: "c15_bad_schema",
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_schema",
          "GRANT CREATE ON SCHEMA aios_data TO c15_bad_schema",
        ],
      },
      {
        name: "direct table privilege",
        login: "c15_bad_table",
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_table",
          "GRANT SELECT ON aios_decision.audit_intent TO c15_bad_table",
        ],
      },
      {
        name: "direct column privilege",
        login: "c15_bad_column",
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_column",
          "GRANT SELECT (subject_sha256) ON aios_decision.audit_intent TO c15_bad_column",
        ],
      },
      {
        name: "direct sequence privilege",
        login: "c15_bad_sequence",
        setup: [
          "CREATE SEQUENCE aios_decision.c15_test_extra_sequence",
        ],
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_sequence",
          "GRANT USAGE ON SEQUENCE aios_decision.c15_test_extra_sequence TO c15_bad_sequence",
        ],
        cleanup: [
          "DROP SEQUENCE aios_decision.c15_test_extra_sequence",
        ],
      },
      {
        name: "direct function privilege",
        login: "c15_bad_function",
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_function",
          "GRANT EXECUTE ON FUNCTION aios_decision.reject_append_only_change() TO c15_bad_function",
        ],
      },
      {
        name: "adjacent direct object privileges",
        login: "c15_bad_adjacent_direct",
        setup: [
          "CREATE SCHEMA aios_c15_adjacent_test",
          "CREATE TABLE aios_c15_adjacent_test.private_record (id integer)",
          "CREATE FUNCTION aios_c15_adjacent_test.private_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
          "REVOKE ALL ON SCHEMA aios_c15_adjacent_test FROM PUBLIC",
          "REVOKE ALL ON ALL TABLES IN SCHEMA aios_c15_adjacent_test FROM PUBLIC",
          "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_c15_adjacent_test FROM PUBLIC",
        ],
        grants: [
          "GRANT aios_c15_runtime TO c15_bad_adjacent_direct",
          "GRANT USAGE ON SCHEMA aios_c15_adjacent_test TO c15_bad_adjacent_direct",
          "GRANT SELECT ON aios_c15_adjacent_test.private_record TO c15_bad_adjacent_direct",
          "GRANT EXECUTE ON FUNCTION aios_c15_adjacent_test.private_function() TO c15_bad_adjacent_direct",
        ],
        cleanup: [
          "DROP SCHEMA aios_c15_adjacent_test CASCADE",
        ],
      },
      {
        name: "CREATEDB",
        login: "c15_bad_createdb",
        attributes: "CREATEDB",
        grants: ["GRANT aios_c15_runtime TO c15_bad_createdb"],
      },
      {
        name: "CREATEROLE",
        login: "c15_bad_createrole",
        attributes: "CREATEROLE",
        grants: ["GRANT aios_c15_runtime TO c15_bad_createrole"],
      },
      {
        name: "REPLICATION",
        login: "c15_bad_replication",
        attributes: "REPLICATION",
        grants: ["GRANT aios_c15_runtime TO c15_bad_replication"],
      },
      {
        name: "SUPERUSER",
        login: "c15_bad_superuser",
        attributes: "SUPERUSER",
        grants: ["GRANT aios_c15_runtime TO c15_bad_superuser"],
      },
      {
        name: "BYPASSRLS",
        login: "c15_bad_bypassrls",
        attributes: "BYPASSRLS",
        grants: ["GRANT aios_c15_runtime TO c15_bad_bypassrls"],
      },
    ];

    for (const entry of cases) {
      await roleTest.test(entry.name, async () => {
        for (const statement of entry.setup ?? []) {
          await adminPool.query(statement);
        }
        await adminPool.query(
          `CREATE ROLE ${entry.login} LOGIN ${entry.attributes ?? ""}`,
        );
        for (const statement of entry.grants) {
          await adminPool.query(statement);
        }
        const unsafePool = new Pool(config(entry.login, 1));
        try {
          const unsafeStore = createPostgresHumanDecisionStore({
            runtimePool: unsafePool,
            effectWorkerPool: pools.effect,
            auditWorkerPool: pools.audit,
            recoveryPool: pools.recovery,
            scopePool: pools.scope,
          });
          await assert.rejects(
            unsafeStore.getArtifact(
              scope(TENANTS[0].tenantId, `unsafe-${entry.login}`),
              records[0].artifact.artifactId,
            ),
            (error) =>
              error instanceof PostgresHumanDecisionStoreError &&
              error.code === "INVALID_CONFIGURATION",
          );
        } finally {
          await unsafePool.end();
          await adminPool.query(`DROP OWNED BY ${entry.login}`);
          await adminPool.query(`DROP ROLE ${entry.login}`);
          for (const role of entry.cleanupRoles ?? []) {
            await adminPool.query(`DROP ROLE ${role}`);
          }
          for (const statement of entry.cleanup ?? []) {
            await adminPool.query(statement);
          }
        }
      });
    }
  });

  await t.test("every pool rejects a missing required privilege", async (poolTest) => {
    const tenantId = TENANTS[0].tenantId;
    const cases = [
      {
        name: "runtime",
        revoke:
          "REVOKE SELECT ON aios_decision.draft_artifact FROM aios_c15_runtime",
        restore:
          "GRANT SELECT ON aios_decision.draft_artifact TO aios_c15_runtime",
        probe: () =>
          store.getArtifact(
            scope(tenantId, "missing-runtime"),
            records[0].artifact.artifactId,
          ),
      },
      {
        name: "effect worker",
        revoke:
          "REVOKE EXECUTE ON FUNCTION aios_decision.claim_effect_outbox(text,text,integer,integer) FROM aios_c15_effect_worker",
        restore:
          "GRANT EXECUTE ON FUNCTION aios_decision.claim_effect_outbox(text,text,integer,integer) TO aios_c15_effect_worker",
        probe: () =>
          store.claimEffects(scope(tenantId, "missing-effect"), {
            workerId: "missing-effect-worker",
            limit: 1,
            leaseDurationSeconds: 30,
          }),
      },
      {
        name: "audit worker",
        revoke:
          "REVOKE EXECUTE ON FUNCTION aios_decision.claim_audit_outbox(text,text,integer,integer) FROM aios_c15_audit_worker",
        restore:
          "GRANT EXECUTE ON FUNCTION aios_decision.claim_audit_outbox(text,text,integer,integer) TO aios_c15_audit_worker",
        probe: () =>
          store.claimAudit(scope(tenantId, "missing-audit"), {
            workerId: "missing-audit-worker",
            limit: 1,
            leaseDurationSeconds: 30,
          }),
      },
      {
        name: "recovery reader",
        revoke:
          "REVOKE SELECT ON aios_decision.draft_artifact FROM aios_c15_recovery_reader",
        restore:
          "GRANT SELECT ON aios_decision.draft_artifact TO aios_c15_recovery_reader",
        probe: () =>
          store.exportRecovery(scope(tenantId, "missing-recovery")),
      },
      {
        name: "scope signer",
        revoke:
          "REVOKE EXECUTE ON FUNCTION aios_data.issue_runtime_scope_signature(text,text,bigint,text,text,text,text,integer,xid8,integer,uuid) FROM aios_c07_scope_runtime",
        restore:
          "GRANT EXECUTE ON FUNCTION aios_data.issue_runtime_scope_signature(text,text,bigint,text,text,text,text,integer,xid8,integer,uuid) TO aios_c07_scope_runtime",
        probe: () =>
          store.getArtifact(
            scope(tenantId, "missing-scope"),
            records[0].artifact.artifactId,
          ),
      },
    ];
    for (const entry of cases) {
      await poolTest.test(entry.name, async () => {
        await adminPool.query(entry.revoke);
        try {
          await assert.rejects(
            entry.probe(),
            (error) =>
              error instanceof PostgresHumanDecisionStoreError &&
              error.code === "INVALID_CONFIGURATION",
          );
        } finally {
          await adminPool.query(entry.restore);
        }
      });
    }
  });
});
