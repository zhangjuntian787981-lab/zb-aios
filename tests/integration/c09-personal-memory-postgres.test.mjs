import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { after, before } from "node:test";
import pg from "pg";
import {
  createPersonalMemoryService,
  createSyntheticHumanConsentAuthority,
  createSyntheticPersonalMemoryCatalog,
} from "../../lib/c09-personal-memory.mjs";
import {
  createPostgresPersonalMemoryStore,
} from "../../lib/c09-personal-memory-postgres-store.mjs";

const { Pool } = pg;
const TENANT_A = "stn_018f0000-0000-7000-8000-000000000010";
const TENANT_B = "stn_01984910-3000-7000-8000-000000000002";
const HUMAN_A = "prn_018f0000-0000-7000-8000-000000000001";
const HUMAN_B = "prn_018f0000-0000-7000-8000-000000000003";
const HUMAN_C = "prn_018f0000-0000-7000-8000-000000000004";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_A = "dlg_018f0000-0000-7000-8000-000000000020";
const DELEGATION_B = "dlg_018f0000-0000-7000-8000-000000000021";
const RUNTIME_LOGIN = "c09_test_runtime_login";
const TENANT_SCOPE_LOGIN = "c09_test_tenant_scope_login";
const PRINCIPAL_SCOPE_LOGIN = "c09_test_principal_scope_login";
const NOW = "2026-07-26T10:00:00.000Z";
const HASH =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];

const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c04/postgresql/0002_identity_federation.sql",
    "../../implementation/p1/c05/postgresql/0007_stable_principal.sql",
    "../../implementation/p1/c05/postgresql/0008_principal_runtime_roles.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c09/postgresql/0015_personal_memory.sql",
    "../../implementation/p1/c09/postgresql/0016_personal_memory_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);
const catalog = createSyntheticPersonalMemoryCatalog(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c09/synthetic-personal-memory-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);

function configuration(user = process.env.C09_TEST_PGUSER, max = 10) {
  if (process.env.C09_TEST_EPHEMERAL !== "1") {
    throw new Error("C09_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C09_TEST_PGHOST",
    "C09_TEST_PGPORT",
    "C09_TEST_PGDATABASE",
    "C09_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C09_TEST_PGHOST,
    port: Number(process.env.C09_TEST_PGPORT),
    database: process.env.C09_TEST_PGDATABASE,
    user,
    max,
  };
}

function deterministicIds(start = 300) {
  let counter = start;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

async function seedTenant(adminPool, tenantId, suffix) {
  const namespaceId =
    `sns_018f0000-0000-7000-8000-${suffix.padStart(12, "0")}`;
  const operationId =
    `op_018f0000-0000-7000-8000-${suffix.padStart(12, "0")}`;
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id,tenant_kind,state,lifecycle_version,generation,
       creation_key,origin_ref,origin_hash,config_refs,
       resource_namespace_id,operation_id,created_at,updated_at
     ) VALUES (
       $1,'SYNTHETIC','PROVISIONING',1,1,$2,$3,$4,'[]'::jsonb,
       $5,$6,'2026-07-26T09:00:00.000Z','2026-07-26T09:00:00.000Z'
     )`,
    [
      tenantId,
      `c09-tenant-${suffix}`,
      `fixture://c09/tenant/${suffix}`,
      HASH,
      namespaceId,
      operationId,
    ],
  );
  for (const projection of PROJECTIONS) {
    await adminPool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,generation,projection,desired_action,status,
         attempt_count,source_event_id,updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [
        tenantId,
        projection,
        `c09-${suffix}-${projection.toLowerCase()}`,
        "2026-07-26T09:01:00.000Z",
      ],
    );
  }
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,
            updated_at='2026-07-26T09:02:00.000Z'
      WHERE tenant_id=$1`,
    [tenantId],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,operation_id,
       state,last_event_id,updated_at
     ) VALUES (
       $1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,
       '2026-07-26T09:02:00.000Z'
     )`,
    [tenantId, operationId, `c09-active-${suffix}`],
  );
}

async function seedPrincipal(adminPool, tenantId, principalId, kind, suffix) {
  await adminPool.query(
    `INSERT INTO aios_core.principal_registry (
       principal_id,tenant_id,tenant_kind,principal_kind,creation_key,
       state,lifecycle_version,security_epoch,created_at,updated_at
     ) VALUES (
       $1,$2,'SYNTHETIC',$3,$4,'ACTIVE',1,1,
       '2026-07-26T09:03:00.000Z','2026-07-26T09:03:00.000Z'
     )`,
    [principalId, tenantId, kind, `c09-principal-${suffix}`],
  );
}

let adminPool;
let runtimePool;
let tenantScopePool;
let principalScopePool;
let store;

before(async () => {
  adminPool = new Pool(configuration());
  for (const migration of migrations) await adminPool.query(migration);
  await adminPool.query(
    `CREATE ROLE ${RUNTIME_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${TENANT_SCOPE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     CREATE ROLE ${PRINCIPAL_SCOPE_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     GRANT aios_c09_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c07_scope_runtime TO ${TENANT_SCOPE_LOGIN};
     GRANT aios_c09_scope_runtime TO ${PRINCIPAL_SCOPE_LOGIN};`,
  );
  await seedTenant(adminPool, TENANT_A, "10");
  await seedTenant(adminPool, TENANT_B, "20");
  await seedPrincipal(adminPool, TENANT_A, HUMAN_A, "HUMAN", "a");
  await seedPrincipal(adminPool, TENANT_A, HUMAN_B, "HUMAN", "b");
  await seedPrincipal(adminPool, TENANT_A, ACTOR, "SERVICE", "actor");
  await seedPrincipal(adminPool, TENANT_B, HUMAN_C, "HUMAN", "c");
  runtimePool = new Pool(configuration(RUNTIME_LOGIN));
  tenantScopePool = new Pool(configuration(TENANT_SCOPE_LOGIN));
  principalScopePool = new Pool(configuration(PRINCIPAL_SCOPE_LOGIN));
  store = createPostgresPersonalMemoryStore({
    runtimePool,
    tenantScopePool,
    principalScopePool,
  });
});

after(async () => {
  await Promise.allSettled([
    runtimePool?.end(),
    tenantScopePool?.end(),
    principalScopePool?.end(),
    adminPool?.end(),
  ]);
});

function createHarness({
  tenantId = TENANT_A,
  humanPrincipalId = HUMAN_A,
  delegationId = DELEGATION_A,
  start = 300,
} = {}) {
  const { issuer: consentIssuer, consentStore } =
    createSyntheticHumanConsentAuthority();
  const mutable = {
    now: NOW,
    sessionId: `session-${humanPrincipalId}`,
    delegationId,
  };
  const service = createPersonalMemoryService({
    catalog,
    store,
    idFactory: deterministicIds(start),
    clock: () => mutable.now,
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          sessionId: mutable.sessionId,
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
          delegationChain: [
            {
              delegationId: mutable.delegationId,
              delegatorPrincipalId: humanPrincipalId,
              delegatePrincipalId: ACTOR,
              lifecycleVersion: 1,
            },
          ],
          trustSource:
            "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
        };
      },
    },
    authorizer: {
      async enforce({ operation }) {
        return {
          allowed: true,
          tenantId,
          humanPrincipalId,
          workloadActorPrincipalId: ACTOR,
          delegationId: mutable.delegationId,
          operation,
          decisionId: `decision-${operation.toLowerCase()}`,
          evidenceRef: "evidence://c09/postgresql",
          policyVersion: "c09-postgresql-policy-v1",
        };
      },
    },
    tenantScopeFactory({ authorization, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 2,
        correlationId,
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.policyVersion,
      };
    },
    humanConsentStore: consentStore,
  });
  return {
    service,
    mutable,
    consentIssuer,
    tenantId,
    humanPrincipalId,
    context: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: ACTOR,
    },
    wrap(command) {
      return {
        sessionToken: `token-${mutable.sessionId}`,
        delegationId: mutable.delegationId,
        command,
      };
    },
    recall(suffix) {
      return {
        sessionToken: `token-${mutable.sessionId}`,
        delegationId: mutable.delegationId,
        correlationId: `pg-recall-${suffix}`,
        limit: 20,
      };
    },
  };
}

function propose(suffix) {
  return {
    kind: "PROPOSE_CANDIDATE",
    candidateRef: "fixture://c09/northstar/preferences/concise",
    idempotencyKey: `pg-propose-${suffix}`,
    correlationId: `pg-propose-${suffix}`,
  };
}

function confirm(
  harness,
  memoryId,
  suffix,
  candidateRef = "fixture://c09/northstar/preferences/concise",
) {
  return {
    kind: "CONFIRM_CANDIDATE",
    memoryId,
    expectedVersion: 1,
    humanConsentToken: harness.consentIssuer.issue({
      tenantId: harness.tenantId,
      humanPrincipalId: harness.humanPrincipalId,
      memoryId,
      expectedVersion: 1,
      contentSha256: catalog.resolve(
        harness.tenantId,
        candidateRef,
      ).contentSha256,
      expiresAt: "2026-07-26T11:00:00.000Z",
      purpose: "CONFIRM_PERSONAL_MEMORY",
    }),
    idempotencyKey: `pg-confirm-${suffix}`,
    correlationId: `pg-confirm-${suffix}`,
  };
}

test("PostgreSQL roles are non-privileged and RLS is forced", async () => {
  const roles = await adminPool.query(
    `SELECT rolname,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole
       FROM pg_roles
      WHERE rolname IN (
        'aios_c09_runtime','aios_c09_scope_runtime',
        $1,$2,$3
      )
      ORDER BY rolname`,
    [RUNTIME_LOGIN, TENANT_SCOPE_LOGIN, PRINCIPAL_SCOPE_LOGIN],
  );
  assert.equal(roles.rowCount, 5);
  assert.ok(
    roles.rows.every(
      (role) =>
        !role.rolsuper &&
        !role.rolbypassrls &&
        !role.rolcreatedb &&
        !role.rolcreaterole,
    ),
  );
  const rls = await adminPool.query(
    `SELECT relname,relrowsecurity,relforcerowsecurity
       FROM pg_class
      WHERE relnamespace='aios_personal_memory'::regnamespace
        AND relname IN (
          'personal_profile','personal_memory','conversation_checkpoint',
          'memory_event','command_receipt'
        )
      ORDER BY relname`,
  );
  assert.equal(rls.rowCount, 5);
  assert.ok(
    rls.rows.every(
      (row) => row.relrowsecurity && row.relforcerowsecurity,
    ),
  );
  const grants = await adminPool.query(
    `SELECT
       has_table_privilege($1,'aios_personal_memory.memory_event','UPDATE')
         AS event_update,
       has_table_privilege($1,'aios_personal_memory.memory_event','DELETE')
         AS event_delete,
       has_table_privilege($1,'aios_personal_memory.personal_memory','DELETE')
         AS memory_delete`,
    [RUNTIME_LOGIN],
  );
  assert.deepEqual(grants.rows[0], {
    event_update: false,
    event_delete: false,
    memory_delete: false,
  });
});

test("Candidate, Human consent confirmation and recall persist through PostgreSQL", async () => {
  const harness = createHarness({ start: 400 });
  const candidate = await harness.service.execute(
    harness.context,
    harness.wrap(propose("basic")),
  );
  assert.equal(candidate.state, "CANDIDATE");
  assert.deepEqual(
    (await harness.service.recall(
      harness.context,
      harness.recall("before-confirm"),
    )).memories,
    [],
  );
  const confirmation = confirm(harness, candidate.memoryId, "basic");
  const active = await harness.service.execute(
    harness.context,
    harness.wrap(confirmation),
  );
  assert.equal(active.state, "CONFIRMED");
  const recalled = await harness.service.recall(
    harness.context,
    harness.recall("after-confirm"),
  );
  assert.equal(recalled.memories.length, 1);
  assert.equal(recalled.memories[0].memoryId, active.memoryId);
  const persistedEvent = await adminPool.query(
    `SELECT human_consent_evidence
       FROM aios_personal_memory.memory_event
      WHERE memory_id=$1 AND event_type='MEMORY_CONFIRMED'`,
    [active.memoryId],
  );
  assert.equal(
    persistedEvent.rows[0].human_consent_evidence.memoryId,
    active.memoryId,
  );
  assert.equal(
    JSON.stringify(persistedEvent.rows[0]).includes(
      confirmation.humanConsentToken,
    ),
    false,
  );
});

test("PostgreSQL pause blocks Checkpoint reads and resume restores them", async () => {
  const harness = createHarness({ start: 1300 });
  const candidate = await harness.service.execute(
    harness.context,
    harness.wrap(propose("pause")),
  );
  const active = await harness.service.execute(
    harness.context,
    harness.wrap(confirm(harness, candidate.memoryId, "pause")),
  );
  const checkpoint = await harness.service.execute(
    harness.context,
    harness.wrap({
      kind: "SAVE_CHECKPOINT",
      checkpointId: null,
      expectedVersion: 0,
      threadRef: "synthetic://c08/thread/c09-pause",
      stateRef: "fixture://c09/checkpoint/postgres-pause",
      stateSha256: HASH,
      memoryIds: [active.memoryId],
      idempotencyKey: "pg-checkpoint-pause",
      correlationId: "pg-checkpoint-pause",
    }),
  );
  await harness.service.execute(
    harness.context,
    harness.wrap({
      kind: "CHANGE_PROFILE_STATE",
      expectedProfileVersion: 1,
      state: "PAUSED",
      idempotencyKey: "pg-pause-profile",
      correlationId: "pg-pause-profile",
    }),
  );
  await assert.rejects(
    harness.service.readCheckpoint(harness.context, {
      sessionToken: `token-${harness.mutable.sessionId}`,
      delegationId: harness.mutable.delegationId,
      checkpointId: checkpoint.checkpointId,
      correlationId: "pg-read-paused-checkpoint",
    }),
    (error) => error?.code === "PROFILE_PAUSED",
  );
  await harness.service.execute(
    harness.context,
    harness.wrap({
      kind: "CHANGE_PROFILE_STATE",
      expectedProfileVersion: 2,
      state: "ACTIVE",
      idempotencyKey: "pg-resume-profile",
      correlationId: "pg-resume-profile",
    }),
  );
  assert.deepEqual(
    (
      await harness.service.readCheckpoint(harness.context, {
        sessionToken: `token-${harness.mutable.sessionId}`,
        delegationId: harness.mutable.delegationId,
        checkpointId: checkpoint.checkpointId,
        correlationId: "pg-read-resumed-checkpoint",
      })
    ).memoryIds,
    [active.memoryId],
  );
});

test("PostgreSQL natural expiry is filtered then materialized once across restart", async () => {
  const harness = createHarness({ start: 1400 });
  const candidate = await harness.service.execute(
    harness.context,
    harness.wrap({
      kind: "PROPOSE_CANDIDATE",
      candidateRef: "fixture://c09/northstar/work-state/catalog",
      idempotencyKey: "pg-propose-expiry",
      correlationId: "pg-propose-expiry",
    }),
  );
  const active = await harness.service.execute(
    harness.context,
    harness.wrap(
      confirm(
        harness,
        candidate.memoryId,
        "expiry",
        "fixture://c09/northstar/work-state/catalog",
      ),
    ),
  );
  const checkpoint = await harness.service.execute(
    harness.context,
    harness.wrap({
      kind: "SAVE_CHECKPOINT",
      checkpointId: null,
      expectedVersion: 0,
      threadRef: "synthetic://c08/thread/c09-expiry",
      stateRef: "fixture://c09/checkpoint/postgres-expiry",
      stateSha256: HASH,
      memoryIds: [active.memoryId],
      idempotencyKey: "pg-checkpoint-expiry",
      correlationId: "pg-checkpoint-expiry",
    }),
  );
  harness.mutable.now = "2026-08-27T00:00:00.000Z";
  assert.deepEqual(
    (
      await harness.service.readCheckpoint(harness.context, {
        sessionToken: `token-${harness.mutable.sessionId}`,
        delegationId: harness.mutable.delegationId,
        checkpointId: checkpoint.checkpointId,
        correlationId: "pg-read-expired-checkpoint",
      })
    ).memoryIds,
    [],
  );
  const materialize = {
    kind: "MATERIALIZE_EXPIRY",
    memoryId: active.memoryId,
    expectedVersion: active.version,
    idempotencyKey: "pg-materialize-expiry",
    correlationId: "pg-materialize-expiry",
  };
  const outcomes = await Promise.all([
    harness.service.execute(
      harness.context,
      harness.wrap(materialize),
    ),
    harness.service.execute(
      harness.context,
      harness.wrap(materialize),
    ),
  ]);
  assert.deepEqual(outcomes[1], outcomes[0]);
  const persisted = await adminPool.query(
    `SELECT memory.state,memory.content,checkpoint.memory_ids,
            count(event.event_id)::integer AS expiry_events
       FROM aios_personal_memory.personal_memory AS memory
       JOIN aios_personal_memory.conversation_checkpoint AS checkpoint
         ON checkpoint.tenant_id=memory.tenant_id
       LEFT JOIN aios_personal_memory.memory_event AS event
         ON event.tenant_id=memory.tenant_id
        AND event.memory_id=memory.memory_id
        AND event.event_type='MEMORY_EXPIRED'
      WHERE memory.memory_id=$1 AND checkpoint.checkpoint_id=$2
      GROUP BY memory.state,memory.content,checkpoint.memory_ids`,
    [active.memoryId, checkpoint.checkpointId],
  );
  assert.deepEqual(persisted.rows[0], {
    state: "EXPIRED",
    content: null,
    memory_ids: [],
    expiry_events: 1,
  });

  await Promise.all([
    runtimePool.end(),
    tenantScopePool.end(),
    principalScopePool.end(),
  ]);
  runtimePool = new Pool(configuration(RUNTIME_LOGIN));
  tenantScopePool = new Pool(configuration(TENANT_SCOPE_LOGIN));
  principalScopePool = new Pool(configuration(PRINCIPAL_SCOPE_LOGIN));
  store = createPostgresPersonalMemoryStore({
    runtimePool,
    tenantScopePool,
    principalScopePool,
  });
  const recovered = createHarness({ start: 1500 });
  recovered.mutable.now = harness.mutable.now;
  assert.deepEqual(
    (
      await recovered.service.readCheckpoint(recovered.context, {
        sessionToken: `token-${recovered.mutable.sessionId}`,
        delegationId: recovered.mutable.delegationId,
        checkpointId: checkpoint.checkpointId,
        correlationId: "pg-read-expired-after-restart",
      })
    ).memoryIds,
    [],
  );
});

test("signed Principal RLS blocks another Human in the same Tenant", async () => {
  const owner = createHarness({ start: 500 });
  const candidate = await owner.service.execute(
    owner.context,
    owner.wrap(propose("owner")),
  );
  await owner.service.execute(
    owner.context,
    owner.wrap(confirm(owner, candidate.memoryId, "owner")),
  );
  const other = createHarness({
    humanPrincipalId: HUMAN_B,
    delegationId: DELEGATION_B,
    start: 600,
  });
  assert.deepEqual(
    (await other.service.recall(
      other.context,
      other.recall("other-human"),
    )).memories,
    [],
  );
});

test("same idempotency replay is stable and conflicting replay fails", async () => {
  const harness = createHarness({ start: 700 });
  const command = propose("replay");
  const first = await harness.service.execute(
    harness.context,
    harness.wrap(command),
  );
  const replay = await harness.service.execute(
    harness.context,
    harness.wrap(command),
  );
  assert.deepEqual(replay, first);
  await assert.rejects(
    harness.service.execute(
      harness.context,
      harness.wrap({
        ...command,
        candidateRef: "fixture://c09/northstar/work-state/catalog",
      }),
    ),
    (error) => error?.code === "IDEMPOTENCY_CONFLICT",
  );
  const count = await adminPool.query(
    `SELECT count(*)::integer AS count
       FROM aios_personal_memory.memory_event
      WHERE memory_id=$1`,
    [first.memoryId],
  );
  assert.equal(count.rows[0].count, 1);
});

test("concurrent confirmation has one winner", async () => {
  const firstHarness = createHarness({ start: 800 });
  const candidate = await firstHarness.service.execute(
    firstHarness.context,
    firstHarness.wrap(propose("concurrency")),
  );
  const secondHarness = createHarness({ start: 900 });
  const outcomes = await Promise.allSettled([
    firstHarness.service.execute(
      firstHarness.context,
      firstHarness.wrap(
        confirm(firstHarness, candidate.memoryId, "concurrency-a"),
      ),
    ),
    secondHarness.service.execute(
      secondHarness.context,
      secondHarness.wrap(
        confirm(secondHarness, candidate.memoryId, "concurrency-b"),
      ),
    ),
  ]);
  assert.equal(
    outcomes.filter((outcome) => outcome.status === "fulfilled").length,
    1,
  );
});

test("deletion scrubs value and Checkpoint references before recovery", async () => {
  const harness = createHarness({ start: 1000 });
  const candidate = await harness.service.execute(
    harness.context,
    harness.wrap(propose("delete")),
  );
  const active = await harness.service.execute(
    harness.context,
    harness.wrap(confirm(harness, candidate.memoryId, "delete")),
  );
  const checkpoint = await harness.service.execute(
    harness.context,
    harness.wrap({
      kind: "SAVE_CHECKPOINT",
      checkpointId: null,
      expectedVersion: 0,
      threadRef: "synthetic://c08/thread/c09-postgres",
      stateRef: "fixture://c09/checkpoint/postgres",
      stateSha256: HASH,
      memoryIds: [active.memoryId],
      idempotencyKey: "pg-checkpoint-delete",
      correlationId: "pg-checkpoint-delete",
    }),
  );
  await harness.service.execute(
    harness.context,
    harness.wrap({
      kind: "DELETE_MEMORY",
      memoryId: active.memoryId,
      expectedVersion: active.version,
      idempotencyKey: "pg-delete-memory",
      correlationId: "pg-delete-memory",
    }),
  );
  const persisted = await adminPool.query(
    `SELECT memory.state,memory.content,checkpoint.memory_ids
       FROM aios_personal_memory.personal_memory AS memory
       JOIN aios_personal_memory.conversation_checkpoint AS checkpoint
         ON checkpoint.tenant_id=memory.tenant_id
      WHERE memory.memory_id=$1 AND checkpoint.checkpoint_id=$2`,
    [active.memoryId, checkpoint.checkpointId],
  );
  assert.deepEqual(persisted.rows[0], {
    state: "DELETED",
    content: null,
    memory_ids: [],
  });

  await Promise.all([
    runtimePool.end(),
    tenantScopePool.end(),
    principalScopePool.end(),
  ]);
  runtimePool = new Pool(configuration(RUNTIME_LOGIN));
  tenantScopePool = new Pool(configuration(TENANT_SCOPE_LOGIN));
  principalScopePool = new Pool(configuration(PRINCIPAL_SCOPE_LOGIN));
  store = createPostgresPersonalMemoryStore({
    runtimePool,
    tenantScopePool,
    principalScopePool,
  });
  const recovered = createHarness({ start: 1100 });
  assert.deepEqual(
    (await recovered.service.recall(
      recovered.context,
      recovered.recall("after-restart"),
    )).memories.filter((memory) => memory.memoryId === active.memoryId),
    [],
  );
});

test("a stale active identity cannot read after Principal suspension", async () => {
  const harness = createHarness({
    humanPrincipalId: HUMAN_B,
    delegationId: DELEGATION_B,
    start: 1200,
  });
  const candidate = await harness.service.execute(
    harness.context,
    harness.wrap(propose("principal-revocation")),
  );
  await harness.service.execute(
    harness.context,
    harness.wrap(
      confirm(harness, candidate.memoryId, "principal-revocation"),
    ),
  );
  await adminPool.query(
    `UPDATE aios_core.principal_registry
        SET state='SUSPENDED',lifecycle_version=2,security_epoch=2,
            updated_at='2026-07-26T11:00:00.000Z'
      WHERE principal_id=$1`,
    [HUMAN_B],
  );
  await assert.rejects(
    harness.service.recall(
      harness.context,
      harness.recall("principal-revoked"),
    ),
    (error) => error?.code === "INTEGRITY_VIOLATION",
  );
});

test("database rejects forbidden categories and append-only event mutation", async () => {
  await assert.rejects(
    adminPool.query(
      `INSERT INTO aios_personal_memory.personal_memory (
         tenant_id,tenant_kind,memory_id,principal_id,state,category,
         content,content_sha256,source_ref,expires_at,version,
         terminal_reason,created_at,updated_at
       ) VALUES (
         $1,'SYNTHETIC',
         'mem_018f0000-0000-7000-8000-000000009999',
         $2,'CANDIDATE','KPI','Synthetic forbidden KPI',$3,
         'fixture://c09/forbidden/kpi','2027-07-26T00:00:00.000Z',
         1,NULL,$4,$4
       )`,
      [TENANT_A, HUMAN_A, HASH, NOW],
    ),
    (error) => error?.code === "23514",
  );
  const event = await adminPool.query(
    `SELECT event_id FROM aios_personal_memory.memory_event LIMIT 1`,
  );
  await assert.rejects(
    adminPool.query(
      `UPDATE aios_personal_memory.memory_event
          SET correlation_id='tampered'
        WHERE event_id=$1`,
      [event.rows[0].event_id],
    ),
    (error) => error?.code === "23514",
  );
});
