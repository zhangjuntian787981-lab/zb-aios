import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test, { after, before } from "node:test";
import pg from "pg";
import {
  createPersonalMemoryRetentionWorker,
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
const HUMAN_D = "prn_018f0000-0000-7000-8000-000000000005";
const HUMAN_E = "prn_018f0000-0000-7000-8000-000000000006";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_A = "dlg_018f0000-0000-7000-8000-000000000020";
const DELEGATION_B = "dlg_018f0000-0000-7000-8000-000000000021";
const RUNTIME_LOGIN = "c09_test_runtime_login";
const TENANT_SCOPE_LOGIN = "c09_test_tenant_scope_login";
const PRINCIPAL_SCOPE_LOGIN = "c09_test_principal_scope_login";
const RETENTION_LOGIN = "c09_test_retention_login";
const RETENTION_SUSPENDED_MEMORY =
  "mem_018f0000-0000-7000-8000-000000008001";
const RETENTION_DEACTIVATED_MEMORY =
  "mem_018f0000-0000-7000-8000-000000008002";
const RETENTION_FUTURE_MEMORY =
  "mem_018f0000-0000-7000-8000-000000008003";
const RETENTION_RESTORE_MEMORY =
  "mem_018f0000-0000-7000-8000-000000008004";
const RECEIPT_REPLAY_CONSENT_UUID =
  "018f0000-0000-7000-8000-000000009901";
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
const SCOPE_GUCS = [
  "tenant_id",
  "tenant_kind",
  "lifecycle_version",
  "correlation_id",
  "decision_id",
  "evidence_ref",
  "policy_version",
  "backend_pid",
  "transaction_id",
  "expires_epoch_ms",
  "scope_nonce",
  "scope_signature",
  "principal_id",
  "principal_lifecycle_version",
  "principal_security_epoch",
  "principal_expires_epoch_ms",
  "principal_scope_nonce",
  "principal_scope_signature",
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
let retentionPool;
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
     CREATE ROLE ${RETENTION_LOGIN}
       LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION
       NOBYPASSRLS;
     GRANT aios_c09_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c07_scope_runtime TO ${TENANT_SCOPE_LOGIN};
     GRANT aios_c09_scope_runtime TO ${PRINCIPAL_SCOPE_LOGIN};
     GRANT aios_c09_retention_runtime TO ${RETENTION_LOGIN};`,
  );
  await seedTenant(adminPool, TENANT_A, "10");
  await seedTenant(adminPool, TENANT_B, "20");
  await seedPrincipal(adminPool, TENANT_A, HUMAN_A, "HUMAN", "a");
  await seedPrincipal(adminPool, TENANT_A, HUMAN_B, "HUMAN", "b");
  await seedPrincipal(adminPool, TENANT_A, HUMAN_D, "HUMAN", "d");
  await seedPrincipal(adminPool, TENANT_A, HUMAN_E, "HUMAN", "e");
  await seedPrincipal(adminPool, TENANT_A, ACTOR, "SERVICE", "actor");
  await seedPrincipal(adminPool, TENANT_B, HUMAN_C, "HUMAN", "c");
  runtimePool = new Pool(configuration(RUNTIME_LOGIN));
  tenantScopePool = new Pool(configuration(TENANT_SCOPE_LOGIN));
  principalScopePool = new Pool(configuration(PRINCIPAL_SCOPE_LOGIN));
  retentionPool = new Pool(configuration(RETENTION_LOGIN));
  store = createPostgresPersonalMemoryStore({
    runtimePool,
    tenantScopePool,
    principalScopePool,
    retentionPool,
  });
});

after(async () => {
  await Promise.allSettled([
    runtimePool?.end(),
    tenantScopePool?.end(),
    principalScopePool?.end(),
    retentionPool?.end(),
    adminPool?.end(),
  ]);
});

function createHarness({
  tenantId = TENANT_A,
  humanPrincipalId = HUMAN_A,
  delegationId = DELEGATION_A,
  start = 300,
  consentTokenFactory,
} = {}) {
  const { issuer: consentIssuer, consentStore } =
    createSyntheticHumanConsentAuthority(
      consentTokenFactory ? { tokenFactory: consentTokenFactory } : {},
    );
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

function retentionWorker(start = 5000) {
  return createPersonalMemoryRetentionWorker({
    store,
    clock: () => "2026-07-26T10:00:00.000Z",
    idFactory: deterministicIds(start),
    workloadIdentityProvider: {
      async resolve({ tenantId }) {
        return {
          trustSource: "C05_VERIFIED_WORKLOAD_IDENTITY",
          tenantId,
          tenantKind: "SYNTHETIC",
          principalId: ACTOR,
          principalKind: "SERVICE",
          lifecycleVersion: 1,
          securityEpoch: 1,
        };
      },
    },
    authorizer: {
      async enforce({ tenantId, operation, identity, resource }) {
        return {
          allowed: true,
          tenantId,
          operation,
          actorPrincipalId: identity.principalId,
          resourceId: resource.resourceId,
          expectedVersion: resource.expectedVersion,
          decisionId: "decision-c09-retention-worker",
          evidenceRef: "policy://c09/retention-worker",
          policyVersion: "c09-retention-worker-v1",
        };
      },
    },
    tenantRegistry: {
      async admitNewRequest({ tenantId }) {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    async tenantScopeFactory({ tenant, authorization, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: tenant.tenantKind,
        lifecycleVersion: tenant.lifecycleVersion,
        correlationId,
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.policyVersion,
      };
    },
  });
}

test("PostgreSQL roles are non-privileged and RLS is forced", async () => {
  const roles = await adminPool.query(
    `SELECT rolname,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole
      FROM pg_roles
      WHERE rolname IN (
        'aios_c09_runtime','aios_c09_scope_runtime',
        'aios_c09_retention_runtime',$1,$2,$3,$4
      )
      ORDER BY rolname`,
    [
      RUNTIME_LOGIN,
      TENANT_SCOPE_LOGIN,
      PRINCIPAL_SCOPE_LOGIN,
      RETENTION_LOGIN,
    ],
  );
  assert.equal(roles.rowCount, 7);
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
  const retentionGrants = await adminPool.query(
    `SELECT
       has_table_privilege(
         $1,'aios_personal_memory.personal_memory','SELECT'
       ) AS memory_select,
       has_table_privilege(
         $1,'aios_personal_memory.personal_memory','UPDATE'
       ) AS memory_update,
       has_table_privilege(
         $1,'aios_personal_memory.memory_event','INSERT'
       ) AS event_insert,
       has_function_privilege(
         $1,
         'aios_personal_memory.materialize_due_expiry(text,text,bigint,text,text,text,text,text,bigint,bigint,jsonb)',
         'EXECUTE'
       ) AS materialize_execute`,
    [RETENTION_LOGIN],
  );
  assert.deepEqual(retentionGrants.rows[0], {
    memory_select: false,
    memory_update: false,
    event_insert: false,
    materialize_execute: true,
  });
});

test("PostgreSQL pools reject mixed, indirect and over-privileged roles before data access", async (t) => {
  const unsafeCases = [
    {
      name: "runtime role with admin option",
      login: "c09_unsafe_admin_option_login",
      setup: `
        CREATE ROLE c09_unsafe_admin_option_login
          LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        GRANT aios_c09_runtime
          TO c09_unsafe_admin_option_login WITH ADMIN OPTION;`,
      cleanup: `
        REVOKE aios_c09_runtime
          FROM c09_unsafe_admin_option_login;
        DROP ROLE c09_unsafe_admin_option_login;`,
    },
    {
      name: "runtime plus C09 owner",
      login: "c09_unsafe_owner_login",
      setup: `
        CREATE ROLE c09_unsafe_owner_login
          LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        GRANT aios_c09_runtime,aios_c09_owner
          TO c09_unsafe_owner_login;`,
      cleanup: "DROP ROLE c09_unsafe_owner_login;",
    },
    {
      name: "runtime plus adjacent C05 writer",
      login: "c09_unsafe_adjacent_login",
      setup: `
        CREATE ROLE c09_unsafe_adjacent_login
          LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        GRANT aios_c09_runtime,aios_c05_core_runtime
          TO c09_unsafe_adjacent_login;`,
      cleanup: "DROP ROLE c09_unsafe_adjacent_login;",
    },
    {
      name: "indirect runtime plus owner chain",
      login: "c09_unsafe_indirect_login",
      setup: `
        CREATE ROLE c09_unsafe_indirect_bridge
          NOLOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        CREATE ROLE c09_unsafe_indirect_login
          LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        GRANT aios_c09_runtime,aios_c09_owner
          TO c09_unsafe_indirect_bridge;
        GRANT c09_unsafe_indirect_bridge
          TO c09_unsafe_indirect_login;`,
      cleanup: `
        DROP ROLE c09_unsafe_indirect_login;
        DROP ROLE c09_unsafe_indirect_bridge;`,
    },
    {
      name: "runtime with direct signing-secret access",
      login: "c09_unsafe_direct_grant_login",
      setup: `
        CREATE ROLE c09_unsafe_direct_grant_login
          LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        GRANT aios_c09_runtime TO c09_unsafe_direct_grant_login;
        GRANT SELECT ON
          aios_personal_memory.personal_scope_signing_secret
          TO c09_unsafe_direct_grant_login;`,
      cleanup: `
        REVOKE SELECT ON
          aios_personal_memory.personal_scope_signing_secret
          FROM c09_unsafe_direct_grant_login;
        DROP ROLE c09_unsafe_direct_grant_login;`,
    },
    {
      name: "runtime with direct extra function execution",
      login: "c09_unsafe_function_grant_login",
      setup: `
        CREATE ROLE c09_unsafe_function_grant_login
          LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        GRANT aios_c09_runtime TO c09_unsafe_function_grant_login;
        GRANT EXECUTE ON FUNCTION
          aios_personal_memory.issue_principal_scope_signature(
            text,text,text,bigint,bigint,integer,xid8,integer,uuid
          )
          TO c09_unsafe_function_grant_login;`,
      cleanup: `
        REVOKE EXECUTE ON FUNCTION
          aios_personal_memory.issue_principal_scope_signature(
            text,text,text,bigint,bigint,integer,xid8,integer,uuid
          )
          FROM c09_unsafe_function_grant_login;
        DROP ROLE c09_unsafe_function_grant_login;`,
    },
    {
      name: "runtime with adjacent direct object privileges",
      login: "c09_unsafe_adjacent_direct_login",
      setup: `
        CREATE SCHEMA aios_c09_adjacent_test;
        CREATE TABLE aios_c09_adjacent_test.private_record (id integer);
        CREATE FUNCTION aios_c09_adjacent_test.private_function()
        RETURNS integer LANGUAGE sql AS 'SELECT 1';
        REVOKE ALL ON SCHEMA aios_c09_adjacent_test FROM PUBLIC;
        REVOKE ALL ON ALL TABLES
          IN SCHEMA aios_c09_adjacent_test FROM PUBLIC;
        REVOKE ALL ON ALL FUNCTIONS
          IN SCHEMA aios_c09_adjacent_test FROM PUBLIC;
        CREATE ROLE c09_unsafe_adjacent_direct_login
          LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        GRANT aios_c09_runtime
          TO c09_unsafe_adjacent_direct_login;
        GRANT USAGE ON SCHEMA aios_c09_adjacent_test
          TO c09_unsafe_adjacent_direct_login;
        GRANT SELECT ON aios_c09_adjacent_test.private_record
          TO c09_unsafe_adjacent_direct_login;
        GRANT EXECUTE ON FUNCTION
          aios_c09_adjacent_test.private_function()
          TO c09_unsafe_adjacent_direct_login;`,
      cleanup: `
        DROP OWNED BY c09_unsafe_adjacent_direct_login;
        DROP ROLE c09_unsafe_adjacent_direct_login;
        DROP SCHEMA aios_c09_adjacent_test CASCADE;`,
    },
    {
      name: "runtime plus built-in read-all role",
      login: "c09_unsafe_builtin_login",
      setup: `
        CREATE ROLE c09_unsafe_builtin_login
          LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOREPLICATION NOBYPASSRLS;
        GRANT aios_c09_runtime,pg_read_all_data
          TO c09_unsafe_builtin_login;`,
      cleanup: `
        REVOKE pg_read_all_data FROM c09_unsafe_builtin_login;
        DROP ROLE c09_unsafe_builtin_login;`,
    },
  ];
  const ownerScope = {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
    principalId: HUMAN_A,
    lifecycleVersion: 2,
    correlationId: "unsafe-role",
    decisionId: "decision-unsafe-role",
    evidenceRef: "evidence://c09/unsafe-role",
    policyVersion: "c09-postgresql-policy-v1",
    principalLifecycleVersion: 1,
    principalSecurityEpoch: 1,
  };
  for (const unsafe of unsafeCases) {
    await t.test(unsafe.name, async () => {
      await adminPool.query(unsafe.setup);
      const unsafeRuntimePool = new Pool(configuration(unsafe.login, 1));
      const unsafeStore = createPostgresPersonalMemoryStore({
        runtimePool: unsafeRuntimePool,
        tenantScopePool,
        principalScopePool,
      });
      try {
        await assert.rejects(
          unsafeStore.readProfile(ownerScope, {
            tenantId: TENANT_A,
            principalId: HUMAN_A,
          }),
          (error) => error?.code === "INVALID_CONFIGURATION",
        );
      } finally {
        await unsafeRuntimePool.end();
        await adminPool.query(unsafe.cleanup);
      }
    });
  }
});

test("runtime Pool discards every one of the 18 leaked identity GUCs", async () => {
  for (const guc of SCOPE_GUCS) {
    const isolatedRuntimePool = new Pool(configuration(RUNTIME_LOGIN, 1));
    try {
      const dirty = await isolatedRuntimePool.connect();
      await dirty.query(`SELECT set_config($1,'polluted',false)`, [
        `aios.${guc}`,
      ]);
      dirty.release();
      const isolatedStore = createPostgresPersonalMemoryStore({
        runtimePool: isolatedRuntimePool,
        tenantScopePool,
        principalScopePool,
      });
      await assert.rejects(
        isolatedStore.readProfile(
          {
            trustSource: "C07_VERIFIED_TENANT_SCOPE",
            tenantId: TENANT_A,
            tenantKind: "SYNTHETIC",
            principalId: HUMAN_A,
            lifecycleVersion: 2,
            correlationId: `guc-${guc}`,
            decisionId: `decision-guc-${guc}`,
            evidenceRef: "evidence://c09/guc-cleanup",
            policyVersion: "c09-postgresql-policy-v1",
            principalLifecycleVersion: 1,
            principalSecurityEpoch: 1,
          },
          { tenantId: TENANT_A, principalId: HUMAN_A },
        ),
        (error) => error?.code === "CONNECTION_CONTEXT_LEAK",
      );
    } finally {
      await isolatedRuntimePool.end();
    }
  }
});

test("runtime Pool clears all 18 identity GUCs after COMMIT and ROLLBACK", async () => {
  const isolatedRuntimePool = new Pool(configuration(RUNTIME_LOGIN, 1));
  const isolatedStore = createPostgresPersonalMemoryStore({
    runtimePool: isolatedRuntimePool,
    tenantScopePool,
    principalScopePool,
  });
  const ownerScope = {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT_A,
    tenantKind: "SYNTHETIC",
    principalId: HUMAN_A,
    lifecycleVersion: 2,
    correlationId: "guc-transaction-cleanup",
    decisionId: "decision-guc-transaction-cleanup",
    evidenceRef: "evidence://c09/guc-transaction-cleanup",
    policyVersion: "c09-postgresql-policy-v1",
    principalLifecycleVersion: 1,
    principalSecurityEpoch: 1,
  };
  const projection = SCOPE_GUCS.map(
    (guc) => `current_setting('aios.${guc}',true) AS "${guc}"`,
  ).join(",");
  async function connectionState() {
    const client = await isolatedRuntimePool.connect();
    try {
      const result = await client.query(
        `SELECT pg_backend_pid() AS session_pid,${projection}`,
      );
      return result.rows[0];
    } finally {
      client.release();
    }
  }
  try {
    const before = await connectionState();
    await isolatedStore.readProfile(ownerScope, {
      tenantId: TENANT_A,
      principalId: HUMAN_A,
    });
    const afterCommit = await connectionState();
    assert.equal(afterCommit.session_pid, before.session_pid);
    assert.equal(
      SCOPE_GUCS.every(
        (guc) => [null, ""].includes(afterCommit[guc]),
      ),
      true,
    );

    await assert.rejects(
      isolatedStore.apply(ownerScope, {
        operation: "DELETE_MEMORY",
        tenantId: TENANT_A,
        tenantKind: "SYNTHETIC",
        principalId: HUMAN_A,
        actorPrincipalId: ACTOR,
        memoryId: "mem_018f0000-0000-7000-8000-000000009999",
        expectedVersion: 1,
        eventId: "mev_018f0000-0000-7000-8000-000000009999",
        idempotencyKey: "guc-rollback-cleanup",
        correlationId: "guc-transaction-cleanup",
        requestHash: HASH,
        authorizationEvidence: {},
        humanConsentEvidence: null,
        now: NOW,
      }),
      (error) => error?.code === "MEMORY_NOT_FOUND",
    );
    const afterRollback = await connectionState();
    assert.equal(afterRollback.session_pid, before.session_pid);
    assert.equal(
      SCOPE_GUCS.every(
        (guc) => [null, ""].includes(afterRollback[guc]),
      ),
      true,
    );
  } finally {
    await isolatedRuntimePool.end();
  }
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

test("committed PostgreSQL confirmation replays after consent restart", async () => {
  const first = createHarness({
    start: 1600,
    consentTokenFactory: () => RECEIPT_REPLAY_CONSENT_UUID,
  });
  const candidate = await first.service.execute(
    first.context,
    first.wrap(propose("receipt-restart")),
  );
  const command = confirm(first, candidate.memoryId, "receipt-restart");
  const confirmed = await first.service.execute(
    first.context,
    first.wrap(command),
  );

  const restarted = createHarness({ start: 1700 });
  assert.deepEqual(
    await restarted.service.execute(
      restarted.context,
      restarted.wrap(command),
    ),
    confirmed,
  );
});

test("PostgreSQL keeps one unmaterialized expiry fixture for restore verification", async () => {
  const harness = createHarness({ start: 1900 });
  const candidate = await harness.service.execute(
    harness.context,
    harness.wrap({
      kind: "PROPOSE_CANDIDATE",
      candidateRef: "fixture://c09/northstar/work-state/catalog",
      idempotencyKey: "pg-propose-restore-expiry",
      correlationId: "pg-propose-restore-expiry",
    }),
  );
  const confirmed = await harness.service.execute(
    harness.context,
    harness.wrap(
      confirm(
        harness,
        candidate.memoryId,
        "restore-expiry",
        "fixture://c09/northstar/work-state/catalog",
      ),
    ),
  );
  assert.equal(confirmed.state, "CONFIRMED");
});

test("retention worker expires due rows for suspended and deactivated Humans only", async () => {
  await adminPool.query(
    `INSERT INTO aios_personal_memory.personal_profile (
       tenant_id,tenant_kind,principal_id,principal_kind,state,version,
       created_at,updated_at
     ) VALUES
       ($1,'SYNTHETIC',$2,'HUMAN','ACTIVE',1,$4,$4),
       ($1,'SYNTHETIC',$3,'HUMAN','ACTIVE',1,$4,$4)`,
    [
      TENANT_A,
      HUMAN_D,
      HUMAN_E,
      "2025-01-01T00:00:00.000Z",
    ],
  );
  await adminPool.query(
    `INSERT INTO aios_personal_memory.personal_memory (
       tenant_id,tenant_kind,memory_id,principal_id,state,category,
       content,content_sha256,source_ref,expires_at,version,
       terminal_reason,created_at,updated_at
     ) VALUES
       ($1,'SYNTHETIC',$4,$2,'CANDIDATE','WORK_STATE',
        'due suspended content',$6,'fixture://c09/retention/suspended',
        $8,1,NULL,$7,$7),
       ($1,'SYNTHETIC',$5,$3,'CONFIRMED','WORK_STATE',
        'due deactivated content',$6,'fixture://c09/retention/deactivated',
        $8,1,NULL,$7,$7),
       ($1,'SYNTHETIC',$9,$2,'CONFIRMED','WORK_STATE',
        'future retained content',$6,'fixture://c09/retention/future',
        $10,1,NULL,$7,$7),
       ($1,'SYNTHETIC',$11,$2,'CANDIDATE','WORK_STATE',
        'due restore content',$6,'fixture://c09/retention/restore',
        $8,1,NULL,$7,$7)`,
    [
      TENANT_A,
      HUMAN_D,
      HUMAN_E,
      RETENTION_SUSPENDED_MEMORY,
      RETENTION_DEACTIVATED_MEMORY,
      HASH,
      "2025-01-01T00:00:00.000Z",
      "2025-01-02T00:00:00.000Z",
      RETENTION_FUTURE_MEMORY,
      "2027-01-02T00:00:00.000Z",
      RETENTION_RESTORE_MEMORY,
    ],
  );
  await adminPool.query(
    `INSERT INTO aios_personal_memory.conversation_checkpoint (
       tenant_id,tenant_kind,checkpoint_id,principal_id,thread_ref,
       state_ref,state_sha256,memory_ids,version,created_at,updated_at
     ) VALUES
       ($1,'SYNTHETIC',
        'ckp_018f0000-0000-7000-8000-000000008011',$2,
        'synthetic://c08/thread/retention-suspended',
        'fixture://c09/checkpoint/retention-suspended',$6,
        ARRAY[$4,$7],1,$8,$8),
       ($1,'SYNTHETIC',
        'ckp_018f0000-0000-7000-8000-000000008012',$3,
        'synthetic://c08/thread/retention-deactivated',
        'fixture://c09/checkpoint/retention-deactivated',$6,
        ARRAY[$5],1,$8,$8)`,
    [
      TENANT_A,
      HUMAN_D,
      HUMAN_E,
      RETENTION_SUSPENDED_MEMORY,
      RETENTION_DEACTIVATED_MEMORY,
      HASH,
      RETENTION_RESTORE_MEMORY,
      "2025-01-01T00:00:00.000Z",
    ],
  );
  await adminPool.query(
    `UPDATE aios_core.principal_registry
        SET state=CASE
              WHEN principal_id=$1 THEN 'SUSPENDED'
              ELSE 'DEACTIVATED'
            END,
            lifecycle_version=2,security_epoch=2,
            updated_at='2026-07-26T11:00:00.000Z'
      WHERE principal_id=ANY($2::text[])`,
    [HUMAN_D, [HUMAN_D, HUMAN_E]],
  );

  const worker = retentionWorker();
  const commands = [
    {
      tenantId: TENANT_A,
      memoryId: RETENTION_SUSPENDED_MEMORY,
      expectedVersion: 1,
      idempotencyKey: "retention-suspended-expiry",
      correlationId: "retention-suspended-expiry",
    },
    {
      tenantId: TENANT_A,
      memoryId: RETENTION_DEACTIVATED_MEMORY,
      expectedVersion: 1,
      idempotencyKey: "retention-deactivated-expiry",
      correlationId: "retention-deactivated-expiry",
    },
  ];
  const outcomes = await Promise.all(
    commands.map((command) => worker.materializeExpiry(command)),
  );
  assert.deepEqual(
    outcomes.map((result) => Object.keys(result).sort()),
    [
      ["memoryId", "state", "version"],
      ["memoryId", "state", "version"],
    ],
  );
  assert.ok(outcomes.every(({ state }) => state === "EXPIRED"));
  assert.equal(JSON.stringify(outcomes).includes("content"), false);
  assert.deepEqual(
    await worker.materializeExpiry(commands[0]),
    outcomes[0],
  );

  await assert.rejects(
    worker.materializeExpiry({
      tenantId: TENANT_A,
      memoryId: RETENTION_FUTURE_MEMORY,
      expectedVersion: 1,
      idempotencyKey: "retention-future-expiry",
      correlationId: "retention-future-expiry",
    }),
    (error) => error?.code === "INVALID_STATE",
  );
  await assert.rejects(
    retentionPool.query(
      `SELECT aios_personal_memory.materialize_due_expiry(
         $1,$2,1,'direct-retention-call','direct-retention-call',
         'mev_018f0000-0000-7000-8000-000000008099',$3,$4,1,1,
         '{}'::jsonb
       )`,
      [TENANT_A, RETENTION_FUTURE_MEMORY, HASH, ACTOR],
    ),
    (error) => error?.code === "42501",
  );
  await assert.rejects(
    retentionPool.query(
      `SELECT content
         FROM aios_personal_memory.personal_memory
        WHERE tenant_id=$1`,
      [TENANT_A],
    ),
    (error) => error?.code === "42501",
  );

  const persisted = await adminPool.query(
    `SELECT memory_id,state,content
       FROM aios_personal_memory.personal_memory
      WHERE memory_id=ANY($1::text[])
      ORDER BY memory_id`,
    [[
      RETENTION_SUSPENDED_MEMORY,
      RETENTION_DEACTIVATED_MEMORY,
      RETENTION_FUTURE_MEMORY,
    ]],
  );
  assert.deepEqual(
    persisted.rows,
    [
      {
        memory_id: RETENTION_SUSPENDED_MEMORY,
        state: "EXPIRED",
        content: null,
      },
      {
        memory_id: RETENTION_DEACTIVATED_MEMORY,
        state: "EXPIRED",
        content: null,
      },
      {
        memory_id: RETENTION_FUTURE_MEMORY,
        state: "CONFIRMED",
        content: "future retained content",
      },
    ],
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
    retentionPool.end(),
  ]);
  runtimePool = new Pool(configuration(RUNTIME_LOGIN));
  tenantScopePool = new Pool(configuration(TENANT_SCOPE_LOGIN));
  principalScopePool = new Pool(configuration(PRINCIPAL_SCOPE_LOGIN));
  retentionPool = new Pool(configuration(RETENTION_LOGIN));
  store = createPostgresPersonalMemoryStore({
    runtimePool,
    tenantScopePool,
    principalScopePool,
    retentionPool,
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

test("PostgreSQL Store rejects Principal substitution inside an authorized Tenant scope", async () => {
  await assert.rejects(
    store.readProfile(
      {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: TENANT_A,
        tenantKind: "SYNTHETIC",
        principalId: HUMAN_A,
        lifecycleVersion: 2,
        correlationId: "pg-principal-substitution",
        decisionId: "decision-pg-principal-substitution",
        evidenceRef: "evidence://c09/principal-substitution",
        policyVersion: "c09-postgresql-policy-v1",
        principalLifecycleVersion: 1,
        principalSecurityEpoch: 1,
      },
      { tenantId: TENANT_A, principalId: HUMAN_B },
    ),
    (error) => error?.code === "IDENTITY_BINDING_INVALID",
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

test("confirmation event failure rolls back the command update and receipt", async () => {
  const harness = createHarness({ start: 1800 });
  const candidate = await harness.service.execute(
    harness.context,
    harness.wrap(propose("forced-rollback")),
  );
  const command = confirm(harness, candidate.memoryId, "forced-rollback");
  await adminPool.query(
    `CREATE FUNCTION aios_personal_memory.fail_test_confirmation_event()
     RETURNS trigger
     LANGUAGE plpgsql
     AS $$
     BEGIN
       IF
         NEW.event_type='MEMORY_CONFIRMED'
         AND NEW.correlation_id='pg-confirm-forced-rollback'
       THEN
         RAISE EXCEPTION 'forced C09 confirmation event failure'
           USING ERRCODE='23514';
       END IF;
       RETURN NEW;
     END
     $$;
     REVOKE ALL ON FUNCTION
       aios_personal_memory.fail_test_confirmation_event()
       FROM PUBLIC;
     CREATE TRIGGER fail_test_confirmation_event
     BEFORE INSERT ON aios_personal_memory.memory_event
     FOR EACH ROW
     EXECUTE FUNCTION aios_personal_memory.fail_test_confirmation_event();`,
  );
  try {
    await assert.rejects(
      harness.service.execute(
        harness.context,
        harness.wrap(command),
      ),
      (error) => error?.code === "INTEGRITY_VIOLATION",
    );
  } finally {
    await adminPool.query(
      `DROP TRIGGER IF EXISTS fail_test_confirmation_event
         ON aios_personal_memory.memory_event;
       DROP FUNCTION IF EXISTS
         aios_personal_memory.fail_test_confirmation_event();`,
    );
  }

  const rolledBack = await adminPool.query(
    `SELECT memory.state,memory.version,
            count(event.event_id) FILTER (
              WHERE event.event_type='MEMORY_CONFIRMED'
            )::integer AS confirmation_events,
            (
              SELECT count(*)::integer
                FROM aios_personal_memory.command_receipt AS receipt
               WHERE receipt.tenant_id=memory.tenant_id
                 AND receipt.principal_id=memory.principal_id
                 AND receipt.idempotency_key='pg-confirm-forced-rollback'
            ) AS confirmation_receipts
       FROM aios_personal_memory.personal_memory AS memory
       LEFT JOIN aios_personal_memory.memory_event AS event
         ON event.tenant_id=memory.tenant_id
        AND event.memory_id=memory.memory_id
      WHERE memory.memory_id=$1
      GROUP BY memory.tenant_id,memory.principal_id,
               memory.state,memory.version`,
    [candidate.memoryId],
  );
  assert.deepEqual(rolledBack.rows[0], {
    state: "CANDIDATE",
    version: "1",
    confirmation_events: 0,
    confirmation_receipts: 0,
  });
  assert.equal(
    (
      await harness.service.execute(
        harness.context,
        harness.wrap(command),
      )
    ).state,
    "CONFIRMED",
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
    retentionPool.end(),
  ]);
  runtimePool = new Pool(configuration(RUNTIME_LOGIN));
  tenantScopePool = new Pool(configuration(TENANT_SCOPE_LOGIN));
  principalScopePool = new Pool(configuration(PRINCIPAL_SCOPE_LOGIN));
  retentionPool = new Pool(configuration(RETENTION_LOGIN));
  store = createPostgresPersonalMemoryStore({
    runtimePool,
    tenantScopePool,
    principalScopePool,
    retentionPool,
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

test("database rejects non-canonical Human consent evidence", async (t) => {
  const mutations = [
    [
      "token",
      `human_consent_evidence ||
        jsonb_build_object('token','must not persist')`,
    ],
    [
      "humanConsentToken",
      `human_consent_evidence ||
        jsonb_build_object('humanConsentToken','hct_must_not_persist')`,
    ],
    [
      "content",
      `human_consent_evidence ||
        jsonb_build_object('content','must not persist')`,
    ],
    [
      "secret",
      `human_consent_evidence ||
        jsonb_build_object('secret','must not persist')`,
    ],
    [
      "expectedVersion type",
      `jsonb_set(
        human_consent_evidence,
        '{expectedVersion}',
        '"1"'::jsonb
      )`,
    ],
  ];
  for (const [index, [name, mutation]] of mutations.entries()) {
    await t.test(name, async () => {
      const suffix = String(index + 1).padStart(12, "0");
      await assert.rejects(
        adminPool.query(
          `INSERT INTO aios_personal_memory.memory_event (
             tenant_id,tenant_kind,event_id,memory_id,principal_id,event_type,
             from_state,to_state,content_sha256,actor_principal_id,
             authorization_evidence,human_consent_evidence,
             correlation_id,created_at
           )
           SELECT tenant_id,tenant_kind,
                  'mev_018f0000-0000-7000-8001-${suffix}',
                  memory_id,principal_id,event_type,from_state,to_state,
                  content_sha256,actor_principal_id,authorization_evidence,
                  ${mutation},
                  'pg-invalid-consent-evidence',created_at
             FROM aios_personal_memory.memory_event
            WHERE human_consent_evidence IS NOT NULL
            ORDER BY created_at,event_id
            LIMIT 1`,
        ),
        (error) => error?.code === "23514",
      );
    });
  }
});
