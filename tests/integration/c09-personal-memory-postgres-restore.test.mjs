import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
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
const HUMAN_OTHER = "prn_018f0000-0000-7000-8000-000000000007";
const HUMAN_C = "prn_018f0000-0000-7000-8000-000000000004";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_A = "dlg_018f0000-0000-7000-8000-000000000020";
const DELEGATION_B = "dlg_018f0000-0000-7000-8000-000000000022";
const DELEGATION_C = "dlg_018f0000-0000-7000-8000-000000000021";
const RUNTIME_LOGIN = "c09_test_runtime_login";
const TENANT_SCOPE_LOGIN = "c09_test_tenant_scope_login";
const PRINCIPAL_SCOPE_LOGIN = "c09_test_principal_scope_login";
const RETENTION_LOGIN = "c09_test_retention_login";
const RETENTION_RESTORE_MEMORY =
  "mem_018f0000-0000-7000-8000-000000008004";
const RECEIPT_REPLAY_CONSENT_TOKEN =
  "hct_018f0000-0000-7000-8000-000000009901";
const C09_TABLES = [
  "personal_scope_signing_secret",
  "personal_profile",
  "personal_memory",
  "conversation_checkpoint",
  "memory_event",
  "command_receipt",
];
const C09_SCOPED_TABLES = new Set(C09_TABLES.slice(1));
const C09_FUNCTIONS = [
  "issue_principal_scope_signature",
  "runtime_principal_allows",
  "reject_append_only_change",
  "reject_row_delete",
  "enforce_profile_update",
  "enforce_memory_update",
  "enforce_checkpoint_update",
  "materialize_due_expiry",
];
const C09_DEPENDENCY_ROLES = [
  "aios_c05_core_runtime",
  "aios_c05_outbox_worker",
  "aios_c07_owner",
  "aios_c07_lifecycle_runtime",
  "aios_c07_data_runtime",
  "aios_c07_scope_runtime",
  "aios_c07_restore_runtime",
  "aios_c09_owner",
  "aios_c09_runtime",
  "aios_c09_scope_runtime",
  "aios_c09_retention_runtime",
];
const APPLICATION_ROLES = [
  "aios_c09_runtime",
  "aios_c07_scope_runtime",
  "aios_c09_scope_runtime",
  "aios_c09_retention_runtime",
];
const TEST_LOGINS = [
  RUNTIME_LOGIN,
  TENANT_SCOPE_LOGIN,
  PRINCIPAL_SCOPE_LOGIN,
  RETENTION_LOGIN,
];
const TABLE_PRIVILEGES = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
  "TRUNCATE",
  "REFERENCES",
  "TRIGGER",
];
const COLUMN_PRIVILEGES = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "REFERENCES",
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
const dataSurfaceCatalog = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c09/personal-memory-data-surface-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const expectedTablePrivileges = {
  aios_c09_runtime: {
    SELECT: C09_TABLES.slice(1),
    INSERT: C09_TABLES.slice(1),
    UPDATE: [
      "personal_profile",
      "personal_memory",
      "conversation_checkpoint",
    ],
  },
  aios_c07_scope_runtime: {},
  aios_c09_scope_runtime: {},
  aios_c09_retention_runtime: {},
};
const expectedSchemaPrivileges = {
  aios_c09_runtime: ["aios_data", "aios_personal_memory"],
  aios_c07_scope_runtime: ["aios_data"],
  aios_c09_scope_runtime: ["aios_personal_memory"],
  aios_c09_retention_runtime: [
    "aios_data",
    "aios_personal_memory",
  ],
};
const expectedFunctionPrivileges = {
  aios_c09_runtime: [
    "aios_data.acquire_runtime_fence()",
    "aios_data.runtime_scope_allows(text,text)",
    "aios_personal_memory.runtime_principal_allows(text,text,text)",
  ],
  aios_c07_scope_runtime: [
    "aios_data.issue_runtime_scope_signature(text,text,bigint,text,text,text,text,integer,xid8,integer,uuid)",
  ],
  aios_c09_scope_runtime: [
    "aios_personal_memory.issue_principal_scope_signature(text,text,text,bigint,bigint,integer,xid8,integer,uuid)",
  ],
  aios_c09_retention_runtime: [
    "aios_data.acquire_runtime_fence()",
    "aios_personal_memory.materialize_due_expiry(text,text,bigint,text,text,text,text,text,bigint,bigint,jsonb)",
  ],
};
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
  if (process.env.C09_TEST_RESTORED !== "1") {
    throw new Error("C09_TEST_RESTORED=1 is required.");
  }
  for (const name of [
    "C09_TEST_PGHOST",
    "C09_TEST_PGPORT",
    "C09_TEST_PGDATABASE",
    "C09_TEST_PGUSER",
    "C09_TEST_SOURCE_SYSTEM_IDENTIFIER",
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

function deterministicIds(start = 3000) {
  let counter = start;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function createHarness({
  store,
  tenantId,
  humanPrincipalId,
  delegationId,
  now,
  humanConsentStore,
  start,
}) {
  const mutable = { now };
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
          sessionId: `restored-session-${humanPrincipalId}`,
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
          delegationChain: [{
            delegationId,
            delegatorPrincipalId: humanPrincipalId,
            delegatePrincipalId: ACTOR,
            lifecycleVersion: 1,
          }],
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
          delegationId,
          operation,
          decisionId: `restored-decision-${operation.toLowerCase()}`,
          evidenceRef: "evidence://c09/restored-postgresql",
          policyVersion: "c09-restored-postgresql-policy-v1",
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
    humanConsentStore,
  });
  return {
    service,
    mutable,
    context: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: ACTOR,
    },
    wrap(command) {
      return {
        sessionToken: `restored-token-${humanPrincipalId}`,
        delegationId,
        command,
      };
    },
    recall(suffix) {
      return {
        sessionToken: `restored-token-${humanPrincipalId}`,
        delegationId,
        correlationId: `restored-recall-${suffix}`,
        limit: 20,
      };
    },
  };
}

async function verifyRestoredStructure(adminPool) {
  const schema = await adminPool.query(
    `SELECT pg_get_userbyid(nspowner) AS owner,
            NOT EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(nspacl,acldefault('n',nspowner))
                ) AS acl
               WHERE acl.grantee=0
            ) AS public_has_no_privilege
       FROM pg_namespace
      WHERE nspname='aios_personal_memory'`,
  );
  assert.deepEqual(schema.rows, [{
    owner: "aios_c09_owner",
    public_has_no_privilege: true,
  }]);

  const tables = await adminPool.query(
    `SELECT relation.relname,
            pg_get_userbyid(relation.relowner) AS owner,
            relation.relrowsecurity,
            relation.relforcerowsecurity,
            NOT EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(
                    relation.relacl,
                    acldefault('r',relation.relowner)
                  )
                ) AS acl
               WHERE acl.grantee=0
            ) AS public_has_no_privilege
       FROM pg_class AS relation
       JOIN pg_namespace AS schema
         ON schema.oid=relation.relnamespace
      WHERE schema.nspname='aios_personal_memory'
        AND relation.relkind='r'
      ORDER BY relation.relname`,
  );
  assert.deepEqual(
    tables.rows.map(({ relname }) => relname),
    [...C09_TABLES].sort(),
  );
  for (const row of tables.rows) {
    assert.equal(row.owner, "aios_c09_owner");
    assert.equal(row.public_has_no_privilege, true);
    assert.equal(row.relrowsecurity, C09_SCOPED_TABLES.has(row.relname));
    assert.equal(
      row.relforcerowsecurity,
      C09_SCOPED_TABLES.has(row.relname),
    );
  }

  const functions = await adminPool.query(
    `SELECT routine.proname,
            routine.oid::regprocedure::text AS function_ref,
            pg_get_userbyid(routine.proowner) AS owner,
            NOT EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(
                    routine.proacl,
                    acldefault('f',routine.proowner)
                  )
                ) AS acl
               WHERE acl.grantee=0
            ) AS public_has_no_privilege
       FROM pg_proc AS routine
       JOIN pg_namespace AS schema
         ON schema.oid=routine.pronamespace
      WHERE schema.nspname='aios_personal_memory'
      ORDER BY routine.proname,routine.oid`,
  );
  assert.deepEqual(
    functions.rows.map(({ proname }) => proname),
    [...C09_FUNCTIONS].sort(),
  );
  for (const row of functions.rows) {
    assert.equal(row.owner, "aios_c09_owner");
    assert.equal(row.public_has_no_privilege, true);
  }

  const publicSequences = await adminPool.query(
    `SELECT relation.relname,
            NOT EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(
                    relation.relacl,
                    acldefault('S',relation.relowner)
                  )
                ) AS acl
               WHERE acl.grantee=0
            ) AS public_has_no_privilege
       FROM pg_class AS relation
       JOIN pg_namespace AS schema
         ON schema.oid=relation.relnamespace
      WHERE schema.nspname='aios_personal_memory'
        AND relation.relkind='S'`,
  );
  assert.ok(
    publicSequences.rows.every(
      ({ public_has_no_privilege: safe }) => safe,
    ),
  );

  const roles = await adminPool.query(
    `SELECT rolname,rolcanlogin,rolsuper,rolinherit,rolcreatedb,
            rolcreaterole,rolreplication,rolbypassrls
       FROM pg_roles
      WHERE rolname=ANY($1::text[])
      ORDER BY rolname`,
    [C09_DEPENDENCY_ROLES],
  );
  assert.deepEqual(
    roles.rows.map(({ rolname }) => rolname),
    [...C09_DEPENDENCY_ROLES].sort(),
  );
  for (const role of roles.rows) {
    assert.equal(role.rolcanlogin, false);
    assert.equal(role.rolsuper, false);
    assert.equal(role.rolinherit, false);
    assert.equal(role.rolcreatedb, false);
    assert.equal(role.rolcreaterole, false);
    assert.equal(role.rolreplication, false);
    assert.equal(role.rolbypassrls, false);
  }

  const memberships = await adminPool.query(
    `SELECT granted.rolname AS granted_role,
            member.rolname AS member_role
       FROM pg_auth_members AS membership
       JOIN pg_roles AS granted ON granted.oid=membership.roleid
       JOIN pg_roles AS member ON member.oid=membership.member
      WHERE granted.rolname=ANY($1::text[])
         OR member.rolname=ANY($1::text[])`,
    [C09_DEPENDENCY_ROLES],
  );
  assert.equal(memberships.rowCount, 0);

  const testLogins = await adminPool.query(
    `SELECT rolname FROM pg_roles WHERE rolname=ANY($1::text[])`,
    [TEST_LOGINS],
  );
  assert.equal(testLogins.rowCount, 0);

  const schemaPrivileges = await adminPool.query(
    `SELECT role_name,schema_name,privilege,
            has_schema_privilege(
              role_name,
              schema_name,
              privilege
            ) AS allowed
       FROM unnest($1::text[]) AS role_name
       CROSS JOIN unnest($2::text[]) AS schema_name
       CROSS JOIN unnest(ARRAY['USAGE','CREATE']) AS privilege
      ORDER BY role_name,schema_name,privilege`,
    [
      APPLICATION_ROLES,
      ["aios_core", "aios_data", "aios_personal_memory"],
    ],
  );
  for (const row of schemaPrivileges.rows) {
    assert.equal(
      row.allowed,
      row.privilege === "USAGE" &&
        expectedSchemaPrivileges[row.role_name].includes(row.schema_name),
      `${row.role_name} ${row.privilege} ${row.schema_name}`,
    );
  }

  const tablePrivileges = await adminPool.query(
    `SELECT role_name,table_name,privilege,
            has_table_privilege(
              role_name,
              format('aios_personal_memory.%I',table_name),
              privilege
            ) AS allowed
       FROM unnest($1::text[]) AS role_name
       CROSS JOIN unnest($2::text[]) AS table_name
       CROSS JOIN unnest($3::text[]) AS privilege
      ORDER BY role_name,table_name,privilege`,
    [APPLICATION_ROLES, C09_TABLES, TABLE_PRIVILEGES],
  );
  assert.equal(
    tablePrivileges.rowCount,
    APPLICATION_ROLES.length *
      C09_TABLES.length *
      TABLE_PRIVILEGES.length,
  );
  for (const row of tablePrivileges.rows) {
    assert.equal(
      row.allowed,
      (
        expectedTablePrivileges[row.role_name][row.privilege] ?? []
      ).includes(row.table_name),
      `${row.role_name} ${row.privilege} ${row.table_name}`,
    );
  }

  const columnPrivileges = await adminPool.query(
    `SELECT role_name,
            relation.relname AS table_name,
            attribute.attname AS column_name,
            privilege,
            has_column_privilege(
              role_name,
              relation.oid,
              attribute.attnum,
              privilege
            ) AS allowed
       FROM unnest($1::text[]) AS role_name
       CROSS JOIN pg_class AS relation
       JOIN pg_namespace AS schema
         ON schema.oid=relation.relnamespace
        AND schema.nspname='aios_personal_memory'
       JOIN pg_attribute AS attribute
         ON attribute.attrelid=relation.oid
        AND attribute.attnum>0
        AND NOT attribute.attisdropped
       CROSS JOIN unnest($2::text[]) AS privilege
      WHERE relation.relkind='r'
      ORDER BY role_name,table_name,column_name,privilege`,
    [APPLICATION_ROLES, COLUMN_PRIVILEGES],
  );
  assert.ok(columnPrivileges.rowCount > 0);
  for (const row of columnPrivileges.rows) {
    assert.equal(
      row.allowed,
      (
        expectedTablePrivileges[row.role_name][row.privilege] ?? []
      ).includes(row.table_name),
      `${row.role_name} ${row.privilege} ` +
        `${row.table_name}.${row.column_name}`,
    );
  }

  const functionPrivileges = await adminPool.query(
    `SELECT role_name,
            routine.oid::regprocedure::text AS function_ref,
            has_function_privilege(
              role_name,
              routine.oid,
              'EXECUTE'
            ) AS allowed
       FROM unnest($1::text[]) AS role_name
       CROSS JOIN pg_proc AS routine
       JOIN pg_namespace AS schema
         ON schema.oid=routine.pronamespace
        AND schema.nspname=ANY($2::text[])
      ORDER BY role_name,function_ref`,
    [
      APPLICATION_ROLES,
      ["aios_core", "aios_data", "aios_personal_memory"],
    ],
  );
  for (const row of functionPrivileges.rows) {
    assert.equal(
      row.allowed,
      expectedFunctionPrivileges[row.role_name].includes(row.function_ref),
      `${row.role_name} EXECUTE ${row.function_ref}`,
    );
  }
  for (const role of APPLICATION_ROLES) {
    assert.deepEqual(
      functionPrivileges.rows
        .filter((row) => row.role_name === role && row.allowed)
        .map(({ function_ref: functionRef }) => functionRef)
        .sort(),
      [...expectedFunctionPrivileges[role]].sort(),
    );
  }

  const sequencePrivileges = await adminPool.query(
    `SELECT role_name,relation.relname,privilege,
            has_sequence_privilege(
              role_name,
              relation.oid,
              privilege
            ) AS allowed
       FROM unnest($1::text[]) AS role_name
       CROSS JOIN pg_class AS relation
       JOIN pg_namespace AS schema
         ON schema.oid=relation.relnamespace
        AND schema.nspname=ANY($2::text[])
       CROSS JOIN unnest(ARRAY['SELECT','UPDATE','USAGE']) AS privilege
      WHERE relation.relkind='S'`,
    [
      APPLICATION_ROLES,
      ["aios_core", "aios_data", "aios_personal_memory"],
    ],
  );
  assert.ok(sequencePrivileges.rows.every(({ allowed }) => !allowed));
}

test("restored PostgreSQL keeps terminal state scrubbed and events opaque", async () => {
  const pool = new Pool(configuration());
  try {
    const system = await pool.query(
      `SELECT system_identifier::text
         FROM pg_control_system()`,
    );
    assert.notEqual(
      system.rows[0].system_identifier,
      process.env.C09_TEST_SOURCE_SYSTEM_IDENTIFIER,
    );
    const terminal = await pool.query(
      `SELECT count(*)::integer AS total,
              count(*) FILTER (WHERE content IS NOT NULL)::integer
                AS plaintext
         FROM aios_personal_memory.personal_memory
        WHERE state IN ('EXPIRED','DELETED')`,
    );
    assert.ok(terminal.rows[0].total > 0);
    assert.equal(terminal.rows[0].plaintext, 0);

    const checkpoint = await pool.query(
      `SELECT count(*)::integer AS terminal_references
         FROM aios_personal_memory.conversation_checkpoint AS checkpoint
         CROSS JOIN LATERAL unnest(checkpoint.memory_ids)
           AS reference(memory_id)
         JOIN aios_personal_memory.personal_memory AS memory
           ON memory.tenant_id=checkpoint.tenant_id
          AND memory.principal_id=checkpoint.principal_id
          AND memory.memory_id=reference.memory_id
        WHERE memory.state IN ('EXPIRED','DELETED')`,
    );
    assert.equal(checkpoint.rows[0].terminal_references, 0);

    const probeHits = await pool.query(
      `SELECT
         (
           SELECT count(*)::integer
             FROM aios_personal_memory.personal_memory
            WHERE tenant_id=$1 AND memory_id=$2
              AND state='DELETED'
         ) AS tombstones,
         (
           SELECT count(*)::integer
             FROM aios_personal_memory.personal_memory
            WHERE tenant_id=$1 AND memory_id=$2
              AND (
                state IN ('CANDIDATE','CONFIRMED')
                OR content IS NOT NULL
              )
         ) AS live_or_plaintext_hits,
         (
           SELECT count(*)::integer
             FROM aios_personal_memory.conversation_checkpoint
            WHERE tenant_id=$1 AND $2=ANY(memory_ids)
         ) AS checkpoint_reference_hits,
         (
           SELECT count(*)::integer
             FROM aios_personal_memory.memory_event AS event
            WHERE event.tenant_id=$1
              AND to_jsonb(event)::text LIKE '%' || $3 || '%'
         ) AS event_plaintext_hits,
         (
           SELECT count(*)::integer
             FROM aios_personal_memory.command_receipt AS receipt
            WHERE receipt.tenant_id=$1
              AND to_jsonb(receipt)::text LIKE '%' || $3 || '%'
         ) AS receipt_plaintext_hits`,
      [
        dataSurfaceCatalog.probe.tenantId,
        dataSurfaceCatalog.probe.memoryId,
        dataSurfaceCatalog.probe.contentCanary,
      ],
    );
    assert.deepEqual(probeHits.rows[0], {
      tombstones: 1,
      live_or_plaintext_hits: 0,
      checkpoint_reference_hits: 0,
      event_plaintext_hits: 0,
      receipt_plaintext_hits: 0,
    });

    const absentRuntimeObjects = await pool.query(
      `SELECT
         (
           SELECT count(*)::integer
             FROM pg_class AS relation
             JOIN pg_namespace AS schema
               ON schema.oid=relation.relnamespace
            WHERE schema.nspname='aios_personal_memory'
              AND relation.relname ~* '(vector|embedding|cache)'
         ) AS vector_or_cache_relations,
         (
           SELECT count(*)::integer
             FROM pg_attribute AS attribute
             JOIN pg_class AS relation
               ON relation.oid=attribute.attrelid
             JOIN pg_namespace AS schema
               ON schema.oid=relation.relnamespace
            WHERE schema.nspname='aios_personal_memory'
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND (
                attribute.attname ~* '(vector|embedding|cache)'
                OR format_type(
                  attribute.atttypid,
                  attribute.atttypmod
                ) ~* 'vector'
              )
         ) AS vector_or_cache_columns`,
    );
    assert.deepEqual(absentRuntimeObjects.rows[0], {
      vector_or_cache_relations: 0,
      vector_or_cache_columns: 0,
    });

    const events = await pool.query(
      `SELECT count(*)::integer AS total,
              count(*) FILTER (
                WHERE human_consent_evidence IS NOT NULL
              )::integer AS consent_events,
              count(*) FILTER (
                WHERE to_jsonb(event) ? 'content'
                   OR human_consent_evidence ? 'humanConsentToken'
                   OR to_jsonb(event)::text
                        ~ 'hct_[0-9a-f-]{36}'
                   OR to_jsonb(event)::text LIKE '%Synthetic preference:%'
                   OR to_jsonb(event)::text LIKE '%Synthetic work state:%'
              )::integer AS plaintext_leaks
         FROM aios_personal_memory.memory_event AS event`,
    );
    assert.ok(events.rows[0].total > 0);
    assert.ok(events.rows[0].consent_events > 0);
    assert.equal(events.rows[0].plaintext_leaks, 0);
  } finally {
    await pool.end();
  }
});

test("restored PostgreSQL preserves service replay, RLS, pause and expiry behavior", async () => {
  const adminPool = new Pool(configuration());
  let runtimePool;
  let tenantScopePool;
  let principalScopePool;
  let retentionPool;
  let gucRuntimePool;
  try {
    await verifyRestoredStructure(adminPool);
    await adminPool.query(
      `CREATE ROLE ${RUNTIME_LOGIN}
         LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
         NOREPLICATION NOBYPASSRLS;
       CREATE ROLE ${TENANT_SCOPE_LOGIN}
         LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
         NOREPLICATION NOBYPASSRLS;
       CREATE ROLE ${PRINCIPAL_SCOPE_LOGIN}
         LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
         NOREPLICATION NOBYPASSRLS;
       CREATE ROLE ${RETENTION_LOGIN}
         LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
         NOREPLICATION NOBYPASSRLS;
       GRANT aios_c09_runtime TO ${RUNTIME_LOGIN};
       GRANT aios_c07_scope_runtime TO ${TENANT_SCOPE_LOGIN};
       GRANT aios_c09_scope_runtime TO ${PRINCIPAL_SCOPE_LOGIN};
       GRANT aios_c09_retention_runtime TO ${RETENTION_LOGIN};`,
    );
    runtimePool = new Pool(configuration(RUNTIME_LOGIN));
    tenantScopePool = new Pool(configuration(TENANT_SCOPE_LOGIN));
    principalScopePool = new Pool(
      configuration(PRINCIPAL_SCOPE_LOGIN),
    );
    retentionPool = new Pool(configuration(RETENTION_LOGIN));
    const store = createPostgresPersonalMemoryStore({
      runtimePool,
      tenantScopePool,
      principalScopePool,
      retentionPool,
    });
    const restoredScope = {
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId: TENANT_A,
      tenantKind: "SYNTHETIC",
      principalId: HUMAN_A,
      lifecycleVersion: 2,
      correlationId: "restored-guc-cleanup",
      decisionId: "restored-decision-guc-cleanup",
      evidenceRef: "evidence://c09/restored-guc-cleanup",
      policyVersion: "c09-restored-postgresql-policy-v1",
      principalLifecycleVersion: 1,
      principalSecurityEpoch: 1,
    };
    gucRuntimePool = new Pool(configuration(RUNTIME_LOGIN, 1));
    const gucStore = createPostgresPersonalMemoryStore({
      runtimePool: gucRuntimePool,
      tenantScopePool,
      principalScopePool,
    });
    for (const guc of SCOPE_GUCS) {
      const dirty = await gucRuntimePool.connect();
      await dirty.query("SELECT set_config($1,'polluted',false)", [
        `aios.${guc}`,
      ]);
      dirty.release();
      await assert.rejects(
        gucStore.readProfile(restoredScope, {
          tenantId: TENANT_A,
          principalId: HUMAN_A,
        }),
        (error) => error?.code === "CONNECTION_CONTEXT_LEAK",
      );
    }
    const projection = SCOPE_GUCS.map(
      (guc) => `current_setting('aios.${guc}',true) AS "${guc}"`,
    ).join(",");
    async function connectionState() {
      const client = await gucRuntimePool.connect();
      try {
        return (
          await client.query(
            `SELECT pg_backend_pid() AS session_pid,${projection}`,
          )
        ).rows[0];
      } finally {
        client.release();
      }
    }
    const beforeCommit = await connectionState();
    await gucStore.readProfile(restoredScope, {
      tenantId: TENANT_A,
      principalId: HUMAN_A,
    });
    const afterCommit = await connectionState();
    assert.equal(afterCommit.session_pid, beforeCommit.session_pid);
    assert.ok(
      SCOPE_GUCS.every(
        (guc) => [null, ""].includes(afterCommit[guc]),
      ),
    );
    await assert.rejects(
      gucStore.apply(restoredScope, {
        operation: "DELETE_MEMORY",
        tenantId: TENANT_A,
        tenantKind: "SYNTHETIC",
        principalId: HUMAN_A,
        actorPrincipalId: ACTOR,
        memoryId: "mem_018f0000-0000-7000-8000-000000009999",
        expectedVersion: 1,
        eventId: "mev_018f0000-0000-7000-8000-000000009999",
        idempotencyKey: "restored-guc-rollback",
        correlationId: restoredScope.correlationId,
        requestHash:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        authorizationEvidence: {
          decisionId: restoredScope.decisionId,
          evidenceRef: restoredScope.evidenceRef,
          policyVersion: restoredScope.policyVersion,
          humanPrincipalId: HUMAN_A,
          workloadActorPrincipalId: ACTOR,
          delegationId: DELEGATION_A,
        },
        humanConsentEvidence: null,
        now: "2026-07-26T10:00:00.000Z",
      }),
      (error) => error?.code === "MEMORY_NOT_FOUND",
    );
    const afterRollback = await connectionState();
    assert.equal(afterRollback.session_pid, beforeCommit.session_pid);
    assert.ok(
      SCOPE_GUCS.every(
        (guc) => [null, ""].includes(afterRollback[guc]),
      ),
    );

    const receipt = await adminPool.query(
      `SELECT result
         FROM aios_personal_memory.command_receipt
        WHERE tenant_id=$1 AND principal_id=$2
          AND idempotency_key='pg-confirm-receipt-restart'`,
      [TENANT_A, HUMAN_A],
    );
    assert.equal(receipt.rowCount, 1);
    let consentCalls = 0;
    const owner = createHarness({
      store,
      tenantId: TENANT_A,
      humanPrincipalId: HUMAN_A,
      delegationId: DELEGATION_A,
      now: "2026-07-26T10:00:00.000Z",
      start: 3100,
      humanConsentStore: {
        async consume() {
          consentCalls += 1;
          throw new Error("restored receipt must precede consent");
        },
      },
    });
    const replay = await owner.service.execute(
      owner.context,
      owner.wrap({
        kind: "CONFIRM_CANDIDATE",
        memoryId: receipt.rows[0].result.memoryId,
        expectedVersion: 1,
        humanConsentToken: RECEIPT_REPLAY_CONSENT_TOKEN,
        idempotencyKey: "pg-confirm-receipt-restart",
        correlationId: "pg-confirm-receipt-restart",
      }),
    );
    assert.deepEqual(replay, receipt.rows[0].result);
    assert.equal(consentCalls, 0);
    const deletedProbeRecall = await owner.service.recall(
      owner.context,
      owner.recall("deleted-probe"),
    );
    assert.deepEqual(
      deletedProbeRecall.memories.filter(
        ({ memoryId }) =>
          memoryId === dataSurfaceCatalog.probe.memoryId,
      ),
      [],
    );
    const deletedProbeCheckpoint =
      await owner.service.readCheckpoint(owner.context, {
        sessionToken: `restored-token-${HUMAN_A}`,
        delegationId: DELEGATION_A,
        checkpointId: dataSurfaceCatalog.probe.checkpointId,
        correlationId: "restored-read-deleted-probe-checkpoint",
      });
    assert.equal(
      deletedProbeCheckpoint.memoryIds.includes(
        dataSurfaceCatalog.probe.memoryId,
      ),
      false,
    );
    await adminPool.query(
      `INSERT INTO aios_core.principal_registry (
         principal_id,tenant_id,tenant_kind,principal_kind,creation_key,
         state,lifecycle_version,security_epoch,created_at,updated_at
       ) VALUES (
         $1,$2,'SYNTHETIC','HUMAN','c09-restored-other-human',
         'ACTIVE',1,1,$3,$3
       )`,
      [HUMAN_OTHER, TENANT_A, "2026-07-26T10:00:00.000Z"],
    );
    const { consentStore: sameTenantConsentStore } =
      createSyntheticHumanConsentAuthority();
    const sameTenantOtherHuman = createHarness({
      store,
      tenantId: TENANT_A,
      humanPrincipalId: HUMAN_OTHER,
      delegationId: DELEGATION_B,
      now: "2026-07-26T10:00:00.000Z",
      start: 3150,
      humanConsentStore: sameTenantConsentStore,
    });
    const sameTenantRecall = await sameTenantOtherHuman.service.recall(
      sameTenantOtherHuman.context,
      sameTenantOtherHuman.recall("same-tenant-other-human"),
    );
    assert.equal(
      sameTenantRecall.memories.some(
        ({ memoryId }) => memoryId === receipt.rows[0].result.memoryId,
      ),
      false,
    );
    await assert.rejects(
      store.readProfile(restoredScope, {
        tenantId: TENANT_A,
        principalId: HUMAN_OTHER,
      }),
      (error) => error?.code === "IDENTITY_BINDING_INVALID",
    );

    const expired = await adminPool.query(
      `SELECT memory_id
         FROM aios_personal_memory.personal_memory
        WHERE tenant_id=$1 AND principal_id=$2
          AND source_ref='fixture://c09/northstar/work-state/catalog'
          AND state='CONFIRMED'
          AND expires_at='2026-08-26T00:00:00.000Z'`,
      [TENANT_A, HUMAN_A],
    );
    assert.equal(expired.rowCount, 1);
    owner.mutable.now = "2026-08-27T00:00:00.000Z";
    const ownerRecall = await owner.service.recall(
      owner.context,
      owner.recall("natural-expiry"),
    );
    assert.equal(
      ownerRecall.memories.some(
        ({ memoryId }) => memoryId === expired.rows[0].memory_id,
      ),
      false,
    );

    const retentionWorker = createPersonalMemoryRetentionWorker({
      store,
      clock: () => "2026-07-26T10:00:00.000Z",
      idFactory: deterministicIds(3300),
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
            decisionId: "restored-decision-retention-worker",
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
      async tenantScopeFactory({
        tenant,
        authorization,
        correlationId,
      }) {
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
    const restoredExpiry =
      await retentionWorker.materializeExpiry({
        tenantId: TENANT_A,
        memoryId: RETENTION_RESTORE_MEMORY,
        expectedVersion: 1,
        idempotencyKey: "restored-retention-expiry",
        correlationId: "restored-retention-expiry",
      });
    assert.deepEqual(restoredExpiry, {
      memoryId: RETENTION_RESTORE_MEMORY,
      state: "EXPIRED",
      version: 2,
    });
    const restoredExpiryRow = await adminPool.query(
      `SELECT state,content
         FROM aios_personal_memory.personal_memory
        WHERE tenant_id=$1 AND memory_id=$2`,
      [TENANT_A, RETENTION_RESTORE_MEMORY],
    );
    assert.deepEqual(restoredExpiryRow.rows[0], {
      state: "EXPIRED",
      content: null,
    });

    const { issuer, consentStore } =
      createSyntheticHumanConsentAuthority();
    const otherTenant = createHarness({
      store,
      tenantId: TENANT_B,
      humanPrincipalId: HUMAN_C,
      delegationId: DELEGATION_C,
      now: "2026-07-26T10:00:00.000Z",
      start: 3200,
      humanConsentStore: consentStore,
    });
    const candidate = await otherTenant.service.execute(
      otherTenant.context,
      otherTenant.wrap({
        kind: "PROPOSE_CANDIDATE",
        candidateRef: "fixture://c09/cedar/preferences/evidence-first",
        idempotencyKey: "restored-pg-propose-tenant-b",
        correlationId: "restored-pg-propose-tenant-b",
      }),
    );
    const confirmation = {
      kind: "CONFIRM_CANDIDATE",
      memoryId: candidate.memoryId,
      expectedVersion: candidate.version,
      humanConsentToken: issuer.issue({
        tenantId: TENANT_B,
        humanPrincipalId: HUMAN_C,
        memoryId: candidate.memoryId,
        expectedVersion: candidate.version,
        contentSha256:
          catalog.resolve(
            TENANT_B,
            "fixture://c09/cedar/preferences/evidence-first",
          ).contentSha256,
        expiresAt: "2026-07-26T11:00:00.000Z",
        purpose: "CONFIRM_PERSONAL_MEMORY",
      }),
      idempotencyKey: "restored-pg-confirm-tenant-b",
      correlationId: "restored-pg-confirm-tenant-b",
    };
    const confirmed = await otherTenant.service.execute(
      otherTenant.context,
      otherTenant.wrap(confirmation),
    );
    const isolated = await otherTenant.service.recall(
      otherTenant.context,
      otherTenant.recall("tenant-b-isolation"),
    );
    assert.deepEqual(
      isolated.memories.map(({ memoryId }) => memoryId),
      [confirmed.memoryId],
    );
    await otherTenant.service.execute(
      otherTenant.context,
      otherTenant.wrap({
        kind: "CHANGE_PROFILE_STATE",
        expectedProfileVersion: 1,
        state: "PAUSED",
        idempotencyKey: "restored-pg-pause-tenant-b",
        correlationId: "restored-pg-pause-tenant-b",
      }),
    );
    assert.deepEqual(
      (
        await otherTenant.service.recall(
          otherTenant.context,
          otherTenant.recall("tenant-b-paused"),
        )
      ).memories,
      [],
    );
  } finally {
    await Promise.allSettled([
      runtimePool?.end(),
      tenantScopePool?.end(),
      principalScopePool?.end(),
      retentionPool?.end(),
      gucRuntimePool?.end(),
      adminPool.end(),
    ]);
  }
});
