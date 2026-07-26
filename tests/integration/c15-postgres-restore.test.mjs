import assert from "node:assert/strict";
import test from "node:test";
import pg from "pg";
import {
  createC15AuditOutboxWorker,
  createC15EffectOutboxWorker,
} from "../../lib/c15-outbox-worker.mjs";
import {
  createC15SyntheticEffectAdapter,
} from "../../lib/c15-synthetic-effect-adapter.mjs";
import {
  createPostgresHumanDecisionStore,
} from "../../lib/postgres-human-decision-store.mjs";

const { Pool } = pg;
const RUNTIME_LOGIN = "c15_restore_runtime_login";
const EFFECT_LOGIN = "c15_restore_effect_login";
const AUDIT_LOGIN = "c15_restore_audit_login";
const RECOVERY_LOGIN = "c15_restore_recovery_login";
const SCOPE_LOGIN = "c15_restore_scope_login";
const C15_TABLES = [
  "draft_artifact",
  "synthetic_test_decision",
  "decision_withdrawal",
  "workflow_effect",
  "effect_outbox",
  "audit_intent",
  "audit_outbox",
  "command_receipt",
];
const C15_FUNCTIONS = [
  "claim_audit_outbox",
  "claim_effect_outbox",
  "complete_effect",
  "enforce_command_receipt_pair",
  "enforce_effect_transition",
  "enforce_outbox_transition",
  "fail_audit_outbox",
  "fail_effect_outbox",
  "publish_audit_outbox",
  "reject_append_only_change",
  "valid_audit_intent",
];
const C15_ROLES = [
  "aios_c15_owner",
  "aios_c15_runtime",
  "aios_c15_effect_worker",
  "aios_c15_audit_worker",
  "aios_c15_recovery_reader",
];
const SECURITY_ROLES = [
  ...C15_ROLES,
  "aios_c07_scope_runtime",
];
const APPLICATION_ROLES = C15_ROLES.slice(1);
const TABLE_PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE"];
const COLUMN_PRIVILEGES = new Set([
  "SELECT",
  "INSERT",
  "UPDATE",
  "REFERENCES",
]);

const expectedTablePrivileges = {
  aios_c15_runtime: {
    SELECT: [
      "draft_artifact",
      "synthetic_test_decision",
      "decision_withdrawal",
      "workflow_effect",
      "command_receipt",
    ],
    INSERT: [
      "draft_artifact",
      "synthetic_test_decision",
      "decision_withdrawal",
      "workflow_effect",
      "effect_outbox",
      "audit_intent",
      "audit_outbox",
      "command_receipt",
    ],
  },
  aios_c15_effect_worker: {
    INSERT: ["audit_intent", "audit_outbox"],
  },
  aios_c15_audit_worker: {},
  aios_c15_recovery_reader: {
    SELECT: C15_TABLES,
  },
};
const schemaCapability = (objectName) => ({
  kind: "schema",
  objectName,
  privilege: "USAGE",
});
const tableCapabilities = (name, privileges) =>
  privileges.flatMap((privilege) => [
    {
      kind: "table",
      objectName: `aios_decision.${name}`,
      privilege,
    },
    ...(COLUMN_PRIVILEGES.has(privilege)
      ? [{
          kind: "column",
          objectName: `aios_decision.${name}`,
          privilege,
        }]
      : []),
  ]);
const functionCapability = (objectName) => ({
  kind: "function",
  objectName,
  privilege: "EXECUTE",
});
const dataCapabilities = [
  schemaCapability("aios_data"),
  functionCapability("aios_data.runtime_scope_allows(text,text)"),
  functionCapability("aios_data.acquire_runtime_fence()"),
];
const expectedRoleCapabilities = {
  aios_c15_runtime: [
    schemaCapability("aios_decision"),
    ...dataCapabilities,
    ...Object.entries(expectedTablePrivileges.aios_c15_runtime)
      .flatMap(([privilege, tables]) =>
        tables.flatMap((name) => tableCapabilities(name, [privilege])),
      ),
    functionCapability(
      "aios_decision.valid_audit_intent(jsonb)",
    ),
  ],
  aios_c15_effect_worker: [
    schemaCapability("aios_decision"),
    ...dataCapabilities,
    ...Object.entries(expectedTablePrivileges.aios_c15_effect_worker)
      .flatMap(([privilege, tables]) =>
        tables.flatMap((name) => tableCapabilities(name, [privilege])),
      ),
    functionCapability(
      "aios_decision.valid_audit_intent(jsonb)",
    ),
    functionCapability(
      "aios_decision.claim_effect_outbox(text,text,integer,integer)",
    ),
    functionCapability(
      "aios_decision.complete_effect(text,text,text,bigint,text,text,jsonb,jsonb,jsonb,text)",
    ),
    functionCapability(
      "aios_decision.fail_effect_outbox(text,text,text,bigint,text,integer,text)",
    ),
  ],
  aios_c15_audit_worker: [
    schemaCapability("aios_decision"),
    ...dataCapabilities,
    functionCapability(
      "aios_decision.claim_audit_outbox(text,text,integer,integer)",
    ),
    functionCapability(
      "aios_decision.publish_audit_outbox(text,text,text,bigint,text,text,text)",
    ),
    functionCapability(
      "aios_decision.fail_audit_outbox(text,text,text,bigint,text,integer,text)",
    ),
  ],
  aios_c15_recovery_reader: [
    schemaCapability("aios_decision"),
    ...dataCapabilities,
    ...C15_TABLES.flatMap((name) =>
      tableCapabilities(name, ["SELECT"]),
    ),
  ],
  aios_c07_scope_runtime: [
    schemaCapability("aios_data"),
    functionCapability(
      "aios_data.issue_runtime_scope_signature(text,text,bigint,text,text,text,text,integer,xid8,integer,uuid)",
    ),
  ],
};

async function assertExactCapabilities(admin, role, expected) {
  const result = await admin.query(
    `WITH protected_schemas AS (
       SELECT oid,nspname
         FROM pg_namespace
        WHERE nspname=ANY($2::text[])
           OR nspname ~ '^aios_'
     ),
     expected_input AS (
       SELECT *
         FROM jsonb_to_recordset($1::jsonb)
           AS entry(kind text, "objectName" text, privilege text)
     ),
     expected AS (
       SELECT kind,
              CASE kind
                WHEN 'schema' THEN (
                  SELECT oid::text
                    FROM pg_namespace
                   WHERE nspname="objectName"
                )
                WHEN 'table' THEN to_regclass("objectName")::oid::text
                WHEN 'column' THEN to_regclass("objectName")::oid::text
                WHEN 'sequence' THEN to_regclass("objectName")::oid::text
                WHEN 'function' THEN
                  to_regprocedure("objectName")::oid::text
              END AS object_oid,
              privilege
         FROM expected_input
     ),
     schema_privileges(privilege) AS (
       VALUES ('USAGE'),('CREATE')
     ),
     relation_privileges(privilege) AS (
       VALUES
         ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),
         ('TRUNCATE'),('REFERENCES'),('TRIGGER')
     ),
     column_privileges(privilege) AS (
       VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')
     ),
     sequence_privileges(privilege) AS (
       VALUES ('SELECT'),('UPDATE'),('USAGE')
     ),
     actual AS (
       SELECT 'schema'::text AS kind,
              schema.oid::text AS object_oid,privilege
         FROM protected_schemas AS schema
         CROSS JOIN schema_privileges
        WHERE has_schema_privilege($3::name,schema.oid,privilege)
       UNION ALL
       SELECT 'table',relation.oid::text,privilege
         FROM protected_schemas AS schema
         JOIN pg_class AS relation
           ON relation.relnamespace=schema.oid
          AND relation.relkind IN ('r','p','v','m','f')
         CROSS JOIN relation_privileges
        WHERE has_table_privilege($3::name,relation.oid,privilege)
       UNION ALL
       SELECT 'column',relation.oid::text,privilege
         FROM protected_schemas AS schema
         JOIN pg_class AS relation
           ON relation.relnamespace=schema.oid
          AND relation.relkind IN ('r','p','v','m','f')
         CROSS JOIN column_privileges
        WHERE has_any_column_privilege(
          $3::name,
          relation.oid,
          privilege
        )
       UNION ALL
       SELECT 'sequence',relation.oid::text,privilege
         FROM protected_schemas AS schema
         JOIN pg_class AS relation
           ON relation.relnamespace=schema.oid
          AND relation.relkind='S'
         CROSS JOIN sequence_privileges
        WHERE has_sequence_privilege($3::name,relation.oid,privilege)
       UNION ALL
       SELECT 'function',routine.oid::text,'EXECUTE'
         FROM protected_schemas AS schema
         JOIN pg_proc AS routine ON routine.pronamespace=schema.oid
        WHERE has_function_privilege($3::name,routine.oid,'EXECUTE')
     ),
     mismatch AS (
       (
         SELECT kind,object_oid,privilege FROM actual
         EXCEPT
         SELECT kind,object_oid,privilege FROM expected
       )
       UNION ALL
       (
         SELECT kind,object_oid,privilege FROM expected
         EXCEPT
         SELECT kind,object_oid,privilege FROM actual
       )
     )
     SELECT
       NOT EXISTS (SELECT 1 FROM mismatch)
       AND NOT EXISTS (
         SELECT 1 FROM expected WHERE object_oid IS NULL
       ) AS privileges_safe`,
    [
      JSON.stringify(expected),
      ["aios_data", "aios_audit", "aios_decision"],
      role,
    ],
  );
  assert.equal(result.rows[0]?.privileges_safe, true, role);
}

function config(user = process.env.C15_RESTORE_PGUSER) {
  if (process.env.C15_RESTORE_EPHEMERAL !== "1") {
    throw new Error("C15_RESTORE_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C15_RESTORE_PGHOST",
    "C15_RESTORE_PGPORT",
    "C15_RESTORE_PGDATABASE",
    "C15_RESTORE_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C15_RESTORE_PGHOST,
    port: Number(process.env.C15_RESTORE_PGPORT),
    database: process.env.C15_RESTORE_PGDATABASE,
    user,
    max: 10,
  };
}

function scope(tenantId, lifecycleVersion, suffix) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion,
    correlationId: `c15-restore-${suffix}`,
    decisionId: `c15-restore-${suffix}`,
    evidenceRef: `evidence://c15/restore/${suffix}`,
    policyVersion: "c15-restore-v1",
  };
}

function deterministicIds() {
  let current = 9000;
  return () =>
    `018f0000-0000-7000-8000-${String(++current).padStart(12, "0")}`;
}

test("C15 pg_dump restores into a fresh cluster and resumes Outboxes", async (t) => {
  const sourceSystemIdentifier =
    process.env.C15_RESTORE_SOURCE_SYSTEM_IDENTIFIER;
  const targetSystemIdentifier =
    process.env.C15_RESTORE_TARGET_SYSTEM_IDENTIFIER;
  assert.match(sourceSystemIdentifier ?? "", /^\d+$/);
  assert.match(targetSystemIdentifier ?? "", /^\d+$/);
  assert.notEqual(sourceSystemIdentifier, targetSystemIdentifier);

  const admin = new Pool(config());
  const pools = {
    runtime: new Pool(config(RUNTIME_LOGIN)),
    effect: new Pool(config(EFFECT_LOGIN)),
    audit: new Pool(config(AUDIT_LOGIN)),
    recovery: new Pool(config(RECOVERY_LOGIN)),
    scope: new Pool(config(SCOPE_LOGIN)),
  };
  t.after(async () => {
    await Promise.all(Object.values(pools).map((pool) => pool.end()));
    await admin.end();
  });

  const restoredSystem = await admin.query(
    "SELECT system_identifier::text FROM pg_control_system()",
  );
  assert.equal(
    restoredSystem.rows[0].system_identifier,
    targetSystemIdentifier,
  );
  assert.notEqual(
    restoredSystem.rows[0].system_identifier,
    sourceSystemIdentifier,
  );

  const restoredSchema = await admin.query(
    `SELECT pg_get_userbyid(nspowner) AS owner,
            NOT EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(nspacl, acldefault('n', nspowner))
                ) AS acl
               WHERE acl.grantee = 0
            ) AS public_has_no_privilege
       FROM pg_namespace
      WHERE nspname = 'aios_decision'`,
  );
  assert.deepEqual(restoredSchema.rows, [{
    owner: "aios_c15_owner",
    public_has_no_privilege: true,
  }]);

  const restoredTables = await admin.query(
    `SELECT c.relname,
            pg_get_userbyid(c.relowner) AS owner,
            c.relrowsecurity,
            c.relforcerowsecurity,
            NOT EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(c.relacl, acldefault('r', c.relowner))
                ) AS acl
               WHERE acl.grantee = 0
            ) AS public_has_no_privilege
       FROM pg_class AS c
       JOIN pg_namespace AS n ON n.oid = c.relnamespace
      WHERE n.nspname = 'aios_decision'
        AND c.relkind = 'r'
      ORDER BY c.relname`,
  );
  assert.deepEqual(
    restoredTables.rows.map((row) => row.relname),
    [...C15_TABLES].sort(),
  );
  for (const row of restoredTables.rows) {
    assert.equal(row.owner, "aios_c15_owner");
    assert.equal(row.relrowsecurity, true);
    assert.equal(row.relforcerowsecurity, true);
    assert.equal(row.public_has_no_privilege, true);
  }

  const restoredFunctions = await admin.query(
    `SELECT p.proname,
            pg_get_userbyid(p.proowner) AS owner,
            NOT EXISTS (
              SELECT 1
                FROM aclexplode(
                  COALESCE(p.proacl, acldefault('f', p.proowner))
                ) AS acl
               WHERE acl.grantee = 0
            ) AS public_has_no_privilege
       FROM pg_proc AS p
       JOIN pg_namespace AS n ON n.oid = p.pronamespace
      WHERE n.nspname = 'aios_decision'
      ORDER BY p.proname`,
  );
  assert.deepEqual(
    restoredFunctions.rows.map((row) => row.proname),
    [...C15_FUNCTIONS].sort(),
  );
  for (const row of restoredFunctions.rows) {
    assert.equal(row.owner, "aios_c15_owner");
    assert.equal(row.public_has_no_privilege, true);
  }
  const restoredFunctionPrivileges = await admin.query(
    `SELECT role_name,function_name,
            has_function_privilege(
              role_name,
              format('aios_decision.%I(jsonb)', function_name),
              'EXECUTE'
            ) AS allowed
       FROM unnest($1::text[]) AS role_name
      CROSS JOIN unnest($2::text[]) AS function_name
      ORDER BY role_name,function_name`,
    [APPLICATION_ROLES, ["valid_audit_intent"]],
  );
  for (const row of restoredFunctionPrivileges.rows) {
    assert.equal(
      row.allowed,
      ["aios_c15_runtime", "aios_c15_effect_worker"].includes(
        row.role_name,
      ),
      `${row.role_name} EXECUTE ${row.function_name}`,
    );
  }

  const restoredRoles = await admin.query(
    `SELECT rolname,rolcanlogin,rolsuper,rolinherit,rolcreatedb,rolcreaterole,
            rolreplication,rolbypassrls
       FROM pg_roles
      WHERE rolname = ANY($1::text[])
      ORDER BY rolname`,
    [SECURITY_ROLES],
  );
  assert.deepEqual(
    restoredRoles.rows.map((row) => row.rolname),
    [...SECURITY_ROLES].sort(),
  );
  for (const row of restoredRoles.rows) {
    assert.equal(row.rolcanlogin, false);
    assert.equal(row.rolsuper, false);
    assert.equal(row.rolinherit, false);
    assert.equal(row.rolcreatedb, false);
    assert.equal(row.rolcreaterole, false);
    assert.equal(row.rolreplication, false);
    assert.equal(row.rolbypassrls, false);
  }

  const restoredPrivileges = await admin.query(
    `SELECT role_name,table_name,privilege,
            has_table_privilege(
              role_name,
              format('aios_decision.%I', table_name),
              privilege
            ) AS allowed
       FROM unnest($1::text[]) AS role_name
      CROSS JOIN unnest($2::text[]) AS table_name
      CROSS JOIN unnest($3::text[]) AS privilege
      ORDER BY role_name,table_name,privilege`,
    [APPLICATION_ROLES, C15_TABLES, TABLE_PRIVILEGES],
  );
  assert.equal(
    restoredPrivileges.rowCount,
    APPLICATION_ROLES.length *
      C15_TABLES.length *
      TABLE_PRIVILEGES.length,
  );
  for (const row of restoredPrivileges.rows) {
    const allowedTables =
      expectedTablePrivileges[row.role_name][row.privilege] ?? [];
    assert.equal(
      row.allowed,
      allowedTables.includes(row.table_name),
      `${row.role_name} ${row.privilege} ${row.table_name}`,
    );
  }
  for (const [role, capabilities] of Object.entries(
    expectedRoleCapabilities,
  )) {
    await assertExactCapabilities(admin, role, capabilities);
  }

  const restored = await admin.query(
    `SELECT outbox.tenant_id,outbox.effect_id,lifecycle.lifecycle_version
       FROM aios_decision.effect_outbox AS outbox
       JOIN aios_data.tenant_data_lifecycle AS lifecycle
         ON lifecycle.tenant_id=outbox.tenant_id
      WHERE outbox.status IN ('PENDING','FAILED')
      ORDER BY outbox.created_at,outbox.effect_id
      LIMIT 1`,
  );
  assert.equal(restored.rowCount, 1);

  await admin.query(
    `CREATE ROLE ${RUNTIME_LOGIN} LOGIN;
     CREATE ROLE ${EFFECT_LOGIN} LOGIN;
     CREATE ROLE ${AUDIT_LOGIN} LOGIN;
     CREATE ROLE ${RECOVERY_LOGIN} LOGIN;
     CREATE ROLE ${SCOPE_LOGIN} LOGIN;
     GRANT aios_c15_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c15_effect_worker TO ${EFFECT_LOGIN};
     GRANT aios_c15_audit_worker TO ${AUDIT_LOGIN};
     GRANT aios_c15_recovery_reader TO ${RECOVERY_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );

  const store = createPostgresHumanDecisionStore({
    runtimePool: pools.runtime,
    effectWorkerPool: pools.effect,
    auditWorkerPool: pools.audit,
    recoveryPool: pools.recovery,
    scopePool: pools.scope,
  });
  const row = restored.rows[0];
  const restoredScope = scope(
    row.tenant_id,
    Number(row.lifecycle_version),
    "effect",
  );
  assert.equal(
    await store.getArtifact(
      restoredScope,
      "dar_018f0000-0000-7000-8000-999999999999",
    ),
    null,
  );
  const unsafeLogin = "c15_restore_unsafe_login";
  await admin.query(
    `CREATE ROLE ${unsafeLogin} LOGIN;
     GRANT aios_c15_runtime TO ${unsafeLogin};
     GRANT EXECUTE ON FUNCTION
       aios_decision.reject_append_only_change()
       TO ${unsafeLogin};`,
  );
  const unsafePool = new Pool(config(unsafeLogin));
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
        restoredScope,
        "dar_018f0000-0000-7000-8000-999999999999",
      ),
      (error) => error.code === "INVALID_CONFIGURATION",
    );
  } finally {
    await unsafePool.end();
    await admin.query(`DROP OWNED BY ${unsafeLogin}`);
    await admin.query(`DROP ROLE ${unsafeLogin}`);
  }
  const adapter = createC15SyntheticEffectAdapter();
  const effectWorker = createC15EffectOutboxWorker({
    store,
    adapter,
    workerId: "c15-restored-effect-worker",
    idFactory: deterministicIds(),
  });
  const completed = await effectWorker.runOnce(restoredScope);
  assert.equal(completed.effectId, row.effect_id);
  assert.equal(completed.status, "SUCCEEDED");
  assert.equal(adapter.snapshot().externalEffectCount, 0);

  const publishedIntentIds = [];
  const auditWorker = createC15AuditOutboxWorker({
    store,
    c18Publisher: {
      async publish(intent) {
        assert.equal(Object.hasOwn(intent, "candidate"), false);
        assert.equal(Object.hasOwn(intent, "display"), false);
        publishedIntentIds.push(intent.intentId);
        throw Object.assign(
          new Error("C18 unavailable after restore"),
          { code: "C18_UNAVAILABLE" },
        );
      },
    },
    workerId: "c15-restored-audit-worker",
    retryDelaySeconds: 0,
  });
  await assert.rejects(
    auditWorker.runOnce(
      scope(row.tenant_id, Number(row.lifecycle_version), "audit"),
    ),
    /C18 unavailable after restore/,
  );
  assert.equal(publishedIntentIds.length, 1);
  const restoredAudit = await admin.query(
    `SELECT status,last_error_code
       FROM aios_decision.audit_outbox
      WHERE tenant_id=$1 AND intent_id=$2`,
    [row.tenant_id, publishedIntentIds[0]],
  );
  assert.deepEqual(restoredAudit.rows[0], {
    status: "FAILED",
    last_error_code: "C18_UNAVAILABLE",
  });

  const persisted = await admin.query(
    `SELECT effect.status AS effect_status,
            outbox.status AS outbox_status
       FROM aios_decision.workflow_effect AS effect
       JOIN aios_decision.effect_outbox AS outbox
         ON outbox.tenant_id=effect.tenant_id
        AND outbox.effect_id=effect.effect_id
      WHERE effect.tenant_id=$1 AND effect.effect_id=$2`,
    [row.tenant_id, row.effect_id],
  );
  assert.deepEqual(persisted.rows[0], {
    effect_status: "SUCCEEDED",
    outbox_status: "PUBLISHED",
  });
  const recovery = await store.exportRecovery(
    scope(row.tenant_id, Number(row.lifecycle_version), "recovery"),
  );
  assert.equal(Object.keys(recovery.collections).length, 8);
});
