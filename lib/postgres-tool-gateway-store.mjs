import { randomUUID } from "node:crypto";
import {
  ToolGatewayError,
  toolGatewaySha256,
  validateC16SyntheticCompletion,
} from "./tool-gateway.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const COLUMN_PRIVILEGES = new Set([
  "SELECT",
  "INSERT",
  "UPDATE",
  "REFERENCES",
]);
const RETRYABLE = new Set(["40001", "40P01"]);

export class PostgresToolGatewayStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PostgresToolGatewayStoreError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PostgresToolGatewayStoreError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function json(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function instant(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function safeInteger(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    fail("STORE_UNAVAILABLE", "C16 PostgreSQL integer is unsafe.");
  }
  return number;
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope?.tenantKind !== "SYNTHETIC" ||
    !SYNTHETIC_TENANT_ID.test(scope?.tenantId ?? "") ||
    !Number.isSafeInteger(scope?.lifecycleVersion) ||
    scope.lifecycleVersion < 1 ||
    typeof scope?.correlationId !== "string" ||
    !scope.correlationId ||
    typeof scope?.decisionId !== "string" ||
    !scope.decisionId ||
    typeof scope?.evidenceRef !== "string" ||
    !scope.evidenceRef ||
    typeof scope?.policyVersion !== "string" ||
    !scope.policyVersion
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C16 requires a C07 Tenant scope.");
  }
  return scope;
}

function without(value, field) {
  const result = clone(value);
  delete result[field];
  return result;
}

function publicConfirmation(value, replayed = false) {
  return deepFreeze({
    schemaVersion: value.schemaVersion,
    confirmationId: value.confirmationId,
    tenantId: value.tenantId,
    tenantKind: value.tenantKind,
    tenantLifecycleVersion: value.tenantLifecycleVersion,
    operationId: value.operationId,
    catalogVersion: value.catalogVersion,
    catalogSha256: value.catalogSha256,
    adapterVersion: value.adapterVersion,
    normalizedParamSha256: value.normalizedParamSha256,
    identitySha256: value.identitySha256,
    authorizationSha256: value.authorizationSha256,
    authorizationAuthoritySha256:
      value.authorizationAuthoritySha256,
    confirmationSha256: value.confirmationSha256,
    confirmedAt: value.confirmedAt,
    expiresAt: value.expiresAt,
    replayed,
  });
}

function confirmationFromRow(row, replayed = false, internal = false) {
  if (!row) return null;
  const value = clone(json(row.confirmation));
  return internal
    ? deepFreeze(value)
    : publicConfirmation(value, replayed);
}

function publicCall(value, replayed = false) {
  return deepFreeze({
    schemaVersion: "c16-tool-call-result.v1",
    callId: value.callId,
    tenantId: value.tenantId,
    tenantKind: value.tenantKind,
    operationId: value.operationId,
    status: value.status,
    result: clone(value.result),
    receipt: clone(value.receipt),
    replayed,
  });
}

function callFromRow(row, replayed = false, internal = false) {
  if (!row) return null;
  const value = clone(json(row.call));
  value.status = row.status;
  value.result = clone(json(row.result));
  value.receipt = clone(json(row.receipt));
  value.lastErrorCode = row.last_error_code;
  value.completedAt = instant(row.completed_at);
  return internal
    ? deepFreeze(value)
    : publicCall(value, replayed);
}

function auditIntentFromRow(row) {
  if (!row) return null;
  return deepFreeze(clone(json(row.metadata)));
}

function auditOutboxFromRow(row) {
  return deepFreeze({
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    intentId: row.intent_id,
    status: row.outbox_status ?? row.status,
    attemptCount: safeInteger(row.attempt_count),
    leaseVersion: safeInteger(row.lease_version),
    leasedBy: row.leased_by,
    leaseUntil: instant(row.lease_until),
    availableAt: instant(row.available_at),
    publishedAt: instant(row.published_at),
    lastErrorCode: row.last_error_code,
    createdAt: instant(row.outbox_created_at ?? row.created_at),
    ...(row.metadata ? { intent: auditIntentFromRow(row) } : {}),
  });
}

function assertAuditIntent(value) {
  const allowed = [
    "schemaVersion",
    "intentId",
    "tenantId",
    "tenantKind",
    "eventType",
    "subjectId",
    "operationId",
    "identitySha256",
    "authorizationSha256",
    "catalogSha256",
    "normalizedParamSha256",
    "resultReceiptSha256",
    "correlationId",
    "metadataOnly",
    "occurredAt",
    "intentSha256",
  ];
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== allowed.length ||
    Object.keys(value).some((key) => !allowed.includes(key)) ||
    value.schemaVersion !== "c16-c18-outbox-intent.v1" ||
    value.tenantKind !== "SYNTHETIC" ||
    value.metadataOnly !== true ||
    !SHA256.test(value.identitySha256 ?? "") ||
    !SHA256.test(value.authorizationSha256 ?? "") ||
    !SHA256.test(value.catalogSha256 ?? "") ||
    !SHA256.test(value.normalizedParamSha256 ?? "") ||
    (value.resultReceiptSha256 !== null &&
      !SHA256.test(value.resultReceiptSha256 ?? "")) ||
    toolGatewaySha256(without(value, "intentSha256")) !==
      value.intentSha256
  ) {
    fail("INVALID_INPUT", "C16 audit intent is invalid.");
  }
}

function validateConfirmationCommand(command) {
  const value = command?.confirmation;
  if (
    command?.tenantId !== value?.tenantId ||
    typeof command?.idempotencyKey !== "string" ||
    !command.idempotencyKey ||
    command.idempotencyKey.length > 128 ||
    !SHA256.test(command?.requestHash ?? "") ||
    value?.schemaVersion !== "c16-tool-confirmation.v1" ||
    value?.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(value?.tenantLifecycleVersion) ||
    value.tenantLifecycleVersion < 1 ||
    !SHA256.test(value?.confirmationSha256 ?? "") ||
    !SHA256.test(value?.authorizationAuthoritySha256 ?? "") ||
    toolGatewaySha256(without(value, "confirmationSha256")) !==
      value.confirmationSha256
  ) {
    fail("INVALID_INPUT", "C16 confirmation command is invalid.");
  }
  assertAuditIntent(command.auditIntent);
}

function validateCallCommand(command) {
  const value = command?.call;
  if (
    command?.tenantId !== value?.tenantId ||
    typeof command?.idempotencyKey !== "string" ||
    !command.idempotencyKey ||
    command.idempotencyKey.length > 128 ||
    !SHA256.test(command?.requestHash ?? "") ||
    value?.schemaVersion !== "c16-tool-call.v1" ||
    value?.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(value?.tenantLifecycleVersion) ||
    value.tenantLifecycleVersion < 1 ||
    !SHA256.test(value?.callSha256 ?? "") ||
    !SHA256.test(value?.authorizationAuthoritySha256 ?? "") ||
    toolGatewaySha256(without(value, "callSha256")) !== value.callSha256
  ) {
    fail("INVALID_INPUT", "C16 call command is invalid.");
  }
}

function databaseFailure(error) {
  if (
    error instanceof PostgresToolGatewayStoreError ||
    error instanceof ToolGatewayError
  ) {
    return error;
  }
  if (error?.code === "42501") {
    return new PostgresToolGatewayStoreError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL denied the C16 Tenant scope.",
    );
  }
  if (error?.code === "55000") {
    return new PostgresToolGatewayStoreError(
      "APPEND_ONLY_VIOLATION",
      "PostgreSQL rejected a C16 state transition.",
    );
  }
  if (
    error?.code === "23505" &&
    error?.constraint === "tool_call_tenant_id_confirmation_id_key"
  ) {
    return new PostgresToolGatewayStoreError(
      "CONFIRMATION_REPLAYED",
      "C16 confirmation was already executed.",
    );
  }
  if (error?.code === "23505") {
    return new PostgresToolGatewayStoreError(
      "IDEMPOTENCY_CONFLICT",
      "C16 unique command binding conflicted.",
    );
  }
  return new PostgresToolGatewayStoreError(
    "STORE_UNAVAILABLE",
    "C16 PostgreSQL store is unavailable.",
  );
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the first failure.
  }
}

export function createPostgresToolGatewayStore({
  runtimePool,
  toolWorkerPool,
  auditWorkerPool,
  recoveryPool,
  scopePool,
  schema = "aios_tool",
  scopeSchema = "aios_data",
  maxSerializableRetries = 10,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof toolWorkerPool?.connect !== "function" ||
    typeof auditWorkerPool?.connect !== "function" ||
    typeof recoveryPool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    new Set([
      runtimePool,
      toolWorkerPool,
      auditWorkerPool,
      recoveryPool,
      scopePool,
    ]).size !== 5 ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C16 PostgreSQL pools are invalid.");
  }
  const table = (name) => `"${schema}"."${name}"`;
  const signer =
    `"${scopeSchema}"."issue_runtime_scope_signature"`;
  const fence = `"${scopeSchema}"."acquire_runtime_fence"`;
  const protectedSchemas = [...new Set([schema, scopeSchema])];
  const schemaCapability = (objectName) => ({
    kind: "schema",
    objectName,
    privilege: "USAGE",
  });
  const tableCapabilities = (objectName, privileges) =>
    privileges.flatMap((privilege) => [
      { kind: "table", objectName, privilege },
      ...(COLUMN_PRIVILEGES.has(privilege)
        ? [{ kind: "column", objectName, privilege }]
        : []),
    ]);
  const functionCapability = (objectName) => ({
    kind: "function",
    objectName,
    privilege: "EXECUTE",
  });
  const commonCapabilities = [
    schemaCapability(schema),
    schemaCapability(scopeSchema),
    functionCapability(
      `${scopeSchema}.runtime_scope_allows(text,text)`,
    ),
    functionCapability(`${scopeSchema}.acquire_runtime_fence()`),
  ];
  const roleCapabilities = {
    aios_c16_runtime: [
      ...commonCapabilities,
      ...tableCapabilities(
        `${schema}.tool_confirmation`,
        ["SELECT", "INSERT"],
      ),
      ...tableCapabilities(
        `${schema}.tool_call`,
        ["SELECT", "INSERT"],
      ),
      ...tableCapabilities(`${schema}.audit_intent`, ["INSERT"]),
      ...tableCapabilities(`${schema}.audit_outbox`, ["INSERT"]),
      functionCapability(`${schema}.valid_audit_intent(jsonb)`),
    ],
    aios_c16_worker: [
      ...commonCapabilities,
      ...tableCapabilities(
        `${schema}.tool_call`,
        ["SELECT", "UPDATE"],
      ),
      ...tableCapabilities(`${schema}.audit_intent`, ["INSERT"]),
      ...tableCapabilities(`${schema}.audit_outbox`, ["INSERT"]),
      functionCapability(`${schema}.valid_audit_intent(jsonb)`),
    ],
    aios_c16_audit_worker: [
      ...commonCapabilities,
      ...tableCapabilities(`${schema}.audit_intent`, ["SELECT"]),
      ...tableCapabilities(
        `${schema}.audit_outbox`,
        ["SELECT", "UPDATE"],
      ),
    ],
    aios_c16_recovery_reader: [
      ...commonCapabilities,
      ...tableCapabilities(`${schema}.audit_intent`, ["SELECT"]),
      ...tableCapabilities(`${schema}.audit_outbox`, ["SELECT"]),
      ...tableCapabilities(`${schema}.tool_call`, ["SELECT"]),
      ...tableCapabilities(
        `${schema}.tool_confirmation`,
        ["SELECT"],
      ),
    ],
    aios_c07_scope_runtime: [
      schemaCapability(scopeSchema),
      functionCapability(
        `${scopeSchema}.issue_runtime_scope_signature(text,text,bigint,text,text,text,text,integer,xid8,integer,uuid)`,
      ),
    ],
  };

  async function assertExpectedPrivileges(client, requiredRole) {
    const expected = roleCapabilities[requiredRole];
    if (!expected) {
      fail("INVALID_CONFIGURATION", "C16 PostgreSQL role is unknown.");
    }
    const result = await client.query(
      `WITH identity_subjects(subject) AS (
         SELECT current_user::text
         UNION
         SELECT session_user::text
       ),
       protected_schemas AS (
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
         SELECT subject,
                kind,
                CASE kind
                  WHEN 'schema' THEN (
                    SELECT oid::text
                      FROM pg_namespace
                     WHERE nspname="objectName"
                  )
                  WHEN 'table' THEN to_regclass("objectName")::oid::text
                  WHEN 'column' THEN to_regclass("objectName")::oid::text
                  WHEN 'function' THEN
                    to_regprocedure("objectName")::oid::text
                END AS object_oid,
                privilege
           FROM identity_subjects
           CROSS JOIN expected_input
       ),
       schema_privileges(privilege) AS (
         VALUES ('USAGE'),('CREATE')
       ),
       relation_privileges(privilege) AS (
         VALUES
           ('SELECT'),('INSERT'),('UPDATE'),('DELETE'),
           ('TRUNCATE'),('REFERENCES'),('TRIGGER')
       ),
       sequence_privileges(privilege) AS (
         VALUES ('SELECT'),('USAGE'),('UPDATE')
       ),
       column_privileges(privilege) AS (
         VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')
       ),
       actual AS (
         SELECT subject,'schema'::text AS kind,
                protected_schema.oid::text AS object_oid,privilege
           FROM identity_subjects
           CROSS JOIN protected_schemas AS protected_schema
           CROSS JOIN schema_privileges
          WHERE has_schema_privilege(
            subject::name,
            protected_schema.oid,
            privilege
          )
         UNION ALL
         SELECT subject,'table',relation.oid::text,privilege
           FROM identity_subjects
           CROSS JOIN protected_schemas AS protected_schema
           JOIN pg_class AS relation
             ON relation.relnamespace=protected_schema.oid
            AND relation.relkind IN ('r','p','v','m','f')
           CROSS JOIN relation_privileges
          WHERE has_table_privilege(
            subject::name,
            relation.oid,
            privilege
          )
         UNION ALL
         SELECT subject,'sequence',sequence.oid::text,privilege
           FROM identity_subjects
           CROSS JOIN protected_schemas AS protected_schema
           JOIN pg_class AS sequence
             ON sequence.relnamespace=protected_schema.oid
            AND sequence.relkind='S'
           CROSS JOIN sequence_privileges
          WHERE has_sequence_privilege(
            subject::name,
            sequence.oid,
            privilege
          )
         UNION ALL
         SELECT subject,'column',relation.oid::text,privilege
           FROM identity_subjects
           CROSS JOIN protected_schemas AS protected_schema
           JOIN pg_class AS relation
             ON relation.relnamespace=protected_schema.oid
            AND relation.relkind IN ('r','p','v','m','f')
           CROSS JOIN column_privileges
          WHERE has_any_column_privilege(
            subject::name,
            relation.oid,
            privilege
          )
         UNION ALL
         SELECT subject,'function',routine.oid::text,'EXECUTE'
           FROM identity_subjects
           CROSS JOIN protected_schemas AS protected_schema
           JOIN pg_proc AS routine
             ON routine.pronamespace=protected_schema.oid
          WHERE has_function_privilege(
            subject::name,
            routine.oid,
            'EXECUTE'
          )
       ),
       mismatch AS (
         (
           SELECT subject,kind,object_oid,privilege FROM actual
           EXCEPT
           SELECT subject,kind,object_oid,privilege FROM expected
         )
         UNION ALL
         (
           SELECT subject,kind,object_oid,privilege FROM expected
           EXCEPT
           SELECT subject,kind,object_oid,privilege FROM actual
         )
       )
       SELECT
         NOT EXISTS (SELECT 1 FROM mismatch)
         AND NOT EXISTS (
           SELECT 1 FROM expected WHERE object_oid IS NULL
         ) AS privileges_safe`,
      [JSON.stringify(expected), protectedSchemas],
    );
    if (result.rows[0]?.privileges_safe !== true) {
      fail(
        "INVALID_CONFIGURATION",
        "C16 PostgreSQL pool has unexpected effective privileges.",
      );
    }
  }

  async function connect(pool, requiredRole) {
    let client;
    try {
      client = await pool.connect();
      const result = await client.query(
        `WITH identity AS (
           SELECT current_user AS current_name,
                  session_user AS session_name
         )
         SELECT identity.*,
                active.rolsuper AS current_super,
                active.rolbypassrls AS current_bypassrls,
                active.rolcreatedb AS current_createdb,
                active.rolcreaterole AS current_createrole,
                active.rolreplication AS current_replication,
                login.rolsuper AS session_super,
                login.rolbypassrls AS session_bypassrls,
                login.rolcreatedb AS session_createdb,
                login.rolcreaterole AS session_createrole,
                login.rolreplication AS session_replication,
                ARRAY(
                  SELECT candidate.rolname::text
                    FROM pg_roles AS candidate
                   WHERE candidate.rolname <> identity.current_name
                     AND pg_has_role(
                       identity.current_name,
                       candidate.oid,
                       'MEMBER'
                     )
                   ORDER BY candidate.rolname
                ) AS current_memberships,
                ARRAY(
                  SELECT candidate.rolname::text
                    FROM pg_roles AS candidate
                   WHERE candidate.rolname <> identity.session_name
                     AND pg_has_role(
                       identity.session_name,
                       candidate.oid,
                       'MEMBER'
                     )
                   ORDER BY candidate.rolname
                ) AS session_memberships,
                ARRAY(
                  SELECT candidate.rolname::text
                    FROM pg_roles AS candidate
                   WHERE candidate.rolname <> identity.current_name
                     AND pg_has_role(
                       identity.current_name,
                       candidate.oid,
                       'USAGE'
                     )
                   ORDER BY candidate.rolname
                ) AS current_usages,
                ARRAY(
                  SELECT candidate.rolname::text
                    FROM pg_roles AS candidate
                   WHERE candidate.rolname <> identity.session_name
                     AND pg_has_role(
                       identity.session_name,
                       candidate.oid,
                       'USAGE'
                     )
                   ORDER BY candidate.rolname
                ) AS session_usages
           FROM identity
           JOIN pg_roles AS active
             ON active.rolname=identity.current_name
           JOIN pg_roles AS login
             ON login.rolname=identity.session_name`,
      );
      const row = result.rows[0];
      const exactRole = (roles) =>
        Array.isArray(roles) &&
        roles.length === 1 &&
        roles[0] === requiredRole;
      if (
        !row ||
        !roleCapabilities[requiredRole] ||
        row.current_super ||
        row.current_bypassrls ||
        row.current_createdb ||
        row.current_createrole ||
        row.current_replication ||
        row.session_super ||
        row.session_bypassrls ||
        row.session_createdb ||
        row.session_createrole ||
        row.session_replication ||
        !exactRole(row.current_memberships) ||
        !exactRole(row.session_memberships) ||
        !exactRole(row.current_usages) ||
        !exactRole(row.session_usages)
      ) {
        client.release(
          new Error("C16 rejected an unsafe PostgreSQL role."),
        );
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C16 PostgreSQL pool role is unsafe.",
        );
      }
      await assertExpectedPrivileges(client, requiredRole);
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C16 could not verify the PostgreSQL role."),
        );
      }
      throw error;
    }
  }

  async function assertScopeCleared(client) {
    const result = await client.query(
      `SELECT current_setting('aios.tenant_id', true) AS tenant_id,
              current_setting('aios.tenant_kind', true) AS tenant_kind,
              current_setting('aios.lifecycle_version', true)
                AS lifecycle_version,
              current_setting('aios.correlation_id', true)
                AS correlation_id,
              current_setting('aios.decision_id', true) AS decision_id,
              current_setting('aios.evidence_ref', true) AS evidence_ref,
              current_setting('aios.policy_version', true)
                AS policy_version,
              current_setting('aios.scope_signature', true)
                AS scope_signature`,
    );
    if (
      Object.values(result.rows[0]).some(
        (value) => value !== null && value !== "",
      )
    ) {
      fail(
        "CONNECTION_CONTEXT_LEAK",
        "C16 PostgreSQL connection retained Tenant scope.",
      );
    }
  }

  async function signScope(scope, backendPid, transactionId) {
    const client = await connect(scopePool, "aios_c07_scope_runtime");
    try {
      const nonce = randomUUID();
      const result = await client.query(
        `SELECT ${signer}(
           $1,$2,$3,$4,$5,$6,$7,$8,$9::xid8,15,$10::uuid
         ) AS signed_scope`,
        [
          scope.tenantId,
          scope.tenantKind,
          scope.lifecycleVersion,
          scope.correlationId,
          scope.decisionId,
          scope.evidenceRef,
          scope.policyVersion,
          backendPid,
          transactionId,
          nonce,
        ],
      );
      const signed = json(result.rows[0]?.signed_scope);
      if (
        !/^[a-f0-9]{64}$/.test(signed?.signature ?? "") ||
        !Number.isSafeInteger(Number(signed?.expires_epoch_ms))
      ) {
        fail("TENANT_SCOPE_VIOLATION", "C07 scope signature is invalid.");
      }
      return {
        nonce,
        expiresEpochMs: String(signed.expires_epoch_ms),
        signature: signed.signature,
      };
    } finally {
      client.release();
    }
  }

  async function runScoped(pool, role, scope, begin, reducer) {
    const client = await connect(pool, role);
    let started = false;
    let discard = false;
    try {
      await client.query(begin);
      started = true;
      const transaction = await client.query(
        `SELECT pg_backend_pid() AS backend_pid,
                pg_current_xact_id()::text AS transaction_id`,
      );
      const backendPid = transaction.rows[0].backend_pid;
      const transactionId = transaction.rows[0].transaction_id;
      const signed = await signScope(scope, backendPid, transactionId);
      await client.query(
        `SELECT set_config('aios.tenant_id',$1,true),
                set_config('aios.tenant_kind',$2,true),
                set_config('aios.lifecycle_version',$3,true),
                set_config('aios.correlation_id',$4,true),
                set_config('aios.decision_id',$5,true),
                set_config('aios.evidence_ref',$6,true),
                set_config('aios.policy_version',$7,true),
                set_config('aios.backend_pid',$8,true),
                set_config('aios.transaction_id',$9,true),
                set_config('aios.expires_epoch_ms',$10,true),
                set_config('aios.scope_nonce',$11,true),
                set_config('aios.scope_signature',$12,true)`,
        [
          scope.tenantId,
          scope.tenantKind,
          String(scope.lifecycleVersion),
          scope.correlationId,
          scope.decisionId,
          scope.evidenceRef,
          scope.policyVersion,
          String(backendPid),
          transactionId,
          signed.expiresEpochMs,
          signed.nonce,
          signed.signature,
        ],
      );
      const acquired = await client.query(
        `SELECT ${fence}() AS acquired`,
      );
      if (acquired.rows[0]?.acquired !== true) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C16 PostgreSQL Tenant fence was not acquired.",
        );
      }
      const value = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return value;
    } catch (error) {
      if (started) await rollback(client);
      try {
        await assertScopeCleared(client);
      } catch {
        discard = true;
      }
      throw error;
    } finally {
      client.release(
        discard
          ? new Error("C16 discarded a scoped PostgreSQL connection.")
          : undefined,
      );
    }
  }

  async function insertAudit(client, audit) {
    assertAuditIntent(audit);
    await client.query(
      `INSERT INTO ${table("audit_intent")} (
         tenant_id,tenant_kind,intent_id,event_type,subject_id,
         intent_sha256,metadata,created_at
       ) VALUES (
         $1,'SYNTHETIC',$2,$3,$4,$5,$6::jsonb,$7::timestamptz
       )`,
      [
        audit.tenantId,
        audit.intentId,
        audit.eventType,
        audit.subjectId,
        audit.intentSha256,
        JSON.stringify(audit),
        audit.occurredAt,
      ],
    );
    await client.query(
      `INSERT INTO ${table("audit_outbox")} (
         tenant_id,tenant_kind,intent_id,status,attempt_count,
         lease_version,leased_by,lease_until,available_at,published_at,
         last_error_code,created_at
       ) VALUES (
         $1,'SYNTHETIC',$2,'PENDING',0,0,NULL,NULL,
         $3::timestamptz,NULL,NULL,$3::timestamptz
       )`,
      [audit.tenantId, audit.intentId, audit.occurredAt],
    );
  }

  async function saveConfirmation(scope, command) {
    const trusted = validateScope(scope);
    validateConfirmationCommand(command);
    if (
      command.tenantId !== trusted.tenantId ||
      command.confirmation.tenantLifecycleVersion !==
        trusted.lifecycleVersion
    ) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C16 confirmation escaped Tenant scope.",
      );
    }
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await runScoped(
          runtimePool,
          "aios_c16_runtime",
          trusted,
          "BEGIN ISOLATION LEVEL SERIALIZABLE",
          async (client) => {
            const prior = await client.query(
              `SELECT request_hash,confirmation
                 FROM ${table("tool_confirmation")}
                WHERE tenant_id=$1 AND idempotency_key=$2`,
              [trusted.tenantId, command.idempotencyKey],
            );
            if (prior.rowCount === 1) {
              if (prior.rows[0].request_hash !== command.requestHash) {
                fail(
                  "IDEMPOTENCY_CONFLICT",
                  "C16 idempotency key was reused.",
                );
              }
              return confirmationFromRow(prior.rows[0], true);
            }
            await insertAudit(client, command.auditIntent);
            const value = command.confirmation;
            const result = await client.query(
              `INSERT INTO ${table("tool_confirmation")} (
                 tenant_id,tenant_kind,tenant_lifecycle_version,
                 confirmation_id,
                 confirmation_sha256,operation_id,catalog_version,
                 catalog_sha256,adapter_version,normalized_param_sha256,
                 identity_sha256,authorization_sha256,
                 authorization_authority_sha256,confirmation,
                 idempotency_key,request_hash,created_audit_intent_id,
                 confirmed_at,expires_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
                 $13::jsonb,$14,$15,$16,$17::timestamptz,
                 $18::timestamptz
               )
               RETURNING confirmation`,
              [
                value.tenantId,
                value.tenantLifecycleVersion,
                value.confirmationId,
                value.confirmationSha256,
                value.operationId,
                value.catalogVersion,
                value.catalogSha256,
                value.adapterVersion,
                value.normalizedParamSha256,
                value.identitySha256,
                value.authorizationSha256,
                value.authorizationAuthoritySha256,
                JSON.stringify(value),
                command.idempotencyKey,
                command.requestHash,
                command.auditIntent.intentId,
                value.confirmedAt,
                value.expiresAt,
              ],
            );
            return confirmationFromRow(result.rows[0]);
          },
        );
      } catch (error) {
        if (
          attempt < maxSerializableRetries &&
          (RETRYABLE.has(error?.code) || error?.code === "23505")
        ) {
          continue;
        }
        throw databaseFailure(error);
      }
    }
  }

  async function getConfirmation(scope, confirmationId) {
    const trusted = validateScope(scope);
    try {
      return await runScoped(
        runtimePool,
        "aios_c16_runtime",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `SELECT confirmation
               FROM ${table("tool_confirmation")}
              WHERE tenant_id=$1 AND confirmation_id=$2`,
            [trusted.tenantId, confirmationId],
          );
          return confirmationFromRow(result.rows[0], false, true);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function beginExecution(scope, command) {
    const trusted = validateScope(scope);
    validateCallCommand(command);
    if (
      command.tenantId !== trusted.tenantId ||
      command.call.tenantLifecycleVersion !== trusted.lifecycleVersion
    ) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C16 execution escaped Tenant scope.",
      );
    }
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await runScoped(
          runtimePool,
          "aios_c16_runtime",
          trusted,
          "BEGIN ISOLATION LEVEL SERIALIZABLE",
          async (client) => {
            const prior = await client.query(
              `SELECT request_hash,status,call,result,receipt,
                      last_error_code,completed_at
                 FROM ${table("tool_call")}
                WHERE tenant_id=$1 AND idempotency_key=$2`,
              [trusted.tenantId, command.idempotencyKey],
            );
            if (prior.rowCount === 1) {
              if (prior.rows[0].request_hash !== command.requestHash) {
                fail(
                  "IDEMPOTENCY_CONFLICT",
                  "C16 idempotency key was reused.",
                );
              }
              return callFromRow(
                prior.rows[0],
                prior.rows[0].status === "SUCCEEDED",
              );
            }
            const value = command.call;
            await client.query(
              `SELECT pg_advisory_xact_lock(
                 hashtextextended($1 || '|' || $2,0)
               )`,
              [trusted.tenantId, value.confirmationId],
            );
            const confirmation = await client.query(
              `SELECT confirmation_sha256,operation_id,catalog_version,
                      catalog_sha256,adapter_version,
                      normalized_param_sha256,identity_sha256,
                      tenant_lifecycle_version,
                      authorization_authority_sha256,
                      expires_at > statement_timestamp() AS active
               FROM ${table("tool_confirmation")}
                WHERE tenant_id=$1 AND confirmation_id=$2`,
              [trusted.tenantId, value.confirmationId],
            );
            const bound = confirmation.rows[0];
            if (
              !bound ||
              !bound.active ||
              bound.confirmation_sha256 !== value.confirmationSha256 ||
              bound.operation_id !== value.operationId ||
              bound.catalog_version !== value.catalogVersion ||
              bound.catalog_sha256 !== value.catalogSha256 ||
              bound.adapter_version !== value.adapterVersion ||
              bound.normalized_param_sha256 !==
                value.normalizedParamSha256 ||
              bound.identity_sha256 !== value.identitySha256 ||
              Number(bound.tenant_lifecycle_version) !==
                value.tenantLifecycleVersion ||
              bound.authorization_authority_sha256 !==
                value.authorizationAuthoritySha256
            ) {
              fail(
                "CONFIRMATION_TAMPERED",
                "C16 confirmation cannot authorize this call.",
              );
            }
            const result = await client.query(
              `INSERT INTO ${table("tool_call")} (
                 tenant_id,tenant_kind,tenant_lifecycle_version,
                 call_id,confirmation_id,
                 confirmation_sha256,operation_id,effect_key,call_sha256,
                 identity_sha256,authorization_sha256,
                 authorization_authority_sha256,status,call,result,receipt,
                 idempotency_key,request_hash,
                 terminal_audit_intent_id,last_error_code,started_at,
                 completed_at,updated_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
                 'STARTED',$12::jsonb,NULL,NULL,$13,$14,NULL,NULL,
                 $15::timestamptz,NULL,$15::timestamptz
               )
               RETURNING status,call,result,receipt,last_error_code,
                         completed_at`,
              [
                value.tenantId,
                value.tenantLifecycleVersion,
                value.callId,
                value.confirmationId,
                value.confirmationSha256,
                value.operationId,
                value.effectKey,
                value.callSha256,
                value.identitySha256,
                value.authorizationSha256,
                value.authorizationAuthoritySha256,
                JSON.stringify(value),
                command.idempotencyKey,
                command.requestHash,
                value.startedAt,
              ],
            );
            return callFromRow(result.rows[0]);
          },
        );
      } catch (error) {
        if (
          attempt < maxSerializableRetries &&
          (RETRYABLE.has(error?.code) || error?.code === "23505")
        ) {
          continue;
        }
        throw databaseFailure(error);
      }
    }
  }

  async function getCall(scope, callId) {
    const trusted = validateScope(scope);
    try {
      return await runScoped(
        runtimePool,
        "aios_c16_runtime",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `SELECT status,call,result,receipt,last_error_code,completed_at
               FROM ${table("tool_call")}
              WHERE tenant_id=$1 AND call_id=$2`,
            [trusted.tenantId, callId],
          );
          return callFromRow(result.rows[0], false, true);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function completeExecution(scope, command) {
    const trusted = validateScope(scope);
    assertAuditIntent(command?.auditIntent);
    if (
      typeof command?.callId !== "string" ||
      !command?.result ||
      typeof command.result !== "object" ||
      !command?.receipt ||
      command.receipt.tenantId !== trusted.tenantId ||
      command.receipt.callId !== command.callId ||
      command.receipt.resultSha256 !==
        toolGatewaySha256(command.result)
    ) {
      fail("CALL_RESULT_CONFLICT", "C16 call result is invalid.");
    }
    try {
      return await runScoped(
        toolWorkerPool,
        "aios_c16_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const selected = await client.query(
            `SELECT status,call,result,receipt,last_error_code,completed_at
               FROM ${table("tool_call")}
              WHERE tenant_id=$1 AND call_id=$2
              FOR UPDATE`,
            [trusted.tenantId, command.callId],
          );
          if (selected.rowCount !== 1) {
            fail("CALL_NOT_FOUND", "C16 call was not found.");
          }
          const current = callFromRow(
            selected.rows[0],
            false,
            true,
          );
          validateC16SyntheticCompletion({
            call: current,
            result: command.result,
            receipt: command.receipt,
          });
          if (current.status === "SUCCEEDED") {
            validateC16SyntheticCompletion({
              call: current,
              result: current.result,
              receipt: current.receipt,
            });
            if (
              toolGatewaySha256(current.result) !==
              toolGatewaySha256(command.result)
            ) {
              fail("CALL_RESULT_CONFLICT", "C16 call result changed.");
            }
            return publicCall(current, true);
          }
          if (
            command.receipt.operationId !== current.operationId ||
            command.receipt.effectKey !== current.effectKey
          ) {
            fail("CALL_RESULT_CONFLICT", "C16 call receipt is invalid.");
          }
          await insertAudit(client, command.auditIntent);
          const result = await client.query(
            `UPDATE ${table("tool_call")}
                SET status='SUCCEEDED',result=$3::jsonb,receipt=$4::jsonb,
                    terminal_audit_intent_id=$5,last_error_code=NULL,
                    completed_at=$6::timestamptz,
                    updated_at=statement_timestamp()
              WHERE tenant_id=$1 AND call_id=$2 AND status='STARTED'
              RETURNING status,call,result,receipt,last_error_code,
                        completed_at`,
            [
              trusted.tenantId,
              command.callId,
              JSON.stringify(command.result),
              JSON.stringify(command.receipt),
              command.auditIntent.intentId,
              command.completedAt,
            ],
          );
          if (result.rowCount !== 1) {
            fail("CALL_STATE_CONFLICT", "C16 call is not active.");
          }
          return callFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function failExecution(scope, command) {
    const trusted = validateScope(scope);
    if (
      typeof command?.callId !== "string" ||
      !/^[A-Z][A-Z0-9_]{0,63}$/.test(command?.errorCode ?? "")
    ) {
      fail("INVALID_INPUT", "C16 failure receipt is invalid.");
    }
    try {
      return await runScoped(
        toolWorkerPool,
        "aios_c16_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `UPDATE ${table("tool_call")}
                SET last_error_code=$3,updated_at=statement_timestamp()
              WHERE tenant_id=$1 AND call_id=$2 AND status='STARTED'
              RETURNING status,call,result,receipt,last_error_code,
                        completed_at`,
            [
              trusted.tenantId,
              command.callId,
              command.errorCode,
            ],
          );
          if (result.rowCount !== 1) {
            fail("CALL_STATE_CONFLICT", "C16 call is not active.");
          }
          return callFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  function validateLease(input) {
    if (
      typeof input?.workerId !== "string" ||
      !input.workerId ||
      !Number.isSafeInteger(input?.limit) ||
      input.limit < 1 ||
      input.limit > 100 ||
      !Number.isSafeInteger(input?.leaseDurationSeconds) ||
      input.leaseDurationSeconds < 1 ||
      input.leaseDurationSeconds > 300
    ) {
      fail("INVALID_INPUT", "C16 Outbox lease is invalid.");
    }
  }

  async function claimAudit(scope, input) {
    const trusted = validateScope(scope);
    validateLease(input);
    try {
      return await runScoped(
        auditWorkerPool,
        "aios_c16_audit_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `WITH candidates AS (
               SELECT tenant_id,intent_id
                 FROM ${table("audit_outbox")}
                WHERE tenant_id=$1
                  AND (
                    (
                      status IN ('PENDING','FAILED')
                      AND available_at <= statement_timestamp()
                    )
                    OR (
                      status='PROCESSING'
                      AND lease_until <= statement_timestamp()
                    )
                  )
                ORDER BY created_at,intent_id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
             ), claimed AS (
               UPDATE ${table("audit_outbox")} AS outbox
                  SET status='PROCESSING',
                      attempt_count=attempt_count+1,
                      lease_version=lease_version+1,
                      leased_by=$3,
                      lease_until=statement_timestamp()
                        + make_interval(secs => $4::double precision),
                      last_error_code=NULL
                 FROM candidates
                WHERE outbox.tenant_id=candidates.tenant_id
                  AND outbox.intent_id=candidates.intent_id
               RETURNING outbox.*
             )
             SELECT intent.metadata,claimed.tenant_id,claimed.tenant_kind,
                    claimed.intent_id,claimed.status AS outbox_status,
                    claimed.attempt_count,claimed.lease_version,
                    claimed.leased_by,claimed.lease_until,
                    claimed.available_at,claimed.published_at,
                    claimed.last_error_code,
                    claimed.created_at AS outbox_created_at
               FROM claimed
               JOIN ${table("audit_intent")} AS intent
                 ON intent.tenant_id=claimed.tenant_id
                AND intent.intent_id=claimed.intent_id
              ORDER BY claimed.created_at,claimed.intent_id`,
            [
              trusted.tenantId,
              input.limit,
              input.workerId,
              input.leaseDurationSeconds,
            ],
          );
          return deepFreeze(result.rows.map(auditOutboxFromRow));
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  function validateAuditMutation(input) {
    if (
      typeof input?.intentId !== "string" ||
      typeof input?.workerId !== "string" ||
      !Number.isSafeInteger(input?.leaseVersion)
    ) {
      fail("INVALID_INPUT", "C16 audit mutation is invalid.");
    }
  }

  async function completeAudit(scope, input) {
    const trusted = validateScope(scope);
    validateAuditMutation(input);
    if (input.ackIntentId !== input.intentId) {
      fail("AUDIT_ACK_MISMATCH", "C18 audit ACK is invalid.");
    }
    try {
      return await runScoped(
        auditWorkerPool,
        "aios_c16_audit_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `UPDATE ${table("audit_outbox")}
                SET status='PUBLISHED',leased_by=NULL,lease_until=NULL,
                    published_at=statement_timestamp(),
                    last_error_code=NULL
              WHERE tenant_id=$1 AND intent_id=$2
                AND status='PROCESSING'
                AND leased_by=$3 AND lease_version=$4
                AND lease_until >= statement_timestamp()
              RETURNING tenant_id,tenant_kind,intent_id,status,
                        attempt_count,lease_version,leased_by,lease_until,
                        available_at,published_at,last_error_code,created_at`,
            [
              trusted.tenantId,
              input.intentId,
              input.workerId,
              input.leaseVersion,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C16 audit lease is stale.");
          }
          return auditOutboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function failAudit(scope, input) {
    const trusted = validateScope(scope);
    validateAuditMutation(input);
    if (
      !Number.isSafeInteger(input?.retryDelaySeconds) ||
      input.retryDelaySeconds < 0 ||
      input.retryDelaySeconds > 3600 ||
      !/^[A-Z][A-Z0-9_]{0,63}$/.test(input?.errorCode ?? "")
    ) {
      fail("INVALID_INPUT", "C16 audit failure is invalid.");
    }
    try {
      return await runScoped(
        auditWorkerPool,
        "aios_c16_audit_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `UPDATE ${table("audit_outbox")}
                SET status='FAILED',leased_by=NULL,lease_until=NULL,
                    available_at=statement_timestamp()
                      + make_interval(secs => $5::double precision),
                    published_at=NULL,last_error_code=$6
              WHERE tenant_id=$1 AND intent_id=$2
                AND status='PROCESSING'
                AND leased_by=$3 AND lease_version=$4
                AND lease_until >= statement_timestamp()
              RETURNING tenant_id,tenant_kind,intent_id,status,
                        attempt_count,lease_version,leased_by,lease_until,
                        available_at,published_at,last_error_code,created_at`,
            [
              trusted.tenantId,
              input.intentId,
              input.workerId,
              input.leaseVersion,
              input.retryDelaySeconds,
              input.errorCode,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C16 audit lease is stale.");
          }
          return auditOutboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function readRecoverySnapshot(scope) {
    const trusted = validateScope(scope);
    try {
      return await runScoped(
        recoveryPool,
        "aios_c16_recovery_reader",
        trusted,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const confirmations = await client.query(
            `SELECT confirmation_id,confirmation_sha256,operation_id,
                    catalog_version,catalog_sha256,adapter_version,
                    normalized_param_sha256,identity_sha256,
                    authorization_sha256,tenant_lifecycle_version,
                    authorization_authority_sha256,
                    confirmed_at,expires_at
               FROM ${table("tool_confirmation")}
              WHERE tenant_id=$1
              ORDER BY confirmation_id`,
            [trusted.tenantId],
          );
          const calls = await client.query(
            `SELECT call_id,confirmation_id,confirmation_sha256,
                    operation_id,effect_key,call_sha256,identity_sha256,
                    authorization_sha256,tenant_lifecycle_version,
                    authorization_authority_sha256,
                    status,last_error_code,
                    started_at,completed_at
               FROM ${table("tool_call")}
              WHERE tenant_id=$1
              ORDER BY call_id`,
            [trusted.tenantId],
          );
          const outbox = await client.query(
            `SELECT tenant_id,tenant_kind,intent_id,status,attempt_count,
                    lease_version,leased_by,lease_until,available_at,
                    published_at,last_error_code,created_at
               FROM ${table("audit_outbox")}
              WHERE tenant_id=$1
              ORDER BY intent_id`,
            [trusted.tenantId],
          );
          return deepFreeze({
            tenantId: trusted.tenantId,
            confirmations: confirmations.rows.map((row) => ({
              ...row,
              tenant_lifecycle_version: safeInteger(
                row.tenant_lifecycle_version,
              ),
              confirmed_at: instant(row.confirmed_at),
              expires_at: instant(row.expires_at),
            })),
            calls: calls.rows.map((row) => ({
              ...row,
              tenant_lifecycle_version: safeInteger(
                row.tenant_lifecycle_version,
              ),
              started_at: instant(row.started_at),
              completed_at: instant(row.completed_at),
            })),
            auditOutbox: outbox.rows.map(auditOutboxFromRow),
          });
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  return Object.freeze({
    saveConfirmation,
    getConfirmation,
    beginExecution,
    getCall,
    completeExecution,
    failExecution,
    claimAudit,
    completeAudit,
    failAudit,
    readRecoverySnapshot,
  });
}
