import { randomUUID } from "node:crypto";
import {
  AuditEvidenceError,
  C18_GENESIS_HASH,
  assertValidAuditPayload,
  auditEvidenceSha256,
  computeAuditEventHash,
  createAuditCloudEvent,
  verifyAuditExport,
} from "./c18-audit-evidence.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EVENT_ID =
  /^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UTC_MILLISECOND_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const COLUMN_PRIVILEGES = new Set([
  "SELECT",
  "INSERT",
  "UPDATE",
  "REFERENCES",
]);
const MAX_OUTBOX_LEASE_SECONDS = 300;
const MAX_OUTBOX_RETRY_SECONDS = 3600;
const RETRYABLE = new Set(["40001", "40P01"]);

function fail(code, message) {
  throw new AuditEvidenceError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function exactKeys(value, fields, name) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join("\u0000") !==
      [...fields].sort().join("\u0000")
  ) {
    fail("INVALID_INPUT", `${name} is invalid.`);
  }
}

function canonicalInstant(value, field) {
  if (
    typeof value !== "string" ||
    !UTC_MILLISECOND_INSTANT.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function nonEmptyString(value, field, maxLength = 256) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > maxLength
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function positiveInteger(value, field) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function safeInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    fail("STORE_CORRUPTION", `${field} is invalid.`);
  }
  return parsed;
}

function json(value) {
  if (value === null || value === undefined) return value;
  return typeof value === "string" ? JSON.parse(value) : value;
}

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    !TENANT_ID.test(scope.tenantId ?? "") ||
    scope.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(scope.lifecycleVersion) ||
    scope.lifecycleVersion < 1
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C18 PostgreSQL scope is invalid.");
  }
  for (const [field, maximum] of [
    ["correlationId", 128],
    ["decisionId", 256],
    ["evidenceRef", 512],
    ["policyVersion", 256],
  ]) {
    nonEmptyString(scope[field], `scope.${field}`, maximum);
  }
  return scope;
}

function validateAppend(input) {
  exactKeys(
    input,
    [
      "eventId",
      "idempotencyKey",
      "requestHash",
      "payload",
      "createdAt",
    ],
    "append input",
  );
  if (!EVENT_ID.test(input.eventId ?? "")) {
    fail("INVALID_INPUT", "eventId is invalid.");
  }
  nonEmptyString(input.idempotencyKey, "idempotencyKey", 128);
  if (!SHA256.test(input.requestHash ?? "")) {
    fail("INVALID_INPUT", "requestHash is invalid.");
  }
  canonicalInstant(input.createdAt, "createdAt");
  assertValidAuditPayload(input.payload, {
    eventId: input.eventId,
    tenantId: input.payload?.tenantId,
    correlationId: input.payload?.correlationId,
    createdAt: input.createdAt,
  });
}

function validateQuery(input) {
  exactKeys(
    input,
    [
      "fromSequence",
      "toSequence",
      "fromOccurredAt",
      "toOccurredAt",
      "limit",
    ],
    "query",
  );
  positiveInteger(input.fromSequence, "fromSequence");
  positiveInteger(input.toSequence, "toSequence");
  positiveInteger(input.limit, "limit");
  canonicalInstant(input.fromOccurredAt, "fromOccurredAt");
  canonicalInstant(input.toOccurredAt, "toOccurredAt");
  if (
    input.fromSequence > input.toSequence ||
    input.limit > 500 ||
    Date.parse(input.fromOccurredAt) > Date.parse(input.toOccurredAt)
  ) {
    fail("INVALID_INPUT", "Audit query range is invalid.");
  }
}

function validateLease(input) {
  exactKeys(
    input,
    ["workerId", "leaseDurationSeconds", "limit"],
    "lease",
  );
  nonEmptyString(input.workerId, "workerId", 128);
  positiveInteger(input.leaseDurationSeconds, "leaseDurationSeconds");
  positiveInteger(input.limit, "limit");
  if (
    input.limit > 100 ||
    input.leaseDurationSeconds > MAX_OUTBOX_LEASE_SECONDS
  ) {
    fail("INVALID_INPUT", "Outbox lease is invalid.");
  }
}

function validateLeaseReceipt(input, failure = false) {
  exactKeys(
    input,
    [
      "eventId",
      "workerId",
      "leaseVersion",
      ...(failure ? ["retryDelaySeconds", "errorCode"] : []),
    ],
    "lease receipt",
  );
  if (!EVENT_ID.test(input.eventId ?? "")) {
    fail("INVALID_INPUT", "eventId is invalid.");
  }
  nonEmptyString(input.workerId, "workerId", 128);
  positiveInteger(input.leaseVersion, "leaseVersion");
  if (failure) {
    positiveInteger(input.retryDelaySeconds, "retryDelaySeconds");
    nonEmptyString(input.errorCode, "errorCode", 64);
    if (input.retryDelaySeconds > MAX_OUTBOX_RETRY_SECONDS) {
      fail("INVALID_INPUT", "retryDelaySeconds is invalid.");
    }
  }
}

function validateRetention(input) {
  exactKeys(input, ["limit"], "retention");
  positiveInteger(input.limit, "limit");
  if (input.limit > 500) {
    fail("INVALID_INPUT", "Retention limit is invalid.");
  }
}

function eventFromRow(row) {
  return {
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    eventId: row.event_id,
    sequence: safeInteger(row.sequence, "sequence"),
    previousEventHash: row.previous_event_hash,
    eventHash: row.event_hash,
    payloadSha256: row.payload_sha256,
    payload: clone(json(row.payload)),
    createdAt: iso(row.created_at),
  };
}

function eventView(record, duplicate = false) {
  return Object.freeze({
    tenantId: record.tenantId,
    tenantKind: record.tenantKind,
    eventId: record.eventId,
    sequence: record.sequence,
    previousEventHash: record.previousEventHash,
    eventHash: record.eventHash,
    payloadSha256: record.payloadSha256,
    provenanceSha256: record.payload.provenanceSha256,
    auditType: record.payload.auditType,
    retentionClass: record.payload.retentionClass,
    createdAt: record.createdAt,
    duplicate,
  });
}

function outboxFromRow(row) {
  return Object.freeze({
    eventId: row.event_id,
    event: clone(json(row.event)),
    status: row.status,
    attemptCount: safeInteger(row.attempt_count, "attemptCount"),
    leaseVersion: safeInteger(row.lease_version, "leaseVersion"),
    workerId: row.leased_by,
    leaseExpiresAt: iso(row.lease_until),
    availableAt: iso(row.available_at),
    publishedAt: iso(row.published_at),
    lastErrorCode: row.last_error_code,
  });
}

function receiptFromRow(row) {
  return Object.freeze({
    idempotencyKey: row.idempotency_key,
    requestHash: row.request_hash,
    eventId: row.event_id,
    createdAt: iso(row.created_at),
  });
}

function headFromRow(row, tenantId) {
  if (!row) {
    return {
      tenantId,
      tenantKind: "SYNTHETIC",
      lastSequence: 0,
      lastEventId: null,
      lastEventHash: C18_GENESIS_HASH,
      updatedAt: null,
    };
  }
  return {
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    lastSequence: safeInteger(row.last_sequence, "lastSequence"),
    lastEventId: row.last_event_id,
    lastEventHash: row.last_event_hash,
    updatedAt: iso(row.updated_at),
  };
}

function deliveryIntentFromRow(row) {
  return Object.freeze({
    eventId: row.event_id,
    event: clone(json(row.event)),
    retentionClass: row.retention_class,
    legalHold: row.legal_hold,
    createdAt: iso(row.created_at),
  });
}

function databaseFailure(error) {
  if (error instanceof AuditEvidenceError) return error;
  if (
    error?.constraint === "audit_event_metadata_only" ||
    error?.constraint === "audit_delivery_intent_metadata_only"
  ) {
    return new AuditEvidenceError(
      "PROHIBITED_AUDIT_BODY",
      "PostgreSQL rejected prohibited audit material.",
    );
  }
  if (
    error?.constraint?.startsWith("audit_") ||
    error?.code === "23503" ||
    error?.code === "23505"
  ) {
    return new AuditEvidenceError(
      "AUDIT_INTEGRITY_VIOLATION",
      "PostgreSQL rejected invalid audit evidence.",
    );
  }
  if (error?.code === "42501") {
    return new AuditEvidenceError(
      "FORBIDDEN",
      "PostgreSQL denied the C18 operation.",
    );
  }
  return new AuditEvidenceError(
    "STORE_UNAVAILABLE",
    "C18 PostgreSQL store is unavailable.",
  );
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // The original database error remains authoritative.
  }
}

export function createPostgresAuditEvidenceStore({
  writerPool,
  readerPool,
  outboxPool,
  recoveryPool,
  restorePool,
  retentionPool,
  scopePool,
  schema = "aios_audit",
  scopeSchema = "aios_data",
  maxSerializableRetries = 10,
}) {
  if (
    typeof writerPool?.connect !== "function" ||
    typeof readerPool?.connect !== "function" ||
    typeof outboxPool?.connect !== "function" ||
    typeof recoveryPool?.connect !== "function" ||
    typeof restorePool?.connect !== "function" ||
    typeof retentionPool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    new Set([
      writerPool,
      readerPool,
      outboxPool,
      recoveryPool,
      restorePool,
      retentionPool,
      scopePool,
    ]).size !== 7 ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C18 PostgreSQL pools are invalid.");
  }
  const table = (name) => `"${schema}"."${name}"`;
  const signer =
    `"${scopeSchema}"."issue_runtime_scope_signature"`;
  const fence = `"${scopeSchema}"."acquire_runtime_fence"`;
  const restoreTargetIsEmpty =
    `"${schema}"."restore_target_is_empty"`;
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
  const scopedCapabilities = [
    schemaCapability(scopeSchema),
    functionCapability(
      `${scopeSchema}.runtime_scope_allows(text,text)`,
    ),
    functionCapability(`${scopeSchema}.acquire_runtime_fence()`),
  ];
  const auditValidationCapabilities = [
    functionCapability(
      `${schema}.jsonb_has_exact_keys(jsonb,text[])`,
    ),
    functionCapability(
      `${schema}.metadata_string_matches(jsonb,text,integer)`,
    ),
    functionCapability(
      `${schema}.metadata_positive_integer(jsonb)`,
    ),
    functionCapability(`${schema}.metadata_shape(jsonb,text)`),
    functionCapability(`${schema}.metadata_only(jsonb)`),
  ];
  const recoveryTables = [
    "audit_head",
    "audit_event",
    "audit_delivery_intent",
    "audit_outbox",
    "audit_command_receipt",
  ];
  const roleCapabilities = {
    aios_c18_writer: [
      schemaCapability(schema),
      ...scopedCapabilities,
      ...tableCapabilities(
        `${schema}.audit_head`,
        ["SELECT", "INSERT", "UPDATE"],
      ),
      ...["audit_event", "audit_command_receipt"].flatMap((name) =>
        tableCapabilities(
          `${schema}.${name}`,
          ["SELECT", "INSERT"],
        ),
      ),
      ...["audit_delivery_intent", "audit_outbox"].flatMap((name) =>
        tableCapabilities(`${schema}.${name}`, ["INSERT"]),
      ),
      ...auditValidationCapabilities,
    ],
    aios_c18_reader: [
      schemaCapability(schema),
      ...scopedCapabilities,
      ...["audit_head", "audit_event"].flatMap((name) =>
        tableCapabilities(`${schema}.${name}`, ["SELECT"]),
      ),
    ],
    aios_c18_outbox_worker: [
      schemaCapability(schema),
      ...scopedCapabilities,
      ...tableCapabilities(
        `${schema}.audit_delivery_intent`,
        ["SELECT"],
      ),
      ...tableCapabilities(
        `${schema}.audit_outbox`,
        ["SELECT", "UPDATE"],
      ),
    ],
    aios_c18_recovery_reader: [
      schemaCapability(schema),
      ...scopedCapabilities,
      ...recoveryTables.flatMap((name) =>
        tableCapabilities(`${schema}.${name}`, ["SELECT"]),
      ),
    ],
    aios_c18_recovery_writer: [
      schemaCapability(schema),
      ...scopedCapabilities,
      ...recoveryTables.flatMap((name) =>
        tableCapabilities(`${schema}.${name}`, ["INSERT"]),
      ),
      ...auditValidationCapabilities,
      functionCapability(`${schema}.restore_target_is_empty(text)`),
    ],
    aios_c18_retention_worker: [
      schemaCapability(schema),
      ...scopedCapabilities,
      ...tableCapabilities(
        `${schema}.audit_delivery_intent`,
        ["SELECT"],
      ),
      ...tableCapabilities(
        `${schema}.audit_outbox`,
        ["SELECT", "DELETE"],
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
      fail("INVALID_CONFIGURATION", "C18 PostgreSQL role is unknown.");
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
                  WHEN 'sequence' THEN to_regclass("objectName")::oid::text
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
       column_privileges(privilege) AS (
         VALUES ('SELECT'),('INSERT'),('UPDATE'),('REFERENCES')
       ),
       sequence_privileges(privilege) AS (
         VALUES ('SELECT'),('UPDATE'),('USAGE')
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
         SELECT subject,'sequence',relation.oid::text,privilege
           FROM identity_subjects
           CROSS JOIN protected_schemas AS protected_schema
           JOIN pg_class AS relation
             ON relation.relnamespace=protected_schema.oid
            AND relation.relkind='S'
           CROSS JOIN sequence_privileges
          WHERE has_sequence_privilege(
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
        "C18 PostgreSQL pool has unexpected effective privileges.",
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
          new Error("C18 rejected an unsafe PostgreSQL role."),
        );
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C18 PostgreSQL pool role is unsafe.",
        );
      }
      await assertExpectedPrivileges(client, requiredRole);
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C18 could not verify the PostgreSQL role."),
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
        "C18 PostgreSQL connection retained Tenant scope.",
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

  async function runScoped(pool, requiredRole, scope, begin, reducer) {
    const client = await connect(pool, requiredRole);
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
          "C18 PostgreSQL Tenant fence was not acquired.",
        );
      }
      const result = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return result;
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
          ? new Error("C18 discarded a scoped PostgreSQL connection.")
          : undefined,
      );
    }
  }

  async function append(scope, input) {
    const trusted = validateScope(scope);
    validateAppend(input);
    if (
      input.payload.tenantId !== trusted.tenantId ||
      input.payload.tenantKind !== "SYNTHETIC" ||
      input.payload.correlationId !== trusted.correlationId
    ) {
      fail("TENANT_SCOPE_VIOLATION", "Audit payload escaped Tenant scope.");
    }
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await runScoped(
          writerPool,
          "aios_c18_writer",
          trusted,
          "BEGIN",
          async (client) => {
            await client.query(
              `INSERT INTO ${table("audit_head")} (
                 tenant_id,tenant_kind,last_sequence,last_event_id,
                 last_event_hash,updated_at
               ) VALUES ($1,'SYNTHETIC',0,NULL,$2,$3::timestamptz)
               ON CONFLICT (tenant_id) DO NOTHING`,
              [trusted.tenantId, C18_GENESIS_HASH, input.createdAt],
            );
            const headResult = await client.query(
              `SELECT *
                 FROM ${table("audit_head")}
                WHERE tenant_id=$1
                FOR UPDATE`,
              [trusted.tenantId],
            );
            if (headResult.rowCount !== 1) {
              fail(
                "AUDIT_INTEGRITY_VIOLATION",
                "Tenant Audit Head is missing.",
              );
            }
            const head = headResult.rows[0];
            const receipt = await client.query(
              `SELECT receipt.request_hash,event.*
                 FROM ${table("audit_command_receipt")} AS receipt
                 JOIN ${table("audit_event")} AS event
                   ON event.tenant_id=receipt.tenant_id
                  AND event.event_id=receipt.event_id
                WHERE receipt.tenant_id=$1
                  AND receipt.idempotency_key=$2`,
              [trusted.tenantId, input.idempotencyKey],
            );
            if (receipt.rowCount === 1) {
              if (receipt.rows[0].request_hash !== input.requestHash) {
                fail(
                  "IDEMPOTENCY_CONFLICT",
                  "Idempotency key was reused.",
                );
              }
              return eventView(eventFromRow(receipt.rows[0]), true);
            }
            const record = {
              tenantId: trusted.tenantId,
              tenantKind: "SYNTHETIC",
              eventId: input.eventId,
              sequence: safeInteger(head.last_sequence, "lastSequence") + 1,
              previousEventHash: head.last_event_hash,
              eventHash: null,
              payloadSha256: auditEvidenceSha256(input.payload),
              payload: clone(input.payload),
              createdAt: input.createdAt,
            };
            record.eventHash = computeAuditEventHash(record);
            const outboxEvent = createAuditCloudEvent(record);
            await client.query(
              `INSERT INTO ${table("audit_event")} (
                 tenant_id,tenant_kind,event_id,sequence,
                 previous_event_hash,event_hash,payload_sha256,payload,
                 created_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7::jsonb,$8::timestamptz
               )`,
              [
                record.tenantId,
                record.eventId,
                record.sequence,
                record.previousEventHash,
                record.eventHash,
                record.payloadSha256,
                JSON.stringify(record.payload),
                record.createdAt,
              ],
            );
            await client.query(
              `INSERT INTO ${table("audit_delivery_intent")} (
                 tenant_id,tenant_kind,event_id,event,retention_class,
                 legal_hold,created_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3::jsonb,'AUDIT_7Y',false,
                 $4::timestamptz
               )`,
              [
                record.tenantId,
                record.eventId,
                JSON.stringify(outboxEvent),
                record.createdAt,
              ],
            );
            await client.query(
              `INSERT INTO ${table("audit_outbox")} (
                 tenant_id,tenant_kind,event_id,status,
                 attempt_count,lease_version,leased_by,lease_until,
                 available_at,published_at,last_error_code,created_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,'PENDING',
                 0,0,NULL,NULL,$3::timestamptz,NULL,NULL,$3::timestamptz
               )`,
              [
                record.tenantId,
                record.eventId,
                record.createdAt,
              ],
            );
            await client.query(
              `INSERT INTO ${table("audit_command_receipt")} (
                 tenant_id,tenant_kind,idempotency_key,request_hash,
                 event_id,created_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3,$4,$5::timestamptz
               )`,
              [
                record.tenantId,
                input.idempotencyKey,
                input.requestHash,
                record.eventId,
                record.createdAt,
              ],
            );
            const advanced = await client.query(
              `UPDATE ${table("audit_head")}
                  SET last_sequence=$2,
                      last_event_id=$3,
                      last_event_hash=$4,
                      updated_at=$5::timestamptz
                WHERE tenant_id=$1
                  AND last_sequence=$2-1
               RETURNING tenant_id`,
              [
                record.tenantId,
                record.sequence,
                record.eventId,
                record.eventHash,
                record.createdAt,
              ],
            );
            if (advanced.rowCount !== 1) {
              fail(
                "AUDIT_INTEGRITY_VIOLATION",
                "Tenant Audit Head did not advance.",
              );
            }
            return eventView(record);
          },
        );
      } catch (error) {
        if (
          RETRYABLE.has(error?.code) &&
          attempt < maxSerializableRetries
        ) {
          continue;
        }
        throw databaseFailure(error);
      }
    }
  }

  async function query(scope, input) {
    const trusted = validateScope(scope);
    validateQuery(input);
    try {
      return await runScoped(
        readerPool,
        "aios_c18_reader",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `SELECT *
               FROM ${table("audit_event")}
              WHERE tenant_id=$1
                AND sequence BETWEEN $2 AND $3
                AND created_at BETWEEN $4::timestamptz
                                   AND $5::timestamptz
              ORDER BY sequence
              LIMIT $6`,
            [
              trusted.tenantId,
              input.fromSequence,
              input.toSequence,
              input.fromOccurredAt,
              input.toOccurredAt,
              input.limit,
            ],
          );
          return Object.freeze(result.rows.map(eventFromRow));
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function exportChain(scope) {
    const trusted = validateScope(scope);
    try {
      return await runScoped(
        recoveryPool,
        "aios_c18_recovery_reader",
        trusted,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const headResult = await client.query(
            `SELECT *
               FROM ${table("audit_head")}
              WHERE tenant_id=$1`,
            [trusted.tenantId],
          );
          const eventsResult = await client.query(
            `SELECT *
               FROM ${table("audit_event")}
              WHERE tenant_id=$1
              ORDER BY sequence`,
            [trusted.tenantId],
          );
          const intentsResult = await client.query(
            `SELECT intent.*
               FROM ${table("audit_delivery_intent")} AS intent
               JOIN ${table("audit_event")} AS event
                 ON event.tenant_id=intent.tenant_id
                AND event.event_id=intent.event_id
              WHERE intent.tenant_id=$1
              ORDER BY event.sequence`,
            [trusted.tenantId],
          );
          const receiptsResult = await client.query(
            `SELECT receipt.*
               FROM ${table("audit_command_receipt")} AS receipt
               JOIN ${table("audit_event")} AS event
                 ON event.tenant_id=receipt.tenant_id
                AND event.event_id=receipt.event_id
              WHERE receipt.tenant_id=$1
              ORDER BY event.sequence`,
            [trusted.tenantId],
          );
          const outboxResult = await client.query(
            `SELECT outbox.*,intent.event
               FROM ${table("audit_outbox")} AS outbox
               JOIN ${table("audit_delivery_intent")} AS intent
                 ON intent.tenant_id=outbox.tenant_id
                AND intent.event_id=outbox.event_id
               JOIN ${table("audit_event")} AS event
                 ON event.tenant_id=outbox.tenant_id
                AND event.event_id=outbox.event_id
              WHERE outbox.tenant_id=$1
                AND outbox.status <> 'PUBLISHED'
              ORDER BY event.sequence`,
            [trusted.tenantId],
          );
          const body = {
            schemaVersion: "c18-audit-recovery.v1",
            tenantId: trusted.tenantId,
            tenantKind: "SYNTHETIC",
            head: headFromRow(headResult.rows[0], trusted.tenantId),
            events: eventsResult.rows.map(eventFromRow),
            deliveryIntents: intentsResult.rows.map(
              deliveryIntentFromRow,
            ),
            receipts: receiptsResult.rows.map(receiptFromRow),
            outbox: outboxResult.rows.map(outboxFromRow),
          };
          const document = {
            ...body,
            recoverySha256: auditEvidenceSha256(body),
          };
          verifyAuditExport(document);
          return document;
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function restoreChain(scope, document) {
    const trusted = validateScope(scope);
    const verification = verifyAuditExport(document);
    if (document.tenantId !== trusted.tenantId) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "Audit recovery bundle escaped Tenant scope.",
      );
    }
    try {
      await runScoped(
        restorePool,
        "aios_c18_recovery_writer",
        trusted,
        "BEGIN",
        async (client) => {
          const target = await client.query(
            `SELECT ${restoreTargetIsEmpty}($1) AS is_empty`,
            [trusted.tenantId],
          );
          if (target.rows[0]?.is_empty !== true) {
            fail(
              "RECOVERY_TARGET_NOT_EMPTY",
              "C18 recovery target Tenant is not empty.",
            );
          }
          for (const record of document.events) {
            await client.query(
              `INSERT INTO ${table("audit_event")} (
                 tenant_id,tenant_kind,event_id,sequence,
                 previous_event_hash,event_hash,payload_sha256,payload,
                 created_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7::jsonb,
                 $8::timestamptz
               )`,
              [
                record.tenantId,
                record.eventId,
                record.sequence,
                record.previousEventHash,
                record.eventHash,
                record.payloadSha256,
                JSON.stringify(record.payload),
                record.createdAt,
              ],
            );
          }
          for (const intent of document.deliveryIntents) {
            await client.query(
              `INSERT INTO ${table("audit_delivery_intent")} (
                 tenant_id,tenant_kind,event_id,event,retention_class,
                 legal_hold,created_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3::jsonb,$4,$5,$6::timestamptz
               )`,
              [
                trusted.tenantId,
                intent.eventId,
                JSON.stringify(intent.event),
                intent.retentionClass,
                intent.legalHold,
                intent.createdAt,
              ],
            );
          }
          for (const receipt of document.receipts) {
            await client.query(
              `INSERT INTO ${table("audit_command_receipt")} (
                 tenant_id,tenant_kind,idempotency_key,request_hash,
                 event_id,created_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3,$4,$5::timestamptz
               )`,
              [
                trusted.tenantId,
                receipt.idempotencyKey,
                receipt.requestHash,
                receipt.eventId,
                receipt.createdAt,
              ],
            );
          }
          for (const entry of document.outbox) {
            const interrupted = entry.status === "PROCESSING";
            await client.query(
              `INSERT INTO ${table("audit_outbox")} (
                 tenant_id,tenant_kind,event_id,status,attempt_count,
                 lease_version,leased_by,lease_until,available_at,
                 published_at,last_error_code,created_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3,$4,$5,NULL,NULL,
                 CASE
                   WHEN $6::boolean THEN statement_timestamp()
                   ELSE $7::timestamptz
                 END,
                 NULL,$8,$9::timestamptz
               )`,
              [
                trusted.tenantId,
                entry.eventId,
                interrupted ? "FAILED" : entry.status,
                entry.attemptCount,
                entry.leaseVersion,
                interrupted,
                entry.availableAt,
                interrupted ? "RECOVERY_REQUEUE" : entry.lastErrorCode,
                document.events.find(
                  (record) => record.eventId === entry.eventId,
                ).createdAt,
              ],
            );
          }
          if (document.head.lastSequence > 0) {
            await client.query(
              `INSERT INTO ${table("audit_head")} (
                 tenant_id,tenant_kind,last_sequence,last_event_id,
                 last_event_hash,updated_at
               ) VALUES (
                 $1,'SYNTHETIC',$2,$3,$4,$5::timestamptz
               )`,
              [
                trusted.tenantId,
                document.head.lastSequence,
                document.head.lastEventId,
                document.head.lastEventHash,
                document.head.updatedAt,
              ],
            );
          }
        },
      );
      return Object.freeze({
        ...verification,
        restored: true,
      });
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function claimOutbox(scope, input) {
    const trusted = validateScope(scope);
    validateLease(input);
    try {
      return await runScoped(
        outboxPool,
        "aios_c18_outbox_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `WITH candidates AS (
               SELECT tenant_id,event_id
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
                ORDER BY created_at,event_id
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
                  AND outbox.event_id=candidates.event_id
               RETURNING outbox.*
             )
             SELECT claimed.*,intent.event
               FROM claimed
               JOIN ${table("audit_delivery_intent")} AS intent
                 ON intent.tenant_id=claimed.tenant_id
                AND intent.event_id=claimed.event_id
              ORDER BY claimed.created_at,claimed.event_id`,
            [
              trusted.tenantId,
              input.limit,
              input.workerId,
              input.leaseDurationSeconds,
            ],
          );
          return Object.freeze(result.rows.map(outboxFromRow));
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function completeOutbox(scope, input) {
    const trusted = validateScope(scope);
    validateLeaseReceipt(input);
    try {
      return await runScoped(
        outboxPool,
        "aios_c18_outbox_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `WITH completed AS (
               UPDATE ${table("audit_outbox")}
                  SET status='PUBLISHED',
                      leased_by=NULL,
                      lease_until=NULL,
                      last_error_code=NULL,
                      published_at=statement_timestamp()
                WHERE tenant_id=$1
                  AND event_id=$2
                  AND leased_by=$3
                  AND lease_version=$4
                  AND lease_until >= statement_timestamp()
                  AND status='PROCESSING'
               RETURNING *
             )
             SELECT completed.*,intent.event
               FROM completed
               JOIN ${table("audit_delivery_intent")} AS intent
                 ON intent.tenant_id=completed.tenant_id
                AND intent.event_id=completed.event_id`,
            [
              trusted.tenantId,
              input.eventId,
              input.workerId,
              input.leaseVersion,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C18 Outbox lease is stale.");
          }
          return outboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function failOutbox(scope, input) {
    const trusted = validateScope(scope);
    validateLeaseReceipt(input, true);
    try {
      return await runScoped(
        outboxPool,
        "aios_c18_outbox_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `WITH failed AS (
               UPDATE ${table("audit_outbox")}
                  SET status='FAILED',
                      leased_by=NULL,
                      lease_until=NULL,
                      available_at=statement_timestamp()
                        + make_interval(secs => $5::double precision),
                      published_at=NULL,
                      last_error_code=$6
                WHERE tenant_id=$1
                  AND event_id=$2
                  AND leased_by=$3
                  AND lease_version=$4
                  AND lease_until >= statement_timestamp()
                  AND status='PROCESSING'
               RETURNING *
             )
             SELECT failed.*,intent.event
               FROM failed
               JOIN ${table("audit_delivery_intent")} AS intent
                 ON intent.tenant_id=failed.tenant_id
                AND intent.event_id=failed.event_id`,
            [
              trusted.tenantId,
              input.eventId,
              input.workerId,
              input.leaseVersion,
              input.retryDelaySeconds,
              input.errorCode,
            ],
          );
          if (result.rowCount !== 1) {
            fail("STALE_OUTBOX_LEASE", "C18 Outbox lease is stale.");
          }
          return outboxFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function purgePublishedOutbox(scope, input) {
    const trusted = validateScope(scope);
    validateRetention(input);
    try {
      return await runScoped(
        retentionPool,
        "aios_c18_retention_worker",
        trusted,
        "BEGIN",
        async (client) => {
          const result = await client.query(
            `WITH candidates AS (
               SELECT outbox.tenant_id,outbox.event_id
                 FROM ${table("audit_outbox")} AS outbox
                 JOIN ${table("audit_delivery_intent")} AS intent
                   ON intent.tenant_id=outbox.tenant_id
                  AND intent.event_id=outbox.event_id
                WHERE outbox.tenant_id=$1
                  AND outbox.status='PUBLISHED'
                  AND outbox.published_at <=
                    statement_timestamp() - interval '30 days'
                  AND intent.legal_hold=false
                ORDER BY outbox.published_at,outbox.event_id
                LIMIT $2
             )
             DELETE FROM ${table("audit_outbox")} AS outbox
              USING candidates
              WHERE outbox.tenant_id=candidates.tenant_id
                AND outbox.event_id=candidates.event_id
             RETURNING outbox.event_id`,
            [trusted.tenantId, input.limit],
          );
          return Object.freeze(
            result.rows.map((row) => row.event_id).sort(),
          );
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  return Object.freeze({
    append,
    query,
    exportChain,
    restoreChain,
    claimOutbox,
    completeOutbox,
    failOutbox,
    purgePublishedOutbox,
  });
}
