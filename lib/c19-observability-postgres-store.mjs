import { randomUUID } from "node:crypto";
import { ObservabilityError } from "./c19-observability.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;
const TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function fail(code, message) {
  throw new ObservabilityError(code, message);
}

function clone(value) {
  return structuredClone(value);
}

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function integer(value, field) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    fail("STORE_CORRUPTION", `${field} is invalid.`);
  }
  return parsed;
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    !TENANT_ID.test(scope.tenantId ?? "") ||
    scope.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(scope.lifecycleVersion) ||
    scope.lifecycleVersion < 1
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C19 PostgreSQL scope is invalid.");
  }
  for (const [field, maximum] of [
    ["correlationId", 128],
    ["decisionId", 256],
    ["evidenceRef", 512],
    ["policyVersion", 256],
  ]) {
    if (
      typeof scope[field] !== "string" ||
      scope[field].length < 1 ||
      scope[field].length > maximum
    ) {
      fail("TENANT_SCOPE_VIOLATION", "C19 PostgreSQL scope is invalid.");
    }
  }
  return scope;
}

function signalFromRow(row) {
  return {
    signalId: row.signal_id,
    tenantId: row.tenant_id,
    principalId: row.principal_id,
    taskRef: row.task_ref,
    traceId: row.trace_id,
    spanId: row.span_id,
    parentSpanId: row.parent_span_id,
    module: row.module,
    operation: row.operation,
    signalType: row.signal_type,
    status: row.status,
    durationMs:
      row.duration_ms === null
        ? null
        : integer(row.duration_ms, "durationMs"),
    errorCode: row.error_code,
    occurredAt: iso(row.occurred_at),
  };
}

function reservationFromRow(row) {
  const base = {
    reservationId: row.reservation_id,
    tenantId: row.tenant_id,
    principalId: row.principal_id,
    planRef: row.plan_ref,
    taskRef: row.task_ref,
    dimensionType: row.dimension_type,
    resourceRef: row.resource_ref,
    meterType: row.meter_type,
    unit: row.unit,
    maxQuantity: integer(row.max_quantity, "maxQuantity"),
    rateVersion: row.rate_version,
    unitRateMicros: integer(
      row.unit_rate_micros,
      "unitRateMicros",
    ),
    reservedCostMicros: integer(
      row.reserved_cost_micros,
      "reservedCostMicros",
    ),
    quotaPeriod: row.quota_period,
    catalogVersion: row.catalog_version,
    catalogSha256: row.catalog_sha256,
    traceId: row.reserve_trace_id,
    spanId: row.reserve_span_id,
    parentSpanId: row.reserve_parent_span_id,
    inputTraceparent: row.reserve_input_traceparent,
    state: row.state,
    createdAt: iso(row.created_at),
  };
  if (row.state === "RESERVED") return base;
  if (row.state === "RELEASED") {
    return {
      ...base,
      releasedAt: iso(row.released_at),
    };
  }
  return {
    ...base,
    receiptRef: row.receipt_ref,
    meterKey: row.meter_key,
    quantity: integer(row.quantity, "quantity"),
    bookedCostMicros: integer(
      row.booked_cost_micros,
      "bookedCostMicros",
    ),
    supplierCostMicros: integer(
      row.supplier_cost_micros,
      "supplierCostMicros",
    ),
    varianceMicros: integer(row.variance_micros, "varianceMicros"),
    sourceModule: row.source_module,
    sourceEvidenceRef: row.source_evidence_ref,
    sourceEvidenceSha256: row.source_evidence_sha256,
    auditEvidenceRef: row.audit_evidence_ref,
    auditEvidenceSha256: row.audit_evidence_sha256,
    traceId: row.settle_trace_id,
    spanId: row.settle_span_id,
    parentSpanId: row.settle_parent_span_id,
    inputTraceparent: row.settle_input_traceparent,
    occurredAt: iso(row.occurred_at),
    settledAt: iso(row.settled_at),
  };
}

function ledgerFromRow(row) {
  return {
    eventId: row.event_id,
    tenantId: row.tenant_id,
    principalId: row.principal_id,
    eventType: row.event_type,
    reservationId: row.reservation_id,
    taskRef: row.task_ref,
    dimensionType: row.dimension_type,
    resourceRef: row.resource_ref,
    meterType: row.meter_type,
    unit: row.unit,
    quantity: integer(row.quantity, "quantity"),
    costMicros: integer(row.cost_micros, "costMicros"),
    rateVersion: row.rate_version,
    receiptRef: row.receipt_ref,
    meterKey: row.meter_key,
    supplierCostMicros:
      row.supplier_cost_micros === null
        ? null
        : integer(row.supplier_cost_micros, "supplierCostMicros"),
    varianceMicros:
      row.variance_micros === null
        ? null
        : integer(row.variance_micros, "varianceMicros"),
    traceId: row.trace_id,
    spanId: row.span_id,
    occurredAt: iso(row.occurred_at),
  };
}

function quotaAccountFromRow(row) {
  return {
    tenantId: row.tenant_id,
    principalId: row.principal_id,
    quotaScope: row.quota_scope,
    quotaSubjectId: row.quota_subject_id,
    quotaPeriod: row.quota_period,
    quotaLimitMicros: integer(
      row.quota_limit_micros,
      "quotaLimitMicros",
    ),
    quotaThresholdBasisPoints: integer(
      row.quota_threshold_basis_points,
      "quotaThresholdBasisPoints",
    ),
    reservedMicros: integer(row.reserved_micros, "reservedMicros"),
    consumedMicros: integer(row.consumed_micros, "consumedMicros"),
    deniedCount: integer(row.denied_count, "deniedCount"),
  };
}

function storedTraceContext(row, phase) {
  return {
    traceparent: row[`${phase}_output_traceparent`],
    tracestate: row[`${phase}_tracestate`],
  };
}

async function lockIdempotency(
  client,
  tenantId,
  operation,
  idempotencyKey,
) {
  await client.query(
    `SELECT pg_catalog.pg_advisory_xact_lock(
       pg_catalog.hashtextextended($1,0)
     )`,
    [`${tenantId}|${operation}|${idempotencyKey}`],
  );
}

function databaseFailure(error) {
  if (error instanceof ObservabilityError) return error;
  if (error?.code === "42501") {
    return new ObservabilityError(
      "FORBIDDEN",
      "PostgreSQL denied the C19 operation.",
    );
  }
  if (error?.code === "23505") {
    if (error.constraint?.includes("meter_key")) {
      return new ObservabilityError(
        "DUPLICATE_METER",
        "Meter evidence was already settled.",
      );
    }
    return new ObservabilityError(
      "IDEMPOTENCY_CONFLICT",
      "PostgreSQL rejected a duplicate C19 command.",
    );
  }
  if (
    error?.code === "23000" ||
    error?.code === "23503" ||
    error?.code === "23514"
  ) {
    return new ObservabilityError(
      "USAGE_INTEGRITY_VIOLATION",
      "PostgreSQL rejected invalid C19 state.",
    );
  }
  return new ObservabilityError(
    "STORE_UNAVAILABLE",
    "C19 PostgreSQL store is unavailable.",
  );
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
    return true;
  } catch {
    // Preserve the original database failure.
    return false;
  }
}

export function createPostgresObservabilityStore({
  writerPool,
  readerPool,
  scopePool,
  schema = "aios_observability",
  scopeSchema = "aios_data",
}) {
  if (
    typeof writerPool?.connect !== "function" ||
    typeof readerPool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    new Set([writerPool, readerPool, scopePool]).size !== 3 ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema)
  ) {
    fail("INVALID_CONFIGURATION", "C19 PostgreSQL pools are invalid.");
  }
  const table = (name) => `"${schema}"."${name}"`;
  const signer =
    `"${scopeSchema}"."issue_runtime_scope_signature"`;
  const fence = `"${scopeSchema}"."acquire_runtime_fence"`;
  const relationCapabilities = (name, privileges) =>
    privileges.flatMap((privilege) => [
      `table|${schema}.${name}|${privilege}`,
      ...["SELECT", "INSERT", "UPDATE", "REFERENCES"].includes(
        privilege,
      )
        ? [`column|${schema}.${name}|${privilege}`]
        : [],
    ]);
  const commonScopeCapabilities = [
    `schema|${scopeSchema}|USAGE`,
    `function|${scopeSchema}.runtime_scope_allows(text,text)|EXECUTE`,
    `function|${scopeSchema}.acquire_runtime_fence()|EXECUTE`,
  ];
  const expectedCapabilities = {
    aios_c19_writer: [
      `schema|${schema}|USAGE`,
      ...commonScopeCapabilities,
      ...relationCapabilities("telemetry_signal", [
        "SELECT",
        "INSERT",
      ]),
      ...relationCapabilities("usage_ledger", [
        "INSERT",
      ]),
      ...relationCapabilities("quota_account", [
        "SELECT",
        "INSERT",
        "UPDATE",
      ]),
      ...relationCapabilities("quota_reservation", [
        "SELECT",
        "INSERT",
        "UPDATE",
      ]),
    ],
    aios_c19_reader: [
      `schema|${schema}|USAGE`,
      ...commonScopeCapabilities,
      ...[
        "telemetry_signal",
        "usage_ledger",
        "quota_account",
        "quota_reservation",
      ].flatMap((name) => relationCapabilities(name, ["SELECT"])),
    ],
    aios_c07_scope_runtime: [
      `schema|${scopeSchema}|USAGE`,
      `function|${scopeSchema}.issue_runtime_scope_signature(text,text,bigint,text,text,text,text,integer,xid8,integer,uuid)|EXECUTE`,
    ],
  };

  async function assertExactCapabilities(client, requiredRole) {
    const expected = expectedCapabilities[requiredRole];
    if (!expected) {
      fail(
        "INVALID_CONFIGURATION",
        "C19 PostgreSQL role is unknown.",
      );
    }
    const result = await client.query(
      `WITH protected_schemas AS (
         SELECT oid,nspname
           FROM pg_namespace
          WHERE nspname ~ '^aios_'
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
       )
       SELECT kind || '|' || object_name || '|' || privilege
                AS capability
         FROM (
           SELECT 'schema'::text AS kind,
                  protected.nspname::text AS object_name,
                  privilege
             FROM protected_schemas protected
             CROSS JOIN schema_privileges
            WHERE has_schema_privilege(
              current_user,
              protected.oid,
              privilege
            )
           UNION ALL
           SELECT 'table',
                  (protected.nspname || '.' || relation.relname)::text,
                  privilege
             FROM protected_schemas protected
             JOIN pg_class relation
               ON relation.relnamespace=protected.oid
              AND relation.relkind IN ('r','p','v','m','f')
             CROSS JOIN relation_privileges
            WHERE has_table_privilege(
              current_user,
              relation.oid,
              privilege
            )
           UNION ALL
           SELECT 'column',
                  (protected.nspname || '.' || relation.relname)::text,
                  privilege
             FROM protected_schemas protected
             JOIN pg_class relation
               ON relation.relnamespace=protected.oid
              AND relation.relkind IN ('r','p','v','m','f')
             CROSS JOIN column_privileges
            WHERE has_any_column_privilege(
              current_user,
              relation.oid,
              privilege
            )
           UNION ALL
           SELECT 'sequence',
                  (protected.nspname || '.' || relation.relname)::text,
                  privilege
             FROM protected_schemas protected
             JOIN pg_class relation
               ON relation.relnamespace=protected.oid
              AND relation.relkind='S'
             CROSS JOIN sequence_privileges
            WHERE has_sequence_privilege(
              current_user,
              relation.oid,
              privilege
            )
           UNION ALL
           SELECT 'function',
                  routine.oid::regprocedure::text AS object_name,
                  'EXECUTE'
             FROM protected_schemas protected
             JOIN pg_proc routine
               ON routine.pronamespace=protected.oid
            WHERE has_function_privilege(
              current_user,
              routine.oid,
              'EXECUTE'
            )
         ) capabilities
        ORDER BY capability`,
    );
    const actual = result.rows.map((row) => row.capability).sort();
    if (
      actual.join("\u0000") !==
      [...expected].sort().join("\u0000")
    ) {
      fail(
        "INVALID_CONFIGURATION",
        "C19 PostgreSQL pool has unexpected effective privileges.",
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
                EXISTS (
                  SELECT 1 FROM pg_auth_members membership
                   WHERE membership.member=active.oid
                     AND membership.admin_option
                ) AS current_admin_option,
                EXISTS (
                  SELECT 1 FROM pg_auth_members membership
                   WHERE membership.member=login.oid
                     AND membership.admin_option
                ) AS session_admin_option,
                ARRAY(
                  SELECT role.rolname::text
                    FROM pg_roles role
                   WHERE role.rolname <> identity.current_name
                     AND pg_has_role(
                       identity.current_name,
                       role.oid,
                       'MEMBER'
                     )
                   ORDER BY role.rolname
                ) AS current_memberships,
                ARRAY(
                  SELECT role.rolname::text
                    FROM pg_roles role
                   WHERE role.rolname <> identity.session_name
                     AND pg_has_role(
                       identity.session_name,
                       role.oid,
                       'MEMBER'
                     )
                   ORDER BY role.rolname
                ) AS session_memberships,
                ARRAY(
                  SELECT role.rolname::text
                    FROM pg_roles role
                   WHERE role.rolname <> identity.current_name
                     AND pg_has_role(
                       identity.current_name,
                       role.oid,
                       'USAGE'
                     )
                   ORDER BY role.rolname
                ) AS current_usages,
                ARRAY(
                  SELECT role.rolname::text
                    FROM pg_roles role
                   WHERE role.rolname <> identity.session_name
                     AND pg_has_role(
                       identity.session_name,
                       role.oid,
                       'USAGE'
                     )
                   ORDER BY role.rolname
                ) AS session_usages
           FROM identity
           JOIN pg_roles active
             ON active.rolname=identity.current_name
           JOIN pg_roles login
             ON login.rolname=identity.session_name`,
      );
      const row = result.rows[0];
      const exactRole = (roles) =>
        Array.isArray(roles) &&
        roles.length === 1 &&
        roles[0] === requiredRole;
      if (
        !row ||
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
        row.current_admin_option ||
        row.session_admin_option ||
        !exactRole(row.current_memberships) ||
        !exactRole(row.session_memberships) ||
        !exactRole(row.current_usages) ||
        !exactRole(row.session_usages)
      ) {
        client.release(
          new Error("C19 rejected an unsafe PostgreSQL role."),
        );
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C19 PostgreSQL pool role is unsafe.",
        );
      }
      await assertExactCapabilities(client, requiredRole);
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C19 could not verify the PostgreSQL role."),
        );
      }
      throw error;
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
      const signed = result.rows[0]?.signed_scope;
      if (
        !/^[0-9a-f]{64}$/.test(signed?.signature ?? "") ||
        !Number.isSafeInteger(Number(signed?.expires_epoch_ms))
      ) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C07 scope signature is invalid.",
        );
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
              current_setting('aios.backend_pid', true) AS backend_pid,
              current_setting('aios.transaction_id', true)
                AS transaction_id,
              current_setting('aios.expires_epoch_ms', true)
                AS expires_epoch_ms,
              current_setting('aios.scope_nonce', true) AS scope_nonce,
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
        "C19 PostgreSQL connection retained Tenant scope.",
      );
    }
  }

  async function runScoped(
    pool,
    requiredRole,
    scopeValue,
    begin,
    work,
  ) {
    const scope = validateScope(scopeValue);
    const client = await connect(pool, requiredRole);
    let started = false;
    let discard = false;
    try {
      await assertScopeCleared(client);
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
          "C19 PostgreSQL Tenant fence was not acquired.",
        );
      }
      const result = await work(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return result;
    } catch (error) {
      if (started && !(await rollback(client))) discard = true;
      if (
        error instanceof ObservabilityError &&
        error.code === "CONNECTION_CONTEXT_LEAK"
      ) {
        discard = true;
      }
      throw databaseFailure(error);
    } finally {
      client.release(
        discard
          ? new Error("C19 discarded a connection with leaked scope.")
          : undefined,
      );
    }
  }

  async function appendSignal(scope, command) {
    return runScoped(
      writerPool,
      "aios_c19_writer",
      scope,
      "BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE",
      async (client) => {
        await lockIdempotency(
          client,
          scope.tenantId,
          "SIGNAL",
          command.idempotencyKey,
        );
        const prior = await client.query(
          `SELECT * FROM ${table("telemetry_signal")}
            WHERE tenant_id=$1 AND idempotency_key=$2`,
          [scope.tenantId, command.idempotencyKey],
        );
        if (prior.rows[0]) {
          if (prior.rows[0].request_hash !== command.requestHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Idempotency key was reused with another request.",
            );
          }
          const signal = signalFromRow(prior.rows[0]);
          const traceFlags =
            command.traceContext.traceparent.slice(-2);
          return {
            signal,
            traceContext: {
              traceparent:
                `00-${signal.traceId}-${signal.spanId}-${traceFlags}`,
              tracestate: command.traceContext.tracestate,
            },
            metricLabels: clone(command.metricLabels),
          };
        }
        const signal = command.signal;
        const result = await client.query(
          `INSERT INTO ${table("telemetry_signal")} (
             tenant_id,tenant_kind,signal_id,idempotency_key,
             request_hash,principal_id,task_ref,trace_id,span_id,parent_span_id,
             module,operation,signal_type,status,duration_ms,error_code,
             occurred_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
             $13,$14,$15,$16
           ) RETURNING *`,
          [
            scope.tenantId,
            signal.signalId,
            command.idempotencyKey,
            command.requestHash,
            signal.principalId,
            signal.taskRef,
            signal.traceId,
            signal.spanId,
            signal.parentSpanId,
            signal.module,
            signal.operation,
            signal.signalType,
            signal.status,
            signal.durationMs,
            signal.errorCode,
            signal.occurredAt,
          ],
        );
        return {
          signal: signalFromRow(result.rows[0]),
          traceContext: clone(command.traceContext),
          metricLabels: clone(command.metricLabels),
        };
      },
    );
  }

  async function querySignals(scope, range) {
    return runScoped(
      readerPool,
      "aios_c19_reader",
      scope,
      "BEGIN ISOLATION LEVEL REPEATABLE READ",
      async (client) => {
        const result = await client.query(
          `SELECT * FROM ${table("telemetry_signal")}
            WHERE tenant_id=$1
              AND occurred_at >= $2
              AND occurred_at < $3
            ORDER BY occurred_at,signal_id`,
          [
            scope.tenantId,
            range.fromOccurredAt,
            range.toOccurredAt,
          ],
        );
        return result.rows.map(signalFromRow);
      },
    );
  }

  async function reserve(scope, command) {
    return runScoped(
      writerPool,
      "aios_c19_writer",
      scope,
      "BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE",
      async (client) => {
        await lockIdempotency(
          client,
          scope.tenantId,
          "RESERVE",
          command.idempotencyKey,
        );
        const prior = await client.query(
          `SELECT * FROM ${table("quota_reservation")}
            WHERE tenant_id=$1 AND reserve_idempotency_key=$2`,
          [scope.tenantId, command.idempotencyKey],
        );
        if (prior.rows[0]) {
          if (
            prior.rows[0].reserve_request_hash !== command.requestHash
          ) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Idempotency key was reused with another request.",
            );
          }
          return {
            reservation: reservationFromRow(prior.rows[0]),
            traceContext: storedTraceContext(
              prior.rows[0],
              "reserve",
            ),
          };
        }
        const definitions = command.quotaAccounts;
        await client.query(
          `INSERT INTO ${table("quota_account")} (
             tenant_id,tenant_kind,quota_scope,quota_subject_id,
             principal_id,quota_period,quota_limit_micros,
             quota_threshold_basis_points,reserved_micros,
             consumed_micros,denied_count,updated_at
           ) VALUES
             ($1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,0,0,0,$8),
             ($1,'SYNTHETIC',$9,$10,$11,$5,$12,$13,0,0,0,$8)
           ON CONFLICT (
             tenant_id,quota_scope,quota_subject_id,quota_period
           ) DO NOTHING`,
          [
            scope.tenantId,
            definitions[0].quotaScope,
            definitions[0].quotaSubjectId,
            definitions[0].principalId,
            command.quotaPeriod,
            definitions[0].quotaLimitMicros,
            definitions[0].quotaThresholdBasisPoints,
            command.reservation.createdAt,
            definitions[1].quotaScope,
            definitions[1].quotaSubjectId,
            definitions[1].principalId,
            definitions[1].quotaLimitMicros,
            definitions[1].quotaThresholdBasisPoints,
          ],
        );
        const accountRows = await client.query(
          `SELECT * FROM ${table("quota_account")}
            WHERE tenant_id=$1
              AND quota_period=$2
              AND (
                (quota_scope=$3 AND quota_subject_id=$4)
                OR (quota_scope=$5 AND quota_subject_id=$6)
              )
            ORDER BY quota_scope,quota_subject_id
            FOR UPDATE`,
          [
            scope.tenantId,
            command.quotaPeriod,
            definitions[0].quotaScope,
            definitions[0].quotaSubjectId,
            definitions[1].quotaScope,
            definitions[1].quotaSubjectId,
          ],
        );
        const accounts = accountRows.rows.map(quotaAccountFromRow);
        if (
          accounts.length !== 2 ||
          accounts.some((account) => {
            const definition = definitions.find(
              (candidate) =>
                candidate.quotaScope === account.quotaScope &&
                candidate.quotaSubjectId === account.quotaSubjectId,
            );
            return (
              !definition ||
              account.principalId !== definition.principalId ||
              account.quotaLimitMicros !==
                definition.quotaLimitMicros ||
              account.quotaThresholdBasisPoints !==
                definition.quotaThresholdBasisPoints
            );
          })
        ) {
          fail(
            "QUOTA_CONFIGURATION_MISMATCH",
            "Quota configuration changed.",
          );
        }
        const denied = accounts.filter(
          (account) =>
            account.reservedMicros +
              account.consumedMicros +
              command.reservation.reservedCostMicros >
            account.quotaLimitMicros,
        );
        if (denied.length > 0) {
          const deniedScopes = denied.map(
            (account) => account.quotaScope,
          );
          for (const account of denied) {
            const updated = await client.query(
              `UPDATE ${table("quota_account")}
                  SET denied_count=denied_count + 1,
                      updated_at=$5
                WHERE tenant_id=$1
                  AND quota_period=$2
                  AND quota_scope=$3
                  AND quota_subject_id=$4`,
              [
                scope.tenantId,
                command.quotaPeriod,
                account.quotaScope,
                account.quotaSubjectId,
                command.reservation.createdAt,
              ],
            );
            if (updated.rowCount !== 1) {
              fail(
                "QUOTA_CONFIGURATION_MISMATCH",
                "Denied quota account is incomplete.",
              );
            }
          }
          return { denied: true, deniedScopes };
        }
        const account = await client.query(
          `UPDATE ${table("quota_account")}
              SET reserved_micros =
                    reserved_micros + $3,
                  updated_at=$4
            WHERE tenant_id=$1
              AND quota_period=$2
              AND (
                (quota_scope=$5 AND quota_subject_id=$6)
                OR (quota_scope=$7 AND quota_subject_id=$8)
              )
          RETURNING quota_scope`,
          [
            scope.tenantId,
            command.quotaPeriod,
            command.reservation.reservedCostMicros,
            command.reservation.createdAt,
            definitions[0].quotaScope,
            definitions[0].quotaSubjectId,
            definitions[1].quotaScope,
            definitions[1].quotaSubjectId,
          ],
        );
        if (account.rowCount !== 2) {
          fail(
            "QUOTA_CONFIGURATION_MISMATCH",
            "Quota accounts are incomplete.",
          );
        }
        const reservation = command.reservation;
        const inserted = await client.query(
          `INSERT INTO ${table("quota_reservation")} (
             tenant_id,tenant_kind,reservation_id,principal_id,
             reserve_idempotency_key,reserve_request_hash,
             plan_ref,task_ref,dimension_type,resource_ref,meter_type,
             unit,max_quantity,rate_version,unit_rate_micros,
             reserved_cost_micros,quota_period,catalog_version,
             catalog_sha256,reserve_trace_id,reserve_span_id,
             reserve_parent_span_id,reserve_input_traceparent,
             reserve_output_traceparent,reserve_tracestate,state,
             created_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
             $13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,
             'RESERVED',$25
           ) RETURNING *`,
          [
            scope.tenantId,
            reservation.reservationId,
            reservation.principalId,
            command.idempotencyKey,
            command.requestHash,
            reservation.planRef,
            reservation.taskRef,
            reservation.dimensionType,
            reservation.resourceRef,
            reservation.meterType,
            reservation.unit,
            reservation.maxQuantity,
            reservation.rateVersion,
            reservation.unitRateMicros,
            reservation.reservedCostMicros,
            reservation.quotaPeriod,
            reservation.catalogVersion,
            reservation.catalogSha256,
            reservation.traceId,
            reservation.spanId,
            reservation.parentSpanId,
            reservation.inputTraceparent,
            command.traceContext.traceparent,
            command.traceContext.tracestate,
            reservation.createdAt,
          ],
        );
        const event = command.ledgerEvent;
        await client.query(
          `INSERT INTO ${table("usage_ledger")} (
             tenant_id,tenant_kind,event_id,event_type,reservation_id,
             principal_id,task_ref,dimension_type,resource_ref,meter_type,unit,
             quantity,cost_micros,rate_version,receipt_ref,meter_key,
             supplier_cost_micros,variance_micros,trace_id,span_id,
             occurred_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
             $13,$14,$15,$16,$17,$18,$19,$20
           )`,
          [
            scope.tenantId,
            event.eventId,
            event.eventType,
            event.reservationId,
            event.principalId,
            event.taskRef,
            event.dimensionType,
            event.resourceRef,
            event.meterType,
            event.unit,
            event.quantity,
            event.costMicros,
            event.rateVersion,
            event.receiptRef,
            event.meterKey,
            event.supplierCostMicros,
            event.varianceMicros,
            event.traceId,
            event.spanId,
            event.occurredAt,
          ],
        );
        return {
          reservation: reservationFromRow(inserted.rows[0]),
          traceContext: clone(command.traceContext),
        };
      },
    );
  }

  async function release(scope, command) {
    return runScoped(
      writerPool,
      "aios_c19_writer",
      scope,
      "BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE",
      async (client) => {
        await lockIdempotency(
          client,
          scope.tenantId,
          "RELEASE",
          command.idempotencyKey,
        );
        const prior = await client.query(
          `SELECT * FROM ${table("quota_reservation")}
            WHERE tenant_id=$1 AND release_idempotency_key=$2`,
          [scope.tenantId, command.idempotencyKey],
        );
        if (prior.rows[0]) {
          if (
            prior.rows[0].release_request_hash !== command.requestHash
          ) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Idempotency key was reused with another request.",
            );
          }
          return {
            release: reservationFromRow(prior.rows[0]),
            traceContext: storedTraceContext(
              prior.rows[0],
              "release",
            ),
          };
        }
        const locked = await client.query(
          `SELECT * FROM ${table("quota_reservation")}
            WHERE tenant_id=$1 AND reservation_id=$2
            FOR UPDATE`,
          [scope.tenantId, command.release.reservationId],
        );
        const reservation = locked.rows[0];
        if (!reservation || reservation.state !== "RESERVED") {
          fail(
            "RESERVATION_NOT_RELEASABLE",
            "Reservation is not releasable.",
          );
        }
        if (
          reservation.principal_id !== command.release.principalId ||
          command.release.releasedAt < iso(reservation.created_at)
        ) {
          fail(
            "SYNTHETIC_FIXTURE_MISMATCH",
            "Release does not match its reservation.",
          );
        }
        const account = await client.query(
          `UPDATE ${table("quota_account")}
              SET reserved_micros =
                    reserved_micros - $3,
                  updated_at=$4
            WHERE tenant_id=$1
              AND quota_period=$2
              AND (
                (quota_scope='TENANT' AND quota_subject_id=$1)
                OR (
                  quota_scope='PRINCIPAL'
                  AND quota_subject_id=$5
                )
              )
          RETURNING quota_scope`,
          [
            scope.tenantId,
            reservation.quota_period,
            integer(
              reservation.reserved_cost_micros,
              "reservedCostMicros",
            ),
            command.release.releasedAt,
            command.release.principalId,
          ],
        );
        if (account.rowCount !== 2) {
          fail(
            "RESERVATION_NOT_RELEASABLE",
            "Quota accounts are incomplete.",
          );
        }
        const updated = await client.query(
          `UPDATE ${table("quota_reservation")}
              SET state='RELEASED',
                  release_idempotency_key=$3,
                  release_request_hash=$4,
                  release_output_traceparent=$5,
                  release_tracestate=$6,
                  released_at=$7
            WHERE tenant_id=$1 AND reservation_id=$2
          RETURNING *`,
          [
            scope.tenantId,
            command.release.reservationId,
            command.idempotencyKey,
            command.requestHash,
            command.traceContext.traceparent,
            command.traceContext.tracestate,
            command.release.releasedAt,
          ],
        );
        const event = {
          eventId: command.release.eventId,
          tenantId: scope.tenantId,
          principalId: reservation.principal_id,
          eventType: "QUOTA_RELEASED",
          reservationId: reservation.reservation_id,
          taskRef: reservation.task_ref,
          dimensionType: reservation.dimension_type,
          resourceRef: reservation.resource_ref,
          meterType: reservation.meter_type,
          unit: reservation.unit,
          quantity: integer(
            reservation.max_quantity,
            "maxQuantity",
          ),
          costMicros: integer(
            reservation.reserved_cost_micros,
            "reservedCostMicros",
          ),
          rateVersion: reservation.rate_version,
          receiptRef: null,
          meterKey: null,
          supplierCostMicros: null,
          varianceMicros: null,
          traceId: command.release.traceId,
          spanId: command.release.spanId,
          occurredAt: command.release.releasedAt,
        };
        await client.query(
          `INSERT INTO ${table("usage_ledger")} (
             tenant_id,tenant_kind,event_id,event_type,reservation_id,
             principal_id,task_ref,dimension_type,resource_ref,meter_type,unit,
             quantity,cost_micros,rate_version,receipt_ref,meter_key,
             supplier_cost_micros,variance_micros,trace_id,span_id,
             occurred_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
             $13,$14,$15,$16,$17,$18,$19,$20
           )`,
          [
            scope.tenantId,
            event.eventId,
            event.eventType,
            event.reservationId,
            event.principalId,
            event.taskRef,
            event.dimensionType,
            event.resourceRef,
            event.meterType,
            event.unit,
            event.quantity,
            event.costMicros,
            event.rateVersion,
            event.receiptRef,
            event.meterKey,
            event.supplierCostMicros,
            event.varianceMicros,
            event.traceId,
            event.spanId,
            event.occurredAt,
          ],
        );
        return {
          release: reservationFromRow(updated.rows[0]),
          traceContext: clone(command.traceContext),
        };
      },
    );
  }

  async function settle(scope, command) {
    return runScoped(
      writerPool,
      "aios_c19_writer",
      scope,
      "BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE",
      async (client) => {
        await lockIdempotency(
          client,
          scope.tenantId,
          "SETTLE",
          command.idempotencyKey,
        );
        const prior = await client.query(
          `SELECT * FROM ${table("quota_reservation")}
            WHERE tenant_id=$1 AND settle_idempotency_key=$2`,
          [scope.tenantId, command.idempotencyKey],
        );
        if (prior.rows[0]) {
          if (
            prior.rows[0].settle_request_hash !== command.requestHash
          ) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Idempotency key was reused with another request.",
            );
          }
          return {
            settlement: reservationFromRow(prior.rows[0]),
            traceContext: storedTraceContext(
              prior.rows[0],
              "settle",
            ),
          };
        }
        const locked = await client.query(
          `SELECT * FROM ${table("quota_reservation")}
            WHERE tenant_id=$1 AND reservation_id=$2
            FOR UPDATE`,
          [
            scope.tenantId,
            command.settlement.reservationId,
          ],
        );
        const reservation = locked.rows[0];
        if (!reservation || reservation.state !== "RESERVED") {
          fail(
            "RESERVATION_NOT_SETTLEABLE",
            "Reservation is not settleable.",
          );
        }
        if (
          reservation.principal_id !==
            command.settlement.principalId ||
          reservation.plan_ref !== command.settlement.planRef ||
          command.settlement.quantity >
            integer(reservation.max_quantity, "maxQuantity") ||
          command.settlement.bookedCostMicros >
            integer(
              reservation.reserved_cost_micros,
              "reservedCostMicros",
            )
        ) {
          fail(
            "SYNTHETIC_FIXTURE_MISMATCH",
            "Receipt does not match its reservation.",
          );
        }
        const account = await client.query(
          `UPDATE ${table("quota_account")}
              SET reserved_micros =
                    reserved_micros - $3,
                  consumed_micros =
                    consumed_micros + $4,
                  updated_at=$5
            WHERE tenant_id=$1
              AND quota_period=$2
              AND (
                (quota_scope='TENANT' AND quota_subject_id=$1)
                OR (
                  quota_scope='PRINCIPAL'
                  AND quota_subject_id=$6
                )
              )
          RETURNING quota_scope`,
          [
            scope.tenantId,
            reservation.quota_period,
            integer(
              reservation.reserved_cost_micros,
              "reservedCostMicros",
            ),
            command.settlement.bookedCostMicros,
            command.settlement.settledAt,
            command.settlement.principalId,
          ],
        );
        if (account.rowCount !== 2) {
          fail(
            "RESERVATION_NOT_SETTLEABLE",
            "Quota accounts are incomplete.",
          );
        }
        const settlement = command.settlement;
        const updated = await client.query(
          `UPDATE ${table("quota_reservation")}
              SET state='SETTLED',
                  settle_idempotency_key=$3,
                  settle_request_hash=$4,
                  receipt_ref=$5,
                  meter_key=$6,
                  quantity=$7,
                  booked_cost_micros=$8,
                  supplier_cost_micros=$9,
                  variance_micros=$10,
                  source_module=$11,
                  source_evidence_ref=$12,
                  source_evidence_sha256=$13,
                  audit_evidence_ref=$14,
                  audit_evidence_sha256=$15,
                  settle_trace_id=$16,
                  settle_span_id=$17,
                  settle_parent_span_id=$18,
                  settle_input_traceparent=$19,
                  settle_output_traceparent=$20,
                  settle_tracestate=$21,
                  occurred_at=$22,
                  settled_at=$23
            WHERE tenant_id=$1 AND reservation_id=$2
          RETURNING *`,
          [
            scope.tenantId,
            settlement.reservationId,
            command.idempotencyKey,
            command.requestHash,
            settlement.receiptRef,
            settlement.meterKey,
            settlement.quantity,
            settlement.bookedCostMicros,
            settlement.supplierCostMicros,
            settlement.varianceMicros,
            settlement.sourceModule,
            settlement.sourceEvidenceRef,
            settlement.sourceEvidenceSha256,
            settlement.auditEvidenceRef,
            settlement.auditEvidenceSha256,
            settlement.traceId,
            settlement.spanId,
            settlement.parentSpanId,
            settlement.inputTraceparent,
            command.traceContext.traceparent,
            command.traceContext.tracestate,
            settlement.occurredAt,
            settlement.settledAt,
          ],
        );
        const event = command.ledgerEvent;
        await client.query(
          `INSERT INTO ${table("usage_ledger")} (
             tenant_id,tenant_kind,event_id,event_type,reservation_id,
             principal_id,task_ref,dimension_type,resource_ref,meter_type,unit,
             quantity,cost_micros,rate_version,receipt_ref,meter_key,
             supplier_cost_micros,variance_micros,trace_id,span_id,
             occurred_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
             $13,$14,$15,$16,$17,$18,$19,$20
           )`,
          [
            scope.tenantId,
            event.eventId,
            event.eventType,
            event.reservationId,
            event.principalId,
            event.taskRef,
            event.dimensionType,
            event.resourceRef,
            event.meterType,
            event.unit,
            event.quantity,
            event.costMicros,
            event.rateVersion,
            event.receiptRef,
            event.meterKey,
            event.supplierCostMicros,
            event.varianceMicros,
            event.traceId,
            event.spanId,
            event.occurredAt,
          ],
        );
        return {
          settlement: reservationFromRow(updated.rows[0]),
          traceContext: clone(command.traceContext),
        };
      },
    );
  }

  async function queryUsage(scope, range) {
    return runScoped(
      readerPool,
      "aios_c19_reader",
      scope,
      "BEGIN ISOLATION LEVEL REPEATABLE READ",
      async (client) => {
        const ledger = await client.query(
          `SELECT * FROM ${table("usage_ledger")}
            WHERE tenant_id=$1
              AND occurred_at >= $2
              AND occurred_at < $3
            ORDER BY occurred_at,event_id`,
          [
            scope.tenantId,
            range.fromOccurredAt,
            range.toOccurredAt,
          ],
        );
        const ledgerEvents = ledger.rows.map(ledgerFromRow);
        const settlements = ledgerEvents
          .filter((event) => event.eventType === "USAGE_SETTLED")
          .map((event) => ({
            tenantId: event.tenantId,
            principalId: event.principalId,
            taskRef: event.taskRef,
            dimensionType: event.dimensionType,
            resourceRef: event.resourceRef,
            meterType: event.meterType,
            unit: event.unit,
            rateVersion: event.rateVersion,
            quantity: event.quantity,
            bookedCostMicros: event.costMicros,
            supplierCostMicros: event.supplierCostMicros,
            varianceMicros: event.varianceMicros,
          }));
        return {
          ledgerEvents,
          settlements,
        };
      },
    );
  }

  async function queryQuota(scope, query) {
    return runScoped(
      readerPool,
      "aios_c19_reader",
      scope,
      "BEGIN ISOLATION LEVEL REPEATABLE READ",
      async (client) => {
        const result = await client.query(
          `SELECT * FROM ${table("quota_account")}
            WHERE tenant_id=$1
              AND quota_period=$2
              AND (
                quota_scope='TENANT'
                OR (
                  quota_scope='PRINCIPAL'
                  AND principal_id=$3
                )
              )
            ORDER BY quota_scope,quota_subject_id`,
          [scope.tenantId, query.quotaPeriod, query.principalId],
        );
        return result.rows.map(quotaAccountFromRow);
      },
    );
  }

  return Object.freeze({
    appendSignal,
    querySignals,
    reserve,
    release,
    settle,
    queryUsage,
    queryQuota,
  });
}
