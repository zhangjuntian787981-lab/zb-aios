import { randomUUID } from "node:crypto";
import {
  PersonalMemoryError,
  validatePersonalMemoryHumanConsentEvidence,
} from "./c09-personal-memory.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/;
const ROLE_NAMES = Object.freeze([
  "aios_c09_runtime",
  "aios_c07_scope_runtime",
  "aios_c09_scope_runtime",
  "aios_c09_retention_runtime",
]);
const RETRYABLE = new Set(["40001", "40P01"]);
const GENERATED_ID_CONSTRAINTS = new Set([
  "personal_memory_pkey",
  "memory_event_pkey",
  "conversation_checkpoint_pkey",
]);

function fail(code, message) {
  throw new PersonalMemoryError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function json(value) {
  return typeof value === "string" ? JSON.parse(value) : clone(value);
}

function memoryFromRow(row) {
  if (!row) return null;
  return {
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    memoryId: row.memory_id,
    principalId: row.principal_id,
    state: row.state,
    category: row.category,
    content: row.content,
    contentSha256: row.content_sha256,
    sourceRef: row.source_ref,
    expiresAt: iso(row.expires_at),
    version: Number(row.version),
    terminalReason: row.terminal_reason,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function profileFromRow(row) {
  if (!row) return null;
  return {
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    principalId: row.principal_id,
    state: row.state,
    version: Number(row.version),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function checkpointFromRow(row) {
  if (!row) return null;
  return {
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    checkpointId: row.checkpoint_id,
    principalId: row.principal_id,
    threadRef: row.thread_ref,
    stateRef: row.state_ref,
    stateSha256: row.state_sha256,
    memoryIds: clone(row.memory_ids),
    version: Number(row.version),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function requireHumanConsent(envelope, contentSha256, purpose) {
  const evidence = envelope.humanConsentEvidence;
  if (
    !evidence ||
    evidence.tenantId !== envelope.tenantId ||
    evidence.humanPrincipalId !== envelope.principalId ||
    evidence.memoryId !== envelope.memoryId ||
    evidence.expectedVersion !== envelope.expectedVersion ||
    evidence.contentSha256 !== contentSha256 ||
    evidence.purpose !== purpose ||
    evidence.consumedAt !== envelope.now ||
    Date.parse(evidence.expiresAt) <= Date.parse(envelope.now)
  ) {
    fail(
      "HUMAN_CONSENT_BINDING_MISMATCH",
      "Stored action does not match consumed Human consent.",
    );
  }
}

function isConnectionFailure(error) {
  return (
    error?.code?.startsWith?.("08") ||
    ["57P01", "57P02", "57P03"].includes(error?.code)
  );
}

function translate(error) {
  if (error instanceof PersonalMemoryError) return error;
  const mapped = (code, message) => {
    const result = new PersonalMemoryError(code, message);
    Object.defineProperty(result, "cause", { value: error });
    return result;
  };
  if (error?.constraint?.includes("version") || error?.code === "40001") {
    return mapped("STALE_VERSION", "Version is stale.");
  }
  if (error?.constraint === "c09_retention_not_due_guard") {
    return mapped("INVALID_STATE", "Memory is not due for expiration.");
  }
  if (error?.constraint === "c09_retention_memory_guard") {
    return mapped("MEMORY_NOT_FOUND", "Memory was not found.");
  }
  if (error?.constraint === "c09_retention_idempotency_guard") {
    return mapped("IDEMPOTENCY_CONFLICT", "Idempotency key was reused.");
  }
  if (
    error?.code === "23505" &&
    error.constraint === "command_receipt_pkey"
  ) {
    return mapped(
      "IDEMPOTENCY_CONFLICT",
      "C09 command receipt already exists.",
    );
  }
  if (
    error?.code === "23505" &&
    GENERATED_ID_CONSTRAINTS.has(error.constraint)
  ) {
    return mapped("ID_COLLISION", "Generated C09 ID already exists.");
  }
  if (error?.code === "23505") {
    return mapped(
      "INTEGRITY_VIOLATION",
      "PostgreSQL rejected conflicting C09 state.",
    );
  }
  if (["23503", "23514", "42501"].includes(error?.code)) {
    return mapped(
      "INTEGRITY_VIOLATION",
      "PostgreSQL rejected invalid C09 state.",
    );
  }
  if (isConnectionFailure(error)) {
    return mapped(
      "STORE_UNAVAILABLE",
      "C09 PostgreSQL is unavailable.",
    );
  }
  return mapped(
    "STORE_UNAVAILABLE",
    "C09 PostgreSQL operation failed.",
  );
}

export function createPostgresPersonalMemoryStore({
  runtimePool,
  tenantScopePool,
  principalScopePool,
  retentionPool = null,
  schema = "aios_personal_memory",
  tenantScopeSchema = "aios_data",
  maxSerializableRetries = 5,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof tenantScopePool?.connect !== "function" ||
    typeof principalScopePool?.connect !== "function" ||
    (
      retentionPool !== null &&
      typeof retentionPool?.connect !== "function"
    ) ||
    new Set(
      [runtimePool, tenantScopePool, principalScopePool, retentionPool]
        .filter(Boolean),
    ).size !== (retentionPool ? 4 : 3) ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(tenantScopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C09 PostgreSQL pools are invalid.");
  }

  const table = (name) => `"${schema}"."${name}"`;
  const tenantSigner =
    `"${tenantScopeSchema}"."issue_runtime_scope_signature"`;
  const fence = `"${tenantScopeSchema}"."acquire_runtime_fence"`;
  const principalSigner =
    `"${schema}"."issue_principal_scope_signature"`;
  const retentionMaterializer =
    `"${schema}"."materialize_due_expiry"`;

  async function connect(pool, requiredRole) {
    let client;
    try {
      client = await pool.connect();
      const checks = ROLE_NAMES.map(
        (role, index) =>
          `pg_has_role(identity.current_name, '${role}', 'MEMBER')
             AS current_role_${index},
           pg_has_role(identity.session_name, '${role}', 'MEMBER')
             AS session_role_${index}`,
      ).join(",\n");
      const result = await client.query(
        `WITH identity AS (
           SELECT current_user::text AS current_name,
                  session_user::text AS session_name
         )
         SELECT identity.*,
                active.rolsuper AS current_super,
                active.rolbypassrls AS current_bypassrls,
                login.rolsuper AS session_super,
                login.rolbypassrls AS session_bypassrls,
                ${checks}
           FROM identity
           JOIN pg_roles AS active ON active.rolname = identity.current_name
           JOIN pg_roles AS login ON login.rolname = identity.session_name`,
      );
      const row = result.rows[0];
      const expectedIndex = ROLE_NAMES.indexOf(requiredRole);
      if (
        !row ||
        expectedIndex < 0 ||
        row.current_super ||
        row.current_bypassrls ||
        row.session_super ||
        row.session_bypassrls ||
        ROLE_NAMES.some(
          (_role, index) =>
            row[`current_role_${index}`] !== (index === expectedIndex) ||
            row[`session_role_${index}`] !== (index === expectedIndex),
        )
      ) {
        client.release(new Error("C09 rejected an unsafe PostgreSQL role."));
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C09 PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C09 could not verify the PostgreSQL role."),
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
              current_setting('aios.backend_pid', true) AS backend_pid,
              current_setting('aios.transaction_id', true)
                AS transaction_id,
              current_setting('aios.expires_epoch_ms', true)
                AS expires_epoch_ms,
              current_setting('aios.scope_nonce', true) AS scope_nonce,
              current_setting('aios.scope_signature', true)
                AS scope_signature,
              current_setting('aios.principal_id', true) AS principal_id,
              current_setting('aios.principal_lifecycle_version', true)
                AS principal_lifecycle_version,
              current_setting('aios.principal_security_epoch', true)
                AS principal_security_epoch,
              current_setting('aios.principal_expires_epoch_ms', true)
                AS principal_expires_epoch_ms,
              current_setting('aios.principal_scope_nonce', true)
                AS principal_scope_nonce,
              current_setting('aios.principal_scope_signature', true)
                AS principal_scope_signature`,
    );
    if (
      Object.values(result.rows[0]).some(
        (value) => value !== null && value !== "",
      )
    ) {
      fail(
        "CONNECTION_CONTEXT_LEAK",
        "C09 PostgreSQL connection retained identity scope.",
      );
    }
  }

  async function signTenantScope(scope, backendPid, transactionId) {
    const client = await connect(
      tenantScopePool,
      "aios_c07_scope_runtime",
    );
    try {
      const nonce = randomUUID();
      const result = await client.query(
        `SELECT ${tenantSigner}(
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
        !/^[0-9a-f]{64}$/.test(signed?.signature ?? "") ||
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

  async function signPrincipalScope(
    scope,
    backendPid,
    transactionId,
  ) {
    const client = await connect(
      principalScopePool,
      "aios_c09_scope_runtime",
    );
    try {
      const nonce = randomUUID();
      const result = await client.query(
        `SELECT ${principalSigner}(
           $1,$2,$3,$4,$5,$6,$7::xid8,15,$8::uuid
         ) AS signed_scope`,
        [
          scope.tenantId,
          scope.tenantKind,
          scope.principalId,
          scope.principalLifecycleVersion,
          scope.principalSecurityEpoch,
          backendPid,
          transactionId,
          nonce,
        ],
      );
      const signed = json(result.rows[0]?.signed_scope);
      if (
        !/^[0-9a-f]{64}$/.test(signed?.signature ?? "") ||
        !Number.isSafeInteger(Number(signed?.expires_epoch_ms))
      ) {
        fail(
          "IDENTITY_BINDING_INVALID",
          "C09 Principal scope signature is invalid.",
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

  async function runScoped(
    scope,
    tenantId,
    principalId,
    begin,
    reducer,
  ) {
    if (
      scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
      scope.tenantId !== tenantId ||
      scope.principalId !== principalId ||
      !Number.isSafeInteger(scope.principalLifecycleVersion) ||
      scope.principalLifecycleVersion < 1 ||
      !Number.isSafeInteger(scope.principalSecurityEpoch) ||
      scope.principalSecurityEpoch < 1
    ) {
      fail(
        "IDENTITY_BINDING_INVALID",
        "C09 PostgreSQL Principal scope is invalid.",
      );
    }
    const client = await connect(runtimePool, "aios_c09_runtime");
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
      const [tenant, principal] = await Promise.all([
        signTenantScope(scope, backendPid, transactionId),
        signPrincipalScope(scope, backendPid, transactionId),
      ]);
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
                set_config('aios.scope_signature',$12,true),
                set_config('aios.principal_id',$13,true),
                set_config('aios.principal_lifecycle_version',$14,true),
                set_config('aios.principal_security_epoch',$15,true),
                set_config('aios.principal_expires_epoch_ms',$16,true),
                set_config('aios.principal_scope_nonce',$17,true),
                set_config('aios.principal_scope_signature',$18,true)`,
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
          tenant.expiresEpochMs,
          tenant.nonce,
          tenant.signature,
          principalId,
          String(scope.principalLifecycleVersion),
          String(scope.principalSecurityEpoch),
          principal.expiresEpochMs,
          principal.nonce,
          principal.signature,
        ],
      );
      const acquired = await client.query(
        `SELECT ${fence}() AS acquired`,
      );
      if (acquired.rows[0]?.acquired !== true) {
        fail("TENANT_SCOPE_VIOLATION", "C07 runtime fence was not acquired.");
      }
      const value = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return value;
    } catch (error) {
      discard = isConnectionFailure(error);
      if (started) {
        try {
          await client.query("ROLLBACK");
        } catch {
          discard = true;
        }
      }
      if (!discard) {
        try {
          await assertScopeCleared(client);
        } catch {
          discard = true;
        }
      }
      throw error;
    } finally {
      client.release(
        discard ? new Error("C09 discarded a failed connection.") : undefined,
      );
    }
  }

  async function runRetentionScoped(scope, reducer) {
    const authorization = scope?.authorizationEvidence;
    if (
      !retentionPool ||
      scope?.trustSource !== "C09_VERIFIED_RETENTION_SCOPE" ||
      scope.tenantKind !== "SYNTHETIC" ||
      scope.operation !== "C09_RETENTION_MATERIALIZE_EXPIRY" ||
      !Number.isSafeInteger(scope.actorLifecycleVersion) ||
      scope.actorLifecycleVersion < 1 ||
      !Number.isSafeInteger(scope.actorSecurityEpoch) ||
      scope.actorSecurityEpoch < 1 ||
      authorization?.tenantId !== scope.tenantId ||
      authorization?.operation !== scope.operation ||
      authorization?.actorPrincipalId !== scope.actorPrincipalId ||
      authorization?.resourceId !== scope.memoryId ||
      authorization?.expectedVersion !== scope.expectedVersion ||
      authorization?.decisionId !== scope.decisionId ||
      authorization?.evidenceRef !== scope.evidenceRef ||
      authorization?.policyVersion !== scope.policyVersion
    ) {
      fail(
        "INVALID_CONFIGURATION",
        "C09 PostgreSQL retention scope is invalid.",
      );
    }
    const client = await connect(
      retentionPool,
      "aios_c09_retention_runtime",
    );
    let started = false;
    let discard = false;
    try {
      await assertScopeCleared(client);
      await client.query("BEGIN ISOLATION LEVEL READ COMMITTED");
      started = true;
      const transaction = await client.query(
        `SELECT pg_backend_pid() AS backend_pid,
                pg_current_xact_id()::text AS transaction_id`,
      );
      const backendPid = transaction.rows[0].backend_pid;
      const transactionId = transaction.rows[0].transaction_id;
      const tenant = await signTenantScope(
        scope,
        backendPid,
        transactionId,
      );
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
          tenant.expiresEpochMs,
          tenant.nonce,
          tenant.signature,
        ],
      );
      const acquired = await client.query(
        `SELECT ${fence}() AS acquired`,
      );
      if (acquired.rows[0]?.acquired !== true) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C07 retention runtime fence was not acquired.",
        );
      }
      const value = await reducer(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return value;
    } catch (error) {
      discard = isConnectionFailure(error);
      if (started) {
        try {
          await client.query("ROLLBACK");
        } catch {
          discard = true;
        }
      }
      if (!discard) {
        try {
          await assertScopeCleared(client);
        } catch {
          discard = true;
        }
      }
      throw error;
    } finally {
      client.release(
        discard
          ? new Error("C09 discarded a failed retention connection.")
          : undefined,
      );
    }
  }

  async function withSerializable(
    scope,
    tenantId,
    principalId,
    reducer,
  ) {
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await runScoped(
          scope,
          tenantId,
          principalId,
          "BEGIN ISOLATION LEVEL SERIALIZABLE",
          reducer,
        );
      } catch (error) {
        if (
          RETRYABLE.has(error?.code) &&
          attempt < maxSerializableRetries
        ) {
          continue;
        }
        throw translate(error);
      }
    }
  }

  async function ensureProfile(client, envelope) {
    await client.query(
      `INSERT INTO ${table("personal_profile")} (
         tenant_id,tenant_kind,principal_id,principal_kind,state,version,
         created_at,updated_at
       ) VALUES ($1,$2,$3,'HUMAN','ACTIVE',1,$4,$4)
       ON CONFLICT (tenant_id,principal_id) DO NOTHING`,
      [
        envelope.tenantId,
        envelope.tenantKind,
        envelope.principalId,
        envelope.now,
      ],
    );
    const result = await client.query(
      `SELECT * FROM ${table("personal_profile")}
        WHERE tenant_id=$1 AND principal_id=$2
        FOR UPDATE`,
      [envelope.tenantId, envelope.principalId],
    );
    const profile = profileFromRow(result.rows[0]);
    if (!profile) fail("INTEGRITY_VIOLATION", "Profile was not created.");
    return profile;
  }

  async function findMemory(client, envelope) {
    const result = await client.query(
      `SELECT * FROM ${table("personal_memory")}
        WHERE tenant_id=$1 AND principal_id=$2 AND memory_id=$3
        FOR UPDATE`,
      [envelope.tenantId, envelope.principalId, envelope.memoryId],
    );
    const memory = memoryFromRow(result.rows[0]);
    if (!memory) fail("MEMORY_NOT_FOUND", "Memory was not found.");
    if (memory.version !== envelope.expectedVersion) {
      fail("STALE_VERSION", "Memory version is stale.");
    }
    return memory;
  }

  async function insertEvent(client, envelope, event) {
    await client.query(
      `INSERT INTO ${table("memory_event")} (
         tenant_id,tenant_kind,event_id,memory_id,principal_id,event_type,
         from_state,to_state,content_sha256,actor_principal_id,
         authorization_evidence,human_consent_evidence,
         correlation_id,created_at
       ) VALUES (
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14
       )`,
      [
        envelope.tenantId,
        envelope.tenantKind,
        event.eventId,
        event.memoryId,
        envelope.principalId,
        event.eventType,
        event.fromState,
        event.toState,
        event.contentSha256,
        envelope.actorPrincipalId,
        JSON.stringify(envelope.authorizationEvidence),
        envelope.humanConsentEvidence
          ? JSON.stringify(envelope.humanConsentEvidence)
          : null,
        envelope.correlationId,
        envelope.now,
      ],
    );
  }

  async function scrubMemory(
    client,
    envelope,
    memory,
    state,
    reason,
  ) {
    const result = await client.query(
      `UPDATE ${table("personal_memory")}
          SET state=$4,content=NULL,version=version+1,
              terminal_reason=$5,updated_at=$6
        WHERE tenant_id=$1 AND principal_id=$2 AND memory_id=$3
          AND version=$7
      RETURNING *`,
      [
        envelope.tenantId,
        envelope.principalId,
        memory.memoryId,
        state,
        reason,
        envelope.now,
        memory.version,
      ],
    );
    if (result.rowCount !== 1) fail("STALE_VERSION", "Memory is stale.");
    await client.query(
      `UPDATE ${table("conversation_checkpoint")}
          SET memory_ids=array_remove(memory_ids,$3),
              version=version+1,updated_at=$4
        WHERE tenant_id=$1 AND principal_id=$2 AND $3=ANY(memory_ids)`,
      [
        envelope.tenantId,
        envelope.principalId,
        memory.memoryId,
        envelope.now,
      ],
    );
    await insertEvent(client, envelope, {
      eventId: envelope.eventId,
      memoryId: memory.memoryId,
      eventType:
        state === "DELETED" ? "MEMORY_DELETED" : "MEMORY_EXPIRED",
      fromState: memory.state,
      toState: state,
      contentSha256: memory.contentSha256,
    });
    return memoryFromRow(result.rows[0]);
  }

  async function applyAction(client, envelope, profile) {
    if (envelope.operation === "PROPOSE_CANDIDATE") {
      if (profile.state !== "ACTIVE") fail("PROFILE_PAUSED", "Profile paused.");
      const result = await client.query(
        `INSERT INTO ${table("personal_memory")} (
           tenant_id,tenant_kind,memory_id,principal_id,state,category,
           content,content_sha256,source_ref,expires_at,version,
           terminal_reason,created_at,updated_at
         ) VALUES (
           $1,$2,$3,$4,'CANDIDATE',$5,$6,$7,$8,$9,1,NULL,$10,$10
         ) RETURNING *`,
        [
          envelope.tenantId,
          envelope.tenantKind,
          envelope.memoryId,
          envelope.principalId,
          envelope.candidate.category,
          envelope.candidate.content,
          envelope.candidate.contentSha256,
          envelope.candidate.candidateRef,
          envelope.candidate.expiresAt,
          envelope.now,
        ],
      );
      const memory = memoryFromRow(result.rows[0]);
      await insertEvent(client, envelope, {
        eventId: envelope.eventId,
        memoryId: memory.memoryId,
        eventType: "MEMORY_CANDIDATE_PROPOSED",
        fromState: null,
        toState: "CANDIDATE",
        contentSha256: memory.contentSha256,
      });
      return {
        memoryId: memory.memoryId,
        state: memory.state,
        version: memory.version,
      };
    }

    if (envelope.operation === "CONFIRM_CANDIDATE") {
      if (profile.state !== "ACTIVE") fail("PROFILE_PAUSED", "Profile paused.");
      const memory = await findMemory(client, envelope);
      if (memory.state !== "CANDIDATE") {
        fail("INVALID_STATE", "Only a Candidate can be confirmed.");
      }
      requireHumanConsent(
        envelope,
        memory.contentSha256,
        "CONFIRM_PERSONAL_MEMORY",
      );
      const updated = await client.query(
        `UPDATE ${table("personal_memory")}
            SET state='CONFIRMED',version=version+1,updated_at=$4
          WHERE tenant_id=$1 AND principal_id=$2 AND memory_id=$3
            AND version=$5
        RETURNING *`,
        [
          envelope.tenantId,
          envelope.principalId,
          memory.memoryId,
          envelope.now,
          memory.version,
        ],
      );
      if (updated.rowCount !== 1) fail("STALE_VERSION", "Memory is stale.");
      const confirmed = memoryFromRow(updated.rows[0]);
      await insertEvent(client, envelope, {
        eventId: envelope.eventId,
        memoryId: memory.memoryId,
        eventType: "MEMORY_CONFIRMED",
        fromState: "CANDIDATE",
        toState: "CONFIRMED",
        contentSha256: memory.contentSha256,
      });
      return {
        memoryId: confirmed.memoryId,
        state: confirmed.state,
        version: confirmed.version,
      };
    }

    if (envelope.operation === "CORRECT_MEMORY") {
      if (profile.state !== "ACTIVE") fail("PROFILE_PAUSED", "Profile paused.");
      const memory = await findMemory(client, envelope);
      if (memory.state !== "CONFIRMED") {
        fail("INVALID_STATE", "Only Confirmed memory can be corrected.");
      }
      requireHumanConsent(
        envelope,
        envelope.replacementCandidate.contentSha256,
        "CORRECT_PERSONAL_MEMORY",
      );
      const deleted = await scrubMemory(
        client,
        envelope,
        memory,
        "DELETED",
        "CORRECTED",
      );
      const inserted = await client.query(
        `INSERT INTO ${table("personal_memory")} (
           tenant_id,tenant_kind,memory_id,principal_id,state,category,
           content,content_sha256,source_ref,expires_at,version,
           terminal_reason,created_at,updated_at
         ) VALUES (
           $1,$2,$3,$4,'CONFIRMED',$5,$6,$7,$8,$9,1,NULL,$10,$10
         ) RETURNING *`,
        [
          envelope.tenantId,
          envelope.tenantKind,
          envelope.replacementMemoryId,
          envelope.principalId,
          envelope.replacementCandidate.category,
          envelope.replacementCandidate.content,
          envelope.replacementCandidate.contentSha256,
          envelope.replacementCandidate.candidateRef,
          envelope.replacementCandidate.expiresAt,
          envelope.now,
        ],
      );
      const replacement = memoryFromRow(inserted.rows[0]);
      await insertEvent(client, envelope, {
        eventId: envelope.replacementEventId,
        memoryId: replacement.memoryId,
        eventType: "MEMORY_CONFIRMED",
        fromState: null,
        toState: "CONFIRMED",
        contentSha256: replacement.contentSha256,
      });
      return {
        deletedMemoryId: deleted.memoryId,
        deletedVersion: deleted.version,
        memoryId: replacement.memoryId,
        state: replacement.state,
        version: replacement.version,
      };
    }

    if (envelope.operation === "CHANGE_PROFILE_STATE") {
      if (profile.version !== envelope.expectedProfileVersion) {
        fail("STALE_VERSION", "Profile version is stale.");
      }
      if (profile.state === envelope.profileState) {
        fail("INVALID_STATE", "Profile already has this state.");
      }
      const updated = await client.query(
        `UPDATE ${table("personal_profile")}
            SET state=$3,version=version+1,updated_at=$4
          WHERE tenant_id=$1 AND principal_id=$2 AND version=$5
        RETURNING *`,
        [
          envelope.tenantId,
          envelope.principalId,
          envelope.profileState,
          envelope.now,
          profile.version,
        ],
      );
      if (updated.rowCount !== 1) fail("STALE_VERSION", "Profile is stale.");
      const changed = profileFromRow(updated.rows[0]);
      return {
        principalId: changed.principalId,
        state: changed.state,
        version: changed.version,
      };
    }

    if (
      ["MATERIALIZE_EXPIRY", "DELETE_MEMORY"].includes(
        envelope.operation,
      )
    ) {
      const memory = await findMemory(client, envelope);
      const expiration = envelope.operation === "MATERIALIZE_EXPIRY";
      if (
        expiration &&
        (
          !["CANDIDATE", "CONFIRMED"].includes(memory.state) ||
          Date.parse(memory.expiresAt) > Date.parse(envelope.now)
        )
      ) {
        fail("INVALID_STATE", "Memory is not due for expiration.");
      }
      if (
        !expiration &&
        !["CANDIDATE", "CONFIRMED", "EXPIRED"].includes(memory.state)
      ) {
        fail("INVALID_STATE", "Memory cannot be deleted again.");
      }
      const terminal = await scrubMemory(
        client,
        envelope,
        memory,
        expiration ? "EXPIRED" : "DELETED",
        expiration ? "RETENTION_EXPIRED" : "OWNER_REQUEST",
      );
      return {
        memoryId: terminal.memoryId,
        state: terminal.state,
        version: terminal.version,
      };
    }

    if (envelope.operation === "SAVE_CHECKPOINT") {
      if (profile.state !== "ACTIVE") fail("PROFILE_PAUSED", "Profile paused.");
      if (envelope.memoryIds.length > 0) {
        const valid = await client.query(
          `SELECT memory_id FROM ${table("personal_memory")}
            WHERE tenant_id=$1 AND principal_id=$2
              AND memory_id=ANY($3::text[])
              AND state='CONFIRMED' AND expires_at>$4
            FOR SHARE`,
          [
            envelope.tenantId,
            envelope.principalId,
            envelope.memoryIds,
            envelope.now,
          ],
        );
        if (valid.rowCount !== envelope.memoryIds.length) {
          fail(
            "INVALID_CHECKPOINT_REFERENCE",
            "Checkpoint memory is invalid.",
          );
        }
      }
      let result;
      if (envelope.expectedVersion === 0) {
        result = await client.query(
          `INSERT INTO ${table("conversation_checkpoint")} (
             tenant_id,tenant_kind,checkpoint_id,principal_id,thread_ref,
             state_ref,state_sha256,memory_ids,version,created_at,updated_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::text[],1,$9,$9)
           RETURNING *`,
          [
            envelope.tenantId,
            envelope.tenantKind,
            envelope.checkpointId,
            envelope.principalId,
            envelope.threadRef,
            envelope.stateRef,
            envelope.stateSha256,
            envelope.memoryIds,
            envelope.now,
          ],
        );
      } else {
        result = await client.query(
          `UPDATE ${table("conversation_checkpoint")}
              SET thread_ref=$4,state_ref=$5,state_sha256=$6,
                  memory_ids=$7::text[],version=version+1,updated_at=$8
            WHERE tenant_id=$1 AND principal_id=$2 AND checkpoint_id=$3
              AND version=$9
          RETURNING *`,
          [
            envelope.tenantId,
            envelope.principalId,
            envelope.checkpointId,
            envelope.threadRef,
            envelope.stateRef,
            envelope.stateSha256,
            envelope.memoryIds,
            envelope.now,
            envelope.expectedVersion,
          ],
        );
        if (result.rowCount !== 1) {
          fail("STALE_VERSION", "Checkpoint is stale.");
        }
      }
      const checkpoint = checkpointFromRow(result.rows[0]);
      return {
        checkpointId: checkpoint.checkpointId,
        version: checkpoint.version,
        memoryIds: checkpoint.memoryIds,
      };
    }
    fail("INVALID_INPUT", "Unsupported C09 operation.");
  }

  return Object.freeze({
    async apply(scope, envelope) {
      if (
        scope?.tenantId !== envelope.tenantId ||
        scope?.tenantKind !== envelope.tenantKind ||
        scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE"
      ) {
        fail("TENANT_SCOPE_VIOLATION", "C09 store scope is invalid.");
      }
      const validatedEnvelope = envelope.humanConsentEvidence === null ||
          envelope.humanConsentEvidence === undefined
        ? envelope
        : {
          ...envelope,
          humanConsentEvidence:
            validatePersonalMemoryHumanConsentEvidence(
              envelope.humanConsentEvidence,
            ),
        };
      return withSerializable(
        scope,
        validatedEnvelope.tenantId,
        validatedEnvelope.principalId,
        async (client) => {
        await client.query(
          `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
          [
            `${validatedEnvelope.tenantId}\u001f` +
              `${validatedEnvelope.principalId}\u001f` +
              validatedEnvelope.idempotencyKey,
          ],
        );
        const replay = await client.query(
          `SELECT request_hash,result
             FROM ${table("command_receipt")}
            WHERE tenant_id=$1 AND principal_id=$2 AND idempotency_key=$3`,
          [
            validatedEnvelope.tenantId,
            validatedEnvelope.principalId,
            validatedEnvelope.idempotencyKey,
          ],
        );
        if (replay.rowCount === 1) {
          if (
            replay.rows[0].request_hash !== validatedEnvelope.requestHash
          ) {
            fail("IDEMPOTENCY_CONFLICT", "Idempotency key was reused.");
          }
          return json(replay.rows[0].result);
        }
        const profile = await ensureProfile(client, validatedEnvelope);
        const result = await applyAction(
          client,
          validatedEnvelope,
          profile,
        );
        await client.query(
          `INSERT INTO ${table("command_receipt")} (
             tenant_id,tenant_kind,principal_id,idempotency_key,
             request_hash,operation,result,created_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`,
          [
            validatedEnvelope.tenantId,
            validatedEnvelope.tenantKind,
            validatedEnvelope.principalId,
            validatedEnvelope.idempotencyKey,
            validatedEnvelope.requestHash,
            validatedEnvelope.operation,
            JSON.stringify(result),
            validatedEnvelope.now,
          ],
        );
        return result;
        },
      );
    },

    async readCommandReceipt(scope, {
      tenantId,
      principalId,
      idempotencyKey,
      requestHash,
    }) {
      return runScoped(
        scope,
        tenantId,
        principalId,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const result = await client.query(
            `SELECT request_hash,result
               FROM ${table("command_receipt")}
              WHERE tenant_id=$1 AND principal_id=$2 AND idempotency_key=$3`,
            [tenantId, principalId, idempotencyKey],
          );
          const receipt = result.rows[0];
          if (!receipt) return null;
          if (receipt.request_hash !== requestHash) {
            fail("IDEMPOTENCY_CONFLICT", "Idempotency key was reused.");
          }
          return json(receipt.result);
        },
      ).catch((error) => {
        throw translate(error);
      });
    },

    async listRecallMetadata(scope, {
      tenantId,
      principalId,
      now,
      limit,
    }) {
      return runScoped(
        scope,
        tenantId,
        principalId,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const result = await client.query(
            `SELECT memory.memory_id,memory.category,
                    memory.content_sha256,memory.version,memory.expires_at
               FROM ${table("personal_memory")} AS memory
               JOIN ${table("personal_profile")} AS profile
                 ON profile.tenant_id=memory.tenant_id
                AND profile.principal_id=memory.principal_id
                AND profile.state='ACTIVE'
              WHERE memory.tenant_id=$1 AND memory.principal_id=$2
                AND memory.state='CONFIRMED' AND memory.expires_at>$3
              ORDER BY memory.created_at,memory.memory_id
              LIMIT $4`,
            [tenantId, principalId, now, limit],
          );
          return result.rows.map((row) => ({
            memoryId: row.memory_id,
            category: row.category,
            contentSha256: row.content_sha256,
            version: Number(row.version),
            expiresAt: iso(row.expires_at),
          }));
        },
      ).catch((error) => {
        throw translate(error);
      });
    },

    async readRecallContent(scope, {
      tenantId,
      principalId,
      memoryId,
      expectedVersion,
      now,
    }) {
      return runScoped(
        scope,
        tenantId,
        principalId,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const result = await client.query(
            `SELECT memory.*
               FROM ${table("personal_memory")} AS memory
               JOIN ${table("personal_profile")} AS profile
                 ON profile.tenant_id=memory.tenant_id
                AND profile.principal_id=memory.principal_id
                AND profile.state='ACTIVE'
              WHERE memory.tenant_id=$1 AND memory.principal_id=$2
                AND memory.memory_id=$3 AND memory.version=$4
                AND memory.state='CONFIRMED' AND memory.expires_at>$5`,
            [tenantId, principalId, memoryId, expectedVersion, now],
          );
          return memoryFromRow(result.rows[0]);
        },
      ).catch((error) => {
        throw translate(error);
      });
    },

    async readProfile(scope, { tenantId, principalId }) {
      return runScoped(
        scope,
        tenantId,
        principalId,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const result = await client.query(
            `SELECT * FROM ${table("personal_profile")}
              WHERE tenant_id=$1 AND principal_id=$2`,
            [tenantId, principalId],
          );
          return profileFromRow(result.rows[0]) ?? {
            tenantId,
            tenantKind: "SYNTHETIC",
            principalId,
            state: "ACTIVE",
            version: 1,
          };
        },
      ).catch((error) => {
        throw translate(error);
      });
    },

    async readConsentTarget(scope, {
      tenantId,
      principalId,
      memoryId,
    }) {
      return runScoped(
        scope,
        tenantId,
        principalId,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const result = await client.query(
            `SELECT memory_id,state,content_sha256,version
               FROM ${table("personal_memory")}
              WHERE tenant_id=$1 AND principal_id=$2 AND memory_id=$3`,
            [tenantId, principalId, memoryId],
          );
          const row = result.rows[0];
          if (!row) return null;
          return {
            memoryId: row.memory_id,
            state: row.state,
            contentSha256: row.content_sha256,
            version: Number(row.version),
          };
        },
      ).catch((error) => {
        throw translate(error);
      });
    },

    async readCheckpoint(scope, {
      tenantId,
      principalId,
      checkpointId,
      asOf,
    }) {
      return runScoped(
        scope,
        tenantId,
        principalId,
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        async (client) => {
          const result = await client.query(
            `SELECT checkpoint.*,
                    ARRAY(
                      SELECT reference.memory_id
                        FROM unnest(checkpoint.memory_ids)
                          WITH ORDINALITY
                          AS reference(memory_id, position)
                        JOIN ${table("personal_memory")} AS memory
                          ON memory.tenant_id=checkpoint.tenant_id
                         AND memory.principal_id=checkpoint.principal_id
                         AND memory.memory_id=reference.memory_id
                       WHERE memory.state='CONFIRMED'
                         AND memory.expires_at>$4
                       ORDER BY reference.position
                    ) AS memory_ids
               FROM ${table("conversation_checkpoint")} AS checkpoint
               JOIN ${table("personal_profile")} AS profile
                 ON profile.tenant_id=checkpoint.tenant_id
                AND profile.principal_id=checkpoint.principal_id
                AND profile.state='ACTIVE'
              WHERE checkpoint.tenant_id=$1
                AND checkpoint.principal_id=$2
                AND checkpoint.checkpoint_id=$3`,
            [tenantId, principalId, checkpointId, asOf],
          );
          return checkpointFromRow(result.rows[0]);
        },
      ).catch((error) => {
        throw translate(error);
      });
    },

    async materializeExpiry(scope, envelope) {
      if (
        scope?.tenantId !== envelope.tenantId ||
        scope?.memoryId !== envelope.memoryId ||
        scope?.expectedVersion !== envelope.expectedVersion ||
        scope?.correlationId !== envelope.correlationId ||
        envelope.operation !== "MATERIALIZE_EXPIRY"
      ) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C09 retention command is outside its authorized scope.",
        );
      }
      return runRetentionScoped(scope, async (client) => {
        const result = await client.query(
          `SELECT ${retentionMaterializer}(
             $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb
           ) AS result`,
          [
            envelope.tenantId,
            envelope.memoryId,
            envelope.expectedVersion,
            envelope.idempotencyKey,
            envelope.correlationId,
            envelope.eventId,
            envelope.requestHash,
            scope.actorPrincipalId,
            scope.actorLifecycleVersion,
            scope.actorSecurityEpoch,
            JSON.stringify(scope.authorizationEvidence),
          ],
        );
        const materialized = json(result.rows[0]?.result);
        if (
          !materialized ||
          Object.keys(materialized).sort().join(",") !==
            "memoryId,state,version" ||
          materialized.memoryId !== envelope.memoryId ||
          materialized.state !== "EXPIRED" ||
          !Number.isSafeInteger(Number(materialized.version))
        ) {
          fail(
            "INTEGRITY_VIOLATION",
            "C09 retention result is invalid.",
          );
        }
        return {
          memoryId: materialized.memoryId,
          state: materialized.state,
          version: Number(materialized.version),
        };
      }).catch((error) => {
        throw translate(error);
      });
    },
  });
}
