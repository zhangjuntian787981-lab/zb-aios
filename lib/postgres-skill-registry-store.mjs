import { createHash, randomUUID } from "node:crypto";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const RETRYABLE_SQL_STATES = new Set([
  "40001",
  "40P01",
  "57P01",
  "08000",
  "08001",
  "08003",
  "08004",
  "08006",
  "08P01",
]);
const RETRYABLE_CONSTRAINTS = new Set([
  "command_receipt_pkey",
  "command_receipt_tenant_id_effect_key_key",
]);
const ROLE_NAMES = Object.freeze([
  "aios_c13_runtime",
  "aios_c13_owner",
  "aios_c07_scope_runtime",
  "aios_c07_data_runtime",
  "aios_c07_lifecycle_runtime",
  "aios_c07_restore_runtime",
  "aios_c07_owner",
]);

export class SkillRegistryStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SkillRegistryStoreError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new SkillRegistryStoreError(code, message);
}

function json(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function integer(value) {
  const number = Number(value);
  if (!Number.isSafeInteger(number)) {
    fail("STORE_UNAVAILABLE", "PostgreSQL returned an unsafe integer.");
  }
  return number;
}

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function hash(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function deriveSkillCommandEffectKey({
  tenantId,
  commandKind,
  idempotencyKey,
}) {
  return hash(JSON.stringify([tenantId, commandKind, idempotencyKey]));
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
    !scope.policyVersion ||
    typeof scope?.operationId !== "string" ||
    !scope.operationId.startsWith("C13_") ||
    scope?.storagePath !== "skill-registry"
  ) {
    fail("TENANT_SCOPE_VIOLATION", "C13 requires a C07 verified scope.");
  }
}

function validateMetadata(metadata) {
  if (
    typeof metadata?.idempotencyKey !== "string" ||
    !metadata.idempotencyKey ||
    metadata.idempotencyKey.length > 128 ||
    !SHA256.test(metadata?.requestHash ?? "") ||
    typeof metadata?.commandKind !== "string" ||
    !/^[A-Z][A-Z0-9_]{0,63}$/.test(metadata.commandKind) ||
    typeof metadata?.correlationId !== "string" ||
    !metadata.correlationId ||
    metadata.correlationId.length > 128
  ) {
    fail("INVALID_INPUT", "C13 command metadata is invalid.");
  }
}

function releaseFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    skillId: row.skill_id,
    releaseId: row.release_id,
    sequence: integer(row.sequence),
    name: row.name,
    version: row.semantic_version,
    manifest: json(row.manifest),
    contentSha256: row.content_sha256,
    sourceReviewRef: row.source_review_ref,
    sourceReviewSha256: row.source_review_sha256,
    lifecycleState: row.lifecycle_state,
    stateVersion: integer(row.state_version),
    staticReport: row.static_report === null ? null : json(row.static_report),
    evaluationSuiteId: row.evaluation_suite_id,
    evaluationSuiteSha256: row.evaluation_suite_sha256,
    evaluationReport:
      row.evaluation_report === null ? null : json(row.evaluation_report),
    pilotPublished: row.pilot_published,
    stablePublished: row.stable_published,
    withdrawnAt: iso(row.withdrawn_at),
    withdrawalReasonRef: row.withdrawal_reason_ref,
    identity: json(row.identity),
    authorization: json(row.authorization_evidence),
    tenantLifecycleVersion: integer(row.tenant_lifecycle_version),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  });
}

function channelFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    skillId: row.skill_id,
    channel: row.channel,
    releaseId: row.release_id,
    generation: integer(row.generation),
    reasonRef: row.reason_ref,
    updatedAt: iso(row.updated_at),
  });
}

function shouldRetry(error) {
  return (
    RETRYABLE_SQL_STATES.has(error?.code) ||
    RETRYABLE_CONSTRAINTS.has(error?.constraint)
  );
}

function shouldDiscard(error) {
  return (
    error?.code === "57P01" ||
    (typeof error?.code === "string" && error.code.startsWith("08"))
  );
}

function retryDelay(key, attempt) {
  let seed = 0;
  for (const character of key) {
    seed = (seed * 31 + character.charCodeAt(0)) >>> 0;
  }
  return Math.min(5 * 2 ** attempt, 100) + (seed % 5);
}

function databaseFailure(error) {
  if (
    error instanceof SkillRegistryStoreError ||
    error?.name === "SkillRegistryError"
  ) {
    return error;
  }
  if (error?.code === "42501") {
    return new SkillRegistryStoreError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL rejected the C13 Tenant scope.",
    );
  }
  if (
    error?.constraint === "skill_release_immutable_guard" ||
    error?.constraint === "skill_release_transition_guard" ||
    error?.constraint === "skill_channel_generation_guard"
  ) {
    return new SkillRegistryStoreError(
      "VERSION_CONFLICT",
      "C13 version or transition conflicts.",
    );
  }
  if (
    error?.constraint ===
      "skill_release_tenant_id_skill_id_sequence_key" ||
    error?.constraint ===
      "skill_release_tenant_id_skill_id_semantic_version_key"
  ) {
    return new SkillRegistryStoreError(
      "VERSION_CONFLICT",
      "C13 Skill sequence or semantic version conflicts.",
    );
  }
  if (error?.code === "23505") {
    return new SkillRegistryStoreError(
      "ID_COLLISION",
      "C13 identifier already exists.",
    );
  }
  if (["23503", "23514", "23000"].includes(error?.code)) {
    return new SkillRegistryStoreError(
      "INTEGRITY_VIOLATION",
      "C13 PostgreSQL invariant failed.",
    );
  }
  return new SkillRegistryStoreError(
    "STORE_UNAVAILABLE",
    "C13 PostgreSQL storage operation failed.",
  );
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the first failure.
  }
}

export function createPostgresSkillRegistryStore({
  runtimePool,
  scopePool,
  schema = "aios_skill",
  scopeSchema = "aios_data",
  maxSerializableRetries = 10,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    runtimePool === scopePool ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C13 PostgreSQL pools are invalid.");
  }
  const table = (name) => `"${schema}"."${name}"`;
  const scopeFunction =
    `"${scopeSchema}"."issue_runtime_scope_signature"`;
  const fenceFunction = `"${scopeSchema}"."acquire_runtime_fence"`;

  async function connect(pool, requiredRole) {
    let client;
    try {
      client = await pool.connect();
      const roleChecks = ROLE_NAMES.map(
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
                ${roleChecks}
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
        client.release(new Error("C13 rejected an unsafe PostgreSQL role."));
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C13 PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C13 could not verify the PostgreSQL role."),
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
                AS scope_signature`,
    );
    if (
      Object.values(result.rows[0]).some(
        (value) => value !== null && value !== "",
      )
    ) {
      fail(
        "CONNECTION_CONTEXT_LEAK",
        "C13 PostgreSQL connection retained Tenant scope.",
      );
    }
  }

  async function issueScopeSignature(scope, backendPid, transactionId) {
    const client = await connect(scopePool, "aios_c07_scope_runtime");
    try {
      const nonce = randomUUID();
      const result = await client.query(
        `SELECT ${scopeFunction}(
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
        !Number.isSafeInteger(Number(signed?.expires_epoch_ms)) ||
        !/^[a-f0-9]{64}$/.test(signed?.signature ?? "")
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

  async function runScoped(begin, scope, operation, lockKey = null) {
    const client = await connect(runtimePool, "aios_c13_runtime");
    let started = false;
    let discard = false;
    let locked = false;
    try {
      if (lockKey !== null) {
        await client.query(
          "SELECT pg_advisory_lock(hashtextextended($1,0))",
          [lockKey],
        );
        locked = true;
      }
      await client.query(begin);
      started = true;
      const transaction = await client.query(
        `SELECT pg_backend_pid() AS backend_pid,
                pg_current_xact_id()::text AS transaction_id`,
      );
      const backendPid = transaction.rows[0].backend_pid;
      const transactionId = transaction.rows[0].transaction_id;
      const signed = await issueScopeSignature(
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
          signed.expiresEpochMs,
          signed.nonce,
          signed.signature,
        ],
      );
      const fence = await client.query(
        `SELECT ${fenceFunction}() AS acquired`,
      );
      if (fence.rows[0]?.acquired !== true) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "C13 PostgreSQL runtime fence was not acquired.",
        );
      }
      const value = await operation(client);
      await client.query("COMMIT");
      started = false;
      await assertScopeCleared(client);
      return value;
    } catch (error) {
      discard = shouldDiscard(error);
      if (started) await rollback(client);
      if (!discard) {
        try {
          await assertScopeCleared(client);
        } catch {
          discard = true;
        }
      }
      throw error;
    } finally {
      if (locked && !discard) {
        try {
          const result = await client.query(
            "SELECT pg_advisory_unlock(hashtextextended($1,0)) AS unlocked",
            [lockKey],
          );
          if (result.rows[0]?.unlocked !== true) discard = true;
        } catch {
          discard = true;
        }
      }
      client.release(
        discard ? new Error("C13 discarded a failed connection.") : undefined,
      );
    }
  }

  function transactionPort(client, scope, metadata, effectKey, events) {
    return Object.freeze({
      async findRelease(releaseId) {
        const result = await client.query(
          `SELECT * FROM ${table("skill_release")}
            WHERE tenant_id=$1 AND release_id=$2
            FOR UPDATE`,
          [scope.tenantId, releaseId],
        );
        return releaseFromRow(result.rows[0]);
      },
      async findReleaseByVersion(skillId, version) {
        const result = await client.query(
          `SELECT * FROM ${table("skill_release")}
            WHERE tenant_id=$1 AND skill_id=$2 AND semantic_version=$3
            FOR UPDATE`,
          [scope.tenantId, skillId, version],
        );
        return releaseFromRow(result.rows[0]);
      },
      async findLatestSequence(skillId) {
        const result = await client.query(
          `SELECT COALESCE(MAX(sequence),0)::bigint AS sequence
             FROM ${table("skill_release")}
            WHERE tenant_id=$1 AND skill_id=$2`,
          [scope.tenantId, skillId],
        );
        return integer(result.rows[0].sequence);
      },
      async insertRelease(value) {
        await client.query(
          `INSERT INTO ${table("skill_release")} (
             tenant_id,tenant_kind,skill_id,release_id,sequence,name,
             semantic_version,manifest,content_sha256,source_review_ref,
             source_review_sha256,lifecycle_state,state_version,
             static_report,evaluation_suite_id,evaluation_suite_sha256,
             evaluation_report,pilot_published,stable_published,
             withdrawn_at,withdrawal_reason_ref,identity,
             authorization_evidence,tenant_lifecycle_version,
             created_at,updated_at
           ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,
             $14::jsonb,$15,$16,$17::jsonb,$18,$19,$20,$21,
             $22::jsonb,$23::jsonb,$24,$25,$26
           )`,
          [
            value.tenantId,
            value.tenantKind,
            value.skillId,
            value.releaseId,
            value.sequence,
            value.name,
            value.version,
            JSON.stringify(value.manifest),
            value.contentSha256,
            value.sourceReviewRef,
            value.sourceReviewSha256,
            value.lifecycleState,
            value.stateVersion,
            value.staticReport === null
              ? null
              : JSON.stringify(value.staticReport),
            value.evaluationSuiteId,
            value.evaluationSuiteSha256,
            value.evaluationReport === null
              ? null
              : JSON.stringify(value.evaluationReport),
            value.pilotPublished,
            value.stablePublished,
            value.withdrawnAt,
            value.withdrawalReasonRef,
            JSON.stringify(value.identity),
            JSON.stringify(value.authorization),
            value.tenantLifecycleVersion,
            value.createdAt,
            value.updatedAt,
          ],
        );
      },
      async updateRelease(value, expectedVersion) {
        const result = await client.query(
          `UPDATE ${table("skill_release")}
              SET lifecycle_state=$4,state_version=$5,static_report=$6::jsonb,
                  evaluation_suite_id=$7,evaluation_suite_sha256=$8,
                  evaluation_report=$9::jsonb,pilot_published=$10,
                  stable_published=$11,withdrawn_at=$12,
                  withdrawal_reason_ref=$13,updated_at=$14
            WHERE tenant_id=$1 AND release_id=$2 AND state_version=$3
          RETURNING *`,
          [
            scope.tenantId,
            value.releaseId,
            expectedVersion,
            value.lifecycleState,
            value.stateVersion,
            value.staticReport === null
              ? null
              : JSON.stringify(value.staticReport),
            value.evaluationSuiteId,
            value.evaluationSuiteSha256,
            value.evaluationReport === null
              ? null
              : JSON.stringify(value.evaluationReport),
            value.pilotPublished,
            value.stablePublished,
            value.withdrawnAt,
            value.withdrawalReasonRef,
            value.updatedAt,
          ],
        );
        if (result.rowCount !== 1) {
          fail("VERSION_CONFLICT", "C13 release CAS did not match.");
        }
        return releaseFromRow(result.rows[0]);
      },
      async findChannel(skillId, channel) {
        const result = await client.query(
          `SELECT * FROM ${table("skill_channel")}
            WHERE tenant_id=$1 AND skill_id=$2 AND channel=$3
            FOR UPDATE`,
          [scope.tenantId, skillId, channel],
        );
        return channelFromRow(result.rows[0]);
      },
      async putChannel(value, expectedGeneration) {
        if (expectedGeneration === 0) {
          await client.query(
            `INSERT INTO ${table("skill_channel")} (
               tenant_id,tenant_kind,skill_id,channel,release_id,
               generation,reason_ref,updated_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [
              value.tenantId,
              value.tenantKind,
              value.skillId,
              value.channel,
              value.releaseId,
              value.generation,
              value.reasonRef,
              value.updatedAt,
            ],
          );
          return;
        }
        const result = await client.query(
          `UPDATE ${table("skill_channel")}
              SET release_id=$5,generation=$6,reason_ref=$7,updated_at=$8
            WHERE tenant_id=$1 AND skill_id=$2 AND channel=$3
              AND generation=$4`,
          [
            value.tenantId,
            value.skillId,
            value.channel,
            expectedGeneration,
            value.releaseId,
            value.generation,
            value.reasonRef,
            value.updatedAt,
          ],
        );
        if (result.rowCount !== 1) {
          fail("VERSION_CONFLICT", "C13 channel CAS did not match.");
        }
      },
      async appendEvent(value) {
        if (events.has(value.eventId)) {
          fail("ID_COLLISION", "C13 event was emitted twice.");
        }
        await client.query(
          `INSERT INTO ${table("skill_event")} (
             tenant_id,tenant_kind,event_id,idempotency_key,request_hash,
             effect_key,command_kind,aggregate_id,aggregate_version,
             event,created_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)`,
          [
            value.tenantId,
            value.tenantKind,
            value.eventId,
            metadata.idempotencyKey,
            metadata.requestHash,
            effectKey,
            metadata.commandKind,
            value.aggregateId,
            value.aggregateVersion,
            JSON.stringify(value.event),
            value.createdAt,
          ],
        );
        events.add(value.eventId);
      },
    });
  }

  function replay(row, metadata, effectKey) {
    if (!row) return null;
    if (
      row.request_hash !== metadata.requestHash ||
      row.effect_key !== effectKey ||
      row.command_kind !== metadata.commandKind
    ) {
      fail(
        "IDEMPOTENCY_CONFLICT",
        "C13 idempotency key was reused with different input.",
      );
    }
    return json(row.result);
  }

  async function runCommand(scope, metadata, reducer) {
    validateScope(scope);
    validateMetadata(metadata);
    if (typeof reducer !== "function") {
      fail("INVALID_INPUT", "C13 command reducer is required.");
    }
    const effectKey = deriveSkillCommandEffectKey({
      tenantId: scope.tenantId,
      commandKind: metadata.commandKind,
      idempotencyKey: metadata.idempotencyKey,
    });
    let lastError;
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      try {
        return await runScoped(
          "BEGIN ISOLATION LEVEL SERIALIZABLE",
          scope,
          async (client) => {
            const existing = await client.query(
              `SELECT request_hash,effect_key,command_kind,result
                 FROM ${table("command_receipt")}
                WHERE tenant_id=$1 AND idempotency_key=$2`,
              [scope.tenantId, metadata.idempotencyKey],
            );
            const previous = replay(
              existing.rows[0],
              metadata,
              effectKey,
            );
            if (previous) {
              return Object.freeze({ duplicate: true, value: previous });
            }
            const events = new Set();
            const value = await reducer(
              transactionPort(
                client,
                scope,
                metadata,
                effectKey,
                events,
              ),
            );
            if (
              !value ||
              typeof value !== "object" ||
              Array.isArray(value) ||
              events.size !== 1
            ) {
              fail(
                "INTEGRITY_VIOLATION",
                "C13 command requires one append-only event.",
              );
            }
            await client.query(
              `INSERT INTO ${table("command_receipt")} (
                 tenant_id,tenant_kind,idempotency_key,request_hash,
                 effect_key,command_kind,correlation_id,result
               ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
              [
                scope.tenantId,
                scope.tenantKind,
                metadata.idempotencyKey,
                metadata.requestHash,
                effectKey,
                metadata.commandKind,
                metadata.correlationId,
                JSON.stringify(value),
              ],
            );
            return Object.freeze({ duplicate: false, value });
          },
          JSON.stringify([scope.tenantId, metadata.idempotencyKey]),
        );
      } catch (error) {
        lastError = error;
        if (shouldRetry(error) && attempt < maxSerializableRetries) {
          await new Promise((resolve) =>
            setTimeout(
              resolve,
              retryDelay(metadata.idempotencyKey, attempt),
            ),
          );
          continue;
        }
        throw databaseFailure(error);
      }
    }
    throw databaseFailure(lastError);
  }

  async function readResolution(scope, query) {
    validateScope(scope);
    try {
      return await runScoped(
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        scope,
        async (client) => {
          const channel = await client.query(
            `SELECT * FROM ${table("skill_channel")}
              WHERE tenant_id=$1 AND skill_id=$2 AND channel=$3`,
            [scope.tenantId, query.skillId, query.channel],
          );
          const release = await client.query(
            `SELECT * FROM ${table("skill_release")}
              WHERE tenant_id=$1 AND skill_id=$2 AND semantic_version=$3`,
            [scope.tenantId, query.skillId, query.version],
          );
          return Object.freeze({
            channel: channelFromRow(channel.rows[0]),
            release: releaseFromRow(release.rows[0]),
          });
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function readRelease(scope, releaseId) {
    validateScope(scope);
    try {
      return await runScoped(
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        scope,
        async (client) => {
          const result = await client.query(
            `SELECT * FROM ${table("skill_release")}
              WHERE tenant_id=$1 AND release_id=$2`,
            [scope.tenantId, releaseId],
          );
          return releaseFromRow(result.rows[0]);
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function readTenantSnapshot(scope) {
    validateScope(scope);
    try {
      return await runScoped(
        "BEGIN ISOLATION LEVEL REPEATABLE READ",
        scope,
        async (client) => {
          const result = await client.query(
            `SELECT
               (SELECT count(*)::integer FROM ${table("skill_release")}
                 WHERE tenant_id=$1) AS releases,
               (SELECT count(*)::integer FROM ${table("skill_channel")}
                 WHERE tenant_id=$1) AS channels,
               (SELECT count(*)::integer FROM ${table("skill_event")}
                 WHERE tenant_id=$1) AS events,
               (SELECT count(*)::integer FROM ${table("command_receipt")}
                 WHERE tenant_id=$1) AS receipts`,
            [scope.tenantId],
          );
          return Object.freeze({
            tenantId: scope.tenantId,
            counts: Object.freeze({
              releases: integer(result.rows[0].releases),
              channels: integer(result.rows[0].channels),
              events: integer(result.rows[0].events),
              receipts: integer(result.rows[0].receipts),
            }),
          });
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  return Object.freeze({
    readRelease,
    readResolution,
    readTenantSnapshot,
    runCommand,
  });
}
