import {
  AuthorizationError,
} from "./authorization-facade.mjs";
import { isDeepStrictEqual } from "node:util";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const RETRYABLE_SQL_STATES = new Set(["40001", "40P01"]);
const RETRYABLE_CONSTRAINTS = new Set([
  "authorization_policy_release_pkey",
  "authorization_policy_release_tenant_template_key",
  "authorization_policy_release_tenant_sequence_key",
  "authorization_activation_tenant_version_key",
  "authorization_command_receipt_pkey",
  "authorization_decision_pkey",
]);

function fail(code, message) {
  throw new AuthorizationError(code, message);
}

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function jsonValue(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function safeInteger(value) {
  const result = Number(value);
  if (!Number.isSafeInteger(result)) {
    fail("STORE_UNAVAILABLE", "PostgreSQL returned an unsafe integer.");
  }
  return result;
}

function releaseFromRow(row) {
  const release = {
    policyReleaseId: row.policy_release_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    tenantLifecycleVersion: safeInteger(row.tenant_lifecycle_version),
    fixtureId: row.fixture_id,
    templateRef: row.template_ref,
    templateSequence: safeInteger(row.template_sequence),
    bundleSha256: row.bundle_sha256,
    modelSha256: row.model_sha256,
    operationCatalogVersion: row.operation_catalog_version,
    fixtureVersion: row.fixture_version,
    state: row.state,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
  if (row.state === "READY") {
    return {
      ...release,
      projectionOperationId: row.projection_operation_id,
      openFgaStoreId: row.openfga_store_id,
      authorizationModelId: row.authorization_model_id,
      tupleBundleSha256: row.tuple_bundle_sha256,
      fixtureReportRef: row.fixture_report_ref,
      fixtureReportSha256: row.fixture_report_sha256,
      fixturePassCount: safeInteger(row.fixture_pass_count),
      fixtureFailCount: safeInteger(row.fixture_fail_count),
    };
  }
  if (row.state === "FAILED") {
    return {
      ...release,
      projectionOperationId: row.projection_operation_id,
      projectionReasonRef: row.projection_reason_ref,
    };
  }
  return release;
}

function activationFromRow(row) {
  if (!row) return null;
  return {
    activationId: row.activation_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    policyReleaseId: row.policy_release_id,
    previousPolicyReleaseId: row.previous_policy_release_id,
    templateSequence: safeInteger(row.template_sequence),
    activationVersion: safeInteger(row.activation_version),
    activationKind: row.activation_kind,
    reasonRef: row.reason_ref,
    activatedAt: iso(row.activated_at),
  };
}

function decisionFromRow(row) {
  return {
    decisionId: row.decision_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    correlationId: row.correlation_id,
    surface: row.surface,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    resourceAuthorizationVersion: safeInteger(
      row.resource_authorization_version,
    ),
    humanPrincipalId: row.human_principal_id,
    humanSecurityEpoch: safeInteger(row.human_security_epoch),
    workloadActorPrincipalId: row.workload_actor_principal_id,
    workloadActorSecurityEpoch: safeInteger(
      row.workload_actor_security_epoch,
    ),
    leafDelegationId: row.leaf_delegation_id,
    delegationChainSha256: row.delegation_chain_sha256,
    purposeRef: row.purpose_ref,
    policyReleaseId: row.policy_release_id,
    bundleSha256: row.bundle_sha256,
    tupleBundleSha256: row.tuple_bundle_sha256,
    openFgaStoreId: row.openfga_store_id,
    authorizationModelId: row.authorization_model_id,
    activationVersion: safeInteger(row.activation_version),
    consistency: row.consistency,
    effect: row.effect,
    authorizationStatus: row.authorization_status,
    reasonCode: row.reason_code,
    inputSha256: row.input_sha256,
    checkTuples: jsonValue(row.check_tuples),
    checkResults: jsonValue(row.check_results),
    checkResultSha256: row.check_result_sha256,
    evaluatedAt: iso(row.evaluated_at),
    evidenceRef: row.evidence_ref,
  };
}

function exactDecisionReplay(
  row,
  {
    tenantId,
    expectedPolicyReleaseId,
    expectedActivationVersion,
    decision,
    event,
  },
) {
  if (!row) return null;
  const stored = decisionFromRow(row);
  const storedEvent = jsonValue(row.decision_event);
  const storedOutboxEvent = jsonValue(row.decision_outbox_event);
  if (
    stored.tenantId !== tenantId ||
    stored.policyReleaseId !== expectedPolicyReleaseId ||
    stored.activationVersion !== expectedActivationVersion ||
    row.decision_event_id !== event.id ||
    row.decision_outbox_event_id !== event.id ||
    !isDeepStrictEqual(stored, decision) ||
    !isDeepStrictEqual(storedEvent, event) ||
    !isDeepStrictEqual(storedOutboxEvent, event)
  ) {
    fail("ID_COLLISION", "Authorization decision already exists.");
  }
  return stored;
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original PostgreSQL failure.
  }
}

function databaseFailure(error) {
  if (error instanceof AuthorizationError) return error;
  if (
    error?.constraint === "authorization_tenant_active_guard"
  ) {
    return new AuthorizationError(
      "TENANT_NOT_ACTIVE",
      "The Synthetic Tenant is not active.",
    );
  }
  if (
    error?.constraint ===
    "authorization_decision_active_policy_guard"
  ) {
    return new AuthorizationError(
      "AUTHORIZATION_CHANGED",
      "Active policy changed during authorization.",
    );
  }
  if (
    error?.constraint?.startsWith("authorization_activation_") ||
    error?.constraint?.startsWith("authorization_active_")
  ) {
    return new AuthorizationError(
      "ACTIVATION_CONFLICT",
      "Policy activation changed.",
    );
  }
  if (
    error?.constraint?.startsWith("authorization_release_") ||
    error?.constraint?.startsWith(
      "authorization_policy_release_",
    )
  ) {
    return new AuthorizationError(
      "RELEASE_CONFLICT",
      "Policy Release conflicts with existing state.",
    );
  }
  if (
    error?.constraint === "authorization_event_outbox_pair_guard" ||
    error?.constraint === "authorization_decision_event_pair_guard"
  ) {
    return new AuthorizationError(
      "EVIDENCE_PAIR_INVALID",
      "Authorization evidence is not transactionally paired.",
    );
  }
  if (error?.code === "23505") {
    return new AuthorizationError(
      "ID_COLLISION",
      "Authorization record already exists.",
    );
  }
  if (error?.code === "23503" || error?.code === "23514") {
    return new AuthorizationError(
      "INTEGRITY_VIOLATION",
      "Authorization storage invariant failed.",
    );
  }
  return new AuthorizationError(
    "STORE_UNAVAILABLE",
    "Authorization storage operation failed.",
  );
}

function shouldRetry(error) {
  if (
    error?.constraint ===
    "authorization_decision_active_policy_guard"
  ) {
    return false;
  }
  return (
    RETRYABLE_SQL_STATES.has(error?.code) ||
    RETRYABLE_CONSTRAINTS.has(error?.constraint)
  );
}

function retryDelay(seed, attempt) {
  let hash = 0;
  for (const character of seed) {
    hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
  }
  return Math.min(5 * 2 ** attempt, 100) + (hash % 5);
}

function commandReplay(result, commandHash) {
  if (!result.rows[0]) return null;
  if (result.rows[0].command_hash !== commandHash) {
    fail(
      "IDEMPOTENCY_CONFLICT",
      "Idempotency key was used for another C06 command.",
    );
  }
  return jsonValue(result.rows[0].result);
}

function validateWorkerId(value) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 128
  ) {
    fail("INVALID_INPUT", "Outbox worker ID is invalid.");
  }
}

function validateEventId(value) {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value.length > 128
  ) {
    fail("INVALID_INPUT", "Outbox event ID is invalid.");
  }
}

export function createPostgresAuthorizationStore({
  pool,
  decisionPool = pool,
  outboxPool = pool,
  schema = "aios_core",
  maxSerializableRetries = 10,
}) {
  if (
    typeof pool?.connect !== "function" ||
    typeof decisionPool?.connect !== "function" ||
    typeof outboxPool?.connect !== "function" ||
    !SAFE_IDENTIFIER.test(schema)
  ) {
    fail(
      "INVALID_STORE",
      "PostgreSQL control, decision and outbox pools are required.",
    );
  }
  if (
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_STORE", "Invalid serializable retry limit.");
  }

  const table = (name) => `"${schema}"."${name}"`;

  async function connect(selectedPool) {
    try {
      return await selectedPool.connect();
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  function transactionPort(client) {
    return Object.freeze({
      async findReleaseByTemplate(tenantId, templateRef) {
        const result = await client.query(
          `SELECT *
             FROM ${table("authorization_policy_release")}
            WHERE tenant_id = $1
              AND template_ref = $2
              AND state <> 'FAILED'
            FOR SHARE`,
          [tenantId, templateRef],
        );
        return result.rows[0] ? releaseFromRow(result.rows[0]) : null;
      },
      async findRelease(policyReleaseId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("authorization_policy_release")}
            WHERE policy_release_id = $1
            FOR UPDATE`,
          [policyReleaseId],
        );
        return result.rows[0] ? releaseFromRow(result.rows[0]) : null;
      },
      async listReleases(tenantId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("authorization_policy_release")}
            WHERE tenant_id = $1
            ORDER BY template_sequence, policy_release_id
            FOR SHARE`,
          [tenantId],
        );
        return result.rows.map(releaseFromRow);
      },
      async insertRelease(release) {
        await client.query(
          `INSERT INTO ${table("authorization_policy_release")} (
             policy_release_id,
             tenant_id,
             tenant_kind,
             tenant_lifecycle_version,
             fixture_id,
             template_ref,
             template_sequence,
             bundle_sha256,
             model_sha256,
             operation_catalog_version,
             fixture_version,
             state,
             created_at,
             updated_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7,
             $8, $9, $10, $11, $12, $13, $14
           )`,
          [
            release.policyReleaseId,
            release.tenantId,
            release.tenantKind,
            release.tenantLifecycleVersion,
            release.fixtureId,
            release.templateRef,
            release.templateSequence,
            release.bundleSha256,
            release.modelSha256,
            release.operationCatalogVersion,
            release.fixtureVersion,
            release.state,
            release.createdAt,
            release.updatedAt,
          ],
        );
      },
      async putRelease(release) {
        const result = await client.query(
          `UPDATE ${table("authorization_policy_release")}
              SET state = $1,
                  projection_operation_id = $2,
                  projection_reason_ref = $3,
                  openfga_store_id = $4,
                  authorization_model_id = $5,
                  tuple_bundle_sha256 = $6,
                  fixture_report_ref = $7,
                  fixture_report_sha256 = $8,
                  fixture_pass_count = $9,
                  fixture_fail_count = $10,
                  updated_at = $11
            WHERE policy_release_id = $12`,
          [
            release.state,
            release.projectionOperationId ?? null,
            release.projectionReasonRef ?? null,
            release.openFgaStoreId ?? null,
            release.authorizationModelId ?? null,
            release.tupleBundleSha256 ?? null,
            release.fixtureReportRef ?? null,
            release.fixtureReportSha256 ?? null,
            release.fixturePassCount ?? null,
            release.fixtureFailCount ?? null,
            release.updatedAt,
            release.policyReleaseId,
          ],
        );
        if (result.rowCount !== 1) {
          fail("RELEASE_NOT_FOUND", "Policy Release was not found.");
        }
      },
      async activePolicy(tenantId) {
        const result = await client.query(
          `SELECT activation.*
             FROM ${table("authorization_active_policy")} AS active
             JOIN ${table("authorization_activation")} AS activation
               ON activation.activation_id = active.activation_id
              AND activation.tenant_id = active.tenant_id
            WHERE active.tenant_id = $1
            FOR UPDATE OF active`,
          [tenantId],
        );
        return result.rows[0] ? activationFromRow(result.rows[0]) : null;
      },
      async activate(activation) {
        await client.query(
          `INSERT INTO ${table("authorization_activation")} (
             activation_id,
             tenant_id,
             tenant_kind,
             policy_release_id,
             previous_policy_release_id,
             template_sequence,
             activation_version,
             activation_kind,
             reason_ref,
             activated_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
           )`,
          [
            activation.activationId,
            activation.tenantId,
            activation.tenantKind,
            activation.policyReleaseId,
            activation.previousPolicyReleaseId,
            activation.templateSequence,
            activation.activationVersion,
            activation.activationKind,
            activation.reasonRef,
            activation.activatedAt,
          ],
        );
        const parameters = [
          activation.tenantId,
          activation.tenantKind,
          activation.policyReleaseId,
          activation.activationId,
          activation.activationVersion,
          activation.activatedAt,
        ];
        if (activation.activationVersion === 1) {
          await client.query(
            `INSERT INTO ${table("authorization_active_policy")} (
               tenant_id,
               tenant_kind,
               policy_release_id,
               activation_id,
               activation_version,
               updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6)`,
            parameters,
          );
        } else {
          const result = await client.query(
            `UPDATE ${table("authorization_active_policy")}
                SET policy_release_id = $3,
                    activation_id = $4,
                    activation_version = $5,
                    updated_at = $6
              WHERE tenant_id = $1
                AND tenant_kind = $2`,
            parameters,
          );
          if (result.rowCount !== 1) {
            fail(
              "ACTIVATION_CONFLICT",
              "Policy activation changed.",
            );
          }
        }
      },
      async appendEvent(event) {
        const payload = JSON.stringify(event);
        await client.query(
          `INSERT INTO ${table("authorization_event")} (
             event_id, tenant_id, tenant_kind, event, created_at
           ) VALUES ($1, $2, $3, $4::jsonb, $5)`,
          [
            event.id,
            event.data.tenant_id,
            event.tenantkind,
            payload,
            event.time,
          ],
        );
        await client.query(
          `INSERT INTO ${table("authorization_outbox")} (
             event_id, tenant_id, tenant_kind, event, created_at
           ) VALUES ($1, $2, $3, $4::jsonb, $5)`,
          [
            event.id,
            event.data.tenant_id,
            event.tenantkind,
            payload,
            event.time,
          ],
        );
      },
    });
  }

  async function readCommandReceipt({
    tenantId,
    idempotencyKey,
    commandHash,
  }) {
    const client = await connect(pool);
    try {
      const result = await client.query(
        `SELECT command_hash, result
           FROM ${table("authorization_command_receipt")}
          WHERE tenant_id = $1
            AND idempotency_key = $2`,
        [tenantId, idempotencyKey],
      );
      return commandReplay(result, commandHash);
    } catch (error) {
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  async function readPolicyRelease(policyReleaseId) {
    const client = await connect(pool);
    try {
      const result = await client.query(
        `SELECT *
           FROM ${table("authorization_policy_release")}
          WHERE policy_release_id = $1`,
        [policyReleaseId],
      );
      return result.rows[0] ? releaseFromRow(result.rows[0]) : null;
    } catch (error) {
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  async function runCommand(
    { tenantId, idempotencyKey, commandHash },
    reducer,
  ) {
    let lastError;
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      const receipt = await readCommandReceipt({
        tenantId,
        idempotencyKey,
        commandHash,
      });
      if (receipt) return { duplicate: true, value: receipt };

      const client = await connect(pool);
      let transactionStarted = false;
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        transactionStarted = true;
        const existing = await client.query(
          `SELECT command_hash, result
             FROM ${table("authorization_command_receipt")}
            WHERE tenant_id = $1
              AND idempotency_key = $2`,
          [tenantId, idempotencyKey],
        );
        const replay = commandReplay(existing, commandHash);
        if (replay) {
          await client.query("COMMIT");
          transactionStarted = false;
          return { duplicate: true, value: replay };
        }
        const value = await reducer(transactionPort(client));
        await client.query(
          `INSERT INTO ${table("authorization_command_receipt")} (
             tenant_id,
             tenant_kind,
             idempotency_key,
             command_hash,
             result
           ) VALUES ($1, 'SYNTHETIC', $2, $3, $4::jsonb)`,
          [
            tenantId,
            idempotencyKey,
            commandHash,
            JSON.stringify(value),
          ],
        );
        await client.query("COMMIT");
        transactionStarted = false;
        return { duplicate: false, value };
      } catch (error) {
        lastError = error;
        if (transactionStarted) await rollback(client);
        if (shouldRetry(error) && attempt < maxSerializableRetries) {
          await new Promise((resolve) =>
            setTimeout(
              resolve,
              retryDelay(idempotencyKey, attempt),
            ),
          );
          continue;
        }
        throw databaseFailure(error);
      } finally {
        client.release();
      }
    }
    throw databaseFailure(lastError);
  }

  async function readActiveRelease(tenantId) {
    const client = await connect(decisionPool);
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const activeResult = await client.query(
        `SELECT activation.*
           FROM ${table("authorization_active_policy")} AS active
           JOIN ${table("authorization_activation")} AS activation
             ON activation.activation_id = active.activation_id
            AND activation.tenant_id = active.tenant_id
          WHERE active.tenant_id = $1`,
        [tenantId],
      );
      if (!activeResult.rows[0]) {
        await client.query("COMMIT");
        return null;
      }
      const releaseResult = await client.query(
        `SELECT *
           FROM ${table("authorization_policy_release")}
          WHERE policy_release_id = $1
            AND tenant_id = $2`,
        [activeResult.rows[0].policy_release_id, tenantId],
      );
      await client.query("COMMIT");
      return {
        active: activationFromRow(activeResult.rows[0]),
        release: releaseResult.rows[0]
          ? releaseFromRow(releaseResult.rows[0])
          : null,
      };
    } catch (error) {
      await rollback(client);
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  async function insertDecision(client, decision) {
    await client.query(
      `INSERT INTO ${table("authorization_decision")} (
         decision_id,
         tenant_id,
         tenant_kind,
         correlation_id,
         surface,
         resource_type,
         resource_id,
         resource_authorization_version,
         human_principal_id,
         human_security_epoch,
         workload_actor_principal_id,
         workload_actor_security_epoch,
         leaf_delegation_id,
         delegation_chain_sha256,
         purpose_ref,
         policy_release_id,
         bundle_sha256,
         openfga_store_id,
         authorization_model_id,
         activation_version,
         consistency,
         effect,
         authorization_status,
         reason_code,
         input_sha256,
         check_tuples,
         check_results,
         check_result_sha256,
         evaluated_at,
         evidence_ref
       ) VALUES (
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
         $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
         $21, $22, $23, $24, $25, $26::jsonb, $27::jsonb, $28,
         $29, $30
       )`,
      [
        decision.decisionId,
        decision.tenantId,
        decision.tenantKind,
        decision.correlationId,
        decision.surface,
        decision.resourceType,
        decision.resourceId,
        decision.resourceAuthorizationVersion,
        decision.humanPrincipalId,
        decision.humanSecurityEpoch,
        decision.workloadActorPrincipalId,
        decision.workloadActorSecurityEpoch,
        decision.leafDelegationId,
        decision.delegationChainSha256,
        decision.purposeRef,
        decision.policyReleaseId,
        decision.bundleSha256,
        decision.openFgaStoreId,
        decision.authorizationModelId,
        decision.activationVersion,
        decision.consistency,
        decision.effect,
        decision.authorizationStatus,
        decision.reasonCode,
        decision.inputSha256,
        JSON.stringify(decision.checkTuples),
        JSON.stringify(decision.checkResults),
        decision.checkResultSha256,
        decision.evaluatedAt,
        decision.evidenceRef,
      ],
    );
  }

  async function appendEvidence(client, event) {
    const payload = JSON.stringify(event);
    await client.query(
      `INSERT INTO ${table("authorization_event")} (
         event_id, tenant_id, tenant_kind, event, created_at
       ) VALUES ($1, $2, $3, $4::jsonb, $5)`,
      [
        event.id,
        event.data.tenant_id,
        event.tenantkind,
        payload,
        event.time,
      ],
    );
    await client.query(
      `INSERT INTO ${table("authorization_outbox")} (
         event_id, tenant_id, tenant_kind, event, created_at
       ) VALUES ($1, $2, $3, $4::jsonb, $5)`,
      [
        event.id,
        event.data.tenant_id,
        event.tenantkind,
        payload,
        event.time,
      ],
    );
  }

  async function recordDecision({
    tenantId,
    expectedPolicyReleaseId,
    expectedActivationVersion,
    decision,
    event,
  }) {
    let lastError;
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      const client = await connect(decisionPool);
      let transactionStarted = false;
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        transactionStarted = true;
        const existing = await client.query(
          `SELECT
             decision.*,
             release.tuple_bundle_sha256,
             evidence.event_id AS decision_event_id,
             evidence.event AS decision_event,
             outbox.event_id AS decision_outbox_event_id,
             outbox.event AS decision_outbox_event
             FROM ${table("authorization_decision")} AS decision
            JOIN ${table("authorization_policy_release")} AS release
               ON release.policy_release_id = decision.policy_release_id
              AND release.tenant_id = decision.tenant_id
            LEFT JOIN ${table("authorization_event")} AS evidence
              ON (evidence.event ->> 'subject') = decision.decision_id
             AND (evidence.event ->> 'type') =
               'product.authorization.decision-recorded.v1'
            LEFT JOIN ${table("authorization_outbox")} AS outbox
              ON outbox.event_id = evidence.event_id
            WHERE decision.decision_id = $1
              AND decision.tenant_id = $2`,
          [decision.decisionId, tenantId],
        );
        const replay = exactDecisionReplay(existing.rows[0], {
          tenantId,
          expectedPolicyReleaseId,
          expectedActivationVersion,
          decision,
          event,
        });
        if (replay) {
          await client.query("COMMIT");
          transactionStarted = false;
          return replay;
        }
        const current = await client.query(
          `SELECT policy_release_id, activation_version
             FROM ${table("authorization_active_policy")}
            WHERE tenant_id = $1`,
          [tenantId],
        );
        if (
          !current.rows[0] ||
          current.rows[0].policy_release_id !==
            expectedPolicyReleaseId ||
          safeInteger(current.rows[0].activation_version) !==
            expectedActivationVersion
        ) {
          fail(
            "AUTHORIZATION_CHANGED",
            "Active policy changed during authorization.",
          );
        }
        await insertDecision(client, decision);
        await appendEvidence(client, event);
        await client.query("COMMIT");
        transactionStarted = false;
        return decision;
      } catch (error) {
        lastError = error;
        if (transactionStarted) await rollback(client);
        if (shouldRetry(error) && attempt < maxSerializableRetries) {
          await new Promise((resolve) =>
            setTimeout(
              resolve,
              retryDelay(decision.decisionId, attempt),
            ),
          );
          continue;
        }
        throw databaseFailure(error);
      } finally {
        client.release();
      }
    }
    throw databaseFailure(lastError);
  }

  async function readDecision(decisionId) {
    const client = await connect(pool);
    try {
      const result = await client.query(
        `SELECT
           decision.*,
           release.tuple_bundle_sha256
           FROM ${table("authorization_decision")} AS decision
           JOIN ${table("authorization_policy_release")} AS release
             ON release.policy_release_id = decision.policy_release_id
            AND release.tenant_id = decision.tenant_id
          WHERE decision.decision_id = $1`,
        [decisionId],
      );
      return result.rows[0] ? decisionFromRow(result.rows[0]) : null;
    } catch (error) {
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  async function readTenantSnapshot(tenantId) {
    const client = await connect(pool);
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const releases = await client.query(
        `SELECT *
           FROM ${table("authorization_policy_release")}
          WHERE tenant_id = $1
          ORDER BY template_sequence, policy_release_id`,
        [tenantId],
      );
      const active = await client.query(
        `SELECT activation.*
           FROM ${table("authorization_active_policy")} AS current
           JOIN ${table("authorization_activation")} AS activation
             ON activation.activation_id = current.activation_id
            AND activation.tenant_id = current.tenant_id
          WHERE current.tenant_id = $1`,
        [tenantId],
      );
      const activations = await client.query(
        `SELECT *
           FROM ${table("authorization_activation")}
          WHERE tenant_id = $1
          ORDER BY activation_version, activation_id`,
        [tenantId],
      );
      const decisions = await client.query(
        `SELECT
           decision.*,
           release.tuple_bundle_sha256
           FROM ${table("authorization_decision")} AS decision
           JOIN ${table("authorization_policy_release")} AS release
             ON release.policy_release_id = decision.policy_release_id
            AND release.tenant_id = decision.tenant_id
          WHERE decision.tenant_id = $1
          ORDER BY decision.evaluated_at, decision.decision_id`,
        [tenantId],
      );
      const events = await client.query(
        `SELECT event
           FROM ${table("authorization_event")}
          WHERE tenant_id = $1
          ORDER BY created_at, event_id`,
        [tenantId],
      );
      const outbox = await client.query(
        `SELECT event
           FROM ${table("authorization_outbox")}
          WHERE tenant_id = $1
          ORDER BY created_at, event_id`,
        [tenantId],
      );
      await client.query("COMMIT");
      return {
        releases: releases.rows.map(releaseFromRow),
        activePolicy: active.rows[0]
          ? activationFromRow(active.rows[0])
          : null,
        activations: activations.rows.map(activationFromRow),
        decisions: decisions.rows.map(decisionFromRow),
        events: events.rows.map(({ event }) => jsonValue(event)),
        outbox: outbox.rows.map(({ event }) => jsonValue(event)),
      };
    } catch (error) {
      await rollback(client);
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  async function claimOutbox({
    workerId,
    limit,
    leaseSeconds,
  }) {
    validateWorkerId(workerId);
    if (
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 100 ||
      !Number.isSafeInteger(leaseSeconds) ||
      leaseSeconds < 1 ||
      leaseSeconds > 300
    ) {
      fail("INVALID_INPUT", "Outbox claim bounds are invalid.");
    }
    const client = await connect(outboxPool);
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `WITH candidates AS (
           SELECT event_id
             FROM ${table("authorization_outbox")}
            WHERE (
                    status IN ('PENDING', 'FAILED')
                    AND available_at <= statement_timestamp()
                  )
               OR (
                    status = 'PROCESSING'
                    AND lease_until < statement_timestamp()
                  )
            ORDER BY created_at, event_id
            FOR UPDATE SKIP LOCKED
            LIMIT $1
         )
         UPDATE ${table("authorization_outbox")} AS outbox
            SET status = 'PROCESSING',
                attempt_count = attempt_count + 1,
                lease_version = lease_version + 1,
                leased_by = $2,
                lease_until =
                  statement_timestamp() + ($3::integer * interval '1 second'),
                last_error_code = NULL
           FROM candidates
          WHERE outbox.event_id = candidates.event_id
         RETURNING outbox.event_id, outbox.lease_version, outbox.event`,
        [limit, workerId, leaseSeconds],
      );
      await client.query("COMMIT");
      return result.rows.map((row) => ({
        eventId: row.event_id,
        workerId,
        leaseVersion: safeInteger(row.lease_version),
        event: jsonValue(row.event),
      }));
    } catch (error) {
      await rollback(client);
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  async function completeOutbox({
    eventId,
    workerId,
    leaseVersion,
  }) {
    validateEventId(eventId);
    validateWorkerId(workerId);
    if (!Number.isSafeInteger(leaseVersion) || leaseVersion < 1) {
      fail("INVALID_INPUT", "Outbox lease version is invalid.");
    }
    const client = await connect(outboxPool);
    try {
      const result = await client.query(
        `UPDATE ${table("authorization_outbox")}
            SET status = 'PUBLISHED',
                leased_by = NULL,
                lease_until = NULL,
                last_error_code = NULL,
                published_at = statement_timestamp()
          WHERE event_id = $1
            AND leased_by = $2
            AND lease_version = $3
            AND lease_until >= statement_timestamp()
            AND status = 'PROCESSING'`,
        [eventId, workerId, leaseVersion],
      );
      if (result.rowCount !== 1) {
        fail("STALE_OUTBOX_LEASE", "Outbox lease is not current.");
      }
    } catch (error) {
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  async function failOutbox({
    eventId,
    workerId,
    leaseVersion,
    errorCode,
    retryDelaySeconds,
  }) {
    validateEventId(eventId);
    validateWorkerId(workerId);
    if (
      !Number.isSafeInteger(leaseVersion) ||
      leaseVersion < 1 ||
      typeof errorCode !== "string" ||
      !errorCode.trim() ||
      errorCode.length > 128 ||
      !Number.isSafeInteger(retryDelaySeconds) ||
      retryDelaySeconds < 1 ||
      retryDelaySeconds > 3600
    ) {
      fail("INVALID_INPUT", "Outbox failure receipt is invalid.");
    }
    const client = await connect(outboxPool);
    try {
      const result = await client.query(
        `UPDATE ${table("authorization_outbox")}
            SET status = 'FAILED',
                available_at =
                  statement_timestamp() +
                  ($4::integer * interval '1 second'),
                leased_by = NULL,
                lease_until = NULL,
                last_error_code = $5,
                published_at = NULL
          WHERE event_id = $1
            AND leased_by = $2
            AND lease_version = $3
            AND lease_until >= statement_timestamp()
            AND status = 'PROCESSING'`,
        [
          eventId,
          workerId,
          leaseVersion,
          retryDelaySeconds,
          errorCode,
        ],
      );
      if (result.rowCount !== 1) {
        fail("STALE_OUTBOX_LEASE", "Outbox lease is not current.");
      }
    } catch (error) {
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    claimOutbox,
    completeOutbox,
    failOutbox,
    readActiveRelease,
    readCommandReceipt,
    readDecision,
    readPolicyRelease,
    readTenantSnapshot,
    recordDecision,
    runCommand,
  });
}
