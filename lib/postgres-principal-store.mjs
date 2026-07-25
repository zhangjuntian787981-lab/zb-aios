import {
  StablePrincipalError,
} from "./stable-principal.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const RETRYABLE_SQL_STATES = new Set(["40001", "40P01"]);
const RETRYABLE_CONSTRAINTS = new Set([
  "principal_registry_creation_key",
  "principal_identity_link_current_account_key",
  "principal_command_receipt_pkey",
]);

function fail(code, message) {
  throw new StablePrincipalError(code, message);
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
    fail("STORE_INVALID_DATA", "Stored integer is outside the safe range.");
  }
  return result;
}

function principalFromRow(row) {
  return {
    principalId: row.principal_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    principalType: row.principal_kind,
    fixturePrincipalRef: row.creation_key,
    state: row.state,
    lifecycleVersion: safeInteger(row.lifecycle_version),
    securityEpoch: safeInteger(row.security_epoch),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function linkFromRow(row) {
  return {
    identityLinkId: row.identity_link_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    identityAccountId: row.identity_account_id,
    providerConnectionId: row.provider_connection_id,
    principalId: row.principal_id,
    principalType: row.principal_kind,
    linkEvidenceRef: row.link_evidence_ref,
    state: row.state,
    lifecycleVersion: safeInteger(row.lifecycle_version),
    accountLifecycleVersion: safeInteger(row.account_lifecycle_version),
    accountRevocationEpoch: safeInteger(row.account_revocation_epoch),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    retiredAt: iso(row.retired_at),
  };
}

function delegationFromRow(row) {
  return {
    delegationId: row.delegation_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    humanSubjectPrincipalId: row.human_subject_principal_id,
    humanSubjectKind: row.human_subject_kind,
    humanSubjectSecurityEpoch: safeInteger(
      row.human_subject_security_epoch,
    ),
    delegatorPrincipalId: row.delegator_principal_id,
    delegatorKind: row.delegator_kind,
    delegatorSecurityEpoch: safeInteger(row.delegator_security_epoch),
    delegatePrincipalId: row.delegate_principal_id,
    delegateKind: row.delegate_kind,
    delegateSecurityEpoch: safeInteger(row.delegate_security_epoch),
    parentDelegationId: row.parent_delegation_id,
    depth: safeInteger(row.depth),
    purposeRef: row.provenance_ref,
    state: row.state,
    lifecycleVersion: safeInteger(row.lifecycle_version),
    issuedAt: iso(row.created_at),
    expiresAt: iso(row.expires_at),
    revokedAt: iso(row.revoked_at),
    revocationReasonRef: row.revocation_reason_ref,
  };
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original database failure.
  }
}

function databaseFailure(error) {
  if (error instanceof StablePrincipalError) return error;
  if (error?.constraint === "principal_tenant_active_guard") {
    return new StablePrincipalError(
      "TENANT_NOT_ACTIVE",
      "Tenant is not active.",
    );
  }
  if (
    error?.constraint === "principal_identity_link_current_account_key"
  ) {
    return new StablePrincipalError(
      "IDENTITY_LINK_CONFLICT",
      "Identity Account already has a current Stable Principal.",
    );
  }
  if (
    error?.constraint === "principal_command_receipt_pkey"
  ) {
    return new StablePrincipalError(
      "IDEMPOTENCY_CONFLICT",
      "C05 command receipt already exists.",
    );
  }
  if (
    [
      "principal_registry_version_guard",
      "principal_identity_link_version_guard",
      "principal_delegation_terminal_guard",
    ].includes(error?.constraint)
  ) {
    return new StablePrincipalError(
      "VERSION_CONFLICT",
      "C05 record changed concurrently.",
    );
  }
  if (
    [
      "principal_registry_terminal_guard",
      "principal_registry_transition_guard",
      "principal_registry_active_relation_guard",
    ].includes(error?.constraint)
  ) {
    return new StablePrincipalError(
      "INVALID_PRINCIPAL_STATE",
      "Principal lifecycle transition is invalid.",
    );
  }
  if (
    [
      "principal_identity_link_account_state_guard",
      "principal_identity_link_principal_state_guard",
      "principal_identity_link_terminal_guard",
      "principal_identity_link_transition_guard",
    ].includes(error?.constraint)
  ) {
    return new StablePrincipalError(
      "IDENTITY_LINK_CONFLICT",
      "Identity Link state is invalid.",
    );
  }
  if (
    typeof error?.constraint === "string" &&
    error.constraint.startsWith("principal_delegation_")
  ) {
    return new StablePrincipalError(
      "DELEGATION_INVALID",
      "Delegation chain is invalid.",
    );
  }
  if (error?.code === "23503") {
    return new StablePrincipalError(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "C05 cross-Tenant or upstream identity binding was rejected.",
    );
  }
  if (error?.code === "23505") {
    return new StablePrincipalError(
      "ID_COLLISION",
      "C05 identifier already exists.",
    );
  }
  return new StablePrincipalError(
    "STORE_UNAVAILABLE",
    "Stable Principal storage operation failed.",
  );
}

function shouldRetry(error) {
  return (
    RETRYABLE_SQL_STATES.has(error?.code) ||
    (error?.code === "23505" &&
      RETRYABLE_CONSTRAINTS.has(error?.constraint))
  );
}

function retryDelay(seed, attempt) {
  let spread = 0;
  for (const character of seed) {
    spread = (spread + character.codePointAt(0)) % 37;
  }
  return Math.min(5 * 2 ** attempt, 100) + spread;
}

function commandReplay(result, commandHash) {
  if (!result.rows[0]) return null;
  if (result.rows[0].command_hash !== commandHash) {
    fail(
      "IDEMPOTENCY_CONFLICT",
      "The idempotency key was used for another C05 command.",
    );
  }
  return {
    duplicate: true,
    value: jsonValue(result.rows[0].result),
  };
}

export function createPostgresPrincipalStore({
  pool,
  schema = "aios_core",
  maxSerializableRetries = 10,
}) {
  if (!pool?.connect || !SAFE_IDENTIFIER.test(schema)) {
    fail("INVALID_STORE", "A PostgreSQL pool and safe schema are required.");
  }
  if (
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_STORE", "Invalid serializable retry limit.");
  }

  const table = (name) => `"${schema}"."${name}"`;

  async function connect() {
    try {
      return await pool.connect();
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  function transactionPort(client) {
    return Object.freeze({
      async findPrincipalByFixture(tenantId, fixturePrincipalRef) {
        const result = await client.query(
          `SELECT *
             FROM ${table("principal_registry")}
            WHERE tenant_id = $1
              AND creation_key = $2`,
          [tenantId, fixturePrincipalRef],
        );
        return result.rows[0] ? principalFromRow(result.rows[0]) : null;
      },
      async loadPrincipalForUpdate(principalId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("principal_registry")}
            WHERE principal_id = $1
            FOR UPDATE`,
          [principalId],
        );
        return result.rows[0] ? principalFromRow(result.rows[0]) : null;
      },
      async insertPrincipal(principal) {
        await client.query(
          `INSERT INTO ${table("principal_registry")} (
             principal_id,
             tenant_id,
             tenant_kind,
             principal_kind,
             creation_key,
             state,
             lifecycle_version,
             security_epoch,
             created_at,
             updated_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
          [
            principal.principalId,
            principal.tenantId,
            principal.tenantKind,
            principal.principalType,
            principal.fixturePrincipalRef,
            principal.state,
            principal.lifecycleVersion,
            principal.securityEpoch,
            principal.createdAt,
            principal.updatedAt,
          ],
        );
      },
      async putPrincipal(principal) {
        const result = await client.query(
          `UPDATE ${table("principal_registry")}
              SET state = $1,
                  lifecycle_version = $2,
                  security_epoch = $3,
                  updated_at = $4
            WHERE principal_id = $5`,
          [
            principal.state,
            principal.lifecycleVersion,
            principal.securityEpoch,
            principal.updatedAt,
            principal.principalId,
          ],
        );
        if (result.rowCount !== 1) {
          fail("PRINCIPAL_NOT_FOUND", "Principal was not found.");
        }
      },
      async loadCurrentIdentityLinkForAccount(
        tenantId,
        identityAccountId,
      ) {
        const result = await client.query(
          `SELECT *
             FROM ${table("principal_identity_link")}
            WHERE tenant_id = $1
              AND identity_account_id = $2
              AND state IN ('ACTIVE', 'SUSPENDED')
            FOR UPDATE`,
          [tenantId, identityAccountId],
        );
        return result.rows[0] ? linkFromRow(result.rows[0]) : null;
      },
      async loadIdentityLinkForUpdate(identityLinkId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("principal_identity_link")}
            WHERE identity_link_id = $1
            FOR UPDATE`,
          [identityLinkId],
        );
        return result.rows[0] ? linkFromRow(result.rows[0]) : null;
      },
      async listIdentityLinks(tenantId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("principal_identity_link")}
            WHERE tenant_id = $1
            ORDER BY identity_link_id
            FOR UPDATE`,
          [tenantId],
        );
        return result.rows.map(linkFromRow);
      },
      async insertIdentityLink(link) {
        await client.query(
          `INSERT INTO ${table("principal_identity_link")} (
             identity_link_id,
             tenant_id,
             tenant_kind,
             identity_account_id,
             provider_connection_id,
             principal_id,
             principal_kind,
             link_evidence_ref,
             state,
             lifecycle_version,
             account_lifecycle_version,
             account_revocation_epoch,
             created_at,
             updated_at,
             retired_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
           )`,
          [
            link.identityLinkId,
            link.tenantId,
            link.tenantKind,
            link.identityAccountId,
            link.providerConnectionId,
            link.principalId,
            link.principalType,
            link.linkEvidenceRef,
            link.state,
            link.lifecycleVersion,
            link.accountLifecycleVersion,
            link.accountRevocationEpoch,
            link.createdAt,
            link.updatedAt,
            link.retiredAt,
          ],
        );
      },
      async putIdentityLink(link) {
        const result = await client.query(
          `UPDATE ${table("principal_identity_link")}
              SET state = $1,
                  lifecycle_version = $2,
                  account_lifecycle_version = $3,
                  account_revocation_epoch = $4,
                  updated_at = $5,
                  retired_at = $6
            WHERE identity_link_id = $7`,
          [
            link.state,
            link.lifecycleVersion,
            link.accountLifecycleVersion,
            link.accountRevocationEpoch,
            link.updatedAt,
            link.retiredAt,
            link.identityLinkId,
          ],
        );
        if (result.rowCount !== 1) {
          fail("IDENTITY_LINK_NOT_FOUND", "Identity Link was not found.");
        }
      },
      async loadDelegationForUpdate(delegationId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("principal_delegation")}
            WHERE delegation_id = $1
            FOR UPDATE`,
          [delegationId],
        );
        return result.rows[0] ? delegationFromRow(result.rows[0]) : null;
      },
      async listDelegations(tenantId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("principal_delegation")}
            WHERE tenant_id = $1
            ORDER BY depth DESC, delegation_id
            FOR UPDATE`,
          [tenantId],
        );
        return result.rows.map(delegationFromRow);
      },
      async insertDelegation(delegation) {
        await client.query(
          `INSERT INTO ${table("principal_delegation")} (
             delegation_id,
             tenant_id,
             tenant_kind,
             human_subject_principal_id,
             human_subject_kind,
             human_subject_security_epoch,
             delegator_principal_id,
             delegator_kind,
             delegator_security_epoch,
             delegate_principal_id,
             delegate_kind,
             delegate_security_epoch,
             parent_delegation_id,
             depth,
             provenance_ref,
             state,
             lifecycle_version,
             created_at,
             expires_at,
             revoked_at,
             revocation_reason_ref
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
             $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
           )`,
          [
            delegation.delegationId,
            delegation.tenantId,
            delegation.tenantKind,
            delegation.humanSubjectPrincipalId,
            delegation.humanSubjectKind,
            delegation.humanSubjectSecurityEpoch,
            delegation.delegatorPrincipalId,
            delegation.delegatorKind,
            delegation.delegatorSecurityEpoch,
            delegation.delegatePrincipalId,
            delegation.delegateKind,
            delegation.delegateSecurityEpoch,
            delegation.parentDelegationId,
            delegation.depth,
            delegation.purposeRef,
            delegation.state,
            delegation.lifecycleVersion,
            delegation.issuedAt,
            delegation.expiresAt,
            delegation.revokedAt,
            delegation.revocationReasonRef,
          ],
        );
      },
      async putDelegation(delegation) {
        const result = await client.query(
          `UPDATE ${table("principal_delegation")}
              SET state = $1,
                  lifecycle_version = $2,
                  revoked_at = $3,
                  revocation_reason_ref = $4
            WHERE delegation_id = $5`,
          [
            delegation.state,
            delegation.lifecycleVersion,
            delegation.revokedAt,
            delegation.revocationReasonRef,
            delegation.delegationId,
          ],
        );
        if (result.rowCount !== 1) {
          fail("DELEGATION_NOT_FOUND", "Delegation was not found.");
        }
      },
      async appendEvent(event) {
        await client.query(
          `INSERT INTO ${table("principal_event")} (
             event_id, tenant_id, tenant_kind, event, created_at
           ) VALUES ($1, $2, $3, $4::jsonb, $5)`,
          [
            event.id,
            event.data.tenant_id,
            event.tenantkind,
            JSON.stringify(event),
            event.time,
          ],
        );
      },
      async appendOutbox(event) {
        await client.query(
          `INSERT INTO ${table("principal_outbox")} (
             event_id, tenant_id, tenant_kind, event, created_at
           ) VALUES ($1, $2, $3, $4::jsonb, $5)`,
          [
            event.id,
            event.data.tenant_id,
            event.tenantkind,
            JSON.stringify(event),
            event.time,
          ],
        );
      },
    });
  }

  async function runCommand(
    { tenantId, idempotencyKey, commandHash },
    reducer,
    preflight = async () => undefined,
  ) {
    let lastError;
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      const receiptClient = await connect();
      try {
        const existing = await receiptClient.query(
          `SELECT command_hash, result
             FROM ${table("principal_command_receipt")}
            WHERE tenant_id = $1
              AND idempotency_key = $2`,
          [tenantId, idempotencyKey],
        );
        const replay = commandReplay(existing, commandHash);
        if (replay) return replay;
      } catch (error) {
        throw databaseFailure(error);
      } finally {
        receiptClient.release();
      }

      const prepared = await preflight();
      const client = await connect();
      let transactionStarted = false;
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        transactionStarted = true;
        const existing = await client.query(
          `SELECT command_hash, result
             FROM ${table("principal_command_receipt")}
            WHERE tenant_id = $1
              AND idempotency_key = $2`,
          [tenantId, idempotencyKey],
        );
        const replay = commandReplay(existing, commandHash);
        if (replay) {
          await client.query("COMMIT");
          transactionStarted = false;
          return replay;
        }
        const value = await reducer(transactionPort(client), prepared);
        await client.query(
          `INSERT INTO ${table("principal_command_receipt")} (
             tenant_id,
             tenant_kind,
             idempotency_key,
             command_hash,
             result
           ) VALUES ($1, 'SYNTHETIC', $2, $3, $4::jsonb)`,
          [tenantId, idempotencyKey, commandHash, JSON.stringify(value)],
        );
        await client.query("COMMIT");
        transactionStarted = false;
        return { duplicate: false, value };
      } catch (error) {
        lastError = error;
        if (transactionStarted) await rollback(client);
        if (
          shouldRetry(error) &&
          attempt < maxSerializableRetries
        ) {
          await new Promise((resolve) =>
            setTimeout(resolve, retryDelay(idempotencyKey, attempt)),
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

  async function readTenantSnapshot(tenantId) {
    const client = await connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const principals = await client.query(
        `SELECT *
           FROM ${table("principal_registry")}
          WHERE tenant_id = $1
          ORDER BY principal_id`,
        [tenantId],
      );
      const links = await client.query(
        `SELECT *
           FROM ${table("principal_identity_link")}
          WHERE tenant_id = $1
          ORDER BY identity_link_id`,
        [tenantId],
      );
      const delegations = await client.query(
        `SELECT *
           FROM ${table("principal_delegation")}
          WHERE tenant_id = $1
          ORDER BY depth, delegation_id`,
        [tenantId],
      );
      const events = await client.query(
        `SELECT event
           FROM ${table("principal_event")}
          WHERE tenant_id = $1
          ORDER BY created_at, event_id`,
        [tenantId],
      );
      const outbox = await client.query(
        `SELECT event
           FROM ${table("principal_outbox")}
          WHERE tenant_id = $1
          ORDER BY created_at, event_id`,
        [tenantId],
      );
      await client.query("COMMIT");
      return {
        principals: principals.rows.map(principalFromRow),
        links: links.rows.map(linkFromRow),
        delegations: delegations.rows.map(delegationFromRow),
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

  async function readActionSnapshot({
    tenantId,
    identityAccountId,
    workloadActorPrincipalId,
    delegationId,
  }) {
    const client = await connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
      const linkResult = await client.query(
        `SELECT *
           FROM ${table("principal_identity_link")}
          WHERE tenant_id = $1
            AND identity_account_id = $2
            AND state IN ('ACTIVE', 'SUSPENDED')`,
        [tenantId, identityAccountId],
      );
      const link = linkResult.rows[0]
        ? linkFromRow(linkResult.rows[0])
        : null;
      const delegationResult = await client.query(
        `WITH RECURSIVE delegation_chain AS (
           SELECT delegation.*, 1 AS walk_depth,
                  ARRAY[delegation.delegation_id]::text[] AS visited
             FROM ${table("principal_delegation")} AS delegation
            WHERE delegation.tenant_id = $1
              AND delegation.delegation_id = $2
           UNION ALL
           SELECT parent.*, chain.walk_depth + 1,
                  chain.visited || parent.delegation_id
             FROM ${table("principal_delegation")} AS parent
             JOIN delegation_chain AS chain
               ON parent.delegation_id = chain.parent_delegation_id
              AND parent.tenant_id = $1
            WHERE chain.walk_depth < 8
              AND NOT parent.delegation_id = ANY(chain.visited)
         )
         SELECT *
           FROM delegation_chain
          ORDER BY depth, delegation_id`,
        [tenantId, delegationId],
      );
      const delegations = delegationResult.rows.map(delegationFromRow);
      const principalIds = Array.from(new Set([
        link?.principalId,
        workloadActorPrincipalId,
        ...delegations.flatMap((delegation) => [
          delegation.humanSubjectPrincipalId,
          delegation.delegatorPrincipalId,
          delegation.delegatePrincipalId,
        ]),
      ].filter(Boolean)));
      const principalResult = await client.query(
        `SELECT *
           FROM ${table("principal_registry")}
          WHERE tenant_id = $1
            AND principal_id = ANY($2::text[])`,
        [tenantId, principalIds],
      );
      const directPrincipals = new Map(
        principalResult.rows.map((row) => {
          const value = principalFromRow(row);
          return [value.principalId, value];
        }),
      );
      await client.query("COMMIT");
      return {
        link,
        humanSubject: link
          ? directPrincipals.get(link.principalId) ?? null
          : null,
        workloadActor:
          directPrincipals.get(workloadActorPrincipalId) ?? null,
        principals: Array.from(directPrincipals.values()),
        delegations,
      };
    } catch (error) {
      await rollback(client);
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  return Object.freeze({
    runCommand,
    readTenantSnapshot,
    readActionSnapshot,
  });
}
