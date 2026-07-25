import { IdentityFederationError } from "./identity-federation.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const RETRYABLE_SQL_STATES = new Set(["40001", "40P01"]);
const RETRYABLE_CONSTRAINTS = new Set([
  "identity_provider_tenant_id_key",
]);

function fail(code, message) {
  throw new IdentityFederationError(code, message);
}

function jsonValue(value) {
  return typeof value === "string" ? JSON.parse(value) : value;
}

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function safeInteger(value) {
  const result = Number(value);
  if (!Number.isSafeInteger(result)) {
    fail("STORE_INVALID_DATA", "Stored integer is outside the safe range.");
  }
  return result;
}

function projectionFromRow(row) {
  return {
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    fixtureRef: {
      fixtureId: row.fixture_id,
      sha256: row.fixture_hash,
    },
    providerConnectionId: row.provider_connection_id,
    state: row.state,
    generation: safeInteger(row.generation),
    operationId: row.operation_id,
    revocationEpoch: safeInteger(row.revocation_epoch),
    updatedAt: iso(row.updated_at),
  };
}

function providerFromRow(row) {
  const configurationState = row.configuration_state ?? "CURRENT";
  return {
    providerConnectionId: row.provider_connection_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    protocol: row.protocol,
    issuer: row.issuer,
    clientId: row.client_id,
    redirectRoutes: jsonValue(
      row.configuration_redirect_routes ?? row.redirect_routes,
    ),
    configurationVersion: safeInteger(row.configuration_version),
    configurationState,
    state: configurationState,
    allowedAlgorithms: jsonValue(
      row.configuration_allowed_algorithms ?? row.allowed_algorithms,
    ),
    allowedKeyIds: jsonValue(
      row.configuration_allowed_key_ids ?? row.allowed_key_ids,
    ),
    requiredAuthenticationMethods: jsonValue(
      row.configuration_required_authentication_methods ??
        row.required_authentication_methods,
    ),
    maxAuthenticationAgeSeconds:
      row.configuration_max_authentication_age_seconds ??
      row.max_authentication_age_seconds,
    upstreamProtocols: jsonValue(
      row.configuration_upstream_protocols ?? row.upstream_protocols,
    ),
    policy: row.policy,
    status: row.status,
    activatedAt: iso(row.configuration_activated_at ?? row.created_at),
    graceUntil: iso(row.configuration_grace_until),
    retiredAt: iso(row.configuration_retired_at),
    retirementMode: row.configuration_retirement_mode ?? null,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function accountFromRow(row) {
  return {
    accountId: row.account_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    providerConnectionId: row.provider_connection_id,
    issuer: row.issuer,
    subject: row.subject,
    directoryObjectId: row.directory_object_id,
    fixtureUserId: row.fixture_user_id,
    state: row.state,
    lifecycleVersion: safeInteger(row.lifecycle_version),
    sourceRevision: safeInteger(row.source_revision),
    sourcePayloadHash: row.source_payload_hash,
    revocationEpoch: safeInteger(row.revocation_epoch),
    incarnation: safeInteger(row.incarnation),
    profileRef: row.profile_ref,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

function loginTransactionFromRow(row) {
  return {
    transactionId: row.transaction_id,
    tenantId: row.tenant_id,
    providerConnectionId: row.provider_connection_id,
    providerConfigurationVersion: safeInteger(
      row.provider_configuration_version,
    ),
    stateHash: row.state_hash,
    nonceHash: row.nonce_hash,
    pkceVerifierHash: row.pkce_verifier_hash,
    redirectUri: row.redirect_uri,
    returnRoute: row.return_route,
    issuedAt: iso(row.issued_at),
    expiresAt: iso(row.expires_at),
    claimedAt: iso(row.claimed_at),
    claimHash: row.claim_hash,
    consumedAt: iso(row.consumed_at),
  };
}

function sessionFromRow(row) {
  return {
    sessionId: row.session_id,
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    accountId: row.account_id,
    providerConnectionId: row.provider_connection_id,
    providerConfigurationVersion: safeInteger(
      row.provider_configuration_version,
    ),
    tokenHash: row.token_hash,
    accountRevocationEpoch: safeInteger(row.account_revocation_epoch),
    tenantRevocationEpoch: safeInteger(row.tenant_revocation_epoch),
    status: row.status,
    authenticationTime: iso(row.authentication_time),
    authenticationMethods: jsonValue(row.authentication_methods),
    issuedAt: iso(row.issued_at),
    expiresAt: iso(row.expires_at),
    revokedAt: iso(row.revoked_at),
  };
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // Preserve the original storage failure.
  }
}

function databaseFailure(error) {
  if (error instanceof IdentityFederationError) return error;
  if (
    error?.constraint === "identity_account_directory_key" ||
    error?.constraint === "identity_account_subject_key"
  ) {
    return new IdentityFederationError(
      "IDENTITY_BINDING_CONFLICT",
      "Synthetic identity is already bound to another account.",
    );
  }
  if (
    error?.constraint === "identity_command_receipt_pkey" ||
    error?.constraint === "identity_source_receipt_pkey"
  ) {
    return new IdentityFederationError(
      "IDEMPOTENCY_CONFLICT",
      "Identity receipt already exists.",
    );
  }
  if (error?.constraint === "identity_provider_binding_guard") {
    return new IdentityFederationError(
      "PROVIDER_BINDING_IMMUTABLE",
      "Provider identity and configuration version are immutable.",
    );
  }
  if (
    error?.constraint ===
      "identity_provider_configuration_payload_guard"
  ) {
    return new IdentityFederationError(
      "PROVIDER_BINDING_IMMUTABLE",
      "Provider configuration payload is immutable.",
    );
  }
  if (
    error?.constraint ===
      "identity_provider_configuration_state_guard" ||
    error?.constraint ===
      "identity_provider_configuration_version_guard" ||
    error?.constraint ===
      "identity_provider_one_current_configuration" ||
    error?.constraint ===
      "identity_provider_configuration_pkey"
  ) {
    return new IdentityFederationError(
      "PROVIDER_CONFIGURATION_CONFLICT",
      "Provider configuration changed concurrently.",
    );
  }
  if (
    error?.constraint === "identity_projection_binding_guard" ||
    error?.constraint === "identity_projection_terminal_guard"
  ) {
    return new IdentityFederationError(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "Tenant identity projection binding is immutable.",
    );
  }
  if (
    error?.constraint === "identity_projection_version_guard" ||
    error?.constraint === "identity_projection_epoch_guard"
  ) {
    return new IdentityFederationError(
      "TENANT_EVENT_MISMATCH",
      "Tenant identity projection version is invalid.",
    );
  }
  if (error?.constraint === "identity_account_binding_guard") {
    return new IdentityFederationError(
      "ACCOUNT_BINDING_IMMUTABLE",
      "Federation and provisioning bindings are immutable.",
    );
  }
  if (error?.constraint === "identity_account_terminal_guard") {
    return new IdentityFederationError(
      "TERMINATED_ACCOUNT",
      "A terminated account incarnation cannot be restored.",
    );
  }
  if (
    error?.constraint === "identity_account_version_guard" ||
    error?.constraint === "identity_account_epoch_guard" ||
    error?.constraint === "identity_account_source_revision_guard"
  ) {
    return new IdentityFederationError(
      "PROVISIONING_VERSION_CONFLICT",
      "Provisioning version is invalid.",
    );
  }
  if (error?.constraint === "identity_login_transaction_guard") {
    return new IdentityFederationError(
      "LOGIN_TRANSACTION_INVALID",
      "Login transaction bindings are immutable.",
    );
  }
  if (
    error?.constraint === "identity_session_binding_guard" ||
    error?.constraint === "identity_session_terminal_guard" ||
    error?.constraint === "identity_session_revocation_guard"
  ) {
    return new IdentityFederationError(
      "SESSION_INVALID",
      "Session identity is immutable.",
    );
  }
  if (error?.code === "23505") {
    return new IdentityFederationError(
      "ID_COLLISION",
      "Identity identifier already exists.",
    );
  }
  return new IdentityFederationError(
    "STORE_UNAVAILABLE",
    "Identity Federation storage operation failed.",
  );
}

function shouldRetry(error) {
  return (
    RETRYABLE_SQL_STATES.has(error?.code) ||
    (
      error?.code === "23505" &&
      RETRYABLE_CONSTRAINTS.has(error?.constraint)
    )
  );
}

function retryDelay(seed, attempt) {
  let spread = 0;
  for (const character of seed) {
    spread = (spread + character.codePointAt(0)) % 37;
  }
  return Math.min(5 * 2 ** attempt, 100) + spread;
}

export function createPostgresIdentityStore({
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
      async loadProjectionForUpdate(tenantId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("identity_tenant_projection")}
            WHERE tenant_id = $1
            FOR UPDATE`,
          [tenantId],
        );
        return result.rows[0]
          ? projectionFromRow(result.rows[0])
          : null;
      },

      async putProjection(value) {
        await client.query(
          `INSERT INTO ${table("identity_tenant_projection")} (
             tenant_id,
             tenant_kind,
             fixture_id,
             fixture_hash,
             provider_connection_id,
             state,
             generation,
             operation_id,
             revocation_epoch,
             updated_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           ON CONFLICT (tenant_id) DO UPDATE
             SET tenant_kind = EXCLUDED.tenant_kind,
                 fixture_id = EXCLUDED.fixture_id,
                 fixture_hash = EXCLUDED.fixture_hash,
                 provider_connection_id = EXCLUDED.provider_connection_id,
                 state = EXCLUDED.state,
                 generation = EXCLUDED.generation,
                 operation_id = EXCLUDED.operation_id,
                 revocation_epoch = EXCLUDED.revocation_epoch,
                 updated_at = EXCLUDED.updated_at`,
          [
            value.tenantId,
            value.tenantKind,
            value.fixtureRef.fixtureId,
            value.fixtureRef.sha256,
            value.providerConnectionId,
            value.state,
            value.generation,
            value.operationId,
            value.revocationEpoch,
            value.updatedAt,
          ],
        );
      },

      async loadProvider(providerConnectionId) {
        const result = await client.query(
          `SELECT
             provider.*,
             configuration.configuration_version,
             configuration.redirect_routes
               AS configuration_redirect_routes,
             configuration.allowed_algorithms
               AS configuration_allowed_algorithms,
             configuration.allowed_key_ids
               AS configuration_allowed_key_ids,
             configuration.required_authentication_methods
               AS configuration_required_authentication_methods,
             configuration.max_authentication_age_seconds
               AS configuration_max_authentication_age_seconds,
             configuration.upstream_protocols
               AS configuration_upstream_protocols,
             configuration.state AS configuration_state,
             configuration.activated_at AS configuration_activated_at,
             configuration.grace_until AS configuration_grace_until,
             configuration.retired_at AS configuration_retired_at,
             configuration.retirement_mode AS configuration_retirement_mode
             FROM ${table("identity_provider")} AS provider
             JOIN ${table("identity_provider_configuration")} AS configuration
               ON configuration.provider_connection_id =
                  provider.provider_connection_id
              AND configuration.state = 'CURRENT'
            WHERE provider.provider_connection_id = $1`,
          [providerConnectionId],
        );
        return result.rows[0] ? providerFromRow(result.rows[0]) : null;
      },

      async putProvider(value) {
        await client.query(
          `INSERT INTO ${table("identity_provider")} (
             provider_connection_id,
             tenant_id,
             tenant_kind,
             protocol,
             issuer,
             client_id,
             redirect_routes,
             configuration_version,
             allowed_algorithms,
             allowed_key_ids,
             required_authentication_methods,
             max_authentication_age_seconds,
             upstream_protocols,
             policy,
             status,
             created_at,
             updated_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8,
             $9::jsonb, $10::jsonb, $11::jsonb, $12,
             $13::jsonb, $14, $15, $16, $17
           )
           ON CONFLICT (provider_connection_id) DO UPDATE
             SET status = EXCLUDED.status,
                 updated_at = EXCLUDED.updated_at`,
          [
            value.providerConnectionId,
            value.tenantId,
            value.tenantKind,
            value.protocol,
            value.issuer,
            value.clientId,
            JSON.stringify(value.redirectRoutes),
            value.configurationVersion,
            JSON.stringify(value.allowedAlgorithms),
            JSON.stringify(value.allowedKeyIds),
            JSON.stringify(value.requiredAuthenticationMethods),
            value.maxAuthenticationAgeSeconds,
            JSON.stringify(value.upstreamProtocols),
            value.policy,
            value.status,
            value.createdAt,
            value.updatedAt,
          ],
        );
        await client.query(
          `INSERT INTO ${table("identity_provider_configuration")} (
             provider_connection_id,
             tenant_id,
             configuration_version,
             redirect_routes,
             allowed_algorithms,
             allowed_key_ids,
             required_authentication_methods,
             max_authentication_age_seconds,
             upstream_protocols,
             state,
             activated_at,
             grace_until,
             retired_at,
             retirement_mode
           ) SELECT
             $1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb,
             $7::jsonb, $8, $9::jsonb, 'CURRENT', $10, NULL, NULL, NULL
            WHERE NOT EXISTS (
              SELECT 1
                FROM ${table("identity_provider_configuration")}
               WHERE provider_connection_id = $1
                 AND configuration_version = $3
            )`,
          [
            value.providerConnectionId,
            value.tenantId,
            value.configurationVersion,
            JSON.stringify(value.redirectRoutes),
            JSON.stringify(value.allowedAlgorithms),
            JSON.stringify(value.allowedKeyIds),
            JSON.stringify(value.requiredAuthenticationMethods),
            value.maxAuthenticationAgeSeconds,
            JSON.stringify(value.upstreamProtocols),
            value.createdAt,
          ],
        );
      },

      async loadProviderConfiguration(
        providerConnectionId,
        configurationVersion,
      ) {
        const result = await client.query(
          `SELECT
             provider.*,
             configuration.configuration_version,
             configuration.redirect_routes
               AS configuration_redirect_routes,
             configuration.allowed_algorithms
               AS configuration_allowed_algorithms,
             configuration.allowed_key_ids
               AS configuration_allowed_key_ids,
             configuration.required_authentication_methods
               AS configuration_required_authentication_methods,
             configuration.max_authentication_age_seconds
               AS configuration_max_authentication_age_seconds,
             configuration.upstream_protocols
               AS configuration_upstream_protocols,
             configuration.state AS configuration_state,
             configuration.activated_at AS configuration_activated_at,
             configuration.grace_until AS configuration_grace_until,
             configuration.retired_at AS configuration_retired_at,
             configuration.retirement_mode AS configuration_retirement_mode
             FROM ${table("identity_provider")} AS provider
             JOIN ${table("identity_provider_configuration")} AS configuration
               ON configuration.provider_connection_id =
                  provider.provider_connection_id
            WHERE provider.provider_connection_id = $1
              AND configuration.configuration_version = $2`,
          [providerConnectionId, configurationVersion],
        );
        return result.rows[0] ? providerFromRow(result.rows[0]) : null;
      },

      async rotateProviderConfiguration({
        providerConnectionId,
        expectedVersion,
        nextConfiguration,
        graceUntil,
        emergency,
        updatedAt,
      }) {
        const current = await client.query(
          `SELECT configuration_version
             FROM ${table("identity_provider_configuration")}
            WHERE provider_connection_id = $1
              AND configuration_version = $2
              AND state = 'CURRENT'
            FOR UPDATE`,
          [providerConnectionId, expectedVersion],
        );
        if (current.rowCount !== 1) {
          fail(
            "PROVIDER_CONFIGURATION_CONFLICT",
            "Provider configuration changed concurrently.",
          );
        }
        if (emergency) {
          await client.query(
            `UPDATE ${table("identity_provider_configuration")}
                SET state = 'RETIRED',
                    retired_at = $2,
                    retirement_mode = 'EMERGENCY'
              WHERE provider_connection_id = $1
                AND state IN ('CURRENT', 'GRACE')`,
            [providerConnectionId, updatedAt],
          );
        } else {
          const previous = await client.query(
            `UPDATE ${table("identity_provider_configuration")}
                SET state = 'GRACE',
                    grace_until = $3
              WHERE provider_connection_id = $1
                AND configuration_version = $2
                AND state = 'CURRENT'`,
            [providerConnectionId, expectedVersion, graceUntil],
          );
          if (previous.rowCount !== 1) {
            fail(
              "PROVIDER_CONFIGURATION_CONFLICT",
              "Provider configuration changed concurrently.",
            );
          }
        }
        await client.query(
          `INSERT INTO ${table("identity_provider_configuration")} (
             provider_connection_id,
             tenant_id,
             configuration_version,
             redirect_routes,
             allowed_algorithms,
             allowed_key_ids,
             required_authentication_methods,
             max_authentication_age_seconds,
             upstream_protocols,
             state,
             activated_at,
             grace_until,
             retired_at,
             retirement_mode
           ) VALUES (
             $1, $2, $3, $4::jsonb, $5::jsonb, $6::jsonb,
             $7::jsonb, $8, $9::jsonb, 'CURRENT', $10, NULL, NULL, NULL
           )`,
          [
            providerConnectionId,
            nextConfiguration.tenantId,
            nextConfiguration.configurationVersion,
            JSON.stringify(nextConfiguration.redirectRoutes),
            JSON.stringify(nextConfiguration.allowedAlgorithms),
            JSON.stringify(nextConfiguration.allowedKeyIds),
            JSON.stringify(
              nextConfiguration.requiredAuthenticationMethods,
            ),
            nextConfiguration.maxAuthenticationAgeSeconds,
            JSON.stringify(nextConfiguration.upstreamProtocols),
            nextConfiguration.activatedAt,
          ],
        );
        await client.query(
          `UPDATE ${table("identity_provider")}
              SET updated_at = $2
            WHERE provider_connection_id = $1`,
          [providerConnectionId, updatedAt],
        );
      },

      async retireProviderConfiguration({
        providerConnectionId,
        configurationVersion,
        retiredAt,
      }) {
        const result = await client.query(
          `UPDATE ${table("identity_provider_configuration")}
              SET state = 'RETIRED',
                  retired_at = $3,
                  retirement_mode = 'NORMAL'
            WHERE provider_connection_id = $1
              AND configuration_version = $2
              AND state = 'GRACE'
              AND grace_until <= $3`,
          [providerConnectionId, configurationVersion, retiredAt],
        );
        if (result.rowCount !== 1) {
          fail(
            "PROVIDER_CONFIGURATION_CONFLICT",
            "Only a grace configuration can be retired.",
          );
        }
      },

      async findAccountByDirectory(
        tenantId,
        providerConnectionId,
        directoryObjectId,
      ) {
        const result = await client.query(
          `SELECT *
             FROM ${table("identity_account")}
            WHERE tenant_id = $1
              AND provider_connection_id = $2
              AND directory_object_id = $3`,
          [tenantId, providerConnectionId, directoryObjectId],
        );
        return result.rows[0] ? accountFromRow(result.rows[0]) : null;
      },

      async findAccountBySubject(
        tenantId,
        providerConnectionId,
        issuer,
        subject,
      ) {
        const result = await client.query(
          `SELECT *
             FROM ${table("identity_account")}
            WHERE tenant_id = $1
              AND provider_connection_id = $2
              AND issuer = $3
              AND subject = $4`,
          [tenantId, providerConnectionId, issuer, subject],
        );
        return result.rows[0] ? accountFromRow(result.rows[0]) : null;
      },

      async loadAccountForUpdate(accountId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("identity_account")}
            WHERE account_id = $1
            FOR UPDATE`,
          [accountId],
        );
        return result.rows[0] ? accountFromRow(result.rows[0]) : null;
      },

      async putAccount(value) {
        await client.query(
          `INSERT INTO ${table("identity_account")} (
             account_id,
             tenant_id,
             tenant_kind,
             provider_connection_id,
             issuer,
             subject,
             directory_object_id,
             fixture_user_id,
             state,
             lifecycle_version,
             source_revision,
             source_payload_hash,
             revocation_epoch,
             incarnation,
             profile_ref,
             created_at,
             updated_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9,
             $10, $11, $12, $13, $14, $15, $16, $17
           )
           ON CONFLICT (account_id) DO UPDATE
             SET tenant_id = EXCLUDED.tenant_id,
                 tenant_kind = EXCLUDED.tenant_kind,
                 provider_connection_id = EXCLUDED.provider_connection_id,
                 issuer = EXCLUDED.issuer,
                 subject = EXCLUDED.subject,
                 directory_object_id = EXCLUDED.directory_object_id,
                 fixture_user_id = EXCLUDED.fixture_user_id,
                 state = EXCLUDED.state,
                 lifecycle_version = EXCLUDED.lifecycle_version,
                 source_revision = EXCLUDED.source_revision,
                 source_payload_hash = EXCLUDED.source_payload_hash,
                 revocation_epoch = EXCLUDED.revocation_epoch,
                 incarnation = EXCLUDED.incarnation,
                 profile_ref = EXCLUDED.profile_ref,
                 created_at = EXCLUDED.created_at,
                 updated_at = EXCLUDED.updated_at`,
          [
            value.accountId,
            value.tenantId,
            value.tenantKind,
            value.providerConnectionId,
            value.issuer,
            value.subject,
            value.directoryObjectId,
            value.fixtureUserId,
            value.state,
            value.lifecycleVersion,
            value.sourceRevision,
            value.sourcePayloadHash,
            value.revocationEpoch,
            value.incarnation,
            value.profileRef,
            value.createdAt,
            value.updatedAt,
          ],
        );
      },

      async listAccounts(tenantId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("identity_account")}
            WHERE tenant_id = $1
            ORDER BY account_id`,
          [tenantId],
        );
        return result.rows.map(accountFromRow);
      },

      async loadSourceReceipt(tenantId, sourceEventId) {
        const result = await client.query(
          `SELECT payload_hash, result
             FROM ${table("identity_source_receipt")}
            WHERE tenant_id = $1 AND source_event_id = $2`,
          [tenantId, sourceEventId],
        );
        return result.rows[0]
          ? {
              payloadHash: result.rows[0].payload_hash,
              result: jsonValue(result.rows[0].result),
            }
          : null;
      },

      async putSourceReceipt(tenantId, sourceEventId, value) {
        await client.query(
          `INSERT INTO ${table("identity_source_receipt")} (
             tenant_id, source_event_id, payload_hash, result
           ) VALUES ($1, $2, $3, $4::jsonb)`,
          [
            tenantId,
            sourceEventId,
            value.payloadHash,
            JSON.stringify(value.result),
          ],
        );
      },

      async insertLoginTransaction(value) {
        const result = await client.query(
          `INSERT INTO ${table("identity_login_transaction")} (
             transaction_id,
             tenant_id,
             provider_connection_id,
             provider_configuration_version,
             state_hash,
             nonce_hash,
             pkce_verifier_hash,
             redirect_uri,
             return_route,
             issued_at,
             expires_at,
             claimed_at,
             claim_hash,
             consumed_at
           )
           SELECT
             $1, $2, $3, $4, $5, $6, $7,
             $8, $9, $10, $11, $12, $13, $14
             FROM ${table("identity_provider_configuration")}
            WHERE provider_connection_id = $3
              AND configuration_version = $4
              AND state = 'CURRENT'`,
          [
            value.transactionId,
            value.tenantId,
            value.providerConnectionId,
            value.providerConfigurationVersion,
            value.stateHash,
            value.nonceHash,
            value.pkceVerifierHash,
            value.redirectUri,
            value.returnRoute,
            value.issuedAt,
            value.expiresAt,
            value.claimedAt,
            value.claimHash,
            value.consumedAt,
          ],
        );
        if (result.rowCount !== 1) {
          fail(
            "PROVIDER_CONFIGURATION_CONFLICT",
            "New logins require the current provider configuration.",
          );
        }
      },

      async loadLoginTransactionForUpdate(transactionId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("identity_login_transaction")}
            WHERE transaction_id = $1
            FOR UPDATE`,
          [transactionId],
        );
        return result.rows[0]
          ? loginTransactionFromRow(result.rows[0])
          : null;
      },

      async putLoginTransaction(value) {
        const result = await client.query(
          `UPDATE ${table("identity_login_transaction")}
              SET tenant_id = $1,
                  provider_connection_id = $2,
                  provider_configuration_version = $3,
                  state_hash = $4,
                  nonce_hash = $5,
                  pkce_verifier_hash = $6,
                  redirect_uri = $7,
                  return_route = $8,
                  issued_at = $9,
                  expires_at = $10,
                  claimed_at = $11,
                  claim_hash = $12,
                  consumed_at = $13
            WHERE transaction_id = $14`,
          [
            value.tenantId,
            value.providerConnectionId,
            value.providerConfigurationVersion,
            value.stateHash,
            value.nonceHash,
            value.pkceVerifierHash,
            value.redirectUri,
            value.returnRoute,
            value.issuedAt,
            value.expiresAt,
            value.claimedAt,
            value.claimHash,
            value.consumedAt,
            value.transactionId,
          ],
        );
        if (result.rowCount !== 1) {
          fail(
            "LOGIN_TRANSACTION_INVALID",
            "Login transaction bindings are immutable.",
          );
        }
      },

      async insertSession(value) {
        await client.query(
          `INSERT INTO ${table("identity_session")} (
             session_id,
             tenant_id,
             tenant_kind,
             account_id,
             provider_connection_id,
             provider_configuration_version,
             token_hash,
             account_revocation_epoch,
             tenant_revocation_epoch,
             status,
             authentication_time,
             authentication_methods,
             issued_at,
             expires_at,
             revoked_at
           ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8,
             $9, $10, $11, $12::jsonb, $13, $14, $15
           )`,
          [
            value.sessionId,
            value.tenantId,
            value.tenantKind,
            value.accountId,
            value.providerConnectionId,
            value.providerConfigurationVersion,
            value.tokenHash,
            value.accountRevocationEpoch,
            value.tenantRevocationEpoch,
            value.status,
            value.authenticationTime,
            JSON.stringify(value.authenticationMethods),
            value.issuedAt,
            value.expiresAt,
            value.revokedAt,
          ],
        );
      },

      async loadSessionByIdForUpdate(sessionId) {
        const result = await client.query(
          `SELECT *
             FROM ${table("identity_session")}
            WHERE session_id = $1
            FOR UPDATE`,
          [sessionId],
        );
        return result.rows[0] ? sessionFromRow(result.rows[0]) : null;
      },

      async putSession(value) {
        const result = await client.query(
          `UPDATE ${table("identity_session")}
              SET tenant_id = $1,
                  tenant_kind = $2,
                  account_id = $3,
                  provider_connection_id = $4,
                  provider_configuration_version = $5,
                  token_hash = $6,
                  account_revocation_epoch = $7,
                  tenant_revocation_epoch = $8,
                  status = $9,
                  authentication_time = $10,
                  authentication_methods = $11::jsonb,
                  issued_at = $12,
                  expires_at = $13,
                  revoked_at = $14
            WHERE session_id = $15`,
          [
            value.tenantId,
            value.tenantKind,
            value.accountId,
            value.providerConnectionId,
            value.providerConfigurationVersion,
            value.tokenHash,
            value.accountRevocationEpoch,
            value.tenantRevocationEpoch,
            value.status,
            value.authenticationTime,
            JSON.stringify(value.authenticationMethods),
            value.issuedAt,
            value.expiresAt,
            value.revokedAt,
            value.sessionId,
          ],
        );
        if (result.rowCount !== 1) {
          fail("SESSION_INVALID", "Session identity is immutable.");
        }
      },

      async revokeSessionsForAccount(accountId, revokedAt) {
        await client.query(
          `UPDATE ${table("identity_session")}
              SET status = 'REVOKED',
                  revoked_at = $2
            WHERE account_id = $1
              AND status = 'ACTIVE'`,
          [accountId, revokedAt],
        );
      },

      async revokeSessionsForTenant(tenantId, revokedAt) {
        await client.query(
          `UPDATE ${table("identity_session")}
              SET status = 'REVOKED',
                  revoked_at = $2
            WHERE tenant_id = $1
              AND status = 'ACTIVE'`,
          [tenantId, revokedAt],
        );
      },

      async appendEvent(event) {
        await client.query(
          `INSERT INTO ${table("identity_event")} (
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
          `INSERT INTO ${table("identity_outbox")} (
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
    { idempotencyKey, commandHash },
    reducer,
  ) {
    let lastError;
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      const client = await connect();
      let retry = false;
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const existing = await client.query(
          `SELECT command_hash, result
             FROM ${table("identity_command_receipt")}
            WHERE idempotency_key = $1`,
          [idempotencyKey],
        );
        if (existing.rows[0]) {
          if (existing.rows[0].command_hash !== commandHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "The idempotency key was used for another identity command.",
            );
          }
          await client.query("COMMIT");
          return {
            duplicate: true,
            value: jsonValue(existing.rows[0].result),
          };
        }

        const value = await reducer(transactionPort(client));
        await client.query(
          `INSERT INTO ${table("identity_command_receipt")} (
             idempotency_key, command_hash, result
           ) VALUES ($1, $2, $3::jsonb)`,
          [idempotencyKey, commandHash, JSON.stringify(value)],
        );
        await client.query("COMMIT");
        return { duplicate: false, value };
      } catch (error) {
        lastError = error;
        await rollback(client);
        retry =
          shouldRetry(error) &&
          attempt < maxSerializableRetries;
        if (!retry) {
          throw databaseFailure(error);
        }
      } finally {
        client.release();
      }
      if (retry) {
        await new Promise((resolve) =>
          setTimeout(resolve, retryDelay(idempotencyKey, attempt)),
        );
      }
    }
    throw databaseFailure(lastError);
  }

  async function transact(reducer) {
    let lastError;
    for (let attempt = 0; attempt <= maxSerializableRetries; attempt += 1) {
      const client = await connect();
      let retry = false;
      try {
        await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
        const value = await reducer(transactionPort(client));
        await client.query("COMMIT");
        return value;
      } catch (error) {
        lastError = error;
        await rollback(client);
        retry =
          shouldRetry(error) &&
          attempt < maxSerializableRetries;
        if (!retry) {
          throw databaseFailure(error);
        }
      } finally {
        client.release();
      }
      if (retry) {
        await new Promise((resolve) =>
          setTimeout(resolve, retryDelay("identity-transact", attempt)),
        );
      }
    }
    throw databaseFailure(lastError);
  }

  async function readTenantSnapshot(tenantId) {
    const client = await connect();
    try {
      await client.query(
        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
      );
      const projectionResult = await client.query(
        `SELECT *
           FROM ${table("identity_tenant_projection")}
          WHERE tenant_id = $1`,
        [tenantId],
      );
      if (!projectionResult.rows[0]) {
        await client.query("COMMIT");
        return null;
      }
      const projection = projectionFromRow(projectionResult.rows[0]);
      const providerResult = await client.query(
        `SELECT
           provider.*,
           configuration.configuration_version,
           configuration.redirect_routes
             AS configuration_redirect_routes,
           configuration.allowed_algorithms
             AS configuration_allowed_algorithms,
           configuration.allowed_key_ids
             AS configuration_allowed_key_ids,
           configuration.required_authentication_methods
             AS configuration_required_authentication_methods,
           configuration.max_authentication_age_seconds
             AS configuration_max_authentication_age_seconds,
           configuration.upstream_protocols
             AS configuration_upstream_protocols,
           configuration.state AS configuration_state,
           configuration.activated_at AS configuration_activated_at,
           configuration.grace_until AS configuration_grace_until,
           configuration.retired_at AS configuration_retired_at,
           configuration.retirement_mode AS configuration_retirement_mode
           FROM ${table("identity_provider")} AS provider
           JOIN ${table("identity_provider_configuration")} AS configuration
             ON configuration.provider_connection_id =
                provider.provider_connection_id
            AND configuration.state = 'CURRENT'
          WHERE provider.provider_connection_id = $1`,
        [projection.providerConnectionId],
      );
      const accountResult = await client.query(
        `SELECT *
           FROM ${table("identity_account")}
          WHERE tenant_id = $1
          ORDER BY account_id`,
        [tenantId],
      );
      const sessionResult = await client.query(
        `SELECT *
           FROM ${table("identity_session")}
          WHERE tenant_id = $1
          ORDER BY session_id`,
        [tenantId],
      );
      const eventResult = await client.query(
        `SELECT event
           FROM ${table("identity_event")}
          WHERE tenant_id = $1
          ORDER BY created_at, event_id`,
        [tenantId],
      );
      const outboxResult = await client.query(
        `SELECT event
           FROM ${table("identity_outbox")}
          WHERE tenant_id = $1
          ORDER BY created_at, event_id`,
        [tenantId],
      );
      await client.query("COMMIT");
      return {
        projection,
        provider: providerResult.rows[0]
          ? providerFromRow(providerResult.rows[0])
          : null,
        accounts: accountResult.rows.map(accountFromRow),
        sessions: sessionResult.rows.map(sessionFromRow),
        events: eventResult.rows.map(({ event }) => jsonValue(event)),
        outbox: outboxResult.rows.map(({ event }) => jsonValue(event)),
      };
    } catch (error) {
      await rollback(client);
      throw databaseFailure(error);
    } finally {
      client.release();
    }
  }

  async function readSessionSnapshot(tokenHash) {
    const client = await connect();
    try {
      await client.query(
        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
      );
      const sessionResult = await client.query(
        `SELECT *
           FROM ${table("identity_session")}
          WHERE token_hash = $1`,
        [tokenHash],
      );
      if (!sessionResult.rows[0]) {
        await client.query("COMMIT");
        return null;
      }
      const session = sessionFromRow(sessionResult.rows[0]);
      const accountResult = await client.query(
        `SELECT *
           FROM ${table("identity_account")}
          WHERE account_id = $1`,
        [session.accountId],
      );
      const projectionResult = await client.query(
        `SELECT *
           FROM ${table("identity_tenant_projection")}
          WHERE tenant_id = $1`,
        [session.tenantId],
      );
      const projection = projectionResult.rows[0]
        ? projectionFromRow(projectionResult.rows[0])
        : null;
      const providerResult = projection
        ? await client.query(
            `SELECT
               provider.*,
               configuration.configuration_version,
               configuration.redirect_routes
                 AS configuration_redirect_routes,
               configuration.allowed_algorithms
                 AS configuration_allowed_algorithms,
               configuration.allowed_key_ids
                 AS configuration_allowed_key_ids,
               configuration.required_authentication_methods
                 AS configuration_required_authentication_methods,
               configuration.max_authentication_age_seconds
                 AS configuration_max_authentication_age_seconds,
               configuration.upstream_protocols
                 AS configuration_upstream_protocols,
               configuration.state AS configuration_state,
               configuration.activated_at AS configuration_activated_at,
               configuration.grace_until AS configuration_grace_until,
               configuration.retired_at AS configuration_retired_at,
               configuration.retirement_mode AS configuration_retirement_mode
               FROM ${table("identity_provider")} AS provider
               JOIN ${table("identity_provider_configuration")} AS configuration
                 ON configuration.provider_connection_id =
                    provider.provider_connection_id
                AND configuration.state = 'CURRENT'
              WHERE provider.provider_connection_id = $1`,
            [projection.providerConnectionId],
          )
        : { rows: [] };
      await client.query("COMMIT");
      return {
        session,
        account: accountResult.rows[0]
          ? accountFromRow(accountResult.rows[0])
          : null,
        projection,
        provider: providerResult.rows[0]
          ? providerFromRow(providerResult.rows[0])
          : null,
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
    transact,
    readTenantSnapshot,
    readSessionSnapshot,
  });
}
