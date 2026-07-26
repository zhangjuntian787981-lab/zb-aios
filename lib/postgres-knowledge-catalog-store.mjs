import { randomUUID } from "node:crypto";
import {
  KnowledgeCatalogError,
  transitionKnowledgeDocument,
} from "./knowledge-catalog.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const ROLE_NAMES = Object.freeze([
  "aios_c10_runtime",
  "aios_c10_reader",
  "aios_c10_owner",
  "aios_c07_scope_runtime",
  "aios_c07_data_runtime",
  "aios_c07_lifecycle_runtime",
  "aios_c07_restore_runtime",
  "aios_c07_owner",
]);
const RETRYABLE_SQL_STATES = new Set(["40001", "40P01"]);

export class PostgresKnowledgeCatalogStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PostgresKnowledgeCatalogStoreError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PostgresKnowledgeCatalogStoreError(code, message);
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

function iso(value) {
  return value instanceof Date ? value.toISOString() : value;
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
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
    fail(
      "TENANT_SCOPE_VIOLATION",
      "C10 PostgreSQL requires a verified C07 Tenant scope.",
    );
  }
}

function databaseFailure(error) {
  if (
    error instanceof PostgresKnowledgeCatalogStoreError ||
    error instanceof KnowledgeCatalogError
  ) {
    return error;
  }
  if (error?.code === "42501") {
    return new PostgresKnowledgeCatalogStoreError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL rejected the C10 Tenant scope.",
    );
  }
  if (
    error?.constraint === "knowledge_document_pkey" ||
    error?.constraint ===
      "knowledge_document_tenant_id_document_id_document_vers_key" ||
    error?.constraint === "knowledge_document_revision_guard"
  ) {
    return new PostgresKnowledgeCatalogStoreError(
      "VERSION_CONFLICT",
      "C10 document version or revision conflicts.",
    );
  }
  if (
    error?.constraint === "knowledge_document_transition_guard" ||
    error?.constraint === "knowledge_document_state_shape"
  ) {
    return new PostgresKnowledgeCatalogStoreError(
      "INVALID_STATE",
      "C10 document state transition failed.",
    );
  }
  if (
    error?.constraint?.startsWith("knowledge_source_") ||
    error?.constraint === "knowledge_document_revision_pair_guard"
  ) {
    return new PostgresKnowledgeCatalogStoreError(
      "INVALID_PROVENANCE",
      "C10 provenance evidence is inconsistent.",
    );
  }
  if (["23503", "23514", "23000"].includes(error?.code)) {
    return new PostgresKnowledgeCatalogStoreError(
      "INTEGRITY_VIOLATION",
      "C10 PostgreSQL invariant failed.",
    );
  }
  return new PostgresKnowledgeCatalogStoreError(
    "STORE_UNAVAILABLE",
    "C10 PostgreSQL operation failed.",
  );
}

function nodeFromRow(row) {
  return Object.freeze({
    nodeId: row.node_id,
    nodeType: row.node_type,
    parentNodeId: row.parent_node_id,
    ordinal: safeInteger(row.ordinal),
    location: jsonValue(row.location),
    textSha256: row.text_sha256,
    sourceSha256: row.source_sha256,
    authorityStatus: row.authority_status,
    availabilityState: row.availability_state,
    deletedAt: iso(row.deleted_at),
  });
}

function documentFromRow(row, nodes = []) {
  if (!row) return null;
  return Object.freeze({
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    documentId: row.document_id,
    documentVersion: safeInteger(row.document_version),
    revision: safeInteger(row.revision),
    state: row.state,
    fixtureRef: row.fixture_ref,
    sourceRef: row.source_ref,
    filename: row.filename,
    declaredMediaType: row.declared_media_type,
    detectedMediaType: row.detected_media_type,
    contentSha256: row.content_sha256,
    contentSize: safeInteger(row.content_size),
    quarantineRef: row.quarantine_ref,
    inspection: jsonValue(row.inspection),
    parserVersion: row.parser_version,
    parseSha256: row.parse_sha256,
    nodes: Object.freeze(nodes.map(nodeFromRow)),
    metadata: jsonValue(row.metadata),
    authorizationEvidence: jsonValue(row.authorization_evidence),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
    publishedAt: iso(row.published_at),
    withdrawnAt: iso(row.withdrawn_at),
    expiredAt: iso(row.expired_at),
    deletedAt: iso(row.deleted_at),
  });
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
  } catch {
    // The original failure is more useful than a rollback failure.
  }
}

export function createPostgresKnowledgeCatalogStore({
  runtimePool,
  readerPool,
  scopePool,
  schema = "aios_knowledge",
  scopeSchema = "aios_data",
  maxSerializableRetries = 5,
}) {
  if (
    typeof runtimePool?.connect !== "function" ||
    typeof readerPool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    runtimePool === readerPool ||
    runtimePool === scopePool ||
    readerPool === scopePool ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C10 PostgreSQL pools are invalid.");
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
        client.release(new Error("C10 rejected an unsafe PostgreSQL role."));
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C10 PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C10 could not verify the PostgreSQL role."),
        );
      }
      throw error;
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
      const signed = jsonValue(result.rows[0]?.signed_scope);
      if (
        !Number.isSafeInteger(Number(signed?.expires_epoch_ms)) ||
        !/^[0-9a-f]{64}$/.test(signed?.signature ?? "")
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

  async function runScoped(pool, requiredRole, scope, begin, operation) {
    validateScope(scope);
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
      if (requiredRole === "aios_c10_runtime") {
        const fence = await client.query(
          `SELECT ${fenceFunction}() AS acquired`,
        );
        if (fence.rows[0]?.acquired !== true) {
          fail(
            "TENANT_SCOPE_VIOLATION",
            "C10 PostgreSQL runtime fence was not acquired.",
          );
        }
      }
      const result = await operation(client);
      await client.query("COMMIT");
      started = false;
      return result;
    } catch (error) {
      discard =
        error?.code === "57P01" ||
        (typeof error?.code === "string" && error.code.startsWith("08"));
      if (started) await rollback(client);
      throw error;
    } finally {
      client.release(
        discard ? new Error("C10 discarded a failed connection.") : undefined,
      );
    }
  }

  async function selectDocument(
    client,
    tenantId,
    documentId,
    documentVersion,
    lock = "",
  ) {
    const document = await client.query(
      `SELECT * FROM ${table("knowledge_document")}
        WHERE tenant_id=$1
          AND document_id=$2
          AND document_version=$3
        ${lock}`,
      [tenantId, documentId, documentVersion],
    );
    if (document.rowCount === 0) return null;
    const nodes = await client.query(
      `SELECT * FROM ${table("source_node")}
        WHERE tenant_id=$1
          AND document_id=$2
          AND document_version=$3
        ORDER BY ordinal`,
      [tenantId, documentId, documentVersion],
    );
    return documentFromRow(document.rows[0], nodes.rows);
  }

  async function insertDocument(client, next) {
    await client.query(
      `INSERT INTO ${table("knowledge_document")} (
         tenant_id,tenant_kind,document_id,document_version,revision,state,
         fixture_ref,source_ref,filename,declared_media_type,
         detected_media_type,content_sha256,content_size,quarantine_ref,
         inspection,parser_version,parse_sha256,metadata,
         authorization_evidence,created_at,updated_at,published_at,
         withdrawn_at,expired_at,deleted_at
       ) VALUES (
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
         $15::jsonb,$16,$17,$18::jsonb,$19::jsonb,$20,$21,$22,$23,$24,$25
       )`,
      [
        next.tenantId,
        next.tenantKind,
        next.documentId,
        next.documentVersion,
        next.revision,
        next.state,
        next.fixtureRef,
        next.sourceRef,
        next.filename,
        next.declaredMediaType,
        next.detectedMediaType,
        next.contentSha256,
        next.contentSize,
        next.quarantineRef,
        next.inspection === null ? null : JSON.stringify(next.inspection),
        next.parserVersion,
        next.parseSha256,
        next.metadata === null ? null : JSON.stringify(next.metadata),
        JSON.stringify(next.authorizationEvidence),
        next.createdAt,
        next.updatedAt,
        next.publishedAt,
        next.withdrawnAt,
        next.expiredAt,
        next.deletedAt,
      ],
    );
  }

  async function updateDocument(client, current, next) {
    const result = await client.query(
      `UPDATE ${table("knowledge_document")}
          SET revision=$5,state=$6,detected_media_type=$7,
              inspection=$8::jsonb,parser_version=$9,parse_sha256=$10,
              metadata=$11::jsonb,authorization_evidence=$12::jsonb,
              updated_at=$13,published_at=$14,withdrawn_at=$15,
              expired_at=$16,deleted_at=$17
        WHERE tenant_id=$1
          AND document_id=$2
          AND document_version=$3
          AND revision=$4`,
      [
        next.tenantId,
        next.documentId,
        next.documentVersion,
        current.revision,
        next.revision,
        next.state,
        next.detectedMediaType,
        next.inspection === null ? null : JSON.stringify(next.inspection),
        next.parserVersion,
        next.parseSha256,
        next.metadata === null ? null : JSON.stringify(next.metadata),
        JSON.stringify(next.authorizationEvidence),
        next.updatedAt,
        next.publishedAt,
        next.withdrawnAt,
        next.expiredAt,
        next.deletedAt,
      ],
    );
    if (result.rowCount !== 1) {
      fail("VERSION_CONFLICT", "C10 document revision is stale.");
    }
  }

  async function writeNodes(client, current, next, commandType) {
    if (commandType === "PARSE") {
      for (const node of [...next.nodes].sort(
        (left, right) => left.ordinal - right.ordinal,
      )) {
        await client.query(
          `INSERT INTO ${table("source_node")} (
             tenant_id,tenant_kind,document_id,document_version,node_id,
             node_type,parent_node_id,ordinal,location,text_sha256,
             source_sha256,authority_status,availability_state,deleted_at
           ) VALUES (
             $1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14
           )`,
          [
            next.tenantId,
            next.tenantKind,
            next.documentId,
            next.documentVersion,
            node.nodeId,
            node.nodeType,
            node.parentNodeId,
            node.ordinal,
            JSON.stringify(node.location),
            node.textSha256,
            node.sourceSha256,
            node.authorityStatus,
            node.availabilityState,
            node.deletedAt,
          ],
        );
      }
      return;
    }
    if (
      current &&
      ["PUBLISH", "WITHDRAW", "EXPIRE", "DELETE"].includes(commandType) &&
      next.nodes.length > 0
    ) {
      const expected = next.nodes[0].availabilityState;
      const deletedAt = expected === "DELETED" ? next.deletedAt : null;
      await client.query(
        `UPDATE ${table("source_node")}
            SET availability_state=$4,deleted_at=$5
          WHERE tenant_id=$1
            AND document_id=$2
            AND document_version=$3`,
        [
          next.tenantId,
          next.documentId,
          next.documentVersion,
          expected,
          deletedAt,
        ],
      );
    }
  }

  async function writeEvidence(client, envelope, next) {
    await client.query(
      `INSERT INTO ${table("knowledge_revision")} (
         tenant_id,tenant_kind,document_id,document_version,revision,
         state,snapshot,effective_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`,
      [
        next.tenantId,
        next.tenantKind,
        next.documentId,
        next.documentVersion,
        next.revision,
        next.state,
        JSON.stringify(next),
        next.updatedAt,
      ],
    );
    const result = { replayed: false, document: next };
    await client.query(
      `INSERT INTO ${table("command_receipt")} (
         tenant_id,tenant_kind,idempotency_key,request_hash,command_kind,
         document_id,document_version,result,created_at
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)`,
      [
        next.tenantId,
        next.tenantKind,
        envelope.idempotencyKey,
        envelope.requestHash,
        envelope.command.type,
        next.documentId,
        next.documentVersion,
        JSON.stringify(result),
        next.updatedAt,
      ],
    );
    return result;
  }

  async function applyOnce(scope, envelope) {
    return runScoped(
      runtimePool,
      "aios_c10_runtime",
      scope,
      "BEGIN ISOLATION LEVEL SERIALIZABLE",
      async (client) => {
        const receipt = await client.query(
          `SELECT request_hash,result
             FROM ${table("command_receipt")}
            WHERE tenant_id=$1 AND idempotency_key=$2`,
          [scope.tenantId, envelope.idempotencyKey],
        );
        if (receipt.rowCount === 1) {
          if (receipt.rows[0].request_hash !== envelope.requestHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Idempotency key was reused with another request.",
            );
          }
          return {
            ...clone(jsonValue(receipt.rows[0].result)),
            replayed: true,
          };
        }
        const current = await selectDocument(
          client,
          scope.tenantId,
          envelope.command.documentId,
          envelope.command.documentVersion,
          "FOR UPDATE",
        );
        const previousVersion =
          envelope.command.documentVersion > 1
            ? await selectDocument(
                client,
                scope.tenantId,
                envelope.command.documentId,
                envelope.command.documentVersion - 1,
                "FOR SHARE",
              )
            : null;
        const next = transitionKnowledgeDocument({
          current,
          previousVersion,
          command: envelope.command,
        });
        if (current) {
          await updateDocument(client, current, next);
        } else {
          await insertDocument(client, next);
        }
        await writeNodes(client, current, next, envelope.command.type);
        return writeEvidence(client, envelope, next);
      },
    );
  }

  async function apply(scope, envelope) {
    validateScope(scope);
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await applyOnce(scope, envelope);
      } catch (error) {
        const retryable =
          RETRYABLE_SQL_STATES.has(error?.code) ||
          (error?.code === "23505" &&
            error?.constraint === "command_receipt_pkey");
        if (!retryable || attempt >= maxSerializableRetries) {
          throw databaseFailure(error);
        }
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(5 * 2 ** attempt, 50)),
        );
      }
    }
  }

  async function readCurrent(scope, coordinates) {
    try {
      return await runScoped(
        readerPool,
        "aios_c10_reader",
        scope,
        "BEGIN READ ONLY",
        (client) =>
          selectDocument(
            client,
            scope.tenantId,
            coordinates.documentId,
            coordinates.documentVersion,
          ),
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function readAsOf(scope, query) {
    try {
      return await runScoped(
        readerPool,
        "aios_c10_reader",
        scope,
        "BEGIN READ ONLY",
        async (client) => {
          const parameters = [scope.tenantId, query.documentId, query.asOf];
          let version = "";
          if (query.documentVersion !== undefined) {
            parameters.push(query.documentVersion);
            version = "AND revision.document_version=$4";
          }
          const result = await client.query(
            `SELECT snapshot
               FROM (
                 SELECT DISTINCT ON (revision.document_version)
                        revision.document_version,
                        revision.revision,
                        revision.snapshot
                   FROM ${table("knowledge_revision")} AS revision
                   JOIN ${table("knowledge_document")} AS document
                     ON document.tenant_id=revision.tenant_id
                    AND document.document_id=revision.document_id
                    AND document.document_version=
                        revision.document_version
                  WHERE revision.tenant_id=$1
                    AND revision.document_id=$2
                    AND revision.effective_at <= $3::timestamptz
                    AND revision.revision <= document.revision
                    ${version}
                  ORDER BY revision.document_version,
                           revision.revision DESC
               ) AS latest
              ORDER BY document_version DESC
              LIMIT 100`,
            parameters,
          );
          for (const row of result.rows) {
            const candidate = jsonValue(row.snapshot);
            if (
              candidate.state === "PUBLISHED" &&
              Date.parse(candidate.metadata.validFrom) <=
                Date.parse(query.asOf) &&
              Date.parse(query.asOf) <
                Date.parse(candidate.metadata.validUntil)
            ) {
              return Object.freeze(candidate);
            }
          }
          return null;
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  return Object.freeze({
    apply,
    readCurrent,
    readAsOf,
  });
}
