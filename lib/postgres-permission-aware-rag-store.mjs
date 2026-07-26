import { randomUUID } from "node:crypto";
import {
  PermissionAwareRagError,
} from "./permission-aware-rag.mjs";

const SAFE_IDENTIFIER = /^[a-z_][a-z0-9_]*$/;
const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const ROLE_NAMES = Object.freeze([
  "aios_c11_projector",
  "aios_c11_query",
  "aios_c11_owner",
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

export class PostgresPermissionAwareRagStoreError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "PostgresPermissionAwareRagStoreError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new PostgresPermissionAwareRagStoreError(code, message);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
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

function vectorLiteral(values) {
  if (
    !Array.isArray(values) ||
    values.length !== 8 ||
    values.some((value) => !Number.isFinite(value))
  ) {
    fail("INVALID_INDEX", "C11 embedding must have eight finite values.");
  }
  return `[${values.join(",")}]`;
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
      "C11 PostgreSQL requires a verified C07 Tenant scope.",
    );
  }
}

function databaseFailure(error) {
  if (
    error instanceof PostgresPermissionAwareRagStoreError ||
    error instanceof PermissionAwareRagError
  ) {
    return error;
  }
  if (error?.code === "42501") {
    return new PostgresPermissionAwareRagStoreError(
      "TENANT_SCOPE_VIOLATION",
      "PostgreSQL rejected the C11 Tenant scope.",
    );
  }
  if (
    error?.constraint === "document_projection_pkey" ||
    error?.constraint === "rag_projection_version_guard"
  ) {
    return new PostgresPermissionAwareRagStoreError(
      "VERSION_CONFLICT",
      "C11 projection version conflicts.",
    );
  }
  if (
    error?.constraint === "projection_receipt_pkey" ||
    error?.constraint === "rag_append_only_guard"
  ) {
    return new PostgresPermissionAwareRagStoreError(
      "IDEMPOTENCY_CONFLICT",
      "C11 projection receipt conflicts.",
    );
  }
  if (
    error?.constraint?.startsWith("rag_chunk_") ||
    error?.constraint?.startsWith("rag_projection_")
  ) {
    return new PostgresPermissionAwareRagStoreError(
      "CATALOG_UNVERIFIED",
      "C11 PostgreSQL rejected catalog or provenance evidence.",
    );
  }
  if (["23503", "23514", "23000"].includes(error?.code)) {
    return new PostgresPermissionAwareRagStoreError(
      "INTEGRITY_VIOLATION",
      "C11 PostgreSQL invariant failed.",
    );
  }
  return new PostgresPermissionAwareRagStoreError(
    "STORE_UNAVAILABLE",
    "C11 PostgreSQL operation failed.",
  );
}

function projectionFromRow(row) {
  if (!row) return null;
  return Object.freeze({
    tenantId: row.tenant_id,
    tenantKind: row.tenant_kind,
    documentId: row.document_id,
    documentVersion: safeInteger(row.document_version),
    projectionVersion: safeInteger(row.projection_version),
    catalogRevision: safeInteger(row.catalog_revision),
    state: row.state,
    contentSha256: row.content_sha256,
    parseSha256: row.parse_sha256,
    validFrom: iso(row.valid_from),
    validUntil: iso(row.valid_until),
    classification: row.classification,
    acl: jsonValue(row.acl),
    indexEpoch: safeInteger(row.index_epoch),
    authorizationEvidence: jsonValue(row.authorization_evidence),
    updatedAt: iso(row.updated_at),
  });
}

function candidateFromRow(row) {
  const projection = projectionFromRow({
    tenant_id: row.tenant_id,
    tenant_kind: row.tenant_kind,
    document_id: row.document_id,
    document_version: row.document_version,
    projection_version: row.projection_version,
    catalog_revision: row.catalog_revision,
    state: row.projection_state,
    content_sha256: row.content_sha256,
    parse_sha256: row.parse_sha256,
    valid_from: row.valid_from,
    valid_until: row.valid_until,
    classification: row.classification,
    acl: row.acl,
    index_epoch: row.projection_index_epoch,
    authorization_evidence: row.authorization_evidence,
    updated_at: row.projection_updated_at,
  });
  return Object.freeze({
    tenantId: row.tenant_id,
    documentId: row.document_id,
    documentVersion: safeInteger(row.document_version),
    catalogRevision: safeInteger(row.catalog_revision),
    state: row.state,
    active: row.active,
    indexEpoch: safeInteger(row.index_epoch),
    chunkId: row.chunk_id,
    ordinal: safeInteger(row.ordinal),
    text: row.chunk_text,
    textSha256: row.text_sha256,
    sourceSha256: row.source_sha256,
    embedding: [],
    originalNodeId: row.original_node_id,
    pageNodeId: row.page_node_id,
    sectionNodeId: row.section_node_id,
    tableNodeId: row.table_node_id,
    location: jsonValue(row.location),
    projection,
    lexicalScore: Number(row.lexical_score),
    vectorScore: Number(row.vector_score),
    score: Number(row.score),
  });
}

async function rollback(client) {
  try {
    await client.query("ROLLBACK");
    return true;
  } catch {
    return false;
  }
}

function connectionFailed(error) {
  return (
    error?.code === "57P01" ||
    (typeof error?.code === "string" && error.code.startsWith("08"))
  );
}

export function createPostgresPermissionAwareRagStore({
  projectorPool,
  queryPool,
  scopePool,
  schema = "aios_rag",
  catalogSchema = "aios_knowledge",
  scopeSchema = "aios_data",
  maxSerializableRetries = 5,
}) {
  if (
    typeof projectorPool?.connect !== "function" ||
    typeof queryPool?.connect !== "function" ||
    typeof scopePool?.connect !== "function" ||
    projectorPool === queryPool ||
    projectorPool === scopePool ||
    queryPool === scopePool ||
    !SAFE_IDENTIFIER.test(schema) ||
    !SAFE_IDENTIFIER.test(catalogSchema) ||
    !SAFE_IDENTIFIER.test(scopeSchema) ||
    !Number.isSafeInteger(maxSerializableRetries) ||
    maxSerializableRetries < 0 ||
    maxSerializableRetries > 10
  ) {
    fail("INVALID_CONFIGURATION", "C11 PostgreSQL pools are invalid.");
  }
  const table = (name) => `"${schema}"."${name}"`;
  const catalogTable = (name) => `"${catalogSchema}"."${name}"`;
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
           JOIN pg_roles AS active ON active.rolname=identity.current_name
           JOIN pg_roles AS login ON login.rolname=identity.session_name`,
      );
      const row = result.rows[0];
      const expected = ROLE_NAMES.indexOf(requiredRole);
      if (
        !row ||
        expected < 0 ||
        row.current_super ||
        row.current_bypassrls ||
        row.session_super ||
        row.session_bypassrls ||
        ROLE_NAMES.some(
          (_role, index) =>
            row[`current_role_${index}`] !== (index === expected) ||
            row[`session_role_${index}`] !== (index === expected),
        )
      ) {
        client.release(new Error("C11 rejected an unsafe PostgreSQL role."));
        client = null;
        fail(
          "INVALID_CONFIGURATION",
          "C11 PostgreSQL pool role is unsafe.",
        );
      }
      return client;
    } catch (error) {
      if (client) {
        client.release(
          new Error("C11 could not verify the PostgreSQL role."),
        );
      }
      throw error;
    }
  }

  async function issueScopeSignature(scope, backendPid, transactionId) {
    const signer = await connect(scopePool, "aios_c07_scope_runtime");
    let releaseError;
    try {
      const nonce = randomUUID();
      const result = await signer.query(
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
    } catch (error) {
      if (connectionFailed(error)) releaseError = error;
      throw error;
    } finally {
      signer.release(releaseError);
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
      if (!begin.includes("READ ONLY")) {
        const fence = await client.query(
          `SELECT ${fenceFunction}() AS acquired`,
        );
        if (fence.rows[0]?.acquired !== true) {
          fail(
            "TENANT_SCOPE_VIOLATION",
            "C11 PostgreSQL runtime fence was not acquired.",
          );
        }
      }
      const result = await operation(client);
      await client.query("COMMIT");
      started = false;
      return result;
    } catch (error) {
      discard = connectionFailed(error);
      if (started && !(await rollback(client))) discard = true;
      throw error;
    } finally {
      client.release(
        discard ? new Error("C11 discarded a failed connection.") : undefined,
      );
    }
  }

  async function applyOnce(scope, envelope) {
    return runScoped(
      projectorPool,
      "aios_c11_projector",
      scope,
      "BEGIN ISOLATION LEVEL SERIALIZABLE",
      async (client) => {
        const receipt = await client.query(
          `SELECT request_hash,result
             FROM ${table("projection_receipt")}
            WHERE tenant_id=$1 AND idempotency_key=$2`,
          [scope.tenantId, envelope.idempotencyKey],
        );
        if (receipt.rowCount === 1) {
          if (receipt.rows[0].request_hash !== envelope.requestHash) {
            fail(
              "IDEMPOTENCY_CONFLICT",
              "Projection idempotency key was reused.",
            );
          }
          return {
            ...clone(jsonValue(receipt.rows[0].result)),
            replayed: true,
          };
        }

        const currentResult = await client.query(
          `SELECT *
             FROM ${table("document_projection")}
            WHERE tenant_id=$1
              AND document_id=$2
              AND document_version=$3
            FOR UPDATE`,
          [
            scope.tenantId,
            envelope.command.documentId,
            envelope.command.documentVersion,
          ],
        );
        const current = projectionFromRow(currentResult.rows[0]);
        const pendingDeleteAtSameRevision =
          current &&
          envelope.command.state === "DELETE_PENDING" &&
          current.state !== "DELETE_PENDING" &&
          current.state !== "DELETED" &&
          envelope.command.catalogRevision === current.catalogRevision;
        if (
          (current &&
            (current.projectionVersion !==
              envelope.command.expectedProjectionVersion ||
              (
                envelope.command.catalogRevision <=
                  current.catalogRevision &&
                !pendingDeleteAtSameRevision
              ))) ||
          (!current &&
            envelope.command.expectedProjectionVersion !== 0)
        ) {
          fail("VERSION_CONFLICT", "C11 projection revision is stale.");
        }
        if (
          envelope.command.state === "PUBLISHED" &&
          (!envelope.command.metadata ||
            envelope.command.chunks.length === 0)
        ) {
          fail(
            "CATALOG_UNVERIFIED",
            "Published projection requires C10 Chunks.",
          );
        }
        if (
          envelope.command.state !== "PUBLISHED" &&
          envelope.command.chunks.length !== 0
        ) {
          fail(
            "PRE_FILTER_VIOLATION",
            "Non-published content cannot enter the C11 index.",
          );
        }

        await client.query(
          `INSERT INTO ${table("tenant_index_epoch")} (
             tenant_id,tenant_kind,index_epoch,updated_at
           ) VALUES ($1,'SYNTHETIC',0,$2)
           ON CONFLICT (tenant_id) DO NOTHING`,
          [scope.tenantId, envelope.command.at],
        );
        const epochResult = await client.query(
          `UPDATE ${table("tenant_index_epoch")}
              SET index_epoch=index_epoch+1,updated_at=$2
            WHERE tenant_id=$1
            RETURNING index_epoch`,
          [scope.tenantId, envelope.command.at],
        );
        if (epochResult.rowCount !== 1) {
          fail("TENANT_SCOPE_VIOLATION", "C11 index epoch is unavailable.");
        }
        const indexEpoch = safeInteger(
          epochResult.rows[0].index_epoch,
        );
        const invalidated = await client.query(
          `DELETE FROM ${table("retrieval_cache")}
            WHERE tenant_id=$1`,
          [scope.tenantId],
        );
        const metadata =
          envelope.command.state === "PUBLISHED"
            ? envelope.command.metadata
            : null;
        const projection = Object.freeze({
          tenantId: scope.tenantId,
          tenantKind: "SYNTHETIC",
          documentId: envelope.command.documentId,
          documentVersion: envelope.command.documentVersion,
          projectionVersion: (current?.projectionVersion ?? 0) + 1,
          catalogRevision: envelope.command.catalogRevision,
          state: envelope.command.state,
          contentSha256: envelope.command.contentSha256,
          parseSha256: envelope.command.parseSha256,
          validFrom: metadata?.validFrom ?? null,
          validUntil: metadata?.validUntil ?? null,
          classification: metadata?.classification ?? null,
          acl: clone(metadata?.acl ?? null),
          indexEpoch,
          authorizationEvidence: clone(
            envelope.command.authorizationEvidence,
          ),
          updatedAt: envelope.command.at,
        });
        if (current) {
          const updated = await client.query(
            `UPDATE ${table("document_projection")}
                SET projection_version=$5,catalog_revision=$6,state=$7,
                    valid_from=$8,valid_until=$9,classification=$10,
                    acl=$11::jsonb,index_epoch=$12,
                    authorization_evidence=$13::jsonb,updated_at=$14
              WHERE tenant_id=$1
                AND document_id=$2
                AND document_version=$3
                AND projection_version=$4`,
            [
              projection.tenantId,
              projection.documentId,
              projection.documentVersion,
              current.projectionVersion,
              projection.projectionVersion,
              projection.catalogRevision,
              projection.state,
              projection.validFrom,
              projection.validUntil,
              projection.classification,
              projection.acl === null
                ? null
                : JSON.stringify(projection.acl),
              projection.indexEpoch,
              JSON.stringify(projection.authorizationEvidence),
              projection.updatedAt,
            ],
          );
          if (updated.rowCount !== 1) {
            fail("VERSION_CONFLICT", "C11 projection revision is stale.");
          }
        } else {
          await client.query(
            `INSERT INTO ${table("document_projection")} (
               tenant_id,tenant_kind,document_id,document_version,
               projection_version,catalog_revision,state,content_sha256,
               parse_sha256,valid_from,valid_until,classification,acl,
               index_epoch,authorization_evidence,updated_at
             ) VALUES (
               $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,
               $14,$15::jsonb,$16
             )`,
            [
              projection.tenantId,
              projection.tenantKind,
              projection.documentId,
              projection.documentVersion,
              projection.projectionVersion,
              projection.catalogRevision,
              projection.state,
              projection.contentSha256,
              projection.parseSha256,
              projection.validFrom,
              projection.validUntil,
              projection.classification,
              projection.acl === null
                ? null
                : JSON.stringify(projection.acl),
              projection.indexEpoch,
              JSON.stringify(projection.authorizationEvidence),
              projection.updatedAt,
            ],
          );
        }

        if (projection.state === "PUBLISHED") {
          for (const chunk of envelope.command.chunks) {
            await client.query(
              `INSERT INTO ${table("chunk_index")} (
                 tenant_id,tenant_kind,document_id,document_version,
                 catalog_revision,chunk_id,ordinal,original_node_id,
                 page_node_id,section_node_id,table_node_id,location,
                 chunk_text,text_sha256,source_sha256,embedding_model,
                 embedding,state,active,index_epoch
               ) VALUES (
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,
                 $13,$14,$15,$16,$17::vector(8),'PUBLISHED',true,$18
               )
               ON CONFLICT (
                 tenant_id,document_id,document_version,chunk_id
               ) DO UPDATE SET
                 catalog_revision=EXCLUDED.catalog_revision,
                 state='PUBLISHED',
                 active=true,
                 index_epoch=EXCLUDED.index_epoch`,
              [
                projection.tenantId,
                projection.tenantKind,
                projection.documentId,
                projection.documentVersion,
                projection.catalogRevision,
                chunk.chunkId,
                chunk.ordinal,
                chunk.originalNodeId,
                chunk.pageNodeId,
                chunk.sectionNodeId,
                chunk.tableNodeId,
                JSON.stringify(chunk.location),
                chunk.text,
                chunk.textSha256,
                chunk.sourceSha256,
                "c11-deterministic-hash-embedding-v1",
                vectorLiteral(chunk.embedding),
                projection.indexEpoch,
              ],
            );
          }
        } else {
          await client.query(
            `UPDATE ${table("chunk_index")}
                SET catalog_revision=$4,state=$5,active=false,index_epoch=$6
              WHERE tenant_id=$1
                AND document_id=$2
                AND document_version=$3`,
            [
              projection.tenantId,
              projection.documentId,
              projection.documentVersion,
              projection.catalogRevision,
              projection.state,
              projection.indexEpoch,
            ],
          );
        }

        const result = Object.freeze({
          replayed: false,
          projection,
          activeChunkCount:
            projection.state === "PUBLISHED"
              ? envelope.command.chunks.length
              : 0,
          invalidatedCacheCount: invalidated.rowCount,
        });
        await client.query(
          `INSERT INTO ${table("projection_receipt")} (
             tenant_id,tenant_kind,idempotency_key,request_hash,
             document_id,document_version,result,created_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8)`,
          [
            projection.tenantId,
            projection.tenantKind,
            envelope.idempotencyKey,
            envelope.requestHash,
            projection.documentId,
            projection.documentVersion,
            JSON.stringify(result),
            projection.updatedAt,
          ],
        );
        return result;
      },
    );
  }

  async function applyProjection(scope, envelope) {
    validateScope(scope);
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await applyOnce(scope, envelope);
      } catch (error) {
        const retryable =
          RETRYABLE_SQL_STATES.has(error?.code) ||
          (error?.code === "23505" &&
            error?.constraint === "projection_receipt_pkey");
        if (!retryable || attempt >= maxSerializableRetries) {
          throw databaseFailure(error);
        }
        await new Promise((resolve) =>
          setTimeout(resolve, Math.min(5 * 2 ** attempt, 50)),
        );
      }
    }
  }

  async function search(scope, filter, input) {
    validateScope(scope);
    try {
      return await runScoped(
        queryPool,
        "aios_c11_query",
        scope,
        "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
        async (client) => {
          const epoch = await client.query(
            `SELECT index_epoch
               FROM ${table("tenant_index_epoch")}
              WHERE tenant_id=$1`,
            [scope.tenantId],
          );
          const observedIndexEpoch =
            epoch.rowCount === 0
              ? 0
              : safeInteger(epoch.rows[0].index_epoch);
          const result = await client.query(
            `WITH authorized_chunks AS MATERIALIZED (
               SELECT
                 chunk.*,
                 projection.projection_version,
                 projection.state AS projection_state,
                 projection.content_sha256,
                 projection.parse_sha256,
                 projection.valid_from,
                 projection.valid_until,
                 projection.classification,
                 projection.acl,
                 projection.index_epoch AS projection_index_epoch,
                 projection.authorization_evidence,
                 projection.updated_at AS projection_updated_at,
                 least(
                   1.0,
                   10.0 * ts_rank_cd(
                     chunk.search_vector,
                     websearch_to_tsquery(
                       'simple',
                       regexp_replace(btrim($4), '\\s+', ' OR ', 'g')
                     )
                   )
                 ) AS lexical_score,
                 greatest(
                   0.0,
                   1.0 - (chunk.embedding <=> $5::vector(8))
                 ) AS vector_score
               FROM ${table("document_projection")} AS projection
               JOIN ${table("chunk_index")} AS chunk
                 ON chunk.tenant_id=projection.tenant_id
                AND chunk.document_id=projection.document_id
                AND chunk.document_version=projection.document_version
               JOIN ${catalogTable("knowledge_document")} AS catalog
                 ON catalog.tenant_id=projection.tenant_id
                AND catalog.document_id=projection.document_id
                AND catalog.document_version=projection.document_version
                AND catalog.revision=projection.catalog_revision
                AND catalog.state='PUBLISHED'
               JOIN ${catalogTable("source_node")} AS source
                 ON source.tenant_id=chunk.tenant_id
                AND source.document_id=chunk.document_id
                AND source.document_version=chunk.document_version
                AND source.node_id=chunk.chunk_id
                AND source.node_type='CHUNK'
                AND source.availability_state='PUBLISHED'
              WHERE projection.tenant_id=$1
                AND projection.state='PUBLISHED'
                AND chunk.state='PUBLISHED'
                AND chunk.active=true
                AND projection.valid_from <= $2::timestamptz
                AND $2::timestamptz < projection.valid_until
                AND EXISTS (
                  SELECT 1
                    FROM jsonb_array_elements_text(
                      projection.acl -> 'readPrincipalRefs'
                    ) AS allowed(reference)
                   WHERE allowed.reference=ANY($3::text[])
                )
                AND chunk.search_vector @@
                  websearch_to_tsquery(
                    'simple',
                    regexp_replace(btrim($4), '\\s+', ' OR ', 'g')
                  )
             ),
             scored AS (
               SELECT *,
                      0.6 * lexical_score + 0.4 * vector_score AS score
                 FROM authorized_chunks
             )
             SELECT *
               FROM scored
              WHERE lexical_score > 0
              ORDER BY score DESC,document_id,ordinal
              LIMIT $6`,
            [
              scope.tenantId,
              filter.asOf,
              filter.principalRefs,
              input.query,
              vectorLiteral(input.embedding),
              input.limit,
            ],
          );
          return Object.freeze({
            observedIndexEpoch,
            candidates: Object.freeze(
              result.rows.map(candidateFromRow),
            ),
          });
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function readCache(scope, filter, cacheKey) {
    validateScope(scope);
    try {
      return await runScoped(
        queryPool,
        "aios_c11_query",
        scope,
        "BEGIN",
        async (client) => {
          await client.query(
            `DELETE FROM ${table("retrieval_cache")}
              WHERE tenant_id=$1
                AND expires_at <= $2::timestamptz`,
            [scope.tenantId, filter.asOf],
          );
          const result = await client.query(
            `SELECT cache.candidates
               FROM ${table("retrieval_cache")} AS cache
               JOIN ${table("tenant_index_epoch")} AS epoch
                 ON epoch.tenant_id=cache.tenant_id
                AND epoch.index_epoch=cache.index_epoch
              WHERE cache.tenant_id=$1
                AND cache.cache_key=$2
                AND cache.principal_scope_hash=$3
                AND cache.as_of <= $4::timestamptz
                AND cache.expires_at > $4::timestamptz
                AND NOT EXISTS (
                  SELECT 1
                    FROM jsonb_array_elements(
                      cache.document_refs
                    ) AS expected(value)
                    LEFT JOIN ${catalogTable("knowledge_document")} AS catalog
                      ON catalog.tenant_id=cache.tenant_id
                     AND catalog.document_id=
                         expected.value ->> 'documentId'
                     AND catalog.document_version=
                         (expected.value ->> 'documentVersion')::bigint
                   WHERE catalog.document_id IS NULL
                      OR catalog.state <> 'PUBLISHED'
                      OR catalog.revision <>
                         (expected.value ->> 'catalogRevision')::bigint
                      OR (catalog.metadata ->> 'validFrom')::timestamptz
                         > $4::timestamptz
                      OR $4::timestamptz >=
                         (catalog.metadata ->> 'validUntil')::timestamptz
                )`,
            [
              scope.tenantId,
              cacheKey,
              filter.principalScopeHash,
              filter.asOf,
            ],
          );
          return result.rowCount === 0
            ? null
            : clone(jsonValue(result.rows[0].candidates));
        },
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  async function writeCache(
    scope,
    filter,
    cacheKey,
    expectedIndexEpoch,
    candidates,
  ) {
    validateScope(scope);
    if (
      !Number.isSafeInteger(expectedIndexEpoch) ||
      expectedIndexEpoch < 0
    ) {
      fail("INVALID_INDEX", "C11 expected index epoch is invalid.");
    }
    try {
      return await runScoped(
        queryPool,
        "aios_c11_query",
        scope,
        "BEGIN ISOLATION LEVEL SERIALIZABLE",
        async (client) => {
          const refs = [
            ...new Map(
              candidates.map((candidate) => {
                const value = {
                  documentId: candidate.documentId,
                  documentVersion: candidate.documentVersion,
                  catalogRevision: candidate.catalogRevision,
                };
                return [JSON.stringify(value), value];
              }),
            ).values(),
          ];
          const written = await client.query(
            `INSERT INTO ${table("retrieval_cache")} (
               tenant_id,tenant_kind,cache_key,principal_scope_hash,
               as_of,expires_at,index_epoch,document_refs,candidates,
               created_at
             )
             SELECT
               $1,'SYNTHETIC',$2,$3,$4,
               $4::timestamptz + interval '30 seconds',
               epoch.index_epoch,
               $6::jsonb,$7::jsonb,statement_timestamp()
               FROM ${table("tenant_index_epoch")} AS epoch
              WHERE epoch.tenant_id=$1
                AND epoch.index_epoch=$5
             ON CONFLICT (tenant_id,cache_key) DO UPDATE SET
               principal_scope_hash=EXCLUDED.principal_scope_hash,
               as_of=EXCLUDED.as_of,
               expires_at=EXCLUDED.expires_at,
               index_epoch=EXCLUDED.index_epoch,
               document_refs=EXCLUDED.document_refs,
               candidates=EXCLUDED.candidates,
               created_at=EXCLUDED.created_at`,
            [
              scope.tenantId,
              cacheKey,
              filter.principalScopeHash,
              filter.asOf,
              expectedIndexEpoch,
              JSON.stringify(refs),
              JSON.stringify(candidates),
            ],
          );
          return written.rowCount === 1;
        },
      );
    } catch (error) {
      if (RETRYABLE_SQL_STATES.has(error?.code)) return false;
      throw databaseFailure(error);
    }
  }

  async function recordAudit(scope, record) {
    validateScope(scope);
    if (
      "query" in record ||
      "text" in record ||
      "context" in record ||
      "answer" in record
    ) {
      fail("LOG_BODY_FORBIDDEN", "C11 audit cannot store body text.");
    }
    try {
      await runScoped(
        queryPool,
        "aios_c11_query",
        scope,
        "BEGIN",
        (client) =>
          client.query(
            `INSERT INTO ${table("query_audit")} (
               tenant_id,tenant_kind,audit_version,request_id_hash,
               query_hash,filter_hash,principal_scope_hash,
               authorization_decision_id,candidate_count,evidence_count,
               result_status,reason_code,evidence_id_hashes,cache_hit,
               recorded_at
             ) VALUES (
               $1,'SYNTHETIC',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
               $12::jsonb,$13,$14
             )`,
            [
              scope.tenantId,
              record.auditVersion,
              record.requestIdHash,
              record.queryHash,
              record.filterHash,
              record.principalScopeHash,
              record.authorizationDecisionId,
              record.candidateCount,
              record.evidenceCount,
              record.resultStatus,
              record.reasonCode,
              JSON.stringify(record.evidenceIdHashes),
              record.cacheHit,
              record.recordedAt,
            ],
          ),
      );
    } catch (error) {
      throw databaseFailure(error);
    }
  }

  return Object.freeze({
    applyProjection,
    search,
    readCache,
    writeCache,
    recordAudit,
  });
}
