import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("C11 OpenAPI freezes server-only filters and P1 boundary", async () => {
  const api = JSON.parse(
    await read(
      "implementation/p1/c11/permission-aware-rag.openapi.v1.json",
    ),
  );
  assert.equal(api.openapi, "3.1.0");
  assert.deepEqual(api["x-c11-boundary"], {
    implementation_status: "IMPLEMENTED",
    verification_status: "EVIDENCE_CANDIDATE",
    verification_scope: "P1_SYNTHETIC_ONLY",
    production_verification_status: "NOT_VERIFIED",
    enterprise_integration_status: "P3_REQUIRED",
    enterprise_connectors: "C0_DISABLED",
    authorization: "SERVER_SIDE_C06_BEFORE_RETRIEVAL",
    tenant_scope: "C07_VERIFIED_SYNTHETIC_TENANT",
    knowledge_truth: "C10_CURRENT_CATALOG",
    filter_authority: "SERVER_ONLY",
    retrieval: "POSTGRESQL_FTS_PLUS_PGVECTOR",
    generation: "EXTRACTIVE_DRAFT_OR_DETERMINISTIC_REFUSAL",
  });
  assert.equal(Object.keys(api.paths).length, 2);
  const search = api.components.schemas.SearchRequest;
  assert.equal(search.additionalProperties, false);
  assert.deepEqual(search.required.sort(), [
    "limit",
    "query",
    "requestId",
  ]);
  for (const forbidden of [
    "tenantId",
    "principalId",
    "principalRefs",
    "acl",
    "state",
    "asOf",
    "filter",
    "embedding",
  ]) {
    assert.equal(forbidden in search.properties, false);
  }
});

test("C11 acceptance matrix freezes forty-two synthetic cases", async () => {
  const matrix = JSON.parse(
    await read("implementation/p1/c11/acceptance-matrix.v1.json"),
  );
  assert.equal(matrix.workPackageId, "C11");
  assert.equal(matrix.caseCount, 42);
  assert.equal(matrix.cases.length, 42);
  assert.equal(
    new Set(matrix.cases.map(({ id }) => id)).size,
    matrix.cases.length,
  );
  assert.equal(
    matrix.cases.every(
      ({ evidenceStatus }) =>
        evidenceStatus === "CANDIDATE_P1_SYNTHETIC",
    ),
    true,
  );
  for (const category of [
    "BOUNDARY",
    "FILTER_AUTHORITY",
    "AUTHORIZATION",
    "TENANT",
    "PRINCIPAL",
    "PREFILTER",
    "RETRIEVAL",
    "EVIDENCE",
    "REFUSAL",
    "CACHE",
    "INVALIDATION",
    "AUDIT",
    "IDEMPOTENCY",
    "CONCURRENCY",
    "RECOVERY",
    "DATABASE",
    "PROVENANCE",
    "BENCHMARK",
  ]) {
    assert.equal(
      matrix.cases.some((entry) => entry.category === category),
      true,
      category,
    );
  }
});

test("C11 migration freezes prefilter, hybrid index, provenance, and RLS", async () => {
  const sql = await read(
    "implementation/p1/c11/postgresql/0025_permission_aware_rag.sql",
  );
  for (const fragment of [
    "CREATE TABLE aios_rag.tenant_index_epoch",
    "CREATE TABLE aios_rag.document_projection",
    "CREATE TABLE aios_rag.chunk_index",
    "CREATE TABLE aios_rag.retrieval_cache",
    "CREATE TABLE aios_rag.projection_receipt",
    "CREATE TABLE aios_rag.query_audit",
    "to_tsvector('simple', chunk_text)",
    "embedding vector(8)",
    "USING hnsw (embedding vector_cosine_ops)",
    "rag_chunk_source_guard",
    "rag_chunk_chain_guard",
    "rag_projection_catalog_guard",
    "DEFERRABLE INITIALLY DEFERRED",
    "FORCE ROW LEVEL SECURITY",
  ]) {
    assert.match(
      sql,
      new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
  }
  assert.doesNotMatch(sql, /\bDROP\s+(?:TABLE|SCHEMA)\b/i);
  assert.doesNotMatch(sql, /tenant_kind\s*=\s*'ENTERPRISE'/i);
  const auditTable = sql.slice(
    sql.indexOf("CREATE TABLE aios_rag.query_audit"),
    sql.indexOf("CREATE INDEX rag_projection_filter_idx"),
  );
  assert.doesNotMatch(
    auditTable,
    /^\s+(?:query|answer|context|body|chunk_text)\s+/im,
  );
});

test("C11 roles separate projector, query, owner, and PUBLIC", async () => {
  const sql = await read(
    "implementation/p1/c11/postgresql/0026_permission_aware_rag_runtime_roles.sql",
  );
  for (const role of [
    "aios_c11_owner",
    "aios_c11_projector",
    "aios_c11_query",
  ]) {
    assert.match(sql, new RegExp(`CREATE ROLE ${role}`));
  }
  assert.match(sql, /REVOKE ALL ON SCHEMA aios_rag FROM PUBLIC/);
  assert.match(
    sql,
    /GRANT SELECT, INSERT, UPDATE ON[\s\S]+TO aios_c11_projector/,
  );
  assert.match(
    sql,
    /GRANT SELECT, INSERT, UPDATE ON aios_rag\.retrieval_cache[\s\S]+TO aios_c11_query/,
  );
  assert.doesNotMatch(
    sql,
    /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)[\s\S]+TO\s+PUBLIC/i,
  );
});

test("C11 store SQL materializes authorization before FTS and vector scoring", async () => {
  const source = await read(
    "lib/postgres-permission-aware-rag-store.mjs",
  );
  const authorized = source.indexOf(
    "WITH authorized_chunks AS MATERIALIZED",
  );
  const tenant = source.indexOf(
    "WHERE projection.tenant_id=$1",
    authorized,
  );
  const acl = source.indexOf(
    "jsonb_array_elements_text",
    authorized,
  );
  const fts = source.indexOf(
    "chunk.search_vector @@",
    authorized,
  );
  const score = source.indexOf("scored AS", authorized);
  assert.ok(authorized >= 0);
  assert.ok(tenant > authorized);
  assert.ok(acl > tenant);
  assert.ok(fts > acl);
  assert.ok(score > fts);
  assert.match(source, /catalog\.state='PUBLISHED'/);
  assert.match(source, /source\.availability_state='PUBLISHED'/);
  assert.match(source, /epoch\.index_epoch=\$5/);
});

test("C11 real PostgreSQL runner is executable and isolated", async () => {
  const path = "implementation/p1/c11/run-postgresql-tests.sh";
  const runner = await read(path);
  const mode = (await stat(new URL(path, root))).mode;
  assert.notEqual(mode & 0o100, 0);
  assert.match(runner, /C11_TEST_EPHEMERAL=1/);
  assert.match(runner, /tests\/integration\/c11-postgres\.test\.mjs/);
  assert.doesNotMatch(runner, /enterprise|production/i);
});
