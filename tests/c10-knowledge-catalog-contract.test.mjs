import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("C10 OpenAPI freezes synthetic, candidate-only, C06, and C07 boundaries", async () => {
  const api = JSON.parse(
    await read("implementation/p1/c10/knowledge-catalog.openapi.v1.json"),
  );
  assert.equal(api.openapi, "3.1.0");
  assert.deepEqual(api["x-c10-boundary"], {
    implementation_status: "IMPLEMENTED",
    verification_status: "VERIFIED",
    verification_scope: "P1_SYNTHETIC_ONLY",
    production_verification_status: "NOT_VERIFIED",
    enterprise_integration_status: "P3_REQUIRED",
    enterprise_connectors: "C0_DISABLED",
    parser_authority: "CANDIDATE_ONLY",
    parser_adapter: "CLOSED_REPLACEABLE_SEAM",
    parser_node_contract: "RECURSIVELY_CLOSED_BY_TYPE",
    parser_quality_evidence: "P1_SYNTHETIC_GOLDEN_ONLY",
    ocr_verification: "NOT_VERIFIED",
    quarantine_storage: "REFERENCE_MAPPED_CONTENT_DEDUPLICATION",
    storage_effect_delivery: "DURABLE_PENDING_RECONCILIATION",
    receipt_replay: "C06_RECHECK_THEN_DURABLE_PREFLIGHT",
    authorization: "SERVER_SIDE_C06_RECHECK",
    tenant_scope: "C07_VERIFIED_SYNTHETIC_TENANT",
    state_truth: "C08_COMPATIBLE_VERSIONED_STATE",
  });
  assert.equal(Object.keys(api.paths).length, 9);
  assert.equal(
    api.components.schemas.SourceNode.additionalProperties,
    false,
  );
  assert.equal(
    api.components.schemas.SourceLocation.oneOf.every(
      ({ additionalProperties }) => additionalProperties === false,
    ),
    true,
  );
  assert.equal(
    api.components.schemas.PublicationMetadata.required.sort().join(","),
    [
      "acl",
      "classification",
      "ownerPrincipalId",
      "sourceRef",
      "validFrom",
      "validUntil",
      "version",
    ].join(","),
  );
});

test("C10 acceptance matrix freezes fifty-two verified P1 synthetic cases", async () => {
  const matrix = JSON.parse(
    await read("implementation/p1/c10/acceptance-matrix.v1.json"),
  );
  assert.equal(matrix.workPackageId, "C10");
  assert.equal(matrix.caseCount, 52);
  assert.equal(matrix.cases.length, 52);
  assert.equal(
    new Set(matrix.cases.map(({ id }) => id)).size,
    matrix.cases.length,
  );
  assert.equal(
    matrix.cases.every(
      ({ evidenceStatus }) =>
        evidenceStatus === "VERIFIED_P1_SYNTHETIC",
    ),
    true,
  );
  for (const category of [
    "BOUNDARY",
    "QUARANTINE",
    "HASH",
    "INSPECTION",
    "PARSER",
    "PARSER_QUALITY",
    "PROVENANCE",
    "PUBLICATION",
    "AUTHORIZATION",
    "TENANT",
    "VERSION",
    "LIFECYCLE",
    "DELETE",
    "IDEMPOTENCY",
    "CONCURRENCY",
    "RECOVERY",
  ]) {
    assert.equal(
      matrix.cases.some((entry) => entry.category === category),
      true,
      category,
    );
  }
});

test("C10 parser golden and quality report remain synthetic and explicitly non-OCR", async () => {
  const golden = JSON.parse(
    await read("implementation/p1/c10/synthetic-parser-golden.v1.json"),
  );
  const report = JSON.parse(
    await read(
      "implementation/p1/c10/synthetic-parser-quality-report.v1.json",
    ),
  );
  assert.equal(golden.verificationScope, "P1_SYNTHETIC_ONLY");
  assert.equal(golden.productionOcrVerified, false);
  assert.equal(golden.fixtures.length, 2);
  assert.equal(
    golden.fixtures.some(
      ({ parserRoute }) =>
        parserRoute === "SYNTHETIC_SCANNED_IMAGE_TRANSCRIPT",
    ),
    true,
  );
  assert.equal(report.verificationScope, "P1_SYNTHETIC_ONLY");
  assert.equal(report.evidenceStatus, "CANDIDATE_P1_SYNTHETIC");
  assert.equal(report.scanEvidence, "PRESET_SYNTHETIC_TRANSCRIPT_NOT_OCR");
  assert.equal(report.productionOcrVerified, false);
  assert.equal(report.failedCount, 0);
  assert.match(report.reportSha256, /^sha256:[0-9a-f]{64}$/);
});

test("C10 PostgreSQL migration freezes catalog, evidence, provenance, and RLS", async () => {
  const sql = await read(
    "implementation/p1/c10/postgresql/0017_knowledge_catalog.sql",
  );
  for (const fragment of [
    "CREATE TABLE aios_knowledge.knowledge_document",
    "CREATE TABLE aios_knowledge.source_node",
    "CREATE TABLE aios_knowledge.knowledge_revision",
    "CREATE TABLE aios_knowledge.command_receipt",
    "CREATE TABLE aios_knowledge.storage_effect",
    "knowledge_document_state_shape",
    "knowledge_document_quarantine_reference_shape",
    "knowledge_document_transition_guard",
    "knowledge_source_parent_guard",
    "knowledge_source_propagation_guard",
    "knowledge_storage_effect_update_guard",
    "DEFERRABLE INITIALLY DEFERRED",
    "FORCE ROW LEVEL SECURITY",
  ]) {
    assert.match(sql, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(sql, /UNIQUE \(tenant_id, quarantine_ref\)/);
  assert.match(sql, /'UPLOAD_PENDING'/);
  assert.match(sql, /'DELETE_PENDING'/);
  assert.doesNotMatch(sql, /\bDROP\s+(?:TABLE|SCHEMA)\b/i);
  assert.doesNotMatch(sql, /tenant_kind\s*=\s*'ENTERPRISE'/i);
});

test("C10 PostgreSQL roles separate runtime, reader, owner, and public", async () => {
  const sql = await read(
    "implementation/p1/c10/postgresql/0018_knowledge_catalog_runtime_roles.sql",
  );
  for (const role of [
    "aios_c10_owner",
    "aios_c10_runtime",
    "aios_c10_reader",
  ]) {
    assert.match(sql, new RegExp(`CREATE ROLE ${role}`));
  }
  assert.match(sql, /REVOKE ALL ON SCHEMA aios_knowledge FROM PUBLIC/);
  assert.match(
    sql,
    /GRANT SELECT, INSERT, UPDATE ON[\s\S]+TO aios_c10_runtime/,
  );
  assert.match(sql, /aios_knowledge\.storage_effect/);
  assert.match(
    sql,
    /GRANT SELECT ON[\s\S]+TO aios_c10_reader/,
  );
  assert.doesNotMatch(sql, /GRANT\s+DELETE[\s\S]+aios_c10_runtime/i);
  assert.doesNotMatch(
    sql,
    /GRANT\s+(?:SELECT|INSERT|UPDATE|DELETE)[\s\S]+TO\s+PUBLIC/i,
  );
});

test("C10 real PostgreSQL runner is executable and targets only C10 integration", async () => {
  const path = "implementation/p1/c10/run-postgresql-tests.sh";
  const runner = await read(path);
  const mode = (await stat(new URL(path, root))).mode;
  assert.notEqual(mode & 0o100, 0);
  assert.match(runner, /C10_TEST_EPHEMERAL=1/);
  assert.match(runner, /tests\/integration\/c10-postgres\.test\.mjs/);
  assert.match(runner, /pg_ctl"[\s\S]*-w restart/);
  assert.match(
    runner,
    /tests\/integration\/c10-postgres-restart\.test\.mjs/,
  );
  assert.doesNotMatch(runner, /enterprise|production/i);
});
