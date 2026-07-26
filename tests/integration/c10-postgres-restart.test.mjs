import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createC10SyntheticBenchmark,
  createKnowledgeCatalog,
  createMemoryC10QuarantineStore,
} from "../../lib/knowledge-catalog.mjs";
import {
  createPostgresKnowledgeCatalogStore,
} from "../../lib/postgres-knowledge-catalog-store.mjs";

const { Pool } = pg;
const TENANT_ID = "stn_01984910-6000-7000-8000-000000000001";
const HUMAN = "prn_01984910-6000-7000-8000-000000000011";
const WORKLOAD = "prn_01984910-6000-7000-8000-000000000012";
const DELEGATION = "dlg_01984910-6000-7000-8000-000000000021";
const benchmark = createC10SyntheticBenchmark(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c10/synthetic-document-benchmark.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);

function config(user = process.env.C10_TEST_PGUSER) {
  if (
    process.env.C10_TEST_EPHEMERAL !== "1" ||
    process.env.C10_TEST_POSTGRES_RESTARTED !== "1"
  ) {
    throw new Error(
      "C10 after-restart test requires an ephemeral restarted PostgreSQL.",
    );
  }
  for (const name of [
    "C10_TEST_PGHOST",
    "C10_TEST_PGPORT",
    "C10_TEST_PGDATABASE",
    "C10_TEST_PGUSER",
    "C10_TEST_PRE_RESTART_EPOCH",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C10_TEST_PGHOST,
    port: Number(process.env.C10_TEST_PGPORT),
    database: process.env.C10_TEST_PGDATABASE,
    user,
  };
}

function tenantScope() {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: "c10-after-postgresql-restart",
    decisionId: "c07-after-postgresql-restart",
    evidenceRef: "evidence://c07/c10-after-postgresql-restart",
    policyVersion: "c07-policy-v1",
  };
}

function context() {
  return {
    tenantScope: tenantScope(),
    c06ServerContext: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId: TENANT_ID,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: WORKLOAD,
    },
    authorizationRequest: {
      sessionToken: "allow",
      delegationId: DELEGATION,
      correlationId: "c06-after-postgresql-restart",
    },
  };
}

function authorizer() {
  return {
    async enforce(serverContext, request, descriptor) {
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        decisionId: "c06-after-postgresql-restart",
        evidenceRef: "evidence://c06/after-postgresql-restart",
        policyVersion: "c06-policy-v1",
        tenantId: serverContext.tenantId,
        surface: descriptor.surface,
        resourceId: request.resourceId,
        humanPrincipalId: HUMAN,
        humanSecurityEpoch: 1,
        workloadActorPrincipalId: WORKLOAD,
        workloadActorSecurityEpoch: 1,
        leafDelegationId: DELEGATION,
        delegationChainSha256:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        purposeRef: "synthetic://c10/postgresql-restart",
      };
    },
  };
}

test("C10 shared references and idempotent deletion survive a real PostgreSQL restart", async (t) => {
  const adminPool = new Pool(config());
  const runtimePool = new Pool(config("c10_test_runtime_login"));
  const readerPool = new Pool(config("c10_test_reader_login"));
  const scopePool = new Pool(config("c10_test_scope_login"));
  t.after(async () => {
    await Promise.all([
      runtimePool.end(),
      readerPool.end(),
      scopePool.end(),
      adminPool.end(),
    ]);
  });

  const postmaster = await adminPool.query(
    `SELECT EXTRACT(EPOCH FROM pg_postmaster_start_time())::float8
       AS started_epoch`,
  );
  assert.equal(
    Number(postmaster.rows[0].started_epoch) >
      Number(process.env.C10_TEST_PRE_RESTART_EPOCH),
    true,
  );

  const documents = await adminPool.query(
    `SELECT document_id,state,content_sha256,quarantine_ref
       FROM aios_knowledge.knowledge_document
      WHERE tenant_id=$1
        AND document_id=ANY($2::text[])
      ORDER BY document_id`,
    [TENANT_ID, ["pg-shared-a", "pg-shared-b"]],
  );
  assert.equal(documents.rowCount, 2);
  assert.deepEqual(
    documents.rows.map(({ state }) => state),
    ["DELETED", "DELETED"],
  );
  assert.equal(
    new Set(documents.rows.map(({ content_sha256 }) => content_sha256))
      .size,
    1,
  );
  assert.equal(
    new Set(documents.rows.map(({ quarantine_ref }) => quarantine_ref))
      .size,
    2,
  );

  const store = createPostgresKnowledgeCatalogStore({
    runtimePool,
    readerPool,
    scopePool,
  });
  const catalog = createKnowledgeCatalog({
    store,
    c06Authorizer: authorizer(),
    benchmark,
    quarantineStore: createMemoryC10QuarantineStore(),
    clock: () => "2026-07-30T00:00:00.000Z",
  });
  const deletion = {
    idempotencyKey: "delete-pg-shared-b-1-1",
    documentId: "pg-shared-b",
    documentVersion: 1,
    expectedRevision: 1,
  };
  const firstReplay = await catalog.delete(context(), deletion);
  const secondReplay = await catalog.delete(context(), deletion);
  assert.equal(firstReplay.replayed, true);
  assert.equal(secondReplay.replayed, true);
  assert.equal(firstReplay.document.state, "DELETED");
  assert.deepEqual(secondReplay.document, firstReplay.document);

  const persisted = await adminPool.query(
    `SELECT
       (SELECT count(*)::int
          FROM aios_knowledge.command_receipt
         WHERE tenant_id=$1
           AND idempotency_key=ANY($2::text[])) AS receipts,
       (SELECT count(*)::int
          FROM aios_knowledge.storage_effect
         WHERE tenant_id=$1
           AND document_id=ANY($3::text[])
           AND effect_kind='ERASE'
           AND status='COMPLETED') AS completed_effects`,
    [
      TENANT_ID,
      [
        "delete-pg-shared-a-1-1",
        "delete-pg-shared-b-1-1",
      ],
      ["pg-shared-a", "pg-shared-b"],
    ],
  );
  assert.deepEqual(persisted.rows[0], {
    receipts: 2,
    completed_effects: 2,
  });
});
