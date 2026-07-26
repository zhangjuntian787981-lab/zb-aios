import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createC10SyntheticBenchmark,
  createKnowledgeCatalog,
} from "../../lib/knowledge-catalog.mjs";
import {
  createPostgresKnowledgeCatalogStore,
} from "../../lib/postgres-knowledge-catalog-store.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c10/postgresql/0017_knowledge_catalog.sql",
    "../../implementation/p1/c10/postgresql/0018_knowledge_catalog_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);
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

const TENANT_A = "stn_01984910-6000-7000-8000-000000000001";
const TENANT_B = "stn_01984910-6000-7000-8000-000000000002";
const HUMAN = "prn_01984910-6000-7000-8000-000000000011";
const WORKLOAD = "prn_01984910-6000-7000-8000-000000000012";
const DELEGATION = "dlg_01984910-6000-7000-8000-000000000021";
const RUNTIME_LOGIN = "c10_test_runtime_login";
const READER_LOGIN = "c10_test_reader_login";
const SCOPE_LOGIN = "c10_test_scope_login";
const PUBLIC_LOGIN = "c10_test_public_login";
const TABLES = [
  "command_receipt",
  "knowledge_document",
  "knowledge_revision",
  "source_node",
];

function config(user = process.env.C10_TEST_PGUSER, max = 30) {
  if (process.env.C10_TEST_EPHEMERAL !== "1") {
    throw new Error("C10_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C10_TEST_PGHOST",
    "C10_TEST_PGPORT",
    "C10_TEST_PGDATABASE",
    "C10_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C10_TEST_PGHOST,
    port: Number(process.env.C10_TEST_PGPORT),
    database: process.env.C10_TEST_PGDATABASE,
    user,
    max,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function scope(tenantId) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: `c10-${tenantId}`,
    decisionId: `c07-decision-${tenantId}`,
    evidenceRef: `evidence://c07/${tenantId}`,
    policyVersion: "c07-policy-v1",
  };
}

function context(tenantId = TENANT_A, sessionToken = "allow") {
  return {
    tenantScope: scope(tenantId),
    c06ServerContext: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: WORKLOAD,
    },
    authorizationRequest: {
      sessionToken,
      delegationId: DELEGATION,
      correlationId: `c06-${tenantId}`,
    },
  };
}

function authorizer() {
  let index = 0;
  return {
    async enforce(serverContext, request, descriptor) {
      index += 1;
      if (request.sessionToken !== "allow") {
        const error = new Error("denied");
        error.code = "ACCESS_DENIED";
        throw error;
      }
      return {
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        decisionId: `c06-${index}`,
        evidenceRef: `evidence://c06/${index}`,
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
        purposeRef: "synthetic://c10/postgresql",
      };
    },
  };
}

function timeSource(start = "2026-07-26T08:00:00.000Z") {
  let time = Date.parse(start);
  return {
    clock() {
      const result = new Date(time).toISOString();
      time += 60_000;
      return result;
    },
    set(value) {
      time = Date.parse(value);
    },
  };
}

function upload(documentId, version = 1) {
  return {
    idempotencyKey: `upload-${documentId}-${version}`,
    documentId,
    documentVersion: version,
    expectedRevision: 0,
    fixtureRef: "fixture://c10/clean-markdown",
    filename: "clean-guide.md",
    declaredMediaType: "text/markdown",
    sourceRef: `fixture://c10/${documentId}/source`,
  };
}

function command(name, documentId, version, expectedRevision) {
  return {
    idempotencyKey: `${name}-${documentId}-${version}-${expectedRevision}`,
    documentId,
    documentVersion: version,
    expectedRevision,
  };
}

function metadata(documentId, version = "2026.1", validUntil = "2027-01-01T00:00:00.000Z") {
  return {
    ownerPrincipalId: HUMAN,
    sourceRef: `fixture://c10/${documentId}/register`,
    version,
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil,
    classification: "INTERNAL",
    acl: {
      resourceId: documentId,
      readPrincipalRefs: ["group:synthetic-readers"],
      managePrincipalRefs: ["group:synthetic-knowledge-owners"],
    },
  };
}

async function seedTenant(adminPool, tenantId, suffix) {
  const time = "2026-07-26T07:00:00.000Z";
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id,tenant_kind,state,lifecycle_version,generation,
       creation_key,origin_ref,origin_hash,config_refs,
       resource_namespace_id,operation_id,created_at,updated_at
     ) VALUES (
       $1,'SYNTHETIC','PROVISIONING',1,1,$2,$3,$4,'[]'::jsonb,$5,$6,$7,$7
     )`,
    [
      tenantId,
      `c10-${suffix}-creation`,
      `fixture://c10/${suffix}/tenant`,
      digest(`c10-${suffix}-origin`),
      `sns_01984910-6000-7000-8000-0000000000${suffix}`,
      `op_01984910-6000-7000-8000-0000000001${suffix}`,
      time,
    ],
  );
  for (const projection of [
    "AUTHORIZATION",
    "IDENTITY",
    "KNOWLEDGE",
    "SECRET_REFS",
    "STORAGE",
  ]) {
    await adminPool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id,generation,projection,desired_action,status,
         attempt_count,source_event_id,updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [tenantId, projection, `c10-${suffix}-${projection}`, time],
    );
  }
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE',lifecycle_version=2,updated_at=$2
      WHERE tenant_id=$1`,
    [tenantId, "2026-07-26T07:01:00.000Z"],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id,tenant_kind,lifecycle_version,generation,operation_id,
       state,last_event_id,updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4)`,
    [
      tenantId,
      `op_01984910-6000-7000-8000-0000000001${suffix}`,
      `c10-${suffix}-active`,
      "2026-07-26T07:01:00.000Z",
    ],
  );
}

async function runRawScoped(
  runtimePool,
  scopePool,
  tenantScope,
  operation,
) {
  const runtime = await runtimePool.connect();
  let started = false;
  try {
    await runtime.query("BEGIN");
    started = true;
    const transaction = await runtime.query(
      `SELECT pg_backend_pid() AS backend_pid,
              pg_current_xact_id()::text AS transaction_id`,
    );
    const backendPid = transaction.rows[0].backend_pid;
    const transactionId = transaction.rows[0].transaction_id;
    const signer = await scopePool.connect();
    let signed;
    const nonce = randomUUID();
    try {
      const result = await signer.query(
        `SELECT aios_data.issue_runtime_scope_signature(
           $1,$2,$3,$4,$5,$6,$7,$8,$9::xid8,15,$10::uuid
         ) AS signed_scope`,
        [
          tenantScope.tenantId,
          tenantScope.tenantKind,
          tenantScope.lifecycleVersion,
          tenantScope.correlationId,
          tenantScope.decisionId,
          tenantScope.evidenceRef,
          tenantScope.policyVersion,
          backendPid,
          transactionId,
          nonce,
        ],
      );
      signed = result.rows[0].signed_scope;
    } finally {
      signer.release();
    }
    await runtime.query(
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
        tenantScope.tenantId,
        tenantScope.tenantKind,
        String(tenantScope.lifecycleVersion),
        tenantScope.correlationId,
        tenantScope.decisionId,
        tenantScope.evidenceRef,
        tenantScope.policyVersion,
        String(backendPid),
        transactionId,
        String(signed.expires_epoch_ms),
        nonce,
        signed.signature,
      ],
    );
    await runtime.query(
      "SELECT aios_data.acquire_runtime_fence() AS acquired",
    );
    const result = await operation(runtime);
    await runtime.query("COMMIT");
    started = false;
    return result;
  } catch (error) {
    if (started) await runtime.query("ROLLBACK");
    throw error;
  } finally {
    runtime.release();
  }
}

async function parsed(catalog, ctx, documentId, version = 1) {
  await catalog.upload(ctx, upload(documentId, version));
  await catalog.inspect(ctx, command("inspect", documentId, version, 1));
  return catalog.parse(ctx, command("parse", documentId, version, 2));
}

test("C10 real PostgreSQL catalog, RLS, roles, concurrency, replay, and recovery", async (t) => {
  const adminPool = new Pool(config());
  const pools = [];
  const pool = (user, max = 30) => {
    const value = new Pool(config(user, max));
    pools.push(value);
    return value;
  };
  t.after(async () => {
    await Promise.all(pools.map((value) => value.end()));
    await adminPool.end();
  });

  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_knowledge') AS knowledge_schema`,
  );
  assert.match(safety.rows[0].database, /^c10_test_[0-9]+$/);
  assert.equal(safety.rows[0].knowledge_schema, null);
  for (const migration of migrations) await adminPool.query(migration);
  await seedTenant(adminPool, TENANT_A, "01");
  await seedTenant(adminPool, TENANT_B, "02");
  await adminPool.query(`CREATE ROLE ${RUNTIME_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${READER_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${SCOPE_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${PUBLIC_LOGIN} LOGIN`);
  await adminPool.query(
    `GRANT aios_c10_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c10_reader TO ${READER_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );

  const runtimePool = pool(RUNTIME_LOGIN, 40);
  const readerPool = pool(READER_LOGIN, 20);
  const scopePool = pool(SCOPE_LOGIN, 40);
  const publicPool = pool(PUBLIC_LOGIN, 2);
  const store = createPostgresKnowledgeCatalogStore({
    runtimePool,
    readerPool,
    scopePool,
  });
  const time = timeSource();
  const catalog = createKnowledgeCatalog({
    store,
    c06Authorizer: authorizer(),
    benchmark,
    clock: time.clock,
  });
  const ctx = context();

  await t.test("roles are NOLOGIN least-privilege and all tables FORCE RLS", async () => {
    const attributes = await adminPool.query(
      `SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolcanlogin,
              rolinherit,rolreplication,rolbypassrls
         FROM pg_roles
        WHERE rolname=ANY($1::text[])
        ORDER BY rolname`,
      [["aios_c10_owner", "aios_c10_reader", "aios_c10_runtime"]],
    );
    assert.equal(attributes.rows.length, 3);
    for (const row of attributes.rows) {
      assert.equal(row.rolsuper, false);
      assert.equal(row.rolcreatedb, false);
      assert.equal(row.rolcreaterole, false);
      assert.equal(row.rolcanlogin, false);
      assert.equal(row.rolinherit, false);
      assert.equal(row.rolreplication, false);
      assert.equal(row.rolbypassrls, false);
    }
    const rls = await adminPool.query(
      `SELECT relname,relrowsecurity,relforcerowsecurity
         FROM pg_class
         JOIN pg_namespace ON pg_namespace.oid=pg_class.relnamespace
        WHERE nspname='aios_knowledge'
          AND relname=ANY($1::text[])
        ORDER BY relname`,
      [TABLES],
    );
    assert.equal(rls.rows.length, 4);
    assert.equal(
      rls.rows.every((row) => row.relrowsecurity && row.relforcerowsecurity),
      true,
    );
    const privileges = await adminPool.query(
      `SELECT
         has_table_privilege('aios_c10_runtime',
           'aios_knowledge.knowledge_document','UPDATE') AS runtime_update,
         has_table_privilege('aios_c10_runtime',
           'aios_knowledge.knowledge_document','DELETE') AS runtime_delete,
         has_table_privilege('aios_c10_reader',
           'aios_knowledge.knowledge_document','SELECT') AS reader_select,
         has_table_privilege('aios_c10_reader',
           'aios_knowledge.knowledge_document','INSERT') AS reader_insert,
         has_table_privilege('aios_c10_reader',
           'aios_knowledge.command_receipt','SELECT') AS reader_receipt`,
    );
    assert.deepEqual(privileges.rows[0], {
      runtime_update: true,
      runtime_delete: false,
      reader_select: true,
      reader_insert: false,
      reader_receipt: false,
    });
  });

  await t.test("quarantine through publication persists exact candidate provenance", async () => {
    const candidate = await parsed(catalog, ctx, "pg-guide");
    assert.equal(candidate.document.state, "PARSED_CANDIDATE");
    assert.equal(
      candidate.document.nodes.every(
        (node) =>
          node.authorityStatus === "CANDIDATE" &&
          node.availabilityState === "CANDIDATE",
      ),
      true,
    );
    const publication = await catalog.publish(ctx, {
      ...command("publish", "pg-guide", 1, 3),
      metadata: metadata("pg-guide"),
    });
    assert.equal(publication.document.state, "PUBLISHED");
    assert.equal(publication.document.nodes.length >= 8, true);
    assert.equal(
      publication.document.nodes.every(
        (node) => node.availabilityState === "PUBLISHED",
      ),
      true,
    );
  });

  await t.test("cross-Tenant RLS returns no rows", async () => {
    assert.equal(
      await catalog.readAsOf(context(TENANT_B), {
        documentId: "pg-guide",
        asOf: "2026-07-26T10:00:00.000Z",
      }),
      null,
    );
    const direct = await runRawScoped(
      runtimePool,
      scopePool,
      scope(TENANT_B),
      (client) =>
        client.query(
          `SELECT count(*) AS count
             FROM aios_knowledge.knowledge_document
            WHERE tenant_id=$1`,
          [TENANT_A],
        ),
    );
    assert.equal(Number(direct.rows[0].count), 0);
  });

  await t.test("idempotent replay survives a store reconstruction", async () => {
    const replayStore = createPostgresKnowledgeCatalogStore({
      runtimePool,
      readerPool,
      scopePool,
    });
    const replayCatalog = createKnowledgeCatalog({
      store: replayStore,
      c06Authorizer: authorizer(),
      benchmark,
      clock: timeSource("2026-07-27T00:00:00.000Z").clock,
    });
    const replay = await replayCatalog.upload(ctx, upload("pg-guide"));
    assert.equal(replay.replayed, true);
    assert.equal(replay.document.revision, 1);
    await assert.rejects(
      replayCatalog.upload(ctx, {
        ...upload("pg-guide"),
        filename: "changed.md",
      }),
      (error) => error.code === "IDEMPOTENCY_CONFLICT",
    );
  });

  await t.test("serializable concurrency permits one publisher", async () => {
    await parsed(catalog, ctx, "pg-concurrent");
    const results = await Promise.allSettled([
      catalog.publish(ctx, {
        ...command("publish-a", "pg-concurrent", 1, 3),
        metadata: metadata("pg-concurrent", "2026.1"),
      }),
      catalog.publish(ctx, {
        ...command("publish-b", "pg-concurrent", 1, 3),
        metadata: metadata("pg-concurrent", "2026.2"),
      }),
    ]);
    assert.equal(
      results.filter((result) => result.status === "fulfilled").length,
      1,
    );
    assert.equal(
      results.filter(
        (result) =>
          result.status === "rejected" &&
          result.reason.code === "VERSION_CONFLICT",
      ).length,
      1,
    );
  });

  await t.test("withdrawal and deletion propagate to every Chunk and as-of view", async () => {
    await parsed(catalog, ctx, "pg-lifecycle");
    await catalog.publish(ctx, {
      ...command("publish", "pg-lifecycle", 1, 3),
      metadata: metadata("pg-lifecycle"),
    });
    const beforeWithdrawal = "2026-07-26T08:12:30.000Z";
    const before = await catalog.readAsOf(ctx, {
      documentId: "pg-lifecycle",
      asOf: beforeWithdrawal,
    });
    assert.equal(before?.state, "PUBLISHED");
    const withdrawn = await catalog.withdraw(
      ctx,
      command("withdraw", "pg-lifecycle", 1, 4),
    );
    assert.equal(
      withdrawn.document.nodes.every(
        (node) => node.availabilityState === "WITHDRAWN",
      ),
      true,
    );
    assert.equal(
      await catalog.readAsOf(ctx, {
        documentId: "pg-lifecycle",
        asOf: "2026-07-26T12:00:00.000Z",
      }),
      null,
    );
    const deleted = await catalog.delete(
      ctx,
      command("delete", "pg-lifecycle", 1, 5),
    );
    assert.equal(
      deleted.document.nodes.every(
        (node) =>
          node.availabilityState === "DELETED" &&
          node.deletedAt === deleted.document.deletedAt,
      ),
      true,
    );
  });

  await t.test("database rejects physical deletion and provenance rewriting", async () => {
    await assert.rejects(
      runRawScoped(
        runtimePool,
        scopePool,
        scope(TENANT_A),
        (client) =>
          client.query(
            `DELETE FROM aios_knowledge.knowledge_document
              WHERE tenant_id=$1 AND document_id='pg-guide'`,
            [TENANT_A],
          ),
      ),
      (error) => error.code === "42501",
    );
    await assert.rejects(
      runRawScoped(
        runtimePool,
        scopePool,
        scope(TENANT_A),
        (client) =>
          client.query(
            `UPDATE aios_knowledge.source_node
                SET text_sha256=$2
              WHERE tenant_id=$1
                AND document_id='pg-guide'
                AND node_type='CHUNK'`,
            [
              TENANT_A,
              "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
          ),
      ),
      (error) =>
        error.code === "23000" &&
        error.constraint === "knowledge_source_immutable_guard",
    );
    await assert.rejects(
      runRawScoped(
        runtimePool,
        scopePool,
        scope(TENANT_A),
        (client) =>
          client.query(
            `UPDATE aios_knowledge.source_node
                SET availability_state='CANDIDATE'
              WHERE tenant_id=$1
                AND document_id='pg-guide'`,
            [TENANT_A],
          ),
      ),
      (error) =>
        error.code === "23000" &&
        error.constraint === "knowledge_source_document_pair_guard",
    );
  });

  await t.test("public and reader logins cannot mutate the catalog", async () => {
    await assert.rejects(
      publicPool.query(
        "SELECT * FROM aios_knowledge.knowledge_document LIMIT 1",
      ),
      (error) => error.code === "42501",
    );
    await assert.rejects(
      readerPool.query(
        `DELETE FROM aios_knowledge.knowledge_document
          WHERE document_id='pg-guide'`,
      ),
      (error) => error.code === "42501",
    );
  });
});
