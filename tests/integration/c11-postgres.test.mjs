import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
import {
  createC11SyntheticBenchmark,
  createC11SyntheticPrincipalResolver,
  createPermissionAwareRag,
} from "../../lib/permission-aware-rag.mjs";
import {
  createPostgresPermissionAwareRagStore,
} from "../../lib/postgres-permission-aware-rag-store.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c10/postgresql/0017_knowledge_catalog.sql",
    "../../implementation/p1/c10/postgresql/0018_knowledge_catalog_runtime_roles.sql",
    "../../implementation/p1/c11/postgresql/0025_permission_aware_rag.sql",
    "../../implementation/p1/c11/postgresql/0026_permission_aware_rag_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);
const c10Benchmark = createC10SyntheticBenchmark(
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
const c11Document = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c11/synthetic-rag-benchmark.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const c11Benchmark = createC11SyntheticBenchmark(c11Document);

const TENANT_A = "stn_01984910-7100-7000-8000-000000000001";
const TENANT_B = "stn_01984910-7100-7000-8000-000000000002";
const SALES = "prn_01984910-7000-7000-8000-000000000011";
const FINANCE = "prn_01984910-7000-7000-8000-000000000012";
const OUTSIDER = "prn_01984910-7000-7000-8000-000000000013";
const WORKLOAD = "prn_01984910-7100-7000-8000-000000000031";
const DELEGATION = "dlg_01984910-7100-7000-8000-000000000041";
const C10_RUNTIME_LOGIN = "c11_test_c10_runtime";
const C10_READER_LOGIN = "c11_test_c10_reader";
const C11_PROJECTOR_LOGIN = "c11_test_projector";
const C11_QUERY_LOGIN = "c11_test_query";
const SCOPE_LOGIN = "c11_test_scope";
const PUBLIC_LOGIN = "c11_test_public";
const AS_OF = "2026-07-26T12:00:00.000Z";

function config(user = process.env.C11_TEST_PGUSER, max = 30) {
  if (process.env.C11_TEST_EPHEMERAL !== "1") {
    throw new Error("C11_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C11_TEST_PGHOST",
    "C11_TEST_PGPORT",
    "C11_TEST_PGDATABASE",
    "C11_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C11_TEST_PGHOST,
    port: Number(process.env.C11_TEST_PGPORT),
    database: process.env.C11_TEST_PGDATABASE,
    user,
    max,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function context(
  tenantId = TENANT_A,
  sessionToken = "owner",
) {
  return {
    tenantScope: {
      trustSource: "C07_VERIFIED_TENANT_SCOPE",
      tenantId,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: 2,
      correlationId: `c11-${tenantId}`,
      decisionId: `c07-decision-${tenantId}`,
      evidenceRef: `evidence://c07/${tenantId}`,
      policyVersion: "c07-policy-v1",
    },
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
  const principals = {
    owner: SALES,
    sales: SALES,
    finance: FINANCE,
    outsider: OUTSIDER,
  };
  let index = 0;
  return {
    async enforce(serverContext, request, descriptor) {
      index += 1;
      const humanPrincipalId = principals[request.sessionToken];
      if (!humanPrincipalId) {
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
        humanPrincipalId,
        humanSecurityEpoch: 1,
        workloadActorPrincipalId: WORKLOAD,
        workloadActorSecurityEpoch: 1,
        leafDelegationId: DELEGATION,
        delegationChainSha256:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        purposeRef: "synthetic://c11/postgresql",
      };
    },
  };
}

function monotonicClock(start = "2026-07-26T08:00:00.000Z") {
  let milliseconds = Date.parse(start);
  return () => {
    const value = new Date(milliseconds).toISOString();
    milliseconds += 60_000;
    return value;
  };
}

function controllableClock(start) {
  let milliseconds = Date.parse(start);
  return {
    now() {
      const value = new Date(milliseconds).toISOString();
      milliseconds += 1;
      return value;
    },
    advance(duration) {
      milliseconds += duration;
    },
  };
}

function fixture(documentId) {
  const value = c11Document.documents.find(
    (candidate) => candidate.document_id === documentId,
  );
  assert.ok(value, `Missing C11 fixture ${documentId}.`);
  return value;
}

function publication(value) {
  return {
    ownerPrincipalId: value.publication.owner_principal_id,
    sourceRef: value.publication.source_ref,
    version: value.publication.version,
    validFrom: value.publication.valid_from,
    validUntil: value.publication.valid_until,
    classification: value.publication.classification,
    acl: structuredClone(value.publication.acl),
  };
}

function command(operation, documentId, expectedRevision) {
  return {
    idempotencyKey: `${operation}-${documentId}-${expectedRevision}`,
    documentId,
    documentVersion: 1,
    expectedRevision,
  };
}

async function prepareCatalogDocument(catalog, tenantContext, documentId) {
  const value = fixture(documentId);
  const markdown = value.fixture_ref.endsWith("clean-markdown");
  await catalog.upload(tenantContext, {
    idempotencyKey: `upload-${documentId}`,
    documentId,
    documentVersion: 1,
    expectedRevision: 0,
    fixtureRef: value.fixture_ref,
    filename: markdown ? `${documentId}.md` : `${documentId}.csv`,
    declaredMediaType: markdown ? "text/markdown" : "text/csv",
    sourceRef: `fixture://c11/${documentId}/source`,
  });
  await catalog.inspect(
    tenantContext,
    command("inspect", documentId, 1),
  );
  const parsed = await catalog.parse(
    tenantContext,
    command("parse", documentId, 2),
  );
  assert.equal(parsed.document.parseSha256, value.parse_sha256);
  const published = await catalog.publish(tenantContext, {
    ...command("publish", documentId, 3),
    metadata: publication(value),
  });
  return published.document;
}

function synchronize(rag, tenantContext, documentId, expected = 0) {
  return rag.synchronize(tenantContext, {
    idempotencyKey: `project-${documentId}-${expected}`,
    documentId,
    documentVersion: 1,
    expectedProjectionVersion: expected,
  });
}

function search(
  rag,
  token,
  query,
  requestId,
  tenantId = TENANT_A,
) {
  return rag.search(context(tenantId, token), {
    requestId,
    query,
    limit: 5,
  });
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
      `c11-${suffix}-creation`,
      `fixture://c11/${suffix}/tenant`,
      digest(`c11-${suffix}-origin`),
      `sns_01984910-7100-7000-8000-0000000000${suffix}`,
      `op_01984910-7100-7000-8000-0000000001${suffix}`,
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
      [tenantId, projection, `c11-${suffix}-${projection}`, time],
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
      `op_01984910-7100-7000-8000-0000000001${suffix}`,
      `c11-${suffix}-active`,
      "2026-07-26T07:01:00.000Z",
    ],
  );
}

test("C11 real PostgreSQL permission-aware RAG", async (t) => {
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
            to_regnamespace('aios_rag') AS rag_schema`,
  );
  assert.match(safety.rows[0].database, /^c11_test_[0-9]+$/);
  assert.equal(safety.rows[0].rag_schema, null);
  for (const migration of migrations) await adminPool.query(migration);
  await seedTenant(adminPool, TENANT_A, "01");
  await seedTenant(adminPool, TENANT_B, "02");
  for (const login of [
    C10_RUNTIME_LOGIN,
    C10_READER_LOGIN,
    C11_PROJECTOR_LOGIN,
    C11_QUERY_LOGIN,
    SCOPE_LOGIN,
    PUBLIC_LOGIN,
  ]) {
    await adminPool.query(`CREATE ROLE ${login} LOGIN`);
  }
  await adminPool.query(
    `GRANT aios_c10_runtime TO ${C10_RUNTIME_LOGIN};
     GRANT aios_c10_reader TO ${C10_READER_LOGIN};
     GRANT aios_c11_projector TO ${C11_PROJECTOR_LOGIN};
     GRANT aios_c11_query TO ${C11_QUERY_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};`,
  );

  const c10RuntimePool = pool(C10_RUNTIME_LOGIN, 30);
  const c10ReaderPool = pool(C10_READER_LOGIN, 20);
  const projectorPool = pool(C11_PROJECTOR_LOGIN, 30);
  const queryPool = pool(C11_QUERY_LOGIN, 30);
  const scopePool = pool(SCOPE_LOGIN, 40);
  const publicPool = pool(PUBLIC_LOGIN, 2);
  const c10Store = createPostgresKnowledgeCatalogStore({
    runtimePool: c10RuntimePool,
    readerPool: c10ReaderPool,
    scopePool,
  });
  const c06Authorizer = authorizer();
  const catalog = createKnowledgeCatalog({
    store: c10Store,
    c06Authorizer,
    benchmark: c10Benchmark,
    clock: monotonicClock(),
  });
  const c11Store = createPostgresPermissionAwareRagStore({
    projectorPool,
    queryPool,
    scopePool,
  });
  const ragTime = controllableClock(AS_OF);
  const rag = createPermissionAwareRag({
    store: c11Store,
    catalogReader: c10Store,
    c06Authorizer,
    principalResolver: createC11SyntheticPrincipalResolver({
      benchmark: c11Benchmark,
    }),
    benchmark: c11Benchmark,
    clock: () => ragTime.now(),
  });
  const ownerContext = context();

  await t.test("roles are least-privilege and every table FORCE RLS", async () => {
    const attributes = await adminPool.query(
      `SELECT rolname,rolsuper,rolcreatedb,rolcreaterole,rolcanlogin,
              rolinherit,rolreplication,rolbypassrls
         FROM pg_roles
        WHERE rolname=ANY($1::text[])
        ORDER BY rolname`,
      [["aios_c11_owner", "aios_c11_projector", "aios_c11_query"]],
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
        WHERE nspname='aios_rag'
          AND relkind='r'
        ORDER BY relname`,
    );
    assert.equal(rls.rows.length, 6);
    assert.equal(
      rls.rows.every((row) => row.relrowsecurity && row.relforcerowsecurity),
      true,
    );
    const privileges = await adminPool.query(
      `SELECT
         has_table_privilege(
           'aios_c11_projector','aios_rag.chunk_index','UPDATE'
         ) AS projector_update,
         has_table_privilege(
           'aios_c11_projector','aios_rag.query_audit','INSERT'
         ) AS projector_audit,
         has_table_privilege(
           'aios_c11_query','aios_rag.chunk_index','UPDATE'
         ) AS query_index_update,
         has_table_privilege(
           'aios_c11_query','aios_rag.retrieval_cache','INSERT'
         ) AS query_cache_insert,
         has_table_privilege(
           'aios_c11_query','aios_rag.query_audit','SELECT'
         ) AS query_audit_select`,
    );
    assert.deepEqual(privileges.rows[0], {
      projector_update: true,
      projector_audit: false,
      query_index_update: false,
      query_cache_insert: true,
      query_audit_select: false,
    });
    await assert.rejects(
      publicPool.query("SELECT * FROM aios_rag.document_projection"),
      (error) => error.code === "42501",
    );
  });

  await t.test("unsafe role closure, attributes, and grants fail closed", async (roleTest) => {
    const cases = [
      {
        name: "required role with admin option",
        login: "c11_bad_admin_option",
        grants: [
          "GRANT aios_c11_query TO c11_bad_admin_option WITH ADMIN OPTION",
        ],
      },
      {
        name: "mixed owner",
        login: "c11_bad_owner",
        grants: [
          "GRANT aios_c11_query TO c11_bad_owner",
          "GRANT aios_c11_owner TO c11_bad_owner",
        ],
      },
      {
        name: "adjacent runtime",
        login: "c11_bad_runtime",
        grants: [
          "GRANT aios_c11_query TO c11_bad_runtime",
          "GRANT aios_c10_runtime TO c11_bad_runtime",
        ],
      },
      {
        name: "indirect role",
        login: "c11_bad_indirect",
        setup: [
          "CREATE ROLE aios_c11_test_bridge NOLOGIN",
          "GRANT aios_c11_query TO aios_c11_test_bridge",
        ],
        grants: [
          "GRANT aios_c11_test_bridge TO c11_bad_indirect",
        ],
      },
      {
        name: "built-in read-all role",
        login: "c11_bad_read_all",
        grants: [
          "GRANT aios_c11_query TO c11_bad_read_all",
          "GRANT pg_read_all_data TO c11_bad_read_all",
        ],
      },
      {
        name: "direct table grant",
        login: "c11_bad_direct",
        grants: [
          "GRANT aios_c11_query TO c11_bad_direct",
          "GRANT SELECT ON aios_data.runtime_scope_signing_secret TO c11_bad_direct",
        ],
      },
      {
        name: "direct adjacent schema table and function grants",
        login: "c11_bad_adjacent_direct",
        setup: [
          "CREATE SCHEMA aios_c11_adjacent_test",
          "CREATE TABLE aios_c11_adjacent_test.private_record (id integer)",
          "CREATE FUNCTION aios_c11_adjacent_test.private_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
          "REVOKE ALL ON SCHEMA aios_c11_adjacent_test FROM PUBLIC",
          "REVOKE ALL ON ALL TABLES IN SCHEMA aios_c11_adjacent_test FROM PUBLIC",
          "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA aios_c11_adjacent_test FROM PUBLIC",
        ],
        grants: [
          "GRANT aios_c11_query TO c11_bad_adjacent_direct",
          "GRANT USAGE ON SCHEMA aios_c11_adjacent_test TO c11_bad_adjacent_direct",
          "GRANT SELECT ON aios_c11_adjacent_test.private_record TO c11_bad_adjacent_direct",
          "GRANT EXECUTE ON FUNCTION aios_c11_adjacent_test.private_function() TO c11_bad_adjacent_direct",
        ],
      },
      {
        name: "CREATEDB",
        login: "c11_bad_createdb",
        attributes: "CREATEDB",
        grants: ["GRANT aios_c11_query TO c11_bad_createdb"],
      },
      {
        name: "CREATEROLE",
        login: "c11_bad_createrole",
        attributes: "CREATEROLE",
        grants: ["GRANT aios_c11_query TO c11_bad_createrole"],
      },
      {
        name: "REPLICATION",
        login: "c11_bad_replication",
        attributes: "REPLICATION",
        grants: ["GRANT aios_c11_query TO c11_bad_replication"],
      },
      {
        name: "SUPERUSER",
        login: "c11_bad_superuser",
        attributes: "SUPERUSER",
        grants: ["GRANT aios_c11_query TO c11_bad_superuser"],
      },
      {
        name: "BYPASSRLS",
        login: "c11_bad_bypassrls",
        attributes: "BYPASSRLS",
        grants: ["GRANT aios_c11_query TO c11_bad_bypassrls"],
      },
    ];

    for (const entry of cases) {
      await roleTest.test(entry.name, async () => {
        for (const statement of entry.setup ?? []) {
          await adminPool.query(statement);
        }
        await adminPool.query(
          `CREATE ROLE ${entry.login} LOGIN ${entry.attributes ?? ""}`,
        );
        for (const statement of entry.grants) {
          await adminPool.query(statement);
        }
        const unsafeQueryPool = pool(entry.login, 1);
        const unsafeStore = createPostgresPermissionAwareRagStore({
          projectorPool,
          queryPool: unsafeQueryPool,
          scopePool,
        });
        await assert.rejects(
          unsafeStore.readCache(
            ownerContext.tenantScope,
            {
              asOf: AS_OF,
              principalScopeHash: digest("unsafe-principal-scope"),
            },
            digest(entry.login),
          ),
          (error) => error.code === "INVALID_CONFIGURATION",
        );
      });
    }
  });

  await t.test("a missing required privilege fails closed", async () => {
    await adminPool.query(
      "REVOKE SELECT ON aios_knowledge.source_node FROM aios_c11_query",
    );
    try {
      await assert.rejects(
        c11Store.readCache(
          ownerContext.tenantScope,
          {
            asOf: AS_OF,
            principalScopeHash: digest("missing-privilege-scope"),
          },
          digest("missing-privilege"),
        ),
        (error) => error.code === "INVALID_CONFIGURATION",
      );
    } finally {
      await adminPool.query(
        "GRANT SELECT ON aios_knowledge.source_node TO aios_c11_query",
      );
    }
  });

  await t.test("exact projector and scope role matrices project C10 provenance", async () => {
    await prepareCatalogDocument(catalog, ownerContext, "sales-guide");
    await prepareCatalogDocument(catalog, ownerContext, "finance-register");
    const sales = await synchronize(
      rag,
      ownerContext,
      "sales-guide",
    );
    const finance = await synchronize(
      rag,
      ownerContext,
      "finance-register",
    );
    assert.equal(sales.activeChunkCount, 4);
    assert.equal(finance.activeChunkCount, 3);
    const rows = await adminPool.query(
      `SELECT document_id,count(*)::int AS chunks
         FROM aios_rag.chunk_index
        WHERE active
        GROUP BY document_id
        ORDER BY document_id`,
    );
    assert.deepEqual(rows.rows, [
      { document_id: "finance-register", chunks: 3 },
      { document_id: "sales-guide", chunks: 4 },
    ]);
    const hashGuard = await adminPool.query(
      `SELECT bool_and(
         text_sha256 =
         'sha256:' || encode(
           digest(convert_to(chunk_text,'UTF8'),'sha256'),
           'hex'
         )
       ) AS valid
       FROM aios_rag.chunk_index`,
    );
    assert.equal(hashGuard.rows[0].valid, true);
  });

  await t.test("exact query and scope role matrices enforce ACL and Tenant prefilters", async () => {
    const sales = await search(
      rag,
      "sales",
      "owner ACL publication",
      "pg-sales",
    );
    assert.equal(sales.status, "ANSWERABLE");
    assert.equal(sales.evidence[0].documentId, "sales-guide");
    assert.equal(sales.evidence[0].chunk.ordinal, 9);
    const finance = await search(
      rag,
      "finance",
      "alpha value",
      "pg-finance",
    );
    assert.equal(finance.status, "ANSWERABLE");
    assert.equal(finance.evidence[0].documentId, "finance-register");
    assert.equal(
      (
        await search(
          rag,
          "sales",
          "alpha value",
          "pg-sales-finance",
        )
      ).status,
      "REFUSED",
    );
    assert.equal(
      (
        await search(
          rag,
          "outsider",
          "owner ACL publication",
          "pg-outsider",
        )
      ).status,
      "REFUSED",
    );
    assert.equal(
      (
        await search(
          rag,
          "sales",
          "owner ACL publication",
          "pg-tenant-b",
          TENANT_B,
        )
      ).status,
      "REFUSED",
    );
    const persisted = await adminPool.query(
      `SELECT count(*)::int AS count
         FROM aios_rag.document_projection
        WHERE tenant_id=$1`,
      [TENANT_B],
    );
    assert.equal(persisted.rows[0].count, 0);
  });

  await t.test("real PostgreSQL keeps UPLOAD_PENDING material unreadable", async () => {
    const pendingFixture = fixture("sales-guide");
    const pendingAt = "2026-07-26T09:00:00.000Z";
    const quarantineRef =
      `quarantine://c10/${TENANT_B}/sales-guide/1/` +
      pendingFixture.content_sha256.slice(7);
    await adminPool.query(
      `INSERT INTO aios_knowledge.knowledge_document (
         tenant_id,tenant_kind,document_id,document_version,revision,
         state,fixture_ref,source_ref,filename,declared_media_type,
         content_sha256,content_size,quarantine_ref,
         authorization_evidence,created_at,updated_at
       ) VALUES (
         $1,'SYNTHETIC','sales-guide',1,1,'UPLOAD_PENDING',$2,$3,
         'sales-guide.md','text/markdown',$4,1,$5,'{}'::jsonb,$6,$6
       )`,
      [
        TENANT_B,
        pendingFixture.fixture_ref,
        "fixture://c11/tenant-b/pending-source",
        pendingFixture.content_sha256,
        quarantineRef,
        pendingAt,
      ],
    );
    const tenantBContext = context(TENANT_B, "owner");
    const pending = await synchronize(
      rag,
      tenantBContext,
      "sales-guide",
    );
    assert.equal(pending.projection.state, "UPLOAD_PENDING");
    assert.equal(pending.activeChunkCount, 0);
    const chunks = await adminPool.query(
      `SELECT count(*)::int AS count
         FROM aios_rag.chunk_index
        WHERE tenant_id=$1
          AND document_id='sales-guide'`,
      [TENANT_B],
    );
    assert.equal(chunks.rows[0].count, 0);
    const result = await search(
      rag,
      "owner",
      "owner ACL publication",
      "pg-upload-pending",
      TENANT_B,
    );
    assert.equal(result.status, "REFUSED");
    assert.deepEqual(result.modelContext, []);
    assert.deepEqual(result.evidence, []);
  });

  await t.test("cache has stable keys, a short TTL, and no body audit", async () => {
    const first = await search(
      rag,
      "sales",
      "owner ACL",
      "pg-cache-one",
    );
    const second = await search(
      rag,
      "sales",
      "owner ACL",
      "pg-cache-two",
    );
    assert.equal(first.cacheHit, false);
    assert.equal(second.cacheHit, true);
    ragTime.advance(31_000);
    const expired = await search(
      rag,
      "sales",
      "owner ACL",
      "pg-cache-expired",
    );
    assert.equal(expired.cacheHit, false);
    const emptyFirst = await search(
      rag,
      "outsider",
      "owner ACL",
      "pg-empty-cache-one",
    );
    const emptySecond = await search(
      rag,
      "outsider",
      "owner ACL",
      "pg-empty-cache-two",
    );
    assert.equal(emptyFirst.status, "REFUSED");
    assert.equal(emptyFirst.cacheHit, false);
    assert.equal(emptySecond.cacheHit, true);
    ragTime.advance(31_000);
    const emptyExpired = await search(
      rag,
      "outsider",
      "owner ACL",
      "pg-empty-cache-expired",
    );
    assert.equal(emptyExpired.cacheHit, false);
    const caches = await adminPool.query(
      `SELECT count(*)::int AS count,
              count(*) FILTER (
                WHERE expires_at <= $2::timestamptz
              )::int AS expired
         FROM aios_rag.retrieval_cache
        WHERE tenant_id=$1`,
      [TENANT_A, ragTime.now()],
    );
    assert.deepEqual(caches.rows[0], { count: 1, expired: 0 });
    const replay = await synchronize(
      rag,
      ownerContext,
      "sales-guide",
    );
    assert.equal(replay.replayed, true);
    const bodyColumns = await adminPool.query(
      `SELECT column_name
         FROM information_schema.columns
        WHERE table_schema='aios_rag'
          AND table_name='query_audit'
          AND column_name=ANY($1::text[])`,
      [["query", "text", "context", "answer", "body"]],
    );
    assert.equal(bodyColumns.rowCount, 0);
    const audits = await adminPool.query(
      `SELECT query_hash,request_id_hash
         FROM aios_rag.query_audit
        ORDER BY audit_id`,
    );
    assert.ok(audits.rowCount >= 2);
    assert.ok(
      audits.rows.every(
        (row) =>
          /^sha256:[0-9a-f]{64}$/.test(row.query_hash) &&
          /^sha256:[0-9a-f]{64}$/.test(row.request_id_hash),
      ),
    );
  });

  await t.test("serializable projection admits one concurrent writer", async () => {
    await prepareCatalogDocument(catalog, ownerContext, "draft-guide");
    const settled = await Promise.allSettled([
      rag.synchronize(ownerContext, {
        idempotencyKey: "pg-concurrent-a",
        documentId: "draft-guide",
        documentVersion: 1,
        expectedProjectionVersion: 0,
      }),
      rag.synchronize(ownerContext, {
        idempotencyKey: "pg-concurrent-b",
        documentId: "draft-guide",
        documentVersion: 1,
        expectedProjectionVersion: 0,
      }),
    ]);
    assert.equal(
      settled.filter((result) => result.status === "fulfilled").length,
      1,
    );
    assert.equal(
      settled.find((result) => result.status === "rejected").reason.code,
      "VERSION_CONFLICT",
    );
    assert.equal(
      (
        await search(
          rag,
          "sales",
          "synthetic records",
          "pg-expired",
        )
      ).evidence.some(
        (evidence) => evidence.documentId === "draft-guide",
      ),
      false,
    );
  });

  await t.test("DELETE_PENDING immediately deactivates indexed chunks", async () => {
    const pendingAt = "2026-07-27T12:00:00.000Z";
    const pendingClient = await adminPool.connect();
    try {
      await pendingClient.query("BEGIN");
      await pendingClient.query(
        `UPDATE aios_knowledge.knowledge_document
            SET state='DELETE_PENDING',updated_at=$4
          WHERE tenant_id=$1
            AND document_id=$2
            AND document_version=$3`,
        [TENANT_A, "draft-guide", 1, pendingAt],
      );
      await pendingClient.query(
        `UPDATE aios_knowledge.source_node
            SET availability_state='DELETE_PENDING'
          WHERE tenant_id=$1
            AND document_id=$2
            AND document_version=$3`,
        [TENANT_A, "draft-guide", 1],
      );
      await pendingClient.query("COMMIT");
    } catch (error) {
      await pendingClient.query("ROLLBACK");
      throw error;
    } finally {
      pendingClient.release();
    }
    const pending = await synchronize(
      rag,
      ownerContext,
      "draft-guide",
      1,
    );
    assert.equal(pending.projection.state, "DELETE_PENDING");
    assert.equal(pending.activeChunkCount, 0);
    assert.ok(pending.invalidatedCacheCount >= 1);
    const chunks = await adminPool.query(
      `SELECT active,state
         FROM aios_rag.chunk_index
        WHERE tenant_id=$1
          AND document_id='draft-guide'`,
      [TENANT_A],
    );
    assert.ok(
      chunks.rows.every(
        ({ active, state }) =>
          active === false && state === "DELETE_PENDING",
      ),
    );
  });

  await t.test("withdrawal and deletion deactivate index and cache atomically", async () => {
    let signalWrite;
    let resumeWrite;
    const writeStarted = new Promise((resolve) => {
      signalWrite = resolve;
    });
    const writeMayResume = new Promise((resolve) => {
      resumeWrite = resolve;
    });
    const delayedStore = {
      ...c11Store,
      async writeCache(...args) {
        signalWrite();
        await writeMayResume;
        return c11Store.writeCache(...args);
      },
    };
    const delayedRag = createPermissionAwareRag({
      store: delayedStore,
      catalogReader: c10Store,
      c06Authorizer,
      principalResolver: createC11SyntheticPrincipalResolver({
        benchmark: c11Benchmark,
      }),
      benchmark: c11Benchmark,
      clock: () => ragTime.now(),
    });
    const inFlight = search(
      delayedRag,
      "sales",
      "Every publication needs",
      "pg-epoch-race",
    );
    await writeStarted;
    await catalog.withdraw(
      ownerContext,
      command("withdraw", "sales-guide", 4),
    );
    const beforeProjectionSync = await search(
      rag,
      "sales",
      "owner ACL publication",
      "pg-before-projection-sync",
    );
    assert.equal(beforeProjectionSync.status, "REFUSED");
    assert.equal(beforeProjectionSync.cacheHit, false);
    const withdrawn = await synchronize(
      rag,
      ownerContext,
      "sales-guide",
      1,
    );
    resumeWrite();
    assert.equal((await inFlight).status, "REFUSED");
    assert.equal(withdrawn.projection.state, "WITHDRAWN");
    assert.equal(withdrawn.activeChunkCount, 0);
    assert.ok(withdrawn.invalidatedCacheCount >= 1);
    assert.equal(
      (
        await search(
          rag,
          "sales",
          "owner ACL publication",
          "pg-after-withdraw",
        )
      ).status,
      "REFUSED",
    );

    await prepareCatalogDocument(
      catalog,
      ownerContext,
      "withdrawn-guide",
    );
    await synchronize(rag, ownerContext, "withdrawn-guide");
    await search(
      rag,
      "sales",
      "owner ACL publication",
      "pg-before-delete",
    );
    await catalog.delete(
      ownerContext,
      command("delete", "withdrawn-guide", 4),
    );
    const deleted = await synchronize(
      rag,
      ownerContext,
      "withdrawn-guide",
      1,
    );
    assert.equal(deleted.projection.state, "DELETED");
    assert.equal(deleted.activeChunkCount, 0);
    const state = await adminPool.query(
      `SELECT active,state
         FROM aios_rag.chunk_index
        WHERE document_id='withdrawn-guide'`,
    );
    assert.ok(
      state.rows.every(
        (row) => row.active === false && row.state === "DELETED",
      ),
    );
  });

  await t.test("a new store instance recovers durable retrieval state", async () => {
    const recoveredStore = createPostgresPermissionAwareRagStore({
      projectorPool,
      queryPool,
      scopePool,
    });
    const recovered = createPermissionAwareRag({
      store: recoveredStore,
      catalogReader: c10Store,
      c06Authorizer: authorizer(),
      principalResolver: createC11SyntheticPrincipalResolver({
        benchmark: c11Benchmark,
      }),
      benchmark: c11Benchmark,
      clock: () => ragTime.now(),
    });
    const result = await search(
      recovered,
      "finance",
      "alpha value",
      "pg-recovered",
    );
    assert.equal(result.status, "ANSWERABLE");
    assert.equal(result.evidence[0].documentId, "finance-register");
  });
});
