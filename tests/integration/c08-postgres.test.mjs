import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import pg from "pg";
import {
  createAiosStateCore,
} from "../../lib/aios-state-core.mjs";
import {
  createPostgresAiosStateStore,
} from "../../lib/postgres-aios-state-store.mjs";
import {
  createC08C0MockToolReceipts,
  createFileC08MockReceiptStore,
} from "../../lib/c08-c0-mock-tool-receipts.mjs";
import {
  createC08SyntheticReferenceCatalog,
} from "../../lib/c08-synthetic-reference-catalog.mjs";
import {
  createC08OutboxWorker,
} from "../../lib/c08-outbox-worker.mjs";

const { Pool } = pg;
const migrations = await Promise.all(
  [
    "../../implementation/p1/c03/postgresql/0001_tenant_registry.sql",
    "../../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    "../../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    "../../implementation/p1/c08/postgresql/0013_aios_state_core.sql",
    "../../implementation/p1/c08/postgresql/0014_aios_state_runtime_roles.sql",
  ].map((path) => readFile(new URL(path, import.meta.url), "utf8")),
);
const REFERENCE_CATALOG_DOCUMENT = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c08/synthetic-reference-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const REFERENCE_CATALOG = createC08SyntheticReferenceCatalog(
  REFERENCE_CATALOG_DOCUMENT,
);
const AUTHORITY_VERSION_CHANGE = JSON.parse(
  await readFile(
    new URL(
      "../../implementation/p1/c08/synthetic-authority-version-change.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

const TENANTS = [
  {
    tenantId: "stn_018f0000-0000-7000-8000-000000000010",
    namespaceId: "sns_01984910-3000-7000-8000-000000000011",
    operationId: "op_01984910-3000-7000-8000-000000000021",
    fixtureId: "northstar",
  },
  {
    tenantId: "stn_01984910-3000-7000-8000-000000000002",
    namespaceId: "sns_01984910-3000-7000-8000-000000000012",
    operationId: "op_01984910-3000-7000-8000-000000000022",
    fixtureId: "cedar",
  },
  {
    tenantId: "stn_01984910-3000-7000-8000-000000000003",
    namespaceId: "sns_01984910-3000-7000-8000-000000000013",
    operationId: "op_01984910-3000-7000-8000-000000000023",
    fixtureId: "north",
  },
];
const RUNTIME_LOGIN = "c08_test_runtime_login";
const SCOPE_LOGIN = "c08_test_scope_login";
const OUTBOX_LOGIN = "c08_test_outbox_login";
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];
const COMMON = Object.freeze({
  caseId: "case-shared-three-tenant",
  threadId: "thread-shared-three-tenant",
  artifactId: "artifact-shared-input",
  runId: "run-shared-three-tenant",
  toolCallId: "tool-call-shared-three-tenant",
});
const HASH_A =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B =
  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C =
  "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D =
  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const HASH_E =
  "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const OUTBOX_FIELDS = [
  "eventId",
  "state",
  "leaseVersion",
  "workerId",
  "leaseExpiresAt",
  "lastErrorCode",
  "event",
  "createdAt",
  "availableAt",
  "publishedAt",
].sort();

function config(user = process.env.C08_TEST_PGUSER, max = 50) {
  if (process.env.C08_TEST_EPHEMERAL !== "1") {
    throw new Error("C08_TEST_EPHEMERAL=1 is required.");
  }
  for (const name of [
    "C08_TEST_PGHOST",
    "C08_TEST_PGPORT",
    "C08_TEST_PGDATABASE",
    "C08_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C08_TEST_PGHOST,
    port: Number(process.env.C08_TEST_PGPORT),
    database: process.env.C08_TEST_PGDATABASE,
    user,
    max,
  };
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string" ||
    typeof value === "number"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

function canonicalDigest(value) {
  return digest(canonicalize(value));
}

function authorityVersion(id) {
  const version = AUTHORITY_VERSION_CHANGE.versions.find(
    (candidate) => candidate.id === id,
  );
  assert.ok(version, `Missing Synthetic authority version ${id}.`);
  return version;
}

function referenceCatalogAtAuthorityVersion(id) {
  const version = authorityVersion(id);
  const document = structuredClone(REFERENCE_CATALOG_DOCUMENT);
  document.catalogVersion = version.catalogVersion;
  const tenant = document.tenants.find(
    ({ tenantId }) => tenantId === TENANTS[0].tenantId,
  );
  const entry = tenant.entries.find(
    ({ kind, ref }) =>
      kind === AUTHORITY_VERSION_CHANGE.sourceKind &&
      ref === AUTHORITY_VERSION_CHANGE.sourceRef,
  );
  assert.ok(entry, "Synthetic authority reference entry is missing.");
  Object.assign(entry, version.reference);
  return createC08SyntheticReferenceCatalog(document);
}

function scope(tenant, correlation = `c08-${tenant.fixtureId}`) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: tenant.tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 2,
    correlationId: correlation,
    decisionId: `decision-${tenant.fixtureId}`,
    evidenceRef: `evidence://c08/${tenant.fixtureId}`,
    policyVersion: "c08-synthetic-policy-v1",
  };
}

async function runRawScoped(
  runtimePool,
  scopePool,
  verifiedScope,
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
    const nonce = randomUUID();
    let signed;
    try {
      const result = await signer.query(
        `SELECT aios_data.issue_runtime_scope_signature(
           $1,$2,$3,$4,$5,$6,$7,$8,$9::xid8,15,$10::uuid
         ) AS signed_scope`,
        [
          verifiedScope.tenantId,
          verifiedScope.tenantKind,
          verifiedScope.lifecycleVersion,
          verifiedScope.correlationId,
          verifiedScope.decisionId,
          verifiedScope.evidenceRef,
          verifiedScope.policyVersion,
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
        verifiedScope.tenantId,
        verifiedScope.tenantKind,
        String(verifiedScope.lifecycleVersion),
        verifiedScope.correlationId,
        verifiedScope.decisionId,
        verifiedScope.evidenceRef,
        verifiedScope.policyVersion,
        String(backendPid),
        transactionId,
        String(signed.expires_epoch_ms),
        nonce,
        signed.signature,
      ],
    );
    const fence = await runtime.query(
      "SELECT aios_data.acquire_runtime_fence() AS acquired",
    );
    assert.equal(fence.rows[0].acquired, true);
    return await operation(runtime);
  } finally {
    if (started) await runtime.query("ROLLBACK").catch(() => {});
    runtime.release();
  }
}

function metadata(kind, suffix) {
  return {
    idempotencyKey: `${kind.toLowerCase()}-${suffix}`,
    requestHash: digest(`request-${kind}-${suffix}`),
    commandKind: kind,
    correlationId: `c08-command-${suffix}`,
  };
}

function domainEvent({
  tenant,
  eventId,
  aggregateType,
  aggregateId,
  aggregateVersion,
  time,
}) {
  return {
    eventId,
    aggregateType,
    aggregateId,
    aggregateVersion,
    createdAt: time,
    event: {
      specversion: "1.0",
      id: eventId,
      source: "/aios-state/core",
      type: `product.aios-state.${aggregateType.toLowerCase()}.changed.v1`,
      subject: aggregateId,
      time,
      datacontenttype: "application/json",
      tenantkind: "SYNTHETIC",
      synthetic: true,
      data: {
        tenant_id: tenant.tenantId,
        aggregate_id: aggregateId,
        aggregate_version: aggregateVersion,
      },
    },
  };
}

function loseFirstCommitAcknowledgement(pool) {
  let lost = false;
  return {
    wasLost() {
      return lost;
    },
    async connect() {
      const client = await pool.connect();
      return new Proxy(client, {
        get(target, property) {
          if (property === "query") {
            return async (...arguments_) => {
              const result = await target.query(...arguments_);
              const query = arguments_[0];
              const text =
                typeof query === "string" ? query : query?.text;
              if (!lost && text?.trim() === "COMMIT") {
                lost = true;
                const error = new Error(
                  "Synthetic COMMIT acknowledgement loss.",
                );
                error.code = "57P01";
                throw error;
              }
              return result;
            };
          }
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    },
  };
}

async function rejectAtCommit(pool, operation, constraint) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await operation(client);
    await assert.rejects(
      client.query("COMMIT"),
      (error) => error?.constraint === constraint,
    );
  } finally {
    await client.query("ROLLBACK");
    client.release();
  }
}

async function seedTenant(adminPool, tenant, index) {
  const createdAt = `2026-07-26T12:0${index}:00.000Z`;
  await adminPool.query(
    `INSERT INTO aios_core.tenant_registry (
       tenant_id, tenant_kind, state, lifecycle_version, generation,
       creation_key, origin_ref, origin_hash, config_refs,
       resource_namespace_id, operation_id, created_at, updated_at
     ) VALUES (
       $1, 'SYNTHETIC', 'PROVISIONING', 1, 1, $2, $3, $4,
       '[]'::jsonb, $5, $6, $7, $7
     )`,
    [
      tenant.tenantId,
      `c08-creation-${tenant.fixtureId}`,
      `fixture://c08/${tenant.fixtureId}`,
      digest(`origin-${tenant.fixtureId}`),
      tenant.namespaceId,
      tenant.operationId,
      createdAt,
    ],
  );
  for (const projection of PROJECTIONS) {
    await adminPool.query(
      `INSERT INTO aios_core.tenant_projection (
         tenant_id, generation, projection, desired_action, status,
         attempt_count, source_event_id, updated_at
       ) VALUES ($1,1,$2,'PROVISION','READY',1,$3,$4)`,
      [
        tenant.tenantId,
        projection,
        `c08-${tenant.fixtureId}-${projection.toLowerCase()}`,
        createdAt,
      ],
    );
  }
  await adminPool.query(
    `UPDATE aios_core.tenant_registry
        SET state='ACTIVE', lifecycle_version=2, updated_at=$2
      WHERE tenant_id=$1`,
    [tenant.tenantId, `2026-07-26T12:1${index}:00.000Z`],
  );
  await adminPool.query(
    `INSERT INTO aios_data.tenant_data_lifecycle (
       tenant_id, tenant_kind, lifecycle_version, generation,
       operation_id, state, last_event_id, updated_at
     ) VALUES ($1,'SYNTHETIC',2,1,$2,'ACTIVE',$3,$4)`,
    [
      tenant.tenantId,
      tenant.operationId,
      `c08-active-${tenant.fixtureId}`,
      `2026-07-26T12:1${index}:00.000Z`,
    ],
  );
}

async function createGraph(store, tenant, index) {
  const time = `2026-07-26T13:0${index}:00.000Z`;
  const event = domainEvent({
    tenant,
    eventId: "event-shared-graph-created",
    aggregateType: "TOOL_CALL",
    aggregateId: COMMON.toolCallId,
    aggregateVersion: 1,
    time,
  });
  return store.runCommand(
    scope(tenant),
    metadata("START_RUN", tenant.fixtureId),
    async (tx) => {
      await tx.insertCase({
        caseId: COMMON.caseId,
        tenantId: tenant.tenantId,
        tenantKind: "SYNTHETIC",
        state: "OPEN",
        version: 1,
        goalRef: `synthetic://c08/${tenant.fixtureId}/goal`,
        createdAt: time,
        updatedAt: time,
      });
      await tx.insertThread({
        threadId: COMMON.threadId,
        caseId: COMMON.caseId,
        state: "OPEN",
        version: 1,
        purposeRef: `synthetic://c08/${tenant.fixtureId}/purpose`,
        createdAt: time,
        updatedAt: time,
      });
      await tx.insertArtifact({
        artifactId: COMMON.artifactId,
        caseId: COMMON.caseId,
        threadId: COMMON.threadId,
        artifactVersion: 1,
        kind: "INPUT",
        contentRef: `synthetic://c08/${tenant.fixtureId}/input`,
        contentSha256: digest(`input-${tenant.fixtureId}`),
        createdAt: time,
      });
      await tx.insertRun({
        runId: COMMON.runId,
        caseId: COMMON.caseId,
        threadId: COMMON.threadId,
        state: "RUNNING",
        version: 1,
        baseManifest: { fixture: tenant.fixtureId, version: 1 },
        identity: { principal: `synthetic-${tenant.fixtureId}` },
        authorization: { decision: `allow-${tenant.fixtureId}` },
        tenantLifecycleVersion: 2,
        resultArtifact: null,
        reconstructionHash: null,
        createdAt: time,
        updatedAt: time,
      });
      await tx.insertToolCall({
        toolCallId: COMMON.toolCallId,
        runId: COMMON.runId,
        state: "PREPARED",
        version: 1,
        operationRef: "synthetic://c08/tool/echo",
        operationVersion: "v1",
        requestHash: digest(`tool-request-${tenant.fixtureId}`),
        effectKey: `effect_${digest(`tool-effect-${tenant.fixtureId}`).slice(7)}`,
        compensationRef: null,
        authorization: {
          decisionId: `tool-decision-${tenant.fixtureId}`,
          evidenceRef: `evidence://c08/tool/${tenant.fixtureId}`,
          policyVersion: "c08-tool-policy-v1",
        },
        receiptRef: null,
        receiptHash: null,
        outcome: null,
        createdAt: time,
        updatedAt: time,
      });
      await tx.appendEvent(event);
      await tx.appendOutbox(event);
      return { runId: COMMON.runId, fixture: tenant.fixtureId };
    },
  );
}

test("C08 PostgreSQL state core is atomic, isolated and retry-safe", async (t) => {
  const adminPool = new Pool(config());
  const runtimePool = new Pool(config(RUNTIME_LOGIN));
  const scopePool = new Pool(config(SCOPE_LOGIN));
  const outboxPool = new Pool(config(OUTBOX_LOGIN));
  const expectedPoolErrors = [];
  runtimePool.on("error", (error) => {
    expectedPoolErrors.push(error);
  });
  t.after(async () => {
    await Promise.all([
      runtimePool.end(),
      scopePool.end(),
      outboxPool.end(),
    ]);
    await adminPool.end();
  });

  const safety = await adminPool.query(
    `SELECT current_database() AS database,
            to_regnamespace('aios_state') AS state_schema`,
  );
  assert.match(safety.rows[0].database, /^c08_test_[0-9]+$/);
  assert.equal(safety.rows[0].state_schema, null);

  for (const migration of migrations) await adminPool.query(migration);
  await adminPool.query(`CREATE ROLE ${RUNTIME_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${SCOPE_LOGIN} LOGIN`);
  await adminPool.query(`CREATE ROLE ${OUTBOX_LOGIN} LOGIN`);
  await adminPool.query(
    `GRANT aios_c08_runtime TO ${RUNTIME_LOGIN};
     GRANT aios_c07_scope_runtime TO ${SCOPE_LOGIN};
     GRANT aios_c08_outbox_worker TO ${OUTBOX_LOGIN};`,
  );
  for (const [index, tenant] of TENANTS.entries()) {
    await seedTenant(adminPool, tenant, index);
  }

  const store = createPostgresAiosStateStore({
    runtimePool,
    scopePool,
    outboxPool,
  });

  await t.test("rollback removes partial state and partial evidence", async () => {
    const tenant = TENANTS[0];
    const time = "2026-07-26T12:30:00.000Z";
    await assert.rejects(
      store.runCommand(
        scope(tenant),
        metadata("CREATE_CASE", "forced-rollback"),
        async (tx) => {
          await tx.insertCase({
            caseId: "case-forced-rollback",
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            state: "OPEN",
            version: 1,
            goalRef: "synthetic://c08/rollback",
            createdAt: time,
            updatedAt: time,
          });
          throw new Error("synthetic reducer failure");
        },
      ),
      (error) => error?.code === "STORE_UNAVAILABLE",
    );

    const unpaired = domainEvent({
      tenant,
      eventId: "event-unpaired",
      aggregateType: "CASE",
      aggregateId: "case-unpaired",
      aggregateVersion: 1,
      time,
    });
    await assert.rejects(
      store.runCommand(
        scope(tenant),
        metadata("CREATE_CASE", "unpaired"),
        async (tx) => {
          await tx.insertCase({
            caseId: "case-unpaired",
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            state: "OPEN",
            version: 1,
            goalRef: "synthetic://c08/unpaired",
            createdAt: time,
            updatedAt: time,
          });
          await tx.appendEvent(unpaired);
          return { caseId: "case-unpaired" };
        },
      ),
      (error) => error?.code === "EVIDENCE_PAIR_INVALID",
    );

    const counts = await adminPool.query(
      `SELECT
         (SELECT count(*)::integer FROM aios_state.aios_case
           WHERE case_id IN ('case-forced-rollback','case-unpaired'))
           AS cases,
         (SELECT count(*)::integer FROM aios_state.domain_event
           WHERE event_id='event-unpaired') AS events,
         (SELECT count(*)::integer FROM aios_state.command_receipt
           WHERE idempotency_key IN (
             'create_case-forced-rollback','create_case-unpaired'
           )) AS receipts`,
    );
    assert.deepEqual(counts.rows[0], {
      cases: 0,
      events: 0,
      receipts: 0,
    });
  });

  await t.test("32 concurrent retries have one durable effect", async () => {
    const tenant = TENANTS[0];
    const time = "2026-07-26T12:40:00.000Z";
    const event = domainEvent({
      tenant,
      eventId: "event-idempotency-32",
      aggregateType: "CASE",
      aggregateId: "case-idempotency-32",
      aggregateVersion: 1,
      time,
    });
    const command = () =>
      store.runCommand(
        scope(tenant),
        metadata("CREATE_CASE", "parallel-32"),
        async (tx) => {
          await tx.insertCase({
            caseId: "case-idempotency-32",
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            state: "OPEN",
            version: 1,
            goalRef: "synthetic://c08/idempotency-32",
            createdAt: time,
            updatedAt: time,
          });
          await tx.appendEvent(event);
          await tx.appendOutbox(event);
          return { caseId: "case-idempotency-32" };
        },
      );
    const results = await Promise.all(
      Array.from({ length: 32 }, () => command()),
    );
    assert.equal(results.filter((result) => !result.duplicate).length, 1);
    assert.equal(results.filter((result) => result.duplicate).length, 31);
    assert.equal(
      results.every(
        (result) => result.value.caseId === "case-idempotency-32",
      ),
      true,
    );
    const counts = await adminPool.query(
      `SELECT
         (SELECT count(*)::integer FROM aios_state.aios_case
           WHERE case_id='case-idempotency-32') AS cases,
         (SELECT count(*)::integer FROM aios_state.domain_event
           WHERE event_id='event-idempotency-32') AS events,
         (SELECT count(*)::integer FROM aios_state.outbox
           WHERE event_id='event-idempotency-32') AS outbox,
         (SELECT count(*)::integer FROM aios_state.command_receipt
           WHERE idempotency_key='create_case-parallel-32') AS receipts`,
    );
    assert.deepEqual(counts.rows[0], {
      cases: 1,
      events: 1,
      outbox: 1,
      receipts: 1,
    });
  });

  await t.test(
    "same command replays under a new correlation ID",
    async () => {
      const tenant = TENANTS[0];
      const original = metadata("CREATE_CASE", "parallel-32");
      let reducerCalled = false;
      const replayed = await store.runCommand(
        scope(tenant, "c08-scope-replay-new-correlation"),
        {
          ...original,
          correlationId: "c08-command-replay-new-correlation",
        },
        async () => {
          reducerCalled = true;
          return { caseId: "should-not-run" };
        },
      );

      assert.equal(replayed.duplicate, true);
      assert.deepEqual(replayed.value, {
        caseId: "case-idempotency-32",
      });
      assert.equal(reducerCalled, false);
    },
  );

  await t.test(
    "deferred evidence guards reject orphan and mismatched rows at COMMIT",
    async () => {
      const tenant = TENANTS[0];
      const time = "2026-07-26T12:50:00.000Z";
      const insertReceipt = (
        client,
        { idempotencyKey, requestHash, effectKey },
      ) =>
        client.query(
          `INSERT INTO aios_state.command_receipt (
             tenant_id,tenant_kind,idempotency_key,request_hash,
             effect_key,command_kind,correlation_id,result
           ) VALUES ($1,'SYNTHETIC',$2,$3,$4,'CREATE_CASE',$5,$6::jsonb)`,
          [
            tenant.tenantId,
            idempotencyKey,
            requestHash,
            effectKey,
            `corr-${idempotencyKey}`,
            JSON.stringify({ idempotencyKey }),
          ],
        );
      const insertEvent = (
        client,
        { eventId, idempotencyKey, requestHash, effectKey },
      ) => {
        const record = domainEvent({
          tenant,
          eventId,
          aggregateType: "CASE",
          aggregateId: "case-idempotency-32",
          aggregateVersion: 1,
          time,
        });
        return client.query(
          `INSERT INTO aios_state.domain_event (
             tenant_id,tenant_kind,event_id,idempotency_key,request_hash,
             effect_key,aggregate_type,aggregate_id,aggregate_version,
             event,created_at
           ) VALUES (
             $1,'SYNTHETIC',$2,$3,$4,$5,'CASE',
             'case-idempotency-32',1,$6::jsonb,$7
           )`,
          [
            tenant.tenantId,
            eventId,
            idempotencyKey,
            requestHash,
            effectKey,
            JSON.stringify(record.event),
            time,
          ],
        );
      };
      const insertOutbox = (
        client,
        { eventId, idempotencyKey, requestHash, effectKey },
      ) => {
        const record = domainEvent({
          tenant,
          eventId,
          aggregateType: "CASE",
          aggregateId: "case-idempotency-32",
          aggregateVersion: 1,
          time,
        });
        return client.query(
          `INSERT INTO aios_state.outbox (
             tenant_id,tenant_kind,event_id,idempotency_key,request_hash,
             effect_key,event,created_at
           ) VALUES ($1,'SYNTHETIC',$2,$3,$4,$5,$6::jsonb,$7)`,
          [
            tenant.tenantId,
            eventId,
            idempotencyKey,
            requestHash,
            effectKey,
            JSON.stringify(record.event),
            time,
          ],
        );
      };

      const orphanEvent = {
        eventId: "event-guard-orphan-outbox",
        idempotencyKey: "guard-orphan-outbox",
        requestHash: digest("guard-orphan-outbox-request"),
        effectKey: digest("guard-orphan-outbox-effect"),
      };
      await rejectAtCommit(
        adminPool,
        async (client) => {
          await insertReceipt(client, orphanEvent);
          await insertEvent(client, orphanEvent);
        },
        "aios_state_event_outbox_pair_guard",
      );

      const orphanReceipt = {
        idempotencyKey: "guard-orphan-receipt",
        requestHash: digest("guard-orphan-receipt-request"),
        effectKey: digest("guard-orphan-receipt-effect"),
      };
      await rejectAtCommit(
        adminPool,
        (client) => insertReceipt(client, orphanReceipt),
        "aios_state_event_receipt_pair_guard",
      );

      const outboxMismatch = {
        eventId: "event-guard-outbox-mismatch",
        idempotencyKey: "guard-outbox-mismatch",
        requestHash: digest("guard-outbox-mismatch-request"),
        effectKey: digest("guard-outbox-mismatch-effect"),
      };
      await rejectAtCommit(
        adminPool,
        async (client) => {
          await insertReceipt(client, outboxMismatch);
          await insertEvent(client, outboxMismatch);
          await insertOutbox(client, {
            ...outboxMismatch,
            requestHash: digest("guard-outbox-mismatch-other-request"),
          });
        },
        "aios_state_event_outbox_pair_guard",
      );

      const receiptMismatch = {
        eventId: "event-guard-receipt-mismatch",
        idempotencyKey: "guard-receipt-mismatch",
        requestHash: digest("guard-receipt-mismatch-request"),
        effectKey: digest("guard-receipt-mismatch-effect"),
      };
      await rejectAtCommit(
        adminPool,
        async (client) => {
          await insertReceipt(client, receiptMismatch);
          const mismatchedEvent = {
            ...receiptMismatch,
            requestHash: digest("guard-receipt-mismatch-other-request"),
            effectKey: digest("guard-receipt-mismatch-other-effect"),
          };
          await insertEvent(client, mismatchedEvent);
          await insertOutbox(client, mismatchedEvent);
        },
        "aios_state_event_receipt_pair_guard",
      );

      const leaked = await adminPool.query(
        `SELECT
           (SELECT count(*)::integer FROM aios_state.command_receipt
             WHERE idempotency_key LIKE 'guard-%') AS receipts,
           (SELECT count(*)::integer FROM aios_state.domain_event
             WHERE event_id LIKE 'event-guard-%') AS events,
           (SELECT count(*)::integer FROM aios_state.outbox
             WHERE event_id LIKE 'event-guard-%') AS outbox`,
      );
      assert.deepEqual(leaked.rows[0], {
        receipts: 0,
        events: 0,
        outbox: 0,
      });
    },
  );

  await t.test("three Synthetic Tenants retain directed isolation", async () => {
    const results = await Promise.all(
      TENANTS.map((tenant, index) => createGraph(store, tenant, index)),
    );
    assert.equal(results.every((result) => !result.duplicate), true);

    for (const tenant of TENANTS) {
      const run = await store.readRun(scope(tenant), {
        runId: COMMON.runId,
      });
      assert.equal(run.run.baseManifest.fixture, tenant.fixtureId);
      const snapshot = await store.readTenantSnapshot(scope(tenant));
      assert.equal(snapshot.counts.cases >= 1, true);
      assert.equal(snapshot.counts.threads, 1);
      assert.equal(snapshot.counts.artifacts, 1);
      assert.equal(snapshot.counts.runs, 1);
      assert.equal(snapshot.counts.toolCalls, 1);
      assert.deepEqual(snapshot.runStates, { RUNNING: 1 });
      assert.deepEqual(snapshot.toolCallStates, { PREPARED: 1 });
    }

    const directed = await adminPool.query(
      `SELECT count(*)::integer AS count
         FROM aios_state.aios_run
        WHERE run_id=$1`,
      [COMMON.runId],
    );
    assert.equal(directed.rows[0].count, 3);
  });

  await t.test(
    "Artifact chain guard does not reveal cross-Tenant identifiers",
    async () => {
      const tenantA = TENANTS[0];
      const tenantB = TENANTS[1];
      const existingId = "artifact-sidechannel-existing";
      await adminPool.query(
        `INSERT INTO aios_state.aios_artifact (
           tenant_id,tenant_kind,artifact_id,case_id,thread_id,
           artifact_version,kind,content_ref,content_sha256,created_at
         ) VALUES (
           $1,'SYNTHETIC',$2,$3,$4,1,'INPUT',$5,$6,$7
         )`,
        [
          tenantB.tenantId,
          existingId,
          COMMON.caseId,
          COMMON.threadId,
          "synthetic://c08/sidechannel/existing",
          digest("sidechannel-existing"),
          "2026-07-26T13:15:00.000Z",
        ],
      );

      const attempt = async (artifactId) => {
        try {
          await runRawScoped(
            runtimePool,
            scopePool,
            scope(tenantA, `artifact-probe-${artifactId}`),
            (client) =>
              client.query(
                `INSERT INTO aios_state.aios_artifact (
                   tenant_id,tenant_kind,artifact_id,case_id,thread_id,
                   artifact_version,kind,content_ref,content_sha256,created_at
                 ) VALUES (
                   $1,'SYNTHETIC',$2,$3,$4,1,'INPUT',$5,$6,$7
                 )`,
                [
                  tenantB.tenantId,
                  artifactId,
                  COMMON.caseId,
                  COMMON.threadId,
                  "synthetic://c08/sidechannel/probe",
                  digest("sidechannel-probe"),
                  "2026-07-26T13:16:00.000Z",
                ],
              ),
          );
          return null;
        } catch (error) {
          return {
            code: error?.code ?? null,
            constraint: error?.constraint ?? null,
            table: error?.table ?? null,
            message: error?.message ?? null,
          };
        }
      };

      const existing = await attempt(existingId);
      const absent = await attempt("artifact-sidechannel-absent");
      assert.deepEqual(existing, absent);
      assert.equal(existing.code, "42501");
      assert.equal(existing.constraint, null);
    },
  );

  await t.test(
    "a valid runtime scope cannot update Case or Thread directly",
    async () => {
      const tenant = TENANTS[0];
      for (const [tableName, idColumn, id] of [
        ["aios_case", "case_id", COMMON.caseId],
        ["aios_thread", "thread_id", COMMON.threadId],
      ]) {
        await assert.rejects(
          runRawScoped(
            runtimePool,
            scopePool,
            scope(tenant, `direct-update-${tableName}`),
            (client) =>
              client.query(
                `UPDATE aios_state.${tableName}
                    SET state='CLOSED',version=version+1
                  WHERE tenant_id=$1 AND ${idColumn}=$2`,
                [tenant.tenantId, id],
              ),
          ),
          (error) => error?.code === "42501",
        );
      }
    },
  );

  await t.test("ToolCall and Run use version CAS and immutable refs", async () => {
    const tenant = TENANTS[0];
    const toolTime = "2026-07-26T13:20:00.000Z";
    const toolEvent = domainEvent({
      tenant,
      eventId: "event-tool-call-succeeded",
      aggregateType: "TOOL_CALL",
      aggregateId: COMMON.toolCallId,
      aggregateVersion: 2,
      time: toolTime,
    });
    const toolResult = await store.runCommand(
      scope(tenant),
      metadata("RECORD_TOOL_CALL_RESULT", "blue"),
      async (tx) => {
        const current = await tx.findToolCall(COMMON.toolCallId);
        const updated = await tx.updateToolCall(
          {
            ...current,
            state: "SUCCEEDED",
            version: 2,
            receiptRef: "synthetic://c08/receipt/blue",
            receiptHash: digest("receipt-blue"),
            outcome: "SUCCEEDED",
            updatedAt: toolTime,
          },
          1,
        );
        await tx.appendEvent(toolEvent);
        await tx.appendOutbox(toolEvent);
        return { toolCallId: updated.toolCallId, version: updated.version };
      },
    );
    assert.deepEqual(toolResult.value, {
      toolCallId: COMMON.toolCallId,
      version: 2,
    });

    const finishTime = "2026-07-26T13:30:00.000Z";
    const runEvent = domainEvent({
      tenant,
      eventId: "event-run-succeeded",
      aggregateType: "RUN",
      aggregateId: COMMON.runId,
      aggregateVersion: 2,
      time: finishTime,
    });
    const resultArtifact = {
      artifactId: "artifact-blue-result",
      artifactVersion: 1,
      contentSha256: digest("result-blue"),
    };
    const finished = await store.runCommand(
      scope(tenant),
      metadata("FINISH_RUN", "blue"),
      async (tx) => {
        const calls = await tx.listToolCallsByRun(COMMON.runId);
        assert.equal(calls.every((call) => call.state === "SUCCEEDED"), true);
        await tx.insertArtifact({
          artifactId: resultArtifact.artifactId,
          caseId: COMMON.caseId,
          threadId: COMMON.threadId,
          artifactVersion: 1,
          kind: "RESULT",
          contentRef: "synthetic://c08/result/blue",
          contentSha256: resultArtifact.contentSha256,
          createdAt: finishTime,
        });
        const current = await tx.findRun(COMMON.runId);
        const updated = await tx.updateRun(
          {
            ...current,
            state: "SUCCEEDED",
            version: 2,
            resultArtifact,
            reconstructionHash: digest("reconstruction-blue"),
            updatedAt: finishTime,
          },
          1,
        );
        await tx.appendEvent(runEvent);
        await tx.appendOutbox(runEvent);
        return { runId: updated.runId, version: updated.version };
      },
    );
    assert.deepEqual(finished.value, { runId: COMMON.runId, version: 2 });
    const stored = await store.readRun(scope(tenant), {
      runId: COMMON.runId,
    });
    assert.equal(stored.run.state, "SUCCEEDED");
    assert.deepEqual(stored.run.resultArtifact, resultArtifact);
    assert.equal(stored.resultArtifact.artifactId, "artifact-blue-result");

    await assert.rejects(
      store.runCommand(
        scope(tenant),
        metadata("FINISH_RUN", "stale-blue"),
        async (tx) => {
          const current = await tx.findRun(COMMON.runId);
          await tx.updateRun({ ...current, version: 2 }, 1);
          return { runId: COMMON.runId };
        },
      ),
      (error) => error?.code === "VERSION_CONFLICT",
    );
  });

  await t.test("backend termination rolls back and retries the command", async () => {
    await adminPool.query(
      `CREATE SEQUENCE c08_termination_once;
       CREATE FUNCTION public.c08_sleep_first_insert()
       RETURNS trigger
       LANGUAGE plpgsql
       SECURITY DEFINER
       SET search_path=pg_catalog
       AS $$
       BEGIN
         IF nextval('public.c08_termination_once') = 1 THEN
           PERFORM pg_sleep(30);
         END IF;
         RETURN NEW;
       END
       $$;
       CREATE TRIGGER c08_sleep_first_insert
       BEFORE INSERT ON aios_state.aios_case
       FOR EACH ROW
       WHEN (NEW.case_id = 'case-backend-termination')
       EXECUTE FUNCTION public.c08_sleep_first_insert();`,
    );
    const tenant = TENANTS[1];
    const time = "2026-07-26T13:40:00.000Z";
    const event = domainEvent({
      tenant,
      eventId: "event-backend-termination",
      aggregateType: "CASE",
      aggregateId: "case-backend-termination",
      aggregateVersion: 1,
      time,
    });
    const running = store.runCommand(
      scope(tenant),
      metadata("CREATE_CASE", "backend-termination"),
      async (tx) => {
        await tx.insertCase({
          caseId: "case-backend-termination",
          tenantId: tenant.tenantId,
          tenantKind: "SYNTHETIC",
          state: "OPEN",
          version: 1,
          goalRef: "synthetic://c08/backend-termination",
          createdAt: time,
          updatedAt: time,
        });
        await tx.appendEvent(event);
        await tx.appendOutbox(event);
        return { caseId: "case-backend-termination" };
      },
    );

    let terminated = false;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const activity = await adminPool.query(
        `SELECT pid
           FROM pg_stat_activity
          WHERE datname=current_database()
            AND usename=$1
            AND wait_event='PgSleep'`,
        [RUNTIME_LOGIN],
      );
      if (activity.rows[0]) {
        const killed = await adminPool.query(
          "SELECT pg_terminate_backend($1) AS terminated",
          [activity.rows[0].pid],
        );
        terminated = killed.rows[0].terminated;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(terminated, true);
    const result = await running;
    assert.equal(result.value.caseId, "case-backend-termination");
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(
      expectedPoolErrors.every(
        (error) =>
          error?.code === "57P01" ||
          error?.message === "Connection terminated unexpectedly",
      ),
      true,
    );

    const counts = await adminPool.query(
      `SELECT
         (SELECT count(*)::integer FROM aios_state.aios_case
           WHERE case_id='case-backend-termination') AS cases,
         (SELECT count(*)::integer FROM aios_state.domain_event
           WHERE event_id='event-backend-termination') AS events,
         (SELECT count(*)::integer FROM aios_state.outbox
           WHERE event_id='event-backend-termination') AS outbox,
         (SELECT count(*)::integer FROM aios_state.command_receipt
           WHERE idempotency_key='create_case-backend-termination')
           AS receipts`,
    );
    assert.deepEqual(counts.rows[0], {
      cases: 1,
      events: 1,
      outbox: 1,
      receipts: 1,
    });
  });

  await t.test(
    "a committed command replays when its COMMIT acknowledgement is lost",
    async (commitTest) => {
      const uncertainRuntimePool = new Pool(config(RUNTIME_LOGIN));
      uncertainRuntimePool.on("error", () => {});
      commitTest.after(() => uncertainRuntimePool.end());
      const uncertainPool =
        loseFirstCommitAcknowledgement(uncertainRuntimePool);
      const uncertainStore = createPostgresAiosStateStore({
        runtimePool: uncertainPool,
        scopePool,
        outboxPool,
      });
      const tenant = TENANTS[1];
      const time = "2026-07-26T13:50:00.000Z";
      const event = domainEvent({
        tenant,
        eventId: "event-commit-ack-lost",
        aggregateType: "CASE",
        aggregateId: "case-commit-ack-lost",
        aggregateVersion: 1,
        time,
      });
      let reducerCalls = 0;

      const result = await uncertainStore.runCommand(
        scope(tenant, "c08-commit-ack-lost"),
        metadata("CREATE_CASE", "commit-ack-lost"),
        async (tx) => {
          reducerCalls += 1;
          await tx.insertCase({
            caseId: "case-commit-ack-lost",
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            state: "OPEN",
            version: 1,
            goalRef: "synthetic://c08/commit-ack-lost",
            createdAt: time,
            updatedAt: time,
          });
          await tx.appendEvent(event);
          await tx.appendOutbox(event);
          return { caseId: "case-commit-ack-lost" };
        },
      );

      assert.equal(uncertainPool.wasLost(), true);
      assert.equal(reducerCalls, 1);
      assert.equal(result.duplicate, true);
      assert.deepEqual(result.value, {
        caseId: "case-commit-ack-lost",
      });
      const counts = await adminPool.query(
        `SELECT
           (SELECT count(*)::integer FROM aios_state.aios_case
             WHERE case_id='case-commit-ack-lost') AS cases,
           (SELECT count(*)::integer FROM aios_state.domain_event
             WHERE event_id='event-commit-ack-lost') AS events,
           (SELECT count(*)::integer FROM aios_state.outbox
             WHERE event_id='event-commit-ack-lost') AS outbox,
           (SELECT count(*)::integer FROM aios_state.command_receipt
             WHERE idempotency_key='create_case-commit-ack-lost')
             AS receipts`,
      );
      assert.deepEqual(counts.rows[0], {
        cases: 1,
        events: 1,
        outbox: 1,
        receipts: 1,
      });
    },
  );

  await t.test("real C08 Core fences Artifact chains and reconstructs", async () => {
    const tenant = TENANTS[0];
    const human =
      "prn_01984910-5000-7000-8000-000000000001";
    const actor =
      "prn_01984910-5000-7000-8000-000000000002";
    const delegation =
      "dlg_01984910-5000-7000-8000-000000000003";
    const humanB =
      "prn_01984910-5000-7000-8000-000000000006";
    const delegationB =
      "dlg_01984910-5000-7000-8000-000000000007";
    let idCounter = 100;
    const idFactory = () => {
      idCounter += 1;
      return `01984910-5000-7000-8000-${idCounter
        .toString(16)
        .padStart(12, "0")}`;
    };
    const identity = {
      tenantId: tenant.tenantId,
      tenantKind: "SYNTHETIC",
      identityAccountId:
        "sia_01984910-5000-7000-8000-000000000004",
      identityLinkId:
        "lnk_01984910-5000-7000-8000-000000000005",
      sessionId: "ses-c08-postgres",
      humanSubject: {
        principalId: human,
        principalType: "HUMAN",
        lifecycleVersion: 1,
        securityEpoch: 1,
      },
      workloadActor: {
        principalId: actor,
        principalType: "SERVICE",
        lifecycleVersion: 1,
        securityEpoch: 1,
      },
      purposeRef: "policy://c08/purpose/analyze-order",
      delegationChain: [
        {
          delegationId: delegation,
          delegatorPrincipalId: human,
          delegatePrincipalId: actor,
          purposeRef: "policy://c08/purpose/analyze-order",
          lifecycleVersion: 1,
          expiresAt: "2026-07-26T16:00:00.000Z",
        },
      ],
      trustSource:
        "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
      authorizationStatus: "NOT_EVALUATED",
    };
    let currentIdentity = structuredClone(identity);
    const mockToolReceipts = createC08C0MockToolReceipts();
    const createCore = (
      referenceCatalog = REFERENCE_CATALOG,
    ) =>
      createAiosStateCore({
        tenantRegistry: {
          async admitNewRequest() {
            return {
              tenantId: tenant.tenantId,
              tenantKind: "SYNTHETIC",
              lifecycleVersion: 2,
              trustSource: "VERIFIED_SERVER_CONTEXT",
            };
          },
        },
        stablePrincipalRegistry: {
          async resolveActionIdentity() {
            return structuredClone(currentIdentity);
          },
        },
        authorizer: {
          async enforce(_context, request, descriptor) {
            const decisionSuffix = descriptor.surface
              .toLowerCase()
              .replace("_", "-");
            return {
              trustSource: "C06_BOUND_DECISION_EVIDENCE",
              decisionId: `c08-postgres-decision-${decisionSuffix}`,
              evidenceRef:
                `evidence://c08/postgres/core-${decisionSuffix}`,
              policyVersion: "c08-postgres-v1",
              tenantId: tenant.tenantId,
              surface: descriptor.surface,
              resourceId: request.resourceId,
              humanPrincipalId:
                currentIdentity.humanSubject.principalId,
              humanSecurityEpoch:
                currentIdentity.humanSubject.securityEpoch,
              workloadActorPrincipalId:
                currentIdentity.workloadActor.principalId,
              workloadActorSecurityEpoch:
                currentIdentity.workloadActor.securityEpoch,
              leafDelegationId:
                currentIdentity.delegationChain.at(-1).delegationId,
              delegationChainSha256: canonicalDigest(
                currentIdentity.delegationChain,
              ),
              purposeRef: currentIdentity.purposeRef,
            };
          },
        },
        controlAuthorize: async () => ({
          allowed: true,
          decisionId: "c08-postgres-control",
          evidenceRef: "evidence://c08/postgres/control",
          policyVersion: "c08-postgres-v1",
        }),
        store,
        referenceCatalog,
        toolReceiptVerifier: mockToolReceipts.verifier,
        idFactory,
        clock: () => "2026-07-26T14:30:00.000Z",
      });
    const core = createCore();
    const serverContext = {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId: tenant.tenantId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: actor,
    };
    const workerContext = {
      synthetic: true,
      routeTrustSource: "VERIFIED_TOOL_RESULT_ROUTE_DESCRIPTOR",
      tenantId: tenant.tenantId,
      workerTrustSource: "VERIFIED_C0_MOCK_TOOL_WORKER",
      workerPrincipalId: actor,
    };
    const executeWith = (targetCore, idempotencyKey, command) =>
      targetCore.execute(serverContext, {
        sessionToken: "c08-postgres-session",
        delegationId:
          currentIdentity.delegationChain.at(-1).delegationId,
        idempotencyKey,
        correlationId: `corr-${idempotencyKey}`,
        command,
      });
    const execute = (idempotencyKey, command) =>
      executeWith(core, idempotencyKey, command);
    const createdCase = await execute("pg-core-case", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/analyze-order",
    });
    const duplicateCase = await execute("pg-core-case", {
      kind: "CREATE_CASE",
      goalRef: "synthetic://c08/goals/analyze-order",
    });
    assert.equal(duplicateCase.duplicate, true);
    assert.equal(duplicateCase.caseId, createdCase.caseId);
    const thread = await execute("pg-core-thread", {
      kind: "OPEN_THREAD",
      caseId: createdCase.caseId,
      purposeRef: "policy://c08/purpose/analyze-order",
    });
    const inputV1 = await execute("pg-core-input-v1", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "INPUT",
      contentRef: "synthetic://c08/artifacts/input-order",
      contentSha256: HASH_A,
    });
    const appendAttempts = await Promise.allSettled(
      ["pg-core-input-v2-a", "pg-core-input-v2-b"].map(
        (idempotencyKey) =>
          execute(idempotencyKey, {
            kind: "RECORD_ARTIFACT_VERSION",
            artifactId: inputV1.artifactId,
            caseId: createdCase.caseId,
            threadId: thread.threadId,
            expectedArtifactVersion: 1,
            artifactKind: "INPUT",
            contentRef: "synthetic://c08/artifacts/input-order-v2",
            contentSha256: HASH_B,
          }),
      ),
    );
    const appended = appendAttempts.filter(
      ({ status }) => status === "fulfilled",
    );
    const fenced = appendAttempts.filter(
      ({ status }) => status === "rejected",
    );
    assert.equal(appended.length, 1);
    assert.equal(fenced.length, 1);
    assert.equal(fenced[0].reason?.code, "STALE_VERSION");
    const input = appended[0].value;
    assert.equal(input.artifactId, inputV1.artifactId);
    assert.equal(input.artifactVersion, 2);
    const artifactChain = await adminPool.query(
      `SELECT artifact_id,artifact_version::integer AS artifact_version,
              content_ref,content_sha256
         FROM aios_state.aios_artifact
        WHERE tenant_id=$1 AND artifact_id=$2
        ORDER BY artifact_version`,
      [tenant.tenantId, inputV1.artifactId],
    );
    assert.deepEqual(artifactChain.rows, [
      {
        artifact_id: inputV1.artifactId,
        artifact_version: 1,
        content_ref: "synthetic://c08/artifacts/input-order",
        content_sha256: HASH_A,
      },
      {
        artifact_id: inputV1.artifactId,
        artifact_version: 2,
        content_ref: "synthetic://c08/artifacts/input-order-v2",
        content_sha256: HASH_B,
      },
    ]);
    const manifest = {
      inputArtifact: {
        artifactId: input.artifactId,
        artifactVersion: input.artifactVersion,
        contentSha256: input.contentSha256,
      },
      model: {
        ref: "synthetic://c08/models/assistant",
        version: "model-1",
        sha256: HASH_B,
      },
      prompt: {
        ref: "synthetic://c08/prompts/run",
        version: "prompt-1",
        sha256: HASH_C,
      },
      skill: {
        ref: "synthetic://c08/skills/analyze",
        version: "skill-1",
        sha256: HASH_D,
      },
      knowledge: [
        {
          evidenceRef: "evidence://c08/knowledge/synthetic-handbook",
          version: "knowledge-1",
          asOf: "2026-07-26T09:59:00.000Z",
          sha256: HASH_E,
        },
      ],
      traceRef: "test://c08/traces/run-1",
    };
    const run = await execute("pg-core-run", {
      kind: "START_RUN",
      threadId: thread.threadId,
      manifest,
    });
    const persistedManifest = await adminPool.query(
      `SELECT base_manifest
         FROM aios_state.aios_run
        WHERE tenant_id=$1 AND run_id=$2`,
      [tenant.tenantId, run.runId],
    );
    assert.equal(persistedManifest.rowCount, 1);
    assert.deepEqual(
      Object.keys(
        persistedManifest.rows[0].base_manifest.knowledge[0],
      ).sort(),
      ["asOf", "evidenceRef", "sha256", "version"],
    );
    const serializedManifest = JSON.stringify(
      persistedManifest.rows[0].base_manifest,
    );
    for (const version of AUTHORITY_VERSION_CHANGE.versions) {
      assert.equal(
        serializedManifest.includes(version.sourceFactMarker),
        false,
      );
    }
    assert.equal(serializedManifest.includes("\"payload\""), false);
    assert.equal(serializedManifest.includes("\"body\""), false);

    const v2 = authorityVersion("V2");
    const currentAuthorityCore = createCore(
      referenceCatalogAtAuthorityVersion("V2"),
    );
    const beforeStaleAttempt = await adminPool.query(
      `SELECT
         (SELECT count(*)::integer FROM aios_state.aios_tool_call
           WHERE tenant_id=$1 AND run_id=$2) AS tool_calls,
         (SELECT count(*)::integer FROM aios_state.domain_event
           WHERE tenant_id=$1) AS events,
         (SELECT count(*)::integer FROM aios_state.outbox
           WHERE tenant_id=$1) AS outbox,
         (SELECT count(*)::integer FROM aios_state.command_receipt
           WHERE tenant_id=$1) AS receipts`,
      [tenant.tenantId, run.runId],
    );
    await assert.rejects(
      currentAuthorityCore.inspectRun(serverContext, {
        sessionToken: "c08-postgres-session",
        delegationId: delegation,
        runId: run.runId,
        correlationId: "corr-pg-core-stale-authority-inspect",
      }),
      (error) => error?.code === "STALE_SOURCE_REFERENCE",
    );
    await assert.rejects(
      executeWith(
        currentAuthorityCore,
        "pg-core-stale-authority-tool",
        {
          kind: "PREPARE_TOOL_CALL",
          runId: run.runId,
          expectedRunVersion: 1,
          operationRef: "synthetic://c08/tools/catalog-read",
          operationVersion: "tool-1",
          requestHash: digest("pg-core-stale-authority-tool"),
          compensationRef: "test://c08/compensations/noop",
        },
      ),
      (error) => error?.code === "STALE_SOURCE_REFERENCE",
    );
    const afterStaleAttempt = await adminPool.query(
      `SELECT
         (SELECT count(*)::integer FROM aios_state.aios_tool_call
           WHERE tenant_id=$1 AND run_id=$2) AS tool_calls,
         (SELECT count(*)::integer FROM aios_state.domain_event
           WHERE tenant_id=$1) AS events,
         (SELECT count(*)::integer FROM aios_state.outbox
           WHERE tenant_id=$1) AS outbox,
         (SELECT count(*)::integer FROM aios_state.command_receipt
           WHERE tenant_id=$1) AS receipts`,
      [tenant.tenantId, run.runId],
    );
    assert.deepEqual(afterStaleAttempt.rows, beforeStaleAttempt.rows);

    const currentManifest = structuredClone(manifest);
    currentManifest.knowledge = [
      {
        evidenceRef: AUTHORITY_VERSION_CHANGE.sourceRef,
        ...v2.reference,
      },
    ];
    const injectedManifest = structuredClone(currentManifest);
    injectedManifest.knowledge[0].payload = {
      sourceFact: v2.sourceFactMarker,
    };
    await assert.rejects(
      executeWith(
        currentAuthorityCore,
        "pg-core-authority-payload-injection",
        {
          kind: "START_RUN",
          threadId: thread.threadId,
          manifest: injectedManifest,
        },
      ),
      (error) => error?.code === "INVALID_INPUT",
    );
    const currentRun = await executeWith(
      currentAuthorityCore,
      "pg-core-authority-v2-run",
      {
        kind: "START_RUN",
        threadId: thread.threadId,
        manifest: currentManifest,
      },
    );
    const currentView = await currentAuthorityCore.inspectRun(
      serverContext,
      {
        sessionToken: "c08-postgres-session",
        delegationId: delegation,
        runId: currentRun.runId,
        correlationId: "corr-pg-core-authority-v2-inspect",
      },
    );
    assert.deepEqual(currentView.snapshot.knowledge, [
      {
        evidenceRef: AUTHORITY_VERSION_CHANGE.sourceRef,
        ...v2.reference,
      },
    ]);

    currentIdentity = {
      ...structuredClone(identity),
      identityAccountId:
        "sia_01984910-5000-7000-8000-000000000008",
      identityLinkId:
        "lnk_01984910-5000-7000-8000-000000000009",
      sessionId: "ses-c08-postgres-human-b",
      humanSubject: {
        ...identity.humanSubject,
        principalId: humanB,
      },
      delegationChain: [
        {
          ...identity.delegationChain[0],
          delegationId: delegationB,
          delegatorPrincipalId: humanB,
        },
      ],
    };
    await assert.rejects(
      execute("pg-core-human-b-tool", {
        kind: "PREPARE_TOOL_CALL",
        runId: run.runId,
        expectedRunVersion: 1,
        operationRef: "synthetic://c08/tools/catalog-read",
        operationVersion: "tool-1",
        requestHash: digest("pg-core-human-b-tool-request"),
        compensationRef: "test://c08/compensations/noop",
      }),
      (error) => error?.code === "RUN_ACTION_IDENTITY_MISMATCH",
    );
    await assert.rejects(
      execute("pg-core-human-b-finish", {
        kind: "FINISH_RUN",
        runId: run.runId,
        expectedRunVersion: 1,
        outcome: "FAILED",
        resultArtifact: {
          artifactId: input.artifactId,
          artifactVersion: input.artifactVersion,
          contentSha256: input.contentSha256,
        },
      }),
      (error) => error?.code === "RUN_ACTION_IDENTITY_MISMATCH",
    );
    const managerView = await core.inspectRun(serverContext, {
      sessionToken: "c08-postgres-session-human-b",
      delegationId: delegationB,
      runId: run.runId,
      correlationId: "corr-pg-core-human-b-inspect",
    });
    assert.equal(
      managerView.snapshot.actor.humanSubject.principalId,
      human,
    );
    assert.equal(managerView.version, 1);
    currentIdentity = structuredClone(identity);
    const prepared = await execute("pg-core-tool", {
      kind: "PREPARE_TOOL_CALL",
      runId: run.runId,
      expectedRunVersion: 1,
      operationRef: "synthetic://c08/tools/catalog-read",
      operationVersion: "tool-1",
      requestHash: digest("pg-core-tool-request"),
      compensationRef: "test://c08/compensations/noop",
    });
    const inspected = await core.inspectRun(serverContext, {
      sessionToken: "c08-postgres-session",
      delegationId: delegation,
      runId: run.runId,
      correlationId: "corr-pg-core-inspect",
    });
    assert.equal(inspected.recoveryStatus, "IN_PROGRESS");
    assert.equal(inspected.version, prepared.runVersion);
    assert.deepEqual(inspected.snapshot.case, {
      caseId: createdCase.caseId,
      state: "OPEN",
      version: 1,
      goalRef: "synthetic://c08/goals/analyze-order",
    });
    assert.deepEqual(inspected.snapshot.thread, {
      threadId: thread.threadId,
      caseId: createdCase.caseId,
      state: "OPEN",
      version: 1,
      purposeRef: "policy://c08/purpose/analyze-order",
    });
    assert.equal(inspected.snapshot.input.artifactVersion, 2);
    assert.deepEqual(inspected.snapshot.tools, [
      {
        toolCallId: prepared.toolCallId,
        state: "PREPARED",
        version: 1,
        operationRef: "synthetic://c08/tools/catalog-read",
        operationVersion: "tool-1",
        requestHash: prepared.requestHash,
        effectKey: prepared.effectKey,
        compensationRef: "test://c08/compensations/noop",
        policy: {
          decisionId: "c08-postgres-decision-tool-call",
          evidenceRef:
            "evidence://c08/postgres/core-tool-call",
          policyVersion: "c08-postgres-v1",
        },
        outcome: null,
        receiptRef: null,
        receiptHash: null,
      },
    ]);
    await assert.rejects(
      execute("pg-core-tool-second", {
        kind: "PREPARE_TOOL_CALL",
        runId: run.runId,
        expectedRunVersion: prepared.runVersion,
        operationRef: "synthetic://c08/tools/catalog-read",
        operationVersion: "tool-1",
        requestHash: digest("pg-core-tool-request-second"),
        compensationRef: "test://c08/compensations/noop",
      }),
      (error) => error?.code === "TOOL_CALL_IN_FLIGHT",
    );
    const accepted = await mockToolReceipts.executor.accept({
      tenantId: tenant.tenantId,
      runId: run.runId,
      toolCallId: prepared.toolCallId,
      effectKey: prepared.effectKey,
      requestHash: prepared.requestHash,
      operationRef: "synthetic://c08/tools/catalog-read",
      operationVersion: "tool-1",
      outcome: "SUCCEEDED",
    });
    await core.recordToolCallResult(workerContext, {
      idempotencyKey: "pg-core-tool-result",
      correlationId: "corr-pg-core-tool-result",
      command: {
        kind: "RECORD_TOOL_CALL_RESULT",
        runId: run.runId,
        expectedRunVersion: prepared.runVersion,
        toolCallId: prepared.toolCallId,
        expectedToolCallVersion: prepared.toolCallVersion,
        receiptId: accepted.receiptId,
      },
    });
    const result = await execute("pg-core-result", {
      kind: "RECORD_ARTIFACT_VERSION",
      artifactId: null,
      caseId: createdCase.caseId,
      threadId: thread.threadId,
      expectedArtifactVersion: 0,
      artifactKind: "RESULT",
      contentRef: "synthetic://c08/artifacts/result-analysis",
      contentSha256: HASH_D,
    });
    const finished = await execute("pg-core-finish", {
      kind: "FINISH_RUN",
      runId: run.runId,
      expectedRunVersion: 3,
      outcome: "SUCCEEDED",
      resultArtifact: {
        artifactId: result.artifactId,
        artifactVersion: result.artifactVersion,
        contentSha256: result.contentSha256,
      },
    });
    assert.equal(finished.state, "SUCCEEDED");
    const reconstructed = await core.reconstructRun(serverContext, {
      sessionToken: "c08-postgres-session",
      delegationId: delegation,
      runId: run.runId,
      correlationId: "corr-pg-core-reconstruct",
    });
    assert.equal(reconstructed.runId, run.runId);
    assert.equal(reconstructed.reconstructionHash, finished.reconstructionHash);
    assert.equal(reconstructed.manifest.tools[0].outcome, "SUCCEEDED");
    const snapshot = await core.snapshot(
      { actor: "c08-test-control" },
      { tenantId: tenant.tenantId },
    );
    assert.equal(snapshot.counts.runs >= 2, true);
    assert.equal(snapshot.runStates.SUCCEEDED >= 1, true);
    assert.equal(snapshot.toolCallStates.SUCCEEDED >= 1, true);
  });

  await t.test("SKIP LOCKED leases are disjoint and version-fenced", async () => {
    const tenant = TENANTS[0];
    const claimNow = new Date().toISOString();
    const [first, second] = await Promise.all([
      store.claimOutbox(scope(tenant), {
        workerId: "worker-a",
        now: claimNow,
        leaseExpiresAt: new Date(
          Date.parse(claimNow) + 1000,
        ).toISOString(),
        limit: 1,
      }),
      store.claimOutbox(scope(tenant), {
        workerId: "worker-b",
        now: claimNow,
        leaseExpiresAt: new Date(
          Date.parse(claimNow) + 30000,
        ).toISOString(),
        limit: 1,
      }),
    ]);
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.notEqual(first[0].eventId, second[0].eventId);
    assert.deepEqual(Object.keys(first[0]).sort(), OUTBOX_FIELDS);
    assert.deepEqual(Object.keys(second[0]).sort(), OUTBOX_FIELDS);
    assert.equal(first[0].state, "LEASED");
    assert.equal(first[0].workerId, "worker-a");

    await new Promise((resolve) => setTimeout(resolve, 1100));
    const reclaimNow = new Date().toISOString();
    const reclaimed = await store.claimOutbox(scope(tenant), {
      workerId: "worker-c",
      now: reclaimNow,
      leaseExpiresAt: new Date(
        Date.parse(reclaimNow) + 30000,
      ).toISOString(),
      limit: 1,
    });
    assert.equal(reclaimed.length, 1);
    assert.equal(reclaimed[0].eventId, first[0].eventId);
    assert.equal(reclaimed[0].leaseVersion, first[0].leaseVersion + 1);

    await assert.rejects(
      store.completeOutbox(scope(tenant), {
        eventId: first[0].eventId,
        workerId: "worker-a",
        leaseVersion: first[0].leaseVersion,
        now: reclaimNow,
      }),
      (error) => error?.code === "STALE_OUTBOX_LEASE",
    );
    const completed = await store.completeOutbox(scope(tenant), {
      eventId: reclaimed[0].eventId,
      workerId: "worker-c",
      leaseVersion: reclaimed[0].leaseVersion,
      now: new Date().toISOString(),
    });
    assert.equal(completed.state, "PUBLISHED");

    const failedAt = new Date().toISOString();
    const failed = await store.failOutbox(scope(tenant), {
      eventId: second[0].eventId,
      workerId: "worker-b",
      leaseVersion: second[0].leaseVersion,
      now: failedAt,
      retryAt: new Date(Date.parse(failedAt) + 1000).toISOString(),
      errorCode: "MOCK_TEMPORARY_FAILURE",
    });
    assert.equal(failed.state, "PENDING");
    assert.deepEqual(Object.keys(failed).sort(), OUTBOX_FIELDS);
    assert.equal(failed.lastErrorCode, "MOCK_TEMPORARY_FAILURE");

    const states = await adminPool.query(
      `SELECT
         count(*) FILTER (WHERE status='PUBLISHED')::integer AS published,
         count(*) FILTER (WHERE status='FAILED')::integer AS failed
         FROM aios_state.outbox
        WHERE tenant_id=$1`,
      [tenant.tenantId],
    );
    assert.deepEqual(states.rows[0], {
      published: 1,
      failed: 1,
    });
  });

  await t.test(
    "PostgreSQL Outbox reuses one effect key after Mock accepted and worker crashed",
    async (testContext) => {
      const tenant = TENANTS[0];
      const time = "2026-07-26T15:00:00.000Z";
      const receiptRoot = await mkdtemp(
        join(tmpdir(), "c08-pg-mock-receipts-"),
      );
      testContext.after(() =>
        rm(receiptRoot, { recursive: true, force: true }),
      );
      const effect = {
        tenantId: tenant.tenantId,
        runId: "run_018f0000-0000-7000-8000-000000000091",
        toolCallId:
          "tcl_018f0000-0000-7000-8000-000000000092",
        effectKey: `effect_${digest("postgres-mock-effect").slice(7)}`,
        requestHash: digest("postgres-mock-request"),
        operationRef: "synthetic://c08/tools/catalog-read",
        operationVersion: "tool-1",
        outcome: "SUCCEEDED",
      };
      const event = domainEvent({
        tenant,
        eventId: "event-postgres-mock-accepted",
        aggregateType: "CASE",
        aggregateId: "case-postgres-mock-accepted",
        aggregateVersion: 1,
        time,
      });
      Object.assign(event.event.data, {
        run_id: effect.runId,
        tool_call_id: effect.toolCallId,
        effect_key: effect.effectKey,
        request_hash: effect.requestHash,
        operation_ref: effect.operationRef,
        operation_version: effect.operationVersion,
        outcome: effect.outcome,
      });
      await store.runCommand(
        scope(tenant, "c08-postgres-mock-accepted"),
        metadata("CREATE_CASE", "postgres-mock-accepted"),
        async (tx) => {
          await tx.insertCase({
            caseId: "case-postgres-mock-accepted",
            tenantId: tenant.tenantId,
            tenantKind: "SYNTHETIC",
            state: "OPEN",
            version: 1,
            goalRef: "synthetic://c08/postgres-mock-accepted",
            createdAt: time,
            updatedAt: time,
          });
          await tx.appendEvent(event);
          await tx.appendOutbox(event);
          return { caseId: "case-postgres-mock-accepted" };
        },
      );

      const mockProcess = () =>
        createC08C0MockToolReceipts({
          store: createFileC08MockReceiptStore({
            rootDir: receiptRoot,
          }),
        });
      const effectFromClaim = (claim) => ({
        tenantId: claim.event.data.tenant_id,
        runId: claim.event.data.run_id,
        toolCallId: claim.event.data.tool_call_id,
        effectKey: claim.event.data.effect_key,
        requestHash: claim.event.data.request_hash,
        operationRef: claim.event.data.operation_ref,
        operationVersion: claim.event.data.operation_version,
        outcome: claim.event.data.outcome,
      });
      const firstNow = new Date().toISOString();
      const firstClaims = await store.claimOutbox(scope(tenant), {
        workerId: "mock-worker-a",
        now: firstNow,
        leaseExpiresAt: new Date(
          Date.parse(firstNow) + 1000,
        ).toISOString(),
        limit: 100,
      });
      const first = firstClaims.find(
        (claim) => claim.eventId === event.eventId,
      );
      assert.ok(first);
      const firstMock = mockProcess();
      const accepted = await firstMock.executor.accept(
        effectFromClaim(first),
      );
      assert.deepEqual(accepted, {
        duplicate: false,
        receiptId: accepted.receiptId,
      });

      await new Promise((resolve) => setTimeout(resolve, 1100));
      const reclaimNow = new Date().toISOString();
      const restartedMock = mockProcess();
      let replayedReceipt = null;
      const restartedWorker = createC08OutboxWorker({
        store,
        publisher: {
          async publish({ eventId, event: claimedEvent }) {
            if (eventId === event.eventId) {
              replayedReceipt =
                await restartedMock.executor.accept(
                  effectFromClaim({ event: claimedEvent }),
                );
            }
            return { eventId };
          },
        },
      });
      const workerResult = await restartedWorker.runOnce(
        scope(tenant),
        {
          workerId: "mock-worker-b",
          now: reclaimNow,
          leaseExpiresAt: new Date(
            Date.parse(reclaimNow) + 30000,
          ).toISOString(),
          retryAt: new Date(
            Date.parse(reclaimNow) + 60000,
          ).toISOString(),
          limit: 100,
        },
      );
      assert.equal(
        workerResult.publishedEventIds.includes(event.eventId),
        true,
      );
      assert.deepEqual(replayedReceipt, {
        receiptId: accepted.receiptId,
        duplicate: true,
      });
      const verified = await restartedMock.verifier.resolve({
        receiptId: accepted.receiptId,
        tenantId: effect.tenantId,
        runId: effect.runId,
        toolCallId: effect.toolCallId,
        effectKey: effect.effectKey,
        requestHash: effect.requestHash,
        operationRef: effect.operationRef,
        operationVersion: effect.operationVersion,
      });
      assert.deepEqual({
        duplicate: true,
        effectKey: verified.effectKey,
      }, {
        duplicate: true,
        effectKey: effect.effectKey,
      });

      await assert.rejects(
        store.completeOutbox(scope(tenant), {
          eventId: first.eventId,
          workerId: "mock-worker-a",
          leaseVersion: first.leaseVersion,
          now: reclaimNow,
        }),
        (error) => error?.code === "STALE_OUTBOX_LEASE",
      );

      const durable = await adminPool.query(
        `SELECT status,lease_version,attempt_count,
                event #>> '{data,effect_key}' AS effect_key
           FROM aios_state.outbox
          WHERE tenant_id=$1 AND event_id=$2`,
        [tenant.tenantId, event.eventId],
      );
      assert.deepEqual(durable.rows[0], {
        status: "PUBLISHED",
        lease_version: String(first.leaseVersion + 1),
        attempt_count: 2,
        effect_key: effect.effectKey,
      });
    },
  );
});
