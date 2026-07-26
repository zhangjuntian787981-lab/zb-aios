import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import pg from "pg";
import {
  createPersonalMemoryService,
  createSyntheticHumanConsentAuthority,
  createSyntheticPersonalMemoryCatalog,
} from "../../lib/c09-personal-memory.mjs";
import {
  createPostgresPersonalMemoryStore,
} from "../../lib/c09-personal-memory-postgres-store.mjs";

const { Pool } = pg;
const TENANT_A = "stn_018f0000-0000-7000-8000-000000000010";
const TENANT_B = "stn_01984910-3000-7000-8000-000000000002";
const HUMAN_A = "prn_018f0000-0000-7000-8000-000000000001";
const HUMAN_C = "prn_018f0000-0000-7000-8000-000000000004";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_A = "dlg_018f0000-0000-7000-8000-000000000020";
const DELEGATION_C = "dlg_018f0000-0000-7000-8000-000000000021";
const RUNTIME_LOGIN = "c09_test_runtime_login";
const TENANT_SCOPE_LOGIN = "c09_test_tenant_scope_login";
const PRINCIPAL_SCOPE_LOGIN = "c09_test_principal_scope_login";
const RECEIPT_REPLAY_CONSENT_TOKEN =
  "hct_018f0000-0000-7000-8000-000000009901";
const catalog = createSyntheticPersonalMemoryCatalog(
  JSON.parse(
    await readFile(
      new URL(
        "../../implementation/p1/c09/synthetic-personal-memory-catalog.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ),
);

function configuration(user = process.env.C09_TEST_PGUSER) {
  if (process.env.C09_TEST_EPHEMERAL !== "1") {
    throw new Error("C09_TEST_EPHEMERAL=1 is required.");
  }
  if (process.env.C09_TEST_RESTORED !== "1") {
    throw new Error("C09_TEST_RESTORED=1 is required.");
  }
  for (const name of [
    "C09_TEST_PGHOST",
    "C09_TEST_PGPORT",
    "C09_TEST_PGDATABASE",
    "C09_TEST_PGUSER",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  return {
    host: process.env.C09_TEST_PGHOST,
    port: Number(process.env.C09_TEST_PGPORT),
    database: process.env.C09_TEST_PGDATABASE,
    user,
  };
}

function deterministicIds(start = 3000) {
  let counter = start;
  return () => {
    counter += 1;
    return `018f0000-0000-7000-8000-${String(counter).padStart(12, "0")}`;
  };
}

function createHarness({
  store,
  tenantId,
  humanPrincipalId,
  delegationId,
  now,
  humanConsentStore,
  start,
}) {
  const mutable = { now };
  const service = createPersonalMemoryService({
    catalog,
    store,
    idFactory: deterministicIds(start),
    clock: () => mutable.now,
    tenantRegistry: {
      async admitNewRequest() {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 2,
        };
      },
    },
    stablePrincipalRegistry: {
      async resolveActionIdentity() {
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          sessionId: `restored-session-${humanPrincipalId}`,
          humanSubject: {
            principalId: humanPrincipalId,
            principalType: "HUMAN",
            lifecycleVersion: 1,
            securityEpoch: 1,
          },
          workloadActor: {
            principalId: ACTOR,
            principalType: "SERVICE",
            lifecycleVersion: 1,
            securityEpoch: 1,
          },
          delegationChain: [{
            delegationId,
            delegatorPrincipalId: humanPrincipalId,
            delegatePrincipalId: ACTOR,
            lifecycleVersion: 1,
          }],
          trustSource:
            "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
        };
      },
    },
    authorizer: {
      async enforce({ operation }) {
        return {
          allowed: true,
          tenantId,
          humanPrincipalId,
          workloadActorPrincipalId: ACTOR,
          delegationId,
          operation,
          decisionId: `restored-decision-${operation.toLowerCase()}`,
          evidenceRef: "evidence://c09/restored-postgresql",
          policyVersion: "c09-restored-postgresql-policy-v1",
        };
      },
    },
    tenantScopeFactory({ authorization, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 2,
        correlationId,
        decisionId: authorization.decisionId,
        evidenceRef: authorization.evidenceRef,
        policyVersion: authorization.policyVersion,
      };
    },
    humanConsentStore,
  });
  return {
    service,
    mutable,
    context: {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: ACTOR,
    },
    wrap(command) {
      return {
        sessionToken: `restored-token-${humanPrincipalId}`,
        delegationId,
        command,
      };
    },
    recall(suffix) {
      return {
        sessionToken: `restored-token-${humanPrincipalId}`,
        delegationId,
        correlationId: `restored-recall-${suffix}`,
        limit: 20,
      };
    },
  };
}

test("restored PostgreSQL keeps terminal state scrubbed and events opaque", async () => {
  const pool = new Pool(configuration());
  try {
    const terminal = await pool.query(
      `SELECT count(*)::integer AS total,
              count(*) FILTER (WHERE content IS NOT NULL)::integer
                AS plaintext
         FROM aios_personal_memory.personal_memory
        WHERE state IN ('EXPIRED','DELETED')`,
    );
    assert.ok(terminal.rows[0].total > 0);
    assert.equal(terminal.rows[0].plaintext, 0);

    const checkpoint = await pool.query(
      `SELECT count(*)::integer AS terminal_references
         FROM aios_personal_memory.conversation_checkpoint AS checkpoint
         CROSS JOIN LATERAL unnest(checkpoint.memory_ids)
           AS reference(memory_id)
         JOIN aios_personal_memory.personal_memory AS memory
           ON memory.tenant_id=checkpoint.tenant_id
          AND memory.principal_id=checkpoint.principal_id
          AND memory.memory_id=reference.memory_id
        WHERE memory.state IN ('EXPIRED','DELETED')`,
    );
    assert.equal(checkpoint.rows[0].terminal_references, 0);

    const events = await pool.query(
      `SELECT count(*)::integer AS total,
              count(*) FILTER (
                WHERE human_consent_evidence IS NOT NULL
              )::integer AS consent_events,
              count(*) FILTER (
                WHERE to_jsonb(event) ? 'content'
                   OR human_consent_evidence ? 'humanConsentToken'
                   OR to_jsonb(event)::text
                        ~ 'hct_[0-9a-f-]{36}'
                   OR to_jsonb(event)::text LIKE '%Synthetic preference:%'
                   OR to_jsonb(event)::text LIKE '%Synthetic work state:%'
              )::integer AS plaintext_leaks
         FROM aios_personal_memory.memory_event AS event`,
    );
    assert.ok(events.rows[0].total > 0);
    assert.ok(events.rows[0].consent_events > 0);
    assert.equal(events.rows[0].plaintext_leaks, 0);
  } finally {
    await pool.end();
  }
});

test("restored PostgreSQL preserves service replay, RLS, pause and expiry behavior", async () => {
  const adminPool = new Pool(configuration());
  const runtimePool = new Pool(configuration(RUNTIME_LOGIN));
  const tenantScopePool = new Pool(configuration(TENANT_SCOPE_LOGIN));
  const principalScopePool = new Pool(
    configuration(PRINCIPAL_SCOPE_LOGIN),
  );
  try {
    const store = createPostgresPersonalMemoryStore({
      runtimePool,
      tenantScopePool,
      principalScopePool,
    });
    const rls = await adminPool.query(
      `SELECT relname,relrowsecurity,relforcerowsecurity
         FROM pg_class
        WHERE relnamespace='aios_personal_memory'::regnamespace
          AND relname IN (
            'personal_profile','personal_memory','conversation_checkpoint',
            'memory_event','command_receipt'
          )
        ORDER BY relname`,
    );
    assert.equal(rls.rowCount, 5);
    assert.ok(
      rls.rows.every(
        (row) => row.relrowsecurity && row.relforcerowsecurity,
      ),
    );

    const receipt = await adminPool.query(
      `SELECT result
         FROM aios_personal_memory.command_receipt
        WHERE tenant_id=$1 AND principal_id=$2
          AND idempotency_key='pg-confirm-receipt-restart'`,
      [TENANT_A, HUMAN_A],
    );
    assert.equal(receipt.rowCount, 1);
    let consentCalls = 0;
    const owner = createHarness({
      store,
      tenantId: TENANT_A,
      humanPrincipalId: HUMAN_A,
      delegationId: DELEGATION_A,
      now: "2026-07-26T10:00:00.000Z",
      start: 3100,
      humanConsentStore: {
        async consume() {
          consentCalls += 1;
          throw new Error("restored receipt must precede consent");
        },
      },
    });
    const replay = await owner.service.execute(
      owner.context,
      owner.wrap({
        kind: "CONFIRM_CANDIDATE",
        memoryId: receipt.rows[0].result.memoryId,
        expectedVersion: 1,
        humanConsentToken: RECEIPT_REPLAY_CONSENT_TOKEN,
        idempotencyKey: "pg-confirm-receipt-restart",
        correlationId: "pg-confirm-receipt-restart",
      }),
    );
    assert.deepEqual(replay, receipt.rows[0].result);
    assert.equal(consentCalls, 0);

    const expired = await adminPool.query(
      `SELECT memory_id
         FROM aios_personal_memory.personal_memory
        WHERE tenant_id=$1 AND principal_id=$2
          AND source_ref='fixture://c09/northstar/work-state/catalog'
          AND state='CONFIRMED'
          AND expires_at='2026-08-26T00:00:00.000Z'`,
      [TENANT_A, HUMAN_A],
    );
    assert.equal(expired.rowCount, 1);
    owner.mutable.now = "2026-08-27T00:00:00.000Z";
    const ownerRecall = await owner.service.recall(
      owner.context,
      owner.recall("natural-expiry"),
    );
    assert.equal(
      ownerRecall.memories.some(
        ({ memoryId }) => memoryId === expired.rows[0].memory_id,
      ),
      false,
    );

    const { issuer, consentStore } =
      createSyntheticHumanConsentAuthority();
    const otherTenant = createHarness({
      store,
      tenantId: TENANT_B,
      humanPrincipalId: HUMAN_C,
      delegationId: DELEGATION_C,
      now: "2026-07-26T10:00:00.000Z",
      start: 3200,
      humanConsentStore: consentStore,
    });
    const candidate = await otherTenant.service.execute(
      otherTenant.context,
      otherTenant.wrap({
        kind: "PROPOSE_CANDIDATE",
        candidateRef: "fixture://c09/cedar/preferences/evidence-first",
        idempotencyKey: "restored-pg-propose-tenant-b",
        correlationId: "restored-pg-propose-tenant-b",
      }),
    );
    const confirmation = {
      kind: "CONFIRM_CANDIDATE",
      memoryId: candidate.memoryId,
      expectedVersion: candidate.version,
      humanConsentToken: issuer.issue({
        tenantId: TENANT_B,
        humanPrincipalId: HUMAN_C,
        memoryId: candidate.memoryId,
        expectedVersion: candidate.version,
        contentSha256:
          catalog.resolve(
            TENANT_B,
            "fixture://c09/cedar/preferences/evidence-first",
          ).contentSha256,
        expiresAt: "2026-07-26T11:00:00.000Z",
        purpose: "CONFIRM_PERSONAL_MEMORY",
      }),
      idempotencyKey: "restored-pg-confirm-tenant-b",
      correlationId: "restored-pg-confirm-tenant-b",
    };
    const confirmed = await otherTenant.service.execute(
      otherTenant.context,
      otherTenant.wrap(confirmation),
    );
    const isolated = await otherTenant.service.recall(
      otherTenant.context,
      otherTenant.recall("tenant-b-isolation"),
    );
    assert.deepEqual(
      isolated.memories.map(({ memoryId }) => memoryId),
      [confirmed.memoryId],
    );
    await otherTenant.service.execute(
      otherTenant.context,
      otherTenant.wrap({
        kind: "CHANGE_PROFILE_STATE",
        expectedProfileVersion: 1,
        state: "PAUSED",
        idempotencyKey: "restored-pg-pause-tenant-b",
        correlationId: "restored-pg-pause-tenant-b",
      }),
    );
    assert.deepEqual(
      (
        await otherTenant.service.recall(
          otherTenant.context,
          otherTenant.recall("tenant-b-paused"),
        )
      ).memories,
      [],
    );
  } finally {
    await Promise.allSettled([
      runtimePool.end(),
      tenantScopePool.end(),
      principalScopePool.end(),
      adminPool.end(),
    ]);
  }
});
