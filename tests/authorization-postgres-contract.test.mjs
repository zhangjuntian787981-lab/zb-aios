import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createPostgresAuthorizationStore } from "../lib/postgres-authorization-store.mjs";

function scriptedPool(responder) {
  const queries = [];
  const client = {
    async query(sql, parameters = []) {
      queries.push({ sql, parameters });
      return responder(sql, parameters);
    },
    release() {},
  };
  return {
    queries,
    pool: {
      async connect() {
        return client;
      },
    },
  };
}

function sampleEvent() {
  return {
    specversion: "1.0",
    id: "evt_01984800-0000-7000-8000-000000000001",
    source: "/product-core/authorization",
    type: "product.authorization.policy-release-staged.v1",
    subject: "azr_01984800-0000-7000-8000-000000000002",
    time: "2026-07-26T08:00:00.000Z",
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: "c06-contract",
    synthetic: true,
    data: {
      tenant_id: "stn_01984800-0000-7000-8000-000000000003",
    },
  };
}

test("the PostgreSQL adapter satisfies the complete C06 Store seam", () => {
  const { pool } = scriptedPool(() => ({ rows: [], rowCount: 1 }));
  const store = createPostgresAuthorizationStore({ pool });
  assert.deepEqual(Object.keys(store).sort(), [
    "claimOutbox",
    "completeOutbox",
    "failOutbox",
    "readActiveRelease",
    "readCommandReceipt",
    "readDecision",
    "readPolicyRelease",
    "readTenantSnapshot",
    "recordDecision",
    "runCommand",
  ]);
});

test("C06 commands use one serializable transaction and pair Event with Outbox", async () => {
  const { pool, queries } = scriptedPool((sql) => {
    if (sql.includes("SELECT command_hash")) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresAuthorizationStore({ pool });
  const event = sampleEvent();
  const result = await store.runCommand(
    {
      tenantId: event.data.tenant_id,
      idempotencyKey: "c06-contract-command",
      commandHash: `sha256:${"a".repeat(64)}`,
    },
    async (transaction) => {
      assert.deepEqual(Object.keys(transaction).sort(), [
        "activate",
        "activePolicy",
        "appendEvent",
        "findRelease",
        "findReleaseByTemplate",
        "insertRelease",
        "listReleases",
        "putRelease",
      ]);
      await transaction.appendEvent(event);
      return { eventId: event.id };
    },
  );
  assert.deepEqual(result, {
    duplicate: false,
    value: { eventId: event.id },
  });
  assert.equal(
    queries.some(
      ({ sql }) => sql === "BEGIN ISOLATION LEVEL SERIALIZABLE",
    ),
    true,
  );
  const eventInsert = queries.find(({ sql }) =>
    sql.includes('"authorization_event"'),
  );
  const outboxInsert = queries.find(({ sql }) =>
    sql.includes('"authorization_outbox"'),
  );
  assert.ok(eventInsert);
  assert.ok(outboxInsert);
  assert.equal(eventInsert.parameters[3], outboxInsert.parameters[3]);
  assert.equal(queries.at(-1).sql, "COMMIT");
});

test("C06 prechecks the active version and its database guard locks before commit", async () => {
  const tenantId = "stn_01984800-0000-7000-8000-000000000003";
  const releaseId = "azr_01984800-0000-7000-8000-000000000002";
  const { pool, queries } = scriptedPool((sql) => {
    if (
      sql.includes("SELECT policy_release_id, activation_version")
    ) {
      return {
        rows: [
          {
            policy_release_id: releaseId,
            activation_version: "1",
          },
        ],
        rowCount: 1,
      };
    }
    if (sql.includes('"authorization_decision"') && sql.includes("SELECT")) {
      return { rows: [], rowCount: 0 };
    }
    return { rows: [], rowCount: 1 };
  });
  const store = createPostgresAuthorizationStore({ pool });
  const event = {
    ...sampleEvent(),
    type: "product.authorization.decision-recorded.v1",
  };
  const decision = {
    decisionId: "azd_01984800-0000-7000-8000-000000000004",
    tenantId,
    tenantKind: "SYNTHETIC",
    correlationId: "c06-contract",
    surface: "READ",
    resourceType: "protected_resource",
    resourceId: "fixture-read",
    resourceAuthorizationVersion: 1,
    humanPrincipalId: "prn_01984800-0000-7000-8000-000000000005",
    humanSecurityEpoch: 1,
    workloadActorPrincipalId:
      "prn_01984800-0000-7000-8000-000000000006",
    workloadActorSecurityEpoch: 1,
    leafDelegationId: "dlg_01984800-0000-7000-8000-000000000007",
    delegationChainSha256: `sha256:${"b".repeat(64)}`,
    purposeRef: "fixture://c06/purpose/read",
    policyReleaseId: releaseId,
    bundleSha256: `sha256:${"c".repeat(64)}`,
    tupleBundleSha256: `sha256:${"f".repeat(64)}`,
    openFgaStoreId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    authorizationModelId: "01ARZ3NDEKTSV4RRFFQ69G5FAW",
    activationVersion: 1,
    consistency: "HIGHER_CONSISTENCY",
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    reasonCode: "ALL_FACTORS_ALLOWED",
    inputSha256: `sha256:${"d".repeat(64)}`,
    checkTuples: {},
    checkResults: { human: true, actor: true, purpose: true },
    checkResultSha256: `sha256:${"e".repeat(64)}`,
    evaluatedAt: "2026-07-26T08:00:00.000Z",
    evidenceRef:
      "evidence://c06/decisions/azd_01984800-0000-7000-8000-000000000004",
  };
  event.subject = decision.decisionId;
  event.data = {
    tenant_id: tenantId,
    decision_id: decision.decisionId,
    tuple_bundle_sha256: decision.tupleBundleSha256,
  };

  await store.recordDecision({
    tenantId,
    expectedPolicyReleaseId: releaseId,
    expectedActivationVersion: 1,
    decision,
    event,
  });

  assert.equal(
    queries.some(
      ({ sql }) =>
        sql.includes('"authorization_active_policy"') &&
        !sql.includes("FOR SHARE"),
    ),
    true,
  );
  const schema = await readFile(
    new URL(
      "../implementation/p1/c06/postgresql/0009_authorization.sql",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(
    schema,
    /CREATE FUNCTION aios_core\.enforce_authorization_decision_insert\(\)[\s\S]*?FROM aios_core\.authorization_active_policy[\s\S]*?FOR SHARE;/,
  );
  assert.equal(
    queries.filter(({ sql }) =>
      sql.includes('INSERT INTO "aios_core"."authorization_decision"'),
    ).length,
    1,
  );
  assert.equal(
    queries.some(({ sql }) =>
      sql.includes("release.tuple_bundle_sha256"),
    ),
    true,
  );
  const existingDecisionRead = queries.findIndex(
    ({ sql }) =>
      sql.includes('"authorization_decision"') &&
      sql.includes('"authorization_event"') &&
      sql.includes('"authorization_outbox"'),
  );
  const activePolicyRead = queries.findIndex(({ sql }) =>
    sql.includes('"authorization_active_policy"'),
  );
  assert.notEqual(existingDecisionRead, -1);
  assert.ok(existingDecisionRead < activePolicyRead);
  assert.equal(queries.at(-1).sql, "COMMIT");
});

test("C06 migrations freeze seven tables, evidence guards and three least-privilege roles", async () => {
  const [schema, roles] = await Promise.all([
    readFile(
      new URL(
        "../implementation/p1/c06/postgresql/0009_authorization.sql",
        import.meta.url,
      ),
      "utf8",
    ),
    readFile(
      new URL(
        "../implementation/p1/c06/postgresql/0010_authorization_runtime_roles.sql",
        import.meta.url,
      ),
      "utf8",
    ),
  ]);
  assert.equal(
    (
      schema.match(
        /CREATE TABLE aios_core\.authorization_[a-z_]+ \(/g,
      ) ?? []
    ).length,
    7,
  );
  for (const marker of [
    "authorization_policy_release",
    "authorization_active_policy",
    "authorization_activation",
    "authorization_decision",
    "authorization_command_receipt",
    "authorization_event",
    "authorization_outbox",
    "authorization_event_outbox_pair_guard",
    "authorization_decision_event_pair_guard",
    "authorization_tenant_active_guard",
    "authorization_decision_active_policy_guard",
    "authorization_policy_release_tenant_template_key",
    "authorization_policy_release_tenant_sequence_key",
  ]) {
    assert.match(schema, new RegExp(marker));
  }
  assert.match(
    schema,
    /CREATE UNIQUE INDEX authorization_policy_release_tenant_template_key[\s\S]*WHERE state <> 'FAILED'/,
  );
  assert.match(
    schema,
    /CREATE UNIQUE INDEX authorization_policy_release_tenant_sequence_key[\s\S]*WHERE state <> 'FAILED'/,
  );
  for (const role of [
    "aios_c06_control_runtime",
    "aios_c06_decision_runtime",
    "aios_c06_outbox_worker",
  ]) {
    assert.match(roles, new RegExp(`CREATE ROLE ${role}`));
  }
  assert.match(roles, /SECURITY DEFINER/);
  assert.match(roles, /SET search_path = pg_catalog, aios_core/);
  assert.doesNotMatch(
    roles,
    /GRANT [^;]*ON TABLE[^;]*(tenant_registry|principal_registry)/s,
  );
});
