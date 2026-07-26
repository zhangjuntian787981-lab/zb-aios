import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createPostgresAiosStateStore,
  deriveCommandEffectKey,
} from "../lib/postgres-aios-state-store.mjs";

const migration = await readFile(
  new URL(
    "../implementation/p1/c08/postgresql/0013_aios_state_core.sql",
    import.meta.url,
  ),
  "utf8",
);
const roles = await readFile(
  new URL(
    "../implementation/p1/c08/postgresql/0014_aios_state_runtime_roles.sql",
    import.meta.url,
  ),
  "utf8",
);
const store = await readFile(
  new URL("../lib/postgres-aios-state-store.mjs", import.meta.url),
  "utf8",
);

test("C08 has exactly eight tenant-scoped FORCE RLS records", () => {
  for (const table of [
    "aios_case",
    "aios_thread",
    "aios_run",
    "aios_artifact",
    "aios_tool_call",
    "domain_event",
    "outbox",
    "command_receipt",
  ]) {
    assert.match(migration, new RegExp(`CREATE TABLE aios_state\\.${table}`));
    assert.match(
      migration,
      new RegExp(
        `ALTER TABLE aios_state\\.${table} FORCE ROW LEVEL SECURITY`,
      ),
    );
  }
  assert.equal(
    (migration.match(/FORCE ROW LEVEL SECURITY/g) ?? []).length,
    8,
  );
  assert.equal(
    (migration.match(/ENABLE ROW LEVEL SECURITY/g) ?? []).length,
    8,
  );
  assert.match(
    roles,
    /runtime_scope_allows\(tenant_id,\s*tenant_kind\)/,
  );
  assert.doesNotMatch(migration, /signing_secret|public\.hmac/);
});

test("C08 atomic evidence and immutable version guards are in the schema", () => {
  assert.match(migration, /DEFERRABLE INITIALLY DEFERRED/);
  assert.match(migration, /aios_state_event_outbox_pair_guard/);
  assert.match(migration, /aios_state_event_receipt_pair_guard/);
  assert.match(migration, /aios_state_event_aggregate_guard/);
  assert.match(migration, /aios_state_version_guard/);
  assert.match(migration, /OLD\.version \+ 1/);
  assert.match(migration, /aios_state_append_only_guard/);
  assert.match(migration, /UNIQUE \(tenant_id, effect_key\)/);
  assert.match(
    migration,
    /CREATE UNIQUE INDEX aios_tool_call_one_prepared_per_run[\s\S]*?ON aios_state\.aios_tool_call\(tenant_id, run_id\)[\s\S]*?WHERE state = 'PREPARED'/,
  );
  assert.match(
    migration,
    /CREATE TABLE aios_state\.aios_tool_call[\s\S]*?authorization_evidence jsonb NOT NULL/,
  );
  assert.match(
    migration,
    /TG_TABLE_NAME = 'aios_tool_call'[\s\S]*?NEW\.authorization_evidence[\s\S]*?IS DISTINCT FROM OLD\.authorization_evidence/,
  );
  assert.match(
    migration,
    /CREATE TABLE aios_state\.domain_event[\s\S]*?UNIQUE \(tenant_id, idempotency_key\)/,
  );
  assert.match(
    migration,
    /request_hash ~ '\^sha256:\[0-9a-f\]\{64\}\$'/,
  );
});

test("C08 Artifact uses a composite version key and an invoker chain guard", () => {
  assert.match(
    migration,
    /CREATE TABLE aios_state\.aios_artifact[\s\S]*?PRIMARY KEY \(tenant_id, artifact_id, artifact_version\)/,
  );
  assert.match(
    migration,
    /CREATE FUNCTION aios_state\.enforce_artifact_version_chain\(\)[\s\S]*?SET search_path = pg_catalog, aios_state[\s\S]*?NEW\.artifact_version <> previous\.artifact_version \+ 1/,
  );
  const chainFunction = migration.match(
    /CREATE FUNCTION aios_state\.enforce_artifact_version_chain\(\)[\s\S]*?\$\$;/,
  )?.[0];
  assert.equal(typeof chainFunction, "string");
  assert.doesNotMatch(chainFunction, /SECURITY DEFINER/);
  assert.match(
    migration,
    /CREATE TRIGGER aios_artifact_version_chain_guard[\s\S]*?BEFORE INSERT ON aios_state\.aios_artifact[\s\S]*?EXECUTE FUNCTION aios_state\.enforce_artifact_version_chain\(\)/,
  );
  assert.match(
    roles,
    /ALTER TABLE aios_state\.aios_artifact OWNER TO aios_c08_owner/,
  );
  assert.match(
    roles,
    /ALTER FUNCTION aios_state\.enforce_artifact_version_chain\(\)\s+OWNER TO aios_c08_owner/,
  );
});

test("C08 Store uses serializable idempotency and fenced SKIP LOCKED leases", () => {
  assert.match(store, /BEGIN ISOLATION LEVEL SERIALIZABLE/);
  assert.match(store, /deriveCommandEffectKey/);
  assert.match(store, /command_receipt/);
  assert.match(store, /FOR UPDATE SKIP LOCKED/);
  assert.match(store, /lease_version=lease_version\+1/);
  assert.match(store, /AND lease_version=\$4/);
  assert.match(store, /issue_runtime_scope_signature/);
  assert.match(store, /acquire_runtime_fence/);
  assert.match(
    store,
    /set_config\('aios\.tenant_id',\s*\$1,\s*true\)/,
  );
  assert.match(store, /pg_has_role/);
  assert.match(store, /current_user/);
  assert.match(store, /session_user/);
  assert.match(store, /"57P01"/);
  assert.doesNotMatch(
    store,
    /row\.correlation_id\s*!==\s*metadata\.correlationId/,
  );
});

test("C08 requires a dedicated Outbox Worker pool and explicit time", () => {
  const runtimePool = { connect() {} };
  const scopePool = { connect() {} };
  const outboxPool = { connect() {} };

  assert.throws(
    () => createPostgresAiosStateStore({ runtimePool, scopePool }),
    (error) => error?.code === "INVALID_CONFIGURATION",
  );
  assert.throws(
    () =>
      createPostgresAiosStateStore({
        runtimePool,
        scopePool,
        outboxPool: runtimePool,
      }),
    (error) => error?.code === "INVALID_CONFIGURATION",
  );
  assert.doesNotThrow(() =>
    createPostgresAiosStateStore({
      runtimePool,
      scopePool,
      outboxPool,
    }),
  );
  assert.doesNotMatch(store, /outboxPool\s*=\s*runtimePool/);
  assert.match(store, /leaseExpiresAt/);
  assert.match(store, /receipt\.now/);
  assert.match(store, /retryAt/);
});

test("C08 command effect keys are stable and tenant-bound", () => {
  const input = {
    tenantId: "stn_01984910-3000-7000-8000-000000000001",
    commandKind: "START_RUN",
    idempotencyKey: "start-1",
  };
  const first = deriveCommandEffectKey(input);
  assert.match(first, /^sha256:[0-9a-f]{64}$/);
  assert.equal(deriveCommandEffectKey({ ...input }), first);
  assert.notEqual(
    deriveCommandEffectKey({
      ...input,
      tenantId: "stn_01984910-3000-7000-8000-000000000002",
    }),
    first,
  );
  assert.notEqual(
    deriveCommandEffectKey({ ...input, idempotencyKey: "start-2" }),
    first,
  );
});

test("C08 runtime roles are non-owner and NOBYPASSRLS", () => {
  for (const role of ["aios_c08_runtime", "aios_c08_outbox_worker"]) {
    assert.match(
      roles,
      new RegExp(
        `CREATE ROLE ${role}[\\s\\S]*?NOLOGIN[\\s\\S]*?NOSUPERUSER[\\s\\S]*?NOBYPASSRLS;`,
      ),
    );
  }
  assert.match(roles, /OWNER TO aios_c08_owner/);
  assert.match(
    roles,
    /GRANT SELECT, INSERT ON TABLE aios_state\.outbox\s+TO aios_c08_runtime/,
  );
  assert.doesNotMatch(
    roles,
    /GRANT [^;]*UPDATE[^;]*ON TABLE aios_state\.outbox\s+TO aios_c08_runtime/,
  );
  assert.match(
    roles,
    /GRANT SELECT, UPDATE ON TABLE aios_state\.outbox\s+TO aios_c08_outbox_worker/,
  );
  assert.match(
    roles,
    /GRANT SELECT, INSERT ON TABLE\s+aios_state\.aios_case,\s+aios_state\.aios_thread\s+TO aios_c08_runtime/,
  );
  assert.doesNotMatch(
    roles,
    /GRANT [^;]*UPDATE[^;]*ON TABLE\s+aios_state\.aios_case/,
  );
  assert.doesNotMatch(
    roles,
    /GRANT [^;]*UPDATE[^;]*ON TABLE\s+aios_state\.aios_thread/,
  );
  assert.doesNotMatch(
    roles,
    /OWNER TO aios_c08_(?:runtime|outbox_worker)/,
  );
  assert.doesNotMatch(roles, /GRANT DELETE|GRANT TRUNCATE/);
});
