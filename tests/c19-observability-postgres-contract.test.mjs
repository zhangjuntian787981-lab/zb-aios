import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  ObservabilityError,
} from "../lib/c19-observability.mjs";
import {
  createPostgresObservabilityStore,
} from "../lib/c19-observability-postgres-store.mjs";

const schemaSql = await readFile(
  new URL(
    "../implementation/p1/c19/postgresql/0033_observability_usage.sql",
    import.meta.url,
  ),
  "utf8",
);
const rolesSql = await readFile(
  new URL(
    "../implementation/p1/c19/postgresql/0034_observability_runtime_roles.sql",
    import.meta.url,
  ),
  "utf8",
);

test("C19 PostgreSQL migrations force RLS and separate exact runtime roles", () => {
  assert.equal(
    (
      schemaSql.match(
        /ALTER TABLE aios_observability\.[a-z_]+\s+FORCE ROW LEVEL SECURITY/g,
      ) ?? []
    ).length,
    4,
  );
  for (const role of [
    "aios_c19_owner",
    "aios_c19_writer",
    "aios_c19_reader",
  ]) {
    assert.match(rolesSql, new RegExp(`CREATE ROLE ${role}`));
  }
  assert.match(schemaSql, /usage_ledger_append_only/);
  assert.match(schemaSql, /quota_reservation_transition/);
  assert.match(schemaSql, /quota_account_balance_deferred/);
  assert.match(schemaSql, /state IN \('RESERVED', 'SETTLED', 'RELEASED'\)/);
  assert.match(
    schemaSql,
    /event_type IN \(\s*'QUOTA_RESERVED',\s*'QUOTA_RELEASED',\s*'USAGE_SETTLED'\s*\)/,
  );
  assert.match(
    schemaSql,
    /UNIQUE \(tenant_id, reservation_id, event_type\)/,
  );
  assert.match(
    schemaSql,
    /meter_key text[\s\S]*supplier_cost_micros bigint[\s\S]*variance_micros bigint/,
  );
  assert.match(
    schemaSql,
    /trace_id ~ '\^\[0-9a-f\]\{32\}\$'[\s\S]*trace_id <> repeat\('0', 32\)/,
  );
  assert.doesNotMatch(schemaSql, /\b(?:jsonb|body|prompt|credential)\b/i);
});

test("C19 PostgreSQL store rejects shared privilege pools", () => {
  const pool = { connect() {} };
  assert.throws(
    () =>
      createPostgresObservabilityStore({
        writerPool: pool,
        readerPool: pool,
        scopePool: pool,
      }),
    (error) =>
      error instanceof ObservabilityError &&
      error.code === "INVALID_CONFIGURATION",
  );
});
