import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const isolationMigration = await readFile(
  new URL(
    "../implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
    import.meta.url,
  ),
  "utf8",
);
const roleMigration = await readFile(
  new URL(
    "../implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    import.meta.url,
  ),
  "utf8",
);
const postgresAdapter = await readFile(
  new URL("../lib/postgres-tenant-data-adapter.mjs", import.meta.url),
  "utf8",
);

test("the C07 migration makes tenant_id and FORCE RLS mandatory", () => {
  assert.match(
    isolationMigration,
    /CREATE EXTENSION(?: IF NOT EXISTS)? vector/,
  );
  assert.match(
    isolationMigration,
    /CREATE EXTENSION(?: IF NOT EXISTS)? pgcrypto/,
  );
  assert.match(isolationMigration, /\bembedding\s+vector\s+NOT NULL/);
  assert.match(isolationMigration, /\bvector_dims\s*\(\s*embedding\s*\)/);
  assert.equal(
    (isolationMigration.match(/\btenant_id\b/g) ?? []).length >= 12,
    true,
  );

  const enabled =
    isolationMigration.match(/ENABLE ROW LEVEL SECURITY/g) ?? [];
  const forced =
    isolationMigration.match(/FORCE ROW LEVEL SECURITY/g) ?? [];
  assert.equal(enabled.length, 6);
  assert.equal(forced.length, enabled.length);
  assert.match(
    roleMigration,
    /CREATE POLICY[\s\S]*USING\s*\([\s\S]*runtime_scope_allows[\s\S]*WITH CHECK\s*\([\s\S]*runtime_scope_allows/,
  );
  assert.match(
    isolationMigration,
    /runtime_scope_allows[\s\S]*current_setting\('aios\.tenant_id',\s*true\)/,
  );
  assert.match(
    isolationMigration,
    /issue_runtime_scope_signature[\s\S]*public\.hmac/,
  );
  assert.match(
    isolationMigration,
    /payload\s*:=\s*jsonb_build_array\(/,
  );
  assert.doesNotMatch(isolationMigration, /concat_ws\s*\(/);
  assert.match(
    isolationMigration,
    /scope_tenant_id IS NULL[\s\S]*scope_nonce IS NULL/,
  );
  assert.match(
    isolationMigration,
    /scope\.backend_pid[\s\S]*pg_backend_pid\(\)[\s\S]*scope\.transaction_id[\s\S]*pg_current_xact_id\(\)/,
  );
  assert.match(
    isolationMigration,
    /CREATE FUNCTION aios_data\.acquire_runtime_fence\(\)[\s\S]*FOR SHARE/,
  );
});

test("C07 runtime roles are non-owner NOBYPASSRLS roles", () => {
  assert.match(
    roleMigration,
    /CREATE ROLE aios_c07_owner[\s\S]*NOLOGIN/,
  );
  for (const role of [
    "aios_c07_lifecycle_runtime",
    "aios_c07_data_runtime",
    "aios_c07_restore_runtime",
    "aios_c07_scope_runtime",
  ]) {
    assert.match(
      roleMigration,
      new RegExp(
        `CREATE ROLE ${role}[\\s\\S]*?NOLOGIN[\\s\\S]*?NOSUPERUSER[\\s\\S]*?NOBYPASSRLS;`,
      ),
    );
  }
  assert.match(roleMigration, /OWNER TO aios_c07_owner/);
  assert.doesNotMatch(
    roleMigration,
    /OWNER TO aios_c07_(?:lifecycle|data)_runtime/,
  );
  assert.match(
    roleMigration,
    /GRANT SELECT ON[\s\S]*TO aios_c07_restore_runtime/,
  );
  const restoreStatements = roleMigration
    .split(";")
    .filter((statement) => statement.includes("aios_c07_restore_runtime"));
  assert.equal(
    restoreStatements.some((statement) =>
      /GRANT\s+(?:INSERT|UPDATE|DELETE|TRUNCATE)/.test(statement),
    ),
    false,
  );
});

test("the PostgreSQL Adapter scopes every pooled transaction locally", () => {
  assert.match(postgresAdapter, /BEGIN/);
  assert.match(postgresAdapter, /COMMIT/);
  assert.match(postgresAdapter, /ROLLBACK/);
  assert.match(
    postgresAdapter,
    /set_config\('aios\.tenant_id',\s*\$1,\s*true\)/,
  );
  assert.match(postgresAdapter, /issue_runtime_scope_signature/);
  assert.match(postgresAdapter, /acquire_runtime_fence/);
  assert.match(postgresAdapter, /pg_has_role/);
  assert.match(postgresAdapter, /current_user/);
  assert.match(postgresAdapter, /session_user/);
  assert.match(postgresAdapter, /aios_c07_scope_runtime/);
  assert.match(postgresAdapter, /aios_c07_restore_runtime/);
  assert.match(
    postgresAdapter,
    /Read-only PostgreSQL endpoint cannot project lifecycle events/,
  );
  assert.match(
    postgresAdapter,
    /Read-only PostgreSQL endpoint cannot expose control snapshots/,
  );
  assert.match(
    postgresAdapter,
    /set_config\('aios\.tenant_kind',\s*\$2,\s*true\)/,
  );
  assert.match(
    postgresAdapter,
    /set_config\('aios\.lifecycle_version',\s*\$3,\s*true\)/,
  );
  assert.match(
    postgresAdapter,
    /set_config\('aios\.correlation_id',\s*\$4,\s*true\)/,
  );
  assert.doesNotMatch(
    postgresAdapter,
    /SET\s+(?:SESSION\s+)?aios\.tenant_id/i,
  );
});
