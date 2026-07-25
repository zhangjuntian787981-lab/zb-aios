import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const schemaUrl = new URL(
  "../implementation/p1/c05/postgresql/0007_stable_principal.sql",
  import.meta.url,
);
const rolesUrl = new URL(
  "../implementation/p1/c05/postgresql/0008_principal_runtime_roles.sql",
  import.meta.url,
);
const apiUrl = new URL(
  "../implementation/p1/c05/stable-principal.openapi.v1.json",
  import.meta.url,
);
const coreUrl = new URL("../lib/stable-principal.mjs", import.meta.url);

const schemaSql = await readFile(schemaUrl, "utf8");
const rolesSql = await readFile(rolesUrl, "utf8");
const api = JSON.parse(await readFile(apiUrl, "utf8"));
const core = await readFile(coreUrl, "utf8");

test("C05 creates exactly the six frozen persistence tables", () => {
  const tables = [
    "principal_registry",
    "principal_identity_link",
    "principal_delegation",
    "principal_command_receipt",
    "principal_event",
    "principal_outbox",
  ];

  for (const table of tables) {
    assert.match(
      schemaSql,
      new RegExp(`CREATE TABLE aios_core\\.${table}`),
    );
  }
  assert.equal(
    Array.from(
      schemaSql.matchAll(/CREATE TABLE aios_core\.principal_/g),
    ).length,
    tables.length,
  );
});

test("principal identifiers and lifecycle are stable and monotonic", () => {
  assert.match(schemaSql, /principal_id ~ '\^prn_/);
  assert.match(schemaSql, /identity_link_id ~ '\^lnk_/);
  assert.match(schemaSql, /delegation_id ~ '\^dlg_/);
  assert.match(
    schemaSql,
    /state IN \('ACTIVE', 'SUSPENDED', 'DEACTIVATED'\)/,
  );
  assert.match(
    schemaSql,
    /OLD\.state = 'ACTIVE'[\s\S]*NEW\.state IN \('SUSPENDED', 'DEACTIVATED'\)/,
  );
  assert.match(
    schemaSql,
    /OLD\.state = 'SUSPENDED'[\s\S]*NEW\.state IN \('ACTIVE', 'DEACTIVATED'\)/,
  );
  assert.match(schemaSql, /principal_registry_terminal_guard/);
  assert.match(
    schemaSql,
    /NEW\.state = OLD\.state[\s\S]*NEW\.lifecycle_version <> OLD\.lifecycle_version[\s\S]*NEW\.security_epoch <> OLD\.security_epoch \+ 1/,
  );
  assert.match(
    schemaSql,
    /NEW\.state IN \('SUSPENDED', 'DEACTIVATED'\)[\s\S]*NEW\.lifecycle_version <> OLD\.lifecycle_version \+ 1[\s\S]*NEW\.security_epoch <> OLD\.security_epoch \+ 1/,
  );
  assert.match(schemaSql, /principal_registry_no_delete/);
  assert.match(
    schemaSql,
    /enforce_principal_registry_insert\(\)[\s\S]*FROM aios_core\.tenant_registry[\s\S]*FOR SHARE[\s\S]*principal_tenant_active_guard/,
  );
  assert.match(
    schemaSql,
    /OLD\.state = 'SUSPENDED' AND NEW\.state = 'ACTIVE'[\s\S]*FROM aios_core\.tenant_registry[\s\S]*FOR SHARE[\s\S]*principal_tenant_active_guard/,
  );
});

test("identity links bind the exact C04 account and one human principal", () => {
  const linkSql = schemaSql.slice(
    schemaSql.indexOf("CREATE TABLE aios_core.principal_identity_link"),
    schemaSql.indexOf("CREATE TABLE aios_core.principal_delegation"),
  );

  assert.match(linkSql, /principal_kind text NOT NULL CHECK \(principal_kind = 'HUMAN'\)/);
  assert.match(
    linkSql,
    /state IN \('ACTIVE', 'SUSPENDED', 'RETIRED'\)/,
  );
  assert.match(
    linkSql,
    /FOREIGN KEY \(\s*identity_account_id,\s*tenant_id,\s*tenant_kind,\s*provider_connection_id\s*\)[\s\S]*REFERENCES aios_core\.identity_account\(\s*account_id,\s*tenant_id,\s*tenant_kind,\s*provider_connection_id\s*\)/,
  );
  assert.match(
    linkSql,
    /FOREIGN KEY \(\s*principal_id,\s*tenant_id,\s*tenant_kind,\s*principal_kind\s*\)[\s\S]*REFERENCES aios_core\.principal_registry/,
  );
  assert.match(
    schemaSql,
    /principal_identity_link_current_account_key[\s\S]*WHERE state IN \('ACTIVE', 'SUSPENDED'\)/,
  );
  assert.match(schemaSql, /principal_identity_link_binding_guard/);
  assert.match(
    linkSql,
    /link_evidence_ref text NOT NULL[\s\S]*\^\(evidence\|fixture\|policy\|profile\|synthetic\|test\):\/\//,
  );
  assert.match(
    schemaSql,
    /NEW\.link_evidence_ref IS DISTINCT FROM OLD\.link_evidence_ref/,
  );
  assert.match(schemaSql, /principal_identity_link_account_state_guard/);
  assert.match(schemaSql, /principal_identity_link_principal_state_guard/);
  assert.match(
    schemaSql,
    /principal_state NOT IN \('ACTIVE', 'SUSPENDED'\)/,
  );
  assert.match(schemaSql, /principal_identity_link_terminal_guard/);
  assert.match(
    schemaSql,
    /enforce_principal_identity_link_insert\(\)[\s\S]*FROM aios_core\.tenant_registry[\s\S]*FOR SHARE[\s\S]*principal_tenant_active_guard/,
  );
  assert.match(
    schemaSql,
    /OLD\.state = 'ACTIVE' AND NEW\.state IN \('ACTIVE', 'SUSPENDED', 'RETIRED'\)/,
  );
  assert.match(
    schemaSql,
    /OLD\.state = 'SUSPENDED'[\s\S]*NEW\.state IN \('ACTIVE', 'SUSPENDED', 'RETIRED'\)/,
  );
  assert.match(
    schemaSql,
    /NEW\.state = OLD\.state[\s\S]*NEW\.account_lifecycle_version = OLD\.account_lifecycle_version[\s\S]*NEW\.account_revocation_epoch = OLD\.account_revocation_epoch/,
  );
});

test("delegations form an immutable tenant-local provenance chain", () => {
  const delegationSql = schemaSql.slice(
    schemaSql.indexOf("CREATE TABLE aios_core.principal_delegation"),
    schemaSql.indexOf("CREATE TABLE aios_core.principal_command_receipt"),
  );

  for (const column of [
    "human_subject_security_epoch",
    "delegator_security_epoch",
    "delegate_security_epoch",
  ]) {
    assert.match(delegationSql, new RegExp(`${column} bigint NOT NULL`));
  }
  assert.match(
    delegationSql,
    /delegate_kind text NOT NULL\s+CHECK \(delegate_kind IN \('AGENT', 'SERVICE'\)\)/,
  );
  assert.match(
    delegationSql,
    /parent_delegation_id IS NULL[\s\S]*delegator_principal_id = human_subject_principal_id[\s\S]*delegator_kind = 'HUMAN'/,
  );
  assert.match(delegationSql, /depth integer NOT NULL CHECK \(depth BETWEEN 1 AND 8\)/);
  assert.match(
    delegationSql,
    /parent_delegation_id IS NULL[\s\S]*depth = 1/,
  );
  assert.match(
    delegationSql,
    /expires_at timestamptz NOT NULL CHECK \(expires_at > created_at\)/,
  );
  assert.match(
    delegationSql,
    /state = 'ACTIVE'[\s\S]*revocation_reason_ref IS NULL[\s\S]*state = 'REVOKED'[\s\S]*revocation_reason_ref IS NOT NULL/,
  );
  assert.match(
    schemaSql,
    /COMMENT ON COLUMN aios_core\.principal_delegation\.provenance_ref[\s\S]*source purposeRef used only for provenance/,
  );
  assert.match(
    delegationSql,
    /CONSTRAINT principal_delegation_parent_fkey[\s\S]*FOREIGN KEY \(\s*parent_delegation_id,\s*tenant_id,\s*tenant_kind,\s*human_subject_principal_id,\s*human_subject_security_epoch,\s*delegator_principal_id,\s*delegator_kind,\s*delegator_security_epoch\s*\)/,
  );
  assert.match(
    delegationSql,
    /REFERENCES aios_core\.principal_delegation\(\s*delegation_id,\s*tenant_id,\s*tenant_kind,\s*human_subject_principal_id,\s*human_subject_security_epoch,\s*delegate_principal_id,\s*delegate_kind,\s*delegate_security_epoch\s*\)/,
  );
  assert.match(
    delegationSql,
    /parent_delegation_id <> delegation_id/,
  );
  assert.match(schemaSql, /principal_delegation_binding_guard/);
  assert.match(
    schemaSql,
    /enforce_principal_delegation_insert\(\)[\s\S]*FROM aios_core\.tenant_registry[\s\S]*FOR SHARE[\s\S]*principal_tenant_active_guard/,
  );
  assert.match(
    schemaSql,
    /NEW\.state <> 'ACTIVE'[\s\S]*NEW\.lifecycle_version <> 1[\s\S]*principal_delegation_initial_state_guard/,
  );
  assert.match(schemaSql, /principal_delegation_active_child_guard/);
  assert.match(schemaSql, /principal_delegation_subject_state_guard/);
  assert.match(schemaSql, /principal_delegation_delegator_state_guard/);
  assert.match(schemaSql, /principal_delegation_delegate_state_guard/);
  assert.match(schemaSql, /principal_delegation_parent_state_guard/);
  assert.match(
    schemaSql,
    /NEW\.depth <> parent_depth \+ 1[\s\S]*NEW\.expires_at > parent_expires_at[\s\S]*NEW\.provenance_ref <> parent_provenance_ref/,
  );
  assert.match(schemaSql, /principal_delegation_parent_bounds_guard/);
  assert.doesNotMatch(
    schemaSql,
    /UNIQUE[\s\S]{0,160}human_subject_principal_id[\s\S]{0,160}delegate_principal_id[\s\S]{0,80}WHERE state = 'ACTIVE'/,
  );
  assert.doesNotMatch(
    delegationSql,
    /depth BETWEEN 2 AND 8\s*\)\s*\)\s*,\s*\)\s*,/,
  );
  const delegatorGuard = schemaSql.slice(
    schemaSql.indexOf("delegation delegator is stale or inactive"),
    schemaSql.indexOf("SELECT state, security_epoch", schemaSql.indexOf(
      "delegation delegator is stale or inactive",
    )),
  );
  assert.equal(
    Array.from(delegatorGuard.matchAll(/\bEND IF;/g)).length,
    1,
  );
});

test("the C05 schema contains provenance, not business authorization policy", () => {
  const forbiddenColumns = [
    /^\s+email\s+/im,
    /^\s+display_name\s+/im,
    /^\s+employee_number\s+/im,
    /^\s+role\s+/im,
    /^\s+group\s+/im,
    /^\s+permission\s+/im,
    /^\s+scope\s+/im,
    /^\s+allow\s+/im,
    /^\s+deny\s+/im,
  ];

  for (const pattern of forbiddenColumns) {
    assert.doesNotMatch(schemaSql, pattern);
  }
});

test("Core, OpenAPI and PostgreSQL accept the same frozen reference schemes", () => {
  const schemes = "evidence|fixture|policy|profile|synthetic|test";

  assert.equal(
    api.components.schemas.SyntheticReference.pattern,
    `^(${schemes})://\\S+$`,
  );
  assert.match(
    core,
    new RegExp(
      `\\/\\^\\(\\?:${schemes.replaceAll("|", "\\|")}\\):\\\\\\/\\\\\\/\\\\S\\+\\$\\/`,
    ),
  );
  assert.equal(
    Array.from(
      schemaSql.matchAll(
        /\^\(evidence\|fixture\|policy\|profile\|synthetic\|test\):\/\//g,
      ),
    ).length >= 3,
    true,
  );
});

test("event and outbox records are exact, paired, and append-only", () => {
  assert.match(
    schemaSql,
    /CHECK \(\(event ->> 'id'\) IS NOT DISTINCT FROM event_id\)/,
  );
  assert.match(
    schemaSql,
    /CREATE CONSTRAINT TRIGGER principal_event_requires_outbox[\s\S]*DEFERRABLE INITIALLY DEFERRED/,
  );
  assert.match(
    schemaSql,
    /CREATE CONSTRAINT TRIGGER principal_outbox_requires_event[\s\S]*DEFERRABLE INITIALLY DEFERRED/,
  );
  assert.match(
    schemaSql,
    /paired_event IS DISTINCT FROM NEW\.event/,
  );
  assert.match(schemaSql, /principal_command_receipt_no_update/);
  assert.match(schemaSql, /principal_event_no_update/);
  assert.match(schemaSql, /principal_outbox_no_delete/);
  assert.match(schemaSql, /principal_outbox_payload_guard/);
  assert.match(schemaSql, /principal_outbox_attempt_lease_match/);
  assert.match(schemaSql, /principal_outbox_claim_guard/);
  assert.match(schemaSql, /principal_outbox_reclaim_guard/);
  assert.match(schemaSql, /principal_outbox_failure_guard/);
  assert.match(schemaSql, /principal_outbox_completion_guard/);
  assert.match(schemaSql, /principal_outbox_published_guard/);
});

test("C05 runtime roles are NOLOGIN and have only their frozen duties", () => {
  for (const role of [
    "aios_c05_core_runtime",
    "aios_c05_outbox_worker",
  ]) {
    assert.match(
      rolesSql,
      new RegExp(
        `CREATE ROLE ${role}[\\s\\S]*?NOLOGIN[\\s\\S]*?NOSUPERUSER[\\s\\S]*?NOCREATEDB[\\s\\S]*?NOCREATEROLE[\\s\\S]*?NOINHERIT[\\s\\S]*?NOREPLICATION[\\s\\S]*?NOBYPASSRLS;`,
      ),
    );
  }

  assert.match(
    rolesSql,
    /GRANT SELECT, INSERT, UPDATE ON TABLE[\s\S]*principal_registry,[\s\S]*principal_identity_link,[\s\S]*principal_delegation[\s\S]*TO aios_c05_core_runtime;/,
  );
  assert.match(
    rolesSql,
    /GRANT SELECT, INSERT ON TABLE[\s\S]*principal_command_receipt,[\s\S]*principal_event,[\s\S]*principal_outbox[\s\S]*TO aios_c05_core_runtime;/,
  );
  assert.match(
    rolesSql,
    /ALTER FUNCTION aios_core\.enforce_principal_identity_link_insert\(\)[\s\S]*SECURITY DEFINER;[\s\S]*SET search_path = pg_catalog, aios_core;/,
  );
  assert.match(
    rolesSql,
    /ALTER FUNCTION aios_core\.enforce_principal_identity_link_update\(\)[\s\S]*SECURITY DEFINER;[\s\S]*SET search_path = pg_catalog, aios_core;/,
  );
  for (const functionName of [
    "enforce_principal_registry_insert",
    "enforce_principal_registry_update",
    "enforce_principal_delegation_insert",
  ]) {
    assert.match(
      rolesSql,
      new RegExp(
        `ALTER FUNCTION aios_core\\.${functionName}\\(\\)[\\s\\S]*?SECURITY DEFINER;[\\s\\S]*?SET search_path = pg_catalog, aios_core;`,
      ),
    );
  }
  assert.doesNotMatch(
    rolesSql,
    /ON TABLE\s+aios_core\.identity_account/,
  );
  assert.doesNotMatch(
    rolesSql,
    /ON TABLE\s+aios_core\.tenant_registry/,
  );
  assert.match(
    rolesSql,
    /REVOKE ALL PRIVILEGES[\s\S]*ON FUNCTION aios_core\.enforce_principal_identity_link_insert\(\)[\s\S]*FROM PUBLIC, aios_c05_core_runtime, aios_c05_outbox_worker;/,
  );
  assert.match(
    rolesSql,
    /REVOKE ALL PRIVILEGES[\s\S]*ON FUNCTION aios_core\.enforce_principal_identity_link_update\(\)[\s\S]*FROM PUBLIC, aios_c05_core_runtime, aios_c05_outbox_worker;/,
  );
  assert.match(
    rolesSql,
    /GRANT SELECT, UPDATE ON TABLE\s+aios_core\.principal_outbox\s+TO aios_c05_outbox_worker;/,
  );
  assert.doesNotMatch(rolesSql, /\bGRANT\s+DELETE\b/i);
  assert.doesNotMatch(rolesSql, /\bGRANT\s+TRUNCATE\b/i);
  assert.match(
    rolesSql,
    /REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA aios_core FROM PUBLIC;/,
  );
});
