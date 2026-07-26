import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function readJson(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

test("C13 Manifest schema is closed and permanently instructions-only in P1", async () => {
  const schema = await readJson(
    "implementation/p1/c13/skill-manifest.v1.schema.json",
  );
  assert.equal(schema.additionalProperties, false);
  assert.equal(
    schema.properties.executionMode.const,
    "INSTRUCTIONS_ONLY",
  );
  assert.equal(Object.hasOwn(schema.properties, "scripts"), false);
  assert.match(
    schema.properties.allowedTools.description,
    /never grant authorization/,
  );
});

test("C13 OpenAPI exposes only governed commands and Run resolution", async () => {
  const api = await readJson(
    "implementation/p1/c13/skill-registry.openapi.v1.json",
  );
  assert.deepEqual(Object.keys(api.paths).sort(), [
    "/v1/skill-registry/commands",
    "/v1/skill-registry/resolutions",
  ]);
  assert.equal(
    api.components.schemas.Resolution.properties.scriptsEnabled.const,
    false,
  );
  assert.equal(
    api.components.schemas.Resolution.properties
      .allowedToolsGrantAuthorization.const,
    false,
  );
});

test("C13 verification matrix covers every required acceptance boundary", async () => {
  const matrix = await readJson(
    "implementation/p1/c13/verification-matrix.v1.json",
  );
  assert.equal(matrix.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(matrix.rows.length, 7);
  const requirements = matrix.rows
    .map((row) => row.requirement)
    .join("\n");
  for (const term of [
    "canonical SHA-256",
    "withdrawal and rollback",
    "cannot resolve",
    "allowedTools",
    "commit-uncertain recovery",
    "FORCE RLS",
    "OCI, SBOM and signing deferred",
  ]) {
    assert.match(requirements, new RegExp(term));
  }
});

test("C13 SQL contract fixes migration names, FORCE RLS and no runtime DELETE", async () => {
  const core = await readFile(
    new URL(
      "../implementation/p1/c13/postgresql/0019_skill_registry.sql",
      import.meta.url,
    ),
    "utf8",
  );
  const roles = await readFile(
    new URL(
      "../implementation/p1/c13/postgresql/0020_skill_registry_runtime_roles.sql",
      import.meta.url,
    ),
    "utf8",
  );
  assert.equal((core.match(/FORCE ROW LEVEL SECURITY/g) ?? []).length, 4);
  assert.match(core, /skill_release_immutable_guard/);
  assert.match(core, /skill_channel_generation_guard/);
  assert.doesNotMatch(roles, /GRANT[^;]*DELETE/is);
  assert.match(
    roles,
    /CREATE ROLE aios_c13_runtime[\s\S]*NOBYPASSRLS;/,
  );
});

test("C13 evidence remains a candidate and makes no production claim", async () => {
  const evidence = await readJson(
    "implementation/p1/c13/c13-verification-evidence.candidate.v1.json",
  );
  assert.equal(evidence.verification_status, "VERIFIED_CANDIDATE");
  assert.equal(evidence.production_verification_status, "NOT_VERIFIED");
  assert.equal(evidence.source_state, "UNCOMMITTED_WORKTREE");
  assert.equal(evidence.verification_results.total_targeted_tests, 18);
  assert.equal(evidence.runtime_boundary.script_execution, "DISABLED");
  assert.equal(
    evidence.runtime_boundary.allowed_tools_grant_authorization,
    false,
  );
  assert.equal(evidence.runtime_boundary.enterprise_connectors, "C0_DISABLED");
});
