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
  assert.deepEqual(
    api.components.schemas.ApproveRelease.required.slice(-4),
    [
      "approvedEvaluationReportRef",
      "approvedEvaluationReportSha256",
      "approvedHumanBaselineDecisionRef",
      "approvedHumanBaselineDecisionSha256",
    ],
  );
  assert.equal(
    api.components.schemas.EvaluationReport.$ref,
    "./evaluation-report.v1.schema.json",
  );
  assert.deepEqual(
    api.components.schemas.RollbackChannel.properties
      .expectedCurrentReleaseId.type,
    ["string", "null"],
  );
});

test("C13 EvaluationReport schema is closed and binds all approval evidence", async () => {
  const schema = await readJson(
    "implementation/p1/c13/evaluation-report.v1.schema.json",
  );
  assert.equal(schema.additionalProperties, false);
  for (const field of [
    "tenantId",
    "skillName",
    "skillVersion",
    "releaseDigest",
    "suiteId",
    "suiteSha256",
    "humanBaselineDecisionRef",
    "humanBaselineDecisionSha256",
    "reportRef",
    "reportSha256",
    "caseResults",
  ]) {
    assert.equal(schema.required.includes(field), true);
  }
  assert.equal(
    schema.$defs.caseResult.additionalProperties,
    false,
  );
});

test("C13 verification matrix covers every required acceptance boundary", async () => {
  const matrix = await readJson(
    "implementation/p1/c13/verification-matrix.v1.json",
  );
  assert.equal(matrix.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(matrix.rows.length, 9);
  const requirements = matrix.rows
    .map((row) => row.requirement)
    .join("\n");
  for (const term of [
    "canonical SHA-256",
    "withdrawal and rollback",
    "Validated F04 human baseline",
    "BLOCKED before FAIL before PASS",
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
  assert.match(
    core,
    /OLD\.static_report IS NOT NULL[\s\S]*OLD\.static_report IS DISTINCT FROM NEW\.static_report/,
  );
  assert.match(
    core,
    /OLD\.evaluation_suite_id IS NOT NULL[\s\S]*OLD\.evaluation_suite_sha256[\s\S]*NEW\.evaluation_suite_sha256/,
  );
  assert.match(
    core,
    /OLD\.evaluation_report IS NOT NULL[\s\S]*OLD\.evaluation_report IS DISTINCT FROM NEW\.evaluation_report/,
  );
  assert.match(core, /skill_channel_generation_guard/);
  assert.doesNotMatch(roles, /GRANT[^;]*DELETE/is);
  assert.match(
    roles,
    /CREATE ROLE aios_c13_runtime[\s\S]*NOBYPASSRLS;/,
  );
});
