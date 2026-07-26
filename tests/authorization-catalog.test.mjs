import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  AuthorizationError,
  buildSyntheticPolicyTuples,
  createSyntheticAuthorizationCatalog,
  hashSyntheticPolicyTuples,
} from "../lib/authorization-facade.mjs";

async function load(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

async function catalog() {
  return createSyntheticAuthorizationCatalog({
    policyCatalog: await load(
      "implementation/p1/c06/synthetic-policy-catalog.v1.json",
    ),
    protectedOperations: await load(
      "implementation/p1/c06/protected-operations.v1.json",
    ),
    fixtures: await load(
      "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
    ),
    model: await load(
      "implementation/p1/c06/openfga/authorization-model.v1.json",
    ),
  });
}

const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const AVA_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const NOAH_ID = "prn_018f0000-0000-7000-8000-000000000003";
const PRINCIPALS = {
  [`fixture://${FIXTURE_ID}/principals/ava`]: AVA_ID,
  [`fixture://${FIXTURE_ID}/principals/assistant-agent`]: ACTOR_ID,
  [`fixture://${FIXTURE_ID}/principals/noah`]: NOAH_ID,
};

test("C06 freezes exactly six protected operations and 60 fixture cases", async () => {
  const value = await catalog();
  const fixtures = value.fixtures();
  const surfaces = [
    "READ",
    "RETRIEVE",
    "DOWNLOAD",
    "MANAGE",
    "TOOL_CALL",
    "SANDBOX_RUN",
  ];

  assert.equal(fixtures.operations.length * fixtures.scenarios.length, 60);
  assert.equal(fixtures.fixture_case_count, 60);
  assert.deepEqual(
    surfaces.map((surface) => value.operation(surface).surface),
    surfaces,
  );
  assert.deepEqual(
    new Set(fixtures.operations.map(({ tenant_fixture_id }) => tenant_fixture_id)),
    new Set([
      "synthetic-tenant-northstar-fasteners",
      "synthetic-tenant-blue-harbor-tools",
      "synthetic-tenant-cedar-field-components",
    ]),
  );
});

test("the baseline and migration templates build immutable 18 and 19 tuple bundles", async () => {
  const value = await catalog();
  const baseline = buildSyntheticPolicyTuples({
    catalog: value,
    templateRef: "fixture://c06/policy-release/baseline-v1",
    fixtureId: FIXTURE_ID,
    principalIdsByFixtureRef: PRINCIPALS,
  });
  const migration = buildSyntheticPolicyTuples({
    catalog: value,
    templateRef: "fixture://c06/policy-release/noah-read-v2",
    fixtureId: FIXTURE_ID,
    principalIdsByFixtureRef: PRINCIPALS,
  });

  assert.equal(baseline.length, 18);
  assert.equal(migration.length, 19);
  assert.equal(
    new Set(
      baseline.map(({ user, relation, object }) => `${user}|${relation}|${object}`),
    ).size,
    18,
  );
  assert.equal(
    baseline.some(({ user }) => user === `human:${NOAH_ID}`),
    false,
  );
  assert.equal(
    migration.some(
      ({ user, relation }) =>
        user === `human:${NOAH_ID}` && relation === "human_can_read",
    ),
    true,
  );
  assert.equal(
    baseline.some(({ user }) => user.includes("@") || user.includes("email")),
    false,
  );
  assert.equal(
    hashSyntheticPolicyTuples(baseline),
    "sha256:303d1010fabf45f5149303fa53731380c0aa21f3ec8255726422e3dbee1ac689",
  );
  assert.equal(
    hashSyntheticPolicyTuples(migration),
    "sha256:1f85e708a40f78a45d3d96212c3d4d27702d57a41cb661cc28797ab17d6f6e02",
  );
  assert.equal(
    hashSyntheticPolicyTuples([...baseline].reverse()),
    hashSyntheticPolicyTuples(baseline),
  );
  assert.notEqual(
    hashSyntheticPolicyTuples(baseline),
    value.template("fixture://c06/policy-release/baseline-v1")
      .bundle_sha256,
  );
});

test("catalog artifacts remain Synthetic-only and reject unknown policy or surface", async () => {
  const value = await catalog();
  assert.throws(
    () => value.operation("ENTERPRISE_ADMIN"),
    (error) =>
      error instanceof AuthorizationError &&
      error.code === "UNKNOWN_SURFACE",
  );
  assert.throws(
    () => value.template("fixture://c06/policy-release/unfrozen"),
    (error) =>
      error instanceof AuthorizationError &&
      error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
  const serialized = JSON.stringify({
    templates: value.listTemplates(),
    fixtures: value.fixtures(),
  });
  for (const connector of ["OA", "U9", "BI", "ENTERPRISE"]) {
    assert.equal(serialized.includes(`"${connector}"`), false);
  }
});

test("a policy template hash cannot be detached from its frozen definition", async () => {
  const [policyCatalog, protectedOperations, fixtures, model] =
    await Promise.all([
      load("implementation/p1/c06/synthetic-policy-catalog.v1.json"),
      load("implementation/p1/c06/protected-operations.v1.json"),
      load(
        "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
      ),
      load("implementation/p1/c06/openfga/authorization-model.v1.json"),
    ]);
  policyCatalog.release_templates[0].migration_expectation = "ALLOW";

  assert.throws(
    () =>
      createSyntheticAuthorizationCatalog({
        policyCatalog,
        protectedOperations,
        fixtures,
        model,
      }),
    { code: "INVALID_POLICY_CATALOG" },
  );
});
