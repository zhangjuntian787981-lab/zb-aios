import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function load(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

const surfaces = [
  "READ",
  "RETRIEVE",
  "DOWNLOAD",
  "MANAGE",
  "TOOL_CALL",
  "SANDBOX_RUN",
];

test("the PEP coverage table maps every protected surface exactly once", async () => {
  const operations = await load(
    "implementation/p1/c06/protected-operations.v1.json",
  );
  const coverage = await load(
    "implementation/p1/c06/pep-coverage.v1.json",
  );

  assert.equal(operations.data_classification, "SYNTHETIC_ONLY");
  assert.equal(coverage.data_classification, "SYNTHETIC_ONLY");
  assert.deepEqual(
    operations.operations.map(({ surface }) => surface),
    surfaces,
  );
  assert.deepEqual(
    coverage.entries.map(({ surface }) => surface),
    surfaces,
  );
  assert.equal(new Set(coverage.entries.map(({ surface }) => surface)).size, 6);
  assert.equal(
    new Set(
      coverage.entries.map(({ representative_adapter }) =>
        representative_adapter,
      ),
    ).size,
    6,
  );
  for (const entry of coverage.entries) {
    assert.equal(
      entry.implementation_ref,
      "lib/synthetic-pep-adapters.mjs#createSyntheticPepAdapters",
    );
    assert.equal(
      entry.verification_test,
      "tests/synthetic-pep-adapters.test.mjs",
    );
  }
});

test("dependent consumers remain explicitly pending instead of being claimed as integrated", async () => {
  const coverage = await load(
    "implementation/p1/c06/pep-coverage.v1.json",
  );

  assert.deepEqual(
    coverage.entries.map(({ dependent_consumer }) => dependent_consumer),
    ["C01", "C11", "C01", "C02", "C16", "O01"],
  );
  for (const entry of coverage.entries) {
    assert.equal(
      entry.consumer_integration_status,
      "PENDING_DEPENDENT_PACKAGE",
    );
    for (const overclaim of ["IMPLEMENTED", "VERIFIED", "INTEGRATED"]) {
      assert.equal(entry.consumer_integration_status.includes(overclaim), false);
    }
  }
});

test("the frozen fixture matrix contains 60 cases across all six surfaces", async () => {
  const fixtures = await load(
    "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
  );

  assert.equal(fixtures.schema_version, "1.0.0");
  assert.equal(fixtures.data_classification, "SYNTHETIC_ONLY");
  assert.deepEqual(
    fixtures.operations.map(({ surface }) => surface),
    surfaces,
  );
  assert.equal(fixtures.operations.length, 6);
  assert.equal(fixtures.scenarios.length, 10);
  assert.equal(
    fixtures.operations.length * fixtures.scenarios.length,
    fixtures.fixture_case_count,
  );
  assert.equal(fixtures.fixture_case_count, 60);
  assert.equal(
    fixtures.scenarios.filter(({ expected }) => expected === "ALLOW").length,
    1,
  );
  assert.equal(
    fixtures.scenarios.filter(({ expected }) => expected === "DENY").length,
    9,
  );
});

test("each protected surface has three distinct factors and one purpose", async () => {
  const operations = await load(
    "implementation/p1/c06/protected-operations.v1.json",
  );

  for (const operation of operations.operations) {
    assert.equal(
      new Set([
        operation.human_relation,
        operation.actor_relation,
        operation.purpose_relation,
      ]).size,
      3,
    );
    assert.match(
      operation.purpose_ref,
      /^synthetic:\/\/c06\/purpose\/[a-z-]+$/,
    );
  }
});
