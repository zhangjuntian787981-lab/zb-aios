import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildFixtureInventory,
  checkPublicContextContainment,
  generateSyntheticTenants,
  scanProtectedSurface,
} from "../scripts/f02-fixtures.mjs";

const fixtureRoot = new URL("../implementation/p0/f02/", import.meta.url);

async function readJson(relativePath) {
  return JSON.parse(await readFile(new URL(relativePath, fixtureRoot), "utf8"));
}

function hashJson(value) {
  return `sha256:${createHash("sha256")
    .update(`${JSON.stringify(value, null, 2)}\n`)
    .digest("hex")}`;
}

function allFixtureRecords(fixture) {
  return [
    fixture,
    fixture.tenant,
    ...Object.values(fixture.records).flat(),
  ];
}

test("F02 generates exactly three deterministic synthetic tenants", async () => {
  const seedCatalog = await readJson("seed-catalog.v1.json");
  const first = generateSyntheticTenants();
  const second = generateSyntheticTenants();

  assert.equal(seedCatalog.seeds.length, 3);
  assert.equal(first.length, 3);
  assert.equal(new Set(first.map(({ seed_id }) => seed_id)).size, 3);
  assert.deepEqual(first, second);
  assert.deepEqual(
    first.map(hashJson),
    second.map(hashJson),
  );
  assert.deepEqual(
    first.map(({ seed_id }) => seed_id),
    seedCatalog.seeds.map(({ seed_id }) => seed_id),
  );
});

test("every fixture record is watermarked, uses .example identities, and has valid relations", () => {
  for (const fixture of generateSyntheticTenants()) {
    assert.ok(
      allFixtureRecords(fixture).every(
        (record) => record.watermark === "SYNTHETIC",
      ),
      fixture.fixture_id,
    );
    assert.equal(fixture.provenance.enterprise_data_used, false);
    assert.equal(fixture.tenant.domain.endsWith(".example"), true);
    assert.ok(
      fixture.records.users.every(({ email }) =>
        email.endsWith(`@${fixture.tenant.domain}`),
      ),
    );
    assert.ok(
      fixture.records.connector_responses.every(({ endpoint }) =>
        new URL(endpoint).hostname.endsWith(".example"),
      ),
    );

    const orgUnitIds = new Set(
      fixture.records.org_units.map(({ id }) => id),
    );
    const userIds = new Set(fixture.records.users.map(({ id }) => id));
    assert.ok(
      fixture.records.users.every(({ org_unit_id }) =>
        orgUnitIds.has(org_unit_id),
      ),
    );
    assert.ok(
      fixture.records.knowledge.every(({ visibility_org_unit_id }) =>
        orgUnitIds.has(visibility_org_unit_id),
      ),
    );
    assert.ok(
      fixture.records.permissions.every(({ subject_id }) =>
        userIds.has(subject_id),
      ),
    );
    assert.ok(
      fixture.records.workflows.every(({ owner_user_id }) =>
        userIds.has(owner_user_id),
      ),
    );
    assert.ok(
      fixture.records.metrics.every(({ org_unit_id }) =>
        orgUnitIds.has(org_unit_id),
      ),
    );
    assert.ok(
      fixture.records.connector_responses.every(({ requested_by_user_id }) =>
        userIds.has(requested_by_user_id),
      ),
    );
  }
});

test("generated fixtures pass the protected-surface rules and publish an exact inventory", async () => {
  const policy = await readJson("protected-surface-policy.v1.json");
  const fixtures = generateSyntheticTenants();
  const result = scanProtectedSurface({
    documents: fixtures.map((content) => ({
      path: `fixtures/${content.fixture_id}.json`,
      content,
    })),
    policy,
  });
  const inventory = await readJson("fixture-inventory.v1.json");

  assert.equal(result.status, "PASS");
  assert.equal(result.findings.length, 0);
  assert.match(result.assurance_limit, /does not prove/i);
  assert.deepEqual(buildFixtureInventory(fixtures), inventory);
});

test("credential, missing-watermark, and forbidden-identifier controls all fail closed", async () => {
  const policy = await readJson("protected-surface-policy.v1.json");
  const cases = [
    ["negative/credential.json", "CREDENTIAL_KEY"],
    ["negative/unwatermarked.json", "MISSING_SYNTHETIC_WATERMARK"],
    ["negative/forbidden-identifier.json", "FORBIDDEN_ENTERPRISE_IDENTIFIER"],
  ];

  for (const [relativePath, expectedCode] of cases) {
    const result = scanProtectedSurface({
      documents: [{ path: relativePath, content: await readJson(relativePath) }],
      policy,
    });

    assert.equal(result.status, "BLOCKED", relativePath);
    assert.ok(
      result.findings.some(({ code }) => code === expectedCode),
      `${relativePath}: ${expectedCode}`,
    );
    assert.match(result.assurance_limit, /does not prove/i);
  }
});

test("public context is valid only in its independent registry and is blocked from a package", async () => {
  const registry = await readJson("public-context-registry/registry.sample.json");
  const registryRoot = new URL("public-context-registry/", fixtureRoot);
  const temporaryRoot = await mkdtemp(
    path.join(os.tmpdir(), "f02-containment-"),
  );
  const packageRoot = path.join(temporaryRoot, "product-package");

  try {
    await mkdir(packageRoot);
    await writeFile(
      path.join(packageRoot, "manifest.json"),
      `${JSON.stringify({ name: "synthetic-product-package" }, null, 2)}\n`,
    );

    const pass = await checkPublicContextContainment({
      registry,
      registryRoot,
      packageRoot,
    });
    assert.equal(pass.status, "PASS");
    assert.equal(pass.findings.length, 0);
    assert.match(pass.assurance_limit, /does not prove/i);

    await writeFile(
      path.join(packageRoot, "leak.txt"),
      `${registry.entries[0].id}\nPUBLIC_EXTERNAL_CONTEXT\n`,
    );
    const blocked = await checkPublicContextContainment({
      registry,
      registryRoot,
      packageRoot,
    });
    assert.equal(blocked.status, "BLOCKED");
    assert.ok(
      blocked.findings.some(
        ({ code }) => code === "PUBLIC_CONTEXT_IN_PRODUCT_PACKAGE",
      ),
    );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("committed reports show a passing protected scan and registry containment check", async () => {
  const protectedReport = await readJson(
    "reports/protected-surface-scan.sample.json",
  );
  const containmentReport = await readJson(
    "reports/public-context-containment.sample.json",
  );

  assert.equal(protectedReport.status, "PASS");
  assert.equal(containmentReport.status, "PASS");
  assert.match(protectedReport.assurance_limit, /does not prove/i);
  assert.match(containmentReport.assurance_limit, /does not prove/i);
});

test("the generator has no environment-secret input path", async () => {
  const source = await readFile(
    new URL("../scripts/f02-fixtures.mjs", import.meta.url),
    "utf8",
  );

  assert.equal(source.includes("process.env"), false);
});
