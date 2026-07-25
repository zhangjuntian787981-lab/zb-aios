import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createSyntheticPrincipalCatalog,
} from "../lib/stable-principal.mjs";

const principalCatalogUrl = new URL(
  "../implementation/p1/c05/synthetic-principal-catalog.v1.json",
  import.meta.url,
);
const identityCatalogUrl = new URL(
  "../implementation/p1/c04/synthetic-identity-catalog.v1.json",
  import.meta.url,
);
const inventoryUrl = new URL(
  "../implementation/p0/f02/fixture-inventory.v1.json",
  import.meta.url,
);

async function readJson(url) {
  return JSON.parse(await readFile(url, "utf8"));
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
    .join(",")}}`;
}

test("the C05 catalog covers exactly the three frozen F02 Synthetic Tenants", async () => {
  const [entries, inventory] = await Promise.all([
    readJson(principalCatalogUrl),
    readJson(inventoryUrl),
  ]);

  assert.equal(entries.length, 3);
  assert.deepEqual(
    entries.map(({ fixtureId }) => fixtureId).sort(),
    inventory.fixtures.map(({ fixture_id: fixtureId }) => fixtureId).sort(),
  );
  for (const entry of entries) {
    assert.deepEqual(Object.keys(entry).sort(), [
      "fixtureId",
      "identityCorrections",
      "principals",
      "sha256",
    ]);
  }
  assert.doesNotThrow(() => createSyntheticPrincipalCatalog(entries));
});

test("each Synthetic Tenant has three HUMAN, one AGENT and one SERVICE principal", async () => {
  const entries = await readJson(principalCatalogUrl);

  for (const entry of entries) {
    assert.equal(entry.principals.length, 5);
    assert.deepEqual(
      entry.principals
        .map(({ principalType }) => principalType)
        .sort(),
      ["AGENT", "HUMAN", "HUMAN", "HUMAN", "SERVICE"],
    );
    for (const principal of entry.principals) {
      assert.deepEqual(Object.keys(principal).sort(), [
        "fixturePrincipalRef",
        "identityProfileRefs",
        "principalType",
      ]);
      if (principal.principalType === "HUMAN") {
        assert.equal(principal.identityProfileRefs.length > 0, true);
      } else {
        assert.deepEqual(principal.identityProfileRefs, []);
      }
    }
  }
});

test("every current C04 profile is explicitly assigned to one HUMAN principal", async () => {
  const [principalEntries, identityEntries] = await Promise.all([
    readJson(principalCatalogUrl),
    readJson(identityCatalogUrl),
  ]);

  for (const identityEntry of identityEntries) {
    const principalEntry = principalEntries.find(
      ({ fixtureId }) => fixtureId === identityEntry.fixtureId,
    );
    const assignments = new Map();
    for (const principal of principalEntry.principals) {
      for (const profileRef of principal.identityProfileRefs) {
        assert.equal(assignments.has(profileRef), false);
        assignments.set(profileRef, principal);
      }
    }
    for (const user of identityEntry.users) {
      const principal = assignments.get(user.profileRef);
      assert.equal(principal?.principalType, "HUMAN");
    }
  }
});

test("the northstar Ava fixture has an explicit migrated identity profile", async () => {
  const entries = await readJson(principalCatalogUrl);
  const northstar = entries.find(
    ({ fixtureId }) => fixtureId === "synthetic-tenant-northstar-fasteners",
  );
  const ava = northstar.principals.find(
    ({ fixturePrincipalRef }) =>
      fixturePrincipalRef ===
      "fixture://synthetic-tenant-northstar-fasteners/principals/ava",
  );

  assert.deepEqual(ava.identityProfileRefs, [
    "fixture://synthetic-tenant-northstar-fasteners/users/northstar-fasteners-user-ava",
    "synthetic://identity-migration/northstar-fasteners/ava/idp-v2",
  ]);
});

test("every frozen identity correction hash binds its exact mapping", async () => {
  const entries = await readJson(principalCatalogUrl);

  for (const entry of entries) {
    for (const correction of entry.identityCorrections) {
      assert.deepEqual(Object.keys(correction).sort(), [
        "correctionRef",
        "identityProfileRef",
        "mappingHash",
        "sourceFixturePrincipalRef",
        "targetFixturePrincipalRef",
      ]);
      const { mappingHash, ...mapping } = correction;
      const actual =
        `sha256:${createHash("sha256")
          .update(canonicalize(mapping))
          .digest("hex")}`;
      assert.equal(mappingHash, actual);
    }
  }
});

test("the C05 catalog contains no inferred identity or business authorization fields", async () => {
  const entries = await readJson(principalCatalogUrl);
  const serialized = JSON.stringify(entries);

  assert.doesNotMatch(
    serialized,
    /"(?:email|name|role|roles|group|groups|permission|permissions|scope|scopes)"\s*:/i,
  );
});

test("the catalog rejects HUMAN principals without an explicit identity profile", async () => {
  const entries = await readJson(principalCatalogUrl);
  entries[0].principals[0].identityProfileRefs = [];

  assert.throws(
    () => createSyntheticPrincipalCatalog(entries),
    (error) => error.code === "INVALID_PRINCIPAL_CATALOG",
  );
});

test("the catalog rejects identity profiles on AGENT or SERVICE principals", async () => {
  const entries = await readJson(principalCatalogUrl);
  const agent = entries[0].principals.find(
    ({ principalType }) => principalType === "AGENT",
  );
  agent.identityProfileRefs = ["synthetic://invalid/agent-login"];

  assert.throws(
    () => createSyntheticPrincipalCatalog(entries),
    (error) => error.code === "INVALID_PRINCIPAL_CATALOG",
  );
});

test("the catalog rejects one identity profile assigned to two principals", async () => {
  const entries = await readJson(principalCatalogUrl);
  entries[0].principals[1].identityProfileRefs = [
    entries[0].principals[0].identityProfileRefs[0],
  ];

  assert.throws(
    () => createSyntheticPrincipalCatalog(entries),
    (error) => error.code === "INVALID_PRINCIPAL_CATALOG",
  );
});
