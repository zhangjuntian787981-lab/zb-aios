import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createSyntheticIdentityCatalog,
} from "../lib/identity-federation.mjs";

const rootUrl = new URL("../", import.meta.url);
const catalogUrl = new URL(
  "../implementation/p1/c04/synthetic-identity-catalog.v1.json",
  import.meta.url,
);
const inventoryUrl = new URL(
  "../implementation/p0/f02/fixture-inventory.v1.json",
  import.meta.url,
);

test("the C04 catalog covers exactly the frozen F02 Synthetic Tenants", async () => {
  const catalogEntries = JSON.parse(await readFile(catalogUrl, "utf8"));
  const inventory = JSON.parse(await readFile(inventoryUrl, "utf8"));
  const catalog = createSyntheticIdentityCatalog(catalogEntries);

  assert.equal(catalogEntries.length, 3);
  assert.deepEqual(
    catalogEntries.map(({ fixtureId }) => fixtureId).sort(),
    inventory.fixtures.map(({ fixture_id: fixtureId }) => fixtureId).sort(),
  );

  for (const fixture of inventory.fixtures) {
    const resolved = catalog.resolveFixture({
      fixtureId: fixture.fixture_id,
      sha256: fixture.sha256,
    });
    assert.equal(resolved.provider.clientId, "synthetic-aios-portal");
    assert.deepEqual(resolved.provider.upstreamProtocols, ["OIDC"]);
    assert.match(resolved.provider.issuer, /^https:\/\/idp\.[a-z0-9-]+\.example\//);
  }
});

test("every C04 subject comes from its matching F02 user record", async () => {
  const catalogEntries = JSON.parse(await readFile(catalogUrl, "utf8"));

  for (const entry of catalogEntries) {
    const fixture = JSON.parse(
      await readFile(
        new URL(
          `implementation/p0/f02/generated/${entry.fixtureId}.json`,
          rootUrl,
        ),
        "utf8",
      ),
    );
    const fixtureUserIds = new Set(
      fixture.records.users.map(({ id }) => id),
    );

    assert.equal(entry.users.length, fixtureUserIds.size);
    for (const user of entry.users) {
      assert.equal(fixtureUserIds.has(user.fixtureUserId), true);
      assert.equal(user.loginSubject, user.fixtureUserId);
      assert.equal(user.profileRef.startsWith("fixture://"), true);
      assert.equal("email" in user, false);
      assert.equal("password" in user, false);
    }
  }
});

test("a synthetic provider catalog must start at configuration version one", async () => {
  const catalogEntries = JSON.parse(await readFile(catalogUrl, "utf8"));
  catalogEntries[0].provider.configurationVersion = 2;

  assert.throws(
    () => createSyntheticIdentityCatalog(catalogEntries),
    (error) => error.code === "INVALID_IDENTITY_CATALOG",
  );
});
