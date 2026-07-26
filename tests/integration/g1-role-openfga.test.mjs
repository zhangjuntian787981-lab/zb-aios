import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createG1RoleAuthorization } from "../../lib/g1-role-authorization.mjs";
import { createG1SyntheticRuntime } from "../../lib/g1-synthetic-runtime.mjs";
import { createOpenFgaPdp } from "../../lib/openfga-pdp.mjs";

const EXPECTED_VERSION = "v1.18.1";
const EXPECTED_SHA256 =
  "d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94";
const EXPECTED_ROLE_PROJECTION_SHA256 =
  "sha256:f191c356cf867f41fee45f71c3bae4142da314cb5b15fc3d1e30dce95b6e0058";
const SURFACES = [
  "SQL",
  "VECTOR",
  "FILE",
  "OBJECT",
  "SEARCH",
  "CACHE",
  "TOOL",
  "RESTORE_REPLICA",
];

if (process.env.G1_ROLE_OPENFGA_EPHEMERAL !== "1") {
  throw new Error("G1_ROLE_OPENFGA_EPHEMERAL=1 is required.");
}
if (!process.env.G1_ROLE_OPENFGA_BASE_URL) {
  throw new Error("G1_ROLE_OPENFGA_BASE_URL is required.");
}
if (process.env.G1_ROLE_OPENFGA_VERIFIED_VERSION !== EXPECTED_VERSION) {
  throw new Error("The locked OpenFGA version was not verified.");
}
if (process.env.G1_ROLE_OPENFGA_VERIFIED_SHA256 !== EXPECTED_SHA256) {
  throw new Error("The locked OpenFGA archive hash was not verified.");
}

async function load(relativePath) {
  return JSON.parse(
    await readFile(new URL(`../../${relativePath}`, import.meta.url), "utf8"),
  );
}

function createRealOpenFgaAdapter() {
  const tenants = new Map();
  const publishedModels = [];
  let actualCheckCount = 0;

  return {
    adapter: {
      async prepareTenant({ tenantId, model }) {
        const pdp = createOpenFgaPdp({
          baseUrl: process.env.G1_ROLE_OPENFGA_BASE_URL,
        });
        const provisioned = await pdp.provisionStore({
          name: `g1-role-${tenants.size + 1}`,
        });
        const published = await pdp.publishModel(model);
        const readback = await pdp.readAuthorizationModel({
          authorizationModelId: published.authorizationModelId,
        });
        assert.deepEqual(readback.model, model);
        tenants.set(tenantId, {
          pdp,
          storeId: provisioned.storeId,
          authorizationModelId: published.authorizationModelId,
        });
        publishedModels.push(readback);
        return {
          storeId: provisioned.storeId,
          authorizationModelId: published.authorizationModelId,
        };
      },
      async writeTuples({
        tenantId,
        storeId,
        authorizationModelId,
        tupleKeys,
      }) {
        const tenant = tenants.get(tenantId);
        assert.equal(tenant.storeId, storeId);
        assert.equal(
          tenant.authorizationModelId,
          authorizationModelId,
        );
        return tenant.pdp.writeTuples({
          authorizationModelId,
          tupleKeys,
        });
      },
      async check({
        tenantId,
        storeId,
        authorizationModelId,
        tupleKey,
      }) {
        const tenant = tenants.get(tenantId);
        assert.equal(tenant.storeId, storeId);
        assert.equal(
          tenant.authorizationModelId,
          authorizationModelId,
        );
        actualCheckCount += 1;
        return tenant.pdp.check({
          authorizationModelId,
          tupleKey,
        });
      },
    },
    observations() {
      return {
        actualCheckCount,
        publishedModelCount: publishedModels.length,
      };
    },
  };
}

test("locked real OpenFGA denies 72 owners only because their role mismatches", async () => {
  const lock = await load(
    "implementation/p1/c06/openfga/openfga-distribution.lock.json",
  );
  const policy = await load(
    "implementation/gates/g1/c06-role-policy.v2.json",
  );
  assert.equal(lock.version, EXPECTED_VERSION);
  assert.equal(lock.sha256, EXPECTED_SHA256);
  assert.equal(policy.openfga.version, EXPECTED_VERSION);

  const runtime = await createG1SyntheticRuntime();
  const deployment = await runtime.deploy();
  const openFga = createRealOpenFgaAdapter();
  const authorization = await createG1RoleAuthorization({
    deployment,
    c06: openFga.adapter,
  });
  let ownerAllowCount = 0;
  let wrongRoleDenyCount = 0;

  for (const tenant of deployment.tenants) {
    for (const [ownerIndex, owner] of tenant.users.entries()) {
      const wrongRoleSource =
        tenant.users[(ownerIndex + 1) % tenant.users.length];
      assert.notEqual(wrongRoleSource.role, owner.role);
      for (const surface of SURFACES) {
        const positiveResourceId =
          `${owner.fixtureUserId}-${surface.toLowerCase()}`;
        await authorization.registerResource({
          tenantId: tenant.tenantId,
          surface,
          resourceId: positiveResourceId,
          ownerSessionId: owner.sessionId,
          requiredRoleSessionId: owner.sessionId,
        });
        const ownerDecision = await authorization.authorize({
          tenantId: tenant.tenantId,
          surface,
          resourceId: positiveResourceId,
          sessionId: owner.sessionId,
        });
        const wrongRoleResourceId =
          `${positiveResourceId}-wrong-role`;
        await authorization.registerResource({
          tenantId: tenant.tenantId,
          surface,
          resourceId: wrongRoleResourceId,
          ownerSessionId: owner.sessionId,
          requiredRoleSessionId: wrongRoleSource.sessionId,
        });
        const wrongRoleDecision = await authorization.authorize({
          tenantId: tenant.tenantId,
          surface,
          resourceId: wrongRoleResourceId,
          sessionId: owner.sessionId,
        });
        assert.equal(ownerDecision.effect, "ALLOW");
        assert.equal(wrongRoleDecision.effect, "DENY");
        assert.equal(
          wrongRoleDecision.principalId,
          owner.principalId,
        );
        assert.equal(
          wrongRoleDecision.authoritativeRole,
          owner.role,
        );
        assert.equal(
          wrongRoleDecision.requiredRole,
          wrongRoleSource.role,
        );
        assert.equal(
          wrongRoleDecision.c06BoundaryEntered,
          true,
        );
        ownerAllowCount += 1;
        wrongRoleDenyCount += 1;
      }
    }
  }

  assert.equal(authorization.roleProjectionSha256, EXPECTED_ROLE_PROJECTION_SHA256);
  assert.equal(ownerAllowCount, 72);
  assert.equal(wrongRoleDenyCount, 72);
  assert.deepEqual(openFga.observations(), {
    actualCheckCount: 144,
    publishedModelCount: 3,
  });
  assert.deepEqual(authorization.evidence(), {
    schemaVersion: "g1-role-authorization-evidence.v2",
    roleProjectionSha256: EXPECTED_ROLE_PROJECTION_SHA256,
    projectedTenantCount: 3,
    projectedUserCount: 9,
    registeredResourceCount: 144,
    c06CheckCount: 144,
    c06AllowCount: 72,
    c06DenyCount: 72,
  });
});
