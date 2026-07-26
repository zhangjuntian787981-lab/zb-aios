import assert from "node:assert/strict";
import test from "node:test";
import { createG1RoleAuthorization } from "../lib/g1-role-authorization.mjs";
import { createG1SyntheticRuntime } from "../lib/g1-synthetic-runtime.mjs";

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

function createRecordingC06() {
  const prepared = [];
  const writes = [];
  const checks = [];
  const tuplesByTenant = new Map();

  function tupleKey(tuple) {
    return `${tuple.user}|${tuple.relation}|${tuple.object}`;
  }

  return {
    adapter: {
      async prepareTenant(input) {
        prepared.push(structuredClone(input));
        const suffix = String(prepared.length).padStart(2, "0");
        return {
          storeId: `g1-role-store-${suffix}`,
          authorizationModelId: `g1-role-model-${suffix}`,
        };
      },
      async writeTuples(input) {
        writes.push(structuredClone(input));
        const tuples = tuplesByTenant.get(input.tenantId) ?? new Set();
        for (const tuple of input.tupleKeys) {
          tuples.add(tupleKey(tuple));
        }
        tuplesByTenant.set(input.tenantId, tuples);
        return {
          storeId: input.storeId,
          authorizationModelId: input.authorizationModelId,
          writtenTupleCount: input.tupleKeys.length,
        };
      },
      async check(input) {
        checks.push(structuredClone(input));
        const tuples = tuplesByTenant.get(input.tenantId) ?? new Set();
        const owner = tuples.has(
          tupleKey({
            user: input.tupleKey.user,
            relation: "owner",
            object: input.tupleKey.object,
          }),
        );
        const requiredRole = [...tuples]
          .map((value) => value.split("|"))
          .find(
            ([, relation, object]) =>
              relation === "required_role" &&
              object === input.tupleKey.object,
          )?.[0];
        const member =
          typeof requiredRole === "string" &&
          tuples.has(
            tupleKey({
              user: input.tupleKey.user,
              relation: "member",
              object: requiredRole,
            }),
          );
        return {
          allowed: owner && member,
          storeId: input.storeId,
          authorizationModelId: input.authorizationModelId,
          consistency: "HIGHER_CONSISTENCY",
        };
      },
    },
    prepared,
    writes,
    checks,
  };
}

async function deployment() {
  const runtime = await createG1SyntheticRuntime();
  return runtime.deploy();
}

test("projects exactly three F02 tenants and nine verified C04/C05 identities into C06", async () => {
  const c06 = createRecordingC06();
  const authorization = await createG1RoleAuthorization({
    deployment: await deployment(),
    c06: c06.adapter,
  });

  assert.equal(
    authorization.roleProjectionSha256,
    EXPECTED_ROLE_PROJECTION_SHA256,
  );
  assert.equal(c06.prepared.length, 3);
  assert.equal(c06.writes.length, 3);
  assert.equal(
    c06.writes.reduce(
      (count, write) => count + write.tupleKeys.length,
      0,
    ),
    9,
  );
  assert.deepEqual(
    c06.writes.flatMap(({ tupleKeys }) => tupleKeys).map(
      ({ relation }) => relation,
    ),
    Array(9).fill("member"),
  );
  assert.deepEqual(authorization.evidence(), {
    schemaVersion: "g1-role-authorization-evidence.v2",
    roleProjectionSha256: EXPECTED_ROLE_PROJECTION_SHA256,
    projectedTenantCount: 3,
    projectedUserCount: 9,
    registeredResourceCount: 0,
    c06CheckCount: 0,
    c06AllowCount: 0,
    c06DenyCount: 0,
  });
});

test("registers owner and required role tuples and allows the verified owner session", async () => {
  const currentDeployment = await deployment();
  const tenant = currentDeployment.tenants[0];
  const owner = tenant.users[0];
  const c06 = createRecordingC06();
  const authorization = await createG1RoleAuthorization({
    deployment: currentDeployment,
    c06: c06.adapter,
  });

  const registration = await authorization.registerResource({
    tenantId: tenant.tenantId,
    surface: "SQL",
    resourceId: "northstar-ava-row",
    ownerSessionId: owner.sessionId,
    requiredRoleSessionId: owner.sessionId,
  });
  const decision = await authorization.authorize({
    tenantId: tenant.tenantId,
    surface: "SQL",
    resourceId: "northstar-ava-row",
    sessionId: owner.sessionId,
  });

  assert.deepEqual(registration, {
    tenantId: tenant.tenantId,
    surface: "SQL",
    resourceId: "northstar-ava-row",
    ownerPrincipalId: owner.principalId,
    requiredRole: owner.role,
  });
  assert.deepEqual(
    c06.writes.at(-1).tupleKeys.map(({ relation }) => relation),
    ["owner", "required_role"],
  );
  assert.deepEqual(decision, {
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    c06BoundaryEntered: true,
    tenantId: tenant.tenantId,
    surface: "SQL",
    resourceId: "northstar-ava-row",
    sessionId: owner.sessionId,
    principalId: owner.principalId,
    authoritativeRole: owner.role,
    requiredRole: owner.role,
    storeId: "g1-role-store-01",
    authorizationModelId: "g1-role-model-01",
    consistency: "HIGHER_CONSISTENCY",
  });
  assert.deepEqual(c06.checks.at(-1).tupleKey, {
    user: `human:${owner.principalId}`,
    relation: "can_access",
    object:
      `g1_resource:${tenant.tenantId}--SQL--northstar-ava-row`,
  });
  assert.deepEqual(authorization.evidence(), {
    schemaVersion: "g1-role-authorization-evidence.v2",
    roleProjectionSha256: EXPECTED_ROLE_PROJECTION_SHA256,
    projectedTenantCount: 3,
    projectedUserCount: 9,
    registeredResourceCount: 1,
    c06CheckCount: 1,
    c06AllowCount: 1,
    c06DenyCount: 0,
  });
});

test("orthogonally denies a wrong principal and a wrong role at C06", async () => {
  const currentDeployment = await deployment();
  const c06 = createRecordingC06();
  const authorization = await createG1RoleAuthorization({
    deployment: currentDeployment,
    c06: c06.adapter,
  });
  const wrongUserDecisions = [];
  const wrongRoleDecisions = [];

  for (const tenant of currentDeployment.tenants) {
    for (const [ownerIndex, owner] of tenant.users.entries()) {
      const wrongUser =
        tenant.users[(ownerIndex + 1) % tenant.users.length];
      const wrongRoleSource =
        tenant.users[(ownerIndex + 2) % tenant.users.length];
      for (const surface of SURFACES) {
        const base = `${owner.fixtureUserId}-${surface.toLowerCase()}`;
        const wrongUserResourceId = `${base}-wrong-user`;
        const wrongRoleResourceId = `${base}-wrong-role`;
        await authorization.registerResource({
          tenantId: tenant.tenantId,
          surface,
          resourceId: wrongUserResourceId,
          ownerSessionId: owner.sessionId,
          requiredRoleSessionId: wrongUser.sessionId,
        });
        wrongUserDecisions.push({
          owner,
          caller: wrongUser,
          decision: await authorization.authorize({
            tenantId: tenant.tenantId,
            surface,
            resourceId: wrongUserResourceId,
            sessionId: wrongUser.sessionId,
          }),
        });
        await authorization.registerResource({
          tenantId: tenant.tenantId,
          surface,
          resourceId: wrongRoleResourceId,
          ownerSessionId: owner.sessionId,
          requiredRoleSessionId: wrongRoleSource.sessionId,
        });
        wrongRoleDecisions.push({
          owner,
          roleSource: wrongRoleSource,
          decision: await authorization.authorize({
            tenantId: tenant.tenantId,
            surface,
            resourceId: wrongRoleResourceId,
            sessionId: owner.sessionId,
          }),
        });
      }
    }
  }

  assert.equal(wrongUserDecisions.length, 72);
  assert.equal(wrongRoleDecisions.length, 72);
  for (const { owner, caller, decision } of wrongUserDecisions) {
    assert.notEqual(caller.principalId, owner.principalId);
    assert.equal(caller.role, decision.requiredRole);
    assert.equal(decision.effect, "DENY");
    assert.equal(decision.c06BoundaryEntered, true);
  }
  for (const { owner, roleSource, decision } of wrongRoleDecisions) {
    assert.equal(decision.principalId, owner.principalId);
    assert.equal(decision.authoritativeRole, owner.role);
    assert.equal(decision.requiredRole, roleSource.role);
    assert.notEqual(decision.authoritativeRole, decision.requiredRole);
    assert.equal(decision.effect, "DENY");
    assert.equal(decision.c06BoundaryEntered, true);
  }
  assert.deepEqual(authorization.evidence(), {
    schemaVersion: "g1-role-authorization-evidence.v2",
    roleProjectionSha256: EXPECTED_ROLE_PROJECTION_SHA256,
    projectedTenantCount: 3,
    projectedUserCount: 9,
    registeredResourceCount: 144,
    c06CheckCount: 144,
    c06AllowCount: 0,
    c06DenyCount: 144,
  });
});

test("the request interface rejects claimedRole instead of treating it as authority", async () => {
  const currentDeployment = await deployment();
  const tenant = currentDeployment.tenants[0];
  const owner = tenant.users[0];
  const otherTenantUser = currentDeployment.tenants[1].users[0];
  const c06 = createRecordingC06();
  const authorization = await createG1RoleAuthorization({
    deployment: currentDeployment,
    c06: c06.adapter,
  });

  await assert.rejects(
    authorization.registerResource({
      tenantId: tenant.tenantId,
      surface: "SQL",
      resourceId: "claimed-role-registration",
      ownerSessionId: owner.sessionId,
      requiredRoleSessionId: owner.sessionId,
      claimedRole: owner.role,
    }),
    (error) => error.code === "G1_ROLE_INVALID_INPUT",
  );
  await assert.rejects(
    authorization.authorize({
      tenantId: tenant.tenantId,
      surface: "SQL",
      resourceId: "claimed-role-check",
      sessionId: owner.sessionId,
      claimedRole: owner.role,
    }),
    (error) => error.code === "G1_ROLE_INVALID_INPUT",
  );
  assert.equal(c06.checks.length, 0);
  await assert.rejects(
    authorization.registerResource({
      tenantId: tenant.tenantId,
      surface: "SQL",
      resourceId: "cross-tenant-role-source",
      ownerSessionId: owner.sessionId,
      requiredRoleSessionId: otherTenantUser.sessionId,
    }),
    (error) => error.code === "G1_ROLE_INVALID_INPUT",
  );
});
