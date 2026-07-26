import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { generateSyntheticTenants } from "../scripts/f02-fixtures.mjs";

const MODEL = JSON.parse(
  readFileSync(
    new URL(
      "../implementation/gates/g1/c06-role-authorization-model.v2.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const POLICY = JSON.parse(
  readFileSync(
    new URL(
      "../implementation/gates/g1/c06-role-policy.v2.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function fail(code) {
  const error = new Error(code);
  error.name = "G1RoleAuthorizationError";
  error.code = code;
  throw error;
}

function exactObject(value, keys) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) {
    fail("G1_ROLE_INVALID_INPUT");
  }
}

function validateC06(c06) {
  if (
    !c06 ||
    typeof c06 !== "object" ||
    typeof c06.prepareTenant !== "function" ||
    typeof c06.writeTuples !== "function" ||
    typeof c06.check !== "function"
  ) {
    fail("G1_ROLE_INVALID_INPUT");
  }
}

function safeC06Id(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

function projectionFrom(deployment) {
  if (
    !deployment ||
    !Array.isArray(deployment.tenants) ||
    deployment.tenants.length !== POLICY.tenant_bindings.length
  ) {
    fail("G1_ROLE_PROJECTION_INVALID");
  }

  const fixtures = new Map(
    generateSyntheticTenants().map((fixture) => [
      fixture.fixture_id,
      fixture,
    ]),
  );
  const deploymentTenants = new Map(
    deployment.tenants.map((tenant) => [tenant.tenantId, tenant]),
  );
  const seenSessions = new Set();
  const seenPrincipals = new Set();
  const tenants = [];

  for (const binding of POLICY.tenant_bindings) {
    const tenant = deploymentTenants.get(binding.tenant_id);
    const fixture = fixtures.get(binding.fixture_id);
    if (
      !tenant ||
      tenant.tenantKind !== "SYNTHETIC" ||
      !fixture ||
      !Array.isArray(tenant.users) ||
      tenant.users.length !== fixture.records.users.length
    ) {
      fail("G1_ROLE_PROJECTION_INVALID");
    }

    const actualUsers = new Map(
      tenant.users.map((user) => [user.fixtureUserId, user]),
    );
    const users = [];
    for (const expected of fixture.records.users) {
      const user = actualUsers.get(expected.id);
      if (
        !user ||
        user.id !== expected.id ||
        user.role !== expected.role ||
        user.trustSource !== "VERIFIED_SESSION" ||
        user.profileRef !==
          `fixture://${fixture.fixture_id}/users/${expected.id}` ||
        !/^ses_[0-9a-f-]{36}$/.test(user.sessionId) ||
        !/^prn_[0-9a-f-]{36}$/.test(user.principalId) ||
        seenSessions.has(user.sessionId) ||
        seenPrincipals.has(user.principalId)
      ) {
        fail("G1_ROLE_PROJECTION_INVALID");
      }
      seenSessions.add(user.sessionId);
      seenPrincipals.add(user.principalId);
      users.push({
        fixtureUserId: user.fixtureUserId,
        principalId: user.principalId,
        role: user.role,
        sessionId: user.sessionId,
      });
    }
    tenants.push({
      tenantId: tenant.tenantId,
      users: users.sort((left, right) =>
        left.fixtureUserId.localeCompare(right.fixtureUserId),
      ),
    });
  }

  return {
    schemaVersion: "g1-role-projection.v2",
    source: "F02_C04_C05_VERIFIED_SESSION_PRINCIPAL",
    tenants: tenants.sort((left, right) =>
      left.tenantId.localeCompare(right.tenantId),
    ),
  };
}

function sha256(value) {
  return `sha256:${createHash("sha256")
    .update(JSON.stringify(value))
    .digest("hex")}`;
}

function roleTuple(tenantId, user) {
  return {
    user: `human:${user.principalId}`,
    relation: "member",
    object: `business_role:${tenantId}--${user.role}`,
  };
}

function resourceObject({ tenantId, surface, resourceId }) {
  return `g1_resource:${tenantId}--${surface}--${resourceId}`;
}

function validateResourceInput(input, sessionKey) {
  exactObject(input, [
    "tenantId",
    "surface",
    "resourceId",
    sessionKey,
  ]);
  if (
    typeof input.tenantId !== "string" ||
    !POLICY.surfaces.includes(input.surface) ||
    typeof input.resourceId !== "string" ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(input.resourceId) ||
    typeof input[sessionKey] !== "string"
  ) {
    fail("G1_ROLE_INVALID_INPUT");
  }
}

export async function createG1RoleAuthorization(options) {
  exactObject(options, ["deployment", "c06"]);
  validateC06(options.c06);
  const projection = projectionFrom(options.deployment);
  const roleProjectionSha256 = sha256(projection);
  const tenantC06 = new Map();
  const sessions = new Map();
  const resources = new Map();
  let c06CheckCount = 0;
  let c06AllowCount = 0;
  let c06DenyCount = 0;

  for (const tenant of projection.tenants) {
    const prepared = await options.c06.prepareTenant({
      tenantId: tenant.tenantId,
      model: structuredClone(MODEL),
    });
    if (
      !prepared ||
      !safeC06Id(prepared.storeId) ||
      !safeC06Id(prepared.authorizationModelId)
    ) {
      fail("G1_ROLE_C06_INVALID_RESPONSE");
    }
    tenantC06.set(tenant.tenantId, prepared);
    for (const user of tenant.users) {
      sessions.set(user.sessionId, {
        ...user,
        tenantId: tenant.tenantId,
      });
    }
    const tupleKeys = tenant.users.map((user) =>
      roleTuple(tenant.tenantId, user),
    );
    const written = await options.c06.writeTuples({
      tenantId: tenant.tenantId,
      storeId: prepared.storeId,
      authorizationModelId: prepared.authorizationModelId,
      tupleKeys,
    });
    if (
      written?.storeId !== prepared.storeId ||
      written?.authorizationModelId !==
        prepared.authorizationModelId ||
      written?.writtenTupleCount !== tupleKeys.length
    ) {
      fail("G1_ROLE_C06_INVALID_RESPONSE");
    }
  }

  return Object.freeze({
    roleProjectionSha256,
    async registerResource(input) {
      validateResourceInput(input, "ownerSessionId");
      const prepared = tenantC06.get(input.tenantId);
      const owner = sessions.get(input.ownerSessionId);
      if (!prepared || !owner || owner.tenantId !== input.tenantId) {
        fail("G1_ROLE_INVALID_INPUT");
      }
      const object = resourceObject(input);
      const key = `${input.tenantId}|${input.surface}|${input.resourceId}`;
      const existing = resources.get(key);
      if (
        existing &&
        existing.ownerPrincipalId !== owner.principalId
      ) {
        fail("G1_ROLE_RESOURCE_OWNER_IMMUTABLE");
      }
      if (!existing) {
        const tupleKeys = [
          {
            user: `human:${owner.principalId}`,
            relation: "owner",
            object,
          },
          {
            user:
              `business_role:${input.tenantId}--${owner.role}`,
            relation: "required_role",
            object,
          },
        ];
        const written = await options.c06.writeTuples({
          tenantId: input.tenantId,
          storeId: prepared.storeId,
          authorizationModelId: prepared.authorizationModelId,
          tupleKeys,
        });
        if (
          written?.storeId !== prepared.storeId ||
          written?.authorizationModelId !==
            prepared.authorizationModelId ||
          written?.writtenTupleCount !== tupleKeys.length
        ) {
          fail("G1_ROLE_C06_INVALID_RESPONSE");
        }
        resources.set(key, {
          ownerPrincipalId: owner.principalId,
          requiredRole: owner.role,
        });
      }
      return Object.freeze({
        tenantId: input.tenantId,
        surface: input.surface,
        resourceId: input.resourceId,
        ownerPrincipalId: owner.principalId,
        requiredRole: owner.role,
      });
    },
    async authorize(input) {
      validateResourceInput(input, "sessionId");
      const prepared = tenantC06.get(input.tenantId);
      const caller = sessions.get(input.sessionId);
      if (!prepared || !caller) fail("G1_ROLE_INVALID_INPUT");
      c06CheckCount += 1;
      const result = await options.c06.check({
        tenantId: input.tenantId,
        storeId: prepared.storeId,
        authorizationModelId: prepared.authorizationModelId,
        tupleKey: {
          user: `human:${caller.principalId}`,
          relation: "can_access",
          object: resourceObject(input),
        },
      });
      if (
        !result ||
        typeof result.allowed !== "boolean" ||
        result.storeId !== prepared.storeId ||
        result.authorizationModelId !==
          prepared.authorizationModelId ||
        result.consistency !== "HIGHER_CONSISTENCY"
      ) {
        fail("G1_ROLE_C06_INVALID_RESPONSE");
      }
      if (result.allowed) c06AllowCount += 1;
      else c06DenyCount += 1;
      return Object.freeze({
        effect: result.allowed ? "ALLOW" : "DENY",
        authorizationStatus: result.allowed
          ? "ALLOWED"
          : "DENIED",
        c06BoundaryEntered: true,
        tenantId: input.tenantId,
        surface: input.surface,
        resourceId: input.resourceId,
        sessionId: input.sessionId,
        principalId: caller.principalId,
        authoritativeRole: caller.role,
        storeId: result.storeId,
        authorizationModelId: result.authorizationModelId,
        consistency: result.consistency,
      });
    },
    evidence() {
      return Object.freeze({
        schemaVersion: "g1-role-authorization-evidence.v2",
        roleProjectionSha256,
        projectedTenantCount: projection.tenants.length,
        projectedUserCount: projection.tenants.reduce(
          (count, tenant) => count + tenant.users.length,
          0,
        ),
        registeredResourceCount: resources.size,
        c06CheckCount,
        c06AllowCount,
        c06DenyCount,
      });
    },
  });
}
