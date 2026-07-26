import assert from "node:assert/strict";
import test from "node:test";
import { runG1PersistentIsolationMatrix } from "../lib/g1-persistent-isolation-matrix.mjs";
import { createG1SyntheticRuntime } from "../lib/g1-synthetic-runtime.mjs";

const SURFACE_NAMES = [
  "SQL",
  "VECTOR",
  "FILE",
  "OBJECT",
  "SEARCH",
  "CACHE",
  "TOOL",
  "RESTORE_REPLICA",
];
const CASE_CLASSES = [
  "POSITIVE",
  "WRONG_TENANT",
  "WRONG_USER",
  "WRONG_ROLE",
];
const FORBIDDEN_EVIDENCE_LABELS = [
  ["SYNTHETIC", "MEMORY", "ADAPTER"].join("_"),
  ["FROZEN", "POSTGRESQL", "ANCHOR"].join("_"),
  ["DATABASE", "ANCHOR", "ONLY"].join("_"),
  ["MEMORY", "SNAPSHOT", "RESTORE"].join("_"),
];

function createRecordingAuthorization(deployment) {
  const sessions = new Map();
  const resources = new Map();
  const registrations = [];
  const checks = [];
  for (const tenant of deployment.tenants) {
    for (const user of tenant.users) {
      sessions.set(user.sessionId, {
        ...user,
        tenantId: tenant.tenantId,
      });
    }
  }

  return {
    authorization: {
      async registerResource(input) {
        registrations.push(structuredClone(input));
        const owner = sessions.get(input.ownerSessionId);
        const requiredRoleSource = sessions.get(
          input.requiredRoleSessionId,
        );
        assert.equal(owner.tenantId, input.tenantId);
        assert.equal(requiredRoleSource.tenantId, input.tenantId);
        resources.set(
          `${input.tenantId}|${input.surface}|${input.resourceId}`,
          { owner, requiredRole: requiredRoleSource.role },
        );
        return {
          tenantId: input.tenantId,
          surface: input.surface,
          resourceId: input.resourceId,
          ownerPrincipalId: owner.principalId,
          requiredRole: requiredRoleSource.role,
        };
      },
      async authorize(input) {
        checks.push(structuredClone(input));
        const caller = sessions.get(input.sessionId);
        const resource = resources.get(
          `${input.tenantId}|${input.surface}|${input.resourceId}`,
        );
        const allowed =
          caller?.tenantId === input.tenantId &&
          caller?.principalId === resource?.owner.principalId &&
          caller?.role === resource?.requiredRole;
        return {
          effect: allowed ? "ALLOW" : "DENY",
          authorizationStatus: allowed ? "ALLOWED" : "DENIED",
          c06BoundaryEntered: true,
          tenantId: input.tenantId,
          surface: input.surface,
          resourceId: input.resourceId,
          sessionId: input.sessionId,
          principalId: caller.principalId,
          authoritativeRole: caller.role,
          requiredRole: resource.requiredRole,
          storeId: `recording-${input.tenantId}`,
          authorizationModelId: "recording-g1-role-v2",
          consistency: "HIGHER_CONSISTENCY",
        };
      },
      evidence() {
        const allowCount = checks.filter((input) => {
          const caller = sessions.get(input.sessionId);
          const resource = resources.get(
            `${input.tenantId}|${input.surface}|${input.resourceId}`,
          );
          return (
            caller?.tenantId === input.tenantId &&
            caller?.principalId === resource?.owner.principalId &&
            caller?.role === resource?.requiredRole
          );
        }).length;
        return {
          schemaVersion: "recording-authorization-evidence.v1",
          c06CheckCount: checks.length,
          c06AllowCount: allowCount,
          c06DenyCount: checks.length - allowCount,
        };
      },
    },
    registrations,
    checks,
  };
}

function createRecordingSurface(name, { persistent = true } = {}) {
  const records = new Map();
  let seedCount = 0;
  let readCount = 0;

  return {
    async seed(input) {
      seedCount += 1;
      records.set(`${input.tenantId}|${input.resourceId}`, {
        attribution: structuredClone(input.attribution),
        marker: `${name}:${input.caseId}`,
      });
    },
    async read(input) {
      readCount += 1;
      return structuredClone(
        records.get(`${input.tenantId}|${input.resourceId}`) ?? null,
      );
    },
    observations() {
      return {
        backendKind: "NON_GATE_TEST_DOUBLE",
        backendInstanceId: `recording-${name.toLowerCase()}`,
        persistent,
        seedCount,
        readCount,
        touchCount: seedCount + readCount,
        negativeStorageTouchCount: 0,
      };
    },
  };
}

function createRecordingSurfaces(overrides = {}) {
  return Object.fromEntries(
    SURFACE_NAMES.map((name) => [
      name,
      createRecordingSurface(name, overrides[name]),
    ]),
  );
}

async function deployment() {
  const runtime = await createG1SyntheticRuntime();
  return runtime.deploy();
}

test("orchestrates 288 cases but never promotes test doubles to gate evidence", async () => {
  const currentDeployment = await deployment();
  const recording = createRecordingAuthorization(currentDeployment);
  const result = await runG1PersistentIsolationMatrix({
    deployment: currentDeployment,
    authorization: recording.authorization,
    surfaces: createRecordingSurfaces(),
  });

  assert.equal(result.schemaVersion, "g1-persistent-isolation-matrix.v1");
  assert.equal(result.evidenceScope, "ORCHESTRATION_CONTRACT");
  assert.equal(result.gateConditionStatus, "NOT_SATISFIED");
  assert.deepEqual(
    result.remainingGaps,
    [
      ...SURFACE_NAMES.map(
        (surface) =>
          `SURFACE_BACKEND_PROVENANCE_NOT_VERIFIED:${surface}`,
      ),
      "INDEPENDENT_BACKEND_PROVENANCE_REQUIRED",
    ],
  );
  assert.deepEqual(result.caseClassSemantics, {
    wrongUser:
      "CALLER_ROLE_MATCHES_REQUIRED_ROLE_BUT_OWNER_PRINCIPAL_DIFFERS",
    wrongRole:
      "CALLER_PRINCIPAL_MATCHES_OWNER_BUT_AUTHORITATIVE_ROLE_DIFFERS_FROM_REQUIRED_ROLE",
  });
  assert.deepEqual(result.counts, {
    total: 288,
    positive: 72,
    negative: 216,
    wrongTenant: 72,
    wrongUser: 72,
    wrongRole: 72,
    wrongUserOrthogonal: 72,
    wrongRoleOrthogonal: 72,
    c06BoundaryEntered: 288,
    positiveAdapterTouches: 144,
    negativeAdapterTouches: 0,
    observedLeaks: 0,
    wrongAttributions: 0,
  });
  assert.equal(recording.registrations.length, 216);
  assert.equal(recording.checks.length, 288);
  assert.ok(
    recording.checks.every(
      (request) =>
        !Object.hasOwn(request, "claimedRole") &&
        Object.keys(request).length === 4,
    ),
  );

  assert.deepEqual(
    result.surfaces.map(({ surface }) => surface),
    SURFACE_NAMES,
  );
  for (const surface of result.surfaces) {
    assert.equal(surface.persistent, true);
    assert.equal(surface.caseCount, 36);
    assert.equal(surface.positiveCount, 9);
    assert.equal(surface.negativeCount, 27);
    assert.equal(surface.negativeAdapterTouches, 0);
    assert.equal(surface.observedLeaks, 0);
    assert.equal(surface.wrongAttributions, 0);
    assert.deepEqual(
      surface.cases.map(({ caseClass }) => caseClass),
      Array(9).fill(CASE_CLASSES).flat(),
    );
    assert.equal(
      new Set(surface.cases.map(({ caseId }) => caseId)).size,
      36,
    );
    for (const item of surface.cases) {
      assert.equal(item.c06BoundaryEntered, true);
      assert.equal(item.casePassed, true);
      if (item.caseClass === "POSITIVE") {
        assert.equal(item.actualAllowed, true);
        assert.equal(item.adapterTouchDelta, 2);
        assert.deepEqual(item.attribution, {
          tenantId: item.tenantId,
          userId: item.ownerUserId,
          role: item.ownerRole,
          principalId: item.ownerPrincipalId,
        });
      } else {
        assert.equal(item.actualAllowed, false);
        assert.equal(item.adapterTouchDelta, 0);
        assert.equal(item.attribution, null);
      }
      if (item.caseClass === "WRONG_USER") {
        assert.notEqual(item.callerUserId, item.ownerUserId);
        assert.equal(item.callerRole, item.requiredRole);
      }
      if (item.caseClass === "WRONG_ROLE") {
        assert.equal(item.callerUserId, item.ownerUserId);
        assert.equal(item.callerPrincipalId, item.ownerPrincipalId);
        assert.notEqual(item.callerRole, item.requiredRole);
      }
    }
  }

  const serialized = JSON.stringify(result);
  for (const forbidden of FORBIDDEN_EVIDENCE_LABELS) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test("does not satisfy the gate when any Adapter omits persistent=true", async () => {
  const currentDeployment = await deployment();
  const recording = createRecordingAuthorization(currentDeployment);
  const result = await runG1PersistentIsolationMatrix({
    deployment: currentDeployment,
    authorization: recording.authorization,
    surfaces: createRecordingSurfaces({
      FILE: { persistent: false },
    }),
  });

  assert.equal(result.gateConditionStatus, "NOT_SATISFIED");
  assert.deepEqual(result.remainingGaps, [
    "SURFACE_PERSISTENCE_NOT_DECLARED:FILE",
    ...SURFACE_NAMES.map(
      (surface) =>
        `SURFACE_BACKEND_PROVENANCE_NOT_VERIFIED:${surface}`,
    ),
    "INDEPENDENT_BACKEND_PROVENANCE_REQUIRED",
  ]);
  assert.equal(
    result.surfaces.find(({ surface }) => surface === "FILE")
      .observations.backendKind,
    "NON_GATE_TEST_DOUBLE",
  );
  assert.match(result.assuranceLimit, /source-backed integration/i);
});
