import assert from "node:assert/strict";
import test from "node:test";
import { runG1IsolationMatrix } from "../lib/g1-isolation-matrix.mjs";

const EXPECTED_SURFACES = [
  "SQL",
  "VECTOR",
  "FILE",
  "OBJECT",
  "SEARCH",
  "CACHE",
  "TOOL",
  "RESTORE_REPLICA",
];
const EXPECTED_CASE_TYPES = [
  "POSITIVE",
  "SAME_TENANT_WRONG_USER",
  "SAME_TENANT_WRONG_ROLE",
  "CROSS_TENANT",
];
const EXPECTED_USERS = [
  "blue-harbor-tools-user-ava",
  "blue-harbor-tools-user-mia",
  "blue-harbor-tools-user-noah",
  "cedar-field-components-user-ava",
  "cedar-field-components-user-mia",
  "cedar-field-components-user-noah",
  "northstar-fasteners-user-ava",
  "northstar-fasteners-user-mia",
  "northstar-fasteners-user-noah",
];

test("G1 exhausts three real F02 identities and role-bound resources through real P1 boundaries", async () => {
  const result = await runG1IsolationMatrix();

  assert.equal(result.schemaVersion, "g1-isolation-matrix-result.v1");
  assert.equal(result.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(result.gateConditionStatus, "SATISFIED");
  assert.equal(result.exhaustive, true);
  assert.equal(result.observedLeakCount, 0);
  assert.deepEqual(result.wrongAttributionCounts, {
    body: 0,
    metadata: 0,
    existenceSignal: 0,
    cache: 0,
    toolExternalEffect: 0,
  });
  assert.deepEqual(result.modulesUsed, [
    "C03",
    "C04",
    "C05",
    "C06",
    "C07",
    "C10",
    "C11",
    "C17",
  ]);
  assert.deepEqual(result.coverage, {
    observedPositiveIdentitiesPerTenant: 3,
    requiredPositiveIdentitiesPerTenant: 3,
    observedCasesPerSurface: 36,
    requiredCasesPerSurface: 36,
  });
  assert.deepEqual(result.remainingGaps, []);
  assert.equal(
    result.authorizationObservations.realC04SessionCount,
    9,
  );
  assert.equal(
    result.authorizationObservations.realC05PrincipalCount,
    9,
  );
  assert.equal(
    result.authorizationObservations.realC06AllowCount > 0,
    true,
  );
  assert.equal(
    result.authorizationObservations.realC06DenyCount > 0,
    true,
  );
  assert.equal(
    result.executionTiers.SQL,
    "C07_REAL_BOUNDARY_WITH_SYNTHETIC_MEMORY_ADAPTER_AND_FROZEN_POSTGRESQL_ANCHOR",
  );
  assert.equal(
    result.executionTiers.TOOL,
    "C17_C0_MOCK_EXECUTION_WITH_C16_FROZEN_DATABASE_ANCHOR_ONLY",
  );
  assert.deepEqual(
    result.fixtures.flatMap(({ users }) => users.map(({ id }) => id)).sort(),
    EXPECTED_USERS,
  );
  for (const fixture of result.fixtures) {
    assert.equal(fixture.users.length, 3);
    assert.deepEqual(
      fixture.users.map(({ role }) => role).sort(),
      ["operations_planner", "quality_reviewer", "sales_analyst"],
    );
  }

  assert.deepEqual(
    result.surfaces.map(({ surface }) => surface),
    EXPECTED_SURFACES,
  );
  for (const surface of result.surfaces) {
    assert.equal(surface.observedLeakCount, 0, surface.surface);
    assert.equal(surface.cases.length, 36, surface.surface);
    for (const fixture of result.fixtures) {
      for (const owner of fixture.users) {
        const cases = surface.cases.filter(
          ({ fixtureId, ownerUserId }) =>
            fixtureId === fixture.fixtureId &&
            ownerUserId === owner.id,
        );
        assert.deepEqual(
          cases.map(({ caseType }) => caseType),
          EXPECTED_CASE_TYPES,
          `${surface.surface}:${fixture.fixtureId}:${owner.id}`,
        );
        const [positive, ...negative] = cases;
        assert.equal(positive.expectedAllowed, true);
        assert.equal(positive.actualAllowed, true);
        assert.equal(positive.allowed, true);
        assert.equal(positive.casePassed, true);
        assert.equal(positive.moduleBoundaryEntered, true);
        assert.equal(positive.lowerTouchDelta > 0, true);
        assert.deepEqual(positive.attribution, {
          fixtureId: fixture.fixtureId,
          userId: owner.id,
          role: owner.role,
          principalId: owner.principalId,
        });
        assert.equal(positive.signals.body, true);
        assert.equal(positive.signals.metadata, true);
        assert.equal(positive.signals.existenceSignal, true);
        for (const denied of negative) {
          assert.equal(denied.expectedAllowed, false);
          assert.equal(denied.actualAllowed, false);
          assert.equal(denied.allowed, false);
          assert.equal(denied.casePassed, true);
          assert.equal(denied.errorCode, "ACCESS_DENIED");
          assert.equal(denied.lowerTouchDelta, 0);
          assert.equal(denied.attribution, null);
          assert.deepEqual(denied.signals, {
            body: false,
            metadata: false,
            existenceSignal: false,
            cache: false,
            toolExternalEffect: false,
          });
          if (denied.caseType === "SAME_TENANT_WRONG_ROLE") {
            assert.equal(denied.moduleBoundaryEntered, false);
          } else {
            assert.equal(denied.moduleBoundaryEntered, true);
          }
        }
      }
    }
  }
  const recomputedWrongAttributionCounts = {
    body: 0,
    metadata: 0,
    existenceSignal: 0,
    cache: 0,
    toolExternalEffect: 0,
  };
  for (const item of result.surfaces.flatMap(({ cases }) => cases)) {
    if (item.expectedAllowed) continue;
    for (const signal of Object.keys(recomputedWrongAttributionCounts)) {
      if (item.signals[signal]) {
        recomputedWrongAttributionCounts[signal] += 1;
      }
    }
  }
  assert.deepEqual(
    result.wrongAttributionCounts,
    recomputedWrongAttributionCounts,
  );

  const cacheCases = result.surfaces.find(
    ({ surface }) => surface === "CACHE",
  ).cases.filter(({ allowed }) => allowed);
  assert.equal(cacheCases.every(({ signals }) => signals.cache), true);
  const toolCases = result.surfaces.find(
    ({ surface }) => surface === "TOOL",
  ).cases.filter(({ allowed }) => allowed);
  assert.equal(
    toolCases.every(
      ({ signals, output }) =>
        signals.toolExternalEffect &&
        output.externalEffectCount === 0 &&
        output.networkRequestCount === 0,
    ),
    true,
  );
  const restoreCases = result.surfaces.find(
    ({ surface }) => surface === "RESTORE_REPLICA",
  ).cases.filter(({ allowed }) => allowed);
  assert.equal(
    restoreCases.every(
      ({ output }) =>
        output.readOnly === true &&
        output.writeRejected === true,
    ),
    true,
  );
});
