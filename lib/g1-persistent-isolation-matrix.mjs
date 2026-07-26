const SURFACE_NAMES = Object.freeze([
  "SQL",
  "VECTOR",
  "FILE",
  "OBJECT",
  "SEARCH",
  "CACHE",
  "TOOL",
  "RESTORE_REPLICA",
]);
const CASE_CLASSES = Object.freeze([
  "POSITIVE",
  "WRONG_TENANT",
  "WRONG_USER",
  "WRONG_ROLE",
]);
const EXPECTED_BACKEND_KIND_BY_SURFACE = Object.freeze({
  SQL: "POSTGRESQL_C07_SOURCE",
  VECTOR: "POSTGRESQL_C07_SOURCE",
  FILE: "C10_FILE_QUARANTINE",
  OBJECT: "C07_FILE_OBJECT_ROOT",
  SEARCH: "POSTGRESQL_C07_SOURCE",
  CACHE: "POSTGRESQL_C07_SOURCE",
  TOOL: "C16_POSTGRESQL_GATEWAY_C0",
  RESTORE_REPLICA: "POSTGRESQL_C07_RESTORE_REPLICA",
});

function fail(code) {
  const error = new Error(code);
  error.name = "G1PersistentIsolationMatrixError";
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
    fail("G1_PERSISTENT_MATRIX_INVALID_INPUT");
  }
}

function validateDeployment(deployment) {
  if (
    !deployment ||
    !Array.isArray(deployment.tenants) ||
    deployment.tenants.length !== 3
  ) {
    fail("G1_PERSISTENT_MATRIX_INVALID_INPUT");
  }
  const tenantIds = new Set();
  const sessionIds = new Set();
  const principalIds = new Set();
  for (const tenant of deployment.tenants) {
    if (
      typeof tenant.tenantId !== "string" ||
      tenantIds.has(tenant.tenantId) ||
      !Array.isArray(tenant.users) ||
      tenant.users.length !== 3
    ) {
      fail("G1_PERSISTENT_MATRIX_INVALID_INPUT");
    }
    tenantIds.add(tenant.tenantId);
    const roles = new Set();
    for (const user of tenant.users) {
      if (
        typeof user.fixtureUserId !== "string" ||
        typeof user.role !== "string" ||
        typeof user.sessionId !== "string" ||
        typeof user.principalId !== "string" ||
        roles.has(user.role) ||
        sessionIds.has(user.sessionId) ||
        principalIds.has(user.principalId)
      ) {
        fail("G1_PERSISTENT_MATRIX_INVALID_INPUT");
      }
      roles.add(user.role);
      sessionIds.add(user.sessionId);
      principalIds.add(user.principalId);
    }
  }
}

function validateAuthorization(authorization) {
  if (
    !authorization ||
    typeof authorization.registerResource !== "function" ||
    typeof authorization.authorize !== "function" ||
    typeof authorization.evidence !== "function"
  ) {
    fail("G1_PERSISTENT_MATRIX_INVALID_INPUT");
  }
}

function validateSurfaces(surfaces) {
  exactObject(surfaces, SURFACE_NAMES);
  for (const surface of SURFACE_NAMES) {
    exactObject(surfaces[surface], [
      "seed",
      "read",
      "observations",
    ]);
    if (
      typeof surfaces[surface].seed !== "function" ||
      typeof surfaces[surface].read !== "function" ||
      typeof surfaces[surface].observations !== "function"
    ) {
      fail("G1_PERSISTENT_MATRIX_INVALID_INPUT");
    }
  }
}

function observe(adapter) {
  const value = adapter.observations();
  if (
    !value ||
    typeof value !== "object" ||
    typeof value.backendKind !== "string" ||
    typeof value.backendInstanceId !== "string" ||
    value.backendInstanceId.length < 1 ||
    typeof value.persistent !== "boolean" ||
    !Number.isSafeInteger(value.seedCount) ||
    value.seedCount < 0 ||
    !Number.isSafeInteger(value.readCount) ||
    value.readCount < 0 ||
    !Number.isSafeInteger(value.touchCount) ||
    value.touchCount !== value.seedCount + value.readCount ||
    !Number.isSafeInteger(value.negativeStorageTouchCount) ||
    value.negativeStorageTouchCount < 0
  ) {
    fail("G1_PERSISTENT_MATRIX_INVALID_OBSERVATION");
  }
  return structuredClone(value);
}

function evidenceCounts(evidence) {
  if (
    !evidence ||
    !Number.isSafeInteger(evidence.c06CheckCount) ||
    !Number.isSafeInteger(evidence.c06AllowCount) ||
    !Number.isSafeInteger(evidence.c06DenyCount)
  ) {
    fail("G1_PERSISTENT_MATRIX_INVALID_AUTHORIZATION_EVIDENCE");
  }
  return {
    checks: evidence.c06CheckCount,
    allows: evidence.c06AllowCount,
    denies: evidence.c06DenyCount,
  };
}

function callerFor({
  deployment,
  tenantIndex,
  ownerIndex,
  caseClass,
}) {
  const tenant = deployment.tenants[tenantIndex];
  const owner = tenant.users[ownerIndex];
  if (caseClass === "POSITIVE") {
    return { tenant, user: owner };
  }
  if (caseClass === "WRONG_TENANT") {
    const otherTenant =
      deployment.tenants[
        (tenantIndex + 1) % deployment.tenants.length
      ];
    return {
      tenant: otherTenant,
      user: otherTenant.users.find(
        ({ role }) => role === owner.role,
      ),
    };
  }
  if (caseClass === "WRONG_ROLE") {
    return { tenant, user: owner };
  }
  return {
    tenant,
    user: tenant.users[(ownerIndex + 1) % tenant.users.length],
  };
}

function attributionFor(tenant, owner) {
  return {
    tenantId: tenant.tenantId,
    userId: owner.fixtureUserId,
    role: owner.role,
    principalId: owner.principalId,
  };
}

function sameAttribution(actual, expected) {
  return (
    actual?.tenantId === expected.tenantId &&
    actual?.userId === expected.userId &&
    actual?.role === expected.role &&
    actual?.principalId === expected.principalId
  );
}

function resourceId(surface, owner) {
  return (
    `${owner.fixtureUserId}-` +
    surface.toLowerCase().replaceAll("_", "-")
  );
}

function caseId(surface, tenantIndex, ownerIndex, caseClass) {
  return (
    `g1-${surface.toLowerCase()}-${tenantIndex + 1}-` +
    `${ownerIndex + 1}-${caseClass.toLowerCase()}`
  );
}

function countBy(items, predicate) {
  return items.reduce(
    (count, item) => count + (predicate(item) ? 1 : 0),
    0,
  );
}

export async function runG1PersistentIsolationMatrix(options) {
  exactObject(options, ["deployment", "authorization", "surfaces"]);
  validateDeployment(options.deployment);
  validateAuthorization(options.authorization);
  validateSurfaces(options.surfaces);

  const authorizationBefore = evidenceCounts(
    options.authorization.evidence(),
  );
  const surfaceResults = [];

  for (const surface of SURFACE_NAMES) {
    const adapter = options.surfaces[surface];
    const cases = [];
    for (
      let tenantIndex = 0;
      tenantIndex < options.deployment.tenants.length;
      tenantIndex += 1
    ) {
      const tenant = options.deployment.tenants[tenantIndex];
      for (
        let ownerIndex = 0;
        ownerIndex < tenant.users.length;
        ownerIndex += 1
      ) {
        const owner = tenant.users[ownerIndex];
        const baseResourceId = resourceId(surface, owner);
        const wrongUser =
          tenant.users[(ownerIndex + 1) % tenant.users.length];
        const wrongRoleSource =
          tenant.users[(ownerIndex + 2) % tenant.users.length];
        const baseRegistration =
          await options.authorization.registerResource({
            tenantId: tenant.tenantId,
            surface,
            resourceId: baseResourceId,
            ownerSessionId: owner.sessionId,
            requiredRoleSessionId: owner.sessionId,
          });
        const wrongUserRegistration =
          await options.authorization.registerResource({
            tenantId: tenant.tenantId,
            surface,
            resourceId: `${baseResourceId}-wrong-user`,
            ownerSessionId: owner.sessionId,
            requiredRoleSessionId: wrongUser.sessionId,
          });
        const wrongRoleRegistration =
          await options.authorization.registerResource({
            tenantId: tenant.tenantId,
            surface,
            resourceId: `${baseResourceId}-wrong-role`,
            ownerSessionId: owner.sessionId,
            requiredRoleSessionId: wrongRoleSource.sessionId,
          });
        const registrationByCase = {
          POSITIVE: baseRegistration,
          WRONG_TENANT: baseRegistration,
          WRONG_USER: wrongUserRegistration,
          WRONG_ROLE: wrongRoleRegistration,
        };

        for (const caseClass of CASE_CLASSES) {
          const registration = registrationByCase[caseClass];
          const currentResourceId = registration.resourceId;
          const requiredRole = registration.requiredRole;
          const caller = callerFor({
            deployment: options.deployment,
            tenantIndex,
            ownerIndex,
            caseClass,
          });
          const expectedAllowed = caseClass === "POSITIVE";
          const currentCaseId = caseId(
            surface,
            tenantIndex,
            ownerIndex,
            caseClass,
          );
          const expectedAttribution = attributionFor(tenant, owner);
          const before = observe(adapter);
          let decision = null;
          let output = null;
          let errorCode = null;

          try {
            decision = await options.authorization.authorize({
              tenantId: tenant.tenantId,
              surface,
              resourceId: currentResourceId,
              sessionId: caller.user.sessionId,
            });
            if (
              decision?.effect === "ALLOW" &&
              decision?.authorizationStatus === "ALLOWED"
            ) {
              await adapter.seed({
                caseId: currentCaseId,
                tenantId: tenant.tenantId,
                surface,
                resourceId: currentResourceId,
                attribution: expectedAttribution,
                authorization: structuredClone(decision),
              });
              output = await adapter.read({
                caseId: currentCaseId,
                tenantId: tenant.tenantId,
                surface,
                resourceId: currentResourceId,
                caller: {
                  tenantId: caller.tenant.tenantId,
                  userId: caller.user.fixtureUserId,
                  role: caller.user.role,
                  principalId: caller.user.principalId,
                },
                authorization: structuredClone(decision),
              });
            }
          } catch (error) {
            errorCode =
              typeof error?.code === "string"
                ? error.code
                : "UNEXPECTED_ERROR";
          }

          const after = observe(adapter);
          const adapterTouchDelta =
            after.touchCount - before.touchCount;
          const actualAllowed =
            decision?.effect === "ALLOW" &&
            decision?.authorizationStatus === "ALLOWED";
          const actualDenied =
            decision?.effect === "DENY" &&
            decision?.authorizationStatus === "DENIED";
          const c06BoundaryEntered =
            decision?.c06BoundaryEntered === true;
          const decisionBound =
            decision?.tenantId === tenant.tenantId &&
            decision?.surface === surface &&
            decision?.resourceId === currentResourceId &&
            decision?.sessionId === caller.user.sessionId &&
            decision?.principalId === caller.user.principalId &&
            decision?.authoritativeRole === caller.user.role &&
            decision?.requiredRole === requiredRole;
          const attribution = output?.attribution ?? null;
          const wrongAttribution =
            output !== null &&
            !sameAttribution(attribution, expectedAttribution);
          const observedLeak =
            !expectedAllowed &&
            (adapterTouchDelta !== 0 || output !== null);
          const casePassed =
            errorCode === null &&
            c06BoundaryEntered &&
            decisionBound &&
            (expectedAllowed
              ? actualAllowed &&
                adapterTouchDelta === 2 &&
                output !== null &&
                !wrongAttribution
              : actualDenied &&
                adapterTouchDelta === 0 &&
                output === null);

          cases.push({
            caseId: currentCaseId,
            caseClass,
            surface,
            tenantId: tenant.tenantId,
            resourceId: currentResourceId,
            requiredRole,
            ownerUserId: owner.fixtureUserId,
            ownerRole: owner.role,
            ownerPrincipalId: owner.principalId,
            callerTenantId: caller.tenant.tenantId,
            callerUserId: caller.user.fixtureUserId,
            callerRole: caller.user.role,
            callerPrincipalId: caller.user.principalId,
            expectedAllowed,
            actualAllowed,
            c06BoundaryEntered,
            decisionBound,
            adapterTouchDelta,
            attribution,
            observedLeak,
            wrongAttribution,
            errorCode,
            casePassed,
          });
        }
      }
    }

    const finalObservations = observe(adapter);
    const positiveCases = cases.filter(
      ({ caseClass }) => caseClass === "POSITIVE",
    );
    const negativeCases = cases.filter(
      ({ caseClass }) => caseClass !== "POSITIVE",
    );
    surfaceResults.push({
      surface,
      persistent: finalObservations.persistent,
      caseCount: cases.length,
      positiveCount: positiveCases.length,
      negativeCount: negativeCases.length,
      positiveAdapterTouches: positiveCases.reduce(
        (count, item) => count + item.adapterTouchDelta,
        0,
      ),
      negativeAdapterTouches: negativeCases.reduce(
        (count, item) => count + item.adapterTouchDelta,
        0,
      ),
      observedLeaks: countBy(
        cases,
        ({ observedLeak }) => observedLeak,
      ),
      wrongAttributions: countBy(
        cases,
        ({ wrongAttribution }) => wrongAttribution,
      ),
      observations: finalObservations,
      cases,
    });
  }

  const cases = surfaceResults.flatMap(
    (surface) => surface.cases,
  );
  const authorizationEvidence = structuredClone(
    options.authorization.evidence(),
  );
  const authorizationAfter = evidenceCounts(authorizationEvidence);
  const authorizationDelta = {
    checks: authorizationAfter.checks - authorizationBefore.checks,
    allows: authorizationAfter.allows - authorizationBefore.allows,
    denies: authorizationAfter.denies - authorizationBefore.denies,
  };
  const counts = {
    total: cases.length,
    positive: countBy(
      cases,
      ({ caseClass }) => caseClass === "POSITIVE",
    ),
    negative: countBy(
      cases,
      ({ caseClass }) => caseClass !== "POSITIVE",
    ),
    wrongTenant: countBy(
      cases,
      ({ caseClass }) => caseClass === "WRONG_TENANT",
    ),
    wrongUser: countBy(
      cases,
      ({ caseClass }) => caseClass === "WRONG_USER",
    ),
    wrongRole: countBy(
      cases,
      ({ caseClass }) => caseClass === "WRONG_ROLE",
    ),
    wrongUserOrthogonal: countBy(
      cases,
      (item) =>
        item.caseClass === "WRONG_USER" &&
        item.callerPrincipalId !== item.ownerPrincipalId &&
        item.callerRole === item.requiredRole,
    ),
    wrongRoleOrthogonal: countBy(
      cases,
      (item) =>
        item.caseClass === "WRONG_ROLE" &&
        item.callerTenantId === item.tenantId &&
        item.callerPrincipalId === item.ownerPrincipalId &&
        item.callerRole === item.ownerRole &&
        item.callerRole !== item.requiredRole,
    ),
    c06BoundaryEntered: countBy(
      cases,
      ({ c06BoundaryEntered }) => c06BoundaryEntered,
    ),
    positiveAdapterTouches: cases
      .filter(({ caseClass }) => caseClass === "POSITIVE")
      .reduce(
        (count, item) => count + item.adapterTouchDelta,
        0,
      ),
    negativeAdapterTouches: cases
      .filter(({ caseClass }) => caseClass !== "POSITIVE")
      .reduce(
        (count, item) => count + item.adapterTouchDelta,
        0,
      ),
    observedLeaks: countBy(
      cases,
      ({ observedLeak }) => observedLeak,
    ),
    wrongAttributions: countBy(
      cases,
      ({ wrongAttribution }) => wrongAttribution,
    ),
  };
  const coverageSatisfied =
    counts.total === 288 &&
    counts.positive === 72 &&
    counts.negative === 216 &&
    counts.wrongTenant === 72 &&
    counts.wrongUser === 72 &&
    counts.wrongRole === 72 &&
    counts.wrongUserOrthogonal === 72 &&
    counts.wrongRoleOrthogonal === 72 &&
    counts.c06BoundaryEntered === 288 &&
    counts.positiveAdapterTouches === 144 &&
    counts.negativeAdapterTouches === 0 &&
    counts.observedLeaks === 0 &&
    counts.wrongAttributions === 0 &&
    cases.every(({ casePassed }) => casePassed) &&
    surfaceResults.every(
      (surface) =>
        surface.caseCount === 36 &&
        surface.positiveCount === 9 &&
        surface.negativeCount === 27,
    );
  const authorizationSatisfied =
    authorizationDelta.checks === 288 &&
    authorizationDelta.allows === 72 &&
    authorizationDelta.denies === 216;
  const remainingGaps = [];
  if (!coverageSatisfied) {
    remainingGaps.push("MATRIX_COVERAGE_NOT_SATISFIED");
  }
  if (!authorizationSatisfied) {
    remainingGaps.push("C06_COUNTS_NOT_SATISFIED");
  }
  for (const surface of surfaceResults) {
    if (!surface.persistent) {
      remainingGaps.push(
        `SURFACE_PERSISTENCE_NOT_DECLARED:${surface.surface}`,
      );
    }
  }
  for (const surface of surfaceResults) {
    if (
      surface.observations.backendKind !==
      EXPECTED_BACKEND_KIND_BY_SURFACE[surface.surface]
    ) {
      remainingGaps.push(
        `SURFACE_BACKEND_PROVENANCE_NOT_VERIFIED:${surface.surface}`,
      );
    }
  }
  remainingGaps.push("INDEPENDENT_BACKEND_PROVENANCE_REQUIRED");

  return {
    schemaVersion: "g1-persistent-isolation-matrix.v1",
    evidenceScope: "ORCHESTRATION_CONTRACT",
    assuranceLimit:
      "Adapter declarations cannot prove backend identity; source-backed integration evidence is required.",
    caseClassSemantics: {
      wrongUser:
        "CALLER_ROLE_MATCHES_REQUIRED_ROLE_BUT_OWNER_PRINCIPAL_DIFFERS",
      wrongRole:
        "CALLER_PRINCIPAL_MATCHES_OWNER_BUT_AUTHORITATIVE_ROLE_DIFFERS_FROM_REQUIRED_ROLE",
    },
    gateConditionStatus: "NOT_SATISFIED",
    counts,
    authorizationDelta,
    authorizationEvidence,
    surfaces: surfaceResults,
    remainingGaps,
  };
}
