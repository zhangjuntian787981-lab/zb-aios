export class C08C06AuthorizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C08C06AuthorizationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C08C06AuthorizationError(code, message);
}

function nonEmpty(value) {
  return typeof value === "string" && value.length > 0;
}

export function createC08C06Authorizer({ authorizationFacade }) {
  if (typeof authorizationFacade?.decide !== "function") {
    fail("INVALID_CONFIGURATION", "C06 Authorization Facade is required.");
  }

  return Object.freeze({
    async enforce(serverContext, request, descriptor) {
      let decision;
      try {
        decision = await authorizationFacade.decide(
          Object.freeze({
            synthetic: true,
            routeTrustSource: serverContext.routeTrustSource,
            tenantId: serverContext.tenantId,
            surface: descriptor.surface,
            workloadTrustSource: serverContext.workloadTrustSource,
            workloadActorPrincipalId:
              serverContext.workloadActorPrincipalId,
          }),
          Object.freeze({
            sessionToken: request.sessionToken,
            delegationId: request.delegationId,
            resourceId: request.resourceId,
            correlationId: request.correlationId,
          }),
        );
      } catch {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C06 authorization is unavailable.",
        );
      }

      if (
        decision?.effect !== "ALLOW" ||
        decision?.authorizationStatus !== "ALLOWED"
      ) {
        fail("ACCESS_DENIED", "C06 denied the C08 operation.");
      }
      for (const field of [
        "decisionId",
        "evidenceRef",
        "authorizationModelId",
        "tenantId",
        "surface",
        "resourceId",
        "humanPrincipalId",
        "workloadActorPrincipalId",
        "leafDelegationId",
        "delegationChainSha256",
        "purposeRef",
      ]) {
        if (!nonEmpty(decision[field])) {
          fail(
            "AUTHORIZATION_UNAVAILABLE",
            "C06 decision binding is incomplete.",
          );
        }
      }
      if (
        !Number.isSafeInteger(decision.humanSecurityEpoch) ||
        decision.humanSecurityEpoch < 1 ||
        !Number.isSafeInteger(decision.workloadActorSecurityEpoch) ||
        decision.workloadActorSecurityEpoch < 1
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C06 decision binding is invalid.",
        );
      }

      return Object.freeze({
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        decisionId: decision.decisionId,
        evidenceRef: decision.evidenceRef,
        policyVersion: decision.authorizationModelId,
        tenantId: decision.tenantId,
        surface: decision.surface,
        resourceId: decision.resourceId,
        humanPrincipalId: decision.humanPrincipalId,
        humanSecurityEpoch: decision.humanSecurityEpoch,
        workloadActorPrincipalId:
          decision.workloadActorPrincipalId,
        workloadActorSecurityEpoch:
          decision.workloadActorSecurityEpoch,
        leafDelegationId: decision.leafDelegationId,
        delegationChainSha256: decision.delegationChainSha256,
        purposeRef: decision.purposeRef,
      });
    },
  });
}
