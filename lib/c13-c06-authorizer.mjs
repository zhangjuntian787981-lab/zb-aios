import {
  isC06DecisionBoundToRequest,
} from "./c06-decision-binding.mjs";

export class C13C06AuthorizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C13C06AuthorizationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C13C06AuthorizationError(code, message);
}

function nonEmpty(value) {
  return typeof value === "string" && value.length > 0;
}

const OPERATIONS = Object.freeze({
  C13_SUBMIT_RELEASE: Object.freeze({
    surface: "MANAGE",
    resourceSuffix: "--skill-submit",
  }),
  C13_RUN_STATIC_CHECK: Object.freeze({
    surface: "MANAGE",
    resourceSuffix: "--skill-static-check",
  }),
  C13_RUN_SYNTHETIC_EVALUATION: Object.freeze({
    surface: "MANAGE",
    resourceSuffix: "--skill-evaluate",
  }),
  C13_APPROVE_RELEASE: Object.freeze({
    surface: "MANAGE",
    resourceSuffix: "--skill-approve",
  }),
  C13_PUBLISH_RELEASE: Object.freeze({
    surface: "MANAGE",
    resourceSuffix: "--skill-publish",
  }),
  C13_WITHDRAW_RELEASE: Object.freeze({
    surface: "MANAGE",
    resourceSuffix: "--skill-withdraw",
  }),
  C13_ROLLBACK_CHANNEL: Object.freeze({
    surface: "MANAGE",
    resourceSuffix: "--skill-rollback",
  }),
  C13_RESOLVE_FOR_RUN: Object.freeze({
    surface: "READ",
    resourceSuffix: "--skill-resolve",
  }),
});

export function createC13C06Authorizer({ authorizationFacade }) {
  if (typeof authorizationFacade?.decide !== "function") {
    fail("INVALID_CONFIGURATION", "C06 Authorization Facade is required.");
  }

  return Object.freeze({
    async enforce(serverContext, request, descriptor) {
      const operation = OPERATIONS[descriptor?.operationId];
      if (
        !operation ||
        descriptor.surface !== operation.surface ||
        descriptor.path !== "skill-registry" ||
        descriptor.mode !==
          (operation.surface === "READ" ? "READ" : "WRITE") ||
        !request.resourceId?.endsWith(operation.resourceSuffix)
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C13 operation authorization binding is invalid.",
        );
      }
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
        fail("ACCESS_DENIED", "C06 denied the C13 operation.");
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
      if (!isC06DecisionBoundToRequest(decision, {
        tenantId: serverContext.tenantId,
        surface: descriptor.surface,
        resourceId: request.resourceId,
        workloadActorPrincipalId:
          serverContext.workloadActorPrincipalId,
        delegationId: request.delegationId,
      })) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C06 decision binding is invalid.",
        );
      }
      return Object.freeze({
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        operationId: descriptor.operationId,
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
