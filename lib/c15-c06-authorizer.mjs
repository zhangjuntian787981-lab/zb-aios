import {
  isC06DecisionBoundToRequest,
} from "./c06-decision-binding.mjs";

const OPERATIONS = Object.freeze({
  C15_PREPARE_DRAFT: Object.freeze({
    surface: "MANAGE",
    suffix: "--decision-prepare",
  }),
  C15_APPROVE_SYNTHETIC_TEST_DECISION: Object.freeze({
    surface: "MANAGE",
    suffix: "--decision-approve",
  }),
  C15_WITHDRAW_SYNTHETIC_TEST_DECISION: Object.freeze({
    surface: "MANAGE",
    suffix: "--decision-withdraw",
  }),
  C15_EXECUTE_SYNTHETIC_PREVIEW: Object.freeze({
    surface: "TOOL_CALL",
    suffix: "--decision-execute",
  }),
});

export class C15C06AuthorizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C15C06AuthorizationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C15C06AuthorizationError(code, message);
}

function nonEmpty(value) {
  return typeof value === "string" && value.length > 0;
}

export function createC15C06Authorizer({ authorizationFacade }) {
  if (typeof authorizationFacade?.decide !== "function") {
    fail("INVALID_CONFIGURATION", "C06 Authorization Facade is required.");
  }

  return Object.freeze({
    async enforce(serverContext, request, descriptor) {
      const operation = OPERATIONS[descriptor?.operationId];
      if (
        !operation ||
        descriptor.surface !== operation.surface ||
        descriptor.path !== "human-decision" ||
        descriptor.mode !== "WRITE" ||
        !request.resourceId?.endsWith(operation.suffix)
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C15 operation authorization binding is invalid.",
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
        fail("ACCESS_DENIED", "C06 denied the C15 operation.");
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
        !isC06DecisionBoundToRequest(decision, {
          tenantId: serverContext.tenantId,
          surface: descriptor.surface,
          resourceId: request.resourceId,
          workloadActorPrincipalId:
            serverContext.workloadActorPrincipalId,
          delegationId: request.delegationId,
        })
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C06 decision is not bound to the C15 request.",
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
