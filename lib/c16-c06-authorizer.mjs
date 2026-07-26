import {
  isC06DecisionBoundToRequest,
} from "./c06-decision-binding.mjs";

const OPERATIONS = new Set([
  "C16_DISCOVER_TOOL",
  "C16_CONFIRM_TOOL",
  "C16_EXECUTE_TOOL",
]);
const RESOURCE =
  /^c16-(?:approval-status-get|erp-order-get|bi-metric-get)$/;

export class C16C06AuthorizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C16C06AuthorizationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C16C06AuthorizationError(code, message);
}

function nonEmpty(value) {
  return typeof value === "string" && value.length > 0;
}

export function createC16C06Authorizer({ authorizationFacade }) {
  if (typeof authorizationFacade?.decide !== "function") {
    fail("INVALID_CONFIGURATION", "C06 Authorization Facade is required.");
  }

  return Object.freeze({
    async enforce(serverContext, request, descriptor) {
      if (
        !OPERATIONS.has(descriptor?.operationId) ||
        descriptor.surface !== "TOOL_CALL" ||
        descriptor.path !== "tool-gateway" ||
        descriptor.mode !== "READ" ||
        !RESOURCE.test(request?.resourceId ?? "")
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C16 operation authorization binding is invalid.",
        );
      }
      let decision;
      try {
        decision = await authorizationFacade.decide(
          Object.freeze({
            synthetic: true,
            routeTrustSource: serverContext.routeTrustSource,
            tenantId: serverContext.tenantId,
            surface: "TOOL_CALL",
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
        fail("ACCESS_DENIED", "C06 denied the C16 operation.");
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
          surface: "TOOL_CALL",
          resourceId: request.resourceId,
          workloadActorPrincipalId:
            serverContext.workloadActorPrincipalId,
          delegationId: request.delegationId,
        })
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C06 decision is not bound to the C16 request.",
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
