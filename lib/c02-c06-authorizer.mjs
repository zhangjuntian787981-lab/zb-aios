import {
  isC06DecisionBoundToRequest,
} from "./c06-decision-binding.mjs";

const OPERATIONS = Object.freeze({
  C02_TENANT_CONFIG_VIEW: ["READ", "c02-tenant-config-"],
  C02_TENANT_CONFIG_CHANGE: ["WRITE", "c02-tenant-config-"],
  C02_PRINCIPAL_ROLE_VIEW: ["READ", "c02-principal-role-"],
  C02_PRINCIPAL_ROLE_CHANGE: ["WRITE", "c02-principal-role-"],
  C02_KNOWLEDGE_RELEASE_VIEW: [
    "READ",
    "c02-knowledge-release-",
  ],
  C02_KNOWLEDGE_RELEASE_CHANGE: [
    "WRITE",
    "c02-knowledge-release-",
  ],
  C02_SKILL_RELEASE_VIEW: ["READ", "c02-skill-release-"],
  C02_SKILL_RELEASE_CHANGE: [
    "WRITE",
    "c02-skill-release-",
  ],
  C02_QUOTA_VIEW: ["READ", "c02-quota-"],
  C02_QUOTA_CHANGE: ["WRITE", "c02-quota-"],
  C02_FORMAL_ARTIFACT_VIEW: [
    "READ",
    "c02-formal-artifact-",
  ],
  C02_FORMAL_ARTIFACT_PUBLISH: [
    "WRITE",
    "c02-formal-artifact-",
  ],
  C02_AUDIT_VIEW: ["READ", "c02-audit-"],
  C02_CONNECTOR_STAGE_VIEW: ["READ", "c02-connector-"],
  C02_CONNECTOR_STAGE_CHANGE: [
    "WRITE",
    "c02-connector-",
  ],
  C02_OBSERVABILITY_VIEW: [
    "READ",
    "c02-observability-",
  ],
});

export class C02C06AuthorizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C02C06AuthorizationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C02C06AuthorizationError(code, message);
}

function nonEmpty(value) {
  return typeof value === "string" && value.length > 0;
}

export function createC02C06Authorizer({ authorizationFacade }) {
  if (typeof authorizationFacade?.decide !== "function") {
    fail("INVALID_CONFIGURATION", "C06 Authorization Facade is required.");
  }

  return Object.freeze({
    async enforce(serverContext, request, descriptor) {
      const operation = OPERATIONS[descriptor?.operationId];
      if (
        !operation ||
        descriptor.surface !== "MANAGE" ||
        descriptor.path !== "tenant-governance" ||
        descriptor.mode !== operation[0] ||
        !request?.resourceId?.startsWith(operation[1])
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C02 operation authorization binding is invalid.",
        );
      }
      let decision;
      try {
        decision = await authorizationFacade.decide(
          Object.freeze({
            synthetic: true,
            routeTrustSource: serverContext.routeTrustSource,
            tenantId: serverContext.tenantId,
            surface: "MANAGE",
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
        fail("ACCESS_DENIED", "C06 denied the C02 operation.");
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
          surface: "MANAGE",
          resourceId: request.resourceId,
          workloadActorPrincipalId:
            serverContext.workloadActorPrincipalId,
          delegationId: request.delegationId,
        })
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C06 decision is not bound to the C02 request.",
        );
      }
      return Object.freeze({
        trustSource: "C06_BOUND_DECISION_EVIDENCE",
        tenantId: decision.tenantId,
        humanPrincipalId: decision.humanPrincipalId,
        workloadActorPrincipalId:
          decision.workloadActorPrincipalId,
        decisionId: decision.decisionId,
        evidenceRef: decision.evidenceRef,
        policyVersion: decision.authorizationModelId,
        resourceId: decision.resourceId,
        operationId: descriptor.operationId,
      });
    },
  });
}
