import {
  isC06DecisionBoundToRequest,
} from "./c06-decision-binding.mjs";

const OPERATIONS = Object.freeze({
  C01_PORTAL_HOME_VIEW: ["READ", "READ", "c01-portal-home-"],
  C01_THREAD_VIEW: ["READ", "READ", "c01-thread-"],
  C01_RUN_VIEW: ["READ", "READ", "c01-run-"],
  C01_RUN_STREAM_VIEW: ["READ", "READ", "c01-run-"],
  C01_FILE_STATUS_VIEW: ["READ", "READ", "c01-file-"],
  C01_RESOURCE_DIRECTORY_VIEW: [
    "READ",
    "READ",
    "c01-resource-directory-",
  ],
  C01_AGENT_SKILL_DIRECTORY_VIEW: [
    "READ",
    "READ",
    "c01-agent-skill-directory-",
  ],
  C01_MEMORY_VIEW: ["READ", "READ", "c01-memory-"],
  C01_APPROVAL_VIEW: ["READ", "READ", "c01-approval-"],
  C01_CITATION_VIEW: ["READ", "READ", "c01-citation-"],
  C01_THREAD_CREATE: ["WRITE", "MANAGE", "c01-thread-"],
  C01_CHAT_SUBMIT: ["WRITE", "MANAGE", "c01-thread-"],
  C01_FILE_QUARANTINE_REQUEST: [
    "WRITE",
    "MANAGE",
    "c01-file-",
  ],
  C01_MEMORY_CONFIRM: ["WRITE", "MANAGE", "c01-memory-"],
  C01_APPROVAL_DECIDE: [
    "WRITE",
    "MANAGE",
    "c01-approval-",
  ],
});

export class C01C06AuthorizationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C01C06AuthorizationError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C01C06AuthorizationError(code, message);
}

function nonEmpty(value) {
  return typeof value === "string" && value.length > 0;
}

export function createC01C06Authorizer({ authorizationFacade }) {
  if (typeof authorizationFacade?.decide !== "function") {
    fail("INVALID_CONFIGURATION", "C06 Authorization Facade is required.");
  }

  return Object.freeze({
    async enforce(serverContext, request, descriptor) {
      const operation = OPERATIONS[descriptor?.operationId];
      if (
        !operation ||
        descriptor.path !== "employee-portal" ||
        descriptor.mode !== operation[0] ||
        descriptor.surface !== operation[1] ||
        !request?.resourceId?.startsWith(operation[2])
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C01 operation authorization binding is invalid.",
        );
      }
      let decision;
      try {
        decision = await authorizationFacade.decide(
          Object.freeze({
            synthetic: true,
            routeTrustSource: serverContext.routeTrustSource,
            tenantId: serverContext.tenantId,
            surface: operation[1],
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
        fail("ACCESS_DENIED", "C06 denied the C01 operation.");
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
          surface: operation[1],
          resourceId: request.resourceId,
          workloadActorPrincipalId:
            serverContext.workloadActorPrincipalId,
          delegationId: request.delegationId,
        })
      ) {
        fail(
          "AUTHORIZATION_UNAVAILABLE",
          "C06 decision is not bound to the C01 request.",
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
