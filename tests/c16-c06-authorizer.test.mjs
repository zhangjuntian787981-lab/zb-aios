import assert from "node:assert/strict";
import test from "node:test";
import {
  C16C06AuthorizationError,
  createC16C06Authorizer,
} from "../lib/c16-c06-authorizer.mjs";

const TENANT = "stn_018f0000-0000-7000-8000-000000000010";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";
const RESOURCE = "c16-approval-status-get";

function decision(overrides = {}) {
  return {
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    decisionId: "decision-c16",
    evidenceRef: "evidence://c16/decision",
    authorizationModelId: "model-c06",
    tenantId: TENANT,
    surface: "TOOL_CALL",
    resourceId: RESOURCE,
    humanPrincipalId:
      "prn_018f0000-0000-7000-8000-000000000001",
    humanSecurityEpoch: 2,
    workloadActorPrincipalId: ACTOR,
    workloadActorSecurityEpoch: 3,
    leafDelegationId: DELEGATION,
    delegationChainSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    purposeRef: "synthetic://c06/purpose/tool-call",
    ...overrides,
  };
}

function context() {
  return {
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: ACTOR,
  };
}

function request() {
  return {
    sessionToken: "synthetic-session",
    delegationId: DELEGATION,
    resourceId: RESOURCE,
    correlationId: "c16-correlation",
  };
}

test("C16 C06 Adapter binds all three stages to TOOL_CALL", async () => {
  for (const operationId of [
    "C16_DISCOVER_TOOL",
    "C16_CONFIRM_TOOL",
    "C16_EXECUTE_TOOL",
  ]) {
    const authorizer = createC16C06Authorizer({
      authorizationFacade: {
        async decide() {
          return { ...decision(), content: "must-not-cross" };
        },
      },
    });
    const result = await authorizer.enforce(
      context(),
      request(),
      {
        operationId,
        surface: "TOOL_CALL",
        path: "tool-gateway",
        mode: "READ",
      },
    );
    assert.equal(result.operationId, operationId);
    assert.equal(result.surface, "TOOL_CALL");
    assert.equal(result.leafDelegationId, DELEGATION);
    assert.equal(Object.hasOwn(result, "content"), false);
  }
});

test("C16 C06 Adapter fails closed on descriptor, denial, and binding drift", async () => {
  const invalidDescriptor = createC16C06Authorizer({
    authorizationFacade: { async decide() { return decision(); } },
  });
  await assert.rejects(
    invalidDescriptor.enforce(
      context(),
      request(),
      {
        operationId: "C16_EXECUTE_TOOL",
        surface: "MANAGE",
        path: "tool-gateway",
        mode: "READ",
      },
    ),
    (error) =>
      error instanceof C16C06AuthorizationError &&
      error.code === "AUTHORIZATION_UNAVAILABLE",
  );

  for (const changed of [
    decision({ effect: "DENY" }),
    decision({
      leafDelegationId:
        "dlg_018f0000-0000-7000-8000-000000000099",
    }),
    decision({ tenantId: "stn_018f0000-0000-7000-8000-000000000011" }),
  ]) {
    const authorizer = createC16C06Authorizer({
      authorizationFacade: { async decide() { return changed; } },
    });
    await assert.rejects(
      authorizer.enforce(
        context(),
        request(),
        {
          operationId: "C16_EXECUTE_TOOL",
          surface: "TOOL_CALL",
          path: "tool-gateway",
          mode: "READ",
        },
      ),
      (error) =>
        error instanceof C16C06AuthorizationError &&
        ["ACCESS_DENIED", "AUTHORIZATION_UNAVAILABLE"].includes(
          error.code,
        ),
    );
  }
});
