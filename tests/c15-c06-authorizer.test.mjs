import assert from "node:assert/strict";
import test from "node:test";
import {
  C15C06AuthorizationError,
  createC15C06Authorizer,
} from "../lib/c15-c06-authorizer.mjs";

const TENANT = "stn_018f0000-0000-7000-8000-000000000010";
const ACTOR = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION =
  "dlg_018f0000-0000-7000-8000-000000000020";

function completeDecision(surface, resourceId) {
  return {
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    decisionId: "decision-c15",
    evidenceRef: "evidence://c15/decision",
    authorizationModelId: "model-c06",
    tenantId: TENANT,
    surface,
    resourceId,
    humanPrincipalId:
      "prn_018f0000-0000-7000-8000-000000000001",
    humanSecurityEpoch: 2,
    workloadActorPrincipalId: ACTOR,
    workloadActorSecurityEpoch: 3,
    leafDelegationId: DELEGATION,
    delegationChainSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    purposeRef: "synthetic://c15/purpose/decision",
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

const CASES = [
  ["C15_PREPARE_DRAFT", "MANAGE", "northstar--decision-prepare"],
  [
    "C15_APPROVE_SYNTHETIC_TEST_DECISION",
    "MANAGE",
    "dar_x--decision-approve",
  ],
  [
    "C15_WITHDRAW_SYNTHETIC_TEST_DECISION",
    "MANAGE",
    "std_x--decision-withdraw",
  ],
  [
    "C15_EXECUTE_SYNTHETIC_PREVIEW",
    "TOOL_CALL",
    "std_x--decision-execute",
  ],
];

test("C15 C06 adapter binds every operation and leaf delegation", async () => {
  for (const [operationId, surface, resourceId] of CASES) {
    const authorizer = createC15C06Authorizer({
      authorizationFacade: {
        async decide() {
          return {
            ...completeDecision(surface, resourceId),
            content: "must-not-cross-the-adapter",
          };
        },
      },
    });
    const result = await authorizer.enforce(
      context(),
      {
        sessionToken: "session",
        delegationId: DELEGATION,
        resourceId,
        correlationId: "correlation",
      },
      {
        operationId,
        surface,
        path: "human-decision",
        mode: "WRITE",
      },
    );
    assert.equal(result.operationId, operationId);
    assert.equal(result.leafDelegationId, DELEGATION);
    assert.equal(Object.hasOwn(result, "content"), false);
  }
});

test("C15 C06 adapter fails closed on operation, denial and binding changes", async () => {
  const authorizer = createC15C06Authorizer({
    authorizationFacade: {
      async decide(_context, request) {
        return completeDecision("MANAGE", request.resourceId);
      },
    },
  });
  await assert.rejects(
    authorizer.enforce(
      context(),
      {
        sessionToken: "session",
        delegationId: DELEGATION,
        resourceId: "northstar--decision-prepare",
        correlationId: "correlation",
      },
      {
        operationId: "C15_EXECUTE_SYNTHETIC_PREVIEW",
        surface: "MANAGE",
        path: "human-decision",
        mode: "WRITE",
      },
    ),
    (error) =>
      error instanceof C15C06AuthorizationError &&
      error.code === "AUTHORIZATION_UNAVAILABLE",
  );

  for (const decision of [
    {
      ...completeDecision(
        "MANAGE",
        "northstar--decision-prepare",
      ),
      effect: "DENY",
    },
    {
      ...completeDecision(
        "MANAGE",
        "northstar--decision-prepare",
      ),
      leafDelegationId:
        "dlg_018f0000-0000-7000-8000-000000000099",
    },
  ]) {
    const denied = createC15C06Authorizer({
      authorizationFacade: {
        async decide() {
          return decision;
        },
      },
    });
    await assert.rejects(
      denied.enforce(
        context(),
        {
          sessionToken: "session",
          delegationId: DELEGATION,
          resourceId: "northstar--decision-prepare",
          correlationId: "correlation",
        },
        {
          operationId: "C15_PREPARE_DRAFT",
          surface: "MANAGE",
          path: "human-decision",
          mode: "WRITE",
        },
      ),
      (error) =>
        error instanceof C15C06AuthorizationError &&
        ["ACCESS_DENIED", "AUTHORIZATION_UNAVAILABLE"].includes(
          error.code,
        ),
    );
  }
});
