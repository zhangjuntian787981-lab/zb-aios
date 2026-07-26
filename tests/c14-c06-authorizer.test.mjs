import assert from "node:assert/strict";
import test from "node:test";
import {
  C14C06AuthorizationError,
  createC14C06Authorizer,
} from "../lib/c14-c06-authorizer.mjs";

const completeDecision = {
  effect: "ALLOW",
  authorizationStatus: "ALLOWED",
  decisionId: "decision-c14",
  evidenceRef: "evidence://c14/decision",
  authorizationModelId: "model-c06",
  tenantId: "stn_018f0000-0000-7000-8000-000000000010",
  surface: "MANAGE",
  resourceId: "tenant--manage",
  humanPrincipalId: "human-a",
  humanSecurityEpoch: 2,
  workloadActorPrincipalId: "actor-a",
  workloadActorSecurityEpoch: 3,
  leafDelegationId: "delegation-a",
  delegationChainSha256:
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  purposeRef: "synthetic://c06/purpose/manage",
};

function inputs() {
  return {
    serverContext: {
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId: completeDecision.tenantId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId:
        completeDecision.workloadActorPrincipalId,
    },
    request: {
      sessionToken: "session",
      delegationId: "delegation-a",
      resourceId: "tenant--manage",
      correlationId: "correlation",
    },
    descriptor: {
      surface: "MANAGE",
      operationId: "C14_ROUTE_MODEL",
    },
  };
}

test("C14 C06 adapter returns a complete bound decision", async () => {
  const calls = [];
  const authorizer = createC14C06Authorizer({
    authorizationFacade: {
      async decide(context, request) {
        calls.push({ context, request });
        return completeDecision;
      },
    },
  });
  const value = inputs();
  const result = await authorizer.enforce(
    value.serverContext,
    value.request,
    value.descriptor,
  );
  assert.equal(result.trustSource, "C06_BOUND_DECISION_EVIDENCE");
  assert.equal(result.policyVersion, completeDecision.authorizationModelId);
  assert.equal(result.humanSecurityEpoch, 2);
  assert.deepEqual(calls[0].context, {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: completeDecision.tenantId,
    surface: "MANAGE",
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: "actor-a",
  });
});

test("C14 C06 adapter denies incomplete, denied, and unavailable decisions", async () => {
  for (const decision of [
    { ...completeDecision, effect: "DENY" },
    { ...completeDecision, evidenceRef: "" },
  ]) {
    const authorizer = createC14C06Authorizer({
      authorizationFacade: {
        async decide() {
          return decision;
        },
      },
    });
    const value = inputs();
    await assert.rejects(
      authorizer.enforce(
        value.serverContext,
        value.request,
        value.descriptor,
      ),
      (error) =>
        error instanceof C14C06AuthorizationError &&
        ["ACCESS_DENIED", "AUTHORIZATION_UNAVAILABLE"].includes(
          error.code,
        ),
    );
  }

  const unavailable = createC14C06Authorizer({
    authorizationFacade: {
      async decide() {
        throw new Error("offline");
      },
    },
  });
  const value = inputs();
  await assert.rejects(
    unavailable.enforce(
      value.serverContext,
      value.request,
      value.descriptor,
    ),
    (error) =>
      error instanceof C14C06AuthorizationError &&
      error.code === "AUTHORIZATION_UNAVAILABLE",
  );
});
