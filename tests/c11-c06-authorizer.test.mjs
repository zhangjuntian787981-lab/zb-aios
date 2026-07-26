import assert from "node:assert/strict";
import test from "node:test";
import {
  C11C06AuthorizationError,
  createC11C06Authorizer,
} from "../lib/c11-c06-authorizer.mjs";

const TENANT = "stn_01984910-7000-7000-8000-000000000001";
const HUMAN = "prn_01984910-7000-7000-8000-000000000011";
const WORKLOAD = "prn_01984910-7000-7000-8000-000000000031";
const DELEGATION = "dlg_01984910-7000-7000-8000-000000000041";
const serverContext = {
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: WORKLOAD,
};
const request = {
  sessionToken: "synthetic-session",
  delegationId: DELEGATION,
  resourceId: "knowledge-search",
  correlationId: "c11-correlation",
};

function allowedDecision(overrides = {}) {
  return {
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    decisionId: "c06-decision",
    evidenceRef: "evidence://c06/c11",
    authorizationModelId: "c06-policy-v1",
    tenantId: TENANT,
    surface: "RETRIEVE",
    resourceId: "knowledge-search",
    humanPrincipalId: HUMAN,
    humanSecurityEpoch: 3,
    workloadActorPrincipalId: WORKLOAD,
    workloadActorSecurityEpoch: 5,
    leafDelegationId: DELEGATION,
    delegationChainSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    purposeRef: "synthetic://c11/retrieval",
    ...overrides,
  };
}

test("C11 C06 adapter binds Tenant, surface, resource, workload, Delegation, and epochs", async () => {
  let observed;
  const adapter = createC11C06Authorizer({
    authorizationFacade: {
      async decide(context, operation) {
        observed = { context, operation };
        return allowedDecision();
      },
    },
  });
  const evidence = await adapter.enforce(
    serverContext,
    request,
    { surface: "RETRIEVE" },
  );
  assert.equal(observed.context.tenantId, TENANT);
  assert.equal(observed.context.surface, "RETRIEVE");
  assert.equal(observed.operation.resourceId, "knowledge-search");
  assert.equal(evidence.trustSource, "C06_BOUND_DECISION_EVIDENCE");
  assert.equal(evidence.humanSecurityEpoch, 3);
  assert.equal(evidence.workloadActorSecurityEpoch, 5);
});

test("C11 C06 adapter fails closed on denial or dependency failure", async () => {
  const denied = createC11C06Authorizer({
    authorizationFacade: {
      async decide() {
        return allowedDecision({
          effect: "DENY",
          authorizationStatus: "DENIED",
        });
      },
    },
  });
  await assert.rejects(
    denied.enforce(serverContext, request, { surface: "RETRIEVE" }),
    (error) =>
      error instanceof C11C06AuthorizationError &&
      error.code === "ACCESS_DENIED",
  );

  const unavailable = createC11C06Authorizer({
    authorizationFacade: {
      async decide() {
        throw new Error("offline");
      },
    },
  });
  await assert.rejects(
    unavailable.enforce(serverContext, request, {
      surface: "RETRIEVE",
    }),
    (error) => error.code === "AUTHORIZATION_UNAVAILABLE",
  );
});

test("C11 C06 adapter rejects stale or mismatched decision bindings", async () => {
  for (const override of [
    {
      tenantId: "stn_01984910-7000-7000-8000-000000000002",
    },
    { surface: "MANAGE" },
    { resourceId: "sales-guide" },
    {
      workloadActorPrincipalId:
        "prn_01984910-7000-7000-8000-000000000099",
    },
    {
      leafDelegationId:
        "dlg_01984910-7000-7000-8000-000000000099",
    },
    { humanSecurityEpoch: 0 },
    { workloadActorSecurityEpoch: 0 },
  ]) {
    const adapter = createC11C06Authorizer({
      authorizationFacade: {
        async decide() {
          return allowedDecision(override);
        },
      },
    });
    await assert.rejects(
      adapter.enforce(serverContext, request, {
        surface: "RETRIEVE",
      }),
      (error) => error.code === "AUTHORIZATION_UNAVAILABLE",
    );
  }
});
