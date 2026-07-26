import assert from "node:assert/strict";
import test from "node:test";
import {
  C10C06AuthorizationError,
  createC10C06Authorizer,
} from "../lib/c10-c06-authorizer.mjs";

const TENANT = "stn_01984910-5000-7000-8000-000000000001";
const HUMAN = "prn_01984910-5000-7000-8000-000000000011";
const WORKLOAD = "prn_01984910-5000-7000-8000-000000000012";
const DELEGATION = "dlg_01984910-5000-7000-8000-000000000021";
const serverContext = {
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: WORKLOAD,
};
const request = {
  sessionToken: "synthetic-session",
  delegationId: DELEGATION,
  resourceId: "policy-guide",
  correlationId: "c10-correlation",
};

function allowedDecision(overrides = {}) {
  return {
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    decisionId: "c06-decision",
    evidenceRef: "evidence://c06/c10",
    authorizationModelId: "c06-policy-v1",
    tenantId: TENANT,
    surface: "MANAGE",
    resourceId: "policy-guide",
    humanPrincipalId: HUMAN,
    humanSecurityEpoch: 1,
    workloadActorPrincipalId: WORKLOAD,
    workloadActorSecurityEpoch: 1,
    leafDelegationId: DELEGATION,
    delegationChainSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    purposeRef: "synthetic://c10/test",
    ...overrides,
  };
}

test("C10 C06 adapter binds Tenant, surface, resource, and workload", async () => {
  let observed;
  const adapter = createC10C06Authorizer({
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
    { surface: "MANAGE" },
  );
  assert.equal(observed.context.tenantId, TENANT);
  assert.equal(observed.context.surface, "MANAGE");
  assert.equal(observed.operation.resourceId, "policy-guide");
  assert.equal(evidence.trustSource, "C06_BOUND_DECISION_EVIDENCE");
  assert.equal(evidence.tenantId, TENANT);
});

test("C10 C06 adapter rejects denial and dependency failures", async () => {
  const denied = createC10C06Authorizer({
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
    denied.enforce(serverContext, request, { surface: "MANAGE" }),
    (error) =>
      error instanceof C10C06AuthorizationError &&
      error.code === "ACCESS_DENIED",
  );
  const unavailable = createC10C06Authorizer({
    authorizationFacade: {
      async decide() {
        throw new Error("unavailable");
      },
    },
  });
  await assert.rejects(
    unavailable.enforce(serverContext, request, { surface: "MANAGE" }),
    (error) => error.code === "AUTHORIZATION_UNAVAILABLE",
  );
});

test("C10 C06 adapter rejects a cross-Tenant or stale request binding", async () => {
  for (const override of [
    {
      tenantId: "stn_01984910-5000-7000-8000-000000000002",
    },
    { surface: "READ" },
    { resourceId: "another-document" },
    {
      workloadActorPrincipalId:
        "prn_01984910-5000-7000-8000-000000000099",
    },
    { humanSecurityEpoch: 0 },
  ]) {
    const adapter = createC10C06Authorizer({
      authorizationFacade: {
        async decide() {
          return allowedDecision(override);
        },
      },
    });
    await assert.rejects(
      adapter.enforce(serverContext, request, { surface: "MANAGE" }),
      (error) => error.code === "AUTHORIZATION_UNAVAILABLE",
    );
  }
});
