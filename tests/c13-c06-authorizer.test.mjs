import assert from "node:assert/strict";
import test from "node:test";
import {
  C13C06AuthorizationError,
  createC13C06Authorizer,
} from "../lib/c13-c06-authorizer.mjs";

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const HUMAN_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const DELEGATION_ID = "dlg_018f0000-0000-7000-8000-000000000020";
const RESOURCE_ID =
  "synthetic-tenant-northstar-fasteners--skill-submit";

const serverContext = {
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT_ID,
  workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
  workloadActorPrincipalId: ACTOR_ID,
};
const request = {
  sessionToken: "synthetic-session",
  delegationId: DELEGATION_ID,
  resourceId: RESOURCE_ID,
  correlationId: "c13-correlation",
};
const descriptor = {
  operationId: "C13_SUBMIT_RELEASE",
  surface: "MANAGE",
  path: "skill-registry",
  mode: "WRITE",
};

function allowedDecision(overrides) {
  return {
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    decisionId: "c06-decision",
    evidenceRef: "evidence://c06/c13",
    authorizationModelId: "c06-policy-v1",
    tenantId: TENANT_ID,
    surface: "MANAGE",
    resourceId: RESOURCE_ID,
    humanPrincipalId: HUMAN_ID,
    humanSecurityEpoch: 1,
    workloadActorPrincipalId: ACTOR_ID,
    workloadActorSecurityEpoch: 1,
    leafDelegationId: DELEGATION_ID,
    delegationChainSha256:
      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    purposeRef: "synthetic://c13/test",
    ...overrides,
  };
}

test("C13 C06 adapter rejects request-binding drift", async () => {
  for (const override of [
    { tenantId: "stn_018f0000-0000-7000-8000-000000000099" },
    { surface: "READ" },
    { resourceId: "another-skill-resource" },
    {
      workloadActorPrincipalId:
        "prn_018f0000-0000-7000-8000-000000000099",
    },
    {
      leafDelegationId:
        "dlg_018f0000-0000-7000-8000-000000000099",
    },
  ]) {
    const adapter = createC13C06Authorizer({
      authorizationFacade: {
        async decide() {
          return allowedDecision(override);
        },
      },
    });
    await assert.rejects(
      adapter.enforce(serverContext, request, descriptor),
      (error) =>
        error instanceof C13C06AuthorizationError &&
        error.code === "AUTHORIZATION_UNAVAILABLE",
    );
  }
});

test("C13 submit authorization cannot be replayed as approve or publish", async () => {
  const adapter = createC13C06Authorizer({
    authorizationFacade: {
      async decide() {
        return allowedDecision();
      },
    },
  });
  const submit = await adapter.enforce(
    serverContext,
    request,
    descriptor,
  );
  assert.equal(submit.operationId, "C13_SUBMIT_RELEASE");

  for (const operationId of [
    "C13_APPROVE_RELEASE",
    "C13_PUBLISH_RELEASE",
  ]) {
    await assert.rejects(
      adapter.enforce(serverContext, request, {
        ...descriptor,
        operationId,
      }),
      (error) =>
        error instanceof C13C06AuthorizationError &&
        error.code === "AUTHORIZATION_UNAVAILABLE",
    );
  }
});
