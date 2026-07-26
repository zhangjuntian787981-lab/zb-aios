import assert from "node:assert/strict";
import test from "node:test";

import {
  PepDeniedError,
} from "../lib/authorization-facade.mjs";
import {
  createSyntheticPepAdapters,
} from "../lib/synthetic-pep-adapters.mjs";

const TENANT_ID = "stn_018f4f9a-7b2c-7c1d-8e3f-123456789abc";
const ACTOR_ID = "prn_018f4f9a-7b2c-7c1d-8e3f-123456789abd";
const REQUEST = Object.freeze({
  sessionToken: "synthetic-session-token",
  delegationId: "dlg_018f4f9a-7b2c-7c1d-8e3f-123456789abe",
  resourceId: "synthetic-resource",
  correlationId: "synthetic-pep-adapter",
});
const ADAPTERS = Object.freeze([
  ["c06.synthetic.read", "READ"],
  ["c06.synthetic.retrieve", "RETRIEVE"],
  ["c06.synthetic.download", "DOWNLOAD"],
  ["c06.synthetic.manage", "MANAGE"],
  ["c06.synthetic.tool-call", "TOOL_CALL"],
  ["c06.synthetic.sandbox-run", "SANDBOX_RUN"],
]);

function adaptersWith(decide) {
  return createSyntheticPepAdapters({
    authorizationFacade: { decide },
    tenantId: TENANT_ID,
    workloadActorPrincipalId: ACTOR_ID,
  });
}

test("the factory exposes exactly the six frozen representative adapters", () => {
  const adapters = adaptersWith(async () => ({
    effect: "DENY",
    authorizationStatus: "DENIED",
  }));

  assert.deepEqual(
    Object.keys(adapters),
    ADAPTERS.map(([adapterId]) => adapterId),
  );
});

for (const [adapterId, surface] of ADAPTERS) {
  test(`${adapterId} binds its server-owned ${surface} context`, async () => {
    let observed;
    const adapters = adaptersWith(async (serverContext, request) => {
      observed = { serverContext, request };
      return {
        effect: "ALLOW",
        authorizationStatus: "ALLOWED",
        decisionId: "azd_018f4f9a-7b2c-7c1d-8e3f-123456789abf",
        evidenceRef: "evidence://c06/decisions/allowed",
        authorizationModelId: "01J00000000000000000000001",
      };
    });

    const result = await adapters[adapterId].enforce({
      ...REQUEST,
      tenantId: "stn_018f4f9a-7b2c-7c1d-8e3f-ffffffffffff",
      surface: "MANAGE",
      routeTrustSource: "CLIENT_ASSERTED",
      workloadActorPrincipalId:
        "prn_018f4f9a-7b2c-7c1d-8e3f-ffffffffffff",
    });

    assert.deepEqual(observed.serverContext, {
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId: TENANT_ID,
      surface,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      workloadActorPrincipalId: ACTOR_ID,
    });
    assert.deepEqual(observed.request, REQUEST);
    assert.deepEqual(result, {
      decisionId: "azd_018f4f9a-7b2c-7c1d-8e3f-123456789abf",
      evidenceRef: "evidence://c06/decisions/allowed",
      policyVersion: "01J00000000000000000000001",
    });
  });

  test(`${adapterId} fails closed on a business Deny`, async () => {
    const adapters = adaptersWith(async () => ({
      effect: "DENY",
      authorizationStatus: "DENIED",
    }));

    await assert.rejects(
      adapters[adapterId].enforce(REQUEST),
      (error) =>
        error instanceof PepDeniedError && error.code === "ACCESS_DENIED",
    );
  });

  test(`${adapterId} fails closed when authorization is unavailable`, async () => {
    const adapters = adaptersWith(async () => {
      throw new Error("synthetic PDP unavailable");
    });

    await assert.rejects(
      adapters[adapterId].enforce(REQUEST),
      (error) =>
        error instanceof PepDeniedError &&
        error.code === "AUTHORIZATION_UNAVAILABLE",
    );
  });
}
