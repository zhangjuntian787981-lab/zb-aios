import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const api = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c14/model-gateway.openapi.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const matrix = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c14/routing-matrix.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const migration = await readFile(
  new URL(
    "../implementation/p1/c14/postgresql/0021_model_gateway.sql",
    import.meta.url,
  ),
  "utf8",
);

test("C14 OpenAPI exposes one closed trusted-workload route", () => {
  assert.deepEqual(Object.keys(api.paths), [
    "/internal/v1/model-routes:execute",
  ]);
  const operation =
    api.paths["/internal/v1/model-routes:execute"].post;
  assert.equal(operation.operationId, "routeModel");
  assert.equal(operation["x-browser-direct-access"], false);
  assert.deepEqual(operation["x-runtime-order"].slice(0, 6), [
    "C05_RESOLVE_ACTION_IDENTITY",
    "C06_ENFORCE_MANAGE",
    "C06_BOUND_DECISION_IDENTITY_CHECK",
    "C05_FINAL_RESOLVE_ACTION_IDENTITY",
    "C03_FINAL_ACTIVE_ADMISSION",
    "TRUSTED_DATA_POLICY_RESOLUTION",
  ]);
  const request = api.components.schemas.RouteRequest;
  assert.equal(request.additionalProperties, false);
  assert.deepEqual(Object.keys(request.properties), request.required);
  for (const forbidden of [
    "tenantId",
    "providerId",
    "providerUrl",
    "region",
    "dataClassification",
    "inputTokens",
    "cost",
    "prompt",
    "inputBody",
  ]) {
    assert.equal(Object.hasOwn(request.properties, forbidden), false);
  }
  assert.equal(
    api["x-c14-boundary"].provider_mode,
    "C0_DETERMINISTIC_MOCK_ONLY",
  );
  assert.equal(
    api["x-c14-boundary"].production_verification_status,
    "NOT_VERIFIED",
  );
});

test("C14 schemas and routing matrix preserve the P1 boundary", () => {
  for (const [name, schema] of Object.entries(
    api.components.schemas,
  )) {
    if (schema.type === "object") {
      assert.equal(schema.additionalProperties, false, name);
    }
  }
  assert.equal(matrix.workPackageId, "C14");
  assert.equal(matrix.cases.length, 34);
  assert.equal(matrix.enterpriseConnectors, "C0_DISABLED");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(
    matrix.cases.every(
      ({ evidenceStatus }) =>
        evidenceStatus === "EXECUTED_NOT_FROZEN",
    ),
    true,
  );
  assert.match(
    migration,
    /cost_microusd <= reserved_cost_microusd/,
  );
});
