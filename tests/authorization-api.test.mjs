import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractUrl = new URL(
  "../implementation/p1/c06/authorization.openapi.v1.json",
  import.meta.url,
);

async function contract() {
  return JSON.parse(await readFile(contractUrl, "utf8"));
}

function operationIds(document) {
  return Object.values(document.paths).flatMap((path) =>
    Object.values(path)
      .filter((operation) => operation?.operationId)
      .map(({ operationId }) => operationId),
  );
}

function propertyKeys(value, result = new Set()) {
  if (!value || typeof value !== "object") return result;
  if (value.properties) {
    for (const key of Object.keys(value.properties)) result.add(key);
  }
  for (const child of Object.values(value)) propertyKeys(child, result);
  return result;
}

test("the C06 contract exposes only command, decision, replay and snapshot operations", async () => {
  const document = await contract();

  assert.equal(document.openapi, "3.1.2");
  assert.deepEqual(operationIds(document).sort(), [
    "decideAuthorization",
    "executeAuthorizationCommand",
    "getAuthorizationSnapshot",
    "replayAuthorizationDecision",
  ]);
  assert.deepEqual(Object.keys(document.paths).sort(), [
    "/internal/v1/authorization/commands",
    "/internal/v1/authorization/decisions:evaluate",
    "/internal/v1/authorization/decisions:replay",
    "/internal/v1/authorization/tenants/{tenantId}",
  ]);
});

test("the boundary remains Synthetic-only until the P3 enterprise integration gate", async () => {
  const document = await contract();

  assert.deepEqual(document["x-c06-boundary"], {
    phase: "P1_SYNTHETIC_ONLY",
    data_classification: "SYNTHETIC_ONLY",
    p1_engineering_status: "IMPLEMENTED",
    production_verification_status: "NOT_VERIFIED",
    enterprise_integration_status: "P3_REQUIRED",
    enterprise_connectors: "C0_DISABLED",
    stable_principal_owner: "C05",
    business_authorization_owner: "C06",
    server_context_source: "VERIFIED_INTERNAL_GATEWAY",
    default_effect: "DENY",
  });
});

test("the decision body cannot assert trusted identity, routing or PDP inputs", async () => {
  const document = await contract();
  const request = document.components.schemas.AuthorizationDecisionRequest;
  const operation =
    document.paths["/internal/v1/authorization/decisions:evaluate"].post;

  assert.equal(request.additionalProperties, false);
  assert.deepEqual(Object.keys(request.properties).sort(), [
    "correlationId",
    "delegationId",
    "resourceId",
    "sessionToken",
  ]);
  assert.deepEqual(request.required.sort(), [
    "correlationId",
    "delegationId",
    "resourceId",
    "sessionToken",
  ]);
  assert.equal(request.properties.sessionToken.writeOnly, true);
  for (const forbidden of [
    "principalId",
    "humanPrincipalId",
    "workloadActorPrincipalId",
    "actorId",
    "tenantId",
    "storeId",
    "openFgaStoreId",
    "modelId",
    "authorizationModelId",
    "relation",
    "allow",
    "allowed",
    "contextualTuple",
    "contextualTuples",
  ]) {
    assert.equal(
      propertyKeys(request).has(forbidden),
      false,
      `${forbidden} must not be caller asserted`,
    );
  }
  assert.deepEqual(operation.security, [{ trustedWorkload: [] }]);
  assert.equal(operation["x-browser-direct-access"], false);
  assert.deepEqual(operation["x-server-context"], {
    source: "VERIFIED_INTERNAL_GATEWAY",
    accepted_from_request_body: false,
    required_fields: [
      "synthetic",
      "routeTrustSource",
      "tenantId",
      "surface",
      "workloadTrustSource",
      "workloadActorPrincipalId",
    ],
  });
});

test("the control surface contains exactly four closed commands", async () => {
  const document = await contract();
  const schemas = document.components.schemas;
  const commands = schemas.AuthorizationCommand.oneOf.map(({ $ref }) => {
    const schemaName = $ref.split("/").at(-1);
    return schemas[schemaName].properties.kind.const;
  });

  assert.deepEqual(commands, [
    "STAGE_SYNTHETIC_POLICY_RELEASE",
    "RECORD_POLICY_PROJECTION",
    "ACTIVATE_POLICY_RELEASE",
    "ROLLBACK_POLICY_RELEASE",
  ]);
  assert.deepEqual(
    Object.keys(
      document.paths["/internal/v1/authorization/commands"].post[
        "x-required-capability-by-command-kind"
      ],
    ),
    commands,
  );
  for (const { $ref } of schemas.AuthorizationCommand.oneOf) {
    const name = $ref.split("/").at(-1);
    assert.equal(
      schemas[name].additionalProperties,
      false,
      `${name} must reject extra control fields`,
    );
  }
});

test("replay is evidence comparison rather than a new authorization decision", async () => {
  const document = await contract();
  const schemas = document.components.schemas;

  assert.deepEqual(Object.keys(schemas.ReplayRequest.properties), [
    "decisionId",
  ]);
  assert.deepEqual(schemas.ReplayRequest.required, ["decisionId"]);
  assert.equal(schemas.ReplayRequest.additionalProperties, false);
  assert.equal(
    schemas.ReplayResult.properties.authorizationStatus.const,
    "NOT_AUTHORIZATION",
  );
});

test("all declared object schemas reject unsupported fields", async () => {
  const document = await contract();
  const objectSchemas = Object.entries(document.components.schemas).filter(
    ([, schema]) => schema.type === "object",
  );

  assert.equal(objectSchemas.length > 0, true);
  for (const [name, schema] of objectSchemas) {
    assert.equal(
      schema.additionalProperties,
      false,
      `${name} must be closed`,
    );
  }
});

test("decision outputs never echo secrets or caller credentials", async () => {
  const document = await contract();
  const properties =
    document.components.schemas.AuthorizationDecision.properties;

  assert.equal(properties.humanSecurityEpoch.minimum, 1);
  assert.equal(properties.workloadActorSecurityEpoch.minimum, 1);
  assert.equal(
    properties.tupleBundleSha256.$ref,
    "#/components/schemas/Sha256",
  );
  for (const forbidden of [
    "sessionToken",
    "password",
    "cookie",
    "claims",
    "accessToken",
    "refreshToken",
  ]) {
    assert.equal(forbidden in properties, false);
  }
});
