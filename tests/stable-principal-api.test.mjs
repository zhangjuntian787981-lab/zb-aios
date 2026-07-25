import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractUrl = new URL(
  "../implementation/p1/c05/stable-principal.openapi.v1.json",
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

test("the C05 contract exposes only the three deep-module operations", async () => {
  const document = await contract();

  assert.equal(document.openapi, "3.1.2");
  assert.deepEqual(operationIds(document).sort(), [
    "executePrincipalCommand",
    "getPrincipalSnapshot",
    "resolveActionIdentity",
  ]);
  assert.deepEqual(Object.keys(document.paths).sort(), [
    "/internal/v1/stable-principals/actions:resolve",
    "/internal/v1/stable-principals/commands",
    "/internal/v1/stable-principals/tenants/{tenantId}",
  ]);
});

test("the command surface contains exactly the eight frozen C05 commands", async () => {
  const document = await contract();
  const schemas = document.components.schemas;
  const commands = schemas.PrincipalCommand.oneOf.map(({ $ref }) => {
    const schemaName = $ref.split("/").at(-1);
    return schemas[schemaName].properties.kind.const;
  });

  assert.deepEqual(commands, [
    "CREATE_SYNTHETIC_PRINCIPAL",
    "LINK_IDENTITY_ACCOUNT",
    "RETIRE_IDENTITY_LINK",
    "REASSIGN_IDENTITY_ACCOUNT",
    "CHANGE_PRINCIPAL_STATE",
    "SYNC_IDENTITY_ACCOUNT",
    "CREATE_DELEGATION",
    "REVOKE_DELEGATION",
  ]);
  assert.deepEqual(
    Object.keys(
      document.paths["/internal/v1/stable-principals/commands"].post[
        "x-required-scope-by-command-kind"
      ],
    ),
    commands,
  );
});

test("each command result has a closed discriminator without a business authorization decision", async () => {
  const document = await contract();
  const schemas = document.components.schemas;
  const receiptNames = schemas.CommandReceipt.oneOf.map(({ $ref }) =>
    $ref.split("/").at(-1),
  );

  assert.equal(receiptNames.length, 8);
  assert.equal(
    schemas.CommandReceipt.discriminator.propertyName,
    "commandKind",
  );
  for (const receiptName of receiptNames) {
    const receipt = schemas[receiptName];
    assert.equal(receipt.additionalProperties, false);
    assert.equal(receipt.required.includes("commandKind"), true);
    assert.equal(receipt.required.includes("tenantId"), true);
    assert.equal(receipt.required.includes("applied"), true);
    assert.equal(receipt.required.includes("duplicate"), true);
    assert.equal(
      "authorizationStatus" in receipt.properties,
      false,
      `${receiptName} must not claim a C06 authorization decision`,
    );
    assert.equal(
      schemas.CommandReceipt.discriminator.mapping[
        receipt.properties.commandKind.const
      ],
      `#/components/schemas/${receiptName}`,
    );
  }
});

test("all object schemas are closed against unsupported fields", async () => {
  const document = await contract();
  const objectSchemas = Object.entries(document.components.schemas).filter(
    ([, schema]) => schema.type === "object",
  );

  assert.equal(objectSchemas.length > 0, true);
  for (const [name, schema] of objectSchemas) {
    assert.equal(
      schema.additionalProperties,
      false,
      `${name} must reject unsupported fields`,
    );
  }
});

test("action resolution accepts only a session, expected Tenant and leaf delegation", async () => {
  const document = await contract();
  const request = document.components.schemas.ActionIdentityRequest;
  const operation =
    document.paths["/internal/v1/stable-principals/actions:resolve"].post;

  assert.deepEqual(Object.keys(request.properties).sort(), [
    "delegationId",
    "expectedTenantId",
    "sessionToken",
  ]);
  assert.deepEqual(request.required.sort(), [
    "delegationId",
    "expectedTenantId",
    "sessionToken",
  ]);
  assert.equal(request.properties.sessionToken.writeOnly, true);
  assert.equal("workloadActorPrincipalId" in request.properties, false);
  assert.equal("humanSubjectPrincipalId" in request.properties, false);
  assert.equal("identityAccountId" in request.properties, false);
  assert.deepEqual(operation.security, [{ trustedWorkload: [] }]);
  assert.equal(operation["x-trusted-server-context-required"], true);
  assert.equal(operation["x-browser-direct-access"], false);
  assert.equal(operation["x-workload-actor-request-field"], false);
  assert.equal(
    document.components.securitySchemes.trustedWorkload.type,
    "mutualTLS",
  );
});

test("the resolved action context contains the exact subject, actor and parent chain", async () => {
  const document = await contract();
  const schemas = document.components.schemas;
  const context = schemas.ActionIdentityContext;

  assert.deepEqual(context.required, [
    "tenantId",
    "tenantKind",
    "identityAccountId",
    "identityLinkId",
    "sessionId",
    "humanSubject",
    "workloadActor",
    "purposeRef",
    "delegationChain",
    "trustSource",
    "authorizationStatus",
  ]);
  assert.equal(context.properties.tenantKind.const, "SYNTHETIC");
  assert.equal(
    context.properties.trustSource.const,
    "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
  );
  assert.equal(
    context.properties.authorizationStatus.const,
    "NOT_EVALUATED",
  );
  assert.equal(context.properties.delegationChain.minItems, 1);
  assert.equal(context.properties.delegationChain.maxItems, 8);
  assert.equal(
    context.properties.delegationChain.items.$ref,
    "#/components/schemas/DelegationStep",
  );
  assert.equal(schemas.HumanSubject.properties.principalType.const, "HUMAN");
  assert.deepEqual(schemas.WorkloadActor.properties.principalType.enum, [
    "AGENT",
    "SERVICE",
  ]);
  for (const schema of [
    schemas.HumanSubject,
    schemas.WorkloadActor,
  ]) {
    assert.equal("lifecycleVersion" in schema.properties, true);
    assert.equal("securityEpoch" in schema.properties, true);
  }
  assert.deepEqual(schemas.DelegationStep.required, [
    "delegationId",
    "delegatorPrincipalId",
    "delegatePrincipalId",
    "purposeRef",
    "lifecycleVersion",
    "expiresAt",
  ]);
  assert.equal(
    schemas.DelegationStep.properties.purposeRef.$ref,
    "#/components/schemas/SyntheticReference",
  );
  assert.equal(
    context.properties.purposeRef.$ref,
    "#/components/schemas/SyntheticReference",
  );
});

test("delegation records express provenance without granting business authorization", async () => {
  const document = await contract();
  const schemas = document.components.schemas;
  const delegationSchemas = {
    CreateDelegation: schemas.CreateDelegation,
    DelegationStep: schemas.DelegationStep,
    DelegationRecord: schemas.DelegationRecord,
  };
  const forbidden = new Set([
    "action",
    "actions",
    "group",
    "groups",
    "permission",
    "permissions",
    "role",
    "roles",
    "scope",
    "scopes",
  ]);

  for (const [name, schema] of Object.entries(delegationSchemas)) {
    for (const key of propertyKeys(schema)) {
      assert.equal(
        forbidden.has(key),
        false,
        `${name}.${key} must not grant business authorization`,
      );
    }
  }
  assert.equal(
    document["x-c05-boundary"].delegation_is_not_authorization,
    true,
  );
  assert.equal(
    document["x-c05-boundary"].business_authorization_owner,
    "C06",
  );
});

test("SYNC_IDENTITY_ACCOUNT accepts no caller-asserted C04 state or version", async () => {
  const document = await contract();
  const sync = document.components.schemas.SyncIdentityAccount;

  assert.deepEqual(Object.keys(sync.properties).sort(), [
    "correlationId",
    "idempotencyKey",
    "identityAccountId",
    "kind",
    "tenantId",
  ]);
  for (const forbidden of [
    "accountState",
    "sourceEventId",
    "sourceLifecycleVersion",
    "sourceRevocationEpoch",
  ]) {
    assert.equal(forbidden in sync.properties, false);
  }
});

test("IdentityLink changes stay explicit and versioned", async () => {
  const document = await contract();
  const schemas = document.components.schemas;

  assert.deepEqual(
    schemas.LinkIdentityAccount.required.filter((field) =>
      [
        "principalId",
        "identityAccountId",
        "linkEvidenceRef",
      ].includes(field),
    ),
    ["principalId", "identityAccountId", "linkEvidenceRef"],
  );
  assert.deepEqual(
    schemas.RetireIdentityLink.required.filter((field) =>
      ["identityLinkId", "expectedVersion", "reasonRef"].includes(field),
    ),
    ["identityLinkId", "expectedVersion", "reasonRef"],
  );
  assert.deepEqual(
    schemas.ReassignIdentityAccount.required.filter((field) =>
      [
        "identityLinkId",
        "targetPrincipalId",
        "expectedVersion",
        "reasonRef",
      ].includes(field),
    ),
    [
      "identityLinkId",
      "targetPrincipalId",
      "expectedVersion",
      "reasonRef",
    ],
  );
  assert.deepEqual(schemas.IdentityLinkRecord.properties.state.enum, [
    "ACTIVE",
    "SUSPENDED",
    "RETIRED",
  ]);
});

test("the public schemas contain no inferred identity or business grant fields", async () => {
  const document = await contract();
  const keys = propertyKeys(document.components.schemas);
  const forbidden = [
    "displayName",
    "employeeNumber",
    "email",
    "group",
    "groups",
    "permission",
    "permissions",
    "role",
    "roles",
  ];

  for (const key of forbidden) assert.equal(keys.has(key), false);
  assert.equal(
    document["x-c05-boundary"].email_is_not_identity_key,
    true,
  );
  assert.equal(
    document["x-c05-boundary"].action_authorization_status,
    "NOT_EVALUATED",
  );
});

test("C05 remains Synthetic-only and keeps every Enterprise Connector disabled", async () => {
  const document = await contract();
  const serializedCommands = JSON.stringify(
    document.components.schemas.PrincipalCommand,
  );

  assert.equal(document["x-c05-boundary"].phase, "P1");
  assert.equal(
    document["x-c05-boundary"].data_classification,
    "SYNTHETIC_ONLY",
  );
  assert.equal(
    document["x-c05-boundary"].p1_engineering_verification_status,
    "VERIFIED",
  );
  assert.equal(
    document["x-c05-boundary"].production_verification_status,
    "NOT_VERIFIED",
  );
  assert.equal(
    document["x-c05-boundary"].enterprise_identity,
    "P3_REQUIRED",
  );
  assert.equal(
    document["x-c05-boundary"].enterprise_connectors,
    "C0_DISABLED",
  );
  assert.equal(serializedCommands.includes("ENTERPRISE"), false);
  assert.equal(serializedCommands.includes("OA"), false);
  assert.equal(serializedCommands.includes("U9"), false);
  assert.equal(serializedCommands.includes("BI"), false);
});

test("C05 identifiers and canonical times match the runtime contract", async () => {
  const document = await contract();
  const schemas = document.components.schemas;

  assert.match(schemas.PrincipalId.pattern, /^\^prn_/);
  assert.match(schemas.IdentityLinkId.pattern, /^\^lnk_/);
  assert.match(schemas.DelegationId.pattern, /^\^dlg_/);
  assert.match(schemas.IdentityAccountId.pattern, /^\^sia_/);
  assert.equal(
    schemas.LinkIdentityAccount.properties.identityAccountId.$ref,
    "#/components/schemas/IdentityAccountId",
  );
  assert.equal(
    schemas.SyncIdentityAccount.properties.identityAccountId.$ref,
    "#/components/schemas/IdentityAccountId",
  );
  assert.equal(
    schemas.CreateDelegation.properties.expiresAt.$ref,
    "#/components/schemas/UtcMillisecondInstant",
  );
  assert.equal(
    schemas.DelegationStep.properties.expiresAt.$ref,
    "#/components/schemas/UtcMillisecondInstant",
  );
});
