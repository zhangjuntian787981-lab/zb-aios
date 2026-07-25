import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractUrl = new URL(
  "../implementation/p1/c04/identity-federation.openapi.v1.json",
  import.meta.url,
);

async function contract() {
  return JSON.parse(await readFile(contractUrl, "utf8"));
}

test("the C04 contract exposes the five deep-module operations", async () => {
  const document = await contract();
  const operationIds = Object.values(document.paths).flatMap((path) =>
    Object.values(path)
      .filter((operation) => operation?.operationId)
      .map(({ operationId }) => operationId),
  );

  assert.deepEqual(operationIds.sort(), [
    "completeSyntheticLogin",
    "executeIdentityCommand",
    "getIdentitySnapshot",
    "resolveSyntheticSession",
    "startSyntheticLogin",
  ]);
});

test("the P1 command contract contains no Enterprise, merge or authorization command", async () => {
  const document = await contract();
  const text = JSON.stringify(document);
  const commands =
    document.components.schemas.IdentityCommand.oneOf.map(({ $ref }) => {
      const name = $ref.split("/").at(-1);
      return document.components.schemas[name].properties.kind.const;
    });

  assert.deepEqual(commands, [
    "APPLY_TENANT_LIFECYCLE_EVENT",
    "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
    "ROTATE_SYNTHETIC_PROVIDER_KEYS",
    "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION",
    "REVOKE_SESSION",
  ]);
  assert.equal(text.includes("CREATE_ENTERPRISE_IDENTITY"), false);
  assert.equal(text.includes("MERGE_USER"), false);
  assert.equal(text.includes("principalId"), false);
  assert.equal(text.includes("\"ALLOWED\""), false);
});

test("the Tenant lifecycle command carries the exact authoritative C03 source tuple", async () => {
  const document = await contract();
  const schema = document.components.schemas.ApplyTenantLifecycle;
  const sourceFields = [
    "sourceLifecycleVersion",
    "sourceGeneration",
    "sourceOperationId",
    "sourceState",
  ];

  for (const field of sourceFields) {
    assert.equal(schema.required.includes(field), true);
    assert.equal(field in schema.properties, true);
  }
  assert.deepEqual(
    document["x-c04-boundary"].implemented_upstream_protocols,
    ["OIDC", "SAML"],
  );
  assert.equal(
    document["x-c04-boundary"].oidc_evidence,
    "CORE_RUNTIME_VERIFIED_SYNTHETIC_ONLY",
  );
  assert.equal(
    document["x-c04-boundary"].saml_evidence,
    "BROKER_PROTOCOL_RUNTIME_ONLY",
  );
  assert.equal(
    document["x-c04-boundary"].scim_evidence,
    "PREVIEW_ADAPTER_RUNTIME_ONLY",
  );
  assert.equal(
    document["x-c04-boundary"].production_verification_status,
    "NOT_VERIFIED",
  );
  assert.equal(
    document["x-c04-boundary"].p1_engineering_verification_status,
    "VERIFIED",
  );
  assert.equal(
    document["x-c04-boundary"].oidc_mfa_evidence,
    "REAL_PASSWORD_TOTP_AND_AMR_VERIFIED_SYNTHETIC_ONLY",
  );
  assert.equal(
    document["x-c04-boundary"].saml_no_jit_evidence,
    "UNKNOWN_UNLINKED_USER_REJECTED",
  );
  assert.equal(
    document["x-c04-boundary"].scim_component_evidence,
    "CORE_BRIDGE_AND_POSTGRES_CHECKPOINT_VERIFIED_SEPARATELY",
  );
});

test("authentication responses explicitly leave business authorization unevaluated", async () => {
  const document = await contract();
  const context = document.components.schemas.AuthenticationContext;
  const session = document.components.schemas.AuthenticatedSession;

  assert.equal(
    document["x-c04-boundary"].authentication_is_not_authorization,
    true,
  );
  assert.equal(
    context.properties.authorizationStatus.const,
    "NOT_EVALUATED",
  );
  assert.equal(context.properties.tenantKind.const, "SYNTHETIC");
  assert.equal("email" in context.properties, false);
  assert.equal("roles" in context.properties, false);
  assert.equal("groups" in context.properties, false);
  assert.equal(session.additionalProperties, false);
  assert.equal("allOf" in session, false);
  for (const field of [
    ...context.required,
    "expiresAt",
    "sessionToken",
  ]) {
    assert.equal(session.required.includes(field), true);
    assert.equal(field in session.properties, true);
  }
  const challenge = document.components.schemas.LoginChallenge;
  assert.equal(challenge.properties.state.readOnly, true);
  assert.equal(challenge.properties.codeVerifier.readOnly, true);
  assert.equal(session.properties.sessionToken.readOnly, true);
  assert.equal(
    "headers" in
      document.paths["/internal/v1/identity/login:complete"].post
        .responses["200"],
    false,
  );
});

test("login and session operations require a trusted BFF boundary", async () => {
  const document = await contract();
  assert.equal(
    document.components.securitySchemes.trustedBff.type,
    "mutualTLS",
  );
  for (const path of [
    "/internal/v1/identity/login:start",
    "/internal/v1/identity/login:complete",
    "/internal/v1/identity/sessions:resolve",
  ]) {
    const operation = document.paths[path].post;
    assert.deepEqual(operation.security, [{ trustedBff: [] }]);
    assert.equal(operation["x-trusted-server-context-required"], true);
    assert.equal(operation["x-browser-direct-access"], false);
  }
});

test("sensitive login fields declare the Core length boundaries", async () => {
  const document = await contract();
  const schemas = document.components.schemas;

  assert.deepEqual(
    {
      state: [
        schemas.LoginChallenge.properties.state.minLength,
        schemas.LoginChallenge.properties.state.maxLength,
      ],
      verifier: [
        schemas.LoginChallenge.properties.codeVerifier.minLength,
        schemas.LoginChallenge.properties.codeVerifier.maxLength,
      ],
      session: [
        schemas.AuthenticatedSession.properties.sessionToken.minLength,
        schemas.AuthenticatedSession.properties.sessionToken.maxLength,
      ],
    },
    {
      state: [43, 128],
      verifier: [43, 128],
      session: [43, 128],
    },
  );
  assert.equal(
    schemas.CompleteLogin.properties.authorizationCode.maxLength,
    2048,
  );
  assert.equal(schemas.CompleteLogin.properties.state.maxLength, 128);
  assert.equal(
    schemas.CompleteLogin.properties.codeVerifier.maxLength,
    128,
  );
  assert.equal(schemas.ResolveSession.properties.sessionToken.maxLength, 128);
});

test("the governance snapshot declares every field returned by the module", async () => {
  const document = await contract();
  const snapshot = document.components.schemas.IdentitySnapshot;

  for (const field of [
    "tenantId",
    "tenantKind",
    "projectionState",
    "generation",
    "operationId",
    "revocationEpoch",
    "provider",
    "accounts",
    "sessions",
    "events",
    "outbox",
    "authorizationStatus",
  ]) {
    assert.equal(snapshot.required.includes(field), true);
    assert.equal(field in snapshot.properties, true);
  }
  for (const schemaName of [
    "ProviderSnapshot",
    "AccountSnapshot",
    "SessionSnapshot",
  ]) {
    assert.equal(
      document.components.schemas[schemaName].additionalProperties,
      false,
    );
  }
  assert.equal(
    snapshot.properties.provider.$ref,
    "#/components/schemas/ProviderSnapshot",
  );
  assert.equal(
    snapshot.properties.accounts.items.$ref,
    "#/components/schemas/AccountSnapshot",
  );
  assert.equal(
    snapshot.properties.sessions.items.$ref,
    "#/components/schemas/SessionSnapshot",
  );
});
