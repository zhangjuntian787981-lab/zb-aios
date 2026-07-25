import assert from "node:assert/strict";
import test from "node:test";
import {
  createIdentityFederation,
  createMemoryIdentityStore,
  createSyntheticIdentityCatalog,
} from "../lib/identity-federation.mjs";
import {
  ScimIdentityProvisionerError,
  createScimIdentityProvisioner,
} from "../lib/scim-identity-provisioner.mjs";

const TENANT_ID = "stn_01984700-0000-7000-8000-000000000001";
const PROVIDER_ID = "idp_01984700-0000-7000-8000-000000000065";
const FIXTURE_USER_ID = "northstar-fasteners-user-ava";
const DIRECTORY_OBJECT_ID = "northstar-directory-ava";
const ISSUER =
  "https://idp.northstar-fasteners.example/realms/synthetic";
const CLIENT_ID = "synthetic-aios-portal";
const REDIRECT_URI =
  "https://portal.northstar-fasteners.example/auth/callback";
const NOW = "2026-07-26T04:00:00.000Z";
const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-northstar-fasteners",
  sha256:
    "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
});
const PROJECT_CONTEXT = Object.freeze({
  actorId: "syn_svc_identity_projection",
  capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
  synthetic: true,
});
const CORE_CONTEXT = Object.freeze({
  actorId: "syn_svc_identity_provisioning",
  capabilities: ["IDENTITY_PROVISIONING_APPLY"],
  synthetic: true,
});
const SERVER_CONTEXT = Object.freeze({
  actorId: "syn_svc_portal_bff",
  synthetic: true,
});
const TENANT_REGISTRY_CONTEXT = Object.freeze({
  actorId: "syn_svc_identity_tenant_reader",
  capabilities: ["TENANT_LIFECYCLE_READ"],
  synthetic: true,
});

function deterministicUuidFactory() {
  let counter = 100;
  return () => {
    counter += 1;
    return `01984700-0000-7000-8000-${counter
      .toString(16)
      .padStart(12, "0")}`;
  };
}

function deterministicSecretFactory() {
  let counter = 0;
  return () => {
    counter += 1;
    return counter.toString(16).padStart(64, "0");
  };
}

function resolvedAccount(overrides = {}) {
  return {
    tenantId: TENANT_ID,
    providerConnectionId: PROVIDER_ID,
    fixtureUserId: FIXTURE_USER_ID,
    directoryObjectId: DIRECTORY_OBJECT_ID,
    loginSubject: FIXTURE_USER_ID,
    profile: {
      givenName: "Ava",
      familyName: "Synthetic",
      email: "ava@northstar-fasteners.example",
    },
    ...overrides,
  };
}

function source(
  sourceRevision,
  desiredState,
  sourceEventId = `source-${sourceRevision}-${desiredState}`,
) {
  return {
    fixtureUserId: FIXTURE_USER_ID,
    sourceEventId,
    sourceRevision,
    desiredState,
    correlationId: `correlation-${sourceEventId}`,
  };
}

function createScimPort() {
  const calls = [];
  let failures = 0;
  return {
    calls,
    failNext() {
      failures += 1;
    },
    async apply(command) {
      calls.push(structuredClone(command));
      if (failures > 0) {
        failures -= 1;
        throw new Error("Synthetic SCIM failure.");
      }
      return {
        externalId: command.externalId,
        resourceId: "synthetic-scim-resource-001",
        sourceRevision: command.sourceRevision,
        state: command.desiredState,
        applied: true,
        stale: false,
      };
    },
  };
}

async function createHarness() {
  const tenant = {
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    synthetic: true,
    state: "PROVISIONING",
    lifecycleVersion: 1,
    generation: 1,
    operationId: "op_01984700-0000-7000-8000-000000000002",
    fixtureRef: FIXTURE_REF,
    trustSource: "VERIFIED_SERVER_CONTEXT",
  };
  let authorizationRequest;
  const federationBroker = {
    async startAuthorization(request) {
      authorizationRequest = structuredClone(request);
      return {
        authorizationUrl:
          `${ISSUER}/protocol/openid-connect/auth`,
      };
    },
    async exchangeAndVerify() {
      return {
        protocol: "OIDC",
        signatureVerified: true,
        synthetic: true,
        issuer: ISSUER,
        audience: [CLIENT_ID],
        authorizedParty: CLIENT_ID,
        subject: FIXTURE_USER_ID,
        nonce: authorizationRequest.nonce,
        issuedAt: NOW,
        notBefore: NOW,
        expiresAt: "2026-07-26T05:00:00.000Z",
        authenticationTime: NOW,
        authenticationMethods: ["pwd", "mfa"],
        algorithm: "RS256",
        keyId: "synthetic-k1",
        configurationVersion: 1,
      };
    },
  };
  const tenantRegistry = {
    async snapshot(context, tenantId) {
      assert.deepEqual(context, TENANT_REGISTRY_CONTEXT);
      assert.equal(tenantId, TENANT_ID);
      return structuredClone(tenant);
    },
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      if (
        tenantId !== TENANT_ID ||
        expectedTenantKind !== "SYNTHETIC" ||
        tenant.state !== "ACTIVE"
      ) {
        throw new Error("Synthetic tenant is unavailable.");
      }
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const identity = createIdentityFederation({
    store: createMemoryIdentityStore(),
    tenantRegistry,
    tenantRegistryContext: TENANT_REGISTRY_CONTEXT,
    identityCatalog: createSyntheticIdentityCatalog([
      {
        ...FIXTURE_REF,
        provider: {
          issuer: ISSUER,
          clientId: CLIENT_ID,
          redirectRoutes: { PORTAL_HOME: REDIRECT_URI },
          configurationVersion: 1,
          allowedAlgorithms: ["RS256"],
          allowedKeyIds: ["synthetic-k1"],
          requiredAuthenticationMethods: ["mfa"],
          maxAuthenticationAgeSeconds: 3600,
          upstreamProtocols: ["OIDC"],
        },
        users: [
          {
            fixtureUserId: FIXTURE_USER_ID,
            directoryObjectId: DIRECTORY_OBJECT_ID,
            loginSubject: FIXTURE_USER_ID,
            profileRef:
              "fixture://synthetic-tenant-northstar-fasteners/users/ava",
          },
        ],
      },
    ]),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    federationBroker,
    clock: () => NOW,
    idFactory: deterministicUuidFactory(),
    secretFactory: deterministicSecretFactory(),
  });
  const projected = await identity.execute(PROJECT_CONTEXT, {
    kind: "APPLY_TENANT_LIFECYCLE_EVENT",
    idempotencyKey: "project-synthetic-tenant",
    tenantId: TENANT_ID,
    sourceEventId: "tenant-source-001",
    sourceLifecycleVersion: tenant.lifecycleVersion,
    sourceGeneration: tenant.generation,
    sourceOperationId: tenant.operationId,
    sourceState: tenant.state,
    correlationId: "project-synthetic-tenant",
  });
  assert.equal(projected.providerConnectionId, PROVIDER_ID);
  tenant.state = "ACTIVE";
  tenant.lifecycleVersion += 1;
  const scimAdapter = createScimPort();
  const provisioner = createScimIdentityProvisioner({
    tenantId: TENANT_ID,
    providerConnectionId: PROVIDER_ID,
    coreContext: CORE_CONTEXT,
    identityFederation: identity,
    scimAdapter,
    resolveSyntheticAccount: async () => resolvedAccount(),
  });

  async function snapshot() {
    return identity.snapshot(PROJECT_CONTEXT, { tenantId: TENANT_ID });
  }

  async function login() {
    const started = await identity.startLogin(SERVER_CONTEXT, {
      tenantId: TENANT_ID,
      providerConnectionId: PROVIDER_ID,
      returnRoute: "PORTAL_HOME",
    });
    return identity.completeLogin(SERVER_CONTEXT, {
      transactionId: started.transactionId,
      state: started.state,
      authorizationCode: "synthetic-code",
      codeVerifier: started.codeVerifier,
    });
  }

  return { identity, login, provisioner, scimAdapter, snapshot };
}

function countOutbox(snapshot, type) {
  return snapshot.outbox.filter((event) => event.type === type).length;
}

test("Core commits ACTIVE, revokes sessions, and retries SCIM without duplicate Outbox", async () => {
  const harness = await createHarness();

  const active = await harness.provisioner.apply(source(1, "ACTIVE"));
  assert.equal(active.core.applied, true);
  assert.equal(active.scim.externalId, DIRECTORY_OBJECT_ID);
  const firstSession = await harness.login();

  harness.scimAdapter.failNext();
  await assert.rejects(
    harness.provisioner.apply(source(2, "SUSPENDED")),
    /Synthetic SCIM failure/,
  );
  const afterFailure = await harness.snapshot();
  assert.equal(afterFailure.accounts[0].state, "SUSPENDED");
  assert.equal(afterFailure.sessions[0].status, "REVOKED");
  assert.equal(
    countOutbox(
      afterFailure,
      "product.identity.account-updated.v1",
    ),
    1,
  );
  await assert.rejects(
    harness.identity.resolveSession(SERVER_CONTEXT, {
      sessionToken: firstSession.sessionToken,
      expectedTenantId: TENANT_ID,
    }),
    (error) => error.code === "SESSION_INVALID",
  );

  const retried = await harness.provisioner.apply(
    source(2, "SUSPENDED"),
  );
  assert.equal(retried.core.duplicate, true);
  assert.equal(retried.scim.state, "SUSPENDED");
  const afterRetry = await harness.snapshot();
  assert.equal(
    countOutbox(afterRetry, "product.identity.account-updated.v1"),
    1,
  );

  await harness.provisioner.apply(source(3, "ACTIVE"));
  const secondSession = await harness.login();
  const terminated = await harness.provisioner.apply(
    source(4, "TERMINATED"),
  );
  assert.equal(terminated.scim.state, "TERMINATED");
  const finalSnapshot = await harness.snapshot();
  assert.equal(finalSnapshot.accounts[0].state, "TERMINATED");
  assert.equal(finalSnapshot.sessions.at(-1).status, "REVOKED");
  assert.equal(
    countOutbox(
      finalSnapshot,
      "product.identity.account-terminated.v1",
    ),
    1,
  );
  await assert.rejects(
    harness.identity.resolveSession(SERVER_CONTEXT, {
      sessionToken: secondSession.sessionToken,
      expectedTenantId: TENANT_ID,
    }),
    (error) => error.code === "SESSION_INVALID",
  );
});

test("replay reconciles SCIM while stale, terminal revival, and event tampering do not call it", async () => {
  const harness = await createHarness();
  const activeSource = source(1, "ACTIVE", "stable-source");
  await harness.provisioner.apply(activeSource);
  const replay = await harness.provisioner.apply(activeSource);
  assert.equal(replay.core.duplicate, true);
  assert.equal(harness.scimAdapter.calls.length, 2);

  await harness.provisioner.apply(source(3, "TERMINATED"));
  const beforeRejectedCommands = harness.scimAdapter.calls.length;
  const stale = await harness.provisioner.apply(source(2, "SUSPENDED"));
  assert.equal(stale.core.stale, true);
  assert.equal(stale.scim, null);
  assert.equal(
    harness.scimAdapter.calls.length,
    beforeRejectedCommands,
  );

  await assert.rejects(
    harness.provisioner.apply(source(4, "ACTIVE")),
    (error) => error.code === "TERMINATED_ACCOUNT",
  );
  assert.equal(
    harness.scimAdapter.calls.length,
    beforeRejectedCommands,
  );

  const secondHarness = await createHarness();
  await secondHarness.provisioner.apply(
    source(1, "ACTIVE", "immutable-event"),
  );
  const beforeTamper = secondHarness.scimAdapter.calls.length;
  await assert.rejects(
    secondHarness.provisioner.apply(
      source(2, "SUSPENDED", "immutable-event"),
    ),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );
  assert.equal(secondHarness.scimAdapter.calls.length, beforeTamper);
});

test("the fixed resolver binding and generated idempotency key fail closed", async () => {
  const executeCalls = [];
  const scimCalls = [];
  const originalContext = {
    actorId: "syn_svc_identity_provisioning",
    capabilities: ["IDENTITY_PROVISIONING_APPLY"],
    synthetic: true,
  };
  const identityFederation = {
    async execute(context, command) {
      executeCalls.push({
        context: structuredClone(context),
        command: structuredClone(command),
      });
      return {
        accountId: "sia_synthetic",
        state: command.desiredState,
        lifecycleVersion: 1,
        revocationEpoch: 1,
        applied: true,
        duplicate: false,
      };
    },
  };
  const scimAdapter = {
    async apply(command) {
      scimCalls.push(structuredClone(command));
      return {
        externalId: command.externalId,
        resourceId: "resource-001",
        sourceRevision: command.sourceRevision,
        state: command.desiredState,
        applied: true,
        stale: false,
      };
    },
  };
  const provisioner = createScimIdentityProvisioner({
    tenantId: TENANT_ID,
    providerConnectionId: PROVIDER_ID,
    coreContext: originalContext,
    identityFederation,
    scimAdapter,
    resolveSyntheticAccount: async () => resolvedAccount(),
  });
  originalContext.actorId = "tampered";
  originalContext.capabilities.push("UNEXPECTED");
  await provisioner.apply(source(1, "ACTIVE", "hash-source"));

  assert.equal(
    executeCalls[0].context.actorId,
    "syn_svc_identity_provisioning",
  );
  assert.deepEqual(
    executeCalls[0].context.capabilities,
    ["IDENTITY_PROVISIONING_APPLY"],
  );
  assert.match(
    executeCalls[0].command.idempotencyKey,
    /^c04-scim-[a-f0-9]{64}$/,
  );
  assert.equal(scimCalls[0].externalId, DIRECTORY_OBJECT_ID);
  assert.equal(scimCalls[0].userName, FIXTURE_USER_ID);

  const wrongBinding = createScimIdentityProvisioner({
    tenantId: TENANT_ID,
    providerConnectionId: PROVIDER_ID,
    coreContext: CORE_CONTEXT,
    identityFederation,
    scimAdapter,
    resolveSyntheticAccount: async () =>
      resolvedAccount({ tenantId: "wrong-tenant" }),
  });
  await assert.rejects(
    wrongBinding.apply(source(1, "ACTIVE")),
    (error) => {
      assert.ok(error instanceof ScimIdentityProvisionerError);
      return error.code === "IDENTITY_BINDING_CONFLICT";
    },
  );
  assert.equal(executeCalls.length, 1);
  assert.equal(scimCalls.length, 1);

  await assert.rejects(
    provisioner.apply({
      ...source(2, "ACTIVE"),
      externalId: "caller-controlled",
    }),
    (error) => error.code === "INVALID_INPUT",
  );
  assert.equal(executeCalls.length, 1);

  assert.throws(
    () =>
      createScimIdentityProvisioner({
        tenantId: TENANT_ID.replace("stn_", "etn_"),
        providerConnectionId: PROVIDER_ID,
        coreContext: CORE_CONTEXT,
        identityFederation,
        scimAdapter,
        resolveSyntheticAccount: async () => resolvedAccount(),
      }),
    (error) => error.code === "INVALID_INPUT",
  );
});

test("a mismatched SCIM receipt is never reported as successful", async () => {
  const provisioner = createScimIdentityProvisioner({
    tenantId: TENANT_ID,
    providerConnectionId: PROVIDER_ID,
    coreContext: CORE_CONTEXT,
    identityFederation: {
      async execute(_context, command) {
        return {
          accountId: "sia_synthetic",
          state: command.desiredState,
          lifecycleVersion: 1,
          revocationEpoch: 1,
          applied: true,
          duplicate: false,
        };
      },
    },
    scimAdapter: {
      async apply(command) {
        return {
          externalId: "wrong-external-id",
          resourceId: "resource-001",
          sourceRevision: command.sourceRevision,
          state: command.desiredState,
          applied: true,
          stale: false,
        };
      },
    },
    resolveSyntheticAccount: async () => resolvedAccount(),
  });

  await assert.rejects(
    provisioner.apply(source(1, "ACTIVE")),
    (error) => error.code === "SCIM_RESULT_MISMATCH",
  );
});
