import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import {
  createIdentityFederation,
  createMemoryIdentityStore,
  createSyntheticIdentityCatalog,
} from "../lib/identity-federation.mjs";
import { validateCloudEvent } from "../scripts/f03-contract-lab.mjs";

const TENANT_ID = "stn_01984700-0000-7000-8000-000000000001";
const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-northstar-fasteners",
  sha256:
    "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
});
const ISSUER =
  "https://idp.northstar-fasteners.example/realms/synthetic";
const CLIENT_ID = "synthetic-aios-portal";
const REDIRECT_URI =
  "https://portal.northstar-fasteners.example/auth/callback";
const apiContract = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c04/identity-federation.openapi.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const sessionRevocationSla = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c04/session-revocation-sla.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const contractValidator = new Ajv({
  allErrors: true,
  schemaId: "auto",
});
addFormats(contractValidator);
contractValidator.addKeyword({
  keyword: "x-sensitive",
  schemaType: "boolean",
});
for (const [name, schema] of Object.entries(
  apiContract.components.schemas,
)) {
  contractValidator.addSchema(schema, `#/components/schemas/${name}`);
}

function assertContract(schemaName, value) {
  const validate = contractValidator.getSchema(
    `#/components/schemas/${schemaName}`,
  );
  assert.equal(
    validate(value),
    true,
    JSON.stringify(validate.errors),
  );
}

const projectWorker = {
  actorId: "syn_svc_identity_projection",
  capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
  synthetic: true,
};
const provisioningWorker = {
  actorId: "syn_svc_identity_provisioning",
  capabilities: ["IDENTITY_PROVISIONING_APPLY", "IDENTITY_READ"],
  synthetic: true,
};
const sessionManager = {
  actorId: "syn_svc_session_manager",
  capabilities: ["IDENTITY_SESSION_REVOKE", "IDENTITY_READ"],
  synthetic: true,
};
const providerManager = {
  actorId: "syn_svc_identity_provider_manager",
  capabilities: ["IDENTITY_PROVIDER_ROTATE", "IDENTITY_READ"],
  synthetic: true,
};
const serverContext = {
  actorId: "syn_svc_portal_bff",
  synthetic: true,
};
const tenantRegistryContext = {
  actorId: "syn_svc_identity_tenant_reader",
  capabilities: ["TENANT_LIFECYCLE_READ"],
  synthetic: true,
};

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

function createCatalog() {
  return createSyntheticIdentityCatalog([
    {
      ...FIXTURE_REF,
      provider: {
        issuer: ISSUER,
        clientId: CLIENT_ID,
        redirectRoutes: {
          PORTAL_HOME: REDIRECT_URI,
        },
        configurationVersion: 1,
        allowedAlgorithms: ["RS256"],
        allowedKeyIds: ["synthetic-k1", "synthetic-k2"],
        requiredAuthenticationMethods: ["mfa"],
        maxAuthenticationAgeSeconds: 3600,
        upstreamProtocols: ["OIDC"],
      },
      users: [
        {
          fixtureUserId: "northstar-fasteners-user-ava",
          directoryObjectId: "northstar-directory-ava",
          loginSubject: "northstar-fasteners-user-ava",
          profileRef:
            "fixture://synthetic-tenant-northstar-fasteners/users/ava",
        },
        {
          fixtureUserId: "northstar-fasteners-user-noah",
          directoryObjectId: "northstar-directory-noah",
          loginSubject: "northstar-fasteners-user-noah",
          profileRef:
            "fixture://synthetic-tenant-northstar-fasteners/users/noah",
        },
      ],
    },
  ]);
}

function createHarness() {
  let currentTime = "2026-07-26T04:00:00.000Z";
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
  const broker = {
    starts: [],
    assertions: new Map(),
    exchangeCount: 0,
    beforeExchange: null,
    async startAuthorization(request) {
      this.starts.push(structuredClone(request));
      return {
        authorizationUrl:
          "https://idp.northstar-fasteners.example/realms/synthetic/protocol/openid-connect/auth",
      };
    },
    async exchangeAndVerify(request) {
      this.exchangeCount += 1;
      if (this.beforeExchange) await this.beforeExchange(request);
      const assertion = this.assertions.get(request.authorizationCode);
      if (assertion instanceof Error) throw assertion;
      return structuredClone(assertion);
    },
  };
  const lifecycleEvents = new Map();
  const tenantRegistry = {
    admissionCount: 0,
    beforeAdmission: null,
    async snapshot(context, tenantId) {
      assert.deepEqual(context, tenantRegistryContext);
      assert.equal(tenantId, TENANT_ID);
      return structuredClone(tenant);
    },
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      this.admissionCount += 1;
      if (this.beforeAdmission) {
        await this.beforeAdmission(this.admissionCount);
      }
      if (
        tenantId !== TENANT_ID ||
        expectedTenantKind !== "SYNTHETIC" ||
        tenant.state !== "ACTIVE"
      ) {
        throw new Error("tenant is not active");
      }
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: tenant.lifecycleVersion,
        trustSource: "VERIFIED_SERVER_CONTEXT",
      };
    },
  };
  const store = createMemoryIdentityStore();
  const identity = createIdentityFederation({
    store,
    tenantRegistry,
    tenantRegistryContext,
    identityCatalog: createCatalog(),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    federationBroker: broker,
    clock: () => currentTime,
    idFactory: deterministicUuidFactory(),
    secretFactory: deterministicSecretFactory(),
  });

  function lifecycleEvent(sourceEventId, overrides = {}) {
    if (!lifecycleEvents.has(sourceEventId)) {
      lifecycleEvents.set(sourceEventId, {
        kind: "APPLY_TENANT_LIFECYCLE_EVENT",
        idempotencyKey: `project-${sourceEventId}`,
        tenantId: TENANT_ID,
        sourceEventId,
        sourceLifecycleVersion: tenant.lifecycleVersion,
        sourceGeneration: tenant.generation,
        sourceOperationId: tenant.operationId,
        sourceState: tenant.state,
        correlationId: "c04-project-northstar",
      });
    }
    return {
      ...structuredClone(lifecycleEvents.get(sourceEventId)),
      ...overrides,
    };
  }

  async function projectTenant(sourceEventId = "tenant-event-001") {
    const result = await identity.execute(
      projectWorker,
      lifecycleEvent(sourceEventId),
    );
    if (tenant.state === "PROVISIONING") {
      tenant.state = "ACTIVE";
      tenant.lifecycleVersion += 1;
    }
    return result;
  }

  async function provisionUser({
    fixtureUserId = "northstar-fasteners-user-ava",
    sourceRevision = 1,
    desiredState = "ACTIVE",
    sourceEventId = `account-${fixtureUserId}-${sourceRevision}-${desiredState}`,
    idempotencyKey = sourceEventId,
    providerConnectionId,
  } = {}) {
    let connectionId = providerConnectionId;
    if (!connectionId) {
      const snapshot = await identity.snapshot(projectWorker, {
        tenantId: TENANT_ID,
      });
      connectionId = snapshot.provider.providerConnectionId;
    }
    return identity.execute(provisioningWorker, {
      kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
      idempotencyKey,
      tenantId: TENANT_ID,
      providerConnectionId: connectionId,
      fixtureUserId,
      sourceEventId,
      sourceRevision,
      desiredState,
      correlationId: "c04-account-northstar",
    });
  }

  function validAssertion({
    subject = "northstar-fasteners-user-ava",
    nonce = broker.starts.at(-1)?.nonce,
    ...overrides
  } = {}) {
    return {
      protocol: "OIDC",
      signatureVerified: true,
      synthetic: true,
      issuer: ISSUER,
      audience: [CLIENT_ID],
      authorizedParty: CLIENT_ID,
      subject,
      nonce,
      issuedAt: currentTime,
      notBefore: currentTime,
      expiresAt: "2026-07-26T05:00:00.000Z",
      authenticationTime: currentTime,
      authenticationMethods: ["pwd", "mfa"],
      algorithm: "RS256",
      keyId: "synthetic-k1",
      configurationVersion: 1,
      ...overrides,
    };
  }

  async function login({
    subject = "northstar-fasteners-user-ava",
    assertionOverrides = {},
    code = `code-${broker.starts.length + 1}`,
  } = {}) {
    const projection = await identity.snapshot(projectWorker, {
      tenantId: TENANT_ID,
    });
    const started = await identity.startLogin(serverContext, {
      tenantId: TENANT_ID,
      providerConnectionId: projection.provider.providerConnectionId,
      returnRoute: "PORTAL_HOME",
    });
    broker.assertions.set(
      code,
      validAssertion({ subject, ...assertionOverrides }),
    );
    const completed = await identity.completeLogin(serverContext, {
      transactionId: started.transactionId,
      state: started.state,
      authorizationCode: code,
      codeVerifier: started.codeVerifier,
    });
    return { started, completed, code };
  }

  return {
    identity,
    tenant,
    tenantRegistry,
    broker,
    lifecycleEvent,
    projectTenant,
    provisionUser,
    validAssertion,
    login,
    setTime(value) {
      currentTime = value;
    },
  };
}

test("the C04 module exposes only its five caller-facing entries", () => {
  const { identity } = createHarness();
  assert.deepEqual(Object.keys(identity).sort(), [
    "completeLogin",
    "execute",
    "resolveSession",
    "snapshot",
    "startLogin",
  ]);
});

test("the synthetic catalog rejects enterprise identity endpoints", () => {
  assert.throws(
    () =>
      createSyntheticIdentityCatalog([
        {
          ...FIXTURE_REF,
          provider: {
            issuer: "https://login.real-enterprise.com",
            clientId: CLIENT_ID,
            redirectRoutes: { PORTAL_HOME: REDIRECT_URI },
            configurationVersion: 1,
            allowedAlgorithms: ["RS256"],
            allowedKeyIds: ["k1"],
            requiredAuthenticationMethods: ["mfa"],
            maxAuthenticationAgeSeconds: 3600,
            upstreamProtocols: ["OIDC"],
          },
          users: [
            {
              fixtureUserId: "synthetic-user",
              directoryObjectId: "synthetic-directory-user",
              loginSubject: "synthetic-subject",
              profileRef: "fixture://synthetic/user",
            },
          ],
        },
      ]),
    (error) => error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
});

test("a C03 provisioning event creates one frozen synthetic provider projection", async () => {
  const { identity, lifecycleEvent, projectTenant } = createHarness();
  const first = await projectTenant();
  const replay = await identity.execute(projectWorker, lifecycleEvent(
    "tenant-event-001",
    {
    idempotencyKey: "project-replay-with-new-key",
    },
  ));

  assert.equal(first.projectionState, "READY");
  assert.equal(first.applied, true);
  assertContract("CommandReceipt", first);
  assert.equal(replay.providerConnectionId, first.providerConnectionId);
  assert.equal(replay.duplicate, true);

  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.tenantKind, "SYNTHETIC");
  assert.equal(snapshot.provider.issuer, ISSUER);
  assert.equal(snapshot.provider.policy, "SCIM_REQUIRED");
  assert.deepEqual(snapshot.provider.upstreamProtocols, ["OIDC"]);
  assert.equal(snapshot.events.length, 1);
  assert.equal(snapshot.outbox.length, 1);
  assert.deepEqual(Object.keys(snapshot.events[0]).sort(), [
    "correlationid",
    "data",
    "datacontenttype",
    "id",
    "source",
    "specversion",
    "subject",
    "synthetic",
    "tenantkind",
    "time",
    "type",
  ]);
  assert.deepEqual(validateCloudEvent(snapshot.events[0]), {
    valid: true,
    errors: [],
  });
});

test("a Tenant suspended before first C04 delivery creates a suspended projection", async () => {
  const { identity, lifecycleEvent, tenant } = createHarness();
  tenant.state = "SUSPENDED";
  tenant.lifecycleVersion += 1;

  const projected = await identity.execute(
    projectWorker,
    lifecycleEvent("tenant-event-early-suspension"),
  );
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });

  assert.equal(projected.projectionState, "SUSPENDED");
  assert.equal(snapshot.projectionState, "SUSPENDED");
  assert.equal(snapshot.provider.status, "ACTIVE");
  assert.equal(snapshot.events.length, 1);
});

test("a newer ACTIVE event restores READY before its older resume event arrives", async () => {
  const { identity, lifecycleEvent, projectTenant, tenant } = createHarness();
  await projectTenant();
  tenant.state = "SUSPENDED";
  tenant.lifecycleVersion += 1;
  await identity.execute(
    projectWorker,
    lifecycleEvent("tenant-event-suspended"),
  );

  tenant.state = "PROVISIONING";
  tenant.lifecycleVersion += 1;
  tenant.generation += 1;
  tenant.operationId = "op_01984700-0000-7000-8000-000000000004";
  const delayedResume = lifecycleEvent("tenant-event-resume-delayed");
  tenant.state = "ACTIVE";
  tenant.lifecycleVersion += 1;

  const restored = await identity.execute(
    projectWorker,
    lifecycleEvent("tenant-event-active-first"),
  );
  const staleResume = await identity.execute(projectWorker, delayedResume);
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });

  assert.equal(restored.projectionState, "READY");
  assert.equal(restored.generation, 2);
  assert.equal(restored.applied, true);
  assert.equal(staleResume.stale, true);
  assert.equal(staleResume.applied, false);
  assert.equal(snapshot.projectionState, "READY");
  assert.equal(snapshot.generation, 2);
});

test("a Tenant deleting before first C04 delivery creates a deleted tombstone", async () => {
  const { identity, lifecycleEvent, tenant } = createHarness();
  tenant.state = "DELETING";
  tenant.lifecycleVersion += 1;
  tenant.generation += 1;
  tenant.operationId = "op_01984700-0000-7000-8000-000000000003";

  const projected = await identity.execute(
    projectWorker,
    lifecycleEvent("tenant-event-early-deletion"),
  );
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });

  assert.equal(projected.projectionState, "DELETED");
  assert.equal(snapshot.projectionState, "DELETED");
  assert.equal(snapshot.provider.status, "DELETED");
  assert.equal(snapshot.accounts.length, 0);
});

test("a source event ID cannot be rebound to different lifecycle content", async () => {
  const { identity, lifecycleEvent, tenant, projectTenant } = createHarness();
  await projectTenant();
  tenant.state = "SUSPENDED";

  await assert.rejects(
    identity.execute(projectWorker, lifecycleEvent("tenant-event-001", {
      idempotencyKey: "lifecycle-event-conflict",
      correlationId: "changed-correlation",
    })),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("out-of-order and newer active snapshots cannot restore a terminated account", async () => {
  const { identity, projectTenant, provisionUser } = createHarness();
  await projectTenant();
  const active = await provisionUser({ sourceRevision: 1 });
  const terminated = await provisionUser({
    sourceRevision: 3,
    desiredState: "TERMINATED",
  });
  const stale = await provisionUser({
    sourceRevision: 2,
    desiredState: "ACTIVE",
  });

  assert.equal(active.state, "ACTIVE");
  assert.equal(terminated.state, "TERMINATED");
  assert.equal(stale.state, "TERMINATED");
  assert.equal(stale.applied, false);
  assert.equal(stale.stale, true);

  await assert.rejects(
    provisionUser({
      sourceRevision: 4,
      desiredState: "ACTIVE",
    }),
    (error) => error.code === "TERMINATED_ACCOUNT",
  );
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.accounts[0].state, "TERMINATED");
  assert.equal(snapshot.accounts[0].lifecycleVersion, 2);
});

test("the same source revision with different content fails closed", async () => {
  const { projectTenant, provisionUser } = createHarness();
  await projectTenant();
  await provisionUser({ sourceRevision: 1, desiredState: "ACTIVE" });

  await assert.rejects(
    provisionUser({
      sourceRevision: 1,
      desiredState: "SUSPENDED",
    }),
    (error) => error.code === "PROVISIONING_VERSION_CONFLICT",
  );
});

test("a newer ACTIVE identity revision revokes sessions without granting business roles", async () => {
  const { identity, projectTenant, provisionUser, login } = createHarness();
  await projectTenant();
  const first = await provisionUser({
    sourceRevision: 1,
    desiredState: "ACTIVE",
  });
  const { completed } = await login();
  const changed = await provisionUser({
    sourceRevision: 2,
    desiredState: "ACTIVE",
    sourceEventId: "account-role-change-2",
  });
  const replay = await provisionUser({
    sourceRevision: 2,
    desiredState: "ACTIVE",
    sourceEventId: "account-role-change-2",
    idempotencyKey: "account-role-change-2-replay",
  });

  assert.equal(changed.state, "ACTIVE");
  assert.equal(changed.lifecycleVersion, first.lifecycleVersion + 1);
  assert.equal(changed.revocationEpoch, first.revocationEpoch + 1);
  assert.equal(replay.duplicate, true);
  await assert.rejects(
    identity.resolveSession(serverContext, {
      sessionToken: completed.sessionToken,
      expectedTenantId: TENANT_ID,
    }),
    (error) => error.code === "SESSION_INVALID",
  );
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.accounts[0].state, "ACTIVE");
  assert.equal(
    snapshot.outbox.filter(
      ({ type }) => type === "product.identity.account-updated.v1",
    ).length,
    1,
  );
  assert.equal("roles" in snapshot.accounts[0], false);
  assert.equal("groups" in snapshot.accounts[0], false);
});

test("different subjects remain different accounts even when assertions share an email", async () => {
  const { identity, projectTenant, provisionUser, login } = createHarness();
  await projectTenant();
  const ava = await provisionUser({
    fixtureUserId: "northstar-fasteners-user-ava",
  });
  const noah = await provisionUser({
    fixtureUserId: "northstar-fasteners-user-noah",
  });

  assert.notEqual(ava.accountId, noah.accountId);
  const sharedEmail = "shared@northstar-fasteners.example";
  const avaLogin = await login({
    assertionOverrides: { email: sharedEmail },
  });
  const noahLogin = await login({
    subject: "northstar-fasteners-user-noah",
    assertionOverrides: { email: sharedEmail },
  });
  assert.notEqual(
    avaLogin.completed.identityAccountId,
    noahLogin.completed.identityAccountId,
  );
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.accounts.length, 2);
});

test("strict OIDC login returns authentication context without business authorization", async () => {
  const { identity, broker, projectTenant, provisionUser, login } =
    createHarness();
  await projectTenant();
  const provisioned = await provisionUser();
  const { started, completed, code } = await login();

  assertContract("CommandReceipt", provisioned);
  assert.equal(broker.starts[0].codeChallengeMethod, "S256");
  assert.equal(broker.starts[0].redirectUri, REDIRECT_URI);
  assert.equal(completed.tenantId, TENANT_ID);
  assert.equal(completed.trustSource, "VERIFIED_SESSION");
  assert.equal(completed.authorizationStatus, "NOT_EVALUATED");
  assert.equal("principalId" in completed, false);
  assert.equal("subject" in completed, false);
  assert.match(completed.sessionToken, /^[A-Za-z0-9._~-]{43,128}$/);
  assertContract("LoginChallenge", started);
  assertContract("AuthenticatedSession", completed);

  const resolved = await identity.resolveSession(serverContext, {
    sessionToken: completed.sessionToken,
    expectedTenantId: TENANT_ID,
  });
  assert.equal(resolved.identityAccountId, completed.identityAccountId);
  assert.equal(resolved.authorizationStatus, "NOT_EVALUATED");
  assertContract("AuthenticationContext", resolved);

  await assert.rejects(
    identity.completeLogin(serverContext, {
      transactionId: started.transactionId,
      state: started.state,
      authorizationCode: code,
      codeVerifier: started.codeVerifier,
    }),
    (error) => error.code === "LOGIN_REPLAY_DETECTED",
  );
});

test("a pending login stays pinned to its grace configuration during key rotation", async () => {
  const {
    identity,
    broker,
    projectTenant,
    provisionUser,
    validAssertion,
  } = createHarness();
  await projectTenant();
  await provisionUser();
  const before = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  const started = await identity.startLogin(serverContext, {
    tenantId: TENANT_ID,
    providerConnectionId: before.provider.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  const rotated = await identity.execute(providerManager, {
    kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
    idempotencyKey: "rotate-provider-to-k2",
    tenantId: TENANT_ID,
    providerConnectionId: before.provider.providerConnectionId,
    expectedConfigurationVersion: 1,
    allowedKeyIds: ["synthetic-k2"],
    emergency: false,
    correlationId: "rotate-provider-to-k2",
  });
  assert.equal(rotated.configurationVersion, 2);
  assertContract("CommandReceipt", rotated);
  broker.assertions.set(
    "pre-rotation-code",
    validAssertion({
      nonce: broker.starts.at(-1).nonce,
      configurationVersion: 1,
      keyId: "synthetic-k1",
    }),
  );
  const completed = await identity.completeLogin(serverContext, {
    transactionId: started.transactionId,
    state: started.state,
    authorizationCode: "pre-rotation-code",
    codeVerifier: started.codeVerifier,
  });
  assert.equal(completed.providerConfigurationVersion, 1);

  const after = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  assert.equal(after.provider.configurationVersion, 2);
  assert.equal(after.provider.configurationState, "CURRENT");
  const nextStarted = await identity.startLogin(serverContext, {
    tenantId: TENANT_ID,
    providerConnectionId: after.provider.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  broker.assertions.set(
    "post-rotation-code",
    validAssertion({
      nonce: broker.starts.at(-1).nonce,
      configurationVersion: 2,
      keyId: "synthetic-k2",
    }),
  );
  const nextCompleted = await identity.completeLogin(serverContext, {
    transactionId: nextStarted.transactionId,
    state: nextStarted.state,
    authorizationCode: "post-rotation-code",
    codeVerifier: nextStarted.codeVerifier,
  });
  assert.equal(nextCompleted.providerConfigurationVersion, 2);
});

test("ordinary retirement cannot shorten the provider grace period", async () => {
  const {
    identity,
    projectTenant,
    provisionUser,
    setTime,
  } = createHarness();
  await projectTenant();
  await provisionUser();
  const before = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  await identity.execute(providerManager, {
    kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
    idempotencyKey: "rotate-provider-before-retirement",
    tenantId: TENANT_ID,
    providerConnectionId: before.provider.providerConnectionId,
    expectedConfigurationVersion: 1,
    allowedKeyIds: ["synthetic-k2"],
    emergency: false,
    correlationId: "rotate-provider-before-retirement",
  });
  await assert.rejects(
    identity.execute(providerManager, {
      kind: "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION",
      idempotencyKey: "retire-provider-v1-too-early",
      tenantId: TENANT_ID,
      providerConnectionId: before.provider.providerConnectionId,
      configurationVersion: 1,
      correlationId: "retire-provider-v1-too-early",
    }),
    (error) => error.code === "PROVIDER_CONFIGURATION_CONFLICT",
  );
  setTime("2026-07-26T04:05:00.000Z");
  const retired = await identity.execute(providerManager, {
    kind: "RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION",
    idempotencyKey: "retire-provider-v1-after-grace",
    tenantId: TENANT_ID,
    providerConnectionId: before.provider.providerConnectionId,
    configurationVersion: 1,
    correlationId: "retire-provider-v1-after-grace",
  });
  assert.equal(retired.state, "RETIRED");
  assertContract("CommandReceipt", retired);
});

test("key rotation compares key sets and emergency rotation removes a key", async () => {
  const { identity, projectTenant, provisionUser } = createHarness();
  await projectTenant();
  await provisionUser();
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  const base = {
    kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
    tenantId: TENANT_ID,
    providerConnectionId: snapshot.provider.providerConnectionId,
    expectedConfigurationVersion: 1,
  };

  await assert.rejects(
    identity.execute(providerManager, {
      ...base,
      idempotencyKey: "reordered-provider-keys",
      allowedKeyIds: ["synthetic-k2", "synthetic-k1"],
      emergency: false,
      correlationId: "reordered-provider-keys",
    }),
    (error) => error.code === "PROVIDER_CONFIGURATION_CONFLICT",
  );
  await assert.rejects(
    identity.execute(providerManager, {
      ...base,
      idempotencyKey: "emergency-provider-key-superset",
      allowedKeyIds: [
        "synthetic-k1",
        "synthetic-k2",
        "synthetic-k3",
      ],
      emergency: true,
      correlationId: "emergency-provider-key-superset",
    }),
    (error) => error.code === "PROVIDER_CONFIGURATION_CONFLICT",
  );
});

test("an emergency key rotation revokes existing sessions", async () => {
  const {
    identity,
    projectTenant,
    provisionUser,
    login,
  } = createHarness();
  await projectTenant();
  await provisionUser();
  const { completed } = await login();
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  await identity.execute(providerManager, {
    kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
    idempotencyKey: "emergency-provider-rotation",
    tenantId: TENANT_ID,
    providerConnectionId: snapshot.provider.providerConnectionId,
    expectedConfigurationVersion: 1,
    allowedKeyIds: ["synthetic-k2"],
    emergency: true,
    correlationId: "emergency-provider-rotation",
  });

  await assert.rejects(
    identity.resolveSession(serverContext, {
      sessionToken: completed.sessionToken,
      expectedTenantId: TENANT_ID,
    }),
    (error) => error.code === "SESSION_INVALID",
  );
});

test("an emergency rotation retires every older grace configuration", async () => {
  const {
    identity,
    broker,
    projectTenant,
    provisionUser,
    validAssertion,
  } = createHarness();
  await projectTenant();
  await provisionUser();
  const initial = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  const pendingV1 = await identity.startLogin(serverContext, {
    tenantId: TENANT_ID,
    providerConnectionId: initial.provider.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  await identity.execute(providerManager, {
    kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
    idempotencyKey: "normal-rotation-v2",
    tenantId: TENANT_ID,
    providerConnectionId: initial.provider.providerConnectionId,
    expectedConfigurationVersion: 1,
    allowedKeyIds: ["synthetic-k2"],
    emergency: false,
    correlationId: "normal-rotation-v2",
  });
  await identity.execute(providerManager, {
    kind: "ROTATE_SYNTHETIC_PROVIDER_KEYS",
    idempotencyKey: "emergency-rotation-v3",
    tenantId: TENANT_ID,
    providerConnectionId: initial.provider.providerConnectionId,
    expectedConfigurationVersion: 2,
    allowedKeyIds: ["synthetic-k3"],
    emergency: true,
    correlationId: "emergency-rotation-v3",
  });
  broker.assertions.set(
    "old-grace-after-emergency",
    validAssertion({
      nonce: broker.starts.at(-1).nonce,
      configurationVersion: 1,
      keyId: "synthetic-k1",
    }),
  );

  await assert.rejects(
    identity.completeLogin(serverContext, {
      transactionId: pendingV1.transactionId,
      state: pendingV1.state,
      authorizationCode: "old-grace-after-emergency",
      codeVerifier: pendingV1.codeVerifier,
    }),
    (error) => error.code === "PROVIDER_CONFIGURATION_RETIRED",
  );
  assert.equal(broker.exchangeCount, 0);
});

test("concurrent callbacks exchange one authorization code at most once", async () => {
  const { identity, broker, projectTenant, provisionUser } = createHarness();
  await projectTenant();
  await provisionUser();
  const projection = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  const started = await identity.startLogin(serverContext, {
    tenantId: TENANT_ID,
    providerConnectionId: projection.provider.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  const code = "concurrent-code";
  broker.assertions.set(code, {
    protocol: "OIDC",
    signatureVerified: true,
    synthetic: true,
    issuer: ISSUER,
    audience: [CLIENT_ID],
    authorizedParty: CLIENT_ID,
    subject: "northstar-fasteners-user-ava",
    nonce: broker.starts.at(-1).nonce,
    issuedAt: "2026-07-26T04:00:00.000Z",
    notBefore: "2026-07-26T04:00:00.000Z",
    expiresAt: "2026-07-26T05:00:00.000Z",
    authenticationTime: "2026-07-26T04:00:00.000Z",
    authenticationMethods: ["pwd", "mfa"],
    algorithm: "RS256",
    keyId: "synthetic-k1",
    configurationVersion: 1,
  });
  let releaseExchange;
  let markExchangeStarted;
  const exchangeStarted = new Promise((resolve) => {
    markExchangeStarted = resolve;
  });
  const exchangeReleased = new Promise((resolve) => {
    releaseExchange = resolve;
  });
  broker.beforeExchange = async () => {
    markExchangeStarted();
    await exchangeReleased;
  };
  const request = {
    transactionId: started.transactionId,
    state: started.state,
    authorizationCode: code,
    codeVerifier: started.codeVerifier,
  };
  const first = identity.completeLogin(serverContext, request);
  await exchangeStarted;
  await assert.rejects(
    identity.completeLogin(serverContext, request),
    (error) => error.code === "LOGIN_REPLAY_DETECTED",
  );
  releaseExchange();
  await first;
  assert.equal(broker.exchangeCount, 1);
});

test("login completion fails if termination commits before the final session check", async () => {
  const {
    identity,
    tenantRegistry,
    projectTenant,
    provisionUser,
    login,
  } = createHarness();
  await projectTenant();
  await provisionUser();
  tenantRegistry.beforeAdmission = async (admissionCount) => {
    if (admissionCount === 3) {
      await provisionUser({
        sourceRevision: 2,
        desiredState: "TERMINATED",
      });
    }
  };

  await assert.rejects(
    login(),
    (error) => error.code === "AUTHENTICATION_FAILED",
  );
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.accounts[0].state, "TERMINATED");
  assert.equal(snapshot.sessions.length, 1);
  assert.equal(snapshot.sessions[0].status, "REVOKED");
});

test("a callback cannot create a session after its login transaction expires", async () => {
  const {
    broker,
    projectTenant,
    provisionUser,
    login,
    setTime,
  } = createHarness();
  await projectTenant();
  await provisionUser();
  broker.beforeExchange = async () => {
    setTime("2026-07-26T04:06:00.000Z");
  };

  await assert.rejects(
    login(),
    (error) => error.code === "LOGIN_TRANSACTION_EXPIRED",
  );
});

test("an unknown subject is rejected even when its OIDC assertion is valid", async () => {
  const { projectTenant, provisionUser, login } = createHarness();
  await projectTenant();
  await provisionUser();

  await assert.rejects(
    login({ subject: "unprovisioned-synthetic-subject" }),
    (error) => error.code === "AUTHENTICATION_FAILED",
  );
});

for (const [name, assertionOverrides, expectedCode] of [
  ["issuer", { issuer: "https://other.example/realm" }, "AUTHENTICATION_FAILED"],
  ["audience", { audience: ["wrong-client"] }, "AUTHENTICATION_FAILED"],
  ["nonce", { nonce: "0".repeat(64) }, "AUTHENTICATION_FAILED"],
  ["algorithm", { algorithm: "none" }, "AUTHENTICATION_FAILED"],
  ["key", { keyId: "attacker-key" }, "AUTHENTICATION_FAILED"],
  ["MFA", { authenticationMethods: ["pwd"] }, "MFA_REQUIRED"],
]) {
  test(`OIDC ${name} mismatch is rejected`, async () => {
    const { projectTenant, provisionUser, login } = createHarness();
    await projectTenant();
    await provisionUser();

    await assert.rejects(
      login({ assertionOverrides }),
      (error) => error.code === expectedCode,
    );
  });
}

test("state and PKCE verifier mismatches fail before token exchange", async () => {
  const { identity, broker, projectTenant, provisionUser } = createHarness();
  await projectTenant();
  await provisionUser();
  const projection = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  const started = await identity.startLogin(serverContext, {
    tenantId: TENANT_ID,
    providerConnectionId: projection.provider.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });

  await assert.rejects(
    identity.completeLogin(serverContext, {
      transactionId: started.transactionId,
      state: "f".repeat(64),
      authorizationCode: "must-not-be-exchanged",
      codeVerifier: started.codeVerifier,
    }),
    (error) => error.code === "AUTHENTICATION_FAILED",
  );
  assert.equal(broker.assertions.has("must-not-be-exchanged"), false);

  await assert.rejects(
    identity.completeLogin(serverContext, {
      transactionId: started.transactionId,
      state: started.state,
      authorizationCode: "must-not-be-exchanged",
      codeVerifier: "e".repeat(64),
    }),
    (error) => error.code === "AUTHENTICATION_FAILED",
  );
});

test("account suspension revokes an existing session by epoch and row state", async () => {
  const { identity, projectTenant, provisionUser, login } = createHarness();
  await projectTenant();
  await provisionUser();
  const { completed } = await login();
  const suspended = await provisionUser({
    sourceRevision: 2,
    desiredState: "SUSPENDED",
  });

  assert.equal(suspended.revocationEpoch, 2);
  await assert.rejects(
    identity.resolveSession(serverContext, {
      sessionToken: completed.sessionToken,
      expectedTenantId: TENANT_ID,
    }),
    (error) => error.code === "SESSION_INVALID",
  );
});

test("account deactivation reaches BFF and Core within the frozen no-cache SLA", async () => {
  const {
    identity,
    projectTenant,
    provisionUser,
    login,
    setTime,
  } = createHarness();
  assert.equal(sessionRevocationSla.workPackageId, "C04");
  assert.equal(
    sessionRevocationSla.acceptanceCriterionId,
    "C04-AC04",
  );
  assert.equal(sessionRevocationSla.evidenceGroupId, "P1-B05");
  assert.equal(sessionRevocationSla.scope, "P1_SYNTHETIC_ONLY");
  assert.equal(
    sessionRevocationSla.surfaces.bff.behavior,
    "CORE_REVALIDATE_EVERY_REQUEST",
  );
  assert.deepEqual(sessionRevocationSla.surfaces.sessionCache, {
    mode: "DISABLED",
    maximumTtlMs: 0,
    cacheHitAllowed: false,
    outageBehavior: "FAIL_CLOSED",
  });

  await projectTenant();
  await provisionUser();
  const { completed } = await login();
  let coreResolveCount = 0;
  const bff = {
    cacheHitCount: 0,
    async protectedRequest() {
      coreResolveCount += 1;
      return identity.resolveSession(serverContext, {
        sessionToken: completed.sessionToken,
        expectedTenantId: TENANT_ID,
      });
    },
  };

  const lastAllowedAt = "2026-07-26T04:00:00.999Z";
  setTime(lastAllowedAt);
  const allowed = await bff.protectedRequest();
  assert.equal(allowed.sessionId, completed.sessionId);

  const committedAt = "2026-07-26T04:00:01.000Z";
  setTime(committedAt);
  await provisionUser({
    sourceRevision: 2,
    desiredState: "SUSPENDED",
    sourceEventId: "account-sla-suspension-2",
  });

  const firstDeniedAt = committedAt;
  setTime(firstDeniedAt);
  await assert.rejects(
    bff.protectedRequest(),
    (error) => error.code === "SESSION_INVALID",
  );
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  const session = snapshot.sessions.find(
    ({ sessionId }) => sessionId === completed.sessionId,
  );
  assert.equal(snapshot.accounts[0].updatedAt, committedAt);
  assert.equal(session.status, "REVOKED");
  assert.equal(session.revokedAt, committedAt);
  assert.equal(bff.cacheHitCount, 0);
  assert.equal(coreResolveCount, 2);

  const propagationMs =
    Date.parse(firstDeniedAt) - Date.parse(committedAt);
  assert.equal(Date.parse(lastAllowedAt) < Date.parse(committedAt), true);
  assert.equal(propagationMs, 0);
  assert.equal(
    propagationMs <= sessionRevocationSla.maximumPropagationMs,
    true,
  );
});

test("Tenant suspension revokes sessions and blocks every login surface", async () => {
  const { identity, lifecycleEvent, tenant, projectTenant, provisionUser, login } =
    createHarness();
  await projectTenant();
  await provisionUser();
  const { completed } = await login();
  tenant.state = "SUSPENDED";
  tenant.lifecycleVersion += 1;
  await identity.execute(projectWorker, lifecycleEvent(
    "tenant-event-suspended-001",
    {
    idempotencyKey: "tenant-suspend-001",
    correlationId: "c04-tenant-suspended",
    },
  ));

  await assert.rejects(
    identity.resolveSession(serverContext, {
      sessionToken: completed.sessionToken,
      expectedTenantId: TENANT_ID,
    }),
    (error) => error.code === "SESSION_INVALID",
  );
  const snapshot = await identity.snapshot(projectWorker, {
    tenantId: TENANT_ID,
  });
  await assert.rejects(
    identity.startLogin(serverContext, {
      tenantId: TENANT_ID,
      providerConnectionId: snapshot.provider.providerConnectionId,
      returnRoute: "PORTAL_HOME",
    }),
    (error) => error.code === "TENANT_NOT_ACTIVE",
  );
});

test("a termination snapshot still applies while its Tenant is suspended", async () => {
  const {
    identity,
    lifecycleEvent,
    tenant,
    projectTenant,
    provisionUser,
    login,
  } = createHarness();
  await projectTenant();
  await provisionUser();
  const { completed } = await login();
  tenant.state = "SUSPENDED";
  tenant.lifecycleVersion += 1;
  await identity.execute(
    projectWorker,
    lifecycleEvent("tenant-event-suspended-before-termination"),
  );

  const terminated = await provisionUser({
    sourceRevision: 2,
    desiredState: "TERMINATED",
  });
  assert.equal(terminated.state, "TERMINATED");
  await assert.rejects(
    identity.resolveSession(serverContext, {
      sessionToken: completed.sessionToken,
      expectedTenantId: TENANT_ID,
    }),
    (error) => error.code === "SESSION_INVALID",
  );
});

test("manual logout is idempotent and never exposes the stored token hash", async () => {
  const { identity, projectTenant, provisionUser, login } = createHarness();
  await projectTenant();
  await provisionUser();
  const { completed } = await login();
  const command = {
    kind: "REVOKE_SESSION",
    idempotencyKey: "logout-session-001",
    tenantId: TENANT_ID,
    sessionId: completed.sessionId,
    reasonRef: "synthetic://user-logout",
    correlationId: "c04-logout",
  };
  const first = await identity.execute(sessionManager, command);
  const replay = await identity.execute(sessionManager, command);

  assert.equal(first.status, "REVOKED");
  assertContract("CommandReceipt", first);
  assert.equal(replay.duplicate, true);
  const snapshot = await identity.snapshot(sessionManager, {
    tenantId: TENANT_ID,
  });
  assert.equal(snapshot.sessions[0].status, "REVOKED");
  assert.equal("tokenHash" in snapshot.sessions[0], false);
});

test("authorization failures and Enterprise commands fail closed", async () => {
  const { identity, lifecycleEvent } = createHarness();
  await assert.rejects(
    identity.execute(
      { actorId: "unauthorized", capabilities: [], synthetic: true },
      lifecycleEvent("unauthorized-event", {
        idempotencyKey: "unauthorized-project",
        correlationId: "unauthorized",
      }),
    ),
    (error) => error.code === "UNAUTHORIZED",
  );
  await assert.rejects(
    identity.execute(projectWorker, {
      kind: "CREATE_ENTERPRISE_IDENTITY",
      enterprisePayload: {
        token: "must-not-be-read",
      },
    }),
    (error) => error.code === "P3_REQUIRED",
  );
});
