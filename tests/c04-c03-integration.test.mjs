import assert from "node:assert/strict";
import test from "node:test";
import {
  createMemoryIdentityStore,
  createIdentityFederation,
  createSyntheticIdentityCatalog,
} from "../lib/identity-federation.mjs";
import {
  createMemoryTenantStore,
  createSyntheticFixtureCatalog,
  createTenantRegistry,
} from "../lib/tenant-registry.mjs";

const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-northstar-fasteners",
  sha256:
    "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
});
const PROJECTIONS = [
  "AUTHORIZATION",
  "IDENTITY",
  "KNOWLEDGE",
  "SECRET_REFS",
  "STORAGE",
];
const ISSUER =
  "https://idp.northstar-fasteners.example/realms/synthetic";
const CLIENT_ID = "synthetic-aios-portal";
const REDIRECT_URI =
  "https://portal.northstar-fasteners.example/auth/callback";
const NOW = "2026-07-26T04:00:00.000Z";

const tenantOperator = {
  actorId: "syn_prn_platform_operator",
  capabilities: ["TENANT_LIFECYCLE_MANAGE"],
  synthetic: true,
};
const tenantProjectionWorker = {
  actorId: "syn_svc_projection_worker",
  capabilities: ["TENANT_PROJECTION_REPORT"],
  synthetic: true,
};
const tenantReconciler = {
  actorId: "syn_svc_tenant_reconciler",
  capabilities: ["TENANT_RECONCILE"],
  synthetic: true,
};
const tenantRegistryContext = {
  actorId: "syn_svc_identity_tenant_reader",
  capabilities: ["TENANT_LIFECYCLE_READ"],
  synthetic: true,
};
const identityProjectionWorker = {
  actorId: "syn_svc_identity_projection",
  capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
  synthetic: true,
};
const identityProvisioningWorker = {
  actorId: "syn_svc_identity_provisioning",
  capabilities: ["IDENTITY_PROVISIONING_APPLY"],
  synthetic: true,
};
const portalContext = {
  actorId: "syn_svc_portal_bff",
  synthetic: true,
};

function deterministicUuidFactory(start = 0) {
  let counter = start;
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

test("C04 uses the real C03 read and admission contracts for one synthetic OIDC session", async () => {
  const tenantRegistry = createTenantRegistry({
    store: createMemoryTenantStore(),
    fixtureCatalog: createSyntheticFixtureCatalog([
      {
        ...FIXTURE_REF,
        allowedConfigRefs: ["fixture://SYNTHETIC-SEED-001"],
      },
    ]),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock: () => NOW,
    idFactory: deterministicUuidFactory(),
  });

  const observedSnapshotContexts = [];
  const observedAdmissionRequests = [];
  const tenantRegistryPort = {
    snapshot(context, tenantId) {
      observedSnapshotContexts.push(context);
      return tenantRegistry.snapshot(context, tenantId);
    },
    admitNewRequest(request) {
      observedAdmissionRequests.push(structuredClone(request));
      return tenantRegistry.admitNewRequest(request);
    },
  };

  let authorizationRequest;
  const federationBroker = {
    async startAuthorization(request) {
      authorizationRequest = structuredClone(request);
      return {
        authorizationUrl:
          "https://idp.northstar-fasteners.example/realms/synthetic/protocol/openid-connect/auth",
      };
    },
    async exchangeAndVerify(request) {
      assert.equal(request.protocol, "OIDC");
      assert.equal(request.authorizationCode, "synthetic-code-001");
      return {
        protocol: "OIDC",
        signatureVerified: true,
        synthetic: true,
        issuer: ISSUER,
        audience: [CLIENT_ID],
        authorizedParty: CLIENT_ID,
        subject: "northstar-fasteners-user-ava",
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

  const identity = createIdentityFederation({
    store: createMemoryIdentityStore(),
    tenantRegistry: tenantRegistryPort,
    tenantRegistryContext,
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
            fixtureUserId: "northstar-fasteners-user-ava",
            directoryObjectId: "northstar-directory-ava",
            loginSubject: "northstar-fasteners-user-ava",
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
    idFactory: deterministicUuidFactory(100),
    secretFactory: deterministicSecretFactory(),
  });

  const created = await tenantRegistry.execute(tenantOperator, {
    kind: "CREATE_SYNTHETIC_TENANT",
    idempotencyKey: "c04-c03-create-001",
    creationKey: "p1:SYNTHETIC-SEED-001",
    fixtureRef: FIXTURE_REF,
    configRefs: ["fixture://SYNTHETIC-SEED-001"],
    correlationId: "c04-c03-create",
  });
  const provisioningTenant = await tenantRegistry.snapshot(
    tenantRegistryContext,
    created.tenantId,
  );
  const provisioningEvent = provisioningTenant.outbox.find(
    ({ type }) => type === "product.tenant.provisioning-requested.v1",
  );
  assert.ok(provisioningEvent);

  const projected = await identity.execute(identityProjectionWorker, {
    kind: "APPLY_TENANT_LIFECYCLE_EVENT",
    idempotencyKey: "c04-c03-project-001",
    tenantId: created.tenantId,
    sourceEventId: provisioningEvent.id,
    sourceLifecycleVersion: provisioningEvent.data.lifecycle_version,
    sourceGeneration: provisioningEvent.data.generation,
    sourceOperationId: provisioningEvent.data.operation_id,
    sourceState: provisioningEvent.data.state,
    correlationId: provisioningEvent.correlationid,
  });
  assert.equal(projected.projectionState, "READY");
  const identityProjection = await identity.snapshot(
    identityProjectionWorker,
    { tenantId: created.tenantId },
  );
  const identityReadyEvent = identityProjection.outbox.find(
    ({ type }) => type === "product.identity.tenant-projection-ready.v1",
  );
  assert.ok(identityReadyEvent);
  assert.equal(
    identityReadyEvent.data.source_event_id,
    provisioningEvent.id,
  );

  for (const [index, projection] of PROJECTIONS.entries()) {
    await tenantRegistry.execute(tenantProjectionWorker, {
      kind: "RECORD_PROJECTION_RESULT",
      idempotencyKey: `c04-c03-ready-${projection}`,
      tenantId: created.tenantId,
      generation: created.generation,
      operationId: created.operationId,
      projection,
      outcome: "SUCCEEDED",
      attempt: 1,
      sourceEventId:
        projection === "IDENTITY"
          ? identityReadyEvent.id
          : `c04-c03-projection-${index + 1}`,
      correlationId: "c04-c03-provision",
    });
  }
  const active = await tenantRegistry.execute(tenantReconciler, {
    kind: "RECONCILE_TENANT",
    idempotencyKey: "c04-c03-reconcile-001",
    tenantId: created.tenantId,
    correlationId: "c04-c03-reconcile",
  });
  assert.equal(active.state, "ACTIVE");

  const provisioned = await identity.execute(identityProvisioningWorker, {
    kind: "APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT",
    idempotencyKey: "c04-c03-account-001",
    tenantId: created.tenantId,
    providerConnectionId: projected.providerConnectionId,
    fixtureUserId: "northstar-fasteners-user-ava",
    sourceEventId: "c04-c03-account-source-001",
    sourceRevision: 1,
    desiredState: "ACTIVE",
    correlationId: "c04-c03-account",
  });
  assert.equal(provisioned.state, "ACTIVE");

  const started = await identity.startLogin(portalContext, {
    tenantId: created.tenantId,
    providerConnectionId: projected.providerConnectionId,
    returnRoute: "PORTAL_HOME",
  });
  assert.equal(authorizationRequest.codeChallengeMethod, "S256");

  const completed = await identity.completeLogin(portalContext, {
    transactionId: started.transactionId,
    state: started.state,
    authorizationCode: "synthetic-code-001",
    codeVerifier: started.codeVerifier,
  });
  const resolved = await identity.resolveSession(portalContext, {
    sessionToken: completed.sessionToken,
    expectedTenantId: created.tenantId,
  });

  assert.equal(resolved.identityAccountId, provisioned.accountId);
  assert.equal(resolved.trustSource, "VERIFIED_SESSION");
  assert.equal(resolved.authorizationStatus, "NOT_EVALUATED");
  assert.ok(
    observedSnapshotContexts.every(
      (context) => context === tenantRegistryContext,
    ),
  );
  assert.ok(observedSnapshotContexts.length >= 2);
  assert.ok(observedAdmissionRequests.length >= 3);
  assert.deepEqual(
    [...new Set(observedAdmissionRequests.map(JSON.stringify))],
    [
      JSON.stringify({
        tenantId: created.tenantId,
        expectedTenantKind: "SYNTHETIC",
      }),
    ],
  );
});
