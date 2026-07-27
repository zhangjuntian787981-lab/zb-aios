import assert from "node:assert/strict";
import test from "node:test";
import {
  createIdentityFederation,
  createMemoryIdentityStore,
  createSyntheticIdentityCatalog,
} from "../lib/identity-federation.mjs";
import { createScimIdentityProvisioner } from "../lib/scim-identity-provisioner.mjs";
import {
  createMemoryPrincipalStore,
  createStablePrincipalRegistry,
  createSyntheticPrincipalCatalog,
} from "../lib/stable-principal.mjs";

const TENANT_ID = "stn_01984700-0000-7000-8000-000000000001";
const NOW = "2026-07-26T08:00:00.000Z";
const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-northstar-fasteners",
  sha256:
    "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
});
const FIXTURE_USER_ID = "northstar-fasteners-user-ava";
const DIRECTORY_OBJECT_ID = "northstar-directory-ava";
const PROFILE_REF =
  "fixture://synthetic-tenant-northstar-fasteners/users/ava";
const HUMAN_REF =
  "fixture://synthetic-tenant-northstar-fasteners/principals/human-ava";
const ISSUER =
  "https://idp.northstar-fasteners.example/realms/synthetic";
const CLIENT_ID = "synthetic-aios-portal";
const REDIRECT_URI =
  "https://portal.northstar-fasteners.example/auth/callback";

const identityProjectionContext = Object.freeze({
  actorId: "syn_svc_identity_projection",
  capabilities: ["IDENTITY_TENANT_PROJECT", "IDENTITY_READ"],
  synthetic: true,
});
const identityProvisioningContext = Object.freeze({
  actorId: "syn_svc_identity_provisioning",
  capabilities: ["IDENTITY_PROVISIONING_APPLY"],
  synthetic: true,
});
const principalOperatorContext = Object.freeze({
  actorId: "syn_svc_principal_operator",
  capabilities: [
    "PRINCIPAL_PROVISION",
    "PRINCIPAL_LINK_MANAGE",
    "PRINCIPAL_LIFECYCLE_APPLY",
    "PRINCIPAL_READ",
  ],
  synthetic: true,
});

function deterministicUuidFactory(start) {
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

function scimEvent(sourceRevision, desiredState, sourceEventId) {
  return {
    fixtureUserId: FIXTURE_USER_ID,
    sourceEventId,
    sourceRevision,
    desiredState,
    correlationId: `correlation-${sourceEventId}`,
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
  const tenantRegistry = {
    async snapshot(_context, tenantId) {
      assert.equal(tenantId, TENANT_ID);
      return structuredClone(tenant);
    },
    async admitNewRequest({ tenantId, expectedTenantKind }) {
      assert.equal(tenantId, TENANT_ID);
      assert.equal(expectedTenantKind, "SYNTHETIC");
      if (tenant.state !== "ACTIVE") {
        throw new Error("Synthetic Tenant is not active.");
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
    tenantRegistryContext: {
      actorId: "syn_svc_identity_tenant_reader",
      synthetic: true,
    },
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
            profileRef: PROFILE_REF,
          },
        ],
      },
    ]),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    federationBroker: {
      async startAuthorization() {
        throw new Error("Login is outside this lifecycle test.");
      },
      async exchangeAndVerify() {
        throw new Error("Login is outside this lifecycle test.");
      },
    },
    clock: () => NOW,
    idFactory: deterministicUuidFactory(100),
    secretFactory: deterministicSecretFactory(),
  });
  const projected = await identity.execute(identityProjectionContext, {
    kind: "APPLY_TENANT_LIFECYCLE_EVENT",
    idempotencyKey: "project-synthetic-tenant",
    tenantId: TENANT_ID,
    sourceEventId: "tenant-provisioning-source",
    sourceLifecycleVersion: tenant.lifecycleVersion,
    sourceGeneration: tenant.generation,
    sourceOperationId: tenant.operationId,
    sourceState: tenant.state,
    correlationId: "project-synthetic-tenant",
  });
  tenant.state = "ACTIVE";
  tenant.lifecycleVersion += 1;

  const scimCalls = [];
  const provisioner = createScimIdentityProvisioner({
    tenantId: TENANT_ID,
    providerConnectionId: projected.providerConnectionId,
    coreContext: identityProvisioningContext,
    identityFederation: identity,
    scimAdapter: {
      async apply(command) {
        scimCalls.push(structuredClone(command));
        return {
          externalId: command.externalId,
          resourceId: "synthetic-scim-resource-ava",
          sourceRevision: command.sourceRevision,
          state: command.desiredState,
          applied: true,
          stale: false,
        };
      },
    },
    resolveSyntheticAccount: async () => ({
      tenantId: TENANT_ID,
      providerConnectionId: projected.providerConnectionId,
      fixtureUserId: FIXTURE_USER_ID,
      directoryObjectId: DIRECTORY_OBJECT_ID,
      loginSubject: FIXTURE_USER_ID,
      profile: {
        givenName: "Ava",
        familyName: "Synthetic",
        email: "ava@northstar-fasteners.example",
      },
    }),
  });
  const principals = createStablePrincipalRegistry({
    store: createMemoryPrincipalStore(),
    tenantRegistry,
    tenantRegistryContext: {
      actorId: "syn_svc_principal_tenant_reader",
      synthetic: true,
    },
    identityFederation: identity,
    identityFederationReadContext: identityProjectionContext,
    identityFederationServerContext: {
      actorId: "syn_svc_principal_session_reader",
      synthetic: true,
    },
    principalCatalog: createSyntheticPrincipalCatalog([
      {
        ...FIXTURE_REF,
        principals: [
          {
            fixturePrincipalRef: HUMAN_REF,
            principalType: "HUMAN",
            identityProfileRefs: [PROFILE_REF],
          },
        ],
        identityCorrections: [],
      },
    ]),
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock: () => NOW,
    idFactory: deterministicUuidFactory(500),
  });
  const human = await principals.execute(principalOperatorContext, {
    kind: "CREATE_SYNTHETIC_PRINCIPAL",
    idempotencyKey: "create-human-ava",
    tenantId: TENANT_ID,
    fixturePrincipalRef: HUMAN_REF,
    correlationId: "create-human-ava",
  });

  async function principalSnapshot() {
    return principals.snapshot(principalOperatorContext, {
      tenantId: TENANT_ID,
    });
  }

  return {
    human,
    identity,
    principalSnapshot,
    principals,
    provisioner,
    scimCalls,
  };
}

async function linkAccount(
  harness,
  identityAccountId,
  idempotencyKey,
) {
  return harness.principals.execute(principalOperatorContext, {
    kind: "LINK_IDENTITY_ACCOUNT",
    idempotencyKey,
    tenantId: TENANT_ID,
    principalId: harness.human.principal.principalId,
    identityAccountId,
    linkEvidenceRef: "synthetic://c04-c05/scim/ava",
    correlationId: idempotencyKey,
  });
}

async function syncAccount(harness, identityAccountId, sourceEventId) {
  return harness.principals.execute(principalOperatorContext, {
    kind: "SYNC_IDENTITY_ACCOUNT",
    idempotencyKey: `sync-${sourceEventId}`,
    tenantId: TENANT_ID,
    identityAccountId,
    correlationId: `sync-${sourceEventId}`,
  });
}

test("duplicate and out-of-order SCIM lifecycle events never create a duplicate IdentityLink", async () => {
  const harness = await createHarness();
  const create = scimEvent(1, "ACTIVE", "scim-create-ava");

  const created = await harness.provisioner.apply(create);
  const linked = await linkAccount(
    harness,
    created.core.accountId,
    "link-scim-create-ava",
  );
  assert.equal(linked.applied, true);

  const duplicateCreate = await harness.provisioner.apply(create);
  assert.equal(duplicateCreate.core.duplicate, true);
  const duplicateDelivery = await linkAccount(
    harness,
    duplicateCreate.core.accountId,
    "link-scim-create-ava-duplicate-delivery",
  );
  assert.equal(duplicateDelivery.applied, false);
  assert.equal(
    duplicateDelivery.identityLink.identityLinkId,
    linked.identityLink.identityLinkId,
  );

  let principalSnapshot = await harness.principalSnapshot();
  assert.equal(principalSnapshot.identityLinks.length, 1);
  assert.equal(
    principalSnapshot.identityLinks.filter(
      ({ state }) => state === "ACTIVE",
    ).length,
    1,
  );

  const suspendedEvent = scimEvent(
    3,
    "SUSPENDED",
    "scim-update-ava-suspended",
  );
  const suspended = await harness.provisioner.apply(suspendedEvent);
  const synchronizedSuspended = await syncAccount(
    harness,
    suspended.core.accountId,
    suspendedEvent.sourceEventId,
  );
  assert.equal(
    synchronizedSuspended.identityLink.identityLinkId,
    linked.identityLink.identityLinkId,
  );
  assert.equal(synchronizedSuspended.identityLink.state, "SUSPENDED");

  const stale = await harness.provisioner.apply(
    scimEvent(2, "ACTIVE", "scim-update-ava-stale"),
  );
  assert.equal(stale.core.stale, true);
  assert.equal(stale.scim, null);
  principalSnapshot = await harness.principalSnapshot();
  assert.equal(principalSnapshot.identityLinks.length, 1);
  assert.equal(principalSnapshot.identityLinks[0].state, "SUSPENDED");

  const duplicateSuspended =
    await harness.provisioner.apply(suspendedEvent);
  assert.equal(duplicateSuspended.core.duplicate, true);
  const duplicateSync = await syncAccount(
    harness,
    duplicateSuspended.core.accountId,
    suspendedEvent.sourceEventId,
  );
  assert.equal(duplicateSync.duplicate, true);

  const restoredEvent = scimEvent(
    4,
    "ACTIVE",
    "scim-update-ava-restored",
  );
  const restored = await harness.provisioner.apply(restoredEvent);
  const synchronizedRestored = await syncAccount(
    harness,
    restored.core.accountId,
    restoredEvent.sourceEventId,
  );
  assert.equal(
    synchronizedRestored.identityLink.identityLinkId,
    linked.identityLink.identityLinkId,
  );
  assert.equal(synchronizedRestored.identityLink.state, "ACTIVE");

  const deleteEvent = scimEvent(
    5,
    "TERMINATED",
    "scim-delete-ava",
  );
  const deleted = await harness.provisioner.apply(deleteEvent);
  const synchronizedDeleted = await syncAccount(
    harness,
    deleted.core.accountId,
    deleteEvent.sourceEventId,
  );
  assert.equal(
    synchronizedDeleted.identityLink.identityLinkId,
    linked.identityLink.identityLinkId,
  );
  assert.equal(synchronizedDeleted.identityLink.state, "RETIRED");

  const duplicateDelete = await harness.provisioner.apply(deleteEvent);
  assert.equal(duplicateDelete.core.duplicate, true);
  const duplicateDeleteSync = await syncAccount(
    harness,
    duplicateDelete.core.accountId,
    deleteEvent.sourceEventId,
  );
  assert.equal(duplicateDeleteSync.duplicate, true);

  const identitySnapshot = await harness.identity.snapshot(
    identityProjectionContext,
    { tenantId: TENANT_ID },
  );
  principalSnapshot = await harness.principalSnapshot();
  assert.equal(identitySnapshot.accounts.length, 1);
  assert.equal(identitySnapshot.accounts[0].state, "TERMINATED");
  assert.equal(principalSnapshot.identityLinks.length, 1);
  assert.equal(principalSnapshot.identityLinks[0].state, "RETIRED");
  assert.equal(
    principalSnapshot.events.filter(
      ({ type }) => type === "product.principal.identity-linked.v1",
    ).length,
    1,
  );
  assert.deepEqual(
    harness.scimCalls.map(({ sourceRevision }) => sourceRevision),
    [1, 1, 3, 3, 4, 5, 5],
  );
});
