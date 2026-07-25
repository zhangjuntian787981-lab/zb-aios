import assert from "node:assert/strict";
import test from "node:test";
import {
  StablePrincipalError,
  createMemoryPrincipalStore,
  createStablePrincipalRegistry,
  createSyntheticPrincipalCatalog,
} from "../lib/stable-principal.mjs";

const TENANT_ID =
  "stn_01984700-0000-7000-8000-000000000001";
const OTHER_TENANT_ID =
  "stn_01984700-0000-7000-8000-000000000002";
const FIXTURE_REF = Object.freeze({
  fixtureId: "synthetic-tenant-northstar-fasteners",
  sha256:
    "sha256:12693f1bed92c45128e0774ee1ea6c71b63a7edad0eff43cb988e79b6771db26",
});
const NOW = "2026-07-26T08:00:00.000Z";
const EXPIRY = "2026-07-26T09:00:00.000Z";
const CHILD_EXPIRY = "2026-07-26T08:30:00.000Z";

const HUMAN_AVA =
  "fixture://synthetic-tenant-northstar-fasteners/principals/human-ava";
const HUMAN_NOAH =
  "fixture://synthetic-tenant-northstar-fasteners/principals/human-noah";
const AGENT_ASSISTANT =
  "fixture://synthetic-tenant-northstar-fasteners/principals/agent-assistant";
const SERVICE_RUNNER =
  "fixture://synthetic-tenant-northstar-fasteners/principals/service-runner";

const PROFILE_AVA =
  "fixture://synthetic-tenant-northstar-fasteners/users/northstar-fasteners-user-ava";
const PROFILE_AVA_MIGRATED =
  "fixture://synthetic-tenant-northstar-fasteners/migrated-idp/northstar-fasteners-user-ava";
const PROFILE_NOAH =
  "fixture://synthetic-tenant-northstar-fasteners/users/northstar-fasteners-user-noah";
const CORRECTION_REF =
  "evidence://c05/identity-link-correction/northstar/ava-to-noah/v1";
const CORRECTION_HASH =
  "sha256:f005fe4d47b09f5d8d7138ef7c8f7e246b83bf8b07fccf6bb5d9b0ba9904e8d7";

const operator = {
  actorId: "syn_svc_c05_operator",
  synthetic: true,
  capabilities: [
    "PRINCIPAL_PROVISION",
    "PRINCIPAL_LINK_MANAGE",
    "PRINCIPAL_LIFECYCLE_APPLY",
    "DELEGATION_MANAGE",
    "PRINCIPAL_READ",
  ],
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

function createHarness({
  correctionHash = CORRECTION_HASH,
  extraPrincipals = [],
  idFactory = deterministicUuidFactory(),
} = {}) {
  let tenantState = "ACTIVE";
  let currentTime = NOW;
  let clockOverride = null;
  const accounts = new Map([
    [
      "sia_01984700-0000-7000-8000-000000000101",
      {
        accountId: "sia_01984700-0000-7000-8000-000000000101",
        tenantId: TENANT_ID,
        providerConnectionId:
          "idp_01984700-0000-7000-8000-000000000201",
        state: "ACTIVE",
        lifecycleVersion: 1,
        revocationEpoch: 1,
        incarnation: 1,
        profileRef: PROFILE_AVA,
        emailHint: "shared@northstar-fasteners.example",
        createdAt: NOW,
        updatedAt: NOW,
      },
    ],
    [
      "sia_01984700-0000-7000-8000-000000000102",
      {
        accountId: "sia_01984700-0000-7000-8000-000000000102",
        tenantId: TENANT_ID,
        providerConnectionId:
          "idp_01984700-0000-7000-8000-000000000202",
        state: "ACTIVE",
        lifecycleVersion: 1,
        revocationEpoch: 1,
        incarnation: 1,
        profileRef: PROFILE_AVA_MIGRATED,
        emailHint: "shared@northstar-fasteners.example",
        createdAt: NOW,
        updatedAt: NOW,
      },
    ],
    [
      "sia_01984700-0000-7000-8000-000000000103",
      {
        accountId: "sia_01984700-0000-7000-8000-000000000103",
        tenantId: TENANT_ID,
        providerConnectionId:
          "idp_01984700-0000-7000-8000-000000000201",
        state: "ACTIVE",
        lifecycleVersion: 1,
        revocationEpoch: 1,
        incarnation: 1,
        profileRef: PROFILE_NOAH,
        emailHint: "shared@northstar-fasteners.example",
        createdAt: NOW,
        updatedAt: NOW,
      },
    ],
  ]);
  const sessions = new Map([
    ["session-ava-primary", accounts.get("sia_01984700-0000-7000-8000-000000000101").accountId],
    ["session-ava-migrated", accounts.get("sia_01984700-0000-7000-8000-000000000102").accountId],
    ["session-noah", accounts.get("sia_01984700-0000-7000-8000-000000000103").accountId],
  ]);
  let sessionSequence = 0;
  let beforeSecondSessionResolve = null;
  const tenantRegistry = {
    async snapshot(_context, tenantId) {
      if (tenantId !== TENANT_ID && tenantId !== OTHER_TENANT_ID) {
        throw new Error("not found");
      }
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        synthetic: true,
        state: tenantState,
        fixtureRef: FIXTURE_REF,
      };
    },
  };
  const identityFederation = {
    async snapshot(_context, { tenantId }) {
      return {
        tenantId,
        tenantKind: "SYNTHETIC",
        accounts: Array.from(accounts.values())
          .filter((account) => account.tenantId === tenantId)
          .map((account) => structuredClone(account)),
        authorizationStatus: "NOT_EVALUATED",
      };
    },
    async resolveSession(_context, { sessionToken, expectedTenantId }) {
      sessionSequence += 1;
      if (sessionSequence % 2 === 0 && beforeSecondSessionResolve) {
        await beforeSecondSessionResolve();
      }
      const accountId = sessions.get(sessionToken);
      const account = accounts.get(accountId);
      if (
        tenantState !== "ACTIVE" ||
        expectedTenantId !== TENANT_ID ||
        !account ||
        account.state !== "ACTIVE"
      ) {
        throw new Error("invalid session");
      }
      return {
        tenantId: TENANT_ID,
        tenantKind: "SYNTHETIC",
        identityAccountId: account.accountId,
        sessionId: `ses_${sessionToken}`,
        trustSource: "VERIFIED_SESSION",
        authorizationStatus: "NOT_EVALUATED",
      };
    },
  };
  function buildPrincipalCatalog() {
    return createSyntheticPrincipalCatalog([
      {
        ...FIXTURE_REF,
        principals: [
          {
            fixturePrincipalRef: HUMAN_AVA,
            principalType: "HUMAN",
            identityProfileRefs: [PROFILE_AVA, PROFILE_AVA_MIGRATED],
          },
          {
            fixturePrincipalRef: HUMAN_NOAH,
            principalType: "HUMAN",
            identityProfileRefs: [PROFILE_NOAH],
          },
          {
            fixturePrincipalRef: AGENT_ASSISTANT,
            principalType: "AGENT",
            identityProfileRefs: [],
          },
          {
            fixturePrincipalRef: SERVICE_RUNNER,
            principalType: "SERVICE",
            identityProfileRefs: [],
          },
          ...extraPrincipals,
        ],
        identityCorrections: [
          {
            correctionRef: CORRECTION_REF,
            mappingHash: correctionHash,
            identityProfileRef: PROFILE_AVA,
            sourceFixturePrincipalRef: HUMAN_AVA,
            targetFixturePrincipalRef: HUMAN_NOAH,
          },
        ],
      },
    ]);
  }
  const principalCatalog = buildPrincipalCatalog();
  const registry = createStablePrincipalRegistry({
    store: createMemoryPrincipalStore(),
    tenantRegistry,
    tenantRegistryContext: {
      actorId: "syn_svc_c05_tenant_reader",
      synthetic: true,
    },
    identityFederation,
    identityFederationReadContext: {
      actorId: "syn_svc_c05_identity_reader",
      synthetic: true,
    },
    identityFederationServerContext: {
      actorId: "syn_svc_c05_session_reader",
      synthetic: true,
    },
    principalCatalog,
    authorize: (context, capability) =>
      context?.synthetic === true &&
      context.capabilities?.includes(capability) === true,
    clock: () =>
      clockOverride ? clockOverride() : currentTime,
    idFactory,
  });
  return {
    registry,
    accounts,
    setTenantState(value) {
      tenantState = value;
    },
    setTime(value) {
      currentTime = value;
    },
    setClock(callback) {
      clockOverride = callback;
    },
    beforeSecondSessionResolve(callback) {
      beforeSecondSessionResolve = callback;
    },
  };
}

async function createPrincipal(registry, fixturePrincipalRef, suffix) {
  return registry.execute(operator, {
    kind: "CREATE_SYNTHETIC_PRINCIPAL",
    idempotencyKey: `create-${suffix}`,
    tenantId: TENANT_ID,
    fixturePrincipalRef,
    correlationId: `create-${suffix}`,
  });
}

async function linkAccount(
  registry,
  principalId,
  identityAccountId,
  suffix,
) {
  return registry.execute(operator, {
    kind: "LINK_IDENTITY_ACCOUNT",
    idempotencyKey: `link-${suffix}`,
    tenantId: TENANT_ID,
    principalId,
    identityAccountId,
    linkEvidenceRef: `synthetic://c05/link/${suffix}`,
    correlationId: `link-${suffix}`,
  });
}

async function createDelegation(
  registry,
  {
    humanSubjectPrincipalId,
    delegatorPrincipalId,
    delegatePrincipalId,
    parentDelegationId,
    expiresAt = EXPIRY,
    suffix,
    purposeRef = `synthetic://c05/delegation/${suffix}`,
  },
) {
  return registry.execute(operator, {
    kind: "CREATE_DELEGATION",
    idempotencyKey: `delegation-${suffix}`,
    tenantId: TENANT_ID,
    humanSubjectPrincipalId,
    delegatorPrincipalId,
    delegatePrincipalId,
    ...(parentDelegationId ? { parentDelegationId } : {}),
    expiresAt,
    purposeRef,
    correlationId: `delegation-${suffix}`,
  });
}

function errorCode(code) {
  return (error) => {
    assert.ok(error instanceof StablePrincipalError);
    assert.equal(error.code, code);
    return true;
  };
}

test("external accounts and identical email hints never become the Stable Principal key", async () => {
  const { registry } = createHarness();
  const ava = await createPrincipal(registry, HUMAN_AVA, "ava");
  const noah = await createPrincipal(registry, HUMAN_NOAH, "noah");
  assert.notEqual(ava.principal.principalId, noah.principal.principalId);

  const primary = await linkAccount(
    registry,
    ava.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "ava-primary",
  );
  const migrated = await linkAccount(
    registry,
    ava.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000102",
    "ava-migrated",
  );
  const distinct = await linkAccount(
    registry,
    noah.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000103",
    "noah",
  );

  assert.equal(primary.identityLink.principalId, ava.principal.principalId);
  assert.equal(migrated.identityLink.principalId, ava.principal.principalId);
  assert.equal(distinct.identityLink.principalId, noah.principal.principalId);
  assert.notEqual(
    distinct.identityLink.principalId,
    primary.identityLink.principalId,
  );
});

test("HUMAN to AGENT to SERVICE resolves a complete server-trusted action identity", async () => {
  const { registry } = createHarness();
  const human = await createPrincipal(registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(registry, AGENT_ASSISTANT, "agent");
  const service = await createPrincipal(registry, SERVICE_RUNNER, "service");
  await linkAccount(
    registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const root = await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "root",
  });
  const child = await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: agent.principal.principalId,
    delegatePrincipalId: service.principal.principalId,
    parentDelegationId: root.delegation.delegationId,
    expiresAt: CHILD_EXPIRY,
    purposeRef: root.delegation.purposeRef,
    suffix: "child",
  });

  const resolved = await registry.resolveActionIdentity(
    {
      synthetic: true,
      workloadActorPrincipalId: service.principal.principalId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    },
    {
      sessionToken: "session-ava-primary",
      expectedTenantId: TENANT_ID,
      delegationId: child.delegation.delegationId,
    },
  );

  assert.equal(
    resolved.humanSubject.principalId,
    human.principal.principalId,
  );
  assert.equal(
    resolved.workloadActor.principalId,
    service.principal.principalId,
  );
  assert.deepEqual(
    resolved.delegationChain.map(({ delegationId }) => delegationId),
    [root.delegation.delegationId, child.delegation.delegationId],
  );
  assert.equal(resolved.purposeRef, root.delegation.purposeRef);
  assert.deepEqual(
    resolved.delegationChain.map(({ purposeRef }) => purposeRef),
    [root.delegation.purposeRef, root.delegation.purposeRef],
  );
  assert.equal(resolved.authorizationStatus, "NOT_EVALUATED");
  assert.equal(
    resolved.trustSource,
    "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
  );
});

test("the client cannot inject a workload actor or an authorization field", async () => {
  const { registry } = createHarness();
  await assert.rejects(
    registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId:
          "prn_01984700-0000-7000-8000-000000000999",
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: "dlg_01984700-0000-7000-8000-000000000999",
        workloadActorPrincipalId:
          "prn_01984700-0000-7000-8000-000000000998",
      },
    ),
    errorCode("INVALID_COMMAND"),
  );

  await assert.rejects(
    registry.execute(operator, {
      kind: "CREATE_DELEGATION",
      idempotencyKey: "delegation-with-scope",
      tenantId: TENANT_ID,
      humanSubjectPrincipalId:
        "prn_01984700-0000-7000-8000-000000000001",
      delegatorPrincipalId:
        "prn_01984700-0000-7000-8000-000000000001",
      delegatePrincipalId:
        "prn_01984700-0000-7000-8000-000000000002",
      expiresAt: EXPIRY,
      purposeRef: "synthetic://c05/no-authorization",
      permission: "orders.write",
      correlationId: "delegation-with-scope",
    }),
    errorCode("INVALID_COMMAND"),
  );
});

test("C04 account suspension fails closed before asynchronous C05 synchronization", async () => {
  const { registry, accounts } = createHarness();
  const human = await createPrincipal(registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(registry, AGENT_ASSISTANT, "agent");
  await linkAccount(
    registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const delegation = await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "root",
  });
  const account = accounts.get(
    "sia_01984700-0000-7000-8000-000000000101",
  );
  account.state = "SUSPENDED";
  account.lifecycleVersion += 1;
  account.revocationEpoch += 1;

  await assert.rejects(
    registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: delegation.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );

  const synchronized = await registry.execute(operator, {
    kind: "SYNC_IDENTITY_ACCOUNT",
    idempotencyKey: "sync-suspended",
    tenantId: TENANT_ID,
    identityAccountId: account.accountId,
    correlationId: "sync-suspended",
  });
  assert.equal(synchronized.identityLink.state, "SUSPENDED");
  assert.equal(synchronized.revokedDelegations, undefined);
  const snapshot = await registry.snapshot(operator, { tenantId: TENANT_ID });
  assert.equal(snapshot.delegations[0].state, "REVOKED");
});

test("C03 Tenant suspension immediately blocks action identity resolution", async () => {
  const harness = createHarness();
  const human = await createPrincipal(harness.registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(
    harness.registry,
    AGENT_ASSISTANT,
    "agent",
  );
  await linkAccount(
    harness.registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const delegation = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "tenant-suspension",
  });
  harness.setTenantState("SUSPENDED");

  await assert.rejects(
    harness.registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: delegation.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );
});

test("IdP migration reissues delegations after each IdentityLink epoch change", async () => {
  const { registry } = createHarness();
  const human = await createPrincipal(registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(registry, AGENT_ASSISTANT, "agent");
  const first = await linkAccount(
    registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "first",
  );
  const oldDelegation = await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "before-migration",
  });
  await linkAccount(
    registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000102",
    "second",
  );
  await assert.rejects(
    registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-migrated",
        expectedTenantId: TENANT_ID,
        delegationId: oldDelegation.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );
  const migrationDelegation = await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "during-migration",
  });
  const duringMigration = await registry.resolveActionIdentity(
    {
      synthetic: true,
      workloadActorPrincipalId: agent.principal.principalId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    },
    {
      sessionToken: "session-ava-migrated",
      expectedTenantId: TENANT_ID,
      delegationId: migrationDelegation.delegation.delegationId,
    },
  );
  assert.equal(
    duringMigration.identityAccountId,
    "sia_01984700-0000-7000-8000-000000000102",
  );
  await registry.execute(operator, {
    kind: "RETIRE_IDENTITY_LINK",
    idempotencyKey: "retire-first",
    tenantId: TENANT_ID,
    identityLinkId: first.identityLink.identityLinkId,
    expectedVersion: 1,
    reasonRef: "synthetic://c05/idp-migration",
    correlationId: "retire-first",
  });
  await assert.rejects(
    registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-migrated",
        expectedTenantId: TENANT_ID,
        delegationId: migrationDelegation.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );
  const finalDelegation = await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "after-migration",
  });
  const resolved = await registry.resolveActionIdentity(
    {
      synthetic: true,
      workloadActorPrincipalId: agent.principal.principalId,
      workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    },
    {
      sessionToken: "session-ava-migrated",
      expectedTenantId: TENANT_ID,
      delegationId: finalDelegation.delegation.delegationId,
    },
  );
  assert.equal(resolved.humanSubject.principalId, human.principal.principalId);
  const snapshot = await registry.snapshot(operator, { tenantId: TENANT_ID });
  assert.equal(snapshot.principals[0].principalId, human.principal.principalId);
  assert.equal(snapshot.principals[0].state, "ACTIVE");
  assert.deepEqual(
    snapshot.identityLinks.map(({ state }) => state).sort(),
    ["ACTIVE", "RETIRED"],
  );
  assert.deepEqual(
    snapshot.delegations.map(({ state }) => state),
    ["REVOKED", "REVOKED", "ACTIVE"],
  );
});

test("explicit link correction changes only future resolution and preserves retired history", async () => {
  const { registry } = createHarness();
  const ava = await createPrincipal(registry, HUMAN_AVA, "ava");
  const noah = await createPrincipal(registry, HUMAN_NOAH, "noah");
  const unrelated = await linkAccount(
    registry,
    ava.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000102",
    "unrelated-before-wrong-link",
  );
  const linked = await linkAccount(
    registry,
    ava.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "wrong-link",
  );
  await assert.rejects(
    registry.execute(operator, {
      kind: "REASSIGN_IDENTITY_ACCOUNT",
      idempotencyKey: "uncatalogued-correction",
      tenantId: TENANT_ID,
      identityLinkId: linked.identityLink.identityLinkId,
      targetPrincipalId: noah.principal.principalId,
      expectedVersion: 1,
      reasonRef: "synthetic://c05/correction/unapproved",
      correlationId: "uncatalogued-correction",
    }),
    errorCode("UNKNOWN_IDENTITY_CORRECTION"),
  );
  const corrected = await registry.execute(operator, {
    kind: "REASSIGN_IDENTITY_ACCOUNT",
    idempotencyKey: "correct-link",
    tenantId: TENANT_ID,
    identityLinkId: linked.identityLink.identityLinkId,
    targetPrincipalId: noah.principal.principalId,
    expectedVersion: 1,
    reasonRef: CORRECTION_REF,
    correlationId: "correct-link",
  });
  assert.equal(corrected.retiredIdentityLink.state, "RETIRED");
  assert.equal(
    corrected.identityLink.principalId,
    noah.principal.principalId,
  );
  const snapshot = await registry.snapshot(operator, { tenantId: TENANT_ID });
  assert.equal(snapshot.identityLinks.length, 3);
  assert.deepEqual(
    snapshot.identityLinks.find(
      ({ identityLinkId }) =>
        identityLinkId === unrelated.identityLink.identityLinkId,
    ),
    unrelated.identityLink,
  );
  assert.equal(
    snapshot.events.at(-1).data.correction_mapping_hash,
    CORRECTION_HASH,
  );
});

test("a tampered identity correction hash is rejected atomically", async () => {
  const { registry } = createHarness({
    correctionHash: `sha256:${"0".repeat(64)}`,
  });
  const ava = await createPrincipal(registry, HUMAN_AVA, "ava");
  const noah = await createPrincipal(registry, HUMAN_NOAH, "noah");
  const linked = await linkAccount(
    registry,
    ava.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "tampered-correction",
  );

  await assert.rejects(
    registry.execute(operator, {
      kind: "REASSIGN_IDENTITY_ACCOUNT",
      idempotencyKey: "tampered-correction",
      tenantId: TENANT_ID,
      identityLinkId: linked.identityLink.identityLinkId,
      targetPrincipalId: noah.principal.principalId,
      expectedVersion: 1,
      reasonRef: CORRECTION_REF,
      correlationId: "tampered-correction",
    }),
    errorCode("INVALID_PRINCIPAL_CATALOG"),
  );
  const snapshot = await registry.snapshot(operator, { tenantId: TENANT_ID });
  assert.deepEqual(
    snapshot.identityLinks.map(({ state }) => state),
    ["ACTIVE"],
  );
});

test("link correction rejects a stale or terminated C04 account", async () => {
  const { registry, accounts } = createHarness();
  const ava = await createPrincipal(registry, HUMAN_AVA, "ava");
  const noah = await createPrincipal(registry, HUMAN_NOAH, "noah");
  const linked = await linkAccount(
    registry,
    ava.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "stale-correction",
  );
  const account = accounts.get(
    "sia_01984700-0000-7000-8000-000000000101",
  );
  account.state = "TERMINATED";
  account.lifecycleVersion += 1;
  account.revocationEpoch += 1;

  await assert.rejects(
    registry.execute(operator, {
      kind: "REASSIGN_IDENTITY_ACCOUNT",
      idempotencyKey: "terminated-correction",
      tenantId: TENANT_ID,
      identityLinkId: linked.identityLink.identityLinkId,
      targetPrincipalId: noah.principal.principalId,
      expectedVersion: 1,
      reasonRef: CORRECTION_REF,
      correlationId: "terminated-correction",
    }),
    errorCode("IDENTITY_LINK_CONFLICT"),
  );
});

test("Principal suspension revokes old delegations and DEACTIVATED is absorbing", async () => {
  const { registry } = createHarness();
  const human = await createPrincipal(registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(registry, AGENT_ASSISTANT, "agent");
  await linkAccount(
    registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "root",
  });
  const suspended = await registry.execute(operator, {
    kind: "CHANGE_PRINCIPAL_STATE",
    idempotencyKey: "suspend-human",
    tenantId: TENANT_ID,
    principalId: human.principal.principalId,
    expectedVersion: 1,
    desiredState: "SUSPENDED",
    reasonRef: "synthetic://c05/principal-suspended",
    correlationId: "suspend-human",
  });
  assert.equal(suspended.principal.state, "SUSPENDED");
  assert.equal(suspended.revokedDelegations, 1);

  const resumed = await registry.execute(operator, {
    kind: "CHANGE_PRINCIPAL_STATE",
    idempotencyKey: "resume-human",
    tenantId: TENANT_ID,
    principalId: human.principal.principalId,
    expectedVersion: 2,
    desiredState: "ACTIVE",
    reasonRef: "synthetic://c05/principal-resumed",
    correlationId: "resume-human",
  });
  assert.equal(resumed.principal.state, "ACTIVE");

  const deactivated = await registry.execute(operator, {
    kind: "CHANGE_PRINCIPAL_STATE",
    idempotencyKey: "deactivate-human",
    tenantId: TENANT_ID,
    principalId: human.principal.principalId,
    expectedVersion: 3,
    desiredState: "DEACTIVATED",
    reasonRef: "synthetic://c05/principal-deactivated",
    correlationId: "deactivate-human",
  });
  assert.equal(deactivated.principal.state, "DEACTIVATED");
  assert.equal(deactivated.retiredIdentityLinks, 1);

  await assert.rejects(
    registry.execute(operator, {
      kind: "CHANGE_PRINCIPAL_STATE",
      idempotencyKey: "reactivate-human",
      tenantId: TENANT_ID,
      principalId: human.principal.principalId,
      expectedVersion: 4,
      desiredState: "ACTIVE",
      reasonRef: "synthetic://c05/forbidden-reactivation",
      correlationId: "reactivate-human",
    }),
    errorCode("INVALID_PRINCIPAL_STATE"),
  );
});

test("idempotency is exact and tenant activity gates creation", async () => {
  const harness = createHarness();
  const command = {
    kind: "CREATE_SYNTHETIC_PRINCIPAL",
    idempotencyKey: "exact-create",
    tenantId: TENANT_ID,
    fixturePrincipalRef: HUMAN_AVA,
    correlationId: "exact-create",
  };
  const first = await harness.registry.execute(operator, command);
  const replay = await harness.registry.execute(operator, command);
  assert.equal(replay.principal.principalId, first.principal.principalId);
  assert.equal(replay.duplicate, true);

  await assert.rejects(
    harness.registry.execute(operator, {
      ...command,
      fixturePrincipalRef: HUMAN_NOAH,
    }),
    errorCode("IDEMPOTENCY_CONFLICT"),
  );

  harness.setTenantState("SUSPENDED");
  const suspendedReplay = await harness.registry.execute(operator, command);
  assert.equal(
    suspendedReplay.principal.principalId,
    first.principal.principalId,
  );
  assert.equal(suspendedReplay.duplicate, true);
  await assert.rejects(
    createPrincipal(harness.registry, AGENT_ASSISTANT, "blocked"),
    errorCode("TENANT_NOT_ACTIVE"),
  );
});

test("a session invalidated during the final C04 recheck never returns a partial identity", async () => {
  const harness = createHarness();
  const human = await createPrincipal(harness.registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(
    harness.registry,
    AGENT_ASSISTANT,
    "agent",
  );
  await linkAccount(
    harness.registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const delegation = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "race",
  });
  harness.beforeSecondSessionResolve(() => {
    const account = harness.accounts.get(
      "sia_01984700-0000-7000-8000-000000000101",
    );
    account.state = "TERMINATED";
    account.lifecycleVersion += 1;
    account.revocationEpoch += 1;
  });

  await assert.rejects(
    harness.registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: delegation.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );
});

test("delegations carry independent purpose labels and fail closed on invalid state", async () => {
  const harness = createHarness();
  const human = await createPrincipal(harness.registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(
    harness.registry,
    AGENT_ASSISTANT,
    "agent",
  );
  const service = await createPrincipal(
    harness.registry,
    SERVICE_RUNNER,
    "service",
  );
  await linkAccount(
    harness.registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const first = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "purpose-one",
  });
  const second = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    expiresAt: CHILD_EXPIRY,
    suffix: "purpose-two",
  });
  assert.notEqual(
    first.delegation.delegationId,
    second.delegation.delegationId,
  );

  await assert.rejects(
    harness.registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: service.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: first.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );

  await harness.registry.execute(operator, {
    kind: "REVOKE_DELEGATION",
    idempotencyKey: "revoke-purpose-one",
    tenantId: TENANT_ID,
    delegationId: first.delegation.delegationId,
    expectedVersion: 1,
    reasonRef: "synthetic://c05/delegation/revoked",
    correlationId: "revoke-purpose-one",
  });
  await assert.rejects(
    harness.registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: first.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );

  harness.setTime("2026-07-26T08:31:00.000Z");
  await assert.rejects(
    harness.registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: second.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );
});

test("revoking a parent delegation invalidates its active leaf", async () => {
  const harness = createHarness();
  const human = await createPrincipal(harness.registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(
    harness.registry,
    AGENT_ASSISTANT,
    "agent",
  );
  const service = await createPrincipal(
    harness.registry,
    SERVICE_RUNNER,
    "service",
  );
  await linkAccount(
    harness.registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const root = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "cascade-root",
  });
  const child = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: agent.principal.principalId,
    delegatePrincipalId: service.principal.principalId,
    parentDelegationId: root.delegation.delegationId,
    expiresAt: CHILD_EXPIRY,
    suffix: "cascade-child",
    purposeRef: root.delegation.purposeRef,
  });
  const revoked = await harness.registry.execute(operator, {
    kind: "REVOKE_DELEGATION",
    idempotencyKey: "revoke-cascade-root",
    tenantId: TENANT_ID,
    delegationId: root.delegation.delegationId,
    expectedVersion: 1,
    reasonRef: "test://c05/delegation/cascade-revoked",
    correlationId: "revoke-cascade-root",
  });
  assert.equal(revoked.revokedDelegations, 2);

  await assert.rejects(
    harness.registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: service.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: child.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );
});

test("delegation cycles and cross-Tenant endpoints are rejected", async () => {
  const { registry } = createHarness();
  const human = await createPrincipal(registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(registry, AGENT_ASSISTANT, "agent");
  const service = await createPrincipal(registry, SERVICE_RUNNER, "service");
  const root = await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "cycle-root",
  });
  await assert.rejects(
    createDelegation(registry, {
      humanSubjectPrincipalId: human.principal.principalId,
      delegatorPrincipalId: agent.principal.principalId,
      delegatePrincipalId: service.principal.principalId,
      parentDelegationId: root.delegation.delegationId,
      expiresAt: CHILD_EXPIRY,
      suffix: "different-purpose",
    }),
    errorCode("DELEGATION_INVALID"),
  );
  const child = await createDelegation(registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: agent.principal.principalId,
    delegatePrincipalId: service.principal.principalId,
    parentDelegationId: root.delegation.delegationId,
    expiresAt: CHILD_EXPIRY,
    purposeRef: root.delegation.purposeRef,
    suffix: "cycle-child",
  });
  await assert.rejects(
    createDelegation(registry, {
      humanSubjectPrincipalId: human.principal.principalId,
      delegatorPrincipalId: service.principal.principalId,
      delegatePrincipalId: agent.principal.principalId,
      parentDelegationId: child.delegation.delegationId,
      expiresAt: CHILD_EXPIRY,
      purposeRef: root.delegation.purposeRef,
      suffix: "cycle-close",
    }),
    errorCode("DELEGATION_INVALID"),
  );

  const otherTenantService = await registry.execute(operator, {
    kind: "CREATE_SYNTHETIC_PRINCIPAL",
    idempotencyKey: "other-tenant-service",
    tenantId: OTHER_TENANT_ID,
    fixturePrincipalRef: SERVICE_RUNNER,
    correlationId: "other-tenant-service",
  });
  await assert.rejects(
    createDelegation(registry, {
      humanSubjectPrincipalId: human.principal.principalId,
      delegatorPrincipalId: human.principal.principalId,
      delegatePrincipalId: otherTenantService.principal.principalId,
      suffix: "cross-tenant",
    }),
    errorCode("PRINCIPAL_NOT_ACTIVE"),
  );
});

test("a ninth delegation hop is rejected and eight committed hops remain intact", async () => {
  const extraPrincipals = Array.from({ length: 7 }, (_, index) => ({
    fixturePrincipalRef: `test://c05/principals/agent-${index + 1}`,
    principalType: "AGENT",
    identityProfileRefs: [],
  }));
  const { registry } = createHarness({ extraPrincipals });
  const human = await createPrincipal(registry, HUMAN_AVA, "depth-human");
  const workloadRefs = [
    AGENT_ASSISTANT,
    SERVICE_RUNNER,
    ...extraPrincipals.map(({ fixturePrincipalRef }) => fixturePrincipalRef),
  ];
  const workloads = [];
  for (const [index, fixturePrincipalRef] of workloadRefs.entries()) {
    workloads.push(
      await createPrincipal(
        registry,
        fixturePrincipalRef,
        `depth-workload-${index + 1}`,
      ),
    );
  }
  let parent = null;
  let delegatorPrincipalId = human.principal.principalId;
  const purposeRef = "test://c05/delegation/eight-hop-limit";
  for (const [index, workload] of workloads.entries()) {
    const operation = createDelegation(registry, {
      humanSubjectPrincipalId: human.principal.principalId,
      delegatorPrincipalId,
      delegatePrincipalId: workload.principal.principalId,
      ...(parent
        ? { parentDelegationId: parent.delegation.delegationId }
        : {}),
      expiresAt: EXPIRY,
      suffix: `depth-${index + 1}`,
      purposeRef,
    });
    if (index === 8) {
      await assert.rejects(operation, errorCode("DELEGATION_INVALID"));
      break;
    }
    parent = await operation;
    delegatorPrincipalId = workload.principal.principalId;
  }
  const snapshot = await registry.snapshot(operator, { tenantId: TENANT_ID });
  assert.equal(snapshot.delegations.length, 8);
});

test("Identity Account IDs must be exact C04 UUIDv7 identifiers", async () => {
  const { registry } = createHarness();
  const human = await createPrincipal(registry, HUMAN_AVA, "human");
  await assert.rejects(
    linkAccount(registry, human.principal.principalId, "sia_-", "invalid-id"),
    errorCode("INVALID_COMMAND"),
  );
});

test("malformed C04 account data fails closed", async () => {
  const { registry, accounts } = createHarness();
  const human = await createPrincipal(registry, HUMAN_AVA, "human");
  accounts.get(
    "sia_01984700-0000-7000-8000-000000000101",
  ).lifecycleVersion = 0;

  await assert.rejects(
    linkAccount(
      registry,
      human.principal.principalId,
      "sia_01984700-0000-7000-8000-000000000101",
      "malformed-account",
    ),
    errorCode("DEPENDENCY_UNAVAILABLE"),
  );
});

test("generated identifiers and delegation times are validated before storage", async () => {
  const invalidIdHarness = createHarness({
    idFactory: () => "not-a-uuid",
  });
  await assert.rejects(
    createPrincipal(invalidIdHarness.registry, HUMAN_AVA, "invalid-id"),
    errorCode("INVALID_COMMAND"),
  );

  const harness = createHarness();
  const human = await createPrincipal(
    harness.registry,
    HUMAN_AVA,
    "time-human",
  );
  const agent = await createPrincipal(
    harness.registry,
    AGENT_ASSISTANT,
    "time-agent",
  );
  let clockReads = 0;
  harness.setClock(() => {
    clockReads += 1;
    return clockReads === 1
      ? "2026-07-26T08:00:00.000Z"
      : "2026-07-26T08:00:00.001Z";
  });
  const delegation = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    expiresAt: "2026-07-26T08:00:00.001Z",
    suffix: "one-millisecond",
  });
  assert.equal(delegation.delegation.issuedAt, "2026-07-26T08:00:00.000Z");

  for (const expiresAt of [
    "2026-02-30T08:00:00.000Z",
    "2026-07-26T09:00:00",
  ]) {
    await assert.rejects(
      createDelegation(harness.registry, {
        humanSubjectPrincipalId: human.principal.principalId,
        delegatorPrincipalId: human.principal.principalId,
        delegatePrincipalId: agent.principal.principalId,
        expiresAt,
        suffix: `invalid-time-${expiresAt}`,
      }),
      errorCode("INVALID_COMMAND"),
    );
  }
});

test("an inactive Tenant permits fail-closing changes but cannot reactivate Principal or IdentityLink state", async () => {
  const harness = createHarness();
  const human = await createPrincipal(harness.registry, HUMAN_AVA, "human");
  await linkAccount(
    harness.registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const suspendedPrincipal = await harness.registry.execute(operator, {
    kind: "CHANGE_PRINCIPAL_STATE",
    idempotencyKey: "suspend-before-tenant",
    tenantId: TENANT_ID,
    principalId: human.principal.principalId,
    expectedVersion: 1,
    desiredState: "SUSPENDED",
    reasonRef: "synthetic://c05/suspend-before-tenant",
    correlationId: "suspend-before-tenant",
  });
  assert.equal(suspendedPrincipal.principal.state, "SUSPENDED");

  const account = harness.accounts.get(
    "sia_01984700-0000-7000-8000-000000000101",
  );
  account.state = "SUSPENDED";
  account.lifecycleVersion += 1;
  account.revocationEpoch += 1;
  await harness.registry.execute(operator, {
    kind: "SYNC_IDENTITY_ACCOUNT",
    idempotencyKey: "sync-link-suspended",
    tenantId: TENANT_ID,
    identityAccountId: account.accountId,
    correlationId: "sync-link-suspended",
  });

  account.state = "ACTIVE";
  account.lifecycleVersion += 1;
  account.revocationEpoch += 1;
  harness.setTenantState("SUSPENDED");
  await assert.rejects(
    harness.registry.execute(operator, {
      kind: "CHANGE_PRINCIPAL_STATE",
      idempotencyKey: "reactivate-under-suspended-tenant",
      tenantId: TENANT_ID,
      principalId: human.principal.principalId,
      expectedVersion: 2,
      desiredState: "ACTIVE",
      reasonRef: "synthetic://c05/blocked-reactivation",
      correlationId: "reactivate-under-suspended-tenant",
    }),
    errorCode("TENANT_NOT_ACTIVE"),
  );
  await assert.rejects(
    harness.registry.execute(operator, {
      kind: "SYNC_IDENTITY_ACCOUNT",
      idempotencyKey: "restore-link-under-suspended-tenant",
      tenantId: TENANT_ID,
      identityAccountId: account.accountId,
      correlationId: "restore-link-under-suspended-tenant",
    }),
    errorCode("TENANT_NOT_ACTIVE"),
  );
});

test("a C05 lifecycle change during resolution is caught by the final C05 recheck", async () => {
  const harness = createHarness();
  const human = await createPrincipal(harness.registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(
    harness.registry,
    AGENT_ASSISTANT,
    "agent",
  );
  await linkAccount(
    harness.registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const delegation = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "actor-race",
  });
  harness.beforeSecondSessionResolve(() =>
    harness.registry.execute(operator, {
      kind: "CHANGE_PRINCIPAL_STATE",
      idempotencyKey: "suspend-actor-during-resolution",
      tenantId: TENANT_ID,
      principalId: agent.principal.principalId,
      expectedVersion: 1,
      desiredState: "SUSPENDED",
      reasonRef: "synthetic://c05/actor-race",
      correlationId: "suspend-actor-during-resolution",
    }),
  );

  await assert.rejects(
    harness.registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: delegation.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );
});

test("an unsynchronized C04 lifecycle revision cannot reuse an old delegation", async () => {
  const harness = createHarness();
  const human = await createPrincipal(harness.registry, HUMAN_AVA, "human");
  const agent = await createPrincipal(
    harness.registry,
    AGENT_ASSISTANT,
    "agent",
  );
  await linkAccount(
    harness.registry,
    human.principal.principalId,
    "sia_01984700-0000-7000-8000-000000000101",
    "human",
  );
  const delegation = await createDelegation(harness.registry, {
    humanSubjectPrincipalId: human.principal.principalId,
    delegatorPrincipalId: human.principal.principalId,
    delegatePrincipalId: agent.principal.principalId,
    suffix: "stale-account-revision",
  });
  const account = harness.accounts.get(
    "sia_01984700-0000-7000-8000-000000000101",
  );
  account.state = "SUSPENDED";
  account.lifecycleVersion += 1;
  account.revocationEpoch += 1;
  account.state = "ACTIVE";
  account.lifecycleVersion += 1;
  account.revocationEpoch += 1;

  await assert.rejects(
    harness.registry.resolveActionIdentity(
      {
        synthetic: true,
        workloadActorPrincipalId: agent.principal.principalId,
        workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
      },
      {
        sessionToken: "session-ava-primary",
        expectedTenantId: TENANT_ID,
        delegationId: delegation.delegation.delegationId,
      },
    ),
    errorCode("ACTION_IDENTITY_INVALID"),
  );
});
