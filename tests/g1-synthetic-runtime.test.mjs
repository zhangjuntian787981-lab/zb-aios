import assert from "node:assert/strict";
import test from "node:test";
import {
  G1_SYNTHETIC_TENANT_IDS,
  createG1SyntheticRuntime,
} from "../lib/g1-synthetic-runtime.mjs";

test("G1 runtime deploys three fixed F02 Synthetic Tenants with three users and three roles each", async () => {
  const runtime = await createG1SyntheticRuntime();

  const deployment = await runtime.deploy();

  assert.deepEqual(
    deployment.tenants.map(({ tenantId }) => tenantId),
    G1_SYNTHETIC_TENANT_IDS,
  );
  for (const tenant of deployment.tenants) {
    assert.equal(tenant.tenantKind, "SYNTHETIC");
    assert.equal(tenant.users.length, 3);
    assert.equal(new Set(tenant.users.map(({ id }) => id)).size, 3);
    assert.deepEqual(
      tenant.roles.map(({ role }) => role).sort(),
      ["operations_planner", "quality_reviewer", "sales_analyst"],
    );
    assert.deepEqual(
      tenant.users.map(({ role }) => role).sort(),
      ["operations_planner", "quality_reviewer", "sales_analyst"],
    );
    for (const user of tenant.users) {
      assert.match(user.accountId, /^sia_[0-9a-f-]{36}$/);
      assert.match(user.profileRef, /^fixture:\/\//);
    }
  }
});

test("G1 deployment establishes nine distinct real C04 user sessions", async () => {
  const runtime = await createG1SyntheticRuntime();

  const deployment = await runtime.deploy();

  const sessionIds = [];
  const accountIds = [];
  for (const tenant of deployment.tenants) {
    assert.equal(tenant.chainActorLogin.module, "C04");
    assert.equal(tenant.chainActorLogin.tenantId, tenant.tenantId);
    assert.equal(tenant.chainActorLogin.selectedForChain, true);
    for (const user of tenant.users) {
      assert.equal(user.trustSource, "VERIFIED_SESSION");
      assert.equal(user.id, user.fixtureUserId);
      assert.ok(user.profileRef.includes(user.fixtureUserId));
      assert.equal("sessionToken" in user, false);
      sessionIds.push(user.sessionId);
      accountIds.push(user.accountId);
    }
  }
  assert.equal(new Set(sessionIds).size, 9);
  assert.equal(new Set(accountIds).size, 9);
});

test("G1 role-bound authorization allows its owner and fails closed for another real user", async () => {
  const runtime = await createG1SyntheticRuntime();
  const deployment = await runtime.deploy();
  const tenant = deployment.tenants[0];
  const [owner, wrongUser] = tenant.users;
  const resourceId = "g1_download_northstar_sales";

  runtime.registerRoleBoundResource({
    tenantId: tenant.tenantId,
    ownerFixtureUserId: owner.fixtureUserId,
    surface: "DOWNLOAD",
    resourceId,
  });
  const allowed = await runtime.authorizeRoleBoundResource({
    targetTenantId: tenant.tenantId,
    callerTenantId: tenant.tenantId,
    callerFixtureUserId: owner.fixtureUserId,
    surface: "DOWNLOAD",
    resourceId,
  });
  const denied = await runtime.authorizeRoleBoundResource({
    targetTenantId: tenant.tenantId,
    callerTenantId: tenant.tenantId,
    callerFixtureUserId: wrongUser.fixtureUserId,
    surface: "DOWNLOAD",
    resourceId,
  });

  assert.equal(allowed.decision.effect, "ALLOW");
  assert.equal(denied.decision.effect, "DENY");
  assert.equal(allowed.caller.principalId, owner.principalId);
  assert.equal(
    allowed.caller.delegationId,
    owner.delegationIds.DOWNLOAD,
  );
  assert.equal("sessionToken" in allowed.caller, false);
  assert.throws(() =>
    runtime.registerRoleBoundResource({
      tenantId: tenant.tenantId,
      ownerFixtureUserId: wrongUser.fixtureUserId,
      surface: "DOWNLOAD",
      resourceId,
    }),
  );
  await assert.rejects(
    runtime.authorizeRoleBoundResource({
      targetTenantId: tenant.tenantId,
      callerTenantId: tenant.tenantId,
      callerFixtureUserId: owner.fixtureUserId,
      surface: "DOWNLOAD",
      resourceId: "g1_download_unknown",
    }),
  );
  await assert.rejects(
    runtime.authorizeRoleBoundResource({
      targetTenantId: tenant.tenantId,
      callerTenantId: tenant.tenantId,
      callerFixtureUserId: owner.fixtureUserId,
      ownerFixtureUserId: owner.fixtureUserId,
      surface: "DOWNLOAD",
      resourceId,
    }),
  );
});

test("G1 cross-Tenant role-bound authorization reaches real identity validation and returns one stable denial", async () => {
  const runtime = await createG1SyntheticRuntime();
  const deployment = await runtime.deploy();
  const [target, callerTenant] = deployment.tenants;
  const owner = target.users[0];
  const caller = callerTenant.users[0];
  const resourceId = "g1_retrieve_cross_tenant";
  runtime.registerRoleBoundResource({
    tenantId: target.tenantId,
    ownerFixtureUserId: owner.fixtureUserId,
    surface: "RETRIEVE",
    resourceId,
  });

  await assert.rejects(
    runtime.authorizeRoleBoundResource({
      targetTenantId: target.tenantId,
      callerTenantId: callerTenant.tenantId,
      callerFixtureUserId: caller.fixtureUserId,
      surface: "RETRIEVE",
      resourceId,
    }),
    (error) => error.code === "CROSS_TENANT_DENIED",
  );
});

test("G1 wrong-Tenant C04 session probe fails closed", async () => {
  const runtime = await createG1SyntheticRuntime();

  await assert.rejects(
    runtime.verifySessionIsolation({
      sourceTenantId: G1_SYNTHETIC_TENANT_IDS[0],
      targetTenantId: G1_SYNTHETIC_TENANT_IDS[1],
    }),
    (error) => typeof error.code === "string",
  );
});

test("G1 run resolves a real C05 principal and a real C06 bound decision", async () => {
  const runtime = await createG1SyntheticRuntime();

  const result = await runtime.runTenant(G1_SYNTHETIC_TENANT_IDS[0]);

  assert.equal(
    result.modules.C05.trustSource,
    "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
  );
  assert.match(
    result.modules.C05.humanPrincipalId,
    /^prn_[0-9a-f-]{36}$/,
  );
  assert.match(
    result.modules.C05.workloadActorPrincipalId,
    /^prn_[0-9a-f-]{36}$/,
  );
  assert.equal(result.modules.C06.effect, "ALLOW");
  assert.equal(result.modules.C06.authorizationStatus, "ALLOWED");
  assert.equal(result.modules.C06.surface, "MANAGE");
});

test("G1 run retrieves tenant-scoped evidence through the real C11 RAG service", async () => {
  const runtime = await createG1SyntheticRuntime();

  const result = await runtime.runTenant(G1_SYNTHETIC_TENANT_IDS[0]);

  assert.equal(result.modules.C11.status, "ANSWERABLE");
  assert.ok(result.modules.C11.evidenceCount > 0);
  assert.match(result.modules.C11.resultSha256, /^sha256:[a-f0-9]{64}$/);
});

test("G1 run uses real C14, C16 and C15 with no external effect", async () => {
  const runtime = await createG1SyntheticRuntime();

  const result = await runtime.runTenant(G1_SYNTHETIC_TENANT_IDS[0]);

  assert.equal(result.modules.C14.status, "SUCCEEDED");
  assert.match(result.modules.C14.modelRef, /^synthetic:\/\/c14\/models\//);
  assert.equal(result.modules.C16.status, "SUCCEEDED");
  assert.equal(result.modules.C16.networkRequestCount, 0);
  assert.equal(result.modules.C16.externalEffectCount, 0);
  assert.equal(result.modules.C15.decisionType, "SYNTHETIC_TEST_DECISION");
  assert.equal(result.modules.C15.outcome, "APPROVE");
  assert.equal(result.modules.C15.externalEffectCount, 0);
  assert.equal(result.modules.C15.effectExecuted, false);
});

test("G1 run is wrapped by real C08 state and completes the real C12 nine-node graph", async () => {
  const runtime = await createG1SyntheticRuntime();

  const result = await runtime.runTenant(G1_SYNTHETIC_TENANT_IDS[0]);

  assert.equal(result.modules.C12.status, "COMPLETED");
  assert.deepEqual(result.modules.C12.nodeOrder, [
    "CLASSIFY",
    "HARD_GATES",
    "RETRIEVE",
    "TOOL",
    "DRAFT",
    "VALIDATE",
    "INDEPENDENT_REVIEW",
    "HUMAN_GATE",
    "COMPLETE",
  ]);
  assert.equal(result.modules.C12.nodeCount, 9);
  assert.equal(result.modules.C12.toolExternalEffectCount, 0);
  assert.equal(result.modules.C12.humanDecisionProductionReusable, false);
  assert.equal(result.modules.C08.state, "SUCCEEDED");
  assert.equal(result.modules.C08.recoveryStatus, "TERMINAL_VERIFIED");
  assert.match(
    result.modules.C08.reconstructionHash,
    /^sha256:[a-f0-9]{64}$/,
  );
  assert.equal(
    result.modules.C08.resultContentSha256,
    result.modules.C12.stateSha256,
  );
});

test("G1 run appends and verifies one real C18 audit chain event", async () => {
  const runtime = await createG1SyntheticRuntime();

  const result = await runtime.runTenant(G1_SYNTHETIC_TENANT_IDS[0]);

  assert.equal(result.modules.C18.sequence, 1);
  assert.equal(result.modules.C18.eventCount, 1);
  assert.equal(result.modules.C18.chainVerified, true);
  assert.match(
    result.modules.C18.eventHash,
    /^sha256:[a-f0-9]{64}$/,
  );
});

test("G1 run records real C19 telemetry and settles model and tool usage on one trace", async () => {
  const runtime = await createG1SyntheticRuntime();

  const result = await runtime.runTenant(G1_SYNTHETIC_TENANT_IDS[0]);

  assert.equal(result.modules.C19.totalSignals, 4);
  assert.equal(result.modules.C19.traceCount, 1);
  assert.match(result.modules.C19.traceId, /^[a-f0-9]{32}$/);
  assert.equal(result.modules.C19.modelSettlementState, "SETTLED");
  assert.equal(result.modules.C19.toolSettlementState, "SETTLED");
  assert.equal(result.modules.C19.c12TaskId, result.modules.C12.taskId);
  assert.ok(result.modules.C19.bookedCostMicros > 0);
});

test("all three fixed Synthetic Tenants complete isolated C08 through C19 chains", async () => {
  const runtime = await createG1SyntheticRuntime();
  const results = [];
  for (const tenantId of G1_SYNTHETIC_TENANT_IDS) {
    results.push(await runtime.runTenant(tenantId));
  }

  assert.deepEqual(
    results.map(({ tenantId }) => tenantId),
    G1_SYNTHETIC_TENANT_IDS,
  );
  assert.equal(
    new Set(results.map(({ modules }) => modules.C08.runId)).size,
    3,
  );
  assert.equal(
    new Set(results.map(({ modules }) => modules.C12.taskId)).size,
    3,
  );
  assert.equal(
    results.every(
      ({ modules }) =>
        modules.C08.state === "SUCCEEDED" &&
        modules.C12.status === "COMPLETED" &&
        modules.C18.chainVerified === true &&
        modules.C19.traceCount === 1 &&
        modules.C16.externalEffectCount === 0,
    ),
    true,
  );
});

test("G1 complete run replays stable C08, C12, C18 and C19 evidence without a new effect", async () => {
  const runtime = await createG1SyntheticRuntime();

  const first = await runtime.runTenant(G1_SYNTHETIC_TENANT_IDS[0]);
  const replay = await runtime.runTenant(G1_SYNTHETIC_TENANT_IDS[0]);

  assert.equal(replay.modules.C08.replayed, true);
  assert.equal(replay.modules.C12.replayed, true);
  assert.equal(replay.modules.C18.replayed, true);
  assert.equal(replay.modules.C19.replayed, true);
  assert.equal(replay.modules.C08.runId, first.modules.C08.runId);
  assert.equal(replay.modules.C12.taskId, first.modules.C12.taskId);
  assert.equal(
    replay.modules.C08.reconstructionHash,
    first.modules.C08.reconstructionHash,
  );
  assert.equal(
    replay.modules.C12.stateSha256,
    first.modules.C12.stateSha256,
  );
  assert.equal(
    replay.modules.C18.eventHash,
    first.modules.C18.eventHash,
  );
  assert.equal(replay.modules.C19.traceId, first.modules.C19.traceId);
  assert.equal(replay.modules.C19.totalSignals, 4);
  assert.equal(replay.modules.C16.externalEffectCount, 0);
  assert.equal(
    replay.modules.C16.adapterNewExecutionCount,
    first.modules.C16.adapterNewExecutionCount,
  );
});
