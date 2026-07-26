import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createG1SyntheticRuntime } from "../lib/g1-synthetic-runtime.mjs";
import { createMemoryToolGatewayStore } from "../lib/tool-gateway.mjs";
import { createG1C16BoundFacade } from "./integration/g1-c16-bound-facade.mjs";

const NOW = "2026-07-27T00:00:00.000Z";
const OPERATION_BY_ROLE = Object.freeze({
  sales_analyst: "synthetic.approval.status.get",
  operations_planner: "synthetic.erp.order.get",
  quality_reviewer: "synthetic.bi.metric.get",
});

async function load(relativePath) {
  return JSON.parse(
    await readFile(new URL(`../${relativePath}`, import.meta.url), "utf8"),
  );
}

const CATALOG_DOCUMENT = await load(
  "implementation/p1/c16/operation-catalog.v1.json",
);
const FIXTURE_DOCUMENT = await load(
  "implementation/p1/c16/synthetic-tool-fixtures.v1.json",
);

function deterministicIds() {
  let value = 900;
  return () => {
    value += 1;
    return `018f0000-0000-7000-8000-${String(value).padStart(12, "0")}`;
  };
}

function memoryStore() {
  const store = createMemoryToolGatewayStore({
    clock: () => NOW,
  });
  return Object.freeze({
    ...store,
    observations() {
      return Object.freeze({
        backendKind: "NON_GATE_TEST_DOUBLE",
        backendInstanceId: "g1-c16-memory-test-double",
        persistent: false,
        negativeStorageTouchCount: 0,
      });
    },
  });
}

function authorization(tenant, user, resourceId) {
  return {
    effect: "ALLOW",
    authorizationStatus: "ALLOWED",
    c06BoundaryEntered: true,
    tenantId: tenant.tenantId,
    surface: "TOOL",
    resourceId,
    sessionId: user.sessionId,
    principalId: user.principalId,
    authoritativeRole: user.role,
    storeId: `store-${tenant.tenantId}`,
    authorizationModelId: "g1-role-model-v2",
    consistency: "HIGHER_CONSISTENCY",
  };
}

async function harness() {
  const deployment = await (await createG1SyntheticRuntime()).deploy();
  const store = memoryStore();
  const facade = createG1C16BoundFacade({
    deployment,
    store,
    catalogDocument: CATALOG_DOCUMENT,
    fixtureDocument: FIXTURE_DOCUMENT,
    clock: () => NOW,
    idFactory: deterministicIds(),
  });
  return { deployment, facade, store };
}

test("all deployed roles execute real C16 C0 calls and replay without a new effect", async () => {
  const { deployment, facade } = await harness();
  const executions = [];

  assert.deepEqual(Object.keys(facade), [
    "confirmBound",
    "executeBound",
    "observations",
  ]);

  for (const tenant of deployment.tenants) {
    for (const user of tenant.users) {
      const operationId = OPERATION_BY_ROLE[user.role];
      const fixture = FIXTURE_DOCUMENT.records.find(
        (record) =>
          record.tenantId === tenant.tenantId &&
          record.operationId === operationId,
      );
      const resourceId = `${user.fixtureUserId}-tool`;
      const decision = authorization(tenant, user, resourceId);
      const caseId = `case-${tenant.tenantId}-${user.fixtureUserId}`;
      const confirmation = await facade.confirmBound({
        tenantId: tenant.tenantId,
        resourceId,
        caseId,
        operationId,
        params: structuredClone(fixture.lookup),
        authorization: decision,
      });
      const execution = await facade.executeBound({
        tenantId: tenant.tenantId,
        resourceId,
        caseId,
        operationId,
        confirmation,
        authorization: decision,
      });
      assert.equal(execution.tenantId, tenant.tenantId);
      assert.equal(execution.operationId, operationId);
      assert.equal(execution.status, "SUCCEEDED");
      assert.equal(execution.receipt.networkRequestCount, 0);
      assert.equal(execution.receipt.externalEffectCount, 0);
      executions.push({
        input: {
          tenantId: tenant.tenantId,
          resourceId,
          caseId,
          operationId,
          confirmation,
          authorization: decision,
        },
        execution,
      });
    }
  }

  const replay = await facade.executeBound(executions[0].input);
  assert.equal(replay.callId, executions[0].execution.callId);
  assert.equal(replay.replayed, true);
  assert.deepEqual(facade.observations(), {
    backendKind: "NON_GATE_TEST_DOUBLE",
    backendInstanceId: "g1-c16-memory-test-double",
    persistent: false,
    confirmCount: 9,
    executeCount: 10,
    newExecutionCount: 9,
    networkRequestCount: 0,
    enterpriseEndpointCount: 0,
    enterpriseCredentialCount: 0,
    externalEffectCount: 0,
    negativeStorageTouchCount: 0,
  });
});

test("wrong session or changed outer decision fails before C16 storage and execution", async () => {
  const { deployment, facade, store } = await harness();
  const tenant = deployment.tenants[0];
  const user = tenant.users[0];
  const operationId = OPERATION_BY_ROLE[user.role];
  const fixture = FIXTURE_DOCUMENT.records.find(
    (record) =>
      record.tenantId === tenant.tenantId &&
      record.operationId === operationId,
  );
  const resourceId = `${user.fixtureUserId}-tool`;
  const decision = authorization(tenant, user, resourceId);
  const base = {
    tenantId: tenant.tenantId,
    resourceId,
    caseId: "case-c16-deny-before-storage",
    operationId,
    params: structuredClone(fixture.lookup),
    authorization: decision,
  };
  const emptySnapshot = store.snapshot();

  for (const changedAuthorization of [
    {
      ...decision,
      sessionId: "ses_018f0000-0000-7000-8000-999999999999",
    },
    {
      ...decision,
      principalId: tenant.users[1].principalId,
    },
    {
      ...decision,
      authoritativeRole: tenant.users[1].role,
    },
    {
      ...decision,
      effect: "DENY",
      authorizationStatus: "DENIED",
    },
  ]) {
    await assert.rejects(
      facade.confirmBound({
        ...base,
        authorization: changedAuthorization,
      }),
      (error) => error.code === "G1_C16_ACCESS_DENIED",
    );
  }
  assert.deepEqual(store.snapshot(), emptySnapshot);

  const confirmation = await facade.confirmBound(base);
  const beforeChangedDecision = store.snapshot();
  for (const changedInput of [
    {
      authorization: {
        ...decision,
        storeId: "different-openfga-store",
      },
    },
    {
      authorization: {
        ...decision,
        authorizationModelId: "different-openfga-model",
      },
    },
    {
      resourceId: `${resourceId}-changed`,
      authorization: {
        ...decision,
        resourceId: `${resourceId}-changed`,
      },
    },
  ]) {
    await assert.rejects(
      facade.executeBound({
        tenantId: tenant.tenantId,
        resourceId,
        caseId: base.caseId,
        operationId,
        confirmation,
        authorization: decision,
        ...changedInput,
      }),
      (error) => error.code === "G1_C16_ACCESS_DENIED",
    );
  }
  assert.deepEqual(store.snapshot(), beforeChangedDecision);
  assert.deepEqual(facade.observations(), {
    backendKind: "NON_GATE_TEST_DOUBLE",
    backendInstanceId: "g1-c16-memory-test-double",
    persistent: false,
    confirmCount: 1,
    executeCount: 0,
    newExecutionCount: 0,
    networkRequestCount: 0,
    enterpriseEndpointCount: 0,
    enterpriseCredentialCount: 0,
    externalEffectCount: 0,
    negativeStorageTouchCount: 0,
  });
});
