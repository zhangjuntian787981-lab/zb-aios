import assert from "node:assert/strict";
import test from "node:test";
import {
  G1_SYNTHETIC_TENANT_IDS,
  createG1SyntheticRuntime,
} from "../lib/g1-synthetic-runtime.mjs";
import { createMemoryTenantStore } from "../lib/tenant-registry.mjs";
import { createMemoryIdentityStore } from "../lib/identity-federation.mjs";
import { createMemoryPrincipalStore } from "../lib/stable-principal.mjs";
import { createMemoryAuthorizationStore } from "../lib/authorization-facade.mjs";
import {
  createMemoryC10QuarantineStore,
  createMemoryKnowledgeCatalogStore,
} from "../lib/knowledge-catalog.mjs";
import { createMemoryPermissionAwareRagStore } from "../lib/permission-aware-rag.mjs";
import { createMemoryModelGatewayStore } from "../lib/model-gateway.mjs";
import { createC14SyntheticModelProvider } from "../lib/c14-synthetic-model-provider.mjs";
import { createMemoryToolGatewayStore } from "../lib/tool-gateway.mjs";
import { createMemoryHumanDecisionStore } from "../lib/human-decision-workflow.mjs";
import { createMemoryC12StatePort } from "../lib/agent-orchestrator.mjs";
import { createMemoryAiosStateStore } from "../lib/aios-state-core.mjs";
import { createC08C0MockToolReceipts } from "../lib/c08-c0-mock-tool-receipts.mjs";
import { createMemoryAuditEvidenceStore } from "../lib/c18-audit-evidence.mjs";
import { createMemoryObservabilityStore } from "../lib/c19-observability.mjs";

function createTenantDataAdapter() {
  const receipts = new Map();
  const calls = [];
  const duplicates = [];
  return {
    calls,
    duplicates,
    async project(event) {
      const prior = receipts.get(event.id);
      const eventJson = JSON.stringify(event);
      calls.push(structuredClone(event));
      if (prior && prior !== eventJson) {
        const error = new Error("Lifecycle event changed.");
        error.code = "LIFECYCLE_EVENT_CONFLICT";
        throw error;
      }
      receipts.set(event.id, eventJson);
      duplicates.push(Boolean(prior));
      return {
        tenantId: event.subject,
        eventId: event.id,
        status: "SUCCEEDED",
        duplicate: Boolean(prior),
      };
    },
  };
}

function createSharedStorage() {
  const tenantDataAdapter = createTenantDataAdapter();
  const modelProvider = createC14SyntheticModelProvider();
  const c12StatePort = createMemoryC12StatePort();
  const c12FactoryCalls = [];
  const confirmationCommands = [];
  const baseToolStore = createMemoryToolGatewayStore();
  const toolStore = {
    ...baseToolStore,
    async saveConfirmation(scope, command) {
      confirmationCommands.push(structuredClone(command));
      return baseToolStore.saveConfirmation(scope, command);
    },
  };
  return {
    storage: {
      tenantStore: createMemoryTenantStore(),
      tenantDataAdapter,
      identityStore: createMemoryIdentityStore(),
      principalStore: createMemoryPrincipalStore(),
      authorizationStore: createMemoryAuthorizationStore(),
      knowledgeCatalogStore: createMemoryKnowledgeCatalogStore(),
      knowledgeQuarantineStore: createMemoryC10QuarantineStore(),
      ragStore: createMemoryPermissionAwareRagStore(),
      modelDraftStore: createMemoryModelGatewayStore(),
      modelReviewStore: createMemoryModelGatewayStore(),
      modelProvider,
      toolStore,
      decisionStore: createMemoryHumanDecisionStore(),
      c12StatePortFactory(tenantRegistry) {
        c12FactoryCalls.push(tenantRegistry);
        return c12StatePort;
      },
      c08StateStore: createMemoryAiosStateStore(),
      c08Receipts: createC08C0MockToolReceipts(),
      auditStore: createMemoryAuditEvidenceStore(),
      observabilityStore: createMemoryObservabilityStore(),
    },
    tenantDataAdapter,
    modelProvider,
    c12FactoryCalls,
    confirmationCommands,
  };
}

function externalOptions(shared, identityInstancePrefix = "1a2b") {
  return {
    storage: shared.storage,
    identityInstancePrefix,
  };
}

test("external G1 storage is exact and identity instance prefix fails closed", async () => {
  const shared = createSharedStorage();
  await assert.rejects(
    createG1SyntheticRuntime({ storage: shared.storage }),
    { code: "INVALID_G1_STORAGE_CONFIGURATION" },
  );
  for (const identityInstancePrefix of [
    "",
    "123",
    "ABCDE",
    "g123",
    "12345",
  ]) {
    await assert.rejects(
      createG1SyntheticRuntime(
        externalOptions(shared, identityInstancePrefix),
      ),
      { code: "INVALID_G1_STORAGE_CONFIGURATION" },
    );
  }
  const missingTenantData = { ...shared.storage };
  delete missingTenantData.tenantDataAdapter;
  await assert.rejects(
    createG1SyntheticRuntime({
      storage: missingTenantData,
      identityInstancePrefix: "1a2b",
    }),
    { code: "INVALID_G1_STORAGE_CONFIGURATION" },
  );
  await assert.rejects(
    createG1SyntheticRuntime({
      ...externalOptions(shared),
      unexpected: true,
    }),
    { code: "INVALID_G1_STORAGE_CONFIGURATION" },
  );
  await assert.rejects(
    createG1SyntheticRuntime({
      storage: { ...shared.storage, unexpected: true },
      identityInstancePrefix: "1a2b",
    }),
    { code: "INVALID_G1_STORAGE_CONFIGURATION" },
  );
  assert.equal(shared.tenantDataAdapter.calls.length, 0);
});

test("external G1 storage validates the C12 factory and returned Port", async () => {
  const missingFactory = createSharedStorage();
  missingFactory.storage.c12StatePortFactory = {};
  await assert.rejects(
    createG1SyntheticRuntime(externalOptions(missingFactory)),
    { code: "INVALID_G1_STORAGE_CONFIGURATION" },
  );

  const invalidPort = createSharedStorage();
  invalidPort.storage.c12StatePortFactory = () => ({});
  await assert.rejects(
    createG1SyntheticRuntime(externalOptions(invalidPort)),
    { code: "INVALID_G1_STORAGE_CONFIGURATION" },
  );
});

test("external G1 storage projects provisioning and activation in Tenant order", async () => {
  const shared = createSharedStorage();
  await createG1SyntheticRuntime(externalOptions(shared));

  assert.deepEqual(
    shared.tenantDataAdapter.calls.map((event) => [
      event.subject,
      event.type,
    ]),
    G1_SYNTHETIC_TENANT_IDS.flatMap((tenantId) => [
      [tenantId, "product.tenant.provisioning-requested.v1"],
      [tenantId, "product.tenant.activated.v1"],
    ]),
  );
  assert.equal(shared.c12FactoryCalls.length, 1);
  assert.equal(
    typeof shared.c12FactoryCalls[0].admitNewRequest,
    "function",
  );
});

test("shared storage replays the complete G1 chain across runtime instances", async () => {
  const shared = createSharedStorage();
  const externalStartedAt = Date.now();
  const firstRuntime = await createG1SyntheticRuntime(
    externalOptions(shared, "1a2b"),
  );
  const first = await firstRuntime.runTenant(
    G1_SYNTHETIC_TENANT_IDS[0],
  );
  const providerCalls = shared.modelProvider.calls.length;
  assert.ok(shared.confirmationCommands.length > 0);
  assert.ok(
    Date.parse(
      shared.confirmationCommands[0].confirmation.expiresAt,
    ) > externalStartedAt,
  );

  const secondRuntime = await createG1SyntheticRuntime(
    externalOptions(shared, "3c4d"),
  );
  assert.deepEqual(
    shared.tenantDataAdapter.duplicates,
    [
      false,
      false,
      false,
      false,
      false,
      false,
      true,
      true,
      true,
      true,
      true,
      true,
    ],
  );
  const second = await secondRuntime.runTenant(
    G1_SYNTHETIC_TENANT_IDS[0],
  );

  assert.equal(second.modules.C08.replayed, true);
  assert.equal(second.modules.C12.replayed, true);
  assert.equal(second.modules.C18.replayed, true);
  assert.equal(second.modules.C19.replayed, true);
  assert.notEqual(
    second.modules.C06.decisionId,
    first.modules.C06.decisionId,
  );
  assert.match(
    first.modules.C06.decisionId,
    /^azd_01985000-1a2b-/,
  );
  assert.match(
    second.modules.C06.decisionId,
    /^azd_01985000-3c4d-/,
  );
  assert.equal(second.modules.C08.runId, first.modules.C08.runId);
  assert.equal(second.modules.C12.taskId, first.modules.C12.taskId);
  assert.equal(
    second.modules.C08.reconstructionHash,
    first.modules.C08.reconstructionHash,
  );
  assert.equal(
    second.modules.C12.stateSha256,
    first.modules.C12.stateSha256,
  );
  assert.equal(second.modules.C18.eventHash, first.modules.C18.eventHash);
  assert.equal(second.modules.C19.traceId, first.modules.C19.traceId);
  assert.equal(second.modules.C11.status, "ANSWERABLE");
  assert.equal(second.modules.C14.status, "SUCCEEDED");
  assert.equal(second.modules.C16.status, "SUCCEEDED");
  assert.equal(second.modules.C15.outcome, "APPROVE");
  assert.equal(second.modules.C16.adapterNewExecutionCount, 0);
  assert.equal(shared.modelProvider.calls.length, providerCalls);
});

test("default memory diagnostic keeps its deterministic C06 and C16 evidence", async () => {
  const firstRuntime = await createG1SyntheticRuntime();
  const secondRuntime = await createG1SyntheticRuntime();
  const first = await firstRuntime.runTenant(
    G1_SYNTHETIC_TENANT_IDS[0],
  );
  const second = await secondRuntime.runTenant(
    G1_SYNTHETIC_TENANT_IDS[0],
  );

  assert.equal(second.modules.C06.decisionId, first.modules.C06.decisionId);
  assert.equal(
    second.modules.C16.receiptSha256,
    first.modules.C16.receiptSha256,
  );
  assert.equal(
    second.modules.C12.stateSha256,
    first.modules.C12.stateSha256,
  );
});
