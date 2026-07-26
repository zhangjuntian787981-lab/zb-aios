import { join } from "node:path";
import pg from "pg";
import {
  createC08C0MockToolReceipts,
  createFileC08MockReceiptStore,
} from "../../lib/c08-c0-mock-tool-receipts.mjs";
import {
  createC14SyntheticModelProvider,
  createFileC14ModelReceiptStore,
} from "../../lib/c14-synthetic-model-provider.mjs";
import {
  createPostgresAuditEvidenceStore,
} from "../../lib/c18-audit-evidence-postgres-store.mjs";
import {
  createPostgresObservabilityStore,
} from "../../lib/c19-observability-postgres-store.mjs";
import { createFileC10QuarantineStore } from "../../lib/file-c10-quarantine-store.mjs";
import { createG1SyntheticRuntime } from "../../lib/g1-synthetic-runtime.mjs";
import {
  createPostgresAgentOrchestratorStatePort,
} from "../../lib/postgres-agent-orchestrator-state-port.mjs";
import {
  createPostgresAiosStateStore,
} from "../../lib/postgres-aios-state-store.mjs";
import {
  createPostgresAuthorizationStore,
} from "../../lib/postgres-authorization-store.mjs";
import {
  createPostgresHumanDecisionStore,
} from "../../lib/postgres-human-decision-store.mjs";
import {
  createPostgresIdentityStore,
} from "../../lib/postgres-identity-store.mjs";
import {
  createPostgresKnowledgeCatalogStore,
} from "../../lib/postgres-knowledge-catalog-store.mjs";
import {
  createPostgresModelGatewayStore,
} from "../../lib/postgres-model-gateway-store.mjs";
import {
  createPostgresPermissionAwareRagStore,
} from "../../lib/postgres-permission-aware-rag-store.mjs";
import {
  createPostgresPrincipalStore,
} from "../../lib/postgres-principal-store.mjs";
import {
  createPostgresTenantDataAdapter,
} from "../../lib/postgres-tenant-data-adapter.mjs";
import {
  createPostgresTenantStore,
} from "../../lib/postgres-tenant-store.mjs";
import {
  createPostgresToolGatewayStore,
} from "../../lib/postgres-tool-gateway-store.mjs";

const { Pool } = pg;
const pools = [];

function configuration(user, max = 12) {
  for (const name of [
    "G1_TEST_PGHOST",
    "G1_TEST_PGPORT",
    "G1_TEST_PGDATABASE",
    "G1_TEST_FILE_ROOT",
    "G1_RUNTIME_MODE",
    "G1_IDENTITY_INSTANCE_PREFIX",
  ]) {
    if (!process.env[name]) throw new Error(`${name} is required.`);
  }
  if (process.env.G1_TEST_EPHEMERAL !== "1") {
    throw new Error("G1_TEST_EPHEMERAL=1 is required.");
  }
  return {
    host: process.env.G1_TEST_PGHOST,
    port: Number(process.env.G1_TEST_PGPORT),
    database: process.env.G1_TEST_PGDATABASE,
    user,
    max,
  };
}

function pool(user, max) {
  const value = new Pool(configuration(user, max));
  pools.push(value);
  return value;
}

async function main() {
  const tenantPool = pool("g1_c03");
  const identityPool = pool("g1_c04");
  const principalPool = pool("g1_c05");
  const authorizationControlPool = pool("g1_c06_control");
  const authorizationDecisionPool = pool("g1_c06_decision");
  const authorizationOutboxPool = pool("g1_c06_outbox");
  const dataPool = pool("g1_c07_data");
  const scopePool = pool("g1_c07_scope", 40);
  const lifecyclePool = pool("g1_c07_lifecycle");
  const dataControlPool = pool("g1_c07_control");
  const c08RuntimePool = pool("g1_c08_runtime");
  const c08OutboxPool = pool("g1_c08_outbox");
  const c10RuntimePool = pool("g1_c10_runtime");
  const c10ReaderPool = pool("g1_c10_reader");
  const c11ProjectorPool = pool("g1_c11_projector");
  const c11QueryPool = pool("g1_c11_query");
  const c12RuntimePool = pool("g1_c12_runtime");
  const c14RuntimePool = pool("g1_c14_runtime");
  const c15RuntimePool = pool("g1_c15_runtime");
  const c15EffectPool = pool("g1_c15_effect");
  const c15AuditPool = pool("g1_c15_audit");
  const c15RecoveryPool = pool("g1_c15_recovery");
  const c16RuntimePool = pool("g1_c16_runtime");
  const c16ToolPool = pool("g1_c16_tool");
  const c16AuditPool = pool("g1_c16_audit");
  const c16RecoveryPool = pool("g1_c16_recovery");
  const c18WriterPool = pool("g1_c18_writer");
  const c18ReaderPool = pool("g1_c18_reader");
  const c18OutboxPool = pool("g1_c18_outbox");
  const c18RecoveryPool = pool("g1_c18_recovery");
  const c18RestorePool = pool("g1_c18_restore");
  const c18RetentionPool = pool("g1_c18_retention");
  const c19WriterPool = pool("g1_c19_writer");
  const c19ReaderPool = pool("g1_c19_reader");

  const fileRoot = process.env.G1_TEST_FILE_ROOT;
  const modelProvider = createC14SyntheticModelProvider({
    receiptStore: createFileC14ModelReceiptStore({
      rootDir: join(fileRoot, "c14"),
    }),
  });
  const tenantDataAdapter = createPostgresTenantDataAdapter({
    runtimePool: dataPool,
    scopePool,
    lifecyclePool,
    controlPool: dataControlPool,
  });
  const storage = {
    tenantStore: createPostgresTenantStore({ pool: tenantPool }),
    tenantDataAdapter,
    identityStore: createPostgresIdentityStore({
      pool: identityPool,
    }),
    principalStore: createPostgresPrincipalStore({
      pool: principalPool,
    }),
    authorizationStore: createPostgresAuthorizationStore({
      pool: authorizationControlPool,
      decisionPool: authorizationDecisionPool,
      outboxPool: authorizationOutboxPool,
    }),
    knowledgeCatalogStore: createPostgresKnowledgeCatalogStore({
      runtimePool: c10RuntimePool,
      readerPool: c10ReaderPool,
      scopePool,
    }),
    knowledgeQuarantineStore: createFileC10QuarantineStore({
      rootDir: join(fileRoot, "c10"),
    }),
    ragStore: createPostgresPermissionAwareRagStore({
      projectorPool: c11ProjectorPool,
      queryPool: c11QueryPool,
      scopePool,
    }),
    modelDraftStore: createPostgresModelGatewayStore({
      runtimePool: c14RuntimePool,
      scopePool,
    }),
    modelReviewStore: createPostgresModelGatewayStore({
      runtimePool: c14RuntimePool,
      scopePool,
    }),
    modelProvider,
    toolStore: createPostgresToolGatewayStore({
      runtimePool: c16RuntimePool,
      toolWorkerPool: c16ToolPool,
      auditWorkerPool: c16AuditPool,
      recoveryPool: c16RecoveryPool,
      scopePool,
    }),
    decisionStore: createPostgresHumanDecisionStore({
      runtimePool: c15RuntimePool,
      effectWorkerPool: c15EffectPool,
      auditWorkerPool: c15AuditPool,
      recoveryPool: c15RecoveryPool,
      scopePool,
    }),
    c12StatePortFactory(tenantRegistry) {
      return createPostgresAgentOrchestratorStatePort({
        runtimePool: c12RuntimePool,
        scopePool,
        tenantRegistry,
      });
    },
    c08StateStore: createPostgresAiosStateStore({
      runtimePool: c08RuntimePool,
      scopePool,
      outboxPool: c08OutboxPool,
    }),
    c08Receipts: createC08C0MockToolReceipts({
      store: createFileC08MockReceiptStore({
        rootDir: join(fileRoot, "c08"),
      }),
    }),
    auditStore: createPostgresAuditEvidenceStore({
      writerPool: c18WriterPool,
      readerPool: c18ReaderPool,
      outboxPool: c18OutboxPool,
      recoveryPool: c18RecoveryPool,
      restorePool: c18RestorePool,
      retentionPool: c18RetentionPool,
      scopePool,
    }),
    observabilityStore: createPostgresObservabilityStore({
      writerPool: c19WriterPool,
      readerPool: c19ReaderPool,
      scopePool,
    }),
  };
  const runtime = await createG1SyntheticRuntime({
    storage,
    identityInstancePrefix:
      process.env.G1_IDENTITY_INSTANCE_PREFIX,
  });
  const deployment = await runtime.deploy();
  const results = [];
  for (const tenant of deployment.tenants) {
    results.push(await runtime.runTenant(tenant.tenantId));
  }
  process.stdout.write(
    JSON.stringify({
      mode: process.env.G1_RUNTIME_MODE,
      deployment,
      results,
      modelProviderNewExecutionCount: modelProvider.calls.length,
    }),
  );
}

try {
  await main();
} finally {
  await Promise.allSettled(pools.map((value) => value.end()));
}
