import assert from "node:assert/strict";
import test from "node:test";
import {
  createPostgresKnowledgeCatalogStore,
} from "../lib/postgres-knowledge-catalog-store.mjs";

const TENANT_ID = "stn_01984910-6000-7000-8000-000000000001";
const ROLE_COUNT = 8;

function roleIdentity(expectedIndex) {
  const row = {
    current_name: "test_role",
    session_name: "test_role",
    current_super: false,
    current_bypassrls: false,
    session_super: false,
    session_bypassrls: false,
  };
  for (let index = 0; index < ROLE_COUNT; index += 1) {
    row[`current_role_${index}`] = index === expectedIndex;
    row[`session_role_${index}`] = index === expectedIndex;
  }
  return row;
}

function pool(client) {
  return {
    async connect() {
      return client;
    },
  };
}

test("C10 discards a PostgreSQL connection when rollback fails", async () => {
  let releaseError;
  const readerClient = {
    async query(sql) {
      if (sql.includes("WITH identity AS")) {
        return { rows: [roleIdentity(1)] };
      }
      if (sql === "BEGIN READ ONLY") return { rows: [] };
      if (sql.includes("pg_backend_pid()")) {
        return { rows: [{ backend_pid: 101, transaction_id: "202" }] };
      }
      if (sql.includes("set_config(")) return { rows: [] };
      if (sql === "ROLLBACK") {
        const error = new Error("rollback failed");
        error.code = "08006";
        throw error;
      }
      const error = new Error("document read failed");
      error.code = "23514";
      throw error;
    },
    release(error) {
      releaseError = error;
    },
  };
  const scopeClient = {
    async query(sql) {
      if (sql.includes("WITH identity AS")) {
        return { rows: [roleIdentity(3)] };
      }
      if (sql.includes("issue_runtime_scope_signature")) {
        return {
          rows: [{
            signed_scope: {
              expires_epoch_ms: 1,
              signature: "a".repeat(64),
            },
          }],
        };
      }
      throw new Error("unexpected scope query");
    },
    release() {},
  };
  const store = createPostgresKnowledgeCatalogStore({
    runtimePool: { connect: async () => null },
    readerPool: pool(readerClient),
    scopePool: pool(scopeClient),
  });

  await assert.rejects(
    store.readCurrent(
      {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: TENANT_ID,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 1,
        correlationId: "c10-rollback-failure",
        decisionId: "decision-c10-rollback-failure",
        evidenceRef: "evidence://c10/rollback-failure",
        policyVersion: "c10-policy-v1",
      },
      { documentId: "knw_document", documentVersion: 1 },
    ),
    (error) => error?.code === "INTEGRITY_VIOLATION",
  );
  assert.ok(releaseError instanceof Error);
});
