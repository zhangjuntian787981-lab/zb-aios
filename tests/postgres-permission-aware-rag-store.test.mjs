import assert from "node:assert/strict";
import test from "node:test";
import {
  createPostgresPermissionAwareRagStore,
} from "../lib/postgres-permission-aware-rag-store.mjs";

const TENANT_ID = "stn_01984910-7000-7000-8000-000000000001";
const ROLE_COUNT = 11;

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

test("C11 discards a PostgreSQL connection when rollback fails", async () => {
  let releaseError;
  const queryClient = {
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
      const error = new Error("search failed");
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
        return { rows: [roleIdentity(6)] };
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
  const store = createPostgresPermissionAwareRagStore({
    projectorPool: { connect: async () => null },
    queryPool: { connect: async () => queryClient },
    scopePool: { connect: async () => scopeClient },
  });

  await assert.rejects(
    store.search(
      {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: TENANT_ID,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 1,
        correlationId: "c11-rollback-failure",
        decisionId: "decision-c11-rollback-failure",
        evidenceRef: "evidence://c11/rollback-failure",
        policyVersion: "c11-policy-v1",
      },
      {
        asOf: "2026-07-26T00:00:00.000Z",
        principalRefs: ["human:test"],
        principalScopeHash:
          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      {
        query: "synthetic",
        embedding: Array(8).fill(0),
        limit: 1,
      },
    ),
    (error) => error?.code === "INTEGRITY_VIOLATION",
  );
  assert.ok(releaseError instanceof Error);
});
