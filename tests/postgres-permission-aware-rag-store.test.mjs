import assert from "node:assert/strict";
import test from "node:test";
import {
  createPostgresPermissionAwareRagStore,
} from "../lib/postgres-permission-aware-rag-store.mjs";

const TENANT_ID = "stn_01984910-7000-7000-8000-000000000001";

function roleIdentity(requiredRole) {
  return {
    current_name: "test_role",
    session_name: "test_role",
    current_super: false,
    current_bypassrls: false,
    current_createdb: false,
    current_createrole: false,
    current_replication: false,
    session_super: false,
    session_bypassrls: false,
    session_createdb: false,
    session_createrole: false,
    session_replication: false,
    current_memberships: [requiredRole],
    session_memberships: [requiredRole],
    current_usages: [requiredRole],
    session_usages: [requiredRole],
  };
}

test("C11 discards a PostgreSQL connection when rollback fails", async () => {
  let releaseError;
  const queryClient = {
    async query(sql) {
      if (sql.includes("WITH identity AS")) {
        return { rows: [roleIdentity("aios_c11_query")] };
      }
      if (sql.includes("protected_schemas AS")) {
        return { rows: [{ privileges_safe: true }] };
      }
      if (sql.includes("READ ONLY")) return { rows: [] };
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
        return {
          rows: [roleIdentity("aios_c07_scope_runtime")],
        };
      }
      if (sql.includes("protected_schemas AS")) {
        return { rows: [{ privileges_safe: true }] };
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

test("C11 discards the scope signer after a connection failure", async () => {
  let signerReleaseError;
  const queryClient = {
    async query(sql) {
      if (sql.includes("WITH identity AS")) {
        return { rows: [roleIdentity("aios_c11_query")] };
      }
      if (sql.includes("protected_schemas AS")) {
        return { rows: [{ privileges_safe: true }] };
      }
      if (sql.includes("READ ONLY") || sql === "ROLLBACK") {
        return { rows: [] };
      }
      if (sql.includes("pg_backend_pid()")) {
        return { rows: [{ backend_pid: 101, transaction_id: "202" }] };
      }
      throw new Error("unexpected query");
    },
    release() {},
  };
  const scopeClient = {
    async query(sql) {
      if (sql.includes("WITH identity AS")) {
        return {
          rows: [roleIdentity("aios_c07_scope_runtime")],
        };
      }
      if (sql.includes("protected_schemas AS")) {
        return { rows: [{ privileges_safe: true }] };
      }
      const error = new Error("scope connection failed");
      error.code = "08006";
      throw error;
    },
    release(error) {
      signerReleaseError = error;
    },
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
        correlationId: "c11-signer-connection-failure",
        decisionId: "decision-c11-signer-connection-failure",
        evidenceRef: "evidence://c11/signer-connection-failure",
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
    (error) => error?.code === "STORE_UNAVAILABLE",
  );
  assert.ok(signerReleaseError instanceof Error);
});
