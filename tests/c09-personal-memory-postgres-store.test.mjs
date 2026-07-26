import assert from "node:assert/strict";
import test from "node:test";
import {
  createPostgresPersonalMemoryStore,
} from "../lib/c09-personal-memory-postgres-store.mjs";
import {
  PersonalMemoryError,
} from "../lib/c09-personal-memory.mjs";

const TENANT_ID = "stn_01984910-4000-7000-8000-000000000001";
const PRINCIPAL_ID = "prn_01984910-4000-7000-8000-000000000011";
const ROLE_COUNT = 3;

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

test("C09 wraps unknown PostgreSQL failures without exposing driver errors", async () => {
  const driverError = new Error("raw driver detail");
  const store = createPostgresPersonalMemoryStore({
    runtimePool: {
      async connect() {
        throw driverError;
      },
    },
    tenantScopePool: { connect: async () => null },
    principalScopePool: { connect: async () => null },
  });

  await assert.rejects(
    store.readProfile(
      {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: TENANT_ID,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 1,
        correlationId: "c09-driver-failure",
        decisionId: "decision-c09-driver-failure",
        evidenceRef: "evidence://c09/driver-failure",
        policyVersion: "c09-policy-v1",
        principalLifecycleVersion: 1,
        principalSecurityEpoch: 1,
      },
      { tenantId: TENANT_ID, principalId: PRINCIPAL_ID },
    ),
    (error) => {
      assert.ok(error instanceof PersonalMemoryError);
      assert.equal(error.code, "STORE_UNAVAILABLE");
      assert.equal(error.message, "C09 PostgreSQL operation failed.");
      assert.equal(error.cause, driverError);
      assert.equal(
        Object.prototype.propertyIsEnumerable.call(error, "cause"),
        false,
      );
      return true;
    },
  );
});

test("C09 discards a PostgreSQL connection when rollback fails", async () => {
  let releaseError;
  const runtimeClient = {
    async query(sql) {
      if (sql.includes("WITH identity AS")) {
        return { rows: [roleIdentity(0)] };
      }
      if (sql === "BEGIN ISOLATION LEVEL REPEATABLE READ") return { rows: [] };
      if (sql.includes("pg_backend_pid()")) {
        return { rows: [{ backend_pid: 101, transaction_id: "202" }] };
      }
      if (sql.includes("set_config(")) return { rows: [] };
      if (sql.includes("acquire_runtime_fence")) {
        return { rows: [{ acquired: true }] };
      }
      if (sql === "ROLLBACK") {
        const error = new Error("rollback failed");
        error.code = "08006";
        throw error;
      }
      const error = new Error("profile read failed");
      error.code = "23514";
      throw error;
    },
    release(error) {
      releaseError = error;
    },
  };
  function signerClient(expectedIndex) {
    return {
      async query(sql) {
        if (sql.includes("WITH identity AS")) {
          return { rows: [roleIdentity(expectedIndex)] };
        }
        if (sql.includes("issue_")) {
          return {
            rows: [{
              signed_scope: {
                expires_epoch_ms: 1,
                signature: "a".repeat(64),
              },
            }],
          };
        }
        throw new Error("unexpected signer query");
      },
      release() {},
    };
  }
  const store = createPostgresPersonalMemoryStore({
    runtimePool: pool(runtimeClient),
    tenantScopePool: pool(signerClient(1)),
    principalScopePool: pool(signerClient(2)),
  });

  await assert.rejects(
    store.readProfile(
      {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: TENANT_ID,
        tenantKind: "SYNTHETIC",
        lifecycleVersion: 1,
        correlationId: "c09-rollback-failure",
        decisionId: "decision-c09-rollback-failure",
        evidenceRef: "evidence://c09/rollback-failure",
        policyVersion: "c09-policy-v1",
        principalLifecycleVersion: 1,
        principalSecurityEpoch: 1,
      },
      { tenantId: TENANT_ID, principalId: PRINCIPAL_ID },
    ),
    (error) => error?.code === "INTEGRITY_VIOLATION",
  );
  assert.ok(releaseError instanceof Error);
});
