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
const MEMORY_ID = "mem_01984910-4000-7000-8000-000000000021";
const ROLE_COUNT = 3;
const NOW = "2026-07-26T10:00:00.000Z";
const SHA256 =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

function scope() {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    lifecycleVersion: 1,
    correlationId: "c09-postgres-store-test",
    decisionId: "decision-c09-postgres-store-test",
    evidenceRef: "evidence://c09/postgres-store-test",
    policyVersion: "c09-policy-v1",
    principalLifecycleVersion: 1,
    principalSecurityEpoch: 1,
  };
}

function envelope(humanConsentEvidence) {
  return {
    operation: "CONFIRM_CANDIDATE",
    tenantId: TENANT_ID,
    tenantKind: "SYNTHETIC",
    principalId: PRINCIPAL_ID,
    actorPrincipalId:
      "prn_01984910-4000-7000-8000-000000000012",
    memoryId: MEMORY_ID,
    expectedVersion: 1,
    eventId: "mev_01984910-4000-7000-8000-000000000031",
    idempotencyKey: "c09-postgres-store-test",
    correlationId: "c09-postgres-store-test",
    requestHash: SHA256,
    authorizationEvidence: {},
    humanConsentEvidence,
    now: NOW,
  };
}

function uniqueViolationStore(constraint) {
  const runtimeClient = {
    async query(sql) {
      if (sql.includes("WITH identity AS")) {
        return { rows: [roleIdentity(0)] };
      }
      if (sql === "BEGIN ISOLATION LEVEL SERIALIZABLE") {
        return { rows: [] };
      }
      if (sql.includes("pg_backend_pid()")) {
        return { rows: [{ backend_pid: 101, transaction_id: "202" }] };
      }
      if (sql.includes("set_config(")) return { rows: [] };
      if (sql.includes("acquire_runtime_fence")) {
        return { rows: [{ acquired: true }] };
      }
      if (sql.includes("pg_advisory_xact_lock")) {
        const error = new Error("unique violation");
        error.code = "23505";
        error.constraint = constraint;
        throw error;
      }
      if (sql === "ROLLBACK") return { rows: [] };
      if (sql.includes("current_setting(")) {
        return {
          rows: [{
            tenant_id: null,
            principal_id: null,
            principal_lifecycle_version: null,
            principal_security_epoch: null,
            tenant_signature: null,
            principal_signature: null,
          }],
        };
      }
      throw new Error("unexpected runtime query");
    },
    release() {},
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
  return createPostgresPersonalMemoryStore({
    runtimePool: pool(runtimeClient),
    tenantScopePool: pool(signerClient(1)),
    principalScopePool: pool(signerClient(2)),
  });
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

test("C09 PostgreSQL store rejects consent evidence with secret fields before connecting", async (t) => {
  for (const unsupportedField of [
    "token",
    "humanConsentToken",
    "content",
    "secret",
  ]) {
    await t.test(unsupportedField, async () => {
      let connections = 0;
      const rejectingPool = {
        async connect() {
          connections += 1;
          throw new Error("must not connect");
        },
      };
      const store = createPostgresPersonalMemoryStore({
        runtimePool: rejectingPool,
        tenantScopePool: { connect: async () => null },
        principalScopePool: { connect: async () => null },
      });
      await assert.rejects(
        store.apply(
          scope(),
          envelope({
            tenantId: TENANT_ID,
            humanPrincipalId: PRINCIPAL_ID,
            memoryId: MEMORY_ID,
            expectedVersion: 1,
            contentSha256: SHA256,
            expiresAt: "2026-07-26T11:00:00.000Z",
            purpose: "CONFIRM_PERSONAL_MEMORY",
            tokenSha256: SHA256,
            consumedAt: NOW,
            [unsupportedField]: "must-not-persist",
          }),
        ),
        (error) =>
          error instanceof PersonalMemoryError &&
          error.code === "INVALID_INPUT",
      );
      assert.equal(connections, 0);
    });
  }
});

test("C09 maps PostgreSQL unique constraints to stable domain errors", async (t) => {
  const cases = [
    ["command_receipt_pkey", "IDEMPOTENCY_CONFLICT"],
    ["personal_memory_pkey", "ID_COLLISION"],
    ["memory_event_pkey", "ID_COLLISION"],
    ["conversation_checkpoint_pkey", "ID_COLLISION"],
    ["unexpected_unique_key", "INTEGRITY_VIOLATION"],
  ];
  for (const [constraint, expectedCode] of cases) {
    await t.test(constraint, async () => {
      const store = uniqueViolationStore(constraint);
      await assert.rejects(
        store.apply(scope(), envelope(null)),
        (error) =>
          error instanceof PersonalMemoryError &&
          error.code === expectedCode,
      );
    });
  }
});
