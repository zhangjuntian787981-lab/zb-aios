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
const OTHER_PRINCIPAL_ID =
  "prn_01984910-4000-7000-8000-000000000012";
const MEMORY_ID = "mem_01984910-4000-7000-8000-000000000021";
const ROLE_NAMES = [
  "aios_c09_runtime",
  "aios_c07_scope_runtime",
  "aios_c09_scope_runtime",
  "aios_c09_retention_runtime",
];
const NOW = "2026-07-26T10:00:00.000Z";
const SHA256 =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SCOPE_GUCS = [
  "tenant_id",
  "tenant_kind",
  "lifecycle_version",
  "correlation_id",
  "decision_id",
  "evidence_ref",
  "policy_version",
  "backend_pid",
  "transaction_id",
  "expires_epoch_ms",
  "scope_nonce",
  "scope_signature",
  "principal_id",
  "principal_lifecycle_version",
  "principal_security_epoch",
  "principal_expires_epoch_ms",
  "principal_scope_nonce",
  "principal_scope_signature",
];

function roleIdentity(expectedIndex) {
  const role = ROLE_NAMES[expectedIndex];
  const row = {
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
    current_memberships: [role],
    session_memberships: [role],
    current_usages: [role],
    session_usages: [role],
  };
  return row;
}

function privilegeCheck() {
  return { rows: [{ privileges_safe: true }] };
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
    principalId: PRINCIPAL_ID,
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
      if (sql.includes("jsonb_to_recordset")) return privilegeCheck();
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
        if (sql.includes("jsonb_to_recordset")) return privilegeCheck();
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
        principalId: PRINCIPAL_ID,
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
      if (sql.includes("jsonb_to_recordset")) return privilegeCheck();
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
        if (sql.includes("jsonb_to_recordset")) return privilegeCheck();
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
        principalId: PRINCIPAL_ID,
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

test("C09 PostgreSQL Store rejects same-Tenant Principal replacement before connecting", async () => {
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
    store.readProfile(scope(), {
      tenantId: TENANT_ID,
      principalId: OTHER_PRINCIPAL_ID,
    }),
    (error) =>
      error instanceof PersonalMemoryError &&
      error.code === "IDENTITY_BINDING_INVALID",
  );
  assert.equal(connections, 0);
});

test("C09 checks all 18 identity GUCs before returning a connection", async () => {
  let scopeCheckSql = "";
  const runtimeClient = {
    async query(sql) {
      if (sql.includes("WITH identity AS")) {
        return { rows: [roleIdentity(0)] };
      }
      if (sql.includes("jsonb_to_recordset")) return privilegeCheck();
      if (sql === "BEGIN ISOLATION LEVEL REPEATABLE READ") {
        return { rows: [] };
      }
      if (sql.includes("pg_backend_pid()")) {
        return { rows: [{ backend_pid: 101, transaction_id: "202" }] };
      }
      if (sql.includes("set_config(")) return { rows: [] };
      if (sql.includes("acquire_runtime_fence")) {
        return { rows: [{ acquired: true }] };
      }
      if (sql.includes('FROM "aios_personal_memory"."personal_profile"')) {
        return { rows: [] };
      }
      if (sql === "COMMIT") return { rows: [] };
      if (sql.includes("current_setting(")) {
        scopeCheckSql = sql;
        return { rows: [{}] };
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
        if (sql.includes("jsonb_to_recordset")) return privilegeCheck();
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
  await store.readProfile(scope(), {
    tenantId: TENANT_ID,
    principalId: PRINCIPAL_ID,
  });
  for (const guc of SCOPE_GUCS) {
    assert.match(
      scopeCheckSql,
      new RegExp(`current_setting\\('aios\\.${guc}', true\\)`),
    );
  }
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
