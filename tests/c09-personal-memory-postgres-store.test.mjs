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
