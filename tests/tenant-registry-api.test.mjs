import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contractUrl = new URL(
  "../implementation/p1/c03/tenant-registry.openapi.v1.json",
  import.meta.url,
);

test("the C03 API exposes only execute, snapshot and admission surfaces", async () => {
  const contract = JSON.parse(await readFile(contractUrl, "utf8"));

  assert.equal(contract.openapi, "3.1.2");
  assert.deepEqual(contract["x-c03-boundary"], {
    phase: "P1",
    tenant_kind: "SYNTHETIC",
    enterprise_onboarding: "P3_REQUIRED",
    connectors: "C0",
    active_is_not_authorization: true,
  });
  assert.equal(
    contract["x-config-ref-membership"],
    "F02_FROZEN_FIXTURE_CATALOG",
  );
  assert.deepEqual(Object.keys(contract.paths).sort(), [
    "/internal/v1/tenant-registry/commands",
    "/internal/v1/tenant-registry/tenants/{tenantId}",
    "/internal/v1/tenant-registry/tenants/{tenantId}:admit",
  ]);
  assert.equal(
    contract.paths["/internal/v1/tenant-registry/commands"].post.operationId,
    "executeTenantLifecycleCommand",
  );
  assert.deepEqual(
    contract.paths["/internal/v1/tenant-registry/commands"].post[
      "x-command-capabilities"
    ],
    {
      CREATE_SYNTHETIC_TENANT: "tenant:lifecycle:manage",
      SUSPEND_TENANT: "tenant:lifecycle:manage",
      RESUME_TENANT: "tenant:lifecycle:manage",
      REQUEST_TENANT_DELETION: "tenant:lifecycle:manage",
      RECORD_PROJECTION_RESULT: "tenant:projection:report",
      RECONCILE_TENANT: "tenant:reconcile",
    },
  );
  assert.equal(
    contract.paths["/internal/v1/tenant-registry/tenants/{tenantId}"].get
      .operationId,
    "getTenantLifecycleSnapshot",
  );
  assert.equal(
    contract.paths[
      "/internal/v1/tenant-registry/tenants/{tenantId}:admit"
    ].post.operationId,
    "admitNewTenantRequest",
  );
});

test("the P1 command contract has no Enterprise create or kind mutation command", async () => {
  const contract = JSON.parse(await readFile(contractUrl, "utf8"));
  const serialized = JSON.stringify(contract.components.schemas.TenantCommand);
  const lifecycleKinds =
    contract.components.schemas.VersionedLifecycleCommand.properties.kind.enum;

  assert.doesNotMatch(serialized, /CREATE_ENTERPRISE_TENANT/);
  assert.doesNotMatch(serialized, /UPDATE_TENANT|SET_KIND|IMPORT_TENANT/);
  assert.deepEqual(lifecycleKinds, [
    "SUSPEND_TENANT",
    "RESUME_TENANT",
    "REQUEST_TENANT_DELETION",
  ]);
  assert.equal(
    contract.components.schemas.AdmittedTenantContext.properties.trustSource
      .const,
    "VERIFIED_SERVER_CONTEXT",
  );
  assert.equal(
    contract.components.schemas.CreateSyntheticTenant.allOf[1].properties
      .configRefs.maxItems,
    32,
  );
});
