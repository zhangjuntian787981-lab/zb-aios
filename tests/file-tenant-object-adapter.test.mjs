import assert from "node:assert/strict";
import { lstat, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createFileTenantObjectAdapter } from "../lib/file-tenant-object-adapter.mjs";

const TENANT_A = "stn_01984910-0000-7000-8000-000000000011";
const TENANT_B = "stn_01984910-0000-7000-8000-000000000012";

function lifecycleEvent({
  tenantId,
  id,
  type,
  version,
  generation = 1,
  state,
}) {
  return {
    specversion: "1.0",
    id,
    source: "/aios-core/tenant-registry",
    type,
    subject: tenantId,
    time: "2026-07-26T09:30:00.000Z",
    datacontenttype: "application/json",
    tenantkind: "SYNTHETIC",
    correlationid: `correlation-${id}`,
    synthetic: true,
    data: {
      tenant_id: tenantId,
      lifecycle_version: version,
      generation,
      operation_id: `operation-${id}`,
      state,
      actor_id: "synthetic-object-worker",
    },
  };
}

function scope(tenantId, lifecycleVersion = 2) {
  return {
    trustSource: "C07_VERIFIED_TENANT_SCOPE",
    tenantId,
    tenantKind: "SYNTHETIC",
    lifecycleVersion,
  };
}

async function activate(adapter, tenantId, suffix) {
  await adapter.project(
    lifecycleEvent({
      tenantId,
      id: `evt-${suffix}-provision`,
      type: "product.tenant.provisioning-requested.v1",
      version: 1,
      state: "PROVISIONING",
    }),
  );
  await adapter.project(
    lifecycleEvent({
      tenantId,
      id: `evt-${suffix}-active`,
      type: "product.tenant.activated.v1",
      version: 2,
      state: "ACTIVE",
    }),
  );
}

async function fixture(t) {
  const rootDir = await mkdtemp(join(tmpdir(), "c07-object-"));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  return createFileTenantObjectAdapter({ rootDir });
}

test("file object Adapter keeps put, get and list inside one Tenant", async (t) => {
  const adapter = await fixture(t);
  await activate(adapter, TENANT_A, "a");
  await activate(adapter, TENANT_B, "b");

  await adapter.execute(scope(TENANT_A), {
    kind: "OBJECT_PUT",
    resourceId: "object_a",
    input: {
      objectKey: "reports/a.txt",
      body: "synthetic tenant A",
      contentType: "text/plain",
    },
  });
  const own = await adapter.execute(scope(TENANT_A), {
    kind: "OBJECT_GET",
    resourceId: "object_a",
    input: { objectKey: "reports/a.txt" },
  });
  const foreign = await adapter.execute(scope(TENANT_B), {
    kind: "OBJECT_GET",
    resourceId: "object_a",
    input: { objectKey: "reports/a.txt" },
  });
  const list = await adapter.execute(scope(TENANT_A), {
    kind: "OBJECT_LIST",
    resourceId: "object_collection",
    input: { cursor: null, limit: 10 },
  });

  assert.equal(own.body, "synthetic tenant A");
  assert.equal(own.tenantId, TENANT_A);
  assert.equal(foreign, null);
  assert.equal(list.items.length, 1);
  assert.equal(Object.hasOwn(list.items[0], "body"), false);
});

test("file object Adapter rejects traversal and unverified scopes", async (t) => {
  const adapter = await fixture(t);
  await activate(adapter, TENANT_A, "a");

  await assert.rejects(
    adapter.execute(scope(TENANT_A), {
      kind: "OBJECT_GET",
      resourceId: "object_a",
      input: { objectKey: "../foreign/secret.txt" },
    }),
    { code: "INVALID_INPUT" },
  );
  await assert.rejects(
    adapter.execute(
      { ...scope(TENANT_A), trustSource: "CLIENT_SCOPE" },
      {
        kind: "OBJECT_GET",
        resourceId: "object_a",
        input: { objectKey: "reports/a.txt" },
      },
    ),
    { code: "TENANT_SCOPE_VIOLATION" },
  );
});

test("file object Adapter binds an object key to its authorized resource", async (t) => {
  const adapter = await fixture(t);
  await activate(adapter, TENANT_A, "a");
  await adapter.execute(scope(TENANT_A), {
    kind: "OBJECT_PUT",
    resourceId: "object_a",
    input: {
      objectKey: "reports/a.txt",
      body: "synthetic tenant A",
      contentType: "text/plain",
    },
  });

  for (const operation of [
    {
      kind: "OBJECT_GET",
      resourceId: "object_b",
      input: { objectKey: "reports/a.txt" },
    },
    {
      kind: "OBJECT_PUT",
      resourceId: "object_b",
      input: {
        objectKey: "reports/a.txt",
        body: "unauthorized replacement",
        contentType: "text/plain",
      },
    },
  ]) {
    await assert.rejects(
      adapter.execute(scope(TENANT_A), operation),
      { code: "TENANT_SCOPE_VIOLATION" },
    );
  }
});

test("file object Adapter blocks suspended state and purges deletion", async (t) => {
  const adapter = await fixture(t);
  await activate(adapter, TENANT_A, "a");
  await adapter.execute(scope(TENANT_A), {
    kind: "OBJECT_PUT",
    resourceId: "object_a",
    input: {
      objectKey: "reports/a.txt",
      body: "synthetic tenant A",
      contentType: "text/plain",
    },
  });

  await adapter.project(
    lifecycleEvent({
      tenantId: TENANT_A,
      id: "evt-a-suspend",
      type: "product.tenant.suspended.v1",
      version: 3,
      state: "SUSPENDED",
    }),
  );
  await assert.rejects(
    adapter.execute(scope(TENANT_A, 3), {
      kind: "OBJECT_GET",
      resourceId: "object_a",
      input: { objectKey: "reports/a.txt" },
    }),
    { code: "TENANT_NOT_ACTIVE" },
  );

  await adapter.project(
    lifecycleEvent({
      tenantId: TENANT_A,
      id: "evt-a-delete",
      type: "product.tenant.deletion-requested.v1",
      version: 4,
      generation: 2,
      state: "DELETING",
    }),
  );
  const snapshot = await adapter.snapshot({ tenantId: TENANT_A });
  assert.equal(snapshot.state, "DELETING");
  assert.equal(snapshot.objectCount, 0);
});

test("file object Adapter freezes exact event replay and rejects gaps", async (t) => {
  const adapter = await fixture(t);
  const provision = lifecycleEvent({
    tenantId: TENANT_A,
    id: "evt-a-provision",
    type: "product.tenant.provisioning-requested.v1",
    version: 1,
    state: "PROVISIONING",
  });
  const first = await adapter.project(provision);
  const duplicate = await adapter.project(provision);
  assert.equal(first.duplicate, false);
  assert.equal(duplicate.duplicate, true);

  await assert.rejects(
    adapter.project(
      lifecycleEvent({
        tenantId: TENANT_A,
        id: "evt-a-gap",
        type: "product.tenant.suspended.v1",
        version: 3,
        state: "SUSPENDED",
      }),
    ),
    { code: "STALE_LIFECYCLE_EVENT" },
  );
});

test("file object Adapter serializes writes with deletion purge", async (t) => {
  const adapter = await fixture(t);
  await activate(adapter, TENANT_A, "a");

  const write = adapter.execute(scope(TENANT_A), {
    kind: "OBJECT_PUT",
    resourceId: "object_race",
    input: {
      objectKey: "reports/race.txt",
      body: "must be purged",
      contentType: "text/plain",
    },
  });
  const deletion = adapter.project(
    lifecycleEvent({
      tenantId: TENANT_A,
      id: "evt-a-race-delete",
      type: "product.tenant.deletion-requested.v1",
      version: 3,
      generation: 2,
      state: "DELETING",
    }),
  );
  await Promise.all([write, deletion]);

  const snapshot = await adapter.snapshot({ tenantId: TENANT_A });
  assert.deepEqual(
    { state: snapshot.state, objectCount: snapshot.objectCount },
    { state: "DELETING", objectCount: 0 },
  );
});

test("file object Adapters share a Tenant deletion lock across instances", async (t) => {
  const rootDir = await mkdtemp(join(tmpdir(), "c07-object-shared-lock-"));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  const writer = createFileTenantObjectAdapter({ rootDir });
  const projector = createFileTenantObjectAdapter({ rootDir });
  await activate(writer, TENANT_A, "shared-lock");

  const write = writer.execute(scope(TENANT_A), {
    kind: "OBJECT_PUT",
    resourceId: "object_shared_race",
    input: {
      objectKey: "reports/shared-race.txt",
      body: "x".repeat(1_048_576),
      contentType: "text/plain",
    },
  });
  const deletion = projector.project(
    lifecycleEvent({
      tenantId: TENANT_A,
      id: "evt-a-shared-race-delete",
      type: "product.tenant.deletion-requested.v1",
      version: 3,
      generation: 2,
      state: "DELETING",
    }),
  );
  await Promise.all([write, deletion]);

  const snapshot = await writer.snapshot({ tenantId: TENANT_A });
  assert.deepEqual(
    { state: snapshot.state, objectCount: snapshot.objectCount },
    { state: "DELETING", objectCount: 0 },
  );
});

test("file object Adapter read-only mode reads without writing", async (t) => {
  const rootDir = await mkdtemp(join(tmpdir(), "c07-object-read-only-"));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  const writable = createFileTenantObjectAdapter({ rootDir });
  await activate(writable, TENANT_A, "read-only");
  await writable.execute(scope(TENANT_A), {
    kind: "OBJECT_PUT",
    resourceId: "object_read_only",
    input: {
      objectKey: "reports/read-only.txt",
      body: "restored object",
      contentType: "text/plain",
    },
  });
  const adapter = createFileTenantObjectAdapter({
    rootDir,
    readOnly: true,
  });

  const object = await adapter.execute(scope(TENANT_A), {
    kind: "OBJECT_GET",
    resourceId: "object_read_only",
    input: { objectKey: "reports/read-only.txt" },
  });
  const list = await adapter.execute(scope(TENANT_A), {
    kind: "OBJECT_LIST",
    resourceId: "object_collection",
    input: { cursor: null, limit: 10 },
  });
  const snapshot = await adapter.snapshot({ tenantId: TENANT_A });

  assert.equal(object.body, "restored object");
  assert.deepEqual(
    list.items.map(({ resourceId }) => resourceId),
    ["object_read_only"],
  );
  assert.deepEqual(
    { state: snapshot.state, objectCount: snapshot.objectCount },
    { state: "ACTIVE", objectCount: 1 },
  );
  await assert.rejects(
    adapter.execute(scope(TENANT_A), {
      kind: "OBJECT_PUT",
      resourceId: "object_read_only",
      input: {
        objectKey: "reports/read-only.txt",
        body: "forbidden replacement",
        contentType: "text/plain",
      },
    }),
    { code: "STORE_UNAVAILABLE" },
  );
  await assert.rejects(
    adapter.project(
      lifecycleEvent({
        tenantId: TENANT_A,
        id: "evt-read-only-suspend",
        type: "product.tenant.suspended.v1",
        version: 3,
        state: "SUSPENDED",
      }),
    ),
    { code: "STORE_UNAVAILABLE" },
  );
  assert.equal(
    (
      await adapter.execute(scope(TENANT_A), {
        kind: "OBJECT_GET",
        resourceId: "object_read_only",
        input: { objectKey: "reports/read-only.txt" },
      })
    ).body,
    "restored object",
  );
});

test("file object Adapter read-only initialization creates no directory", async (t) => {
  const parent = await mkdtemp(join(tmpdir(), "c07-object-read-only-parent-"));
  const rootDir = join(parent, "missing");
  t.after(() => rm(parent, { recursive: true, force: true }));
  const adapter = createFileTenantObjectAdapter({
    rootDir,
    readOnly: true,
  });

  assert.deepEqual(
    await adapter.snapshot({ tenantId: TENANT_A }),
    {
      state: "NOT_PROVISIONED",
      lifecycleVersion: 0,
      objectCount: 0,
    },
  );
  await assert.rejects(lstat(rootDir), { code: "ENOENT" });
});

test("file object Adapter rejects a symlink Tenant directory", async (t) => {
  const rootDir = await mkdtemp(join(tmpdir(), "c07-object-root-"));
  const outside = await mkdtemp(join(tmpdir(), "c07-object-outside-"));
  t.after(() => Promise.all([
    rm(rootDir, { recursive: true, force: true }),
    rm(outside, { recursive: true, force: true }),
  ]));
  await symlink(outside, join(rootDir, TENANT_A), "dir");
  const adapter = createFileTenantObjectAdapter({ rootDir });

  await assert.rejects(
    adapter.project(
      lifecycleEvent({
        tenantId: TENANT_A,
        id: "evt-a-symlink",
        type: "product.tenant.provisioning-requested.v1",
        version: 1,
        state: "PROVISIONING",
      }),
    ),
    { code: "TENANT_SCOPE_VIOLATION" },
  );
});

test("file object Adapter refuses broad storage roots", () => {
  assert.throws(
    () => createFileTenantObjectAdapter({ rootDir: "/" }),
    { code: "INVALID_CONFIGURATION" },
  );
});
