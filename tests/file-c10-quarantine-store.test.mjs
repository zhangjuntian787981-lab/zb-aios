import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  rm,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createFileC10QuarantineStore } from "../lib/file-c10-quarantine-store.mjs";
import { c10Sha256 } from "../lib/knowledge-catalog.mjs";

const TENANT_A = "stn_01984910-0000-7000-8000-000000000011";
const TENANT_B = "stn_01984910-0000-7000-8000-000000000012";
const DOCUMENT_ID = "sales-guide";
const DOCUMENT_VERSION = 1;

function coordinates(tenantId, content) {
  const contentSha256 = c10Sha256(content);
  return {
    tenantId,
    quarantineRef:
      `quarantine://c10/${tenantId}/${DOCUMENT_ID}/${DOCUMENT_VERSION}/` +
      contentSha256.slice(7),
    contentSha256,
  };
}

async function root(t) {
  const directory = await mkdtemp(join(tmpdir(), "c10-quarantine-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test("C10 file quarantine survives a new Store instance", async (t) => {
  const rootDir = await root(t);
  const content = Buffer.from("synthetic file body", "utf8");
  const input = coordinates(TENANT_A, content);
  const first = createFileC10QuarantineStore({ rootDir });

  assert.equal(
    await first.put({ ...input, content }),
    input.quarantineRef,
  );

  const restarted = createFileC10QuarantineStore({ rootDir });
  assert.deepEqual(await restarted.read(input), content);
  assert.equal(await restarted.has(input), true);
});

test("C10 file quarantine binds Tenant, reference and content hash", async (t) => {
  const rootDir = await root(t);
  const content = Buffer.from("tenant A only", "utf8");
  const input = coordinates(TENANT_A, content);
  const store = createFileC10QuarantineStore({ rootDir });
  await store.put({ ...input, content });

  await assert.rejects(
    store.read({ ...input, tenantId: TENANT_B }),
    { code: "TENANT_SCOPE_VIOLATION" },
  );
  await assert.rejects(
    store.put({
      ...input,
      content: Buffer.from("changed", "utf8"),
    }),
    { code: "CONTENT_HASH_MISMATCH" },
  );
  await assert.rejects(
    store.read({
      ...input,
      quarantineRef:
        `quarantine://c10/${TENANT_A}/../1/${input.contentSha256.slice(7)}`,
    }),
    { code: "TENANT_SCOPE_VIOLATION" },
  );
});

test("C10 file quarantine put is concurrent and erase is durable", async (t) => {
  const rootDir = await root(t);
  const content = Buffer.from("one durable body", "utf8");
  const input = coordinates(TENANT_A, content);
  const first = createFileC10QuarantineStore({ rootDir });
  const second = createFileC10QuarantineStore({ rootDir });

  assert.deepEqual(
    await Promise.all(
      [first, second].map((store) =>
        store.put({ ...input, content })
      ),
    ),
    [input.quarantineRef, input.quarantineRef],
  );
  assert.deepEqual(await second.read(input), content);

  await first.erase(input);
  await assert.rejects(second.read(input), {
    code: "QUARANTINE_NOT_FOUND",
  });
  assert.equal(await second.has(input), false);
});

test("C10 file quarantine rejects unsafe roots and symlinked Tenant directories", async (t) => {
  assert.throws(
    () => createFileC10QuarantineStore({ rootDir: "." }),
    { code: "INVALID_CONFIGURATION" },
  );
  assert.throws(
    () => createFileC10QuarantineStore({ rootDir: "/" }),
    { code: "INVALID_CONFIGURATION" },
  );

  const rootDir = await root(t);
  const outside = await root(t);
  await mkdir(rootDir, { recursive: true });
  await symlink(outside, join(rootDir, TENANT_A), "dir");
  const content = Buffer.from("must not escape", "utf8");
  const input = coordinates(TENANT_A, content);
  const store = createFileC10QuarantineStore({ rootDir });

  await assert.rejects(
    store.put({ ...input, content }),
    { code: "TENANT_SCOPE_VIOLATION" },
  );
});
