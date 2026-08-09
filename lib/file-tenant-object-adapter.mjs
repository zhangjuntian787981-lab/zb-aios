import { createHash, randomUUID } from "node:crypto";
import {
  mkdir,
  lstat,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { isAbsolute, join, resolve, sep } from "node:path";
import { TenantDataIsolationError } from "./tenant-data-boundary.mjs";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const OBJECT_KEY =
  /^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$/;
const EVENT_STATE = Object.freeze({
  "product.tenant.provisioning-requested.v1": "PROVISIONING",
  "product.tenant.activated.v1": "ACTIVE",
  "product.tenant.suspended.v1": "SUSPENDED",
  "product.tenant.resume-requested.v1": "PROVISIONING",
  "product.tenant.deletion-requested.v1": "DELETING",
  "product.tenant.deleted.v1": "DELETED",
});
const LIFECYCLE_TRANSITIONS = Object.freeze({
  NOT_PROVISIONED: Object.freeze(["PROVISIONING"]),
  PROVISIONING: Object.freeze(["ACTIVE", "SUSPENDED", "DELETING"]),
  ACTIVE: Object.freeze(["SUSPENDED", "DELETING"]),
  SUSPENDED: Object.freeze(["PROVISIONING", "DELETING"]),
  DELETING: Object.freeze(["DELETED"]),
  DELETED: Object.freeze([]),
});
const TENANT_LOCKS = new Map();

function fail(code, message) {
  throw new TenantDataIsolationError(code, message);
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validateTenantId(value) {
  if (!SYNTHETIC_TENANT_ID.test(value ?? "")) {
    fail("TENANT_SCOPE_VIOLATION", "Object Tenant scope is invalid.");
  }
}

function validateObjectKey(value) {
  if (
    typeof value !== "string" ||
    value.length > 512 ||
    isAbsolute(value) ||
    !OBJECT_KEY.test(value) ||
    value.split("/").some((part) => part === "." || part === "..")
  ) {
    fail("INVALID_INPUT", "Logical object key is invalid.");
  }
}

function validateScope(scope) {
  if (
    scope?.trustSource !== "C07_VERIFIED_TENANT_SCOPE" ||
    scope?.tenantKind !== "SYNTHETIC" ||
    !Number.isSafeInteger(scope?.lifecycleVersion) ||
    scope.lifecycleVersion < 1
  ) {
    fail("TENANT_SCOPE_VIOLATION", "Object scope is not C07 verified.");
  }
  validateTenantId(scope.tenantId);
}

async function readJson(path, canonicalRoot) {
  try {
    const information = await lstat(path);
    if (information.isSymbolicLink() || !information.isFile()) {
      fail("TENANT_SCOPE_VIOLATION", "Object path is not a regular file.");
    }
    const canonicalPath = await realpath(path);
    if (!canonicalPath.startsWith(`${canonicalRoot}${sep}`)) {
      fail("TENANT_SCOPE_VIOLATION", "Object path escaped its root.");
    }
    return JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    if (error instanceof TenantDataIsolationError) throw error;
    fail("STORE_UNAVAILABLE", "Object metadata could not be read.");
  }
}

async function writeJsonAtomic(path, value) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporary, path);
  } catch {
    try {
      await rm(temporary, { force: true });
    } catch {
      // Preserve the storage failure.
    }
    fail("STORE_UNAVAILABLE", "Object metadata could not be written.");
  }
}

export function createFileTenantObjectAdapter({
  rootDir,
  readOnly = false,
}) {
  if (typeof rootDir !== "string" || !rootDir.trim()) {
    fail("INVALID_CONFIGURATION", "Object rootDir is required.");
  }
  if (typeof readOnly !== "boolean") {
    fail("INVALID_CONFIGURATION", "Object readOnly mode is invalid.");
  }
  const root = resolve(rootDir);
  if (root === "/" || root === resolve(".")) {
    fail("INVALID_CONFIGURATION", "Object rootDir is unsafe.");
  }
  const lifecycleRoot = join(root, ".lifecycle");
  let canonicalRoot;

  async function ensureDirectory(path, create) {
    if (create) await mkdir(path, { recursive: true, mode: 0o700 });
    let information;
    try {
      information = await lstat(path);
    } catch (error) {
      if (error?.code === "ENOENT") return false;
      fail("STORE_UNAVAILABLE", "Object directory could not be inspected.");
    }
    if (information.isSymbolicLink() || !information.isDirectory()) {
      fail("TENANT_SCOPE_VIOLATION", "Object directory is unsafe.");
    }
    const canonicalPath = await realpath(path);
    if (path === root) {
      canonicalRoot = canonicalPath;
    } else if (
      !canonicalRoot ||
      !canonicalPath.startsWith(`${canonicalRoot}${sep}`)
    ) {
      fail("TENANT_SCOPE_VIOLATION", "Object directory escaped its root.");
    }
    return true;
  }

  async function ensureRoot(create = !readOnly) {
    if (!(await ensureDirectory(root, create))) return;
    await ensureDirectory(lifecycleRoot, create);
  }

  async function withTenantLock(tenantId, operation) {
    const lockKey = `${root}\u0000${tenantId}`;
    const previous = TENANT_LOCKS.get(lockKey) ?? Promise.resolve();
    let release;
    const current = new Promise((resolveLock) => {
      release = resolveLock;
    });
    TENANT_LOCKS.set(lockKey, current);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (TENANT_LOCKS.get(lockKey) === current) {
        TENANT_LOCKS.delete(lockKey);
      }
    }
  }

  function tenantDirectory(tenantId) {
    validateTenantId(tenantId);
    return join(root, tenantId);
  }

  function objectPath(tenantId, objectKey) {
    validateObjectKey(objectKey);
    return join(tenantDirectory(tenantId), `${hash(objectKey)}.json`);
  }

  function lifecyclePath(tenantId) {
    validateTenantId(tenantId);
    return join(lifecycleRoot, `${hash(tenantId)}.json`);
  }

  async function executeUnlocked(scope, operation) {
    await ensureRoot();
    const lifecycle = await readJson(
      lifecyclePath(scope.tenantId),
      canonicalRoot,
    );
    if (
      lifecycle?.state !== "ACTIVE" ||
      lifecycle.lifecycleVersion !== scope.lifecycleVersion
    ) {
      fail(
        "TENANT_NOT_ACTIVE",
        "Object lifecycle projection is not active.",
      );
    }
    const { input } = operation;
    if (operation.kind === "OBJECT_PUT") {
      validateObjectKey(input.objectKey);
      if (
        typeof input.body !== "string" ||
        input.body.length > 1_048_576 ||
        typeof input.contentType !== "string" ||
        !input.contentType.trim() ||
        input.contentType.length > 128
      ) {
        fail("INVALID_INPUT", "Object content is invalid.");
      }
      const directory = tenantDirectory(scope.tenantId);
      await ensureDirectory(directory, true);
      const path = objectPath(scope.tenantId, input.objectKey);
      const existing = await readJson(path, canonicalRoot);
      if (existing && existing.resourceId !== operation.resourceId) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "Object key belongs to another authorized resource.",
        );
      }
      const record = {
        tenantId: scope.tenantId,
        tenantKind: "SYNTHETIC",
        resourceId: operation.resourceId,
        objectKey: input.objectKey,
        contentType: input.contentType,
        body: input.body,
      };
      await writeJsonAtomic(
        path,
        record,
      );
      return Object.freeze({
        resourceId: operation.resourceId,
        objectKey: input.objectKey,
        contentType: input.contentType,
        size: Buffer.byteLength(input.body),
      });
    }
    if (operation.kind === "OBJECT_GET") {
      validateObjectKey(input.objectKey);
      if (!(await ensureDirectory(tenantDirectory(scope.tenantId), false))) {
        return null;
      }
      const record = await readJson(
        objectPath(scope.tenantId, input.objectKey),
        canonicalRoot,
      );
      if (!record) return null;
      if (
        record.tenantId !== scope.tenantId ||
        record.tenantKind !== "SYNTHETIC" ||
        record.objectKey !== input.objectKey ||
        record.resourceId !== operation.resourceId
      ) {
        fail("TENANT_SCOPE_VIOLATION", "Object envelope is inconsistent.");
      }
      return Object.freeze({ ...record });
    }
    if (operation.kind === "OBJECT_LIST") {
      const cursor = input.cursor;
      if (
        cursor !== null &&
        (typeof cursor !== "string" || cursor.length > 512)
      ) {
        fail("INVALID_INPUT", "Object cursor is invalid.");
      }
      if (
        !Number.isSafeInteger(input.limit) ||
        input.limit < 1 ||
        input.limit > 100
      ) {
        fail("INVALID_INPUT", "Object list limit is invalid.");
      }
      let names;
      if (!(await ensureDirectory(tenantDirectory(scope.tenantId), false))) {
        return Object.freeze({ items: Object.freeze([]), nextCursor: null });
      }
      try {
        names = await readdir(tenantDirectory(scope.tenantId));
      } catch (error) {
        if (error?.code === "ENOENT") {
          return Object.freeze({ items: Object.freeze([]), nextCursor: null });
        }
        fail("STORE_UNAVAILABLE", "Object directory could not be listed.");
      }
      const records = [];
      for (const name of names.filter((value) => value.endsWith(".json"))) {
        const record = await readJson(
          join(tenantDirectory(scope.tenantId), name),
          canonicalRoot,
        );
        if (
          record?.tenantId !== scope.tenantId ||
          record?.tenantKind !== "SYNTHETIC"
        ) {
          fail("TENANT_SCOPE_VIOLATION", "Object envelope is inconsistent.");
        }
        records.push(record);
      }
      records.sort((left, right) =>
        left.objectKey.localeCompare(right.objectKey),
      );
      const selected = records
        .filter(({ objectKey }) => cursor === null || objectKey > cursor)
        .slice(0, input.limit);
      const hasMore =
        selected.length > 0 &&
        records.some(
          ({ objectKey }) =>
            objectKey > selected[selected.length - 1].objectKey,
        );
      return Object.freeze({
        items: Object.freeze(
          selected.map((record) =>
            Object.freeze({
              tenantId: record.tenantId,
              tenantKind: record.tenantKind,
              resourceId: record.resourceId,
              objectKey: record.objectKey,
              contentType: record.contentType,
            }),
          ),
        ),
        nextCursor: hasMore
          ? selected[selected.length - 1].objectKey
          : null,
      });
    }
    fail("UNKNOWN_OPERATION", "Object operation is not registered.");
  }

  async function execute(scope, operation) {
    validateScope(scope);
    if (readOnly && operation?.kind === "OBJECT_PUT") {
      fail("STORE_UNAVAILABLE", "Object endpoint is read-only.");
    }
    return withTenantLock(
      scope.tenantId,
      () => executeUnlocked(scope, operation),
    );
  }

  async function projectUnlocked(event) {
    await ensureRoot();
    const expectedState = EVENT_STATE[event.type];
    if (
      !expectedState ||
      event.tenantkind !== "SYNTHETIC" ||
      event.synthetic !== true ||
      event.data?.tenant_id !== event.subject ||
      event.data?.state !== expectedState ||
      !Number.isSafeInteger(event.data?.lifecycle_version) ||
      event.data.lifecycle_version < 1
    ) {
      fail("INVALID_LIFECYCLE_EVENT", "Object lifecycle event is invalid.");
    }
    const path = lifecyclePath(event.subject);
    const current = await readJson(path, canonicalRoot);
    const eventSha256 = `sha256:${hash(JSON.stringify(event))}`;
    if (current?.lastEventId === event.id) {
      if (current.eventSha256 !== eventSha256) {
        fail("LIFECYCLE_EVENT_CONFLICT", "Object event ID was reused.");
      }
      return Object.freeze({
        tenantId: event.subject,
        eventId: event.id,
        status: "SUCCEEDED",
        duplicate: true,
      });
    }
    const expectedVersion = current
      ? current.lifecycleVersion + 1
      : 1;
    if (event.data.lifecycle_version !== expectedVersion) {
      fail("STALE_LIFECYCLE_EVENT", "Object lifecycle version is not next.");
    }
    const currentState = current?.state ?? "NOT_PROVISIONED";
    if (!LIFECYCLE_TRANSITIONS[currentState]?.includes(expectedState)) {
      fail(
        "INVALID_LIFECYCLE_EVENT",
        "Object lifecycle transition is invalid.",
      );
    }
    if (
      ["DELETING", "DELETED"].includes(expectedState)
    ) {
      await ensureDirectory(tenantDirectory(event.subject), false);
      await rm(tenantDirectory(event.subject), {
        recursive: true,
        force: true,
      });
    } else {
      await ensureDirectory(tenantDirectory(event.subject), true);
    }
    await writeJsonAtomic(path, {
      tenantId: event.subject,
      tenantKind: "SYNTHETIC",
      lifecycleVersion: event.data.lifecycle_version,
      generation: event.data.generation,
      operationId: event.data.operation_id,
      state: expectedState,
      lastEventId: event.id,
      eventSha256,
    });
    return Object.freeze({
      tenantId: event.subject,
      eventId: event.id,
      status: "SUCCEEDED",
      duplicate: false,
    });
  }

  async function project(event) {
    if (readOnly) {
      fail("STORE_UNAVAILABLE", "Object endpoint is read-only.");
    }
    validateTenantId(event?.subject);
    return withTenantLock(
      event.subject,
      () => projectUnlocked(event),
    );
  }

  async function snapshotUnlocked({ tenantId }) {
    await ensureRoot();
    validateTenantId(tenantId);
    const lifecycle = await readJson(
      lifecyclePath(tenantId),
      canonicalRoot,
    );
    let objectCount = 0;
    try {
      if (await ensureDirectory(tenantDirectory(tenantId), false)) {
        objectCount = (
          await readdir(tenantDirectory(tenantId))
        ).filter((name) => name.endsWith(".json")).length;
      }
    } catch (error) {
      if (error?.code !== "ENOENT") {
        fail("STORE_UNAVAILABLE", "Object snapshot failed.");
      }
    }
    return Object.freeze({
      state: lifecycle?.state ?? "NOT_PROVISIONED",
      lifecycleVersion: lifecycle?.lifecycleVersion ?? 0,
      objectCount,
    });
  }

  async function snapshot(query) {
    validateTenantId(query?.tenantId);
    return withTenantLock(
      query.tenantId,
      () => snapshotUnlocked(query),
    );
  }

  return Object.freeze({
    id: "c07.object-storage",
    paths: Object.freeze(["OBJECT"]),
    execute,
    project,
    snapshot,
  });
}
