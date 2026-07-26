import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  link,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  unlink,
} from "node:fs/promises";
import { isAbsolute, join, resolve, sep } from "node:path";
import {
  KnowledgeCatalogError,
  c10Sha256,
} from "./knowledge-catalog.mjs";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const SYNTHETIC_TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const DOCUMENT_ID = /^[a-z][a-z0-9_-]{0,127}$/;
const QUARANTINE_REF = new RegExp(
  `^quarantine://c10/(stn_${UUID_V7})/` +
    "([a-z][a-z0-9_-]{0,127})/([1-9][0-9]*)/([0-9a-f]{64})$",
);

function fail(code, message) {
  throw new KnowledgeCatalogError(code, message);
}

function validateCoordinates({
  tenantId,
  quarantineRef,
  contentSha256,
}) {
  if (
    !SYNTHETIC_TENANT_ID.test(tenantId ?? "") ||
    !SHA256.test(contentSha256 ?? "")
  ) {
    fail(
      "TENANT_SCOPE_VIOLATION",
      "Quarantine coordinates are invalid.",
    );
  }
  const match =
    typeof quarantineRef === "string"
      ? QUARANTINE_REF.exec(quarantineRef)
      : null;
  if (
    !match ||
    match[1] !== tenantId ||
    !DOCUMENT_ID.test(match[2]) ||
    !Number.isSafeInteger(Number(match[3])) ||
    match[4] !== contentSha256.slice(7)
  ) {
    fail(
      "TENANT_SCOPE_VIOLATION",
      "Quarantine reference crossed Tenant scope.",
    );
  }
}

function recordName(quarantineRef) {
  return `${createHash("sha256").update(quarantineRef).digest("hex")}.json`;
}

export function createFileC10QuarantineStore({ rootDir }) {
  if (
    typeof rootDir !== "string" ||
    !isAbsolute(rootDir) ||
    resolve(rootDir) === "/" ||
    resolve(rootDir) === resolve(".")
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C10 quarantine root must be a dedicated absolute directory.",
    );
  }
  const root = resolve(rootDir);

  async function inspectDirectory(path, expectedParent, create) {
    if (create) await mkdir(path, { recursive: true, mode: 0o700 });
    let information;
    try {
      information = await lstat(path);
    } catch (error) {
      if (error?.code === "ENOENT") return null;
      fail("STORE_UNAVAILABLE", "C10 quarantine storage is unavailable.");
    }
    if (information.isSymbolicLink() || !information.isDirectory()) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C10 quarantine directory is unsafe.",
      );
    }
    const canonical = await realpath(path);
    if (
      expectedParent &&
      !canonical.startsWith(`${expectedParent}${sep}`)
    ) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C10 quarantine directory escaped its root.",
      );
    }
    return canonical;
  }

  async function tenantDirectory(tenantId, create) {
    if (!SYNTHETIC_TENANT_ID.test(tenantId ?? "")) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "Quarantine Tenant is invalid.",
      );
    }
    const canonicalRoot = await inspectDirectory(root, null, create);
    if (!canonicalRoot) return null;
    const path = join(root, tenantId);
    const canonicalTenant = await inspectDirectory(
      path,
      canonicalRoot,
      create,
    );
    return canonicalTenant ? { path, canonicalTenant } : null;
  }

  async function readStored(
    coordinates,
    { allowMissing = false } = {},
  ) {
    validateCoordinates(coordinates);
    const directory = await tenantDirectory(
      coordinates.tenantId,
      false,
    );
    if (!directory) {
      if (allowMissing) return null;
      fail("QUARANTINE_NOT_FOUND", "Quarantine object is unavailable.");
    }
    const path = join(
      directory.path,
      recordName(coordinates.quarantineRef),
    );
    let information;
    try {
      information = await lstat(path);
    } catch (error) {
      if (error?.code === "ENOENT") {
        if (allowMissing) return null;
        fail(
          "QUARANTINE_NOT_FOUND",
          "Quarantine object is unavailable.",
        );
      }
      fail("STORE_UNAVAILABLE", "C10 quarantine storage is unavailable.");
    }
    if (information.isSymbolicLink() || !information.isFile()) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C10 quarantine object is unsafe.",
      );
    }
    const canonicalPath = await realpath(path);
    if (!canonicalPath.startsWith(`${directory.canonicalTenant}${sep}`)) {
      fail(
        "TENANT_SCOPE_VIOLATION",
        "C10 quarantine object escaped its Tenant.",
      );
    }
    let record;
    try {
      record = JSON.parse(await readFile(path, "utf8"));
    } catch {
      fail("CONTENT_HASH_MISMATCH", "Quarantine object is corrupt.");
    }
    if (
      !record ||
      Object.keys(record).sort().join(",") !==
        "contentBase64,contentSha256,quarantineRef,tenantId" ||
      record.tenantId !== coordinates.tenantId ||
      record.quarantineRef !== coordinates.quarantineRef ||
      record.contentSha256 !== coordinates.contentSha256 ||
      typeof record.contentBase64 !== "string"
    ) {
      fail("CONTENT_HASH_MISMATCH", "Quarantine object is corrupt.");
    }
    const content = Buffer.from(record.contentBase64, "base64");
    if (c10Sha256(content) !== coordinates.contentSha256) {
      fail("CONTENT_HASH_MISMATCH", "Quarantine object is corrupt.");
    }
    return { path, content };
  }

  async function writeIfAbsent(coordinates, content) {
    const directory = await tenantDirectory(coordinates.tenantId, true);
    const finalPath = join(
      directory.path,
      recordName(coordinates.quarantineRef),
    );
    const temporaryPath = join(
      directory.path,
      `.${randomUUID()}.tmp`,
    );
    let handle;
    try {
      handle = await open(temporaryPath, "wx", 0o600);
      await handle.writeFile(
        JSON.stringify({
          tenantId: coordinates.tenantId,
          quarantineRef: coordinates.quarantineRef,
          contentSha256: coordinates.contentSha256,
          contentBase64: Buffer.from(content).toString("base64"),
        }),
        "utf8",
      );
      await handle.sync();
      await handle.close();
      handle = null;
      try {
        await link(temporaryPath, finalPath);
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        const existing = await readStored(coordinates);
        if (!existing.content.equals(Buffer.from(content))) {
          fail(
            "CONTENT_HASH_MISMATCH",
            "Quarantine reference changed its content.",
          );
        }
      }
    } catch (error) {
      if (error instanceof KnowledgeCatalogError) throw error;
      fail("STORE_UNAVAILABLE", "C10 quarantine storage is unavailable.");
    } finally {
      if (handle) await handle.close().catch(() => {});
      await unlink(temporaryPath).catch((error) => {
        if (error?.code !== "ENOENT") {
          fail(
            "STORE_UNAVAILABLE",
            "C10 quarantine storage is unavailable.",
          );
        }
      });
    }
  }

  return Object.freeze({
    async put({ tenantId, quarantineRef, contentSha256, content }) {
      const coordinates = {
        tenantId,
        quarantineRef,
        contentSha256,
      };
      validateCoordinates(coordinates);
      if (
        !(content instanceof Uint8Array) ||
        c10Sha256(content) !== contentSha256
      ) {
        fail("CONTENT_HASH_MISMATCH", "Quarantine input hash changed.");
      }
      await writeIfAbsent(coordinates, content);
      return quarantineRef;
    },

    async read(coordinates) {
      const stored = await readStored(coordinates);
      return Buffer.from(stored.content);
    },

    async erase(coordinates) {
      const stored = await readStored(coordinates, {
        allowMissing: true,
      });
      if (!stored) return;
      try {
        await unlink(stored.path);
      } catch (error) {
        if (error?.code !== "ENOENT") {
          fail(
            "STORE_UNAVAILABLE",
            "C10 quarantine storage is unavailable.",
          );
        }
      }
    },

    async has({ tenantId, contentSha256 }) {
      if (
        !SYNTHETIC_TENANT_ID.test(tenantId ?? "") ||
        !SHA256.test(contentSha256 ?? "")
      ) {
        fail(
          "TENANT_SCOPE_VIOLATION",
          "Quarantine coordinates are invalid.",
        );
      }
      const directory = await tenantDirectory(tenantId, false);
      if (!directory) return false;
      let entries;
      try {
        entries = await readdir(directory.path);
      } catch {
        fail("STORE_UNAVAILABLE", "C10 quarantine storage is unavailable.");
      }
      for (const entry of entries) {
        if (!/^[0-9a-f]{64}\.json$/.test(entry)) continue;
        let record;
        try {
          record = JSON.parse(
            await readFile(join(directory.path, entry), "utf8"),
          );
        } catch {
          fail("CONTENT_HASH_MISMATCH", "Quarantine object is corrupt.");
        }
        if (
          record?.tenantId === tenantId &&
          record?.contentSha256 === contentSha256
        ) {
          const stored = await readStored({
            tenantId,
            quarantineRef: record.quarantineRef,
            contentSha256,
          });
          return Boolean(stored);
        }
      }
      return false;
    },
  });
}
