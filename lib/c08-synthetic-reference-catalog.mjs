const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const FIXTURE_ID = /^synthetic-tenant-[a-z0-9-]{1,96}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|profile|synthetic|test):\/\/\S+$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const KINDS = new Set([
  "ARTIFACT_CONTENT",
  "COMPENSATION",
  "GOAL",
  "KNOWLEDGE",
  "MODEL",
  "PROMPT",
  "PURPOSE",
  "SKILL",
  "TOOL_OPERATION",
  "TRACE",
]);
const VERSION_AND_HASH = new Set([
  "ARTIFACT_CONTENT",
  "KNOWLEDGE",
  "MODEL",
  "PROMPT",
  "SKILL",
]);
const VERSION_ONLY = new Set(["TOOL_OPERATION"]);
const DEPENDENCY_STATUS = new Set([
  "C08_SYNTHETIC_FIXTURE",
  "PENDING_DEPENDENT_PACKAGE",
]);
const INTENDED_OWNER = Object.freeze({
  ARTIFACT_CONTENT: "C08",
  COMPENSATION: "C16",
  GOAL: "C08",
  KNOWLEDGE: "C10",
  MODEL: "C14",
  PROMPT: "C13",
  PURPOSE: "C08",
  SKILL: "C13",
  TOOL_OPERATION: "C16",
  TRACE: "C08",
});

export class C08SyntheticReferenceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C08SyntheticReferenceError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C08SyntheticReferenceError(code, message);
}

function exactKeys(value, keys, field) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) {
    fail("INVALID_REFERENCE_CATALOG", `${field} is not closed.`);
  }
}

function validInstant(value) {
  return (
    typeof value === "string" &&
    INSTANT.test(value) &&
    new Date(value).toISOString() === value
  );
}

function entryKey({ kind, ref, version, asOf }) {
  return JSON.stringify([kind, ref, version, asOf]);
}

function validateEntry(entry) {
  exactKeys(
    entry,
    [
      "kind",
      "ref",
      "version",
      "sha256",
      "asOf",
      "fixtureSourcePackage",
      "intendedOwnerPackage",
      "dependencyStatus",
    ],
    "reference entry",
  );
  if (
    !KINDS.has(entry.kind) ||
    typeof entry.ref !== "string" ||
    !REFERENCE.test(entry.ref) ||
    entry.fixtureSourcePackage !== "C08" ||
    entry.intendedOwnerPackage !== INTENDED_OWNER[entry.kind] ||
    entry.dependencyStatus !==
      (entry.intendedOwnerPackage === "C08"
        ? "C08_SYNTHETIC_FIXTURE"
        : "PENDING_DEPENDENT_PACKAGE") ||
    !DEPENDENCY_STATUS.has(entry.dependencyStatus)
  ) {
    fail("INVALID_REFERENCE_CATALOG", "Reference entry is invalid.");
  }
  if (VERSION_AND_HASH.has(entry.kind)) {
    if (
      !VERSION.test(entry.version ?? "") ||
      !SHA256.test(entry.sha256 ?? "")
    ) {
      fail(
        "INVALID_REFERENCE_CATALOG",
        "Versioned reference entry is incomplete.",
      );
    }
  } else if (VERSION_ONLY.has(entry.kind)) {
    if (!VERSION.test(entry.version ?? "") || entry.sha256 !== null) {
      fail(
        "INVALID_REFERENCE_CATALOG",
        "Tool operation reference entry is incomplete.",
      );
    }
  } else if (entry.version !== null || entry.sha256 !== null) {
    fail(
      "INVALID_REFERENCE_CATALOG",
      "Unversioned reference entry contains a version or hash.",
    );
  }
  if (entry.kind === "KNOWLEDGE") {
    if (!validInstant(entry.asOf)) {
      fail(
        "INVALID_REFERENCE_CATALOG",
        "Knowledge reference requires a canonical asOf.",
      );
    }
  } else if (entry.asOf !== null) {
    fail(
      "INVALID_REFERENCE_CATALOG",
      "Only knowledge references can contain asOf.",
    );
  }
}

export function createC08SyntheticReferenceCatalog(catalog) {
  exactKeys(
    catalog,
    [
      "schemaVersion",
      "catalogVersion",
      "phase",
      "dataClassification",
      "enterpriseConnectors",
      "sharedEntries",
      "tenants",
    ],
    "reference catalog",
  );
  if (
    catalog.phase !== "P1_SYNTHETIC_ONLY" ||
    catalog.dataClassification !== "SYNTHETIC_ONLY" ||
    catalog.enterpriseConnectors !== "C0_DISABLED" ||
    !Array.isArray(catalog.sharedEntries) ||
    catalog.sharedEntries.length === 0 ||
    !Array.isArray(catalog.tenants) ||
    catalog.tenants.length === 0
  ) {
    fail("INVALID_REFERENCE_CATALOG", "Reference catalog boundary is invalid.");
  }

  const sharedEntries = new Map();
  for (const entry of catalog.sharedEntries) {
    validateEntry(entry);
    const key = entryKey(entry);
    if (sharedEntries.has(key)) {
      fail("INVALID_REFERENCE_CATALOG", "Reference entry is duplicated.");
    }
    sharedEntries.set(key, Object.freeze(structuredClone(entry)));
  }

  const tenants = new Map();
  for (const tenant of catalog.tenants) {
    exactKeys(
      tenant,
      [
        "tenantId",
        "fixtureId",
        "authorizationResources",
        "entries",
      ],
      "tenant catalog",
    );
    exactKeys(
      tenant.authorizationResources,
      ["READ", "MANAGE", "TOOL_CALL"],
      "authorization resources",
    );
    if (
      !TENANT_ID.test(tenant.tenantId ?? "") ||
      !FIXTURE_ID.test(tenant.fixtureId ?? "") ||
      tenant.authorizationResources.READ !==
        `${tenant.fixtureId}--read` ||
      tenant.authorizationResources.MANAGE !==
        `${tenant.fixtureId}--manage` ||
      tenant.authorizationResources.TOOL_CALL !==
        `${tenant.fixtureId}--tool-call` ||
      !Array.isArray(tenant.entries) ||
      tenants.has(tenant.tenantId)
    ) {
      fail("INVALID_REFERENCE_CATALOG", "Tenant catalog is invalid.");
    }
    const entries = new Map(sharedEntries);
    for (const entry of tenant.entries) {
      validateEntry(entry);
      const key = entryKey(entry);
      if (entries.has(key)) {
        fail("INVALID_REFERENCE_CATALOG", "Reference entry is duplicated.");
      }
      entries.set(key, Object.freeze(structuredClone(entry)));
    }
    tenants.set(
      tenant.tenantId,
      Object.freeze({
        authorizationResources: Object.freeze({
          ...tenant.authorizationResources,
        }),
        entries,
      }),
    );
  }

  return Object.freeze({
    verify(query) {
      exactKeys(
        query,
        ["tenantId", "kind", "ref", "version", "sha256", "asOf"],
        "reference query",
      );
      const tenant = tenants.get(query.tenantId);
      const entry = tenant?.entries.get(entryKey(query));
      if (
        !entry ||
        entry.sha256 !== query.sha256 ||
        !KINDS.has(query.kind)
      ) {
        fail(
          "SYNTHETIC_REFERENCE_UNVERIFIED",
          "Reference is not in the frozen Synthetic catalog.",
        );
      }
      return entry;
    },
    authorizationResources(tenantId) {
      const resources = tenants.get(tenantId)?.authorizationResources;
      if (!resources) {
        fail(
          "SYNTHETIC_REFERENCE_UNVERIFIED",
          "Synthetic Tenant is not in the frozen reference catalog.",
        );
      }
      return resources;
    },
  });
}
