import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  C07OperationCatalogError,
  createC07OperationCatalog,
} from "../lib/c07-operation-catalog.mjs";

const rootUrl = new URL("../", import.meta.url);
const catalogDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c07/operation-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const matrix = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c07/isolation-matrix.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const lock = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c07/pgvector/pgvector-distribution.lock.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

const EXPECTED_OPERATIONS = Object.freeze({
  SQL_PUT: ["c07.postgres", "records", "MANAGE", "WRITE"],
  SQL_GET: ["c07.postgres", "records", "READ", "READ"],
  VECTOR_UPSERT: ["c07.postgres", "vectors", "MANAGE", "WRITE"],
  VECTOR_SEARCH: ["c07.postgres", "vectors", "RETRIEVE", "READ"],
  SEARCH_INDEX: [
    "c07.postgres",
    "search-documents",
    "MANAGE",
    "WRITE",
  ],
  SEARCH_QUERY: [
    "c07.postgres",
    "search-documents",
    "RETRIEVE",
    "READ",
  ],
  CACHE_PUT: ["c07.postgres", "cache-entries", "MANAGE", "WRITE"],
  CACHE_GET: ["c07.postgres", "cache-entries", "READ", "READ"],
  OBJECT_PUT: ["c07.object-storage", "objects", "MANAGE", "WRITE"],
  OBJECT_GET: ["c07.object-storage", "objects", "DOWNLOAD", "READ"],
  OBJECT_LIST: ["c07.object-storage", "objects", "RETRIEVE", "READ"],
});

test("C07 resolves exactly the frozen server-owned operation descriptors", () => {
  const catalog = createC07OperationCatalog(catalogDocument);

  assert.deepEqual(
    catalog.list().map(({ operationId }) => operationId).sort(),
    Object.keys(EXPECTED_OPERATIONS).sort(),
  );
  assert.equal(Object.isFrozen(catalog), true);
  assert.equal(Object.isFrozen(catalog.list()), true);

  for (const [operationId, expected] of Object.entries(
    EXPECTED_OPERATIONS,
  )) {
    const resolved = catalog.resolve(operationId, {
      tenantId: "stn_client_asserted",
      surface: "MANAGE",
    });
    assert.equal(Object.isFrozen(resolved), true);
    assert.equal(Object.isFrozen(resolved.inputKeys), true);
    assert.deepEqual(
      [
        resolved.adapterId,
        resolved.path,
        resolved.surface,
        resolved.mode,
      ],
      expected,
    );
    assert.equal(resolved.kind, operationId);
    assert.equal(resolved.operationId, operationId);
  }

  assert.equal(catalog.resolve("SQL_GET").surface, "READ");
  assert.equal(catalog.resolve("OBJECT_GET").surface, "DOWNLOAD");
});

test("C07 rejects unknown or altered operation descriptors", () => {
  const catalog = createC07OperationCatalog(catalogDocument);
  assert.throws(
    () => catalog.resolve("ARBITRARY_SQL"),
    (error) =>
      error instanceof C07OperationCatalogError &&
      error.code === "UNKNOWN_OPERATION",
  );

  for (const mutate of [
    (document) => {
      document.operations[1].surface = "MANAGE";
    },
    (document) => {
      document.operations[1].inputKeys.push("tenantId");
    },
    (document) => {
      document.operations[1].path = "caller-path";
    },
    (document) => {
      document.productionVerificationStatus = "VERIFIED";
    },
  ]) {
    const changed = structuredClone(catalogDocument);
    mutate(changed);
    assert.throws(
      () => createC07OperationCatalog(changed),
      (error) =>
        error instanceof C07OperationCatalogError &&
        error.code === "INVALID_CATALOG",
    );
  }
});

test("the frozen matrix covers and traces every required case", async () => {
  assert.equal(matrix.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(matrix.dataClassification, "SYNTHETIC_ONLY");
  assert.equal(matrix.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(matrix.p3VerificationStatus, "NOT_VERIFIED");
  assert.equal(matrix.enterpriseConnectors, "C0_DISABLED");
  assert.deepEqual(matrix.syntheticTenants, [
    "synthetic-tenant-blue-harbor-tools",
    "synthetic-tenant-cedar-field-components",
    "synthetic-tenant-northstar-fasteners",
  ]);

  const operationIds = new Set(Object.keys(EXPECTED_OPERATIONS));
  const caseIds = matrix.cases.map(({ caseId }) => caseId);
  assert.equal(new Set(caseIds).size, caseIds.length);
  assert.deepEqual(
    Object.keys(matrix.verificationMap).sort(),
    [...caseIds].sort(),
  );
  for (const layer of [
    "SQL",
    "VECTOR",
    "OBJECT",
    "SEARCH",
    "CACHE",
    "POOL",
    "RESTORE",
  ]) {
    const cases = matrix.cases.filter((entry) => entry.layer === layer);
    assert.equal(
      cases.some(({ caseType }) => caseType === "POSITIVE"),
      true,
      `${layer} needs a positive case`,
    );
    assert.equal(
      cases.some(
        ({ caseType }) => caseType === "CROSS_TENANT_NEGATIVE",
      ),
      true,
      `${layer} needs a cross-Tenant negative case`,
    );
  }
  assert.equal(
    matrix.cases.some(
      ({ caseType }) => caseType === "INJECTION_NEGATIVE",
    ),
    true,
  );
  assert.equal(
    matrix.cases.some(
      ({ caseType }) => caseType === "LIFECYCLE_NEGATIVE",
    ),
    true,
  );
  assert.equal(
    matrix.cases.some(
      ({ caseType }) => caseType === "FAULT_NEGATIVE",
    ),
    true,
  );
  for (const entry of matrix.cases) {
    assert.match(entry.caseId, /^[A-Z]+(?:-[A-Z]+)*-[0-9]{2}$/);
    assert.equal(
      entry.operationIds.every((operationId) =>
        operationIds.has(operationId),
      ),
      true,
    );
    const references = matrix.verificationMap[entry.caseId];
    assert.equal(Array.isArray(references) && references.length > 0, true);
    for (const reference of references) {
      const separator = reference.indexOf("#");
      const path = reference.slice(0, separator);
      const testName = reference.slice(separator + 1);
      assert.equal(separator > 0 && testName.length > 0, true);
      assert.equal(path.startsWith("tests/"), true);
      const source = await readFile(new URL(path, rootUrl), "utf8");
      assert.equal(source.includes(testName), true, reference);
    }
  }
});

test("the pgvector lock freezes supplied source and measured control hashes", () => {
  assert.equal(lock.version, "0.8.5");
  assert.equal(lock.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(lock.productionVerificationStatus, "NOT_VERIFIED");
  assert.equal(lock.p3VerificationStatus, "NOT_VERIFIED");
  assert.equal(lock.enterpriseConnectors, "C0_DISABLED");
  assert.equal(
    lock.distribution.sha256,
    "sha256:6f88a5cbdde31666f4b6c1a6b75c51dcbeffe58f9a7d2b26e502d5a6e5e14d44",
  );
  assert.equal(
    lock.measuredControlFile.sha256,
    "sha256:cd7733e99b25bd02b11db28f5f53a1fb7d253dd773e4bc47f6e3236950ff0ddd",
  );
});
