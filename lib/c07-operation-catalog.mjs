const EXPECTED_DOCUMENT = Object.freeze({
  schemaVersion: "1.0.0",
  catalogVersion: "c07-operation-catalog-v1",
  phase: "P1_SYNTHETIC_ONLY",
  dataClassification: "SYNTHETIC_ONLY",
  productionVerificationStatus: "NOT_VERIFIED",
  p3VerificationStatus: "NOT_VERIFIED",
  enterpriseConnectors: "C0_DISABLED",
});

function descriptor({
  operationId,
  adapterId,
  path,
  surface,
  mode,
  inputKeys,
}) {
  return Object.freeze({
    operationId,
    adapterId,
    kind: operationId,
    path,
    surface,
    mode,
    inputKeys: Object.freeze([...inputKeys]),
  });
}

const EXPECTED_OPERATIONS = Object.freeze([
  descriptor({
    operationId: "SQL_PUT",
    adapterId: "c07.postgres",
    path: "records",
    surface: "MANAGE",
    mode: "WRITE",
    inputKeys: ["resourceId", "value"],
  }),
  descriptor({
    operationId: "SQL_GET",
    adapterId: "c07.postgres",
    path: "records",
    surface: "READ",
    mode: "READ",
    inputKeys: ["resourceId"],
  }),
  descriptor({
    operationId: "VECTOR_UPSERT",
    adapterId: "c07.postgres",
    path: "vectors",
    surface: "MANAGE",
    mode: "WRITE",
    inputKeys: ["resourceId", "embedding", "metadata"],
  }),
  descriptor({
    operationId: "VECTOR_SEARCH",
    adapterId: "c07.postgres",
    path: "vectors",
    surface: "RETRIEVE",
    mode: "READ",
    inputKeys: ["embedding", "limit"],
  }),
  descriptor({
    operationId: "SEARCH_INDEX",
    adapterId: "c07.postgres",
    path: "search-documents",
    surface: "MANAGE",
    mode: "WRITE",
    inputKeys: ["resourceId", "text", "metadata"],
  }),
  descriptor({
    operationId: "SEARCH_QUERY",
    adapterId: "c07.postgres",
    path: "search-documents",
    surface: "RETRIEVE",
    mode: "READ",
    inputKeys: ["query", "limit"],
  }),
  descriptor({
    operationId: "CACHE_PUT",
    adapterId: "c07.postgres",
    path: "cache-entries",
    surface: "MANAGE",
    mode: "WRITE",
    inputKeys: ["cacheKey", "value", "ttlSeconds"],
  }),
  descriptor({
    operationId: "CACHE_GET",
    adapterId: "c07.postgres",
    path: "cache-entries",
    surface: "READ",
    mode: "READ",
    inputKeys: ["cacheKey"],
  }),
  descriptor({
    operationId: "OBJECT_PUT",
    adapterId: "c07.object-storage",
    path: "objects",
    surface: "MANAGE",
    mode: "WRITE",
    inputKeys: ["objectKey", "body", "contentType"],
  }),
  descriptor({
    operationId: "OBJECT_GET",
    adapterId: "c07.object-storage",
    path: "objects",
    surface: "DOWNLOAD",
    mode: "READ",
    inputKeys: ["objectKey"],
  }),
  descriptor({
    operationId: "OBJECT_LIST",
    adapterId: "c07.object-storage",
    path: "objects",
    surface: "RETRIEVE",
    mode: "READ",
    inputKeys: ["cursor", "limit"],
  }),
]);

const EXPECTED_BY_ID = new Map(
  EXPECTED_OPERATIONS.map((operation) => [
    operation.operationId,
    operation,
  ]),
);

const FORBIDDEN_INPUT_KEYS = new Set([
  "adapterId",
  "bucket",
  "index",
  "namespace",
  "path",
  "sql",
  "surface",
  "tenantId",
]);

export class C07OperationCatalogError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C07OperationCatalogError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C07OperationCatalogError(code, message);
}

function exactKeys(value, expectedKeys, field) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("INVALID_CATALOG", `${field} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail("INVALID_CATALOG", `${field} fields are not frozen.`);
  }
}

function validateDescriptor(value, index, seen) {
  exactKeys(
    value,
    [
      "operationId",
      "adapterId",
      "kind",
      "path",
      "surface",
      "mode",
      "inputKeys",
    ],
    `operations[${index}]`,
  );
  const expected = EXPECTED_BY_ID.get(value.operationId);
  if (!expected || seen.has(value.operationId)) {
    fail("INVALID_CATALOG", "Operation IDs must be exact and unique.");
  }
  seen.add(value.operationId);
  for (const key of [
    "operationId",
    "adapterId",
    "kind",
    "path",
    "surface",
    "mode",
  ]) {
    if (value[key] !== expected[key]) {
      fail(
        "INVALID_CATALOG",
        `${value.operationId}.${key} does not match the frozen descriptor.`,
      );
    }
  }
  if (
    !Array.isArray(value.inputKeys) ||
    value.inputKeys.length !== expected.inputKeys.length ||
    value.inputKeys.some(
      (key, inputIndex) =>
        key !== expected.inputKeys[inputIndex] ||
        FORBIDDEN_INPUT_KEYS.has(key),
    )
  ) {
    fail(
      "INVALID_CATALOG",
      `${value.operationId}.inputKeys are not frozen.`,
    );
  }
}

function validateDocument(document) {
  exactKeys(
    document,
    [...Object.keys(EXPECTED_DOCUMENT), "operations"],
    "catalog",
  );
  for (const [key, expected] of Object.entries(EXPECTED_DOCUMENT)) {
    if (document[key] !== expected) {
      fail("INVALID_CATALOG", `${key} does not match the P1 boundary.`);
    }
  }
  if (
    !Array.isArray(document.operations) ||
    document.operations.length !== EXPECTED_OPERATIONS.length
  ) {
    fail("INVALID_CATALOG", "The frozen operation set is incomplete.");
  }
  const seen = new Set();
  document.operations.forEach((value, index) =>
    validateDescriptor(value, index, seen),
  );
  if (EXPECTED_OPERATIONS.some(({ operationId }) => !seen.has(operationId))) {
    fail("INVALID_CATALOG", "The frozen operation set is incomplete.");
  }
}

export function createC07OperationCatalog(document) {
  validateDocument(document);
  return Object.freeze({
    resolve(operationId) {
      const value = EXPECTED_BY_ID.get(operationId);
      if (!value) {
        fail("UNKNOWN_OPERATION", "C07 operation is not registered.");
      }
      return value;
    },
    list() {
      return EXPECTED_OPERATIONS;
    },
  });
}
