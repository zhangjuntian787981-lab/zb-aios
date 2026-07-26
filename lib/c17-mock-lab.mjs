import { types } from "node:util";
import {
  C17ConnectorError,
  c17ConnectorSha256,
  createC17ConnectorTemplates,
} from "./c17-connector-sdk.mjs";
import { normalizeC17DateTime } from "./c17-time.mjs";

const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EXPECTED_FIXTURE_SHA256 =
  "sha256:bd0c738e02ea48cc504037ef50655e543ea3f598793ff2224d30d48769302976";
const EXPECTED_TENANTS = new Set([
  "stn_018f0000-0000-7000-8000-000000000010",
  "stn_018f0000-0000-7000-8000-000000000011",
  "stn_018f0000-0000-7000-8000-000000000012",
]);
const C17_MOCK_LABS = new WeakSet();
const FAULT_MODES = new Set([
  "NONE",
  "TIMEOUT",
  "THROW",
  "EXTRA_FIELD",
  "LOOKUP_CONFUSION",
]);

export function isC17MockLab(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    C17_MOCK_LABS.has(value)
  );
}

function fail(code, message) {
  throw new C17ConnectorError(code, message);
}

function plainObject(value) {
  return (
    value &&
    typeof value === "object" &&
    !types.isProxy(value) &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function dataDescriptors(value) {
  if (!plainObject(value)) return null;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some(
      (key) =>
        typeof key !== "string" ||
        !descriptors[key].enumerable ||
        !Object.hasOwn(descriptors[key], "value"),
    )
  ) {
    return null;
  }
  return descriptors;
}

function exactKeys(value, allowed) {
  const descriptors = dataDescriptors(value);
  return (
    descriptors !== null &&
    Reflect.ownKeys(descriptors).length === allowed.length &&
    Reflect.ownKeys(descriptors).every((key) =>
      allowed.includes(key),
    )
  );
}

function readClosedConfiguration(value, allowed, required) {
  const descriptors = dataDescriptors(value);
  if (descriptors === null) return null;
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) => !allowed.includes(key)) ||
    required.some((key) => !Object.hasOwn(descriptors, key))
  ) {
    return null;
  }
  return Object.fromEntries(
    keys.map((key) => [key, descriptors[key].value]),
  );
}

function canonicalInstant(value) {
  return normalizeC17DateTime(value) !== null;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function fixtureKey(tenantId, operationId, lookup) {
  return c17ConnectorSha256({ tenantId, operationId, lookup });
}

function validBoundedJson(value) {
  try {
    c17ConnectorSha256(value);
    return true;
  } catch {
    return false;
  }
}

function loadFixtures(document, templates) {
  let fixtureSha256;
  try {
    fixtureSha256 = c17ConnectorSha256(document);
  } catch {
    fail("INVALID_CONFIGURATION", "C17 Mock fixtures are invalid.");
  }
  if (
    !exactKeys(document, [
      "schemaVersion",
      "fixtureVersion",
      "phase",
      "dataClassification",
      "connectorStage",
      "networkAccess",
      "records",
    ]) ||
    document.schemaVersion !== "1.0.0" ||
    document.fixtureVersion !==
      "c17-synthetic-connector-fixtures-v1" ||
    document.phase !== "P1_SYNTHETIC_ONLY" ||
    document.dataClassification !== "SYNTHETIC_ONLY" ||
    document.connectorStage !== "C0_DISABLED" ||
    document.networkAccess !== "DISABLED" ||
    !Array.isArray(document.records) ||
    document.records.length !== 9 ||
    fixtureSha256 !== EXPECTED_FIXTURE_SHA256
  ) {
    fail("INVALID_CONFIGURATION", "C17 Mock fixtures are invalid.");
  }
  const records = new Map();
  const coverage = new Set();
  for (const record of document.records) {
    if (
      !exactKeys(record, [
        "tenantId",
        "operationId",
        "lookup",
        "data",
        "asOf",
      ]) ||
      !SYNTHETIC_TENANT_ID.test(record.tenantId ?? "") ||
      !EXPECTED_TENANTS.has(record.tenantId) ||
      !templates.validateParameters(
        record.operationId,
        record.lookup,
      ) ||
      !templates.validateResult(record.operationId, record.data) ||
      !canonicalInstant(record.asOf)
    ) {
      fail("INVALID_CONFIGURATION", "C17 Mock fixture row is invalid.");
    }
    const key = fixtureKey(
      record.tenantId,
      record.operationId,
      record.lookup,
    );
    if (records.has(key)) {
      fail("INVALID_CONFIGURATION", "C17 Mock fixture is duplicated.");
    }
    coverage.add(`${record.tenantId}|${record.operationId}`);
    records.set(
      key,
      deepFreeze({
        data: structuredClone(record.data),
        asOf: normalizeC17DateTime(record.asOf),
      }),
    );
  }
  if (coverage.size !== 9) {
    fail(
      "INVALID_CONFIGURATION",
      "C17 Mock fixtures must cover three Tenants and Templates.",
    );
  }
  return records;
}

export function createC17MockLab(configuration) {
  const parsedConfiguration = readClosedConfiguration(
    configuration,
    [
      "templateDocument",
      "fixtureDocument",
      "observedAt",
      "faultMode",
    ],
    ["templateDocument", "fixtureDocument", "observedAt"],
  );
  if (parsedConfiguration === null) {
    fail("INVALID_CONFIGURATION", "C17 Mock Lab clock is invalid.");
  }
  const {
    templateDocument,
    fixtureDocument,
    observedAt,
  } = parsedConfiguration;
  const faultMode =
    parsedConfiguration.faultMode === undefined
      ? "NONE"
      : parsedConfiguration.faultMode;
  if (
    !canonicalInstant(observedAt) ||
    !FAULT_MODES.has(faultMode)
  ) {
    fail("INVALID_CONFIGURATION", "C17 Mock Lab clock is invalid.");
  }
  const templates = createC17ConnectorTemplates(templateDocument);
  const fixtures = loadFixtures(fixtureDocument, templates);
  const normalizedObservedAt = normalizeC17DateTime(observedAt);
  let invocationCount = 0;

  const lab = Object.freeze({
    async execute(call) {
      if (
        !validBoundedJson(call) ||
        !exactKeys(call, [
          "tenantId",
          "tenantKind",
          "operationId",
          "parameters",
          "requestedAsOf",
        ]) ||
        call.tenantKind !== "SYNTHETIC" ||
        !EXPECTED_TENANTS.has(call.tenantId) ||
        !templates.validateParameters(
          call.operationId,
          call.parameters,
        ) ||
        !(
          call.requestedAsOf === null ||
          canonicalInstant(call.requestedAsOf)
        )
      ) {
        fail(
          "SYNTHETIC_BOUNDARY_VIOLATION",
          "C17 Mock Lab accepts only a fixed synthetic call.",
        );
      }
      invocationCount += 1;
      if (faultMode === "TIMEOUT") {
        return new Promise(() => {});
      }
      if (faultMode === "THROW") {
        throw new Error("Synthetic C17 Mock Lab failure.");
      }
      const fixture = fixtures.get(
        fixtureKey(
          call.tenantId,
          call.operationId,
          call.parameters,
        ),
      );
      if (!fixture) {
        fail(
          "SYNTHETIC_RECORD_NOT_FOUND",
          "C17 synthetic record was not found.",
        );
      }
      const result = {
        status: "OK",
        data: structuredClone(fixture.data),
        provenance: {
          source_mode: "SYNTHETIC",
          freshness_status: "CURRENT",
          as_of: fixture.asOf,
          observed_at: normalizedObservedAt,
          content_hash: c17ConnectorSha256(fixture.data),
        },
        error: null,
      };
      if (faultMode === "EXTRA_FIELD") {
        result.providerPrivateField = "synthetic-hidden-value";
      } else if (faultMode === "LOOKUP_CONFUSION") {
        const field = Object.keys(call.parameters)[0];
        result.data[field] = `${result.data[field]}-confused`;
        result.provenance.content_hash =
          c17ConnectorSha256(result.data);
      }
      return deepFreeze(result);
    },

    snapshot() {
      return deepFreeze({
        invocationCount,
        networkRequestCount: 0,
        enterpriseEndpointCount: 0,
        enterpriseCredentialCount: 0,
        externalEffectCount: 0,
      });
    },
  });
  C17_MOCK_LABS.add(lab);
  return lab;
}
