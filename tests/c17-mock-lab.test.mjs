import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createC17MockLab,
} from "../lib/c17-mock-lab.mjs";
import {
  C17ConnectorError,
} from "../lib/c17-connector-sdk.mjs";

const templateDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c17/connector-templates.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const fixtureDocument = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c17/synthetic-connector-fixtures.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TENANTS = [
  "stn_018f0000-0000-7000-8000-000000000010",
  "stn_018f0000-0000-7000-8000-000000000011",
  "stn_018f0000-0000-7000-8000-000000000012",
];
const LOOKUPS = [
  [
    "synthetic.approval.status.get",
    (index) => ({ approvalRef: `SYN-APR-000${index + 1}` }),
  ],
  [
    "synthetic.erp.order.get",
    (index) => ({ orderRef: `SYN-ORD-000${index + 1}` }),
  ],
  [
    "synthetic.bi.metric.get",
    (index) => ({
      metricCode:
        index === 1 ? "open_order_count" : "on_time_delivery_rate",
      period: index === 2 ? "2026-Q2" : "2026-Q1",
    }),
  ],
];

function countedProxy(value, counter) {
  return new Proxy(value, {
    get(target, property, receiver) {
      counter.count += 1;
      return Reflect.get(target, property, receiver);
    },
    getPrototypeOf(target) {
      counter.count += 1;
      return Reflect.getPrototypeOf(target);
    },
    ownKeys(target) {
      counter.count += 1;
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor(target, property) {
      counter.count += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
}

test("Mock Lab isolates nine deterministic records across three tenants", async () => {
  const lab = createC17MockLab({
    templateDocument,
    fixtureDocument,
    observedAt: "2026-07-26T12:00:00.000Z",
  });
  for (const [tenantIndex, tenantId] of TENANTS.entries()) {
    for (const [operationId, lookup] of LOOKUPS) {
      const result = await lab.execute({
        tenantId,
        tenantKind: "SYNTHETIC",
        operationId,
        parameters: lookup(tenantIndex),
        requestedAsOf: null,
      });
      assert.equal(result.status, "OK");
      assert.equal(result.provenance.source_mode, "SYNTHETIC");
      assert.match(
        result.provenance.content_hash,
        /^sha256:[a-f0-9]{64}$/,
      );
    }
  }
  assert.deepEqual(lab.snapshot(), {
    invocationCount: 9,
    networkRequestCount: 0,
    enterpriseEndpointCount: 0,
    enterpriseCredentialCount: 0,
    externalEffectCount: 0,
  });
});

test("Mock Lab rejects a schema-valid local Fixture replacement", () => {
  const changed = structuredClone(fixtureDocument);
  changed.records[2].data.value = 95.5;
  assert.throws(
    () =>
      createC17MockLab({
        templateDocument,
        fixtureDocument: changed,
        observedAt: "2026-07-26T12:00:00.000Z",
      }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
});

test("Mock Lab rejects executable clock injection without invoking it", () => {
  let externalEffectCount = 0;
  assert.throws(
    () =>
      createC17MockLab({
        templateDocument,
        fixtureDocument,
        clock: () => {
          externalEffectCount += 1;
          return "2026-07-26T12:00:00.000Z";
        },
      }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(externalEffectCount, 0);
});

test("Mock Lab inertly rejects configuration accessors and Proxies", () => {
  const accessorConfiguration = {
    templateDocument,
    fixtureDocument,
  };
  let getterCount = 0;
  Object.defineProperty(accessorConfiguration, "observedAt", {
    enumerable: true,
    get() {
      getterCount += 1;
      return "2026-07-26T12:00:00.000Z";
    },
  });
  assert.throws(
    () => createC17MockLab(accessorConfiguration),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(getterCount, 0);

  const trapCounter = { count: 0 };
  const proxyConfiguration = countedProxy(
    {
      templateDocument,
      fixtureDocument,
      observedAt: "2026-07-26T12:00:00.000Z",
    },
    trapCounter,
  );
  assert.throws(
    () => createC17MockLab(proxyConfiguration),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
  assert.equal(trapCounter.count, 0);
});

test("Mock Lab inertly rejects nested parameter accessors and Proxies", async () => {
  const accessorParameters = {};
  let getterCount = 0;
  Object.defineProperty(accessorParameters, "approvalRef", {
    enumerable: true,
    get() {
      getterCount += 1;
      return "SYN-APR-0001";
    },
  });
  const accessorLab = createC17MockLab({
    templateDocument,
    fixtureDocument,
    observedAt: "2026-07-26T12:00:00.000Z",
  });
  await assert.rejects(
    accessorLab.execute({
      tenantId: TENANTS[0],
      tenantKind: "SYNTHETIC",
      operationId: "synthetic.approval.status.get",
      parameters: accessorParameters,
      requestedAsOf: null,
    }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
  assert.equal(getterCount, 0);
  assert.equal(accessorLab.snapshot().invocationCount, 0);

  const trapCounter = { count: 0 };
  const proxyValue = countedProxy(
    { toString: () => "SYN-APR-0001" },
    trapCounter,
  );
  const proxyLab = createC17MockLab({
    templateDocument,
    fixtureDocument,
    observedAt: "2026-07-26T12:00:00.000Z",
  });
  await assert.rejects(
    proxyLab.execute({
      tenantId: TENANTS[0],
      tenantKind: "SYNTHETIC",
      operationId: "synthetic.approval.status.get",
      parameters: { approvalRef: proxyValue },
      requestedAsOf: null,
    }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "SYNTHETIC_BOUNDARY_VIOLATION",
  );
  assert.equal(trapCounter.count, 0);
  assert.equal(proxyLab.snapshot().invocationCount, 0);
});

test("Mock Lab rejects a 20000-level Fixture as configuration, not a native error", () => {
  const changed = structuredClone(fixtureDocument);
  let nested = "leaf";
  for (let depth = 0; depth < 20_000; depth += 1) {
    nested = { nested };
  }
  changed.records[0].data.nested = nested;

  assert.throws(
    () =>
      createC17MockLab({
        templateDocument,
        fixtureDocument: changed,
        observedAt: "2026-07-26T12:00:00.000Z",
      }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "INVALID_CONFIGURATION",
  );
});

test("Mock Lab never resolves another Tenant's lookup", async () => {
  const lab = createC17MockLab({
    templateDocument,
    fixtureDocument,
    observedAt: "2026-07-26T12:00:00.000Z",
  });
  await assert.rejects(
    lab.execute({
      tenantId: TENANTS[0],
      tenantKind: "SYNTHETIC",
      operationId: "synthetic.approval.status.get",
      parameters: { approvalRef: "SYN-APR-0002" },
      requestedAsOf: null,
    }),
    (error) =>
      error instanceof C17ConnectorError &&
      error.code === "SYNTHETIC_RECORD_NOT_FOUND",
  );
});

test("Mock Lab normalizes an accepted offset clock before returning provenance", async () => {
  const lab = createC17MockLab({
    templateDocument,
    fixtureDocument,
    observedAt: "2026-07-26T20:00:00+08:00",
  });
  const result = await lab.execute({
    tenantId: TENANTS[0],
    tenantKind: "SYNTHETIC",
    operationId: "synthetic.approval.status.get",
    parameters: { approvalRef: "SYN-APR-0001" },
    requestedAsOf: "2026-07-26T11:55:00Z",
  });
  assert.equal(
    result.provenance.observed_at,
    "2026-07-26T12:00:00.000Z",
  );
});
