import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv from "ajv";
import {
  createMemoryObservabilityStore,
  createObservabilityService,
  createSyntheticObservabilityCatalog,
  ObservabilityError,
} from "../lib/c19-observability.mjs";

async function json(path) {
  return JSON.parse(
    await readFile(new URL(path, import.meta.url), "utf8"),
  );
}

const boundary = await json(
  "../implementation/p1/c19/fact-boundary.v1.json",
);
const boundarySchema = await json(
  "../implementation/p1/c19/fact-boundary-api.v1.schema.json",
);
const databaseSchema = await readFile(
  new URL(
    "../implementation/p1/c19/postgresql/0033_observability_usage.sql",
    import.meta.url,
  ),
  "utf8",
);
const catalog = createSyntheticObservabilityCatalog(
  await json(
    "../implementation/p1/c19/synthetic-observability-catalog.v1.json",
  ),
);
const schemaValidator = new Ajv({
  allErrors: true,
  strict: true,
}).compile(boundarySchema);

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const PRINCIPAL =
  "prn_018f0000-0000-7000-8000-000000000001";
const CONTEXT = {
  synthetic: true,
  routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
  tenantId: TENANT,
  identityContextRef:
    "fixture://c19/northstar/identity-context/ava",
};
const TRACEPARENT =
  "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

const VALID_INVOCATIONS = Object.freeze({
  recordSignal: {
    operation: "recordSignal",
    request: {
      idempotencyKey: "idem-c19-fact-signal",
      traceparent: TRACEPARENT,
      tracestate: null,
      signalType: "LOG",
      operation: "c19.usage.settle",
      taskRef:
        "tsk_018f0000-0000-7000-8000-000000000101",
      status: "OK",
      durationMs: null,
      errorCode: null,
    },
  },
  reserve: {
    operation: "reserve",
    request: {
      idempotencyKey: "idem-c19-fact-reserve",
      planRef: "fixture://c19/northstar/plans/model",
      traceparent: TRACEPARENT,
      tracestate: null,
    },
  },
  release: {
    operation: "release",
    request: {
      idempotencyKey: "idem-c19-fact-release",
      reservationId:
        "qrs_018f0000-0000-7000-8000-000000000001",
      traceparent: TRACEPARENT,
      tracestate: null,
    },
  },
  settle: {
    operation: "settle",
    request: {
      idempotencyKey: "idem-c19-fact-settle",
      reservationId:
        "qrs_018f0000-0000-7000-8000-000000000001",
      receiptRef: "fixture://c19/northstar/receipts/model",
      traceparent: TRACEPARENT,
      tracestate: null,
    },
  },
});

const PROHIBITED_FACTS = Object.freeze([
  {
    field: "project_progress",
    value: {
      workPackageId: "C19",
      status: "VERIFIED",
    },
    authority: "D1_APPEND_ONLY_GOVERNANCE_LEDGER",
  },
  {
    field: "invoice",
    value: {
      invoiceNumber: "SYNTHETIC-INV-001",
      amountMinor: 100,
    },
    authority: "ERP_OR_FINANCE_SYSTEM_OF_RECORD",
  },
  {
    field: "business_metric",
    value: {
      metricId: "synthetic_revenue",
      value: 100,
    },
    authority: "GOVERNED_BI_SEMANTIC_LAYER",
  },
  {
    field: "metadata",
    value: {
      arbitrary: "synthetic extension",
    },
    authority: null,
  },
  {
    field: "payload",
    value: {
      arbitrary: "synthetic body",
    },
    authority: null,
  },
  {
    field: "body",
    value: "synthetic arbitrary body",
    authority: null,
  },
]);

function createHarness() {
  let nextId = 0;
  let nextSpan = 0x1000000000000000n;
  const store = createMemoryObservabilityStore();
  const service = createObservabilityService({
    catalog,
    store,
    tenantRegistry: {
      async admitNewRequest({ tenantId, expectedTenantKind }) {
        assert.equal(tenantId, TENANT);
        assert.equal(expectedTenantKind, "SYNTHETIC");
        return {
          tenantId,
          tenantKind: "SYNTHETIC",
          lifecycleVersion: 1,
        };
      },
    },
    tenantScopeFactory({ tenant, scopeEvidence, correlationId }) {
      return {
        trustSource: "C07_VERIFIED_TENANT_SCOPE",
        tenantId: tenant.tenantId,
        tenantKind: tenant.tenantKind,
        lifecycleVersion: tenant.lifecycleVersion,
        correlationId,
        decisionId: scopeEvidence.decisionId,
        evidenceRef: scopeEvidence.evidenceRef,
        policyVersion: scopeEvidence.policyVersion,
      };
    },
    principalResolver: {
      async resolveActionIdentity() {
        return {
          tenantId: TENANT,
          tenantKind: "SYNTHETIC",
          trustSource:
            "VERIFIED_SESSION_IDENTITY_LINK_AND_WORKLOAD_CONTEXT",
          humanSubject: {
            principalId: PRINCIPAL,
            principalType: "HUMAN",
            lifecycleVersion: 1,
            securityEpoch: 1,
          },
        };
      },
    },
    clock: () => "2026-07-28T00:00:00.000Z",
    idFactory: () => {
      nextId += 1;
      return `018f0000-0000-7000-8000-${String(nextId).padStart(12, "0")}`;
    },
    spanIdFactory: () => {
      nextSpan += 1n;
      return nextSpan.toString(16);
    },
  });
  return service;
}

test("fact boundary assigns excluded truth to D1, ERP/Finance and governed BI", () => {
  assert.equal(boundary.criterionId, "C19-AC09");
  assert.equal(boundary.phase, "P1_SYNTHETIC_ONLY");
  assert.equal(
    boundary.artifactRole,
    "C19_FACT_AUTHORITY_BOUNDARY_SOURCE",
  );
  assert.deepEqual(
    boundary.excludedAuthoritativeFacts.map((entry) => [
      entry.factType,
      entry.authority,
      entry.c19Policy,
    ]),
    [
      [
        "PROJECT_WORK_PACKAGE_PROGRESS",
        "D1_APPEND_ONLY_GOVERNANCE_LEDGER",
        "REJECT",
      ],
      [
        "INVOICE_AND_ACCOUNTING",
        "ERP_OR_FINANCE_SYSTEM_OF_RECORD",
        "REJECT",
      ],
      [
        "ENTERPRISE_BUSINESS_METRIC",
        "GOVERNED_BI_SEMANTIC_LAYER",
        "REJECT",
      ],
    ],
  );
  assert.deepEqual(
    boundary.c19AuthoritativeRecords,
    [
      "OBSERVABILITY_SIGNAL",
      "USAGE_METER",
      "QUOTA",
      "COST_ATTRIBUTION",
    ],
  );
  assert.equal(boundary.dataScope, "SYNTHETIC_ONLY");
  assert.equal(boundary.enterpriseData, "NOT_PRESENT");
  assert.deepEqual(boundary.verificationResults, {
    schemaInvalidCases: 24,
    apiInvalidCases: 24,
    databaseInvalidColumns: 6,
    c19Runner: "37 PASS, 0 FAIL",
    lint: "PASS",
  });
});

test("closed JSON Schema rejects authoritative facts and arbitrary extensions", () => {
  for (const invocation of Object.values(VALID_INVOCATIONS)) {
    assert.equal(
      schemaValidator(invocation),
      true,
      JSON.stringify(schemaValidator.errors),
    );
    for (const prohibited of PROHIBITED_FACTS) {
      const candidate = structuredClone(invocation);
      candidate.request[prohibited.field] = prohibited.value;
      assert.equal(
        schemaValidator(candidate),
        false,
        `${invocation.operation} accepted ${prohibited.field}`,
      );
    }
  }
});

test("public write APIs reject authoritative facts before any C19 record is stored", async () => {
  const service = createHarness();
  for (const invocation of Object.values(VALID_INVOCATIONS)) {
    for (const prohibited of PROHIBITED_FACTS) {
      const candidate = structuredClone(invocation.request);
      candidate[prohibited.field] = prohibited.value;
      await assert.rejects(
        service[invocation.operation](CONTEXT, candidate),
        (error) =>
          error instanceof ObservabilityError &&
          error.code ===
            (["metadata", "body"].includes(prohibited.field)
              ? "PROHIBITED_TELEMETRY_FIELD"
              : "INVALID_INPUT"),
        `${invocation.operation} accepted ${prohibited.field}`,
      );
    }
  }

  const telemetry = await service.telemetryReport(CONTEXT, {
    fromOccurredAt: "2026-07-27T00:00:00.000Z",
    toOccurredAt: "2026-07-29T00:00:00.000Z",
  });
  const cost = await service.costVarianceReport(CONTEXT, {
    fromOccurredAt: "2026-07-27T00:00:00.000Z",
    toOccurredAt: "2026-07-29T00:00:00.000Z",
  });
  assert.equal(telemetry.records.length, 0);
  assert.equal(cost.ledgerEvents.length, 0);
});

test("PostgreSQL schema has no project, invoice, BI metric or extension-body columns", () => {
  const tableBlocks = [
    ...databaseSchema.matchAll(
      /CREATE TABLE aios_observability\.([a-z_]+) \(([\s\S]*?)\n\);/g,
    ),
  ];
  assert.deepEqual(
    tableBlocks.map((match) => match[1]),
    [
      "telemetry_signal",
      "quota_account",
      "quota_reservation",
      "usage_ledger",
    ],
  );
  const columns = tableBlocks.flatMap((match) =>
    [...match[2].matchAll(/^  ([a-z_][a-z0-9_]*)\s+/gm)].map(
      (column) => column[1],
    ),
  );
  for (const prohibited of PROHIBITED_FACTS) {
    assert.equal(
      columns.includes(prohibited.field),
      false,
      `C19 schema contains ${prohibited.field}`,
    );
  }
  assert.doesNotMatch(
    databaseSchema,
    /\b(?:json|jsonb|project_progress|invoice|business_metric|metadata|payload|body)\b/i,
  );
});
