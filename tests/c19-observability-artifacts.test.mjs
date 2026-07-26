import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  parseTraceContext,
} from "../lib/c19-observability.mjs";

async function json(path) {
  return JSON.parse(
    await readFile(new URL(path, import.meta.url), "utf8"),
  );
}

const emission = await json(
  "../implementation/p1/c19/otel-emission-contract.v1.json",
);
const trace = await json(
  "../implementation/p1/c19/synthetic-trace-evidence.v1.json",
);
const cost = await json(
  "../implementation/p1/c19/synthetic-cost-variance-report.v1.json",
);
const dashboard = await json(
  "../implementation/p1/c19/grafana-dashboard.v1.json",
);
const slo = await json(
  "../implementation/p1/c19/slo-draft.v1.json",
);
const verification = await json(
  "../implementation/p1/c19/verification-matrix.v1.json",
);
const catalog = await json(
  "../implementation/p1/c19/synthetic-observability-catalog.v1.json",
);
const readme = await readFile(
  new URL("../implementation/p1/c19/README.md", import.meta.url),
  "utf8",
);
const prometheus = await readFile(
  new URL(
    "../implementation/p1/c19/prometheus-recording-and-alert-rules.v1.yaml",
    import.meta.url,
  ),
  "utf8",
);

test("OTel emission contract fixes low-cardinality labels and prohibits sensitive bodies", () => {
  assert.equal(emission.phase, "P1_SYNTHETIC_ONLY");
  assert.deepEqual(emission.metricLabelKeys, [
    "module",
    "operation",
    "signal_type",
    "status",
    "error_code",
  ]);
  for (const prohibited of [
    "tenant_id",
    "principal_id",
    "task_ref",
    "trace_id",
  ]) {
    assert.equal(emission.metricLabelKeys.includes(prohibited), false);
    assert.equal(
      emission.prohibitedMetricLabelKeys.includes(prohibited),
      true,
    );
  }
  for (const prohibited of [
    "prompt",
    "file",
    "tool_arguments",
    "credential",
  ]) {
    assert.equal(emission.prohibitedTelemetryFields.includes(prohibited), true);
  }
});

test("frozen trace evidence preserves one W3C trace and a strict parent chain", () => {
  let parentSpanId = trace.entryParentSpanId;
  for (const span of trace.spans) {
    const parsed = parseTraceContext({
      traceparent: span.traceparent,
      tracestate: span.tracestate,
    });
    assert.equal(parsed.traceId, trace.traceId);
    assert.equal(parsed.parentId, span.spanId);
    assert.equal(span.parentSpanId, parentSpanId);
    assert.deepEqual(Object.keys(span.metricLabels), [
      "module",
      "operation",
      "signal_type",
      "status",
      "error_code",
    ]);
    assert.equal(JSON.stringify(span.metricLabels).includes("stn_"), false);
    assert.equal(JSON.stringify(span.metricLabels).includes("tsk_"), false);
    parentSpanId = span.spanId;
  }
});

test("cost evidence reconciles Tenant, task, model, Tool and sandbox", () => {
  const rows = [
    ...cost.byModel,
    ...cost.byTool,
    ...cost.bySandbox,
  ];
  const total = (field) =>
    rows.reduce((sum, row) => sum + row[field], 0);
  assert.equal(cost.tenantId.startsWith("stn_"), true);
  assert.equal(cost.byTask.length, 1);
  assert.equal(cost.byPrincipal.length, 1);
  assert.deepEqual(
    rows.map((row) => row.unit),
    ["TOKEN", "CALL", "VCPU_MILLISECOND"],
  );
  assert.equal(
    total("bookedCostMicros"),
    cost.totals.bookedCostMicros,
  );
  assert.equal(
    total("supplierCostMicros"),
    cost.totals.supplierCostMicros,
  );
  assert.equal(
    total("varianceMicros"),
    cost.totals.varianceMicros,
  );
});

test("synthetic service fixtures contain canonical evidence digests, not placeholder hashes", () => {
  const hashes = catalog.tenants.flatMap((tenant) =>
    tenant.plans.flatMap((plan) => [
      plan.sourceEvidenceSha256,
      plan.auditEvidenceSha256,
    ]),
  );
  assert.equal(
    hashes.every(
      (hash) =>
        /^sha256:[0-9a-f]{64}$/.test(hash) &&
        !/^sha256:([0-9a-f])\1{63}$/.test(hash.slice(0, 71)),
    ),
    true,
  );
});

test("SLO, Prometheus and Grafana artifacts remain drafts with low-cardinality queries", () => {
  assert.equal(slo.approvalStatus, "DRAFT_NOT_APPROVED");
  assert.equal(slo.objectives.length >= 4, true);
  assert.equal(dashboard.title, "C19 Synthetic Observability");
  assert.equal(dashboard.panels.length >= 3, true);
  const queries = JSON.stringify(dashboard.panels) + prometheus;
  assert.doesNotMatch(
    queries,
    /\b(?:tenant_id|principal_id|task_ref|trace_id)\b/,
  );
  assert.match(prometheus, /aios_c19_signal_total/);
  assert.match(prometheus, /aios_c19_quota_utilization_ratio/);
  assert.match(prometheus, /aios_c19_quota_denial_total/);
  assert.match(prometheus, /C19SyntheticQuotaThreshold/);
  assert.match(prometheus, /C19SyntheticQuotaDenied/);
});

test("P1 implementation is closed while production deployment remains unverified", () => {
  assert.equal(verification.verificationStatus, "EVIDENCE_CANDIDATE");
  assert.equal(
    verification.upstreamEmitterIntegrationStatus,
    "P1_SYNTHETIC_WRAPPER_VERIFIED",
  );
  assert.equal(verification.implementationStatus, "IMPLEMENTED");
  assert.equal(
    verification.principalQuotaStatus,
    "P1_SYNTHETIC_VERIFIED",
  );
  assert.equal(
    verification.deployedAlertingStatus,
    "SERVICE_ALERTS_VERIFIED_RULES_NOT_DEPLOYED",
  );
  assert.deepEqual(verification.openP1Items, []);
  assert.match(readme, /C19 wrapper 在公开接口边界记录的 Span/);
  assert.match(readme, /Failed-Usage Receipt/);
  assert.match(readme, /没有修改 C14、C16 或 C18/);
});
