import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  evaluateC11RetrievalQuality,
} from "../lib/c11-retrieval-quality.mjs";

const frozenBenchmark = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c11/synthetic-retrieval-quality-benchmark.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("C11 quality benchmark freezes formulas, denominators, and thresholds before execution", () => {
  assert.equal(
    frozenBenchmark.schemaVersion,
    "c11-synthetic-retrieval-quality-benchmark.v1",
  );
  assert.equal(frozenBenchmark.acceptanceCriterionId, "C11-AC04");
  assert.equal(frozenBenchmark.evidenceGroupId, "P1-B10");
  assert.equal(frozenBenchmark.scope, "P1_SYNTHETIC_ONLY");
  assert.deepEqual(frozenBenchmark.metricPolicy, {
    k: 3,
    positiveQueryDenominator:
      "queries where expectedStatus is ANSWERABLE",
    negativeQueryDenominator:
      "queries where expectedStatus is REFUSED",
    precisionAtKFormula:
      "truePositiveCount / min(k, returnedEvidenceCount); zero when returnedEvidenceCount is zero",
    recallAtKFormula:
      "truePositiveCount / relevantEvidenceCount",
    macroPrecisionAtKFormula:
      "sum(query precisionAtK) / positiveQueryCount",
    macroRecallAtKFormula:
      "sum(query recallAtK) / positiveQueryCount",
    microPrecisionAtKFormula:
      "sum(truePositiveCount) / sum(min(k, returnedEvidenceCount))",
    microRecallAtKFormula:
      "sum(truePositiveCount) / sum(relevantEvidenceCount)",
    statusAccuracyFormula:
      "queries with observedStatus equal to expectedStatus / allQueryCount",
    negativeRefusalAccuracyFormula:
      "negative queries observed as REFUSED with zero evidence / negativeQueryCount",
    thresholds: {
      minimumMacroPrecisionAtK: 0.8,
      minimumMacroRecallAtK: 0.95,
      minimumMicroPrecisionAtK: 0.8,
      minimumMicroRecallAtK: 0.95,
      minimumStatusAccuracy: 1,
      minimumNegativeRefusalAccuracy: 1,
    },
  });
  assert.equal(frozenBenchmark.queries.length, 10);
  assert.equal(
    frozenBenchmark.queries.filter(
      ({ expectedStatus }) => expectedStatus === "ANSWERABLE",
    ).length,
    6,
  );
  assert.equal(
    frozenBenchmark.queries.filter(
      ({ expectedStatus }) => expectedStatus === "REFUSED",
    ).length,
    4,
  );
});

test("C11 quality evaluator uses the frozen per-query and aggregate denominators", () => {
  const benchmark = {
    schemaVersion: "c11-synthetic-retrieval-quality-benchmark.v1",
    workPackageId: "C11",
    acceptanceCriterionId: "C11-AC04",
    evidenceGroupId: "P1-B10",
    scope: "P1_SYNTHETIC_ONLY",
    metricPolicy: {
      k: 2,
      thresholds: {
        minimumMacroPrecisionAtK: 0.7,
        minimumMacroRecallAtK: 0.7,
        minimumMicroPrecisionAtK: 0.6,
        minimumMicroRecallAtK: 0.6,
        minimumStatusAccuracy: 1,
        minimumNegativeRefusalAccuracy: 1,
      },
    },
    queries: [
      {
        id: "positive-two-relevant",
        expectedStatus: "ANSWERABLE",
        relevantEvidence: [
          { documentId: "doc-a", chunkOrdinal: 1 },
          { documentId: "doc-a", chunkOrdinal: 2 },
        ],
      },
      {
        id: "positive-one-relevant",
        expectedStatus: "ANSWERABLE",
        relevantEvidence: [
          { documentId: "doc-b", chunkOrdinal: 1 },
        ],
      },
      {
        id: "negative",
        expectedStatus: "REFUSED",
        relevantEvidence: [],
      },
    ],
  };
  const report = evaluateC11RetrievalQuality({
    benchmark,
    results: [
      {
        id: "positive-two-relevant",
        observedStatus: "ANSWERABLE",
        returnedEvidence: [
          { documentId: "doc-a", chunkOrdinal: 1 },
          { documentId: "doc-x", chunkOrdinal: 1 },
        ],
      },
      {
        id: "positive-one-relevant",
        observedStatus: "ANSWERABLE",
        returnedEvidence: [
          { documentId: "doc-b", chunkOrdinal: 1 },
        ],
      },
      {
        id: "negative",
        observedStatus: "REFUSED",
        returnedEvidence: [],
      },
    ],
  });

  assert.deepEqual(
    report.perQuery.map(
      ({
        id,
        truePositiveCount,
        retrievedDenominator,
        relevantDenominator,
        precisionAtK,
        recallAtK,
      }) => ({
        id,
        truePositiveCount,
        retrievedDenominator,
        relevantDenominator,
        precisionAtK,
        recallAtK,
      }),
    ),
    [
      {
        id: "positive-two-relevant",
        truePositiveCount: 1,
        retrievedDenominator: 2,
        relevantDenominator: 2,
        precisionAtK: 0.5,
        recallAtK: 0.5,
      },
      {
        id: "positive-one-relevant",
        truePositiveCount: 1,
        retrievedDenominator: 1,
        relevantDenominator: 1,
        precisionAtK: 1,
        recallAtK: 1,
      },
      {
        id: "negative",
        truePositiveCount: 0,
        retrievedDenominator: 0,
        relevantDenominator: 0,
        precisionAtK: null,
        recallAtK: null,
      },
    ],
  );
  assert.equal(report.metrics.macroPrecisionAtK, 0.75);
  assert.equal(report.metrics.macroRecallAtK, 0.75);
  assert.equal(report.metrics.microPrecisionAtK, 0.66666667);
  assert.equal(report.metrics.microRecallAtK, 0.66666667);
  assert.equal(report.metrics.statusAccuracy, 1);
  assert.equal(report.metrics.negativeRefusalAccuracy, 1);
  assert.equal(report.passed, true);
});
