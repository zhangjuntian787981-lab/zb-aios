function fail(message) {
  throw new Error(`C11 retrieval quality: ${message}`);
}

function evidenceKey(value) {
  if (
    typeof value?.documentId !== "string" ||
    !value.documentId ||
    !Number.isSafeInteger(value?.chunkOrdinal) ||
    value.chunkOrdinal < 1
  ) {
    fail("evidence labels must bind a document and positive Chunk ordinal.");
  }
  return `${value.documentId}\u0000${value.chunkOrdinal}`;
}

function ratio(numerator, denominator) {
  return Number((numerator / denominator).toFixed(8));
}

export function evaluateC11RetrievalQuality({ benchmark, results }) {
  if (
    benchmark?.schemaVersion !==
      "c11-synthetic-retrieval-quality-benchmark.v1" ||
    benchmark?.workPackageId !== "C11" ||
    benchmark?.acceptanceCriterionId !== "C11-AC04" ||
    benchmark?.evidenceGroupId !== "P1-B10" ||
    benchmark?.scope !== "P1_SYNTHETIC_ONLY" ||
    !Number.isSafeInteger(benchmark?.metricPolicy?.k) ||
    benchmark.metricPolicy.k < 1 ||
    !Array.isArray(benchmark?.queries) ||
    !Array.isArray(results)
  ) {
    fail("benchmark or result shape is invalid.");
  }
  const thresholdEntries = Object.entries(
    benchmark.metricPolicy.thresholds ?? {},
  );
  if (
    thresholdEntries.length !== 6 ||
    thresholdEntries.some(
      ([, value]) =>
        typeof value !== "number" || value < 0 || value > 1,
    )
  ) {
    fail("six frozen thresholds in the range 0..1 are required.");
  }
  const resultById = new Map();
  for (const result of results) {
    if (
      typeof result?.id !== "string" ||
      resultById.has(result.id) ||
      !["ANSWERABLE", "REFUSED"].includes(result?.observedStatus) ||
      !Array.isArray(result?.returnedEvidence)
    ) {
      fail("result cases must be unique and complete.");
    }
    resultById.set(result.id, result);
  }
  const queryIds = new Set();
  const perQuery = benchmark.queries.map((query) => {
    if (
      typeof query?.id !== "string" ||
      queryIds.has(query.id) ||
      !["ANSWERABLE", "REFUSED"].includes(query?.expectedStatus) ||
      !Array.isArray(query?.relevantEvidence)
    ) {
      fail("query cases must be unique and labelled.");
    }
    queryIds.add(query.id);
    const result = resultById.get(query.id);
    if (!result) fail(`result is missing for ${query.id}.`);
    const relevantKeys = query.relevantEvidence.map(evidenceKey);
    const returnedEvidence = result.returnedEvidence.slice(
      0,
      benchmark.metricPolicy.k,
    );
    const returnedKeys = returnedEvidence.map(evidenceKey);
    if (
      new Set(relevantKeys).size !== relevantKeys.length ||
      new Set(returnedKeys).size !== returnedKeys.length
    ) {
      fail(`duplicate evidence exists for ${query.id}.`);
    }
    if (
      (query.expectedStatus === "ANSWERABLE" &&
        relevantKeys.length === 0) ||
      (query.expectedStatus === "REFUSED" &&
        relevantKeys.length !== 0)
    ) {
      fail(`relevance labels do not match ${query.id} status.`);
    }
    const relevantSet = new Set(relevantKeys);
    const truePositiveCount = returnedKeys.filter((key) =>
      relevantSet.has(key),
    ).length;
    const retrievedDenominator = returnedKeys.length;
    const relevantDenominator = relevantKeys.length;
    const positive = query.expectedStatus === "ANSWERABLE";
    return Object.freeze({
      id: query.id,
      expectedStatus: query.expectedStatus,
      observedStatus: result.observedStatus,
      relevantEvidence: structuredClone(query.relevantEvidence),
      returnedEvidence: structuredClone(returnedEvidence),
      truePositiveCount,
      retrievedDenominator,
      relevantDenominator,
      precisionAtK: positive
        ? retrievedDenominator === 0
          ? 0
          : ratio(truePositiveCount, retrievedDenominator)
        : null,
      recallAtK: positive
        ? ratio(truePositiveCount, relevantDenominator)
        : null,
      statusCorrect: result.observedStatus === query.expectedStatus,
      refusalCorrect:
        !positive &&
        result.observedStatus === "REFUSED" &&
        returnedEvidence.length === 0,
    });
  });
  if (
    resultById.size !== queryIds.size ||
    [...resultById.keys()].some((id) => !queryIds.has(id))
  ) {
    fail("results contain an unknown query case.");
  }
  const positive = perQuery.filter(
    ({ expectedStatus }) => expectedStatus === "ANSWERABLE",
  );
  const negative = perQuery.filter(
    ({ expectedStatus }) => expectedStatus === "REFUSED",
  );
  if (positive.length === 0 || negative.length === 0) {
    fail("positive and negative query denominators are required.");
  }
  const sum = (values) =>
    values.reduce((total, value) => total + value, 0);
  const truePositives = sum(
    positive.map(({ truePositiveCount }) => truePositiveCount),
  );
  const retrieved = sum(
    positive.map(({ retrievedDenominator }) => retrievedDenominator),
  );
  const relevant = sum(
    positive.map(({ relevantDenominator }) => relevantDenominator),
  );
  const metrics = Object.freeze({
    macroPrecisionAtK: ratio(
      sum(positive.map(({ precisionAtK }) => precisionAtK)),
      positive.length,
    ),
    macroRecallAtK: ratio(
      sum(positive.map(({ recallAtK }) => recallAtK)),
      positive.length,
    ),
    microPrecisionAtK:
      retrieved === 0 ? 0 : ratio(truePositives, retrieved),
    microRecallAtK: ratio(truePositives, relevant),
    statusAccuracy: ratio(
      perQuery.filter(({ statusCorrect }) => statusCorrect).length,
      perQuery.length,
    ),
    negativeRefusalAccuracy: ratio(
      negative.filter(({ refusalCorrect }) => refusalCorrect).length,
      negative.length,
    ),
  });
  const thresholds = benchmark.metricPolicy.thresholds;
  const thresholdResults = Object.freeze({
    macroPrecisionAtK:
      metrics.macroPrecisionAtK >= thresholds.minimumMacroPrecisionAtK,
    macroRecallAtK:
      metrics.macroRecallAtK >= thresholds.minimumMacroRecallAtK,
    microPrecisionAtK:
      metrics.microPrecisionAtK >= thresholds.minimumMicroPrecisionAtK,
    microRecallAtK:
      metrics.microRecallAtK >= thresholds.minimumMicroRecallAtK,
    statusAccuracy:
      metrics.statusAccuracy >= thresholds.minimumStatusAccuracy,
    negativeRefusalAccuracy:
      metrics.negativeRefusalAccuracy >=
      thresholds.minimumNegativeRefusalAccuracy,
  });
  return Object.freeze({
    schemaVersion: "c11-retrieval-quality-report.v1",
    scope: "P1_SYNTHETIC_ONLY",
    k: benchmark.metricPolicy.k,
    positiveQueryCount: positive.length,
    negativeQueryCount: negative.length,
    perQuery: Object.freeze(perQuery),
    metrics,
    thresholds: structuredClone(thresholds),
    thresholdResults,
    passed: Object.values(thresholdResults).every(Boolean),
  });
}
