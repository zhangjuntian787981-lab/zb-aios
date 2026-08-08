import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} 必须是对象。`);
  }
}

function requireArray(value, label) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} 必须是数组。`);
  }
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function average(values) {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function evaluateHumanBaseline(config, suite, report) {
  const validation = report.human_baseline_validation;
  const expectedIds = suite.cases.map(({ id }) => id).sort();
  const coveredIds = Array.isArray(validation?.covered_case_ids)
    ? uniqueSorted(validation.covered_case_ids)
    : [];
  const valid =
    validation?.status === config.human_baseline.accepted_status &&
    validation?.source === config.human_baseline.accepted_source &&
    JSON.stringify(coveredIds) === JSON.stringify(expectedIds);

  return {
    valid,
    status: validation?.status ?? "MISSING",
    source: validation?.source ?? "MISSING",
    coveredCaseCount: coveredIds.length,
    requiredCaseCount: expectedIds.length,
  };
}

export function evaluateRelease({
  config,
  suite,
  report,
  expectedReleaseDigest,
}) {
  requireObject(config, "config");
  requireObject(suite, "suite");
  requireObject(report, "report");
  requireArray(suite.cases, "suite.cases");
  requireArray(report.case_results, "report.case_results");
  requireArray(
    config.zero_tolerance_rule_ids,
    "config.zero_tolerance_rule_ids",
  );

  const qualityFailures = [];
  const zeroToleranceFailures = [];
  const zeroToleranceRuleIds = new Set(config.zero_tolerance_rule_ids);
  const resultByCaseId = new Map();
  const duplicateResultIds = [];

  for (const result of report.case_results) {
    if (resultByCaseId.has(result.case_id)) {
      duplicateResultIds.push(result.case_id);
    }
    resultByCaseId.set(result.case_id, result);
  }
  for (const caseId of uniqueSorted(duplicateResultIds)) {
    qualityFailures.push(`${caseId} 出现重复结果。`);
  }

  const suiteCaseIds = new Set(suite.cases.map(({ id }) => id));
  for (const result of report.case_results) {
    if (!suiteCaseIds.has(result.case_id)) {
      qualityFailures.push(`${result.case_id} 不属于冻结测试集。`);
    }
  }

  const scores = [];
  const scoresByCategory = new Map();
  const minimumCaseScore = config.thresholds.minimum_case_score;

  for (const testCase of suite.cases) {
    const result = resultByCaseId.get(testCase.id);
    const isZeroTolerance =
      testCase.severity === "ZERO_TOLERANCE";
    if (
      isZeroTolerance &&
      !zeroToleranceRuleIds.has(testCase.zero_tolerance_rule_id)
    ) {
      zeroToleranceFailures.push(testCase.id);
    }
    const scoreIsValid =
      typeof result?.score === "number" &&
      Number.isFinite(result.score) &&
      result.score >= 0 &&
      result.score <= 1;
    const casePassed =
      result?.outcome === "PASS" &&
      scoreIsValid &&
      result.score >= minimumCaseScore;

    if (scoreIsValid) {
      scores.push(result.score);
      const categoryScores = scoresByCategory.get(testCase.category) ?? [];
      categoryScores.push(result.score);
      scoresByCategory.set(testCase.category, categoryScores);
    }

    if (!casePassed) {
      if (isZeroTolerance) {
        zeroToleranceFailures.push(testCase.id);
      } else if (!result) {
        qualityFailures.push(`${testCase.id} 缺少结果。`);
      } else if (!scoreIsValid) {
        qualityFailures.push(`${testCase.id} 分数无效。`);
      } else if (result.outcome !== "PASS") {
        qualityFailures.push(`${testCase.id} 未通过。`);
      } else {
        qualityFailures.push(
          `${testCase.id} 分数 ${result.score} 低于单例阈值 ${minimumCaseScore}。`,
        );
      }
    }
  }

  const categoryScores = {};
  for (const [category, values] of scoresByCategory) {
    categoryScores[category] = average(values);
  }
  for (const [category, threshold] of Object.entries(
    config.thresholds.minimum_category_scores,
  )) {
    const categoryScore = categoryScores[category];
    if (typeof categoryScore !== "number" || categoryScore < threshold) {
      qualityFailures.push(
        `${category} 类别分数 ${categoryScore ?? "缺失"} 低于阈值 ${threshold}。`,
      );
    }
  }

  const overallScore = average(scores);
  if (overallScore < config.thresholds.minimum_overall_score) {
    qualityFailures.push(
      `总分 ${overallScore} 低于阈值 ${config.thresholds.minimum_overall_score}。`,
    );
  }
  if (report.suite_id !== suite.id) {
    qualityFailures.push("报告 suite_id 与冻结测试集不一致。");
  }
  const digestPattern = /^sha256:[0-9a-f]{64}$/;
  if (!digestPattern.test(expectedReleaseDigest ?? "")) {
    qualityFailures.push("预期 release_digest 缺失或格式无效。");
  }
  if (!digestPattern.test(report.release_digest ?? "")) {
    qualityFailures.push("报告 release_digest 缺失或格式无效。");
  } else if (report.release_digest !== expectedReleaseDigest) {
    qualityFailures.push("报告 release_digest 与预期发布不一致。");
  }

  const humanBaseline = evaluateHumanBaseline(config, suite, report);
  if (!humanBaseline.valid) {
    qualityFailures.push(
      "人工基线未由人工完整验证；自动 Judge 不能替代人工基线。",
    );
  }

  const blockedIds = uniqueSorted(zeroToleranceFailures);
  const failedReasons = uniqueSorted(qualityFailures);
  const decision =
    blockedIds.length > 0
      ? "BLOCKED"
      : failedReasons.length > 0
        ? "FAIL"
        : "PASS";

  return {
    schemaVersion: "1.0",
    suiteId: suite.id,
    releaseDigest: report.release_digest ?? null,
    decision,
    zeroToleranceFailures: blockedIds,
    qualityFailures: failedReasons,
    humanBaseline,
    metrics: {
      caseCount: suite.cases.length,
      reportedCaseCount: report.case_results.length,
      overallScore,
      categoryScores,
    },
    automatedJudgeUsedForDecision: false,
  };
}

async function loadJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function main() {
  const reportPath = process.argv[2];
  const expectedReleaseDigest = process.argv[3];
  if (!reportPath || !expectedReleaseDigest) {
    console.error(
      "用法：node scripts/f04-release-gate.mjs <evaluation-report.json> <expected-release-digest>",
    );
    process.exitCode = 2;
    return;
  }
  const [config, suite, report] = await Promise.all([
    loadJson("implementation/p0/f04/release-gate.config.v1.json"),
    loadJson("implementation/p0/f04/frozen-evaluation-cases.v1.json"),
    loadJson(reportPath),
  ]);
  const result = evaluateRelease({
    config,
    suite,
    report,
    expectedReleaseDigest,
  });
  console.log(JSON.stringify(result, null, 2));
  if (result.decision === "FAIL") process.exitCode = 2;
  if (result.decision === "BLOCKED") process.exitCode = 3;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}
