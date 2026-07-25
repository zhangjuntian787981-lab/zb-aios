import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { evaluateRelease } from "../scripts/f04-release-gate.mjs";

const baseUrl = new URL("../implementation/p0/f04/", import.meta.url);

async function loadJson(relativePath) {
  return JSON.parse(await readFile(new URL(relativePath, baseUrl), "utf8"));
}

async function loadFixtureSet() {
  const [config, suite, passReport, failReport, blockedReport] =
    await Promise.all([
      loadJson("release-gate.config.v1.json"),
      loadJson("frozen-evaluation-cases.v1.json"),
      loadJson("examples/pass-report.v1.json"),
      loadJson("examples/fail-report.v1.json"),
      loadJson("examples/blocked-report.v1.json"),
    ]);
  return { config, suite, passReport, failReport, blockedReport };
}

test("frozen suite covers every required F04 abuse category", async () => {
  const { suite } = await loadFixtureSet();
  const categories = new Set(suite.cases.map(({ category }) => category));

  assert.equal(suite.freeze.status, "FROZEN");
  assert.equal(suite.freeze.change_policy, "NEW_VERSION_REQUIRED");
  assert.deepEqual(
    [
      "normal",
      "refusal",
      "cross_tenant",
      "unauthorized_access",
      "prompt_injection",
      "approval_bypass",
      "resource_abuse",
      "enterprise_data_early_entry",
    ].filter((category) => !categories.has(category)),
    [],
  );
});

test("passing frozen evidence returns PASS", async () => {
  const { config, suite, passReport } = await loadFixtureSet();
  const result = evaluateRelease({ config, suite, report: passReport });

  assert.equal(result.decision, "PASS");
  assert.deepEqual(result.zeroToleranceFailures, []);
  assert.deepEqual(result.qualityFailures, []);
  assert.equal(result.humanBaseline.valid, true);
  assert.equal(result.automatedJudgeUsedForDecision, false);
});

test("automatic judge cannot replace a validated human baseline", async () => {
  const { config, suite, passReport } = await loadFixtureSet();
  const withoutHumanBaseline = structuredClone(passReport);
  withoutHumanBaseline.human_baseline_validation = {
    status: "NOT_VALIDATED",
    source: "AUTOMATIC_JUDGE",
    covered_case_ids: suite.cases.map(({ id }) => id),
  };
  withoutHumanBaseline.automatic_judge = {
    status: "PASS",
    overall_score: 1,
  };

  const result = evaluateRelease({
    config,
    suite,
    report: withoutHumanBaseline,
  });

  assert.equal(result.decision, "FAIL");
  assert.equal(result.humanBaseline.valid, false);
  assert.match(result.qualityFailures.join("\n"), /人工基线/);
  assert.equal(result.automatedJudgeUsedForDecision, false);
});

test("one zero-tolerance failure blocks release even with a high average", async () => {
  const { config, suite, passReport } = await loadFixtureSet();
  const report = structuredClone(passReport);
  const crossTenant = report.case_results.find(
    ({ case_id }) => case_id === "F04-E003",
  );
  crossTenant.outcome = "FAIL";
  crossTenant.score = 0.99;

  const result = evaluateRelease({ config, suite, report });

  assert.equal(result.decision, "BLOCKED");
  assert.deepEqual(result.zeroToleranceFailures, ["F04-E003"]);
  assert.ok(result.metrics.overallScore > 0.98);
});

test("zero-tolerance severity fails closed even if configuration omits its rule", async () => {
  const { config, suite, passReport } = await loadFixtureSet();
  const incompleteConfig = structuredClone(config);
  incompleteConfig.zero_tolerance_rule_ids =
    incompleteConfig.zero_tolerance_rule_ids.filter(
      (ruleId) => ruleId !== "ZT-01",
    );
  const report = structuredClone(passReport);
  report.case_results.find(
    ({ case_id }) => case_id === "F04-E003",
  ).outcome = "FAIL";

  const result = evaluateRelease({
    config: incompleteConfig,
    suite,
    report,
  });

  assert.equal(result.decision, "BLOCKED");
  assert.deepEqual(result.zeroToleranceFailures, ["F04-E003", "F04-E004"]);
});

test("a missing zero-tolerance case fails closed as BLOCKED", async () => {
  const { config, suite, passReport } = await loadFixtureSet();
  const report = structuredClone(passReport);
  report.case_results = report.case_results.filter(
    ({ case_id }) => case_id !== "F04-E006",
  );

  const result = evaluateRelease({ config, suite, report });

  assert.equal(result.decision, "BLOCKED");
  assert.deepEqual(result.zeroToleranceFailures, ["F04-E006"]);
});

test("ordinary quality below a configured threshold returns FAIL", async () => {
  const { config, suite, passReport } = await loadFixtureSet();
  const report = structuredClone(passReport);
  const normal = report.case_results.find(
    ({ case_id }) => case_id === "F04-E001",
  );
  normal.score = 0.4;

  const result = evaluateRelease({ config, suite, report });

  assert.equal(result.decision, "FAIL");
  assert.deepEqual(result.zeroToleranceFailures, []);
  assert.match(result.qualityFailures.join("\n"), /F04-E001/);
});

test("checked-in PASS, FAIL and BLOCKED examples match the pure evaluator", async () => {
  const { config, suite, passReport, failReport, blockedReport } =
    await loadFixtureSet();

  assert.equal(
    evaluateRelease({ config, suite, report: passReport }).decision,
    "PASS",
  );
  assert.equal(
    evaluateRelease({ config, suite, report: failReport }).decision,
    "FAIL",
  );
  assert.equal(
    evaluateRelease({ config, suite, report: blockedReport }).decision,
    "BLOCKED",
  );
});

test("fixed inputs are repeatable and are not mutated", async () => {
  const { config, suite, passReport } = await loadFixtureSet();
  const original = structuredClone({ config, suite, report: passReport });

  const first = evaluateRelease({ config, suite, report: passReport });
  const second = evaluateRelease({ config, suite, report: passReport });

  assert.deepEqual(second, first);
  assert.deepEqual({ config, suite, report: passReport }, original);
});
