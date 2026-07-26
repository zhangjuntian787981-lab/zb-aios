import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createC13SyntheticSkillCatalog,
} from "../lib/c13-synthetic-skill-catalog.mjs";
import { evaluateRelease } from "../scripts/f04-release-gate.mjs";

const raw = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c13/synthetic-skill-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const reportBytes = await readFile(
  new URL(
    "../implementation/p1/c13/synthetic-evaluation-reports.v1.json",
    import.meta.url,
  ),
);
const reportBundle = JSON.parse(reportBytes);
const [
  f04Config,
  f04Suite,
  humanBaselineCandidate,
  humanBaselineGovernance,
] = await Promise.all(
  [
    "release-gate.config.v1.json",
    "frozen-evaluation-cases.v1.json",
    "human-baseline-candidate.v1.json",
  ].map(async (name) =>
    JSON.parse(
      await readFile(
        new URL(`../implementation/p0/f04/${name}`, import.meta.url),
        "utf8",
      ),
    ),
  ).concat(
    readFile(
      new URL(
        "../implementation/p1/c13/f04-human-baseline-governance-reference.v1.json",
        import.meta.url,
      ),
      "utf8",
    ).then(JSON.parse),
  ),
);

test("C13 catalog is frozen to three Synthetic Tenants and the F04 suite", () => {
  const catalog = createC13SyntheticSkillCatalog(raw);
  assert.deepEqual(catalog.summary(), {
    tenantCount: 3,
    releaseCount: 4,
    suiteId: "f04-frozen-evaluation-suite-v1",
    suiteSha256:
      "sha256:628503bc3001d50d8eb30d89ce4f45e184918c63ba4fc0e8d3f6594d345a3259",
    humanBaselineStatus: "VALIDATED",
    scriptExecution: "DISABLED",
    allowedToolsGrantAuthorization: false,
  });
});

test("C13 catalog binds source review and evaluation to tenant, version and digest", () => {
  const catalog = createC13SyntheticSkillCatalog(raw);
  const tenant = raw.tenants[0];
  const release = tenant.releases[0];
  assert.equal(
    catalog.verifySource({
      tenantId: tenant.tenantId,
      manifest: release.manifest,
      contentSha256: release.contentSha256,
      sourceReviewRef: release.sourceReviewRef,
      sourceReviewSha256: release.sourceReviewSha256,
    }).contentSha256,
    release.contentSha256,
  );
  assert.equal(
    catalog.evaluate({
      tenantId: tenant.tenantId,
      name: release.manifest.name,
      version: release.manifest.version,
      contentSha256: release.contentSha256,
      suiteId: raw.frozenEvaluationSuite.suiteId,
      suiteSha256: raw.frozenEvaluationSuite.suiteSha256,
    }).status,
    "BLOCKED",
  );
  assert.throws(
    () =>
      catalog.evaluate({
        tenantId: tenant.tenantId,
        name: release.manifest.name,
        version: release.manifest.version,
        contentSha256:
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        suiteId: raw.frozenEvaluationSuite.suiteId,
        suiteSha256: raw.frozenEvaluationSuite.suiteSha256,
      }),
    { code: "EVALUATION_UNAVAILABLE" },
  );
});

test("C13 recomputes the frozen F04 gate and blocks missing case evidence", () => {
  const reportSha256 = `sha256:${createHash("sha256")
    .update(reportBytes)
    .digest("hex")}`;
  assert.equal(reportSha256, raw.evaluationReportBundle.sha256);
  assert.equal(
    reportBundle.humanBaselineCandidateSha256,
    raw.frozenEvaluationSuite.humanBaselineCandidateSha256,
  );
  assert.equal(humanBaselineCandidate.status, "PENDING_HUMAN_VALIDATION");
  assert.equal(
    reportBundle.humanBaselineStatus,
    humanBaselineGovernance.decision,
  );
  assert.equal(
    humanBaselineGovernance.candidateSha256,
    raw.frozenEvaluationSuite.humanBaselineCandidateSha256,
  );
  assert.equal(reportBundle.automaticJudgeCanApprove, false);
  assert.equal(reportBundle.promptfooStatus, "NOT_VERIFIED");

  for (const tenant of raw.tenants) {
    for (const release of tenant.releases) {
      const report = reportBundle.reports.find(
        ({ reportId }) => reportId === release.evaluation.reportId,
      );
      assert.ok(report);
      assert.equal(report.tenantId, tenant.tenantId);
      assert.equal(report.skillName, release.manifest.name);
      assert.equal(report.skillVersion, release.manifest.version);
      assert.equal(report.releaseDigest, release.contentSha256);
      const gate = evaluateRelease({
        config: f04Config,
        suite: f04Suite,
        report: {
          suite_id: f04Suite.id,
          release_digest: report.releaseDigest,
          human_baseline_validation: {
            status: humanBaselineGovernance.decision,
            source: humanBaselineGovernance.decisionSource,
            covered_case_ids:
              humanBaselineGovernance.coveredCaseIds,
          },
          case_results: report.caseResults.map((result) => ({
            case_id: result.caseId,
            outcome: result.outcome,
            score: result.score,
          })),
        },
      });
      assert.equal(gate.decision, report.decision);
      assert.equal(
        gate.metrics.reportedCaseCount,
        report.reportedCaseCount,
      );
      assert.equal(release.evaluation.status, gate.decision);
      assert.equal(release.evaluation.reportSha256, reportSha256);
      const runtimeReport = createC13SyntheticSkillCatalog(raw).evaluate({
        tenantId: tenant.tenantId,
        name: release.manifest.name,
        version: release.manifest.version,
        contentSha256: release.contentSha256,
        suiteId: raw.frozenEvaluationSuite.suiteId,
        suiteSha256: raw.frozenEvaluationSuite.suiteSha256,
      });
      assert.equal(runtimeReport.tenantId, tenant.tenantId);
      assert.equal(runtimeReport.skillName, release.manifest.name);
      assert.equal(runtimeReport.skillVersion, release.manifest.version);
      assert.equal(runtimeReport.releaseDigest, release.contentSha256);
      assert.equal(
        runtimeReport.humanBaselineDecisionSha256,
        reportBundle.humanBaselineDecisionSha256,
      );
      assert.equal(runtimeReport.reportedCaseCount, 0);
      assert.deepEqual(runtimeReport.caseResults, []);
    }
  }
});

test("C13 source review references are real file hashes", async () => {
  const expected = new Map([
    [
      "evidence://c13/source-review/analyze-synthetic-order/1.0.0",
      "../implementation/p1/c13/source-reviews/analyze-synthetic-order-1.0.0.review.v1.json",
    ],
    [
      "evidence://c13/source-review/analyze-synthetic-order/1.1.0",
      "../implementation/p1/c13/source-reviews/analyze-synthetic-order-1.1.0.review.v1.json",
    ],
  ]);
  for (const release of raw.tenants.flatMap(({ releases }) => releases)) {
    const bytes = await readFile(
      new URL(expected.get(release.sourceReviewRef), import.meta.url),
    );
    assert.equal(
      `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      release.sourceReviewSha256,
    );
  }
});
