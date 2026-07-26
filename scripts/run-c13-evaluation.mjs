#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  createC13SyntheticSkillCatalog,
} from "../lib/c13-synthetic-skill-catalog.mjs";
import { evaluateRelease } from "./f04-release-gate.mjs";

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function readJson(root, path) {
  const bytes = await readFile(resolve(root, path));
  return { bytes, value: JSON.parse(bytes) };
}

export async function verifyC13DeterministicEvaluation({
  root = process.cwd(),
  configPath =
    "implementation/p1/c13/deterministic-evaluation.config.v1.json",
} = {}) {
  const { value: config } = await readJson(root, configPath);
  requireCondition(
    config.schemaVersion ===
      "c13-deterministic-evaluation-config.v1" &&
      config.workPackage === "C13" &&
      config.phase === "P1_SYNTHETIC_ONLY" &&
      config.engine === "BUILTIN_F04_DETERMINISTIC_GATE" &&
      config.engineClaim === "FROZEN_GATE_EQUIVALENCE_ONLY" &&
      config.promptfooStatus === "NOT_VERIFIED" &&
      config.promptfooEvidenceAccepted === false &&
      config.promptfooNoGoRule ===
        "NO_GO_IF_PROMPTFOO_EXECUTION_IS_CLAIMED_WITHOUT_MACHINE_EVIDENCE",
    "C13 deterministic evaluation boundary is invalid.",
  );

  const [catalogInput, reportInput, governanceInput, gateInput, suiteInput] =
    await Promise.all([
      readJson(root, config.paths.catalog),
      readJson(root, config.paths.reportBundle),
      readJson(root, config.paths.governanceReference),
      readJson(root, config.paths.gateConfig),
      readJson(root, config.paths.suite),
    ]);
  const catalogRaw = catalogInput.value;
  const reportBundle = reportInput.value;
  const governance = governanceInput.value;
  const catalog = createC13SyntheticSkillCatalog(catalogRaw);
  const summary = catalog.summary();

  requireCondition(
    sha256(reportInput.bytes) ===
      catalogRaw.evaluationReportBundle.sha256,
    "Evaluation report bundle hash mismatch.",
  );
  requireCondition(
    sha256(governanceInput.bytes) ===
      reportBundle.humanBaselineDecisionSha256 &&
      reportBundle.humanBaselineDecisionSha256 ===
        catalogRaw.frozenEvaluationSuite
          .humanBaselineDecisionSha256,
    "Human baseline decision hash mismatch.",
  );
  requireCondition(
    governance.decision === "VALIDATED" &&
      governance.decisionSource === "HUMAN" &&
      governance.candidateSha256 ===
        reportBundle.humanBaselineCandidateSha256 &&
      governance.externalEventId === null &&
      governance.externalEventRecordedAt === null &&
      governance.externalEventArchiveStatus ===
        "PENDING_G1_ARCHIVE",
    "Human baseline governance reference is invalid.",
  );
  requireCondition(
    sha256(gateInput.bytes) === reportBundle.gateConfigSha256 &&
      sha256(suiteInput.bytes) === reportBundle.suiteSha256,
    "Frozen F04 input hash mismatch.",
  );

  for (const artifact of config.sourceReviewArtifacts) {
    const input = await readJson(root, artifact.path);
    requireCondition(
      sha256(input.bytes) === artifact.sha256 &&
        input.value.reviewRef === artifact.ref &&
        input.value.decision === "PASS" &&
        input.value.repositoryEnforcementStatus ===
          "NOT_VERIFIED",
      `Source review artifact mismatch: ${artifact.ref}`,
    );
  }

  const reportsById = new Map(
    reportBundle.reports.map((report) => [report.reportId, report]),
  );
  let checked = 0;
  let blocked = 0;
  let reportedCaseCount = 0;
  for (const tenant of catalogRaw.tenants) {
    for (const release of tenant.releases) {
      const report = reportsById.get(release.evaluation.reportId);
      requireCondition(report, "Evaluation report is missing.");
      const gate = evaluateRelease({
        config: gateInput.value,
        suite: suiteInput.value,
        report: {
          suite_id: reportBundle.suiteId,
          release_digest: report.releaseDigest,
          human_baseline_validation: {
            status: governance.decision,
            source: governance.decisionSource,
            covered_case_ids: governance.coveredCaseIds,
          },
          case_results: report.caseResults.map((result) => ({
            case_id: result.caseId,
            outcome: result.outcome,
            score: result.score,
          })),
        },
      });
      const runtimeReport = catalog.evaluate({
        tenantId: tenant.tenantId,
        name: release.manifest.name,
        version: release.manifest.version,
        contentSha256: release.contentSha256,
        suiteId: reportBundle.suiteId,
        suiteSha256: reportBundle.suiteSha256,
      });
      requireCondition(
        gate.decision === config.expected.releaseDecision &&
          report.decision === config.expected.releaseDecision &&
          report.tenantId === tenant.tenantId &&
          report.skillName === release.manifest.name &&
          report.skillVersion === release.manifest.version &&
          report.releaseDigest === release.contentSha256 &&
          report.reportedCaseCount ===
            config.expected.reportedCaseCount &&
          report.reasonCode === config.expected.reasonCode &&
          runtimeReport.status === config.expected.releaseDecision &&
          runtimeReport.tenantId === tenant.tenantId &&
          runtimeReport.skillName === release.manifest.name &&
          runtimeReport.skillVersion === release.manifest.version &&
          runtimeReport.releaseDigest === release.contentSha256 &&
          runtimeReport.reportedCaseCount ===
            config.expected.reportedCaseCount &&
          runtimeReport.reasonCode === config.expected.reasonCode,
        `Release evaluation binding failed: ${release.evaluation.reportId}`,
      );
      checked += 1;
      blocked += runtimeReport.status === "BLOCKED" ? 1 : 0;
      reportedCaseCount += runtimeReport.reportedCaseCount;
    }
  }
  requireCondition(
    summary.tenantCount === config.expected.tenantCount &&
      checked === config.expected.releaseCount &&
      blocked === config.expected.releaseCount &&
      summary.suiteId === config.expected.suiteId &&
      reportBundle.caseCount === config.expected.caseCount &&
      summary.humanBaselineStatus ===
        config.expected.humanBaselineStatus &&
      reportedCaseCount === 0,
    "C13 deterministic evaluation summary mismatch.",
  );

  return Object.freeze({
    status: "PASS",
    workPackage: "C13",
    phase: "P1_SYNTHETIC_ONLY",
    engine: config.engine,
    engineClaim: config.engineClaim,
    promptfooStatus: config.promptfooStatus,
    promptfooEvidenceAccepted: false,
    releasesChecked: checked,
    blockedReleases: blocked,
    reportedCaseCount,
    externalGovernanceEventArchiveStatus:
      governance.externalEventArchiveStatus,
  });
}

async function main() {
  try {
    const result = await verifyC13DeterministicEvaluation({
      configPath: process.argv[2],
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`C13 deterministic evaluation failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  await main();
}
