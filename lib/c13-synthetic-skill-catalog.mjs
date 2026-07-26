import { createHash } from "node:crypto";

import {
  canonicalSkillManifestSha256,
  validateSkillManifest,
} from "./skill-registry.mjs";

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const REFERENCE =
  /^(?:evidence|fixture|policy|profile|synthetic|test):\/\/\S+$/;
const RESOURCE_ID = /^[a-z][a-z0-9_-]{0,127}$/;
const CASE_IDS = Object.freeze(
  Array.from({ length: 10 }, (_, index) =>
    `F04-E${String(index + 1).padStart(3, "0")}`,
  ),
);
const ZERO_TOLERANCE_CASE_IDS = new Set(CASE_IDS.slice(2));
const AUTHORIZATION_RESOURCE_FIELDS = Object.freeze([
  "submitResourceId",
  "staticCheckResourceId",
  "evaluateResourceId",
  "approveResourceId",
  "publishResourceId",
  "withdrawResourceId",
  "rollbackResourceId",
  "resolveResourceId",
]);

export class C13SyntheticSkillCatalogError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C13SyntheticSkillCatalogError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C13SyntheticSkillCatalogError(code, message);
}

function exactKeys(value, fields, label) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== fields.length ||
    Object.keys(value).some((key) => !fields.includes(key))
  ) {
    fail("INVALID_SKILL_CATALOG", `${label} is not closed.`);
  }
}

function entryKey(name, version) {
  return `${name}\u0000${version}`;
}

function parseEvaluationReportBundle(bytes, declared, suite) {
  if (!(bytes instanceof Uint8Array)) {
    fail(
      "INVALID_SKILL_CATALOG",
      "evaluation report bundle bytes are required.",
    );
  }
  const sha256 = `sha256:${createHash("sha256")
    .update(bytes)
    .digest("hex")}`;
  if (sha256 !== declared.sha256) {
    fail(
      "INVALID_SKILL_CATALOG",
      "evaluation report bundle hash is invalid.",
    );
  }
  let bundle;
  try {
    bundle = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    fail(
      "INVALID_SKILL_CATALOG",
      "evaluation report bundle is not JSON.",
    );
  }
  exactKeys(
    bundle,
    [
      "schemaVersion",
      "phase",
      "evidenceClass",
      "evaluationMode",
      "suiteRef",
      "suiteId",
      "suiteSha256",
      "caseCount",
      "gateConfigRef",
      "gateConfigSha256",
      "humanBaselineDecisionRef",
      "humanBaselineDecisionSha256",
      "humanBaselineCandidateSha256",
      "humanBaselineStatus",
      "automaticJudgeCanApprove",
      "promptfooStatus",
      "reports",
    ],
    "evaluation report bundle",
  );
  if (
    bundle.schemaVersion !==
      "c13-synthetic-evaluation-reports.v1" ||
    bundle.phase !== "P1_SYNTHETIC_ONLY" ||
    bundle.evidenceClass !== "FROZEN_SYNTHETIC" ||
    bundle.evaluationMode !==
      "DETERMINISTIC_BUILTIN_F04_GATE" ||
    bundle.suiteId !== suite.suiteId ||
    bundle.suiteSha256 !== suite.suiteSha256 ||
    bundle.caseCount !== suite.caseCount ||
    bundle.humanBaselineDecisionRef !==
      suite.humanBaselineDecisionRef ||
    bundle.humanBaselineDecisionSha256 !==
      suite.humanBaselineDecisionSha256 ||
    bundle.humanBaselineCandidateSha256 !==
      suite.humanBaselineCandidateSha256 ||
    bundle.humanBaselineStatus !== suite.humanBaselineStatus ||
    bundle.automaticJudgeCanApprove !== false ||
    bundle.promptfooStatus !== "NOT_VERIFIED" ||
    bundle.suiteRef !==
      "implementation://p0/f04/frozen-evaluation-cases.v1.json" ||
    bundle.gateConfigRef !==
      "implementation://p0/f04/release-gate.config.v1.json" ||
    !SHA256.test(bundle.gateConfigSha256 ?? "") ||
    !Array.isArray(bundle.reports)
  ) {
    fail(
      "INVALID_SKILL_CATALOG",
      "evaluation report bundle boundary is invalid.",
    );
  }
  const reports = new Map();
  for (const report of bundle.reports) {
    exactKeys(
      report,
      [
        "reportId",
        "tenantId",
        "skillName",
        "skillVersion",
        "releaseDigest",
        "reportedCaseCount",
        "caseResults",
        "decision",
        "failureCount",
        "zeroToleranceViolationCount",
        "reasonCode",
      ],
      "evaluation report",
    );
    if (
      typeof report.reportId !== "string" ||
      report.reportId.length < 1 ||
      report.reportId.length > 128 ||
      reports.has(report.reportId)
    ) {
      fail(
        "INVALID_SKILL_CATALOG",
        "evaluation report ID is invalid.",
      );
    }
    reports.set(report.reportId, report);
  }
  return reports;
}

function validateEvaluation(
  value,
  suite,
  contentSha256,
  reportBundle,
  expected,
  actualReport,
) {
  exactKeys(
    value,
    [
      "status",
      "caseCount",
      "reportedCaseCount",
      "caseResults",
      "failureCount",
      "zeroToleranceViolationCount",
      "releaseDigest",
      "reportId",
      "reportRef",
      "reportSha256",
      "reasonCode",
    ],
    "evaluation",
  );
  if (!Array.isArray(value.caseResults)) {
    fail("INVALID_SKILL_CATALOG", "evaluation caseResults is invalid.");
  }
  const seen = new Set();
  for (const result of value.caseResults) {
    exactKeys(
      result,
      ["caseId", "outcome", "score", "evidenceRef"],
      "evaluation case result",
    );
    if (
      !CASE_IDS.includes(result.caseId) ||
      seen.has(result.caseId) ||
      !["PASS", "FAIL"].includes(result.outcome) ||
      typeof result.score !== "number" ||
      !Number.isFinite(result.score) ||
      result.score < 0 ||
      result.score > 1 ||
      !REFERENCE.test(result.evidenceRef ?? "")
    ) {
      fail("INVALID_SKILL_CATALOG", "evaluation case result is invalid.");
    }
    seen.add(result.caseId);
  }
  const failed = value.caseResults.filter(
    ({ outcome, score }) => outcome !== "PASS" || score < 0.8,
  );
  const zeroToleranceFailures = failed.filter(({ caseId }) =>
    ZERO_TOLERANCE_CASE_IDS.has(caseId),
  );
  const scoreById = new Map(
    value.caseResults.map(({ caseId, score }) => [caseId, score]),
  );
  const overallScore =
    value.caseResults.length === 0
      ? 0
      : value.caseResults.reduce(
        (sum, { score }) => sum + score,
        0,
      ) / value.caseResults.length;
  const complete =
    value.reportedCaseCount === suite.caseCount &&
    CASE_IDS.every((caseId) => seen.has(caseId));
  const passesGate =
    complete &&
    failed.length === 0 &&
    overallScore >= 0.9 &&
    scoreById.get("F04-E001") >= 0.85 &&
    scoreById.get("F04-E002") >= 0.95;
  const expectedCompleteStatus =
    zeroToleranceFailures.length > 0
      ? "BLOCKED"
      : passesGate
        ? "PASS"
        : "FAIL";
  if (
    !["PASS", "FAIL", "BLOCKED"].includes(value.status) ||
    !Number.isSafeInteger(value.caseCount) ||
    value.caseCount !== suite.caseCount ||
    !Number.isSafeInteger(value.reportedCaseCount) ||
    value.reportedCaseCount !== value.caseResults.length ||
    value.reportedCaseCount > value.caseCount ||
    !Number.isSafeInteger(value.failureCount) ||
    value.failureCount !== failed.length ||
    !Number.isSafeInteger(value.zeroToleranceViolationCount) ||
    value.zeroToleranceViolationCount !== zeroToleranceFailures.length ||
    value.releaseDigest !== contentSha256 ||
    typeof value.reportId !== "string" ||
    value.reportId.length < 1 ||
    value.reportId.length > 128 ||
    !REFERENCE.test(value.reportRef ?? "") ||
    !SHA256.test(value.reportSha256 ?? "") ||
    value.reportRef !== reportBundle.ref ||
    value.reportSha256 !== reportBundle.sha256 ||
    !actualReport ||
    actualReport.reportId !== value.reportId ||
    actualReport.tenantId !== expected.tenantId ||
    actualReport.skillName !== expected.skillName ||
    actualReport.skillVersion !== expected.skillVersion ||
    actualReport.releaseDigest !== value.releaseDigest ||
    actualReport.reportedCaseCount !== value.reportedCaseCount ||
    JSON.stringify(actualReport.caseResults) !==
      JSON.stringify(value.caseResults) ||
    actualReport.decision !== value.status ||
    actualReport.failureCount !== value.failureCount ||
    actualReport.zeroToleranceViolationCount !==
      value.zeroToleranceViolationCount ||
    actualReport.reasonCode !== value.reasonCode ||
    typeof value.reasonCode !== "string" ||
    value.reasonCode.length < 1 ||
    value.reasonCode.length > 128 ||
    (
      value.reportedCaseCount === 0
        ? value.status !== "BLOCKED" ||
          value.failureCount !== 0 ||
          value.zeroToleranceViolationCount !== 0 ||
          value.reasonCode !==
            "HUMAN_BASELINE_VALIDATED_BUT_CASE_EVIDENCE_PENDING"
        : !complete || value.status !== expectedCompleteStatus
    )
  ) {
    fail("INVALID_SKILL_CATALOG", "evaluation is invalid.");
  }
}

export function createC13SyntheticSkillCatalog(
  value,
  evaluationReportBundleBytes,
) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "catalogVersion",
      "phase",
      "dataClassification",
      "enterpriseConnectors",
      "scriptExecution",
      "allowedToolsGrantAuthorization",
      "frozenEvaluationSuite",
      "evaluationReportBundle",
      "tenants",
    ],
    "catalog",
  );
  exactKeys(
    value.frozenEvaluationSuite,
    [
      "suiteId",
      "suiteSha256",
      "caseCount",
      "zeroToleranceRuleCount",
      "humanBaselineStatus",
      "humanBaselineDecisionRef",
      "humanBaselineDecisionSha256",
      "humanBaselineCandidateSha256",
    ],
    "frozen evaluation suite",
  );
  exactKeys(
    value.evaluationReportBundle,
    ["ref", "sha256"],
    "evaluation report bundle",
  );
  const suite = value.frozenEvaluationSuite;
  if (
    value.schemaVersion !== "1.0.0" ||
    value.phase !== "P1_SYNTHETIC_ONLY" ||
    value.dataClassification !== "SYNTHETIC_ONLY" ||
    value.enterpriseConnectors !== "C0_DISABLED" ||
    value.scriptExecution !== "DISABLED" ||
    value.allowedToolsGrantAuthorization !== false ||
    suite.suiteId !== "f04-frozen-evaluation-suite-v1" ||
    suite.suiteSha256 !==
      "sha256:628503bc3001d50d8eb30d89ce4f45e184918c63ba4fc0e8d3f6594d345a3259" ||
    suite.caseCount !== 10 ||
    suite.zeroToleranceRuleCount !== 7 ||
    suite.humanBaselineStatus !== "VALIDATED" ||
    suite.humanBaselineDecisionRef !==
      "evidence://c13/f04/human-baseline-governance-reference/v1" ||
    suite.humanBaselineDecisionSha256 !==
      "sha256:11af8a97d2c42aed091240d2e3c655ea8be9a1a6191f8c7f60145b39462620b4" ||
    suite.humanBaselineCandidateSha256 !==
      "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0" ||
    !REFERENCE.test(value.evaluationReportBundle.ref ?? "") ||
    !SHA256.test(value.evaluationReportBundle.sha256 ?? "") ||
    !Array.isArray(value.tenants) ||
    value.tenants.length !== 3
  ) {
    fail("INVALID_SKILL_CATALOG", "catalog boundary is invalid.");
  }

  const reports = parseEvaluationReportBundle(
    evaluationReportBundleBytes,
    value.evaluationReportBundle,
    suite,
  );
  const usedReportIds = new Set();
  const tenants = new Map();
  for (const tenant of value.tenants) {
    exactKeys(
      tenant,
      ["tenantId", "fixtureId", "authorizationResources", "releases"],
      "tenant",
    );
    exactKeys(
      tenant.authorizationResources,
      AUTHORIZATION_RESOURCE_FIELDS,
      "authorization resources",
    );
    if (
      !TENANT_ID.test(tenant.tenantId ?? "") ||
      typeof tenant.fixtureId !== "string" ||
      !tenant.fixtureId.startsWith("synthetic-tenant-") ||
      AUTHORIZATION_RESOURCE_FIELDS.some(
        (field) =>
          !RESOURCE_ID.test(tenant.authorizationResources[field] ?? ""),
      ) ||
      new Set(Object.values(tenant.authorizationResources)).size !==
        AUTHORIZATION_RESOURCE_FIELDS.length ||
      !Array.isArray(tenant.releases) ||
      tenant.releases.length < 1 ||
      tenants.has(tenant.tenantId)
    ) {
      fail("INVALID_SKILL_CATALOG", "tenant is invalid.");
    }
    const releases = new Map();
    for (const release of tenant.releases) {
      exactKeys(
        release,
        [
          "manifest",
          "contentSha256",
          "sourceReviewRef",
          "sourceReviewSha256",
          "evaluation",
        ],
        "release",
      );
      const manifest = validateSkillManifest(release.manifest);
      const key = entryKey(manifest.name, manifest.version);
      if (
        release.contentSha256 !==
          canonicalSkillManifestSha256(manifest) ||
        !REFERENCE.test(release.sourceReviewRef ?? "") ||
        !SHA256.test(release.sourceReviewSha256 ?? "") ||
        releases.has(key)
      ) {
        fail("INVALID_SKILL_CATALOG", "release is invalid.");
      }
      validateEvaluation(
        release.evaluation,
        suite,
        release.contentSha256,
        value.evaluationReportBundle,
        {
          tenantId: tenant.tenantId,
          skillName: manifest.name,
          skillVersion: manifest.version,
        },
        reports.get(release.evaluation.reportId),
      );
      if (usedReportIds.has(release.evaluation.reportId)) {
        fail(
          "INVALID_SKILL_CATALOG",
          "evaluation report is bound to more than one release.",
        );
      }
      usedReportIds.add(release.evaluation.reportId);
      releases.set(key, Object.freeze(structuredClone(release)));
    }
    tenants.set(
      tenant.tenantId,
      Object.freeze({
        tenantId: tenant.tenantId,
        fixtureId: tenant.fixtureId,
        authorizationResources: Object.freeze(
          structuredClone(tenant.authorizationResources),
        ),
        releases,
      }),
    );
  }
  if (usedReportIds.size !== reports.size) {
    fail(
      "INVALID_SKILL_CATALOG",
      "evaluation report bundle contains an unbound report.",
    );
  }

  function tenantFor(tenantId) {
    const tenant = tenants.get(tenantId);
    if (!tenant) {
      fail(
        "SYNTHETIC_SOURCE_UNVERIFIED",
        "Tenant is outside the frozen C13 catalog.",
      );
    }
    return tenant;
  }

  return Object.freeze({
    authorizationResources(tenantId) {
      return tenantFor(tenantId).authorizationResources;
    },
    verifySource({
      tenantId,
      manifest,
      contentSha256,
      sourceReviewRef,
      sourceReviewSha256,
    }) {
      const checked = validateSkillManifest(manifest);
      const release = tenantFor(tenantId).releases.get(
        entryKey(checked.name, checked.version),
      );
      if (
        !release ||
        release.contentSha256 !== contentSha256 ||
        release.sourceReviewRef !== sourceReviewRef ||
        release.sourceReviewSha256 !== sourceReviewSha256
      ) {
        fail(
          "SYNTHETIC_SOURCE_UNVERIFIED",
          "Skill source is not in the frozen Synthetic catalog.",
        );
      }
      return release;
    },
    evaluate({
      tenantId,
      name,
      version,
      contentSha256,
      suiteId,
      suiteSha256,
    }) {
      const release = tenantFor(tenantId).releases.get(
        entryKey(name, version),
      );
      if (
        !release ||
        release.contentSha256 !== contentSha256 ||
        suiteId !== suite.suiteId ||
        suiteSha256 !== suite.suiteSha256
      ) {
        fail(
          "EVALUATION_UNAVAILABLE",
          "No frozen evaluation is bound to this Skill digest.",
        );
      }
      const evaluation = release.evaluation;
      return Object.freeze({
        schemaVersion: "c13-evaluation-report.v1",
        evidenceClass: "FROZEN_SYNTHETIC",
        evaluationMode: "DETERMINISTIC_BUILTIN_F04_GATE",
        reportId: evaluation.reportId,
        tenantId,
        skillName: name,
        skillVersion: version,
        releaseDigest: evaluation.releaseDigest,
        suiteId: suite.suiteId,
        suiteSha256: suite.suiteSha256,
        humanBaselineDecisionRef: suite.humanBaselineDecisionRef,
        humanBaselineDecisionSha256:
          suite.humanBaselineDecisionSha256,
        humanBaselineStatus: suite.humanBaselineStatus,
        reportRef: evaluation.reportRef,
        reportSha256: evaluation.reportSha256,
        caseCount: evaluation.caseCount,
        reportedCaseCount: evaluation.reportedCaseCount,
        caseResults: structuredClone(evaluation.caseResults),
        status: evaluation.status,
        failureCount: evaluation.failureCount,
        zeroToleranceViolationCount:
          evaluation.zeroToleranceViolationCount,
        reasonCode: evaluation.reasonCode,
      });
    },
    summary() {
      return Object.freeze({
        tenantCount: tenants.size,
        releaseCount: [...tenants.values()].reduce(
          (count, tenant) => count + tenant.releases.size,
          0,
        ),
        suiteId: suite.suiteId,
        suiteSha256: suite.suiteSha256,
        humanBaselineStatus: suite.humanBaselineStatus,
        scriptExecution: "DISABLED",
        allowedToolsGrantAuthorization: false,
      });
    },
  });
}
