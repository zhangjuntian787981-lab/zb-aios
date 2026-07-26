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

function validateEvaluation(
  value,
  suite,
  contentSha256,
  reportBundle,
) {
  exactKeys(
    value,
    [
      "status",
      "caseCount",
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
  if (
    !["PASS", "FAIL", "BLOCKED"].includes(value.status) ||
    !Number.isSafeInteger(value.caseCount) ||
    value.caseCount < 0 ||
    value.caseCount > suite.caseCount ||
    !Number.isSafeInteger(value.failureCount) ||
    value.failureCount < 0 ||
    !Number.isSafeInteger(value.zeroToleranceViolationCount) ||
    value.zeroToleranceViolationCount < 0 ||
    value.releaseDigest !== contentSha256 ||
    typeof value.reportId !== "string" ||
    value.reportId.length < 1 ||
    value.reportId.length > 128 ||
    !REFERENCE.test(value.reportRef ?? "") ||
    !SHA256.test(value.reportSha256 ?? "") ||
    value.reportRef !== reportBundle.ref ||
    value.reportSha256 !== reportBundle.sha256 ||
    typeof value.reasonCode !== "string" ||
    value.reasonCode.length < 1 ||
    value.reasonCode.length > 128 ||
    (value.status === "PASS" &&
      (suite.humanBaselineStatus !== "VALIDATED" ||
        value.caseCount !== suite.caseCount ||
        value.failureCount !== 0 ||
        value.zeroToleranceViolationCount !== 0)) ||
    (suite.humanBaselineStatus !== "VALIDATED" &&
      value.status !== "BLOCKED")
  ) {
    fail("INVALID_SKILL_CATALOG", "evaluation is invalid.");
  }
}

export function createC13SyntheticSkillCatalog(value) {
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
      "humanBaselineSha256",
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
    suite.humanBaselineStatus !== "PENDING_HUMAN_VALIDATION" ||
    suite.humanBaselineSha256 !==
      "sha256:1ac738d40ed6fb0bdaadb876c92b4f3cbde0d722142093bb786447365c9c5de0" ||
    !REFERENCE.test(value.evaluationReportBundle.ref ?? "") ||
    !SHA256.test(value.evaluationReportBundle.sha256 ?? "") ||
    !Array.isArray(value.tenants) ||
    value.tenants.length !== 3
  ) {
    fail("INVALID_SKILL_CATALOG", "catalog boundary is invalid.");
  }

  const tenants = new Map();
  for (const tenant of value.tenants) {
    exactKeys(
      tenant,
      ["tenantId", "fixtureId", "authorizationResources", "releases"],
      "tenant",
    );
    exactKeys(
      tenant.authorizationResources,
      ["readResourceId", "manageResourceId"],
      "authorization resources",
    );
    if (
      !TENANT_ID.test(tenant.tenantId ?? "") ||
      typeof tenant.fixtureId !== "string" ||
      !tenant.fixtureId.startsWith("synthetic-tenant-") ||
      !RESOURCE_ID.test(
        tenant.authorizationResources.readResourceId ?? "",
      ) ||
      !RESOURCE_ID.test(
        tenant.authorizationResources.manageResourceId ?? "",
      ) ||
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
      );
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
      return Object.freeze(structuredClone(release.evaluation));
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
