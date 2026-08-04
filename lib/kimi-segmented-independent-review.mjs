import { createHash } from "node:crypto";
import { validateIndependentReviewSchemaInstance } from "./independent-model-review.mjs";
import {
  validateKimiK3TokenEstimateEvidenceV2,
} from "./kimi-k3-review-evidence.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const ALLOWED_GIT_MODES = new Set(["100644", "100755"]);
const DECISIONS = new Set(["CLEAR", "BLOCKED", "INCONCLUSIVE"]);
const K3_MODEL = "kimi-k3";
const K3_PROVIDER = "moonshot";
const K3_BASE_URL = "https://api.moonshot.ai/v1";
const K3_CHAT_ENDPOINT = "/chat/completions";
const K3_MAX_COMPLETION_TOKENS = 32_768;
const K3_CONTEXT_TOKENS = 1_048_576;
const K3_BUDGET_MICROS = 4_000_000;
const VERIFIED_EXECUTIONS = new WeakSet();
const VERIFIED_EXECUTION_DATA = new WeakMap();
const VERIFIED_SEGMENT_RECEIPT_SETS = new WeakSet();
const VERIFIED_SEGMENT_RECEIPT_SET_DATA = new WeakMap();
const VERIFIED_REVIEW_RECEIPT_SETS = new WeakSet();
const VERIFIED_REVIEW_RECEIPT_SET_DATA = new WeakMap();
const SEGMENT_MATERIAL_MAGIC = Buffer.from(
  "KIMI-SEGMENT-REVIEW-MATERIAL/1\n",
  "utf8",
);
const INTEGRATION_MATERIAL_MAGIC = Buffer.from(
  "KIMI-CROSS-CUTTING-INTEGRATION-MATERIAL/1\n",
  "utf8",
);
const PLAN_BINDING_KEYS = Object.freeze([
  "reviewBundle",
  "segmentReviewerPrompt",
  "integrationReviewerPrompt",
  "canonicalOutputSchema",
  "providerTransportSchema",
  "providerConfig",
  "providerConfigSchema",
  "tokenEstimateEvidenceSchema",
  "segmentedTransportEvidenceSchema",
  "segmentReceiptSchema",
  "integrationReceiptSchema",
  "aggregateReceiptSchema",
]);
const SEGMENTS = Object.freeze([
  Object.freeze({
    segmentId: "GOVERNANCE_LINEAGE",
    ordinal: 1,
    semanticScope: "GOVERNANCE_POLICY_ADR_CONFIG_AND_HISTORY",
  }),
  Object.freeze({
    segmentId: "SCHEMAS_WIRE_CONTRACTS",
    ordinal: 2,
    semanticScope: "CLOSED_FIELD_SCHEMAS_AND_WIRE_CONTRACTS",
  }),
  Object.freeze({
    segmentId: "RUNTIME_ORCHESTRATION",
    ordinal: 3,
    semanticScope: "VALIDATORS_RUNTIME_ADAPTERS_AND_ORCHESTRATION",
  }),
  Object.freeze({
    segmentId: "TESTS_VERIFICATION",
    ordinal: 4,
    semanticScope: "TESTS_FIXTURES_SANDBOX_AND_VERIFICATION_PLAN",
  }),
]);
const HISTORICAL_EVIDENCE_PATHS = new Set([
  "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/formal-request.json",
  "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/review-bundle.v2.json",
  "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/review-material.v3.utf8",
  "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/single-call-outcome.v1.json",
  "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/token-estimate-request.json",
]);
const HISTORICAL_EVIDENCE_PATH_LIST = Object.freeze([
  ...HISTORICAL_EVIDENCE_PATHS,
]);
const HISTORICAL_EVIDENCE_BYTES = new Map([
  [HISTORICAL_EVIDENCE_PATH_LIST[0], Object.freeze({ byteLength: 1_014_092, sha256: "sha256:11f68ce448e836caee68ab718a9e03cacca5b643822b821e3bbd935dbc2763e0" })],
  [HISTORICAL_EVIDENCE_PATH_LIST[1], Object.freeze({ byteLength: 28_183, sha256: "sha256:7401a94fcef52a62905ba37f08fe6f1e913069f39dc6fe4476738acd2c2affb1" })],
  [HISTORICAL_EVIDENCE_PATH_LIST[2], Object.freeze({ byteLength: 957_096, sha256: "sha256:1b00dde4aff6c8feaee05df9480667d6063e0a6c50e80f38e42d246e2b4d5724" })],
  [HISTORICAL_EVIDENCE_PATH_LIST[3], Object.freeze({ byteLength: 3_967, sha256: "sha256:6d130f4c3819fb83b99bd5bd295272691ac010502fb2074058f070a4dc974b93" })],
  [HISTORICAL_EVIDENCE_PATH_LIST[4], Object.freeze({ byteLength: 1_012_452, sha256: "sha256:0e2d77b325e1b92eaf8e0051a931aec235af58ead76d43c65742521a0c970ca3" })],
]);
const REQUIRED_INTEGRATION_SECTIONS = Object.freeze([
  Object.freeze({
    kind: "GOVERNANCE",
    path: "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  }),
  Object.freeze({
    kind: "GOVERNANCE",
    path: "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
  }),
  Object.freeze({
    kind: "GOVERNANCE",
    path: "docs/adr/0020-kimi-k3-segmented-independent-review.md",
  }),
  Object.freeze({ kind: "SPECIFICATION", path: "CONTEXT.md" }),
]);
const V7_EVIDENCE_PREFIX =
  "implementation/governance/independent-review/evidence/kimi-k3-v7-final-20260801/";

class SegmentedIndependentReviewError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "SegmentedIndependentReviewError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new SegmentedIndependentReviewError(code, message);
}

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      fail("SEGMENT_JSON_INVALID", "Non-finite JSON number.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object" && value !== undefined) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("SEGMENT_JSON_INVALID", "Only JSON values are allowed.");
}

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function sha256Value(value) {
  return sha256Bytes(Buffer.from(canonicalize(value), "utf8"));
}

function clone(value) {
  return JSON.parse(canonicalize(value));
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function immutableClone(value) {
  return deepFreeze(clone(value));
}

function withoutField(value, field) {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== field),
  );
}

function sameValue(left, right) {
  return canonicalize(left) === canonicalize(right);
}

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    sameValue(Object.keys(value).sort(), [...expected].sort())
  );
}

function safePath(path) {
  return (
    typeof path === "string" &&
    path.length > 0 &&
    path.length <= 1024 &&
    SAFE_PATH.test(path)
  );
}

function assertNoDuplicateJsonKeys(text, code) {
  let offset = 0;
  const whitespace = () => {
    while (/\s/u.test(text[offset] ?? "")) offset += 1;
  };
  const string = () => {
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      if (text[offset] === "\\") {
        offset += 2;
      } else if (text[offset] === '"') {
        offset += 1;
        return JSON.parse(text.slice(start, offset));
      } else {
        offset += 1;
      }
    }
    fail(code, "JSON string is truncated.");
  };
  const value = () => {
    whitespace();
    if (text[offset] === "{") {
      offset += 1;
      whitespace();
      const keys = new Set();
      if (text[offset] === "}") {
        offset += 1;
        return;
      }
      while (offset < text.length) {
        if (text[offset] !== '"') fail(code, "JSON object key is invalid.");
        const key = string();
        if (keys.has(key)) fail(code, "JSON object contains duplicate keys.");
        keys.add(key);
        whitespace();
        if (text[offset] !== ":") fail(code, "JSON object separator is invalid.");
        offset += 1;
        value();
        whitespace();
        if (text[offset] === "}") {
          offset += 1;
          return;
        }
        if (text[offset] !== ",") fail(code, "JSON object delimiter is invalid.");
        offset += 1;
        whitespace();
      }
      fail(code, "JSON object is truncated.");
    }
    if (text[offset] === "[") {
      offset += 1;
      whitespace();
      if (text[offset] === "]") {
        offset += 1;
        return;
      }
      while (offset < text.length) {
        value();
        whitespace();
        if (text[offset] === "]") {
          offset += 1;
          return;
        }
        if (text[offset] !== ",") fail(code, "JSON array delimiter is invalid.");
        offset += 1;
      }
      fail(code, "JSON array is truncated.");
    }
    if (text[offset] === '"') {
      string();
      return;
    }
    const start = offset;
    while (offset < text.length && !/[\s,\]}]/u.test(text[offset])) offset += 1;
    if (start === offset) fail(code, "JSON value is invalid.");
    JSON.parse(text.slice(start, offset));
  };
  value();
  whitespace();
  if (offset !== text.length) fail(code, "JSON has trailing data.");
}

function parseStrictJsonBytes(bytes, code) {
  assertBytes(bytes, code);
  let text;
  let value;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    assertNoDuplicateJsonKeys(text, code);
    value = JSON.parse(text);
  } catch {
    fail(code, "Expected exact canonical UTF-8 JSON bytes.");
  }
  return value;
}

function validDescriptor(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    Object.keys(value).length === 3 &&
    typeof value.path === "string" &&
    safePath(value.path) &&
    Number.isSafeInteger(value.byteLength) &&
    value.byteLength >= 0 &&
    SHA256.test(value.sha256)
  );
}

function descriptor(path, bytes) {
  return {
    path,
    byteLength: bytes.byteLength,
    sha256: sha256Bytes(bytes),
  };
}

function assertBytes(value, code) {
  if (!Buffer.isBuffer(value)) {
    fail(code, "Expected exact Buffer bytes.");
  }
  return value;
}

function assertDescriptorBytes(subject, bytes, code) {
  assertBytes(bytes, code);
  const byteBinding = {
    path: subject?.path,
    byteLength: subject?.byteLength,
    sha256: subject?.sha256,
  };
  if (
    !validDescriptor(byteBinding) ||
    byteBinding.byteLength !== bytes.byteLength ||
    byteBinding.sha256 !== sha256Bytes(bytes)
  ) {
    fail(code, `Byte binding mismatch for ${subject?.path ?? "unknown"}.`);
  }
}

function sortedUniquePaths(paths, code) {
  if (
    !Array.isArray(paths) ||
    paths.some((path) => !safePath(path)) ||
    new Set(paths).size !== paths.length
  ) {
    fail(code, "Paths must be safe and unique.");
  }
  const sorted = [...paths].sort((left, right) => left.localeCompare(right));
  if (!sameValue(paths, sorted)) {
    fail(code, "Paths must be UTF-8 sorted.");
  }
  return sorted;
}

export function classifyKimiSegmentReviewPath(path) {
  if (HISTORICAL_EVIDENCE_PATHS.has(path)) {
    return "GOVERNANCE_LINEAGE";
  }
  if (path.startsWith(V7_EVIDENCE_PREFIX)) {
    const name = path.slice(V7_EVIDENCE_PREFIX.length);
    if (name === "review-material.v4.utf8") return "TESTS_VERIFICATION";
    if (
      name.includes("request") ||
      name.includes("response") ||
      name.includes("diagnostic") ||
      name.includes("token-estimate-evidence")
    ) {
      return "RUNTIME_ORCHESTRATION";
    }
    return "GOVERNANCE_LINEAGE";
  }
  if (
    path.startsWith("tests/") ||
    path ===
      "implementation/governance/independent-review/independent-review-test-plan.v2.json" ||
    path ===
      "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in"
  ) {
    return "TESTS_VERIFICATION";
  }
  if (path.startsWith("implementation/governance/schemas/")) {
    return "SCHEMAS_WIRE_CONTRACTS";
  }
  if (
    path.startsWith("lib/") ||
    path.startsWith("scripts/") ||
    path === "package.json" ||
    path === "package-lock.json"
  ) {
    return "RUNTIME_ORCHESTRATION";
  }
  if (
    path.startsWith("docs/adr/") ||
    path.startsWith("docs/research/") ||
    path.startsWith("implementation/governance/independent-review/")
  ) {
    return "GOVERNANCE_LINEAGE";
  }
  fail("SEGMENT_PATH_UNCLASSIFIED", `No frozen segment owns ${path}.`);
}

function validateBundleShape(bundle) {
  if (
    !bundle ||
    typeof bundle !== "object" ||
    !Array.isArray(bundle.reviewedPaths) ||
    !Array.isArray(bundle.sourceSubjects) ||
    !bundle.source ||
    !COMMIT.test(bundle.source.baseCommit) ||
    !COMMIT.test(bundle.source.sourceCommit) ||
    !COMMIT.test(bundle.source.headCommit) ||
    !COMMIT.test(bundle.source.tree) ||
    !SHA256.test(bundle.source.diffSha256) ||
    !SHA256.test(bundle.source.changedPathsDigest)
  ) {
    fail("SEGMENT_BUNDLE_INVALID", "Review Bundle source binding is invalid.");
  }
  const reviewedPaths = sortedUniquePaths(
    bundle.reviewedPaths,
    "SEGMENT_BUNDLE_INVALID",
  );
  if (sha256Value(reviewedPaths) !== bundle.source.changedPathsDigest) {
    fail("SEGMENT_BUNDLE_INVALID", "Bundle changedPathsDigest mismatch.");
  }
  const subjectPaths = bundle.sourceSubjects.map(({ path }) => path);
  sortedUniquePaths(subjectPaths, "SEGMENT_BUNDLE_INVALID");
  if (
    !sameValue(subjectPaths, reviewedPaths) ||
    bundle.sourceSubjects.some(
      (subject) =>
        !exactKeys(subject, ["path", "gitMode", "blobSha256"]) ||
        !safePath(subject.path) ||
        !ALLOWED_GIT_MODES.has(subject.gitMode) ||
        !SHA256.test(subject.blobSha256),
    )
  ) {
    fail("SEGMENT_BUNDLE_INVALID", "Bundle sourceSubjects are incomplete.");
  }
}

function sourceBinding(source) {
  return {
    baseCommit: source.baseCommit,
    sourceCommit: source.sourceCommit,
    headCommit: source.headCommit,
    tree: source.tree,
    diffSha256: source.diffSha256,
    changedPathsDigest: source.changedPathsDigest,
  };
}

function validatePlanBindings(bindings) {
  if (
    !bindings ||
    !sameValue(Object.keys(bindings).sort(), [...PLAN_BINDING_KEYS].sort()) ||
    PLAN_BINDING_KEYS.some((key) => !validDescriptor(bindings[key]))
  ) {
    fail("SEGMENT_PLAN_BINDING_INVALID", "Plan byte bindings are invalid.");
  }
}

function validatePlanBindingPathIsolation(
  bindings,
  commonSections,
  integrationSections,
) {
  const bindingPaths = PLAN_BINDING_KEYS.map((key) => bindings[key].path);
  if (new Set(bindingPaths).size !== bindingPaths.length) {
    fail(
      "SEGMENT_PLAN_BINDING_PATH_DUPLICATE",
      "Each Plan binding must identify a distinct byte source.",
    );
  }
  const commonPaths = new Set(commonSections.map(({ path }) => path));
  if (bindingPaths.some((path) => commonPaths.has(path))) {
    fail(
      "SEGMENT_PLAN_BINDING_COMMON_OVERLAP",
      "A Plan binding cannot repeat a content common section.",
    );
  }
  const integrationPaths = new Set(integrationSections.map(({ path }) => path));
  if (bindingPaths.some((path) => integrationPaths.has(path))) {
    fail(
      "SEGMENT_PLAN_BINDING_INTEGRATION_OVERLAP",
      "A Plan binding cannot repeat a fixed integration contract section.",
    );
  }
}

function validateCommonSections(commonSections, { requireNonEmpty = false } = {}) {
  if (
    !Array.isArray(commonSections) ||
    commonSections.length > 64 ||
    (requireNonEmpty && commonSections.length === 0)
  ) {
    fail("SEGMENT_PLAN_COMMON_SECTION_INVALID", "Common sections are required.");
  }
  const paths = commonSections.map(({ path }) => path);
  if (new Set(paths).size !== paths.length) {
    fail("SEGMENT_PLAN_COMMON_SECTION_INVALID", "Common sections repeat paths.");
  }
  for (const section of commonSections) {
    if (
      !section ||
      typeof section !== "object" ||
      !exactKeys(section, ["kind", "path", "byteLength", "sha256"]) ||
      !["GOVERNANCE", "SPECIFICATION", "TEST_EVIDENCE"].includes(
        section.kind,
      ) ||
      !validDescriptor({
        path: section.path,
        byteLength: section.byteLength,
        sha256: section.sha256,
      })
    ) {
      fail(
        "SEGMENT_PLAN_COMMON_SECTION_INVALID",
        "Common section descriptor is invalid.",
      );
    }
  }
}

function validateContentCommonSections(commonSections, reviewedPaths) {
  validateCommonSections(commonSections);
  if (
    commonSections.some(({ path }) => reviewedPaths.includes(path))
  ) {
    fail(
      "SEGMENT_PLAN_COMMON_SECTION_OVERLAP",
      "A reviewed path cannot be repeated as a content common section.",
    );
  }
}

function validateIntegrationSections(integrationSections) {
  validateCommonSections(integrationSections, { requireNonEmpty: true });
  const contract = integrationSections.map(({ kind, path }) => ({ kind, path }));
  if (!sameValue(contract, REQUIRED_INTEGRATION_SECTIONS)) {
    fail(
      "SEGMENT_PLAN_INTEGRATION_CONTRACT_INVALID",
      "The fixed Policy, ADR, and cross-module contract set is incomplete.",
    );
  }
}

export const segmentedKimiReviewDigests = Object.freeze({
  bytes: sha256Bytes,
  value: sha256Value,
  canonicalize,
});

export async function createKimiSegmentReviewPlan({
  planId,
  bundle,
  bundleBytes,
  bindings,
  commonSections,
  integrationSections,
  sourceBytesResolver,
}) {
  validateBundleShape(bundle);
  validatePlanBindings(bindings);
  validateContentCommonSections(commonSections, bundle.reviewedPaths);
  validateIntegrationSections(integrationSections);
  validatePlanBindingPathIsolation(bindings, commonSections, integrationSections);
  if (
    typeof planId !== "string" ||
    !/^imsrp_[a-z0-9_-]+$/u.test(planId) ||
    typeof sourceBytesResolver !== "function"
  ) {
    fail("SEGMENT_PLAN_INVALID", "Plan identifier or resolver is invalid.");
  }
  assertBytes(bundleBytes, "SEGMENT_BUNDLE_BYTES_MISMATCH");
  if (
    bundleBytes.byteLength !== bindings.reviewBundle.byteLength ||
    sha256Bytes(bundleBytes) !== bindings.reviewBundle.sha256
  ) {
    fail("SEGMENT_BUNDLE_BYTES_MISMATCH", "Bundle bytes do not match binding.");
  }
  if (!sameValue(parseStrictJsonBytes(bundleBytes, "SEGMENT_BUNDLE_BYTES_MISMATCH"), bundle)) {
    fail("SEGMENT_BUNDLE_BYTES_MISMATCH", "Bundle object and frozen bytes disagree.");
  }
  if (
    HISTORICAL_EVIDENCE_PATH_LIST.some(
      (path) =>
        !bundle.reviewedPaths.includes(path) ||
        !bundle.sourceSubjects.some((subject) => subject.path === path),
    )
  ) {
    fail(
      "SEGMENT_HISTORICAL_EVIDENCE_INCOMPLETE",
      "All five historical review artifacts must be reviewed as full source bytes.",
    );
  }
  const subjects = new Map(
    bundle.sourceSubjects.map((subject) => [subject.path, subject]),
  );
  const owned = new Map(SEGMENTS.map(({ segmentId }) => [segmentId, []]));
  for (const path of bundle.reviewedPaths) {
    const subject = subjects.get(path);
    const bytes = assertBytes(
      await sourceBytesResolver(path),
      "SEGMENT_SOURCE_BYTES_MISSING",
    );
    if (
      !subject ||
      !ALLOWED_GIT_MODES.has(subject.gitMode) ||
      !SHA256.test(subject.blobSha256) ||
      sha256Bytes(bytes) !== subject.blobSha256
    ) {
      fail("SEGMENT_SOURCE_BYTES_MISMATCH", `Source bytes drifted for ${path}.`);
    }
    const segmentId = classifyKimiSegmentReviewPath(path);
    const historical = HISTORICAL_EVIDENCE_BYTES.get(path);
    if (
      historical &&
      (subject.gitMode !== "100644" ||
        bytes.byteLength !== historical.byteLength ||
        subject.blobSha256 !== historical.sha256)
    ) {
      fail(
        "SEGMENT_HISTORICAL_EVIDENCE_BYTES_MISMATCH",
        `Historical review artifact bytes drifted for ${path}.`,
      );
    }
    owned.get(segmentId).push({
      path,
      gitMode: subject.gitMode,
      byteLength: bytes.byteLength,
      contentSha256: subject.blobSha256,
    });
  }
  const segments = SEGMENTS.map((segment) => {
    const ownedPaths = owned
      .get(segment.segmentId)
      .sort(({ path: left }, { path: right }) => left.localeCompare(right));
    return {
      ...segment,
      ownedPaths,
      pathCount: ownedPaths.length,
      pathSetSha256: sha256Value(ownedPaths.map(({ path }) => path)),
      ownedUtf8ByteLength: ownedPaths.reduce(
        (total, { byteLength }) => total + byteLength,
        0,
      ),
    };
  });
  const flattened = segments.flatMap(({ ownedPaths }) =>
    ownedPaths.map(({ path }) => path),
  );
  const counts = new Map();
  for (const path of flattened) counts.set(path, (counts.get(path) ?? 0) + 1);
  const expected = bundle.reviewedPaths;
  const actualSet = [...new Set(flattened)].sort((a, b) => a.localeCompare(b));
  const coverage = {
    expectedPathCount: expected.length,
    actualPathCount: flattened.length,
    missingPaths: expected.filter((path) => !counts.has(path)),
    duplicatePaths: actualSet.filter((path) => counts.get(path) !== 1),
    unexpectedPaths: actualSet.filter((path) => !expected.includes(path)),
    unionPathSetSha256: sha256Value(actualSet),
  };
  if (
    coverage.missingPaths.length ||
    coverage.duplicatePaths.length ||
    coverage.unexpectedPaths.length ||
    coverage.actualPathCount !== coverage.expectedPathCount ||
    coverage.unionPathSetSha256 !== bundle.source.changedPathsDigest
  ) {
    fail("SEGMENT_COVERAGE_INVALID", "Content segment coverage is not exact.");
  }
  const plan = {
    schemaVersion: "kimi-segment-review-plan.v1",
    planId,
    lifecycle: "CANDIDATE_LOCAL_ONLY",
    strategy: "FOUR_CONTENT_SEGMENTS_PLUS_CROSS_CUTTING_INTEGRATION",
    source: sourceBinding(bundle.source),
    bindings: clone(bindings),
    commonSections: clone(commonSections),
    integrationSections: clone(integrationSections),
    segments,
    coverage,
    executionPreview: {
      tokenEstimateRequestCount: 5,
      conditionalChatRequestCount: 5,
      maximumNetworkRequestCount: 10,
      networkExecutionAuthorized: false,
      budgetAuthorization: "NOT_GRANTED_BY_PLAN",
    },
    executionAuthorization: "LOCAL_MATERIALIZATION_ONLY_NO_NETWORK",
  };
  return {
    ...plan,
    planSha256: sha256Value(plan),
  };
}

export async function validateKimiSegmentReviewPlan({
  plan,
  bundle,
  sourceBytesResolver,
}) {
  try {
    validateBundleShape(bundle);
    validatePlanBindings(plan?.bindings);
    validateContentCommonSections(plan?.commonSections, bundle.reviewedPaths);
    validateIntegrationSections(plan?.integrationSections);
    validatePlanBindingPathIsolation(
      plan.bindings,
      plan.commonSections,
      plan.integrationSections,
    );
    if (
      !exactKeys(plan, [
        "schemaVersion",
        "planId",
        "lifecycle",
        "strategy",
        "source",
        "bindings",
        "commonSections",
        "integrationSections",
        "segments",
        "coverage",
        "executionPreview",
        "executionAuthorization",
        "planSha256",
      ]) ||
      plan?.schemaVersion !== "kimi-segment-review-plan.v1" ||
      plan?.lifecycle !== "CANDIDATE_LOCAL_ONLY" ||
      plan?.strategy !==
        "FOUR_CONTENT_SEGMENTS_PLUS_CROSS_CUTTING_INTEGRATION" ||
      plan?.executionAuthorization !==
        "LOCAL_MATERIALIZATION_ONLY_NO_NETWORK" ||
      !SHA256.test(plan?.planSha256) ||
      sha256Value(withoutField(plan, "planSha256")) !== plan.planSha256 ||
      !sameValue(plan.source, sourceBinding(bundle.source)) ||
      !exactKeys(plan.source, [
        "baseCommit",
        "sourceCommit",
        "headCommit",
        "tree",
        "diffSha256",
        "changedPathsDigest",
      ]) ||
      !exactKeys(plan.coverage, [
        "expectedPathCount",
        "actualPathCount",
        "missingPaths",
        "duplicatePaths",
        "unexpectedPaths",
        "unionPathSetSha256",
      ]) ||
      !exactKeys(plan.executionPreview, [
        "tokenEstimateRequestCount",
        "conditionalChatRequestCount",
        "maximumNetworkRequestCount",
        "networkExecutionAuthorized",
        "budgetAuthorization",
      ]) ||
      !sameValue(plan.executionPreview, {
        tokenEstimateRequestCount: 5,
        conditionalChatRequestCount: 5,
        maximumNetworkRequestCount: 10,
        networkExecutionAuthorized: false,
        budgetAuthorization: "NOT_GRANTED_BY_PLAN",
      }) ||
      typeof sourceBytesResolver !== "function" ||
      !Array.isArray(plan.segments) ||
      plan.segments.length !== SEGMENTS.length
    ) {
      return { ok: false, reasonCode: "SEGMENT_PLAN_INVALID" };
    }
    const paths = [];
    for (let index = 0; index < SEGMENTS.length; index += 1) {
      const expectedSegment = SEGMENTS[index];
      const segment = plan.segments[index];
      if (
        !exactKeys(segment, [
          "segmentId",
          "ordinal",
          "semanticScope",
          "ownedPaths",
          "pathCount",
          "pathSetSha256",
          "ownedUtf8ByteLength",
        ]) ||
        segment.segmentId !== expectedSegment.segmentId ||
        segment.ordinal !== expectedSegment.ordinal ||
        segment.semanticScope !== expectedSegment.semanticScope ||
        !Array.isArray(segment.ownedPaths) ||
        segment.pathCount !== segment.ownedPaths.length ||
        segment.pathSetSha256 !==
          sha256Value(segment.ownedPaths.map(({ path }) => path)) ||
        segment.ownedUtf8ByteLength !==
          segment.ownedPaths.reduce(
            (total, { byteLength }) => total + byteLength,
            0,
          )
      ) {
        return { ok: false, reasonCode: "SEGMENT_PLAN_INVALID" };
      }
      for (const subject of segment.ownedPaths) {
        const bundleSubject = bundle.sourceSubjects.find(
          ({ path }) => path === subject?.path,
        );
        const sourceBytes = await sourceBytesResolver(subject?.path);
        if (
          !exactKeys(subject, [
            "path",
            "gitMode",
            "byteLength",
            "contentSha256",
          ]) ||
          !safePath(subject.path) ||
          classifyKimiSegmentReviewPath(subject.path) !== segment.segmentId ||
          !ALLOWED_GIT_MODES.has(subject.gitMode) ||
          !Number.isSafeInteger(subject.byteLength) ||
          subject.byteLength < 0 ||
          !SHA256.test(subject.contentSha256) ||
          !bundleSubject ||
          bundleSubject.gitMode !== subject.gitMode ||
          bundleSubject.blobSha256 !== subject.contentSha256 ||
          !Buffer.isBuffer(sourceBytes) ||
          sourceBytes.byteLength !== subject.byteLength ||
          sha256Bytes(sourceBytes) !== subject.contentSha256
        ) {
          return { ok: false, reasonCode: "SEGMENT_PLAN_INVALID" };
        }
        const historical = HISTORICAL_EVIDENCE_BYTES.get(subject.path);
        if (
          historical &&
          (subject.gitMode !== "100644" ||
            subject.byteLength !== historical.byteLength ||
            subject.contentSha256 !== historical.sha256)
        ) {
          return {
            ok: false,
            reasonCode: "SEGMENT_HISTORICAL_EVIDENCE_BYTES_MISMATCH",
          };
        }
        paths.push(subject.path);
      }
    }
    const sorted = [...paths].sort((a, b) => a.localeCompare(b));
    const counts = new Map();
    for (const path of paths) counts.set(path, (counts.get(path) ?? 0) + 1);
    if (
      paths.length !== bundle.reviewedPaths.length ||
      counts.size !== paths.length ||
      !sameValue(sorted, bundle.reviewedPaths) ||
      sha256Value(sorted) !== bundle.source.changedPathsDigest ||
      plan.coverage.expectedPathCount !== bundle.reviewedPaths.length ||
      plan.coverage.actualPathCount !== paths.length ||
      plan.coverage.missingPaths.length !== 0 ||
      plan.coverage.duplicatePaths.length !== 0 ||
      plan.coverage.unexpectedPaths.length !== 0 ||
      plan.coverage.unionPathSetSha256 !== bundle.source.changedPathsDigest
    ) {
      return { ok: false, reasonCode: "SEGMENT_COVERAGE_INVALID" };
    }
    if (
      HISTORICAL_EVIDENCE_PATH_LIST.some(
        (path) =>
          !paths.includes(path) ||
          classifyKimiSegmentReviewPath(path) !== "GOVERNANCE_LINEAGE",
      )
    ) {
      return {
        ok: false,
        reasonCode: "SEGMENT_HISTORICAL_EVIDENCE_INCOMPLETE",
      };
    }
    return { ok: true, reasonCode: null };
  } catch (error) {
    return {
      ok: false,
      reasonCode: error?.code ?? "SEGMENT_PLAN_INVALID",
    };
  }
}

function bindingSections(bindings) {
  return PLAN_BINDING_KEYS.map((key) => ({
    binding: key,
    kind:
      key === "reviewBundle"
        ? "REVIEW_BUNDLE"
        : key.endsWith("Schema")
          ? "SPECIFICATION"
          : "GOVERNANCE",
    ...clone(bindings[key]),
  }));
}

function encodeMaterialEnvelope(magic, material, payloads) {
  const headerBytes = Buffer.from(canonicalize(material), "utf8");
  const prefix = Buffer.from(
    `${headerBytes.byteLength.toString(16).padStart(12, "0")}\n`,
    "ascii",
  );
  return Buffer.concat([magic, prefix, headerBytes, ...payloads]);
}

function parseMaterialEnvelope(bytes, magic) {
  assertBytes(bytes, "SEGMENT_MATERIAL_INVALID");
  if (!bytes.subarray(0, magic.byteLength).equals(magic)) {
    fail("SEGMENT_MATERIAL_INVALID", "Material magic mismatch.");
  }
  const lengthStart = magic.byteLength;
  const lengthEnd = lengthStart + 13;
  const lengthLine = bytes.subarray(lengthStart, lengthEnd).toString("ascii");
  if (!/^[a-f0-9]{12}\n$/u.test(lengthLine)) {
    fail("SEGMENT_MATERIAL_INVALID", "Material header length is invalid.");
  }
  const headerLength = Number.parseInt(lengthLine.slice(0, 12), 16);
  const headerStart = lengthEnd;
  const headerEnd = headerStart + headerLength;
  if (headerEnd > bytes.byteLength) {
    fail("SEGMENT_MATERIAL_INVALID", "Material header is truncated.");
  }
  let material;
  const headerBytes = bytes.subarray(headerStart, headerEnd);
  try {
    material = parseStrictJsonBytes(headerBytes, "SEGMENT_MATERIAL_INVALID");
  } catch {
    fail("SEGMENT_MATERIAL_INVALID", "Material header is not JSON.");
  }
  if (
    !Buffer.from(canonicalize(material), "utf8").equals(headerBytes) ||
    !SHA256.test(material?.materialSha256) ||
    sha256Value(withoutField(material, "materialSha256")) !==
      material.materialSha256 ||
    !Array.isArray(material.payloadOrder)
  ) {
    fail("SEGMENT_MATERIAL_INVALID", "Material digest is invalid.");
  }
  const payloads = [];
  let offset = headerEnd;
  for (const item of material.payloadOrder) {
    if (
      !Number.isSafeInteger(item.byteLength) ||
      item.byteLength < 0 ||
      !SHA256.test(item.sha256) ||
      offset + item.byteLength > bytes.byteLength
    ) {
      fail("SEGMENT_MATERIAL_INVALID", "Material payload is truncated.");
    }
    const payload = bytes.subarray(offset, offset + item.byteLength);
    if (sha256Bytes(payload) !== item.sha256) {
      fail("SEGMENT_MATERIAL_INVALID", "Material payload digest mismatch.");
    }
    payloads.push(Buffer.from(payload));
    offset += item.byteLength;
  }
  if (offset !== bytes.byteLength) {
    fail("SEGMENT_MATERIAL_INVALID", "Material has trailing bytes.");
  }
  return { material, payloads };
}

function sectionPayloadOrder(scope, sections) {
  return sections.map((section, index) => ({
    scope,
    index,
    path: section.path,
    byteLength: section.byteLength,
    sha256: section.sha256,
  }));
}

export async function buildKimiSegmentReviewMaterials({
  plan,
  bundle,
  bundleBytes,
  sourceBytesResolver,
  commonBytesResolver,
}) {
  const validation = await validateKimiSegmentReviewPlan({
    plan,
    bundle,
    sourceBytesResolver,
  });
  if (!validation.ok) fail(validation.reasonCode, "Segment Plan is invalid.");
  if (
    typeof sourceBytesResolver !== "function" ||
    typeof commonBytesResolver !== "function"
  ) {
    fail("SEGMENT_MATERIAL_INVALID", "Material resolvers are required.");
  }
  assertDescriptorBytes(plan.bindings.reviewBundle, bundleBytes, "SEGMENT_BUNDLE_BYTES_MISMATCH");
  const boundSections = bindingSections(plan.bindings).filter(
    ({ binding, path }) =>
      binding === "reviewBundle" || !bundle.reviewedPaths.includes(path),
  );
  const boundBytes = [];
  for (const section of boundSections) {
    const bytes =
      section.binding === "reviewBundle"
        ? bundleBytes
        : await commonBytesResolver(section.path);
    assertDescriptorBytes(section, bytes, "SEGMENT_BINDING_BYTES_MISMATCH");
    boundBytes.push(Buffer.from(bytes));
  }
  const commonBytes = [];
  for (const section of plan.commonSections) {
    const bytes = await commonBytesResolver(section.path);
    assertDescriptorBytes(section, bytes, "SEGMENT_COMMON_BYTES_MISMATCH");
    commonBytes.push(Buffer.from(bytes));
  }
  const results = [];
  for (const segment of plan.segments) {
    const reviewedSections = segment.ownedPaths.map((subject) => ({
      kind: "SOURCE",
      ...clone(subject),
      sha256: subject.contentSha256,
    }));
    for (const section of reviewedSections) delete section.contentSha256;
    const reviewedBytes = [];
    for (const section of reviewedSections) {
      const bytes = await sourceBytesResolver(section.path);
      assertDescriptorBytes(section, bytes, "SEGMENT_SOURCE_BYTES_MISMATCH");
      reviewedBytes.push(Buffer.from(bytes));
    }
    const payloadOrder = [
      ...sectionPayloadOrder("BINDING", boundSections),
      ...sectionPayloadOrder("COMMON", plan.commonSections),
      ...sectionPayloadOrder("REVIEWED", reviewedSections),
    ];
    const material = {
      schemaVersion: "kimi-segment-review-material.v1",
      materialId: `${plan.planId}_${segment.segmentId.toLowerCase()}`,
      segmentPlanSha256: plan.planSha256,
      source: clone(plan.source),
      bindings: clone(plan.bindings),
      segment: {
        segmentId: segment.segmentId,
        ordinal: segment.ordinal,
        semanticScope: segment.semanticScope,
        pathSetSha256: segment.pathSetSha256,
      },
      bindingSections: boundSections,
      commonSections: clone(plan.commonSections),
      reviewedSections,
      payloadOrder,
      payloadUtf8ByteLength: payloadOrder.reduce(
        (total, { byteLength }) => total + byteLength,
        0,
      ),
      executionAuthorization: "LOCAL_MATERIALIZATION_ONLY_NO_NETWORK",
    };
    material.materialSha256 = sha256Value(material);
    const payloads = [...boundBytes, ...commonBytes, ...reviewedBytes];
    const materialBytes = encodeMaterialEnvelope(
      SEGMENT_MATERIAL_MAGIC,
      material,
      payloads,
    );
    results.push({
      segmentId: segment.segmentId,
      segmentOrdinal: segment.ordinal,
      material,
      materialBytes,
      materialBytesSha256: sha256Bytes(materialBytes),
    });
  }
  return results;
}

export function parseKimiSegmentReviewMaterial(materialBytes) {
  const parsed = parseMaterialEnvelope(materialBytes, SEGMENT_MATERIAL_MAGIC);
  const { material, payloads } = parsed;
  if (
    material.schemaVersion !== "kimi-segment-review-material.v1" ||
    material.executionAuthorization !==
      "LOCAL_MATERIALIZATION_ONLY_NO_NETWORK"
  ) {
    fail("SEGMENT_MATERIAL_INVALID", "Unexpected segment material contract.");
  }
  const bindingCount = material.bindingSections.length;
  const commonCount = material.commonSections.length;
  return {
    material,
    bindingSectionBytes: payloads.slice(0, bindingCount),
    commonSectionBytes: payloads.slice(
      bindingCount,
      bindingCount + commonCount,
    ),
    reviewedSectionBytes: payloads.slice(bindingCount + commonCount),
  };
}

export async function validateKimiSegmentReviewMaterial({
  materialBytes,
  plan,
  bundle,
  sourceBytesResolver,
}) {
  try {
    const planValidation = await validateKimiSegmentReviewPlan({
      plan,
      bundle,
      sourceBytesResolver,
    });
    if (!planValidation.ok) {
      return { ok: false, reasonCode: planValidation.reasonCode };
    }
    const parsed = parseKimiSegmentReviewMaterial(materialBytes);
    const { material } = parsed;
    const segment = plan.segments.find(
      ({ segmentId }) => segmentId === material?.segment?.segmentId,
    );
    if (!segment) {
      return { ok: false, reasonCode: "SEGMENT_MATERIAL_SCOPE_INVALID" };
    }
    const expectedBindingSections = bindingSections(plan.bindings).filter(
      ({ binding, path }) =>
        binding === "reviewBundle" || !bundle.reviewedPaths.includes(path),
    );
    const expectedReviewedSections = segment.ownedPaths.map((subject) => ({
      kind: "SOURCE",
      path: subject.path,
      gitMode: subject.gitMode,
      byteLength: subject.byteLength,
      sha256: subject.contentSha256,
    }));
    const expectedSegment = {
      segmentId: segment.segmentId,
      ordinal: segment.ordinal,
      semanticScope: segment.semanticScope,
      pathSetSha256: segment.pathSetSha256,
    };
    const expectedPayloadOrder = [
      ...sectionPayloadOrder("BINDING", expectedBindingSections),
      ...sectionPayloadOrder("COMMON", plan.commonSections),
      ...sectionPayloadOrder("REVIEWED", expectedReviewedSections),
    ];
    if (
      !exactKeys(material, [
        "schemaVersion",
        "materialId",
        "segmentPlanSha256",
        "source",
        "bindings",
        "segment",
        "bindingSections",
        "commonSections",
        "reviewedSections",
        "payloadOrder",
        "payloadUtf8ByteLength",
        "executionAuthorization",
        "materialSha256",
      ]) ||
      material.materialId !==
        `${plan.planId}_${segment.segmentId.toLowerCase()}` ||
      material.segmentPlanSha256 !== plan.planSha256 ||
      !sameValue(material.source, plan.source) ||
      !sameValue(material.bindings, plan.bindings) ||
      !sameValue(material.segment, expectedSegment) ||
      !sameValue(material.bindingSections, expectedBindingSections) ||
      !sameValue(material.commonSections, plan.commonSections) ||
      !sameValue(material.reviewedSections, expectedReviewedSections) ||
      !sameValue(material.payloadOrder, expectedPayloadOrder) ||
      material.payloadUtf8ByteLength !==
        expectedPayloadOrder.reduce(
          (total, { byteLength }) => total + byteLength,
          0,
        ) ||
      parsed.bindingSectionBytes.length !== expectedBindingSections.length ||
      parsed.commonSectionBytes.length !== plan.commonSections.length ||
      parsed.reviewedSectionBytes.length !== expectedReviewedSections.length
    ) {
      return { ok: false, reasonCode: "SEGMENT_MATERIAL_INVALID" };
    }
    const bundleBytes = parsed.bindingSectionBytes[0];
    if (
      !bundleBytes ||
      !sameValue(
        parseStrictJsonBytes(bundleBytes, "SEGMENT_BUNDLE_BYTES_MISMATCH"),
        bundle,
      )
    ) {
      return { ok: false, reasonCode: "SEGMENT_BUNDLE_BYTES_MISMATCH" };
    }
    for (let index = 0; index < expectedReviewedSections.length; index += 1) {
      const expectedBytes = await sourceBytesResolver(
        expectedReviewedSections[index].path,
      );
      if (
        !Buffer.isBuffer(expectedBytes) ||
        !parsed.reviewedSectionBytes[index].equals(expectedBytes)
      ) {
        return { ok: false, reasonCode: "SEGMENT_SOURCE_BYTES_MISMATCH" };
      }
    }
    return { ok: true, reasonCode: null };
  } catch (error) {
    return {
      ok: false,
      reasonCode: error?.code ?? "SEGMENT_MATERIAL_INVALID",
    };
  }
}

function validFinding(finding, allowedPaths, allowNullPath) {
  const keys = [
    "detailsSha256",
    "endLine",
    "findingId",
    "path",
    "relatedPaths",
    "resolutionEvidenceDigests",
    "severity",
    "startLine",
    "status",
    "summary",
  ];
  return (
    finding &&
    typeof finding === "object" &&
    sameValue(Object.keys(finding).sort(), keys) &&
    typeof finding.findingId === "string" &&
    finding.findingId.length > 0 &&
    finding.findingId.length <= 160 &&
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(
      finding.severity,
    ) &&
    ["OPEN", "RESOLVED"].includes(finding.status) &&
    ((allowNullPath && finding.path === null) ||
      (safePath(finding.path) && allowedPaths.has(finding.path))) &&
    Array.isArray(finding.relatedPaths) &&
    finding.relatedPaths.length <= 4096 &&
    new Set(finding.relatedPaths).size === finding.relatedPaths.length &&
    finding.relatedPaths.every(
      (path) => safePath(path) && allowedPaths.has(path),
    ) &&
    (finding.startLine === null ||
      (Number.isSafeInteger(finding.startLine) && finding.startLine > 0)) &&
    (finding.endLine === null ||
      (Number.isSafeInteger(finding.endLine) &&
        finding.endLine >= (finding.startLine ?? 1))) &&
    typeof finding.summary === "string" &&
    finding.summary.length > 0 &&
    finding.summary.length <= 4096 &&
    SHA256.test(finding.detailsSha256) &&
    Array.isArray(finding.resolutionEvidenceDigests) &&
    finding.resolutionEvidenceDigests.length <= 64 &&
    finding.resolutionEvidenceDigests.every((digest) => SHA256.test(digest))
  );
}

function validByteArtifact(value) {
  return (
    exactKeys(value, ["path", "encoding", "byteLength", "sha256"]) &&
    safePath(value.path) &&
    value.encoding === "UTF-8" &&
    Number.isSafeInteger(value.byteLength) &&
    value.byteLength >= 0 &&
    SHA256.test(value.sha256)
  );
}

function validResponseArtifact(value) {
  return (
    exactKeys(value, [
      "path",
      "encoding",
      "byteLength",
      "sha256",
      "httpStatus",
      "contentType",
    ]) &&
    validByteArtifact({
      path: value.path,
      encoding: value.encoding,
      byteLength: value.byteLength,
      sha256: value.sha256,
    }) &&
    value.httpStatus === 200 &&
    value.contentType === "application/json; charset=utf-8"
  );
}

async function resolveArtifact(evidenceResolver, artifact) {
  if (typeof evidenceResolver !== "function" || !safePath(artifact?.path)) {
    return null;
  }
  try {
    const bytes = await evidenceResolver(artifact.path);
    return Buffer.isBuffer(bytes) ? Buffer.from(bytes) : null;
  } catch {
    return null;
  }
}

function artifactMatches(artifact, bytes, response = false) {
  return (
    (response ? validResponseArtifact(artifact) : validByteArtifact(artifact)) &&
    Buffer.isBuffer(bytes) &&
    artifact.byteLength === bytes.byteLength &&
    artifact.sha256 === sha256Bytes(bytes)
  );
}

function ceilDiv(numerator, denominator) {
  return Math.floor((numerator + denominator - 1) / denominator);
}

function validProviderUsage(usage) {
  return (
    exactKeys(usage, [
      "prompt_tokens",
      "completion_tokens",
      "total_tokens",
      "cached_tokens",
    ]) &&
    [
      usage.prompt_tokens,
      usage.completion_tokens,
      usage.total_tokens,
      usage.cached_tokens,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    usage.completion_tokens <= K3_MAX_COMPLETION_TOKENS &&
    usage.cached_tokens <= usage.prompt_tokens &&
    usage.total_tokens === usage.prompt_tokens + usage.completion_tokens &&
    usage.total_tokens <= K3_CONTEXT_TOKENS
  );
}

function validTransportUsage(usage) {
  return (
    exactKeys(usage, [
      "promptTokens",
      "completionTokens",
      "totalTokens",
      "cachedTokens",
    ]) &&
    [
      usage.promptTokens,
      usage.completionTokens,
      usage.totalTokens,
      usage.cachedTokens,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    usage.completionTokens <= K3_MAX_COMPLETION_TOKENS &&
    usage.cachedTokens <= usage.promptTokens &&
    usage.totalTokens === usage.promptTokens + usage.completionTokens &&
    usage.totalTokens <= K3_CONTEXT_TOKENS
  );
}

function validTransportEvidenceShape(evidence) {
  const bindings = evidence?.bindings;
  return (
    exactKeys(evidence, [
      "schemaVersion",
      "evidenceId",
      "reviewKind",
      "provider",
      "requestedModel",
      "actualReturnedModel",
      "responseId",
      "baseURL",
      "endpoint",
      "source",
      "bindings",
      "request",
      "response",
      "content",
      "repositoryBefore",
      "repositoryAfter",
      "protocol",
      "usage",
      "cost",
      "validators",
      "startedAt",
      "finishedAt",
      "transportEvidenceSha256",
    ]) &&
    evidence.schemaVersion ===
      "independent-review-segmented-transport-evidence.v1" &&
    /^irste_[a-z0-9][a-z0-9_-]{7,127}$/u.test(evidence.evidenceId ?? "") &&
    ["SEGMENT", "INTEGRATION"].includes(evidence.reviewKind) &&
    evidence.provider === K3_PROVIDER &&
    evidence.requestedModel === K3_MODEL &&
    evidence.actualReturnedModel === K3_MODEL &&
    /^chatcmpl_[A-Za-z0-9_-]{8,255}$/u.test(evidence.responseId ?? "") &&
    evidence.baseURL === K3_BASE_URL &&
    evidence.endpoint === K3_CHAT_ENDPOINT &&
    exactKeys(evidence.source, ["sourceCommit", "sourceTree"]) &&
    COMMIT.test(evidence.source.sourceCommit) &&
    COMMIT.test(evidence.source.sourceTree) &&
    exactKeys(bindings, [
      "segmentPlanSha256",
      "reviewBundleSha256",
      "reviewMaterialSha256",
      "reviewerPromptSha256",
      "canonicalOutputSchemaSha256",
      "providerTransportSchemaSha256",
      "providerConfigSha256",
      "receiptSchemaSha256",
      "tokenEstimateEvidenceSchemaSha256",
      "tokenEstimateEvidenceSha256",
      "segmentedTransportEvidenceSchemaSha256",
      "formalRequestSha256",
      "messagesSha256",
      "nonMessageVisibleInputSha256",
    ]) &&
    Object.values(bindings).every((value) => SHA256.test(value)) &&
    validByteArtifact(evidence.request) &&
    validResponseArtifact(evidence.response) &&
    validByteArtifact(evidence.content) &&
    validByteArtifact(evidence.repositoryBefore) &&
    validByteArtifact(evidence.repositoryAfter) &&
    new Set([
      evidence.request.path,
      evidence.response.path,
      evidence.content.path,
      evidence.repositoryBefore.path,
      evidence.repositoryAfter.path,
    ]).size === 5 &&
    exactKeys(evidence.protocol, [
      "toolsAbsent",
      "toolChoiceNone",
      "thinkingAbsent",
      "reasoningEffort",
      "strictSchema",
      "maxCompletionTokens",
      "networkAttemptCount",
      "choiceCount",
      "finishReason",
      "providerTransportSchemaValidated",
      "canonicalOutputSchemaValidated",
      "semanticValidated",
    ]) &&
    evidence.protocol.toolsAbsent === true &&
    evidence.protocol.toolChoiceNone === true &&
    evidence.protocol.thinkingAbsent === true &&
    evidence.protocol.reasoningEffort === "max" &&
    evidence.protocol.strictSchema === true &&
    evidence.protocol.maxCompletionTokens === K3_MAX_COMPLETION_TOKENS &&
    evidence.protocol.networkAttemptCount === 1 &&
    evidence.protocol.choiceCount === 1 &&
    evidence.protocol.finishReason === "stop" &&
    evidence.protocol.providerTransportSchemaValidated === true &&
    evidence.protocol.canonicalOutputSchemaValidated === true &&
    evidence.protocol.semanticValidated === true &&
    validTransportUsage(evidence.usage) &&
    exactKeys(evidence.cost, [
      "currency",
      "taxBasis",
      "inputMicros",
      "outputMicros",
      "totalMicros",
      "budgetMicros",
      "withinBudget",
    ]) &&
    evidence.cost.currency === "USD" &&
    evidence.cost.taxBasis === "TAX_EXCLUSIVE" &&
    [
      evidence.cost.inputMicros,
      evidence.cost.outputMicros,
      evidence.cost.totalMicros,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    evidence.cost.budgetMicros === K3_BUDGET_MICROS &&
    evidence.cost.withinBudget === true &&
    exactKeys(evidence.validators, [
      "schemaValidatorVersion",
      "semanticValidatorVersion",
    ]) &&
    evidence.validators.schemaValidatorVersion === "ajv@8.20.0" &&
    evidence.validators.semanticValidatorVersion ===
      "kimi-k3-segmented-independent-review-validator.v1" &&
    validReceiptTimes(evidence.startedAt, evidence.finishedAt) &&
    SHA256.test(evidence.transportEvidenceSha256)
  );
}

export function createKimiSegmentedTransportEvidence(input) {
  const evidence = {
    ...clone(input),
    transportEvidenceSha256: `sha256:${"0".repeat(64)}`,
  };
  evidence.transportEvidenceSha256 = sha256Value(
    withoutField(evidence, "transportEvidenceSha256"),
  );
  return evidence;
}

function uniqueFindingIds(findings) {
  return (
    Array.isArray(findings) &&
    new Set(findings.map(({ findingId }) => findingId)).size === findings.length
  );
}

function modelOutputSemanticValid({ output, reviewKind, plan, segment }) {
  if (
    !exactKeys(output, [
      "schemaVersion",
      "reviewSummary",
      "findings",
      "decision",
    ]) ||
    output.schemaVersion !== "independent-model-segmented-review-output.v1" ||
    typeof output.reviewSummary !== "string" ||
    output.reviewSummary.length === 0 ||
    output.reviewSummary.length > 4096 ||
    !Array.isArray(output.findings) ||
    output.findings.length > 1024 ||
    !uniqueFindingIds(output.findings) ||
    !DECISIONS.has(output.decision)
  ) {
    return false;
  }
  const allPaths = new Set(
    plan.segments.flatMap(({ ownedPaths }) =>
      ownedPaths.map(({ path }) => path),
    ),
  );
  const allowedPaths =
    reviewKind === "SEGMENT"
      ? new Set(segment.ownedPaths.map(({ path }) => path))
      : allPaths;
  for (const finding of output.findings) {
    if (!validFinding(finding, allowedPaths, reviewKind === "INTEGRATION")) {
      return false;
    }
    if (reviewKind === "SEGMENT") {
      if (
        finding.path === null ||
        finding.relatedPaths.length === 0 ||
        !finding.relatedPaths.includes(finding.path)
      ) {
        return false;
      }
    } else {
      const relatedSegments = new Set(
        finding.relatedPaths.map((path) =>
          plan.segments.find(({ ownedPaths }) =>
            ownedPaths.some((subject) => subject.path === path),
          )?.segmentId,
        ),
      );
      if (
        finding.relatedPaths.length < 2 ||
        relatedSegments.has(undefined) ||
        relatedSegments.size < 2 ||
        (finding.path !== null && !finding.relatedPaths.includes(finding.path))
      ) {
        return false;
      }
    }
  }
  return !(
    output.decision === "CLEAR" &&
    output.findings.some(
      ({ severity, status }) =>
        status === "OPEN" && ["CRITICAL", "HIGH"].includes(severity),
    )
  );
}

function validFormalRequest(request) {
  return (
    exactKeys(request, [
      "model",
      "messages",
      "reasoning_effort",
      "tool_choice",
      "response_format",
      "max_completion_tokens",
    ]) &&
    request.model === K3_MODEL &&
    Array.isArray(request.messages) &&
    request.messages.length === 2 &&
    request.messages.every(
      (message, index) =>
        exactKeys(message, ["role", "content"]) &&
        message.role === (index === 0 ? "system" : "user") &&
        typeof message.content === "string" &&
        message.content.length > 0,
    ) &&
    request.reasoning_effort === "max" &&
    request.tool_choice === "none" &&
    !Object.hasOwn(request, "tools") &&
    !Object.hasOwn(request, "thinking") &&
    exactKeys(request.response_format, ["type", "json_schema"]) &&
    request.response_format.type === "json_schema" &&
    exactKeys(request.response_format.json_schema, ["name", "strict", "schema"]) &&
    request.response_format.json_schema.strict === true &&
    request.max_completion_tokens === K3_MAX_COMPLETION_TOKENS
  );
}

function nonMessageVisibleBytes(request) {
  if (!validFormalRequest(request)) return null;
  const copy = clone(request);
  delete copy.messages;
  return Buffer.from(canonicalize(copy), "utf8");
}

async function resolveBoundBytes(plan, evidenceResolver) {
  const resolved = {};
  for (const key of PLAN_BINDING_KEYS) {
    const bytes = await resolveArtifact(evidenceResolver, {
      ...plan.bindings[key],
      encoding: "UTF-8",
    });
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.byteLength !== plan.bindings[key].byteLength ||
      sha256Bytes(bytes) !== plan.bindings[key].sha256
    ) {
      fail("MODEL_EXECUTION_BINDING_BYTES_MISMATCH", `${key} bytes drifted.`);
    }
    resolved[key] = bytes;
  }
  return resolved;
}

function executionArtifacts({
  reviewMaterialArtifact,
  tokenEstimateEvidenceArtifact,
  transportEvidenceArtifact,
  transportEvidence,
}) {
  return {
    reviewMaterial: clone(reviewMaterialArtifact),
    tokenEstimateEvidence: clone(tokenEstimateEvidenceArtifact),
    transportEvidence: clone(transportEvidenceArtifact),
    request: clone(transportEvidence.request),
    response: clone(transportEvidence.response),
    content: clone(transportEvidence.content),
    repositoryBefore: clone(transportEvidence.repositoryBefore),
    repositoryAfter: clone(transportEvidence.repositoryAfter),
  };
}

export async function verifyKimiSegmentedModelExecution(input) {
  const commonKeys = [
    "reviewKind",
    "plan",
    "bundle",
    "reviewMaterialArtifact",
    "tokenEstimateEvidence",
    "tokenEstimateEvidenceArtifact",
    "transportEvidence",
    "transportEvidenceArtifact",
    "evidenceResolver",
    "sourceBytesResolver",
  ];
  const expectedKeys =
    input?.reviewKind === "INTEGRATION"
      ? [...commonKeys, "verifiedSegmentReceiptSet"]
      : commonKeys;
  if (
    !exactKeys(input, expectedKeys) ||
    !["SEGMENT", "INTEGRATION"].includes(input.reviewKind) ||
    typeof input.evidenceResolver !== "function" ||
    typeof input.sourceBytesResolver !== "function" ||
    !validByteArtifact(input.reviewMaterialArtifact) ||
    !validByteArtifact(input.tokenEstimateEvidenceArtifact) ||
    !validByteArtifact(input.transportEvidenceArtifact)
  ) {
    fail("MODEL_EXECUTION_PROOF_REQUIRED", "Exact verified execution input is required.");
  }
  const planValidation = await validateKimiSegmentReviewPlan({
    plan: input.plan,
    bundle: input.bundle,
    sourceBytesResolver: input.sourceBytesResolver,
  });
  if (!planValidation.ok) fail(planValidation.reasonCode, "Plan is invalid.");
  const [
    materialBytes,
    tokenEvidenceBytes,
    transportEvidenceBytes,
    boundBytes,
  ] = await Promise.all([
    resolveArtifact(input.evidenceResolver, input.reviewMaterialArtifact),
    resolveArtifact(input.evidenceResolver, input.tokenEstimateEvidenceArtifact),
    resolveArtifact(input.evidenceResolver, input.transportEvidenceArtifact),
    resolveBoundBytes(input.plan, input.evidenceResolver),
  ]);
  if (
    !artifactMatches(input.reviewMaterialArtifact, materialBytes) ||
    !artifactMatches(input.tokenEstimateEvidenceArtifact, tokenEvidenceBytes) ||
    !artifactMatches(input.transportEvidenceArtifact, transportEvidenceBytes) ||
    !sameValue(
      parseStrictJsonBytes(tokenEvidenceBytes, "MODEL_EXECUTION_TOKEN_EVIDENCE_INVALID"),
      input.tokenEstimateEvidence,
    ) ||
    !sameValue(
      parseStrictJsonBytes(transportEvidenceBytes, "MODEL_EXECUTION_TRANSPORT_EVIDENCE_INVALID"),
      input.transportEvidence,
    )
  ) {
    fail("MODEL_EXECUTION_ARTIFACT_MISMATCH", "Execution evidence bytes drifted.");
  }
  let segment = null;
  if (input.reviewKind === "SEGMENT") {
    const materialValidation = await validateKimiSegmentReviewMaterial({
      materialBytes,
      plan: input.plan,
      bundle: input.bundle,
      sourceBytesResolver: input.sourceBytesResolver,
    });
    if (!materialValidation.ok) {
      fail(materialValidation.reasonCode, "Segment Material is invalid.");
    }
    const parsed = parseKimiSegmentReviewMaterial(materialBytes);
    segment = input.plan.segments.find(
      ({ segmentId }) => segmentId === parsed.material.segment.segmentId,
    );
  } else {
    if (!VERIFIED_SEGMENT_RECEIPT_SETS.has(input.verifiedSegmentReceiptSet)) {
      fail("SEGMENT_RECEIPT_SET_INVALID", "Verified Segment Receipt set is required.");
    }
    const materialValidation = await validateKimiIntegrationReviewMaterial({
      materialBytes,
      plan: input.plan,
      bundle: input.bundle,
      verifiedSegmentReceiptSet: input.verifiedSegmentReceiptSet,
      sourceBytesResolver: input.sourceBytesResolver,
    });
    if (!materialValidation.ok) {
      fail(materialValidation.reasonCode, "Integration Material is invalid.");
    }
  }
  const tokenValidation = await validateKimiK3TokenEstimateEvidenceV2({
    evidence: input.tokenEstimateEvidence,
    evidenceResolver: input.evidenceResolver,
  });
  if (!tokenValidation.valid) {
    fail("MODEL_EXECUTION_TOKEN_EVIDENCE_INVALID", tokenValidation.reasonCodes.join(","));
  }
  const evidence = input.transportEvidence;
  if (
    !validTransportEvidenceShape(evidence) ||
    evidence.transportEvidenceSha256 !==
      sha256Value(withoutField(evidence, "transportEvidenceSha256")) ||
    evidence.reviewKind !== input.reviewKind ||
    !sameValue(evidence.source, {
      sourceCommit: input.plan.source.sourceCommit,
      sourceTree: input.plan.source.tree,
    })
  ) {
    fail("MODEL_EXECUTION_TRANSPORT_EVIDENCE_INVALID", "Transport evidence is invalid.");
  }
  const receiptSchemaKey =
    input.reviewKind === "SEGMENT"
      ? "segmentReceiptSchema"
      : "integrationReceiptSchema";
  const promptKey =
    input.reviewKind === "SEGMENT"
      ? "segmentReviewerPrompt"
      : "integrationReviewerPrompt";
  const token = input.tokenEstimateEvidence;
  if (
    evidence.bindings.segmentPlanSha256 !== input.plan.planSha256 ||
    evidence.bindings.reviewBundleSha256 !== input.plan.bindings.reviewBundle.sha256 ||
    evidence.bindings.reviewMaterialSha256 !== input.reviewMaterialArtifact.sha256 ||
    evidence.bindings.reviewerPromptSha256 !== input.plan.bindings[promptKey].sha256 ||
    evidence.bindings.canonicalOutputSchemaSha256 !== input.plan.bindings.canonicalOutputSchema.sha256 ||
    evidence.bindings.providerTransportSchemaSha256 !== input.plan.bindings.providerTransportSchema.sha256 ||
    evidence.bindings.providerConfigSha256 !== input.plan.bindings.providerConfig.sha256 ||
    evidence.bindings.receiptSchemaSha256 !== input.plan.bindings[receiptSchemaKey].sha256 ||
    evidence.bindings.tokenEstimateEvidenceSchemaSha256 !== input.plan.bindings.tokenEstimateEvidenceSchema.sha256 ||
    evidence.bindings.segmentedTransportEvidenceSchemaSha256 !== input.plan.bindings.segmentedTransportEvidenceSchema.sha256 ||
    evidence.bindings.tokenEstimateEvidenceSha256 !== token.evidenceSha256 ||
    evidence.bindings.formalRequestSha256 !== token.bindings.formalRequestSha256 ||
    evidence.bindings.messagesSha256 !== token.bindings.messagesSha256 ||
    evidence.bindings.nonMessageVisibleInputSha256 !== token.bindings.nonMessageVisibleInputSha256 ||
    token.source.sourceCommit !== input.plan.source.sourceCommit ||
    token.source.sourceTree !== input.plan.source.tree ||
    token.bindings.reviewMaterialSha256 !== input.reviewMaterialArtifact.sha256 ||
    token.bindings.reviewBundleSha256 !== input.plan.bindings.reviewBundle.sha256 ||
    token.bindings.configSha256 !== input.plan.bindings.providerConfig.sha256 ||
    token.bindings.configSchemaSha256 !== input.plan.bindings.providerConfigSchema.sha256 ||
    token.bindings.outputSchemaSha256 !==
      sha256Value(parseStrictJsonBytes(boundBytes.providerTransportSchema, "MODEL_EXECUTION_SCHEMA_INVALID"))
  ) {
    fail("MODEL_EXECUTION_BINDING_MISMATCH", "Execution bindings drifted.");
  }
  const [requestBytes, responseBytes, contentBytes, beforeBytes, afterBytes] =
    await Promise.all([
      resolveArtifact(input.evidenceResolver, evidence.request),
      resolveArtifact(input.evidenceResolver, evidence.response),
      resolveArtifact(input.evidenceResolver, evidence.content),
      resolveArtifact(input.evidenceResolver, evidence.repositoryBefore),
      resolveArtifact(input.evidenceResolver, evidence.repositoryAfter),
    ]);
  if (
    !artifactMatches(evidence.request, requestBytes) ||
    !artifactMatches(evidence.response, responseBytes, true) ||
    !artifactMatches(evidence.content, contentBytes) ||
    !artifactMatches(evidence.repositoryBefore, beforeBytes) ||
    !artifactMatches(evidence.repositoryAfter, afterBytes) ||
    !beforeBytes.equals(afterBytes)
  ) {
    fail("MODEL_EXECUTION_BYTES_MISMATCH", "Execution bytes or repository snapshot drifted.");
  }
  const repositoryBefore = parseStrictJsonBytes(
    beforeBytes,
    "MODEL_EXECUTION_REPOSITORY_SNAPSHOT_INVALID",
  );
  const repositoryAfter = parseStrictJsonBytes(
    afterBytes,
    "MODEL_EXECUTION_REPOSITORY_SNAPSHOT_INVALID",
  );
  if (
    !validRepositorySnapshot(repositoryBefore, input.plan) ||
    !sameValue(repositoryBefore, repositoryAfter)
  ) {
    fail(
      "MODEL_EXECUTION_REPOSITORY_SNAPSHOT_INVALID",
      "Repository snapshots do not bind the exact source commit and tree.",
    );
  }
  const request = parseStrictJsonBytes(requestBytes, "MODEL_EXECUTION_REQUEST_INVALID");
  const response = parseStrictJsonBytes(responseBytes, "MODEL_EXECUTION_RESPONSE_INVALID");
  const output = parseStrictJsonBytes(contentBytes, "MODEL_EXECUTION_OUTPUT_INVALID");
  const providerSchema = parseStrictJsonBytes(
    boundBytes.providerTransportSchema,
    "MODEL_EXECUTION_SCHEMA_INVALID",
  );
  const nonMessageBytes = nonMessageVisibleBytes(request);
  const promptBytes = Buffer.from(request?.messages?.[0]?.content ?? "", "utf8");
  const requestMaterialBytes = Buffer.from(
    request?.messages?.[1]?.content ?? "",
    "utf8",
  );
  if (
    !validFormalRequest(request) ||
    sha256Bytes(requestBytes) !== evidence.bindings.formalRequestSha256 ||
    sha256Bytes(Buffer.from(JSON.stringify(request.messages), "utf8")) !== evidence.bindings.messagesSha256 ||
    sha256Bytes(promptBytes) !== input.plan.bindings[promptKey].sha256 ||
    !requestMaterialBytes.equals(materialBytes) ||
    !sameValue(request.response_format.json_schema.schema, providerSchema) ||
    !nonMessageBytes ||
    sha256Bytes(nonMessageBytes) !== evidence.bindings.nonMessageVisibleInputSha256
  ) {
    fail("MODEL_EXECUTION_REQUEST_INVALID", "Formal request binding is invalid.");
  }
  const providerValidation = await validateIndependentReviewSchemaInstance({
    schemaBytes: boundBytes.providerTransportSchema,
    expectedSchemaSha256: input.plan.bindings.providerTransportSchema.sha256,
    instance: output,
    label: "Segmented provider output",
  });
  const canonicalValidation = await validateIndependentReviewSchemaInstance({
    schemaBytes: boundBytes.canonicalOutputSchema,
    expectedSchemaSha256: input.plan.bindings.canonicalOutputSchema.sha256,
    instance: output,
    label: "Segmented canonical output",
  });
  const choice = response?.choices?.[0];
  const message = choice?.message;
  const messageKeys = Object.keys(message ?? {}).sort();
  const responseValid =
    exactKeys(response, ["id", "object", "created", "model", "choices", "usage"]) &&
    response.id === evidence.responseId &&
    response.object === "chat.completion" &&
    Number.isSafeInteger(response.created) &&
    response.created >= 0 &&
    response.model === K3_MODEL &&
    Array.isArray(response.choices) &&
    response.choices.length === 1 &&
    exactKeys(choice, ["index", "message", "finish_reason"]) &&
    choice.index === 0 &&
    choice.finish_reason === "stop" &&
    (sameValue(messageKeys, ["content", "role"]) ||
      sameValue(messageKeys, ["content", "reasoning_content", "role"])) &&
    message.role === "assistant" &&
    message.content === new TextDecoder("utf-8", { fatal: true }).decode(contentBytes) &&
    !Object.hasOwn(message, "tool_calls") &&
    !Object.hasOwn(message, "function_call") &&
    validProviderUsage(response.usage) &&
    response.usage.prompt_tokens === evidence.usage.promptTokens &&
    response.usage.completion_tokens === evidence.usage.completionTokens &&
    response.usage.total_tokens === evidence.usage.totalTokens &&
    response.usage.cached_tokens === evidence.usage.cachedTokens;
  const inputMicros = ceilDiv(
    (evidence.usage.promptTokens - evidence.usage.cachedTokens) * 3_000_000 +
      evidence.usage.cachedTokens * 300_000,
    1_000_000,
  );
  const outputMicros = ceilDiv(
    evidence.usage.completionTokens * 15_000_000,
    1_000_000,
  );
  if (
    !responseValid ||
    providerValidation.ok !== true ||
    canonicalValidation.ok !== true ||
    !modelOutputSemanticValid({
      output,
      reviewKind: input.reviewKind,
      plan: input.plan,
      segment,
    }) ||
    evidence.cost.inputMicros !== inputMicros ||
    evidence.cost.outputMicros !== outputMicros ||
    evidence.cost.totalMicros !== inputMicros + outputMicros ||
    evidence.cost.withinBudget !==
      (evidence.cost.totalMicros <= evidence.cost.budgetMicros)
  ) {
    fail("MODEL_EXECUTION_RESPONSE_INVALID", "K3 response or output is invalid.");
  }
  const proofData = Object.freeze({
    reviewKind: input.reviewKind,
    planSha256: input.plan.planSha256,
    planSnapshot: immutableClone(input.plan),
    segmentId: segment?.segmentId ?? null,
    output: immutableClone(output),
    reviewerSessionId: evidence.responseId,
    usage: immutableClone(evidence.usage),
    actualCostMicros: evidence.cost.totalMicros,
    startedAt: evidence.startedAt,
    finishedAt: evidence.finishedAt,
    artifacts: immutableClone(executionArtifacts({
      reviewMaterialArtifact: input.reviewMaterialArtifact,
      tokenEstimateEvidenceArtifact: input.tokenEstimateEvidenceArtifact,
      transportEvidenceArtifact: input.transportEvidenceArtifact,
      transportEvidence: evidence,
    })),
  });
  const proof = Object.freeze({ kind: "VERIFIED_KIMI_MODEL_EXECUTION" });
  VERIFIED_EXECUTIONS.add(proof);
  VERIFIED_EXECUTION_DATA.set(proof, proofData);
  return proof;
}

function validReviewer(reviewer) {
  return (
    exactKeys(reviewer, [
      "provider",
      "requestedModel",
      "actualReturnedModel",
      "reviewerSessionId",
      "independentOfImplementation",
    ]) &&
    reviewer.provider === "moonshot" &&
    reviewer.requestedModel === "kimi-k3" &&
    reviewer.actualReturnedModel === "kimi-k3" &&
    typeof reviewer.reviewerSessionId === "string" &&
    reviewer.reviewerSessionId.length >= 8 &&
    reviewer.reviewerSessionId.length <= 256 &&
    reviewer.independentOfImplementation === true
  );
}

function validRepositorySnapshot(snapshot, plan) {
  return (
    exactKeys(snapshot, [
      "head",
      "tree",
      "worktreeStatusSha256",
      "worktreeContentManifestSha256",
      "worktreePathCount",
      "protectedPathSetSha256",
      "protectedFilesDigest",
      "ignoredExclusionPolicySha256",
      "ignoredExcludedPathCount",
    ]) &&
    snapshot.head === plan.source.sourceCommit &&
    snapshot.tree === plan.source.tree &&
    [
      snapshot.worktreeStatusSha256,
      snapshot.worktreeContentManifestSha256,
      snapshot.protectedPathSetSha256,
      snapshot.protectedFilesDigest,
      snapshot.ignoredExclusionPolicySha256,
    ].every((value) => SHA256.test(value)) &&
    Number.isSafeInteger(snapshot.worktreePathCount) &&
    snapshot.worktreePathCount >= 0 &&
    Number.isSafeInteger(snapshot.ignoredExcludedPathCount) &&
    snapshot.ignoredExcludedPathCount >= 0
  );
}

function validArtifacts(artifacts, expectedArtifacts) {
  const keys = [
    "reviewMaterial",
    "tokenEstimateEvidence",
    "transportEvidence",
    "request",
    "response",
    "content",
    "repositoryBefore",
    "repositoryAfter",
  ];
  return (
    exactKeys(artifacts, keys) &&
    keys.every((key) =>
      key === "response"
        ? validResponseArtifact(artifacts[key])
        : validByteArtifact(artifacts[key]),
    ) &&
    sameValue(artifacts, expectedArtifacts)
  );
}

function validUsage(usage) {
  const keys = [
    "promptTokens",
    "completionTokens",
    "totalTokens",
    "cachedTokens",
  ];
  return (
    exactKeys(usage, keys) &&
    keys.every((key) => Number.isSafeInteger(usage[key]) && usage[key] >= 0) &&
    usage.totalTokens === usage.promptTokens + usage.completionTokens &&
    usage.cachedTokens <= usage.promptTokens
  );
}

function validReceiptTimes(startedAt, finishedAt) {
  return (
    typeof startedAt === "string" &&
    typeof finishedAt === "string" &&
    !Number.isNaN(Date.parse(startedAt)) &&
    !Number.isNaN(Date.parse(finishedAt)) &&
    Date.parse(finishedAt) >= Date.parse(startedAt)
  );
}

function validModelReceiptCommon({
  receipt,
  proof,
  allowedPaths,
  allowNullPath,
  expectedConclusion,
}) {
  return (
    typeof receipt.receiptId === "string" &&
    receipt.receiptId.length >= 8 &&
    receipt.receiptId.length <= 160 &&
    validReviewer(receipt.reviewer) &&
    proof &&
    receipt.reviewer.reviewerSessionId === proof.reviewerSessionId &&
    validArtifacts(receipt.artifacts, proof.artifacts) &&
    validUsage(receipt.usage) &&
    sameValue(receipt.usage, proof.usage) &&
    Number.isSafeInteger(receipt.actualCostMicros) &&
    receipt.actualCostMicros === proof.actualCostMicros &&
    receipt.actualCostMicros <= K3_BUDGET_MICROS &&
    Array.isArray(receipt.findings) &&
    receipt.findings.length <= 1024 &&
    uniqueFindingIds(receipt.findings) &&
    receipt.findings.every((finding) =>
      validFinding(finding, allowedPaths, allowNullPath),
    ) &&
    sameValue(receipt.findings, proof.output.findings) &&
    receipt.findingsSha256 === sha256Value(receipt.findings) &&
    DECISIONS.has(receipt.decision) &&
    receipt.decision === proof.output.decision &&
    receipt.conclusion === expectedConclusion &&
    !(
      receipt.decision === "CLEAR" &&
      receipt.findings.some(
        ({ severity, status }) =>
          status === "OPEN" && ["CRITICAL", "HIGH"].includes(severity),
      )
    ) &&
    receipt.modelReviewClearForPreproduction === false &&
    receipt.humanReviewClaim === false &&
    receipt.governanceEffect === "NONE" &&
    validReceiptTimes(receipt.startedAt, receipt.finishedAt) &&
    receipt.startedAt === proof.startedAt &&
    receipt.finishedAt === proof.finishedAt &&
    SHA256.test(receipt.receiptSha256) &&
    sha256Value(withoutField(receipt, "receiptSha256")) ===
      receipt.receiptSha256
  );
}

function segmentConclusion(decision) {
  return `SEGMENT_REVIEW_${decision}`;
}

export function createKimiSegmentReceipt(input) {
  if (
    !exactKeys(input, ["receiptId", "plan", "verifiedExecution"]) ||
    !VERIFIED_EXECUTIONS.has(input.verifiedExecution) ||
    VERIFIED_EXECUTION_DATA.get(input.verifiedExecution)?.reviewKind !== "SEGMENT"
  ) {
    fail("MODEL_EXECUTION_PROOF_REQUIRED", "Verified Segment execution is required.");
  }
  const proof = VERIFIED_EXECUTION_DATA.get(input.verifiedExecution);
  if (!sameValue(input.plan, proof.planSnapshot)) {
    fail("SEGMENT_RECEIPT_SCOPE_INVALID", "Segment Plan binding drifted.");
  }
  const plan = proof.planSnapshot;
  const segment = plan?.segments?.find(
    ({ segmentId }) =>
      segmentId === proof.segmentId,
  );
  const expectedSegment = plan?.segments?.find(
    ({ segmentId }) => segment?.segmentId === segmentId,
  );
  if (
    !expectedSegment ||
    !sameValue(expectedSegment, segment) ||
    proof.planSha256 !== plan.planSha256 ||
    typeof input.receiptId !== "string" ||
    input.receiptId.length < 8 ||
    input.receiptId.length > 160
  ) {
    fail("SEGMENT_RECEIPT_SCOPE_INVALID", "Segment does not belong to plan.");
  }
  const findings = clone(proof.output.findings);
  const receipt = {
    schemaVersion: "kimi-segment-review-receipt.v1",
    receiptId: input.receiptId,
    segmentPlanSha256: plan.planSha256,
    source: clone(plan.source),
    bundleSha256: plan.bindings.reviewBundle.sha256,
    segment: {
      segmentId: segment.segmentId,
      ordinal: segment.ordinal,
      semanticScope: segment.semanticScope,
      pathSetSha256: segment.pathSetSha256,
      reviewedPaths: segment.ownedPaths.map(({ path }) => path),
    },
    reviewer: {
      provider: "moonshot",
      requestedModel: "kimi-k3",
      actualReturnedModel: "kimi-k3",
      reviewerSessionId: proof.reviewerSessionId,
      independentOfImplementation: true,
    },
    artifacts: clone(proof.artifacts),
    usage: clone(proof.usage),
    actualCostMicros: proof.actualCostMicros,
    findings,
    findingsSha256: sha256Value(findings),
    decision: proof.output.decision,
    conclusion: segmentConclusion(proof.output.decision),
    modelReviewClearForPreproduction: false,
    humanReviewClaim: false,
    governanceEffect: "NONE",
    startedAt: proof.startedAt,
    finishedAt: proof.finishedAt,
  };
  const signed = { ...receipt, receiptSha256: sha256Value(receipt) };
  if (
    !validateKimiSegmentReceipt({
      receipt: signed,
      plan,
      verifiedExecution: input.verifiedExecution,
    }).ok
  ) {
    fail("SEGMENT_RECEIPT_INVALID", "Generated Segment Receipt is invalid.");
  }
  return signed;
}

export function validateKimiSegmentReceipt({
  receipt,
  plan,
  verifiedExecution,
}) {
  try {
    if (
      !VERIFIED_EXECUTIONS.has(verifiedExecution) ||
      VERIFIED_EXECUTION_DATA.get(verifiedExecution)?.reviewKind !== "SEGMENT" ||
      VERIFIED_EXECUTION_DATA.get(verifiedExecution)?.planSha256 !== plan.planSha256 ||
      !sameValue(
        plan,
        VERIFIED_EXECUTION_DATA.get(verifiedExecution)?.planSnapshot,
      )
    ) {
      return { ok: false, reasonCode: "MODEL_EXECUTION_PROOF_REQUIRED" };
    }
    const proof = VERIFIED_EXECUTION_DATA.get(verifiedExecution);
    const segment = plan?.segments?.find(
      ({ segmentId }) => segmentId === receipt?.segment?.segmentId,
    );
    const allowedPaths = new Set(segment?.ownedPaths?.map(({ path }) => path));
    if (
      !segment ||
      !exactKeys(receipt, [
        "schemaVersion",
        "receiptId",
        "segmentPlanSha256",
        "source",
        "bundleSha256",
        "segment",
        "reviewer",
        "artifacts",
        "usage",
        "actualCostMicros",
        "findings",
        "findingsSha256",
        "decision",
        "conclusion",
        "modelReviewClearForPreproduction",
        "humanReviewClaim",
        "governanceEffect",
        "startedAt",
        "finishedAt",
        "receiptSha256",
      ]) ||
      receipt?.schemaVersion !== "kimi-segment-review-receipt.v1" ||
      receipt?.segmentPlanSha256 !== plan.planSha256 ||
      !sameValue(receipt.source, plan.source) ||
      !exactKeys(receipt.source, [
        "baseCommit",
        "sourceCommit",
        "headCommit",
        "tree",
        "diffSha256",
        "changedPathsDigest",
      ]) ||
      receipt.bundleSha256 !== plan.bindings.reviewBundle.sha256 ||
      !exactKeys(receipt.segment, [
        "segmentId",
        "ordinal",
        "semanticScope",
        "pathSetSha256",
        "reviewedPaths",
      ]) ||
      receipt.segment.segmentId !== segment.segmentId ||
      receipt.segment.segmentId !== proof.segmentId ||
      receipt.segment.ordinal !== segment.ordinal ||
      receipt.segment.semanticScope !== segment.semanticScope ||
      !sameValue(receipt.segment.reviewedPaths, [...allowedPaths]) ||
      receipt.segment.pathSetSha256 !== segment.pathSetSha256 ||
      !validModelReceiptCommon({
        receipt,
        proof,
        allowedPaths,
        allowNullPath: false,
        expectedConclusion: segmentConclusion(receipt.decision),
      })
    ) {
      return { ok: false, reasonCode: "SEGMENT_RECEIPT_INVALID" };
    }
    return { ok: true, reasonCode: null };
  } catch {
    return { ok: false, reasonCode: "SEGMENT_RECEIPT_INVALID" };
  }
}

export function verifyKimiSegmentReceiptSet({
  plan,
  segmentReceipts,
  verifiedExecutions,
}) {
  if (
    !Array.isArray(segmentReceipts) ||
    segmentReceipts.length !== 4 ||
    !Array.isArray(verifiedExecutions) ||
    verifiedExecutions.length !== 4
  ) {
    fail("SEGMENT_RECEIPT_SET_INVALID", "Exactly four verified receipts are required.");
  }
  const sessions = new Set();
  const findingIds = new Set();
  for (let index = 0; index < plan.segments.length; index += 1) {
    const receipt = segmentReceipts[index];
    const proofToken = verifiedExecutions[index];
    const proof = VERIFIED_EXECUTION_DATA.get(proofToken);
    if (
      proof?.segmentId !== plan.segments[index].segmentId ||
      receipt?.segment?.segmentId !== plan.segments[index].segmentId ||
      !validateKimiSegmentReceipt({
        receipt,
        plan,
        verifiedExecution: proofToken,
      }).ok ||
      sessions.has(receipt.reviewer.reviewerSessionId) ||
      receipt.findings.some(({ findingId }) => findingIds.has(findingId))
    ) {
      fail("SEGMENT_RECEIPT_SET_INVALID", "Segment receipt set is invalid.");
    }
    sessions.add(receipt.reviewer.reviewerSessionId);
    for (const { findingId } of receipt.findings) findingIds.add(findingId);
  }
  const planSnapshot = immutableClone(plan);
  const setData = Object.freeze({
    planSha256: planSnapshot.planSha256,
    planSnapshot,
    segmentReceipts: immutableClone(segmentReceipts),
    verifiedExecutions: Object.freeze([...verifiedExecutions]),
    sessionIds: Object.freeze([...sessions]),
  });
  const set = Object.freeze({ kind: "VERIFIED_KIMI_SEGMENT_RECEIPT_SET" });
  VERIFIED_SEGMENT_RECEIPT_SETS.add(set);
  VERIFIED_SEGMENT_RECEIPT_SET_DATA.set(set, setData);
  return set;
}

function receiptBinding(receipt, segmentId) {
  const bytes = Buffer.from(canonicalize(receipt), "utf8");
  return {
    receiptId: receipt.receiptId,
    segmentId,
    decision: receipt.decision,
    receiptSha256: receipt.receiptSha256,
    byteLength: bytes.byteLength,
    bytesSha256: sha256Bytes(bytes),
  };
}

export async function buildKimiIntegrationReviewMaterial({
  plan,
  bundle,
  bundleBytes,
  verifiedSegmentReceiptSet,
  patchBytes,
  bytesResolver,
  sourceBytesResolver,
}) {
  const planValidation = await validateKimiSegmentReviewPlan({
    plan,
    bundle,
    sourceBytesResolver,
  });
  if (!planValidation.ok) fail(planValidation.reasonCode, "Plan is invalid.");
  if (
    !VERIFIED_SEGMENT_RECEIPT_SETS.has(verifiedSegmentReceiptSet) ||
    VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(verifiedSegmentReceiptSet)
      ?.planSha256 !== plan.planSha256 ||
    !sameValue(
      plan,
      VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(verifiedSegmentReceiptSet)
        ?.planSnapshot,
    )
  ) {
    fail("SEGMENT_RECEIPT_SET_INVALID", "Verified Segment Receipt set is required.");
  }
  const segmentReceipts = VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(
    verifiedSegmentReceiptSet,
  ).segmentReceipts;
  assertDescriptorBytes(plan.bindings.reviewBundle, bundleBytes, "SEGMENT_BUNDLE_BYTES_MISMATCH");
  if (!sameValue(parseStrictJsonBytes(bundleBytes, "SEGMENT_BUNDLE_BYTES_MISMATCH"), bundle)) {
    fail("SEGMENT_BUNDLE_BYTES_MISMATCH", "Bundle object and frozen bytes disagree.");
  }
  assertBytes(patchBytes, "INTEGRATION_PATCH_BYTES_MISMATCH");
  if (sha256Bytes(patchBytes) !== plan.source.diffSha256) {
    fail("INTEGRATION_PATCH_BYTES_MISMATCH", "Patch does not match Bundle.");
  }
  validateIntegrationSections(plan.integrationSections);
  if (typeof bytesResolver !== "function") {
    fail("INTEGRATION_MATERIAL_INVALID", "Integration resolver is required.");
  }
  const boundSections = bindingSections(plan.bindings);
  const boundBytes = [];
  for (const section of boundSections) {
    const bytes =
      section.binding === "reviewBundle"
        ? bundleBytes
        : await bytesResolver(section.path);
    assertDescriptorBytes(section, bytes, "INTEGRATION_BINDING_BYTES_MISMATCH");
    boundBytes.push(Buffer.from(bytes));
  }
  const receiptBindings = segmentReceipts.map((receipt) =>
    receiptBinding(receipt, receipt.segment.segmentId),
  );
  const receiptBytes = segmentReceipts.map((receipt) =>
    Buffer.from(canonicalize(receipt), "utf8"),
  );
  const integrationBytes = [];
  for (const section of plan.integrationSections) {
    const bytes = await bytesResolver(section.path);
    assertDescriptorBytes(section, bytes, "INTEGRATION_SECTION_BYTES_MISMATCH");
    integrationBytes.push(Buffer.from(bytes));
  }
  const fullPatch = descriptor("artifacts/source.diff", patchBytes);
  const relationshipSubject = {
    reviewedPaths: bundle.reviewedPaths,
    sourceSubjects: bundle.sourceSubjects,
  };
  const payloadOrder = [
    ...sectionPayloadOrder("BINDING", boundSections),
    ...receiptBindings.map((binding, index) => ({
      scope: "SEGMENT_RECEIPT",
      index,
      path: `receipts/${binding.segmentId}.json`,
      byteLength: binding.byteLength,
      sha256: binding.bytesSha256,
    })),
    {
      scope: "FULL_PATCH",
      index: 0,
      ...fullPatch,
    },
    ...sectionPayloadOrder("INTEGRATION_CONTRACT", plan.integrationSections),
  ];
  const material = {
    schemaVersion: "kimi-cross-cutting-integration-material.v1",
    materialId: `${plan.planId}_cross_cutting_integration`,
    segmentPlanSha256: plan.planSha256,
    source: clone(plan.source),
    bindings: clone(plan.bindings),
    segmentReceiptBindings: receiptBindings,
    fullPatch,
    bundlePathInventoryDigest: sha256Value(relationshipSubject),
    integrationSections: clone(plan.integrationSections),
    payloadOrder,
    payloadUtf8ByteLength: payloadOrder.reduce(
      (total, { byteLength }) => total + byteLength,
      0,
    ),
    pathOwnershipEffect: "NONE_REPEATED_READING_DOES_NOT_CHANGE_OWNERSHIP",
    executionAuthorization: "LOCAL_MATERIALIZATION_ONLY_NO_NETWORK",
  };
  material.materialSha256 = sha256Value(material);
  const materialBytes = encodeMaterialEnvelope(
    INTEGRATION_MATERIAL_MAGIC,
    material,
    [
      ...boundBytes,
      ...receiptBytes,
      Buffer.from(patchBytes),
      ...integrationBytes,
    ],
  );
  return {
    material,
    materialBytes,
    materialBytesSha256: sha256Bytes(materialBytes),
  };
}

export function parseKimiIntegrationReviewMaterial(materialBytes) {
  const { material, payloads } = parseMaterialEnvelope(
    materialBytes,
    INTEGRATION_MATERIAL_MAGIC,
  );
  if (
    material.schemaVersion !==
      "kimi-cross-cutting-integration-material.v1" ||
    material.executionAuthorization !==
      "LOCAL_MATERIALIZATION_ONLY_NO_NETWORK" ||
    material.pathOwnershipEffect !==
      "NONE_REPEATED_READING_DOES_NOT_CHANGE_OWNERSHIP"
  ) {
    fail("INTEGRATION_MATERIAL_INVALID", "Unexpected integration contract.");
  }
  const bindingCount = material.bindingSections?.length ??
    PLAN_BINDING_KEYS.length;
  const receiptCount = material.segmentReceiptBindings.length;
  const patchIndex = bindingCount + receiptCount;
  return {
    material,
    bindingSectionBytes: payloads.slice(0, bindingCount),
    segmentReceiptBytes: payloads.slice(bindingCount, patchIndex),
    patchBytes: payloads[patchIndex],
    integrationSectionBytes: payloads.slice(patchIndex + 1),
  };
}

export async function validateKimiIntegrationReviewMaterial({
  materialBytes,
  plan,
  bundle,
  verifiedSegmentReceiptSet,
  sourceBytesResolver,
}) {
  try {
    const planValidation = await validateKimiSegmentReviewPlan({
      plan,
      bundle,
      sourceBytesResolver,
    });
    if (!planValidation.ok) {
      return { ok: false, reasonCode: planValidation.reasonCode };
    }
    if (
      !VERIFIED_SEGMENT_RECEIPT_SETS.has(verifiedSegmentReceiptSet) ||
      VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(verifiedSegmentReceiptSet)
        ?.planSha256 !== plan.planSha256 ||
      !sameValue(
        plan,
        VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(verifiedSegmentReceiptSet)
          ?.planSnapshot,
      )
    ) {
      return { ok: false, reasonCode: "SEGMENT_RECEIPT_SET_INVALID" };
    }
    const segmentReceipts = VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(
      verifiedSegmentReceiptSet,
    ).segmentReceipts;
    const parsed = parseKimiIntegrationReviewMaterial(materialBytes);
    const { material } = parsed;
    const expectedBindingSections = bindingSections(plan.bindings);
    const expectedReceiptBindings = segmentReceipts.map((receipt) =>
      receiptBinding(receipt, receipt.segment.segmentId),
    );
    const expectedFullPatch = {
      path: "artifacts/source.diff",
      byteLength: parsed.patchBytes.byteLength,
      sha256: plan.source.diffSha256,
    };
    const expectedPayloadOrder = [
      ...sectionPayloadOrder("BINDING", expectedBindingSections),
      ...expectedReceiptBindings.map((binding, index) => ({
        scope: "SEGMENT_RECEIPT",
        index,
        path: `receipts/${binding.segmentId}.json`,
        byteLength: binding.byteLength,
        sha256: binding.bytesSha256,
      })),
      { scope: "FULL_PATCH", index: 0, ...expectedFullPatch },
      ...sectionPayloadOrder(
        "INTEGRATION_CONTRACT",
        plan.integrationSections,
      ),
    ];
    validateIntegrationSections(material.integrationSections);
    const relationshipSubject = {
      reviewedPaths: bundle.reviewedPaths,
      sourceSubjects: bundle.sourceSubjects,
    };
    if (
      !exactKeys(material, [
        "schemaVersion",
        "materialId",
        "segmentPlanSha256",
        "source",
        "bindings",
        "segmentReceiptBindings",
        "fullPatch",
        "bundlePathInventoryDigest",
        "integrationSections",
        "payloadOrder",
        "payloadUtf8ByteLength",
        "pathOwnershipEffect",
        "executionAuthorization",
        "materialSha256",
      ]) ||
      material.materialId !==
        `${plan.planId}_cross_cutting_integration` ||
      material.segmentPlanSha256 !== plan.planSha256 ||
      !sameValue(material.source, plan.source) ||
      !sameValue(material.bindings, plan.bindings) ||
      !sameValue(material.segmentReceiptBindings, expectedReceiptBindings) ||
      !sameValue(material.fullPatch, expectedFullPatch) ||
      material.bundlePathInventoryDigest !== sha256Value(relationshipSubject) ||
      !sameValue(material.integrationSections, plan.integrationSections) ||
      !sameValue(material.payloadOrder, expectedPayloadOrder) ||
      material.payloadUtf8ByteLength !==
        expectedPayloadOrder.reduce(
          (total, { byteLength }) => total + byteLength,
          0,
        ) ||
      parsed.bindingSectionBytes.length !== expectedBindingSections.length ||
      parsed.segmentReceiptBytes.length !== expectedReceiptBindings.length ||
      parsed.integrationSectionBytes.length !==
        material.integrationSections.length ||
      sha256Bytes(parsed.patchBytes) !== plan.source.diffSha256
    ) {
      return { ok: false, reasonCode: "INTEGRATION_MATERIAL_INVALID" };
    }
    for (let index = 0; index < expectedBindingSections.length; index += 1) {
      const section = expectedBindingSections[index];
      if (
        parsed.bindingSectionBytes[index]?.byteLength !== section.byteLength ||
        sha256Bytes(parsed.bindingSectionBytes[index]) !== section.sha256
      ) {
        return { ok: false, reasonCode: "INTEGRATION_BINDING_BYTES_MISMATCH" };
      }
    }
    if (
      !sameValue(
        parseStrictJsonBytes(
          parsed.bindingSectionBytes[0],
          "SEGMENT_BUNDLE_BYTES_MISMATCH",
        ),
        bundle,
      )
    ) {
      return { ok: false, reasonCode: "SEGMENT_BUNDLE_BYTES_MISMATCH" };
    }
    for (let index = 0; index < segmentReceipts.length; index += 1) {
      const expectedBytes = Buffer.from(
        canonicalize(segmentReceipts[index]),
        "utf8",
      );
      if (!parsed.segmentReceiptBytes[index].equals(expectedBytes)) {
        return { ok: false, reasonCode: "INTEGRATION_MATERIAL_INVALID" };
      }
    }
    return { ok: true, reasonCode: null };
  } catch (error) {
    return {
      ok: false,
      reasonCode: error?.code ?? "INTEGRATION_MATERIAL_INVALID",
    };
  }
}

function integrationConclusion(decision) {
  return `INTEGRATION_REVIEW_${decision}`;
}

export function createKimiIntegrationReceipt(input) {
  if (
    !exactKeys(input, [
      "receiptId",
      "plan",
      "verifiedSegmentReceiptSet",
      "verifiedExecution",
    ]) ||
    !VERIFIED_SEGMENT_RECEIPT_SETS.has(input.verifiedSegmentReceiptSet) ||
    !VERIFIED_EXECUTIONS.has(input.verifiedExecution)
  ) {
    fail("MODEL_EXECUTION_PROOF_REQUIRED", "Verified Integration execution is required.");
  }
  const setData = VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(
    input.verifiedSegmentReceiptSet,
  );
  const proof = VERIFIED_EXECUTION_DATA.get(input.verifiedExecution);
  if (
    setData.planSha256 !== input.plan.planSha256 ||
    !sameValue(input.plan, setData.planSnapshot) ||
    !sameValue(input.plan, proof?.planSnapshot) ||
    proof?.reviewKind !== "INTEGRATION" ||
    proof.planSha256 !== input.plan.planSha256 ||
    typeof input.receiptId !== "string" ||
    input.receiptId.length < 8 ||
    input.receiptId.length > 160
  ) {
    fail("INTEGRATION_RECEIPT_INVALID", "Integration proof scope is invalid.");
  }
  if (setData.sessionIds.includes(proof.reviewerSessionId)) {
    fail(
      "INTEGRATION_REVIEWER_SESSION_REUSED",
      "Integration review must use a fifth independent session.",
    );
  }
  const bindings = setData.segmentReceipts.map((receipt) =>
    receiptBinding(receipt, receipt.segment.segmentId),
  );
  const findings = clone(proof.output.findings);
  const receipt = {
    schemaVersion: "kimi-cross-cutting-integration-receipt.v1",
    receiptId: input.receiptId,
    segmentPlanSha256: setData.planSnapshot.planSha256,
    source: clone(setData.planSnapshot.source),
    bundleSha256: setData.planSnapshot.bindings.reviewBundle.sha256,
    segmentReceiptBindings: bindings,
    reviewer: {
      provider: "moonshot",
      requestedModel: "kimi-k3",
      actualReturnedModel: "kimi-k3",
      reviewerSessionId: proof.reviewerSessionId,
      independentOfImplementation: true,
    },
    artifacts: clone(proof.artifacts),
    usage: clone(proof.usage),
    actualCostMicros: proof.actualCostMicros,
    findings,
    findingsSha256: sha256Value(findings),
    decision: proof.output.decision,
    conclusion: integrationConclusion(proof.output.decision),
    modelReviewClearForPreproduction: false,
    humanReviewClaim: false,
    governanceEffect: "NONE",
    startedAt: proof.startedAt,
    finishedAt: proof.finishedAt,
  };
  const signed = { ...receipt, receiptSha256: sha256Value(receipt) };
  if (
    !validateKimiIntegrationReceipt({
      receipt: signed,
      plan: input.plan,
      verifiedSegmentReceiptSet: input.verifiedSegmentReceiptSet,
      verifiedExecution: input.verifiedExecution,
    }).ok
  ) {
    fail(
      "INTEGRATION_RECEIPT_INVALID",
      "Generated Integration Receipt is invalid.",
    );
  }
  return signed;
}

export function validateKimiIntegrationReceipt({
  receipt,
  plan,
  verifiedSegmentReceiptSet,
  verifiedExecution,
}) {
  try {
    if (
      !VERIFIED_SEGMENT_RECEIPT_SETS.has(verifiedSegmentReceiptSet) ||
      !VERIFIED_EXECUTIONS.has(verifiedExecution)
    ) {
      return { ok: false, reasonCode: "MODEL_EXECUTION_PROOF_REQUIRED" };
    }
    const setData = VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(
      verifiedSegmentReceiptSet,
    );
    const proof = VERIFIED_EXECUTION_DATA.get(verifiedExecution);
    if (
      setData.planSha256 !== plan.planSha256 ||
      !sameValue(plan, setData.planSnapshot) ||
      !sameValue(plan, proof?.planSnapshot) ||
      proof.reviewKind !== "INTEGRATION" ||
      proof.planSha256 !== plan.planSha256
    ) {
      return { ok: false, reasonCode: "INTEGRATION_RECEIPT_INVALID" };
    }
    const allowedPaths = new Set(
      plan.segments.flatMap(({ ownedPaths }) =>
        ownedPaths.map(({ path }) => path),
      ),
    );
    const expectedBindings = setData.segmentReceipts.map((item) =>
      receiptBinding(item, item.segment.segmentId),
    );
    if (
      !exactKeys(receipt, [
        "schemaVersion",
        "receiptId",
        "segmentPlanSha256",
        "source",
        "bundleSha256",
        "segmentReceiptBindings",
        "reviewer",
        "artifacts",
        "usage",
        "actualCostMicros",
        "findings",
        "findingsSha256",
        "decision",
        "conclusion",
        "modelReviewClearForPreproduction",
        "humanReviewClaim",
        "governanceEffect",
        "startedAt",
        "finishedAt",
        "receiptSha256",
      ]) ||
      receipt?.schemaVersion !==
        "kimi-cross-cutting-integration-receipt.v1" ||
      receipt?.segmentPlanSha256 !== plan.planSha256 ||
      !sameValue(receipt.source, plan.source) ||
      !exactKeys(receipt.source, [
        "baseCommit",
        "sourceCommit",
        "headCommit",
        "tree",
        "diffSha256",
        "changedPathsDigest",
      ]) ||
      receipt.bundleSha256 !== plan.bindings.reviewBundle.sha256 ||
      !sameValue(receipt.segmentReceiptBindings, expectedBindings) ||
      !validModelReceiptCommon({
        receipt,
        proof,
        allowedPaths,
        allowNullPath: true,
        expectedConclusion: integrationConclusion(receipt.decision),
      }) ||
      setData.sessionIds.includes(receipt.reviewer.reviewerSessionId)
    ) {
      return { ok: false, reasonCode: "INTEGRATION_RECEIPT_INVALID" };
    }
    return { ok: true, reasonCode: null };
  } catch {
    return { ok: false, reasonCode: "INTEGRATION_RECEIPT_INVALID" };
  }
}

export function verifyKimiReviewReceiptSet({
  plan,
  verifiedSegmentReceiptSet,
  integrationReceipt,
  verifiedIntegrationExecution,
}) {
  if (
    !VERIFIED_SEGMENT_RECEIPT_SETS.has(verifiedSegmentReceiptSet) ||
    !validateKimiIntegrationReceipt({
      receipt: integrationReceipt,
      plan,
      verifiedSegmentReceiptSet,
      verifiedExecution: verifiedIntegrationExecution,
    }).ok
  ) {
    fail("AGGREGATE_INPUT_INVALID", "Five verified Receipts are required.");
  }
  const segmentData = VERIFIED_SEGMENT_RECEIPT_SET_DATA.get(
    verifiedSegmentReceiptSet,
  );
  const allFindingIds = [
    ...segmentData.segmentReceipts,
    integrationReceipt,
  ].flatMap(({ findings }) => findings.map(({ findingId }) => findingId));
  if (
    !sameValue(plan, segmentData.planSnapshot) ||
    new Set(allFindingIds).size !== allFindingIds.length
  ) {
    fail("AGGREGATE_INPUT_INVALID", "Receipt findings or Plan binding conflict.");
  }
  const set = Object.freeze({ kind: "VERIFIED_KIMI_REVIEW_RECEIPT_SET" });
  VERIFIED_REVIEW_RECEIPT_SETS.add(set);
  VERIFIED_REVIEW_RECEIPT_SET_DATA.set(
    set,
    Object.freeze({
      planSha256: segmentData.planSha256,
      planSnapshot: segmentData.planSnapshot,
      segmentReceipts: segmentData.segmentReceipts,
      integrationReceipt: immutableClone(integrationReceipt),
    }),
  );
  return set;
}

export function evaluateKimiAggregateDecision(decisions) {
  if (
    !Array.isArray(decisions) ||
    decisions.length !== 5 ||
    decisions.some((decision) => !DECISIONS.has(decision)) ||
    decisions.includes("INCONCLUSIVE")
  ) {
    return "INCONCLUSIVE";
  }
  if (decisions.includes("BLOCKED")) return "BLOCKED";
  return "CLEAR";
}

export function evaluateKimiAggregateInputs({
  plan,
  verifiedReviewReceiptSet,
}) {
  try {
    if (!VERIFIED_REVIEW_RECEIPT_SETS.has(verifiedReviewReceiptSet)) {
      throw new Error("verified review receipt set is required");
    }
    const data = VERIFIED_REVIEW_RECEIPT_SET_DATA.get(verifiedReviewReceiptSet);
    if (
      data.planSha256 !== plan.planSha256 ||
      !sameValue(plan, data.planSnapshot)
    ) {
      throw new Error("plan drift");
    }
    return {
      decision: evaluateKimiAggregateDecision([
        ...data.segmentReceipts.map(({ decision }) => decision),
        data.integrationReceipt.decision,
      ]),
      aggregateReceipt: null,
      reasonCodes: [],
    };
  } catch {
    return {
      decision: "INCONCLUSIVE",
      aggregateReceipt: null,
      reasonCodes: ["AGGREGATE_INPUT_INVALID"],
    };
  }
}

function aggregateFindingBindings(receipts) {
  return receipts.flatMap((receipt) =>
    receipt.findings.map((finding) => ({
      sourceReceiptId: receipt.receiptId,
      sourceReceiptSha256: receipt.receiptSha256,
      finding: clone(finding),
      findingSha256: sha256Value(finding),
    })),
  );
}

export function createKimiAggregateReceipt({
  receiptId,
  plan,
  verifiedReviewReceiptSet,
}) {
  if (
    typeof receiptId !== "string" ||
    receiptId.length < 8 ||
    receiptId.length > 160
  ) {
    fail("AGGREGATE_RECEIPT_INVALID", "Aggregate receiptId is invalid.");
  }
  if (!VERIFIED_REVIEW_RECEIPT_SETS.has(verifiedReviewReceiptSet)) {
    fail("AGGREGATE_INPUT_INVALID", "Five verified review receipts are required.");
  }
  const data = VERIFIED_REVIEW_RECEIPT_SET_DATA.get(verifiedReviewReceiptSet);
  if (
    data.planSha256 !== plan.planSha256 ||
    !sameValue(plan, data.planSnapshot)
  ) {
    fail("AGGREGATE_INPUT_INVALID", "Aggregate Plan binding drifted.");
  }
  const { segmentReceipts, integrationReceipt, planSnapshot } = data;
  const inputEvaluation = evaluateKimiAggregateInputs({
    plan,
    verifiedReviewReceiptSet,
  });
  if (inputEvaluation.reasonCodes.length > 0) {
    fail("AGGREGATE_INPUT_INVALID", "All five receipts must be valid.");
  }
  const orderedIds = planSnapshot.segments.map(({ segmentId }) => segmentId);
  if (
    !sameValue(
      segmentReceipts.map(({ segment }) => segment.segmentId),
      orderedIds,
    )
  ) {
    fail("SEGMENT_RECEIPT_SET_INVALID", "Segment receipt order is invalid.");
  }
  const allReceipts = [...segmentReceipts, integrationReceipt];
  const decision = evaluateKimiAggregateDecision(
    allReceipts.map(({ decision: value }) => value),
  );
  const segmentReceiptBindings = segmentReceipts.map((receipt) => ({
    receiptId: receipt.receiptId,
    segmentId: receipt.segment.segmentId,
    receiptSha256: receipt.receiptSha256,
    decision: receipt.decision,
  }));
  const integrationReceiptBinding = {
    receiptId: integrationReceipt.receiptId,
    receiptSha256: integrationReceipt.receiptSha256,
    decision: integrationReceipt.decision,
  };
  const findings = aggregateFindingBindings(allReceipts);
  const receipt = {
    schemaVersion: "kimi-deterministic-aggregate-receipt.v1",
    receiptId,
    aggregationMode: "LOCAL_PURE_FUNCTION_NO_MODEL_NO_NETWORK",
    segmentPlanSha256: planSnapshot.planSha256,
    source: clone(planSnapshot.source),
    bundleSha256: planSnapshot.bindings.reviewBundle.sha256,
    segmentReceiptBindings,
    integrationReceiptBinding,
    inputReceiptSetSha256: sha256Value([
      ...segmentReceiptBindings.map(({ receiptSha256 }) => receiptSha256),
      integrationReceiptBinding.receiptSha256,
    ]),
    findings,
    findingsSha256: sha256Value(findings),
    decision,
    conclusion:
      decision === "CLEAR"
        ? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
        : `MODEL_REVIEW_${decision}_FOR_PREPRODUCTION`,
    modelReviewClearForPreproduction: decision === "CLEAR",
    humanReviewClaim: false,
    governanceEffect: "NONE",
  };
  return { ...receipt, receiptSha256: sha256Value(receipt) };
}

export async function validateKimiAggregateReceipt({
  receipt,
  plan,
  verifiedReviewReceiptSet,
}) {
  try {
    const expected = createKimiAggregateReceipt({
      receiptId: receipt.receiptId,
      plan,
      verifiedReviewReceiptSet,
    });
    if (!sameValue(receipt, expected)) {
      return { ok: false, reasonCode: "AGGREGATE_RECEIPT_INVALID" };
    }
    return { ok: true, reasonCode: null };
  } catch {
    return { ok: false, reasonCode: "AGGREGATE_RECEIPT_INVALID" };
  }
}
