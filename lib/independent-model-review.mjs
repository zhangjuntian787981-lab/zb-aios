import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*[\u0000-\u001f\\]).+$/u;
const BLOCKING_SEVERITIES = new Set(["HIGH", "CRITICAL"]);
const DECISIONS = new Set(["CLEAR", "BLOCKED", "INCONCLUSIVE"]);
const CONCLUSIONS = Object.freeze({
  CLEAR: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  BLOCKED: "BLOCKED",
  INCONCLUSIVE: "INCONCLUSIVE",
});
const ALLOWED_REVIEW_SCOPES = [
  "CHECK_ISSUER_OR_MAPPER",
  "INDEPENDENCE_VALIDATOR",
  "JSON_SCHEMA",
  "ORDINARY_PREPRODUCTION_CODE",
  "POLICY",
  "RULESET_CONFIGURATION",
  "SEMANTIC_VALIDATOR",
];
const ALLOWED_INPUTS = [
  "SPECIFICATION",
  "SOURCE_COMMIT",
  "DIFF",
  "TEST_EVIDENCE",
  "ACCEPTANCE_EVIDENCE",
  "RELEVANT_FILES",
];
const FORBIDDEN_CAPABILITIES = [
  "COMMIT",
  "D1_WRITE",
  "DEPLOY",
  "FILE_WRITE",
  "GOVERNANCE_DECISION",
  "PUSH",
];

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

async function hashBytes(value) {
  const bytes =
    value instanceof Uint8Array
      ? value
      : new TextEncoder().encode(String(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
}

const policyDigest = (policy) =>
  sha256ProjectValue(withoutField(policy, "policySha256"));
const bundleDigest = (bundle) =>
  sha256ProjectValue(withoutField(bundle, "bundleSha256"));
const receiptDigest = (receipt) =>
  sha256ProjectValue(withoutField(receipt, "receiptSha256"));
const runtimeDigest = (runtimeAttestation) =>
  sha256ProjectValue(runtimeAttestation);
const modelOutputDigest = (modelOutput) => sha256ProjectValue(modelOutput);

export const independentModelReviewDigests = Object.freeze({
  policy: policyDigest,
  bundle: bundleDigest,
  receipt: receiptDigest,
  runtime: runtimeDigest,
  modelOutput: modelOutputDigest,
  value: sha256ProjectValue,
  bytes: hashBytes,
  canonicalize: canonicalizeProjectJson,
});

function keysExactly(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalizeProjectJson(Object.keys(value).sort()) ===
      canonicalizeProjectJson([...expected].sort())
  );
}

function unique(values) {
  return Array.isArray(values) && new Set(values).size === values.length;
}

function sorted(values) {
  return (
    Array.isArray(values) &&
    canonicalizeProjectJson(values) ===
      canonicalizeProjectJson([...values].sort())
  );
}

function safePath(value) {
  return typeof value === "string" && SAFE_PATH.test(value);
}

function validDate(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

function result(ok, status, reasonCodes, extra = {}) {
  return {
    ok,
    status,
    reasonCodes: [...new Set(reasonCodes)],
    ...extra,
  };
}

function fixedPolicyReasonCodes(policy) {
  const reasonCodes = [];
  if (
    !keysExactly(policy, [
      "schemaVersion",
      "policyId",
      "policyVersion",
      "lifecycle",
      "assuranceLevel",
      "applicablePhases",
      "dataBoundary",
      "humanIndependentReviewSatisfied",
      "independentModelReviewRequired",
      "p3HumanReviewRequired",
      "allowedModelConclusion",
      "forbiddenHumanConclusion",
      "allowedReviewScopes",
      "reviewerIndependence",
      "p3HumanReviewBoundary",
      "historicalTreatment",
      "requiredCheck",
      "canonicalization",
      "governanceBoundary",
      "policySha256",
    ])
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    policy?.schemaVersion !== "independent-review-policy.v2" ||
    policy?.lifecycle !== "CANDIDATE_NOT_ACTIVATED" ||
    policy?.assuranceLevel !== "MODEL_ONLY_PREPRODUCTION" ||
    canonicalizeProjectJson(policy?.applicablePhases) !==
      canonicalizeProjectJson(["P0", "P1", "P2"]) ||
    policy?.dataBoundary !== "SYNTHETIC_ONLY" ||
    policy?.independentModelReviewRequired !== true ||
    policy?.p3HumanReviewRequired !== true ||
    policy?.allowedModelConclusion !==
      "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    policy?.humanIndependentReviewSatisfied !== false ||
    policy?.forbiddenHumanConclusion !==
      "INDEPENDENT_HUMAN_REVIEW_COMPLETE" ||
    policy?.governanceBoundary?.githubHumanApprovalClaimAllowed !== false
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_HUMAN_CLAIM_FORBIDDEN");
  }
  if (
    canonicalizeProjectJson([...(policy?.allowedReviewScopes ?? [])].sort()) !==
      canonicalizeProjectJson(ALLOWED_REVIEW_SCOPES) ||
    !keysExactly(policy?.reviewerIndependence, [
      "differentModelIdRequired",
      "differentProviderOrFamilyPreferred",
      "freshIsolatedContextRequired",
      "fullImplementationHistoryAllowed",
      "implementationParticipationAllowed",
      "allowedInputs",
      "promptInjectionIsUntrustedData",
      "forbiddenCapabilities",
    ]) ||
    policy?.reviewerIndependence?.differentModelIdRequired !== true ||
    policy?.reviewerIndependence?.differentProviderOrFamilyPreferred !== true ||
    policy?.reviewerIndependence?.freshIsolatedContextRequired !== true ||
    policy?.reviewerIndependence?.fullImplementationHistoryAllowed !== false ||
    policy?.reviewerIndependence?.implementationParticipationAllowed !== false ||
    canonicalizeProjectJson(policy?.reviewerIndependence?.allowedInputs) !==
      canonicalizeProjectJson(ALLOWED_INPUTS) ||
    policy?.reviewerIndependence?.promptInjectionIsUntrustedData !== true ||
    canonicalizeProjectJson(
      policy?.reviewerIndependence?.forbiddenCapabilities,
    ) !== canonicalizeProjectJson(FORBIDDEN_CAPABILITIES)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    policy?.historicalTreatment?.preserveHistoricalRecords !== true ||
    policy?.historicalTreatment?.retroactiveSatisfaction !== false ||
    policy?.historicalTreatment?.p1B11ReevaluationMode !== "APPEND_ONLY" ||
    !policy?.historicalTreatment?.preservedReasonCodes?.includes(
      "INCONCLUSIVE_INDEPENDENT_REVIEWER_MISSING",
    ) ||
    !policy?.historicalTreatment?.preservedReasonCodes?.includes(
      "INCONCLUSIVE_INDEPENDENT_HUMAN_REVIEWER_MISSING",
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_HISTORICAL_RECORD_MUTATION");
  }
  if (
    policy?.p3HumanReviewBoundary?.modelReviewSubstitutionAllowed !== false ||
    !policy?.p3HumanReviewBoundary?.phases?.includes("P3") ||
    !policy?.p3HumanReviewBoundary?.highRiskScopes?.includes(
      "D1_GATE_PROFILE_START_AUTHORIZATION",
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_P3_HUMAN_REVIEW_REQUIRED");
  }
  if (
    policy?.governanceBoundary?.d1RemainsStateTruth !== true ||
    policy?.governanceBoundary?.gitRemainsEvidenceTruth !== true ||
    policy?.governanceBoundary?.secondStatusTruthAllowed !== false ||
    policy?.governanceBoundary?.governanceEffect !== "NONE" ||
    policy?.governanceBoundary?.isProgressTracker !== false ||
    policy?.governanceBoundary?.selfAuthorizing !== false
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    !keysExactly(policy?.requiredCheck, [
      "context",
      "clearConclusion",
      "blockedConclusion",
      "inconclusiveConclusion",
      "githubHumanApproveCreated",
      "remotePublicationAuthorized",
    ]) ||
    policy?.requiredCheck?.context !== "independent-model-review" ||
    policy?.requiredCheck?.clearConclusion !== "success" ||
    policy?.requiredCheck?.blockedConclusion !== "failure" ||
    policy?.requiredCheck?.inconclusiveConclusion !== "failure" ||
    policy?.requiredCheck?.githubHumanApproveCreated !== false ||
    policy?.requiredCheck?.remotePublicationAuthorized !== false ||
    policy?.canonicalization !== "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  return reasonCodes;
}

export async function validateIndependentReviewPolicy(policy) {
  const reasonCodes = fixedPolicyReasonCodes(policy);
  if (
    !SHA256.test(policy?.policySha256 ?? "") ||
    (SHA256.test(policy?.policySha256 ?? "") &&
      (await policyDigest(policy)) !== policy.policySha256)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_HASH_MISMATCH");
  }
  return reasonCodes.length === 0
    ? result(true, "VALID_CANDIDATE", [])
    : result(false, "INVALID", reasonCodes);
}

const BUNDLE_INPUT_KEYS = [
  "bundleId",
  "generatedAt",
  "applicablePhase",
  "policyPath",
  "policy",
  "artifacts",
  "source",
  "reviewedPaths",
  "sourceSubjects",
  "specificationSubjects",
  "testEvidenceSubjects",
  "implementationIdentity",
];

export async function createIndependentReviewBundle(input) {
  if (!keysExactly(input, BUNDLE_INPUT_KEYS)) {
    throw new TypeError(
      "Independent Review Bundle input contains missing or unknown fields.",
    );
  }
  const policyValidation = await validateIndependentReviewPolicy(input.policy);
  if (!policyValidation.ok) {
    throw new TypeError("Independent Review Policy candidate is invalid.");
  }
  const bundle = {
    schemaVersion: "independent-review-bundle.v2",
    bundleId: input.bundleId,
    lifecycle: "CANDIDATE",
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    applicablePhase: input.applicablePhase,
    dataBoundary: "SYNTHETIC_ONLY",
    enterpriseDataUsed: false,
    productionEffect: false,
    policy: {
      path: input.policyPath,
      version: input.policy.policyVersion,
      sha256: input.policy.policySha256,
    },
    artifacts: structuredClone(input.artifacts),
    source: structuredClone(input.source),
    reviewedPaths: structuredClone(input.reviewedPaths),
    sourceSubjects: structuredClone(input.sourceSubjects),
    specificationSubjects: structuredClone(input.specificationSubjects),
    testEvidenceSubjects: structuredClone(input.testEvidenceSubjects),
    implementationIdentity: structuredClone(input.implementationIdentity),
    requiredRuntimeConstraints: {
      differentModelIdRequired: true,
      differentProviderOrFamilyPreferred: true,
      freshIsolatedContextRequired: true,
      fullImplementationHistoryAllowed: false,
      implementationParticipationAllowed: false,
      allowedInputsOnly: true,
      promptInjectionTreatedAsData: true,
      sandbox: "read-only",
      ephemeral: true,
      forbiddenCapabilities: [
        "COMMIT",
        "D1_WRITE",
        "DEPLOY",
        "FILE_WRITE",
        "GOVERNANCE_DECISION",
        "PUSH",
      ],
    },
    governanceBoundary: {
      governanceEffect: "NONE",
      isProgressTracker: false,
      selfAuthorizing: false,
      humanIndependentReviewSatisfied: false,
      remoteCheckPublished: false,
      p1B11StatusChanged: false,
    },
    generatedAt: input.generatedAt,
    bundleSha256: `sha256:${"0".repeat(64)}`,
  };
  bundle.bundleSha256 = await bundleDigest(bundle);
  const validation = await validateIndependentReviewBundle(bundle, {
    policy: input.policy,
  });
  if (!validation.ok) {
    throw new TypeError(
      `Independent Review Bundle is invalid: ${validation.reasonCodes.join(",")}`,
    );
  }
  return bundle;
}

function bundleBaseReasonCodes(bundle, policy) {
  const reasonCodes = [];
  if (
    !keysExactly(bundle, [
      "schemaVersion",
      "bundleId",
      "lifecycle",
      "assuranceLevel",
      "applicablePhase",
      "dataBoundary",
      "enterpriseDataUsed",
      "productionEffect",
      "policy",
      "artifacts",
      "source",
      "reviewedPaths",
      "sourceSubjects",
      "specificationSubjects",
      "testEvidenceSubjects",
      "implementationIdentity",
      "requiredRuntimeConstraints",
      "governanceBoundary",
      "generatedAt",
      "bundleSha256",
    ]) ||
    bundle?.schemaVersion !== "independent-review-bundle.v2" ||
    bundle?.lifecycle !== "CANDIDATE" ||
    bundle?.assuranceLevel !== "MODEL_ONLY_PREPRODUCTION" ||
    bundle?.dataBoundary !== "SYNTHETIC_ONLY"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_BUNDLE_INVALID");
  }
  if (
    bundle?.applicablePhase === "P3" ||
    bundle?.enterpriseDataUsed !== false ||
    bundle?.productionEffect !== false
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_P3_HUMAN_REVIEW_REQUIRED");
  } else if (!["P0", "P1", "P2"].includes(bundle?.applicablePhase)) {
    reasonCodes.push("INDEPENDENT_REVIEW_BUNDLE_INVALID");
  }
  if (
    !keysExactly(bundle?.policy, ["path", "version", "sha256"]) ||
    bundle?.policy?.sha256 !== policy?.policySha256 ||
    bundle?.policy?.version !== policy?.policyVersion ||
    !safePath(bundle?.policy?.path)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    !keysExactly(bundle?.artifacts, [
      "receiptSchemaPath",
      "receiptSchemaSha256",
      "outputSchemaPath",
      "outputSchemaSha256",
      "semanticValidatorPath",
      "semanticValidatorSha256",
      "independenceValidatorPath",
      "independenceValidatorSha256",
      "checkMapperPath",
      "checkMapperSha256",
      "promptPath",
      "promptSha256",
    ]) ||
    Object.entries(bundle?.artifacts ?? {}).some(([key, value]) =>
      key.endsWith("Path") ? !safePath(value) : !SHA256.test(value),
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_BUNDLE_INVALID");
  }
  if (
    !keysExactly(bundle?.source, [
      "baseCommit",
      "sourceCommit",
      "headCommit",
      "tree",
      "diffSha256",
      "changedPathsDigest",
    ]) ||
    !GIT_COMMIT.test(bundle?.source?.baseCommit ?? "") ||
    !GIT_COMMIT.test(bundle?.source?.sourceCommit ?? "") ||
    !GIT_COMMIT.test(bundle?.source?.headCommit ?? "") ||
    !GIT_COMMIT.test(bundle?.source?.tree ?? "") ||
    bundle?.source?.sourceCommit !== bundle?.source?.headCommit
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_BASE_HEAD_TREE_MISMATCH");
  }
  if (
    !SHA256.test(bundle?.source?.diffSha256 ?? "") ||
    !SHA256.test(bundle?.source?.changedPathsDigest ?? "")
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_DIFF_DIGEST_MISMATCH");
  }
  if (
    !Array.isArray(bundle?.reviewedPaths) ||
    bundle.reviewedPaths.length === 0 ||
    !bundle.reviewedPaths.every(safePath) ||
    !unique(bundle.reviewedPaths) ||
    !sorted(bundle.reviewedPaths)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_CHANGED_PATHS_MISMATCH");
  }
  const subjectPaths = bundle?.sourceSubjects?.map((subject) => subject.path);
  if (
    !Array.isArray(subjectPaths) ||
    canonicalizeProjectJson(subjectPaths) !==
      canonicalizeProjectJson(bundle?.reviewedPaths) ||
    !bundle.sourceSubjects.every(
      (subject) =>
        keysExactly(subject, ["path", "gitMode", "blobSha256"]) &&
        safePath(subject.path) &&
        /^(100644|100755|120000|160000)$/u.test(subject.gitMode) &&
        SHA256.test(subject.blobSha256),
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_SCOPE_INCOMPLETE");
  }
  if (
    !bundle?.specificationSubjects?.length ||
    !bundle.specificationSubjects.every(
      (subject) =>
        keysExactly(subject, ["path", "blobSha256"]) &&
        safePath(subject.path) &&
        SHA256.test(subject.blobSha256),
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_SCOPE_INCOMPLETE");
  }
  if (
    !bundle?.testEvidenceSubjects?.length ||
    !bundle.testEvidenceSubjects.every(
      (evidence) =>
        keysExactly(evidence, [
          "evidenceId",
          "command",
          "status",
          "exitCode",
          "outputRef",
          "outputSha256",
          "outputByteLength",
          "truncated",
          "sourceCommit",
          "runner",
          "toolVersions",
        ]) &&
        evidence.status === "PASS" &&
        evidence.exitCode === 0 &&
        safePath(evidence.outputRef) &&
        SHA256.test(evidence.outputSha256) &&
        Number.isInteger(evidence.outputByteLength) &&
        evidence.outputByteLength > 0 &&
        evidence.truncated === false &&
        evidence.sourceCommit === bundle?.source?.sourceCommit &&
        Array.isArray(evidence.toolVersions) &&
        evidence.toolVersions.length > 0,
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_TEST_EVIDENCE_MISMATCH");
  }
  if (
    !keysExactly(bundle?.implementationIdentity, [
      "provider",
      "modelId",
      "modelVersion",
      "participantManifestSha256",
      "sessionIdSha256",
    ]) ||
    typeof bundle?.implementationIdentity?.provider !== "string" ||
    typeof bundle?.implementationIdentity?.modelId !== "string" ||
    typeof bundle?.implementationIdentity?.modelVersion !== "string" ||
    !SHA256.test(
      bundle?.implementationIdentity?.participantManifestSha256 ?? "",
    ) ||
    !SHA256.test(bundle?.implementationIdentity?.sessionIdSha256 ?? "")
  ) {
    reasonCodes.push(
      "INDEPENDENT_REVIEW_IMPLEMENTATION_PARTICIPATION_NOT_PROVED",
    );
  }
  if (
    !SHA256.test(bundle?.artifacts?.promptSha256 ?? "") ||
    !safePath(bundle?.artifacts?.promptPath)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_PROMPT_DIGEST_MISMATCH");
  }
  if (
    !keysExactly(bundle?.requiredRuntimeConstraints, [
      "differentModelIdRequired",
      "differentProviderOrFamilyPreferred",
      "freshIsolatedContextRequired",
      "fullImplementationHistoryAllowed",
      "implementationParticipationAllowed",
      "allowedInputsOnly",
      "promptInjectionTreatedAsData",
      "sandbox",
      "ephemeral",
      "forbiddenCapabilities",
    ]) ||
    bundle?.requiredRuntimeConstraints?.differentModelIdRequired !== true ||
    bundle?.requiredRuntimeConstraints?.freshIsolatedContextRequired !== true ||
    bundle?.requiredRuntimeConstraints?.fullImplementationHistoryAllowed !==
      false ||
    bundle?.requiredRuntimeConstraints?.implementationParticipationAllowed !==
      false ||
    bundle?.requiredRuntimeConstraints?.promptInjectionTreatedAsData !== true ||
    bundle?.requiredRuntimeConstraints?.allowedInputsOnly !== true ||
    bundle?.requiredRuntimeConstraints?.sandbox !== "read-only" ||
    bundle?.requiredRuntimeConstraints?.ephemeral !== true ||
    canonicalizeProjectJson(
      bundle?.requiredRuntimeConstraints?.forbiddenCapabilities,
    ) !== canonicalizeProjectJson(FORBIDDEN_CAPABILITIES)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_CONTEXT_ISOLATION_NOT_PROVED");
  }
  if (
    bundle?.governanceBoundary?.governanceEffect !== "NONE" ||
    bundle?.governanceBoundary?.isProgressTracker !== false ||
    bundle?.governanceBoundary?.selfAuthorizing !== false ||
    bundle?.governanceBoundary?.humanIndependentReviewSatisfied !== false ||
    bundle?.governanceBoundary?.remoteCheckPublished !== false ||
    bundle?.governanceBoundary?.p1B11StatusChanged !== false
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_HUMAN_CLAIM_FORBIDDEN");
  }
  return reasonCodes;
}

export async function validateIndependentReviewBundle(bundle, { policy }) {
  const reasonCodes = bundleBaseReasonCodes(bundle, policy);
  if (
    !SHA256.test(bundle?.bundleSha256 ?? "") ||
    (SHA256.test(bundle?.bundleSha256 ?? "") &&
      (await bundleDigest(bundle)) !== bundle.bundleSha256)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_BUNDLE_HASH_MISMATCH");
  }
  return reasonCodes.length === 0
    ? result(true, "VALID", [])
    : result(false, "INVALID", reasonCodes);
}

const RUNTIME_KEYS = [
  "schemaVersion",
  "runtime",
  "cliVersion",
  "provider",
  "modelId",
  "modelFamily",
  "modelVersion",
  "modelVersionEvidence",
  "backendBuildId",
  "diversityLevel",
  "implementationModelIds",
  "ephemeral",
  "sandbox",
  "networkAccess",
  "userConfigLoaded",
  "projectRulesLoaded",
  "fullImplementationConversationImported",
  "implementationConclusionsProvided",
  "allowedInputsOnly",
  "promptInjectionTreatedAsData",
  "capabilities",
  "inputBundleSha256",
  "outputSchemaSha256",
  "rawModelOutputSha256",
  "startedAt",
  "finishedAt",
];

export async function validateIndependentModelIndependence({
  policy,
  bundle,
  runtimeAttestation,
}) {
  const blocked = [];
  const inconclusive = [];
  if (
    !keysExactly(runtimeAttestation, RUNTIME_KEYS) ||
    runtimeAttestation?.schemaVersion !==
      "independent-model-runtime-attestation.v1"
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_IMPLEMENTATION_PARTICIPATION_NOT_PROVED");
  }
  const implementationModelIds = bundle?.implementationIdentity?.modelId
    ? [bundle.implementationIdentity.modelId]
    : [];
  if (
    runtimeAttestation?.modelId === bundle?.implementationIdentity?.modelId
  ) {
    blocked.push("INDEPENDENT_REVIEW_MODEL_IDENTITY_NOT_DISTINCT");
  }
  if (
    runtimeAttestation?.implementationModelIds?.includes(
      runtimeAttestation?.modelId,
    )
  ) {
    blocked.push("INDEPENDENT_REVIEW_IMPLEMENTATION_PARTICIPATION_CONFLICT");
  }
  if (
    !unique(runtimeAttestation?.implementationModelIds) ||
    canonicalizeProjectJson(runtimeAttestation?.implementationModelIds) !==
      canonicalizeProjectJson(implementationModelIds)
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_IMPLEMENTATION_PARTICIPATION_NOT_PROVED");
  }
  if (
    typeof runtimeAttestation?.modelId !== "string" ||
    typeof runtimeAttestation?.modelVersion !== "string" ||
    runtimeAttestation.modelId.length === 0 ||
    runtimeAttestation.modelVersion.length === 0 ||
    runtimeAttestation?.modelVersionEvidence !==
      "CLI_REQUEST_AND_RUNTIME_REPORTED_MODEL_ID"
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_MODEL_IDENTITY_UNPINNED");
  }
  const expectedDiversity =
    runtimeAttestation?.provider !== bundle?.implementationIdentity?.provider
      ? "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER"
      : "DIFFERENT_MODEL_ID_SAME_PROVIDER";
  if (
    runtimeAttestation?.diversityLevel !== expectedDiversity &&
    !(
      runtimeAttestation?.provider === bundle?.implementationIdentity?.provider &&
      runtimeAttestation?.diversityLevel ===
        "DIFFERENT_MODEL_ID_DIFFERENT_FAMILY"
    )
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_MODEL_IDENTITY_UNPINNED");
  }
  if (
    runtimeAttestation?.ephemeral !== true ||
    runtimeAttestation?.userConfigLoaded !== false ||
    runtimeAttestation?.projectRulesLoaded !== false ||
    runtimeAttestation?.fullImplementationConversationImported !== false ||
    runtimeAttestation?.implementationConclusionsProvided !== false ||
    runtimeAttestation?.allowedInputsOnly !== true ||
    runtimeAttestation?.promptInjectionTreatedAsData !== true
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_CONTEXT_ISOLATION_NOT_PROVED");
  }
  if (
    runtimeAttestation?.sandbox !== "read-only" ||
    runtimeAttestation?.networkAccess !==
      "MODEL_TOOL_NETWORK_DISABLED_BY_READ_ONLY_SANDBOX" ||
    !keysExactly(runtimeAttestation?.capabilities, [
      "fileWrite",
      "commit",
      "push",
      "d1Write",
      "deploy",
      "governanceDecision",
    ]) ||
    Object.values(runtimeAttestation?.capabilities ?? {}).some(
      (allowed) => allowed !== false,
    )
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_READ_ONLY_PERMISSION_NOT_PROVED");
  }
  if (
    runtimeAttestation?.inputBundleSha256 !== bundle?.bundleSha256 ||
    runtimeAttestation?.outputSchemaSha256 !==
      bundle?.artifacts?.outputSchemaSha256
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_SCOPE_INCOMPLETE");
  }
  if (
    !validDate(runtimeAttestation?.startedAt) ||
    !validDate(runtimeAttestation?.finishedAt) ||
    Date.parse(runtimeAttestation.startedAt) >
      Date.parse(runtimeAttestation.finishedAt)
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_TIME_ORDER_INVALID");
  }
  if (policy?.assuranceLevel !== "MODEL_ONLY_PREPRODUCTION") {
    inconclusive.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (blocked.length > 0) {
    return result(false, "BLOCKED", blocked, {
      diversityLevel: runtimeAttestation?.diversityLevel ?? "UNPROVED",
    });
  }
  if (inconclusive.length > 0) {
    return result(false, "INCONCLUSIVE", inconclusive, {
      diversityLevel: runtimeAttestation?.diversityLevel ?? "UNPROVED",
    });
  }
  return result(true, "PROVED", [], {
    diversityLevel: runtimeAttestation.diversityLevel,
  });
}

function outputIsClosed(output) {
  const findingIds = output?.findings?.map((finding) => finding.findingId);
  return (
    keysExactly(output, [
      "schemaVersion",
      "reviewSummary",
      "findings",
      "decision",
      "startedAt",
      "finishedAt",
    ]) &&
    output.schemaVersion === "independent-model-review-output.v2" &&
    DECISIONS.has(output.decision) &&
    typeof output.reviewSummary === "string" &&
    output.reviewSummary.length > 0 &&
    Array.isArray(output.findings) &&
    unique(findingIds) &&
    output.findings.every(
      (finding) =>
        keysExactly(finding, [
          "findingId",
          "severity",
          "status",
          "path",
          "startLine",
          "endLine",
          "summary",
          "detailsSha256",
          "resolutionEvidenceDigests",
        ]) &&
        ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(
          finding.severity,
        ) &&
        ["OPEN", "RESOLVED"].includes(finding.status) &&
        (finding.path === null || safePath(finding.path)) &&
        SHA256.test(finding.detailsSha256) &&
        (finding.startLine === null ||
          (Number.isInteger(finding.startLine) && finding.startLine > 0)) &&
        (finding.endLine === null ||
          (Number.isInteger(finding.endLine) && finding.endLine > 0)) &&
        (finding.startLine === null ||
          finding.endLine === null ||
          finding.startLine <= finding.endLine) &&
        Array.isArray(finding.resolutionEvidenceDigests) &&
        unique(finding.resolutionEvidenceDigests) &&
        finding.resolutionEvidenceDigests.every((value) => SHA256.test(value)),
    ) &&
    validDate(output.startedAt) &&
    validDate(output.finishedAt)
  );
}

export function parseIndependentModelReviewOutput(raw) {
  if (
    typeof raw !== "string" ||
    Buffer.byteLength(raw, "utf8") === 0 ||
    Buffer.byteLength(raw, "utf8") > 64 * 1024
  ) {
    throw new TypeError("Independent model review output is not bounded JSON.");
  }
  let index = 0;
  const skipWhitespace = () => {
    while (index < raw.length && /[\u0020\t\r\n]/u.test(raw[index])) index += 1;
  };
  const parseString = () => {
    const start = index;
    if (raw[index] !== '"') throw new TypeError("Expected a JSON string.");
    index += 1;
    while (index < raw.length) {
      if (raw[index] === '"') {
        index += 1;
        return JSON.parse(raw.slice(start, index));
      }
      if (raw[index] === "\\") {
        index += 2;
      } else {
        index += 1;
      }
    }
    throw new TypeError("Unterminated JSON string.");
  };
  const parseValue = () => {
    skipWhitespace();
    if (raw[index] === "{") {
      index += 1;
      const keys = new Set();
      skipWhitespace();
      if (raw[index] === "}") {
        index += 1;
        return;
      }
      while (index < raw.length) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) {
          throw new TypeError("Independent model review output has duplicate keys.");
        }
        keys.add(key);
        skipWhitespace();
        if (raw[index] !== ":") throw new TypeError("Expected JSON colon.");
        index += 1;
        parseValue();
        skipWhitespace();
        if (raw[index] === "}") {
          index += 1;
          return;
        }
        if (raw[index] !== ",") throw new TypeError("Expected JSON comma.");
        index += 1;
      }
    } else if (raw[index] === "[") {
      index += 1;
      skipWhitespace();
      if (raw[index] === "]") {
        index += 1;
        return;
      }
      while (index < raw.length) {
        parseValue();
        skipWhitespace();
        if (raw[index] === "]") {
          index += 1;
          return;
        }
        if (raw[index] !== ",") throw new TypeError("Expected JSON comma.");
        index += 1;
      }
    } else if (raw[index] === '"') {
      parseString();
    } else {
      const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(
        raw.slice(index),
      )?.[0];
      if (!token) throw new TypeError("Invalid JSON value.");
      index += token.length;
    }
  };
  parseValue();
  skipWhitespace();
  if (index !== raw.length) {
    throw new TypeError("Independent model review output has trailing content.");
  }
  return JSON.parse(raw);
}

export async function createIndependentModelReviewReceipt({
  receiptId,
  policy,
  bundle,
  runtimeAttestationPath,
  runtimeAttestation,
  modelOutputPath,
  modelOutput,
}) {
  const bundleValidation = await validateIndependentReviewBundle(bundle, {
    policy,
  });
  if (!bundleValidation.ok || !outputIsClosed(modelOutput)) {
    throw new TypeError("Independent model review inputs are invalid.");
  }
  const receipt = {
    schemaVersion: "independent-model-review-receipt.v2",
    receiptId,
    policyVersion: policy.policyVersion,
    policySha256: policy.policySha256,
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    applicablePhase: bundle.applicablePhase,
    humanIndependentReviewSatisfied: false,
    independentModelReviewRequired: true,
    p3HumanReviewRequired: true,
    bundleId: bundle.bundleId,
    bundleSha256: bundle.bundleSha256,
    reviewer: {
      provider: runtimeAttestation.provider,
      modelId: runtimeAttestation.modelId,
      modelFamily: runtimeAttestation.modelFamily,
      modelVersion: runtimeAttestation.modelVersion,
      modelVersionEvidence: runtimeAttestation.modelVersionEvidence,
      backendBuildId: runtimeAttestation.backendBuildId,
      diversityLevel: runtimeAttestation.diversityLevel,
    },
    source: structuredClone(bundle.source),
    promptSha256: bundle.artifacts.promptSha256,
    reviewedPaths: structuredClone(bundle.reviewedPaths),
    findings: structuredClone(modelOutput.findings),
    testEvidenceDigests: bundle.testEvidenceSubjects.map(
      (evidence) => evidence.outputSha256,
    ),
    runtimeAttestationPath,
    runtimeAttestationSha256: await runtimeDigest(runtimeAttestation),
    modelOutputPath,
    modelOutputSha256: await modelOutputDigest(modelOutput),
    decision: modelOutput.decision,
    conclusion: CONCLUSIONS[modelOutput.decision],
    humanReviewClaim: false,
    governanceEffect: "NONE",
    selfAuthorizing: false,
    startedAt: modelOutput.startedAt,
    finishedAt: modelOutput.finishedAt,
    receiptSha256: `sha256:${"0".repeat(64)}`,
  };
  receipt.receiptSha256 = await receiptDigest(receipt);
  return receipt;
}

function receiptBindingReasonCodes({
  policy,
  bundle,
  receipt,
  runtimeAttestation,
  modelOutput,
}) {
  const reasonCodes = [];
  if (
    !keysExactly(receipt, [
      "schemaVersion",
      "receiptId",
      "policyVersion",
      "policySha256",
      "assuranceLevel",
      "applicablePhase",
      "humanIndependentReviewSatisfied",
      "independentModelReviewRequired",
      "p3HumanReviewRequired",
      "bundleId",
      "bundleSha256",
      "reviewer",
      "source",
      "promptSha256",
      "reviewedPaths",
      "findings",
      "testEvidenceDigests",
      "runtimeAttestationPath",
      "runtimeAttestationSha256",
      "modelOutputPath",
      "modelOutputSha256",
      "decision",
      "conclusion",
      "humanReviewClaim",
      "governanceEffect",
      "selfAuthorizing",
      "startedAt",
      "finishedAt",
      "receiptSha256",
    ]) ||
    receipt?.schemaVersion !== "independent-model-review-receipt.v2"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_INVALID");
  }
  if (
    !keysExactly(receipt?.reviewer, [
      "provider",
      "modelId",
      "modelFamily",
      "modelVersion",
      "modelVersionEvidence",
      "backendBuildId",
      "diversityLevel",
    ]) ||
    !keysExactly(receipt?.source, [
      "baseCommit",
      "sourceCommit",
      "headCommit",
      "tree",
      "diffSha256",
      "changedPathsDigest",
    ])
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_INVALID");
  }
  if (
    receipt?.humanIndependentReviewSatisfied !== false ||
    receipt?.humanReviewClaim !== false ||
    receipt?.governanceEffect !== "NONE" ||
    receipt?.selfAuthorizing !== false ||
    receipt?.conclusion === "INDEPENDENT_HUMAN_REVIEW_COMPLETE"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_HUMAN_CLAIM_FORBIDDEN");
  }
  if (
    receipt?.policyVersion !== policy?.policyVersion ||
    receipt?.policySha256 !== policy?.policySha256 ||
    receipt?.assuranceLevel !== "MODEL_ONLY_PREPRODUCTION" ||
    receipt?.bundleId !== bundle?.bundleId ||
    receipt?.bundleSha256 !== bundle?.bundleSha256 ||
    receipt?.applicablePhase !== bundle?.applicablePhase
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (
    canonicalizeProjectJson(receipt?.source) !==
      canonicalizeProjectJson(bundle?.source) ||
    receipt?.promptSha256 !== bundle?.artifacts?.promptSha256 ||
    canonicalizeProjectJson(receipt?.reviewedPaths) !==
      canonicalizeProjectJson(bundle?.reviewedPaths) ||
    canonicalizeProjectJson(receipt?.testEvidenceDigests) !==
      canonicalizeProjectJson(
        bundle?.testEvidenceSubjects?.map(
          (evidence) => evidence.outputSha256,
        ),
      )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (
    receipt?.reviewer?.provider !== runtimeAttestation?.provider ||
    receipt?.reviewer?.modelId !== runtimeAttestation?.modelId ||
    receipt?.reviewer?.modelFamily !== runtimeAttestation?.modelFamily ||
    receipt?.reviewer?.modelVersion !== runtimeAttestation?.modelVersion ||
    receipt?.reviewer?.modelVersionEvidence !==
      runtimeAttestation?.modelVersionEvidence ||
    receipt?.reviewer?.backendBuildId !==
      runtimeAttestation?.backendBuildId ||
    receipt?.reviewer?.diversityLevel !==
      runtimeAttestation?.diversityLevel
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_MODEL_IDENTITY_UNPINNED");
  }
  if (
    canonicalizeProjectJson(receipt?.findings) !==
      canonicalizeProjectJson(modelOutput?.findings) ||
    receipt?.decision !== modelOutput?.decision ||
    receipt?.conclusion !== CONCLUSIONS[modelOutput?.decision]
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (
    !safePath(receipt?.runtimeAttestationPath) ||
    !safePath(receipt?.modelOutputPath)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_INVALID");
  }
  if (
    !validDate(receipt?.startedAt) ||
    !validDate(receipt?.finishedAt) ||
    Date.parse(receipt.startedAt) > Date.parse(receipt.finishedAt)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_TIME_ORDER_INVALID");
  }
  return reasonCodes;
}

export async function validateIndependentModelReviewReceipt({
  policy,
  bundle,
  receipt,
  runtimeAttestation,
  modelOutput,
}) {
  const reasonCodes = [
    ...receiptBindingReasonCodes({
      policy,
      bundle,
      receipt,
      runtimeAttestation,
      modelOutput,
    }),
  ];
  if (
    !SHA256.test(receipt?.receiptSha256 ?? "") ||
    (SHA256.test(receipt?.receiptSha256 ?? "") &&
      (await receiptDigest(receipt)) !== receipt.receiptSha256)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_HASH_MISMATCH");
  }
  if (
    receipt?.runtimeAttestationSha256 !==
      (await runtimeDigest(runtimeAttestation)) ||
    receipt?.modelOutputSha256 !== (await modelOutputDigest(modelOutput)) ||
    runtimeAttestation?.rawModelOutputSha256 !==
      (await modelOutputDigest(modelOutput))
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (!outputIsClosed(modelOutput)) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_INVALID");
  }
  const independence = await validateIndependentModelIndependence({
    policy,
    bundle,
    runtimeAttestation,
  });
  reasonCodes.push(...independence.reasonCodes);
  const openBlockingFinding = modelOutput?.findings?.some(
    (finding) =>
      BLOCKING_SEVERITIES.has(finding.severity) && finding.status === "OPEN",
  );
  if (receipt?.decision === "CLEAR" && openBlockingFinding) {
    reasonCodes.push("INDEPENDENT_REVIEW_UNRESOLVED_BLOCKING_FINDING");
  }
  const uniqueReasonCodes = [...new Set(reasonCodes)];
  if (independence.status === "BLOCKED" || receipt?.decision === "BLOCKED") {
    return result(false, "BLOCKED", uniqueReasonCodes, {
      conclusion: "BLOCKED",
    });
  }
  if (
    independence.status === "INCONCLUSIVE" ||
    receipt?.decision === "INCONCLUSIVE"
  ) {
    return result(false, "INCONCLUSIVE", uniqueReasonCodes, {
      conclusion: "INCONCLUSIVE",
    });
  }
  if (openBlockingFinding) {
    return result(false, "BLOCKED", uniqueReasonCodes, {
      conclusion: "BLOCKED",
    });
  }
  if (uniqueReasonCodes.length > 0) {
    return result(false, "BLOCKED", uniqueReasonCodes, {
      conclusion: "BLOCKED",
    });
  }
  return result(true, "CLEAR", [], {
    conclusion: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  });
}

export function mapIndependentModelReviewCheckResult(validation) {
  if (
    !keysExactly(validation, [
      "ok",
      "status",
      "conclusion",
      "reasonCodes",
    ]) ||
    !["CLEAR", "BLOCKED", "INCONCLUSIVE"].includes(validation.status) ||
    !Array.isArray(validation.reasonCodes)
  ) {
    throw new TypeError(
      "Independent model review check requires a validated result.",
    );
  }
  const clear =
    validation.ok === true &&
    validation.status === "CLEAR" &&
    validation.conclusion === "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION";
  const title = clear
    ? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
    : validation.status;
  return {
    schemaVersion: "independent-model-review-check-result.v2",
    context: "independent-model-review",
    conclusion: clear ? "success" : "failure",
    title,
    exitCode: clear ? 0 : validation.status === "BLOCKED" ? 2 : 3,
    remotePublished: false,
    governanceEffect: "NONE",
    humanIndependentReviewSatisfied: false,
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    reasonCodes: structuredClone(validation.reasonCodes),
  };
}
