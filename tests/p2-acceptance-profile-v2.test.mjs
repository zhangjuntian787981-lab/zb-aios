import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import test from "node:test";

const root = new URL("../", import.meta.url);
const execFileAsync = promisify(execFile);
const profilePath =
  "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json";
const profileBytes = await readFile(new URL(profilePath, root));
const profile = JSON.parse(profileBytes);
const finalProfilePath =
  "implementation/p2/acceptance/p2-acceptance-profile.v2.json";
const finalProfileBytes = await readFile(new URL(finalProfilePath, root));
const finalProfile = JSON.parse(finalProfileBytes);

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function readFrozenBlob(commit, path) {
  const { stdout } = await execFileAsync(
    "/usr/bin/git",
    ["--no-replace-objects", "cat-file", "blob", `${commit}:${path}`],
    { cwd: root, encoding: null },
  );
  return Buffer.from(stdout);
}

test("v2 Candidate preserves all P2 criteria without becoming status or start authority", async () => {
  assert.equal(profile.schemaVersion, "p2-acceptance-profile.v2");
  assert.equal(profile.artifactLifecycle, "GIT_FROZEN_CANDIDATE");
  assert.equal(profile.isProgressTracker, false);
  assert.equal(profile.selfAuthorizing, false);
  assert.equal(profile.authorityBoundary.recordsWorkPackageStatus, false);
  assert.equal(profile.authorityBoundary.recordsGateSubmissionOrDecision, false);
  assert.equal(profile.criteria.length, 91);
  assert.equal(profile.crossStageCriteria.length, 5);
  assert.equal(
    [...profile.criteria, ...profile.crossStageCriteria].every(
      (criterion) =>
        criterion.receiptSchemaRef ===
          "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json" &&
        criterion.independentReviewRequired === true &&
        criterion.metricPolicyStatus === "UNRESOLVED_BLOCKS_PASS",
    ),
    true,
  );

  assert.deepEqual(profile.startBoundary, {
    runtimeStateRecordedHere: false,
    receiptCollectionAuthorizedHere: false,
    defaultEffect: "DENY",
    protectedWorkPackages: ["O02", "O03"],
    profileApprovalEventType: "P2_ACCEPTANCE_PROFILE_APPROVED",
    startAuthorizationEventType: "P2_WORK_PACKAGE_START_AUTHORIZED",
    startAuthorizationDigestBinding: "executionBaselineDigest",
    completionReceiptDigestBinding: "finalReleaseDigest",
    currentCandidateEffect: "NO_AUTHORITY",
  });
  assert.equal(Object.hasOwn(profile.startBoundary, "startO02Authorized"), false);
  assert.equal(Object.hasOwn(profile.startBoundary, "startO03Authorized"), false);

  assert.equal(finalProfile.schemaVersion, "p2-acceptance-profile.v2");
  assert.equal(finalProfile.artifactLifecycle, "GIT_FROZEN_CANDIDATE");
  assert.equal(finalProfile.profileFreeze, "CANDIDATE_NOT_ACTIVATED");
  assert.equal(finalProfile.isProgressTracker, false);
  assert.equal(finalProfile.selfAuthorizing, false);
  assert.equal(finalProfile.authorityBoundary.recordsWorkPackageStatus, false);
  assert.equal(
    finalProfile.authorityBoundary.recordsGateSubmissionOrDecision,
    false,
  );
  assert.equal(finalProfile.startBoundary.currentCandidateEffect, "NO_AUTHORITY");
  assert.equal(finalProfile.receiptPolicy.singleImplementerEffect, "INCONCLUSIVE");
});

test("v2 Candidate records a real UTC time and a Git-bound baseline recipe", () => {
  assert.match(
    profile.recordedAt,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
  );
  assert.equal(Date.parse(profile.recordedAt) <= Date.now(), true);
  assert.equal(
    profile.governanceEventContract.profileApproval
      .executionBaselineRecipePath,
    "implementation/p2/acceptance/p2-execution-baseline-recipe.v1.json",
  );
  assert.equal(
    profile.governanceEventContract.workPackageStartAuthorization.causalOrder,
    "PROFILE_APPROVAL_REVISION_MUST_BE_LOWER_THAN_START_AUTHORIZATION_REVISION",
  );
  assert.deepEqual(profile.digestPolicy.executionBaseline.gitBinding, {
    commitObjectType: "EXACT_COMMIT",
    gitEnvironment:
      "SANITIZED_NO_GIT_DIR_WORK_TREE_CONFIG_REPLACE_OR_ALTERNATE_ENVIRONMENT",
    gitExecutable: "/usr/bin/git",
    recipeSchemaVersion: "p2-execution-baseline-recipe.v1",
    recipePath:
      "implementation/p2/acceptance/p2-execution-baseline-recipe.v1.json",
    sourceCommitBinding:
      "SOURCE_COMMIT_INJECTED_AFTER_COMMIT_ID_VERIFICATION",
    verification:
      "READ_RECIPE_PROFILE_SCHEMA_VALIDATOR_FIXTURES_AND_TOOL_LOCKS_FROM_SOURCE_COMMIT",
  });

  assert.equal(
    finalProfile.governanceEventContract.profileApproval
      .executionBaselineRecipePath,
    "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json",
  );
  assert.deepEqual(finalProfile.digestPolicy.executionBaseline.gitBinding, {
    commitObjectType: "EXACT_COMMIT",
    gitEnvironment:
      "SANITIZED_NO_GIT_DIR_WORK_TREE_CONFIG_REPLACE_OR_ALTERNATE_ENVIRONMENT",
    gitExecutable: "/usr/bin/git",
    recipeSchemaVersion: "p2-execution-baseline-recipe.v1",
    recipePath:
      "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json",
    sourceCommitBinding:
      "SOURCE_COMMIT_INJECTED_AFTER_COMMIT_ID_VERIFICATION",
    verification:
      "READ_RECIPE_PROFILE_SCHEMA_VALIDATOR_FIXTURES_AND_TOOL_LOCKS_FROM_SOURCE_COMMIT",
  });
  assert.deepEqual(finalProfile.baselineRefs.supplementalEvidenceIndex, {
    path: "implementation/governance/v5.3-supplemental-evidence-index.v3.json",
    sha256:
      "sha256:acade5a2d5c0c0a46c6f29e25541c30614cea95199458ca162ac1b8d7fcdc884",
    freezeCommit: "37881ca870282da6adb54a0ff68b3a25539d79eb",
  });
  assert.deepEqual(finalProfile.baselineRefs.independentReviewPolicy, {
    path: "implementation/governance/independent-review/independent-review-policy.v2.json",
    sha256:
      "sha256:1bc70e243ccf1d3dc0d202a300469f0e169b40632712f12d0910573e03ccff8d",
    freezeCommit: "bcc314f65709aebb21dc5afa923753a224a6de4c",
    lifecycle: "ACTIVE",
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    applicablePhases: ["P0", "P1", "P2"],
    dataBoundary: "SYNTHETIC_ONLY",
    humanIndependentReviewRequired: false,
    humanIndependentReviewSatisfied: false,
    independentModelReviewRequired: true,
    p3HumanReviewRequired: true,
    allowedModelConclusion: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  });
  assert.deepEqual(
    Object.keys(finalProfile.baselineRefs.independentReviewPolicy).sort(),
    [
      "allowedModelConclusion",
      "applicablePhases",
      "assuranceLevel",
      "dataBoundary",
      "freezeCommit",
      "humanIndependentReviewRequired",
      "humanIndependentReviewSatisfied",
      "independentModelReviewRequired",
      "lifecycle",
      "p3HumanReviewRequired",
      "path",
      "sha256",
    ].sort(),
  );
});

test("v2 Candidate defines the non-circular digest and conditional applicability policies", () => {
  assert.deepEqual(profile.digestPolicy.order, [
    "FREEZE_SOURCE",
    "COMPUTE_EXECUTION_BASELINE_DIGEST",
    "EXECUTE_TESTS",
    "FREEZE_RAW_EVIDENCE",
    "COMPUTE_EVIDENCE_INDEX_DIGEST",
    "COMPUTE_ARTIFACT_MANIFEST_DIGEST",
    "COMPUTE_FINAL_RELEASE_DIGEST",
    "ISSUE_RECEIPTS",
  ]);
  assert.deepEqual(profile.digestPolicy.executionBaseline.includes, [
    "sourceCommit",
    "acceptanceProfileRawBytesSha256",
    "receiptSchemaVersionAndSha256",
    "semanticValidatorVersionAndSha256",
    "fixtureSubjects",
    "toolLocks",
  ]);
  assert.deepEqual(profile.digestPolicy.executionBaseline.excludes, [
    "rawEvidence",
    "evidenceIndexDigest",
    "artifactManifestDigest",
    "finalReleaseDigest",
    "receipts",
  ]);
  assert.equal(
    profile.digestPolicy.rawEvidence.bindsTo,
    "executionBaselineDigest",
  );
  assert.deepEqual(profile.digestPolicy.finalRelease.inputs, [
    "executionBaselineDigest",
    "evidenceIndexDigest",
    "artifactManifestDigest",
  ]);
  assert.deepEqual(profile.digestPolicy.finalRelease.excludes, [
    "finalReleaseDescriptor",
    "receipts",
  ]);
  assert.equal(
    profile.digestPolicy.artifactManifest.requiresGitFreezeCommit,
    true,
  );
  assert.equal(
    profile.digestPolicy.artifactManifest.controlDocumentContentDetectionRequired,
    true,
  );
  assert.equal(
    profile.digestPolicy.artifactManifest.allowedKinds.includes("RECEIPT"),
    false,
  );
  assert.equal(profile.digestPolicy.evidenceIndex.allEntriesMustBeGitVerified, true);
  assert.deepEqual(
    profile.digestPolicy.rawEvidence.forbiddenControlDocumentSchemas,
    [
      "p2-acceptance-receipt.v*",
      "p2-evidence-index.v1",
      "p2-final-release.v1",
      "p2-final-release-subject.v1",
      "p2-artifact-manifest.v1",
    ],
  );
  assert.equal(Object.hasOwn(profile, "executionBaselineDigest"), false);
  assert.equal(Object.hasOwn(profile, "finalReleaseDigest"), false);

  const conditional = profile.crossStageCriteria.find(
    ({ criterionId }) => criterionId === "C17-AC09",
  );
  assert.deepEqual(conditional.applicabilityRule, {
    predicateRef: "release.capabilities.webhookExposed",
    notApplicableWhen: false,
    unknownEffect: "INCONCLUSIVE",
  });
});

test("v2 Candidate fixes the append-only D1 event and rejection contracts", () => {
  const contract = profile.governanceEventContract;
  assert.equal(
    contract.ledgerAuthority,
    "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
  );
  assert.equal(contract.createsSecondStatusTruth, false);
  assert.equal(
    contract.profileApproval.eventType,
    "P2_ACCEPTANCE_PROFILE_APPROVED",
  );
  assert.equal(
    contract.workPackageStartAuthorization.eventType,
    "P2_WORK_PACKAGE_START_AUTHORIZED",
  );
  assert.equal(
    contract.workPackageStartAuthorization.finalReleaseDigestForbidden,
    true,
  );
  assert.equal(
    contract.profileApproval.approvalIdUniqueness,
    "GLOBAL_IN_LEDGER",
  );
  assert.equal(
    contract.workPackageStartAuthorization.authorizationIdUniqueness,
    "GLOBAL_IN_LEDGER",
  );
  assert.equal(
    contract.workPackageStartAuthorization.revocationScope,
    "EXACT_CURRENT_AUTHORIZATION_IN_SAME_WORK_PACKAGE",
  );
  assert.equal(
    contract.idempotency.sameKeySameCommand,
    "RETURN_ORIGINAL_EVENT_WITHOUT_REVISION_INCREMENT",
  );
  assert.equal(
    contract.revision.staleEffect,
    "REJECT_STALE_REVISION_WITHOUT_APPEND",
  );
  assert.equal(
    contract.revision.fullLedgerSequence,
    "UNIQUE_EVENT_IDS_AND_CONTIGUOUS_UNIQUE_REVISIONS_FROM_ONE",
  );
  assert.equal(
    contract.denyBehavior.revokedAuthorization,
    "DENY_FUTURE_PROGRESS_WITHOUT_REWRITING_HISTORY",
  );
});

test("v2 Candidate records reference adoption boundaries and leaves history immutable", async () => {
  assert.deepEqual(profile.referenceAdoption.adopted, [
    "JSON_SCHEMA_2020_12_WITH_AJV_8_20_0_FOR_STRUCTURE",
    "SLSA_SUBJECT_AND_MATERIAL_DIGEST_PATTERN",
    "IN_TOTO_SUBJECT_PREDICATE_SEPARATION_PATTERN",
    "COSIGN_DIGEST_FIRST_VERIFICATION_PATTERN",
    "GITHUB_CI_CODEOWNERS_RULESET_GUIDANCE_ONLY",
  ]);
  assert.deepEqual(profile.referenceAdoption.notAdopted, [
    "NO_SLSA_LEVEL_CLAIM",
    "NO_DSSE_OR_IN_TOTO_STATEMENT_IMPLEMENTATION",
    "NO_COSIGN_FULCIO_REKOR_OR_SIGNATURE_OPERATION",
    "NO_GITHUB_REMOTE_CI_CODEOWNERS_OR_RULESET_CHANGE",
    "NO_EXTERNAL_PROJECT_CODE_COPIED",
  ]);

  assert.deepEqual(finalProfile.referenceAdoption.adopted, [
    "JSON_SCHEMA_2020_12_WITH_AJV_8_20_0_FOR_STRUCTURE",
    "SLSA_SUBJECT_AND_MATERIAL_DIGEST_PATTERN",
    "IN_TOTO_SUBJECT_PREDICATE_SEPARATION_PATTERN",
    "COSIGN_DIGEST_FIRST_VERIFICATION_PATTERN",
    "GITHUB_REQUIRED_CHECK_AND_RULESET_EVIDENCED_BY_P1_B11_SUPPLEMENTAL_INDEX_V3",
  ]);
  assert.deepEqual(finalProfile.referenceAdoption.notAdopted, [
    "NO_SLSA_LEVEL_CLAIM",
    "NO_DSSE_OR_IN_TOTO_STATEMENT_IMPLEMENTATION",
    "NO_COSIGN_FULCIO_REKOR_OR_SIGNATURE_OPERATION",
    "NO_EXTERNAL_PROJECT_CODE_COPIED",
  ]);

  const candidateProjection = structuredClone(finalProfile);
  candidateProjection.baselineRefs = structuredClone(profile.baselineRefs);
  candidateProjection.governanceEventContract.profileApproval.executionBaselineRecipePath =
    profile.governanceEventContract.profileApproval.executionBaselineRecipePath;
  candidateProjection.digestPolicy.executionBaseline.gitBinding.recipePath =
    profile.digestPolicy.executionBaseline.gitBinding.recipePath;
  candidateProjection.referenceAdoption = structuredClone(
    profile.referenceAdoption,
  );
  assert.deepEqual(candidateProjection, profile);

  const [policyBytes, indexBytes] = await Promise.all([
    readFrozenBlob(
      "bcc314f65709aebb21dc5afa923753a224a6de4c",
      finalProfile.baselineRefs.independentReviewPolicy.path,
    ),
    readFrozenBlob(
      "37881ca870282da6adb54a0ff68b3a25539d79eb",
      finalProfile.baselineRefs.supplementalEvidenceIndex.path,
    ),
  ]);
  assert.equal(
    sha256(policyBytes),
    finalProfile.baselineRefs.independentReviewPolicy.sha256,
  );
  assert.equal(
    sha256(indexBytes),
    finalProfile.baselineRefs.supplementalEvidenceIndex.sha256,
  );
  const frozenPolicy = JSON.parse(policyBytes);
  for (const key of [
    "lifecycle",
    "assuranceLevel",
    "applicablePhases",
    "dataBoundary",
    "humanIndependentReviewRequired",
    "humanIndependentReviewSatisfied",
    "independentModelReviewRequired",
    "p3HumanReviewRequired",
    "allowedModelConclusion",
  ]) {
    assert.deepEqual(
      finalProfile.baselineRefs.independentReviewPolicy[key],
      frozenPolicy[key],
    );
  }
  const frozenIndex = JSON.parse(indexBytes);
  const p1B11 = frozenIndex.groups.find(({ groupId }) => groupId === "P1-B11");
  assert.deepEqual(p1B11.evidence, {
    path: "implementation/p1/c13/p1-b11-model-only-protected-review-evidence.v1.json",
    sha256:
      "sha256:9bbad8ac7f7090323aadbb0a98980a4d14fafc5c55e5aaa1b4e84d2eeedc2d37",
  });
  assert.equal(
    p1B11.evidenceFreezeCommit,
    "55bbad5149ca377442157267a5ffc636e9f07224",
  );
  assert.equal(
    sha256(await readFrozenBlob(p1B11.evidenceFreezeCommit, p1B11.evidence.path)),
    p1B11.evidence.sha256,
  );

  const [v1Profile, v1Schema, candidateProfile, legacyRecipe, indexV1, indexV2] =
    await Promise.all([
    readFile(
      new URL(
        "implementation/p2/acceptance/p2-acceptance-profile.v1.json",
        root,
      ),
    ),
    readFile(
      new URL(
        "implementation/p2/acceptance/p2-acceptance-receipt.v1.schema.json",
        root,
      ),
    ),
    readFile(new URL(profilePath, root)),
    readFile(
      new URL(
        "implementation/p2/acceptance/p2-execution-baseline-recipe.v1.json",
        root,
      ),
    ),
    readFile(
      new URL(
        "implementation/governance/v5.3-supplemental-evidence-index.v1.json",
        root,
      ),
    ),
    readFile(
      new URL(
        "implementation/governance/v5.3-supplemental-evidence-index.v2.json",
        root,
      ),
    ),
  ]);
  assert.equal(
    sha256(v1Profile),
    "sha256:689a7d4816ac41a574414cb633a022ffaa1a5c6a59c5d8fee2906d3879a16dcf",
  );
  assert.equal(
    sha256(v1Schema),
    "sha256:0463a6eb892d300ab560a1587e39191a1d36086700275e65f7c9f6cf227375f2",
  );
  assert.equal(
    sha256(candidateProfile),
    "sha256:90a9741d6ae39012458f073523da0c7b4dc8e4eef53ea759b32d6640e6aaef32",
  );
  assert.equal(
    sha256(legacyRecipe),
    "sha256:43289d9784888585ad427b723370e89debc3a67bf14e424b4bfb41e101bc37ef",
  );
  assert.equal(
    sha256(indexV1),
    "sha256:692c4b3927da1f8be6f9d59ae5e225389f40bb0e7ed9b4fc722466ff7003aec0",
  );
  assert.equal(
    sha256(indexV2),
    "sha256:6327632b416687987e49fa207f1c4562647cb1298f276490822c85850ea8c05a",
  );
});
