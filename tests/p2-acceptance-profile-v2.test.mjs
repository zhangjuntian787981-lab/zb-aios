import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const profilePath =
  "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json";
const profileBytes = await readFile(new URL(profilePath, root));
const profile = JSON.parse(profileBytes);

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
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
    contract.idempotency.sameKeySameCommand,
    "RETURN_ORIGINAL_EVENT_WITHOUT_REVISION_INCREMENT",
  );
  assert.equal(
    contract.revision.staleEffect,
    "REJECT_STALE_REVISION_WITHOUT_APPEND",
  );
  assert.equal(
    contract.denyBehavior.revokedAuthorization,
    "DENY_FUTURE_PROGRESS_WITHOUT_REWRITING_HISTORY",
  );
});

test("v2 Candidate records reference adoption boundaries and leaves v1 immutable", async () => {
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

  const [v1Profile, v1Schema] = await Promise.all([
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
  ]);
  assert.equal(
    sha256(v1Profile),
    "sha256:689a7d4816ac41a574414cb633a022ffaa1a5c6a59c5d8fee2906d3879a16dcf",
  );
  assert.equal(
    sha256(v1Schema),
    "sha256:0463a6eb892d300ab560a1587e39191a1d36086700275e65f7c9f6cf227375f2",
  );
});
