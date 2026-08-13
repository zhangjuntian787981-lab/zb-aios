import assert from "node:assert/strict";
import test from "node:test";
import "./independent-model-review-policy-activation.cases.mjs";
import supplementalEvidenceIndex from "../implementation/governance/v5.3-supplemental-evidence-index.v3.json" with { type: "json" };
import candidateProfile from "../implementation/p2/acceptance/p2-acceptance-profile.v2.json" with { type: "json" };
import { P2_WORKER_ATTESTATION_PIN_POLICY } from "../lib/p2-worker-attestation-policy.mjs";
import {
  P2_GOVERNANCE_LIFECYCLE_TERMS,
  P2_V2_CANDIDATE_READINESS_VIEW,
  P2_V2_CANDIDATE_PROFILE_READINESS_POLICY,
  P2_V2_CANDIDATE_START_READINESS_POLICY,
  createP2ProfileReadinessVerifier,
  createP2WorkPackageStartReadinessVerifier,
  verifyP2ProfileReadinessFromFrozenEvidence,
  verifyP2WorkPackageStartReadinessFromFrozenProfile,
} from "../lib/p2-governance-readiness.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "../lib/p2-start-authorization.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;
const requiredEvidenceGroupIds = ["P0-B04", "P0-B07", "P0-B11", "P1-B11"];
const closedSupplementalEvidenceIndex = {
  externalBlockers: [],
  groups: requiredEvidenceGroupIds.map((groupId) => ({
    groupId,
    classification: "GIT_FROZEN_PASS",
  })),
};
const closedSupplementalEvidenceIndexCanonicalSha256 =
  "sha256:afb3a2bc5dc2866273a96de3ddfaaf08cd3d51402652320d83b990295d19de90";
const selectedO02Locks = [
  {
    domain: "O02_SECRETS_SYSTEM",
    selection: "SELECTED",
    version: "1.2.3",
    sha256: digest("1"),
  },
  {
    domain: "O02_WORKLOAD_IDENTITY",
    selection: "SELECTED",
    version: "4.5.6",
    sha256: digest("2"),
  },
];
const selectedO03Locks = [
  {
    domain: "O03_SBOM_GENERATOR",
    selection: "SELECTED",
    version: "1.0.0",
    sha256: digest("3"),
  },
  {
    domain: "O03_SIGNER_AND_VERIFIER",
    selection: "SELECTED",
    version: "2.0.0",
    sha256: digest("4"),
  },
  {
    domain: "O03_VULNERABILITY_SCANNER",
    selection: "SELECTED",
    version: "3.0.0",
    sha256: digest("5"),
  },
  {
    domain: "O03_LICENSE_SCANNER",
    selection: "SELECTED",
    version: "4.0.0",
    sha256: digest("6"),
  },
  {
    domain: "O03_ADMISSION_CONTROLLER",
    selection: "SELECTED",
    version: "5.0.0",
    sha256: digest("7"),
  },
];

function createStartVerifier(profile, profileCanonicalSha256) {
  return createP2WorkPackageStartReadinessVerifier({
    profile,
    profileSha256: digest("a"),
    profileCanonicalSha256,
    sourceCommit: "b".repeat(40),
    executionBaselineDigest: digest("c"),
  });
}

function startBinding(workPackageId) {
  return {
    workPackageId,
    profileApprovalId: "p2pa_profile_approved_01",
    profileSha256: digest("a"),
    sourceCommit: "b".repeat(40),
    executionBaselineDigest: digest("c"),
  };
}

test("final v2 Profile evidence is ready for a future D1 Profile Approval while preserving the approval boundary", async () => {
  assert.deepEqual(
    supplementalEvidenceIndex.groups
      .filter(({ groupId }) =>
        requiredEvidenceGroupIds.includes(groupId),
      )
      .map(({ groupId, classification }) => ({
        groupId,
        classification,
      })),
    ["P0-B04", "P0-B07", "P0-B11", "P1-B11"].map((groupId) => ({
      groupId,
      classification: "GIT_FROZEN_AFTER_REMEDIATION",
    })),
  );
  assert.equal(
    P2_V2_CANDIDATE_PROFILE_READINESS_POLICY
      .requiredEvidenceGroupIds.length,
    26,
  );
  assert.equal(
    await verifyP2ProfileReadinessFromFrozenEvidence({
      profileSha256: P2_V2_CANDIDATE_START_POLICY.profile.sha256,
      supplementalEvidenceIndexSha256:
        P2_V2_CANDIDATE_PROFILE_READINESS_POLICY
          .supplementalEvidenceIndexSha256,
      sourceCommit: P2_WORKER_ATTESTATION_PIN_POLICY.source.commit,
      executionBaselineDigest:
        P2_WORKER_ATTESTATION_PIN_POLICY.executionBaseline.digest,
    }),
    true,
  );
  assert.equal(
    P2_V2_CANDIDATE_PROFILE_READINESS_POLICY.profileSha256,
    "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5",
  );
  assert.equal(
    P2_V2_CANDIDATE_PROFILE_READINESS_POLICY
      .supplementalEvidenceIndexSha256,
    "sha256:acade5a2d5c0c0a46c6f29e25541c30614cea95199458ca162ac1b8d7fcdc884",
  );
  assert.equal(
    P2_V2_CANDIDATE_PROFILE_READINESS_POLICY.sourceCommit,
    "bc718bc1a069deaa388b9a00e0135c8e9427dd91",
  );
  assert.equal(
    P2_V2_CANDIDATE_PROFILE_READINESS_POLICY.executionBaselineDigest,
    "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec",
  );
});

test("Profile readiness accepts a matching Git-frozen binding only after every hard blocker is closed", async () => {
  const profileSha256 = digest("a");
  const supplementalEvidenceIndexSha256 = digest("b");
  const sourceCommit = "c".repeat(40);
  const executionBaselineDigest = digest("d");
  const verify = createP2ProfileReadinessVerifier({
    profile: {
      baselineRefs: {
        supplementalEvidenceIndex: {
          sha256: supplementalEvidenceIndexSha256,
        },
      },
    },
    supplementalEvidenceIndex: closedSupplementalEvidenceIndex,
    profileSha256,
    supplementalEvidenceIndexSha256,
    supplementalEvidenceIndexCanonicalSha256:
      closedSupplementalEvidenceIndexCanonicalSha256,
    sourceCommit,
    executionBaselineDigest,
    requiredEvidenceGroupIds,
  });

  assert.equal(
    await verify({
      profileSha256,
      supplementalEvidenceIndexSha256,
      sourceCommit,
      executionBaselineDigest,
    }),
    true,
  );
});

test("Profile readiness rejects changed Supplemental Index content behind the same declared raw hash", async () => {
  const profileSha256 = digest("a");
  const supplementalEvidenceIndexSha256 = digest("b");
  const verify = createP2ProfileReadinessVerifier({
    profile: {
      baselineRefs: {
        supplementalEvidenceIndex: {
          sha256: supplementalEvidenceIndexSha256,
        },
      },
    },
    supplementalEvidenceIndex: {
      ...closedSupplementalEvidenceIndex,
      marker: "tampered",
    },
    profileSha256,
    supplementalEvidenceIndexSha256,
    supplementalEvidenceIndexCanonicalSha256:
      closedSupplementalEvidenceIndexCanonicalSha256,
    sourceCommit: "c".repeat(40),
    executionBaselineDigest: digest("d"),
    requiredEvidenceGroupIds,
  });

  assert.equal(
    await verify({
      profileSha256,
      supplementalEvidenceIndexSha256,
      sourceCommit: "c".repeat(40),
      executionBaselineDigest: digest("d"),
    }),
    false,
  );
});

test("Profile readiness rejects any unresolved external blocker, not only the four currently pending groups", async () => {
  const supplementalEvidenceIndexSha256 = digest("b");
  const verify = createP2ProfileReadinessVerifier({
    profile: {
      baselineRefs: {
        supplementalEvidenceIndex: {
          sha256: supplementalEvidenceIndexSha256,
        },
      },
    },
    supplementalEvidenceIndex: {
      ...closedSupplementalEvidenceIndex,
      externalBlockers: [{ groupId: "P2-B99" }],
    },
    profileSha256: digest("a"),
    supplementalEvidenceIndexSha256,
    supplementalEvidenceIndexCanonicalSha256:
      "sha256:7689ebb879ab8a1680a6d0034e2ab23f916f5e76768794d43b2c8c00ac07c5d0",
    sourceCommit: "c".repeat(40),
    executionBaselineDigest: digest("d"),
    requiredEvidenceGroupIds,
  });

  assert.equal(
    await verify({
      profileSha256: digest("a"),
      supplementalEvidenceIndexSha256,
      sourceCommit: "c".repeat(40),
      executionBaselineDigest: digest("d"),
    }),
    false,
  );
});

test("Profile readiness rejects Profile, Supplemental Index, source and execution-baseline binding drift", async () => {
  const profileSha256 = digest("a");
  const supplementalEvidenceIndexSha256 = digest("b");
  const sourceCommit = "c".repeat(40);
  const executionBaselineDigest = digest("d");
  const verify = createP2ProfileReadinessVerifier({
    profile: {
      baselineRefs: {
        supplementalEvidenceIndex: {
          sha256: supplementalEvidenceIndexSha256,
        },
      },
    },
    supplementalEvidenceIndex: closedSupplementalEvidenceIndex,
    profileSha256,
    supplementalEvidenceIndexSha256,
    supplementalEvidenceIndexCanonicalSha256:
      closedSupplementalEvidenceIndexCanonicalSha256,
    sourceCommit,
    executionBaselineDigest,
    requiredEvidenceGroupIds,
  });
  const binding = {
    profileSha256,
    supplementalEvidenceIndexSha256,
    sourceCommit,
    executionBaselineDigest,
  };

  for (const changed of [
    { profileSha256: digest("e") },
    { supplementalEvidenceIndexSha256: digest("f") },
    { sourceCommit: "0".repeat(40) },
    { executionBaselineDigest: digest("1") },
  ]) {
    assert.equal(await verify({ ...binding, ...changed }), false);
  }
  assert.equal(await verify({ ...binding, ready: true }), false);
});

test("governance lifecycle terms distinguish Git preparation, D1 approval, authorization, execution and verification", () => {
  assert.deepEqual(Object.values(P2_GOVERNANCE_LIFECYCLE_TERMS), [
    "CANDIDATE_PREPARED",
    "GIT_FROZEN",
    "D1_APPROVED",
    "START_AUTHORIZED",
    "STARTED",
    "VERIFIED",
  ]);
  assert.equal(
    new Set(Object.values(P2_GOVERNANCE_LIFECYCLE_TERMS)).size,
    6,
  );
});

test("the minimal server readiness view exactly matches the frozen Candidate fields it enforces", () => {
  const enforcedDomains = new Set(
    P2_V2_CANDIDATE_READINESS_VIEW.implementationToolLocks.map(
      ({ domain }) => domain,
    ),
  );
  assert.deepEqual(P2_V2_CANDIDATE_READINESS_VIEW, {
    baselineRefs: {
      supplementalEvidenceIndex: {
        sha256:
          candidateProfile.baselineRefs.supplementalEvidenceIndex.sha256,
      },
    },
    implementationToolLocks:
      candidateProfile.implementationToolLocks.filter(({ domain }) =>
        enforcedDomains.has(domain),
      ),
  });
});

test("current v2 Candidate denies O02 and O03 start readiness while their tool locks remain unselected", async () => {
  const baseBinding = {
    profileApprovalId: "p2pa_profile_approved_01",
    profileSha256: P2_V2_CANDIDATE_START_READINESS_POLICY.profileSha256,
    sourceCommit: P2_V2_CANDIDATE_START_READINESS_POLICY.sourceCommit,
    executionBaselineDigest:
      P2_V2_CANDIDATE_START_READINESS_POLICY.executionBaselineDigest,
  };
  assert.equal(
    await verifyP2WorkPackageStartReadinessFromFrozenProfile({
      ...baseBinding,
      workPackageId: "O02",
    }),
    false,
  );
  assert.equal(
    await verifyP2WorkPackageStartReadinessFromFrozenProfile({
      ...baseBinding,
      workPackageId: "O03",
    }),
    false,
  );
});

test("O02 and O03 each accept only their own complete selected, versioned and digested tool locks", async () => {
  const profile = {
    implementationToolLocks: [
      ...selectedO02Locks,
      ...selectedO03Locks,
      {
        domain: "O06_BROWSER_AND_ACCESSIBILITY",
        selection: "UNSELECTED_BLOCKS_EVIDENCE",
      },
    ],
  };
  const profileCanonicalSha256 =
    "sha256:c470d1caae2d4043e665ee301f9e8e8834d0deca20fa259ca17ed1eb07a0d175";
  const verify = createStartVerifier(profile, profileCanonicalSha256);

  assert.equal(await verify(startBinding("O02")), true);
  assert.equal(await verify(startBinding("O03")), true);
  assert.equal(
    await createStartVerifier(
      {
        implementationToolLocks: selectedO02Locks,
      },
      "sha256:8e238fce6d5c60ca10a91f303c1179ee6ce9c3e59a5ee8b34406529819fe0707",
    )(startBinding("O03")),
    false,
  );
});

test("start readiness fails closed on profile, source, baseline or tool-lock binding drift", async () => {
  const profile = {
    implementationToolLocks: selectedO02Locks,
  };
  const verify = createStartVerifier(
    profile,
    "sha256:8e238fce6d5c60ca10a91f303c1179ee6ce9c3e59a5ee8b34406529819fe0707",
  );
  for (const changed of [
    { profileApprovalId: "not-a-governed-profile-id" },
    { profileSha256: digest("d") },
    { sourceCommit: "e".repeat(40) },
    { executionBaselineDigest: digest("f") },
  ]) {
    assert.equal(
      await verify({ ...startBinding("O02"), ...changed }),
      false,
    );
  }
  assert.equal(
    await createStartVerifier(
      {
        implementationToolLocks: [
          selectedO02Locks[0],
          {
            ...selectedO02Locks[1],
            selection: "UNSELECTED_BLOCKS_EVIDENCE",
          },
        ],
      },
      "sha256:63fe593c20f23fd71db4fc6eddfa656a23ab74c9be82e2e1ed30cdf895987836",
    )(startBinding("O02")),
    false,
  );
});
