import supplementalEvidenceIndex from "../implementation/governance/v5.3-supplemental-evidence-index.v1.json" with { type: "json" };
import { sha256ProjectValue } from "./project-control.mjs";
import { P2_WORKER_ATTESTATION_PIN_POLICY } from "./p2-worker-attestation-policy.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const PROFILE_APPROVAL_ID = /^p2pa_[a-z0-9][a-z0-9_-]{7,127}$/;
const PROFILE_APPROVAL_REQUIRED_GROUP_IDS = Object.freeze(
  supplementalEvidenceIndex.groups.map(({ groupId }) => groupId),
);
const CLOSED_CLASSIFICATIONS = new Set([
  "EXISTING_EVIDENCE_REUSED",
  "GIT_FROZEN_AFTER_REMEDIATION",
  "GIT_FROZEN_PASS",
]);
const START_READINESS_TOOL_LOCKS = Object.freeze({
  O02: Object.freeze([
    "O02_SECRETS_SYSTEM",
    "O02_WORKLOAD_IDENTITY",
  ]),
  O03: Object.freeze([
    "O03_SBOM_GENERATOR",
    "O03_SIGNER_AND_VERIFIER",
    "O03_VULNERABILITY_SCANNER",
    "O03_LICENSE_SCANNER",
    "O03_ADMISSION_CONTROLLER",
  ]),
});
const SUPPLEMENTAL_EVIDENCE_INDEX_SHA256 =
  "sha256:692c4b3927da1f8be6f9d59ae5e225389f40bb0e7ed9b4fc722466ff7003aec0";

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function exactBinding(binding, expected) {
  return (
    binding &&
    typeof binding === "object" &&
    !Array.isArray(binding) &&
    JSON.stringify(Object.keys(binding).sort()) ===
      JSON.stringify(Object.keys(expected).sort()) &&
    Object.entries(expected).every(([key, value]) => binding[key] === value)
  );
}

function requiredEvidenceGroupsClosed(index, requiredEvidenceGroupIds) {
  if (
    !Array.isArray(index?.groups) ||
    !Array.isArray(index.externalBlockers) ||
    index.externalBlockers.length > 0
  ) {
    return false;
  }
  const groups = new Map();
  for (const group of index.groups) {
    if (
      typeof group?.groupId !== "string" ||
      groups.has(group.groupId)
    ) {
      return false;
    }
    groups.set(group.groupId, group);
  }
  return requiredEvidenceGroupIds.every((groupId) => {
    const group = groups.get(groupId);
    return (
      group &&
      CLOSED_CLASSIFICATIONS.has(group.classification)
    );
  });
}

function selectedToolLocksReady(candidateProfile, requiredDomains) {
  if (
    !Array.isArray(candidateProfile?.implementationToolLocks) ||
    !Array.isArray(requiredDomains)
  ) {
    return false;
  }
  const locks = new Map();
  for (const lock of candidateProfile.implementationToolLocks) {
    if (
      !lock ||
      typeof lock !== "object" ||
      Array.isArray(lock) ||
      typeof lock.domain !== "string" ||
      locks.has(lock.domain)
    ) {
      return false;
    }
    locks.set(lock.domain, lock);
  }
  return requiredDomains.every((domain) => {
    const lock = locks.get(domain);
    return (
      lock?.selection === "SELECTED" &&
      typeof lock.version === "string" &&
      lock.version.trim().length > 0 &&
      SHA256.test(lock.sha256 ?? "")
    );
  });
}

export const P2_GOVERNANCE_LIFECYCLE_TERMS = Object.freeze({
  candidatePrepared: "CANDIDATE_PREPARED",
  gitFrozen: "GIT_FROZEN",
  d1Approved: "D1_APPROVED",
  startAuthorized: "START_AUTHORIZED",
  started: "STARTED",
  verified: "VERIFIED",
});

export const P2_V2_CANDIDATE_READINESS_VIEW = deepFreeze({
  baselineRefs: {
    supplementalEvidenceIndex: {
      sha256: SUPPLEMENTAL_EVIDENCE_INDEX_SHA256,
    },
  },
  implementationToolLocks: [
    ...START_READINESS_TOOL_LOCKS.O02,
    ...START_READINESS_TOOL_LOCKS.O03,
  ].map((domain) => ({
    domain,
    selection: "UNSELECTED_BLOCKS_EVIDENCE",
  })),
});

export const P2_V2_CANDIDATE_PROFILE_READINESS_POLICY = Object.freeze({
  profileSha256:
    "sha256:90a9741d6ae39012458f073523da0c7b4dc8e4eef53ea759b32d6640e6aaef32",
  supplementalEvidenceIndexSha256: SUPPLEMENTAL_EVIDENCE_INDEX_SHA256,
  supplementalEvidenceIndexCanonicalSha256:
    "sha256:9ed2b07d8de8d37667124d43e8ce6e752a2c77a5fa802a5f5c2a6ad25d8cddda",
  sourceCommit: P2_WORKER_ATTESTATION_PIN_POLICY.source.commit,
  executionBaselineDigest:
    P2_WORKER_ATTESTATION_PIN_POLICY.executionBaseline.digest,
  requiredEvidenceGroupIds: PROFILE_APPROVAL_REQUIRED_GROUP_IDS,
});

export const P2_V2_CANDIDATE_START_READINESS_POLICY = Object.freeze({
  profileSha256:
    "sha256:90a9741d6ae39012458f073523da0c7b4dc8e4eef53ea759b32d6640e6aaef32",
  profileCanonicalSha256:
    "sha256:25ae0e3848ac8dba2f0c512764ad0b9f117cac4f7ff2710ef267d7a0a88dc2f3",
  sourceCommit: P2_WORKER_ATTESTATION_PIN_POLICY.source.commit,
  executionBaselineDigest:
    P2_WORKER_ATTESTATION_PIN_POLICY.executionBaseline.digest,
  requiredToolLocks: START_READINESS_TOOL_LOCKS,
});

export function createP2ProfileReadinessVerifier({
  profile,
  supplementalEvidenceIndex,
  profileSha256,
  supplementalEvidenceIndexSha256,
  supplementalEvidenceIndexCanonicalSha256,
  sourceCommit,
  executionBaselineDigest,
  requiredEvidenceGroupIds,
}) {
  let assets = null;
  try {
    assets = deepFreeze({
      profile: structuredClone(profile),
      supplementalEvidenceIndex: structuredClone(supplementalEvidenceIndex),
      requiredEvidenceGroupIds: structuredClone(requiredEvidenceGroupIds),
      supplementalEvidenceIndexCanonicalSha256,
      expectedBinding: {
        profileSha256,
        supplementalEvidenceIndexSha256,
        sourceCommit,
        executionBaselineDigest,
      },
    });
  } catch {
    assets = null;
  }
  return async function verify(binding) {
    try {
      return (
        assets !== null &&
        exactBinding(binding, assets.expectedBinding) &&
        assets.profile.baselineRefs.supplementalEvidenceIndex.sha256 ===
          supplementalEvidenceIndexSha256 &&
        (await sha256ProjectValue(assets.supplementalEvidenceIndex)) ===
          assets.supplementalEvidenceIndexCanonicalSha256 &&
        requiredEvidenceGroupsClosed(
          assets.supplementalEvidenceIndex,
          assets.requiredEvidenceGroupIds,
        )
      );
    } catch {
      return false;
    }
  };
}

export const verifyP2ProfileReadinessFromFrozenEvidence =
  createP2ProfileReadinessVerifier({
    profile: P2_V2_CANDIDATE_READINESS_VIEW,
    supplementalEvidenceIndex,
    ...P2_V2_CANDIDATE_PROFILE_READINESS_POLICY,
  });

export function createP2WorkPackageStartReadinessVerifier({
  profile,
  profileSha256,
  profileCanonicalSha256,
  sourceCommit,
  executionBaselineDigest,
  requiredToolLocks = START_READINESS_TOOL_LOCKS,
}) {
  let assets = null;
  try {
    assets = deepFreeze({
      profile: structuredClone(profile),
      profileCanonicalSha256,
      requiredToolLocks: structuredClone(requiredToolLocks),
      expectedBinding: {
        profileSha256,
        sourceCommit,
        executionBaselineDigest,
      },
    });
  } catch {
    assets = null;
  }
  return async function verify(binding) {
    try {
      const expectedKeys = [
        "executionBaselineDigest",
        "profileApprovalId",
        "profileSha256",
        "sourceCommit",
        "workPackageId",
      ];
      return (
        assets !== null &&
        binding &&
        typeof binding === "object" &&
        !Array.isArray(binding) &&
        JSON.stringify(Object.keys(binding).sort()) ===
          JSON.stringify(expectedKeys) &&
        PROFILE_APPROVAL_ID.test(binding.profileApprovalId ?? "") &&
        binding.profileSha256 === assets.expectedBinding.profileSha256 &&
        binding.sourceCommit === assets.expectedBinding.sourceCommit &&
        binding.executionBaselineDigest ===
          assets.expectedBinding.executionBaselineDigest &&
        Object.hasOwn(assets.requiredToolLocks, binding.workPackageId) &&
        (await sha256ProjectValue(assets.profile)) ===
          assets.profileCanonicalSha256 &&
        selectedToolLocksReady(
          assets.profile,
          assets.requiredToolLocks[binding.workPackageId],
        )
      );
    } catch {
      return false;
    }
  };
}

export const verifyP2WorkPackageStartReadinessFromFrozenProfile =
  createP2WorkPackageStartReadinessVerifier({
    profile: P2_V2_CANDIDATE_READINESS_VIEW,
    ...P2_V2_CANDIDATE_START_READINESS_POLICY,
  });
