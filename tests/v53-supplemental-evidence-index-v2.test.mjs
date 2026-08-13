import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { sha256ProjectValue } from "../lib/project-control.mjs";
import {
  P2_V2_CANDIDATE_PROFILE_READINESS_POLICY,
  verifyP2ProfileReadinessFromFrozenEvidence,
} from "../lib/p2-governance-readiness.mjs";

const root = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(root);
const candidateIndexPath =
  "../implementation/governance/v5.3-supplemental-evidence-index.v2.candidate.json";
const finalIndexPath =
  "../implementation/governance/v5.3-supplemental-evidence-index.v2.json";
const v3IndexPath =
  "../implementation/governance/v5.3-supplemental-evidence-index.v3.json";
const finalIndexCanonicalSha256 =
  "sha256:fc70d17b9004b87ce418b5498bf3c3330c819532552a6153c3f29ccd37bc2fcd";
const finalIndexRawSha256 =
  "sha256:6327632b416687987e49fa207f1c4562647cb1298f276490822c85850ea8c05a";
const v3IndexCanonicalSha256 =
  "sha256:681be20a84cda885a412158928e8eade97fc08ceac75780b11c7b2410f2509ec";
const v3IndexRawSha256 =
  "sha256:acade5a2d5c0c0a46c6f29e25541c30614cea95199458ca162ac1b8d7fcdc884";
const v3IndexByteLength = 19245;
const v3RecordedAt = "2026-08-13T06:03:54.000Z";
const v3GovernanceStatement =
  "本索引仅在 Supplemental Evidence 层追加冻结 P1-B11 的 P0–P2 model-only 远端保护证据；历史 INCONCLUSIVE 记录保持不变，且它不改变 Manifest、D1、Gate、Profile、Recipe、Attestation、runtime pin 或工作包状态，也不产生 Profile Approval、P3/生产批准或启动授权。";
const candidateIndex = JSON.parse(
  await readFile(new URL(candidateIndexPath, import.meta.url), "utf8"),
);
const v3Index = JSON.parse(
  await readFile(new URL(v3IndexPath, import.meta.url), "utf8"),
);

const protectedGroups = Object.freeze({
  "P0-B04": {
    gitMode: "100644",
    byteLength: 12672,
    sourceCommit: "862adfd58c8ead48f4a18d84a72cdbc28c89bc5c",
    evidenceFreezeCommit:
      "96ccc8fd375cf895285c42971b76863184b320b0",
    path:
      "implementation/p0/f02/f02-hosted-ci-supplemental-evidence.v1.json",
    sha256:
      "sha256:5df82bdad73e2b9a55710a4c5e04662d38f8045b83089ed51b5e19a92bd2a0ac",
  },
  "P0-B07": {
    gitMode: "100644",
    byteLength: 10196,
    sourceCommit: "807172852044d4c86480f05845b358e5ed394e9e",
    evidenceFreezeCommit:
      "5d12201e984937a905ab8bae90a86a4b1763d899",
    path:
      "implementation/p0/f03/f03-hosted-ci-supplemental-evidence.v1.json",
    sha256:
      "sha256:e9c0f323f9e58f77e74fc0b433595c790c5477ce6a2b47f15d8f644649c5a413",
  },
  "P0-B11": {
    gitMode: "100644",
    byteLength: 7410,
    sourceCommit: "127f7dac03aec2569af1c538d37c04670d2c2fbb",
    evidenceFreezeCommit:
      "3cca881e9f6bc89cba28fc7fc5a42663208c8a10",
    path:
      "implementation/p0/evidence/p0-b11-f04-ac07-supplemental-evidence.v1.json",
    sha256:
      "sha256:58f2ae65e0dfb17e848fbb5aba07695ba38cdf9351f6f67aa23a740653f37165",
  },
});

const p1B11Closure = Object.freeze({
  gitMode: "100644",
  byteLength: 18027,
  sourceCommit: "fa9b353644314f70a1849d0def1396301e136240",
  evidenceFreezeCommit: "55bbad5149ca377442157267a5ffc636e9f07224",
  path:
    "implementation/p1/c13/p1-b11-model-only-protected-review-evidence.v1.json",
  sha256:
    "sha256:9bbad8ac7f7090323aadbb0a98980a4d14fafc5c55e5aaa1b4e84d2eeedc2d37",
  limitation:
    "仅闭合 P0–P2 Synthetic 的 model-only 受保护评审补证；humanIndependentReviewSatisfied 仍为 false，历史 INCONCLUSIVE 不被追溯覆盖，且不授权 P3、真实数据/凭据、真实用户或生产。",
});

const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_EXTERNAL_DIFF: "",
});

function sha256(content) {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

function git(args) {
  return execFileSync("/usr/bin/git", args, {
    cwd: repositoryRoot,
    env: gitEnvironment,
  });
}

async function loadFinalIndex() {
  return JSON.parse(
    await readFile(new URL(finalIndexPath, import.meta.url), "utf8"),
  );
}

async function withRecomputedSelfHash(value) {
  const result = structuredClone(value);
  delete result.indexCanonicalSha256;
  result.indexCanonicalSha256 = await sha256ProjectValue(result);
  return result;
}

async function assertFinalIndex(finalIndex) {
  const expected = structuredClone(candidateIndex);
  expected.schemaVersion = "v5.3-supplemental-evidence-index.v2";
  expected.artifactLifecycle = "GIT_FROZEN";
  expected.indexCanonicalSha256 = finalIndexCanonicalSha256;
  assert.equal(
    finalIndex.schemaVersion,
    "v5.3-supplemental-evidence-index.v2",
  );
  assert.equal(finalIndex.recordType, "STATIC_SUPPLEMENTAL_EVIDENCE_INDEX");
  assert.equal(finalIndex.artifactLifecycle, "GIT_FROZEN");
  assert.equal(finalIndex.isProgressTracker, false);
  assert.equal(finalIndex.selfAuthorizing, false);
  assert.equal(
    finalIndex.governanceDisclaimer.isWorkPackageOrGateStatusAuthority,
    false,
  );
  assert.equal(finalIndex.governanceDisclaimer.d1LedgerChanged, false);
  assert.equal(finalIndex.governanceDisclaimer.profileApproved, false);
  assert.equal(finalIndex.governanceDisclaimer.startAuthorized, false);
  assert.deepEqual(
    finalIndex.groups.map(({ groupId }) => groupId),
    candidateIndex.groups.map(({ groupId }) => groupId),
  );
  assert.equal(finalIndex.groups.length, 26);
  assert.equal(
    new Set(finalIndex.groups.map(({ groupId }) => groupId)).size,
    26,
  );
  assert.deepEqual(
    finalIndex.externalBlockers.map(({ groupId }) => groupId),
    ["P1-B11"],
  );
  assert.deepEqual(finalIndex.remainingProfileApprovalHardBlockers, [
    "P1-B11",
  ]);
  assert.equal(
    finalIndex.groups.find(({ groupId }) => groupId === "P1-B11")
      .classification,
    "PARTIAL_EXTERNAL_EVIDENCE_PENDING",
  );
  assert.equal(
    finalIndex.profileReadinessEffect,
    "NONE_P1_B11_STILL_OPEN",
  );
  assert.equal(
    finalIndex.governanceDisclaimer.statement,
    candidateIndex.governanceDisclaimer.statement,
  );
  for (const [groupId, expected] of Object.entries(protectedGroups)) {
    const group = finalIndex.groups.find(({ groupId: id }) => id === groupId);
    assert.equal(group.classification, "GIT_FROZEN_AFTER_REMEDIATION");
    assert.deepEqual(
      {
        sourceCommit: group.sourceCommit,
        evidenceFreezeCommit: group.evidenceFreezeCommit,
        path: group.evidence.path,
        sha256: group.evidence.sha256,
      },
      {
        sourceCommit: expected.sourceCommit,
        evidenceFreezeCommit: expected.evidenceFreezeCommit,
        path: expected.path,
        sha256: expected.sha256,
      },
    );
  }
  const subject = structuredClone(finalIndex);
  delete subject.indexCanonicalSha256;
  assert.equal(
    await sha256ProjectValue(subject),
    finalIndexCanonicalSha256,
  );
  assert.deepEqual(finalIndex, expected);
}

async function assertV3Index(index) {
  const finalIndex = await loadFinalIndex();
  const expected = structuredClone(finalIndex);
  expected.schemaVersion = "v5.3-supplemental-evidence-index.v3";
  expected.recordedAt = v3RecordedAt;
  expected.governanceDisclaimer.statement = v3GovernanceStatement;
  expected.classificationSummary.GIT_FROZEN_AFTER_REMEDIATION = 11;
  expected.classificationSummary.PARTIAL_EXTERNAL_EVIDENCE_PENDING = 0;
  expected.externalBlockers = [];
  expected.groups[21] = {
    groupId: "P1-B11",
    criteria: ["C13-AC02"],
    classification: "GIT_FROZEN_AFTER_REMEDIATION",
    sourceCommit: p1B11Closure.sourceCommit,
    evidenceFreezeCommit: p1B11Closure.evidenceFreezeCommit,
    evidence: {
      path: p1B11Closure.path,
      sha256: p1B11Closure.sha256,
    },
    limitation: p1B11Closure.limitation,
  };
  expected.supersedes = {
    path: "implementation/governance/v5.3-supplemental-evidence-index.v2.json",
    rawSha256: finalIndexRawSha256,
  };
  expected.profileReadinessEffect =
    "NONE_ACTIVE_PROFILE_REMAINS_BOUND_TO_V1";
  expected.remainingProfileApprovalHardBlockers = [];
  expected.governanceEffect = "NONE";
  expected.indexCanonicalSha256 = v3IndexCanonicalSha256;

  assert.equal(index.schemaVersion, "v5.3-supplemental-evidence-index.v3");
  assert.equal(index.recordType, "STATIC_SUPPLEMENTAL_EVIDENCE_INDEX");
  assert.equal(index.artifactLifecycle, "GIT_FROZEN");
  assert.equal(index.isProgressTracker, false);
  assert.equal(index.selfAuthorizing, false);
  assert.equal(index.governanceEffect, "NONE");
  assert.equal(
    index.governanceDisclaimer.isWorkPackageOrGateStatusAuthority,
    false,
  );
  assert.equal(index.governanceDisclaimer.d1LedgerChanged, false);
  assert.equal(index.governanceDisclaimer.gateSubmissionChanged, false);
  assert.equal(index.governanceDisclaimer.gateDecisionChanged, false);
  assert.equal(index.governanceDisclaimer.profileApproved, false);
  assert.equal(index.governanceDisclaimer.startAuthorized, false);
  assert.deepEqual(index.externalBlockers, []);
  assert.deepEqual(index.remainingProfileApprovalHardBlockers, []);
  assert.equal(
    index.profileReadinessEffect,
    "NONE_ACTIVE_PROFILE_REMAINS_BOUND_TO_V1",
  );
  assert.deepEqual(
    index.groups.map(({ groupId }) => groupId),
    finalIndex.groups.map(({ groupId }) => groupId),
  );
  assert.equal(index.groups.length, 26);
  assert.equal(new Set(index.groups.map(({ groupId }) => groupId)).size, 26);
  for (const [position, group] of index.groups.entries()) {
    if (group.groupId !== "P1-B11") {
      assert.deepEqual(group, finalIndex.groups[position], group.groupId);
      assert.equal(
        JSON.stringify(group),
        JSON.stringify(finalIndex.groups[position]),
        group.groupId,
      );
    }
  }
  const subject = structuredClone(index);
  delete subject.indexCanonicalSha256;
  assert.equal(await sha256ProjectValue(subject), v3IndexCanonicalSha256);
  assert.deepEqual(index, expected);
}

test("v2 candidate closes only the three newly frozen P0 supplements", async () => {
  assert.equal(
    candidateIndex.schemaVersion,
    "v5.3-supplemental-evidence-index.v2.candidate",
  );
  assert.equal(candidateIndex.recordType, "STATIC_SUPPLEMENTAL_EVIDENCE_INDEX");
  assert.equal(candidateIndex.artifactLifecycle, "GIT_FROZEN_CANDIDATE");
  assert.equal(candidateIndex.isProgressTracker, false);
  assert.equal(candidateIndex.selfAuthorizing, false);
  assert.equal(
    candidateIndex.governanceDisclaimer.isWorkPackageOrGateStatusAuthority,
    false,
  );
  assert.equal(candidateIndex.governanceDisclaimer.d1LedgerChanged, false);
  assert.equal(candidateIndex.governanceDisclaimer.profileApproved, false);
  assert.equal(candidateIndex.governanceDisclaimer.startAuthorized, false);
  assert.equal(candidateIndex.groups.length, 26);
  assert.equal(
    new Set(candidateIndex.groups.map(({ groupId }) => groupId)).size,
    26,
  );
  assert.deepEqual(
    candidateIndex.externalBlockers.map(({ groupId }) => groupId),
    ["P1-B11"],
  );
  assert.equal(
    candidateIndex.groups.find(({ groupId }) => groupId === "P1-B11")
      .classification,
    "PARTIAL_EXTERNAL_EVIDENCE_PENDING",
  );
  for (const groupId of Object.keys(protectedGroups)) {
    assert.equal(
      candidateIndex.groups.find(({ groupId: id }) => id === groupId)
        .classification,
      "GIT_FROZEN_AFTER_REMEDIATION",
    );
  }

  const candidateBytes = await readFile(
    new URL(candidateIndexPath, import.meta.url),
  );
  assert.equal(
    sha256(candidateBytes),
    "sha256:f3c9802853856420efb8d01bc0d2509becc8ba3f0176b07f593b1598af015850",
  );
  const finalIndex = await loadFinalIndex();
  await assertFinalIndex(finalIndex);
  const finalBytes = await readFile(new URL(finalIndexPath, import.meta.url));
  assert.equal(finalBytes.byteLength, 19476);
  assert.equal(sha256(finalBytes), finalIndexRawSha256);
  await assertV3Index(v3Index);
  assert.deepEqual(v3Index.classificationSummary, {
    GIT_FROZEN_PASS: 14,
    GIT_FROZEN_AFTER_REMEDIATION: 11,
    EXISTING_EVIDENCE_REUSED: 1,
    PARTIAL_EXTERNAL_EVIDENCE_PENDING: 0,
    BLOCKED_EXTERNAL_READ: 0,
    groupCount: 26,
    criterionCount: 29,
  });
  const v3Bytes = await readFile(new URL(v3IndexPath, import.meta.url));
  assert.equal(v3Bytes.byteLength, v3IndexByteLength);
  assert.equal(sha256(v3Bytes), v3IndexRawSha256);
});

test("the three P0 closures resolve to exact frozen Git bytes", async () => {
  const finalIndex = await loadFinalIndex();
  for (const [groupId, expected] of Object.entries(protectedGroups)) {
    for (const currentIndex of [candidateIndex, finalIndex]) {
      const group = currentIndex.groups.find(
        ({ groupId: id }) => id === groupId,
      );
      assert.deepEqual(
        {
          sourceCommit: group.sourceCommit,
          evidenceFreezeCommit: group.evidenceFreezeCommit,
          path: group.evidence.path,
          sha256: group.evidence.sha256,
        },
        {
          sourceCommit: expected.sourceCommit,
          evidenceFreezeCommit: expected.evidenceFreezeCommit,
          path: expected.path,
          sha256: expected.sha256,
        },
      );
    }
    git([
      "merge-base",
      "--is-ancestor",
      expected.sourceCommit,
      expected.evidenceFreezeCommit,
    ]);
    const treeEntry = git([
      "ls-tree",
      "-z",
      "-l",
      expected.evidenceFreezeCommit,
      "--",
      expected.path,
    ]).toString("utf8");
    const [metadata, treePath] = treeEntry.slice(0, -1).split("\t");
    const [mode, objectType, , byteLength] = metadata.split(/\s+/);
    assert.equal(mode, expected.gitMode, groupId);
    assert.equal(objectType, "blob", groupId);
    assert.equal(Number(byteLength), expected.byteLength, groupId);
    assert.equal(treePath, expected.path, groupId);
    const bytes = git([
      "-c",
      "diff.external=",
      "-c",
      "diff.trustExitCode=false",
      "-c",
      "core.attributesFile=/dev/null",
      "show",
      `${expected.evidenceFreezeCommit}:${expected.path}`,
    ]);
    assert.equal(bytes.byteLength, expected.byteLength, groupId);
    assert.equal(sha256(bytes), expected.sha256, groupId);
    const currentBytes = await readFile(
      new URL(`../${expected.path}`, import.meta.url),
    );
    assert.equal(currentBytes.byteLength, expected.byteLength, groupId);
    assert.equal(sha256(currentBytes), expected.sha256, groupId);
  }

  const p1B11Group = v3Index.groups.find(
    ({ groupId }) => groupId === "P1-B11",
  );
  assert.deepEqual(p1B11Group, {
    groupId: "P1-B11",
    criteria: ["C13-AC02"],
    classification: "GIT_FROZEN_AFTER_REMEDIATION",
    sourceCommit: p1B11Closure.sourceCommit,
    evidenceFreezeCommit: p1B11Closure.evidenceFreezeCommit,
    evidence: {
      path: p1B11Closure.path,
      sha256: p1B11Closure.sha256,
    },
    limitation: p1B11Closure.limitation,
  });
  git([
    "merge-base",
    "--is-ancestor",
    p1B11Closure.sourceCommit,
    p1B11Closure.evidenceFreezeCommit,
  ]);
  const treeEntry = git([
    "ls-tree",
    "-z",
    "-l",
    p1B11Closure.evidenceFreezeCommit,
    "--",
    p1B11Closure.path,
  ]).toString("utf8");
  const [metadata, treePath] = treeEntry.slice(0, -1).split("\t");
  const [mode, objectType, , byteLength] = metadata.split(/\s+/);
  assert.equal(mode, p1B11Closure.gitMode);
  assert.equal(objectType, "blob");
  assert.equal(Number(byteLength), p1B11Closure.byteLength);
  assert.equal(treePath, p1B11Closure.path);
  const frozenEvidenceBytes = git([
    "-c",
    "diff.external=",
    "-c",
    "diff.trustExitCode=false",
    "-c",
    "core.attributesFile=/dev/null",
    "show",
    `${p1B11Closure.evidenceFreezeCommit}:${p1B11Closure.path}`,
  ]);
  assert.equal(frozenEvidenceBytes.byteLength, p1B11Closure.byteLength);
  assert.equal(sha256(frozenEvidenceBytes), p1B11Closure.sha256);
  const currentEvidenceBytes = await readFile(
    new URL(`../${p1B11Closure.path}`, import.meta.url),
  );
  assert.equal(currentEvidenceBytes.byteLength, p1B11Closure.byteLength);
  assert.equal(sha256(currentEvidenceBytes), p1B11Closure.sha256);
});

test("the candidate is self-hashed and tampering fails closed", async () => {
  const declared = candidateIndex.indexCanonicalSha256;
  const subject = structuredClone(candidateIndex);
  delete subject.indexCanonicalSha256;
  assert.equal(await sha256ProjectValue(subject), declared);

  subject.externalBlockers = [];
  assert.notEqual(await sha256ProjectValue(subject), declared);

  const finalIndex = await loadFinalIndex();
  await assertFinalIndex(finalIndex);
  for (const groupId of Object.keys(protectedGroups)) {
    const missingClosure = structuredClone(finalIndex);
    missingClosure.groups = missingClosure.groups.filter(
      ({ groupId: id }) => id !== groupId,
    );
    await assert.rejects(
      assertFinalIndex(await withRecomputedSelfHash(missingClosure)),
    );
  }

  const duplicateGroup = structuredClone(finalIndex);
  duplicateGroup.groups.push(structuredClone(duplicateGroup.groups[0]));
  await assert.rejects(
    assertFinalIndex(await withRecomputedSelfHash(duplicateGroup)),
  );

  const closedP1B11 = structuredClone(finalIndex);
  closedP1B11.groups.find(
    ({ groupId }) => groupId === "P1-B11",
  ).classification = "GIT_FROZEN_AFTER_REMEDIATION";
  closedP1B11.externalBlockers = [];
  closedP1B11.remainingProfileApprovalHardBlockers = [];
  await assert.rejects(
    assertFinalIndex(await withRecomputedSelfHash(closedP1B11)),
  );

  const extraBlocker = structuredClone(finalIndex);
  extraBlocker.externalBlockers.push({
    groupId: "P0-B11",
    kind: "FORGED_BLOCKER",
    reason: "forged",
  });
  await assert.rejects(
    assertFinalIndex(await withRecomputedSelfHash(extraBlocker)),
  );

  await assertV3Index(v3Index);
  const v3Mutations = [
    (value) => value.groups.splice(0, 1),
    (value) => value.groups.push(structuredClone(value.groups[0])),
    (value) => value.groups.splice(0, 2, value.groups[1], value.groups[0]),
    (value) => {
      value.groups[0].limitation = "tampered";
    },
    (value) => {
      value.groups[21].classification = "GIT_FROZEN_PASS";
    },
    (value) => {
      value.groups[21].sourceCommit = "0".repeat(40);
    },
    (value) => {
      value.groups[21].evidenceFreezeCommit = "0".repeat(40);
    },
    (value) => {
      value.groups[21].evidence.path = "implementation/p1/c13/forged.json";
    },
    (value) => {
      value.groups[21].evidence.sha256 = `sha256:${"0".repeat(64)}`;
    },
    (value) => {
      value.groups[21].limitation = "tampered";
    },
    (value) => {
      value.classificationSummary.GIT_FROZEN_AFTER_REMEDIATION = 10;
    },
    (value) => value.externalBlockers.push({ groupId: "P1-B11" }),
    (value) => value.remainingProfileApprovalHardBlockers.push("P1-B11"),
    (value) => {
      value.governanceEffect = "PROFILE_APPROVED";
    },
    (value) => {
      value.profileReadinessEffect = "PROFILE_READINESS_TRUE";
    },
    (value) => {
      value.governanceDisclaimer.d1LedgerChanged = true;
    },
    (value) => {
      value.governanceDisclaimer.gateDecisionChanged = true;
    },
    (value) => {
      value.governanceDisclaimer.profileApproved = true;
    },
    (value) => {
      value.governanceDisclaimer.startAuthorized = true;
    },
    (value) => {
      value.supersedes.rawSha256 = `sha256:${"0".repeat(64)}`;
    },
  ];
  for (const mutate of v3Mutations) {
    const tampered = structuredClone(v3Index);
    mutate(tampered);
    await assert.rejects(
      assertV3Index(await withRecomputedSelfHash(tampered)),
    );
  }

  const forgedSelfHash = structuredClone(v3Index);
  forgedSelfHash.indexCanonicalSha256 = `sha256:${"0".repeat(64)}`;
  await assert.rejects(assertV3Index(forgedSelfHash));
});

test("v1 remains byte-identical while the final Profile runtime binds v3 without granting governance authority", async () => {
  const v1Path =
    "../implementation/governance/v5.3-supplemental-evidence-index.v1.json";
  const v1Bytes = await readFile(new URL(v1Path, import.meta.url));
  assert.equal(
    sha256(v1Bytes),
    "sha256:692c4b3927da1f8be6f9d59ae5e225389f40bb0e7ed9b4fc722466ff7003aec0",
  );

  const candidateProfile = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(
    candidateProfile.baselineRefs.supplementalEvidenceIndex.path,
    "implementation/governance/v5.3-supplemental-evidence-index.v1.json",
  );
  assert.equal(
    candidateProfile.baselineRefs.supplementalEvidenceIndex.sha256,
    "sha256:692c4b3927da1f8be6f9d59ae5e225389f40bb0e7ed9b4fc722466ff7003aec0",
  );
  const activeProfile = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p2/acceptance/p2-acceptance-profile.v2.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(
    activeProfile.baselineRefs.supplementalEvidenceIndex.path,
    "implementation/governance/v5.3-supplemental-evidence-index.v3.json",
  );
  assert.equal(
    activeProfile.baselineRefs.supplementalEvidenceIndex.sha256,
    "sha256:acade5a2d5c0c0a46c6f29e25541c30614cea95199458ca162ac1b8d7fcdc884",
  );
  assert.equal(
    candidateIndex.profileReadinessEffect,
    "NONE_P1_B11_STILL_OPEN",
  );
  const finalIndex = await loadFinalIndex();
  assert.equal(finalIndex.profileReadinessEffect, "NONE_P1_B11_STILL_OPEN");
  assert.equal(
    P2_V2_CANDIDATE_PROFILE_READINESS_POLICY
      .supplementalEvidenceIndexSha256,
    "sha256:acade5a2d5c0c0a46c6f29e25541c30614cea95199458ca162ac1b8d7fcdc884",
  );
  assert.equal(
    v3Index.profileReadinessEffect,
    "NONE_ACTIVE_PROFILE_REMAINS_BOUND_TO_V1",
  );
  assert.equal(v3Index.governanceEffect, "NONE");
  assert.deepEqual(v3Index.externalBlockers, []);
  assert.deepEqual(v3Index.remainingProfileApprovalHardBlockers, []);
  assert.equal(
    await verifyP2ProfileReadinessFromFrozenEvidence({
      profileSha256:
        P2_V2_CANDIDATE_PROFILE_READINESS_POLICY.profileSha256,
      supplementalEvidenceIndexSha256:
        P2_V2_CANDIDATE_PROFILE_READINESS_POLICY
          .supplementalEvidenceIndexSha256,
      sourceCommit:
        P2_V2_CANDIDATE_PROFILE_READINESS_POLICY.sourceCommit,
      executionBaselineDigest:
        P2_V2_CANDIDATE_PROFILE_READINESS_POLICY
          .executionBaselineDigest,
    }),
    true,
  );
});
