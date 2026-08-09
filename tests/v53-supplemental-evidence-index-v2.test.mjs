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
const finalIndexCanonicalSha256 =
  "sha256:fc70d17b9004b87ce418b5498bf3c3330c819532552a6153c3f29ccd37bc2fcd";
const finalIndexRawSha256 =
  "sha256:6327632b416687987e49fa207f1c4562647cb1298f276490822c85850ea8c05a";
const candidateIndex = JSON.parse(
  await readFile(new URL(candidateIndexPath, import.meta.url), "utf8"),
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
});

test("v1 remains byte-identical and the runtime still rejects the candidate", async () => {
  const v1Path =
    "../implementation/governance/v5.3-supplemental-evidence-index.v1.json";
  const v1Bytes = await readFile(new URL(v1Path, import.meta.url));
  assert.equal(
    sha256(v1Bytes),
    "sha256:692c4b3927da1f8be6f9d59ae5e225389f40bb0e7ed9b4fc722466ff7003aec0",
  );

  const profile = JSON.parse(
    await readFile(
      new URL(
        "../implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  assert.equal(
    profile.baselineRefs.supplementalEvidenceIndex.path,
    "implementation/governance/v5.3-supplemental-evidence-index.v1.json",
  );
  assert.equal(
    profile.baselineRefs.supplementalEvidenceIndex.sha256,
    "sha256:692c4b3927da1f8be6f9d59ae5e225389f40bb0e7ed9b4fc722466ff7003aec0",
  );
  assert.equal(
    candidateIndex.profileReadinessEffect,
    "NONE_P1_B11_STILL_OPEN",
  );
  const finalIndex = await loadFinalIndex();
  assert.equal(finalIndex.profileReadinessEffect, "NONE_P1_B11_STILL_OPEN");
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
    false,
  );
});
