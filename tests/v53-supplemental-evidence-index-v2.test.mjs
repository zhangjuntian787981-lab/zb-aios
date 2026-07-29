import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const root = new URL("../", import.meta.url);
const repositoryRoot = fileURLToPath(root);
const indexPath =
  "../implementation/governance/v5.3-supplemental-evidence-index.v2.candidate.json";
const index = JSON.parse(
  await readFile(new URL(indexPath, import.meta.url), "utf8"),
);

const protectedGroups = Object.freeze({
  "P0-B04": {
    sourceCommit: "862adfd58c8ead48f4a18d84a72cdbc28c89bc5c",
    evidenceFreezeCommit:
      "96ccc8fd375cf895285c42971b76863184b320b0",
    path:
      "implementation/p0/f02/f02-hosted-ci-supplemental-evidence.v1.json",
    sha256:
      "sha256:5df82bdad73e2b9a55710a4c5e04662d38f8045b83089ed51b5e19a92bd2a0ac",
  },
  "P0-B07": {
    sourceCommit: "807172852044d4c86480f05845b358e5ed394e9e",
    evidenceFreezeCommit:
      "5d12201e984937a905ab8bae90a86a4b1763d899",
    path:
      "implementation/p0/f03/f03-hosted-ci-supplemental-evidence.v1.json",
    sha256:
      "sha256:e9c0f323f9e58f77e74fc0b433595c790c5477ce6a2b47f15d8f644649c5a413",
  },
  "P0-B11": {
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

test("v2 candidate closes only the three newly frozen P0 supplements", () => {
  assert.equal(
    index.schemaVersion,
    "v5.3-supplemental-evidence-index.v2.candidate",
  );
  assert.equal(index.recordType, "STATIC_SUPPLEMENTAL_EVIDENCE_INDEX");
  assert.equal(index.artifactLifecycle, "GIT_FROZEN_CANDIDATE");
  assert.equal(index.isProgressTracker, false);
  assert.equal(index.selfAuthorizing, false);
  assert.equal(
    index.governanceDisclaimer.isWorkPackageOrGateStatusAuthority,
    false,
  );
  assert.equal(index.governanceDisclaimer.d1LedgerChanged, false);
  assert.equal(index.governanceDisclaimer.profileApproved, false);
  assert.equal(index.governanceDisclaimer.startAuthorized, false);
  assert.equal(index.groups.length, 26);
  assert.equal(
    new Set(index.groups.map(({ groupId }) => groupId)).size,
    26,
  );
  assert.deepEqual(
    index.externalBlockers.map(({ groupId }) => groupId),
    ["P1-B11"],
  );
  assert.equal(
    index.groups.find(({ groupId }) => groupId === "P1-B11")
      .classification,
    "PARTIAL_EXTERNAL_EVIDENCE_PENDING",
  );
  for (const groupId of Object.keys(protectedGroups)) {
    assert.equal(
      index.groups.find(({ groupId: id }) => id === groupId)
        .classification,
      "GIT_FROZEN_AFTER_REMEDIATION",
    );
  }
});

test("the three P0 closures resolve to exact frozen Git bytes", () => {
  for (const [groupId, expected] of Object.entries(protectedGroups)) {
    const group = index.groups.find(({ groupId: id }) => id === groupId);
    assert.deepEqual(
      {
        sourceCommit: group.sourceCommit,
        evidenceFreezeCommit: group.evidenceFreezeCommit,
        path: group.evidence.path,
        sha256: group.evidence.sha256,
      },
      expected,
    );
    git([
      "merge-base",
      "--is-ancestor",
      expected.sourceCommit,
      expected.evidenceFreezeCommit,
    ]);
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
    assert.equal(sha256(bytes), expected.sha256, groupId);
  }
});

test("the candidate is self-hashed and tampering fails closed", async () => {
  const declared = index.indexCanonicalSha256;
  const subject = structuredClone(index);
  delete subject.indexCanonicalSha256;
  assert.equal(await sha256ProjectValue(subject), declared);

  subject.externalBlockers = [];
  assert.notEqual(await sha256ProjectValue(subject), declared);
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
  assert.equal(index.profileReadinessEffect, "NONE_P1_B11_STILL_OPEN");
});
