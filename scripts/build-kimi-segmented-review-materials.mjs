#!/usr/bin/env node

import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { promisify } from "node:util";
import {
  buildKimiSegmentReviewMaterials,
  classifyKimiSegmentReviewPath,
  createKimiSegmentReviewPlan,
  segmentedKimiReviewDigests,
} from "../lib/kimi-segmented-independent-review.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const ALLOWED_GIT_MODES = new Set(["100644", "100755"]);
const SEGMENT_IDS = [
  "GOVERNANCE_LINEAGE",
  "SCHEMAS_WIRE_CONTRACTS",
  "RUNTIME_ORCHESTRATION",
  "TESTS_VERIFICATION",
];
const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
});

async function git(repoPath, args, encoding = "buffer") {
  return execFileAsync(
    "/usr/bin/git",
    ["--no-replace-objects", "-C", repoPath, ...args],
    {
      encoding,
      env: gitEnvironment,
      maxBuffer: 64 * 1024 * 1024,
    },
  );
}

async function requireCommit(repoPath, commit, label) {
  if (!COMMIT.test(commit)) {
    throw new TypeError(`${label} must be an exact commit.`);
  }
  const { stdout } = await git(repoPath, ["cat-file", "-t", commit], "utf8");
  if (stdout.trim() !== "commit") {
    throw new TypeError(`${label} is not a commit object.`);
  }
}

async function commitBytes(repoPath, sourceCommit, path) {
  if (!SAFE_PATH.test(path)) {
    throw new TypeError("Frozen Git path is unsafe.");
  }
  const { stdout } = await git(repoPath, [
    "cat-file",
    "blob",
    `${sourceCommit}:${path}`,
  ]);
  return Buffer.from(stdout);
}

async function treeSubject(repoPath, sourceCommit, path) {
  const { stdout } = await git(
    repoPath,
    ["ls-tree", "-z", sourceCommit, "--", path],
    "utf8",
  );
  const match = /^(100644|100755|120000|160000) (blob|commit) [a-f0-9]{40}\t([^\0]+)\0$/u.exec(
    stdout,
  );
  if (
    !match ||
    match[2] !== "blob" ||
    match[3] !== path ||
    !ALLOWED_GIT_MODES.has(match[1])
  ) {
    throw new TypeError(`Frozen Git subject is unsafe: ${path}`);
  }
  const bytes = await commitBytes(repoPath, sourceCommit, path);
  return {
    path,
    gitMode: match[1],
    blobSha256: segmentedKimiReviewDigests.bytes(bytes),
    byteLength: bytes.byteLength,
  };
}

async function changedPaths(repoPath, baseCommit, sourceCommit) {
  const { stdout } = await git(repoPath, [
    "diff-tree",
    "--no-commit-id",
    "--name-only",
    "--no-renames",
    "-r",
    "-z",
    baseCommit,
    sourceCommit,
  ]);
  const paths = Buffer.from(stdout)
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .sort((left, right) => left.localeCompare(right));
  if (
    paths.length === 0 ||
    paths.length !== new Set(paths).size ||
    paths.some((path) => !SAFE_PATH.test(path))
  ) {
    throw new TypeError("Frozen changed paths are empty, duplicated, or unsafe.");
  }
  return paths;
}

export async function collectKimiSegmentedReviewInventoryFromGit({
  repoPath,
  baseCommit,
  sourceCommit,
}) {
  const exactRepoPath = resolve(repoPath);
  await requireCommit(exactRepoPath, baseCommit, "baseCommit");
  await requireCommit(exactRepoPath, sourceCommit, "sourceCommit");
  try {
    await git(exactRepoPath, [
      "merge-base",
      "--is-ancestor",
      baseCommit,
      sourceCommit,
    ]);
  } catch {
    throw new TypeError("baseCommit must be an ancestor of sourceCommit.");
  }
  const [{ stdout: treeText }, reviewedPaths, { stdout: patchOutput }] =
    await Promise.all([
      git(exactRepoPath, ["rev-parse", `${sourceCommit}^{tree}`], "utf8"),
      changedPaths(exactRepoPath, baseCommit, sourceCommit),
      git(exactRepoPath, [
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        baseCommit,
        sourceCommit,
        "--",
      ]),
    ]);
  const fullSubjects = await Promise.all(
    reviewedPaths.map((path) => treeSubject(exactRepoPath, sourceCommit, path)),
  );
  const sourceSubjects = fullSubjects.map(
    ({ path, gitMode, blobSha256 }) => ({ path, gitMode, blobSha256 }),
  );
  const segmentPathCounts = Object.fromEntries(
    SEGMENT_IDS.map((segmentId) => [segmentId, 0]),
  );
  const segmentUtf8ByteLengths = Object.fromEntries(
    SEGMENT_IDS.map((segmentId) => [segmentId, 0]),
  );
  for (const subject of fullSubjects) {
    const segmentId = classifyKimiSegmentReviewPath(subject.path);
    segmentPathCounts[segmentId] += 1;
    segmentUtf8ByteLengths[segmentId] += subject.byteLength;
  }
  const patchBytes = Buffer.from(patchOutput);
  return {
    source: {
      baseCommit,
      sourceCommit,
      headCommit: sourceCommit,
      tree: treeText.trim(),
      diffSha256: segmentedKimiReviewDigests.bytes(patchBytes),
      changedPathsDigest: segmentedKimiReviewDigests.value(reviewedPaths),
    },
    reviewedPaths,
    sourceSubjects,
    segmentPathCounts,
    segmentUtf8ByteLengths,
    patchByteLength: patchBytes.byteLength,
    patchSha256: segmentedKimiReviewDigests.bytes(patchBytes),
    networkCalls: 0,
  };
}

export async function buildKimiSegmentedContentMaterialsFromGit({
  repoPath,
  planId,
  bundle,
  bundleBytes,
  bindings,
  commonSections,
  integrationSections,
}) {
  const inventory = await collectKimiSegmentedReviewInventoryFromGit({
    repoPath,
    baseCommit: bundle?.source?.baseCommit,
    sourceCommit: bundle?.source?.sourceCommit,
  });
  if (
    segmentedKimiReviewDigests.canonicalize(inventory.source) !==
      segmentedKimiReviewDigests.canonicalize(bundle?.source) ||
    segmentedKimiReviewDigests.canonicalize(inventory.reviewedPaths) !==
      segmentedKimiReviewDigests.canonicalize(bundle?.reviewedPaths) ||
    segmentedKimiReviewDigests.canonicalize(inventory.sourceSubjects) !==
      segmentedKimiReviewDigests.canonicalize(bundle?.sourceSubjects)
  ) {
    throw new TypeError("Frozen Bundle does not match the Git object inventory.");
  }
  const exactRepoPath = resolve(repoPath);
  const sourceBytesResolver = (path) =>
    commitBytes(exactRepoPath, inventory.source.sourceCommit, path);
  const commonBytesResolver = (path) =>
    path === bindings.reviewBundle.path
      ? Buffer.from(bundleBytes)
      : commitBytes(exactRepoPath, inventory.source.sourceCommit, path);
  const plan = await createKimiSegmentReviewPlan({
    planId,
    bundle,
    bundleBytes: Buffer.from(bundleBytes),
    bindings,
    commonSections,
    integrationSections,
    sourceBytesResolver,
  });
  const materials = await buildKimiSegmentReviewMaterials({
    plan,
    bundle,
    bundleBytes: Buffer.from(bundleBytes),
    sourceBytesResolver,
    commonBytesResolver,
  });
  return { inventory, plan, materials, networkCalls: 0 };
}
