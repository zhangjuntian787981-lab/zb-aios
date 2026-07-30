#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  buildKimiIndependentReviewRequest,
  createKimiIndependentModelReviewReceipt,
  executeKimiIndependentReview,
  independentKimiReviewDigests,
  kimiIndependentReviewMaterialGovernancePaths,
  validateKimiIndependentModelReviewReceipt,
} from "../lib/kimi-independent-review.mjs";
import {
  independentModelReviewFixedSpecificationPaths,
  parseIndependentReviewJsonBytes,
  validateIndependentReviewBundle,
  validateIndependentReviewPolicy,
  validateIndependentReviewTestEvidenceClosure,
} from "../lib/independent-model-review.mjs";
import {
  captureIndependentReviewRuntimeBinding,
} from "../lib/independent-review-runtime-binding.mjs";
import {
  assertIndependentReviewBootstrapEnvironment,
  captureIndependentReviewRuntimeDependencyManifest,
  validateIndependentReviewRuntimeDependencyManifest,
} from "../lib/independent-review-runtime-manifest.mjs";
import {
  buildIndependentReviewBundleFromGit,
  createTrustedGitDiffCheck,
} from "./build-independent-review-bundle.mjs";
import { buildIndependentReviewMaterialFromGit } from "./build-independent-review-material.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const FIXED_PATHS = Object.freeze({
  policy:
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  config:
    "implementation/governance/independent-review/moonshot-kimi-k2.7-code.v1.json",
  prompt:
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  outputSchema:
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json",
  runtimeManifest:
    "implementation/governance/independent-review/kimi-runtime-manifest.v1.json",
  testPlan:
    "implementation/governance/independent-review/independent-review-test-plan.v2.json",
  testEvidenceCollector:
    "scripts/run-independent-review-test-evidence.mjs",
  testResultSchema:
    "implementation/governance/schemas/independent-review-test-result.v3.schema.json",
  sandboxPolicyTemplate:
    "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in",
});
const EXECUTING_PATHS = Object.freeze([
  "lib/p2-start-authorization.mjs",
  "lib/project-control.mjs",
  "lib/independent-model-review.mjs",
  "lib/independent-review-runtime-binding.mjs",
  "lib/kimi-independent-review.mjs",
  "package-lock.json",
  "scripts/build-independent-review-bundle.mjs",
  "scripts/build-independent-review-material.mjs",
  "scripts/bootstrap-kimi-independent-review.mjs",
  "scripts/launch-kimi-independent-review.sh",
  "scripts/run-independent-review-test-evidence.mjs",
  "scripts/run-kimi-independent-review.mjs",
]);
const moduleRoot = resolve(new URL("../", import.meta.url).pathname);
const fixedFetch = globalThis.fetch.bind(globalThis);
const KEYCHAIN_SERVICE = "kimi-p2-independent-review";
const IGNORED_WORKTREE_EXCLUSIONS = Object.freeze([
  {
    pathPrefix: "node_modules/",
    binding: "RUNTIME_DEPENDENCY_MANIFEST",
  },
  { pathPrefix: ".next/", binding: "EPHEMERAL_BUILD_OUTPUT" },
  { pathPrefix: ".vinext/", binding: "EPHEMERAL_BUILD_OUTPUT" },
  { pathPrefix: ".wrangler/", binding: "EPHEMERAL_BUILD_OUTPUT" },
  { pathPrefix: "dist/", binding: "EPHEMERAL_BUILD_OUTPUT" },
  {
    pathPrefix: "outputs/",
    binding: "NON_RUNTIME_IGNORED_ARTIFACT_ROOT",
  },
  {
    pathPrefix: "work/",
    binding: "NON_RUNTIME_IGNORED_ARTIFACT_ROOT",
  },
  { pathSuffix: "/.DS_Store", binding: "NON_EXECUTABLE_OS_METADATA" },
  { exactPath: ".DS_Store", binding: "NON_EXECUTABLE_OS_METADATA" },
]);
const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
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

async function commitBytes(repoPath, sourceCommit, path) {
  if (!COMMIT.test(sourceCommit) || !SAFE_PATH.test(path)) {
    throw new TypeError("Kimi review frozen Git binding is invalid.");
  }
  const { stdout } = await git(repoPath, [
    "cat-file",
    "blob",
    `${sourceCommit}:${path}`,
  ]);
  return Buffer.from(stdout);
}

async function requireCommit(repoPath, commit, label) {
  if (!COMMIT.test(commit ?? "")) {
    throw new TypeError(`${label} is not an exact Git commit.`);
  }
  const { stdout } = await git(
    repoPath,
    ["cat-file", "-t", commit],
    "utf8",
  );
  if (stdout.trim() !== "commit") {
    throw new TypeError(`${label} is not a Git commit.`);
  }
}

async function exactChangedPaths(repoPath, baseCommit, sourceCommit) {
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
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
  } catch {
    throw new TypeError("Kimi review Git scope is not valid UTF-8.");
  }
  const paths = decoded.split("\0").filter(Boolean).sort();
  if (
    paths.length === 0 ||
    new Set(paths).size !== paths.length ||
    paths.some((path) => !SAFE_PATH.test(path))
  ) {
    throw new TypeError("Kimi review Git scope is invalid.");
  }
  return paths;
}

async function sourceSubject(repoPath, sourceCommit, path) {
  const { stdout } = await git(
    repoPath,
    ["ls-tree", "-z", sourceCommit, "--", path],
    "utf8",
  );
  const value = stdout.replace(/\0$/u, "");
  const match =
    /^(100644|100755|120000|160000) (?:blob|commit) [a-f0-9]{40}\t(.+)$/u.exec(
      value,
    );
  if (!match || match[2] !== path) {
    throw new TypeError("Kimi review Git source subject is missing.");
  }
  const bytes = await commitBytes(repoPath, sourceCommit, path);
  return {
    path,
    gitMode: match[1],
    blobSha256: independentKimiReviewDigests.bytes(bytes),
  };
}

export async function verifyKimiReviewBundleGitBindings({
  repoPath,
  bundle,
}) {
  const exactRepoPath = await realpath(resolve(repoPath));
  const baseCommit = bundle?.source?.baseCommit;
  const sourceCommit = bundle?.source?.sourceCommit;
  await requireCommit(exactRepoPath, baseCommit, "Review Bundle baseCommit");
  await requireCommit(
    exactRepoPath,
    sourceCommit,
    "Review Bundle sourceCommit",
  );
  try {
    await git(exactRepoPath, [
      "merge-base",
      "--is-ancestor",
      baseCommit,
      sourceCommit,
    ]);
  } catch {
    throw new TypeError(
      "Review Bundle baseCommit is not an ancestor of sourceCommit.",
    );
  }
  const [
    { stdout: treeText },
    { stdout: patchValue },
    changedPaths,
  ] = await Promise.all([
    git(exactRepoPath, ["rev-parse", `${sourceCommit}^{tree}`], "utf8"),
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
    exactChangedPaths(exactRepoPath, baseCommit, sourceCommit),
  ]);
  const patchBytes = Buffer.from(patchValue);
  const gitDiffCheck = await createTrustedGitDiffCheck({
    repoPath: exactRepoPath,
    baseCommit,
    sourceCommit,
    sourceTree: treeText.trim(),
    patchBytes,
    runnerGitBlobSha256:
      bundle?.artifacts?.bundleGeneratorSha256,
    runnerExecutedBytesSha256:
      bundle?.artifacts?.bundleGeneratorSha256,
  });
  if (
    bundle.source.headCommit !== sourceCommit ||
    treeText.trim() !== bundle.source.tree ||
    independentKimiReviewDigests.bytes(patchBytes) !==
      bundle.source.diffSha256 ||
    JSON.stringify(changedPaths) !==
      JSON.stringify(bundle.reviewedPaths) ||
    independentKimiReviewDigests.value(changedPaths) !==
      bundle.source.changedPathsDigest ||
    JSON.stringify(gitDiffCheck) !==
      JSON.stringify(bundle.source.gitDiffCheck)
  ) {
    throw new TypeError("Review Bundle does not match the real Git patch.");
  }
  const actualSources = await Promise.all(
    changedPaths.map((path) =>
      sourceSubject(exactRepoPath, sourceCommit, path),
    ),
  );
  if (
    JSON.stringify(actualSources) !== JSON.stringify(bundle.sourceSubjects)
  ) {
    throw new TypeError("Review Bundle source scope does not match Git.");
  }
  if (
    JSON.stringify(
      bundle.specificationSubjects?.map(({ path }) => path),
    ) !== JSON.stringify(independentModelReviewFixedSpecificationPaths)
  ) {
    throw new TypeError(
      "Review Bundle specification scope does not match Git.",
    );
  }
  for (const subject of bundle.specificationSubjects ?? []) {
    const bytes = await commitBytes(
      exactRepoPath,
      sourceCommit,
      subject.path,
    );
    if (
      independentKimiReviewDigests.bytes(bytes) !== subject.blobSha256
    ) {
      throw new TypeError(
        "Review Bundle specification does not match Git.",
      );
    }
  }
  return true;
}

function bundleWithoutRuntimeEvidence(bundle) {
  const copy = structuredClone(bundle);
  delete copy.testEvidenceSubjects;
  delete copy.bundleSha256;
  return copy;
}

async function buildTrustedKimiReviewInputs({
  repoPath,
  submittedBundle,
  materialId,
}) {
  const evidenceRoot = await mkdtemp(
    join(tmpdir(), "zb-kimi-trusted-test-evidence-"),
  );
  try {
    const bundle = await buildIndependentReviewBundleFromGit({
      repoPath,
      baseCommit: submittedBundle.source.baseCommit,
      sourceCommit: submittedBundle.source.sourceCommit,
      generatedAt: submittedBundle.generatedAt,
      bundleId: submittedBundle.bundleId,
      applicablePhase: submittedBundle.applicablePhase,
      testEvidenceRoot: evidenceRoot,
    });
    if (
      JSON.stringify(bundleWithoutRuntimeEvidence(bundle)) !==
      JSON.stringify(bundleWithoutRuntimeEvidence(submittedBundle))
    ) {
      throw new TypeError(
        "Submitted Review Bundle static scope differs from trusted rebuild.",
      );
    }
    const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
    const { material, materialBytes } =
      await buildIndependentReviewMaterialFromGit({
        repoPath,
        reviewBundleBytes,
        testEvidenceRoot: evidenceRoot,
        materialId,
      });
    return {
      bundle,
      reviewBundleBytes,
      material,
      materialBytes,
      evidenceRoot,
    };
  } catch (error) {
    await rm(evidenceRoot, { recursive: true, force: true });
    throw error;
  }
}

async function evidenceResolverForRoot(testEvidenceRoot) {
  const exactRoot = await realpath(resolve(testEvidenceRoot));
  if (!(await stat(exactRoot)).isDirectory()) {
    throw new TypeError("Kimi review test evidence root is invalid.");
  }
  return async (ref) => {
    if (!SAFE_PATH.test(ref)) {
      throw new TypeError("Kimi review test evidence reference is unsafe.");
    }
    const exactPath = await realpath(resolve(exactRoot, ref));
    if (
      exactPath !== exactRoot &&
      !exactPath.startsWith(`${exactRoot}${sep}`)
    ) {
      throw new TypeError(
        "Kimi review test evidence reference escapes its root.",
      );
    }
    if (!(await stat(exactPath)).isFile()) {
      throw new TypeError("Kimi review test evidence is not a file.");
    }
    return readFile(exactPath);
  };
}

async function trustedEvidenceArtifacts(bundle, evidenceRoot) {
  const resolver = await evidenceResolverForRoot(evidenceRoot);
  const artifacts = {};
  for (const subject of bundle.testEvidenceSubjects) {
    const resultBytes = await resolver(subject.outputRef);
    const result = parseIndependentReviewJsonBytes(
      resultBytes,
      "Kimi trusted test evidence",
      1024 * 1024,
    );
    for (const ref of [
      subject.outputRef,
      result.stdoutRef,
      result.stderrRef,
      result.runtimeBinding.artifactRef,
    ]) {
      artifacts[`test-evidence/${ref}`] = await resolver(ref);
    }
  }
  return artifacts;
}

async function verifyExecutingBytes(repoPath, sourceCommit) {
  for (const path of EXECUTING_PATHS) {
    const [currentBytes, frozenBytes] = await Promise.all([
      readFile(resolve(moduleRoot, path)),
      commitBytes(repoPath, sourceCommit, path),
    ]);
    if (
      independentKimiReviewDigests.bytes(currentBytes) !==
      independentKimiReviewDigests.bytes(frozenBytes)
    ) {
      throw new TypeError(
        `Running Kimi review component is not frozen: ${path}`,
      );
    }
  }
}

function hashStatus(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

async function worktreeContentManifest(repoPath) {
  const { stdout } = await git(repoPath, [
    "ls-files",
    "-z",
    "--cached",
    "--others",
    "--exclude-standard",
  ]);
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
  } catch {
    throw new TypeError("Repository worktree paths are not valid UTF-8.");
  }
  const paths = decoded.split("\0").filter(Boolean);
  paths.sort((left, right) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (
    new Set(paths).size !== paths.length ||
    paths.some((path) => !SAFE_PATH.test(path))
  ) {
    throw new TypeError(
      "Repository worktree paths are unsafe or duplicated.",
    );
  }
  const descriptors = [];
  for (const path of paths) {
    const target = resolve(repoPath, path);
    if (!target.startsWith(`${repoPath}${sep}`)) {
      throw new TypeError("Repository worktree path escapes the repository.");
    }
    try {
      const metadata = await lstat(target);
      if (metadata.isFile()) {
        const bytes = await readFile(target);
        descriptors.push({
          path,
          type: "FILE",
          mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
          byteLength: bytes.byteLength,
          sha256: independentKimiReviewDigests.bytes(bytes),
        });
      } else if (metadata.isSymbolicLink()) {
        const bytes = await readlink(target, { encoding: "buffer" });
        descriptors.push({
          path,
          type: "SYMLINK",
          mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
          byteLength: bytes.byteLength,
          sha256: independentKimiReviewDigests.bytes(bytes),
        });
      } else {
        throw new TypeError(
          "Repository worktree contains an unsupported entry.",
        );
      }
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      descriptors.push({
        path,
        type: "MISSING",
        mode: null,
        byteLength: 0,
        sha256: null,
      });
    }
  }
  return {
    digest: independentKimiReviewDigests.value(descriptors),
    pathCount: descriptors.length,
  };
}

async function protectedFilesDigest(repoPath, protectedPaths) {
  const descriptors = [];
  for (const path of protectedPaths) {
    if (!SAFE_PATH.test(path)) {
      throw new TypeError("Repository protected path is unsafe.");
    }
    const target = resolve(repoPath, path);
    if (target !== repoPath && !target.startsWith(`${repoPath}${sep}`)) {
      throw new TypeError("Repository protected path escapes the repository.");
    }
    let descriptor;
    try {
      const fileStat = await stat(target);
      if (!fileStat.isFile()) {
        throw new TypeError("Repository protected path is not a file.");
      }
      const bytes = await readFile(target);
      descriptor = {
        path,
        state: "PRESENT",
        byteLength: bytes.byteLength,
        sha256: independentKimiReviewDigests.bytes(bytes),
      };
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      descriptor = {
        path,
        state: "MISSING",
        byteLength: 0,
        sha256: null,
      };
    }
    descriptors.push(descriptor);
  }
  return independentKimiReviewDigests.value(descriptors);
}

async function ignoredWorktreeExclusionSnapshot(repoPath) {
  const { stdout } = await git(repoPath, [
    "ls-files",
    "-z",
    "--others",
    "--ignored",
    "--exclude-standard",
  ]);
  let decoded;
  try {
    decoded = new TextDecoder("utf-8", { fatal: true }).decode(stdout);
  } catch {
    throw new TypeError("Ignored repository paths are not valid UTF-8.");
  }
  const paths = decoded.split("\0").filter(Boolean);
  if (
    new Set(paths).size !== paths.length ||
    paths.some((path) => !SAFE_PATH.test(path))
  ) {
    throw new TypeError("Ignored repository paths are unsafe or duplicated.");
  }
  for (const path of paths) {
    const allowed = IGNORED_WORKTREE_EXCLUSIONS.some(
      (rule) =>
        rule.exactPath === path ||
        (rule.pathPrefix && path.startsWith(rule.pathPrefix)) ||
        (rule.pathSuffix && path.endsWith(rule.pathSuffix)),
    );
    if (!allowed) {
      throw new TypeError(
        `Ignored repository path is outside the frozen exclusion policy: ${path}`,
      );
    }
  }
  return {
    ignoredExclusionPolicySha256:
      independentKimiReviewDigests.value(IGNORED_WORKTREE_EXCLUSIONS),
    ignoredExcludedPathCount: paths.length,
  };
}

export async function captureKimiReviewRepositorySnapshot({
  repoPath,
  protectedPaths,
}) {
  const exactRepoPath = await realpath(resolve(repoPath));
  const [{ stdout: headText }, { stdout: treeText }, { stdout: statusBytes }] =
    await Promise.all([
      git(exactRepoPath, ["rev-parse", "HEAD"], "utf8"),
      git(exactRepoPath, ["rev-parse", "HEAD^{tree}"], "utf8"),
      git(exactRepoPath, [
        "status",
        "--porcelain=v2",
        "-z",
        "--untracked-files=all",
      ]),
    ]);
  const exactProtectedPaths = [...protectedPaths].sort();
  const [contentManifest, ignoredExclusions] = await Promise.all([
    worktreeContentManifest(exactRepoPath),
    ignoredWorktreeExclusionSnapshot(exactRepoPath),
  ]);
  return {
    head: headText.trim(),
    tree: treeText.trim(),
    worktreeStatusSha256: hashStatus(statusBytes),
    worktreeContentManifestSha256: contentManifest.digest,
    worktreePathCount: contentManifest.pathCount,
    protectedPathSetSha256:
      independentKimiReviewDigests.value(exactProtectedPaths),
    protectedFilesDigest: await protectedFilesDigest(
      exactRepoPath,
      exactProtectedPaths,
    ),
    ...ignoredExclusions,
  };
}

async function writeArtifacts(outputDir, artifacts) {
  for (const [name, bytes] of Object.entries(artifacts)) {
    if (!SAFE_PATH.test(name)) {
      throw new TypeError("Kimi review evidence artifact path is unsafe.");
    }
    const path = resolve(outputDir, name);
    if (!path.startsWith(`${outputDir}${sep}`)) {
      throw new TypeError("Kimi review evidence artifact escapes output.");
    }
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes, { flag: "wx" });
  }
}

async function safeOutputCandidate(repoPath, outputDir) {
  const requested = resolve(outputDir);
  const physicalParent = await realpath(dirname(requested));
  const candidate = resolve(physicalParent, basename(requested));
  if (
    candidate === repoPath ||
    candidate.startsWith(`${repoPath}${sep}`)
  ) {
    throw new TypeError(
      "Kimi review evidence output must be physically outside the repository.",
    );
  }
  try {
    await lstat(requested);
    throw new TypeError("Kimi review evidence output already exists.");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  return candidate;
}

async function createVerifiedOutputDirectory(repoPath, outputDir) {
  await mkdir(outputDir, { recursive: false });
  const [physical, descriptor] = await Promise.all([
    realpath(outputDir),
    lstat(outputDir),
  ]);
  if (
    physical !== outputDir ||
    descriptor.isSymbolicLink() ||
    !descriptor.isDirectory() ||
    physical === repoPath ||
    physical.startsWith(`${repoPath}${sep}`)
  ) {
    throw new TypeError("Kimi review evidence output is not a safe directory.");
  }
}

async function verifyArtifactReadback(outputDir, artifacts) {
  for (const [name, expected] of Object.entries(artifacts)) {
    const actual = await readFile(resolve(outputDir, name));
    if (
      independentKimiReviewDigests.bytes(actual) !==
      independentKimiReviewDigests.bytes(expected)
    ) {
      throw new TypeError("Kimi review evidence readback mismatch.");
    }
  }
}

async function runtimeClosureIsProved(verifyRuntimeClosure) {
  if (typeof verifyRuntimeClosure !== "function") return false;
  try {
    return (await verifyRuntimeClosure()) === true;
  } catch {
    return false;
  }
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

async function validateFormalRuntimeTrust({
  repoPath,
  sourceCommit,
  sourceTree,
  runtimeTrust,
}) {
  if (
    !exactKeys(runtimeTrust, [
      "bootstrapSha256",
      "launcherSha256",
      "runtimeCommit",
      "runtimeTree",
      "subjectCommit",
      "subjectTree",
    ]) ||
    !COMMIT.test(runtimeTrust.runtimeCommit ?? "") ||
    !COMMIT.test(runtimeTrust.runtimeTree ?? "") ||
    !COMMIT.test(runtimeTrust.subjectCommit ?? "") ||
    !COMMIT.test(runtimeTrust.subjectTree ?? "") ||
    !SHA256.test(runtimeTrust.bootstrapSha256 ?? "") ||
    !SHA256.test(runtimeTrust.launcherSha256 ?? "") ||
    runtimeTrust.runtimeCommit === runtimeTrust.subjectCommit ||
    runtimeTrust.subjectCommit !== sourceCommit ||
    runtimeTrust.subjectTree !== sourceTree
  ) {
    throw new TypeError("KIMI_RUNTIME_TRUST_NOT_PROVED");
  }
  try {
    const [
      { stdout: runtimeTree },
      { stdout: subjectTreeText },
      bootstrapBytes,
      launcherBytes,
    ] = await Promise.all([
      git(
        repoPath,
        ["rev-parse", `${runtimeTrust.runtimeCommit}^{tree}`],
        "utf8",
      ),
      git(
        repoPath,
        ["rev-parse", `${runtimeTrust.subjectCommit}^{tree}`],
        "utf8",
      ),
      commitBytes(
        repoPath,
        runtimeTrust.runtimeCommit,
        "scripts/bootstrap-kimi-independent-review.mjs",
      ),
      commitBytes(
        repoPath,
        runtimeTrust.runtimeCommit,
        "scripts/launch-kimi-independent-review.sh",
      ),
    ]);
    await git(
      repoPath,
      [
        "merge-base",
        "--is-ancestor",
        runtimeTrust.runtimeCommit,
        runtimeTrust.subjectCommit,
      ],
      "utf8",
    );
    if (
      runtimeTree.trim() !== runtimeTrust.runtimeTree ||
      subjectTreeText.trim() !== runtimeTrust.subjectTree ||
      independentKimiReviewDigests.bytes(bootstrapBytes) !==
        runtimeTrust.bootstrapSha256 ||
      independentKimiReviewDigests.bytes(launcherBytes) !==
        runtimeTrust.launcherSha256
    ) {
      throw new TypeError("KIMI_RUNTIME_TRUST_NOT_PROVED");
    }
  } catch (error) {
    if (error?.message === "KIMI_RUNTIME_TRUST_NOT_PROVED") throw error;
    throw new TypeError("KIMI_RUNTIME_TRUST_NOT_PROVED");
  }
}

async function createFormalRuntimeClosure({
  repoPath,
  sourceCommit,
  sourceTree,
  runtimeTrust,
}) {
  assertIndependentReviewBootstrapEnvironment({ requiredExecArgv: [] });
  if (process.env.ZB_KIMI_SANITIZED_LAUNCHER !== "1") {
    throw new TypeError("INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED");
  }
  await validateFormalRuntimeTrust({
    repoPath,
    sourceCommit,
    sourceTree,
    runtimeTrust,
  });
  await verifyExecutingBytes(repoPath, runtimeTrust.runtimeCommit);
  const runtimeManifestBytes = await commitBytes(
    repoPath,
    runtimeTrust.runtimeCommit,
    FIXED_PATHS.runtimeManifest,
  );
  const runnerBytes = await commitBytes(
    repoPath,
    runtimeTrust.runtimeCommit,
    "scripts/run-kimi-independent-review.mjs",
  );
  const runtimeManifest = parseIndependentReviewJsonBytes(
    runtimeManifestBytes,
    "Independent Review Runtime Manifest",
    4 * 1024 * 1024,
  );
  if (
    !validateIndependentReviewRuntimeDependencyManifest(runtimeManifest).ok
  ) {
    throw new TypeError("INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED");
  }
  const dependencyRoot = await realpath(resolve(moduleRoot, "node_modules"));
  const verify = async () => {
    try {
      const current =
        await captureIndependentReviewRuntimeDependencyManifest({
          sourceRoot: moduleRoot,
          dependencyRoot,
          requiredExecArgv: [],
        });
      return JSON.stringify(current) === JSON.stringify(runtimeManifest);
    } catch {
      return false;
    }
  };
  if (!(await verify())) {
    throw new TypeError("INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED");
  }
  return {
    runtimeManifestBytes,
    verify,
    receiptRuntimeTrust: {
      mode: "ANCESTOR_RUNTIME_COMMIT",
      ...runtimeTrust,
      runtimeManifestGitBlobSha256:
        independentKimiReviewDigests.bytes(runtimeManifestBytes),
      runnerGitBlobSha256:
        independentKimiReviewDigests.bytes(runnerBytes),
    },
  };
}

async function readKimiCredentialFromKeychain() {
  try {
    const { stdout } = await execFileAsync(
      "/usr/bin/security",
      ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
      {
        encoding: "buffer",
        env: gitEnvironment,
        maxBuffer: 64 * 1024,
      },
    );
    const bytes = Buffer.from(stdout);
    const credential = new TextDecoder("utf-8", { fatal: true })
      .decode(bytes)
      .replace(/\r?\n$/u, "");
    bytes.fill(0);
    if (credential.length < 16 || credential.length > 4096) {
      throw new TypeError("KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED");
    }
    return credential;
  } catch {
    throw new TypeError("KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED");
  }
}

async function runKimiIndependentReviewCore({
  repoPath,
  reviewBundleBytes,
  reviewMaterialBytes,
  outputDir,
  reviewId,
  credentialProvider,
  verifyRuntimeClosure = async () => false,
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
  runtimeTrust = null,
  runtimeManifestBytesOverride = null,
  formalReceipt = false,
}) {
  const exactRepoPath = await realpath(resolve(repoPath));
  const exactOutputDir = await safeOutputCandidate(
    exactRepoPath,
    outputDir,
  );
  const submittedBundle = parseIndependentReviewJsonBytes(
    reviewBundleBytes,
    "Independent Review Bundle",
    16 * 1024 * 1024,
  );
  const submittedMaterial = parseIndependentReviewJsonBytes(
    reviewMaterialBytes,
    "Independent Review Material",
    16 * 1024 * 1024,
  );
  const sourceCommit = submittedBundle?.source?.sourceCommit;
  if (
    !COMMIT.test(sourceCommit ?? "") ||
    submittedMaterial?.source?.sourceCommit !== sourceCommit ||
    submittedMaterial?.bindings?.reviewBundle?.bundleDigest !==
      submittedBundle?.bundleSha256
  ) {
    throw new TypeError("Kimi review sourceCommit binding is invalid.");
  }
  if (!formalReceipt) {
    await verifyExecutingBytes(exactRepoPath, sourceCommit);
  }
  const runtimeBindingBefore =
    await captureIndependentReviewRuntimeBinding();
  const [
    policyBytes,
    configBytes,
    promptBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
    frozenRuntimeManifestBytes,
  ] = await Promise.all(
    [
      FIXED_PATHS.policy,
      FIXED_PATHS.config,
      FIXED_PATHS.prompt,
      FIXED_PATHS.outputSchema,
      FIXED_PATHS.receiptSchema,
      FIXED_PATHS.runtimeManifest,
    ].map((path) => commitBytes(exactRepoPath, sourceCommit, path)),
  );
  const runtimeManifestBytes =
    runtimeManifestBytesOverride ?? frozenRuntimeManifestBytes;
  const policy = parseIndependentReviewJsonBytes(
    policyBytes,
    "Independent Review Policy",
    1024 * 1024,
  );
  const config = parseIndependentReviewJsonBytes(
    configBytes,
    "Moonshot Kimi configuration",
    1024 * 1024,
  );
  const [policyValidation, bundleValidation] = await Promise.all([
    validateIndependentReviewPolicy(policy),
    validateIndependentReviewBundle(submittedBundle, { policy }),
  ]);
  if (!policyValidation.ok || !bundleValidation.ok) {
    throw new TypeError("Kimi review Policy or Bundle is invalid.");
  }
  await verifyKimiReviewBundleGitBindings({
    repoPath: exactRepoPath,
    bundle: submittedBundle,
  });
  if (
    submittedBundle.artifacts.testPlanPath !== FIXED_PATHS.testPlan ||
    submittedBundle.artifacts.testEvidenceCollectorPath !==
      FIXED_PATHS.testEvidenceCollector
  ) {
    throw new TypeError(
      "Kimi review frozen test evidence paths do not match.",
    );
  }
  const before = await captureKimiReviewRepositorySnapshot({
    repoPath: exactRepoPath,
    protectedPaths:
      submittedBundle.repositoryProtection.protectedPaths,
  });
  if (
    before.head !== sourceCommit ||
    before.tree !== submittedBundle.source.tree
  ) {
    throw new TypeError("Repository snapshot does not match sourceCommit.");
  }
  let trusted = null;
  let pendingReceiptPath = null;
  let networkAttemptCount = 0;
  try {
    trusted = await buildTrustedKimiReviewInputs({
      repoPath: exactRepoPath,
      submittedBundle,
      materialId: submittedMaterial.materialId,
    });
    const {
      bundle,
      reviewBundleBytes: trustedReviewBundleBytes,
      material,
      materialBytes: trustedMaterialBytes,
      evidenceRoot,
    } = trusted;
    const afterTests = await captureKimiReviewRepositorySnapshot({
      repoPath: exactRepoPath,
      protectedPaths: bundle.repositoryProtection.protectedPaths,
    });
    if (JSON.stringify(before) !== JSON.stringify(afterTests)) {
      throw new TypeError(
        "Repository changed during trusted Kimi test collection.",
      );
    }
    if (
      JSON.stringify(runtimeBindingBefore) !==
      JSON.stringify(await captureIndependentReviewRuntimeBinding())
    ) {
      throw new TypeError(
        "Independent review runtime changed during trusted test collection.",
      );
    }
    const [
      testPlanBytes,
      collectorBytes,
      testResultSchemaBytes,
      sandboxPolicyTemplateBytes,
      evidenceArtifacts,
    ] =
      await Promise.all([
        commitBytes(exactRepoPath, sourceCommit, FIXED_PATHS.testPlan),
        commitBytes(
          exactRepoPath,
          sourceCommit,
          FIXED_PATHS.testEvidenceCollector,
        ),
        commitBytes(
          exactRepoPath,
          sourceCommit,
          FIXED_PATHS.testResultSchema,
        ),
        commitBytes(
          exactRepoPath,
          sourceCommit,
          FIXED_PATHS.sandboxPolicyTemplate,
        ),
        trustedEvidenceArtifacts(bundle, evidenceRoot),
      ]);
    const governanceSubjectBindings = await Promise.all(
      kimiIndependentReviewMaterialGovernancePaths.map(async (path) => {
        const bytes = await commitBytes(exactRepoPath, sourceCommit, path);
        return {
          path,
          byteLength: bytes.byteLength,
          sha256: independentKimiReviewDigests.bytes(bytes),
        };
      }),
    );
    const request = await buildKimiIndependentReviewRequest({
      config,
      configBytes,
      bundle,
      reviewBundleBytes: trustedReviewBundleBytes,
      promptBytes,
      materialBytes: trustedMaterialBytes,
      outputSchemaBytes,
      receiptSchemaBytes,
      governanceSubjectBindings,
    });
    if (!(await runtimeClosureIsProved(verifyRuntimeClosure))) {
      return {
        ok: false,
        status: "BLOCKED",
        reasonCodes: [
          "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
        ],
        networkAttemptCount: 0,
        trustedBundleSha256: bundle.bundleSha256,
        trustedMaterialSha256: material.materialSha256,
      };
    }
    let apiKey = "";
    try {
      apiKey = await credentialProvider();
    } catch {
      apiKey = "";
    }
    if (typeof apiKey !== "string" || apiKey.length === 0) {
      return {
        ok: false,
        status: "BLOCKED",
        reasonCodes: ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
        networkAttemptCount: 0,
        trustedBundleSha256: bundle.bundleSha256,
        trustedMaterialSha256: material.materialSha256,
      };
    }
    const startedAt = now().toISOString();
    const transport = await executeKimiIndependentReview({
      config,
      requestBytes: request.requestBytes,
      promptBytes,
      materialBytes: trustedMaterialBytes,
      outputSchemaBytes,
      apiKey,
      fetchImpl: (...args) => {
        networkAttemptCount += 1;
        return fetchImpl(...args);
      },
    });
    const finishedAt = now().toISOString();
    if (!transport.ok) {
      return {
        ...transport,
        networkAttemptCount,
      };
    }
    if (!(await runtimeClosureIsProved(verifyRuntimeClosure))) {
      return {
        ok: false,
        status: "INCONCLUSIVE",
        reasonCodes: [
          "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
        ],
        networkAttemptCount,
      };
    }
    const artifactPaths = {
      request: "request.json",
      response: "response.json",
      content: "content.json",
      material: "material.json",
    };
    const transportArtifacts = {
      "bundle.json": trustedReviewBundleBytes,
      "request.json": request.requestBytes,
      "response.json": transport.responseBytes,
      "content.json": transport.contentBytes,
      "material.json": trustedMaterialBytes,
      ...evidenceArtifacts,
    };
    await createVerifiedOutputDirectory(exactRepoPath, exactOutputDir);
    await writeArtifacts(exactOutputDir, transportArtifacts);
    await verifyArtifactReadback(exactOutputDir, transportArtifacts);
    const persistedClosure =
      await validateIndependentReviewTestEvidenceClosure({
        bundle,
        testPlanBytes,
        collectorBytes,
        testResultSchemaBytes,
        sandboxPolicyTemplateBytes,
        expectedRuntimeBinding: runtimeBindingBefore,
        evidenceResolver:
          await evidenceResolverForRoot(
            resolve(exactOutputDir, "test-evidence"),
          ),
      });
    if (!persistedClosure.ok) {
      throw new TypeError(
        "Persisted Kimi test evidence closure is invalid.",
      );
    }
    const after = await captureKimiReviewRepositorySnapshot({
      repoPath: exactRepoPath,
      protectedPaths: bundle.repositoryProtection.protectedPaths,
    });
    const snapshots = { before, after };
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      return {
        ok: false,
        status: "INCONCLUSIVE",
        reasonCodes: ["KIMI_REPOSITORY_CHANGED_DURING_REVIEW"],
        networkAttemptCount,
      };
    }
    if (
      JSON.stringify(runtimeBindingBefore) !==
      JSON.stringify(await captureIndependentReviewRuntimeBinding())
    ) {
      return {
        ok: false,
        status: "INCONCLUSIVE",
        reasonCodes: ["KIMI_RUNTIME_CHANGED_DURING_REVIEW"],
        networkAttemptCount,
      };
    }
    if (!formalReceipt) {
      const testOnlyOutput = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(
          transport.contentBytes,
        ),
      );
      return {
        ok: false,
        status: "INCONCLUSIVE",
        conclusion: "INCONCLUSIVE",
        reasonCodes: ["KIMI_TEST_HARNESS_CANNOT_PUBLISH_RECEIPT"],
        networkAttemptCount,
        testOnlyModelDecision: testOnlyOutput.decision,
        formalReceiptPublished: false,
        outputDirectory: exactOutputDir,
      };
    }
    const receipt = await createKimiIndependentModelReviewReceipt({
      receiptId: reviewId,
      policy,
      bundle,
      config,
      configBytes,
      material,
      rawMaterialBytes: trustedMaterialBytes,
      reviewBundleBytes: trustedReviewBundleBytes,
      promptBytes,
      outputSchemaBytes,
      receiptSchemaBytes,
      runtimeManifestBytes,
      requestBytes: request.requestBytes,
      responseBytes: transport.responseBytes,
      contentBytes: transport.contentBytes,
      responseId: transport.responseId,
      actualReturnedModel: transport.actualReturnedModel,
      startedAt,
      finishedAt,
      snapshots,
      artifactPaths,
      governanceSubjectBindings,
      runtimeTrust,
    });
    const validation = await validateKimiIndependentModelReviewReceipt({
      receipt,
      policy,
      bundle,
      config,
      configBytes,
      material,
      rawMaterialBytes: trustedMaterialBytes,
      reviewBundleBytes: trustedReviewBundleBytes,
      promptBytes,
      outputSchemaBytes,
      receiptSchemaBytes,
      runtimeManifestBytes,
      requestBytes: request.requestBytes,
      responseBytes: transport.responseBytes,
      contentBytes: transport.contentBytes,
      snapshots,
      governanceSubjectBindings,
      runtimeTrust,
    });
    if (validation.reasonCodes.length > 0) {
      return {
        ...validation,
        networkAttemptCount,
      };
    }
    if (!(await runtimeClosureIsProved(verifyRuntimeClosure))) {
      return {
        ok: false,
        status: "INCONCLUSIVE",
        reasonCodes: [
          "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
        ],
        networkAttemptCount,
      };
    }
    const receiptBytes = Buffer.from(JSON.stringify(receipt), "utf8");
    pendingReceiptPath = resolve(exactOutputDir, "receipt.pending.json");
    await writeArtifacts(exactOutputDir, {
      "receipt.pending.json": receiptBytes,
    });
    await verifyArtifactReadback(exactOutputDir, {
      "receipt.pending.json": receiptBytes,
    });
    const finalSnapshot = await captureKimiReviewRepositorySnapshot({
      repoPath: exactRepoPath,
      protectedPaths: bundle.repositoryProtection.protectedPaths,
    });
    if (JSON.stringify(before) !== JSON.stringify(finalSnapshot)) {
      await rm(pendingReceiptPath, { force: true });
      pendingReceiptPath = null;
      return {
        ok: false,
        status: "INCONCLUSIVE",
        reasonCodes: ["KIMI_REPOSITORY_CHANGED_DURING_REVIEW"],
        networkAttemptCount,
      };
    }
    if (
      JSON.stringify(runtimeBindingBefore) !==
      JSON.stringify(await captureIndependentReviewRuntimeBinding())
    ) {
      await rm(pendingReceiptPath, { force: true });
      pendingReceiptPath = null;
      return {
        ok: false,
        status: "INCONCLUSIVE",
        reasonCodes: ["KIMI_RUNTIME_CHANGED_DURING_REVIEW"],
        networkAttemptCount,
      };
    }
    if (!(await runtimeClosureIsProved(verifyRuntimeClosure))) {
      await rm(pendingReceiptPath, { force: true });
      pendingReceiptPath = null;
      return {
        ok: false,
        status: "INCONCLUSIVE",
        reasonCodes: [
          "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
        ],
        networkAttemptCount,
      };
    }
    await rename(
      pendingReceiptPath,
      resolve(exactOutputDir, "receipt.json"),
    );
    pendingReceiptPath = null;
    return {
      ok: validation.ok,
      status: validation.status,
      conclusion: validation.conclusion,
      reasonCodes: validation.reasonCodes,
      networkAttemptCount,
      reviewId,
      receiptSha256: receipt.receiptSha256,
      receiptArtifactSha256:
        independentKimiReviewDigests.bytes(receiptBytes),
      outputDirectory: exactOutputDir,
    };
  } catch (error) {
    if (pendingReceiptPath) {
      await rm(pendingReceiptPath, { force: true });
      pendingReceiptPath = null;
    }
    error.networkAttemptCount = networkAttemptCount;
    throw error;
  } finally {
    if (trusted?.evidenceRoot) {
      await rm(trusted.evidenceRoot, { recursive: true, force: true });
    }
  }
}

export async function runKimiIndependentReviewTestHarness({
  apiKey = "",
  verifyRuntimeClosure = async () => false,
  fetchImpl,
  now,
  ...input
}) {
  return runKimiIndependentReviewCore({
    ...input,
    credentialProvider: async () => apiKey,
    verifyRuntimeClosure,
    fetchImpl,
    now,
    formalReceipt: false,
  });
}

export async function runKimiIndependentReviewFromFrozenBootstrap(input) {
  const submittedBundle = parseIndependentReviewJsonBytes(
    input.reviewBundleBytes,
    "Independent Review Bundle",
    16 * 1024 * 1024,
  );
  const sourceCommit = submittedBundle?.source?.sourceCommit;
  const sourceTree = submittedBundle?.source?.tree;
  if (!COMMIT.test(sourceCommit ?? "") || !COMMIT.test(sourceTree ?? "")) {
    throw new TypeError("Kimi review sourceCommit binding is invalid.");
  }
  const runtime = await createFormalRuntimeClosure({
    repoPath: await realpath(resolve(input.repoPath)),
    sourceCommit,
    sourceTree,
    runtimeTrust: input.runtimeTrust,
  });
  return runKimiIndependentReviewCore({
    ...input,
    credentialProvider: readKimiCredentialFromKeychain,
    verifyRuntimeClosure: runtime.verify,
    fetchImpl: fixedFetch,
    now: () => new Date(),
    runtimeManifestBytesOverride: runtime.runtimeManifestBytes,
    runtimeTrust: runtime.receiptRuntimeTrust,
    formalReceipt: true,
  });
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  process.stdout.write(
    `${JSON.stringify({
      ok: false,
      status: "BLOCKED",
      reasonCodes: ["KIMI_BOOTSTRAP_REQUIRED"],
      networkAttemptCount: 0,
    })}\n`,
  );
  process.exitCode = 2;
}
