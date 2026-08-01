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
  createKimiIndependentReviewTransportEvidence,
  createKimiIndependentModelReviewReceipt,
  executeKimiIndependentReview,
  independentKimiReviewDigests,
  kimiIndependentReviewFixedBaseCommit,
  kimiIndependentReviewMaterialGovernancePaths,
  parseIndependentReviewMaterialEnvelope,
  validateKimiIndependentModelReviewReceipt,
} from "../lib/kimi-independent-review.mjs";
import {
  buildKimiK3IndependentReviewRequest,
  buildKimiK3TokenEstimateRequest,
  createKimiK3TokenEstimateDiagnosticArtifacts,
  createKimiK3TokenEstimateDiagnosticArtifactsV2,
  createKimiK3TokenEstimateEvidence,
  evaluateKimiK3SingleCallPreflight,
  executeKimiK3ChatCompletion,
  executeKimiK3TokenEstimate,
  kimiK3ReviewMaterialGovernancePaths,
  kimiK3ReviewMaterialPathsV2,
  kimiK3ReviewMaterialPathsV3,
  validateKimiK3TokenEstimateEvidence,
  validateMoonshotKimiK3FrozenContract,
} from "../lib/kimi-k3-independent-review.mjs";
import {
  createKimiK3ReviewReceiptV5,
  createKimiK3TokenEstimateEvidenceV2,
  createKimiK3TransportEvidenceV3,
  validateKimiK3ReviewReceiptV5,
  validateKimiK3TokenEstimateEvidenceV2,
  validateKimiK3TransportEvidenceV3,
} from "../lib/kimi-k3-review-evidence.mjs";
import {
  independentModelReviewFixedSpecificationPaths,
  parseIndependentReviewJsonBytes,
  validateIndependentReviewBundle,
  validateIndependentReviewPolicy,
  validateIndependentReviewSchemaInstance,
  validateIndependentReviewTestEvidenceClosure,
} from "../lib/independent-model-review.mjs";
import {
  captureIndependentReviewRuntimeBinding,
} from "../lib/independent-review-runtime-binding.mjs";
import {
  assertIndependentReviewBootstrapEnvironment,
  captureKimiK3IndependentReviewRuntimeDependencyManifest,
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
const K2_FIXED_PATHS = Object.freeze({
  contractVersion: "K2_7_V1_HISTORICAL",
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
  materialSchema:
    "implementation/governance/schemas/independent-review-material.v2.schema.json",
  transportEvidenceSchema:
    "implementation/governance/schemas/independent-review-transport-evidence.v1.schema.json",
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
const K3_V2_FIXED_PATHS = Object.freeze({
  contractVersion: "K3_V2_HISTORICAL",
  policy:
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  config: kimiK3ReviewMaterialPathsV2.config,
  research:
    "docs/research/moonshot-kimi-k3-transport-contract-2026-07-31.md",
  prompt: kimiK3ReviewMaterialPathsV2.prompt,
  outputSchema: kimiK3ReviewMaterialPathsV2.outputSchema,
  receiptSchema: kimiK3ReviewMaterialPathsV2.receiptSchema,
  materialSchema: kimiK3ReviewMaterialPathsV2.materialSchema,
  transportEvidenceSchema:
    "implementation/governance/schemas/independent-review-transport-evidence.v2.schema.json",
  tokenEstimateEvidenceSchema:
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v1.schema.json",
  tokenEstimateDiagnosticSchema:
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v1.schema.json",
  runtimeManifest:
    "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
  testPlan:
    "implementation/governance/independent-review/independent-review-test-plan.v2.json",
  testEvidenceCollector:
    "scripts/run-independent-review-test-evidence.mjs",
  testResultSchema:
    "implementation/governance/schemas/independent-review-test-result.v3.schema.json",
  sandboxPolicyTemplate:
    "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in",
});
const K3_V3_FIXED_PATHS = Object.freeze({
  contractVersion: "K3_V3_CANDIDATE",
  policy:
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  config: kimiK3ReviewMaterialPathsV3.config,
  configSchema:
    "implementation/governance/schemas/moonshot-kimi-independent-review-config.v3.schema.json",
  research:
    "docs/research/moonshot-kimi-k3-transport-contract-v3-2026-08-01.md",
  prompt: kimiK3ReviewMaterialPathsV3.prompt,
  outputSchema: kimiK3ReviewMaterialPathsV3.outputSchema,
  receiptSchema: kimiK3ReviewMaterialPathsV3.receiptSchema,
  materialSchema: kimiK3ReviewMaterialPathsV3.materialSchema,
  transportEvidenceSchema:
    "implementation/governance/schemas/independent-review-transport-evidence.v3.schema.json",
  tokenEstimateEvidenceSchema:
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v2.schema.json",
  tokenEstimateDiagnosticSchema:
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v2.schema.json",
  runtimeManifest:
    "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
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
  "lib/independent-review-transport-evidence.mjs",
  "lib/kimi-independent-review.mjs",
  "package-lock.json",
  "scripts/build-independent-review-bundle.mjs",
  "scripts/build-independent-review-material.mjs",
  "scripts/bootstrap-kimi-independent-review.mjs",
  "scripts/launch-kimi-independent-review.sh",
  "scripts/run-independent-review-test-evidence.mjs",
  "scripts/run-kimi-independent-review.mjs",
]);
const K3_EXECUTING_PATHS = Object.freeze(
  [
    ...EXECUTING_PATHS,
    "lib/kimi-k3-independent-review.mjs",
    "lib/kimi-k3-review-evidence.mjs",
  ].sort(),
);
const moduleRoot = resolve(new URL("../", import.meta.url).pathname);
const fixedFetch = globalThis.fetch.bind(globalThis);
const KEYCHAIN_SERVICE = "kimi-p2-independent-review";
const KEYCHAIN_ACCOUNT = "p2-independent-review";
const IGNORED_WORKTREE_EXCLUSIONS = Object.freeze([
  { exactPath: "node_modules", binding: "RUNTIME_DEPENDENCY_MANIFEST" },
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
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
  ...(process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
    "DENY_ALL_OFFLINE_ALTERNATIVES" &&
  typeof process.env.xcrun_db === "string" &&
  process.env.xcrun_db.startsWith("/") &&
  !process.env.xcrun_db.includes("\0")
    ? { xcrun_db: process.env.xcrun_db }
    : {}),
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

async function commitPathExists(repoPath, sourceCommit, path) {
  if (!COMMIT.test(sourceCommit) || !SAFE_PATH.test(path)) return false;
  try {
    await git(repoPath, ["cat-file", "-e", `${sourceCommit}:${path}`]);
    return true;
  } catch {
    return false;
  }
}

async function fixedPathsForCommit(repoPath, sourceCommit) {
  if (
    await commitPathExists(
      repoPath,
      sourceCommit,
      kimiK3ReviewMaterialPathsV3.config,
    )
  ) {
    return K3_V3_FIXED_PATHS;
  }
  if (
    await commitPathExists(
      repoPath,
      sourceCommit,
      kimiK3ReviewMaterialPathsV2.config,
    )
  ) {
    return K3_V2_FIXED_PATHS;
  }
  return K2_FIXED_PATHS;
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
  if (baseCommit !== kimiIndependentReviewFixedBaseCommit) {
    throw new TypeError(
      "Review Bundle baseCommit does not match the fixed Kimi review base.",
    );
  }
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
  const fixedPaths = await fixedPathsForCommit(repoPath, sourceCommit);
  const executingPaths =
    fixedPaths.contractVersion.startsWith("K3_")
      ? K3_EXECUTING_PATHS
      : EXECUTING_PATHS;
  for (const path of executingPaths) {
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

function utf8Artifact(path, bytes) {
  return {
    path,
    encoding: "UTF-8",
    byteLength: bytes.byteLength,
    sha256: independentKimiReviewDigests.bytes(bytes),
  };
}

function jsonResponseArtifact(path, bytes, httpStatus, contentType) {
  return {
    ...utf8Artifact(path, bytes),
    httpStatus,
    contentType,
  };
}

function artifactResolver(artifacts) {
  return async (path) => artifacts[path] ?? null;
}

function ceilDiv(numerator, denominator) {
  return Math.floor((numerator + denominator - 1) / denominator);
}

function normalizedK3Usage(usage) {
  return {
    promptTokens: usage.prompt_tokens,
    completionTokens: usage.completion_tokens,
    totalTokens: usage.total_tokens,
    cachedTokens: usage.cached_tokens,
  };
}

function k3ActualCost(config, usage) {
  const cacheMissTokens = usage.prompt_tokens - usage.cached_tokens;
  const inputMicros = ceilDiv(
    cacheMissTokens * config.pricing.cacheMissInputMicrosPerMillion +
      usage.cached_tokens * config.pricing.cacheHitInputMicrosPerMillion,
    config.pricing.unitTokens,
  );
  const outputMicros = ceilDiv(
    usage.completion_tokens * config.pricing.outputMicrosPerMillion,
    config.pricing.unitTokens,
  );
  return {
    inputMicros,
    outputMicros,
    totalMicros: inputMicros + outputMicros,
  };
}

function modelReviewConclusion(decision) {
  return decision === "CLEAR"
    ? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
    : decision;
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
  const fixedPaths = await fixedPathsForCommit(
    repoPath,
    runtimeTrust.runtimeCommit,
  );
  if (fixedPaths.contractVersion !== "K3_V3_CANDIDATE") {
    throw new TypeError("KIMI_K3_RUNTIME_CONTRACT_REQUIRED");
  }
  const runtimeManifestBytes = await commitBytes(
    repoPath,
    runtimeTrust.runtimeCommit,
    fixedPaths.runtimeManifest,
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
        await captureKimiK3IndependentReviewRuntimeDependencyManifest({
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

export function clearKeychainProcessBuffers(value) {
  if (Buffer.isBuffer(value?.stdout)) value.stdout.fill(0);
  if (Buffer.isBuffer(value?.stderr)) value.stderr.fill(0);
}

export function decodeAndClearKeychainCredential({ stdout, stderr }) {
  try {
    if (!Buffer.isBuffer(stdout) || !Buffer.isBuffer(stderr)) {
      throw new TypeError("KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED");
    }
    const credential = new TextDecoder("utf-8", { fatal: true })
      .decode(stdout)
      .replace(/\r?\n$/u, "");
    if (credential.length < 16 || credential.length > 4096) {
      throw new TypeError("KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED");
    }
    return credential;
  } catch {
    throw new TypeError("KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED");
  } finally {
    clearKeychainProcessBuffers({ stdout, stderr });
  }
}

export async function readKimiCredentialFromKeychain({
  execImpl = execFileAsync,
} = {}) {
  try {
    const existenceResult = await execImpl(
      "/usr/bin/security",
      [
        "find-generic-password",
        "-s",
        KEYCHAIN_SERVICE,
        "-a",
        KEYCHAIN_ACCOUNT,
      ],
      {
        encoding: "buffer",
        env: gitEnvironment,
        maxBuffer: 64 * 1024,
      },
    );
    clearKeychainProcessBuffers(existenceResult);
    const secretResult = await execImpl(
      "/usr/bin/security",
      [
        "find-generic-password",
        "-s",
        KEYCHAIN_SERVICE,
        "-a",
        KEYCHAIN_ACCOUNT,
        "-w",
      ],
      {
        encoding: "buffer",
        env: gitEnvironment,
        maxBuffer: 64 * 1024,
      },
    );
    return decodeAndClearKeychainCredential(secretResult);
  } catch (error) {
    clearKeychainProcessBuffers(error);
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
  const { material: submittedMaterial } =
    parseIndependentReviewMaterialEnvelope(reviewMaterialBytes);
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
  const fixedPaths = await fixedPathsForCommit(exactRepoPath, sourceCommit);
  const isK3 = fixedPaths.contractVersion.startsWith("K3_");
  const isK3V3 = fixedPaths.contractVersion === "K3_V3_CANDIDATE";
  if (
    isK3V3 &&
    submittedMaterial?.schemaVersion !== "independent-review-material.v4"
  ) {
    throw new TypeError("KIMI_K3_REVIEW_MATERIAL_V4_REQUIRED");
  }
  if (formalReceipt && !isK3V3) {
    throw new TypeError("KIMI_K3_RUNTIME_CONTRACT_REQUIRED");
  }
  const runtimeBindingBefore =
    await captureIndependentReviewRuntimeBinding();
  const [
    policyBytes,
    configBytes,
    promptBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
    materialSchemaBytes,
    transportEvidenceSchemaBytes,
    frozenRuntimeManifestBytes,
    tokenEstimateEvidenceSchemaBytes,
    tokenEstimateDiagnosticSchemaBytes,
    researchBytes,
    configSchemaBytes,
  ] = await Promise.all(
    [
      fixedPaths.policy,
      fixedPaths.config,
      fixedPaths.prompt,
      fixedPaths.outputSchema,
      fixedPaths.receiptSchema,
      fixedPaths.materialSchema,
      fixedPaths.transportEvidenceSchema,
      fixedPaths.runtimeManifest,
      fixedPaths.tokenEstimateEvidenceSchema ?? null,
      fixedPaths.tokenEstimateDiagnosticSchema ?? null,
      fixedPaths.research ?? null,
      fixedPaths.configSchema ?? null,
    ].map((path) =>
      path === null
        ? Promise.resolve(null)
        : commitBytes(exactRepoPath, sourceCommit, path),
    ),
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
  if (
    isK3 &&
    !(
      await validateMoonshotKimiK3FrozenContract({
        config,
        researchBytes,
      })
    ).ok
  ) {
    throw new TypeError("Frozen Moonshot Kimi K3 configuration is invalid.");
  }
  if (isK3V3) {
    const configSchemaValidation =
      await validateIndependentReviewSchemaInstance({
        schemaBytes: configSchemaBytes,
        expectedSchemaSha256:
          independentKimiReviewDigests.bytes(configSchemaBytes),
        instance: config,
        label: "Moonshot Kimi K3 Config v3 Schema",
      });
    if (!configSchemaValidation.ok) {
      throw new TypeError("Frozen Moonshot Kimi K3 v3 Schema is invalid.");
    }
  }
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
    submittedBundle.artifacts.testPlanPath !== fixedPaths.testPlan ||
    submittedBundle.artifacts.testEvidenceCollectorPath !==
      fixedPaths.testEvidenceCollector
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
  let tokenEstimateAttemptCount = 0;
  let chatCompletionAttemptCount = 0;
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
    if (isK3) {
      const materialSchemaValidation =
        await validateIndependentReviewSchemaInstance({
          schemaBytes: materialSchemaBytes,
          expectedSchemaSha256:
            independentKimiReviewDigests.bytes(materialSchemaBytes),
          instance: material,
          label: "Kimi K3 Review Material v4 Schema",
        });
      if (!materialSchemaValidation.ok) {
        throw new TypeError("KIMI_K3_REVIEW_MATERIAL_V4_SCHEMA_INVALID");
      }
    }
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
        commitBytes(exactRepoPath, sourceCommit, fixedPaths.testPlan),
        commitBytes(
          exactRepoPath,
          sourceCommit,
          fixedPaths.testEvidenceCollector,
        ),
        commitBytes(
          exactRepoPath,
          sourceCommit,
          fixedPaths.testResultSchema,
        ),
        commitBytes(
          exactRepoPath,
          sourceCommit,
          fixedPaths.sandboxPolicyTemplate,
        ),
        trustedEvidenceArtifacts(bundle, evidenceRoot),
      ]);
    const governancePaths = isK3
      ? kimiK3ReviewMaterialGovernancePaths
      : kimiIndependentReviewMaterialGovernancePaths;
    const governanceSubjectBindings = await Promise.all(
      governancePaths.map(async (path) => {
        const bytes = await commitBytes(exactRepoPath, sourceCommit, path);
        return {
          path,
          byteLength: bytes.byteLength,
          sha256: independentKimiReviewDigests.bytes(bytes),
        };
      }),
    );
    const request = isK3
      ? await buildKimiK3IndependentReviewRequest({
          config,
          promptBytes,
          materialBytes: trustedMaterialBytes,
          outputSchemaBytes,
        })
      : await buildKimiIndependentReviewRequest({
          config,
          configBytes,
          bundle,
          reviewBundleBytes: trustedReviewBundleBytes,
          promptBytes,
          materialBytes: trustedMaterialBytes,
          outputSchemaBytes,
          receiptSchemaBytes,
          materialSchemaBytes,
          materialSectionDescriptors: material.sections,
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
    if (isK3) {
      await createVerifiedOutputDirectory(exactRepoPath, exactOutputDir);
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
    if (isK3V3) {
      try {
        const estimateRequest = buildKimiK3TokenEstimateRequest({
          config,
          formalRequestBytes: request.requestBytes,
        });
        const estimate = await executeKimiK3TokenEstimate({
          config,
          estimateRequestBytes: estimateRequest.requestBytes,
          formalRequestBytes: request.requestBytes,
          materialBytes: trustedMaterialBytes,
          apiKey,
          fetchImpl: (...args) => {
            tokenEstimateAttemptCount += 1;
            networkAttemptCount += 1;
            return fetchImpl(...args);
          },
        });
        const estimateFinishedAt = now().toISOString();
        const diagnosticArtifacts =
          createKimiK3TokenEstimateDiagnosticArtifactsV2({
            requestSha256: independentKimiReviewDigests.bytes(
              estimateRequest.requestBytes,
            ),
            messagesSha256: estimateRequest.messagesSha256,
            reviewMaterialSha256: request.materialSha256,
            sourceCommit,
            requestedModel: config.reviewerModel,
            endpoint: `${config.baseURL}${config.tokenEstimateEndpoint}`,
            diagnostic: estimate.diagnostic,
            responseBytes: estimate.responseBytes,
            recordedAt: estimateFinishedAt,
          });
        const diagnosticSchemaValidation =
          await validateIndependentReviewSchemaInstance({
            schemaBytes: tokenEstimateDiagnosticSchemaBytes,
            expectedSchemaSha256:
              independentKimiReviewDigests.bytes(
                tokenEstimateDiagnosticSchemaBytes,
              ),
            instance: diagnosticArtifacts.evidence,
            label: "Kimi K3 Token Estimate Diagnostic Evidence Schema",
          });
        if (!diagnosticSchemaValidation.ok) {
          throw new TypeError(
            "Kimi K3 Token Estimate diagnostic evidence is invalid.",
          );
        }
        await writeArtifacts(exactOutputDir, diagnosticArtifacts.artifacts);
        await verifyArtifactReadback(
          exactOutputDir,
          diagnosticArtifacts.artifacts,
        );
        if (!estimate.ok) {
          return {
            ok: false,
            status: "BLOCKED",
            conclusion: "INCONCLUSIVE",
            reasonCodes: ["KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
            tokenEstimateDiagnostic: diagnosticArtifacts.evidence,
            tokenEstimateDiagnosticEvidenceSha256:
              diagnosticArtifacts.evidence.evidenceSha256,
            tokenEstimateResponseSha256:
              diagnosticArtifacts.evidence.responseBodySha256,
            outputDirectory: exactOutputDir,
          };
        }
        const estimateBindings = {
          formalRequestSha256: estimate.formalRequestSha256,
          messagesSha256: estimate.messagesSha256,
          materialSha256: estimate.materialSha256,
          nonMessageVisibleInputSha256:
            estimate.nonMessageVisibleInputSha256,
          nonMessageVisibleInputByteLength:
            estimate.nonMessageVisibleInputByteLength,
        };
        const expectedBindings = {
          formalRequestSha256: request.requestSha256,
          messagesSha256: request.messagesSha256,
          materialSha256: request.materialSha256,
          nonMessageVisibleInputSha256:
            request.nonMessageVisibleInputSha256,
          nonMessageVisibleInputByteLength:
            request.nonMessageVisibleInputByteLength,
        };
        const preflight = evaluateKimiK3SingleCallPreflight({
          config,
          estimatedMessageInputTokens: estimate.estimatedInputTokens,
          estimateCoverage: estimate.coverage,
          estimateBindings,
          expectedBindings,
          pricingObservedAt: estimateFinishedAt,
        });
        if (!preflight.ok) {
          return {
            ok: false,
            status: "BLOCKED",
            conclusion: "INCONCLUSIVE",
            reasonCodes: preflight.reasonCodes,
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
            formalRequestSha256: request.requestSha256,
            tokenEstimateRequestSha256: estimate.estimateRequestSha256,
            tokenEstimateResponseSha256: estimate.responseSha256,
            reviewMaterialByteLength: trustedMaterialBytes.byteLength,
            formalRequestByteLength: request.requestBytes.byteLength,
            estimatedMessageInputTokens: estimate.estimatedInputTokens,
            requiredContextTokens: preflight.requiredContextTokens,
            worstCaseTotalCostMicros: preflight.worstCaseTotalCostMicros,
            outputDirectory: exactOutputDir,
          };
        }
        const tokenEstimatePaths = {
          formalRequest: "request.json",
          request: "token-estimate-request.json",
          response: "token-estimate-response.json",
          evidence: "token-estimate-evidence.v2.json",
        };
        const outputSchema = parseIndependentReviewJsonBytes(
          outputSchemaBytes,
          "Kimi K3 output Schema",
          1024 * 1024,
        );
        const tokenEstimateEvidence =
          createKimiK3TokenEstimateEvidenceV2({
            schemaVersion:
              "moonshot-kimi-k3-token-estimate-evidence.v2",
            evidenceId: `mk3tee_${reviewId.slice("imrr_".length)}`,
            provider: "moonshot",
            model: "kimi-k3",
            baseURL: config.baseURL,
            endpoint: config.tokenEstimateEndpoint,
            source: {
              runtimeCommit:
                runtimeTrust?.runtimeCommit ?? bundle.source.baseCommit,
              sourceCommit,
              sourceTree: bundle.source.tree,
            },
            bindings: {
              formalRequestSha256: request.requestSha256,
              messagesSha256: request.messagesSha256,
              reviewMaterialSha256: request.materialSha256,
              reviewBundleSha256: bundle.bundleSha256,
              configSha256:
                independentKimiReviewDigests.bytes(configBytes),
              configSchemaSha256:
                independentKimiReviewDigests.bytes(configSchemaBytes),
              outputSchemaSha256:
                independentKimiReviewDigests.value(outputSchema),
              nonMessageVisibleInputSha256:
                request.nonMessageVisibleInputSha256,
              nonMessageVisibleInputByteLength:
                request.nonMessageVisibleInputByteLength,
              requestSchemaCoverage: config.tokenEstimateCoverage,
            },
            formalRequest: utf8Artifact(
              tokenEstimatePaths.formalRequest,
              request.requestBytes,
            ),
            request: utf8Artifact(
              tokenEstimatePaths.request,
              estimateRequest.requestBytes,
            ),
            response: jsonResponseArtifact(
              tokenEstimatePaths.response,
              estimate.responseBytes,
              estimate.httpStatus,
              estimate.contentType,
            ),
            estimate: {
              estimatedMessageInputTokens: estimate.estimatedInputTokens,
              contextWindowTokens: config.contextWindowTokens,
              nonMessageVisibleTokenReserve:
                config.nonMessageVisibleTokenReserve,
              maxCompletionTokens: config.maxCompletionTokens,
              safetyMarginTokens: config.safetyMarginTokens,
              requiredContextTokens: preflight.requiredContextTokens,
              coverage: config.tokenEstimateCoverage,
              contextProved: true,
            },
            budget: {
              currency: config.pricing.currency,
              taxBasis: config.pricing.taxBasis,
              budgetMicros: config.taxExclusiveBudgetMicros,
              cacheMissInputPriceMicrosPerMillion:
                config.pricing.cacheMissInputMicrosPerMillion,
              outputPriceMicrosPerMillion:
                config.pricing.outputMicrosPerMillion,
              worstCaseBillableInputTokens:
                estimate.estimatedInputTokens +
                config.nonMessageVisibleTokenReserve,
              worstCaseInputMicros: preflight.worstCaseInputCostMicros,
              worstCaseOutputMicros: preflight.worstCaseOutputCostMicros,
              worstCaseTotalMicros: preflight.worstCaseTotalCostMicros,
              budgetProved: true,
            },
            networkAttemptCount: 1,
            startedAt,
            finishedAt: estimateFinishedAt,
          });
        const tokenEstimateEvidenceBytes = Buffer.from(
          JSON.stringify(tokenEstimateEvidence),
          "utf8",
        );
        const tokenArtifacts = {
          [tokenEstimatePaths.formalRequest]: request.requestBytes,
          [tokenEstimatePaths.request]: estimateRequest.requestBytes,
          [tokenEstimatePaths.response]: estimate.responseBytes,
          [tokenEstimatePaths.evidence]: tokenEstimateEvidenceBytes,
        };
        const tokenEvidenceResolver = artifactResolver(tokenArtifacts);
        const [tokenEstimateSchemaValidation, tokenEstimateSemanticValidation] =
          await Promise.all([
            validateIndependentReviewSchemaInstance({
              schemaBytes: tokenEstimateEvidenceSchemaBytes,
              expectedSchemaSha256:
                independentKimiReviewDigests.bytes(
                  tokenEstimateEvidenceSchemaBytes,
                ),
              instance: tokenEstimateEvidence,
              label: "Kimi K3 Token Estimate Evidence v2 Schema",
            }),
            validateKimiK3TokenEstimateEvidenceV2({
              evidence: tokenEstimateEvidence,
              evidenceResolver: tokenEvidenceResolver,
            }),
          ]);
        if (
          !tokenEstimateSchemaValidation.ok ||
          !tokenEstimateSemanticValidation.valid
        ) {
          return {
            ok: false,
            status: "BLOCKED",
            conclusion: "INCONCLUSIVE",
            reasonCodes: ["KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
          };
        }
        const preflightBytes = Buffer.from(
          JSON.stringify({
            schemaVersion: "kimi-k3-single-call-preflight.v2",
            sourceCommit,
            sourceTree: bundle.source.tree,
            formalRequestSha256: request.requestSha256,
            messagesSha256: request.messagesSha256,
            reviewMaterialSha256: request.materialSha256,
            nonMessageVisibleInputSha256:
              request.nonMessageVisibleInputSha256,
            nonMessageVisibleInputByteLength:
              request.nonMessageVisibleInputByteLength,
            tokenEstimateRequestSha256: estimate.estimateRequestSha256,
            tokenEstimateResponseSha256: estimate.responseSha256,
            tokenEstimateEvidenceSha256:
              tokenEstimateEvidence.evidenceSha256,
            tokenEstimateCoverage: estimate.coverage,
            estimatedMessageInputTokens: estimate.estimatedInputTokens,
            ...preflight,
            startedAt,
            finishedAt: estimateFinishedAt,
          }),
          "utf8",
        );
        const estimateArtifacts = {
          "bundle.json": trustedReviewBundleBytes,
          "material.v4.utf8": trustedMaterialBytes,
          ...tokenArtifacts,
          "single-call-preflight.v2.json": preflightBytes,
          ...evidenceArtifacts,
        };
        await writeArtifacts(exactOutputDir, estimateArtifacts);
        await verifyArtifactReadback(exactOutputDir, estimateArtifacts);

        const chatStartedAt = now().toISOString();
        const chat = await executeKimiK3ChatCompletion({
          config,
          formalRequestBytes: request.requestBytes,
          outputSchemaBytes,
          apiKey,
          fetchImpl: (...args) => {
            chatCompletionAttemptCount += 1;
            networkAttemptCount += 1;
            return fetchImpl(...args);
          },
        });
        const chatFinishedAt = now().toISOString();
        if (!chat.ok) {
          return {
            ok: false,
            status: "BLOCKED",
            conclusion: "INCONCLUSIVE",
            reasonCodes: ["KIMI_K3_REVIEW_NOT_PROVED"],
            transportReasonCodes: chat.reasonCodes,
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
            formalRequestSha256: request.requestSha256,
            tokenEstimateEvidenceSha256:
              tokenEstimateEvidence.evidenceSha256,
            outputDirectory: exactOutputDir,
          };
        }
        if (!(await runtimeClosureIsProved(verifyRuntimeClosure))) {
          return {
            ok: false,
            status: "INCONCLUSIVE",
            reasonCodes: ["INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
          };
        }
        const after = await captureKimiReviewRepositorySnapshot({
          repoPath: exactRepoPath,
          protectedPaths: bundle.repositoryProtection.protectedPaths,
        });
        if (JSON.stringify(before) !== JSON.stringify(after)) {
          return {
            ok: false,
            status: "INCONCLUSIVE",
            reasonCodes: ["KIMI_REPOSITORY_CHANGED_DURING_REVIEW"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
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
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
          };
        }
        const usage = normalizedK3Usage(chat.usage);
        const actualCost = k3ActualCost(config, chat.usage);
        const transportPaths = {
          request: tokenEstimatePaths.formalRequest,
          response: "response.json",
          content: "content.json",
          evidence: "transport-evidence.v3.json",
        };
        const transportEvidence = createKimiK3TransportEvidenceV3({
          schemaVersion: "independent-review-transport-evidence.v3",
          evidenceId: `irte_${reviewId.slice("imrr_".length)}`,
          provider: "moonshot",
          requestedModel: config.reviewerModel,
          actualReturnedModel: chat.actualReturnedModel,
          responseId: chat.responseId,
          baseURL: config.baseURL,
          endpoint: config.endpoint,
          source: {
            sourceCommit,
            sourceTree: bundle.source.tree,
          },
          bindings: {
            reviewBundleSha256: bundle.bundleSha256,
            reviewMaterialSha256: request.materialSha256,
            reviewerPromptSha256:
              independentKimiReviewDigests.bytes(promptBytes),
            receiptSchemaSha256:
              independentKimiReviewDigests.bytes(receiptSchemaBytes),
            outputSchemaPath: fixedPaths.outputSchema,
            outputSchemaSha256:
              independentKimiReviewDigests.value(outputSchema),
            providerConfigSha256:
              independentKimiReviewDigests.bytes(configBytes),
            providerConfigSchemaSha256:
              independentKimiReviewDigests.bytes(configSchemaBytes),
            tokenEstimateEvidenceSchemaSha256:
              independentKimiReviewDigests.bytes(
                tokenEstimateEvidenceSchemaBytes,
              ),
            tokenEstimateEvidenceSha256:
              tokenEstimateEvidence.evidenceSha256,
            formalRequestSha256: request.requestSha256,
            messagesSha256: request.messagesSha256,
            nonMessageVisibleInputSha256:
              request.nonMessageVisibleInputSha256,
          },
          request: utf8Artifact(
            transportPaths.request,
            request.requestBytes,
          ),
          response: jsonResponseArtifact(
            transportPaths.response,
            chat.responseBytes,
            chat.httpStatus,
            chat.contentType,
          ),
          content: utf8Artifact(
            transportPaths.content,
            chat.contentBytes,
          ),
          protocol: {
            toolsAbsent: true,
            toolChoiceNone: true,
            thinkingAbsent: true,
            reasoningEffort: "max",
            strictSchema: true,
            maxCompletionTokens: config.maxCompletionTokens,
            networkAttemptCount: 1,
            choiceCount: 1,
            finishReason: chat.finishReason,
            outputSchemaValidated: true,
            semanticValidated: true,
          },
          usage,
          cost: {
            currency: config.pricing.currency,
            taxBasis: config.pricing.taxBasis,
            inputMicros: actualCost.inputMicros,
            outputMicros: actualCost.outputMicros,
            totalMicros: actualCost.totalMicros,
            budgetMicros: config.taxExclusiveBudgetMicros,
            withinBudget:
              actualCost.totalMicros <= config.taxExclusiveBudgetMicros,
          },
          validators: {
            schemaValidatorVersion: "ajv@8.20.0",
            semanticValidatorVersion:
              "kimi-k3-independent-review-transport-validator.v2",
          },
          startedAt: chatStartedAt,
          finishedAt: chatFinishedAt,
        });
        const transportEvidenceBytes = Buffer.from(
          JSON.stringify(transportEvidence),
          "utf8",
        );
        const allEvidenceArtifacts = {
          ...tokenArtifacts,
          [transportPaths.response]: chat.responseBytes,
          [transportPaths.content]: chat.contentBytes,
          [transportPaths.evidence]: transportEvidenceBytes,
          [fixedPaths.outputSchema]: outputSchemaBytes,
          "material.v4.utf8": trustedMaterialBytes,
        };
        const allEvidenceResolver = artifactResolver(allEvidenceArtifacts);
        const [transportSchemaValidation, transportSemanticValidation] =
          await Promise.all([
            validateIndependentReviewSchemaInstance({
              schemaBytes: transportEvidenceSchemaBytes,
              expectedSchemaSha256:
                independentKimiReviewDigests.bytes(
                  transportEvidenceSchemaBytes,
                ),
              instance: transportEvidence,
              label: "Kimi K3 Transport Evidence v3 Schema",
            }),
            validateKimiK3TransportEvidenceV3({
              evidence: transportEvidence,
              tokenEstimateEvidence,
              evidenceResolver: allEvidenceResolver,
            }),
          ]);
        if (!transportSchemaValidation.ok || !transportSemanticValidation.valid) {
          return {
            ok: false,
            status: "BLOCKED",
            conclusion: "INCONCLUSIVE",
            reasonCodes: ["KIMI_K3_REVIEW_NOT_PROVED"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
          };
        }
        const transportArtifacts = {
          [transportPaths.response]: chat.responseBytes,
          [transportPaths.content]: chat.contentBytes,
          [transportPaths.evidence]: transportEvidenceBytes,
        };
        await writeArtifacts(exactOutputDir, transportArtifacts);
        await verifyArtifactReadback(exactOutputDir, transportArtifacts);
        const modelOutput = parseIndependentReviewJsonBytes(
          chat.contentBytes,
          "Kimi K3 model output",
          config.maxResponseUtf8Bytes,
        );
        if (!formalReceipt) {
          return {
            ok: false,
            status: "INCONCLUSIVE",
            conclusion: "INCONCLUSIVE",
            reasonCodes: ["KIMI_TEST_HARNESS_CANNOT_PUBLISH_RECEIPT"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
            testOnlyModelDecision: modelOutput.decision,
            formalReceiptPublished: false,
            outputDirectory: exactOutputDir,
          };
        }
        const runtimeManifest = parseIndependentReviewJsonBytes(
          runtimeManifestBytes,
          "Independent Review Runtime Manifest",
          4 * 1024 * 1024,
        );
        if (
          !validateIndependentReviewRuntimeDependencyManifest(runtimeManifest).ok
        ) {
          throw new TypeError(
            "Kimi K3 Receipt runtime manifest is invalid.",
          );
        }
        const receiptArtifacts = {
          tokenEstimateRequest: utf8Artifact(
            tokenEstimatePaths.request,
            estimateRequest.requestBytes,
          ),
          tokenEstimateResponse: utf8Artifact(
            tokenEstimatePaths.response,
            estimate.responseBytes,
          ),
          tokenEstimateEvidence: utf8Artifact(
            tokenEstimatePaths.evidence,
            tokenEstimateEvidenceBytes,
          ),
          request: utf8Artifact(
            transportPaths.request,
            request.requestBytes,
          ),
          response: utf8Artifact(
            transportPaths.response,
            chat.responseBytes,
          ),
          content: utf8Artifact(
            transportPaths.content,
            chat.contentBytes,
          ),
          material: utf8Artifact(
            "material.v4.utf8",
            trustedMaterialBytes,
          ),
          transportEvidence: utf8Artifact(
            transportPaths.evidence,
            transportEvidenceBytes,
          ),
        };
        const receipt = createKimiK3ReviewReceiptV5({
          schemaVersion: "independent-model-review-receipt.v5",
          receiptId: reviewId,
          receiptSchemaVersion: "independent-model-review-receipt.v5",
          reviewId,
          policyVersion: policy.policyVersion,
          policySha256: policy.policySha256,
          assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
          applicablePhase: bundle.applicablePhase,
          humanIndependentReviewSatisfied: false,
          independentModelReviewRequired: true,
          p3HumanReviewRequired: true,
          bundleId: bundle.bundleId,
          bundleSha256: bundle.bundleSha256,
          reviewMaterialSha256: request.materialSha256,
          reviewer: {
            reviewerProvider: "moonshot",
            requestedModel: config.reviewerModel,
            actualReturnedModel: chat.actualReturnedModel,
            apiBaseURL: config.baseURL,
            endpoint: config.endpoint,
            reviewerSessionId: chat.responseId,
            reviewerIndependentOfImplementation: true,
            implementationProvider: bundle.implementationIdentity.provider,
            implementationModel: bundle.implementationIdentity.modelId,
            diversityLevel: "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER",
          },
          source: structuredClone(bundle.source),
          bindings: {
            reviewBundleSha256: bundle.bundleSha256,
            reviewMaterialSha256: request.materialSha256,
            reviewMaterialSchemaSha256:
              independentKimiReviewDigests.bytes(materialSchemaBytes),
            reviewMaterialSchemaVersion: "independent-review-material.v4",
            reviewMaterialFormat: "LENGTH_PREFIXED_UTF8_ENVELOPE_V1",
            reviewerPromptSha256:
              independentKimiReviewDigests.bytes(promptBytes),
            canonicalReceiptSchemaSha256:
              independentKimiReviewDigests.bytes(receiptSchemaBytes),
            canonicalOutputSchemaSha256:
              independentKimiReviewDigests.bytes(outputSchemaBytes),
            providerTransportSchemaSha256: null,
            transportEvidenceSchemaSha256:
              independentKimiReviewDigests.bytes(
                transportEvidenceSchemaBytes,
              ),
            transportEvidenceSha256:
              transportEvidence.transportEvidenceSha256,
            tokenEstimateEvidenceSchemaSha256:
              independentKimiReviewDigests.bytes(
                tokenEstimateEvidenceSchemaBytes,
              ),
            tokenEstimateEvidenceSha256:
              tokenEstimateEvidence.evidenceSha256,
            providerConfigSha256:
              independentKimiReviewDigests.bytes(configBytes),
            providerConfigSchemaSha256:
              independentKimiReviewDigests.bytes(configSchemaBytes),
            rawTokenEstimateRequestSha256:
              tokenEstimateEvidence.request.sha256,
            rawTokenEstimateResponseSha256:
              tokenEstimateEvidence.response.sha256,
            rawRequestArtifactSha256: transportEvidence.request.sha256,
            rawResponseUtf8Sha256: transportEvidence.response.sha256,
            rawContentUtf8Sha256: transportEvidence.content.sha256,
            schemaValidatorVersion: "ajv@8.20.0",
            semanticValidatorVersion:
              "kimi-k3-independent-model-review-semantic-validator.v2",
          },
          artifacts: receiptArtifacts,
          contextAndBudget: {
            estimateCoverage: config.tokenEstimateCoverage,
            estimatedMessageInputTokens: estimate.estimatedInputTokens,
            nonMessageVisibleTokenReserve:
              config.nonMessageVisibleTokenReserve,
            nonMessageVisibleInputByteLength:
              request.nonMessageVisibleInputByteLength,
            nonMessageVisibleInputSha256:
              request.nonMessageVisibleInputSha256,
            contextWindowTokens: config.contextWindowTokens,
            maxCompletionTokens: config.maxCompletionTokens,
            safetyMarginTokens: config.safetyMarginTokens,
            requiredContextTokens: preflight.requiredContextTokens,
            contextProved: true,
            budgetMicros: config.taxExclusiveBudgetMicros,
            worstCaseBillableInputTokens:
              estimate.estimatedInputTokens +
              config.nonMessageVisibleTokenReserve,
            worstCaseTotalMicros: preflight.worstCaseTotalCostMicros,
            budgetProved: true,
          },
          usage,
          cost: {
            currency: config.pricing.currency,
            taxBasis: config.pricing.taxBasis,
            actualInputMicros: actualCost.inputMicros,
            actualOutputMicros: actualCost.outputMicros,
            actualTotalMicros: actualCost.totalMicros,
            budgetMicros: config.taxExclusiveBudgetMicros,
            withinBudget:
              actualCost.totalMicros <= config.taxExclusiveBudgetMicros,
          },
          isolationEvidence: {
            mode: "API_NO_TOOLS",
            toolsAbsent: true,
            toolChoiceNone: true,
            strictSchema: true,
            credentialsExposedToModel: false,
            implementationConversationImported: false,
            modelToolCapabilities: {
              fileRead: false,
              fileWrite: false,
              shell: false,
              git: false,
              browser: false,
              d1: false,
              sites: false,
              governanceDecision: false,
            },
            repositoryBefore: structuredClone(before),
            repositoryAfter: structuredClone(after),
            repositoryUnchanged: true,
            runtimeTrust: structuredClone(runtimeTrust),
            runtimeDependencyManifest: {
              path: fixedPaths.runtimeManifest,
              gitBlobSha256:
                independentKimiReviewDigests.bytes(runtimeManifestBytes),
              manifestSha256: runtimeManifest.manifestSha256,
              nodeExecutableSha256:
                runtimeManifest.node.executableSha256,
              fullDependencyTreeSha256:
                runtimeManifest.dependencies.fullTreeSha256,
              npmPackageTreeSha256:
                runtimeManifest.npm.packageTreeSha256,
            },
          },
          reviewedPaths: structuredClone(bundle.reviewedPaths),
          findings: structuredClone(modelOutput.findings),
          testEvidenceDigests: bundle.testEvidenceSubjects.map(
            (subject) => subject.outputSha256,
          ),
          decision: modelOutput.decision,
          conclusion: modelReviewConclusion(modelOutput.decision),
          historicalTerraEvidenceAccepted: false,
          historicalK2EvidenceAccepted: false,
          humanReviewClaim: false,
          governanceEffect: "NONE",
          selfAuthorizing: false,
          startedAt,
          finishedAt: chatFinishedAt,
          recordedAt: chatFinishedAt,
        });
        const [receiptSchemaValidation, receiptSemanticValidation] =
          await Promise.all([
            validateIndependentReviewSchemaInstance({
              schemaBytes: receiptSchemaBytes,
              expectedSchemaSha256:
                independentKimiReviewDigests.bytes(receiptSchemaBytes),
              instance: receipt,
              label: "Kimi K3 Review Receipt v5 Schema",
            }),
            validateKimiK3ReviewReceiptV5({
              receipt,
              transportEvidence,
              tokenEstimateEvidence,
              evidenceResolver: allEvidenceResolver,
            }),
          ]);
        if (!receiptSchemaValidation.ok || !receiptSemanticValidation.valid) {
          return {
            ok: false,
            status: "BLOCKED",
            conclusion: "INCONCLUSIVE",
            reasonCodes: ["KIMI_K3_REVIEW_NOT_PROVED"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
          };
        }
        if (!(await runtimeClosureIsProved(verifyRuntimeClosure))) {
          return {
            ok: false,
            status: "INCONCLUSIVE",
            reasonCodes: ["INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
          };
        }
        const finalSnapshot = await captureKimiReviewRepositorySnapshot({
          repoPath: exactRepoPath,
          protectedPaths: bundle.repositoryProtection.protectedPaths,
        });
        if (JSON.stringify(before) !== JSON.stringify(finalSnapshot)) {
          return {
            ok: false,
            status: "INCONCLUSIVE",
            reasonCodes: ["KIMI_REPOSITORY_CHANGED_DURING_REVIEW"],
            networkAttemptCount,
            tokenEstimateAttemptCount,
            chatCompletionAttemptCount,
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
        await rename(
          pendingReceiptPath,
          resolve(exactOutputDir, "receipt.json"),
        );
        pendingReceiptPath = null;
        return {
          ok: receiptSemanticValidation.valid,
          status: receiptSemanticValidation.status,
          conclusion: receiptSemanticValidation.conclusion,
          reasonCodes: receiptSemanticValidation.reasonCodes,
          networkAttemptCount,
          tokenEstimateAttemptCount,
          chatCompletionAttemptCount,
          reviewId,
          receiptSha256: receipt.receiptSha256,
          receiptArtifactSha256:
            independentKimiReviewDigests.bytes(receiptBytes),
          tokenEstimateEvidenceSha256:
            tokenEstimateEvidence.evidenceSha256,
          transportEvidenceSha256:
            transportEvidence.transportEvidenceSha256,
          outputDirectory: exactOutputDir,
        };
      } finally {
        apiKey = "";
      }
    }
    if (!isK3V3 && isK3) {
      try {
      const estimateRequest = buildKimiK3TokenEstimateRequest({
        config,
        formalRequestBytes: request.requestBytes,
      });
      const estimate = await executeKimiK3TokenEstimate({
        config,
        estimateRequestBytes: estimateRequest.requestBytes,
        formalRequestBytes: request.requestBytes,
        materialBytes: trustedMaterialBytes,
        apiKey,
        fetchImpl: (...args) => {
          tokenEstimateAttemptCount += 1;
          networkAttemptCount += 1;
          return fetchImpl(...args);
        },
      });
      const finishedAt = now().toISOString();
      const diagnosticArtifacts =
        createKimiK3TokenEstimateDiagnosticArtifacts({
          requestSha256: independentKimiReviewDigests.bytes(
            estimateRequest.requestBytes,
          ),
          messagesSha256: estimateRequest.messagesSha256,
          reviewMaterialSha256: request.materialSha256,
          sourceCommit,
          requestedModel: config.reviewerModel,
          endpoint: `${config.baseURL}${config.tokenEstimateEndpoint}`,
          diagnostic: estimate.diagnostic,
          responseBytes: estimate.responseBytes,
          recordedAt: finishedAt,
        });
      const diagnosticSchemaValidation =
        await validateIndependentReviewSchemaInstance({
          schemaBytes: tokenEstimateDiagnosticSchemaBytes,
          expectedSchemaSha256: independentKimiReviewDigests.bytes(
            tokenEstimateDiagnosticSchemaBytes,
          ),
          instance: diagnosticArtifacts.evidence,
          label: "Kimi K3 Token Estimate Diagnostic Evidence Schema",
        });
      if (!diagnosticSchemaValidation.ok) {
        throw new TypeError(
          "Kimi K3 Token Estimate diagnostic evidence is invalid.",
        );
      }
      await writeArtifacts(
        exactOutputDir,
        diagnosticArtifacts.artifacts,
      );
      await verifyArtifactReadback(
        exactOutputDir,
        diagnosticArtifacts.artifacts,
      );
      if (!estimate.ok) {
        apiKey = "";
        return {
          ok: false,
          status: "BLOCKED",
          conclusion: "INCONCLUSIVE",
          reasonCodes: ["KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED"],
          networkAttemptCount,
          tokenEstimateAttemptCount: networkAttemptCount,
          chatCompletionAttemptCount: 0,
          tokenEstimateDiagnostic:
            diagnosticArtifacts.evidence,
          tokenEstimateDiagnosticEvidenceSha256:
            diagnosticArtifacts.evidence.evidenceSha256,
          tokenEstimateResponseSha256:
            diagnosticArtifacts.evidence.responseBodySha256,
          outputDirectory: exactOutputDir,
        };
      }
      const preflight = evaluateKimiK3SingleCallPreflight({
        config,
        estimatedInputTokens: estimate.estimatedInputTokens,
        estimateCoverage: estimate.coverage,
        estimateBindingsMatch:
          estimate.formalRequestSha256 === request.requestSha256 &&
          estimate.messagesSha256 === request.messagesSha256 &&
          estimate.materialSha256 === request.materialSha256,
        priceEvidenceCurrent:
          startedAt.slice(0, 10) === config.pricing.asOf,
        reasoningUsageCoveredByCompletionLimit: false,
        reasoningUsageCoveredByPublishedOutputPrice: false,
      });
      const tokenEstimateEvidence = createKimiK3TokenEstimateEvidence({
        evidenceId: `mk3tee_${reviewId.slice("imrr_".length)}`,
        config,
        configBytes,
        source: {
          runtimeCommit: runtimeTrust?.runtimeCommit,
          sourceCommit,
          sourceTree: bundle.source.tree,
        },
        reviewBundleSha256: bundle.bundleSha256,
        formalRequestBytes: request.requestBytes,
        materialBytes: trustedMaterialBytes,
        estimateRequestBytes: estimateRequest.requestBytes,
        estimateResponseBytes: estimate.responseBytes,
        estimatedInputTokens: estimate.estimatedInputTokens,
        coverage: estimate.coverage,
        httpStatus: estimate.httpStatus,
        contentType: estimate.contentType,
        networkAttemptCount: estimate.networkAttemptCount,
        startedAt,
        finishedAt,
        artifactPaths: {
          request: "token-estimate-request.json",
          response: "token-estimate-response.json",
        },
      });
      const [tokenEstimateSchemaValidation, tokenEstimateSemanticValidation] =
        await Promise.all([
          validateIndependentReviewSchemaInstance({
            schemaBytes: tokenEstimateEvidenceSchemaBytes,
            expectedSchemaSha256: independentKimiReviewDigests.bytes(
              tokenEstimateEvidenceSchemaBytes,
            ),
            instance: tokenEstimateEvidence,
            label: "Kimi K3 Token Estimate Evidence Schema",
          }),
          validateKimiK3TokenEstimateEvidence({
            evidence: tokenEstimateEvidence,
            config,
            configBytes,
            source: tokenEstimateEvidence.source,
            reviewBundleSha256: bundle.bundleSha256,
            formalRequestBytes: request.requestBytes,
            materialBytes: trustedMaterialBytes,
            estimateRequestBytes: estimateRequest.requestBytes,
            estimateResponseBytes: estimate.responseBytes,
          }),
        ]);
      if (
        !tokenEstimateSchemaValidation.ok ||
        !tokenEstimateSemanticValidation.ok
      ) {
        apiKey = "";
        return {
          ok: false,
          status: "BLOCKED",
          conclusion: "INCONCLUSIVE",
          reasonCodes: ["KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED"],
          networkAttemptCount,
          tokenEstimateAttemptCount: 1,
          chatCompletionAttemptCount: 0,
        };
      }
      const preflightBytes = Buffer.from(
        JSON.stringify({
          schemaVersion: "kimi-k3-single-call-preflight.v1",
          sourceCommit,
          sourceTree: bundle.source.tree,
          formalRequestSha256: request.requestSha256,
          messagesSha256: request.messagesSha256,
          reviewMaterialSha256: request.materialSha256,
          tokenEstimateRequestSha256: estimate.estimateRequestSha256,
          tokenEstimateResponseSha256: estimate.responseSha256,
          tokenEstimateCoverage: estimate.coverage,
          estimatedInputTokens: estimate.estimatedInputTokens,
          ...preflight,
          startedAt,
          finishedAt,
        }),
        "utf8",
      );
      const estimateArtifacts = {
        "bundle.json": trustedReviewBundleBytes,
        "material.v4.utf8": trustedMaterialBytes,
        "request.json": request.requestBytes,
        "token-estimate-request.json": estimateRequest.requestBytes,
        "token-estimate-response.json": estimate.responseBytes,
        "token-estimate-evidence.json": Buffer.from(
          JSON.stringify(tokenEstimateEvidence),
          "utf8",
        ),
        "single-call-preflight.json": preflightBytes,
        ...evidenceArtifacts,
      };
      await writeArtifacts(exactOutputDir, estimateArtifacts);
      await verifyArtifactReadback(exactOutputDir, estimateArtifacts);
      if (!preflight.ok) {
        apiKey = "";
        return {
          ok: false,
          status: "BLOCKED",
          conclusion: "INCONCLUSIVE",
          reasonCodes: preflight.reasonCodes,
          networkAttemptCount,
          tokenEstimateAttemptCount: 1,
          chatCompletionAttemptCount: 0,
          formalRequestSha256: request.requestSha256,
          tokenEstimateRequestSha256: estimate.estimateRequestSha256,
          tokenEstimateResponseSha256: estimate.responseSha256,
          tokenEstimateEvidenceSha256:
            tokenEstimateEvidence.evidenceSha256,
          reviewMaterialByteLength: trustedMaterialBytes.byteLength,
          formalRequestByteLength: request.requestBytes.byteLength,
          estimatedInputTokens: estimate.estimatedInputTokens,
          requiredContextTokens: preflight.requiredContextTokens,
          worstCaseTotalCostMicros: preflight.worstCaseTotalCostMicros,
          outputDirectory: exactOutputDir,
        };
      }
      return {
        ok: false,
        status: "BLOCKED",
        conclusion: "INCONCLUSIVE",
        reasonCodes: ["KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED"],
        networkAttemptCount,
        tokenEstimateAttemptCount: 1,
        chatCompletionAttemptCount: 0,
        formalRequestSha256: request.requestSha256,
        tokenEstimateRequestSha256: estimate.estimateRequestSha256,
        tokenEstimateResponseSha256: estimate.responseSha256,
        tokenEstimateEvidenceSha256:
          tokenEstimateEvidence.evidenceSha256,
      };
      } finally {
        apiKey = "";
      }
    }
    let transport;
    try {
      transport = await executeKimiIndependentReview({
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
    } finally {
      apiKey = "";
    }
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
      material: "material.v2.utf8",
      transportEvidence: "transport-evidence.json",
    };
    const transportEvidence =
      await createKimiIndependentReviewTransportEvidence({
        evidenceId: `irte_${reviewId.slice(5)}`,
        config,
        bundle,
        promptBytes,
        outputSchemaBytes,
        receiptSchemaBytes,
        requestBytes: request.requestBytes,
        responseBytes: transport.responseBytes,
        contentBytes: transport.contentBytes,
        transportEvidenceSchemaBytes,
        actualReturnedModel: transport.actualReturnedModel,
        httpStatus: transport.httpStatus,
        contentType: transport.contentType,
        networkAttemptCount,
        startedAt,
        finishedAt,
        artifactPaths,
      });
    const transportEvidenceBytes = Buffer.from(
      JSON.stringify(transportEvidence),
      "utf8",
    );
    const transportArtifacts = {
      "bundle.json": trustedReviewBundleBytes,
      "request.json": request.requestBytes,
      "response.json": transport.responseBytes,
      "content.json": transport.contentBytes,
      "material.v2.utf8": trustedMaterialBytes,
      "transport-evidence.json": transportEvidenceBytes,
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
      materialSchemaBytes,
      transportEvidenceSchemaBytes,
      materialSectionDescriptors: material.sections,
      runtimeManifestBytes,
      requestBytes: request.requestBytes,
      responseBytes: transport.responseBytes,
      contentBytes: transport.contentBytes,
      transportEvidence,
      transportEvidenceBytes,
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
      materialSchemaBytes,
      transportEvidenceSchemaBytes,
      materialSectionDescriptors: material.sections,
      runtimeManifestBytes,
      requestBytes: request.requestBytes,
      responseBytes: transport.responseBytes,
      contentBytes: transport.contentBytes,
      transportEvidence,
      transportEvidenceBytes,
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
    if (isK3) {
      error.tokenEstimateAttemptCount = tokenEstimateAttemptCount;
      error.chatCompletionAttemptCount = chatCompletionAttemptCount;
    }
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
