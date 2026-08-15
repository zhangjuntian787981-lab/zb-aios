#!/usr/bin/env node

import { execFile, execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  assertIndependentReviewGitCollectionUnchanged,
  parseIndependentReviewJsonBytes,
  parseIndependentReviewTapSummary,
  tapSummaryMatchesExpectation,
  validateIndependentReviewSchemaInstance,
  validateIndependentReviewTestEvidenceClosure,
  validateIndependentReviewTestPlan,
} from "../lib/independent-model-review.mjs";
import {
  sha256ProjectValue,
} from "../lib/project-control.mjs";
import {
  captureIndependentReviewRuntimeBinding,
  independentReviewRuntimeBinding,
  serializeIndependentReviewRuntimeBinding,
} from "../lib/independent-review-runtime-binding.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const MAX_OUTPUT = 64 * 1024 * 1024;
const PROCESS_GROUP_EXIT_WAIT_MS = 2000;
const PROCESS_GROUP_EXIT_POLL_MS = 10;
const PROCESS_SNAPSHOT_TIMEOUT_MS = 2000;
const PROCESS_SNAPSHOT_MAX_BUFFER = 1024 * 1024;
const RUNNER_PATH = "scripts/run-independent-review-test-evidence.mjs";
const RUNTIME_BINDING_GENERATOR_PATH =
  "lib/independent-review-runtime-binding.mjs";
const TEST_SANDBOX_POLICY_PATH =
  "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in";
const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const SANDBOX_VERSION =
  "isolation=macos-sandbox-exec-git-archive-readonly-history-network-denied";
const NETWORK_TEST_MODE =
  "network-test-mode=frozen-deterministic-offline-alternatives";
const FORMAL_NPM_TEST_SCRIPT =
  "npm run build && node --test --test-reporter=tap tests/*.test.mjs";
const FORMAL_NPM_SCRIPT_CLOSURE = Object.freeze({
  test: FORMAL_NPM_TEST_SCRIPT,
  build:
    "npm run f02:gate:prebuild && npm run build:app && npm run f02:gate:release",
  "build:app": "WRANGLER_LOG_PATH=.wrangler/wrangler.log vinext build",
  "postbuild:app": "npm run p2:verify:worker-bundle",
  "f02:gate:prebuild":
    "node scripts/f02-protected-surface-gate.mjs --stage PREBUILD",
  "f02:gate:release":
    "node scripts/f02-protected-surface-gate.mjs --stage RELEASE",
  "p2:verify:worker-bundle":
    "node scripts/verify-p2-worker-runtime-bundle.mjs",
  lint: "eslint . --ignore-pattern dist --ignore-pattern .next",
});
const FORBIDDEN_NPM_LIFECYCLE_SCRIPTS = Object.freeze(
  Object.keys(FORMAL_NPM_SCRIPT_CLOSURE)
    .flatMap((name) => [`pre${name}`, `post${name}`])
    .filter((name) => name !== "postbuild:app")
    .sort(),
);

function rebuildFormalTestEvidence({
  testPlan,
  staticInputs,
  evidenceByName,
  sourceCommit,
  sourceTree,
}) {
  const rows = testPlan.commands.map((command) => {
    const outputRef = `${command.commandId}.result.json`;
    const artifact = evidenceByName.get(outputRef);
    const result = parseIndependentReviewJsonBytes(artifact.bytes, outputRef);
    const { runtimeBinding, executionSource: { sandbox } } = result;
    const toolVersions = [
      SANDBOX_VERSION,
      NETWORK_TEST_MODE,
      ...[
        ["runtime-binding", runtimeBinding.bindingSha256],
        ["node-executable", runtimeBinding.nodeExecutableSha256],
        ["dependency-set", runtimeBinding.dependencySetSha256],
        ["git-toolchain", runtimeBinding.gitToolchainSha256],
        ["system-toolchain", runtimeBinding.systemToolchainSha256],
        ["sandbox-template", sandbox.templateSha256],
        ["sandbox-invocation", sandbox.invocationSha256],
      ].map((pair) => pair.join("=")),
    ];
    return {
      command,
      result,
      summary: {
        evidenceId: command.commandId,
        command: `${command.executable} ${command.args.join(" ")}`,
        status: "PASS",
        exitCode: 0,
        outputRef,
        outputSha256: artifact.rawSha256,
        outputByteLength: artifact.byteLength,
        truncated: false,
        sourceCommit,
        runner: "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE",
        toolVersions,
      },
    };
  });
  const [plan, collector, resultSchema, sandboxPolicy, generator] = staticInputs;
  const generatorMatches = rows.every(({ result }) =>
    result.runtimeBinding.generator.path === generator.path &&
    result.runtimeBinding.generator.gitBlobSha256 === generator.rawSha256 &&
    result.runtimeBinding.generator.executedBytesSha256 === generator.rawSha256
  );
  const commandSummaries = rows.map(({ command, result }) => {
    const summary = result.testSummary;
    return {
      commandId: command.commandId,
      tests: summary?.tests ?? null,
      pass: summary?.pass ?? null,
      fail: summary?.fail ?? null,
      skipped: summary?.skipped ?? null,
      argvSha256: result.argvSha256,
      allowedSkippedTestSetSha256: summary?.skippedTestSetSha256 ?? null,
    };
  });
  return {
    rows,
    generatorMatches,
    commandSummaries,
    bundle: {
      source: { sourceCommit, tree: sourceTree },
      artifacts: {
        testPlanSha256: plan.rawSha256,
        testEvidenceCollectorPath: collector.path,
        testEvidenceCollectorSha256: collector.rawSha256,
        testResultSchemaPath: resultSchema.path,
        testResultSchemaSha256: resultSchema.rawSha256,
        sandboxPolicyTemplatePath: sandboxPolicy.path,
        sandboxPolicyTemplateSha256: sandboxPolicy.rawSha256,
      },
      testEvidenceSubjects: rows.map(({ summary }) => summary),
    },
  };
}

export async function validateFormalTestEvidenceForEnvelope(input) {
  const rebuilt = rebuildFormalTestEvidence(input);
  const packageBoundaryValid = validateIndependentReviewNpmPackageBoundary({
    packageJson: input.packageJson,
    projectNpmrcPaths: input.projectNpmrcPaths,
  });
  const closure = await validateIndependentReviewTestEvidenceClosure({
    bundle: rebuilt.bundle,
    testPlanBytes: input.staticInputs[0].bytes,
    collectorBytes: input.staticInputs[1].bytes,
    testResultSchemaBytes: input.staticInputs[2].bytes,
    sandboxPolicyTemplateBytes: input.staticInputs[3].bytes,
    evidenceResolver: async (name) => input.evidenceByName.get(name)?.bytes,
  });
  return {
    ok: rebuilt.generatorMatches && packageBoundaryValid && closure.ok,
    bundle: rebuilt.bundle,
    commandSummaries: rebuilt.commandSummaries,
  };
}

export function parseGitPatchRanges(bytes) {
  const oldRanges = [];
  const newRanges = [];
  const hunks = bytes.toString().matchAll(
    /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/gmu,
  );
  for (const match of hunks) {
    for (const [target, start, length] of [
      [oldRanges, +match[1], +(match[2] ?? 1)],
      [newRanges, +match[3], +(match[4] ?? 1)],
    ]) {
      if (length > 0) target.push([start, start + length - 1]);
    }
  }
  return { oldRanges, newRanges };
}

export function buildFindingCoverageIndex({
  generatedEnvelopePath,
  envelopeSha256,
  fullFiles,
  patches,
  digestSubjects,
}) {
  return [
    {
      path: generatedEnvelopePath,
      evidenceMode: "VERBATIM_FULL_FILE",
      evidenceDigest: envelopeSha256,
      lineCount: 1,
    },
    ...fullFiles.map((item) => ({
      path: item.path,
      evidenceMode: "VERBATIM_FULL_FILE",
      evidenceDigest: item.rawSha256,
      lineCount:
        item.bytes.toString().split("\n").length -
        (item.bytes.at(-1) === 10 ? 1 : 0),
    })),
    ...patches.map((item) => ({
      path: item.path,
      evidenceMode: "VERBATIM_PATCH",
      evidenceDigest: item.rawSha256,
      oldRanges: item.oldRanges,
      newRanges: item.newRanges,
    })),
    ...digestSubjects.map((item) => ({
      path: item.path,
      evidenceMode: "DIGEST_ONLY_SUMMARY",
      evidenceDigest: item.rawSha256,
    })),
  ];
}

export function buildDigestOnlyTestCoverage({
  contract,
  testSubjects,
  repositoryTestPaths,
  materialPaths,
}) {
  const testPaths = contract.testPaths;
  const { repositoryBlobCount, ...testCounts } = contract.counts;
  const testWhitelist = {
    pathSetSha256: contract.sets.tests,
    ...testCounts,
    subjects: testSubjects.map(({ path, gitMode, byteLength, rawSha256 }) => ({
      path,
      gitMode,
      byteLength,
      rawSha256,
    })),
    purposeAssignments: contract.purposes,
  };
  const testWhitelistValid =
    repositoryTestPaths.length === repositoryBlobCount &&
    testPaths.length === testCounts.includedBlobCount &&
    hashBytes(Buffer.from(`${[...testPaths].sort().join("\n")}\n`)) ===
      contract.sets.tests &&
    Buffer.byteLength(JSON.stringify(testWhitelist)) <=
      contract.caps.testWhitelist;
  const subjectPaths = new Set([
    ...contract.full,
    ...contract.patch,
    ...testPaths,
    ...contract.digestSubjects.map(([path]) => path),
  ]);
  const subjectSetValid = [...materialPaths, ...contract.anchors].every((path) =>
    subjectPaths.has(path),
  );
  return { testWhitelist, testWhitelistValid, subjectSetValid };
}

export async function envelopeSchemaMatches({ envelope, schema, expectedSha256 }) {
  return schema.rawSha256 === expectedSha256 &&
    (await validateIndependentReviewSchemaInstance({
      schemaBytes: schema.bytes,
      expectedSchemaSha256: expectedSha256,
      instance: envelope,
      label: "Envelope",
    })).ok;
}

function requiredCheckError(reason) {
  throw new TypeError(`INDEPENDENT_MODEL_REVIEW_${reason}`);
}

function requiredCheckGitBytes(repository, args, maximumBytes) {
  return execFileSync(
    "/usr/bin/git",
    ["--no-replace-objects", "-C", repository, ...args],
    {
      encoding: "buffer",
      env: {
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        PATH: "/usr/bin:/bin",
      },
      maxBuffer: maximumBytes,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
}

const requiredCheckGitText = (repository, args, maximumBytes) =>
  requiredCheckGitBytes(repository, args, maximumBytes).toString("utf8").trim();

function requiredCheckCommitMetadata(repository, commit) {
  const [parent, tree] = requiredCheckGitText(
    repository,
    ["show", "-s", "--format=%P%x00%T", commit],
    256,
  ).split("\0");
  if (!COMMIT.test(parent) || !COMMIT.test(tree)) {
    requiredCheckError("TOPOLOGY_INVALID");
  }
  return { commit, parent, tree };
}

function requiredCheckChanges(repository, parent, commit) {
  const fields = requiredCheckGitBytes(
    repository,
    ["diff", "--name-status", "-z", "--no-renames", parent, commit],
    1 << 20,
  ).toString().split("\0").filter(Boolean);
  if (fields.length % 2 !== 0) requiredCheckError("CHANGE_SET_INVALID");
  return Array.from({ length: fields.length / 2 }, (_, index) => ({
    status: fields[index * 2],
    path: fields[index * 2 + 1],
  })).sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
}

function requiredCheckPathSet(paths) {
  return hashBytes(Buffer.from(`${[...paths].sort().join("\n")}\n`));
}

function requireExactChanges({
  repository,
  parent,
  commit,
  count,
  expectedPathSet,
  statuses,
  prefix = "",
}) {
  const changes = requiredCheckChanges(repository, parent, commit);
  const paths = changes.map(({ path }) => path);
  if (
    changes.length !== count ||
    requiredCheckPathSet(paths) !== expectedPathSet ||
    changes.map(({ status }) => status).join("") !== statuses ||
    paths.some((path) => !path.startsWith(prefix))
  ) {
    requiredCheckError("COMMIT_SCOPE_INVALID");
  }
  return changes;
}

function requiredCheckSubject(repository, commit, path) {
  const row = requiredCheckGitText(
    repository,
    ["ls-tree", commit, "--", `:(literal)${path}`],
    1024,
  ).split(/\s+/u);
  if (row[0] !== "100644" || row[1] !== "blob") requiredCheckError("FROZEN_PATH_INVALID");
  const byteLength = +requiredCheckGitText(repository, ["cat-file", "-s", row[2]], 64);
  if (byteLength > 1 << 20) requiredCheckError("FROZEN_SIZE_INVALID");
  const bytes = requiredCheckGitBytes(repository, ["cat-file", "blob", row[2]], (1 << 20) + 1);
  if (bytes.length !== byteLength) requiredCheckError("FROZEN_SIZE_CHANGED");
  return { path, gitMode: "100644", byteLength, rawSha256: hashBytes(bytes), bytes };
}

function containsFrozenReference(bytes, ...values) {
  return values.some((value) => bytes.includes(Buffer.from(value)));
}

export async function prepareRequiredCheckEnvelopeInputs({
  repository,
  expectedHead,
  expectedTree,
  expectedBase,
  materialPaths,
  contractPath,
  contractSha256,
}) {
  const contractSubject = requiredCheckSubject(repository, expectedHead, contractPath);
  const match = /<!-- REQUIRED_CHECK_ENVELOPE_CONTRACT_V1\n(\{[^\n]+\})\n-->/u.exec(
    contractSubject.bytes.toString(),
  );
  if (contractSubject.rawSha256 !== contractSha256 || !match) requiredCheckError("CONTRACT_INVALID");
  const contract = parseIndependentReviewJsonBytes(
    Buffer.from(match[1]),
    "Required Check contract",
    64 * 1024,
  );
  const gitObject = (expression) => requiredCheckGitText(
    repository,
    ["rev-parse", "--verify", expression],
    1024,
  );
  if (
    !COMMIT.test(expectedHead) ||
    !COMMIT.test(expectedTree) ||
    !COMMIT.test(expectedBase) ||
    requiredCheckGitText(repository, ["merge-base", expectedBase, contract.parent], 64) !== expectedBase ||
    gitObject(`${expectedHead}^{commit}`) !== expectedHead ||
    gitObject(`${expectedHead}^{tree}`) !== expectedTree
  ) {
    requiredCheckError("GIT_BINDING_INVALID");
  }
  const finalCommit = requiredCheckCommitMetadata(repository, expectedHead);
  const implementation = requiredCheckCommitMetadata(repository, finalCommit.parent);
  const materialParentTree = requiredCheckCommitMetadata(repository, contract.parent).tree;
  if (implementation.parent !== contract.parent) requiredCheckError("PARENT_CHAIN_INVALID");
  const implementationChanges = requireExactChanges({
    repository,
    parent: contract.parent,
    commit: implementation.commit,
    count: 9,
    expectedPathSet: contract.sets.m1a,
    statuses: "AAAAMMMMM",
  });
  const evidenceChanges = requireExactChanges({
    repository,
    parent: implementation.commit,
    commit: finalCommit.commit,
    count: 10,
    expectedPathSet: contract.sets.m1b,
    statuses: "AAAAAAAAAA",
    prefix: `${contract.evidenceRoot}/`,
  });
  const lineage = [];
  for (const [stage, commit] of [
    ...contract.chains,
    ["M1A_IMPLEMENTATION", implementation.commit],
    ["M1B_FORMAL_EVIDENCE", finalCommit.commit],
  ]) {
    const metadata = requiredCheckCommitMetadata(repository, commit);
    const changes = requiredCheckChanges(repository, metadata.parent, commit);
    lineage.push({
      stage,
      parent: metadata.parent,
      commit,
      tree: metadata.tree,
      pathSetSha256: requiredCheckPathSet(changes.map(({ path }) => path)),
      patchSha256: hashBytes(requiredCheckGitBytes(
        repository,
        ["diff", "--binary", metadata.parent, commit],
        1 << 22,
      )),
    });
  }
  const fullFiles = contract.full.map((path) => requiredCheckSubject(repository, expectedHead, path));
  const patches = contract.patch.map((path) => {
    const bytes = requiredCheckGitBytes(
      repository,
      ["diff", "--no-ext-diff", "--no-renames", "--binary", "--unified=8",
        contract.parent, implementation.commit, "--", `:(literal)${path}`],
      contract.caps.patch + 1,
    );
    const limit = path.startsWith("scripts/") ? contract.caps.scriptPatch : contract.caps.libPatch;
    if (bytes.length > limit) requiredCheckError("PATCH_BUDGET_EXCEEDED");
    return {
      path,
      baseCommit: contract.parent,
      headCommit: implementation.commit,
      byteLength: bytes.length,
      rawSha256: hashBytes(bytes),
      bytes,
      ...parseGitPatchRanges(bytes),
    };
  });
  const fullFileByteLength = fullFiles.reduce((total, item) => total + item.byteLength, 0);
  const patchByteLength = patches.reduce((total, item) => total + item.byteLength, 0);
  if (fullFileByteLength > contract.caps.full || patchByteLength > contract.caps.patch) {
    requiredCheckError("VERBATIM_BUDGET_EXCEEDED");
  }
  for (const { path } of implementationChanges) {
    if (containsFrozenReference(
      requiredCheckSubject(repository, implementation.commit, path).bytes,
      implementation.commit,
      implementation.tree,
    )) requiredCheckError("M1A_SELF_REFERENCE");
  }
  const testSubjects = contract.testPaths.map((path) => requiredCheckSubject(repository, expectedHead, path));
  const repositoryTestPaths = requiredCheckGitBytes(
    repository,
    ["ls-tree", "-r", "-z", "--name-only", expectedHead, "--", "tests"],
    128 * 1024,
  ).toString().split("\0").filter(Boolean);
  const coverage = buildDigestOnlyTestCoverage({
    contract,
    testSubjects,
    repositoryTestPaths,
    materialPaths,
  });
  if (!coverage.testWhitelistValid) requiredCheckError("TEST_WHITELIST_INVALID");
  const staticInputs = contract.static.map((path) =>
    requiredCheckSubject(repository, implementation.commit, path));
  const evidenceFiles = evidenceChanges.map(({ path }) =>
    requiredCheckSubject(repository, expectedHead, path));
  for (const item of evidenceFiles) {
    if (containsFrozenReference(item.bytes, expectedHead, finalCommit.tree)) {
      requiredCheckError("M1B_SELF_REFERENCE");
    }
  }
  const evidenceByName = new Map(evidenceFiles.map((item) =>
    [item.path.slice(contract.evidenceRoot.length + 1), item]));
  const testPlan = parseIndependentReviewJsonBytes(staticInputs[0].bytes, "test plan");
  const projectNpmrcPaths = requiredCheckGitBytes(
    repository,
    ["ls-tree", "-z", "--name-only", implementation.commit],
    128 * 1024,
  ).toString().split("\0").filter((path) => path.toLowerCase() === ".npmrc");
  const formalEvidence = await validateFormalTestEvidenceForEnvelope({
    testPlan,
    staticInputs,
    evidenceByName,
    sourceCommit: implementation.commit,
    sourceTree: implementation.tree,
    packageJson: parseIndependentReviewJsonBytes(staticInputs[5].bytes, "package.json"),
    projectNpmrcPaths,
  });
  if (!formalEvidence.ok) requiredCheckError("TEST_EVIDENCE_MISMATCH");
  if (!coverage.subjectSetValid) requiredCheckError("SUBJECT_SET_INVALID");
  const digestSubjects = contract.digestSubjects.map(([path, origin]) => {
    const originCommit = origin === "M1A" ? implementation.commit : origin;
    const item = {...requiredCheckSubject(repository, expectedHead, path), originCommit};
    if (item.rawSha256 !== requiredCheckSubject(repository, originCommit, path).rawSha256) {
      requiredCheckError("SUBJECT_DRIFT");
    }
    return item;
  });
  const reviewBinding = {
    eventBaseCommit: expectedBase,
    materialParentCommit: contract.parent,
    materialParentTree,
    implementationCommit: implementation.commit,
    implementationTree: implementation.tree,
    finalHead: finalCommit.commit,
    finalTree: finalCommit.tree,
    implementationPathSetSha256: contract.sets.m1a,
    evidencePathSetSha256: contract.sets.m1b,
    coverageMode: contract.mode,
  };
  return {
    contract,
    reviewBinding,
    lineage,
    testWhitelist: coverage.testWhitelist,
    commandSummaries: formalEvidence.commandSummaries,
    staticInputs,
    evidenceFiles,
    digestSubjects,
    findingDigestSubjects: [...testSubjects, ...staticInputs, ...evidenceFiles, ...digestSubjects],
    fullFiles,
    patches,
    fullFileByteLength,
    patchByteLength,
  };
}
const DEVELOPER_TOOLCHAIN_ROOT =
  "/Library/Developer/CommandLineTools";
const SYSTEM_GIT_SHIM = "/usr/bin/git";
const SYSTEM_XCRUN = "/usr/bin/xcrun";
const SYSTEM_SHASUM = "/usr/bin/shasum";
const SYSTEM_PERL = "/usr/bin/perl";
const BUILD_OUTPUT_DIRS = Object.freeze([
  ".next",
  ".vinext",
  ".wrangler",
  "dist",
]);
const WRITABLE_WORK_ROOTS = Object.freeze([
  ...BUILD_OUTPUT_DIRS,
  "node_modules/.vite-temp",
]);
const RESERVED_SOURCE_ROOTS = new Set([
  ...BUILD_OUTPUT_DIRS,
  ".git",
  "node_modules",
]);
const frozenXcrunEnvironment =
  process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
    "DENY_ALL_OFFLINE_ALTERNATIVES" &&
  typeof process.env.xcrun_db === "string" &&
  process.env.xcrun_db.startsWith("/") &&
  !process.env.xcrun_db.includes("\0")
    ? Object.freeze({ xcrun_db: process.env.xcrun_db })
    : Object.freeze({});

const hashBytes = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

function attachErrorList(error, property, errors) {
  if (
    errors.length === 0 ||
    (typeof error !== "object" && typeof error !== "function") ||
    error === null
  ) {
    return;
  }
  const existing = Array.isArray(error[property]) ? error[property] : [];
  try {
    Object.defineProperty(error, property, {
      configurable: true,
      value: [...existing, ...errors],
      writable: true,
    });
  } catch {
    // Preserve the primary error object even when it is non-extensible.
  }
}

function setErrorProperty(error, property, value) {
  if (
    (typeof error !== "object" && typeof error !== "function") ||
    error === null
  ) {
    return;
  }
  try {
    Object.defineProperty(error, property, {
      configurable: true,
      value,
      writable: true,
    });
  } catch {
    // Preserve the primary error object even when it is non-extensible.
  }
}

function collectCleanupErrors(error, errors, seen) {
  if (seen.has(error)) return;
  seen.add(error);
  errors.push(error);
  if (
    (typeof error === "object" || typeof error === "function") &&
    error !== null &&
    Array.isArray(error.cleanupErrors)
  ) {
    for (const cleanupError of error.cleanupErrors) {
      collectCleanupErrors(cleanupError, errors, seen);
    }
  }
}

export async function runIndependentReviewLifecycle({
  operation,
  cleanupOperations,
}) {
  if (
    typeof operation !== "function" ||
    !Array.isArray(cleanupOperations) ||
    cleanupOperations.some((cleanup) => typeof cleanup !== "function")
  ) {
    throw new TypeError("Independent review lifecycle is invalid.");
  }
  let operationFailed = false;
  let primaryError;
  let result;
  try {
    result = await operation();
  } catch (error) {
    operationFailed = true;
    primaryError = error;
  }
  const cleanupErrors = [];
  const seenCleanupErrors = new Set();
  for (const cleanup of cleanupOperations) {
    try {
      await cleanup();
    } catch (error) {
      collectCleanupErrors(error, cleanupErrors, seenCleanupErrors);
    }
  }
  if (operationFailed) {
    attachErrorList(primaryError, "cleanupErrors", cleanupErrors);
    if (cleanupErrors.length > 0) {
      setErrorProperty(
        primaryError,
        "independentReviewCleanupFailed",
        true,
      );
    }
    throw primaryError;
  }
  if (cleanupErrors.length > 0) {
    const cleanupFailure = new TypeError(
      "INDEPENDENT_REVIEW_CLEANUP_FAILED",
      { cause: cleanupErrors[0] },
    );
    cleanupFailure.reasonCodes = [
      "INDEPENDENT_REVIEW_CLEANUP_FAILED",
    ];
    attachErrorList(cleanupFailure, "cleanupErrors", cleanupErrors);
    cleanupFailure.independentReviewCleanupFailed = true;
    throw cleanupFailure;
  }
  return result;
}

const wait = (milliseconds) =>
  new Promise((resolveWait) => setTimeout(resolveWait, milliseconds));

function terminateProcessGroup(processId) {
  if (!Number.isInteger(processId) || processId <= 0) return;
  try {
    process.kill(-processId, "SIGKILL");
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

async function descendantProcessIds(processId) {
  if (!Number.isInteger(processId) || processId <= 0) return [];
  const { stdout } = await execFileAsync(
    "/bin/ps",
    ["-axo", "pid=,ppid="],
    {
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      maxBuffer: PROCESS_SNAPSHOT_MAX_BUFFER,
      timeout: PROCESS_SNAPSHOT_TIMEOUT_MS,
    },
  );
  const childrenByParent = new Map();
  for (const line of stdout.split("\n")) {
    const [pid, parentPid] = line.trim().split(/\s+/u).map(Number);
    if (!Number.isInteger(pid) || !Number.isInteger(parentPid)) continue;
    const children = childrenByParent.get(parentPid) ?? [];
    children.push(pid);
    childrenByParent.set(parentPid, children);
  }
  const descendants = [];
  const pending = [processId];
  const seen = new Set(pending);
  while (pending.length > 0) {
    const parentPid = pending.shift();
    for (const childPid of childrenByParent.get(parentPid) ?? []) {
      if (seen.has(childPid)) continue;
      seen.add(childPid);
      descendants.push(childPid);
      pending.push(childPid);
    }
  }
  return descendants;
}

async function terminateProcessTree(processId) {
  const errors = [];
  let descendants = [];
  try {
    descendants = await descendantProcessIds(processId);
  } catch (error) {
    errors.push(error);
  }
  for (const descendant of [...descendants].reverse()) {
    try {
      process.kill(descendant, "SIGKILL");
    } catch (error) {
      if (error?.code !== "ESRCH") errors.push(error);
    }
  }
  try {
    terminateProcessGroup(processId);
  } catch (error) {
    errors.push(error);
  }
  return { descendants, errors };
}

async function waitForProcessTreeExit(processId, descendants) {
  if (!Number.isInteger(processId) || processId <= 0) return;
  const deadline = Date.now() + PROCESS_GROUP_EXIT_WAIT_MS;
  while (true) {
    let processGroupRunning = false;
    try {
      process.kill(-processId, 0);
      processGroupRunning = true;
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
    const remainingDescendants = [];
    for (const descendant of descendants) {
      try {
        process.kill(descendant, 0);
        remainingDescendants.push(descendant);
      } catch (error) {
        if (error?.code !== "ESRCH") throw error;
      }
    }
    if (!processGroupRunning && remainingDescendants.length === 0) return;
    if (Date.now() >= deadline) {
      const error = new Error(
        "Independent review process tree did not exit after SIGKILL.",
      );
      error.code = "INDEPENDENT_REVIEW_PROCESS_TREE_STILL_RUNNING";
      error.remainingProcessIds = remainingDescendants;
      throw error;
    }
    await wait(PROCESS_GROUP_EXIT_POLL_MS);
  }
}

export function executeIndependentReviewProcessGroup(file, args, options) {
  if (
    typeof file !== "string" ||
    file.length === 0 ||
    !Array.isArray(args) ||
    !args.every((argument) => typeof argument === "string") ||
    options === null ||
    typeof options !== "object"
  ) {
    throw new TypeError("Independent review command is invalid.");
  }
  const { cwd, encoding, env, maxBuffer, timeout } = options;
  if (
    encoding !== "buffer" ||
    !Number.isInteger(maxBuffer) ||
    maxBuffer <= 0 ||
    !Number.isInteger(timeout) ||
    timeout <= 0
  ) {
    throw new TypeError("Independent review command timeout is invalid.");
  }
  return new Promise((resolveExecution, rejectExecution) => {
    let processId = null;
    let timeoutHandle = null;
    let primaryError = null;
    let settled = false;
    let stdoutByteLength = 0;
    let stderrByteLength = 0;
    const stdoutChunks = [];
    const stderrChunks = [];
    const processGroupErrors = [];
    let termination = null;
    const stopProcessTree = () => {
      termination ??= terminateProcessTree(processId);
      return termination;
    };
    const recordOutput = (streamName, chunk) => {
      const bytes = Buffer.from(chunk);
      const currentByteLength =
        streamName === "stdout" ? stdoutByteLength : stderrByteLength;
      const remaining = Math.max(0, maxBuffer - currentByteLength);
      if (remaining > 0) {
        const captured = bytes.subarray(0, remaining);
        if (streamName === "stdout") {
          stdoutChunks.push(captured);
          stdoutByteLength += captured.byteLength;
        } else {
          stderrChunks.push(captured);
          stderrByteLength += captured.byteLength;
        }
      }
      if (bytes.byteLength > remaining && primaryError === null) {
        primaryError = new RangeError(
          `${streamName} exceeded the independent review output limit.`,
        );
        primaryError.code = "ERR_CHILD_PROCESS_STDIO_MAXBUFFER";
        if (timeoutHandle !== null) clearTimeout(timeoutHandle);
        void stopProcessTree();
      }
    };
    const child = spawn(file, args, {
      cwd,
      detached: true,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    processId = child.pid;
    child.stdout.on("data", (chunk) => recordOutput("stdout", chunk));
    child.stderr.on("data", (chunk) => recordOutput("stderr", chunk));
    child.once("error", (error) => {
      primaryError ??= error;
    });
    child.once("exit", (exitCode, signal) => {
      if (timeoutHandle !== null) clearTimeout(timeoutHandle);
      if (primaryError === null && (exitCode !== 0 || signal !== null)) {
        primaryError = new Error(
          `Independent review command failed with exit code ${String(exitCode)}.`,
        );
        primaryError.code = exitCode;
        primaryError.killed = false;
        primaryError.signal = signal;
      }
      void stopProcessTree();
    });
    child.once("close", () => {
      if (settled) return;
      settled = true;
      void (async () => {
        if (timeoutHandle !== null) clearTimeout(timeoutHandle);
        const terminated = await stopProcessTree();
        processGroupErrors.push(...terminated.errors);
        try {
          await waitForProcessTreeExit(processId, terminated.descendants);
        } catch (processGroupError) {
          processGroupErrors.push(processGroupError);
        }
        const stdout = Buffer.concat(stdoutChunks, stdoutByteLength);
        const stderr = Buffer.concat(stderrChunks, stderrByteLength);
        if (primaryError) {
          primaryError.stdout = stdout;
          primaryError.stderr = stderr;
          if (processGroupErrors.length > 0) {
            attachErrorList(
              primaryError,
              "processGroupErrors",
              processGroupErrors,
            );
            primaryError.processGroupTerminationFailed = true;
          }
          rejectExecution(primaryError);
          return;
        }
        if (processGroupErrors.length > 0) {
          const [processGroupPrimaryError, ...remainingProcessGroupErrors] =
            processGroupErrors;
          attachErrorList(
            processGroupPrimaryError,
            "processGroupErrors",
            remainingProcessGroupErrors,
          );
          processGroupPrimaryError.stdout = stdout;
          processGroupPrimaryError.stderr = stderr;
          processGroupPrimaryError.processGroupTerminationFailed = true;
          rejectExecution(processGroupPrimaryError);
          return;
        }
        resolveExecution({ stdout, stderr });
      })().catch(rejectExecution);
    });
    timeoutHandle = setTimeout(() => {
      if (primaryError === null) {
        primaryError = new Error(
          `Independent review command timed out after ${timeout} ms.`,
        );
        primaryError.killed = true;
        primaryError.signal = "SIGKILL";
      }
      void stopProcessTree();
    }, timeout);
  });
}

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

function transcriptContainsActiveMoonshotCredential(stdout, stderr) {
  const credential = process.env.MOONSHOT_API_KEY;
  if (typeof credential !== "string" || credential.length === 0) {
    return false;
  }
  const credentialBytes = Buffer.from(credential, "utf8");
  return (
    Buffer.from(stdout).includes(credentialBytes) ||
    Buffer.from(stderr).includes(credentialBytes)
  );
}

async function validatePlan(plan) {
  if (!(await validateIndependentReviewTestPlan(plan))) {
    throw new TypeError("Independent review test plan is invalid.");
  }
}

export function validateIndependentReviewNpmPackageBoundary({
  packageJson,
  projectNpmrcPaths,
}) {
  return (
    packageJson !== null &&
    typeof packageJson === "object" &&
    !Array.isArray(packageJson) &&
    packageJson.scripts !== null &&
    typeof packageJson.scripts === "object" &&
    !Array.isArray(packageJson.scripts) &&
    Array.isArray(projectNpmrcPaths) &&
    projectNpmrcPaths.length === 0 &&
    Object.entries(FORMAL_NPM_SCRIPT_CLOSURE).every(
      ([name, command]) => packageJson.scripts[name] === command,
    ) &&
    FORBIDDEN_NPM_LIFECYCLE_SCRIPTS.every(
      (name) => !Object.hasOwn(packageJson.scripts, name),
    )
  );
}

function asciiCaseFold(value) {
  return value.replace(/[A-Z]/gu, (character) =>
    String.fromCharCode(character.charCodeAt(0) + 32),
  );
}

async function gitBytes(repoPath, sourceCommit, path) {
  const { stdout } = await execFileAsync(
    "/usr/bin/git",
    [
      "--no-replace-objects",
      "-C",
      repoPath,
      "cat-file",
      "blob",
      `${sourceCommit}:${path}`,
    ],
    {
      encoding: "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
        GIT_OPTIONAL_LOCKS: "0",
        ...frozenXcrunEnvironment,
      },
      maxBuffer: MAX_OUTPUT,
    },
  );
  return Buffer.from(stdout);
}

async function git(repoPath, args, options = {}) {
  return execFileAsync(
    "/usr/bin/git",
    ["--no-replace-objects", "-C", repoPath, ...args],
    {
      encoding: options.encoding ?? "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
        GIT_OPTIONAL_LOCKS: "0",
        ...frozenXcrunEnvironment,
      },
      maxBuffer: MAX_OUTPUT,
    },
  );
}

async function expectedGitSourceRecords(repoPath, sourceCommit) {
  const { stdout } = await git(repoPath, [
    "ls-tree",
    "-r",
    "-z",
    "--full-tree",
    sourceCommit,
  ]);
  const raw = Buffer.from(stdout);
  const records = [];
  let offset = 0;
  let previousPathBytes = null;
  while (offset < raw.byteLength) {
    const terminator = raw.indexOf(0, offset);
    if (terminator === -1) {
      throw new TypeError("Git tree output is not NUL terminated.");
    }
    const recordBytes = raw.subarray(offset, terminator);
    offset = terminator + 1;
    const tab = recordBytes.indexOf(9);
    if (tab === -1) {
      throw new TypeError("Git tree record is malformed.");
    }
    const header = recordBytes.subarray(0, tab).toString("ascii");
    const match =
      /^(100644|100755|120000) blob ([a-f0-9]{40})$/u.exec(header);
    if (!match) {
      throw new TypeError(
        "Git tree contains an unsupported entry type.",
      );
    }
    const pathBytes = recordBytes.subarray(tab + 1);
    let path;
    try {
      path = new TextDecoder("utf-8", { fatal: true }).decode(pathBytes);
    } catch {
      throw new TypeError("Git tree path is not valid UTF-8.");
    }
    const root = path.split("/", 1)[0];
    if (
      !SAFE_PATH.test(path) ||
      RESERVED_SOURCE_ROOTS.has(root) ||
      (previousPathBytes && Buffer.compare(previousPathBytes, pathBytes) >= 0)
    ) {
      throw new TypeError(
        "Git tree path is unsafe, duplicated, or reserved.",
      );
    }
    previousPathBytes = Buffer.from(pathBytes);
    const bytes = await gitBytes(repoPath, sourceCommit, path);
    records.push({
      path,
      type: match[1] === "120000" ? "SYMLINK" : "FILE",
      gitMode: match[1],
      byteLength: bytes.byteLength,
      sha256: hashBytes(bytes),
    });
  }
  if (records.length === 0) {
    throw new TypeError("Git source tree is empty.");
  }
  return records;
}

async function actualSourceRecords(rootPath) {
  const entries = [];
  const visit = async (directory, relativeDirectory = "") => {
    const children = (await readdir(directory, { withFileTypes: true })).sort(
      ({ name: left }, { name: right }) =>
        Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
    );
    for (const child of children) {
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${child.name}`
        : child.name;
      if (
        relativeDirectory === "" &&
        RESERVED_SOURCE_ROOTS.has(child.name)
      ) {
        continue;
      }
      const absolutePath = join(directory, child.name);
      const metadata = await lstat(absolutePath);
      if (child.isDirectory()) {
        await visit(absolutePath, relativePath);
      } else if (child.isSymbolicLink()) {
        const bytes = await readlink(absolutePath, { encoding: "buffer" });
        entries.push({
          path: relativePath,
          type: "SYMLINK",
          gitMode: "120000",
          byteLength: bytes.byteLength,
          sha256: hashBytes(bytes),
        });
      } else if (child.isFile()) {
        const bytes = await readFile(absolutePath);
        entries.push({
          path: relativePath,
          type: "FILE",
          gitMode: metadata.mode & 0o111 ? "100755" : "100644",
          byteLength: bytes.byteLength,
          sha256: hashBytes(bytes),
        });
      } else {
        throw new TypeError(
          "Git archive contains an unsupported filesystem entry.",
        );
      }
    }
  };
  await visit(rootPath);
  entries.sort(({ path: left }, { path: right }) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (
    entries.some(({ path }) => !SAFE_PATH.test(path)) ||
    new Set(entries.map(({ path }) => path)).size !== entries.length
  ) {
    throw new TypeError(
      "Git archive contains an unsafe or duplicated path.",
    );
  }
  return entries;
}

async function filesystemManifest(rootPath) {
  const records = [];
  const visit = async (directory, relativeDirectory = "") => {
    const children = (await readdir(directory, { withFileTypes: true })).sort(
      ({ name: left }, { name: right }) =>
        Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
    );
    for (const child of children) {
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${child.name}`
        : child.name;
      if (!SAFE_PATH.test(relativePath)) {
        throw new TypeError("Git history metadata path is unsafe.");
      }
      const absolutePath = join(directory, child.name);
      const metadata = await lstat(absolutePath);
      if (child.isDirectory()) {
        records.push({
          path: relativePath,
          type: "DIRECTORY",
          mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
          byteLength: 0,
          sha256: hashBytes(Buffer.alloc(0)),
        });
        await visit(absolutePath, relativePath);
        continue;
      }
      let bytes;
      if (child.isFile()) {
        if (metadata.nlink !== 1) {
          throw new TypeError("Git history contains a hard-linked file.");
        }
        bytes = await readFile(absolutePath);
      } else if (child.isSymbolicLink()) {
        throw new TypeError("Git history contains a symbolic link.");
      } else {
        throw new TypeError("Git history contains a special file.");
      }
      records.push({
        path: relativePath,
        type: "FILE",
        mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
        byteLength: bytes.byteLength,
        sha256: hashBytes(bytes),
      });
    }
  };
  await visit(rootPath);
  records.sort(({ path: left }, { path: right }) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (records.length === 0) {
    throw new TypeError("Git history metadata is empty.");
  }
  return sha256ProjectValue(records);
}

async function reachableGitObjects(repoPath, rootObjectIds) {
  if (
    !Array.isArray(rootObjectIds) ||
    rootObjectIds.length === 0 ||
    rootObjectIds.length > 4097 ||
    rootObjectIds.some((objectId) => !COMMIT.test(objectId))
  ) {
    throw new TypeError("Git reachable roots are invalid.");
  }
  const { stdout } = await git(repoPath, [
    "rev-list",
    "--objects",
    "--no-object-names",
    ...[...new Set(rootObjectIds)].sort(),
  ]);
  const objects = Buffer.from(stdout)
    .toString("ascii")
    .trim()
    .split("\n")
    .filter(Boolean)
    .sort();
  if (
    objects.length === 0 ||
    objects.some((objectId) => !COMMIT.test(objectId)) ||
    new Set(objects).size !== objects.length
  ) {
    throw new TypeError("Git reachable object set is invalid.");
  }
  return objects;
}

async function exactGitRefTips(repoPath) {
  const { stdout } = await git(repoPath, [
    "for-each-ref",
    "--sort=refname",
    "--format=%(refname)%00%(objectname)%00",
  ]);
  const fields = Buffer.from(stdout)
    .toString("utf8")
    .split("\0")
    .map((value) => value.replace(/^\n+|\n+$/gu, ""))
    .filter(Boolean);
  if (
    fields.length === 0 ||
    fields.length % 2 !== 0 ||
    fields.length / 2 > 4096
  ) {
    throw new TypeError("Git ref-tip set is invalid.");
  }
  const records = [];
  for (let index = 0; index < fields.length; index += 2) {
    const refName = fields[index];
    const objectId = fields[index + 1];
    if (
      !/^refs\/[^\u0000-\u001f ~^:?*[\\]+$/u.test(refName) ||
      !COMMIT.test(objectId)
    ) {
      throw new TypeError("Git ref-tip record is invalid.");
    }
    records.push({ refName, objectId });
  }
  if (
    new Set(records.map(({ refName }) => refName)).size !== records.length ||
    JSON.stringify(records) !==
      JSON.stringify(
        [...records].sort(({ refName: left }, { refName: right }) =>
          Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
        ),
      )
  ) {
    throw new TypeError("Git ref-tip ordering is invalid.");
  }
  return records;
}

async function allGitObjects(repoPath) {
  const { stdout } = await git(repoPath, [
    "cat-file",
    "--batch-all-objects",
    "--batch-check=%(objectname)",
  ]);
  const objects = Buffer.from(stdout)
    .toString("ascii")
    .trim()
    .split("\n")
    .filter(Boolean)
    .sort();
  if (
    objects.length === 0 ||
    objects.some((objectId) => !COMMIT.test(objectId)) ||
    new Set(objects).size !== objects.length
  ) {
    throw new TypeError("Git object inventory is invalid.");
  }
  return objects;
}

async function assertNoGitObjectAlternates(gitHistoryRoot) {
  for (const name of ["alternates", "http-alternates"]) {
    try {
      await lstat(resolve(gitHistoryRoot, "objects", "info", name));
      throw new TypeError("Git history uses an external object alternate.");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
}

async function gitDirectory(gitDirectory, args) {
  return execFileAsync(
    "/usr/bin/git",
    [
      "--no-replace-objects",
      `--git-dir=${gitDirectory}`,
      ...args,
    ],
    {
      encoding: "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
        GIT_OPTIONAL_LOCKS: "0",
        ...frozenXcrunEnvironment,
      },
      maxBuffer: MAX_OUTPUT,
    },
  );
}

async function makeDirectoryTreeReadOnly(rootPath) {
  const visit = async (directory) => {
    const children = await readdir(directory, { withFileTypes: true });
    for (const child of children) {
      const absolutePath = join(directory, child.name);
      if (child.isDirectory()) {
        await visit(absolutePath);
        await chmod(absolutePath, 0o555);
      } else if (child.isFile()) {
        const metadata = await lstat(absolutePath);
        await chmod(
          absolutePath,
          metadata.mode & 0o111 ? 0o555 : 0o444,
        );
      }
    }
  };
  await visit(rootPath);
  await chmod(rootPath, 0o555);
}

async function createGitHistorySnapshot({
  repoPath,
  parent,
  source,
  sourceCommit,
  sourceTree,
  expectedXcrunCacheSha256,
  expectedRefTips,
  expectedObjects,
}) {
  const requestedGitHistoryRoot = resolve(parent, "git-history");
  const refTipsBefore = await exactGitRefTips(repoPath);
  await assertIndependentReviewGitCollectionUnchanged(
    expectedRefTips,
    refTipsBefore,
  );
  const rootObjectIds = [
    sourceCommit,
    ...expectedRefTips.map(({ objectId }) => objectId),
  ];
  if (
    JSON.stringify(
      await reachableGitObjects(repoPath, rootObjectIds),
    ) !== JSON.stringify(expectedObjects)
  ) {
    throw new TypeError(
      "Independent review reachable object set changed during collection.",
    );
  }
  await mkdir(requestedGitHistoryRoot, { mode: 0o700 });
  const gitHistoryRoot = await realpath(requestedGitHistoryRoot);
  await gitDirectory(gitHistoryRoot, ["init", "--bare", "-q"]);
  await gitDirectory(gitHistoryRoot, [
    "fetch",
    "--no-tags",
    "--no-write-fetch-head",
    repoPath,
    ...[...new Set(rootObjectIds)]
      .sort()
      .map(
        (objectId, index) =>
          `+${objectId}:refs/review-snapshot/${String(index).padStart(4, "0")}`,
      ),
  ]);
  await gitDirectory(gitHistoryRoot, [
    "update-ref",
    "refs/heads/review-source",
    sourceCommit,
  ]);
  await gitDirectory(gitHistoryRoot, [
    "symbolic-ref",
    "HEAD",
    "refs/heads/review-source",
  ]);
  await gitDirectory(gitHistoryRoot, ["config", "core.bare", "false"]);
  await gitDirectory(gitHistoryRoot, [
    "config",
    "core.worktree",
    source,
  ]);
  await gitDirectory(gitHistoryRoot, ["read-tree", sourceCommit]);

  const { stdout: cachePathStdout } = await execFileAsync(
    SYSTEM_XCRUN,
    ["--show-cache-path"],
    {
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
        ...frozenXcrunEnvironment,
      },
      maxBuffer: 1024 * 1024,
    },
  );
  const xcrunCacheSource = cachePathStdout.trim();
  const xcrunDb = resolve(gitHistoryRoot, "xcrun_db");
  await copyFile(xcrunCacheSource, xcrunDb);
  if (hashBytes(await readFile(xcrunDb)) !== expectedXcrunCacheSha256) {
    throw new TypeError("Frozen xcrun cache bytes changed.");
  }

  const pointerBytes = Buffer.from(
    `gitdir: ${gitHistoryRoot}\n`,
    "utf8",
  );
  await writeFile(resolve(source, ".git"), pointerBytes, { mode: 0o400 });

  const refTipsAfter = await exactGitRefTips(repoPath);
  await assertIndependentReviewGitCollectionUnchanged(
    expectedRefTips,
    refTipsAfter,
  );
  const actualObjects = await reachableGitObjects(source, rootObjectIds);
  const allObjects = await allGitObjects(source);
  const { stdout: actualTreeBytes } = await git(source, [
    "rev-parse",
    `${sourceCommit}^{tree}`,
  ]);
  if (
    JSON.stringify(actualObjects) !== JSON.stringify(expectedObjects) ||
    JSON.stringify(allObjects) !== JSON.stringify(expectedObjects) ||
    Buffer.from(actualTreeBytes).toString("utf8").trim() !== sourceTree
  ) {
    throw new TypeError("Read-only Git history snapshot is incomplete.");
  }
  await assertNoGitObjectAlternates(gitHistoryRoot);

  await makeDirectoryTreeReadOnly(gitHistoryRoot);
  return {
    root: gitHistoryRoot,
    xcrunDb,
    rootObjectIds,
    binding: {
      mode: "READ_ONLY_ALL_REF_REACHABLE_OBJECT_SNAPSHOT",
      sourceCommit,
      sourceTree,
      refTipCount: expectedRefTips.length,
      refTipSetSha256: await sha256ProjectValue(expectedRefTips),
      reachableObjectCount: expectedObjects.length,
      reachableObjectSetSha256:
        await sha256ProjectValue(expectedObjects),
      pointerSha256: hashBytes(pointerBytes),
      beforeManifestSha256:
        await filesystemManifest(gitHistoryRoot),
      afterManifestSha256: `sha256:${"0".repeat(64)}`,
      unchanged: false,
      metadataWritable: false,
    },
  };
}

async function finishGitHistorySnapshot(source, gitHistory) {
  const pointerBytes = await readFile(resolve(source, ".git"));
  const actualObjects = await reachableGitObjects(
    source,
    gitHistory.rootObjectIds,
  );
  const allObjects = await allGitObjects(source);
  return {
    ...gitHistory.binding,
    reachableObjectCount: actualObjects.length,
    reachableObjectSetSha256: await sha256ProjectValue(actualObjects),
    pointerSha256: hashBytes(pointerBytes),
    afterManifestSha256:
      await filesystemManifest(gitHistory.root),
    unchanged:
      hashBytes(pointerBytes) === gitHistory.binding.pointerSha256 &&
      actualObjects.length ===
        gitHistory.binding.reachableObjectCount &&
      JSON.stringify(allObjects) === JSON.stringify(actualObjects) &&
      (await sha256ProjectValue(actualObjects)) ===
        gitHistory.binding.reachableObjectSetSha256 &&
      (await filesystemManifest(gitHistory.root)) ===
        gitHistory.binding.beforeManifestSha256,
  };
}

async function executionSnapshot(
  rootPath,
  sourceCommit,
  sourceTree,
  expectedRecords,
) {
  const actualRecords = await actualSourceRecords(rootPath);
  if (JSON.stringify(actualRecords) !== JSON.stringify(expectedRecords)) {
    throw new TypeError(
      "Git archive bytes do not match the frozen source tree.",
    );
  }
  return {
    head: sourceCommit,
    tree: sourceTree,
    sourceManifestSha256: await sha256ProjectValue(expectedRecords),
  };
}

async function validateExecutionInfrastructure({
  source,
  dependencyRoot,
  dependencyOverlayEntries,
  gitHistory,
}) {
  const gitPointerPath = resolve(source, ".git");
  const gitPointerMetadata = await lstat(gitPointerPath);
  const gitPointerBytes = await readFile(gitPointerPath);
  if (
    !gitPointerMetadata.isFile() ||
    gitPointerMetadata.isSymbolicLink() ||
    hashBytes(gitPointerBytes) !== gitHistory.binding.pointerSha256 ||
    (await realpath(gitHistory.root)) !== gitHistory.root ||
    !(await lstat(gitHistory.root)).isDirectory()
  ) {
    throw new TypeError("Read-only Git history binding is invalid.");
  }
  for (const buildOutput of BUILD_OUTPUT_DIRS) {
    const path = resolve(source, buildOutput);
    const metadata = await lstat(path);
    const exactPath = await realpath(path);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      exactPath !== path ||
      !exactPath.startsWith(`${source}${sep}`)
    ) {
      throw new TypeError("Build output root escaped the source export.");
    }
  }
  const dependencyLink = resolve(source, "node_modules");
  if (dependencyRoot === null) {
    try {
      await lstat(dependencyLink);
      throw new TypeError("Unexpected node_modules exists in source export.");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    return;
  }
  const metadata = await lstat(dependencyLink);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    (await realpath(dependencyLink)) !== dependencyLink
  ) {
    throw new TypeError("Dependency overlay is invalid.");
  }
  const children = (await readdir(dependencyLink, {
    withFileTypes: true,
  })).sort(({ name: left }, { name: right }) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (
    JSON.stringify(children.map(({ name }) => name)) !==
      JSON.stringify([".vite-temp", ...dependencyOverlayEntries].sort()) ||
    !children.find(({ name }) => name === ".vite-temp")?.isDirectory()
  ) {
    throw new TypeError("Dependency overlay entries are invalid.");
  }
  for (const name of dependencyOverlayEntries) {
    const entry = children.find((child) => child.name === name);
    if (
      !entry?.isSymbolicLink() ||
      (await realpath(resolve(dependencyLink, name))) !==
        (await realpath(resolve(dependencyRoot, name)))
    ) {
      throw new TypeError("Dependency overlay target is invalid.");
    }
  }
  const viteTempPath = resolve(dependencyLink, ".vite-temp");
  const viteTempMetadata = await lstat(viteTempPath);
  if (
    !viteTempMetadata.isDirectory() ||
    viteTempMetadata.isSymbolicLink() ||
    (await realpath(viteTempPath)) !== viteTempPath
  ) {
    throw new TypeError("Vite temporary output root is invalid.");
  }
}

async function makeSourceReadOnly(rootPath) {
  const visit = async (directory, relativeDirectory = "") => {
    const children = await readdir(directory, { withFileTypes: true });
    for (const child of children) {
      if (
        relativeDirectory === "" &&
        (child.name === "node_modules" ||
          BUILD_OUTPUT_DIRS.includes(child.name))
      ) {
        continue;
      }
      const absolutePath = join(directory, child.name);
      if (child.isDirectory()) {
        await visit(absolutePath, relativeDirectory
          ? `${relativeDirectory}/${child.name}`
          : child.name);
        await chmod(absolutePath, 0o755);
      } else if (child.isFile()) {
        const metadata = await lstat(absolutePath);
        await chmod(
          absolutePath,
          metadata.mode & 0o111 ? 0o555 : 0o444,
        );
      }
    }
  };
  await visit(rootPath);
  await chmod(rootPath, 0o755);
}

async function makeSourceDisposable(rootPath) {
  const errors = [];
  const visit = async (path) => {
    let metadata;
    try {
      metadata = await lstat(path);
    } catch (error) {
      if (error?.code === "ENOENT") return;
      errors.push(error);
      return;
    }
    if (metadata.isSymbolicLink()) return;
    if (metadata.isDirectory()) {
      try {
        await chmod(path, 0o700);
      } catch (error) {
        errors.push(error);
      }
      let children;
      try {
        children = await readdir(path, { withFileTypes: true });
      } catch (error) {
        errors.push(error);
        return;
      }
      for (const child of children) {
        await visit(join(path, child.name));
      }
    } else if (metadata.isFile()) {
      try {
        await chmod(path, 0o600);
      } catch (error) {
        errors.push(error);
      }
    }
  };
  await visit(rootPath);
  if (errors.length > 0) {
    const [primaryError, ...remainingErrors] = errors;
    attachErrorList(primaryError, "cleanupErrors", remainingErrors);
    throw primaryError;
  }
}

async function removeOwnedRoot(rootPath) {
  const errors = [];
  try {
    await makeSourceDisposable(rootPath);
  } catch (error) {
    errors.push(error);
  }
  try {
    await rm(rootPath, { recursive: true, force: true });
  } catch (error) {
    errors.push(error);
  }
  try {
    await lstat(rootPath);
    const error = new Error("Independent review temporary root remains.");
    error.code = "INDEPENDENT_REVIEW_TEMPORARY_ROOT_REMAINS";
    errors.push(error);
  } catch (error) {
    if (error?.code !== "ENOENT") errors.push(error);
  }
  if (errors.length > 0) {
    const [primaryError, ...remainingErrors] = errors;
    attachErrorList(primaryError, "cleanupErrors", remainingErrors);
    throw primaryError;
  }
}

async function isolatedSourceExport(
  repoPath,
  sourceCommit,
  sourceTree,
  expectedXcrunCacheSha256,
  expectedRefTips,
  expectedObjects,
) {
  const parent = await mkdtemp(
    join(
      tmpdir(),
      `zb-independent-review-test-export-${sourceCommit}-`,
    ),
  );
  const source = join(parent, "source");
  const archive = join(parent, "source.tar");
  try {
    const expectedRecords = await expectedGitSourceRecords(
      repoPath,
      sourceCommit,
    );
    const { stdout: actualTreeBytes } = await git(repoPath, [
      "rev-parse",
      `${sourceCommit}^{tree}`,
    ]);
    const actualTree = Buffer.from(actualTreeBytes)
      .toString("utf8")
      .trim();
    if (actualTree !== sourceTree) {
      throw new TypeError("Git source tree does not match sourceCommit.");
    }
    await mkdir(source, { mode: 0o700 });
    await execFileAsync(
      "/usr/bin/git",
      [
        "--no-replace-objects",
        "-C",
        repoPath,
        "archive",
        "--format=tar",
        `--output=${archive}`,
        sourceCommit,
      ],
      {
        encoding: "buffer",
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_SYSTEM: "/dev/null",
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_ATTR_NOSYSTEM: "1",
          GIT_OPTIONAL_LOCKS: "0",
          ...frozenXcrunEnvironment,
        },
        maxBuffer: MAX_OUTPUT,
      },
    );
    await execFileAsync("/usr/bin/tar", ["-xf", archive, "-C", source], {
      encoding: "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
      },
      maxBuffer: MAX_OUTPUT,
    });
    await rm(archive, { force: true });
    try {
      await lstat(resolve(source, ".npmrc"));
      throw new TypeError(
        "Git archive contains a case-aliased project npm configuration.",
      );
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    for (const buildOutput of BUILD_OUTPUT_DIRS) {
      const target = resolve(source, buildOutput);
      try {
        await lstat(target);
        throw new TypeError(
          "A reserved build-output path is tracked by sourceCommit.",
        );
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
      await mkdir(target, { mode: 0o700 });
    }
    let dependencyRoot = null;
    let dependencyOverlayEntries = [];
    const dependencyCandidate = resolve(repoPath, "node_modules");
    const dependencyOverlay = resolve(source, "node_modules");
    try {
      await lstat(dependencyOverlay);
      throw new TypeError("Git archive contains a reserved node_modules.");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    try {
      const dependencyMetadata = await stat(dependencyCandidate);
      if (!dependencyMetadata.isDirectory()) {
        throw new TypeError("Repository node_modules is not a directory.");
      }
      dependencyRoot = await realpath(dependencyCandidate);
      dependencyOverlayEntries = (
        await readdir(dependencyRoot, { withFileTypes: true })
      )
        .map(({ name }) => name)
        .filter((name) => name !== ".vite-temp")
        .sort((left, right) =>
          Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
        );
      if (
        dependencyOverlayEntries.length === 0 ||
        dependencyOverlayEntries.some(
          (name) =>
            name.length === 0 ||
            name === "." ||
            name === ".." ||
            name.includes("/") ||
            name.includes("\u0000"),
        )
      ) {
        throw new TypeError("Dependency overlay source is invalid.");
      }
      await mkdir(dependencyOverlay, { mode: 0o700 });
      for (const name of dependencyOverlayEntries) {
        await symlink(
          resolve(dependencyRoot, name),
          resolve(dependencyOverlay, name),
        );
      }
      await mkdir(resolve(dependencyOverlay, ".vite-temp"), {
        mode: 0o700,
      });
      await chmod(dependencyOverlay, 0o555);
    } catch (error) {
      // A frozen command that needs dependencies will fail closed without them.
      if (error?.code !== "ENOENT") throw error;
    }
    const exactSource = await realpath(source);
    const gitHistory = await createGitHistorySnapshot({
      repoPath,
      parent,
      source: exactSource,
      sourceCommit,
      sourceTree,
      expectedXcrunCacheSha256,
      expectedRefTips,
      expectedObjects,
    });
    await validateExecutionInfrastructure({
      source: exactSource,
      dependencyRoot,
      dependencyOverlayEntries,
      gitHistory,
    });
    await makeSourceReadOnly(exactSource);
    const before = await executionSnapshot(
      exactSource,
      sourceCommit,
      sourceTree,
      expectedRecords,
    );
    return {
      parent,
      source: exactSource,
      dependencyRoot,
      dependencyOverlayEntries,
      gitHistory,
      expectedRecords,
      before,
    };
  } catch (error) {
    return runIndependentReviewLifecycle({
      operation: async () => {
        throw error;
      },
      cleanupOperations: [
        () => removeOwnedRoot(source),
        () => removeOwnedRoot(resolve(parent, "git-history")),
        () => removeOwnedRoot(parent),
      ],
    });
  }
}

function executableFor(symbol) {
  if (symbol === "NODE") return process.execPath;
  if (symbol === "NPM") {
    return resolve(dirname(process.execPath), "npm");
  }
  throw new TypeError("Unknown independent review test executable.");
}

async function executeSandboxedCommand({
  isolated,
  command,
  sandboxTemplateBytes,
}) {
  if (!(await stat(SANDBOX_EXEC)).isFile()) {
    throw new TypeError(
      "macOS sandbox-exec is required for independent review tests.",
    );
  }
  const scratchRoot = await mkdtemp(
    join(tmpdir(), "zb-independent-review-test-scratch-"),
  );
  let npmConfigRoot = null;
  const operation = async () => {
    npmConfigRoot = await mkdtemp(
      join(isolated.parent, "npm-config-"),
    );
    const exactScratchRoot = await realpath(scratchRoot);
    const exactNpmConfigRoot = await realpath(npmConfigRoot);
    const npmUserConfig = resolve(exactNpmConfigRoot, "user.npmrc");
    const npmGlobalConfig = resolve(exactNpmConfigRoot, "global.npmrc");
    const emptyNpmConfigBytes = Buffer.alloc(0);
    await Promise.all([
      writeFile(npmUserConfig, emptyNpmConfigBytes, { mode: 0o400 }),
      writeFile(npmGlobalConfig, emptyNpmConfigBytes, { mode: 0o400 }),
    ]);
    await chmod(exactNpmConfigRoot, 0o500);
    const npmConfigSha256 = hashBytes(emptyNpmConfigBytes);
    const assertNpmConfigsUnchanged = async () => {
      const [userBytes, globalBytes] = await Promise.all([
        readFile(npmUserConfig),
        readFile(npmGlobalConfig),
      ]);
      if (
        hashBytes(userBytes) !== npmConfigSha256 ||
        hashBytes(globalBytes) !== npmConfigSha256
      ) {
        throw new TypeError(
          "Frozen npm configuration changed during test execution.",
        );
      }
    };
    const exactNodeRuntimeRoot = await realpath(
      resolve(dirname(process.execPath), ".."),
    );
    const sandboxTemplate = new TextDecoder("utf-8", { fatal: true }).decode(
      sandboxTemplateBytes,
    );
    if (
      sandboxTemplate.length === 0 ||
      sandboxTemplateBytes.byteLength > 64 * 1024
    ) {
      throw new TypeError("Frozen test sandbox template is invalid.");
    }
    const dependencyRoot =
      isolated.dependencyRoot ?? exactNodeRuntimeRoot;
    const sandboxTemplateSha256 = hashBytes(sandboxTemplateBytes);
    const sandboxParameterSetSha256 = await sha256ProjectValue({
      WORK_ROOT: hashBytes(Buffer.from(isolated.source, "utf8")),
      TMP_ROOT: hashBytes(Buffer.from(exactScratchRoot, "utf8")),
      NODE_RUNTIME_ROOT: hashBytes(
        Buffer.from(exactNodeRuntimeRoot, "utf8"),
      ),
      DEPENDENCY_ROOT: hashBytes(Buffer.from(dependencyRoot, "utf8")),
      GIT_HISTORY_ROOT: hashBytes(
        Buffer.from(isolated.gitHistory.root, "utf8"),
      ),
      XCRUN_DB: hashBytes(
        Buffer.from(isolated.gitHistory.xcrunDb, "utf8"),
      ),
      SYSTEM_GIT_SHIM: hashBytes(
        Buffer.from(SYSTEM_GIT_SHIM, "utf8"),
      ),
      SYSTEM_XCRUN: hashBytes(Buffer.from(SYSTEM_XCRUN, "utf8")),
      SYSTEM_SHASUM: hashBytes(Buffer.from(SYSTEM_SHASUM, "utf8")),
      SYSTEM_PERL: hashBytes(Buffer.from(SYSTEM_PERL, "utf8")),
      DEVELOPER_TOOLCHAIN_ROOT: hashBytes(
        Buffer.from(DEVELOPER_TOOLCHAIN_ROOT, "utf8"),
      ),
      WRITABLE_WORK_ROOTS: await sha256ProjectValue(
        WRITABLE_WORK_ROOTS,
      ),
      NPM_USER_CONFIG: hashBytes(
        Buffer.from(npmUserConfig, "utf8"),
      ),
      NPM_USER_CONFIG_SHA256: npmConfigSha256,
      NPM_GLOBAL_CONFIG: hashBytes(Buffer.from(npmGlobalConfig, "utf8")),
      NPM_GLOBAL_CONFIG_SHA256: npmConfigSha256,
      NPM_SCRIPT_SHELL: hashBytes(Buffer.from("/bin/sh", "utf8")),
      NPM_NODE_OPTIONS: hashBytes(Buffer.alloc(0)),
    });
    const sandboxInvocationSha256 = await sha256ProjectValue({
      executable: SANDBOX_EXEC,
      templateSha256: sandboxTemplateSha256,
      parameterSetSha256: sandboxParameterSetSha256,
    });
    const sandboxBinding = {
      templateSha256: sandboxTemplateSha256,
      parameterSetSha256: sandboxParameterSetSha256,
      invocationSha256: sandboxInvocationSha256,
    };
    let executionFailed = false;
    let executionError;
    let result;
    try {
      result = await executeIndependentReviewProcessGroup(
        SANDBOX_EXEC,
        [
          "-D",
          `WORK_ROOT=${isolated.source}`,
          "-D",
          `TMP_ROOT=${exactScratchRoot}`,
          "-D",
          `NODE_RUNTIME_ROOT=${exactNodeRuntimeRoot}`,
          "-D",
          `DEPENDENCY_ROOT=${dependencyRoot}`,
          "-D",
          `GIT_HISTORY_ROOT=${isolated.gitHistory.root}`,
          "-D",
          `NPM_USER_CONFIG=${npmUserConfig}`,
          "-D",
          `NPM_GLOBAL_CONFIG=${npmGlobalConfig}`,
          "-D",
          `XCRUN_DB=${isolated.gitHistory.xcrunDb}`,
          "-D",
          `SYSTEM_GIT_SHIM=${SYSTEM_GIT_SHIM}`,
          "-D",
          `SYSTEM_XCRUN=${SYSTEM_XCRUN}`,
          "-D",
          `SYSTEM_SHASUM=${SYSTEM_SHASUM}`,
          "-D",
          `SYSTEM_PERL=${SYSTEM_PERL}`,
          "-D",
          `DEVELOPER_TOOLCHAIN_ROOT=${DEVELOPER_TOOLCHAIN_ROOT}`,
          "-p",
          sandboxTemplate,
          executableFor(command.executable),
          ...command.args,
        ],
        {
          cwd: isolated.source,
          encoding: "buffer",
          env: {
            PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
            LANG: "C",
            LC_ALL: "C",
            HOME: exactScratchRoot,
            TMPDIR: exactScratchRoot,
            TMP: exactScratchRoot,
            TEMP: exactScratchRoot,
            XDG_CACHE_HOME: exactScratchRoot,
            DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
            xcrun_db: isolated.gitHistory.xcrunDb,
            npm_config_cache: exactScratchRoot,
            npm_config_userconfig: npmUserConfig,
            npm_config_globalconfig: npmGlobalConfig,
            npm_config_script_shell: "/bin/sh",
            npm_config_node_options: "",
            npm_config_ignore_scripts: "false",
            npm_config_prefix: resolve(exactScratchRoot, "prefix"),
            npm_config_audit: "false",
            npm_config_fund: "false",
            npm_config_update_notifier: "false",
            CI: "1",
            INDEPENDENT_REVIEW_NETWORK_MODE:
              "DENY_ALL_OFFLINE_ALTERNATIVES",
            WRANGLER_SEND_METRICS: "false",
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_SYSTEM: "/dev/null",
            GIT_CONFIG_GLOBAL: "/dev/null",
            GIT_ATTR_NOSYSTEM: "1",
            GIT_OPTIONAL_LOCKS: "0",
          },
          maxBuffer: MAX_OUTPUT,
          timeout: command.timeoutMs,
        },
      );
    } catch (error) {
      executionFailed = true;
      executionError = error;
    }
    let npmConfigError = null;
    try {
      await assertNpmConfigsUnchanged();
    } catch (error) {
      npmConfigError = error;
    }
    if (executionFailed) {
      executionError.sandboxBinding = sandboxBinding;
      if (npmConfigError) {
        attachErrorList(
          executionError,
          "postconditionErrors",
          [npmConfigError],
        );
      }
      throw executionError;
    }
    if (npmConfigError) {
      npmConfigError.sandboxBinding = sandboxBinding;
      throw npmConfigError;
    }
    return { ...result, sandboxBinding };
  };
  return runIndependentReviewLifecycle({
    operation,
    cleanupOperations: [
      () => removeOwnedRoot(scratchRoot),
      () =>
        npmConfigRoot === null
          ? undefined
          : removeOwnedRoot(npmConfigRoot),
    ],
  });
}

export async function collectIndependentReviewTestEvidence({
  repoPath,
  sourceCommit,
  sourceTree,
  planPath,
  evidenceRoot,
}) {
  if (!COMMIT.test(sourceCommit) || !COMMIT.test(sourceTree)) {
    throw new TypeError("Test evidence requires exact Git source bindings.");
  }
  const [
    planBytes,
    frozenRunnerBytes,
    executedRunnerBytes,
    frozenRuntimeBindingGeneratorBytes,
    executedRuntimeBindingGeneratorBytes,
    sandboxTemplateBytes,
  ] = await Promise.all([
    gitBytes(repoPath, sourceCommit, planPath),
    gitBytes(repoPath, sourceCommit, RUNNER_PATH),
    readFile(fileURLToPath(import.meta.url)),
    gitBytes(repoPath, sourceCommit, RUNTIME_BINDING_GENERATOR_PATH),
    readFile(
      new URL(
        "../lib/independent-review-runtime-binding.mjs",
        import.meta.url,
      ),
    ),
    gitBytes(repoPath, sourceCommit, TEST_SANDBOX_POLICY_PATH),
  ]);
  if (
    hashBytes(frozenRunnerBytes) !== hashBytes(executedRunnerBytes) ||
    hashBytes(frozenRuntimeBindingGeneratorBytes) !==
      hashBytes(executedRuntimeBindingGeneratorBytes)
  ) {
    throw new TypeError("Executed test collector differs from sourceCommit.");
  }
  let plan;
  try {
    plan = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(planBytes),
    );
  } catch {
    throw new TypeError("Independent review test plan is not valid UTF-8 JSON.");
  }
  await validatePlan(plan);
  if (plan.commands.some(({ executable }) => executable === "NPM")) {
    let packageJson;
    let projectNpmrcPaths;
    try {
      const [packageJsonBytes, rootTree] = await Promise.all([
        gitBytes(repoPath, sourceCommit, "package.json"),
        git(repoPath, [
          "ls-tree",
          "-z",
          "--name-only",
          sourceCommit,
        ]),
      ]);
      packageJson = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(packageJsonBytes),
      );
      projectNpmrcPaths = new TextDecoder("utf-8", { fatal: true })
        .decode(Buffer.from(rootTree.stdout))
        .split("\0")
        .filter((name) => asciiCaseFold(name) === ".npmrc");
    } catch {
      throw new TypeError(
        "Frozen npm execution boundary is invalid.",
      );
    }
    if (
      !validateIndependentReviewNpmPackageBoundary({
        packageJson,
        projectNpmrcPaths,
      })
    ) {
      throw new TypeError(
        "Frozen npm execution boundary is invalid.",
      );
    }
  }
  const exactRepoPath = await realpath(resolve(repoPath));
  const exactEvidenceRoot = await realpath(resolve(evidenceRoot));
  if (!(await stat(exactEvidenceRoot)).isDirectory()) {
    throw new TypeError("Test evidence root is not a directory.");
  }
  const overlaps = (left, right) =>
    left === right ||
    left.startsWith(`${right}${sep}`) ||
    right.startsWith(`${left}${sep}`);
  let exactDependencyRoot = null;
  try {
    exactDependencyRoot = await realpath(
      resolve(exactRepoPath, "node_modules"),
    );
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (
    overlaps(exactEvidenceRoot, exactRepoPath) ||
    (exactDependencyRoot !== null &&
      overlaps(exactEvidenceRoot, exactDependencyRoot))
  ) {
    throw new TypeError(
      "Test evidence root overlaps the repository or shared dependencies.",
    );
  }
  const frozenRefTips = await exactGitRefTips(exactRepoPath);
  const frozenRootObjectIds = [
    sourceCommit,
    ...frozenRefTips.map(({ objectId }) => objectId),
  ];
  const frozenReachableObjects = await reachableGitObjects(
    exactRepoPath,
    frozenRootObjectIds,
  );
  const runtimeBinding =
    await captureIndependentReviewRuntimeBinding();
  const runtimeBindingBytes =
    serializeIndependentReviewRuntimeBinding(runtimeBinding);
  const runtimeBindingDescriptor = {
    artifactRef: independentReviewRuntimeBinding.artifactRef,
    artifactSha256: hashBytes(runtimeBindingBytes),
    artifactByteLength: runtimeBindingBytes.byteLength,
    bindingSha256: runtimeBinding.bindingSha256,
    nodeExecutableSha256: runtimeBinding.nodeExecutable.sha256,
    dependencySetSha256: runtimeBinding.dependencySetSha256,
    gitToolchainSha256: runtimeBinding.gitToolchain.bindingSha256,
    systemToolchainSha256:
      runtimeBinding.systemToolchain.bindingSha256,
    generator: {
      path: RUNTIME_BINDING_GENERATOR_PATH,
      gitBlobSha256: hashBytes(frozenRuntimeBindingGeneratorBytes),
      executedBytesSha256: hashBytes(executedRuntimeBindingGeneratorBytes),
    },
  };
  await writeFile(
    resolve(
      exactEvidenceRoot,
      independentReviewRuntimeBinding.artifactRef,
    ),
    runtimeBindingBytes,
    { mode: 0o600 },
  );
  const summaries = [];

  for (const command of plan.commands) {
    const isolated = await isolatedSourceExport(
      repoPath,
      sourceCommit,
      sourceTree,
      runtimeBinding.gitToolchain.xcrunCache.sha256,
      frozenRefTips,
      frozenReachableObjects,
    );
    const isolatedCleanupOperations = [
      () => removeOwnedRoot(isolated.source),
      () => removeOwnedRoot(isolated.gitHistory.root),
      () => removeOwnedRoot(isolated.parent),
    ];
    if (
      process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
      "DENY_ALL_OFFLINE_ALTERNATIVES"
    ) {
      const error = new TypeError(
        "NESTED_TEST_COLLECTOR_SEATBELT_UNAVAILABLE",
      );
      error.reasonCodes = ["NESTED_TEST_COLLECTOR_SEATBELT_UNAVAILABLE"];
      await runIndependentReviewLifecycle({
        operation: async () => {
          throw error;
        },
        cleanupOperations: isolatedCleanupOperations,
      });
    }
    const startedAt = new Date().toISOString();
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let exitCode = 0;
    let signal = null;
    let timedOut = false;
    let sandboxBinding = null;
    try {
      const result = await executeSandboxedCommand({
        isolated,
        command,
        sandboxTemplateBytes,
      });
      stdout = Buffer.from(result.stdout);
      stderr = Buffer.from(result.stderr);
      sandboxBinding = result.sandboxBinding;
    } catch (error) {
      if (
        error?.independentReviewCleanupFailed === true ||
        error?.processGroupTerminationFailed === true
      ) {
        await runIndependentReviewLifecycle({
          operation: async () => {
            throw error;
          },
          cleanupOperations: isolatedCleanupOperations,
        });
      }
      stdout = Buffer.from(error?.stdout ?? "");
      stderr = Buffer.from(error?.stderr ?? "");
      exitCode = Number.isInteger(error?.code) ? error.code : 1;
      signal = typeof error?.signal === "string" ? error.signal : null;
      timedOut = error?.killed === true && signal === "SIGKILL";
      sandboxBinding =
        error?.sandboxBinding &&
        typeof error.sandboxBinding === "object"
          ? error.sandboxBinding
          : null;
    }
    if (
      new TextDecoder("utf-8", { fatal: false })
        .decode(stderr)
        .startsWith("sandbox-exec: sandbox_apply:")
    ) {
      const error = new TypeError(
        "NESTED_TEST_COLLECTOR_SEATBELT_UNAVAILABLE",
      );
      error.reasonCodes = [
        "NESTED_TEST_COLLECTOR_SEATBELT_UNAVAILABLE",
      ];
      await runIndependentReviewLifecycle({
        operation: async () => {
          throw error;
        },
        cleanupOperations: isolatedCleanupOperations,
      });
    }
    const finishedAt = new Date().toISOString();
    let after;
    let gitHistoryAfter;
    await runIndependentReviewLifecycle({
      operation: async () => {
        if (transcriptContainsActiveMoonshotCredential(stdout, stderr)) {
          throw new TypeError(
            "Independent review test transcript contains an active credential.",
          );
        }
        after = await executionSnapshot(
          isolated.source,
          sourceCommit,
          sourceTree,
          isolated.expectedRecords,
        );
        gitHistoryAfter = await finishGitHistorySnapshot(
          isolated.source,
          isolated.gitHistory,
        );
        await validateExecutionInfrastructure(isolated);
      },
      cleanupOperations: isolatedCleanupOperations,
    });
    const executionUnchanged =
      JSON.stringify(isolated.before) === JSON.stringify(after) &&
      gitHistoryAfter.unchanged === true;
    const testSummary = Object.hasOwn(command, "testExpectation")
      ? await parseIndependentReviewTapSummary(stdout)
      : null;
    const testExpectationMatched = Object.hasOwn(
      command,
      "testExpectation",
    )
      ? await tapSummaryMatchesExpectation(
          testSummary,
          command.testExpectation,
        )
      : true;
    if (
      JSON.stringify(await captureIndependentReviewRuntimeBinding()) !==
      JSON.stringify(runtimeBinding)
    ) {
      throw new TypeError(
        "Independent review runtime changed during test execution.",
      );
    }
    const stdoutRef = `${command.commandId}.stdout.log`;
    const stderrRef = `${command.commandId}.stderr.log`;
    const resultRef = `${command.commandId}.result.json`;
    await Promise.all([
      writeFile(resolve(exactEvidenceRoot, stdoutRef), stdout, { mode: 0o600 }),
      writeFile(resolve(exactEvidenceRoot, stderrRef), stderr, { mode: 0o600 }),
    ]);
    const result = {
      schemaVersion: "independent-review-test-result.v3",
      evidenceId: command.commandId,
      testPlanSha256: plan.planSha256,
      sourceCommit,
      sourceTree,
      runner: {
        path: RUNNER_PATH,
        gitBlobSha256: hashBytes(frozenRunnerBytes),
        executedBytesSha256: hashBytes(executedRunnerBytes),
      },
      runtimeBinding: structuredClone(runtimeBindingDescriptor),
      executionSource: {
        mode: "MACOS_SEATBELT_GIT_ARCHIVE_READONLY_HISTORY_V3",
        cloneMode:
          "GIT_ARCHIVE_WITH_READ_ONLY_HISTORY_SNAPSHOT",
        before: isolated.before,
        after,
        unchanged: executionUnchanged,
        gitHistory: gitHistoryAfter,
        sourceExportRemoved: true,
        sandbox: {
          executable: SANDBOX_EXEC,
          templatePath: TEST_SANDBOX_POLICY_PATH,
          templateSha256:
            sandboxBinding?.templateSha256 ??
            hashBytes(sandboxTemplateBytes),
          parameterSetSha256:
            sandboxBinding?.parameterSetSha256 ??
            `sha256:${"0".repeat(64)}`,
          invocationSha256:
            sandboxBinding?.invocationSha256 ??
            `sha256:${"0".repeat(64)}`,
          sourceWritable: false,
          buildOutputsWritable: true,
          writableWorkRoots: [...WRITABLE_WORK_ROOTS],
          scratchWritable: true,
          gitMetadataPresent: true,
          gitMetadataWritable: false,
          sharedDependenciesWritable: false,
          networkPolicy: "DENY_ALL",
          networkDependentTestMode:
            "FROZEN_DETERMINISTIC_OFFLINE_ALTERNATIVES",
        },
      },
      commandId: command.commandId,
      argvSha256: await sha256ProjectValue({
        executable: command.executable,
        args: command.args,
      }),
      observation: {
        exitCode,
        signal,
        timedOut,
        startedAt,
        finishedAt,
      },
      testSummary,
      stdoutRef,
      stdoutSha256: hashBytes(stdout),
      stdoutByteLength: stdout.byteLength,
      stderrRef,
      stderrSha256: hashBytes(stderr),
      stderrByteLength: stderr.byteLength,
      resultSha256: `sha256:${"0".repeat(64)}`,
    };
    result.resultSha256 = await sha256ProjectValue(
      withoutField(result, "resultSha256"),
    );
    const resultBytes = Buffer.from(`${JSON.stringify(result)}\n`, "utf8");
    await writeFile(resolve(exactEvidenceRoot, resultRef), resultBytes, {
      mode: 0o600,
    });
    summaries.push({
      evidenceId: result.evidenceId,
      command: `${command.executable} ${command.args.join(" ")}`,
      status:
        result.observation.exitCode === 0 &&
        result.observation.signal === null &&
        result.observation.timedOut === false &&
        executionUnchanged &&
        testExpectationMatched
          ? "PASS"
          : "FAIL",
      exitCode: result.observation.exitCode,
      outputRef: resultRef,
      outputSha256: hashBytes(resultBytes),
      outputByteLength: resultBytes.byteLength,
      truncated: false,
      sourceCommit,
      runner: "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE",
      toolVersions: [
        `node=${process.version}`,
        `runner=${basename(RUNNER_PATH)}`,
        `runtime-binding=${runtimeBinding.bindingSha256}`,
        `node-executable=${runtimeBinding.nodeExecutable.sha256}`,
        `dependency-set=${runtimeBinding.dependencySetSha256}`,
        `git-toolchain=${runtimeBinding.gitToolchain.bindingSha256}`,
        `system-toolchain=${runtimeBinding.systemToolchain.bindingSha256}`,
        SANDBOX_VERSION,
        NETWORK_TEST_MODE,
        `sandbox-template=${result.executionSource.sandbox.templateSha256}`,
        `sandbox-invocation=${result.executionSource.sandbox.invocationSha256}`,
      ],
    });
  }
  await assertIndependentReviewGitCollectionUnchanged(
    frozenRefTips,
    await exactGitRefTips(exactRepoPath),
  );
  if (
    JSON.stringify(
      await reachableGitObjects(exactRepoPath, frozenRootObjectIds),
    ) !== JSON.stringify(frozenReachableObjects)
  ) {
    throw new TypeError(
      "Independent review reachable object set changed during collection.",
    );
  }
  return summaries;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stderr.write(
    `${JSON.stringify({
      code: "INDEPENDENT_REVIEW_TEST_COLLECTOR_LIBRARY_ONLY",
    })}\n`,
  );
  process.exitCode = 2;
}
