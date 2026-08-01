#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const REVIEW_ID = /^imrr_[a-z0-9][a-z0-9_-]{7,127}$/u;
const K3_RUNTIME_MANIFEST_PATH =
  "implementation/governance/independent-review/kimi-runtime-manifest.v5.json";
const RUNTIME_MANIFEST_MODULE_PATH =
  "lib/independent-review-runtime-manifest.mjs";
const RUNNER_PATH = "scripts/run-kimi-independent-review.mjs";
const BOOTSTRAP_PATH = "scripts/bootstrap-kimi-independent-review.mjs";
const LAUNCHER_PATH = "scripts/launch-kimi-independent-review.sh";
const MAX_INPUT_BYTES = 16 * 1024 * 1024;
const cleanEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
});

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function fail(reasonCode) {
  const error = new TypeError(reasonCode);
  error.reasonCodes = [reasonCode];
  throw error;
}

export function bootstrapFailureResult(error) {
  const networkAttemptCount = Number.isSafeInteger(
    error?.networkAttemptCount,
  )
    ? Math.min(2, Math.max(0, error.networkAttemptCount))
    : 0;
  const tokenEstimateAttemptCount = Number.isSafeInteger(
    error?.tokenEstimateAttemptCount,
  )
    ? Math.min(1, Math.max(0, error.tokenEstimateAttemptCount))
    : 0;
  const chatCompletionAttemptCount = Number.isSafeInteger(
    error?.chatCompletionAttemptCount,
  )
    ? Math.min(1, Math.max(0, error.chatCompletionAttemptCount))
    : 0;
  return {
    ok: false,
    status: "BLOCKED",
    reasonCodes: [
      error?.reasonCodes?.[0] ??
        "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
    ],
    networkAttemptCount,
    tokenEstimateAttemptCount,
    chatCompletionAttemptCount,
  };
}

function assertBootstrapEnvironment() {
  const environmentKeys = Object.keys(process.env).sort();
  const allowedEnvironmentKeys = [
    "LANG",
    "LC_ALL",
    "PATH",
    "ZB_KIMI_SANITIZED_LAUNCHER",
  ];
  if (Object.hasOwn(process.env, "__CF_USER_TEXT_ENCODING")) {
    allowedEnvironmentKeys.push("__CF_USER_TEXT_ENCODING");
  }
  if (
    JSON.stringify(environmentKeys) !==
      JSON.stringify(allowedEnvironmentKeys.sort()) ||
    process.env.PATH !== "/usr/bin:/bin" ||
    process.env.LANG !== "C" ||
    process.env.LC_ALL !== "C" ||
    process.env.ZB_KIMI_SANITIZED_LAUNCHER !== "1" ||
    (Object.hasOwn(process.env, "__CF_USER_TEXT_ENCODING") &&
      !/^0x[0-9A-F]+:(?:0x[0-9A-F]+:0x[0-9A-F]+|[0-9]+:[0-9]+)$/u.test(
        process.env.__CF_USER_TEXT_ENCODING,
      )) ||
    Object.hasOwn(process.env, "NODE_OPTIONS") ||
    Object.hasOwn(process.env, "NODE_PATH") ||
    Object.hasOwn(process.env, "MOONSHOT_API_KEY") ||
    process.execArgv.length !== 0
  ) {
    fail("INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED");
  }
}

function parseArguments(values) {
  const allowed = new Set([
    "repo",
    "bundle",
    "material",
    "output-dir",
    "review-id",
    "runtime-commit",
    "runtime-tree",
    "bootstrap-sha256",
    "launcher-sha256",
  ]);
  const result = {};
  for (let index = 0; index < values.length; index += 2) {
    const raw = values[index];
    const value = values[index + 1];
    if (
      typeof raw !== "string" ||
      !raw.startsWith("--") ||
      !allowed.has(raw.slice(2)) ||
      typeof value !== "string" ||
      value.length === 0 ||
      Object.hasOwn(result, raw.slice(2))
    ) {
      fail("KIMI_BOOTSTRAP_ARGUMENTS_INVALID");
    }
    result[raw.slice(2)] = value;
  }
  if (
    values.length !== allowed.size * 2 ||
    Object.keys(result).length !== allowed.size ||
    !REVIEW_ID.test(result["review-id"] ?? "")
  ) {
    fail("KIMI_BOOTSTRAP_ARGUMENTS_INVALID");
  }
  return result;
}

async function git(repoPath, args, encoding = "buffer") {
  return execFileAsync(
    "/usr/bin/git",
    ["--no-replace-objects", "-C", repoPath, ...args],
    {
      encoding,
      env: cleanEnvironment,
      maxBuffer: 64 * 1024 * 1024,
    },
  );
}

async function gitBytes(repoPath, sourceCommit, path) {
  const { stdout } = await git(repoPath, [
    "cat-file",
    "blob",
    `${sourceCommit}:${path}`,
  ]);
  return Buffer.from(stdout);
}

function runtimeTrustFailure() {
  fail("KIMI_RUNTIME_TRUST_NOT_PROVED");
}

export async function validateKimiRuntimeTrustAnchor({
  repoPath,
  subjectCommit,
  subjectTree,
  anchor,
  executingBootstrapPath = fileURLToPath(import.meta.url),
  executingLauncherPath = resolve(
    new URL("../", import.meta.url).pathname,
    LAUNCHER_PATH,
  ),
}) {
  if (
    !anchor ||
    JSON.stringify(Object.keys(anchor).sort()) !==
      JSON.stringify(
        [
          "bootstrapSha256",
          "launcherSha256",
          "runtimeCommit",
          "runtimeTree",
        ].sort(),
      ) ||
    !COMMIT.test(subjectCommit ?? "") ||
    !COMMIT.test(subjectTree ?? "") ||
    !COMMIT.test(anchor.runtimeCommit ?? "") ||
    !COMMIT.test(anchor.runtimeTree ?? "") ||
    !SHA256.test(anchor.bootstrapSha256 ?? "") ||
    !SHA256.test(anchor.launcherSha256 ?? "") ||
    anchor.runtimeCommit === subjectCommit
  ) {
    runtimeTrustFailure();
  }
  try {
    const [
      { stdout: subjectType },
      { stdout: exactSubjectTree },
      { stdout: runtimeType },
      { stdout: exactRuntimeTree },
      frozenBootstrapBytes,
      frozenLauncherBytes,
      executingBootstrapBytes,
      executingLauncherBytes,
    ] = await Promise.all([
      git(repoPath, ["cat-file", "-t", subjectCommit], "utf8"),
      git(repoPath, ["rev-parse", `${subjectCommit}^{tree}`], "utf8"),
      git(repoPath, ["cat-file", "-t", anchor.runtimeCommit], "utf8"),
      git(
        repoPath,
        ["rev-parse", `${anchor.runtimeCommit}^{tree}`],
        "utf8",
      ),
      gitBytes(repoPath, anchor.runtimeCommit, BOOTSTRAP_PATH),
      gitBytes(repoPath, anchor.runtimeCommit, LAUNCHER_PATH),
      readFile(executingBootstrapPath),
      readFile(executingLauncherPath),
    ]);
    await git(
      repoPath,
      [
        "merge-base",
        "--is-ancestor",
        anchor.runtimeCommit,
        subjectCommit,
      ],
      "utf8",
    );
    if (
      subjectType.trim() !== "commit" ||
      runtimeType.trim() !== "commit" ||
      exactSubjectTree.trim() !== subjectTree ||
      exactRuntimeTree.trim() !== anchor.runtimeTree ||
      sha256Bytes(frozenBootstrapBytes) !== anchor.bootstrapSha256 ||
      sha256Bytes(frozenLauncherBytes) !== anchor.launcherSha256 ||
      sha256Bytes(executingBootstrapBytes) !== anchor.bootstrapSha256 ||
      sha256Bytes(executingLauncherBytes) !== anchor.launcherSha256
    ) {
      runtimeTrustFailure();
    }
  } catch (error) {
    if (error?.reasonCodes?.[0] === "KIMI_RUNTIME_TRUST_NOT_PROVED") {
      throw error;
    }
    runtimeTrustFailure();
  }
  return {
    ok: true,
    runtimeCommit: anchor.runtimeCommit,
    runtimeTree: anchor.runtimeTree,
    subjectCommit,
    subjectTree,
    bootstrapSha256: anchor.bootstrapSha256,
    launcherSha256: anchor.launcherSha256,
  };
}

async function boundedRead(path) {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size <= 0 || metadata.size > MAX_INPUT_BYTES) {
    fail("KIMI_BOOTSTRAP_INPUT_INVALID");
  }
  return readFile(path);
}

async function exactSourceCommit(repoPath, bundleBytes) {
  let bundle;
  try {
    bundle = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bundleBytes),
    );
  } catch {
    fail("KIMI_BOOTSTRAP_INPUT_INVALID");
  }
  const sourceCommit = bundle?.source?.sourceCommit;
  const sourceTree = bundle?.source?.tree;
  if (!COMMIT.test(sourceCommit ?? "") || !COMMIT.test(sourceTree ?? "")) {
    fail("KIMI_BOOTSTRAP_SOURCE_CLOSURE_NOT_PROVED");
  }
  const [{ stdout: type }, { stdout: tree }] = await Promise.all([
    git(repoPath, ["cat-file", "-t", sourceCommit], "utf8"),
    git(repoPath, ["rev-parse", `${sourceCommit}^{tree}`], "utf8"),
  ]);
  if (type.trim() !== "commit" || tree.trim() !== sourceTree) {
    fail("KIMI_BOOTSTRAP_SOURCE_CLOSURE_NOT_PROVED");
  }
  return { sourceCommit, sourceTree };
}

async function sourceArchive(repoPath, sourceCommit) {
  const parent = await mkdtemp(join(tmpdir(), "zb-kimi-bootstrap-"));
  const source = join(parent, "source");
  const archive = join(parent, "source.tar");
  try {
    await mkdir(source, { mode: 0o700 });
    await git(repoPath, [
      "archive",
      "--format=tar",
      `--output=${archive}`,
      sourceCommit,
    ]);
    await execFileAsync("/usr/bin/tar", ["-xf", archive, "-C", source], {
      encoding: "buffer",
      env: cleanEnvironment,
      maxBuffer: 64 * 1024 * 1024,
    });
    await rm(archive, { force: true });
    try {
      await lstat(resolve(source, ".git"));
      fail("KIMI_BOOTSTRAP_SOURCE_CLOSURE_NOT_PROVED");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    return { parent, source: await realpath(source) };
  } catch (error) {
    await rm(parent, { recursive: true, force: true });
    throw error;
  }
}

async function runtimePreflight({
  repoPath,
  sourceCommit,
  sourceRoot,
}) {
  const [manifestBytes, frozenManifestBytes, runtimeModuleBytes] =
    await Promise.all([
      readFile(resolve(sourceRoot, K3_RUNTIME_MANIFEST_PATH)),
      gitBytes(repoPath, sourceCommit, K3_RUNTIME_MANIFEST_PATH),
      readFile(resolve(sourceRoot, RUNTIME_MANIFEST_MODULE_PATH)),
    ]);
  if (sha256Bytes(manifestBytes) !== sha256Bytes(frozenManifestBytes)) {
    fail("KIMI_BOOTSTRAP_SOURCE_CLOSURE_NOT_PROVED");
  }
  let expected;
  try {
    expected = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes),
    );
  } catch {
    fail("INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED");
  }
  const runtimeSubject = expected?.source?.localModuleSubjects?.find(
    ({ path }) => path === RUNTIME_MANIFEST_MODULE_PATH,
  );
  if (
    runtimeSubject?.sha256 !== sha256Bytes(runtimeModuleBytes) ||
    runtimeSubject?.byteLength !== runtimeModuleBytes.byteLength
  ) {
    fail("KIMI_BOOTSTRAP_SOURCE_CLOSURE_NOT_PROVED");
  }
  const runtimeModule = await import(
    pathToFileURL(resolve(sourceRoot, RUNTIME_MANIFEST_MODULE_PATH)).href
  );
  if (
    !runtimeModule.validateIndependentReviewRuntimeDependencyManifest(
      expected,
    ).ok
  ) {
    fail("INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED");
  }
  runtimeModule.assertIndependentReviewBootstrapEnvironment({
    requiredExecArgv: [],
  });
  const dependencyRoot = await realpath(resolve(repoPath, "node_modules"));
  const actual =
    await runtimeModule.captureKimiK3IndependentReviewRuntimeDependencyManifestV5({
      sourceRoot,
      dependencyRoot,
      requiredExecArgv: [],
    });
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail("INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED");
  }
  return { runtimeModule, dependencyRoot, expected };
}

export async function runKimiIndependentReviewBootstrap(values) {
  assertBootstrapEnvironment();
  const args = parseArguments(values);
  const repoPath = await realpath(resolve(args.repo));
  const bundleBytes = await boundedRead(resolve(args.bundle));
  const materialBytes = await boundedRead(resolve(args.material));
  const { sourceCommit, sourceTree } =
    await exactSourceCommit(repoPath, bundleBytes);
  const runtimeTrustValidation = await validateKimiRuntimeTrustAnchor({
    repoPath,
    subjectCommit: sourceCommit,
    subjectTree: sourceTree,
    anchor: {
      runtimeCommit: args["runtime-commit"],
      runtimeTree: args["runtime-tree"],
      bootstrapSha256: args["bootstrap-sha256"],
      launcherSha256: args["launcher-sha256"],
    },
  });
  const runtimeTrust = {
    runtimeCommit: runtimeTrustValidation.runtimeCommit,
    runtimeTree: runtimeTrustValidation.runtimeTree,
    subjectCommit: runtimeTrustValidation.subjectCommit,
    subjectTree: runtimeTrustValidation.subjectTree,
    bootstrapSha256: runtimeTrustValidation.bootstrapSha256,
    launcherSha256: runtimeTrustValidation.launcherSha256,
  };
  const isolated = await sourceArchive(
    repoPath,
    runtimeTrust.runtimeCommit,
  );
  try {
    const { dependencyRoot } = await runtimePreflight({
      repoPath,
      sourceCommit: runtimeTrust.runtimeCommit,
      sourceRoot: isolated.source,
    });
    const dependencyLink = resolve(isolated.source, "node_modules");
    try {
      await lstat(dependencyLink);
      fail("KIMI_BOOTSTRAP_SOURCE_CLOSURE_NOT_PROVED");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    await symlink(dependencyRoot, dependencyLink, "dir");
    const runnerModule = await import(
      pathToFileURL(resolve(isolated.source, RUNNER_PATH)).href
    );
    return await runnerModule.runKimiIndependentReviewFromFrozenBootstrap({
      repoPath,
      reviewBundleBytes: bundleBytes,
      reviewMaterialBytes: materialBytes,
      outputDir: args["output-dir"],
      reviewId: args["review-id"],
      runtimeTrust,
    });
  } finally {
    await rm(isolated.parent, { recursive: true, force: true });
  }
}

async function main() {
  const result = await runKimiIndependentReviewBootstrap(
    process.argv.slice(2),
  );
  process.stdout.write(
    `${JSON.stringify({
      ok: result.ok,
      status: result.status,
      conclusion: result.conclusion ?? null,
      reasonCodes: result.reasonCodes,
      networkAttemptCount: result.networkAttemptCount,
      tokenEstimateAttemptCount:
        result.tokenEstimateAttemptCount ?? 0,
      chatCompletionAttemptCount:
        result.chatCompletionAttemptCount ?? 0,
      formalRequestSha256: result.formalRequestSha256 ?? null,
      tokenEstimateRequestSha256:
        result.tokenEstimateRequestSha256 ?? null,
      tokenEstimateResponseSha256:
        result.tokenEstimateResponseSha256 ?? null,
      tokenEstimateEvidenceSha256:
        result.tokenEstimateEvidenceSha256 ?? null,
      estimatedInputTokens: result.estimatedInputTokens ?? null,
      requiredContextTokens: result.requiredContextTokens ?? null,
      reviewId: result.reviewId ?? null,
      receiptSha256: result.receiptSha256 ?? null,
      receiptArtifactSha256: result.receiptArtifactSha256 ?? null,
      transportReasonCodes: result.transportReasonCodes ?? [],
      chatDiagnosticEvidenceSha256:
        result.chatDiagnosticEvidenceSha256 ?? null,
      chatDiagnosticResponseSha256:
        result.chatDiagnosticResponseSha256 ?? null,
      chatDiagnosticResponseByteLength:
        result.chatDiagnosticResponseByteLength ?? null,
    })}\n`,
  );
  if (!result.ok) process.exitCode = 2;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stdout.write(
      `${JSON.stringify(bootstrapFailureResult(error))}\n`,
    );
    process.exitCode = 2;
  });
}
