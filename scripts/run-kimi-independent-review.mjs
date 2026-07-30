#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstat,
  mkdir,
  readFile,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  buildKimiIndependentReviewRequest,
  createKimiIndependentModelReviewReceipt,
  executeKimiIndependentReview,
  independentKimiReviewDigests,
  validateKimiIndependentModelReviewReceipt,
} from "../lib/kimi-independent-review.mjs";
import {
  parseIndependentReviewJsonBytes,
  validateIndependentReviewBundle,
  validateIndependentReviewPolicy,
} from "../lib/independent-model-review.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/u;
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
});
const EXECUTING_PATHS = Object.freeze([
  "lib/independent-model-review.mjs",
  "lib/kimi-independent-review.mjs",
  "package-lock.json",
  "scripts/run-kimi-independent-review.mjs",
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

async function verifyExecutingBytes(repoPath, sourceCommit) {
  const root = resolve(new URL("../", import.meta.url).pathname);
  for (const path of EXECUTING_PATHS) {
    const [currentBytes, frozenBytes] = await Promise.all([
      readFile(resolve(root, path)),
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
  return {
    head: headText.trim(),
    tree: treeText.trim(),
    worktreeStatusSha256: hashStatus(statusBytes),
    protectedPathSetSha256:
      independentKimiReviewDigests.value(exactProtectedPaths),
    protectedFilesDigest: await protectedFilesDigest(
      exactRepoPath,
      exactProtectedPaths,
    ),
  };
}

function parseArguments(values) {
  const allowed = new Set([
    "repo",
    "bundle",
    "material",
    "output-dir",
    "review-id",
  ]);
  const args = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    const name = key?.slice(2);
    if (
      !key?.startsWith("--") ||
      value === undefined ||
      !allowed.has(name) ||
      Object.hasOwn(args, name)
    ) {
      throw new TypeError("Kimi review CLI arguments are invalid.");
    }
    args[name] = value;
  }
  if (
    Object.keys(args).length !== allowed.size ||
    [...allowed].some((name) => !Object.hasOwn(args, name)) ||
    !/^imrr_[a-z0-9][a-z0-9_-]{7,127}$/u.test(args["review-id"] ?? "")
  ) {
    throw new TypeError("Kimi review CLI arguments are incomplete.");
  }
  return args;
}

async function writeArtifacts(outputDir, artifacts) {
  for (const [name, bytes] of Object.entries(artifacts)) {
    await writeFile(resolve(outputDir, name), bytes, { flag: "wx" });
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

export async function runKimiIndependentReview({
  repoPath,
  reviewBundleBytes,
  reviewMaterialBytes,
  outputDir,
  reviewId,
  apiKey,
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
}) {
  const exactRepoPath = await realpath(resolve(repoPath));
  const exactOutputDir = await safeOutputCandidate(
    exactRepoPath,
    outputDir,
  );
  const bundle = parseIndependentReviewJsonBytes(
    reviewBundleBytes,
    "Independent Review Bundle",
    16 * 1024 * 1024,
  );
  const material = parseIndependentReviewJsonBytes(
    reviewMaterialBytes,
    "Independent Review Material",
    16 * 1024 * 1024,
  );
  const sourceCommit = bundle?.source?.sourceCommit;
  if (
    !COMMIT.test(sourceCommit ?? "") ||
    material?.source?.sourceCommit !== sourceCommit
  ) {
    throw new TypeError("Kimi review sourceCommit binding is invalid.");
  }
  await verifyExecutingBytes(exactRepoPath, sourceCommit);
  const [
    policyBytes,
    configBytes,
    promptBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
  ] = await Promise.all(
    [
      FIXED_PATHS.policy,
      FIXED_PATHS.config,
      FIXED_PATHS.prompt,
      FIXED_PATHS.outputSchema,
      FIXED_PATHS.receiptSchema,
    ].map((path) => commitBytes(exactRepoPath, sourceCommit, path)),
  );
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
    validateIndependentReviewBundle(bundle, { policy }),
  ]);
  if (!policyValidation.ok || !bundleValidation.ok) {
    throw new TypeError("Kimi review Policy or Bundle is invalid.");
  }
  const before = await captureKimiReviewRepositorySnapshot({
    repoPath: exactRepoPath,
    protectedPaths: bundle.repositoryProtection.protectedPaths,
  });
  if (
    before.head !== sourceCommit ||
    before.tree !== bundle.source.tree
  ) {
    throw new TypeError("Repository snapshot does not match sourceCommit.");
  }
  const request = await buildKimiIndependentReviewRequest({
    config,
    configBytes,
    bundle,
    reviewBundleBytes,
    promptBytes,
    materialBytes: reviewMaterialBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
  });
  if (typeof apiKey !== "string" || apiKey.length === 0) {
    return {
      ok: false,
      status: "BLOCKED",
      reasonCodes: ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
      networkAttemptCount: 0,
    };
  }
  const startedAt = now().toISOString();
  let networkAttemptCount = 0;
  try {
    const transport = await executeKimiIndependentReview({
      config,
      requestBytes: request.requestBytes,
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
    const artifactPaths = {
      request: "request.json",
      response: "response.json",
      content: "content.json",
      material: "material.json",
    };
    const transportArtifacts = {
      "request.json": request.requestBytes,
      "response.json": transport.responseBytes,
      "content.json": transport.contentBytes,
      "material.json": reviewMaterialBytes,
    };
    await createVerifiedOutputDirectory(exactRepoPath, exactOutputDir);
    await writeArtifacts(exactOutputDir, transportArtifacts);
    await verifyArtifactReadback(exactOutputDir, transportArtifacts);
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
    const receipt = await createKimiIndependentModelReviewReceipt({
      receiptId: reviewId,
      policy,
      bundle,
      config,
      configBytes,
      material,
      rawMaterialBytes: reviewMaterialBytes,
      reviewBundleBytes,
      promptBytes,
      outputSchemaBytes,
      receiptSchemaBytes,
      requestBytes: request.requestBytes,
      responseBytes: transport.responseBytes,
      contentBytes: transport.contentBytes,
      responseId: transport.responseId,
      actualReturnedModel: transport.actualReturnedModel,
      startedAt,
      finishedAt,
      snapshots,
      artifactPaths,
    });
    const validation = await validateKimiIndependentModelReviewReceipt({
      receipt,
      policy,
      bundle,
      config,
      configBytes,
      material,
      rawMaterialBytes: reviewMaterialBytes,
      reviewBundleBytes,
      promptBytes,
      outputSchemaBytes,
      receiptSchemaBytes,
      requestBytes: request.requestBytes,
      responseBytes: transport.responseBytes,
      contentBytes: transport.contentBytes,
      snapshots,
    });
    if (validation.reasonCodes.length > 0) {
      return {
        ...validation,
        networkAttemptCount,
      };
    }
    const receiptBytes = Buffer.from(JSON.stringify(receipt), "utf8");
    await writeArtifacts(exactOutputDir, { "receipt.json": receiptBytes });
    await verifyArtifactReadback(exactOutputDir, {
      ...transportArtifacts,
      "receipt.json": receiptBytes,
    });
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
      };
    }
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
    error.networkAttemptCount = networkAttemptCount;
    throw error;
  }
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const result = await runKimiIndependentReview({
    repoPath: args.repo,
    reviewBundleBytes: await readFile(resolve(args.bundle)),
    reviewMaterialBytes: await readFile(resolve(args.material)),
    outputDir: args["output-dir"],
    reviewId: args["review-id"],
    apiKey: process.env.MOONSHOT_API_KEY ?? "",
    fetchImpl: globalThis.fetch,
  });
  process.stdout.write(
    `${JSON.stringify({
      ok: result.ok,
      status: result.status,
      conclusion: result.conclusion ?? null,
      reasonCodes: result.reasonCodes,
      networkAttemptCount: result.networkAttemptCount,
      reviewId: result.reviewId ?? null,
      receiptSha256: result.receiptSha256 ?? null,
      receiptArtifactSha256: result.receiptArtifactSha256 ?? null,
    })}\n`,
  );
  if (!result.ok) process.exitCode = 2;
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(
      `${JSON.stringify({
        ok: false,
        status: "BLOCKED",
        reasonCodes: [
          error?.reasonCodes?.[0] ?? "KIMI_INDEPENDENT_REVIEW_FAILED",
        ],
        networkAttemptCount:
          Number.isInteger(error?.networkAttemptCount) &&
          error.networkAttemptCount >= 0
            ? error.networkAttemptCount
            : 0,
      })}\n`,
    );
    process.exitCode = 2;
  });
}
