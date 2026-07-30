#!/usr/bin/env node

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  createIndependentReviewBundle,
  independentModelReviewDigests,
  validateIndependentReviewPolicy,
} from "../lib/independent-model-review.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*[\u0000-\u001f\\]).+$/u;
const scriptRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const FIXED_PATHS = Object.freeze({
  policy:
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v2.schema.json",
  outputSchema:
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  validator: "lib/independent-model-review.mjs",
  checkMapper: "lib/independent-model-review.mjs",
  prompt:
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  specifications: [
    "AGENTS.md",
    "CONTEXT.md",
    "docs/agents/issue-tracker.md",
    "docs/adr/0008-c13-protected-source-review.md",
  ],
});

const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
});

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

async function git(repoPath, args, options = {}) {
  return execFileAsync(
    "/usr/bin/git",
    ["--no-replace-objects", "-C", repoPath, ...args],
    {
      encoding: options.encoding ?? "buffer",
      env: gitEnvironment,
      maxBuffer: 32 * 1024 * 1024,
    },
  );
}

async function requireCommit(repoPath, value, field) {
  if (!COMMIT.test(value)) {
    throw new TypeError(`${field} must be an exact 40-character commit.`);
  }
  const { stdout } = await git(repoPath, ["cat-file", "-t", value], {
    encoding: "utf8",
  });
  if (stdout.trim() !== "commit") {
    throw new TypeError(`${field} is not a commit object.`);
  }
}

async function commitBytes(repoPath, sourceCommit, path) {
  if (!SAFE_PATH.test(path)) {
    throw new TypeError("Git subject path is unsafe.");
  }
  const { stdout } = await git(repoPath, [
    "cat-file",
    "blob",
    `${sourceCommit}:${path}`,
  ]);
  return new Uint8Array(stdout);
}

async function treeEntry(repoPath, sourceCommit, path) {
  const { stdout } = await git(
    repoPath,
    ["ls-tree", "-z", sourceCommit, "--", path],
    { encoding: "utf8" },
  );
  const value = stdout.replace(/\0$/u, "");
  const match = /^(100644|100755|120000|160000) (blob|commit) [a-f0-9]{40}\t(.+)$/u.exec(
    value,
  );
  if (!match || match[3] !== path) {
    throw new TypeError(`Git subject is missing or ambiguous: ${path}`);
  }
  return {
    path,
    gitMode: match[1],
    blobSha256: await independentModelReviewDigests.bytes(
      await commitBytes(repoPath, sourceCommit, path),
    ),
  };
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
  const paths = Buffer.from(stdout)
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .sort();
  if (
    paths.length === 0 ||
    new Set(paths).size !== paths.length ||
    paths.some((path) => !SAFE_PATH.test(path))
  ) {
    throw new TypeError("Changed-path set is empty, duplicated, or unsafe.");
  }
  return paths;
}

function validateTestEvidence(testEvidence, sourceCommit) {
  if (
    !Array.isArray(testEvidence) ||
    testEvidence.length === 0 ||
    testEvidence.some(
      (evidence) =>
        !exactKeys(evidence, [
          "evidenceId",
          "command",
          "status",
          "exitCode",
          "outputRef",
          "outputSha256",
          "outputByteLength",
          "truncated",
          "sourceCommit",
          "runner",
          "toolVersions",
        ]) ||
        evidence.status !== "PASS" ||
        evidence.exitCode !== 0 ||
        evidence.sourceCommit !== sourceCommit ||
        !SAFE_PATH.test(evidence.outputRef) ||
        !SHA256.test(evidence.outputSha256) ||
        !Number.isInteger(evidence.outputByteLength) ||
        evidence.outputByteLength <= 0 ||
        evidence.truncated !== false ||
        !Array.isArray(evidence.toolVersions) ||
        evidence.toolVersions.length === 0,
    )
  ) {
    throw new TypeError("Test evidence is incomplete or not bound to sourceCommit.");
  }
}

export async function buildIndependentReviewBundleFromGit({
  repoPath,
  baseCommit,
  sourceCommit,
  generatedAt,
  bundleId,
  applicablePhase,
  testEvidence,
  implementationIdentity,
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
  const { stdout: treeStdout } = await git(
    exactRepoPath,
    ["rev-parse", `${sourceCommit}^{tree}`],
    { encoding: "utf8" },
  );
  const tree = treeStdout.trim();
  const reviewedPaths = await exactChangedPaths(
    exactRepoPath,
    baseCommit,
    sourceCommit,
  );
  const sourceSubjects = await Promise.all(
    reviewedPaths.map((path) => treeEntry(exactRepoPath, sourceCommit, path)),
  );
  const specificationSubjects = await Promise.all(
    FIXED_PATHS.specifications.map(async (path) => ({
      path,
      blobSha256: await independentModelReviewDigests.bytes(
        await commitBytes(exactRepoPath, sourceCommit, path),
      ),
    })),
  );
  const policyBytes = await commitBytes(
    exactRepoPath,
    sourceCommit,
    FIXED_PATHS.policy,
  );
  const policy = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(policyBytes));
  const policyValidation = await validateIndependentReviewPolicy(policy);
  if (!policyValidation.ok) {
    throw new TypeError("Frozen Independent Review Policy is invalid.");
  }
  const currentValidatorBytes = await readFile(
    resolve(scriptRoot, FIXED_PATHS.validator),
  );
  const frozenValidatorBytes = await commitBytes(
    exactRepoPath,
    sourceCommit,
    FIXED_PATHS.validator,
  );
  if (
    (await independentModelReviewDigests.bytes(currentValidatorBytes)) !==
    (await independentModelReviewDigests.bytes(frozenValidatorBytes))
  ) {
    throw new TypeError(
      "Running Bundle generator does not match the frozen sourceCommit validator.",
    );
  }
  const artifactDigest = async (path) =>
    independentModelReviewDigests.bytes(
      await commitBytes(exactRepoPath, sourceCommit, path),
    );
  const { stdout: diffBytes } = await git(exactRepoPath, [
    "diff",
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    baseCommit,
    sourceCommit,
    "--",
  ]);
  validateTestEvidence(testEvidence, sourceCommit);
  return createIndependentReviewBundle({
    bundleId,
    generatedAt,
    applicablePhase,
    policyPath: FIXED_PATHS.policy,
    policy,
    artifacts: {
      receiptSchemaPath: FIXED_PATHS.receiptSchema,
      receiptSchemaSha256: await artifactDigest(FIXED_PATHS.receiptSchema),
      outputSchemaPath: FIXED_PATHS.outputSchema,
      outputSchemaSha256: await artifactDigest(FIXED_PATHS.outputSchema),
      semanticValidatorPath: FIXED_PATHS.validator,
      semanticValidatorSha256: await artifactDigest(FIXED_PATHS.validator),
      independenceValidatorPath: FIXED_PATHS.validator,
      independenceValidatorSha256: await artifactDigest(FIXED_PATHS.validator),
      checkMapperPath: FIXED_PATHS.checkMapper,
      checkMapperSha256: await artifactDigest(FIXED_PATHS.checkMapper),
      promptPath: FIXED_PATHS.prompt,
      promptSha256: await artifactDigest(FIXED_PATHS.prompt),
    },
    source: {
      baseCommit,
      sourceCommit,
      headCommit: sourceCommit,
      tree,
      diffSha256: await independentModelReviewDigests.bytes(diffBytes),
      changedPathsDigest:
        await independentModelReviewDigests.value(reviewedPaths),
    },
    reviewedPaths,
    sourceSubjects,
    specificationSubjects,
    testEvidenceSubjects: structuredClone(testEvidence),
    implementationIdentity: structuredClone(implementationIdentity),
  });
}

function parseArguments(values) {
  const args = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || value === undefined) {
      throw new TypeError("Bundle generator arguments must be --key value pairs.");
    }
    args[key.slice(2)] = value;
  }
  return args;
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const testEvidence = JSON.parse(args["test-evidence-json"] ?? "null");
  const bundle = await buildIndependentReviewBundleFromGit({
    repoPath: args.repo ?? scriptRoot,
    baseCommit: args.base,
    sourceCommit: args.source,
    generatedAt: args["generated-at"],
    bundleId: args["bundle-id"],
    applicablePhase: args["applicable-phase"],
    testEvidence,
    implementationIdentity: {
      provider: "openai",
      modelId: args["implementation-model-id"],
      modelVersion: args["implementation-model-version"],
      participantManifestSha256: args["participant-manifest-sha256"],
      sessionIdSha256: args["implementation-session-sha256"],
    },
  });
  process.stdout.write(`${JSON.stringify(bundle, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(
      `${JSON.stringify({
        code: "INDEPENDENT_REVIEW_BUNDLE_BUILD_FAILED",
        message: error instanceof Error ? error.message : "Unknown error.",
      })}\n`,
    );
    process.exitCode = 1;
  });
}
