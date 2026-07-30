#!/usr/bin/env node

import { execFile } from "node:child_process";
import { readFile, realpath, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  createIndependentReviewBundle,
  independentModelReviewFixedSpecificationPaths,
  independentModelReviewDigests,
  parseIndependentReviewJsonBytes,
  validateIndependentReviewPolicy,
  validateIndependentReviewTestEvidenceClosure,
} from "../lib/independent-model-review.mjs";
import {
  captureIndependentReviewRuntimeBinding,
} from "../lib/independent-review-runtime-binding.mjs";
import { collectIndependentReviewTestEvidence } from "./run-independent-review-test-evidence.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*[\u0000-\u001f\\]).+$/u;
const scriptRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const FIXED_PATHS = Object.freeze({
  policy:
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  policySchema:
    "implementation/governance/schemas/independent-review-policy.v2.schema.json",
  bundleSchema:
    "implementation/governance/schemas/independent-review-bundle.v2.schema.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v2.schema.json",
  outputSchema:
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  runtimeEvidenceSchema:
    "implementation/governance/schemas/independent-model-runtime-evidence.v2.schema.json",
  transportEvidenceSchema:
    "implementation/governance/schemas/independent-review-transport-evidence.v1.schema.json",
  testResultSchema:
    "implementation/governance/schemas/independent-review-test-result.v3.schema.json",
  validator: "lib/independent-model-review.mjs",
  runtimeEvidenceValidator: "lib/independent-review-runtime-evidence.mjs",
  transportEvidenceValidator:
    "lib/independent-review-transport-evidence.mjs",
  checkMapper: "lib/independent-model-review.mjs",
  generator: "scripts/build-independent-review-bundle.mjs",
  testPlan:
    "implementation/governance/independent-review/independent-review-test-plan.v2.json",
  testEvidenceCollector:
    "scripts/run-independent-review-test-evidence.mjs",
  runtimeControlPlane:
    "scripts/run-independent-review-control-plane.mjs",
  sandboxPolicyTemplate:
    "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in",
  implementationParticipantManifest:
    "implementation/governance/independent-review/implementation-participant.v1.json",
  prompt:
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  specifications: independentModelReviewFixedSpecificationPaths,
});
const FIXED_REPOSITORY_PROTECTED_PATHS = Object.freeze(
  [
    "README.md",
    "docs/plans/通用多企业AI员工平台_v5.1新增内容与开源参考对照表_v1.0.md",
    "docs/plans/通用多企业AI员工平台_完备工程级方案_v5.2.md",
  ].sort(),
);

const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
});
const EMPTY_SHA256 =
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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

export async function createTrustedGitDiffCheck({
  repoPath,
  baseCommit,
  sourceCommit,
  sourceTree,
  patchBytes,
  runnerGitBlobSha256,
  runnerExecutedBytesSha256,
}) {
  const exactRepoPath = resolve(repoPath);
  let checkResult;
  try {
    checkResult = await git(exactRepoPath, [
      "diff",
      "--check",
      "--no-ext-diff",
      "--no-textconv",
      baseCommit,
      sourceCommit,
      "--",
    ]);
  } catch {
    throw new TypeError(
      "Frozen source patch failed the trusted Git diff check.",
    );
  }
  const stdoutBytes = Buffer.from(checkResult.stdout);
  const stderrBytes = Buffer.from(checkResult.stderr);
  if (stdoutBytes.byteLength !== 0 || stderrBytes.byteLength !== 0) {
    throw new TypeError(
      "Trusted Git diff check returned unexpected output.",
    );
  }
  const { stdout: gitVersionBytes, stderr: gitVersionErrorBytes } =
    await git(exactRepoPath, ["--version"]);
  const gitVersion = Buffer.from(gitVersionBytes)
    .toString("utf8")
    .trim();
  if (
    Buffer.from(gitVersionErrorBytes).byteLength !== 0 ||
    !/^git version [^\r\n]{1,128}$/u.test(gitVersion)
  ) {
    throw new TypeError("Trusted Git version is invalid.");
  }
  const logicalCommandSha256 = await independentModelReviewDigests.value({
    executable: "/usr/bin/git",
    fixedArguments: [
      "--no-replace-objects",
      "-C",
      "<TRUSTED_REPOSITORY>",
      "diff",
      "--check",
      "--no-ext-diff",
      "--no-textconv",
    ],
    baseCommit,
    sourceCommit,
    terminator: "--",
  });
  const check = {
    schemaVersion: "independent-review-git-diff-check.v1",
    checkId: "base-to-source-diff-check",
    executionMode: "TRUSTED_GIT_OBJECT_DATABASE_CONTROL_PLANE",
    baseCommit,
    sourceCommit,
    sourceTree,
    checkedPatchSha256:
      await independentModelReviewDigests.bytes(patchBytes),
    runnerPath: FIXED_PATHS.generator,
    runnerGitBlobSha256,
    runnerExecutedBytesSha256,
    gitExecutable: "/usr/bin/git",
    gitVersion,
    logicalCommandSha256,
    environmentSha256:
      await independentModelReviewDigests.value(gitEnvironment),
    exitCode: 0,
    status: "PASS",
    stdoutSha256: EMPTY_SHA256,
    stdoutByteLength: 0,
    stderrSha256: EMPTY_SHA256,
    stderrByteLength: 0,
    resultSha256: `sha256:${"0".repeat(64)}`,
  };
  check.resultSha256 = await independentModelReviewDigests.value(
    Object.fromEntries(
      Object.entries(check).filter(([key]) => key !== "resultSha256"),
    ),
  );
  return check;
}

export async function buildIndependentReviewBundleFromGit(input) {
  if (
    !exactKeys(input, [
      "repoPath",
      "baseCommit",
      "sourceCommit",
      "generatedAt",
      "bundleId",
      "applicablePhase",
      "testEvidenceRoot",
    ])
  ) {
    throw new TypeError(
      "Bundle generator input contains missing or caller-controlled evidence fields.",
    );
  }
  const {
    repoPath,
    baseCommit,
    sourceCommit,
    generatedAt,
    bundleId,
    applicablePhase,
    testEvidenceRoot,
  } = input;
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
  const participantManifestBytes = await commitBytes(
    exactRepoPath,
    sourceCommit,
    FIXED_PATHS.implementationParticipantManifest,
  );
  const participantManifest = parseIndependentReviewJsonBytes(
    participantManifestBytes,
    "Implementation participant manifest",
    16 * 1024,
  );
  if (
    !exactKeys(participantManifest, [
      "schemaVersion",
      "manifestId",
      "lifecycle",
      "provider",
      "modelId",
      "modelVersion",
      "participationRole",
      "sessionIdSha256",
      "sessionBindingSource",
      "externalNonRepudiationProvided",
      "hostOwnerCanForgeEvidence",
    ]) ||
    participantManifest.schemaVersion !==
      "independent-review-implementation-participant.v1" ||
    participantManifest.manifestId !==
      "zb-aios-gpt-5-6-sol-implementation-session" ||
    participantManifest.lifecycle !== "CANDIDATE" ||
    participantManifest.provider !== "openai" ||
    participantManifest.modelId !== "gpt-5.6-sol" ||
    participantManifest.modelVersion !== "gpt-5.6-sol" ||
    participantManifest.participationRole !== "IMPLEMENTER" ||
    !SHA256.test(participantManifest.sessionIdSha256) ||
    participantManifest.sessionBindingSource !==
      "CODEX_THREAD_ID_SHA256_RECORDED_AT_FREEZE" ||
    participantManifest.externalNonRepudiationProvided !== false ||
    participantManifest.hostOwnerCanForgeEvidence !== true
  ) {
    throw new TypeError(
      "Frozen implementation participant manifest is invalid.",
    );
  }
  const implementationIdentity = {
    provider: participantManifest.provider,
    modelId: participantManifest.modelId,
    modelVersion: participantManifest.modelVersion,
    participantManifestSha256:
      await independentModelReviewDigests.bytes(participantManifestBytes),
    sessionIdSha256: participantManifest.sessionIdSha256,
  };
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
  const currentGeneratorBytes = await readFile(fileURLToPath(import.meta.url));
  const frozenGeneratorBytes = await commitBytes(
    exactRepoPath,
    sourceCommit,
    FIXED_PATHS.generator,
  );
  const generatorSha256 =
    await independentModelReviewDigests.bytes(frozenGeneratorBytes);
  if (
    (await independentModelReviewDigests.bytes(currentGeneratorBytes)) !==
    generatorSha256
  ) {
    throw new TypeError(
      "Running Bundle generator does not match the frozen sourceCommit generator.",
    );
  }
  const currentCollectorBytes = await readFile(
    resolve(scriptRoot, FIXED_PATHS.testEvidenceCollector),
  );
  const frozenCollectorBytes = await commitBytes(
    exactRepoPath,
    sourceCommit,
    FIXED_PATHS.testEvidenceCollector,
  );
  const collectorSha256 =
    await independentModelReviewDigests.bytes(frozenCollectorBytes);
  if (
    (await independentModelReviewDigests.bytes(currentCollectorBytes)) !==
    collectorSha256
  ) {
    throw new TypeError(
      "Running test evidence collector does not match the frozen sourceCommit collector.",
    );
  }
  const artifactDigest = async (path) =>
    independentModelReviewDigests.bytes(
      await commitBytes(exactRepoPath, sourceCommit, path),
    );
  const testPlanBytes = await commitBytes(
    exactRepoPath,
    sourceCommit,
    FIXED_PATHS.testPlan,
  );
  const [testResultSchemaBytes, sandboxPolicyTemplateBytes] =
    await Promise.all([
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
    ]);
  const testPlanSha256 =
    await independentModelReviewDigests.bytes(testPlanBytes);
  const testResultSchemaSha256 =
    await independentModelReviewDigests.bytes(testResultSchemaBytes);
  const sandboxPolicyTemplateSha256 =
    await independentModelReviewDigests.bytes(sandboxPolicyTemplateBytes);
  const testPlan = parseIndependentReviewJsonBytes(
    testPlanBytes,
    "Independent review test plan",
    1024 * 1024,
  );
  if (!SHA256.test(testPlan?.planSha256 ?? "")) {
    throw new TypeError("Frozen Independent Review test plan is invalid.");
  }
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
  const gitDiffCheck = await createTrustedGitDiffCheck({
    repoPath: exactRepoPath,
    baseCommit,
    sourceCommit,
    sourceTree: tree,
    patchBytes: diffBytes,
    runnerGitBlobSha256: generatorSha256,
    runnerExecutedBytesSha256: generatorSha256,
  });
  const runtimeBindingBefore =
    await captureIndependentReviewRuntimeBinding();
  const testEvidence = await collectIndependentReviewTestEvidence({
    repoPath: exactRepoPath,
    sourceCommit,
    sourceTree: tree,
    planPath: FIXED_PATHS.testPlan,
    evidenceRoot: testEvidenceRoot,
  });
  const runtimeBindingAfter =
    await captureIndependentReviewRuntimeBinding();
  if (
    JSON.stringify(runtimeBindingBefore) !==
    JSON.stringify(runtimeBindingAfter)
  ) {
    throw new TypeError(
      "Independent review runtime changed during evidence collection.",
    );
  }
  const exactEvidenceRoot = await realpath(resolve(testEvidenceRoot));
  const closure = await validateIndependentReviewTestEvidenceClosure({
    bundle: {
      source: { sourceCommit, tree },
      artifacts: {
        testPlanSha256,
        testEvidenceCollectorPath: FIXED_PATHS.testEvidenceCollector,
        testEvidenceCollectorSha256: collectorSha256,
        testResultSchemaPath: FIXED_PATHS.testResultSchema,
        testResultSchemaSha256,
        sandboxPolicyTemplatePath: FIXED_PATHS.sandboxPolicyTemplate,
        sandboxPolicyTemplateSha256,
      },
      testEvidenceSubjects: testEvidence,
    },
    testPlanBytes,
    collectorBytes: frozenCollectorBytes,
    testResultSchemaBytes,
    sandboxPolicyTemplateBytes,
    expectedRuntimeBinding: runtimeBindingBefore,
    evidenceResolver: async (ref) => {
      if (!SAFE_PATH.test(ref)) {
        throw new TypeError("Test evidence reference is unsafe.");
      }
      const path = await realpath(resolve(exactEvidenceRoot, ref));
      if (
        !path.startsWith(`${exactEvidenceRoot}/`) ||
        !(await stat(path)).isFile()
      ) {
        throw new TypeError(
          "Test evidence reference escapes its trusted root.",
        );
      }
      return readFile(path);
    },
  });
  if (!closure.ok) {
    throw new TypeError("Test evidence closure is not trusted.");
  }
  return createIndependentReviewBundle({
    bundleId,
    generatedAt,
    applicablePhase,
    policyPath: FIXED_PATHS.policy,
    policy,
    artifacts: {
      policySchemaPath: FIXED_PATHS.policySchema,
      policySchemaSha256: await artifactDigest(FIXED_PATHS.policySchema),
      bundleSchemaPath: FIXED_PATHS.bundleSchema,
      bundleSchemaSha256: await artifactDigest(FIXED_PATHS.bundleSchema),
      receiptSchemaPath: FIXED_PATHS.receiptSchema,
      receiptSchemaSha256: await artifactDigest(FIXED_PATHS.receiptSchema),
      outputSchemaPath: FIXED_PATHS.outputSchema,
      outputSchemaSha256: await artifactDigest(FIXED_PATHS.outputSchema),
      runtimeEvidenceSchemaPath: FIXED_PATHS.runtimeEvidenceSchema,
      runtimeEvidenceSchemaSha256: await artifactDigest(
        FIXED_PATHS.runtimeEvidenceSchema,
      ),
      transportEvidenceSchemaPath: FIXED_PATHS.transportEvidenceSchema,
      transportEvidenceSchemaSha256: await artifactDigest(
        FIXED_PATHS.transportEvidenceSchema,
      ),
      testResultSchemaPath: FIXED_PATHS.testResultSchema,
      testResultSchemaSha256,
      semanticValidatorPath: FIXED_PATHS.validator,
      semanticValidatorSha256: await artifactDigest(FIXED_PATHS.validator),
      independenceValidatorPath: FIXED_PATHS.validator,
      independenceValidatorSha256: await artifactDigest(FIXED_PATHS.validator),
      runtimeEvidenceValidatorPath: FIXED_PATHS.runtimeEvidenceValidator,
      runtimeEvidenceValidatorSha256: await artifactDigest(
        FIXED_PATHS.runtimeEvidenceValidator,
      ),
      transportEvidenceValidatorPath: FIXED_PATHS.transportEvidenceValidator,
      transportEvidenceValidatorSha256: await artifactDigest(
        FIXED_PATHS.transportEvidenceValidator,
      ),
      checkMapperPath: FIXED_PATHS.checkMapper,
      checkMapperSha256: await artifactDigest(FIXED_PATHS.checkMapper),
      bundleGeneratorPath: FIXED_PATHS.generator,
      bundleGeneratorSha256: generatorSha256,
      testPlanPath: FIXED_PATHS.testPlan,
      testPlanSha256,
      testEvidenceCollectorPath: FIXED_PATHS.testEvidenceCollector,
      testEvidenceCollectorSha256: collectorSha256,
      runtimeControlPlanePath: FIXED_PATHS.runtimeControlPlane,
      runtimeControlPlaneSha256: await artifactDigest(
        FIXED_PATHS.runtimeControlPlane,
      ),
      sandboxPolicyTemplatePath: FIXED_PATHS.sandboxPolicyTemplate,
      sandboxPolicyTemplateSha256,
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
      gitDiffCheck,
    },
    repositoryProtection: {
      protectedPaths: [...FIXED_REPOSITORY_PROTECTED_PATHS],
      protectedPathSetSha256: await independentModelReviewDigests.value(
        FIXED_REPOSITORY_PROTECTED_PATHS,
      ),
    },
    reviewedPaths,
    sourceSubjects,
    specificationSubjects,
    testEvidenceSubjects: structuredClone(testEvidence),
    implementationIdentity: structuredClone(implementationIdentity),
  });
}

function parseArguments(values) {
  const allowed = new Set([
    "repo",
    "base",
    "source",
    "generated-at",
    "bundle-id",
    "applicable-phase",
    "test-evidence-root",
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
      throw new TypeError("Bundle generator arguments must be --key value pairs.");
    }
    args[name] = value;
  }
  return args;
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const bundle = await buildIndependentReviewBundleFromGit({
    repoPath: args.repo ?? scriptRoot,
    baseCommit: args.base,
    sourceCommit: args.source,
    generatedAt: args["generated-at"],
    bundleId: args["bundle-id"],
    applicablePhase: args["applicable-phase"],
    testEvidenceRoot: args["test-evidence-root"],
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
