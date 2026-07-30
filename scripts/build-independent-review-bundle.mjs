#!/usr/bin/env node

import { execFile } from "node:child_process";
import { readFile, realpath, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  createIndependentReviewBundle,
  independentModelReviewDigests,
  parseIndependentReviewJsonBytes,
  validateIndependentReviewPolicy,
} from "../lib/independent-model-review.mjs";
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
    "implementation/governance/schemas/independent-review-test-result.v2.schema.json",
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
    "implementation/governance/independent-review/macos-independent-review-readonly.sb.in",
  prompt:
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  specifications: [
    "AGENTS.md",
    "CONTEXT.md",
    "docs/agents/issue-tracker.md",
    "docs/adr/0008-c13-protected-source-review.md",
    "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
  ],
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

async function validateTestEvidence(
  testEvidence,
  sourceCommit,
  sourceTree,
  testEvidenceRoot,
  testPlanBindingSha256,
  collectorSha256,
) {
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
        evidence.runner !== "GIT_FROZEN_ISOLATED_CLONE_CONTROL_PLANE" ||
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
  const exactEvidenceRoot = await realpath(resolve(testEvidenceRoot));
  for (const evidence of testEvidence) {
    const exactEvidencePath = await realpath(
      resolve(exactEvidenceRoot, evidence.outputRef),
    );
    if (
      !exactEvidencePath.startsWith(`${exactEvidenceRoot}/`) ||
      !(await stat(exactEvidencePath)).isFile()
    ) {
      throw new TypeError("Test evidence path escapes the trusted evidence root.");
    }
    const bytes = await readFile(exactEvidencePath);
    if (
      (await independentModelReviewDigests.bytes(bytes)) !==
        evidence.outputSha256 ||
      bytes.byteLength !== evidence.outputByteLength
    ) {
      throw new TypeError("Test evidence bytes do not match the declared digest.");
    }
    let attestation;
    try {
      attestation = parseIndependentReviewJsonBytes(
        bytes,
        "Independent review test result",
        1024 * 1024,
      );
    } catch {
      throw new TypeError("Test evidence is not a closed runner attestation.");
    }
    if (
      !exactKeys(attestation, [
        "schemaVersion",
        "evidenceId",
        "testPlanSha256",
        "sourceCommit",
        "sourceTree",
        "runner",
        "executionSource",
        "commandId",
        "argvSha256",
        "observation",
        "stdoutRef",
        "stdoutSha256",
        "stdoutByteLength",
        "stderrRef",
        "stderrSha256",
        "stderrByteLength",
        "resultSha256",
      ]) ||
      attestation.schemaVersion !== "independent-review-test-result.v2" ||
      attestation.evidenceId !== evidence.evidenceId ||
      attestation.sourceCommit !== evidence.sourceCommit ||
      attestation.sourceTree !== sourceTree ||
      attestation.testPlanSha256 !== testPlanBindingSha256 ||
      !exactKeys(attestation.runner, [
        "path",
        "gitBlobSha256",
        "executedBytesSha256",
      ]) ||
      attestation.runner.path !== FIXED_PATHS.testEvidenceCollector ||
      attestation.runner.gitBlobSha256 !== collectorSha256 ||
      attestation.runner.executedBytesSha256 !== collectorSha256 ||
      !exactKeys(attestation.executionSource, [
        "mode",
        "before",
        "after",
        "unchanged",
      ]) ||
      attestation.executionSource.mode !== "ISOLATED_LOCAL_CLONE" ||
      !exactKeys(attestation.executionSource.before, [
        "head",
        "tree",
        "worktreeStatusSha256",
      ]) ||
      !exactKeys(attestation.executionSource.after, [
        "head",
        "tree",
        "worktreeStatusSha256",
      ]) ||
      attestation.executionSource.before.head !== sourceCommit ||
      attestation.executionSource.after.head !== sourceCommit ||
      attestation.executionSource.before.tree !== sourceTree ||
      attestation.executionSource.after.tree !== sourceTree ||
      !SHA256.test(
        attestation.executionSource.before.worktreeStatusSha256,
      ) ||
      attestation.executionSource.before.worktreeStatusSha256 !==
        attestation.executionSource.after.worktreeStatusSha256 ||
      attestation.executionSource.unchanged !== true ||
      attestation.commandId !== evidence.evidenceId ||
      !SHA256.test(attestation.argvSha256) ||
      !exactKeys(attestation.observation, [
        "exitCode",
        "signal",
        "timedOut",
        "startedAt",
        "finishedAt",
      ]) ||
      attestation.observation.exitCode !== 0 ||
      attestation.observation.signal !== null ||
      attestation.observation.timedOut !== false ||
      !Number.isFinite(Date.parse(attestation.observation.startedAt)) ||
      !Number.isFinite(Date.parse(attestation.observation.finishedAt)) ||
      Date.parse(attestation.observation.startedAt) >
        Date.parse(attestation.observation.finishedAt) ||
      !SAFE_PATH.test(attestation.stdoutRef) ||
      !SAFE_PATH.test(attestation.stderrRef) ||
      !SHA256.test(attestation.stdoutSha256) ||
      !SHA256.test(attestation.stderrSha256) ||
      !Number.isInteger(attestation.stdoutByteLength) ||
      !Number.isInteger(attestation.stderrByteLength) ||
      attestation.stdoutByteLength < 0 ||
      attestation.stderrByteLength < 0 ||
      !SHA256.test(attestation.resultSha256) ||
      attestation.resultSha256 !==
        (await independentModelReviewDigests.value(
          Object.fromEntries(
            Object.entries(attestation).filter(
              ([key]) => key !== "resultSha256",
            ),
          ),
        ))
    ) {
      throw new TypeError(
        "Test evidence metadata does not match its runner attestation.",
      );
    }
    for (const [ref, digest, length] of [
      [
        attestation.stdoutRef,
        attestation.stdoutSha256,
        attestation.stdoutByteLength,
      ],
      [
        attestation.stderrRef,
        attestation.stderrSha256,
        attestation.stderrByteLength,
      ],
    ]) {
      const exactTranscriptPath = await realpath(
        resolve(exactEvidenceRoot, ref),
      );
      if (
        !exactTranscriptPath.startsWith(`${exactEvidenceRoot}/`) ||
        !(await stat(exactTranscriptPath)).isFile()
      ) {
        throw new TypeError(
          "Test transcript path escapes the trusted evidence root.",
        );
      }
      const transcriptBytes = await readFile(exactTranscriptPath);
      if (
        transcriptBytes.byteLength !== length ||
        (await independentModelReviewDigests.bytes(transcriptBytes)) !== digest
      ) {
        throw new TypeError(
          "Test transcript bytes do not match the runner attestation.",
        );
      }
    }
  }
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
      "implementationIdentity",
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
    implementationIdentity,
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
  if (
    (await independentModelReviewDigests.bytes(currentGeneratorBytes)) !==
    (await independentModelReviewDigests.bytes(frozenGeneratorBytes))
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
  const testPlanSha256 =
    await independentModelReviewDigests.bytes(testPlanBytes);
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
  const testEvidence = await collectIndependentReviewTestEvidence({
    repoPath: exactRepoPath,
    sourceCommit,
    sourceTree: tree,
    planPath: FIXED_PATHS.testPlan,
    evidenceRoot: testEvidenceRoot,
  });
  await validateTestEvidence(
    testEvidence,
    sourceCommit,
    tree,
    testEvidenceRoot,
    testPlan.planSha256,
    collectorSha256,
  );
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
      testResultSchemaSha256: await artifactDigest(FIXED_PATHS.testResultSchema),
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
      bundleGeneratorSha256: await artifactDigest(FIXED_PATHS.generator),
      testPlanPath: FIXED_PATHS.testPlan,
      testPlanSha256,
      testEvidenceCollectorPath: FIXED_PATHS.testEvidenceCollector,
      testEvidenceCollectorSha256: collectorSha256,
      runtimeControlPlanePath: FIXED_PATHS.runtimeControlPlane,
      runtimeControlPlaneSha256: await artifactDigest(
        FIXED_PATHS.runtimeControlPlane,
      ),
      sandboxPolicyTemplatePath: FIXED_PATHS.sandboxPolicyTemplate,
      sandboxPolicyTemplateSha256: await artifactDigest(
        FIXED_PATHS.sandboxPolicyTemplate,
      ),
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
    "implementation-model-id",
    "implementation-model-version",
    "participant-manifest-sha256",
    "implementation-session-sha256",
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
