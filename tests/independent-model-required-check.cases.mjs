import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  adaptQwenSummaryTransport,
  buildPromptBoundReviewMaterial,
  containsSelfReference,
  validateIndependentModelRequiredCheck,
} from "../scripts/validate-independent-model-review-check.mjs";
import {
  independentModelReviewDigests,
  parseIndependentReviewJsonBytes,
  parseIndependentReviewTapSummary,
  validateIndependentModelReviewOutputArtifact,
  validateIndependentReviewSchemaInstance,
  validateIndependentReviewTestEvidenceClosure,
} from "../lib/independent-model-review.mjs";
import {
  serializeIndependentReviewRuntimeBinding,
} from "../lib/independent-review-runtime-binding.mjs";

const root = new URL("../", import.meta.url);
const readText = (path) => readFile(new URL(path, root), "utf8");
const REQUIRED_CHECK_PROVIDER = "ALIBABA_CLOUD_MODEL_STUDIO";
const REQUIRED_CHECK_REGION = "CHINA_BEIJING";
const REQUIRED_CHECK_MODEL = "qwen3.7-max-2026-05-20";
const REQUIRED_CHECK_BASE_URL =
  "https://ws-lkkcajn7d1l4okvo.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";
const REQUIRED_CHECK_ASSURANCE = "PLATFORM_TCB_PROMPT_BOUND_MODEL_REVIEW";
const MATERIAL_PARENT = "944ef9daafc6ceb97999501f9162a569d25c214a";
const M1A_PATHS = Object.freeze([
  "docs/adr/0027-reference-review-required-check-material-envelope.md",
  "implementation/governance/independent-review/github-required-check-prompt.v2.md",
  "implementation/governance/schemas/independent-model-review-material-envelope.v1.schema.json",
  "implementation/governance/schemas/independent-model-review-output.v3.schema.json",
  "lib/independent-model-review.mjs",
  "scripts/run-independent-review-test-evidence.mjs",
  "scripts/validate-independent-model-review-check.mjs",
  "tests/independent-model-required-check.cases.mjs",
  "tests/independent-review-bundle-generator.test.mjs",
]);
const M1A_PATH_SET =
  "sha256:7df05c017bba4b532e155185cfe66a94f4718886191cbcc9cd6d0855ddc837b1";
const M1B_DIRECTORY =
  "implementation/governance/independent-review/evidence/required-check-material-envelope-v1";
const M1B_BASENAMES = Object.freeze([
  "formal-repository-gates-with-recursive-skips.result.json",
  "formal-repository-gates-with-recursive-skips.stderr.log",
  "formal-repository-gates-with-recursive-skips.stdout.log",
  "formal-targeted-with-recursive-skips.result.json",
  "formal-targeted-with-recursive-skips.stderr.log",
  "formal-targeted-with-recursive-skips.stdout.log",
  "lint.result.json",
  "lint.stderr.log",
  "lint.stdout.log",
  "runtime-binding.v1.json",
]);
const FORMAL_STATIC_PATHS = Object.freeze([
  "implementation/governance/independent-review/independent-review-test-plan.v2.json",
  "scripts/run-independent-review-test-evidence.mjs",
  "implementation/governance/schemas/independent-review-test-result.v3.schema.json",
  "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in",
  "lib/independent-review-runtime-binding.mjs",
  "package.json",
]);
const TEST_ISOLATION_VERSION =
  "isolation=macos-sandbox-exec-git-archive-readonly-history-network-denied";
const NETWORK_TEST_MODE =
  "network-test-mode=frozen-deterministic-offline-alternatives";
const MATERIAL_FULL_PATHS = Object.freeze([
  "implementation/governance/independent-review/github-required-check-prompt.v2.md",
  "implementation/governance/independent-review/independent-review-policy.v2.json",
  "implementation/governance/schemas/independent-model-review-material-envelope.v1.schema.json",
  "implementation/governance/schemas/independent-model-review-output.v3.schema.json",
  "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json",
  "implementation/p2/attestations/p2-execution-baseline-attestation.bc718b.v1.json",
  "lib/p2-worker-attestation-policy.mjs",
].sort());
const MATERIAL_PATCH_PATHS = Object.freeze([
  "lib/independent-model-review.mjs",
  "scripts/validate-independent-model-review-check.mjs",
]);
const TEST_WHITELIST_PATHS = Object.freeze([
  "tests/c13-hosted-source-review-workflow.test.mjs",
  "tests/independent-model-required-check.cases.mjs",
  "tests/independent-model-review-policy-activation.cases.mjs",
  "tests/independent-model-review.test.mjs",
  "tests/independent-review-runtime-manifest.test.mjs",
  "tests/p1-b11-protected-review-candidate.test.mjs",
  "tests/p1-b11-protected-review-preparation-evidence.test.mjs",
  "tests/p2-acceptance-profile-v2.test.mjs",
  "tests/p2-acceptance-receipt-v2.test.mjs",
  "tests/p2-execution-baseline-git.test.mjs",
  "tests/p2-governance-readiness.test.mjs",
  "tests/p2-profile-backfill-preparation.test.mjs",
  "tests/p2-readiness-route.test.mjs",
  "tests/p2-start-authorization.test.mjs",
  "tests/p2-start-policy.test.mjs",
  "tests/p2-worker-attestation.test.mjs",
  "tests/p2-worker-runtime-wiring.test.mjs",
  "tests/reference-review-fixtures.mjs",
  "tests/reference-review-readiness.test.mjs",
  "tests/reference-review-receipt.test.mjs",
  "tests/v53-supplemental-evidence-index-v2.test.mjs",
]);
const TEST_WHITELIST_PATH_SET =
  "sha256:0e18cbf47bd69aa19ef982dc1388e07062080134ceada555ba21eda00f216a58";
const GIT = "/usr/bin/git";
const GIT_ENV = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
});

function git(repository, args, options = {}) {
  return execFileSync(
    GIT,
    ["--no-replace-objects", "-C", repository, ...args],
    {
      env: GIT_ENV,
      stdio: ["ignore", "pipe", "pipe"],
      ...options,
    },
  );
}

function gitText(repository, args) {
  return git(repository, args, { encoding: "utf8" }).trim();
}

function commitFixture(repository, message, paths) {
  git(repository, ["add", "--", ...paths]);
  assert.deepEqual(
    git(repository, ["diff", "--cached", "--name-only", "-z", "--"])
      .toString("utf8")
      .split("\0")
      .filter(Boolean)
      .sort(),
    [...paths].sort(),
  );
  git(
    repository,
    [
      "-c",
      "user.name=Independent Model Check Test",
      "-c",
      "user.email=independent-model-check@example.invalid",
      "-c",
      "commit.gpgSign=false",
      "-c",
      "core.hooksPath=/dev/null",
      "commit",
      "-qm",
      message,
    ],
  );
}

function gitBlob(repository, commit, path) {
  return git(repository, ["cat-file", "blob", `${commit}:${path}`]);
}

function renderSyntheticTap(expectation, { actualFailure = false } = {}) {
  const counts = actualFailure
    ? { ...expectation, pass: expectation.pass - 1, fail: 1 }
    : expectation;
  const lines = ["TAP version 13"];
  let index = 1;
  for (let pass = 0; pass < counts.pass; pass += 1) {
    lines.push(
      `# Subtest: synthetic pass ${index}`,
      `ok ${index} - synthetic pass ${index}`,
    );
    index += 1;
  }
  for (let fail = 0; fail < counts.fail; fail += 1) {
    lines.push(
      `# Subtest: synthetic actual failure ${index}`,
      `not ok ${index} - synthetic actual failure ${index}`,
    );
    index += 1;
  }
  for (const name of expectation.allowedSkippedTestNames) {
    lines.push(`# Subtest: ${name}`, `ok ${index} - ${name} # SKIP`);
    index += 1;
  }
  lines.push(
    `1..${counts.tests}`,
    `# tests ${counts.tests}`,
    "# suites 0",
    `# pass ${counts.pass}`,
    `# fail ${counts.fail}`,
    `# cancelled ${counts.cancelled}`,
    `# skipped ${counts.skipped}`,
    `# todo ${counts.todo}`,
    "# duration_ms 1",
  );
  return Buffer.from(`${lines.join("\n")}\n`, "utf8");
}

async function syntheticRuntimeBinding() {
  const digest = async (label) =>
    independentModelReviewDigests.bytes(Buffer.from(label, "utf8"));
  const toolchainFile = async (label) => ({
    pathSha256: await digest(`${label}:path`),
    byteLength: 1,
    sha256: await digest(`${label}:bytes`),
  });
  const dependencyPackages = [];
  for (const [name, version] of [
    ["ajv", "8.20.0"],
    ["ajv-formats", "2.1.1"],
    ["fast-deep-equal", "3.1.3"],
    ["fast-uri", "3.1.2"],
    ["json-schema-traverse", "1.0.0"],
    ["require-from-string", "2.0.2"],
  ]) {
    dependencyPackages.push({
      name,
      version,
      entryCount: 1,
      totalByteLength: 1,
      manifestSha256: await digest(`package:${name}`),
    });
  }
  const gitToolchain = {
    version: "git version 2.50.1",
    developerDirectoryPathSha256: await digest("developer-directory"),
    shimExecutable: await toolchainFile("git-shim"),
    resolvedExecutable: await toolchainFile("git-resolved"),
    xcrunLibrary: await toolchainFile("xcrun-library"),
    xcrunExecutable: await toolchainFile("xcrun-executable"),
    xcrunCache: await toolchainFile("xcrun-cache"),
    bindingSha256: `sha256:${"0".repeat(64)}`,
  };
  gitToolchain.bindingSha256 = await independentModelReviewDigests.value(
    Object.fromEntries(
      Object.entries(gitToolchain).filter(([key]) => key !== "bindingSha256"),
    ),
  );
  const systemToolchain = {
    shasumExecutable: await toolchainFile("shasum"),
    perlExecutable: await toolchainFile("perl"),
    bindingSha256: `sha256:${"0".repeat(64)}`,
  };
  systemToolchain.bindingSha256 = await independentModelReviewDigests.value(
    Object.fromEntries(
      Object.entries(systemToolchain).filter(
        ([key]) => key !== "bindingSha256",
      ),
    ),
  );
  const binding = {
    schemaVersion: "independent-review-runtime-binding.v1",
    nodeExecutable: {
      version: "v24.18.0",
      pathSha256: await digest("node:path"),
      byteLength: 1,
      sha256: await digest("node:bytes"),
    },
    dependencyPackages,
    dependencySetSha256:
      await independentModelReviewDigests.value(dependencyPackages),
    gitToolchain,
    systemToolchain,
    bindingSha256: `sha256:${"0".repeat(64)}`,
  };
  binding.bindingSha256 = await independentModelReviewDigests.value(
    Object.fromEntries(
      Object.entries(binding).filter(([key]) => key !== "bindingSha256"),
    ),
  );
  return binding;
}

async function writeSyntheticCollectorEvidence({
  repository,
  implementationCommit,
  implementationTree,
}) {
  const planPath =
    "implementation/governance/independent-review/independent-review-test-plan.v2.json";
  const collectorPath = "scripts/run-independent-review-test-evidence.mjs";
  const sandboxPath =
    "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in";
  const runtimeGeneratorPath = "lib/independent-review-runtime-binding.mjs";
  const [planBytes, collectorBytes, sandboxBytes, runtimeGeneratorBytes] = [
    planPath,
    collectorPath,
    sandboxPath,
    runtimeGeneratorPath,
  ].map((path) => gitBlob(repository, implementationCommit, path));
  const plan = JSON.parse(planBytes.toString("utf8"));
  const runtimeBinding = await syntheticRuntimeBinding();
  const runtimeBindingBytes = serializeIndependentReviewRuntimeBinding(runtimeBinding);
  const runtimeBindingDescriptor = {
    artifactRef: "runtime-binding.v1.json",
    artifactSha256: await independentModelReviewDigests.bytes(runtimeBindingBytes),
    artifactByteLength: runtimeBindingBytes.byteLength,
    bindingSha256: runtimeBinding.bindingSha256,
    nodeExecutableSha256: runtimeBinding.nodeExecutable.sha256,
    dependencySetSha256: runtimeBinding.dependencySetSha256,
    gitToolchainSha256: runtimeBinding.gitToolchain.bindingSha256,
    systemToolchainSha256: runtimeBinding.systemToolchain.bindingSha256,
    generator: {
      path: runtimeGeneratorPath,
      gitBlobSha256:
        await independentModelReviewDigests.bytes(runtimeGeneratorBytes),
      executedBytesSha256:
        await independentModelReviewDigests.bytes(runtimeGeneratorBytes),
    },
  };
  const evidenceDirectory = join(repository, M1B_DIRECTORY);
  await mkdir(evidenceDirectory, { recursive: true });
  await writeFile(
    join(evidenceDirectory, "runtime-binding.v1.json"),
    runtimeBindingBytes,
  );
  const collectorSha256 =
    await independentModelReviewDigests.bytes(collectorBytes);
  const sandboxSha256 = await independentModelReviewDigests.bytes(sandboxBytes);
  const sourceManifestSha256 = `sha256:${"1".repeat(64)}`;
  const parameterSetSha256 = `sha256:${"2".repeat(64)}`;
  const invocationSha256 = await independentModelReviewDigests.value({
    executable: "/usr/bin/sandbox-exec",
    templateSha256: sandboxSha256,
    parameterSetSha256,
  });
  for (const command of plan.commands) {
    const hasTestExpectation = Object.hasOwn(command, "testExpectation");
    const claimedStdout = hasTestExpectation
      ? renderSyntheticTap(command.testExpectation)
      : null;
    const stdout = hasTestExpectation
      ? renderSyntheticTap(command.testExpectation)
      : Buffer.from("synthetic lint pass\n", "utf8");
    const stderr = Buffer.alloc(0);
    const testSummary = hasTestExpectation
      ? await parseIndependentReviewTapSummary(claimedStdout)
      : null;
    if (hasTestExpectation) {
      assert.notEqual(testSummary, null);
    }
    const stdoutRef = `${command.commandId}.stdout.log`;
    const stderrRef = `${command.commandId}.stderr.log`;
    const resultRef = `${command.commandId}.result.json`;
    const result = {
      schemaVersion: "independent-review-test-result.v3",
      evidenceId: command.commandId,
      testPlanSha256: plan.planSha256,
      sourceCommit: implementationCommit,
      sourceTree: implementationTree,
      runner: {
        path: collectorPath,
        gitBlobSha256: collectorSha256,
        executedBytesSha256: collectorSha256,
      },
      runtimeBinding: structuredClone(runtimeBindingDescriptor),
      executionSource: {
        mode: "MACOS_SEATBELT_GIT_ARCHIVE_READONLY_HISTORY_V3",
        cloneMode: "GIT_ARCHIVE_WITH_READ_ONLY_HISTORY_SNAPSHOT",
        before: {
          head: implementationCommit,
          tree: implementationTree,
          sourceManifestSha256,
        },
        after: {
          head: implementationCommit,
          tree: implementationTree,
          sourceManifestSha256,
        },
        unchanged: true,
        gitHistory: {
          mode: "READ_ONLY_ALL_REF_REACHABLE_OBJECT_SNAPSHOT",
          sourceCommit: implementationCommit,
          sourceTree: implementationTree,
          refTipCount: 1,
          refTipSetSha256: `sha256:${"3".repeat(64)}`,
          reachableObjectCount: 1,
          reachableObjectSetSha256: `sha256:${"4".repeat(64)}`,
          pointerSha256: `sha256:${"5".repeat(64)}`,
          beforeManifestSha256: `sha256:${"6".repeat(64)}`,
          afterManifestSha256: `sha256:${"6".repeat(64)}`,
          unchanged: true,
          metadataWritable: false,
        },
        sourceExportRemoved: true,
        sandbox: {
          executable: "/usr/bin/sandbox-exec",
          templatePath: sandboxPath,
          templateSha256: sandboxSha256,
          parameterSetSha256,
          invocationSha256,
          sourceWritable: false,
          buildOutputsWritable: true,
          writableWorkRoots: [
            ".next",
            ".vinext",
            ".wrangler",
            "dist",
            "node_modules/.vite-temp",
          ],
          scratchWritable: true,
          gitMetadataPresent: true,
          gitMetadataWritable: false,
          sharedDependenciesWritable: false,
          networkPolicy: "DENY_ALL",
          networkDependentTestMode: "FROZEN_DETERMINISTIC_OFFLINE_ALTERNATIVES",
        },
      },
      commandId: command.commandId,
      argvSha256: await independentModelReviewDigests.value({
        executable: command.executable,
        args: command.args,
      }),
      observation: {
        exitCode: 0,
        signal: null,
        timedOut: false,
        startedAt: "2026-08-15T00:00:00.000Z",
        finishedAt: "2026-08-15T00:00:01.000Z",
      },
      testSummary,
      stdoutRef,
      stdoutSha256: await independentModelReviewDigests.bytes(stdout),
      stdoutByteLength: stdout.byteLength,
      stderrRef,
      stderrSha256: await independentModelReviewDigests.bytes(stderr),
      stderrByteLength: stderr.byteLength,
      resultSha256: `sha256:${"0".repeat(64)}`,
    };
    const unsignedResult = structuredClone(result);
    delete unsignedResult.resultSha256;
    result.resultSha256 =
      await independentModelReviewDigests.value(unsignedResult);
    await Promise.all([
      writeFile(join(evidenceDirectory, stdoutRef), stdout),
      writeFile(join(evidenceDirectory, stderrRef), stderr),
      writeFile(
        join(evidenceDirectory, resultRef),
        `${JSON.stringify(result)}\n`,
        "utf8",
      ),
    ]);
  }
  assert.deepEqual(
    (await readdir(evidenceDirectory)).sort(),
    [...M1B_BASENAMES].sort(),
  );
}

async function semanticEnvelopeTopologyFixture() {
  const directory = await mkdtemp(join(tmpdir(), "semantic-envelope-check-"));
  const repository = join(directory, "repository");
  execFileSync(
    GIT,
    [
      "--no-replace-objects",
      "clone",
      "-q",
      "--no-hardlinks",
      "--no-checkout",
      fileURLToPath(root),
      repository,
    ],
    {
      env: GIT_ENV,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  git(repository, ["checkout", "-q", "--detach", MATERIAL_PARENT]);
  assert.equal(gitText(repository, ["rev-parse", "HEAD"]), MATERIAL_PARENT);
  const eventBase = gitText(repository, [
    "rev-parse",
    `${MATERIAL_PARENT}^`,
  ]);
  for (const path of M1A_PATHS) {
    const target = join(repository, path);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(fileURLToPath(new URL(path, root)), target);
    await chmod(target, 0o600);
  }
  commitFixture(repository, "synthetic M1A", M1A_PATHS);
  const implementationCommit = gitText(repository, ["rev-parse", "HEAD"]);
  const implementationTree = gitText(repository, ["rev-parse", "HEAD^{tree}"]);
  assert.equal(
    gitText(repository, ["rev-parse", `${implementationCommit}^`]),
    MATERIAL_PARENT,
  );
  await writeSyntheticCollectorEvidence({
    repository,
    implementationCommit,
    implementationTree,
  });
  commitFixture(
    repository,
    "synthetic M1B",
    M1B_BASENAMES.map((name) => `${M1B_DIRECTORY}/${name}`),
  );
  const head = gitText(repository, ["rev-parse", "HEAD"]);
  const tree = gitText(repository, ["rev-parse", "HEAD^{tree}"]);
  assert.equal(
    gitText(repository, ["rev-parse", `${head}^`]),
    implementationCommit,
  );
  const outputFile = join(directory, "output.json");
  const materialFile = join(directory, "review-material.txt");
  const writeOutput = (value) =>
    writeFile(outputFile, JSON.stringify(value), "utf8");
  const validationCounts = { outer: 0 };
  const validate = (overrides = {}) => {
    validationCounts.outer += 1;
    return validateIndependentModelRequiredCheck({
      repository,
      outputFile,
      expectedHead: head,
      expectedTree: tree,
      expectedBase: eventBase,
      requestedProvider: REQUIRED_CHECK_PROVIDER,
      requestedRegion: REQUIRED_CHECK_REGION,
      baseUrl: REQUIRED_CHECK_BASE_URL,
      requestedModel: REQUIRED_CHECK_MODEL,
      assuranceLevel: REQUIRED_CHECK_ASSURANCE,
      materialFile,
      eventName: "pull_request",
      ...overrides,
    });
  };
  return {
    directory,
    repository,
    eventBase,
    implementationCommit,
    implementationTree,
    head,
    tree,
    outputFile,
    materialFile,
    writeOutput,
    validate,
    validationCounts,
  };
}

function frozenSubject(repository, commit, path) {
  const fields = gitText(repository, [
    "ls-tree",
    commit,
    "--",
    `:(literal)${path}`,
  ]).split(/\s+/u);
  assert.equal(fields[0], "100644");
  assert.equal(fields[1], "blob");
  const bytes = gitBlob(repository, commit, path);
  return {
    path,
    gitMode: fields[0],
    byteLength: bytes.byteLength,
    rawSha256: null,
    bytes,
  };
}

async function frozenSubjectWithDigest(repository, commit, path) {
  const subject = frozenSubject(repository, commit, path);
  subject.rawSha256 = await independentModelReviewDigests.bytes(subject.bytes);
  return subject;
}

function cloneEvidenceMap(evidenceMap) {
  return new Map(
    [...evidenceMap].map(([name, bytes]) => [name, Buffer.from(bytes)]),
  );
}

async function rewriteResultEvidence(evidenceMap, commandId, mutate) {
  const resultRef = `${commandId}.result.json`;
  const result = parseIndependentReviewJsonBytes(
    evidenceMap.get(resultRef),
    `synthetic ${commandId} result`,
  );
  await mutate(result);
  delete result.resultSha256;
  result.resultSha256 = await independentModelReviewDigests.value(result);
  evidenceMap.set(
    resultRef,
    Buffer.from(`${JSON.stringify(result)}\n`, "utf8"),
  );
  return result;
}

async function syntheticEvidenceClosureHarness(fixture) {
  const staticSubjects = await Promise.all(
    FORMAL_STATIC_PATHS.map((path) =>
      frozenSubjectWithDigest(
        fixture.repository,
        fixture.implementationCommit,
        path,
      ),
    ),
  );
  const evidenceMap = new Map(
    M1B_BASENAMES.map((name) => [
      name,
      gitBlob(
        fixture.repository,
        fixture.head,
        `${M1B_DIRECTORY}/${name}`,
      ),
    ]),
  );
  const plan = parseIndependentReviewJsonBytes(
    staticSubjects[0].bytes,
    "synthetic Independent Review test plan",
  );
  const createBundle = async (activeEvidenceMap) => {
    const testEvidenceSubjects = [];
    for (const command of plan.commands) {
      const outputRef = `${command.commandId}.result.json`;
      const outputBytes = activeEvidenceMap.get(outputRef);
      const result = parseIndependentReviewJsonBytes(
        outputBytes,
        `synthetic ${command.commandId} result`,
      );
      const { runtimeBinding, executionSource } = result;
      testEvidenceSubjects.push({
        evidenceId: result.evidenceId,
        command: `${command.executable} ${command.args.join(" ")}`,
        status: "PASS",
        exitCode: result.observation.exitCode,
        outputRef,
        outputSha256:
          await independentModelReviewDigests.bytes(outputBytes),
        outputByteLength: outputBytes.byteLength,
        truncated: false,
        sourceCommit: fixture.implementationCommit,
        runner: "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE",
        toolVersions: [
          TEST_ISOLATION_VERSION,
          NETWORK_TEST_MODE,
          `runtime-binding=${runtimeBinding.bindingSha256}`,
          `node-executable=${runtimeBinding.nodeExecutableSha256}`,
          `dependency-set=${runtimeBinding.dependencySetSha256}`,
          `git-toolchain=${runtimeBinding.gitToolchainSha256}`,
          `system-toolchain=${runtimeBinding.systemToolchainSha256}`,
          `sandbox-template=${executionSource.sandbox.templateSha256}`,
          `sandbox-invocation=${executionSource.sandbox.invocationSha256}`,
        ],
      });
    }
    return {
      source: {
        sourceCommit: fixture.implementationCommit,
        tree: fixture.implementationTree,
      },
      artifacts: {
        testPlanSha256: staticSubjects[0].rawSha256,
        testEvidenceCollectorPath: staticSubjects[1].path,
        testEvidenceCollectorSha256: staticSubjects[1].rawSha256,
        testResultSchemaPath: staticSubjects[2].path,
        testResultSchemaSha256: staticSubjects[2].rawSha256,
        sandboxPolicyTemplatePath: staticSubjects[3].path,
        sandboxPolicyTemplateSha256: staticSubjects[3].rawSha256,
      },
      testEvidenceSubjects,
    };
  };
  const bundle = await createBundle(evidenceMap);
  const validate = async ({
    activeEvidenceMap = evidenceMap,
    activeBundle = bundle,
    testPlanBytes = staticSubjects[0].bytes,
    collectorBytes = staticSubjects[1].bytes,
    testResultSchemaBytes = staticSubjects[2].bytes,
    sandboxPolicyTemplateBytes = staticSubjects[3].bytes,
  } = {}) =>
    validateIndependentReviewTestEvidenceClosure({
      bundle: activeBundle,
      testPlanBytes,
      collectorBytes,
      testResultSchemaBytes,
      sandboxPolicyTemplateBytes,
      evidenceResolver: async (name) => activeEvidenceMap.get(name),
    });
  return {
    plan,
    staticSubjects,
    evidenceMap,
    createBundle,
    validate,
  };
}

async function materializeFrozenPaths({
  sourceRepository,
  sourceCommit,
  targetRepository,
  paths,
}) {
  for (const path of paths) {
    const target = join(targetRepository, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, gitBlob(sourceRepository, sourceCommit, path));
    await chmod(target, 0o600);
  }
}

async function writeEvidenceMap(repository, evidenceMap, basenames) {
  for (const name of basenames) {
    const target = join(repository, M1B_DIRECTORY, name);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, evidenceMap.get(name));
    await chmod(target, 0o600);
  }
}

async function createM1BVariant({
  repository,
  implementationCommit,
  evidenceMap,
  basenames = M1B_BASENAMES,
  extraEvidence = null,
}) {
  git(repository, ["checkout", "-q", "--detach", implementationCommit]);
  await writeEvidenceMap(repository, evidenceMap, basenames);
  const paths = basenames.map((name) => `${M1B_DIRECTORY}/${name}`);
  if (extraEvidence !== null) {
    const target = join(repository, M1B_DIRECTORY, extraEvidence.name);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, extraEvidence.bytes);
    await chmod(target, 0o600);
    paths.push(`${M1B_DIRECTORY}/${extraEvidence.name}`);
  }
  commitFixture(repository, "synthetic M1B variant", paths);
  return {
    head: gitText(repository, ["rev-parse", "HEAD"]),
    tree: gitText(repository, ["rev-parse", "HEAD^{tree}"]),
  };
}

async function createM1AVariant({
  repository,
  fixture,
  paths = M1A_PATHS,
  drift = null,
}) {
  git(repository, ["checkout", "-q", "--detach", MATERIAL_PARENT]);
  await materializeFrozenPaths({
    sourceRepository: fixture.repository,
    sourceCommit: fixture.implementationCommit,
    targetRepository: repository,
    paths,
  });
  const committedPaths = [...paths];
  if (drift !== null) {
    const target = join(repository, drift.path);
    await mkdir(dirname(target), { recursive: true });
    const original = gitBlob(fixture.repository, MATERIAL_PARENT, drift.path);
    await writeFile(
      target,
      Buffer.concat([original, Buffer.from("\nsynthetic drift\n", "utf8")]),
    );
    await chmod(target, 0o600);
    if (!committedPaths.includes(drift.path)) {
      committedPaths.push(drift.path);
    }
  }
  commitFixture(repository, "synthetic M1A variant", committedPaths);
  return gitText(repository, ["rev-parse", "HEAD"]);
}

async function assertMaterialBuilderRejects(repository, head, pattern) {
  const tree = gitText(repository, ["rev-parse", `${head}^{tree}`]);
  await assert.rejects(
    () =>
      buildPromptBoundReviewMaterial({
        repository,
        expectedHead: head,
        expectedTree: tree,
        expectedBase: MATERIAL_PARENT,
      }),
    pattern,
  );
}

function clearRequiredCheckOutput(material) {
  return {
    schemaVersion: "independent-model-review-output.v3",
    reviewBinding: structuredClone(
      material.requiredCheckContract.reviewBinding,
    ),
    coverage: structuredClone(material.requiredCheckContract.coverage),
    reviewSummary: material.bindingSummary,
    findings: [],
    decision: "CLEAR",
  };
}

function differentSha256(value) {
  const replacement = value.endsWith("0") ? "1" : "0";
  return `${value.slice(0, -1)}${replacement}`;
}

function findingForSubject(subject, overrides = {}) {
  let lineSide = null;
  let startLine = null;
  let endLine = null;
  if (subject.evidenceMode === "VERBATIM_FULL_FILE") {
    lineSide = "FILE";
    startLine = 1;
    endLine = 1;
  } else if (subject.evidenceMode === "VERBATIM_PATCH") {
    const [start, end] = subject.newRanges[0] ?? subject.oldRanges[0];
    lineSide = subject.newRanges.length > 0 ? "NEW" : "OLD";
    startLine = start;
    endLine = end;
  }
  return {
    findingId: "required-check-binding",
    severity: "LOW",
    status: "OPEN",
    evidenceMode: subject.evidenceMode,
    evidenceDigest: subject.evidenceDigest,
    path: subject.path,
    lineSide,
    startLine,
    endLine,
    summary: "The bounded subject needs attention.",
    detailsSha256: `sha256:${"a".repeat(64)}`,
    resolutionEvidenceDigests: [],
    ...overrides,
  };
}

async function materialWithMutatedEnvelope(material, mutate) {
  const envelope = structuredClone(material.envelope);
  mutate(envelope);
  const digestOnlyCoverage = structuredClone(envelope.digestOnlyCoverage);
  delete digestOnlyCoverage.manifestSha256;
  envelope.digestOnlyCoverage.manifestSha256 =
    await independentModelReviewDigests.value(digestOnlyCoverage);
  const unsigned = structuredClone(envelope);
  delete unsigned.envelopeSha256;
  envelope.envelopeSha256 =
    await independentModelReviewDigests.value(unsigned);
  const replacement = Buffer.from(
    independentModelReviewDigests.canonicalize(envelope),
    "utf8",
  );
  const original = Buffer.from(material.envelopeBytes);
  const start = Buffer.from(material.bytes).indexOf(original);
  assert.ok(start >= 0);
  return Buffer.concat([
    Buffer.from(material.bytes).subarray(0, start),
    replacement,
    Buffer.from(material.bytes).subarray(start + original.byteLength),
  ]);
}

export async function assertIndependentModelRequiredCheckContract() {
  const [
    workflow,
    historicalPrompt,
    prompt,
    validator,
    providerDecision,
    envelopeDecision,
  ] = await Promise.all([
    readText(".github/workflows/independent-model-review.yml"),
    readText(
      "implementation/governance/independent-review/github-required-check-prompt.v1.md",
    ),
    readText(
      "implementation/governance/independent-review/github-required-check-prompt.v2.md",
    ),
    readText("scripts/validate-independent-model-review-check.mjs"),
    readText("docs/adr/0023-qwen-independent-model-required-check.md"),
    readText(
      "docs/adr/0027-reference-review-required-check-material-envelope.md",
    ),
  ]);

  assert.match(workflow, /^name: Independent model review$/mu);
  assert.match(workflow, /^  pull_request:$/mu);
  assert.match(workflow, /^  merge_group:$/mu);
  assert.doesNotMatch(workflow, /pull_request_target|\n\s+paths(?:-ignore)?:/u);
  assert.match(workflow, /^  contents: read$/mu);
  assert.match(workflow, /^  independent-model-review:$/mu);
  assert.match(workflow, /^    name: independent-model-review$/mu);
  assert.match(workflow, /^    runs-on: ubuntu-24\.04$/mu);
  assert.match(
    workflow,
    /actions\/checkout@11d5960a326750d5838078e36cf38b85af677262/u,
  );
  assert.match(
    workflow,
    /QwenLM\/qwen-code-action@132374a450dd882f728d117fdafc64201e81abff/u,
  );
  assert.match(workflow, /persist-credentials: false/u);
  assert.match(workflow, /openai_api_key: \$\{\{ secrets\.DASHSCOPE_API_KEY \}\}/u);
  assert.match(
    workflow,
    /openai_base_url: https:\/\/ws-lkkcajn7d1l4okvo\.cn-beijing\.maas\.aliyuncs\.com\/compatible-mode\/v1/u,
  );
  assert.match(workflow, /openai_model: "qwen3\.7-max-2026-05-20"/u);
  assert.match(workflow, /qwen_cli_version: "0\.21\.10"/u);
  assert.match(workflow, /qwen_debug: "false"/u);
  assert.match(workflow, /upload_artifacts: "false"/u);
  assert.match(workflow, /"maxToolCalls": 0/u);
  assert.match(workflow, /"skipStartupContext": true/u);
  assert.match(
    workflow,
    /"fileName": "__QWEN_REQUIRED_CHECK_NO_CONTEXT__\.md"/u,
  );
  assert.match(workflow, /"computerUse": \{ "enabled": false \}/u);
  assert.match(workflow, /"webSearch": \{ "enabled": false \}/u);
  assert.match(workflow, /"toolSearch": \{ "enabled": false \}/u);
  assert.match(workflow, /"disableAllHooks": true/u);
  assert.match(workflow, /"excluded": \["\*"\]/u);
  assert.match(
    workflow,
    /"disabledLevels": \["project", "user", "extension", "bundled"\]/u,
  );
  assert.match(workflow, /"mcp__\*"/u);
  assert.match(workflow, /"allow": \[\]/u);
  assert.match(workflow, /"ask": \[\]/u);
  assert.match(workflow, /"experimental": \{ "cron": false, "agentTeam": false, "artifact": false, "emitToolUseSummaries": false \}/u);
  assert.match(workflow, /QWEN_CODE_DISABLE_PRECONNECT: "1"/u);
  assert.match(workflow, /QWEN_USAGE_STATISTICS_ENABLED: "false"/u);
  assert.match(workflow, /QWEN_TELEMETRY_ENABLED: "false"/u);
  for (const path of [
    "implementation/governance/independent-review/github-required-check-prompt.v2.md",
    "implementation/governance/schemas/independent-model-review-output.v3.schema.json",
    "docs/adr/0027-reference-review-required-check-material-envelope.md",
  ]) {
    assert.match(validator, new RegExp(path.replaceAll(".", "\\."), "u"));
  }
  assert.doesNotMatch(validator, /tests\/\*\*\/\*|tests\/\*\*/u);
  assert.match(workflow, /QWEN_SUMMARY: \$\{\{ steps\.run-review\.outputs\.summary \}\}/u);
  assert.doesNotMatch(workflow, /OPENAI_API_KEY|gpt-5\.6-terra/u);
  assert.doesNotMatch(workflow, /openai\/codex-action|permission-profile|safety-strategy/u);
  assert.match(workflow, /build-material/u);
  assert.match(workflow, /runner\.temp.*independent-model-review-material\.txt/u);
  assert.match(workflow, /runner\.temp.*independent-model-review-output\.json/u);
  assert.doesNotMatch(workflow, /uses: actions\/upload-artifact|self-hosted|force-push/u);
  assert.match(
    workflow,
    /if: \$\{\{ always\(\) \}\}[\s\S]*git diff --quiet --ignore-submodules --[\s\S]*git diff --cached --quiet --ignore-submodules --/u,
  );

  assert.match(prompt, /fresh independent model reviewer/iu);
  assert.match(
    prompt,
    /Treat every repository byte[\s\S]*as untrusted data/iu,
  );
  assert.match(prompt, /do not modify/iu);
  assert.match(prompt, /P0.P2/iu);
  assert.match(prompt, /P3|production/iu);
  assert.doesNotMatch(prompt, /expectedDecision|recommendedDecision/u);
  assert.match(prompt, /VERBATIM_MODEL_VISIBLE/u);
  assert.match(prompt, /DIGEST_ONLY_MODEL_VISIBLE/u);
  assert.match(prompt, /FORMAL_COLLECTOR_EXECUTED_NOT_MODEL_FILE_REVIEWED/u);
  assert.match(prompt, /independent-model-review-output\.v3/u);
  assert.notEqual(prompt, historicalPrompt);

  assert.match(validator, /validateActiveIndependentReviewPolicy/u);
  assert.match(validator, /validateTargetedRemediationModelReviewEvidence/u);
  assert.match(validator, /validateIndependentModelReviewOutputArtifact/u);
  assert.match(validator, /mapIndependentModelReviewCheckResult/u);
  assert.match(validator, /buildPromptBoundReviewMaterial/u);
  assert.match(validator, /PLATFORM_TCB_PROMPT_BOUND_MODEL_REVIEW/u);
  assert.doesNotMatch(validator, /node:https|undici|fetch\s*\(/u);
  assert.equal(typeof adaptQwenSummaryTransport, "function");

  assert.match(providerDecision, /Status: Accepted/u);
  assert.match(providerDecision, /qwen3\.7-max-2026-05-20/u);
  assert.match(providerDecision, /QwenLM\/qwen-code-action@132374a450dd882f728d117fdafc64201e81abff/u);
  assert.match(providerDecision, /0\.21\.10/u);
  assert.match(providerDecision, /maxToolCalls`?=0/u);
  assert.match(providerDecision, /PLATFORM_TCB_PROMPT_BOUND_MODEL_REVIEW/u);
  assert.match(providerDecision, /exit 55/u);
  assert.match(providerDecision, /DASHSCOPE_API_KEY/u);
  assert.match(providerDecision, /general Model Studio[\s\S]*pay-as-you-go/iu);
  assert.match(
    providerDecision,
    /structured-output enforcement must not be treated as proven/iu,
  );
  assert.match(providerDecision, /existing provider-neutral output Schema[\s\S]*fail-closed authority/iu);
  assert.match(providerDecision, /does not alter[\s\S]*P1-B11[\s\S]*P3[\s\S]*production/iu);
  assert.match(
    providerDecision,
    /terminal output contract[\s\S]*after all untrusted review material/iu,
  );
  assert.match(
    providerDecision,
    /first non-whitespace byte[\s\S]*last non-whitespace byte/iu,
  );
  assert.match(
    providerDecision,
    /exactly one JSON object[\s\S]*Markdown code fences[\s\S]*prefixes[\s\S]*suffixes/iu,
  );
  assert.match(providerDecision, /reviewSummary[\s\S]*start exactly/iu);
  assert.match(
    providerDecision,
    /31637078154[\s\S]*31659601178[\s\S]*transport wrapper/iu,
  );
  assert.match(
    providerDecision,
    /raw JSON remains[\s\S]*unchanged[\s\S]*one lowercase `json` Markdown fence/iu,
  );
  assert.match(
    providerDecision,
    /Multiple fences[\s\S]*unknown language labels[\s\S]*trailing content[\s\S]*remain invalid/iu,
  );
  assert.match(envelopeDecision, /Status: Accepted/u);
  assert.match(envelopeDecision, /MIXED_VERBATIM_PATCH_AND_GIT_DIGEST_ONLY/u);
  assert.match(envelopeDecision, /exact 21-path allowlist/iu);
  assert.match(envelopeDecision, /Historical Output v2 remains valid only/iu);
  const envelopeContractMatch = envelopeDecision.match(
    /<!-- REQUIRED_CHECK_ENVELOPE_CONTRACT_V1\n(\{[^\n]+\})\n-->/u,
  );
  assert.ok(envelopeContractMatch);
  const envelopeContract = parseIndependentReviewJsonBytes(
    Buffer.from(envelopeContractMatch[1], "utf8"),
    "Required Check Envelope contract",
    64 * 1024,
  );
  assert.deepEqual(envelopeContract.performance, {
    reusableKey: ["repository", "head", "tree", "eventBase"],
    pureOutputMatrixUsesFrozenMaterial: true,
    outerRequiredCheckRevalidates: [
      "gitObjects",
      "material",
      "topology",
      "provider",
      "location",
      "dirtyWorktree",
      "replay",
    ],
    testCasesRemoved: 0,
    topLevelTestNodeChanges: 0,
  });
  assert.deepEqual(envelopeContract.collectorLifecycle, {
    processGroup: "POSIX_DETACHED_NO_SHELL",
    timeoutSignal: "SIGKILL",
    waitForGroupExitBeforeCleanup: true,
    preservePrimaryError: true,
    cleanupErrorsAreAncillary: true,
    successCleanupFailure: "FAIL_CLOSED",
    cleanupRoots: [
      "scratchRoot",
      "npmConfigRoot",
      "isolated.source",
      "gitHistory.root",
      "isolated.parent",
    ],
    attemptAllCleanupRoots: true,
    restoreOwnerPermissionsWithoutFollowingSymlinks: true,
    verifyRootsAbsent: true,
  });

  const fixture = await semanticEnvelopeTopologyFixture();
  try {
    const closureHarness = await syntheticEvidenceClosureHarness(fixture);
    assert.equal((await closureHarness.validate()).ok, true);

    const maliciousEvidence = cloneEvidenceMap(closureHarness.evidenceMap);
    const targetedCommand = closureHarness.plan.commands.find(
      ({ commandId }) =>
        commandId === "formal-targeted-with-recursive-skips",
    );
    assert.ok(targetedCommand);
    const maliciousStdout = renderSyntheticTap(
      targetedCommand.testExpectation,
      { actualFailure: true },
    );
    maliciousEvidence.set(
      `${targetedCommand.commandId}.stdout.log`,
      maliciousStdout,
    );
    const claimedResult = await rewriteResultEvidence(
      maliciousEvidence,
      targetedCommand.commandId,
      async (result) => {
        result.stdoutSha256 =
          await independentModelReviewDigests.bytes(maliciousStdout);
        result.stdoutByteLength = maliciousStdout.byteLength;
      },
    );
    const actualSummary =
      await parseIndependentReviewTapSummary(maliciousStdout);
    assert.equal(actualSummary.tests, 85);
    assert.equal(actualSummary.pass, 73);
    assert.equal(actualSummary.fail, 1);
    assert.equal(actualSummary.skipped, 11);
    assert.equal(claimedResult.testSummary.pass, 74);
    assert.equal(claimedResult.testSummary.fail, 0);
    assert.equal(
      claimedResult.stdoutSha256,
      await independentModelReviewDigests.bytes(maliciousStdout),
    );
    const unsignedClaimedResult = structuredClone(claimedResult);
    delete unsignedClaimedResult.resultSha256;
    assert.equal(
      claimedResult.resultSha256,
      await independentModelReviewDigests.value(unsignedClaimedResult),
    );
    assert.equal(
      (
        await validateIndependentReviewSchemaInstance({
          schemaBytes: closureHarness.staticSubjects[2].bytes,
          expectedSchemaSha256:
            closureHarness.staticSubjects[2].rawSha256,
          instance: claimedResult,
          label: "synthetic malicious test result Schema",
        })
      ).ok,
      true,
    );
    assert.equal(
      (
        await closureHarness.validate({
          activeEvidenceMap: maliciousEvidence,
          activeBundle:
            await closureHarness.createBundle(maliciousEvidence),
        })
      ).ok,
      false,
    );

    for (const name of M1B_BASENAMES) {
      const tamperedEvidence = cloneEvidenceMap(
        closureHarness.evidenceMap,
      );
      tamperedEvidence.set(
        name,
        Buffer.concat([
          tamperedEvidence.get(name),
          Buffer.from("synthetic tamper", "utf8"),
        ]),
      );
      assert.equal(
        (
          await closureHarness.validate({
            activeEvidenceMap: tamperedEvidence,
          })
        ).ok,
        false,
        name,
      );
    }
    for (const [label, field, subjectIndex] of [
      ["test plan", "testPlanBytes", 0],
      ["collector", "collectorBytes", 1],
      ["result Schema", "testResultSchemaBytes", 2],
      ["sandbox", "sandboxPolicyTemplateBytes", 3],
    ]) {
      const driftedBytes = Buffer.concat([
        closureHarness.staticSubjects[subjectIndex].bytes,
        Buffer.from("synthetic drift", "utf8"),
      ]);
      assert.equal(
        (
          await closureHarness.validate({
            [field]: driftedBytes,
          })
        ).ok,
        false,
        label,
      );
    }

    const siblingRepository = join(
      fixture.directory,
      "topology-sibling",
    );
    execFileSync(
      GIT,
      [
        "--no-replace-objects",
        "clone",
        "-q",
        "--no-hardlinks",
        "--no-checkout",
        fixture.repository,
        siblingRepository,
      ],
      {
        env: GIT_ENV,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    const incompleteM1A = await createM1AVariant({
      repository: siblingRepository,
      fixture,
      paths: M1A_PATHS.filter(
        (path) =>
          path !== "tests/independent-model-required-check.cases.mjs",
      ),
    });
    const incompleteM1AFinal = await createM1BVariant({
      repository: siblingRepository,
      implementationCommit: incompleteM1A,
      evidenceMap: closureHarness.evidenceMap,
    });
    await assertMaterialBuilderRejects(
      siblingRepository,
      incompleteM1AFinal.head,
      /INDEPENDENT_MODEL_REVIEW_COMMIT_SCOPE_INVALID/u,
    );

    for (const staticPath of FORMAL_STATIC_PATHS) {
      const driftedM1A = await createM1AVariant({
        repository: siblingRepository,
        fixture,
        drift: { path: staticPath },
      });
      const driftedM1AFinal = await createM1BVariant({
        repository: siblingRepository,
        implementationCommit: driftedM1A,
        evidenceMap: closureHarness.evidenceMap,
      });
      await assertMaterialBuilderRejects(
        siblingRepository,
        driftedM1AFinal.head,
        staticPath === "scripts/run-independent-review-test-evidence.mjs"
          ? /INDEPENDENT_MODEL_REVIEW_TEST_EVIDENCE_MISMATCH/u
          : /INDEPENDENT_MODEL_REVIEW_COMMIT_SCOPE_INVALID/u,
      );
    }

    const missingM1B = await createM1BVariant({
      repository: siblingRepository,
      implementationCommit: fixture.implementationCommit,
      evidenceMap: closureHarness.evidenceMap,
      basenames: M1B_BASENAMES.slice(1),
    });
    await assertMaterialBuilderRejects(
      siblingRepository,
      missingM1B.head,
      /INDEPENDENT_MODEL_REVIEW_COMMIT_SCOPE_INVALID/u,
    );
    const extraM1B = await createM1BVariant({
      repository: siblingRepository,
      implementationCommit: fixture.implementationCommit,
      evidenceMap: closureHarness.evidenceMap,
      extraEvidence: {
        name: "unexpected-evidence.log",
        bytes: Buffer.from("unexpected Evidence\n", "utf8"),
      },
    });
    await assertMaterialBuilderRejects(
      siblingRepository,
      extraM1B.head,
      /INDEPENDENT_MODEL_REVIEW_COMMIT_SCOPE_INVALID/u,
    );

    const generatorDriftEvidence = cloneEvidenceMap(
      closureHarness.evidenceMap,
    );
    const generatorDriftSha = `sha256:${"9".repeat(64)}`;
    for (const command of closureHarness.plan.commands) {
      await rewriteResultEvidence(
        generatorDriftEvidence,
        command.commandId,
        (result) => {
          result.runtimeBinding.generator.gitBlobSha256 =
            generatorDriftSha;
          result.runtimeBinding.generator.executedBytesSha256 =
            generatorDriftSha;
        },
      );
    }
    const generatorDriftM1B = await createM1BVariant({
      repository: siblingRepository,
      implementationCommit: fixture.implementationCommit,
      evidenceMap: generatorDriftEvidence,
    });
    await assertMaterialBuilderRejects(
      siblingRepository,
      generatorDriftM1B.head,
      /INDEPENDENT_MODEL_REVIEW_TEST_EVIDENCE_MISMATCH/u,
    );

    git(siblingRepository, [
      "checkout",
      "-q",
      "--detach",
      fixture.head,
    ]);
    assert.equal(
      containsSelfReference(Buffer.from(`head=${fixture.head}`, "utf8"), fixture.head, fixture.tree),
      true,
    );
    assert.equal(
      containsSelfReference(Buffer.from(`tree=${fixture.tree}`, "utf8"), fixture.head, fixture.tree),
      true,
    );
    assert.equal(containsSelfReference(Buffer.from("no final identity", "utf8"), fixture.head, fixture.tree), false);
    for (const bytes of closureHarness.evidenceMap.values()) {
      assert.equal(containsSelfReference(bytes, fixture.head, fixture.tree), false);
    }
    const replayPath = `${M1B_DIRECTORY}/lint.stderr.log`;
    await writeFile(
      join(siblingRepository, replayPath),
      Buffer.from(
        `claimedFinalHead=${fixture.head}\nclaimedFinalTree=${fixture.tree}\n`,
        "utf8",
      ),
    );
    commitFixture(
      siblingRepository,
      "synthetic post-M1B topology replay",
      [replayPath],
    );
    const topologyReplayHead = gitText(siblingRepository, [
      "rev-parse",
      "HEAD",
    ]);
    assert.notEqual(topologyReplayHead, fixture.head);
    assert.match(
      gitBlob(
        siblingRepository,
        topologyReplayHead,
        replayPath,
      ).toString("utf8"),
      new RegExp(`${fixture.head}\\nclaimedFinalTree=${fixture.tree}`, "u"),
    );
    await assertMaterialBuilderRejects(
      siblingRepository,
      topologyReplayHead,
      /INDEPENDENT_MODEL_REVIEW_PARENT_CHAIN_INVALID/u,
    );

    const buildMaterial = () =>
      buildPromptBoundReviewMaterial({
        repository: fixture.repository,
        expectedHead: fixture.head,
        expectedTree: fixture.tree,
        expectedBase: fixture.eventBase,
      });
    const material = await buildMaterial();
    const duplicateMaterial = await buildMaterial();
    assert.deepEqual(duplicateMaterial, material);
    const outputSchemaSubject = await frozenSubjectWithDigest(
      fixture.repository,
      fixture.head,
      "implementation/governance/schemas/independent-model-review-output.v3.schema.json",
    );
    let pureOutputValidationCount = 0;
    const validatePureOutput = (value) => {
      pureOutputValidationCount += 1;
      const rawModelOutput =
        value instanceof Uint8Array
          ? value
          : Buffer.from(
              typeof value === "string" ? value : JSON.stringify(value),
              "utf8",
            );
      return validateIndependentModelReviewOutputArtifact({
        rawModelOutput: adaptQwenSummaryTransport(rawModelOutput),
        outputSchemaBytes: outputSchemaSubject.bytes,
        expectedOutputSchemaSha256: outputSchemaSubject.rawSha256,
        expectedRequiredCheckContract: material.requiredCheckContract,
      });
    };
    assert.equal(material.envelope.reviewBinding.eventBaseCommit, fixture.eventBase);
    assert.equal(material.envelope.reviewBinding.materialParentCommit, MATERIAL_PARENT);
    assert.equal(
      material.envelope.reviewBinding.implementationPathSetSha256,
      M1A_PATH_SET,
    );
    await assert.rejects(
      () =>
        buildPromptBoundReviewMaterial({
          repository: fixture.repository,
          expectedHead: fixture.head,
          expectedTree: fixture.tree,
          expectedBase: fixture.implementationCommit,
        }),
      /INDEPENDENT_MODEL_REVIEW_GIT_BINDING_INVALID/u,
    );
    assert.equal(
      material.coverageMode,
      "MIXED_VERBATIM_PATCH_AND_GIT_DIGEST_ONLY",
    );
    assert.equal(
      material.envelope.schemaVersion,
      "independent-model-review-material-envelope.v1",
    );
    assert.equal(
      material.envelope.reviewBinding.implementationCommit,
      fixture.implementationCommit,
    );
    assert.equal(
      material.envelope.reviewBinding.implementationTree,
      fixture.implementationTree,
    );
    assert.equal(material.envelope.reviewBinding.finalHead, fixture.head);
    assert.equal(material.envelope.reviewBinding.finalTree, fixture.tree);
    assert.equal(
      material.envelope.reviewBinding.materialParentCommit,
      MATERIAL_PARENT,
    );
    assert.deepEqual(material.envelope.scopeBoundary, {
      applicablePhases: ["P0", "P1", "P2"],
      dataBoundary: "SYNTHETIC_ONLY",
      allowedConclusion: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
      humanIndependentReviewSatisfied: false,
      p3HumanReviewRequired: true,
      governanceEffect: "NONE",
      profileReadiness: true,
      profileApproval: false,
      d1AppendCount: 0,
      gateChanges: 0,
      manifestChanges: 0,
      workPackageStateChanges: 0,
      o02Authorized: false,
      o03Authorized: false,
      p3Approved: false,
      productionAuthorized: false,
    });
    const unsignedEnvelope = structuredClone(material.envelope);
    delete unsignedEnvelope.envelopeSha256;
    assert.equal(
      material.envelope.envelopeSha256,
      await independentModelReviewDigests.value(unsignedEnvelope),
    );
    assert.deepEqual(
      Buffer.from(material.envelopeBytes),
      Buffer.from(
        independentModelReviewDigests.canonicalize(material.envelope),
        "utf8",
      ),
    );

    const { verbatimCoverage, digestOnlyCoverage } = material.envelope;
    assert.equal(verbatimCoverage.visibility, "VERBATIM_MODEL_VISIBLE");
    assert.deepEqual(verbatimCoverage.fullFilePaths, MATERIAL_FULL_PATHS);
    assert.deepEqual(
      verbatimCoverage.patches.map(({ path }) => path),
      MATERIAL_PATCH_PATHS,
    );
    assert.equal(
      digestOnlyCoverage.visibility,
      "DIGEST_ONLY_MODEL_VISIBLE",
    );
    assert.equal(
      digestOnlyCoverage.formalCollector.visibility,
      "FORMAL_COLLECTOR_EXECUTED_NOT_MODEL_FILE_REVIEWED",
    );
    const inventory = digestOnlyCoverage.subjectInventory;
    const inventorySubjects = inventory.relativePaths.map((relativePath, index) => ({
      path:
        inventory.pathPrefixes[inventory.pathPrefixIndexes[index]] +
        relativePath,
      gitMode: inventory.gitMode,
      byteLength: inventory.byteLengths[index],
      rawSha256: `${inventory.sha256Prefix}${inventory.rawSha256Hex[index]}`,
      originCommit: inventory.originCommits[inventory.originCommitIndexes[index]],
    }));
    assert.equal(inventorySubjects.length, 92);
    assert.deepEqual(
      inventorySubjects.map(({ path }) => path),
      [...inventorySubjects.map(({ path }) => path)].sort(),
    );
    assert.equal(new Set(inventorySubjects.map(({ path }) => path)).size, 92);
    const bundleGeneratorTestSubject = await frozenSubjectWithDigest(
      fixture.repository,
      fixture.implementationCommit,
      "tests/independent-review-bundle-generator.test.mjs",
    );
    assert.deepEqual(inventorySubjects.at(-1), {
      path: bundleGeneratorTestSubject.path,
      gitMode: bundleGeneratorTestSubject.gitMode,
      byteLength: bundleGeneratorTestSubject.byteLength,
      rawSha256: bundleGeneratorTestSubject.rawSha256,
      originCommit: fixture.implementationCommit,
    });
    assert.deepEqual(
      digestOnlyCoverage.formalCollector.staticInputSubjectIndexes.map(
        (index) => inventorySubjects[index].path,
      ),
      FORMAL_STATIC_PATHS,
    );
    for (const [position, subjectIndex] of
      digestOnlyCoverage.formalCollector.staticInputSubjectIndexes.entries()) {
      const subject = inventorySubjects[subjectIndex];
      assert.deepEqual(subject, {
        path: closureHarness.staticSubjects[position].path,
        gitMode: closureHarness.staticSubjects[position].gitMode,
        byteLength: closureHarness.staticSubjects[position].byteLength,
        rawSha256: closureHarness.staticSubjects[position].rawSha256,
        originCommit: fixture.implementationCommit,
      });
    }
    assert.equal(inventory.fullObjectProjectCanonical.length, 1);
    assert.equal(inventory.deleteFieldProjectCanonical.subjects.length, 16);
    assert.equal(inventory.deleteFieldProjectCanonical.fields.length, 16);
    assert.equal(inventory.deleteFieldProjectCanonical.sha256Hex.length, 16);
    assert.deepEqual(inventory.fullObjectProjectCanonical, [
      {
        subjectIndex: 62,
        derivedSha256Hex:
          "6402d72d3d7c0a88c362a2dbb376645dabc13c2aceb47825cb02fa031428836d",
      },
    ]);
    assert.deepEqual(
      inventory.deleteFieldProjectCanonical.subjects.map((subjectIndex, index) => [
        inventorySubjects[subjectIndex].path,
        inventory.deleteFieldProjectCanonical.fields[index],
      ]),
      [
        [
          "implementation/governance/reference-review/p2-profile-backfill/c04/applicability-evidence.v2.json",
          "reportSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c04/r09-keycloak-reference-review-receipt.v1.json",
          "receiptSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c04/reference-review-bundle.v1.json",
          "bundleSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c04/reference-review-freeze-attestation.v1.json",
          "attestationSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c06/applicability-evidence.v2.json",
          "reportSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c06/r11-openfga-reference-review-receipt.v1.json",
          "receiptSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c06/reference-review-bundle.v1.json",
          "bundleSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c06/reference-review-freeze-attestation.v1.json",
          "attestationSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c07/applicability-evidence.v2.json",
          "reportSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c07/r12-pgvector-reference-review-receipt.v1.json",
          "receiptSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c07/r12-postgresql-rls-reference-review-receipt.v1.json",
          "receiptSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c07/reference-review-bundle.v1.json",
          "bundleSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/c07/reference-review-freeze-attestation.v1.json",
          "attestationSha256",
        ],
        [
          "implementation/governance/reference-review/p2-profile-backfill/reference-review-runtime-proof.v1.json",
          "proofSha256",
        ],
        [
          "implementation/governance/v5.3-supplemental-evidence-index.v3.json",
          "indexCanonicalSha256",
        ],
        [
          "implementation/p1/c13/p1-b11-model-only-protected-review-evidence.v1.json",
          "evidenceSha256",
        ],
      ],
    );
    assert.deepEqual(material.envelope.mechanicalChecks.checks, [
      { checkId: "M1A_M1B_TOPOLOGY", passed: true },
      { checkId: "NO_SELF_REFERENCE", passed: true },
      { checkId: "TESTS_21_OF_254", passed: true },
      { checkId: "COLLECTOR_CLOSURE", passed: true },
      { checkId: "SEMANTIC_PROJECTION", passed: true },
      { checkId: "CAPACITY", passed: true },
    ]);
    const claims = material.envelope.semanticSummary.claims;
    assert.deepEqual(
      claims.map(({ claimId }) => claimId),
      [
        "P1_PROFILE_EXECUTION",
        "REFERENCE_REVIEW_R0_R1_R2",
        "PROFILE_READINESS",
        "GOVERNANCE_BOUNDARY",
        "TEST_PURPOSES",
      ],
    );
    assert.match(claims[0].value, /CANDIDATE_NOT_ACTIVATED\/SYNTHETIC\/NO_AUTHORITY/u);
    assert.match(claims[1].value, /R1=3reports\/4ADOPT\/4conformance\/3bundles/u);
    assert.match(claims[1].value, /37artifactSelfRef:0/u);
    assert.match(claims[1].value, /R2=3attestations\/7source\/53evidence\/3attestationSubjects/u);
    assert.ok(claims[1].evidenceRefs.includes("SUBJECT:72"));
    assert.match(claims[2].value, /VERIFIERS=supplemental\/execution\/reference:true/u);
    assert.ok(claims[2].evidenceRefs.includes("SUBJECT:1"));
    assert.match(claims[3].value, /profileApproval=false/u);
    assert.match(claims[4].value, /FORMAL_COLLECTOR_RESULTS_NOT_MODEL_FILE_REVIEWED/u);
    const whitelist = digestOnlyCoverage.testWhitelist;
    assert.equal(whitelist.pathSetSha256, TEST_WHITELIST_PATH_SET);
    assert.equal(whitelist.includedBlobCount, 21);
    assert.equal(whitelist.excludedBlobCount, 233);
    assert.equal(whitelist.selectedTopLevelCount, 18);
    assert.deepEqual(
      whitelist.subjects.map(({ path }) => path),
      TEST_WHITELIST_PATHS,
    );
    assert.equal(
      await independentModelReviewDigests.bytes(
        Buffer.from(`${TEST_WHITELIST_PATHS.join("\n")}\n`, "utf8"),
      ),
      TEST_WHITELIST_PATH_SET,
    );
    for (const subject of whitelist.subjects) {
      assert.equal(subject.gitMode, "100644");
      assert.ok(subject.byteLength > 0);
      assert.match(subject.rawSha256, /^sha256:[a-f0-9]{64}$/u);
    }
    assert.deepEqual(
      digestOnlyCoverage.formalCollector.commands.map(
        ({ commandId, tests, pass, fail, skipped }) => ({
          commandId,
          tests,
          pass,
          fail,
          skipped,
        }),
      ),
      [
        {
          commandId: "formal-targeted-with-recursive-skips",
          tests: 85,
          pass: 74,
          fail: 0,
          skipped: 11,
        },
        {
          commandId: "formal-repository-gates-with-recursive-skips",
          tests: 1671,
          pass: 1642,
          fail: 0,
          skipped: 29,
        },
        {
          commandId: "lint",
          tests: null,
          pass: null,
          fail: null,
          skipped: null,
        },
      ],
    );

    const materialManifest = JSON.parse(
      Buffer.from(material.bytes)
        .toString("utf8")
        .split("\n")
        .find((line) =>
          line.startsWith(
            '{"schemaVersion":"prompt-bound-independent-model-review-material.v2"',
          ),
        ),
    );
    const fullByteLength = materialManifest.artifacts.reduce(
      (total, { byteLength }) => total + byteLength,
      0,
    );
    const patchByteLength = verbatimCoverage.patches.reduce(
      (total, { byteLength }) => total + byteLength,
      0,
    );
    const framingByteLength =
      material.byteLength -
      material.envelopeByteLength -
      fullByteLength -
      patchByteLength;
    assert.ok(fullByteLength <= 26486);
    assert.ok(patchByteLength <= 26624);
    assert.ok(material.envelopeByteLength <= 28672);
    assert.ok(framingByteLength <= 8192);
    assert.ok(material.byteLength <= 96 * 1024);
    assert.ok(96 * 1024 - material.byteLength >= 8330);

    const materialText = material.bytes.toString("utf8");
    const manifest = materialManifest;
    assert.equal(
      manifest.schemaVersion,
      "prompt-bound-independent-model-review-material.v2",
    );
    assert.equal(manifest.baseCommit, fixture.eventBase);
    assert.equal(manifest.sourceCommit, fixture.head);
    assert.equal(manifest.sourceTree, fixture.tree);
    assert.equal(manifest.implementationCommit, fixture.implementationCommit);
    assert.equal(manifest.implementationTree, fixture.implementationTree);
    assert.equal(manifest.envelopeSha256, material.envelopeSha256);
    for (const path of MATERIAL_FULL_PATHS) {
      assert.equal(materialText.split(`<<<BEGIN:${path}>>>`).length, 2);
      assert.equal(materialText.split(`<<<END:${path}>>>`).length, 2);
    }
    for (const path of MATERIAL_PATCH_PATHS) {
      assert.equal(
        materialText.split(`<<<BEGIN_GIT_PATCH:${path}>>>`).length,
        2,
      );
      assert.equal(
        materialText.split(`<<<END_GIT_PATCH:${path}>>>`).length,
        2,
      );
    }
    for (const path of TEST_WHITELIST_PATHS) {
      assert.doesNotMatch(
        materialText,
        new RegExp(`<<<BEGIN:${path.replaceAll(".", "\\.")}>>>`, "u"),
      );
    }
    assert.match(
      materialText,
      /The top-level object may contain only: schemaVersion, reviewBinding, coverage, reviewSummary, findings, decision\./u,
    );
    assert.match(
      materialText,
      /Digest-only and collector subjects cannot support line findings or byte-review claims\./u,
    );
    assert.ok(
      materialText.lastIndexOf("<<<AUTHORITATIVE_FINAL_OUTPUT_CONTRACT>>>") >
        materialText.lastIndexOf("<<<END_GIT_PATCH:"),
    );

    const clearOutput = clearRequiredCheckOutput(material);
    await writeFile(fixture.materialFile, material.bytes);
    await fixture.writeOutput(clearOutput);
    const clear = await fixture.validate();
    assert.equal(clear.conclusion, "success");
    assert.equal(clear.title, "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION");
    assert.equal(clear.humanIndependentReviewSatisfied, false);
    assert.equal(clear.governanceEffect, "NONE");

    await fixture.writeOutput({
      schemaVersion: "independent-model-review-output.v2",
      reviewSummary: material.bindingSummary,
      findings: [],
      decision: "CLEAR",
    });
    assert.equal((await fixture.validate()).conclusion, "failure");
    await fixture.writeOutput(clearOutput);

    for (const [label, mutate] of [
      ["missing", (envelope) => envelope.digestOnlyCoverage.testWhitelist.subjects.pop()],
      [
        "extra",
        (envelope) =>
          envelope.digestOnlyCoverage.testWhitelist.subjects.push({
            ...envelope.digestOnlyCoverage.testWhitelist.subjects[0],
            path: "tests/not-in-required-check-whitelist.test.mjs",
          }),
      ],
      [
        "duplicate",
        (envelope) => {
          envelope.digestOnlyCoverage.testWhitelist.subjects[20] =
            structuredClone(
              envelope.digestOnlyCoverage.testWhitelist.subjects[0],
            );
        },
      ],
      [
        "out-of-order",
        (envelope) => {
          const subjects = envelope.digestOnlyCoverage.testWhitelist.subjects;
          [subjects[0], subjects[1]] = [subjects[1], subjects[0]];
        },
      ],
      [
        "wrong-mode",
        (envelope) => {
          envelope.digestOnlyCoverage.testWhitelist.subjects[0].gitMode =
            "100755";
        },
      ],
      [
        "wrong-length",
        (envelope) => {
          envelope.digestOnlyCoverage.testWhitelist.subjects[0].byteLength += 1;
        },
      ],
      [
        "wrong-raw-sha",
        (envelope) => {
          const subject =
            envelope.digestOnlyCoverage.testWhitelist.subjects[0];
          subject.rawSha256 = differentSha256(subject.rawSha256);
        },
      ],
      [
        "wrong-path-set",
        (envelope) => {
          const testWhitelist = envelope.digestOnlyCoverage.testWhitelist;
          testWhitelist.pathSetSha256 = differentSha256(
            testWhitelist.pathSetSha256,
          );
        },
      ],
      [
        "Manifest state changed",
        (envelope) => {
          envelope.scopeBoundary.manifestChanges = 1;
        },
      ],
      [
        "P3 approved",
        (envelope) => {
          envelope.scopeBoundary.p3Approved = true;
        },
      ],
    ]) {
      await writeFile(
        fixture.materialFile,
        await materialWithMutatedEnvelope(material, mutate),
      );
      const result = await fixture.validate();
      assert.equal(result.conclusion, "failure", label);
    }
    await writeFile(fixture.materialFile, material.bytes);

    for (const [label, mutate] of [
      [
        "source commit",
        (output) => {
          output.reviewBinding.sourceCommit = differentSha256(
            output.reviewBinding.sourceCommit,
          );
        },
      ],
      [
        "source tree",
        (output) => {
          output.reviewBinding.sourceTree = differentSha256(
            output.reviewBinding.sourceTree,
          );
        },
      ],
      [
        "material digest",
        (output) => {
          output.reviewBinding.materialSha256 = differentSha256(
            output.reviewBinding.materialSha256,
          );
        },
      ],
      [
        "Envelope digest",
        (output) => {
          output.reviewBinding.envelopeSha256 = differentSha256(
            output.reviewBinding.envelopeSha256,
          );
        },
      ],
      [
        "coverage mode",
        (output) => {
          output.coverage.coverageMode = "VERBATIM_ONLY";
        },
      ],
      [
        "full-file manifest",
        (output) => {
          output.coverage.verbatimFullFileManifestSha256 = differentSha256(
            output.coverage.verbatimFullFileManifestSha256,
          );
        },
      ],
      [
        "patch manifest",
        (output) => {
          output.coverage.verbatimPatchManifestSha256 = differentSha256(
            output.coverage.verbatimPatchManifestSha256,
          );
        },
      ],
      [
        "digest-only manifest",
        (output) => {
          output.coverage.digestOnlyManifestSha256 = differentSha256(
            output.coverage.digestOnlyManifestSha256,
          );
        },
      ],
      [
        "digest-only byte-reviewed flag",
        (output) => {
          output.coverage.digestOnlyNotByteReviewed = false;
        },
      ],
    ]) {
      const output = clearRequiredCheckOutput(material);
      mutate(output);
      assert.equal((await validatePureOutput(output)).ok, false, label);
    }

    const findingSubjects = material.requiredCheckContract.findingSubjects;
    const fullSubject = findingSubjects.find(
      ({ evidenceMode, path }) =>
        evidenceMode === "VERBATIM_FULL_FILE" &&
        path ===
          "implementation/governance/independent-review/github-required-check-prompt.v2.md",
    );
    const patchSubject = findingSubjects.find(
      ({ evidenceMode, newRanges, oldRanges }) =>
        evidenceMode === "VERBATIM_PATCH" &&
        (newRanges.length > 0 || oldRanges.length > 0),
    );
    const digestSubject = findingSubjects.find(
      ({ evidenceMode, path }) =>
        evidenceMode === "DIGEST_ONLY_SUMMARY" && path.startsWith("tests/"),
    );
    const manifestNamedDigestSubject = findingSubjects.find(
      ({ evidenceMode, path }) =>
        evidenceMode === "DIGEST_ONLY_SUMMARY" &&
        path.includes("runtime-manifest"),
    );
    assert.ok(fullSubject);
    assert.ok(patchSubject);
    assert.ok(digestSubject);
    assert.ok(manifestNamedDigestSubject);
    for (const subject of [
      fullSubject,
      patchSubject,
      digestSubject,
      manifestNamedDigestSubject,
    ]) {
      const output = clearRequiredCheckOutput(material);
      output.findings = [findingForSubject(subject)];
      const result = await validatePureOutput(output);
      assert.equal(result.ok, true);
      assert.equal(result.status, "CLEAR");
    }
    for (const summary of [
      "Minor implementation issue.",
      "Hash mismatch in frozen subject.",
    ]) {
      const output = clearRequiredCheckOutput(material);
      output.findings = [findingForSubject(fullSubject, { summary })];
      const result = await validatePureOutput(output);
      assert.equal(result.ok, true, summary);
      assert.equal(result.status, "CLEAR", summary);
    }

    for (const [label, finding] of [
      [
        "digest-only line claim",
        findingForSubject(digestSubject, {
          lineSide: "FILE",
          startLine: 1,
          endLine: 1,
        }),
      ],
      [
        "full-file line outside visible bytes",
        findingForSubject(fullSubject, {
          startLine: fullSubject.lineCount + 1,
          endLine: fullSubject.lineCount + 1,
        }),
      ],
      [
        "full-file reversed line range",
        findingForSubject(fullSubject, {
          startLine: 2,
          endLine: 1,
        }),
      ],
      [
        "patch line outside visible hunks",
        findingForSubject(patchSubject, {
          startLine: 1_000_000,
          endLine: 1_000_000,
        }),
      ],
      [
        "patch reversed line range",
        findingForSubject(patchSubject, {
          startLine:
            (patchSubject.newRanges[0] ?? patchSubject.oldRanges[0])[0] + 1,
          endLine:
            (patchSubject.newRanges[0] ?? patchSubject.oldRanges[0])[0],
        }),
      ],
      [
        "test source falsely claimed verbatim",
        findingForSubject(digestSubject, {
          evidenceMode: "VERBATIM_FULL_FILE",
          lineSide: "FILE",
          startLine: 1,
          endLine: 1,
        }),
      ],
      [
        "excluded subject",
        findingForSubject(digestSubject, {
          path: "tests/not-in-required-check-whitelist.test.mjs",
        }),
      ],
      [
        "governance overclaim in finding ID",
        findingForSubject(fullSubject, {
          findingId: "profile_is_approved",
        }),
      ],
      [
        "reversed Profile overclaim in finding ID",
        findingForSubject(fullSubject, {
          findingId: "approved_profile",
        }),
      ],
      [
        "reversed human-review overclaim in finding ID",
        findingForSubject(fullSubject, {
          findingId: "review_completed_by_human",
        }),
      ],
      [
        "digest-only finding claims source-byte inspection",
        findingForSubject(digestSubject, {
          summary: "I inspected every source byte in this test",
        }),
      ],
      [
        "digest-only finding claims line-by-line source read",
        findingForSubject(digestSubject, {
          summary: "I read this test source line by line",
        }),
      ],
      [
        "suite finding claims source coverage",
        findingForSubject(digestSubject, {
          summary: "Suite results prove source coverage",
        }),
      ],
      [
        "test-result finding claims every helper ran",
        findingForSubject(digestSubject, {
          summary: "The test result proves every helper ran independently",
        }),
      ],
      [
        "finding claims Profile authorization",
        findingForSubject(fullSubject, {
          summary: "The Profile authorization has been granted.",
        }),
      ],
      [
        "finding claims human sign-off",
        findingForSubject(fullSubject, {
          summary: "Human sign-off is complete.",
        }),
      ],
      [
        "finding claims digest-only source audit",
        findingForSubject(digestSubject, {
          summary: "I audited each digest-only test source.",
        }),
      ],
      [
        "finding claims model checked every test file",
        findingForSubject(digestSubject, {
          summary: "The model checked every test file.",
        }),
      ],
      [
        "finding claims collector per-file proof",
        findingForSubject(fullSubject, {
          summary:
            "The formal collector establishes all test files were checked by the model.",
        }),
      ],
      [
        "finding claims every helper validation",
        findingForSubject(fullSubject, {
          summary: "Every helper was successfully validated on its own.",
        }),
      ],
    ]) {
      const output = clearRequiredCheckOutput(material);
      output.findings = [finding];
      assert.equal((await validatePureOutput(output)).ok, false, label);
    }

    for (const severity of ["HIGH", "CRITICAL"]) {
      const output = clearRequiredCheckOutput(material);
      output.findings = [findingForSubject(fullSubject, { severity })];
      const result = await validatePureOutput(output);
      assert.equal(result.ok, false);
      assert.equal(result.status, "BLOCKED");
    }
    for (const decision of ["BLOCKED", "INCONCLUSIVE"]) {
      const output = clearRequiredCheckOutput(material);
      output.decision = decision;
      const result = await validatePureOutput(output);
      assert.equal(result.ok, true);
      assert.equal(result.status, decision);
      assert.equal(result.conclusion, decision);
    }
    for (const claim of [
      "INDEPENDENT_HUMAN_REVIEW_COMPLETE",
      "P3_OR_PRODUCTION_RELEASE_APPROVED",
      "humanIndependentReviewSatisfied=true",
      "PROFILE_APPROVAL=true",
      "Profile is approved",
      "The approved Profile is now in force",
      "Review by a human is complete",
      "D1_APPROVED",
      "MANIFEST_CHANGES=1",
      "O02_OR_O03_AUTHORIZED",
      "P3_APPROVED=true",
      "digest-only byte reviewed",
      "digest-only test was byte inspected",
      "I inspected every byte of each digest-only test",
      "I inspected the source of each digest-only test",
      "I read every digest-only test file",
      "I reviewed digest-only test source",
      "formal collector model per-file reviewed",
      "formal collector proves every test file was examined by the model",
      "Every test file was examined by the model according to the formal collector",
      "formal collector proves source coverage",
      "formal collector proves every helper ran independently",
      "Suite results prove source coverage",
      "The test result proves every helper ran independently",
      "I read every test source file",
      "I inspected all test files",
      "All tests were reviewed line by line",
      "Every excluded test was source reviewed",
      "The Profile authorization has been granted.",
      "The Profile has received final sign-off.",
      "Human sign-off is complete.",
      "I audited each digest-only test source.",
      "The model checked every test file.",
      "The formal collector establishes all test files were checked by the model.",
      "Every helper was successfully validated on its own.",
      "PRO\u200bFILE authorization has been granted.",
      "PRO-FILE authorization has been granted.",
      "\uff30\uff32\uff2f\uff26\uff29\uff2c\uff25 authorization has been granted.",
      "PR\u041eFILE authorization has been granted.",
      "DIGEST-ON\u200bLY source was audited.",
    ]) {
      const output = clearRequiredCheckOutput(material);
      output.reviewSummary = `${material.bindingSummary} ${claim}`;
      assert.equal((await validatePureOutput(output)).ok, false, claim);
    }

    const clearJson = JSON.stringify(clearRequiredCheckOutput(material), null, 2);
    for (const [index, { runId, headSha }] of [
      {
        runId: 31637078154,
        headSha: "0502b51d5f291fa038819391060c08c43191e8e6",
      },
      {
        runId: 31659601178,
        headSha: "97fb4f567b689a963636ab32f7f8a533e254251a",
      },
    ].entries()) {
      assert.ok(runId > 0);
      assert.match(headSha, /^[a-f0-9]{40}$/u);
      const fencedTransport = `\`\`\`json\n${clearJson}\n\`\`\``;
      const result = await validatePureOutput(fencedTransport);
      assert.equal(result.ok, true);
      assert.equal(result.status, "CLEAR");
      if (index === 0) {
        await writeFile(fixture.outputFile, fencedTransport, "utf8");
        assert.equal((await fixture.validate()).conclusion, "success");
      }
    }
    const whitespaceFencedTransport =
      `\t\r\n\`\`\`json\r\n${clearJson.replaceAll("\n", "\r\n")}\r\n\`\`\`\r\n `;
    assert.equal(
      (await validatePureOutput(whitespaceFencedTransport)).ok,
      true,
    );
    const rejectedTransports = [
      `prefix\n\`\`\`json\n${clearJson}\n\`\`\``,
      `\`\`\`json\n${clearJson}\n\`\`\`\nsuffix`,
      `\`\`\`JSON\n${clearJson}\n\`\`\``,
      `\`\`\`javascript\n${clearJson}\n\`\`\``,
      `\`\`\`json\n{}\n\`\`\``,
      `\`\`\`json\n${clearJson}\n\`\`\`\n\`\`\`json\n${clearJson}\n\`\`\``,
      `\`\`\`json\n${clearJson}\n${clearJson}\n\`\`\``,
      `\`\`\`json\n${clearJson} trailing\n\`\`\``,
      `\`\`\`json\n[${clearJson}]\n\`\`\``,
      "```json\n\n```",
      `\ufeff\`\`\`json\n${clearJson}\n\`\`\``,
      `\u00a0\`\`\`json\n${clearJson}\n\`\`\``,
      `\u000b\`\`\`json\n${clearJson}\n\`\`\``,
      `\u000c\`\`\`json\n${clearJson}\n\`\`\``,
      `\u2028\`\`\`json\n${clearJson}\n\`\`\``,
      `\u2029\`\`\`json\n${clearJson}\n\`\`\``,
    ];
    for (const [index, rejectedTransport] of rejectedTransports.entries()) {
      assert.equal((await validatePureOutput(rejectedTransport)).ok, false);
      if (index === 5) {
        await writeFile(fixture.outputFile, rejectedTransport, "utf8");
        assert.equal((await fixture.validate()).conclusion, "failure");
      }
    }
    const invalidUtf8Transport = Buffer.concat([
      Buffer.from("```json\n", "utf8"),
      Buffer.from([0xff]),
      Buffer.from("\n```", "utf8"),
    ]);
    assert.equal((await validatePureOutput(invalidUtf8Transport)).ok, false);
    const oversizedTransport = Buffer.concat([
      Buffer.from(" \n".repeat(64 * 1024), "utf8"),
      Buffer.from(`\`\`\`json\n${clearJson}\n\`\`\``, "utf8"),
    ]);
    assert.equal(
      (await validatePureOutput(oversizedTransport)).ok,
      false,
    );

    for (const malformed of [
      Buffer.from("not-json", "utf8"),
      Buffer.from(
        JSON.stringify({
          ...clearRequiredCheckOutput(material),
          findings: null,
        }),
        "utf8",
      ),
      Buffer.from(
        JSON.stringify({
          ...clearRequiredCheckOutput(material),
          decision: "APPROVED",
        }),
        "utf8",
      ),
    ]) {
      assert.equal((await validatePureOutput(malformed)).ok, false);
    }

    await fixture.writeOutput(clearRequiredCheckOutput(material));
    for (const [overrides, reasonCode] of [
      [
        { expectedHead: "0".repeat(40) },
        "INDEPENDENT_MODEL_REVIEW_GIT_BINDING_MISMATCH",
      ],
      [
        { expectedTree: "0".repeat(40) },
        "INDEPENDENT_MODEL_REVIEW_GIT_BINDING_MISMATCH",
      ],
      [
        { expectedBase: "0".repeat(40) },
        "INDEPENDENT_MODEL_REVIEW_MATERIAL_BINDING_INVALID",
      ],
      [
        { requestedProvider: "OPENAI" },
        "INDEPENDENT_MODEL_REVIEW_PROVIDER_MISMATCH",
      ],
      [
        { requestedRegion: "SINGAPORE" },
        "INDEPENDENT_MODEL_REVIEW_REGION_MISMATCH",
      ],
      [
        { baseUrl: "https://example.invalid/compatible-mode/v1" },
        "INDEPENDENT_MODEL_REVIEW_ENDPOINT_MISMATCH",
      ],
      [
        { assuranceLevel: "API_NO_TOOLS" },
        "INDEPENDENT_MODEL_REVIEW_ASSURANCE_MISMATCH",
      ],
      [
        { requestedModel: "qwen3.7-max" },
        "INDEPENDENT_MODEL_REVIEW_MODEL_MISMATCH",
      ],
      [{ eventName: "push" }, "INDEPENDENT_MODEL_REVIEW_EVENT_INVALID"],
    ]) {
      const result = await fixture.validate(overrides);
      assert.equal(result.conclusion, "failure");
      assert.ok(result.reasonCodes.includes(reasonCode));
    }

    const insideRepository = join(fixture.repository, "model-output.json");
    await writeFile(insideRepository, JSON.stringify(clearOutput), "utf8");
    const materialInsideRepository = join(
      fixture.repository,
      "review-material.txt",
    );
    await writeFile(materialInsideRepository, material.bytes);
    const linkedOutput = join(fixture.directory, "linked-model-output.json");
    const linkedMaterial = join(fixture.directory, "linked-review-material.txt");
    await Promise.all([
      symlink(insideRepository, linkedOutput),
      symlink(materialInsideRepository, linkedMaterial),
    ]);
    for (const result of [
      await fixture.validate({
        outputFile: insideRepository,
        materialFile: linkedMaterial,
      }),
      await fixture.validate({
        outputFile: linkedOutput,
        materialFile: materialInsideRepository,
      }),
    ]) {
      assert.equal(result.conclusion, "failure");
      assert.ok(result.reasonCodes.includes(
        "INDEPENDENT_MODEL_REVIEW_OUTPUT_LOCATION_INVALID",
      ));
      assert.ok(result.reasonCodes.includes(
        "INDEPENDENT_MODEL_REVIEW_MATERIAL_LOCATION_INVALID",
      ));
    }
    assert.equal(
      (
        await fixture.validate({
          outputFile: join(fixture.directory, "missing-output.json"),
        })
      ).conclusion,
      "failure",
    );

    await writeFile(fixture.materialFile, material.bytes);
    await fixture.writeOutput(clearRequiredCheckOutput(material));
    const dirtyPath = join(
      fixture.repository,
      "implementation/governance/independent-review/github-required-check-prompt.v2.md",
    );
    const cleanBytes = await readFile(dirtyPath);
    try {
      await writeFile(
        dirtyPath,
        Buffer.concat([cleanBytes, Buffer.from("dirty working tree", "utf8")]),
      );
      assert.deepEqual(await buildMaterial(), material);
      assert.equal((await fixture.validate()).conclusion, "success");
    } finally {
      await writeFile(dirtyPath, cleanBytes);
    }

    git(fixture.repository, [
      "-c",
      "user.name=Independent Model Check Test",
      "-c",
      "user.email=independent-model-check@example.invalid",
      "-c",
      "commit.gpgSign=false",
      "-c",
      "core.hooksPath=/dev/null",
      "commit",
      "--allow-empty",
      "-qm",
      "same-tree replay",
    ]);
    const replayHead = gitText(fixture.repository, ["rev-parse", "HEAD"]);
    const replayTree = gitText(fixture.repository, ["rev-parse", "HEAD^{tree}"]);
    assert.notEqual(replayHead, fixture.head);
    assert.equal(replayTree, fixture.tree);
    await assert.rejects(
      () =>
        buildPromptBoundReviewMaterial({
          repository: fixture.repository,
          expectedHead: replayHead,
          expectedTree: replayTree,
          expectedBase: MATERIAL_PARENT,
        }),
      /parent(?:_| )chain|commit(?:_| )scope|topology/iu,
    );
    assert.equal(
      (
        await fixture.validate({
          expectedHead: replayHead,
          expectedTree: replayTree,
          expectedBase: MATERIAL_PARENT,
        })
      ).conclusion,
      "failure",
    );
    assert.equal(fixture.validationCounts.outer, 28);
    assert.equal(pureOutputValidationCount, 103);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
}
