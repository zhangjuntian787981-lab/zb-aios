import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { sha256ProjectValue } from "../lib/project-control.mjs";
import { independentKimiReviewDigests } from "../lib/kimi-independent-review.mjs";
import {
  buildIndependentReviewBundleFromGit,
  createTrustedGitDiffCheck,
} from "../scripts/build-independent-review-bundle.mjs";
import { buildIndependentReviewMaterialFromGit } from "../scripts/build-independent-review-material.mjs";
import {
  captureKimiReviewRepositorySnapshot,
  runKimiIndependentReviewTestHarness,
  verifyKimiReviewBundleGitBindings,
} from "../scripts/run-kimi-independent-review.mjs";

const execFileAsync = promisify(execFile);
const root = new URL("../", import.meta.url);
const nestedTestCollectorUnavailable =
  process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
  "DENY_ALL_OFFLINE_ALTERNATIVES";
const recursiveCollectorTest = nestedTestCollectorUnavailable
  ? test.skip
  : test;
const digest = (character) => `sha256:${character.repeat(64)}`;
const runtimeApiKeyFixture = () =>
  ["unit", "runtime", "credential", "outside", "review", "material"].join(
    "-",
  );
const testPlanPath =
  "implementation/governance/independent-review/independent-review-test-plan.v2.json";
const implementationParticipantManifestPath =
  "implementation/governance/independent-review/implementation-participant.v1.json";
const fixtureChangedSourcePath =
  "implementation/governance/independent-review/material-fixture-change.txt";
const basePaths = [
  "package-lock.json",
  "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
  "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  "implementation/governance/independent-review/independent-review-test-plan.v2.json",
  "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in",
  implementationParticipantManifestPath,
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  "implementation/governance/schemas/independent-model-review-receipt.v2.schema.json",
  "implementation/governance/schemas/independent-model-runtime-evidence.v2.schema.json",
  "implementation/governance/schemas/independent-review-bundle.v2.schema.json",
  "implementation/governance/schemas/independent-review-policy.v2.schema.json",
  "implementation/governance/schemas/independent-review-test-result.v3.schema.json",
  "implementation/governance/schemas/independent-review-transport-evidence.v1.schema.json",
  "implementation/governance/independent-review/kimi-runtime-manifest.v1.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v1.schema.json",
  "lib/independent-model-review.mjs",
  "lib/independent-review-runtime-evidence.mjs",
  "lib/independent-review-runtime-manifest.mjs",
  "lib/independent-review-transport-evidence.mjs",
  "lib/p2-start-authorization.mjs",
  "lib/project-control.mjs",
  "scripts/build-independent-review-bundle.mjs",
  "scripts/bootstrap-kimi-independent-review.mjs",
  "scripts/run-independent-review-control-plane.mjs",
  "scripts/build-independent-review-runtime-manifest.mjs",
  "scripts/run-independent-review-test-evidence.mjs",
  "tests/independent-model-review.test.mjs",
  "tests/independent-review-bundle-generator.test.mjs",
  "tests/independent-review-control-plane.test.mjs",
  "tests/independent-review-material-generator.test.mjs",
  "tests/independent-review-transport-evidence.test.mjs",
];
const candidatePaths = [
  "docs/adr/0012-moonshot-kimi-independent-review-transport.md",
  "implementation/governance/independent-review/moonshot-kimi-k2.7-code.v1.json",
  "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json",
  "implementation/governance/schemas/independent-review-material.v1.schema.json",
  "implementation/governance/schemas/moonshot-kimi-independent-review-config.v1.schema.json",
  "lib/independent-review-runtime-binding.mjs",
  "lib/kimi-independent-review.mjs",
  "scripts/build-independent-review-material.mjs",
  "scripts/launch-kimi-independent-review.sh",
  "scripts/run-kimi-independent-review.mjs",
  "tests/kimi-independent-review.test.mjs",
];

async function git(repo, args, encoding = "utf8") {
  return execFileAsync("/usr/bin/git", ["-C", repo, ...args], {
    encoding,
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_SYSTEM: "/dev/null",
      GIT_CONFIG_GLOBAL: "/dev/null",
      ...(process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
        "DENY_ALL_OFFLINE_ALTERNATIVES" &&
      typeof process.env.xcrun_db === "string"
        ? { xcrun_db: process.env.xcrun_db }
        : {}),
    },
    maxBuffer: 64 * 1024 * 1024,
  });
}

async function write(repo, path, value) {
  const target = join(repo, path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, value);
}

async function copyCandidate(repo, path) {
  await write(repo, path, await readFile(new URL(path, root)));
}

async function writeFixtureTestPlan(repo) {
  const unsignedPlan = {
    schemaVersion: "independent-review-test-plan.v2",
    planId: "fixture-kimi-review-plan",
    commands: [
      {
        commandId: "fixture-tests",
        executable: "NODE",
        args: [
          "-e",
          "const fs=require('fs');const value=fs.readFileSync('fixture-execution-source.txt','utf8');if(value!=='frozen execution source\\n')process.exit(7);process.stdout.write('fixture material evidence\\n')",
        ],
        timeoutMs: 10000,
      },
    ],
  };
  const plan = {
    ...unsignedPlan,
    planSha256: await sha256ProjectValue(unsignedPlan),
  };
  await write(repo, testPlanPath, `${JSON.stringify(plan, null, 2)}\n`);
}

async function fixtureRepository(t) {
  const repo = await mkdtemp(join(tmpdir(), "zb-kimi-material-"));
  t.after(() => rm(repo, { recursive: true, force: true }));
  await git(repo, ["init", "-q"]);
  await git(repo, ["config", "user.name", "Kimi Material Test"]);
  await git(repo, [
    "config",
    "user.email",
    "review-test@example.invalid",
  ]);
  for (const path of [
    "AGENTS.md",
    "CONTEXT.md",
    "docs/agents/issue-tracker.md",
    "docs/adr/0008-c13-protected-source-review.md",
  ]) {
    await write(repo, path, `frozen specification: ${path}\n`);
  }
  for (const path of new Set([...basePaths, ...candidatePaths])) {
    await copyCandidate(repo, path);
  }
  await writeFixtureTestPlan(repo);
  await write(
    repo,
    "fixture-execution-source.txt",
    "frozen execution source\n",
  );
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-q", "-m", "base"]);
  const { stdout: baseText } = await git(repo, ["rev-parse", "HEAD"]);
  await write(
    repo,
    fixtureChangedSourcePath,
    "deterministic source change represented by the exact Git patch\n",
  );
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-q", "-m", "candidate"]);
  const { stdout: sourceText } = await git(repo, ["rev-parse", "HEAD"]);
  const evidenceRoot = await mkdtemp(
    join(tmpdir(), "zb-independent-review-material-evidence-"),
  );
  t.after(() => rm(evidenceRoot, { recursive: true, force: true }));
  return {
    repo,
    baseCommit: baseText.trim(),
    sourceCommit: sourceText.trim(),
    evidenceRoot,
  };
}

async function bundleFor(fixture) {
  return buildIndependentReviewBundleFromGit({
    repoPath: fixture.repo,
    baseCommit: fixture.baseCommit,
    sourceCommit: fixture.sourceCommit,
    generatedAt: "2026-07-30T12:00:00.000Z",
    bundleId: "imrb_kimi_material_fixture",
    applicablePhase: "P1",
    testEvidenceRoot: fixture.evidenceRoot,
  });
}

async function rehashBundle(bundle) {
  bundle.bundleSha256 = await sha256ProjectValue(
    Object.fromEntries(
      Object.entries(bundle).filter(([key]) => key !== "bundleSha256"),
    ),
  );
  return Buffer.from(JSON.stringify(bundle), "utf8");
}

async function forgePassingEvidenceForCommit(
  fixture,
  bundle,
  sourceCommit,
  sourceTree,
  marker = "forged",
) {
  const trustedResult = JSON.parse(
    await readFile(
      join(
        fixture.evidenceRoot,
        bundle.testEvidenceSubjects[0].outputRef,
      ),
      "utf8",
    ),
  );
  const plan = JSON.parse(
    await readFile(join(fixture.repo, testPlanPath), "utf8"),
  );
  const command = plan.commands[0];
  const stdout = Buffer.from("forged pass without execution\n", "utf8");
  const stderr = Buffer.alloc(0);
  const stdoutRef = `${command.commandId}.stdout.log`;
  const stderrRef = `${command.commandId}.stderr.log`;
  const outputRef = `${command.commandId}.result.json`;
  const parameterSetSha256 = digest("a");
  const invocationSha256 = await sha256ProjectValue({
    executable: "/usr/bin/sandbox-exec",
    templateSha256: bundle.artifacts.sandboxPolicyTemplateSha256,
    parameterSetSha256,
  });
  const attestation = {
    schemaVersion: "independent-review-test-result.v3",
    evidenceId: command.commandId,
    testPlanSha256: plan.planSha256,
    sourceCommit,
    sourceTree,
    runner: {
      path: bundle.artifacts.testEvidenceCollectorPath,
      gitBlobSha256:
        bundle.artifacts.testEvidenceCollectorSha256,
      executedBytesSha256:
        bundle.artifacts.testEvidenceCollectorSha256,
    },
    runtimeBinding: structuredClone(trustedResult.runtimeBinding),
    executionSource: {
      mode: "MACOS_SEATBELT_GIT_ARCHIVE_READONLY_HISTORY_V3",
      cloneMode:
        "GIT_ARCHIVE_WITH_READ_ONLY_HISTORY_SNAPSHOT",
      before: {
        head: sourceCommit,
        tree: sourceTree,
        sourceManifestSha256: digest("0"),
      },
      after: {
        head: sourceCommit,
        tree: sourceTree,
        sourceManifestSha256: digest("0"),
      },
      unchanged: true,
      gitHistory: {
        mode: "READ_ONLY_ALL_REF_REACHABLE_OBJECT_SNAPSHOT",
        sourceCommit,
        sourceTree,
        refTipCount: 1,
        refTipSetSha256: digest("0"),
        reachableObjectCount: 1,
        reachableObjectSetSha256: digest("1"),
        pointerSha256: digest("2"),
        beforeManifestSha256: digest("3"),
        afterManifestSha256: digest("3"),
        unchanged: true,
        metadataWritable: false,
      },
      sourceExportRemoved: true,
      sandbox: {
        executable: "/usr/bin/sandbox-exec",
        templatePath: bundle.artifacts.sandboxPolicyTemplatePath,
        templateSha256: bundle.artifacts.sandboxPolicyTemplateSha256,
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
      exitCode: 0,
      signal: null,
      timedOut: false,
      startedAt: "2026-07-30T12:00:00.000Z",
      finishedAt: "2026-07-30T12:00:01.000Z",
    },
    testSummary: null,
    stdoutRef,
    stdoutSha256: independentKimiReviewDigests.bytes(stdout),
    stdoutByteLength: stdout.byteLength,
    stderrRef,
    stderrSha256: independentKimiReviewDigests.bytes(stderr),
    stderrByteLength: stderr.byteLength,
    resultSha256: digest("0"),
  };
  attestation.resultSha256 = await sha256ProjectValue(
    Object.fromEntries(
      Object.entries(attestation).filter(
        ([key]) => key !== "resultSha256",
      ),
    ),
  );
  const resultBytes = Buffer.from(`${JSON.stringify(attestation)}\n`, "utf8");
  await Promise.all([
    write(fixture.evidenceRoot, stdoutRef, stdout),
    write(fixture.evidenceRoot, stderrRef, stderr),
    write(fixture.evidenceRoot, outputRef, resultBytes),
  ]);
  return {
    evidenceId: command.commandId,
    command: `${command.executable} ${command.args.join(" ")}`,
    status: "PASS",
    exitCode: 0,
    outputRef,
    outputSha256:
      independentKimiReviewDigests.bytes(resultBytes),
    outputByteLength: resultBytes.byteLength,
    truncated: false,
    sourceCommit,
    runner: "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE",
    toolVersions: [
      `node=${marker}`,
      `runner=${marker}`,
      "isolation=macos-sandbox-exec-git-archive-readonly-history-network-denied",
      "network-test-mode=frozen-deterministic-offline-alternatives",
      `sandbox-template=${bundle.artifacts.sandboxPolicyTemplateSha256}`,
      `sandbox-invocation=${invocationSha256}`,
      `runtime-binding=${trustedResult.runtimeBinding.bindingSha256}`,
      `node-executable=${trustedResult.runtimeBinding.nodeExecutableSha256}`,
      `dependency-set=${trustedResult.runtimeBinding.dependencySetSha256}`,
      `git-toolchain=${trustedResult.runtimeBinding.gitToolchainSha256}`,
      `system-toolchain=${trustedResult.runtimeBinding.systemToolchainSha256}`,
    ],
  };
}

function rebindMaterialToBundle(material, bundle, reviewBundleBytes) {
  const reviewBundleSection = material.sections.find(
    ({ kind }) => kind === "REVIEW_BUNDLE",
  );
  reviewBundleSection.content = reviewBundleBytes.toString("utf8");
  reviewBundleSection.byteLength = reviewBundleBytes.byteLength;
  reviewBundleSection.sha256 =
    independentKimiReviewDigests.bytes(reviewBundleBytes);
  material.bindings.reviewBundle.byteLength = reviewBundleBytes.byteLength;
  material.bindings.reviewBundle.sha256 =
    reviewBundleSection.sha256;
  material.bindings.reviewBundle.bundleDigest = bundle.bundleSha256;
  material.sectionSetSha256 = independentKimiReviewDigests.value(
    material.sections.map((section) => {
      const descriptor = structuredClone(section);
      delete descriptor.content;
      return descriptor;
    }),
  );
  material.totalSectionUtf8ByteLength = material.sections.reduce(
    (total, section) => total + section.byteLength,
    0,
  );
  material.materialSha256 =
    independentKimiReviewDigests.material(material);
  return Buffer.from(JSON.stringify(material), "utf8");
}

recursiveCollectorTest("Review Material re-reads Bundle, diff, source, specifications and test evidence from frozen bytes", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const { material, materialBytes } =
    await buildIndependentReviewMaterialFromGit({
      repoPath: fixture.repo,
      reviewBundleBytes,
      testEvidenceRoot: fixture.evidenceRoot,
      materialId: "irm_kimi_material_fixture",
    });

  assert.equal(material.source.sourceCommit, fixture.sourceCommit);
  assert.equal(material.source.sourceTree, bundle.source.tree);
  assert.equal(
    material.bindings.reviewBundle.bundleDigest,
    bundle.bundleSha256,
  );
  assert.ok(
    material.sections.some(
      ({ kind, path }) =>
        kind === "PATCH" && path === "artifacts/source.diff",
    ),
  );
  assert.ok(
    material.sections.some(
      ({ kind, path }) =>
        kind === "GOVERNANCE" &&
        path === "lib/kimi-independent-review.mjs",
    ),
  );
  assert.equal(
    material.sections.some(({ kind }) => kind === "SOURCE"),
    false,
  );
  const patchSection = material.sections.find(
    ({ kind }) => kind === "PATCH",
  );
  assert.match(
    patchSection.content,
    new RegExp(fixtureChangedSourcePath.replaceAll(".", "\\."), "u"),
  );
  const sectionKindsByPath = new Map();
  for (const { kind, path } of material.sections) {
    const kinds = sectionKindsByPath.get(path) ?? new Set();
    kinds.add(kind);
    sectionKindsByPath.set(path, kinds);
  }
  assert.equal(
    [...sectionKindsByPath.values()].some(
      (kinds) => kinds.has("SOURCE") && kinds.has("GOVERNANCE"),
    ),
    false,
  );
  assert.equal(
    material.sections.filter(({ kind }) => kind === "TEST_EVIDENCE")
      .length,
    1,
  );
  const testResult = JSON.parse(
    await readFile(
      join(fixture.evidenceRoot, bundle.testEvidenceSubjects[0].outputRef),
      "utf8",
    ),
  );
  assert.ok(
    material.sections.some(
      ({ kind, path }) =>
        kind === "TEST_EVIDENCE" &&
        path === bundle.testEvidenceSubjects[0].outputRef,
    ),
    `missing exact test result section: ${bundle.testEvidenceSubjects[0].outputRef}`,
  );
  for (const path of [
    testResult.stdoutRef,
    testResult.stderrRef,
    testResult.runtimeBinding.artifactRef,
  ]) {
    assert.equal(
      material.sections.some(
        ({ kind, path: sectionPath }) =>
          kind === "TEST_EVIDENCE" && sectionPath === path,
      ),
      false,
      `raw successful transcript must remain external frozen evidence: ${path}`,
    );
  }
  assert.equal(
    materialBytes.includes(
      Buffer.from("fixture material evidence\n", "utf8"),
    ),
    false,
  );
  assert.equal(
    testResult.stdoutSha256,
    independentKimiReviewDigests.bytes(
      Buffer.from("fixture material evidence\n", "utf8"),
    ),
  );
  assert.ok(materialBytes.byteLength <= material.contextBudgetUtf8Bytes);
});

recursiveCollectorTest("Dirty workspace bytes and tampered Bundle or test evidence cannot impersonate frozen Review Material", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const first = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_material_fixture",
  });
  await write(
    fixture.repo,
    "lib/kimi-independent-review.mjs",
    "dirty bytes outside sourceCommit\n",
  );
  const second = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_material_fixture",
  });
  assert.equal(second.material.materialSha256, first.material.materialSha256);

  const tamperedBundle = structuredClone(bundle);
  tamperedBundle.source.tree = "1".repeat(40);
  await assert.rejects(
    buildIndependentReviewMaterialFromGit({
      repoPath: fixture.repo,
      reviewBundleBytes: Buffer.from(JSON.stringify(tamperedBundle), "utf8"),
      testEvidenceRoot: fixture.evidenceRoot,
      materialId: "irm_kimi_material_fixture",
    }),
    /Bundle|Policy|tree/u,
  );

  const outputRef = bundle.testEvidenceSubjects[0].outputRef;
  await write(
    fixture.evidenceRoot,
    outputRef,
    '{"tampered":true}\n',
  );
  await assert.rejects(
    buildIndependentReviewMaterialFromGit({
      repoPath: fixture.repo,
      reviewBundleBytes,
      testEvidenceRoot: fixture.evidenceRoot,
      materialId: "irm_kimi_material_fixture",
    }),
    /test evidence (?:bytes drifted|closure is invalid)/u,
  );
});

recursiveCollectorTest("a rehashed result cannot replace the frozen sandbox template binding", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const forgedBundle = structuredClone(bundle);
  const evidence = forgedBundle.testEvidenceSubjects[0];
  const resultPath = join(fixture.evidenceRoot, evidence.outputRef);
  const attestation = JSON.parse(await readFile(resultPath, "utf8"));
  attestation.executionSource.sandbox.templateSha256 = digest("e");
  attestation.executionSource.sandbox.invocationSha256 =
    await sha256ProjectValue({
      executable: "/usr/bin/sandbox-exec",
      templateSha256:
        attestation.executionSource.sandbox.templateSha256,
      parameterSetSha256:
        attestation.executionSource.sandbox.parameterSetSha256,
    });
  attestation.resultSha256 = await sha256ProjectValue(
    Object.fromEntries(
      Object.entries(attestation).filter(
        ([key]) => key !== "resultSha256",
      ),
    ),
  );
  const resultBytes = Buffer.from(`${JSON.stringify(attestation)}\n`, "utf8");
  await write(fixture.evidenceRoot, evidence.outputRef, resultBytes);
  evidence.outputSha256 =
    independentKimiReviewDigests.bytes(resultBytes);
  evidence.outputByteLength = resultBytes.byteLength;
  evidence.toolVersions = evidence.toolVersions.map((value) => {
    if (value.startsWith("sandbox-template=")) {
      return `sandbox-template=${attestation.executionSource.sandbox.templateSha256}`;
    }
    if (value.startsWith("sandbox-invocation=")) {
      return `sandbox-invocation=${attestation.executionSource.sandbox.invocationSha256}`;
    }
    return value;
  });
  const forgedBundleBytes = await rehashBundle(forgedBundle);

  await assert.rejects(
    buildIndependentReviewMaterialFromGit({
      repoPath: fixture.repo,
      reviewBundleBytes: forgedBundleBytes,
      testEvidenceRoot: fixture.evidenceRoot,
      materialId: "irm_kimi_forged_sandbox_binding",
    }),
    /test evidence closure is invalid/u,
  );
});

recursiveCollectorTest("Kimi runner performs zero network calls without a credential", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_material_fixture",
  });
  const outputParent = await mkdtemp(join(tmpdir(), "zb-kimi-output-"));
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  let networkCalls = 0;
  const result = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    outputDir: join(outputParent, "review"),
    reviewId: "imrr_kimi_runner_fixture",
    apiKey: "",
    verifyRuntimeClosure: async () => true,
    fetchImpl: async () => {
      networkCalls += 1;
      throw new Error("must not be called");
    },
  });
  assert.equal(result.ok, false);
  assert.equal(result.status, "BLOCKED");
  assert.deepEqual(result.reasonCodes, [
    "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
  ]);
  assert.equal(result.networkAttemptCount, 0);
  assert.match(result.trustedBundleSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.match(result.trustedMaterialSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(networkCalls, 0);
});

recursiveCollectorTest("Kimi runner fails closed before network without a trusted runtime closure verifier", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_runtime_closure_missing",
  });
  const outputParent = await mkdtemp(join(tmpdir(), "zb-kimi-output-"));
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  let networkCalls = 0;

  const result = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    outputDir: join(outputParent, "review"),
    reviewId: "imrr_kimi_runtime_closure_missing",
    apiKey: runtimeApiKeyFixture(),
    fetchImpl: async () => {
      networkCalls += 1;
      throw new Error("must not be called");
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, "BLOCKED");
  assert.deepEqual(result.reasonCodes, [
    "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
  ]);
  assert.equal(result.networkAttemptCount, 0);
  assert.equal(networkCalls, 0);
});

recursiveCollectorTest("Kimi test harness cannot publish a formal Receipt from injected controls", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_runtime_closure_changes",
  });
  const outputParent = await mkdtemp(join(tmpdir(), "zb-kimi-output-"));
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  const outputDir = join(outputParent, "review");
  let networkCalls = 0;
  let runtimeClosureChecks = 0;
  const content = JSON.stringify({
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "No blocking findings.",
    findings: [],
    decision: "CLEAR",
  });

  const result = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    outputDir,
    reviewId: "imrr_kimi_runtime_closure_changes",
    apiKey: runtimeApiKeyFixture(),
    verifyRuntimeClosure: async () => {
      runtimeClosureChecks += 1;
      return true;
    },
    fetchImpl: async () => {
      networkCalls += 1;
      const responseBytes = Buffer.from(
        JSON.stringify({
          id: "chatcmpl_runtime_closure_changes",
          object: "chat.completion",
          model: "kimi-k2.7-code",
          choices: [
            {
              index: 0,
              finish_reason: "stop",
              message: { role: "assistant", content },
            },
          ],
        }),
        "utf8",
      );
      return {
        status: 200,
        redirected: false,
        url: "https://api.moonshot.ai/v1/chat/completions",
        headers: new Headers({ "content-type": "application/json" }),
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(responseBytes);
            controller.close();
          },
        }),
      };
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, "INCONCLUSIVE");
  assert.deepEqual(result.reasonCodes, [
    "KIMI_TEST_HARNESS_CANNOT_PUBLISH_RECEIPT",
  ]);
  assert.equal(result.networkAttemptCount, 1);
  assert.equal(networkCalls, 1);
  assert.equal(runtimeClosureChecks, 2);
  await assert.rejects(readFile(join(outputDir, "receipt.json")));
});

test("repository snapshot binds tracked, untracked and symlink worktree bytes", async (t) => {
  const repo = await mkdtemp(join(tmpdir(), "zb-kimi-snapshot-"));
  t.after(() => rm(repo, { recursive: true, force: true }));
  await git(repo, ["init", "-q"]);
  await git(repo, ["config", "user.name", "Snapshot Test"]);
  await git(repo, [
    "config",
    "user.email",
    "snapshot-test@example.invalid",
  ]);
  await write(repo, "tracked.txt", "frozen\n");
  await git(repo, ["add", "tracked.txt"]);
  await git(repo, ["commit", "-q", "-m", "snapshot base"]);
  await write(repo, "tracked.txt", "first-a\n");
  await write(repo, "untracked.txt", "first-b\n");
  await symlink("missing-a", join(repo, "link"));

  const before = await captureKimiReviewRepositorySnapshot({
    repoPath: repo,
    protectedPaths: [],
  });
  await write(repo, "tracked.txt", "seconda\n");
  await write(repo, "untracked.txt", "secondb\n");
  await rm(join(repo, "link"));
  await symlink("missing-b", join(repo, "link"));
  const after = await captureKimiReviewRepositorySnapshot({
    repoPath: repo,
    protectedPaths: [],
  });

  assert.equal(
    before.worktreeStatusSha256,
    after.worktreeStatusSha256,
  );
  assert.notEqual(
    before.worktreeContentManifestSha256,
    after.worktreeContentManifestSha256,
  );
  assert.equal(before.worktreePathCount, 3);
  assert.equal(after.worktreePathCount, 3);
});

test("repository snapshot rejects ignored paths outside its frozen exclusion policy", async (t) => {
  const repo = await mkdtemp(join(tmpdir(), "zb-kimi-ignored-path-"));
  t.after(() => rm(repo, { recursive: true, force: true }));
  await git(repo, ["init", "-q"]);
  await git(repo, ["config", "user.name", "Snapshot Test"]);
  await git(repo, [
    "config",
    "user.email",
    "snapshot-test@example.invalid",
  ]);
  await write(repo, ".gitignore", ".env\n");
  await git(repo, ["add", ".gitignore"]);
  await git(repo, ["commit", "-q", "-m", "snapshot base"]);
  await write(repo, ".env", "synthetic-placeholder\n");

  await assert.rejects(
    captureKimiReviewRepositorySnapshot({
      repoPath: repo,
      protectedPaths: [],
    }),
    /outside the frozen exclusion policy/u,
  );
});

recursiveCollectorTest("Kimi runner writes only sanitized exact-byte artifacts outside the unchanged repository", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_material_fixture",
  });
  const outputParent = await mkdtemp(join(tmpdir(), "zb-kimi-output-"));
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  const outputDir = join(outputParent, "review");
  const output = {
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "The frozen candidate is clear for bounded preproduction use.",
    findings: [],
    decision: "CLEAR",
  };
  const content = JSON.stringify(output);
  const runtimeOnlyCredential = [
    "runtime",
    "credential",
    "fixture",
    randomTokenForTest(),
  ].join("-");
  let networkCalls = 0;
  const times = [
    new Date("2026-07-30T12:10:00.000Z"),
    new Date("2026-07-30T12:10:01.000Z"),
  ];
  const result = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    outputDir,
    reviewId: "imrr_kimi_runner_fixture",
    apiKey: runtimeOnlyCredential,
    verifyRuntimeClosure: async () => true,
    fetchImpl: async (_url, options) => {
      networkCalls += 1;
      assert.equal(options.method, "POST");
      assert.equal(options.redirect, "error");
      const responseBytes = Buffer.from(
        JSON.stringify({
          id: "chatcmpl_runner_fixture",
          object: "chat.completion",
          model: "kimi-k2.7-code",
          choices: [
            {
              index: 0,
              finish_reason: "stop",
              message: { role: "assistant", content },
            },
          ],
        }),
        "utf8",
      );
      return {
        status: 200,
        redirected: false,
        url: "https://api.moonshot.ai/v1/chat/completions",
        headers: new Headers({ "content-type": "application/json" }),
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(responseBytes);
            controller.close();
          },
        }),
      };
    },
    now: () => times.shift(),
  });
  assert.equal(networkCalls, 1);
  assert.equal(result.ok, false);
  assert.equal(result.status, "INCONCLUSIVE");
  assert.deepEqual(result.reasonCodes, [
    "KIMI_TEST_HARNESS_CANNOT_PUBLISH_RECEIPT",
  ]);
  assert.equal(result.testOnlyModelDecision, "CLEAR");
  assert.equal(result.formalReceiptPublished, false);
  for (const name of [
    "request.json",
    "response.json",
    "content.json",
    "material.json",
  ]) {
    const bytes = await readFile(join(outputDir, name));
    assert.equal(bytes.includes(runtimeOnlyCredential), false);
  }
  const requestArtifact = JSON.parse(
    await readFile(join(outputDir, "request.json"), "utf8"),
  );
  assert.equal(Object.hasOwn(requestArtifact, "headers"), false);
  assert.equal(Object.hasOwn(requestArtifact, "authorization"), false);
  await assert.rejects(readFile(join(outputDir, "receipt.json")));
});

recursiveCollectorTest("Kimi test harness never freezes model outcomes as formal Receipts", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_material_fixture",
  });
  const outputParent = await mkdtemp(join(tmpdir(), "zb-kimi-outcomes-"));
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  const runtimeOnlyCredential = [
    "runtime",
    "credential",
    randomTokenForTest(),
  ].join("-");
  let networkCalls = 0;
  for (const decision of ["BLOCKED", "INCONCLUSIVE"]) {
    const outputDir = join(outputParent, decision.toLowerCase());
    const content = JSON.stringify({
      schemaVersion: "independent-model-review-output.v2",
      reviewSummary: `The frozen candidate review concluded ${decision}.`,
      findings: [],
      decision,
    });
    const times = [
      new Date("2026-07-30T12:20:00.000Z"),
      new Date("2026-07-30T12:20:01.000Z"),
    ];
    const result = await runKimiIndependentReviewTestHarness({
      repoPath: fixture.repo,
      reviewBundleBytes,
      reviewMaterialBytes: materialBytes,
      testEvidenceRoot: fixture.evidenceRoot,
      outputDir,
      reviewId: `imrr_kimi_${decision.toLowerCase()}_fixture`,
      apiKey: runtimeOnlyCredential,
      verifyRuntimeClosure: async () => true,
      fetchImpl: async () => {
        networkCalls += 1;
        const responseBytes = Buffer.from(
          JSON.stringify({
            id: `chatcmpl_${decision.toLowerCase()}_fixture`,
            object: "chat.completion",
            model: "kimi-k2.7-code",
            choices: [
              {
                index: 0,
                finish_reason: "stop",
                message: { role: "assistant", content },
              },
            ],
          }),
          "utf8",
        );
        return {
          status: 200,
          redirected: false,
          url: "https://api.moonshot.ai/v1/chat/completions",
          headers: new Headers({ "content-type": "application/json" }),
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(responseBytes);
              controller.close();
            },
          }),
        };
      },
      now: () => times.shift(),
    });
    assert.equal(result.ok, false);
    assert.equal(result.status, "INCONCLUSIVE", JSON.stringify(result));
    assert.equal(result.conclusion, "INCONCLUSIVE", JSON.stringify(result));
    assert.deepEqual(result.reasonCodes, [
      "KIMI_TEST_HARNESS_CANNOT_PUBLISH_RECEIPT",
    ]);
    assert.equal(result.testOnlyModelDecision, decision);
    assert.equal(result.networkAttemptCount, 1);
    await assert.rejects(readFile(join(outputDir, "receipt.json")));
  }
  assert.equal(networkCalls, 2);
});

recursiveCollectorTest("Kimi runner rejects a symlinked output parent before network or repository writes", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_material_fixture",
  });
  const outside = await mkdtemp(join(tmpdir(), "zb-kimi-link-"));
  t.after(() => rm(outside, { recursive: true, force: true }));
  const linkedRepo = join(outside, "linked-repo");
  await symlink(fixture.repo, linkedRepo, "dir");
  let networkCalls = 0;
  await assert.rejects(
    runKimiIndependentReviewTestHarness({
      repoPath: fixture.repo,
      reviewBundleBytes,
      reviewMaterialBytes: materialBytes,
      testEvidenceRoot: fixture.evidenceRoot,
      outputDir: join(linkedRepo, "review"),
      reviewId: "imrr_kimi_symlink_fixture",
      apiKey: runtimeApiKeyFixture(),
      verifyRuntimeClosure: async () => true,
      fetchImpl: async () => {
        networkCalls += 1;
        throw new Error("must not be called");
      },
    }),
    /outside|symbolic|repository/iu,
  );
  assert.equal(networkCalls, 0);
  await assert.rejects(readFile(join(fixture.repo, "review", "request.json")));
});

recursiveCollectorTest("Kimi runner re-proves Bundle patch and scope from the real source commit", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  await assert.doesNotReject(
    verifyKimiReviewBundleGitBindings({
      repoPath: fixture.repo,
      bundle,
    }),
  );

  const forgedPatch = structuredClone(bundle);
  forgedPatch.source.diffSha256 = digest("e");
  await assert.rejects(
    verifyKimiReviewBundleGitBindings({
      repoPath: fixture.repo,
      bundle: forgedPatch,
    }),
    /Git|Bundle|patch/iu,
  );

  const forgedDiffCheck = structuredClone(bundle);
  forgedDiffCheck.source.gitDiffCheck.resultSha256 = digest("d");
  await assert.rejects(
    verifyKimiReviewBundleGitBindings({
      repoPath: fixture.repo,
      bundle: forgedDiffCheck,
    }),
    /Git|Bundle|patch/iu,
  );

  const omittedScope = structuredClone(bundle);
  omittedScope.reviewedPaths = omittedScope.reviewedPaths.slice(1);
  omittedScope.sourceSubjects = omittedScope.sourceSubjects.slice(1);
  omittedScope.source.changedPathsDigest = await sha256ProjectValue(
    omittedScope.reviewedPaths,
  );
  await assert.rejects(
    verifyKimiReviewBundleGitBindings({
      repoPath: fixture.repo,
      bundle: omittedScope,
    }),
    /Git|Bundle|scope/iu,
  );

  const forgedSource = structuredClone(bundle);
  forgedSource.sourceSubjects[0].blobSha256 = digest("f");
  await assert.rejects(
    verifyKimiReviewBundleGitBindings({
      repoPath: fixture.repo,
      bundle: forgedSource,
    }),
    /Git|Bundle|source/iu,
  );

  const omittedSpecification = structuredClone(bundle);
  omittedSpecification.specificationSubjects =
    omittedSpecification.specificationSubjects.slice(1);
  await assert.rejects(
    verifyKimiReviewBundleGitBindings({
      repoPath: fixture.repo,
      bundle: omittedSpecification,
    }),
    /Git|Bundle|specification/iu,
  );
});

recursiveCollectorTest("Kimi runner discards caller-rehashed test evidence and rebuilds the frozen test plan result", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const { material } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_material_fixture",
  });
  const forgedBundle = structuredClone(bundle);
  forgedBundle.testEvidenceSubjects[0].command =
    "NODE -e process.stdout.write('forged pass')";
  const forgedBundleBytes = await rehashBundle(forgedBundle);
  const forgedMaterialBytes = rebindMaterialToBundle(
    structuredClone(material),
    forgedBundle,
    forgedBundleBytes,
  );
  const outputParent = await mkdtemp(join(tmpdir(), "zb-kimi-output-"));
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  let networkCalls = 0;
  const result = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes: forgedBundleBytes,
    reviewMaterialBytes: forgedMaterialBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    outputDir: join(outputParent, "review"),
    reviewId: "imrr_kimi_runner_forged_test_evidence",
    apiKey: "",
    verifyRuntimeClosure: async () => true,
    fetchImpl: async () => {
      networkCalls += 1;
      throw new Error("must not be called");
    },
  });
  assert.equal(result.status, "BLOCKED");
  assert.deepEqual(result.reasonCodes, [
    "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
  ]);
  assert.equal(networkCalls, 0);
});

recursiveCollectorTest("Kimi runner re-executes the frozen test plan instead of trusting a fully forged PASS closure", async (t) => {
  const fixture = await fixtureRepository(t);
  const originalBundle = await bundleFor(fixture);
  await write(
    fixture.repo,
    "fixture-execution-source.txt",
    "this source must fail the frozen test plan\n",
  );
  await git(fixture.repo, ["add", "fixture-execution-source.txt"]);
  await git(fixture.repo, ["commit", "-q", "-m", "failing source"]);
  const [{ stdout: sourceText }, { stdout: treeText }] = await Promise.all([
    git(fixture.repo, ["rev-parse", "HEAD"]),
    git(fixture.repo, ["rev-parse", "HEAD^{tree}"]),
  ]);
  const sourceCommit = sourceText.trim();
  const sourceTree = treeText.trim();
  const { stdout: patchBytes } = await git(
    fixture.repo,
    [
      "diff",
      "--binary",
      "--full-index",
      "--no-ext-diff",
      "--no-textconv",
      fixture.sourceCommit,
      sourceCommit,
      "--",
    ],
    "buffer",
  );
  const sourceBytes = await readFile(
    join(fixture.repo, "fixture-execution-source.txt"),
  );
  const forgedBundle = structuredClone(originalBundle);
  const gitDiffCheck = await createTrustedGitDiffCheck({
    repoPath: fixture.repo,
    baseCommit: fixture.sourceCommit,
    sourceCommit,
    sourceTree,
    patchBytes: Buffer.from(patchBytes),
    runnerGitBlobSha256:
      originalBundle.artifacts.bundleGeneratorSha256,
    runnerExecutedBytesSha256:
      originalBundle.artifacts.bundleGeneratorSha256,
  });
  forgedBundle.source = {
    baseCommit: fixture.sourceCommit,
    sourceCommit,
    headCommit: sourceCommit,
    tree: sourceTree,
    diffSha256:
      independentKimiReviewDigests.bytes(Buffer.from(patchBytes)),
    changedPathsDigest: await sha256ProjectValue([
      "fixture-execution-source.txt",
    ]),
    gitDiffCheck,
  };
  forgedBundle.reviewedPaths = ["fixture-execution-source.txt"];
  forgedBundle.sourceSubjects = [
    {
      path: "fixture-execution-source.txt",
      gitMode: "100644",
      blobSha256:
        independentKimiReviewDigests.bytes(sourceBytes),
    },
  ];
  forgedBundle.testEvidenceSubjects = [
    await forgePassingEvidenceForCommit(
      fixture,
      forgedBundle,
      sourceCommit,
      sourceTree,
    ),
  ];
  const forgedBundleBytes = await rehashBundle(forgedBundle);
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes: forgedBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_forged_pass_fixture",
  });
  const outputParent = await mkdtemp(join(tmpdir(), "zb-kimi-output-"));
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  let networkCalls = 0;
  await assert.rejects(
    runKimiIndependentReviewTestHarness({
      repoPath: fixture.repo,
      reviewBundleBytes: forgedBundleBytes,
      reviewMaterialBytes: materialBytes,
      testEvidenceRoot: fixture.evidenceRoot,
      outputDir: join(outputParent, "review"),
      reviewId: "imrr_kimi_runner_forged_pass_closure",
      apiKey: "",
      verifyRuntimeClosure: async () => true,
      fetchImpl: async () => {
        networkCalls += 1;
        throw new Error("must not be called");
      },
    }),
    /not reproved|frozen source|test evidence closure/iu,
  );
  assert.equal(networkCalls, 0);
});

recursiveCollectorTest("Kimi request and Receipt replace a fully forged PASS closure with fresh trusted evidence", async (t) => {
  const fixture = await fixtureRepository(t);
  const originalBundle = await bundleFor(fixture);
  const [{ stdout: treeText }] = await Promise.all([
    git(fixture.repo, ["rev-parse", "HEAD^{tree}"]),
  ]);
  const marker = `FORGED_TEST_EVIDENCE_${process.pid}_${Date.now()}`;
  originalBundle.testEvidenceSubjects = [
    await forgePassingEvidenceForCommit(
      fixture,
      originalBundle,
      fixture.sourceCommit,
      treeText.trim(),
      marker,
    ),
  ];
  const forgedBundleBytes = await rehashBundle(originalBundle);
  const { materialBytes: forgedMaterialBytes } =
    await buildIndependentReviewMaterialFromGit({
      repoPath: fixture.repo,
      reviewBundleBytes: forgedBundleBytes,
      testEvidenceRoot: fixture.evidenceRoot,
      materialId: "irm_kimi_forged_but_passing_fixture",
    });
  assert.match(forgedMaterialBytes.toString("utf8"), new RegExp(marker, "u"));
  const outputParent = await mkdtemp(join(tmpdir(), "zb-kimi-output-"));
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  let networkCalls = 0;
  let sentRequest = "";
  const result = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes: forgedBundleBytes,
    reviewMaterialBytes: forgedMaterialBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    outputDir: join(outputParent, "review"),
    reviewId: "imrr_kimi_runner_replaces_forged_pass",
    apiKey: runtimeApiKeyFixture(),
    verifyRuntimeClosure: async () => true,
    fetchImpl: async (_url, options) => {
      networkCalls += 1;
      sentRequest = options.body;
      const responseBytes = Buffer.from(
        JSON.stringify({
          id: "chatcmpl_kimi_review_replaces_forged_pass",
          object: "chat.completion",
          model: "kimi-k2.7-code",
          choices: [
            {
              index: 0,
              finish_reason: "stop",
              message: {
                role: "assistant",
                content: JSON.stringify({
                  schemaVersion: "independent-model-review-output.v2",
                  reviewSummary: "No blocking findings.",
                  decision: "CLEAR",
                  findings: [],
                }),
              },
            },
          ],
        }),
        "utf8",
      );
      return {
        status: 200,
        redirected: false,
        url: "https://api.moonshot.ai/v1/chat/completions",
        headers: new Headers({ "content-type": "application/json" }),
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(responseBytes);
            controller.close();
          },
        }),
      };
    },
  });
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.status, "INCONCLUSIVE");
  assert.equal(result.testOnlyModelDecision, "CLEAR");
  assert.equal(networkCalls, 1);
  assert.equal(sentRequest.includes(marker), false);
  const outputDir = join(outputParent, "review");
  for (const path of [
    "material.json",
    "bundle.json",
  ]) {
    assert.equal(
      (await readFile(join(outputDir, path), "utf8")).includes(marker),
      false,
    );
  }
});

function randomTokenForTest() {
  return `${process.pid}-${Date.now()}`;
}
