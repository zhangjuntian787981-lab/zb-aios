import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdir,
  lstat,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { sha256ProjectValue } from "../lib/project-control.mjs";
import {
  encodeIndependentReviewMaterialEnvelope,
  independentKimiReviewDigests,
  kimiIndependentReviewFixedBaseCommit,
  parseIndependentReviewMaterialEnvelope,
  validateIndependentReviewMaterial,
} from "../lib/kimi-independent-review.mjs";
import {
  classifyKimiK3V5ContractPresence,
  classifyKimiK3V6ContractPresence,
  classifyKimiK3V7ContractPresence,
  kimiK3HistoricalReviewEvidenceContract,
  kimiK3HistoricalReviewEvidencePaths,
  validateIndependentReviewHistoricalEvidenceIndex,
} from "../lib/kimi-k3-independent-review.mjs";
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
const fixtureBinarySourcePath =
  "implementation/governance/independent-review/material-fixture-binary.bin";
const protectedWorkspacePaths = new Set([
  "README.md",
  "docs/plans/通用多企业AI员工平台_v5.1新增内容与开源参考对照表_v1.0.md",
  "docs/plans/通用多企业AI员工平台_完备工程级方案_v5.2.md",
]);
const cumulativeCandidateWorkspacePaths = new Set([
  "docs/adr/0014-k3-historical-evidence-materialization-checkpoint.md",
  "docs/adr/0015-kimi-k3-transport-contract-v3.md",
  "docs/adr/0016-kimi-k3-mfjs-provider-transport-adapter.md",
  "docs/adr/0017-kimi-k3-explicit-undici-timeout-contract.md",
  "docs/adr/0018-kimi-k3-extended-chat-deadline-contract.md",
  "docs/adr/0019-kimi-k3-chat-response-sensitive-material-contract.md",
  "docs/research/moonshot-kimi-k3-transport-contract-v3-2026-08-01.md",
  "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/historical-evidence-index.v1.json",
  "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
  "implementation/governance/independent-review/kimi-runtime-manifest.v3.json",
  "implementation/governance/independent-review/kimi-runtime-manifest.v4.json",
  "implementation/governance/independent-review/kimi-runtime-manifest.v5.json",
  "implementation/governance/independent-review/moonshot-kimi-k3.v3.json",
  "implementation/governance/schemas/independent-model-review-receipt.v5.schema.json",
  "implementation/governance/schemas/independent-model-review-receipt.v6.schema.json",
  "implementation/governance/schemas/independent-model-review-receipt.v7.schema.json",
  "implementation/governance/schemas/independent-model-review-receipt.v8.schema.json",
  "implementation/governance/schemas/independent-model-review-receipt.v9.schema.json",
  "implementation/governance/schemas/independent-review-historical-evidence-index.v1.schema.json",
  "implementation/governance/schemas/independent-review-material.v4.schema.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v2.schema.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v3.schema.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v4.schema.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v5.schema.json",
  "implementation/governance/schemas/independent-review-transport-evidence.v3.schema.json",
  "implementation/governance/schemas/independent-review-transport-evidence.v4.schema.json",
  "implementation/governance/schemas/moonshot-kimi-independent-review-config.v3.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v1.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v2.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v3.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v1.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v2.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v3.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v4.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v2.schema.json",
  "lib/kimi-independent-review.mjs",
  "lib/independent-review-runtime-manifest.mjs",
  "lib/kimi-k3-independent-review.mjs",
  "lib/kimi-k3-review-evidence.mjs",
  "package-lock.json",
  "package.json",
  "scripts/build-independent-review-material.mjs",
  "scripts/build-independent-review-runtime-manifest.mjs",
  "scripts/bootstrap-kimi-independent-review.mjs",
  "scripts/run-kimi-independent-review.mjs",
  "tests/independent-review-material-generator.test.mjs",
  "tests/independent-review-runtime-manifest.test.mjs",
  "tests/kimi-independent-review-bootstrap.test.mjs",
  "tests/kimi-k3-independent-review.test.mjs",
  "tests/kimi-k3-review-evidence.test.mjs",
]);
const historicalEvidenceOutcomePath =
  "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/single-call-outcome.v1.json";
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
  "tests/independent-review-material-generator.test.mjs",
];
const candidatePaths = [
  "docs/adr/0012-moonshot-kimi-independent-review-transport.md",
  "implementation/governance/independent-review/moonshot-kimi-k2.7-code.v1.json",
  "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json",
  "implementation/governance/schemas/independent-review-material.v1.schema.json",
  "implementation/governance/schemas/independent-review-material.v2.schema.json",
  "implementation/governance/schemas/moonshot-kimi-independent-review-config.v1.schema.json",
  "lib/independent-review-runtime-binding.mjs",
  "lib/kimi-independent-review.mjs",
  "scripts/build-independent-review-material.mjs",
  "scripts/launch-kimi-independent-review.sh",
  "scripts/run-kimi-independent-review.mjs",
  "tests/kimi-independent-review.test.mjs",
];
const k3V2CandidatePaths = [
  "docs/adr/0013-moonshot-kimi-k3-single-call-transport.md",
  "docs/research/moonshot-kimi-k3-transport-contract-2026-07-31.md",
  "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
  "implementation/governance/schemas/independent-model-review-receipt.v4.schema.json",
  "implementation/governance/schemas/independent-review-material.v3.schema.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v2.schema.json",
  "implementation/governance/schemas/independent-review-transport-evidence.v2.schema.json",
  "implementation/governance/schemas/moonshot-kimi-independent-review-config.v2.schema.json",
  "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v1.schema.json",
  "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
  "lib/kimi-k3-independent-review.mjs",
  "lib/kimi-k3-review-evidence.mjs",
  "scripts/bootstrap-kimi-independent-review.mjs",
  "scripts/launch-kimi-independent-review.sh",
  "tests/kimi-k3-independent-review.test.mjs",
  "tests/kimi-k3-review-evidence.test.mjs",
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

function nulPaths(bytes) {
  return Buffer.from(bytes)
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
}

async function assertOnlyProtectedWorkspaceChanges(sourceRepository) {
  const [
    { stdout: trackedBytes },
    { stdout: untrackedBytes },
    { stdout: stagedBytes },
  ] =
    await Promise.all([
      git(
        sourceRepository,
        ["diff", "--name-only", "-z", "--"],
        null,
      ),
      git(
        sourceRepository,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        null,
      ),
      git(
        sourceRepository,
        ["diff", "--cached", "--name-only", "-z", "HEAD", "--"],
        null,
      ),
    ]);
  const trackedPaths = nulPaths(trackedBytes);
  const untrackedPaths = nulPaths(untrackedBytes);
  const stagedPaths = nulPaths(stagedBytes);
  const unexpected = [
    ...trackedPaths,
    ...untrackedPaths,
    ...stagedPaths,
  ].filter(
    (path) =>
      !protectedWorkspacePaths.has(path) &&
      !cumulativeCandidateWorkspacePaths.has(path),
  );
  assert.deepEqual(
    unexpected,
    [],
    "the cumulative fixture only accepts the explicit task candidate and protected workspace paths",
  );
  assert.deepEqual(
    stagedPaths.filter((path) =>
      protectedWorkspacePaths.has(path),
    ),
    [],
    "protected workspace paths must never enter the staged candidate",
  );
  const candidatePaths = [
    ...new Set([...trackedPaths, ...untrackedPaths, ...stagedPaths]),
  ]
    .filter((path) => cumulativeCandidateWorkspacePaths.has(path))
    .sort();
  for (const path of candidatePaths) {
    const entry = await lstat(join(sourceRepository, path));
    assert.equal(entry.isFile(), true, `candidate path must be a file: ${path}`);
    assert.equal(
      entry.isSymbolicLink(),
      false,
      `candidate path must not be a symlink: ${path}`,
    );
  }
  return {
    candidatePaths,
    untrackedCandidatePaths: untrackedPaths.filter((path) =>
      cumulativeCandidateWorkspacePaths.has(path),
    ),
  };
}

function rehashHistoricalEvidenceIndex(index) {
  for (const entry of index.entries) {
    entry.entrySha256 = independentKimiReviewDigests.value(
      Object.fromEntries(
        Object.entries(entry).filter(([key]) => key !== "entrySha256"),
      ),
    );
  }
  index.entrySetSha256 = independentKimiReviewDigests.value(index.entries);
  index.pathSetSha256 = independentKimiReviewDigests.value(
    index.entries.map(({ path }) => path),
  );
  index.indexSha256 = independentKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(index).filter(([key]) => key !== "indexSha256"),
    ),
  );
  return index;
}

async function frozenGitPath(repo, commit, path) {
  const [{ stdout: bytes }, { stdout: entryBytes }] = await Promise.all([
    git(repo, ["cat-file", "blob", `${commit}:${path}`], null),
    git(repo, ["ls-tree", "-z", commit, "--", path], null),
  ]);
  const entry = Buffer.from(entryBytes).toString("utf8").replace(/\0$/u, "");
  const match = /^(100644|100755|120000|160000) (blob|commit) [a-f0-9]{40}\t(.+)$/u.exec(
    entry,
  );
  assert.ok(match, `missing exact Git entry: ${commit}:${path}`);
  assert.equal(match[3], path);
  return { bytes: Buffer.from(bytes), gitMode: match[1] };
}

async function applyStagedCandidate(
  repo,
  sourceRepository,
  currentHead,
) {
  const workspace =
    await assertOnlyProtectedWorkspaceChanges(sourceRepository);
  const { stdout: sourceIndexBefore } = await git(
    sourceRepository,
    ["ls-files", "--stage", "-z"],
    null,
  );
  assert.ok(sourceIndexBefore instanceof Buffer);
  assert.equal(
    / [1-3]\t/u.test(sourceIndexBefore.toString("utf8")),
    false,
    "the cumulative candidate index must not contain unresolved stages",
  );
  const { stdout: patchBytes } = await git(
    sourceRepository,
    ["diff", "--cached", "--binary", "--full-index", "HEAD", "--"],
    null,
  );
  assert.ok(patchBytes instanceof Buffer);
  if (patchBytes.byteLength > 0) {
    const patchPath = join(repo, ".git", "staged-candidate.patch");
    await writeFile(patchPath, patchBytes);
    try {
      await git(repo, ["apply", "--index", "--binary", patchPath]);
    } finally {
      await rm(patchPath, { force: true });
    }
  }
  const { stdout: worktreePatchBytes } = await git(
    sourceRepository,
    [
      "diff",
      "--binary",
      "--full-index",
      "--",
      ...workspace.candidatePaths,
    ],
    null,
  );
  if (worktreePatchBytes.byteLength > 0) {
    const worktreePatchPath = join(repo, ".git", "worktree-candidate.patch");
    await writeFile(worktreePatchPath, worktreePatchBytes);
    try {
      await git(repo, ["apply", "--index", "--binary", worktreePatchPath]);
    } finally {
      await rm(worktreePatchPath, { force: true });
    }
  }
  for (const path of workspace.untrackedCandidatePaths) {
    await write(repo, path, await readFile(join(sourceRepository, path)));
    await git(repo, ["add", "--", path]);
  }
  const { stdout: candidatePathBytes } = await git(
    repo,
    ["diff", "--cached", "--name-only", "-z", currentHead, "--"],
    null,
  );
  assert.deepEqual(
    nulPaths(candidatePathBytes).sort(),
    workspace.candidatePaths,
    "the cumulative fixture must contain every and only explicit task candidate path",
  );
  for (const path of workspace.candidatePaths) {
    const [{ stdout: fixtureBytes }, sourceBytes] = await Promise.all([
      git(repo, ["cat-file", "blob", `:${path}`], null),
      readFile(join(sourceRepository, path)),
    ]);
    assert.deepEqual(
      fixtureBytes,
      sourceBytes,
      `the cumulative fixture must freeze exact worktree bytes: ${path}`,
    );
  }
  const { stdout: combinedPatchBytes } = await git(
    repo,
    ["diff", "--cached", "--binary", "--full-index", currentHead, "--"],
    null,
  );
  let sourceCommit = currentHead;
  if (combinedPatchBytes.byteLength > 0) {
    await git(repo, ["commit", "-q", "-m", "exact task candidate"]);
    const { stdout } = await git(repo, ["rev-parse", "HEAD"]);
    sourceCommit = stdout.trim();
  }
  const [
    { stdout: sourceIndexAfter },
    { stdout: sourceTreeText },
    { stdout: sourceParentText },
  ] = await Promise.all([
    git(sourceRepository, ["ls-files", "--stage", "-z"], null),
    git(repo, ["rev-parse", `${sourceCommit}^{tree}`]),
    combinedPatchBytes.byteLength > 0
      ? git(repo, ["rev-parse", `${sourceCommit}^`])
      : Promise.resolve({ stdout: `${currentHead}\n` }),
  ]);
  assert.deepEqual(
    sourceIndexAfter,
    sourceIndexBefore,
    "the cumulative fixture must not mutate the source index",
  );
  assert.equal(sourceParentText.trim(), currentHead);
  return {
    sourceCommit,
    sourceTree: sourceTreeText.trim(),
    sourceIndexSha256:
      independentKimiReviewDigests.bytes(sourceIndexBefore),
    stagedPatchSha256:
      independentKimiReviewDigests.bytes(combinedPatchBytes),
  };
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

async function fixtureRepository(
  t,
  { includeCumulativeHead = false, includeK3V2 = false } = {},
) {
  const repo = await mkdtemp(join(tmpdir(), "zb-kimi-material-"));
  t.after(() => rm(repo, { recursive: true, force: true }));
  const sourceRepository = fileURLToPath(root);
  const { stdout: currentHeadText } = await git(sourceRepository, [
    "rev-parse",
    "HEAD",
  ]);
  await git(repo, ["init", "-q"]);
  await git(repo, ["remote", "add", "source", sourceRepository]);
  await git(repo, [
    "fetch",
    "-q",
    "--no-tags",
    "source",
    currentHeadText.trim(),
  ]);
  if (includeCumulativeHead) {
    await git(repo, [
      "fetch",
      "-q",
      "--no-tags",
      "source",
      "+refs/heads/*:refs/remotes/source/*",
      "+refs/tags/*:refs/tags/*",
    ]);
  }
  await git(repo, [
    "checkout",
    "-q",
    "-B",
    "fixture-source",
    includeCumulativeHead
      ? currentHeadText.trim()
      : kimiIndependentReviewFixedBaseCommit,
  ]);
  await git(repo, ["config", "user.name", "Kimi Material Test"]);
  await git(repo, [
    "config",
    "user.email",
    "review-test@example.invalid",
  ]);
  let exactCandidate = null;
  if (includeCumulativeHead) {
    exactCandidate = await applyStagedCandidate(
      repo,
      sourceRepository,
      currentHeadText.trim(),
    );
  } else {
    for (const path of new Set([
      ...basePaths,
      ...candidatePaths,
      ...(includeK3V2 ? k3V2CandidatePaths : []),
    ])) {
      if (
        [
          "tests/independent-review-material-generator.test.mjs",
          "tests/kimi-independent-review.test.mjs",
          "tests/kimi-k3-review-evidence.test.mjs",
        ].includes(path)
      ) {
        await write(
          repo,
          path,
          "// bounded synthetic governance subject for the positive Material fixture\n",
        );
      } else {
        await copyCandidate(repo, path);
      }
    }
    await writeFixtureTestPlan(repo);
    await write(
      repo,
      "fixture-execution-source.txt",
      "frozen execution source\n",
    );
    await write(
      repo,
      fixtureChangedSourcePath,
      "deterministic source change represented by the exact Git patch\n",
    );
    await write(
      repo,
      fixtureBinarySourcePath,
      Buffer.from([0xff, 0xfe, 0x00, 0x80]),
    );
    await git(repo, ["add", "."]);
    await git(repo, ["commit", "-q", "-m", "candidate"]);
  }
  if (includeCumulativeHead) {
    await symlink(
      fileURLToPath(new URL("node_modules", root)),
      join(repo, "node_modules"),
      "dir",
    );
  }
  const { stdout: sourceText } = await git(repo, ["rev-parse", "HEAD"]);
  const evidenceRoot = await mkdtemp(
    join(tmpdir(), "zb-independent-review-material-evidence-"),
  );
  t.after(() => rm(evidenceRoot, { recursive: true, force: true }));
  return {
    repo,
    baseCommit: kimiIndependentReviewFixedBaseCommit,
    sourceCommit: exactCandidate?.sourceCommit ?? sourceText.trim(),
    sourceTree: exactCandidate?.sourceTree ?? null,
    sourceIndexSha256: exactCandidate?.sourceIndexSha256 ?? null,
    stagedPatchSha256: exactCandidate?.stagedPatchSha256 ?? null,
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

async function rebindMaterialToBundle(
  materialBytes,
  bundle,
  reviewBundleBytes,
) {
  const { material, sectionBytes } =
    parseIndependentReviewMaterialEnvelope(materialBytes);
  const reviewBundleSection = material.sections.find(
    ({ kind }) => kind === "REVIEW_BUNDLE",
  );
  const reviewBundleSectionIndex =
    material.sections.indexOf(reviewBundleSection);
  sectionBytes[reviewBundleSectionIndex] = reviewBundleBytes;
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
  material.totalSectionUtf8ByteLength = sectionBytes.reduce(
    (total, bytes) => total + bytes.byteLength,
    0,
  );
  material.materialSha256 =
    independentKimiReviewDigests.material(material);
  return encodeIndependentReviewMaterialEnvelope({
    material,
    sectionBytes,
  });
}

recursiveCollectorTest("Review Material v2 re-reads exact source changes and frozen evidence into one bounded Envelope", async (t) => {
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
  assert.equal(
    material.source.baseCommit,
    kimiIndependentReviewFixedBaseCommit,
  );
  assert.equal(material.schemaVersion, "independent-review-material.v2");
  assert.equal(material.source.sourceTree, bundle.source.tree);
  assert.equal(
    material.bindings.reviewBundle.bundleDigest,
    bundle.bundleSha256,
  );
  const parsed = parseIndependentReviewMaterialEnvelope(materialBytes);
  assert.deepEqual(parsed.material, material);
  assert.equal(parsed.sectionBytes.length, material.sections.length);
  assert.equal(
    material.sections.every(
      (descriptor) => !Object.hasOwn(descriptor, "content"),
    ),
    true,
  );
  const sourceChangeSections = material.sections.filter(
    ({ kind, path }) =>
      (kind === "SOURCE" || kind === "PATCH") &&
      bundle.reviewedPaths.includes(path),
  );
  assert.deepEqual(
    sourceChangeSections.map(({ path }) => path).sort(),
    bundle.reviewedPaths,
  );
  assert.equal(
    sourceChangeSections.length,
    bundle.reviewedPaths.length,
  );
  const utf8AddedIndex = material.sections.findIndex(
    ({ kind, path }) =>
      kind === "SOURCE" && path === fixtureChangedSourcePath,
  );
  assert.notEqual(utf8AddedIndex, -1);
  assert.equal(
    parsed.sectionBytes[utf8AddedIndex].toString("utf8"),
    "deterministic source change represented by the exact Git patch\n",
  );
  const binaryAddedIndex = material.sections.findIndex(
    ({ kind, path }) =>
      kind === "PATCH" && path === fixtureBinarySourcePath,
  );
  assert.notEqual(binaryAddedIndex, -1);
  assert.match(
    parsed.sectionBytes[binaryAddedIndex].toString("utf8"),
    new RegExp(fixtureBinarySourcePath.replaceAll(".", "\\."), "u"),
  );
  assert.equal(
    material.sections.some(
      ({ kind, path }) =>
        kind === "PATCH" && path === "artifacts/source.diff",
    ),
    false,
  );
  const sectionKindsByPath = new Map();
  for (const { kind, path } of material.sections) {
    const kinds = sectionKindsByPath.get(path) ?? new Set();
    kinds.add(kind);
    sectionKindsByPath.set(path, kinds);
  }
  for (const path of bundle.reviewedPaths) {
    const kinds = sectionKindsByPath.get(path);
    assert.equal(
      [...kinds].filter((kind) => kind === "SOURCE" || kind === "PATCH")
        .length,
      1,
    );
    assert.equal(kinds.has("GOVERNANCE"), false);
    assert.equal(kinds.has("SPECIFICATION"), false);
  }
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

recursiveCollectorTest("the cumulative K3 candidate uses the additive v3 byte-defense budget", async (t) => {
  const v5Absent = Array(6).fill(false);
  const v5Present = Array(6).fill(true);
  const v6Absent = Array(4).fill(false);
  const v6Present = Array(4).fill(true);
  const v7Absent = Array(5).fill(false);
  const v7Present = Array(5).fill(true);
  assert.equal(
    classifyKimiK3V5ContractPresence({
      v4Presence: [true, true, true],
      v5AdditivePresence: v5Absent,
    }),
    "K3_V4_COMPLETE",
  );
  assert.equal(
    classifyKimiK3V5ContractPresence({
      v4Presence: [true, true, true],
      v5AdditivePresence: v5Present,
    }),
    "K3_V5_COMPLETE",
  );
  assert.equal(
    classifyKimiK3V5ContractPresence({
      v4Presence: [true, false, true],
      v5AdditivePresence: v5Absent,
    }),
    "K3_V4_INCOMPLETE",
  );
  assert.equal(
    classifyKimiK3V5ContractPresence({
      v4Presence: [true, true, true],
      v5AdditivePresence: [true, true, true, true, true, false],
    }),
    "K3_V5_INCOMPLETE",
  );
  assert.equal(
    classifyKimiK3V5ContractPresence({
      v4Presence: [true, false, true],
      v5AdditivePresence: v5Present,
    }),
    "K3_V5_INCOMPLETE",
  );
  for (let missingIndex = 0; missingIndex < v5Present.length; missingIndex += 1) {
    const incomplete = [...v5Present];
    incomplete[missingIndex] = false;
    assert.equal(
      classifyKimiK3V5ContractPresence({
        v4Presence: [true, true, true],
        v5AdditivePresence: incomplete,
      }),
      "K3_V5_INCOMPLETE",
    );
  }
  assert.equal(
    classifyKimiK3V6ContractPresence({
      v4Presence: [true, true, true, true, true],
      v5AdditivePresence: v5Present,
      v6AdditivePresence: v6Absent,
    }),
    "K3_V5_COMPLETE",
  );
  assert.equal(
    classifyKimiK3V6ContractPresence({
      v4Presence: [true, true, true, true, true],
      v5AdditivePresence: v5Present,
      v6AdditivePresence: v6Present,
    }),
    "K3_V6_COMPLETE",
  );
  const incompleteV6 = [...v6Present];
  incompleteV6[2] = false;
  assert.equal(
    classifyKimiK3V6ContractPresence({
      v4Presence: [true, true, true, true, true],
      v5AdditivePresence: v5Present,
      v6AdditivePresence: incompleteV6,
    }),
    "K3_V6_INCOMPLETE",
  );
  assert.equal(
    classifyKimiK3V7ContractPresence({
      v4Presence: [true, true, true, true, true],
      v5AdditivePresence: v5Present,
      v6AdditivePresence: v6Present,
      v7AdditivePresence: v7Absent,
    }),
    "K3_V6_COMPLETE",
  );
  assert.equal(
    classifyKimiK3V7ContractPresence({
      v4Presence: [true, true, true, true, true],
      v5AdditivePresence: v5Present,
      v6AdditivePresence: v6Present,
      v7AdditivePresence: v7Present,
    }),
    "K3_V7_COMPLETE",
  );
  for (let missingIndex = 0; missingIndex < v7Present.length; missingIndex += 1) {
    const incomplete = [...v7Present];
    incomplete[missingIndex] = false;
    assert.equal(
      classifyKimiK3V7ContractPresence({
        v4Presence: [true, true, true, true, true],
        v5AdditivePresence: v5Present,
        v6AdditivePresence: v6Present,
        v7AdditivePresence: incomplete,
      }),
      "K3_V7_INCOMPLETE",
    );
  }
  const historicalFixture = await fixtureRepository(t, {
    includeK3V2: true,
  });
  const historicalBundle = await bundleFor(historicalFixture);
  const historicalBundleBytes = Buffer.from(
    JSON.stringify(historicalBundle),
    "utf8",
  );
  await assert.rejects(
    buildIndependentReviewMaterialFromGit({
      repoPath: historicalFixture.repo,
      reviewBundleBytes: historicalBundleBytes,
      testEvidenceRoot: historicalFixture.evidenceRoot,
      materialId: "irm_kimi_k3_v2_historical_fixture",
    }),
    (error) =>
      error?.reasonCodes?.includes(
        "KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_EXCEEDED",
      ) && error?.contextBudgetUtf8Bytes === 1024 * 1024,
    "historical K3 v2 must retain its original 1 MiB fail-closed budget",
  );

  const fixture = await fixtureRepository(t, {
    includeCumulativeHead: true,
  });
  const bundle = await bundleFor(fixture);
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");

  const { material, materialBytes } =
    await buildIndependentReviewMaterialFromGit({
      repoPath: fixture.repo,
      reviewBundleBytes,
      testEvidenceRoot: fixture.evidenceRoot,
      materialId: "irm_kimi_cumulative_budget_fixture",
    });
  assert.equal(material.schemaVersion, "independent-review-material.v4");
  assert.equal(
    material.source.baseCommit,
    kimiIndependentReviewFixedBaseCommit,
  );
  assert.equal(material.source.sourceCommit, fixture.sourceCommit);
  assert.equal(material.source.sourceTree, fixture.sourceTree);
  assert.equal(bundle.source.sourceCommit, fixture.sourceCommit);
  assert.equal(bundle.source.tree, fixture.sourceTree);
  const diagnosticV2Path =
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v2.schema.json";
  const diagnosticV3Paths = [
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v3.schema.json",
    "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v3.schema.json",
  ];
  const diagnosticV4Path =
    "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v4.schema.json";
  const providerTransportSchemaPath =
    "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json";
  assert.equal(bundle.reviewedPaths.includes(diagnosticV2Path), true);
  assert.equal(
    bundle.sourceSubjects.filter(({ path }) => path === diagnosticV2Path)
      .length,
    1,
  );
  for (const diagnosticV3Path of diagnosticV3Paths) {
    assert.equal(bundle.reviewedPaths.includes(diagnosticV3Path), true);
    assert.equal(
      bundle.sourceSubjects.filter(({ path }) => path === diagnosticV3Path)
        .length,
      1,
    );
  }
  assert.equal(bundle.reviewedPaths.includes(diagnosticV4Path), true);
  assert.equal(
    bundle.sourceSubjects.filter(({ path }) => path === diagnosticV4Path)
      .length,
    1,
  );
  assert.equal(bundle.reviewedPaths.includes(providerTransportSchemaPath), true);
  assert.equal(
    bundle.sourceSubjects.filter(
      ({ path }) => path === providerTransportSchemaPath,
    ).length,
    1,
  );
  assert.match(fixture.sourceIndexSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.match(fixture.stagedPatchSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(material.contextBudgetUtf8Bytes, 4 * 1024 * 1024);
  assert.equal(
    material.resourceCeilingBasis,
    "TRANSPORT_RESOURCE_CEILING_ONLY_NOT_CONTEXT_PROOF",
  );
  assert.ok(
    materialBytes.byteLength >= 1_108_242,
    "the complete scope accepted by the v3 resource ceiling must include the previously measured 1,108,242-byte Material",
  );
  assert.ok(materialBytes.byteLength <= material.contextBudgetUtf8Bytes);
  t.diagnostic(
    JSON.stringify({
      materialUtf8Bytes: materialBytes.byteLength,
      totalSectionUtf8ByteLength:
        material.totalSectionUtf8ByteLength,
      sectionCount: material.sections.length,
      priorReviewEvidenceReferenceCount:
        material.priorReviewEvidenceReferences.length,
    }),
  );

  const indexPath = kimiK3HistoricalReviewEvidenceContract.indexPath;
  const indexSchemaPath =
    kimiK3HistoricalReviewEvidenceContract.indexSchemaPath;
  const [{ bytes: indexBytes }, { bytes: indexSchemaBytes }] =
    await Promise.all([
      frozenGitPath(fixture.repo, fixture.sourceCommit, indexPath),
      frozenGitPath(fixture.repo, fixture.sourceCommit, indexSchemaPath),
    ]);
  const historicalIndex = JSON.parse(indexBytes.toString("utf8"));
  const indexValidation =
    validateIndependentReviewHistoricalEvidenceIndex({
      index: historicalIndex,
      expected: {
        indexBytesSha256:
          kimiK3HistoricalReviewEvidenceContract.indexBytesSha256,
        actualIndexBytesSha256:
          independentKimiReviewDigests.bytes(indexBytes),
        evidenceOriginCommit:
          kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit,
        evidenceOriginTree:
          kimiK3HistoricalReviewEvidenceContract.evidenceOriginTree,
      },
    });
  assert.deepEqual(indexValidation.reasonCodes, []);
  assert.equal(indexValidation.ok, true);
  assert.equal(
    material.bindings.historicalEvidenceIndex.path,
    indexPath,
  );
  assert.equal(
    material.bindings.historicalEvidenceIndex.byteLength,
    indexBytes.byteLength,
  );
  assert.equal(
    material.bindings.historicalEvidenceIndex.sha256,
    independentKimiReviewDigests.bytes(indexBytes),
  );
  assert.equal(
    material.bindings.historicalEvidenceIndex.indexDigest,
    historicalIndex.indexSha256,
  );
  assert.equal(
    material.bindings.historicalEvidenceIndexSchema.path,
    indexSchemaPath,
  );
  assert.equal(
    material.bindings.historicalEvidenceIndexSchema.byteLength,
    indexSchemaBytes.byteLength,
  );
  assert.equal(
    material.bindings.historicalEvidenceIndexSchema.sha256,
    independentKimiReviewDigests.bytes(indexSchemaBytes),
  );
  assert.deepEqual(
    material.priorReviewEvidenceReferences,
    indexValidation.references,
  );
  assert.deepEqual(
    material.priorReviewEvidenceReferences.map(({ path }) => path),
    kimiK3HistoricalReviewEvidencePaths,
  );
  assert.equal(
    material.priorReviewEvidenceReferenceSetSha256,
    independentKimiReviewDigests.value(
      material.priorReviewEvidenceReferences,
    ),
  );

  const rawReviewedPaths = material.sections
    .filter(
      ({ kind, path }) =>
        (kind === "SOURCE" || kind === "PATCH") &&
        bundle.reviewedPaths.includes(path),
    )
    .map(({ path }) => path);
  const diagnosticV2Sections = material.sections.filter(
    ({ kind, path }) =>
      path === diagnosticV2Path && (kind === "SOURCE" || kind === "PATCH"),
  );
  const diagnosticV2Source = await frozenGitPath(
    fixture.repo,
    fixture.sourceCommit,
    diagnosticV2Path,
  );
  assert.equal(diagnosticV2Sections.length, 1);
  assert.equal(
    diagnosticV2Sections[0].byteLength,
    diagnosticV2Source.bytes.byteLength,
  );
  assert.equal(
    diagnosticV2Sections[0].sha256,
    independentKimiReviewDigests.bytes(diagnosticV2Source.bytes),
  );
  for (const diagnosticV3Path of diagnosticV3Paths) {
    const sections = material.sections.filter(
      ({ kind, path }) =>
        path === diagnosticV3Path &&
        (kind === "SOURCE" || kind === "PATCH"),
    );
    const source = await frozenGitPath(
      fixture.repo,
      fixture.sourceCommit,
      diagnosticV3Path,
    );
    assert.equal(sections.length, 1);
    assert.equal(sections[0].byteLength, source.bytes.byteLength);
    assert.equal(
      sections[0].sha256,
      independentKimiReviewDigests.bytes(source.bytes),
    );
  }
  const providerTransportSchemaSections = material.sections.filter(
    ({ kind, path }) =>
      path === providerTransportSchemaPath &&
      (kind === "SOURCE" || kind === "PATCH"),
  );
  const providerTransportSchemaSource = await frozenGitPath(
    fixture.repo,
    fixture.sourceCommit,
    providerTransportSchemaPath,
  );
  assert.equal(providerTransportSchemaSections.length, 1);
  assert.equal(
    providerTransportSchemaSections[0].byteLength,
    providerTransportSchemaSource.bytes.byteLength,
  );
  assert.equal(
    providerTransportSchemaSections[0].sha256,
    independentKimiReviewDigests.bytes(providerTransportSchemaSource.bytes),
  );
  assert.equal(
    material.priorReviewEvidenceReferences.some(
      ({ path }) => path === providerTransportSchemaPath,
    ),
    false,
  );
  const referencedPaths = material.priorReviewEvidenceReferences.map(
    ({ path }) => path,
  );
  assert.deepEqual(
    rawReviewedPaths.filter((path) => referencedPaths.includes(path)),
    [],
    "historical derived evidence must be referenced, never duplicated as raw model-visible bytes",
  );
  assert.deepEqual(
    [...rawReviewedPaths, ...referencedPaths].sort(),
    [...bundle.reviewedPaths].sort(),
    "raw sections and historical references must cover every reviewed path exactly once",
  );
  assert.equal(
    new Set([...rawReviewedPaths, ...referencedPaths]).size,
    bundle.reviewedPaths.length,
  );

  const historicalBytesByType = new Map();
  for (const expectedEntry of
    kimiK3HistoricalReviewEvidenceContract.entries) {
    const origin = await frozenGitPath(
      fixture.repo,
      kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit,
      expectedEntry.path,
    );
    const current = await frozenGitPath(
      fixture.repo,
      fixture.sourceCommit,
      expectedEntry.path,
    );
    assert.equal(origin.gitMode, "100644");
    assert.equal(current.gitMode, "100644");
    assert.equal(origin.bytes.byteLength, expectedEntry.byteLength);
    assert.equal(
      independentKimiReviewDigests.bytes(origin.bytes),
      expectedEntry.sha256,
    );
    assert.deepEqual(current.bytes, origin.bytes);
    assert.equal(
      materialBytes.includes(origin.bytes),
      false,
      `historical derived bytes must not recur in Material v4: ${expectedEntry.path}`,
    );
    historicalBytesByType.set(expectedEntry.artifactType, origin.bytes);
  }

  const priorMaterialBytes = historicalBytesByType.get("REVIEW_MATERIAL");
  const priorBundleBytes = historicalBytesByType.get("REVIEW_BUNDLE");
  const formalRequest = JSON.parse(
    historicalBytesByType.get("FORMAL_REQUEST").toString("utf8"),
  );
  const tokenEstimateRequest = JSON.parse(
    historicalBytesByType
      .get("TOKEN_ESTIMATE_REQUEST")
      .toString("utf8"),
  );
  const priorMaterial = parseIndependentReviewMaterialEnvelope(
    priorMaterialBytes,
  );
  const priorBundleSectionIndex = priorMaterial.material.sections.findIndex(
    ({ kind }) => kind === "REVIEW_BUNDLE",
  );
  assert.notEqual(priorBundleSectionIndex, -1);
  assert.deepEqual(
    priorMaterial.sectionBytes[priorBundleSectionIndex],
    priorBundleBytes,
  );
  assert.deepEqual(tokenEstimateRequest.messages, formalRequest.messages);
  assert.deepEqual(
    Buffer.from(formalRequest.messages[1].content, "utf8"),
    priorMaterialBytes,
  );

  const historicalOutcome = JSON.parse(
    historicalBytesByType.get("SINGLE_CALL_OUTCOME").toString("utf8"),
  );
  assert.equal(
    historicalOutcome.source.baseCommit,
    "ab95d8a18d80a74631e31d6a060dcf19019b098e",
  );
  assert.equal(historicalOutcome.execution.status, "BLOCKED");
  assert.equal(historicalOutcome.execution.conclusion, "INCONCLUSIVE");
  assert.equal(historicalOutcome.execution.chatCompletionAttemptCount, 0);
  assert.equal(historicalOutcome.execution.receiptArtifact, null);
  assert.equal(
    historicalIndex.baseCommitCorrection.outcomePath,
    historicalEvidenceOutcomePath,
  );
  assert.equal(
    historicalIndex.baseCommitCorrection.recordedBaseCommit,
    historicalOutcome.source.baseCommit,
  );
  assert.equal(
    historicalIndex.baseCommitCorrection.correctedCoverageBaseCommit,
    kimiIndependentReviewFixedBaseCommit,
  );
  assert.equal(
    historicalIndex.baseCommitCorrection.historicalArtifactMutated,
    false,
  );
  assert.equal(
    historicalIndex.baseCommitCorrection.confersClearStatus,
    false,
  );
  assert.equal(historicalIndex.baseCommitCorrection.governanceEffect, "NONE");
  assert.equal(historicalIndex.priorReview.conclusion, "INCONCLUSIVE");
  assert.equal(historicalIndex.priorReview.clearReceiptExists, false);
  assert.deepEqual(historicalIndex.governanceBoundary, {
    historicalConclusion: "INCONCLUSIVE",
    clearReceiptExists: false,
    coverageBaseAdvanced: false,
    rawEvidencePreserved: true,
    governanceEffect: "NONE",
  });

  const materialExpected = {
    source: material.source,
    bindings: material.bindings,
    sectionDescriptors: material.sections,
    priorReviewEvidenceReferences:
      material.priorReviewEvidenceReferences,
    bundle,
    contextBudgetUtf8Bytes: material.contextBudgetUtf8Bytes,
    resourceCeilingBasis: material.resourceCeilingBasis,
  };
  const materialValidation = await validateIndependentReviewMaterial({
    material,
    rawMaterialBytes: materialBytes,
    expected: materialExpected,
  });
  assert.deepEqual(materialValidation.reasonCodes, []);
  assert.equal(materialValidation.ok, true);

  const overResourceCeilingValidation =
    await validateIndependentReviewMaterial({
      material,
      rawMaterialBytes: Buffer.alloc(4 * 1024 * 1024 + 1, 0x20),
      expected: materialExpected,
    });
  assert.equal(overResourceCeilingValidation.ok, false);
  assert.ok(
    overResourceCeilingValidation.reasonCodes.includes(
      "KIMI_REVIEW_MATERIAL_RESOURCE_CEILING_EXCEEDED",
    ),
  );

  const rawReferenceOverlap = structuredClone(material);
  rawReferenceOverlap.sections.push({
    kind: "SOURCE",
    path: referencedPaths[0],
    encoding: "UTF-8",
    byteLength: 2,
    sha256: independentKimiReviewDigests.bytes(
      Buffer.from("{}", "utf8"),
    ),
  });
  rawReferenceOverlap.sections.sort((left, right) =>
    Buffer.compare(
      Buffer.from(`${left.kind}:${left.path}`, "utf8"),
      Buffer.from(`${right.kind}:${right.path}`, "utf8"),
    ),
  );
  rawReferenceOverlap.sectionSetSha256 =
    independentKimiReviewDigests.value(rawReferenceOverlap.sections);
  rawReferenceOverlap.materialSha256 =
    independentKimiReviewDigests.material(rawReferenceOverlap);
  const overlapValidation = await validateIndependentReviewMaterial({
    material: rawReferenceOverlap,
    rawMaterialBytes: materialBytes,
    expected: materialExpected,
  });
  assert.equal(overlapValidation.ok, false);
  assert.ok(
    overlapValidation.reasonCodes.includes(
      "KIMI_REVIEW_MATERIAL_HISTORICAL_EVIDENCE_RAW_DUPLICATED",
    ),
  );

  const materialReferenceAttacks = [
    (value) => value.priorReviewEvidenceReferences.pop(),
    (value) => {
      value.priorReviewEvidenceReferences[0] = structuredClone(
        value.priorReviewEvidenceReferences[1],
      );
    },
    (value) => {
      value.priorReviewEvidenceReferences[0].path =
        "lib/masquerading-review-evidence.json";
    },
    (value) => {
      value.priorReviewEvidenceReferences[0].evidenceOriginCommit =
        "1".repeat(40);
    },
    (value) => {
      value.priorReviewEvidenceReferences[0].byteLength += 1;
    },
    (value) => {
      value.priorReviewEvidenceReferences[0].indexEntrySha256 = digest("d");
    },
    (value) => {
      value.bindings.historicalEvidenceIndex.path =
        "implementation/governance/independent-review/evidence/unknown.json";
    },
  ];
  for (const mutate of materialReferenceAttacks) {
    const attacked = structuredClone(material);
    mutate(attacked);
    attacked.priorReviewEvidenceReferenceSetSha256 =
      independentKimiReviewDigests.value(
        attacked.priorReviewEvidenceReferences,
      );
    attacked.materialSha256 = independentKimiReviewDigests.material(attacked);
    const result = await validateIndependentReviewMaterial({
      material: attacked,
      rawMaterialBytes: materialBytes,
      expected: materialExpected,
    });
    assert.equal(result.ok, false);
    assert.ok(
      result.reasonCodes.includes(
        "KIMI_REVIEW_MATERIAL_HISTORICAL_EVIDENCE_REFERENCE_INVALID",
      ),
    );
  }

  const historicalIndexAttacks = [
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_INDEX_INVALID",
      mutate: (value) => {
        value.entries[0].path =
          "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/unknown.json";
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_ENTRY_INVALID",
      mutate: (value) => {
        value.entries[0].path = "lib/masquerading-review-evidence.json";
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_ENTRY_INVALID",
      mutate: (value) => {
        value.entries[0].gitMode = "120000";
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_ENTRY_INVALID",
      mutate: (value) => {
        value.entries[0].gitMode = "100755";
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_ENTRY_INVALID",
      mutate: (value) => {
        value.entries[0].byteLength += 1;
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_ENTRY_INVALID",
      mutate: (value) => {
        value.entries[0].sha256 = digest("f");
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_LINEAGE_INVALID",
      mutate: (value) => {
        value.entries[0].derivedFrom = [
          {
            path: value.entries[0].path,
            relationship: "BINDS_ARTIFACT_BYTES",
            sha256: value.entries[0].sha256,
          },
        ];
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_INDEX_INVALID",
      mutate: (value) => {
        value.evidenceOrigin.commit = "1".repeat(40);
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_INDEX_INVALID",
      mutate: (value) => {
        value.evidenceOrigin.tree = "2".repeat(40);
      },
    },
    {
      expectedReason:
        "KIMI_REVIEW_HISTORICAL_EVIDENCE_OUTCOME_CORRECTION_INVALID",
      mutate: (value) => {
        value.baseCommitCorrection.correctedCoverageBaseCommit =
          fixture.sourceCommit;
      },
    },
    {
      expectedReason:
        "KIMI_REVIEW_HISTORICAL_EVIDENCE_OUTCOME_CORRECTION_INVALID",
      mutate: (value) => {
        value.baseCommitCorrection.confersClearStatus = true;
        value.governanceBoundary.coverageBaseAdvanced = true;
      },
    },
    {
      expectedReason:
        "KIMI_REVIEW_HISTORICAL_EVIDENCE_OUTCOME_CORRECTION_INVALID",
      mutate: (value) => {
        value.priorReview.conclusion = "CLEAR";
        value.priorReview.clearReceiptExists = true;
      },
    },
    {
      expectedReason:
        "KIMI_REVIEW_HISTORICAL_EVIDENCE_INDEX_BYTES_MISMATCH",
      bindChangedBytes: true,
      mutate: (value) => {
        value.reviewId = "imrr_kimi_k3_20260731_attempt_002";
      },
    },
    {
      expectedReason: "KIMI_REVIEW_HISTORICAL_EVIDENCE_DIGEST_MISMATCH",
      rehash: false,
      mutate: (value) => {
        value.indexSha256 = digest("e");
      },
    },
  ];
  for (const attack of historicalIndexAttacks) {
    const attacked = structuredClone(historicalIndex);
    attack.mutate(attacked);
    if (attack.rehash !== false) rehashHistoricalEvidenceIndex(attacked);
    const result = validateIndependentReviewHistoricalEvidenceIndex({
      index: attacked,
      expected: {
        indexBytesSha256:
          kimiK3HistoricalReviewEvidenceContract.indexBytesSha256,
        actualIndexBytesSha256:
          attack.bindChangedBytes === true
            ? independentKimiReviewDigests.bytes(
                Buffer.from(JSON.stringify(attacked), "utf8"),
              )
            : independentKimiReviewDigests.bytes(indexBytes),
        evidenceOriginCommit:
          kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit,
        evidenceOriginTree:
          kimiK3HistoricalReviewEvidenceContract.evidenceOriginTree,
      },
    });
    assert.equal(result.ok, false);
    assert.ok(result.reasonCodes.includes(attack.expectedReason));
  }

  const outputParent = await mkdtemp(
    join(tmpdir(), "zb-kimi-k3-diagnostic-output-"),
  );
  t.after(() => rm(outputParent, { recursive: true, force: true }));
  const outputDir = join(outputParent, "review");
  const responseBytes = Buffer.from(
    JSON.stringify({ error: { code: "service_unavailable" } }),
    "utf8",
  );
  let tokenEstimateCalls = 0;
  let chatCompletionCalls = 0;
  const runnerResult = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    outputDir,
    reviewId: "imrr_kimi_k3_diagnostic_persistence_fixture",
    apiKey: runtimeApiKeyFixture(),
    verifyRuntimeClosure: async () => true,
    dispatcherFactory: () => ({
      dispatch() {},
      async close() {
        throw new Error("synthetic post-response cleanup failure");
      },
    }),
    fetchImpl: async (url) => {
      if (
        url ===
        "https://api.moonshot.ai/v1/tokenizers/estimate-token-count"
      ) {
        tokenEstimateCalls += 1;
        return {
          status: 503,
          redirected: false,
          url,
          headers: new Headers({
            "content-type": "application/json; charset=utf-8",
          }),
          body: new ReadableStream({
            start(controller) {
              controller.enqueue(responseBytes.subarray(0, 7));
              controller.enqueue(responseBytes.subarray(7));
              controller.close();
            },
          }),
        };
      }
      chatCompletionCalls += 1;
      throw new Error("K3 Chat must not run after Token Estimate failure.");
    },
  });
  assert.equal(runnerResult.ok, false);
  assert.equal(runnerResult.status, "BLOCKED");
  assert.deepEqual(runnerResult.reasonCodes, [
    "KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED",
  ]);
  assert.equal(runnerResult.networkAttemptCount, 1);
  assert.equal(runnerResult.tokenEstimateAttemptCount, 1);
  assert.equal(runnerResult.chatCompletionAttemptCount, 0);
  assert.equal(tokenEstimateCalls, 1);
  assert.equal(chatCompletionCalls, 0);
  assert.deepEqual(runnerResult.transportReasonCodes, [
    "KIMI_K3_RESPONSE_HTTP_INVALID",
  ]);

  const diagnosticBytes = await readFile(
    join(outputDir, "token-estimate-diagnostic-evidence.json"),
  );
  const diagnostic = JSON.parse(diagnosticBytes.toString("utf8"));
  assert.deepEqual(
    diagnosticBytes,
    Buffer.from(JSON.stringify(diagnostic), "utf8"),
  );
  const persistedResponseBytes = await readFile(
    join(outputDir, "token-estimate-diagnostic-response.bin"),
  );
  assert.deepEqual(persistedResponseBytes, responseBytes);
  assert.equal(
    diagnostic.schemaVersion,
    "moonshot-kimi-k3-token-estimate-diagnostic-evidence.v3",
  );
  assert.equal(diagnostic.httpStatus, 503);
  assert.equal(diagnostic.jsonParsed, true);
  assert.equal(diagnostic.schemaValidated, false);
  assert.equal(diagnostic.semanticValidated, false);
  assert.equal(diagnostic.failureStage, "HTTP_STATUS");
  assert.equal(diagnostic.reasonCode, "KIMI_K3_RESPONSE_HTTP_INVALID");
  assert.equal(diagnostic.responseBodyByteLength, responseBytes.byteLength);
  assert.equal(
    diagnostic.responseBodySha256,
    independentKimiReviewDigests.bytes(responseBytes),
  );
  assert.equal(
    diagnostic.responseArtifact,
    "token-estimate-diagnostic-response.bin",
  );
  assert.equal(
    runnerResult.tokenEstimateDiagnosticEvidenceSha256,
    diagnostic.evidenceSha256,
  );
  for (const forbiddenArtifact of [
    "token-estimate-evidence.v2.json",
    "transport-evidence.v3.json",
    "transport-evidence.v4.json",
    "receipt.json",
  ]) {
    await assert.rejects(readFile(join(outputDir, forbiddenArtifact)));
  }

  const successfulEstimateBytes = Buffer.from(
    JSON.stringify({
      code: 0,
      data: { total_tokens: 1_000 },
      scode: "0x0",
      status: true,
    }),
    "utf8",
  );
  const tokenCleanupOutputDir = join(outputParent, "token-cleanup");
  let tokenCleanupNetworkCalls = 0;
  const tokenCleanupResult = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    outputDir: tokenCleanupOutputDir,
    reviewId: "imrr_kimi_k3_token_cleanup_fixture",
    apiKey: runtimeApiKeyFixture(),
    verifyRuntimeClosure: async () => true,
    dispatcherFactory: () => ({
      dispatch() {},
      async close() {
        throw new Error("synthetic post-response cleanup failure");
      },
    }),
    fetchImpl: async (url) => {
      tokenCleanupNetworkCalls += 1;
      assert.equal(
        url,
        "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
      );
      return {
        status: 200,
        redirected: false,
        url,
        headers: new Headers({ "content-type": "application/json" }),
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(successfulEstimateBytes);
            controller.close();
          },
        }),
      };
    },
  });
  assert.equal(tokenCleanupNetworkCalls, 1);
  assert.equal(tokenCleanupResult.ok, false);
  assert.equal(tokenCleanupResult.status, "BLOCKED");
  assert.equal(tokenCleanupResult.conclusion, "INCONCLUSIVE");
  assert.deepEqual(tokenCleanupResult.reasonCodes, [
    "KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED",
  ]);
  assert.equal(tokenCleanupResult.networkAttemptCount, 1);
  assert.equal(tokenCleanupResult.tokenEstimateAttemptCount, 1);
  assert.equal(tokenCleanupResult.chatCompletionAttemptCount, 0);
  assert.deepEqual(tokenCleanupResult.transportReasonCodes, [
    "KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED",
  ]);
  const tokenCleanupDiagnostic = JSON.parse(
    await readFile(
      join(
        tokenCleanupOutputDir,
        "token-estimate-diagnostic-evidence.json",
      ),
      "utf8",
    ),
  );
  assert.deepEqual(
    await readFile(
      join(
        tokenCleanupOutputDir,
        "token-estimate-diagnostic-evidence.json",
      ),
    ),
    Buffer.from(JSON.stringify(tokenCleanupDiagnostic), "utf8"),
  );
  assert.equal(
    tokenCleanupDiagnostic.schemaVersion,
    "moonshot-kimi-k3-token-estimate-diagnostic-evidence.v3",
  );
  assert.equal(
    tokenCleanupDiagnostic.failureStage,
    "POST_RESPONSE_CLEANUP",
  );
  assert.equal(
    tokenCleanupDiagnostic.reasonCode,
    "KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED",
  );
  assert.deepEqual(
    [
      tokenCleanupDiagnostic.responseReceived,
      tokenCleanupDiagnostic.responseEndpointMatched,
      tokenCleanupDiagnostic.responseBodyComplete,
      tokenCleanupDiagnostic.jsonParsed,
      tokenCleanupDiagnostic.schemaValidated,
      tokenCleanupDiagnostic.semanticValidated,
    ],
    [true, true, true, true, true, true],
  );
  assert.deepEqual(
    await readFile(
      join(
        tokenCleanupOutputDir,
        "token-estimate-diagnostic-response.bin",
      ),
    ),
    successfulEstimateBytes,
  );
  assert.equal(
    tokenCleanupResult.tokenEstimateDiagnosticEvidenceSha256,
    tokenCleanupDiagnostic.evidenceSha256,
  );
  assert.equal(
    tokenCleanupResult.tokenEstimateResponseSha256,
    tokenCleanupDiagnostic.responseBodySha256,
  );
  for (const forbiddenArtifact of [
    "token-estimate-evidence.v2.json",
    "chat-diagnostic-evidence.json",
    "transport-evidence.v3.json",
    "transport-evidence.v4.json",
    "receipt.json",
  ]) {
    await assert.rejects(
      readFile(join(tokenCleanupOutputDir, forbiddenArtifact)),
    );
  }

  const clearContent = JSON.stringify({
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "No blocking finding in the frozen material.",
    findings: [],
    decision: "CLEAR",
  });
  const successfulChatBytes = Buffer.from(
    JSON.stringify({
      id: "chatcmpl_kimi_k3_cleanup_fixture",
      object: "chat.completion",
      created: 1785513600,
      model: "kimi-k3",
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: clearContent },
          finish_reason: "stop",
        },
      ],
      usage: {
        prompt_tokens: 1_000,
        completion_tokens: 100,
        total_tokens: 1_100,
        cached_tokens: 0,
      },
    }),
    "utf8",
  );
  const chatCleanupOutputDir = join(outputParent, "chat-cleanup");
  let chatCleanupNetworkCalls = 0;
  let dispatcherCount = 0;
  const chatCleanupResult = await runKimiIndependentReviewTestHarness({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    outputDir: chatCleanupOutputDir,
    reviewId: "imrr_kimi_k3_chat_cleanup_fixture",
    apiKey: runtimeApiKeyFixture(),
    verifyRuntimeClosure: async () => true,
    dispatcherFactory: () => {
      dispatcherCount += 1;
      const current = dispatcherCount;
      return {
        dispatch() {},
        async close() {
          if (current === 2) {
            throw new Error("synthetic post-response cleanup failure");
          }
        },
      };
    },
    fetchImpl: async (url) => {
      chatCleanupNetworkCalls += 1;
      const responseBody = url.endsWith("estimate-token-count")
        ? successfulEstimateBytes
        : successfulChatBytes;
      return {
        status: 200,
        redirected: false,
        url,
        headers: new Headers({ "content-type": "application/json" }),
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(responseBody);
            controller.close();
          },
        }),
      };
    },
  });
  assert.equal(chatCleanupNetworkCalls, 2);
  assert.equal(chatCleanupResult.ok, false);
  assert.equal(chatCleanupResult.status, "BLOCKED");
  assert.equal(chatCleanupResult.conclusion, "INCONCLUSIVE");
  assert.deepEqual(chatCleanupResult.reasonCodes, [
    "KIMI_K3_REVIEW_NOT_PROVED",
  ]);
  assert.equal(dispatcherCount, 2);
  assert.equal(chatCleanupResult.networkAttemptCount, 2);
  assert.equal(chatCleanupResult.tokenEstimateAttemptCount, 1);
  assert.equal(chatCleanupResult.chatCompletionAttemptCount, 1);
  assert.deepEqual(chatCleanupResult.transportReasonCodes, [
    "KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED",
  ]);
  const chatCleanupDiagnostic = JSON.parse(
    await readFile(
      join(chatCleanupOutputDir, "chat-diagnostic-evidence.json"),
      "utf8",
    ),
  );
  assert.deepEqual(
    await readFile(
      join(chatCleanupOutputDir, "chat-diagnostic-evidence.json"),
    ),
    Buffer.from(JSON.stringify(chatCleanupDiagnostic), "utf8"),
  );
  assert.equal(
    chatCleanupDiagnostic.schemaVersion,
    "moonshot-kimi-k3-chat-diagnostic-evidence.v4",
  );
  assert.equal(
    chatCleanupDiagnostic.failureStage,
    "POST_RESPONSE_CLEANUP",
  );
  assert.deepEqual(chatCleanupDiagnostic.reasonCodes, [
    "KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED",
  ]);
  assert.deepEqual(
    [
      chatCleanupDiagnostic.responseReceived,
      chatCleanupDiagnostic.responseEndpointMatched,
      chatCleanupDiagnostic.responseBodyComplete,
      chatCleanupDiagnostic.jsonParsed,
      chatCleanupDiagnostic.protocolValidated,
      chatCleanupDiagnostic.outputSchemaValidated,
      chatCleanupDiagnostic.semanticValidated,
    ],
    [true, true, true, true, true, true, true],
  );
  assert.deepEqual(
    await readFile(
      join(chatCleanupOutputDir, "chat-diagnostic-response.bin"),
    ),
    successfulChatBytes,
  );
  assert.equal(
    chatCleanupResult.chatDiagnosticEvidenceSha256,
    chatCleanupDiagnostic.evidenceSha256,
  );
  assert.equal(
    chatCleanupResult.chatDiagnosticResponseSha256,
    chatCleanupDiagnostic.responseBodySha256,
  );
  assert.equal(
    chatCleanupResult.chatDiagnosticResponseByteLength,
    successfulChatBytes.byteLength,
  );
  for (const forbiddenArtifact of [
    "transport-evidence.v3.json",
    "transport-evidence.v4.json",
    "receipt.json",
  ]) {
    await assert.rejects(
      readFile(join(chatCleanupOutputDir, forbiddenArtifact)),
    );
  }
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

  const wrongBaseBundle = structuredClone(bundle);
  wrongBaseBundle.source.baseCommit = fixture.sourceCommit;
  await assert.rejects(
    buildIndependentReviewMaterialFromGit({
      repoPath: fixture.repo,
      reviewBundleBytes: Buffer.from(
        JSON.stringify(wrongBaseBundle),
        "utf8",
      ),
      testEvidenceRoot: fixture.evidenceRoot,
      materialId: "irm_kimi_wrong_base_fixture",
    }),
    /baseCommit is not the frozen Kimi review base/u,
  );

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
    "material.v2.utf8",
    "transport-evidence.json",
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
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: fixture.repo,
    reviewBundleBytes,
    testEvidenceRoot: fixture.evidenceRoot,
    materialId: "irm_kimi_material_fixture",
  });
  const forgedBundle = structuredClone(bundle);
  forgedBundle.testEvidenceSubjects[0].command =
    "NODE -e process.stdout.write('forged pass')";
  const forgedBundleBytes = await rehashBundle(forgedBundle);
  const forgedMaterialBytes = await rebindMaterialToBundle(
    materialBytes,
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
      kimiIndependentReviewFixedBaseCommit,
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
    baseCommit: kimiIndependentReviewFixedBaseCommit,
    sourceCommit,
    sourceTree,
    patchBytes: Buffer.from(patchBytes),
    runnerGitBlobSha256:
      originalBundle.artifacts.bundleGeneratorSha256,
    runnerExecutedBytesSha256:
      originalBundle.artifacts.bundleGeneratorSha256,
  });
  forgedBundle.source = {
    baseCommit: kimiIndependentReviewFixedBaseCommit,
    sourceCommit,
    headCommit: sourceCommit,
    tree: sourceTree,
    diffSha256:
      independentKimiReviewDigests.bytes(Buffer.from(patchBytes)),
    changedPathsDigest:
      originalBundle.source.changedPathsDigest,
    gitDiffCheck,
  };
  forgedBundle.sourceSubjects = originalBundle.sourceSubjects.map(
    (subject) =>
      subject.path === "fixture-execution-source.txt"
        ? {
            ...subject,
            blobSha256:
              independentKimiReviewDigests.bytes(sourceBytes),
          }
        : subject,
  );
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
    "material.v2.utf8",
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
