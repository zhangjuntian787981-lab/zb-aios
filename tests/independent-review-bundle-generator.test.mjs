import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { sha256ProjectValue } from "../lib/project-control.mjs";
import { buildIndependentReviewBundleFromGit } from "../scripts/build-independent-review-bundle.mjs";

const execFileAsync = promisify(execFile);
const root = new URL("../", import.meta.url);
const digest = (character) => `sha256:${character.repeat(64)}`;
const testPlanPath =
  "implementation/governance/independent-review/independent-review-test-plan.v2.json";
const testCollectorPath =
  "scripts/run-independent-review-test-evidence.mjs";
const runtimeEvidenceSchemaPath =
  "implementation/governance/schemas/independent-model-runtime-evidence.v2.schema.json";
const transportEvidenceSchemaPath =
  "implementation/governance/schemas/independent-review-transport-evidence.v1.schema.json";
const testResultSchemaPath =
  "implementation/governance/schemas/independent-review-test-result.v2.schema.json";
const runtimeEvidenceValidatorPath =
  "lib/independent-review-runtime-evidence.mjs";
const transportEvidenceValidatorPath =
  "lib/independent-review-transport-evidence.mjs";
const runtimeControlPlanePath =
  "scripts/run-independent-review-control-plane.mjs";
const sandboxPolicyTemplatePath =
  "implementation/governance/independent-review/macos-independent-review-readonly.sb.in";

const candidatePaths = [
  "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
  "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  testPlanPath,
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  "implementation/governance/schemas/independent-model-review-receipt.v2.schema.json",
  "implementation/governance/schemas/independent-review-bundle.v2.schema.json",
  "implementation/governance/schemas/independent-review-policy.v2.schema.json",
  runtimeEvidenceSchemaPath,
  transportEvidenceSchemaPath,
  testResultSchemaPath,
  "lib/independent-model-review.mjs",
  runtimeEvidenceValidatorPath,
  transportEvidenceValidatorPath,
  "scripts/build-independent-review-bundle.mjs",
  testCollectorPath,
  runtimeControlPlanePath,
  sandboxPolicyTemplatePath,
  "tests/independent-model-review.test.mjs",
  "tests/independent-review-bundle-generator.test.mjs",
  "tests/independent-review-control-plane.test.mjs",
  "tests/independent-review-transport-evidence.test.mjs",
];

async function git(repo, args, options = {}) {
  return execFileAsync("/usr/bin/git", ["-C", repo, ...args], {
    encoding: options.encoding ?? "utf8",
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
    },
  });
}

async function write(repo, path, value) {
  const target = join(repo, path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, value);
}

async function copyCandidate(repo, path) {
  const target = join(repo, path);
  await mkdir(dirname(target), { recursive: true });
  await cp(new URL(path, root), target);
}

async function writeFixtureTestPlan(repo) {
  const unsignedPlan = {
    schemaVersion: "independent-review-test-plan.v2",
    planId: "fixture-independent-review-plan",
    commands: [
      {
        commandId: "fixture-tests",
        executable: "NODE",
        args: [
          "-e",
          "const fs=require('fs');const value=fs.readFileSync('fixture-execution-source.txt','utf8');if(value!=='frozen execution source\\n')process.exit(7);process.stdout.write('fixture test evidence from frozen plan\\n')",
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
  return plan;
}

async function fixtureRepository(t) {
  const repo = await mkdtemp(join(tmpdir(), "zb-independent-review-"));
  t.after(() => rm(repo, { recursive: true, force: true }));
  await git(repo, ["init", "-q"]);
  await git(repo, ["config", "user.name", "Independent Review Test"]);
  await git(repo, ["config", "user.email", "review-test@example.invalid"]);
  for (const path of [
    "AGENTS.md",
    "CONTEXT.md",
    "docs/agents/issue-tracker.md",
    "docs/adr/0008-c13-protected-source-review.md",
  ]) {
    await write(repo, path, `frozen specification: ${path}\n`);
  }
  await write(repo, "fixture-execution-source.txt", "frozen execution source\n");
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-q", "-m", "base"]);
  const { stdout: baseStdout } = await git(repo, ["rev-parse", "HEAD"]);
  const baseCommit = baseStdout.trim();
  for (const path of candidatePaths) {
    await copyCandidate(repo, path);
  }
  const testPlan = await writeFixtureTestPlan(repo);
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-q", "-m", "candidate"]);
  const { stdout: sourceStdout } = await git(repo, ["rev-parse", "HEAD"]);
  const sourceCommit = sourceStdout.trim();
  const evidenceRoot = join(repo, ".bundle-evidence");
  return {
    repo,
    baseCommit,
    sourceCommit,
    evidenceRoot,
    testPlan,
  };
}

function buildInput(fixture) {
  return {
    repoPath: fixture.repo,
    baseCommit: fixture.baseCommit,
    sourceCommit: fixture.sourceCommit,
    generatedAt: "2026-07-30T11:00:00.000Z",
    bundleId: "imrb_git_fixture_20260730",
    applicablePhase: "P1",
    testEvidenceRoot: fixture.evidenceRoot,
    implementationIdentity: {
      provider: "openai",
      modelId: "gpt-5.6-sol",
      modelVersion: "gpt-5.6-sol",
      participantManifestSha256: digest("b"),
      sessionIdSha256: digest("c"),
    },
  };
}

test("Git Bundle generator binds the exact parent, source commit, tree, diff, and all changed paths", async (t) => {
  const fixture = await fixtureRepository(t);
  const bundle = await buildIndependentReviewBundleFromGit(buildInput(fixture));
  assert.equal(bundle.source.baseCommit, fixture.baseCommit);
  assert.equal(bundle.source.sourceCommit, fixture.sourceCommit);
  assert.equal(bundle.source.headCommit, fixture.sourceCommit);
  assert.match(bundle.source.tree, /^[a-f0-9]{40}$/u);
  assert.match(bundle.source.diffSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.match(bundle.source.changedPathsDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(bundle.reviewedPaths, [...candidatePaths].sort());
  assert.deepEqual(
    bundle.sourceSubjects.map((subject) => subject.path),
    bundle.reviewedPaths,
  );
  assert.ok(
    bundle.specificationSubjects.some(
      ({ path }) =>
        path ===
        "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
    ),
  );
  assert.equal(bundle.artifacts.testPlanPath, testPlanPath);
  const frozenTestPlanBytes = await readFile(join(fixture.repo, testPlanPath));
  assert.equal(
    bundle.artifacts.testPlanSha256,
    `sha256:${createHash("sha256").update(frozenTestPlanBytes).digest("hex")}`,
  );
  assert.equal(bundle.artifacts.testEvidenceCollectorPath, testCollectorPath);
  assert.equal(
    bundle.artifacts.runtimeEvidenceSchemaPath,
    runtimeEvidenceSchemaPath,
  );
  assert.equal(bundle.artifacts.testResultSchemaPath, testResultSchemaPath);
  assert.equal(
    bundle.artifacts.runtimeEvidenceValidatorPath,
    runtimeEvidenceValidatorPath,
  );
  assert.equal(
    bundle.artifacts.transportEvidenceSchemaPath,
    transportEvidenceSchemaPath,
  );
  assert.equal(
    bundle.artifacts.transportEvidenceValidatorPath,
    transportEvidenceValidatorPath,
  );
  assert.equal(
    bundle.artifacts.runtimeControlPlanePath,
    runtimeControlPlanePath,
  );
  assert.equal(
    bundle.artifacts.sandboxPolicyTemplatePath,
    sandboxPolicyTemplatePath,
  );
  assert.equal(
    bundle.testEvidenceSubjects[0].runner,
    "GIT_FROZEN_ISOLATED_CLONE_CONTROL_PLANE",
  );
  assert.equal(bundle.testEvidenceSubjects[0].status, "PASS");
  const testResult = JSON.parse(
    await readFile(
      join(fixture.evidenceRoot, bundle.testEvidenceSubjects[0].outputRef),
      "utf8",
    ),
  );
  assert.equal(testResult.executionSource.mode, "ISOLATED_LOCAL_CLONE");
  assert.equal(testResult.executionSource.before.head, fixture.sourceCommit);
  assert.equal(testResult.executionSource.after.head, fixture.sourceCommit);
  assert.equal(
    testResult.executionSource.before.tree,
    testResult.executionSource.after.tree,
  );
  assert.equal(testResult.executionSource.unchanged, true);
});

test("Dirty working-tree bytes cannot impersonate bytes frozen in sourceCommit", async (t) => {
  const fixture = await fixtureRepository(t);
  const first = await buildIndependentReviewBundleFromGit(buildInput(fixture));
  await write(
    fixture.repo,
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
    "dirty prompt that is not in the commit\n",
  );
  await write(
    fixture.repo,
    "fixture-execution-source.txt",
    "dirty execution source\n",
  );
  const second = await buildIndependentReviewBundleFromGit(buildInput(fixture));
  assert.equal(
    second.artifacts.promptSha256,
    first.artifacts.promptSha256,
  );
  assert.equal(
    second.artifacts.testPlanSha256,
    first.artifacts.testPlanSha256,
  );
  assert.equal(second.source.diffSha256, first.source.diffSha256);
});

test("Nonexistent commits and non-parent bases fail closed", async (t) => {
  const fixture = await fixtureRepository(t);
  await assert.rejects(
    buildIndependentReviewBundleFromGit({
      ...buildInput(fixture),
      sourceCommit: "1".repeat(40),
    }),
    /commit|object/u,
  );
  await assert.rejects(
    buildIndependentReviewBundleFromGit({
      ...buildInput(fixture),
      baseCommit: fixture.sourceCommit,
    }),
    /Changed-path set|ancestor/u,
  );
});

test("Caller-supplied test evidence is rejected before it can replace frozen-plan evidence", async (t) => {
  const fixture = await fixtureRepository(t);
  const forged = buildInput(fixture);
  forged.testEvidence = [
    {
      evidenceId: "caller-forged-pass",
      status: "PASS",
      outputSha256: digest("f"),
    },
  ];
  await assert.rejects(
    buildIndependentReviewBundleFromGit(forged),
    /caller-controlled evidence fields/u,
  );
});

test("A frozen test plan whose self-hash no longer matches fails closed", async (t) => {
  const fixture = await fixtureRepository(t);
  const plan = structuredClone(fixture.testPlan);
  plan.commands[0].args[1] = "process.stdout.write('tampered plan\\n')";
  await write(fixture.repo, testPlanPath, `${JSON.stringify(plan, null, 2)}\n`);
  await git(fixture.repo, ["add", testPlanPath]);
  await git(fixture.repo, ["commit", "-q", "-m", "tamper plan"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);
  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit: stdout.trim() }),
    ),
    /test plan is invalid/u,
  );
});

test("A failing command observed by the frozen collector cannot become PASS evidence", async (t) => {
  const fixture = await fixtureRepository(t);
  const plan = structuredClone(fixture.testPlan);
  plan.commands[0].args[1] = "process.exit(9)";
  delete plan.planSha256;
  plan.planSha256 = await sha256ProjectValue(plan);
  await write(fixture.repo, testPlanPath, `${JSON.stringify(plan, null, 2)}\n`);
  await git(fixture.repo, ["add", testPlanPath]);
  await git(fixture.repo, ["commit", "-q", "-m", "failing frozen test"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);
  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit: stdout.trim() }),
    ),
    /Test evidence is incomplete/u,
  );
});

test("A passing command that mutates its isolated frozen source cannot become PASS evidence", async (t) => {
  const fixture = await fixtureRepository(t);
  const plan = structuredClone(fixture.testPlan);
  plan.commands[0].args[1] =
    "require('fs').writeFileSync('AGENTS.md','mutated by test\\n')";
  delete plan.planSha256;
  plan.planSha256 = await sha256ProjectValue(plan);
  await write(fixture.repo, testPlanPath, `${JSON.stringify(plan, null, 2)}\n`);
  await git(fixture.repo, ["add", testPlanPath]);
  await git(fixture.repo, ["commit", "-q", "-m", "mutating frozen test"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);

  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit: stdout.trim() }),
    ),
    /Test evidence is incomplete/u,
  );
  assert.equal(
    await readFile(join(fixture.repo, "AGENTS.md"), "utf8"),
    "frozen specification: AGENTS.md\n",
  );
});

test("A passing command that creates an untracked file in its isolated frozen source cannot become PASS evidence", async (t) => {
  const fixture = await fixtureRepository(t);
  const plan = structuredClone(fixture.testPlan);
  plan.commands[0].args[1] =
    "require('fs').writeFileSync('untracked-by-test.txt','created by test\\n')";
  delete plan.planSha256;
  plan.planSha256 = await sha256ProjectValue(plan);
  await write(fixture.repo, testPlanPath, `${JSON.stringify(plan, null, 2)}\n`);
  await git(fixture.repo, ["add", testPlanPath]);
  await git(fixture.repo, ["commit", "-q", "-m", "untracked mutating test"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);

  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit: stdout.trim() }),
    ),
    /Test evidence is incomplete/u,
  );
});

test("A frozen collector that differs from the executed collector fails closed", async (t) => {
  const fixture = await fixtureRepository(t);
  await write(
    fixture.repo,
    testCollectorPath,
    "#!/usr/bin/env node\nthrow new Error('forged collector');\n",
  );
  await git(fixture.repo, ["add", testCollectorPath]);
  await git(fixture.repo, ["commit", "-q", "-m", "forge collector"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);
  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit: stdout.trim() }),
    ),
    /collector does not match the frozen sourceCommit collector/u,
  );
});

test("Bundle generator must match its own bytes frozen in sourceCommit", async (t) => {
  const fixture = await fixtureRepository(t);
  await write(
    fixture.repo,
    "scripts/build-independent-review-bundle.mjs",
    "#!/usr/bin/env node\nthrow new Error('forged generator');\n",
  );
  await git(fixture.repo, ["add", "scripts/build-independent-review-bundle.mjs"]);
  await git(fixture.repo, ["commit", "-q", "-m", "forge generator"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);
  const input = buildInput({
    ...fixture,
    sourceCommit: stdout.trim(),
  });
  await assert.rejects(
    buildIndependentReviewBundleFromGit(input),
    /does not match the frozen sourceCommit generator/u,
  );
});

test("The CLI builder is stdout-only and exposes no output-file option", async () => {
  const source = await readFile(
    new URL("../scripts/build-independent-review-bundle.mjs", import.meta.url),
    "utf8",
  );
  assert.equal(source.includes("writeFile("), false);
  assert.equal(source.includes("--output"), false);
  assert.equal(source.includes("test-evidence-json"), false);
  assert.equal(source.includes("journal.append("), false);
});
