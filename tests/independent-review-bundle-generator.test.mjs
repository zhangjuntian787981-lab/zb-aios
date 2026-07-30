import assert from "node:assert/strict";
import { execFile } from "node:child_process";
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
import { buildIndependentReviewBundleFromGit } from "../scripts/build-independent-review-bundle.mjs";

const execFileAsync = promisify(execFile);
const root = new URL("../", import.meta.url);
const digest = (character) => `sha256:${character.repeat(64)}`;

const candidatePaths = [
  "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  "implementation/governance/schemas/independent-model-review-receipt.v2.schema.json",
  "implementation/governance/schemas/independent-review-bundle.v2.schema.json",
  "implementation/governance/schemas/independent-review-policy.v2.schema.json",
  "lib/independent-model-review.mjs",
  "scripts/build-independent-review-bundle.mjs",
  "tests/independent-model-review.test.mjs",
  "tests/independent-review-bundle-generator.test.mjs",
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
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-q", "-m", "base"]);
  const { stdout: baseStdout } = await git(repo, ["rev-parse", "HEAD"]);
  const baseCommit = baseStdout.trim();
  for (const path of candidatePaths) {
    await copyCandidate(repo, path);
  }
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-q", "-m", "candidate"]);
  const { stdout: sourceStdout } = await git(repo, ["rev-parse", "HEAD"]);
  return {
    repo,
    baseCommit,
    sourceCommit: sourceStdout.trim(),
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
    testEvidence: [
      {
        evidenceId: "fixture-tests",
        command: "node --test tests/independent-model-review.test.mjs",
        status: "PASS",
        exitCode: 0,
        outputRef:
          "implementation/governance/independent-review/reviews/source/test-evidence/fixture.log",
        outputSha256: digest("a"),
        outputByteLength: 256,
        truncated: false,
        sourceCommit: fixture.sourceCommit,
        runner: "LOCAL_TRUSTED_RUNNER",
        toolVersions: ["node=v24.4.1"],
      },
    ],
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
});

test("Dirty working-tree bytes cannot impersonate bytes frozen in sourceCommit", async (t) => {
  const fixture = await fixtureRepository(t);
  const first = await buildIndependentReviewBundleFromGit(buildInput(fixture));
  await write(
    fixture.repo,
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
    "dirty prompt that is not in the commit\n",
  );
  const second = await buildIndependentReviewBundleFromGit(buildInput(fixture));
  assert.equal(
    second.artifacts.promptSha256,
    first.artifacts.promptSha256,
  );
  assert.equal(second.bundleSha256, first.bundleSha256);
});

test("Nonexistent commits, non-parent bases, and stale test evidence fail closed", async (t) => {
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
  const stale = buildInput(fixture);
  stale.testEvidence[0].sourceCommit = fixture.baseCommit;
  await assert.rejects(
    buildIndependentReviewBundleFromGit(stale),
    /not bound to sourceCommit/u,
  );
});

test("The CLI builder is stdout-only and exposes no output-file option", async () => {
  const source = await readFile(
    new URL("../scripts/build-independent-review-bundle.mjs", import.meta.url),
    "utf8",
  );
  assert.equal(source.includes("writeFile("), false);
  assert.equal(source.includes("--output"), false);
  assert.equal(source.includes("journal.append("), false);
});
