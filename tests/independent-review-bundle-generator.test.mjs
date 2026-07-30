import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
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
  "implementation/governance/schemas/independent-review-test-result.v3.schema.json";
const runtimeEvidenceValidatorPath =
  "lib/independent-review-runtime-evidence.mjs";
const transportEvidenceValidatorPath =
  "lib/independent-review-transport-evidence.mjs";
const runtimeControlPlanePath =
  "scripts/run-independent-review-control-plane.mjs";
const sandboxPolicyTemplatePath =
  "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in";
const implementationParticipantManifestPath =
  "implementation/governance/independent-review/implementation-participant.v1.json";

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
  "lib/independent-review-runtime-binding.mjs",
  "lib/p2-start-authorization.mjs",
  "lib/project-control.mjs",
  runtimeEvidenceValidatorPath,
  transportEvidenceValidatorPath,
  "scripts/build-independent-review-bundle.mjs",
  testCollectorPath,
  runtimeControlPlanePath,
  sandboxPolicyTemplatePath,
  implementationParticipantManifestPath,
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
  await write(repo, path, await readFile(new URL(path, root)));
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
  await write(
    repo,
    "readonly-copy-source/nested/file.txt",
    "frozen source copied into bounded output\n",
  );
  await write(repo, "a/x.txt", "nested Git ordering fixture\n");
  await write(repo, "a.ext", "sibling Git ordering fixture\n");
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
  const evidenceRoot = await mkdtemp(
    join(tmpdir(), "zb-independent-review-bundle-evidence-"),
  );
  t.after(() => rm(evidenceRoot, { recursive: true, force: true }));
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
    "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE",
  );
  assert.equal(bundle.testEvidenceSubjects[0].status, "PASS");
  const participantManifestBytes = await readFile(
    join(fixture.repo, implementationParticipantManifestPath),
  );
  assert.equal(
    bundle.implementationIdentity.participantManifestSha256,
    `sha256:${createHash("sha256").update(participantManifestBytes).digest("hex")}`,
  );
  assert.equal(bundle.implementationIdentity.provider, "openai");
  assert.equal(bundle.implementationIdentity.modelId, "gpt-5.6-sol");
  const testResult = JSON.parse(
    await readFile(
      join(fixture.evidenceRoot, bundle.testEvidenceSubjects[0].outputRef),
      "utf8",
    ),
  );
  assert.equal(
    testResult.executionSource.mode,
    "MACOS_SEATBELT_GIT_ARCHIVE_READONLY_HISTORY_V3",
  );
  assert.equal(
    testResult.executionSource.cloneMode,
    "GIT_ARCHIVE_WITH_READ_ONLY_HISTORY_SNAPSHOT",
  );
  assert.equal(testResult.executionSource.before.head, fixture.sourceCommit);
  assert.equal(testResult.executionSource.after.head, fixture.sourceCommit);
  assert.equal(
    testResult.executionSource.before.tree,
    testResult.executionSource.after.tree,
  );
  assert.equal(testResult.executionSource.unchanged, true);
  assert.equal(testResult.executionSource.gitHistory.unchanged, true);
  assert.equal(
    testResult.executionSource.gitHistory.metadataWritable,
    false,
  );
  assert.equal(
    testResult.executionSource.gitHistory.sourceCommit,
    fixture.sourceCommit,
  );
  assert.match(
    testResult.executionSource.gitHistory.reachableObjectSetSha256,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.equal(testResult.executionSource.sourceExportRemoved, true);
  assert.equal(
    testResult.executionSource.sandbox.templatePath,
    sandboxPolicyTemplatePath,
  );
  assert.equal(
    testResult.executionSource.sandbox.templateSha256,
    bundle.artifacts.sandboxPolicyTemplateSha256,
  );
});

test("caller-provided implementation identity cannot replace the frozen participant manifest", async (t) => {
  const fixture = await fixtureRepository(t);
  const input = buildInput(fixture);
  input.implementationIdentity = {
    provider: "moonshot",
    modelId: "kimi-k2.7-code",
    modelVersion: "kimi-k2.7-code",
    participantManifestSha256: digest("f"),
    sessionIdSha256: digest("e"),
  };
  await assert.rejects(
    buildIndependentReviewBundleFromGit(input),
    /caller-controlled|implementation identity|participant manifest/iu,
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

test("Test evidence output cannot overlap the repository or shared dependencies", async (t) => {
  const fixture = await fixtureRepository(t);
  const inRepository = join(fixture.repo, ".bundle-evidence");
  await mkdir(inRepository);
  await assert.rejects(
    buildIndependentReviewBundleFromGit({
      ...buildInput(fixture),
      testEvidenceRoot: inRepository,
    }),
    /evidence root overlaps/iu,
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

test("trusted control plane rejects a frozen patch with whitespace errors", async (t) => {
  const fixture = await fixtureRepository(t);
  await write(
    fixture.repo,
    "fixture-whitespace-error.txt",
    "trailing whitespace is forbidden   \n",
  );
  await git(fixture.repo, ["add", "fixture-whitespace-error.txt"]);
  await git(fixture.repo, ["commit", "-q", "-m", "whitespace error"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);

  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit: stdout.trim() }),
    ),
    /trusted Git diff check/u,
  );
});

test("git archive export-ignore or export-subst cannot change frozen source bytes", async (t) => {
  for (const [attributes, extraPath, extraContent] of [
    ["AGENTS.md export-ignore\n", null, null],
    [
      "fixture-export-subst.txt export-subst\n",
      "fixture-export-subst.txt",
      "$Format:%H$\n",
    ],
  ]) {
    const fixture = await fixtureRepository(t);
    await write(fixture.repo, ".gitattributes", attributes);
    if (extraPath) {
      await write(fixture.repo, extraPath, extraContent);
    }
    await git(fixture.repo, ["add", ".gitattributes"]);
    if (extraPath) await git(fixture.repo, ["add", extraPath]);
    await git(fixture.repo, ["commit", "-q", "-m", "archive transform"]);
    const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);

    await assert.rejects(
      buildIndependentReviewBundleFromGit(
        buildInput({ ...fixture, sourceCommit: stdout.trim() }),
      ),
      /Git archive bytes do not match the frozen source tree/u,
    );
  }
});

test("tracked node_modules cannot bypass source and dependency bindings", async (t) => {
  const fixture = await fixtureRepository(t);
  await write(
    fixture.repo,
    "node_modules/tracked-fixture.txt",
    "must be rejected\n",
  );
  await git(fixture.repo, ["add", "-f", "node_modules/tracked-fixture.txt"]);
  await git(fixture.repo, ["commit", "-q", "-m", "tracked dependency"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);

  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit: stdout.trim() }),
    ),
    /reserved/u,
  );
});

test("the frozen test-result Schema is executed against collected evidence", async (t) => {
  const fixture = await fixtureRepository(t);
  const schema = JSON.parse(
    await readFile(join(fixture.repo, testResultSchemaPath), "utf8"),
  );
  schema.required.push("schemaCanary");
  schema.properties.schemaCanary = { const: "REQUIRED_BY_FROZEN_SCHEMA" };
  await write(
    fixture.repo,
    testResultSchemaPath,
    `${JSON.stringify(schema, null, 2)}\n`,
  );
  await git(fixture.repo, ["add", testResultSchemaPath]);
  await git(fixture.repo, ["commit", "-q", "-m", "require schema canary"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);

  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit: stdout.trim() }),
    ),
    /Test evidence closure is not trusted/u,
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
    /Test evidence (?:is incomplete|closure is not trusted)/u,
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
    /Test evidence (?:is incomplete|closure is not trusted)/u,
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
    /Test evidence (?:is incomplete|closure is not trusted)/u,
  );
});

test("the frozen collector mounts exact read-only Git history, protects source and dependencies, permits bounded outputs and nested tools, and denies all network", async (t) => {
  const fixture = await fixtureRepository(t);
  const outsideReadCanary = join(
    tmpdir(),
    `zb-independent-review-outside-read-${process.pid}-${Date.now()}`,
  );
  await writeFile(outsideReadCanary, "outside read must be denied\n");
  t.after(() => rm(outsideReadCanary, { force: true }));
  const dependencyRoot = join(fixture.repo, "node_modules");
  await mkdir(dependencyRoot);
  await writeFile(
    join(dependencyRoot, "sandbox-sentinel.txt"),
    "dependency remains read-only\n",
  );
  const probeSource = [
    "const fs=require('fs');",
    "const net=require('net');",
    "const path=require('path');",
    "const child=require('child_process');",
    "const denied=new Set(['EACCES','EPERM']);",
    "const mustDeny=(operation,code)=>{try{operation();process.exit(code)}catch(error){if(!denied.has(error.code))process.exit(code+1)}};",
    "if(!fs.statSync('.git').isFile())process.exit(80);",
    "mustDeny(()=>fs.writeFileSync('AGENTS.md','forbidden\\n'),81);",
    "mustDeny(()=>fs.unlinkSync('AGENTS.md'),83);",
    "mustDeny(()=>fs.renameSync('AGENTS.md','dist/moved-source'),85);",
    "mustDeny(()=>fs.chmodSync('AGENTS.md',0o600),87);",
    "mustDeny(()=>fs.linkSync('AGENTS.md','dist/hard-source'),89);",
    "mustDeny(()=>fs.writeFileSync('node_modules/sandbox-sentinel.txt','forbidden\\n'),91);",
    `mustDeny(()=>fs.readFileSync(${JSON.stringify(outsideReadCanary)}),92);`,
    "const keychain=child.spawnSync('/usr/bin/security',['find-generic-password','-s','zb-aios-sandbox-probe-does-not-exist','-w'],{encoding:'utf8'});",
    "if(!keychain.error||!denied.has(keychain.error.code))process.exit(93);",
    "const nested=child.spawnSync(process.execPath,['-e','process.stdout.write(\"nested-ok\")'],{encoding:'utf8'});",
    "if(nested.status!==0||nested.stdout!=='nested-ok')process.exit(94);",
    "const npm=child.spawnSync(path.resolve(path.dirname(process.execPath),'npm'),['--version'],{encoding:'utf8'});",
    "if(npm.status!==0||!/^\\d+\\.\\d+\\.\\d+/.test(npm.stdout))process.exit(95);",
    "const git=child.spawnSync('/usr/bin/git',['--version'],{encoding:'utf8'});",
    "if(git.status!==0||!/^git version /.test(git.stdout))process.exit(97);",
    "const head=child.spawnSync('/usr/bin/git',['rev-parse','HEAD'],{encoding:'utf8'});",
    "if(head.status!==0||!/^[a-f0-9]{40}\\n$/.test(head.stdout)||head.stderr!=='')process.exit(99);",
    "const diff=child.spawnSync('/usr/bin/git',['diff','--check'],{encoding:'utf8'});",
    "if(diff.status!==0||diff.stdout!==''||diff.stderr!=='')process.exit(100);",
    "const gitDir=fs.readFileSync('.git','utf8').trim().replace(/^gitdir: /,'');",
    "mustDeny(()=>fs.writeFileSync(path.join(gitDir,'config'),'forbidden\\n'),101);",
    "const tag=child.spawnSync('/usr/bin/git',['tag','sandbox-write-probe'],{encoding:'utf8'});",
    "if(tag.status===0)process.exit(103);",
    "const shasum=child.spawnSync('/usr/bin/shasum',['-a','256','AGENTS.md'],{encoding:'utf8'});",
    "if(shasum.status!==0||!/^[a-f0-9]{64}  AGENTS\\.md\\n$/.test(shasum.stdout))process.exit(104);",
    "fs.writeFileSync(path.join(process.env.TMPDIR,'allowed.txt'),'allowed\\n');",
    "fs.writeFileSync('dist/allowed.txt','bounded build output\\n');",
    "const copy=child.spawnSync(process.execPath,['-e',\"const fs=require('fs/promises');(async()=>{await fs.cp('readonly-copy-source','dist/copied-source',{recursive:true});await fs.rm('dist/copied-source',{recursive:true,force:true})})().catch(()=>process.exit(1))\"],{encoding:'utf8'});",
    "if(copy.status!==0)process.exit(98);",
    "fs.writeFileSync('node_modules/.vite-temp/allowed.txt','bounded Vite config output\\n');",
    "fs.renameSync('dist/allowed.txt','dist/renamed.txt');",
    "fs.unlinkSync('dist/renamed.txt');",
    "fs.symlinkSync('../AGENTS.md','dist/source-link');",
    "mustDeny(()=>fs.writeFileSync('dist/source-link','forbidden\\n'),96);",
    "const loopback=net.connect({host:'127.0.0.1',port:65534});",
    "loopback.once('connect',()=>process.exit(83));",
    "loopback.once('error',(loopbackError)=>{",
    "  if(!denied.has(loopbackError.code))process.exit(84);",
    "  const external=net.connect({host:'192.0.2.1',port:9});",
    "  external.once('connect',()=>process.exit(85));",
    "  external.once('error',(externalError)=>{",
    "    if(!denied.has(externalError.code))process.exit(86);",
    "    process.stdout.write('sandbox-boundaries-proved\\n');",
    "    process.exit(0);",
    "  });",
    "});",
    "setTimeout(()=>process.exit(87),2000);",
  ].join("");
  const unsignedPlan = {
    schemaVersion: "independent-review-test-plan.v2",
    planId: "fixture-sandbox-enforcement-plan",
    commands: [
      {
        commandId: "sandbox-enforcement",
        executable: "NODE",
        args: ["-e", probeSource],
        timeoutMs: 10000,
      },
    ],
  };
  const plan = {
    ...unsignedPlan,
    planSha256: await sha256ProjectValue(unsignedPlan),
  };
  await write(
    fixture.repo,
    testPlanPath,
    `${JSON.stringify(plan, null, 2)}\n`,
  );
  await git(fixture.repo, ["add", testPlanPath]);
  await git(fixture.repo, ["commit", "-q", "-m", "sandbox probe"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);

  const bundle = await buildIndependentReviewBundleFromGit(
    buildInput({ ...fixture, sourceCommit: stdout.trim() }),
  );
  const result = JSON.parse(
    await readFile(
      join(fixture.evidenceRoot, bundle.testEvidenceSubjects[0].outputRef),
      "utf8",
    ),
  );
  const stdoutBytes = await readFile(
    join(fixture.evidenceRoot, result.stdoutRef),
    "utf8",
  );
  assert.match(stdoutBytes, /sandbox-boundaries-proved/u);
  assert.ok(
    bundle.testEvidenceSubjects[0].toolVersions.includes(
      "isolation=macos-sandbox-exec-git-archive-readonly-history-network-denied",
    ),
  );
  assert.equal(result.executionSource.sandbox.networkPolicy, "DENY_ALL");
  assert.equal(result.executionSource.sandbox.sourceWritable, false);
  assert.equal(result.executionSource.sandbox.buildOutputsWritable, true);
  assert.deepEqual(result.executionSource.sandbox.writableWorkRoots, [
    ".next",
    ".vinext",
    ".wrangler",
    "dist",
    "node_modules/.vite-temp",
  ]);
  assert.match(
    result.runtimeBinding.gitToolchainSha256,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.match(
    result.runtimeBinding.systemToolchainSha256,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.equal(result.executionSource.sandbox.gitMetadataPresent, true);
  assert.equal(result.executionSource.sandbox.gitMetadataWritable, false);
  assert.equal(
    result.executionSource.sandbox.networkDependentTestMode,
    "FROZEN_DETERMINISTIC_OFFLINE_ALTERNATIVES",
  );
  assert.equal(
    bundle.testEvidenceSubjects[0].toolVersions.filter((version) =>
      /^sandbox-template=sha256:[a-f0-9]{64}$/u.test(version),
    ).length,
    1,
  );
  assert.equal(
    bundle.testEvidenceSubjects[0].toolVersions.filter((version) =>
      /^sandbox-invocation=sha256:[a-f0-9]{64}$/u.test(version),
    ).length,
    1,
  );
  assert.equal(
    await readFile(join(fixture.repo, "AGENTS.md"), "utf8"),
    "frozen specification: AGENTS.md\n",
  );
  assert.equal(
    await readFile(
      join(dependencyRoot, "sandbox-sentinel.txt"),
      "utf8",
    ),
    "dependency remains read-only\n",
  );
  await assert.rejects(
    readFile(join(dependencyRoot, ".vite-temp", "allowed.txt")),
    { code: "ENOENT" },
  );
});

test("the frozen collector rejects a transcript containing the active Moonshot credential", async (t) => {
  const fixture = await fixtureRepository(t);
  const marker = `moonshot-fixture-${process.pid}-${Date.now()}`;
  const previous = process.env.MOONSHOT_API_KEY;
  process.env.MOONSHOT_API_KEY = marker;
  t.after(() => {
    if (previous === undefined) delete process.env.MOONSHOT_API_KEY;
    else process.env.MOONSHOT_API_KEY = previous;
  });
  const plan = structuredClone(fixture.testPlan);
  plan.commands[0].args = [
    "-e",
    `process.stdout.write(${JSON.stringify(marker)})`,
  ];
  delete plan.planSha256;
  plan.planSha256 = await sha256ProjectValue(plan);
  await write(fixture.repo, testPlanPath, `${JSON.stringify(plan, null, 2)}\n`);
  await git(fixture.repo, ["add", testPlanPath]);
  await git(fixture.repo, ["commit", "-q", "-m", "credential echo probe"]);
  const { stdout } = await git(fixture.repo, ["rev-parse", "HEAD"]);
  const sourceCommit = stdout.trim();
  const clonePrefix =
    `zb-independent-review-test-export-${sourceCommit}-`;
  const clonesBefore = new Set(
    (await readdir(tmpdir())).filter((name) => name.startsWith(clonePrefix)),
  );

  await assert.rejects(
    buildIndependentReviewBundleFromGit(
      buildInput({ ...fixture, sourceCommit }),
    ),
    /credential/iu,
  );
  const clonesAfter = new Set(
    (await readdir(tmpdir())).filter((name) => name.startsWith(clonePrefix)),
  );
  assert.deepEqual(clonesAfter, clonesBefore);
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
