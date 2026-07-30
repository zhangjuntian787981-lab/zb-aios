import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  cp,
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
import { buildIndependentReviewBundleFromGit } from "../scripts/build-independent-review-bundle.mjs";
import { buildIndependentReviewMaterialFromGit } from "../scripts/build-independent-review-material.mjs";
import { runKimiIndependentReview } from "../scripts/run-kimi-independent-review.mjs";

const execFileAsync = promisify(execFile);
const root = new URL("../", import.meta.url);
const digest = (character) => `sha256:${character.repeat(64)}`;
const testPlanPath =
  "implementation/governance/independent-review/independent-review-test-plan.v2.json";
const basePaths = [
  "package-lock.json",
  "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
  "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  "implementation/governance/independent-review/independent-review-test-plan.v2.json",
  "implementation/governance/independent-review/macos-independent-review-readonly.sb.in",
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  "implementation/governance/schemas/independent-model-review-receipt.v2.schema.json",
  "implementation/governance/schemas/independent-model-runtime-evidence.v2.schema.json",
  "implementation/governance/schemas/independent-review-bundle.v2.schema.json",
  "implementation/governance/schemas/independent-review-policy.v2.schema.json",
  "implementation/governance/schemas/independent-review-test-result.v2.schema.json",
  "implementation/governance/schemas/independent-review-transport-evidence.v1.schema.json",
  "lib/independent-model-review.mjs",
  "lib/independent-review-runtime-evidence.mjs",
  "lib/independent-review-transport-evidence.mjs",
  "scripts/build-independent-review-bundle.mjs",
  "scripts/run-independent-review-control-plane.mjs",
  "scripts/run-independent-review-test-evidence.mjs",
  "tests/independent-model-review.test.mjs",
  "tests/independent-review-bundle-generator.test.mjs",
  "tests/independent-review-control-plane.test.mjs",
  "tests/independent-review-transport-evidence.test.mjs",
];
const candidatePaths = [
  "docs/adr/0012-moonshot-kimi-independent-review-transport.md",
  "implementation/governance/independent-review/moonshot-kimi-k2.7-code.v1.json",
  "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json",
  "implementation/governance/schemas/independent-review-material.v1.schema.json",
  "implementation/governance/schemas/moonshot-kimi-independent-review-config.v1.schema.json",
  "lib/kimi-independent-review.mjs",
  "scripts/build-independent-review-material.mjs",
  "scripts/run-kimi-independent-review.mjs",
  "tests/independent-review-material-generator.test.mjs",
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
      GIT_CONFIG_GLOBAL: "/dev/null",
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
  const target = join(repo, path);
  await mkdir(dirname(target), { recursive: true });
  await cp(new URL(path, root), target);
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
  for (const path of basePaths) {
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
  for (const path of candidatePaths) {
    await copyCandidate(repo, path);
  }
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-q", "-m", "candidate"]);
  const { stdout: sourceText } = await git(repo, ["rev-parse", "HEAD"]);
  return {
    repo,
    baseCommit: baseText.trim(),
    sourceCommit: sourceText.trim(),
    evidenceRoot: join(repo, ".review-evidence"),
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
    implementationIdentity: {
      provider: "openai",
      modelId: "gpt-5.6-sol",
      modelVersion: "gpt-5.6-sol",
      participantManifestSha256: digest("b"),
      sessionIdSha256: digest("c"),
    },
  });
}

test("Review Material re-reads Bundle, diff, source, specifications and test evidence from frozen bytes", async (t) => {
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
        kind === "SOURCE" && path === "lib/kimi-independent-review.mjs",
    ),
  );
  assert.ok(
    material.sections.some(
      ({ kind }) => kind === "TEST_EVIDENCE",
    ),
  );
  assert.ok(materialBytes.byteLength <= material.contextBudgetUtf8Bytes);
});

test("Dirty workspace bytes and tampered Bundle or test evidence cannot impersonate frozen Review Material", async (t) => {
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
    /test evidence bytes drifted/u,
  );
});

test("Kimi runner performs zero network calls without a credential", async (t) => {
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
  const result = await runKimiIndependentReview({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    outputDir: join(outputParent, "review"),
    reviewId: "imrr_kimi_runner_fixture",
    apiKey: "",
    fetchImpl: async () => {
      networkCalls += 1;
      throw new Error("must not be called");
    },
  });
  assert.deepEqual(result, {
    ok: false,
    status: "BLOCKED",
    reasonCodes: ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
    networkAttemptCount: 0,
  });
  assert.equal(networkCalls, 0);
});

test("Kimi runner writes only sanitized exact-byte artifacts outside the unchanged repository", async (t) => {
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
  const result = await runKimiIndependentReview({
    repoPath: fixture.repo,
    reviewBundleBytes,
    reviewMaterialBytes: materialBytes,
    outputDir,
    reviewId: "imrr_kimi_runner_fixture",
    apiKey: runtimeOnlyCredential,
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
        async arrayBuffer() {
          return responseBytes.buffer.slice(
            responseBytes.byteOffset,
            responseBytes.byteOffset + responseBytes.byteLength,
          );
        },
      };
    },
    now: () => times.shift(),
  });
  assert.equal(networkCalls, 1);
  assert.equal(result.ok, true);
  assert.equal(result.status, "CLEAR");
  assert.equal(
    result.conclusion,
    "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  );
  for (const name of [
    "request.json",
    "response.json",
    "content.json",
    "material.json",
    "receipt.json",
  ]) {
    const bytes = await readFile(join(outputDir, name));
    assert.equal(bytes.includes(runtimeOnlyCredential), false);
  }
  const requestArtifact = JSON.parse(
    await readFile(join(outputDir, "request.json"), "utf8"),
  );
  assert.equal(Object.hasOwn(requestArtifact, "headers"), false);
  assert.equal(Object.hasOwn(requestArtifact, "authorization"), false);
  const receipt = JSON.parse(
    await readFile(join(outputDir, "receipt.json"), "utf8"),
  );
  assert.equal(receipt.isolationEvidence.repositoryUnchanged, true);
  assert.equal(receipt.historicalTerraEvidenceAccepted, false);
});

test("Kimi runner freezes valid BLOCKED and INCONCLUSIVE Receipts after one network call", async (t) => {
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
    const result = await runKimiIndependentReview({
      repoPath: fixture.repo,
      reviewBundleBytes,
      reviewMaterialBytes: materialBytes,
      outputDir,
      reviewId: `imrr_kimi_${decision.toLowerCase()}_fixture`,
      apiKey: runtimeOnlyCredential,
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
          async arrayBuffer() {
            return responseBytes.buffer.slice(
              responseBytes.byteOffset,
              responseBytes.byteOffset + responseBytes.byteLength,
            );
          },
        };
      },
      now: () => times.shift(),
    });
    assert.equal(result.ok, false);
    assert.equal(result.status, decision, JSON.stringify(result));
    assert.equal(result.conclusion, decision, JSON.stringify(result));
    assert.deepEqual(result.reasonCodes, []);
    assert.equal(result.networkAttemptCount, 1);
    assert.match(result.receiptSha256, /^sha256:[a-f0-9]{64}$/u);
    const receipt = JSON.parse(
      await readFile(join(outputDir, "receipt.json"), "utf8"),
    );
    assert.equal(receipt.decision, decision);
    assert.equal(receipt.conclusion, decision);
    assert.equal(receipt.receiptSha256, result.receiptSha256);
  }
  assert.equal(networkCalls, 2);
});

test("Kimi runner rejects a symlinked output parent before network or repository writes", async (t) => {
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
    runKimiIndependentReview({
      repoPath: fixture.repo,
      reviewBundleBytes,
      reviewMaterialBytes: materialBytes,
      outputDir: join(linkedRepo, "review"),
      reviewId: "imrr_kimi_symlink_fixture",
      apiKey: "test-only-runtime-credential-0123456789",
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

function randomTokenForTest() {
  return `${process.pid}-${Date.now()}`;
}
