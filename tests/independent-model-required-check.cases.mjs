import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildPromptBoundReviewMaterial,
  validateIndependentModelRequiredCheck,
} from "../scripts/validate-independent-model-review-check.mjs";

const root = new URL("../", import.meta.url);
const readText = (path) => readFile(new URL(path, root), "utf8");
const fixturePaths = Object.freeze([
  "implementation/governance/independent-review/independent-review-policy.v2.json",
  "implementation/governance/schemas/independent-review-policy.v2.active.schema.json",
  "implementation/governance/independent-review/evidence/terra-targeted-remediation-ec8315c/targeted-remediation-model-review-evidence.v1.json",
  "implementation/governance/schemas/targeted-remediation-model-review-evidence.v1.schema.json",
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  "implementation/governance/independent-review/github-required-check-prompt.v1.md",
  ".github/workflows/independent-model-review.yml",
  "scripts/validate-independent-model-review-check.mjs",
  "tests/independent-model-required-check.cases.mjs",
  "docs/adr/0023-qwen-independent-model-required-check.md",
  "implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v1.json",
  "implementation/p1/c13/p1-b11-protected-review-preparation-evidence.v1.json",
]);
const clearOutput = Object.freeze({
  schemaVersion: "independent-model-review-output.v2",
  reviewSummary: "The current P0-P2 preproduction review boundary is clear.",
  findings: [],
  decision: "CLEAR",
});
const REQUIRED_CHECK_PROVIDER = "ALIBABA_CLOUD_MODEL_STUDIO";
const REQUIRED_CHECK_REGION = "CHINA_BEIJING";
const REQUIRED_CHECK_MODEL = "qwen3.7-max-2026-05-20";
const REQUIRED_CHECK_BASE_URL =
  "https://ws-lkkcajn7d1l4okvo.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";
const REQUIRED_CHECK_ASSURANCE = "PLATFORM_TCB_PROMPT_BOUND_MODEL_REVIEW";

async function validationFixture() {
  const directory = await mkdtemp(join(tmpdir(), "independent-model-check-"));
  const repository = join(directory, "repository");
  await mkdir(repository);
  for (const path of fixturePaths) {
    const destination = join(repository, path);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(fileURLToPath(new URL(path, root)), destination);
  }
  execFileSync("git", ["init", "-q"], { cwd: repository });
  execFileSync("git", ["add", "--", "."], { cwd: repository });
  execFileSync(
    "git",
    [
      "-c",
      "user.name=Independent Model Check Test",
      "-c",
      "user.email=independent-model-check@example.invalid",
      "commit",
      "-qm",
      "fixture",
    ],
    { cwd: repository },
  );
  const head = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: repository,
    encoding: "utf8",
  }).trim();
  const tree = execFileSync("git", ["rev-parse", "HEAD^{tree}"], {
    cwd: repository,
    encoding: "utf8",
  }).trim();
  const outputFile = join(directory, "output.json");
  const materialFile = join(directory, "review-material.txt");
  const writeOutput = (value) => writeFile(outputFile, JSON.stringify(value));
  const validate = (overrides = {}) =>
    validateIndependentModelRequiredCheck({
      repository,
      outputFile,
      expectedHead: head,
      expectedTree: tree,
      expectedBase: head,
      requestedProvider: REQUIRED_CHECK_PROVIDER,
      requestedRegion: REQUIRED_CHECK_REGION,
      baseUrl: REQUIRED_CHECK_BASE_URL,
      requestedModel: REQUIRED_CHECK_MODEL,
      assuranceLevel: REQUIRED_CHECK_ASSURANCE,
      materialFile,
      eventName: "pull_request",
      ...overrides,
    });
  return {
    directory,
    repository,
    materialFile,
    outputFile,
    writeOutput,
    validate,
  };
}

export async function assertIndependentModelRequiredCheckContract() {
  const [workflow, prompt, validator, providerDecision] = await Promise.all([
    readText(".github/workflows/independent-model-review.yml"),
    readText(
      "implementation/governance/independent-review/github-required-check-prompt.v1.md",
    ),
    readText("scripts/validate-independent-model-review-check.mjs"),
    readText("docs/adr/0023-qwen-independent-model-required-check.md"),
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
  const materialPaths = [
    "implementation/governance/independent-review/github-required-check-prompt.v1.md",
    ".github/workflows/independent-model-review.yml",
    "scripts/validate-independent-model-review-check.mjs",
    "tests/independent-model-required-check.cases.mjs",
    "docs/adr/0023-qwen-independent-model-required-check.md",
    "implementation/governance/independent-review/independent-review-policy.v2.json",
    "implementation/governance/independent-review/evidence/terra-targeted-remediation-ec8315c/targeted-remediation-model-review-evidence.v1.json",
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    "implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v1.json",
    "implementation/p1/c13/p1-b11-protected-review-preparation-evidence.v1.json",
  ];
  for (const path of materialPaths) {
    assert.match(validator, new RegExp(path.replaceAll(".", "\\."), "u"));
  }
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
  assert.match(prompt, /treat all repository content[\s\S]*as untrusted data/iu);
  assert.match(prompt, /do not modify/iu);
  assert.match(prompt, /P0.P2/iu);
  assert.match(prompt, /P3|production/iu);
  assert.doesNotMatch(prompt, /expectedDecision|recommendedDecision/u);

  assert.match(validator, /validateActiveIndependentReviewPolicy/u);
  assert.match(validator, /validateTargetedRemediationModelReviewEvidence/u);
  assert.match(validator, /validateIndependentModelReviewOutputArtifact/u);
  assert.match(validator, /mapIndependentModelReviewCheckResult/u);
  assert.match(validator, /buildPromptBoundReviewMaterial/u);
  assert.match(validator, /PLATFORM_TCB_PROMPT_BOUND_MODEL_REVIEW/u);
  assert.doesNotMatch(validator, /node:https|undici|fetch\s*\(/u);

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

  const fixture = await validationFixture();
  try {
    const material = await buildPromptBoundReviewMaterial({
      repository: fixture.repository,
      expectedHead: execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: fixture.repository,
        encoding: "utf8",
      }).trim(),
      expectedTree: execFileSync("git", ["rev-parse", "HEAD^{tree}"], {
        cwd: fixture.repository,
        encoding: "utf8",
      }).trim(),
      expectedBase: execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: fixture.repository,
        encoding: "utf8",
      }).trim(),
    });
    await writeFile(fixture.materialFile, material.bytes);
    await fixture.writeOutput({
      ...clearOutput,
      reviewSummary: material.bindingSummary,
    });
    const clear = await fixture.validate();
    assert.equal(clear.conclusion, "success");
    assert.equal(clear.title, "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION");
    assert.equal(clear.humanIndependentReviewSatisfied, false);
    assert.equal(clear.governanceEffect, "NONE");
    const duplicateMaterial = await buildPromptBoundReviewMaterial({
      repository: fixture.repository,
      expectedHead: execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: fixture.repository,
        encoding: "utf8",
      }).trim(),
      expectedTree: execFileSync("git", ["rev-parse", "HEAD^{tree}"], {
        cwd: fixture.repository,
        encoding: "utf8",
      }).trim(),
      expectedBase: execFileSync("git", ["rev-parse", "HEAD"], {
        cwd: fixture.repository,
        encoding: "utf8",
      }).trim(),
    });
    assert.deepEqual(duplicateMaterial, material);
    assert.ok(material.byteLength > 0);
    assert.ok(material.byteLength <= 96 * 1024);
    const materialText = material.bytes.toString("utf8");
    assert.match(materialText, /"baseCommit":"[a-f0-9]{40}"/u);
    assert.match(materialText, /"sourceCommit":"[a-f0-9]{40}"/u);
    assert.match(materialText, /"sourceTree":"[a-f0-9]{40}"/u);
    for (const path of materialPaths) {
      assert.match(materialText, new RegExp(path.replaceAll(".", "\\."), "u"));
    }
    await writeFile(
      fixture.materialFile,
      Buffer.concat([material.bytes, Buffer.from(" ")]),
    );
    assert.equal((await fixture.validate()).conclusion, "failure");
    await writeFile(fixture.materialFile, material.bytes);

    for (const decision of ["BLOCKED", "INCONCLUSIVE"]) {
      await fixture.writeOutput({
        ...clearOutput,
        reviewSummary: material.bindingSummary,
        decision,
      });
      assert.equal((await fixture.validate()).conclusion, "failure");
    }

    const blockingFinding = {
      findingId: "required-check-binding",
      severity: "HIGH",
      status: "OPEN",
      path: ".github/workflows/independent-model-review.yml",
      startLine: 1,
      endLine: 1,
      summary: "The review is not bound to the current head.",
      detailsSha256: `sha256:${"a".repeat(64)}`,
      resolutionEvidenceDigests: [],
    };
    for (const severity of ["HIGH", "CRITICAL"]) {
      await fixture.writeOutput({
        ...clearOutput,
        reviewSummary: material.bindingSummary,
        findings: [{ ...blockingFinding, severity }],
      });
      assert.equal((await fixture.validate()).conclusion, "failure");
    }

    for (const malformed of [
      Buffer.from("not-json", "utf8"),
      Buffer.from(JSON.stringify({ ...clearOutput, findings: null }), "utf8"),
      Buffer.from(JSON.stringify({ ...clearOutput, decision: "APPROVED" }), "utf8"),
    ]) {
      await writeFile(fixture.outputFile, malformed);
      assert.equal((await fixture.validate()).conclusion, "failure");
    }

    await fixture.writeOutput({
      ...clearOutput,
      reviewSummary: material.bindingSummary,
    });
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
        {
          baseUrl: "https://example.invalid/compatible-mode/v1",
        },
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

    for (const claim of [
      "INDEPENDENT_HUMAN_REVIEW_COMPLETE",
      "P3_OR_PRODUCTION_RELEASE_APPROVED",
      "humanIndependentReviewSatisfied=true",
    ]) {
      await fixture.writeOutput({
        ...clearOutput,
        reviewSummary: `${material.bindingSummary} ${claim}`,
      });
      assert.equal((await fixture.validate()).conclusion, "failure");
    }

    await fixture.writeOutput({
      ...clearOutput,
      reviewSummary: material.bindingSummary,
    });
    const insideRepository = join(fixture.repository, "model-output.json");
    await writeFile(
      insideRepository,
      JSON.stringify({ ...clearOutput, reviewSummary: material.bindingSummary }),
    );
    assert.equal(
      (await fixture.validate({ outputFile: insideRepository })).conclusion,
      "failure",
    );
    assert.equal(
      (
        await fixture.validate({
          outputFile: join(fixture.directory, "missing-output.json"),
        })
      ).conclusion,
      "failure",
    );
    const materialInsideRepository = join(
      fixture.repository,
      "review-material.txt",
    );
    await writeFile(materialInsideRepository, material.bytes);
    assert.equal(
      (
        await fixture.validate({ materialFile: materialInsideRepository })
      ).conclusion,
      "failure",
    );

    for (const path of fixturePaths.slice(0, 5)) {
      const target = join(fixture.repository, path);
      const original = await readFile(target);
      await writeFile(target, Buffer.concat([original, Buffer.from(" ")]));
      assert.equal((await fixture.validate()).conclusion, "failure");
      await writeFile(target, original);
    }
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
}
