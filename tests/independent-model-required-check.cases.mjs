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
import { validateIndependentModelRequiredCheck } from "../scripts/validate-independent-model-review-check.mjs";

const root = new URL("../", import.meta.url);
const readText = (path) => readFile(new URL(path, root), "utf8");
const fixturePaths = Object.freeze([
  "implementation/governance/independent-review/independent-review-policy.v2.json",
  "implementation/governance/schemas/independent-review-policy.v2.active.schema.json",
  "implementation/governance/independent-review/evidence/terra-targeted-remediation-ec8315c/targeted-remediation-model-review-evidence.v1.json",
  "implementation/governance/schemas/targeted-remediation-model-review-evidence.v1.schema.json",
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  "implementation/governance/independent-review/github-required-check-prompt.v1.md",
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
const REQUIRED_CHECK_ENDPOINT =
  "https://dashscope.aliyuncs.com/compatible-mode/v1/responses";

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
  const writeOutput = (value) => writeFile(outputFile, JSON.stringify(value));
  const validate = (overrides = {}) =>
    validateIndependentModelRequiredCheck({
      repository,
      outputFile,
      expectedHead: head,
      expectedTree: tree,
      requestedProvider: REQUIRED_CHECK_PROVIDER,
      requestedRegion: REQUIRED_CHECK_REGION,
      responsesEndpoint: REQUIRED_CHECK_ENDPOINT,
      requestedModel: REQUIRED_CHECK_MODEL,
      eventName: "pull_request",
      ...overrides,
    });
  return { directory, repository, outputFile, writeOutput, validate };
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
    /openai\/codex-action@52fe01ec70a42f454c9d2ebd47598f9fd6893d56/u,
  );
  assert.match(workflow, /persist-credentials: false/u);
  assert.match(workflow, /openai-api-key: \$\{\{ secrets\.DASHSCOPE_API_KEY \}\}/u);
  assert.match(
    workflow,
    /responses-api-endpoint: https:\/\/dashscope\.aliyuncs\.com\/compatible-mode\/v1\/responses/u,
  );
  assert.match(workflow, /model: "qwen3\.7-max-2026-05-20"/u);
  assert.doesNotMatch(workflow, /OPENAI_API_KEY|gpt-5\.6-terra/u);
  assert.match(workflow, /codex-version: "0\.147\.0"/u);
  assert.match(workflow, /permission-profile: ":read-only"/u);
  assert.doesNotMatch(workflow, /^\s+sandbox:/mu);
  assert.match(workflow, /safety-strategy: drop-sudo/u);
  assert.match(workflow, /codex-home: \$\{\{ runner\.temp \}\}\/codex-home/u);
  assert.match(workflow, /codex-args: '\["--ephemeral"\]'/u);
  assert.doesNotMatch(workflow, /^\s+output-schema-file:/mu);
  assert.match(workflow, /runner\.temp.*independent-model-review-output\.json/u);
  assert.doesNotMatch(workflow, /upload-artifact|self-hosted|force-push/u);

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
  assert.doesNotMatch(validator, /node:https|undici|fetch\s*\(/u);

  assert.match(providerDecision, /Status: Accepted/u);
  assert.match(providerDecision, /qwen3\.7-max-2026-05-20/u);
  assert.match(providerDecision, /DASHSCOPE_API_KEY/u);
  assert.match(providerDecision, /general Model Studio[\s\S]*pay-as-you-go/iu);
  assert.match(providerDecision, /must not treat API-side structured-output enforcement as proven/iu);
  assert.match(providerDecision, /existing provider-neutral output Schema[\s\S]*fail-closed authority/iu);
  assert.match(providerDecision, /does not alter[\s\S]*P1-B11[\s\S]*P3[\s\S]*production/iu);

  const fixture = await validationFixture();
  try {
    await fixture.writeOutput(clearOutput);
    const clear = await fixture.validate();
    assert.equal(clear.conclusion, "success");
    assert.equal(clear.title, "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION");
    assert.equal(clear.humanIndependentReviewSatisfied, false);
    assert.equal(clear.governanceEffect, "NONE");

    for (const decision of ["BLOCKED", "INCONCLUSIVE"]) {
      await fixture.writeOutput({ ...clearOutput, decision });
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

    await fixture.writeOutput(clearOutput);
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
        { requestedProvider: "OPENAI" },
        "INDEPENDENT_MODEL_REVIEW_PROVIDER_MISMATCH",
      ],
      [
        { requestedRegion: "SINGAPORE" },
        "INDEPENDENT_MODEL_REVIEW_REGION_MISMATCH",
      ],
      [
        {
          responsesEndpoint:
            "https://example.invalid/compatible-mode/v1/responses",
        },
        "INDEPENDENT_MODEL_REVIEW_ENDPOINT_MISMATCH",
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
      await fixture.writeOutput({ ...clearOutput, reviewSummary: claim });
      assert.equal((await fixture.validate()).conclusion, "failure");
    }

    await fixture.writeOutput(clearOutput);
    const insideRepository = join(fixture.repository, "model-output.json");
    await writeFile(insideRepository, JSON.stringify(clearOutput));
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
