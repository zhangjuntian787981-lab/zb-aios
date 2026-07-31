import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  buildKimiIndependentReviewRequest,
  createKimiModelVisibleProtocolBytes,
  createKimiIndependentModelReviewReceipt,
  executeKimiIndependentReview,
  independentKimiReviewDigests,
  kimiIndependentReviewMaterialGovernancePaths,
  validateIndependentReviewMaterial,
  validateKimiIndependentModelReviewReceipt,
  validateMoonshotKimiConfig,
} from "../lib/kimi-independent-review.mjs";
import { createIndependentReviewBundle } from "../lib/independent-model-review.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);
const configPath =
  "implementation/governance/independent-review/moonshot-kimi-k2.7-code.v1.json";
const configSchemaPath =
  "implementation/governance/schemas/moonshot-kimi-independent-review-config.v1.schema.json";
const materialSchemaPath =
  "implementation/governance/schemas/independent-review-material.v1.schema.json";
const receiptSchemaPath =
  "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json";
const outputSchemaPath =
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json";
const policyPath =
  "implementation/governance/independent-review/independent-review-policy.v2.candidate.json";
const bundleSchemaPath =
  "implementation/governance/schemas/independent-review-bundle.v2.schema.json";
const policySchemaPath =
  "implementation/governance/schemas/independent-review-policy.v2.schema.json";
const receiptV2SchemaPath =
  "implementation/governance/schemas/independent-model-review-receipt.v2.schema.json";
const runtimeEvidenceSchemaPath =
  "implementation/governance/schemas/independent-model-runtime-evidence.v2.schema.json";
const transportEvidenceSchemaPath =
  "implementation/governance/schemas/independent-review-transport-evidence.v1.schema.json";
const testResultSchemaPath =
  "implementation/governance/schemas/independent-review-test-result.v3.schema.json";
const runtimeManifestPath =
  "implementation/governance/independent-review/kimi-runtime-manifest.v1.json";
const validatorPath = "lib/independent-model-review.mjs";
const runtimeEvidenceValidatorPath =
  "lib/independent-review-runtime-evidence.mjs";
const transportEvidenceValidatorPath =
  "lib/independent-review-transport-evidence.mjs";
const bundleGeneratorPath = "scripts/build-independent-review-bundle.mjs";
const testPlanPath =
  "implementation/governance/independent-review/independent-review-test-plan.v2.json";
const testEvidenceCollectorPath =
  "scripts/run-independent-review-test-evidence.mjs";
const runtimeControlPlanePath =
  "scripts/run-independent-review-control-plane.mjs";
const sandboxPolicyTemplatePath =
  "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in";
const promptPath =
  "implementation/governance/independent-review/independent-model-review-prompt.v2.md";
const PATCH_TEXT = "diff --git a/a b/a\n";
const SOURCE_TEXT = "export const ok = true;\n";
const SPECIFICATION_TEXT = "Review this specification.\n";
const ADR_TEXT = "Review this architecture decision.\n";
const TEST_STDOUT_TEXT = "targeted tests passed\n";
const TEST_STDERR_TEXT = "";
const TEST_RUNTIME_BINDING_TEXT = JSON.stringify({
  schemaVersion: "independent-review-runtime-binding.v1",
  fixture: "closed-test-evidence-runtime-binding",
});
const TEST_RUNTIME_BINDING = {
  artifactRef: "evidence/runtime-binding.v1.json",
  artifactSha256: sha256Bytes(
    Buffer.from(TEST_RUNTIME_BINDING_TEXT, "utf8"),
  ),
  artifactByteLength: Buffer.byteLength(TEST_RUNTIME_BINDING_TEXT),
  bindingSha256: digest("d"),
  nodeExecutableSha256: digest("e"),
  dependencySetSha256: digest("f"),
  gitToolchainSha256: digest("0"),
  generator: {
    path: "lib/independent-review-runtime-binding.mjs",
    gitBlobSha256: digest("1"),
    executedBytesSha256: digest("1"),
  },
};
const TEST_EVIDENCE_TEXT = JSON.stringify({
  stdoutRef: "evidence/targeted.stdout.log",
  stdoutSha256: sha256Bytes(Buffer.from(TEST_STDOUT_TEXT, "utf8")),
  stdoutByteLength: Buffer.byteLength(TEST_STDOUT_TEXT),
  stderrRef: "evidence/targeted.stderr.log",
  stderrSha256: sha256Bytes(Buffer.from(TEST_STDERR_TEXT, "utf8")),
  stderrByteLength: Buffer.byteLength(TEST_STDERR_TEXT),
  runtimeBinding: TEST_RUNTIME_BINDING,
});
const require = createRequire(import.meta.url);
const installedAjvVersion = require("ajv/package.json").version;

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function commit(character) {
  return character.repeat(40);
}

function digest(character) {
  return `sha256:${character.repeat(64)}`;
}
const emptySha256 =
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

async function gitDiffCheckFixture({
  baseCommit,
  sourceCommit,
  sourceTree,
  patchSha256,
  generatorSha256,
}) {
  const value = {
    schemaVersion: "independent-review-git-diff-check.v1",
    checkId: "base-to-source-diff-check",
    executionMode: "TRUSTED_GIT_OBJECT_DATABASE_CONTROL_PLANE",
    baseCommit,
    sourceCommit,
    sourceTree,
    checkedPatchSha256: patchSha256,
    runnerPath: bundleGeneratorPath,
    runnerGitBlobSha256: generatorSha256,
    runnerExecutedBytesSha256: generatorSha256,
    gitExecutable: "/usr/bin/git",
    gitVersion: "git version 2.50.1 (fixture)",
    logicalCommandSha256: await independentKimiReviewDigests.value({
      executable: "/usr/bin/git",
      fixedArguments: [
        "--no-replace-objects",
        "-C",
        "<TRUSTED_REPOSITORY>",
        "diff",
        "--check",
        "--no-ext-diff",
        "--no-textconv",
      ],
      baseCommit,
      sourceCommit,
      terminator: "--",
    }),
    environmentSha256: await independentKimiReviewDigests.value({
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
      GIT_ATTR_NOSYSTEM: "1",
    }),
    exitCode: 0,
    status: "PASS",
    stdoutSha256: emptySha256,
    stdoutByteLength: 0,
    stderrSha256: emptySha256,
    stderrByteLength: 0,
    resultSha256: digest("0"),
  };
  const subject = clone(value);
  delete subject.resultSha256;
  value.resultSha256 =
    await independentKimiReviewDigests.value(subject);
  return value;
}

function runtimeApiKeyFixture() {
  return [
    "unit",
    "runtime",
    "credential",
    "not",
    "present",
    "in",
    "material",
  ].join("-");
}

function clone(value) {
  return structuredClone(value);
}

async function rehashMaterial(material) {
  material.totalSectionUtf8ByteLength = material.sections.reduce(
    (total, sectionValue) => total + sectionValue.byteLength,
    0,
  );
  material.sectionSetSha256 =
    await independentKimiReviewDigests.value(
      material.sections.map((sectionValue) => {
        const descriptor = clone(sectionValue);
        delete descriptor.content;
        return descriptor;
      }),
    );
  material.materialSha256 =
    await independentKimiReviewDigests.material(material);
  return Buffer.from(JSON.stringify(material), "utf8");
}

async function readJson(path) {
  return JSON.parse(await readFile(resolve(root, path), "utf8"));
}

async function compileSchema(path) {
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    validateFormats: true,
  });
  addFormats(ajv);
  return ajv.compile(await readJson(path));
}

function section(kind, path, content) {
  const bytes = Buffer.from(content, "utf8");
  return {
    kind,
    path,
    encoding: "UTF-8",
    byteLength: bytes.byteLength,
    sha256: sha256Bytes(bytes),
    content,
  };
}

async function validBundleFixture() {
  const paths = [
    policyPath,
    policySchemaPath,
    bundleSchemaPath,
    receiptV2SchemaPath,
    outputSchemaPath,
    runtimeEvidenceSchemaPath,
    transportEvidenceSchemaPath,
    testResultSchemaPath,
    validatorPath,
    runtimeEvidenceValidatorPath,
    transportEvidenceValidatorPath,
    bundleGeneratorPath,
    testPlanPath,
    testEvidenceCollectorPath,
    runtimeControlPlanePath,
    sandboxPolicyTemplatePath,
    promptPath,
  ];
  const bytes = new Map(
    await Promise.all(
      paths.map(async (path) => [path, await readFile(resolve(root, path))]),
    ),
  );
  const policy = JSON.parse(bytes.get(policyPath).toString("utf8"));
  const artifactSha = (path) => sha256Bytes(bytes.get(path));
  const protectedPaths = [
    "README.md",
    "docs/plans/通用多企业AI员工平台_v5.1新增内容与开源参考对照表_v1.0.md",
    "docs/plans/通用多企业AI员工平台_完备工程级方案_v5.2.md",
  ].sort();
  const kimiValidatorBytes = await readFile(
    resolve(root, "lib/kimi-independent-review.mjs"),
  );
  const reviewedPaths = [
    "lib/example.mjs",
    "lib/kimi-independent-review.mjs",
  ];
  const fixturePatchSha256 = sha256Bytes(
    Buffer.from(PATCH_TEXT, "utf8"),
  );
  const generatorSha256 = artifactSha(bundleGeneratorPath);
  const bundle = await createIndependentReviewBundle({
    bundleId: "imrb_kimi_fixture_001",
    generatedAt: "2026-07-30T09:59:00.000Z",
    applicablePhase: "P1",
    policyPath,
    policy,
    artifacts: {
      policySchemaPath,
      policySchemaSha256: artifactSha(policySchemaPath),
      bundleSchemaPath,
      bundleSchemaSha256: artifactSha(bundleSchemaPath),
      receiptSchemaPath: receiptV2SchemaPath,
      receiptSchemaSha256: artifactSha(receiptV2SchemaPath),
      outputSchemaPath,
      outputSchemaSha256: artifactSha(outputSchemaPath),
      runtimeEvidenceSchemaPath,
      runtimeEvidenceSchemaSha256: artifactSha(runtimeEvidenceSchemaPath),
      transportEvidenceSchemaPath,
      transportEvidenceSchemaSha256: artifactSha(
        transportEvidenceSchemaPath,
      ),
      testResultSchemaPath,
      testResultSchemaSha256: artifactSha(testResultSchemaPath),
      semanticValidatorPath: validatorPath,
      semanticValidatorSha256: artifactSha(validatorPath),
      independenceValidatorPath: validatorPath,
      independenceValidatorSha256: artifactSha(validatorPath),
      runtimeEvidenceValidatorPath,
      runtimeEvidenceValidatorSha256: artifactSha(
        runtimeEvidenceValidatorPath,
      ),
      transportEvidenceValidatorPath,
      transportEvidenceValidatorSha256: artifactSha(
        transportEvidenceValidatorPath,
      ),
      checkMapperPath: validatorPath,
      checkMapperSha256: artifactSha(validatorPath),
      bundleGeneratorPath,
      bundleGeneratorSha256: generatorSha256,
      testPlanPath,
      testPlanSha256: artifactSha(testPlanPath),
      testEvidenceCollectorPath,
      testEvidenceCollectorSha256: artifactSha(
        testEvidenceCollectorPath,
      ),
      runtimeControlPlanePath,
      runtimeControlPlaneSha256: artifactSha(runtimeControlPlanePath),
      sandboxPolicyTemplatePath,
      sandboxPolicyTemplateSha256: artifactSha(
        sandboxPolicyTemplatePath,
      ),
      promptPath,
      promptSha256: artifactSha(promptPath),
    },
    source: {
      baseCommit: commit("1"),
      sourceCommit: commit("2"),
      headCommit: commit("2"),
      tree: commit("4"),
      diffSha256: fixturePatchSha256,
      changedPathsDigest:
        await independentKimiReviewDigests.value(reviewedPaths),
      gitDiffCheck: await gitDiffCheckFixture({
        baseCommit: commit("1"),
        sourceCommit: commit("2"),
        sourceTree: commit("4"),
        patchSha256: fixturePatchSha256,
        generatorSha256,
      }),
    },
    repositoryProtection: {
      protectedPaths,
      protectedPathSetSha256:
        await independentKimiReviewDigests.value(protectedPaths),
    },
    reviewedPaths,
    sourceSubjects: [
      {
        path: "lib/example.mjs",
        gitMode: "100644",
        blobSha256: sha256Bytes(Buffer.from(SOURCE_TEXT, "utf8")),
      },
      {
        path: "lib/kimi-independent-review.mjs",
        gitMode: "100644",
        blobSha256: sha256Bytes(kimiValidatorBytes),
      },
    ],
    specificationSubjects: [
      {
        path: "AGENTS.md",
        blobSha256: sha256Bytes(
          Buffer.from(SPECIFICATION_TEXT, "utf8"),
        ),
      },
      {
        path: "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
        blobSha256: sha256Bytes(Buffer.from(ADR_TEXT, "utf8")),
      },
    ],
    testEvidenceSubjects: [
      {
        evidenceId: "targeted-tests",
        command: "node --test tests/kimi-independent-review.test.mjs",
        status: "PASS",
        exitCode: 0,
        outputRef: "evidence/targeted.json",
        outputSha256: sha256Bytes(
          Buffer.from(TEST_EVIDENCE_TEXT, "utf8"),
        ),
        outputByteLength: Buffer.byteLength(TEST_EVIDENCE_TEXT),
        truncated: false,
        sourceCommit: commit("2"),
        runner: "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE",
        toolVersions: ["node=v24.18.0"],
      },
    ],
    implementationIdentity: {
      provider: "openai",
      modelId: "gpt-5.6-sol",
      modelVersion: "gpt-5.6-sol",
      participantManifestSha256: digest("b"),
      sessionIdSha256: digest("c"),
    },
  });
  return { policy, bundle };
}

async function materialFixture(config, bundle) {
  const promptBytes = await readFile(
    resolve(
      root,
      "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
    ),
  );
  const outputSchemaBytes = await readFile(resolve(root, outputSchemaPath));
  const receiptSchemaBytes = await readFile(resolve(root, receiptSchemaPath));
  const runtimeManifestBytes = await readFile(
    resolve(root, runtimeManifestPath),
  );
  const configBytes = Buffer.from(JSON.stringify(config), "utf8");
  const reviewBundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const governanceSubjectBindings = await Promise.all(
    kimiIndependentReviewMaterialGovernancePaths.map(async (path) => {
      const bytes = await readFile(resolve(root, path));
      return {
        path,
        byteLength: bytes.byteLength,
        sha256: sha256Bytes(bytes),
      };
    }),
  );
  const sections = [
    section(
      "REVIEW_BUNDLE",
      "artifacts/independent-review-bundle.v2.json",
      JSON.stringify(bundle),
    ),
    section("PATCH", "artifacts/source.diff", PATCH_TEXT),
    section(
      "SPECIFICATION",
      "AGENTS.md",
      SPECIFICATION_TEXT,
    ),
    section(
      "SPECIFICATION",
      "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
      ADR_TEXT,
    ),
    section(
      "TEST_EVIDENCE",
      "evidence/targeted.json",
      TEST_EVIDENCE_TEXT,
    ),
    section(
      "GOVERNANCE",
      "artifacts/moonshot-kimi-model-visible-protocol.v1.json",
      createKimiModelVisibleProtocolBytes(config).toString("utf8"),
    ),
  ];
  for (const binding of governanceSubjectBindings) {
    const bytes = await readFile(resolve(root, binding.path));
    sections.push(
      section(
        "GOVERNANCE",
        binding.path,
        bytes.toString("utf8"),
      ),
    );
  }
  sections.sort((left, right) =>
    `${left.kind}:${left.path}`.localeCompare(
      `${right.kind}:${right.path}`,
      "en",
    ),
  );
  const reviewBundleSection = sections.find(
    ({ kind }) => kind === "REVIEW_BUNDLE",
  );
  const material = {
    schemaVersion: "independent-review-material.v1",
    materialId: "irm_fixture_001",
    source: {
      baseCommit: bundle.source.baseCommit,
      sourceCommit: bundle.source.sourceCommit,
      sourceTree: bundle.source.tree,
      patchSha256: bundle.source.diffSha256,
      gitDiffCheckSha256: bundle.source.gitDiffCheck.resultSha256,
    },
    bindings: {
      reviewBundle: {
        path: reviewBundleSection.path,
        byteLength: reviewBundleSection.byteLength,
        sha256: reviewBundleSection.sha256,
        bundleDigest: bundle.bundleSha256,
      },
      reviewerPrompt: {
        path:
          "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
        byteLength: promptBytes.byteLength,
        sha256: sha256Bytes(promptBytes),
      },
      canonicalOutputSchema: {
        path: outputSchemaPath,
        byteLength: outputSchemaBytes.byteLength,
        sha256: sha256Bytes(outputSchemaBytes),
      },
      canonicalReceiptSchema: {
        path: receiptSchemaPath,
        byteLength: receiptSchemaBytes.byteLength,
        sha256: sha256Bytes(receiptSchemaBytes),
      },
      providerConfig: {
        path: configPath,
        byteLength: configBytes.byteLength,
        sha256: sha256Bytes(configBytes),
      },
    },
    sections,
    sectionSetSha256: await independentKimiReviewDigests.value(
      sections.map((value) => {
        const descriptor = structuredClone(value);
        delete descriptor.content;
        return descriptor;
      }),
    ),
    totalSectionUtf8ByteLength: sections.reduce(
      (total, current) => total + current.byteLength,
      0,
    ),
    contextBudgetUtf8Bytes: config.maxReviewMaterialUtf8Bytes,
    materialSha256: digest("0"),
  };
  material.materialSha256 =
    await independentKimiReviewDigests.material(material);
  return {
    material,
    materialBytes: Buffer.from(JSON.stringify(material), "utf8"),
    configBytes,
    reviewBundleBytes,
    promptBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
    runtimeManifestBytes,
    runtimeTrust: {
      mode: "ANCESTOR_RUNTIME_COMMIT",
      runtimeCommit: commit("1"),
      runtimeTree: commit("3"),
      subjectCommit: bundle.source.sourceCommit,
      subjectTree: bundle.source.tree,
      bootstrapSha256: digest("9"),
      launcherSha256: digest("a"),
      runtimeManifestGitBlobSha256:
        sha256Bytes(runtimeManifestBytes),
      runnerGitBlobSha256: digest("d"),
    },
    governanceSubjectBindings,
  };
}

function materialExpected(current) {
  const protocolBytes = createKimiModelVisibleProtocolBytes(current.config);
  return {
    bundle: current.bundle,
    governanceSubjectBindings: current.governanceSubjectBindings,
    sourceCommit: current.bundle.source.sourceCommit,
    sourceTree: current.bundle.source.tree,
    reviewBundleBytesSha256: sha256Bytes(current.reviewBundleBytes),
    reviewBundleByteLength: current.reviewBundleBytes.byteLength,
    reviewBundleDigest: current.bundle.bundleSha256,
    reviewerPromptSha256: sha256Bytes(current.promptBytes),
    reviewerPromptByteLength: current.promptBytes.byteLength,
    canonicalOutputSchemaSha256: sha256Bytes(current.outputSchemaBytes),
    canonicalOutputSchemaByteLength: current.outputSchemaBytes.byteLength,
    canonicalReceiptSchemaSha256: sha256Bytes(current.receiptSchemaBytes),
    canonicalReceiptSchemaByteLength:
      current.receiptSchemaBytes.byteLength,
    providerConfigSha256: sha256Bytes(current.configBytes),
    providerConfigByteLength: current.configBytes.byteLength,
    modelVisibleProtocolSha256: sha256Bytes(protocolBytes),
    modelVisibleProtocolByteLength: protocolBytes.byteLength,
    contextBudgetUtf8Bytes: current.config.maxReviewMaterialUtf8Bytes,
  };
}

async function requestFixture() {
  const config = await readJson(configPath);
  const governance = await validBundleFixture();
  const material = await materialFixture(config, governance.bundle);
  const request = await buildKimiIndependentReviewRequest({
    config,
    configBytes: material.configBytes,
    bundle: governance.bundle,
    reviewBundleBytes: material.reviewBundleBytes,
    promptBytes: material.promptBytes,
    materialBytes: material.materialBytes,
    outputSchemaBytes: material.outputSchemaBytes,
    receiptSchemaBytes: material.receiptSchemaBytes,
    governanceSubjectBindings: material.governanceSubjectBindings,
  });
  return {
    config,
    ...governance,
    ...material,
    ...request,
  };
}

function clearOutput() {
  return {
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "The frozen candidate meets the bounded preproduction policy.",
    findings: [],
    decision: "CLEAR",
  };
}

function responseFor(content, model = "kimi-k2.7-code") {
  return {
    id: "chatcmpl_fixture_001",
    object: "chat.completion",
    model,
    choices: [
      {
        index: 0,
        finish_reason: "stop",
        message: {
          role: "assistant",
          content,
        },
      },
    ],
  };
}

function responseObject(body, status = 200) {
  const bytes = Buffer.from(JSON.stringify(body), "utf8");
  return responseBytesObject(bytes, status);
}

function responseBytesObject(bytes, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    redirected: false,
    url: "https://api.moonshot.ai/v1/chat/completions",
    headers: new Headers({ "content-type": "application/json" }),
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(bytes);
        controller.close();
      },
    }),
  };
}

test("fixed Moonshot Kimi config is closed, self-hashed and exact", async () => {
  const config = await readJson(configPath);
  const validateSchema = await compileSchema(configSchemaPath);

  assert.equal(validateSchema(config), true);
  assert.deepEqual(await validateMoonshotKimiConfig(config), {
    ok: true,
    reasonCodes: [],
  });
  assert.equal(config.reviewerProvider, "moonshot");
  assert.equal(config.reviewerModel, "kimi-k2.7-code");
  assert.equal(config.baseURL, "https://api.moonshot.ai/v1");
  assert.equal(config.endpoint, "/chat/completions");
  assert.equal(config.credentialEnv, "MOONSHOT_API_KEY");
  assert.deepEqual(config.thinking, { type: "enabled" });
  assert.equal(config.toolChoice, "none");
  assert.equal(config.toolsOmitted, true);
  assert.equal(config.responseFormat.strict, true);
  assert.equal(config.fallbackPolicy, "DISABLED_FAIL_CLOSED");
  assert.equal(config.contextBudgetBasis, "FIXED_UTF8_FAIL_CLOSED_V1");
  assert.ok(
    config.maxReviewMaterialUtf8Bytes <
      config.maxRequestUtf8Bytes,
  );
  assert.ok(
    config.maxResponseUtf8Bytes <
      config.maxRequestUtf8Bytes,
  );
  assert.equal(
    config.configSha256,
    await independentKimiReviewDigests.config(config),
  );
});

test("provider, model, base URL, protocol and fallback drift fail closed", async () => {
  const config = await readJson(configPath);
  for (const mutate of [
    (value) => (value.reviewerProvider = "openai"),
    (value) => (value.reviewerModel = "gpt-5.6-terra"),
    (value) => (value.reviewerModel = "kimi-k2.7-code-highspeed"),
    (value) => (value.baseURL = "https://proxy.example.invalid/v1"),
    (value) => (value.toolChoice = "auto"),
    (value) => (value.toolsOmitted = false),
    (value) => (value.thinking.type = "disabled"),
    (value) => (value.responseFormat.strict = false),
    (value) => (value.fallbackPolicy = "AUTO"),
  ]) {
    const candidate = clone(config);
    mutate(candidate);
    candidate.configSha256 =
      await independentKimiReviewDigests.config(candidate);
    const result = await validateMoonshotKimiConfig(candidate);
    assert.equal(result.ok, false);
  }
});

test("review material is closed, byte-bound and enforces the context budget", async () => {
  const config = await readJson(configPath);
  const validateSchema = await compileSchema(materialSchemaPath);
  const { bundle } = await validBundleFixture();
  const fixture = {
    config,
    bundle,
    ...(await materialFixture(config, bundle)),
  };
  const { material, materialBytes } = fixture;

  assert.equal(validateSchema(material), true);
  assert.deepEqual(
    await validateIndependentReviewMaterial({
      material,
      rawMaterialBytes: materialBytes,
      expected: materialExpected(fixture),
    }),
    { ok: true, reasonCodes: [] },
  );

  const changed = clone(material);
  changed.sections[0].content += " ";
  assert.equal(
    (
      await validateIndependentReviewMaterial({
        material: changed,
        rawMaterialBytes: Buffer.from(JSON.stringify(changed), "utf8"),
        expected: materialExpected(fixture),
      })
    ).ok,
    false,
  );

  const overBudget = clone(material);
  overBudget.contextBudgetUtf8Bytes = 1;
  overBudget.materialSha256 =
    await independentKimiReviewDigests.material(overBudget);
  const result = await validateIndependentReviewMaterial({
    material: overBudget,
    rawMaterialBytes: Buffer.from(JSON.stringify(overBudget), "utf8"),
    expected: materialExpected(fixture),
  });
  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_EXCEEDED",
    ),
  );
});

test("request body is exact Kimi JSON Schema mode with tools and sampling absent", async () => {
  const current = await requestFixture();
  const request = JSON.parse(current.requestBytes.toString("utf8"));

  assert.deepEqual(Object.keys(request).sort(), [
    "messages",
    "model",
    "response_format",
    "thinking",
    "tool_choice",
  ]);
  assert.equal(request.model, "kimi-k2.7-code");
  assert.deepEqual(request.thinking, { type: "enabled" });
  assert.equal(request.tool_choice, "none");
  assert.equal(Object.hasOwn(request, "tools"), false);
  for (const field of current.config.forbiddenRequestFields) {
    assert.equal(Object.hasOwn(request, field), false);
  }
  assert.equal(request.response_format.type, "json_schema");
  assert.equal(request.response_format.json_schema.strict, true);
  assert.equal(
    request.messages[0].content,
    current.promptBytes.toString("utf8"),
  );
  assert.equal(
    request.messages[1].content,
    current.materialBytes.toString("utf8"),
  );
  assert.equal(current.toolsAbsent, true);
  assert.equal(current.toolChoiceNone, true);
});

test("transport rejects a request whose frozen prompt, material or embedded schema was substituted", async () => {
  const current = await requestFixture();
  const request = JSON.parse(current.requestBytes.toString("utf8"));
  const mutations = [
    (value) => {
      value.messages[0].content += "\nsubstituted prompt";
    },
    (value) => {
      value.messages[1].content += "\nsubstituted material";
    },
    (value) => {
      value.response_format.json_schema.schema = {
        type: "object",
        additionalProperties: false,
        properties: {},
        required: [],
      };
    },
  ];

  for (const mutate of mutations) {
    const candidate = clone(request);
    mutate(candidate);
    let networkCalls = 0;
    const result = await executeKimiIndependentReview({
      config: current.config,
      requestBytes: Buffer.from(JSON.stringify(candidate), "utf8"),
      promptBytes: current.promptBytes,
      materialBytes: current.materialBytes,
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey: runtimeApiKeyFixture(),
      fetchImpl: async () => {
        networkCalls += 1;
        return responseObject(
          responseFor(JSON.stringify(clearOutput())),
        );
      },
    });

    assert.equal(networkCalls, 0);
    assert.equal(result.ok, false);
    assert.deepEqual(result.reasonCodes, [
      "KIMI_REQUEST_BINDING_MISMATCH",
    ]);
  }

  const reorderedRequestBytes = Buffer.from(
    JSON.stringify({
      tool_choice: request.tool_choice,
      thinking: request.thinking,
      response_format: request.response_format,
      model: request.model,
      messages: request.messages,
    }),
    "utf8",
  );
  let reorderedNetworkCalls = 0;
  const reorderedResult = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: reorderedRequestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: runtimeApiKeyFixture(),
    fetchImpl: async () => {
      reorderedNetworkCalls += 1;
      return responseObject(responseFor(JSON.stringify(clearOutput())));
    },
  });
  assert.equal(reorderedNetworkCalls, 0);
  assert.deepEqual(reorderedResult.reasonCodes, [
    "KIMI_REQUEST_BINDING_MISMATCH",
  ]);
});

test("request preflight independently binds the real Bundle, frozen Schemas and config bytes", async () => {
  const current = await requestFixture();
  const base = {
    config: current.config,
    configBytes: current.configBytes,
    bundle: current.bundle,
    reviewBundleBytes: current.reviewBundleBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    receiptSchemaBytes: current.receiptSchemaBytes,
    runtimeManifestBytes: current.runtimeManifestBytes,
    governanceSubjectBindings: current.governanceSubjectBindings,
  };
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      configBytes: undefined,
    }),
    /config|bytes/iu,
  );
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      reviewBundleBytes: Buffer.from(
        JSON.stringify({ ...current.bundle, bundleId: "tampered_bundle" }),
        "utf8",
      ),
    }),
    /Bundle|material|inputs|JSON/iu,
  );
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      receiptSchemaBytes: Buffer.from("{}"),
    }),
    /Schema|material/iu,
  );
  const tamperedMaterial = clone(current.material);
  tamperedMaterial.source.sourceTree = commit("5");
  tamperedMaterial.materialSha256 =
    await independentKimiReviewDigests.material(tamperedMaterial);
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      materialBytes: Buffer.from(
        JSON.stringify(tamperedMaterial),
        "utf8",
      ),
    }),
    /material/iu,
  );
});

test("request preflight rejects rehashed Material with incomplete or substituted section coverage", async () => {
  const current = await requestFixture();
  const base = {
    config: current.config,
    configBytes: current.configBytes,
    bundle: current.bundle,
    reviewBundleBytes: current.reviewBundleBytes,
    promptBytes: current.promptBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    receiptSchemaBytes: current.receiptSchemaBytes,
    runtimeManifestBytes: current.runtimeManifestBytes,
    governanceSubjectBindings: current.governanceSubjectBindings,
  };
  const duplicatedSource = clone(current.material);
  duplicatedSource.sections.push(
    section("SOURCE", "lib/example.mjs", SOURCE_TEXT),
  );
  duplicatedSource.sections.sort((left, right) =>
    `${left.kind}:${left.path}`.localeCompare(
      `${right.kind}:${right.path}`,
      "en",
    ),
  );
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      materialBytes: await rehashMaterial(duplicatedSource),
    }),
    /material/iu,
  );

  const substitutedPatch = clone(current.material);
  const patch = substitutedPatch.sections.find(
    ({ kind }) => kind === "PATCH",
  );
  const substitutedBytes = Buffer.from("unrelated patch\n", "utf8");
  patch.content = substitutedBytes.toString("utf8");
  patch.byteLength = substitutedBytes.byteLength;
  patch.sha256 = sha256Bytes(substitutedBytes);
  substitutedPatch.source.patchSha256 = patch.sha256;
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      materialBytes: await rehashMaterial(substitutedPatch),
    }),
    /material/iu,
  );

  for (const kind of [
    "SPECIFICATION",
    "TEST_EVIDENCE",
    "GOVERNANCE",
  ]) {
    const missing = clone(current.material);
    const index = missing.sections.findIndex(
      (sectionValue) => sectionValue.kind === kind,
    );
    missing.sections.splice(index, 1);
    await assert.rejects(
      buildKimiIndependentReviewRequest({
        ...base,
        materialBytes: await rehashMaterial(missing),
      }),
      /material/iu,
    );
  }

  const missingDeduplicatedSource = clone(current.material);
  missingDeduplicatedSource.sections =
    missingDeduplicatedSource.sections.filter(
      ({ kind, path }) =>
        !(
          kind === "GOVERNANCE" &&
          path === "lib/kimi-independent-review.mjs"
        ),
    );
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      materialBytes: await rehashMaterial(missingDeduplicatedSource),
    }),
    /material/iu,
  );

  const renamed = clone(current.material);
  const source = renamed.sections.find(
    ({ kind }) => kind === "SPECIFICATION",
  );
  source.kind = "SOURCE";
  renamed.sections.sort((left, right) =>
    `${left.kind}:${left.path}`.localeCompare(
      `${right.kind}:${right.path}`,
      "en",
    ),
  );
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      materialBytes: await rehashMaterial(renamed),
    }),
    /material/iu,
  );

  const extra = clone(current.material);
  extra.sections.push(
    section("SOURCE", "lib/unreviewed.mjs", "export const hidden = true;\n"),
  );
  extra.sections.sort((left, right) =>
    `${left.kind}:${left.path}`.localeCompare(
      `${right.kind}:${right.path}`,
      "en",
    ),
  );
  await assert.rejects(
    buildKimiIndependentReviewRequest({
      ...base,
      materialBytes: await rehashMaterial(extra),
    }),
    /material/iu,
  );
});

test("missing credential fails before any network attempt", async () => {
  const current = await requestFixture();
  let networkCalls = 0;
  const result = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: "",
    fetchImpl: async () => {
      networkCalls += 1;
      throw new Error("must not be called");
    },
  });

  assert.equal(networkCalls, 0);
  assert.deepEqual(result, {
    ok: false,
    status: "BLOCKED",
    reasonCodes: ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
    networkAttemptCount: 0,
  });
});

test("successful transport preserves exact response and content UTF-8 bytes", async () => {
  const current = await requestFixture();
  const content = JSON.stringify(clearOutput());
  let networkCalls = 0;
  const result = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: runtimeApiKeyFixture(),
    fetchImpl: async (_url, options) => {
      networkCalls += 1;
      assert.equal(options.method, "POST");
      assert.equal(options.body, current.requestBytes);
      assert.equal(options.redirect, "error");
      return responseObject(responseFor(content));
    },
  });

  assert.equal(result.ok, true);
  assert.equal(networkCalls, 1);
  assert.equal(result.actualReturnedModel, "kimi-k2.7-code");
  assert.equal(result.responseId, "chatcmpl_fixture_001");
  assert.equal(result.contentBytes.toString("utf8"), content);
  assert.equal(
    result.rawResponseSha256,
    sha256Bytes(result.responseBytes),
  );
  assert.equal(
    result.rawContentSha256,
    sha256Bytes(result.contentBytes),
  );
});

test("returned model fallback, empty content, truncation, invalid JSON, HTTP, timeout and network failures close", async () => {
  const current = await requestFixture();
  const cases = [
    responseObject(
      responseFor(JSON.stringify(clearOutput()), "kimi-k2.7-code-highspeed"),
    ),
    responseObject(responseFor("")),
    responseObject({
      ...responseFor(JSON.stringify(clearOutput())),
      choices: [
        {
          index: 0,
          finish_reason: "length",
          message: { role: "assistant", content: JSON.stringify(clearOutput()) },
        },
      ],
    }),
    responseObject(responseFor("not-json")),
    responseObject({ error: { message: "unavailable" } }, 503),
  ];
  for (const response of cases) {
    const result = await executeKimiIndependentReview({
      config: current.config,
      requestBytes: current.requestBytes,
      promptBytes: current.promptBytes,
      materialBytes: current.materialBytes,
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey: runtimeApiKeyFixture(),
      fetchImpl: async () => response,
    });
    assert.equal(result.ok, false);
  }

  for (const error of [
    new Error("network failed"),
    new DOMException("timed out", "AbortError"),
  ]) {
    const result = await executeKimiIndependentReview({
      config: current.config,
      requestBytes: current.requestBytes,
      promptBytes: current.promptBytes,
      materialBytes: current.materialBytes,
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey: runtimeApiKeyFixture(),
      fetchImpl: async () => {
        throw error;
      },
    });
    assert.equal(result.ok, false);
    assert.equal(result.networkAttemptCount, 1);
  }

  const credentialOrBalance = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: runtimeApiKeyFixture(),
    fetchImpl: async () =>
      responseObject({ error: { message: "not recorded" } }, 401),
  });
  assert.deepEqual(credentialOrBalance.reasonCodes, [
    "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
  ]);
});

test("redirects, tool responses, secret echo and body-read timeout fail closed", async () => {
  const current = await requestFixture();
  const apiKey = runtimeApiKeyFixture();
  const content = JSON.stringify(clearOutput());
  const redirected = responseObject(responseFor(content));
  redirected.redirected = true;
  redirected.url = "https://proxy.example.invalid/chat/completions";
  const toolResponse = responseFor(content);
  toolResponse.choices[0].index = 1;
  toolResponse.choices[0].message = {
    role: "tool",
    content,
    tool_calls: [{ id: "forbidden" }],
  };
  for (const response of [
    redirected,
    responseObject(toolResponse),
    responseObject({
      ...responseFor(content),
      debug: apiKey,
    }),
  ]) {
    const result = await executeKimiIndependentReview({
      config: current.config,
      requestBytes: current.requestBytes,
      promptBytes: current.promptBytes,
      materialBytes: current.materialBytes,
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey,
      fetchImpl: async () => response,
    });
    assert.equal(result.ok, false);
    assert.equal(Object.hasOwn(result, "responseBytes"), false);
  }

  const slowBody = responseObject(responseFor(content));
  slowBody.body = new ReadableStream({
    async pull(controller) {
      await new Promise((resolvePull) => setTimeout(resolvePull, 50));
      controller.enqueue(
        Buffer.from(JSON.stringify(responseFor(content)), "utf8"),
      );
      controller.close();
    },
  });
  const timedOut = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey,
    fetchImpl: async () => slowBody,
    timeoutMs: 5,
  });
  assert.equal(timedOut.ok, false);
  assert.ok(timedOut.reasonCodes.includes("KIMI_TRANSPORT_TIMEOUT"));
});

test("chunked and falsely short response bodies stop at the byte limit", async () => {
  const current = await requestFixture();
  const apiKey = runtimeApiKeyFixture();
  const chunk = Buffer.alloc(current.config.maxResponseUtf8Bytes, 0x20);
  for (const headers of [
    new Headers({ "content-type": "application/json" }),
    new Headers({
      "content-type": "application/json",
      "content-length": "1",
    }),
  ]) {
    let cancelled = false;
    let pulls = 0;
    const response = {
      status: 200,
      redirected: false,
      url: "https://api.moonshot.ai/v1/chat/completions",
      headers,
      body: new ReadableStream({
        pull(controller) {
          pulls += 1;
          controller.enqueue(chunk);
          controller.enqueue(Buffer.from("x", "utf8"));
        },
        cancel() {
          cancelled = true;
        },
      }),
    };
    const result = await executeKimiIndependentReview({
      config: current.config,
      requestBytes: current.requestBytes,
      promptBytes: current.promptBytes,
      materialBytes: current.materialBytes,
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey,
      fetchImpl: async () => response,
    });
    assert.equal(result.ok, false);
    assert.deepEqual(result.reasonCodes, [
      "KIMI_RESPONSE_BYTES_LIMIT_EXCEEDED",
    ]);
    assert.equal(cancelled, true);
    assert.ok(pulls <= 2);
    assert.equal(Object.hasOwn(result, "responseBytes"), false);
  }

  let announcedLengthCancelled = false;
  const announcedTooLarge = {
    status: 200,
    redirected: false,
    url: "https://api.moonshot.ai/v1/chat/completions",
    headers: new Headers({
      "content-type": "application/json",
      "content-length": String(
        current.config.maxResponseUtf8Bytes + 1,
      ),
    }),
    body: new ReadableStream({
      start() {},
      cancel() {
        announcedLengthCancelled = true;
      },
    }),
  };
  const announcedResult = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey,
    fetchImpl: async () => announcedTooLarge,
  });
  assert.deepEqual(announcedResult.reasonCodes, [
    "KIMI_RESPONSE_BYTES_LIMIT_EXCEEDED",
  ]);
  assert.equal(announcedLengthCancelled, true);
});

test("credentials cannot enter the request or survive decoded response inspection", async () => {
  const current = await requestFixture();
  const apiKey = runtimeApiKeyFixture();
  const request = JSON.parse(current.requestBytes.toString("utf8"));
  request.messages[0].content += `\n${apiKey}`;
  let requestNetworkCalls = 0;
  const requestLeak = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: Buffer.from(JSON.stringify(request), "utf8"),
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey,
    fetchImpl: async () => {
      requestNetworkCalls += 1;
      return responseObject(responseFor(JSON.stringify(clearOutput())));
    },
  });
  assert.equal(requestNetworkCalls, 0);
  assert.deepEqual(requestLeak.reasonCodes, [
    "KIMI_REQUEST_CREDENTIAL_EXPOSED",
  ]);

  const escapedApiKey = [...apiKey]
    .map(
      (character) =>
        `\\u${character.codePointAt(0).toString(16).padStart(4, "0")}`,
    )
    .join("");
  const baseResponse = JSON.stringify(
    responseFor(JSON.stringify(clearOutput())),
  );
  const encodedResponse =
    `${baseResponse.slice(0, -1)},"debug":"${escapedApiKey}"}`;
  const responseLeak = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey,
    fetchImpl: async () =>
      responseBytesObject(Buffer.from(encodedResponse, "utf8")),
  });
  assert.equal(responseLeak.ok, false);
  assert.deepEqual(responseLeak.reasonCodes, [
    "KIMI_RESPONSE_CREDENTIAL_ECHOED",
  ]);
  assert.equal(Object.hasOwn(responseLeak, "responseBytes"), false);
});

test("duplicate provider response keys fail closed", async () => {
  const current = await requestFixture();
  const apiKey = runtimeApiKeyFixture();
  const baseResponse = JSON.stringify(
    responseFor(JSON.stringify(clearOutput())),
  );
  for (const duplicateResponse of [
    baseResponse.replace(
      '"model":"kimi-k2.7-code"',
      '"model":"kimi-k3","model":"kimi-k2.7-code"',
    ),
    baseResponse.replace(
      '"choices":[',
      '"choices":[],"choices":[',
    ),
  ]) {
    const result = await executeKimiIndependentReview({
      config: current.config,
      requestBytes: current.requestBytes,
      promptBytes: current.promptBytes,
      materialBytes: current.materialBytes,
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey,
      fetchImpl: async () =>
        responseBytesObject(Buffer.from(duplicateResponse, "utf8")),
    });
    assert.equal(result.ok, false);
    assert.deepEqual(result.reasonCodes, [
      "KIMI_RESPONSE_PROTOCOL_INVALID",
    ]);
  }
});

test("unpaired UTF-16 surrogates fail closed before request transport and in responses", async () => {
  const current = await requestFixture();
  const apiKey = runtimeApiKeyFixture();
  const request = JSON.parse(current.requestBytes.toString("utf8"));
  request.messages[0].content += "\ud800";
  let networkCalls = 0;
  const invalidRequest = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: Buffer.from(JSON.stringify(request), "utf8"),
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey,
    fetchImpl: async () => {
      networkCalls += 1;
      return responseObject(responseFor(JSON.stringify(clearOutput())));
    },
  });
  assert.equal(networkCalls, 0);
  assert.deepEqual(invalidRequest.reasonCodes, ["KIMI_REQUEST_INVALID"]);

  const validResponse = JSON.stringify(
    responseFor(JSON.stringify(clearOutput())),
  );
  const invalidResponseBytes = Buffer.from(
    `${validResponse.slice(0, -1)},"debug":"\\ud800"}`,
    "utf8",
  );
  const invalidResponse = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey,
    fetchImpl: async () => responseBytesObject(invalidResponseBytes),
  });
  assert.equal(invalidResponse.ok, false);
  assert.deepEqual(invalidResponse.reasonCodes, [
    "KIMI_RESPONSE_PROTOCOL_INVALID",
  ]);
  assert.equal(Object.hasOwn(invalidResponse, "responseBytes"), false);
});

test("formal Kimi Receipt binds transport, schemas, source and no-tool isolation", async () => {
  const current = await requestFixture();
  const output = clearOutput();
  const content = JSON.stringify(output);
  const transport = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: runtimeApiKeyFixture(),
    fetchImpl: async () => responseObject(responseFor(content)),
  });
  const snapshots = {
    before: {
      head: commit("2"),
      tree: commit("4"),
      worktreeStatusSha256: digest("6"),
      worktreeContentManifestSha256: digest("5"),
      worktreePathCount: 42,
      protectedPathSetSha256: digest("7"),
      protectedFilesDigest: digest("8"),
      ignoredExclusionPolicySha256: digest("e"),
      ignoredExcludedPathCount: 3,
    },
    after: {
      head: commit("2"),
      tree: commit("4"),
      worktreeStatusSha256: digest("6"),
      worktreeContentManifestSha256: digest("5"),
      worktreePathCount: 42,
      protectedPathSetSha256: digest("7"),
      protectedFilesDigest: digest("8"),
      ignoredExclusionPolicySha256: digest("e"),
      ignoredExcludedPathCount: 3,
    },
  };
  const bundle = current.bundle;
  const policy = current.policy;
  const receipt = await createKimiIndependentModelReviewReceipt({
    receiptId: "imrr_kimi_fixture_001",
    policy,
    bundle,
    config: current.config,
    configBytes: current.configBytes,
    material: current.material,
    rawMaterialBytes: current.materialBytes,
    reviewBundleBytes: current.reviewBundleBytes,
    promptBytes: current.promptBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    receiptSchemaBytes: current.receiptSchemaBytes,
    runtimeManifestBytes: current.runtimeManifestBytes,
    requestBytes: current.requestBytes,
    responseBytes: transport.responseBytes,
    contentBytes: transport.contentBytes,
    responseId: transport.responseId,
    actualReturnedModel: transport.actualReturnedModel,
    startedAt: "2026-07-30T10:00:00.000Z",
    finishedAt: "2026-07-30T10:00:01.000Z",
    snapshots,
    governanceSubjectBindings: current.governanceSubjectBindings,
    artifactPaths: {
      request: "reviews/kimi/request.json",
      response: "reviews/kimi/response.json",
      content: "reviews/kimi/content.json",
      material: "reviews/kimi/material.json",
    },
    runtimeTrust: current.runtimeTrust,
  });
  const validateSchema = await compileSchema(receiptSchemaPath);
  assert.equal(validateSchema(receipt), true);

  const validation = await validateKimiIndependentModelReviewReceipt({
    receipt,
    policy,
    bundle,
    config: current.config,
    configBytes: current.configBytes,
    material: current.material,
    rawMaterialBytes: current.materialBytes,
    reviewBundleBytes: current.reviewBundleBytes,
    promptBytes: current.promptBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    receiptSchemaBytes: current.receiptSchemaBytes,
    runtimeManifestBytes: current.runtimeManifestBytes,
    requestBytes: current.requestBytes,
    responseBytes: transport.responseBytes,
    contentBytes: transport.contentBytes,
    snapshots,
    governanceSubjectBindings: current.governanceSubjectBindings,
    runtimeTrust: current.runtimeTrust,
  });
  assert.deepEqual(validation, {
    ok: true,
    status: "CLEAR",
    conclusion: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
    reasonCodes: [],
  });
  assert.equal(receipt.reviewer.reviewerProvider, "moonshot");
  assert.equal(receipt.reviewer.requestedModel, "kimi-k2.7-code");
  assert.equal(receipt.reviewer.actualReturnedModel, "kimi-k2.7-code");
  assert.equal(receipt.bindings.providerTransportSchemaSha256, null);
  assert.equal(receipt.isolationEvidence.toolsAbsent, true);
  assert.equal(receipt.isolationEvidence.toolChoiceNone, true);
  assert.equal(receipt.isolationEvidence.repositoryUnchanged, true);
  assert.equal(
    receipt.isolationEvidence.runtimeTrust.mode,
    "ANCESTOR_RUNTIME_COMMIT",
  );
  assert.notEqual(
    receipt.isolationEvidence.runtimeTrust.runtimeCommit,
    receipt.source.sourceCommit,
  );
  assert.equal(receipt.historicalTerraEvidenceAccepted, false);
  assert.equal(
    receipt.bindings.schemaValidatorVersion,
    `ajv@${installedAjvVersion}`,
  );
});

test("Receipt rejects byte, schema, semantic, model, source and legacy Terra substitutions", async () => {
  const current = await requestFixture();
  const output = clearOutput();
  const content = JSON.stringify(output);
  const transport = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    promptBytes: current.promptBytes,
    materialBytes: current.materialBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: runtimeApiKeyFixture(),
    fetchImpl: async () => responseObject(responseFor(content)),
  });
  const snapshots = {
    before: {
      head: commit("2"),
      tree: commit("4"),
      worktreeStatusSha256: digest("6"),
      worktreeContentManifestSha256: digest("5"),
      worktreePathCount: 42,
      protectedPathSetSha256: digest("7"),
      protectedFilesDigest: digest("8"),
      ignoredExclusionPolicySha256: digest("e"),
      ignoredExcludedPathCount: 3,
    },
    after: {
      head: commit("2"),
      tree: commit("4"),
      worktreeStatusSha256: digest("6"),
      worktreeContentManifestSha256: digest("5"),
      worktreePathCount: 42,
      protectedPathSetSha256: digest("7"),
      protectedFilesDigest: digest("8"),
      ignoredExclusionPolicySha256: digest("e"),
      ignoredExcludedPathCount: 3,
    },
  };
  const bundle = current.bundle;
  const policy = current.policy;
  const create = () =>
    createKimiIndependentModelReviewReceipt({
      receiptId: "imrr_kimi_fixture_001",
      policy,
      bundle,
      config: current.config,
      configBytes: current.configBytes,
      material: current.material,
      rawMaterialBytes: current.materialBytes,
      reviewBundleBytes: current.reviewBundleBytes,
      promptBytes: current.promptBytes,
      outputSchemaBytes: current.outputSchemaBytes,
      receiptSchemaBytes: current.receiptSchemaBytes,
      runtimeManifestBytes: current.runtimeManifestBytes,
      requestBytes: current.requestBytes,
      responseBytes: transport.responseBytes,
      contentBytes: transport.contentBytes,
      responseId: transport.responseId,
      actualReturnedModel: transport.actualReturnedModel,
      startedAt: "2026-07-30T10:00:00.000Z",
      finishedAt: "2026-07-30T10:00:01.000Z",
      snapshots,
      governanceSubjectBindings: current.governanceSubjectBindings,
      runtimeTrust: current.runtimeTrust,
      artifactPaths: {
        request: "reviews/kimi/request.json",
        response: "reviews/kimi/response.json",
        content: "reviews/kimi/content.json",
        material: "reviews/kimi/material.json",
      },
    });
  const receipt = await create();
  const base = {
    receipt,
    policy,
    bundle,
    config: current.config,
    configBytes: current.configBytes,
    material: current.material,
    rawMaterialBytes: current.materialBytes,
    reviewBundleBytes: current.reviewBundleBytes,
    promptBytes: current.promptBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    receiptSchemaBytes: current.receiptSchemaBytes,
    runtimeManifestBytes: current.runtimeManifestBytes,
    requestBytes: current.requestBytes,
    responseBytes: transport.responseBytes,
    contentBytes: transport.contentBytes,
    snapshots,
    governanceSubjectBindings: current.governanceSubjectBindings,
    runtimeTrust: current.runtimeTrust,
  };
  for (const change of [
    { responseBytes: Buffer.concat([transport.responseBytes, Buffer.from(" ")]) },
    { contentBytes: Buffer.from(JSON.stringify({ ...output, decision: "CLEAR", findings: [{ severity: "HIGH" }] })) },
    { promptBytes: Buffer.concat([current.promptBytes, Buffer.from(" ")]) },
    { outputSchemaBytes: Buffer.from("{}") },
    { receiptSchemaBytes: Buffer.from("{}") },
    {
      runtimeManifestBytes: Buffer.concat([
        current.runtimeManifestBytes,
        Buffer.from(" "),
      ]),
    },
    { bundle: { ...bundle, bundleSha256: digest("e") } },
    {
      runtimeTrust: {
        ...current.runtimeTrust,
        runtimeCommit: current.runtimeTrust.subjectCommit,
      },
    },
    {
      receipt: {
        ...receipt,
        reviewer: {
          ...receipt.reviewer,
          reviewerProvider: "openai",
          requestedModel: "gpt-5.6-terra",
          actualReturnedModel: "gpt-5.6-terra",
        },
      },
    },
  ]) {
    const result = await validateKimiIndependentModelReviewReceipt({
      ...base,
      ...change,
    });
    assert.equal(result.ok, false);
  }

  const parsedRequest = JSON.parse(current.requestBytes.toString("utf8"));
  for (const mutate of [
    (value) => {
      value.messages[0].content += "\nsubstituted prompt";
    },
    (value) => {
      value.messages[1].content += "\nsubstituted material";
    },
    (value) => {
      value.response_format.json_schema.schema = {
        type: "object",
        additionalProperties: false,
        properties: {},
        required: [],
      };
    },
  ]) {
    const candidateRequest = clone(parsedRequest);
    mutate(candidateRequest);
    const candidateRequestBytes = Buffer.from(
      JSON.stringify(candidateRequest),
      "utf8",
    );
    const candidateReceipt = clone(receipt);
    candidateReceipt.bindings.rawRequestArtifactSha256 =
      sha256Bytes(candidateRequestBytes);
    candidateReceipt.artifacts.request.byteLength =
      candidateRequestBytes.byteLength;
    candidateReceipt.artifacts.request.sha256 =
      sha256Bytes(candidateRequestBytes);
    candidateReceipt.receiptSha256 =
      await independentKimiReviewDigests.receipt(candidateReceipt);

    const result = await validateKimiIndependentModelReviewReceipt({
      ...base,
      receipt: candidateReceipt,
      requestBytes: candidateRequestBytes,
    });
    assert.equal(result.ok, false);
    assert.ok(
      result.reasonCodes.includes("KIMI_REQUEST_BINDING_MISMATCH"),
    );
  }

  const semanticOutput = {
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "A blocking issue remains open.",
    findings: [
      {
        findingId: "open_high_001",
        severity: "HIGH",
        status: "OPEN",
        path: "lib/example.mjs",
        startLine: 1,
        endLine: 1,
        summary: "The high-severity issue has not been resolved.",
        detailsSha256: digest("f"),
        resolutionEvidenceDigests: [],
      },
    ],
    decision: "CLEAR",
  };
  const semanticContentBytes = Buffer.from(
    JSON.stringify(semanticOutput),
    "utf8",
  );
  const semanticResponseBytes = Buffer.from(
    JSON.stringify(
      responseFor(semanticContentBytes.toString("utf8")),
    ),
    "utf8",
  );
  const semanticResult =
    await validateKimiIndependentModelReviewReceipt({
      ...base,
      responseBytes: semanticResponseBytes,
      contentBytes: semanticContentBytes,
    });
  assert.equal(semanticResult.ok, false);
  assert.ok(
    semanticResult.reasonCodes.includes(
      "KIMI_RECEIPT_OPEN_BLOCKING_FINDING",
    ),
  );

  const sameProviderBundle = clone(bundle);
  sameProviderBundle.implementationIdentity.provider = "moonshot";
  sameProviderBundle.bundleSha256 =
    await independentKimiReviewDigests.value(
      Object.fromEntries(
        Object.entries(sameProviderBundle).filter(
          ([key]) => key !== "bundleSha256",
        ),
      ),
    );
  await assert.rejects(
    createKimiIndependentModelReviewReceipt({
      ...base,
      receiptId: "imrr_kimi_same_provider",
      bundle: sameProviderBundle,
      receipt: undefined,
      responseId: transport.responseId,
      actualReturnedModel: transport.actualReturnedModel,
      startedAt: "2026-07-30T10:00:00.000Z",
      finishedAt: "2026-07-30T10:00:01.000Z",
      artifactPaths: {
        request: "reviews/kimi/request.json",
        response: "reviews/kimi/response.json",
        content: "reviews/kimi/content.json",
        material: "reviews/kimi/material.json",
      },
    }),
    /Receipt|Bundle|identity|provider/iu,
  );
});

test("logs and request artifacts never contain credentials or authorization fields", async () => {
  const current = await requestFixture();
  const requestText = current.requestBytes.toString("utf8");
  assert.equal(requestText.includes(runtimeApiKeyFixture()), false);
  const request = JSON.parse(requestText);
  assert.equal(Object.hasOwn(request, "authorization"), false);
  assert.equal(Object.hasOwn(request, "headers"), false);
  assert.equal(Object.hasOwn(request, "cookie"), false);
});

test("ordinary project-control and progress snapshot paths cannot invoke Kimi", async () => {
  for (const path of [
    "lib/project-control.mjs",
    "app/api/progress/route.ts",
  ]) {
    const text = await readFile(resolve(root, path), "utf8");
    assert.equal(text.includes("runKimiIndependentReview"), false);
    assert.equal(text.includes("executeKimiIndependentReview"), false);
    assert.equal(text.includes("MOONSHOT_API_KEY"), false);
  }
});
