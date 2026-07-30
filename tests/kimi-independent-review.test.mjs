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
  createKimiIndependentModelReviewReceipt,
  executeKimiIndependentReview,
  independentKimiReviewDigests,
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
  "implementation/governance/schemas/independent-review-test-result.v2.schema.json";
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
  "implementation/governance/independent-review/macos-independent-review-readonly.sb.in";
const promptPath =
  "implementation/governance/independent-review/independent-model-review-prompt.v2.md";
const PATCH_TEXT = "diff --git a/a b/a\n";
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

function clone(value) {
  return structuredClone(value);
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
  const reviewedPaths = ["lib/example.mjs"];
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
      bundleGeneratorSha256: artifactSha(bundleGeneratorPath),
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
      diffSha256: sha256Bytes(Buffer.from(PATCH_TEXT, "utf8")),
      changedPathsDigest:
        await independentKimiReviewDigests.value(reviewedPaths),
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
        blobSha256: digest("7"),
      },
    ],
    specificationSubjects: [
      { path: "AGENTS.md", blobSha256: digest("8") },
      {
        path: "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
        blobSha256: digest("9"),
      },
    ],
    testEvidenceSubjects: [
      {
        evidenceId: "targeted-tests",
        command: "node --test tests/kimi-independent-review.test.mjs",
        status: "PASS",
        exitCode: 0,
        outputRef: "evidence/targeted.json",
        outputSha256: digest("a"),
        outputByteLength: 1024,
        truncated: false,
        sourceCommit: commit("2"),
        runner: "GIT_FROZEN_ISOLATED_CLONE_CONTROL_PLANE",
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
  const configBytes = Buffer.from(JSON.stringify(config), "utf8");
  const sections = [
    section(
      "REVIEW_BUNDLE",
      "artifacts/review-bundle.json",
      JSON.stringify(bundle),
    ),
    section("PATCH", "artifacts/source.diff", PATCH_TEXT),
    section("SOURCE", "lib/example.mjs", "export const ok = true;\n"),
    section("SPECIFICATION", "AGENTS.md", "Review this specification.\n"),
    section("TEST_EVIDENCE", "evidence/targeted.json", '{"status":"PASS"}'),
    section(
      "GOVERNANCE",
      "artifacts/moonshot-kimi-model-visible-protocol.v1.json",
      JSON.stringify({
        schemaVersion: "moonshot-kimi-model-visible-protocol.v1",
        reviewerProvider: config.reviewerProvider,
        reviewerModel: config.reviewerModel,
        baseURL: config.baseURL,
        endpoint: config.endpoint,
        thinking: config.thinking,
        toolChoice: config.toolChoice,
        toolsOmitted: config.toolsOmitted,
        responseFormat: config.responseFormat,
        forbiddenRequestFields: config.forbiddenRequestFields,
        maxReviewMaterialUtf8Bytes:
          config.maxReviewMaterialUtf8Bytes,
        maxRequestUtf8Bytes: config.maxRequestUtf8Bytes,
        maxResponseUtf8Bytes: config.maxResponseUtf8Bytes,
        contextBudgetBasis: config.contextBudgetBasis,
        fallbackPolicy: config.fallbackPolicy,
      }),
    ),
    section(
      "GOVERNANCE",
      outputSchemaPath,
      new TextDecoder().decode(outputSchemaBytes),
    ),
    section(
      "GOVERNANCE",
      receiptSchemaPath,
      new TextDecoder().decode(receiptSchemaBytes),
    ),
  ];
  const material = {
    schemaVersion: "independent-review-material.v1",
    materialId: "irm_fixture_001",
    source: {
      baseCommit: bundle.source.baseCommit,
      sourceCommit: bundle.source.sourceCommit,
      sourceTree: bundle.source.tree,
      patchSha256: sections[1].sha256,
    },
    bindings: {
      reviewBundle: {
        path: sections[0].path,
        byteLength: sections[0].byteLength,
        sha256: sections[0].sha256,
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
    promptBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
  };
}

async function requestFixture() {
  const config = await readJson(configPath);
  const governance = await validBundleFixture();
  const material = await materialFixture(config, governance.bundle);
  const reviewBundleBytes = Buffer.from(
    JSON.stringify(governance.bundle),
    "utf8",
  );
  const request = await buildKimiIndependentReviewRequest({
    config,
    configBytes: material.configBytes,
    bundle: governance.bundle,
    reviewBundleBytes,
    promptBytes: material.promptBytes,
    materialBytes: material.materialBytes,
    outputSchemaBytes: material.outputSchemaBytes,
    receiptSchemaBytes: material.receiptSchemaBytes,
  });
  return {
    config,
    reviewBundleBytes,
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
    async arrayBuffer() {
      return bytes.buffer.slice(
        bytes.byteOffset,
        bytes.byteOffset + bytes.byteLength,
      );
    },
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
  const { material, materialBytes } = await materialFixture(config, bundle);

  assert.equal(validateSchema(material), true);
  assert.deepEqual(
    await validateIndependentReviewMaterial({
      material,
      rawMaterialBytes: materialBytes,
      expected: {
        sourceCommit: commit("2"),
        sourceTree: commit("4"),
        reviewBundleBytesSha256: material.bindings.reviewBundle.sha256,
        reviewBundleDigest: material.bindings.reviewBundle.bundleDigest,
        reviewerPromptSha256: material.bindings.reviewerPrompt.sha256,
        canonicalOutputSchemaSha256:
          material.bindings.canonicalOutputSchema.sha256,
        canonicalReceiptSchemaSha256:
          material.bindings.canonicalReceiptSchema.sha256,
        providerConfigSha256: material.bindings.providerConfig.sha256,
      },
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
        expected: {
          sourceCommit: commit("2"),
          sourceTree: commit("4"),
          reviewBundleBytesSha256: material.bindings.reviewBundle.sha256,
          reviewBundleDigest: material.bindings.reviewBundle.bundleDigest,
          reviewerPromptSha256: material.bindings.reviewerPrompt.sha256,
          canonicalOutputSchemaSha256:
            material.bindings.canonicalOutputSchema.sha256,
          canonicalReceiptSchemaSha256:
            material.bindings.canonicalReceiptSchema.sha256,
          providerConfigSha256: material.bindings.providerConfig.sha256,
        },
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
    expected: {
      sourceCommit: commit("2"),
      sourceTree: commit("4"),
      reviewBundleBytesSha256: material.bindings.reviewBundle.sha256,
      reviewBundleDigest: material.bindings.reviewBundle.bundleDigest,
      reviewerPromptSha256: material.bindings.reviewerPrompt.sha256,
      canonicalOutputSchemaSha256:
        material.bindings.canonicalOutputSchema.sha256,
      canonicalReceiptSchemaSha256:
        material.bindings.canonicalReceiptSchema.sha256,
      providerConfigSha256: material.bindings.providerConfig.sha256,
    },
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

test("missing credential fails before any network attempt", async () => {
  const current = await requestFixture();
  let networkCalls = 0;
  const result = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
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
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: "test-only-placeholder",
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
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey: "test-only-placeholder",
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
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey: "test-only-placeholder",
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
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: "test-only-placeholder",
    fetchImpl: async () =>
      responseObject({ error: { message: "not recorded" } }, 401),
  });
  assert.deepEqual(credentialOrBalance.reasonCodes, [
    "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
  ]);
});

test("redirects, tool responses, secret echo and body-read timeout fail closed", async () => {
  const current = await requestFixture();
  const apiKey = "test-only-runtime-credential-0123456789";
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
      outputSchemaBytes: current.outputSchemaBytes,
      apiKey,
      fetchImpl: async () => response,
    });
    assert.equal(result.ok, false);
    assert.equal(Object.hasOwn(result, "responseBytes"), false);
  }

  const slowBody = responseObject(responseFor(content));
  slowBody.arrayBuffer = async () =>
    new Promise((resolveBody) => {
      setTimeout(
        () =>
          resolveBody(
            Buffer.from(
              JSON.stringify(responseFor(content)),
              "utf8",
            ),
          ),
        50,
      );
    });
  const timedOut = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: current.requestBytes,
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey,
    fetchImpl: async () => slowBody,
    timeoutMs: 5,
  });
  assert.equal(timedOut.ok, false);
  assert.ok(timedOut.reasonCodes.includes("KIMI_TRANSPORT_TIMEOUT"));
});

test("credentials cannot enter the request or survive decoded response inspection", async () => {
  const current = await requestFixture();
  const apiKey = "test-only-runtime-credential-0123456789";
  const request = JSON.parse(current.requestBytes.toString("utf8"));
  request.messages[0].content += `\n${apiKey}`;
  let requestNetworkCalls = 0;
  const requestLeak = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: Buffer.from(JSON.stringify(request), "utf8"),
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
  const apiKey = "test-only-runtime-credential-0123456789";
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
  const apiKey = "test-only-runtime-credential-0123456789";
  const request = JSON.parse(current.requestBytes.toString("utf8"));
  request.messages[0].content += "\ud800";
  let networkCalls = 0;
  const invalidRequest = await executeKimiIndependentReview({
    config: current.config,
    requestBytes: Buffer.from(JSON.stringify(request), "utf8"),
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
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: "test-only-placeholder",
    fetchImpl: async () => responseObject(responseFor(content)),
  });
  const snapshots = {
    before: {
      head: commit("2"),
      tree: commit("4"),
      worktreeStatusSha256: digest("6"),
      protectedPathSetSha256: digest("7"),
      protectedFilesDigest: digest("8"),
    },
    after: {
      head: commit("2"),
      tree: commit("4"),
      worktreeStatusSha256: digest("6"),
      protectedPathSetSha256: digest("7"),
      protectedFilesDigest: digest("8"),
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
    requestBytes: current.requestBytes,
    responseBytes: transport.responseBytes,
    contentBytes: transport.contentBytes,
    responseId: transport.responseId,
    actualReturnedModel: transport.actualReturnedModel,
    startedAt: "2026-07-30T10:00:00.000Z",
    finishedAt: "2026-07-30T10:00:01.000Z",
    snapshots,
    artifactPaths: {
      request: "reviews/kimi/request.json",
      response: "reviews/kimi/response.json",
      content: "reviews/kimi/content.json",
      material: "reviews/kimi/material.json",
    },
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
    requestBytes: current.requestBytes,
    responseBytes: transport.responseBytes,
    contentBytes: transport.contentBytes,
    snapshots,
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
    outputSchemaBytes: current.outputSchemaBytes,
    apiKey: "test-only-placeholder",
    fetchImpl: async () => responseObject(responseFor(content)),
  });
  const snapshots = {
    before: {
      head: commit("2"),
      tree: commit("4"),
      worktreeStatusSha256: digest("6"),
      protectedPathSetSha256: digest("7"),
      protectedFilesDigest: digest("8"),
    },
    after: {
      head: commit("2"),
      tree: commit("4"),
      worktreeStatusSha256: digest("6"),
      protectedPathSetSha256: digest("7"),
      protectedFilesDigest: digest("8"),
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
      requestBytes: current.requestBytes,
      responseBytes: transport.responseBytes,
      contentBytes: transport.contentBytes,
      responseId: transport.responseId,
      actualReturnedModel: transport.actualReturnedModel,
      startedAt: "2026-07-30T10:00:00.000Z",
      finishedAt: "2026-07-30T10:00:01.000Z",
      snapshots,
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
    requestBytes: current.requestBytes,
    responseBytes: transport.responseBytes,
    contentBytes: transport.contentBytes,
    snapshots,
  };
  for (const change of [
    { responseBytes: Buffer.concat([transport.responseBytes, Buffer.from(" ")]) },
    { contentBytes: Buffer.from(JSON.stringify({ ...output, decision: "CLEAR", findings: [{ severity: "HIGH" }] })) },
    { promptBytes: Buffer.concat([current.promptBytes, Buffer.from(" ")]) },
    { outputSchemaBytes: Buffer.from("{}") },
    { receiptSchemaBytes: Buffer.from("{}") },
    { bundle: { ...bundle, bundleSha256: digest("e") } },
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
  assert.equal(requestText.includes("test-only-placeholder"), false);
  const request = JSON.parse(requestText);
  assert.equal(Object.hasOwn(request, "authorization"), false);
  assert.equal(Object.hasOwn(request, "headers"), false);
  assert.equal(Object.hasOwn(request, "cookie"), false);
  assert.equal(requestText.includes("MOONSHOT_API_KEY"), false);
  assert.equal(requestText.includes("kimi-p2-independent-review"), false);
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
