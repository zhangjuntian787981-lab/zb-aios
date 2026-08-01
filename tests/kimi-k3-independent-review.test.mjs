import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  buildKimiK3IndependentReviewRequest,
  buildKimiK3TokenEstimateRequest,
  createKimiK3ChatDiagnosticArtifactsV1,
  createKimiK3ChatDiagnosticArtifactsV2,
  createKimiK3TokenEstimateDiagnosticArtifactsV2,
  createKimiK3TokenEstimateDiagnosticEvidence,
  createKimiK3TokenEstimateDiagnosticEvidenceV2,
  createKimiK3TokenEstimateEvidence,
  evaluateKimiK3SingleCallPreflight,
  executeKimiK3ChatCompletion,
  executeKimiK3TokenEstimate,
  kimiK3Digests,
  kimiK3ReviewMaterialGovernancePaths,
  kimiK3ReviewMaterialPaths,
  kimiK3ReviewMaterialPathsV3,
  validateKimiK3ChatDiagnosticEvidenceV1,
  validateKimiK3ChatDiagnosticEvidenceV2,
  validateKimiK3TokenEstimateDiagnosticEvidence,
  validateKimiK3TokenEstimateDiagnosticEvidenceV2,
  validateKimiK3ChatResponse,
  validateKimiK3TokenEstimateEvidence,
  validateMoonshotKimiK3Config,
  validateMoonshotKimiK3TransportSchema,
} from "../lib/kimi-k3-independent-review.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);
const configPath = resolve(
  root,
  "implementation/governance/independent-review/moonshot-kimi-k3.v3.json",
);
const configSchemaPath = resolve(
  root,
  "implementation/governance/schemas/moonshot-kimi-independent-review-config.v3.schema.json",
);
const tokenEstimateDiagnosticSchemaV1Path = resolve(
  root,
  "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v1.schema.json",
);
const tokenEstimateDiagnosticSchemaV2Path = resolve(
  root,
  "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v2.schema.json",
);
const chatDiagnosticSchemaV1Path = resolve(
  root,
  "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v1.schema.json",
);
const chatDiagnosticSchemaV2Path = resolve(
  root,
  "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v2.schema.json",
);
const canonicalOutputSchemaPath = resolve(
  root,
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
);
const providerTransportSchemaPath = resolve(
  root,
  "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json",
);

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function fileSha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function compileSchema(path) {
  const schema = await readJson(path);
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

function clone(value) {
  return structuredClone(value);
}

function bytes(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function k3TokenEstimateResponse(totalTokens, overrides = {}) {
  return {
    code: 0,
    data: { total_tokens: totalTokens },
    scode: "0x0",
    status: true,
    ...overrides,
  };
}

function responseObject(url, body, status = 200, headers = {}) {
  const bodyBytes = Buffer.isBuffer(body) ? body : bytes(body);
  return {
    redirected: false,
    url,
    status,
    headers: new Headers({
      "content-type": "application/json",
      "content-encoding": "identity",
      ...headers,
    }),
    body: new ReadableStream({
      start(controller) {
        controller.enqueue(bodyBytes);
        controller.close();
      },
    }),
  };
}

const outputSchema = {
  type: "object",
  additionalProperties: false,
  required: ["decision", "findings"],
  properties: {
    decision: {
      type: "string",
      enum: ["CLEAR", "BLOCKED", "INCONCLUSIVE"],
    },
    findings: { type: "array", items: { type: "string" } },
  },
};

test("K3 v3 config separates resource ceilings from context proof", async () => {
  const config = await readJson(configPath);
  const validateSchema = await compileSchema(configSchemaPath);

  assert.equal(validateSchema(config), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(await validateMoonshotKimiK3Config(config), {
    ok: true,
    reasonCodes: [],
  });
  assert.equal(config.reviewerProvider, "moonshot");
  assert.equal(config.reviewerModel, "kimi-k3");
  assert.equal(config.contextWindowTokens, 1_048_576);
  assert.equal(config.reasoningEffort, "max");
  assert.equal(Object.hasOwn(config, "thinking"), false);
  assert.equal(config.toolChoice, "none");
  assert.equal(config.toolsOmitted, true);
  assert.equal(config.responseFormat.strict, true);
  assert.equal(config.maxCompletionTokens, 32_768);
  assert.equal(config.safetyMarginTokens, 8_192);
  assert.equal(config.nonMessageVisibleTokenReserve, 65_536);
  assert.equal(config.nonMessageVisibleInputMaxUtf8Bytes, 16_384);
  assert.equal(config.maxReviewMaterialUtf8Bytes, 4_194_304);
  assert.equal(config.maxRequestUtf8Bytes, 8_388_608);
  assert.equal(config.maxResponseUtf8Bytes, 1_048_576);
  assert.equal(
    config.contextBudgetBasis,
    "TRANSPORT_RESOURCE_CEILING_ONLY_NOT_CONTEXT_PROOF",
  );
  assert.equal(config.taxExclusiveBudgetMicros, 4_000_000);
  assert.equal(config.fallbackPolicy, "DISABLED_FAIL_CLOSED");
  assert.equal(
    kimiK3ReviewMaterialPaths.materialSchema,
    "implementation/governance/schemas/independent-review-material.v4.schema.json",
  );
  assert.equal(
    kimiK3ReviewMaterialPaths.config,
    "implementation/governance/independent-review/moonshot-kimi-k3.v3.json",
  );
  assert.equal(
    kimiK3ReviewMaterialPaths.receiptSchema,
    "implementation/governance/schemas/independent-model-review-receipt.v6.schema.json",
  );
  assert.equal(
    kimiK3ReviewMaterialPaths.providerTransportSchema,
    "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json",
  );
  assert.equal(
    kimiK3ReviewMaterialPathsV3.receiptSchema,
    "implementation/governance/schemas/independent-model-review-receipt.v5.schema.json",
  );
  assert.equal(
    kimiK3ReviewMaterialGovernancePaths.includes(
      "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/historical-evidence-index.v1.json",
    ),
    true,
  );
  assert.equal(config.configSha256, kimiK3Digests.config(config));
  assert.equal(
    config.officialContract.researchSha256,
    kimiK3Digests.bytes(
      await readFile(resolve(root, config.officialContract.researchPath)),
    ),
  );
});

test("K2.7 v1 artifacts remain byte-identical historical evidence", async () => {
  const expected = new Map([
    [
      "implementation/governance/independent-review/moonshot-kimi-k2.7-code.v1.json",
      "9bac1965f984e8fa028d1cae89287b090e025b6b8fcd06a1e5c20190ca29970c",
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-independent-review-config.v1.schema.json",
      "6b2b0e8befd6b5fa396a6e6725cfc0b2bb115981166e1ef61767b89086d05dfb",
    ],
    [
      "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json",
      "2abedd0c606327f7329fdfeae0406cf90ae15963d8d7067e07d5464685f33911",
    ],
    [
      "docs/adr/0012-moonshot-kimi-independent-review-transport.md",
      "19f888122b8a14f51411a04cc7662dd374a3d69580bbc86dd730089bf04bf792",
    ],
    [
      "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
      "d67eea5b02e683b2d899a66f851236dd380a948009429e40ce5a97cf0db7c565",
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-independent-review-config.v2.schema.json",
      "5a5c14cc479b72547848529bc4079ab8d28ab5d7d6ee521e16a61c125e5ecaab",
    ],
    [
      "implementation/governance/schemas/independent-model-review-receipt.v4.schema.json",
      "9f02f8a0e5af7165efe194dd9760c7322109272ee98c255f816557dc9e1698af",
    ],
    [
      "implementation/governance/schemas/independent-review-transport-evidence.v2.schema.json",
      "5c85a5040c1c32a2b06cddeb3a718129e342fee7808355c278eb7354a75bae8e",
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v1.schema.json",
      "852417a37db7cb0394d683b8d0c5ab82f14d770fdcb754e0c0164f06cf418637",
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v1.schema.json",
      "6a7e87bfd379c959a864af02a4cec72fcb1fc57f79cebc8554b831c5f1ba45c5",
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v1.schema.json",
      "0ccd5764ee25472a54f2928beb0acb42e9f516c08eb7a434965ac28458712a52",
    ],
    [
      "docs/adr/0013-moonshot-kimi-k3-single-call-transport.md",
      "acc350ba628b8e7023670b485d67f21ba2408712f57f405170a0a99a3a7ef438",
    ],
  ]);
  for (const [path, sha256] of expected) {
    assert.equal(await fileSha256(resolve(root, path)), sha256, path);
  }
  assert.deepEqual(
    await validateMoonshotKimiK3Config(
      await readJson(
        resolve(
          root,
          "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
        ),
      ),
    ),
    { ok: true, reasonCodes: [] },
  );
  await assertFrozenK3ContractAndFailedAttempt();
});

test("formal v4 orchestration estimates once, proves dual-Schema evidence, then chats once without fallback", async () => {
  const [runnerSource, bootstrapSource] = await Promise.all([
    readFile(resolve(root, "scripts/run-kimi-independent-review.mjs"), "utf8"),
    readFile(resolve(root, "scripts/bootstrap-kimi-independent-review.mjs"), "utf8"),
  ]);
  assert.equal(runnerSource.includes('"material.v4.utf8"'), true);
  assert.equal(
    runnerSource.indexOf("KIMI_K3_REVIEW_MATERIAL_V4_SCHEMA_INVALID") <
      runnerSource.indexOf("await credentialProvider()"),
    true,
  );
  assert.equal(
    runnerSource.indexOf("KIMI_K3_DUAL_OUTPUT_SCHEMA_PREFLIGHT_FAILED") <
      runnerSource.indexOf("await credentialProvider()"),
    true,
  );
  assert.equal(bootstrapSource.includes("kimi-runtime-manifest.v1.json"), false);
  assert.equal(bootstrapSource.includes("kimi-runtime-manifest.v2.json"), true);
  const estimateIndex = runnerSource.indexOf(
    "const estimate = await executeKimiK3TokenEstimate",
  );
  const preflightIndex = runnerSource.indexOf(
    "evaluateKimiK3SingleCallPreflight({",
    estimateIndex,
  );
  const preflightFailureIndex = runnerSource.indexOf(
    "if (!preflight.ok)",
    preflightIndex,
  );
  const estimateEvidenceIndex = runnerSource.indexOf(
    "createKimiK3TokenEstimateEvidenceV2({",
    preflightFailureIndex,
  );
  const chatIndex = runnerSource.indexOf(
    "await executeKimiK3ChatCompletion({",
    estimateEvidenceIndex,
  );
  const chatDiagnosticV2Index = runnerSource.indexOf(
    "createKimiK3ChatDiagnosticArtifactsV2({",
    chatIndex,
  );
  const chatDiagnosticIndex = runnerSource.indexOf(
    "createKimiK3ChatDiagnosticArtifactsV1({",
    chatDiagnosticV2Index,
  );
  const chatDiagnosticWriteIndex = runnerSource.indexOf(
    "await writeArtifacts(",
    chatDiagnosticIndex,
  );
  const chatDiagnosticReadbackIndex = runnerSource.indexOf(
    "await verifyArtifactReadback(",
    chatDiagnosticWriteIndex,
  );
  const chatFailureReturnIndex = runnerSource.indexOf(
    'reasonCodes: ["KIMI_K3_REVIEW_NOT_PROVED"]',
    chatDiagnosticReadbackIndex,
  );
  const transportEvidenceIndex = runnerSource.indexOf(
    "const transportEvidence = isK3V4",
    chatIndex,
  );
  const receiptIndex = runnerSource.indexOf(
    "const receipt = createReceipt({",
    transportEvidenceIndex,
  );
  assert.ok(estimateIndex > 0);
  assert.ok(preflightIndex > estimateIndex);
  assert.ok(preflightFailureIndex > preflightIndex);
  assert.ok(estimateEvidenceIndex > preflightFailureIndex);
  assert.ok(chatIndex > estimateEvidenceIndex);
  assert.ok(chatDiagnosticV2Index > chatIndex);
  assert.ok(chatDiagnosticIndex > chatDiagnosticV2Index);
  assert.ok(chatDiagnosticWriteIndex > chatDiagnosticIndex);
  assert.ok(chatDiagnosticReadbackIndex > chatDiagnosticWriteIndex);
  assert.ok(chatFailureReturnIndex > chatDiagnosticReadbackIndex);
  assert.ok(transportEvidenceIndex > chatIndex);
  assert.ok(receiptIndex > transportEvidenceIndex);
  assert.match(
    runnerSource,
    /\[fixedPaths\.outputSchema\]: outputSchemaBytes/u,
  );
  assert.match(
    runnerSource,
    /providerTransportSchemaBytes:\s*formalOutputSchemaBytes/u,
  );
  assert.match(
    runnerSource,
    /canonicalOutputSchemaBytes:\s*outputSchemaBytes/u,
  );
  assert.match(
    runnerSource,
    /providerTransportSchemaPath:\s*fixedPaths\.providerTransportSchema/u,
  );
  assert.match(
    runnerSource,
    /canonicalOutputSchemaPath:\s*fixedPaths\.outputSchema/u,
  );
  assert.match(runnerSource, /let tokenEstimateAttemptCount = 0/u);
  assert.match(runnerSource, /let chatCompletionAttemptCount = 0/u);
  assert.match(runnerSource, /K3_V2_HISTORICAL/u);
  assert.match(runnerSource, /K3_V3_CANDIDATE/u);
  assert.match(runnerSource, /K3_V4_CANDIDATE/u);
  assert.match(
    runnerSource,
    /enforceProviderTransportSchema:\s*isK3V4/u,
  );
  assert.equal(
    runnerSource.match(/enforceProviderTransportSchema:\s*isK3V4/gu)
      ?.length,
    2,
  );
  assert.match(runnerSource, /if \(isK3V3 \|\| isK3V4\)/u);
  assert.match(
    runnerSource,
    /if \(!isK3V3 && !isK3V4 && isK3\)/u,
  );
  assert.match(runnerSource, /KIMI_K3_MFJS_V4_CONTRACT_INCOMPLETE/u);
  assert.equal(runnerSource.includes("kimi-k2.7-code-highspeed"), false);
  assert.match(runnerSource, /KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED/u);
  assert.match(runnerSource, /KIMI_K3_REVIEW_NOT_PROVED/u);
  assert.match(
    bootstrapSource,
    /chatDiagnosticEvidenceSha256:\s*result\.chatDiagnosticEvidenceSha256/u,
  );
  assert.match(
    bootstrapSource,
    /transportReasonCodes:\s*result\.transportReasonCodes/u,
  );
  const config = await readJson(configPath);
  const canonicalOutputSchemaBytes = await readFile(canonicalOutputSchemaPath);
  await assert.rejects(
    buildKimiK3IndependentReviewRequest({
      config,
      promptBytes: Buffer.from("prompt", "utf8"),
      materialBytes: Buffer.from("material", "utf8"),
      outputSchemaBytes: canonicalOutputSchemaBytes,
    }),
  );
  const historical = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes: Buffer.from("material", "utf8"),
    outputSchemaBytes: canonicalOutputSchemaBytes,
    enforceProviderTransportSchema: false,
  });
  assert.deepEqual(
    JSON.parse(historical.requestBytes.toString("utf8")).response_format
      .json_schema.schema,
    JSON.parse(canonicalOutputSchemaBytes.toString("utf8")),
  );
  await assertRunnerDiagnosticMapping();
});

test("K3 config rejects identity, protocol, limit and fallback drift", async () => {
  const config = await readJson(configPath);
  for (const mutate of [
    (value) => (value.reviewerModel = "kimi-k2.7-code"),
    (value) => (value.reviewerModel = "kimi-k2.7-code-highspeed"),
    (value) => (value.baseURL = "https://api.kimi.com/coding/v1"),
    (value) => (value.reasoningEffort = "high"),
    (value) => (value.toolChoice = "auto"),
    (value) => (value.toolsOmitted = false),
    (value) => (value.responseFormat.strict = false),
    (value) => (value.maxCompletionTokens = 32_767),
    (value) => (value.contextWindowTokens = 1_000_000),
    (value) => (value.fallbackPolicy = "AUTO"),
    (value) => (value.officialContract.modelUrl = "https://attacker.invalid/models"),
    (value) => (value.officialContract.chatUrl = "https://attacker.invalid/chat"),
    (value) =>
      (value.officialContract.tokenEstimateUrl =
        "https://attacker.invalid/estimate"),
    (value) =>
      (value.officialContract.structuredOutputUrl =
        "https://attacker.invalid/structured"),
    (value) =>
      (value.officialContract.pricingUrl = "https://attacker.invalid/pricing"),
    (value) =>
      (value.officialContract.researchSha256 = `sha256:${"1".repeat(64)}`),
  ]) {
    const candidate = clone(config);
    mutate(candidate);
    candidate.configSha256 = kimiK3Digests.config(candidate);
    assert.equal((await validateMoonshotKimiK3Config(candidate)).ok, false);
  }
});

test("K3 formal request has exactly the fixed single-call fields", async () => {
  const config = await readJson(configPath);
  const promptBytes = Buffer.from("review exactly these frozen bytes", "utf8");
  const materialBytes = Buffer.from("frozen review material", "utf8");
  const canonicalOutputSchemaBytes = await readFile(canonicalOutputSchemaPath);
  const outputSchemaBytes = await readFile(providerTransportSchemaPath);
  assert.deepEqual(
    validateMoonshotKimiK3TransportSchema(outputSchemaBytes),
    { ok: true, reasonCodes: [] },
  );
  const built = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes,
    materialBytes,
    outputSchemaBytes,
  });
  const request = JSON.parse(built.requestBytes.toString("utf8"));

  assert.deepEqual(Object.keys(request), [
    "model",
    "messages",
    "reasoning_effort",
    "tool_choice",
    "response_format",
    "max_completion_tokens",
  ]);
  assert.equal(request.model, "kimi-k3");
  assert.equal(request.reasoning_effort, "max");
  assert.equal(request.tool_choice, "none");
  assert.equal(Object.hasOwn(request, "thinking"), false);
  assert.equal(Object.hasOwn(request, "tools"), false);
  assert.equal(request.response_format.type, "json_schema");
  assert.equal(request.response_format.json_schema.strict, true);
  assert.deepEqual(
    request.response_format.json_schema.schema,
    JSON.parse(outputSchemaBytes.toString("utf8")),
  );
  assert.notDeepEqual(
    request.response_format.json_schema.schema,
    JSON.parse(canonicalOutputSchemaBytes.toString("utf8")),
  );
  assert.equal(
    request.response_format.json_schema.schema.$defs.finding.properties.status
      .type,
    "string",
  );
  assert.equal(
    Object.hasOwn(request.response_format.json_schema.schema, "$schema"),
    false,
  );
  assert.equal(
    validateMoonshotKimiK3TransportSchema(canonicalOutputSchemaBytes).ok,
    false,
  );
  for (const mutate of [
    (value) => {
      for (const key of Object.keys(value)) delete value[key];
    },
    (value) => delete value.type,
    (value) => delete value.additionalProperties,
    (value) => value.required.pop(),
    (value) => {
      value.properties.findings = { type: "array" };
    },
    (value) => {
      value.properties.findings = {
        type: "string",
        items: { type: "string" },
      };
    },
    (value) => delete value.$defs.finding.properties.status.type,
    (value) => (value.$schema = "https://json-schema.org/draft/2020-12/schema"),
    (value) => (value.$defs.path = { type: ["string", "null"] }),
    (value) =>
      (value.$defs.finding.properties.path.$ref = "#/$defs/missing"),
    (value) => {
      value.$defs.cycleA = { $ref: "#/$defs/cycleB" };
      value.$defs.cycleB = { $ref: "#/$defs/cycleA" };
    },
  ]) {
    const changed = JSON.parse(outputSchemaBytes.toString("utf8"));
    mutate(changed);
    assert.equal(
      validateMoonshotKimiK3TransportSchema(bytes(changed)).ok,
      false,
    );
  }
  assert.equal(request.max_completion_tokens, 32_768);
  assert.equal(built.requestSha256, kimiK3Digests.bytes(built.requestBytes));
  const nonMessage = { ...request };
  delete nonMessage.messages;
  const expectedNonMessageBytes = Buffer.from(
    JSON.stringify(nonMessage, Object.keys(nonMessage).sort()),
    "utf8",
  );
  assert.equal(built.nonMessageVisibleInputByteLength > 0, true);
  assert.equal(
    built.nonMessageVisibleInputByteLength <=
      config.nonMessageVisibleInputMaxUtf8Bytes,
    true,
  );
  assert.equal(
    built.nonMessageVisibleInputSha256,
    kimiK3Digests.bytes(built.nonMessageVisibleInputBytes),
  );
  assert.equal(
    built.nonMessageVisibleInputByteLength,
    built.nonMessageVisibleInputBytes.byteLength,
  );
  assert.equal(expectedNonMessageBytes.byteLength > 0, true);
});

test("K3 token estimate request contains the exact formal messages only", async () => {
  const config = await readJson(configPath);
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes: Buffer.from("material", "utf8"),
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  const formalObject = JSON.parse(formal.requestBytes.toString("utf8"));
  const estimateObject = JSON.parse(estimate.requestBytes.toString("utf8"));

  assert.deepEqual(Object.keys(estimateObject), ["model", "messages"]);
  assert.equal(estimateObject.model, "kimi-k3");
  assert.deepEqual(estimateObject.messages, formalObject.messages);
  assert.equal(
    estimate.messagesSha256,
    kimiK3Digests.bytes(
      Buffer.from(JSON.stringify(formalObject.messages), "utf8"),
    ),
  );
  assert.equal(
    estimate.coverage,
    "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE",
  );
  assert.equal(
    estimate.nonMessageVisibleInputSha256,
    formal.nonMessageVisibleInputSha256,
  );
  assert.equal(
    estimate.nonMessageVisibleInputByteLength,
    formal.nonMessageVisibleInputByteLength,
  );
});

test("K3 estimate rejects any mutated formal request contract", async () => {
  const config = await readJson(configPath);
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes: Buffer.from("material", "utf8"),
    outputSchemaBytes: bytes(outputSchema),
  });
  const original = JSON.parse(formal.requestBytes.toString("utf8"));
  for (const mutate of [
    (value) => delete value.reasoning_effort,
    (value) => (value.reasoning_effort = "high"),
    (value) => (value.thinking = { type: "enabled" }),
    (value) => (value.tool_choice = "auto"),
    (value) => (value.tools = []),
    (value) => (value.response_format.json_schema.strict = false),
    (value) => (value.model = "kimi-k2.7-code"),
  ]) {
    const changed = clone(original);
    mutate(changed);
    assert.throws(() =>
      buildKimiK3TokenEstimateRequest({
        config,
        formalRequestBytes: bytes(changed),
      }),
    );
  }
});

test("K3 material, request and response byte defenses fail closed", async () => {
  const config = await readJson(configPath);
  const [providerTransportSchemaBytes, canonicalOutputSchemaBytes] =
    await Promise.all([
      readFile(providerTransportSchemaPath),
      readFile(canonicalOutputSchemaPath),
    ]);
  await assert.rejects(
    buildKimiK3IndependentReviewRequest({
      config,
      promptBytes: Buffer.from("prompt", "utf8"),
      materialBytes: Buffer.alloc(config.maxReviewMaterialUtf8Bytes + 1, 0x61),
      outputSchemaBytes: providerTransportSchemaBytes,
    }),
  );
  await assert.rejects(
    buildKimiK3IndependentReviewRequest({
      config,
      promptBytes: Buffer.alloc(config.maxRequestUtf8Bytes + 1, 0x61),
      materialBytes: Buffer.from("material", "utf8"),
      outputSchemaBytes: providerTransportSchemaBytes,
    }),
  );
  const responseWithReasoning = (reasoningLength) =>
    bytes({
      id: "chatcmpl_kimi_k3_byte_defense",
      object: "chat.completion",
      created: 1785513600,
      model: "kimi-k3",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: JSON.stringify({
              schemaVersion: "independent-model-review-output.v2",
              reviewSummary: "No blocking finding.",
              findings: [],
              decision: "CLEAR",
            }),
            reasoning_content: "r".repeat(reasoningLength),
          },
          finish_reason: "stop",
        },
      ],
      usage: {
        prompt_tokens: 1,
        completion_tokens: 1,
        total_tokens: 2,
        cached_tokens: 0,
      },
    });
  const responseOverhead = responseWithReasoning(0).byteLength;
  const withinLimit = responseWithReasoning(
    config.maxResponseUtf8Bytes - responseOverhead,
  );
  const beyondLimit = responseWithReasoning(
    config.maxResponseUtf8Bytes - responseOverhead + 1,
  );
  assert.equal(withinLimit.byteLength, config.maxResponseUtf8Bytes);
  assert.equal(
    (
      await validateKimiK3ChatResponse({
        config,
        responseBytes: withinLimit,
        providerTransportSchemaBytes,
        canonicalOutputSchemaBytes,
      })
    ).ok,
    true,
  );
  assert.equal(beyondLimit.byteLength, config.maxResponseUtf8Bytes + 1);
  assert.equal(
    (
      await validateKimiK3ChatResponse({
        config,
        responseBytes: beyondLimit,
        providerTransportSchemaBytes,
        canonicalOutputSchemaBytes,
      })
    ).ok,
    false,
  );
});

test("K3 preflight uses the safe additive context boundary", async () => {
  const config = await readJson(configPath);
  const binding = `sha256:${"a".repeat(64)}`;
  const common = {
    config,
    estimateCoverage: "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE",
    estimateBindings: {
      formalRequestSha256: binding,
      messagesSha256: binding,
      materialSha256: binding,
      nonMessageVisibleInputSha256: binding,
      nonMessageVisibleInputByteLength: 1024,
    },
    expectedBindings: {
      formalRequestSha256: binding,
      messagesSha256: binding,
      materialSha256: binding,
      nonMessageVisibleInputSha256: binding,
      nonMessageVisibleInputByteLength: 1024,
    },
    pricingObservedAt: "2026-08-01T00:00:00.000Z",
  };
  assert.equal(
    evaluateKimiK3SingleCallPreflight({
      ...common,
      estimatedMessageInputTokens: 942_080,
    }).ok,
    true,
  );
  const rejected = evaluateKimiK3SingleCallPreflight({
    ...common,
    estimatedMessageInputTokens: 942_081,
  });
  assert.equal(rejected.ok, false);
  assert.deepEqual(rejected.reasonCodes, [
    "KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED",
  ]);
});

test("K3 preflight rejects incomplete coverage and every exact binding drift", async () => {
  const config = await readJson(configPath);
  const binding = `sha256:${"a".repeat(64)}`;
  const other = `sha256:${"b".repeat(64)}`;
  const base = {
    config,
    estimatedMessageInputTokens: 100,
    estimateCoverage: "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE",
    estimateBindings: {
      formalRequestSha256: binding,
      messagesSha256: binding,
      materialSha256: binding,
      nonMessageVisibleInputSha256: binding,
      nonMessageVisibleInputByteLength: 1024,
    },
    expectedBindings: {
      formalRequestSha256: binding,
      messagesSha256: binding,
      materialSha256: binding,
      nonMessageVisibleInputSha256: binding,
      nonMessageVisibleInputByteLength: 1024,
    },
    pricingObservedAt: "2026-08-01T00:00:00.000Z",
  };
  for (const override of [
    { estimateCoverage: "MESSAGES_ONLY" },
    { pricingObservedAt: "2026-07-31T23:59:59.999Z" },
    {
      estimateBindings: {
        ...base.estimateBindings,
        formalRequestSha256: other,
      },
    },
    {
      estimateBindings: {
        ...base.estimateBindings,
        nonMessageVisibleInputSha256: other,
      },
    },
    {
      estimateBindings: {
        ...base.estimateBindings,
        nonMessageVisibleInputByteLength: 16_385,
      },
    },
  ]) {
    const result = evaluateKimiK3SingleCallPreflight({
      ...base,
      ...override,
    });
    assert.equal(result.ok, false);
    assert.deepEqual(result.reasonCodes, [
      "KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED",
    ]);
  }
});

test("missing estimate credential fails before a network attempt", async () => {
  const config = await readJson(configPath);
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes: Buffer.from("material", "utf8"),
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  let calls = 0;
  const result = await executeKimiK3TokenEstimate({
    config,
    estimateRequestBytes: estimate.requestBytes,
    formalRequestBytes: formal.requestBytes,
    materialBytes: Buffer.from("material", "utf8"),
    apiKey: "",
    fetchImpl: async () => {
      calls += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(calls, 0);
  assert.deepEqual(result.reasonCodes, [
    "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
  ]);
  assert.equal(result.networkAttemptCount, 0);
});

test("token estimate binds exact endpoint, request bytes and response bytes", async () => {
  const config = await readJson(configPath);
  const materialBytes = Buffer.from("material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes,
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  let captured;
  const result = await executeKimiK3TokenEstimate({
    config,
    estimateRequestBytes: estimate.requestBytes,
    formalRequestBytes: formal.requestBytes,
    materialBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async (url, init) => {
      captured = { url, init };
      return responseObject(url, {
        code: 0,
        data: { total_tokens: 1234 },
        scode: "0x0",
        status: true,
      });
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.estimatedInputTokens, 1234);
  assert.equal(result.networkAttemptCount, 1);
  assert.equal(
    captured.url,
    "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
  );
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.init.headers["accept-encoding"], "identity");
  assert.deepEqual(Buffer.from(captured.init.body), estimate.requestBytes);
  assert.equal(result.responseSha256, kimiK3Digests.bytes(result.responseBytes));
  assert.equal(
    result.coverage,
    "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE",
  );
  assert.deepEqual(result.diagnostic, {
    responseReceived: true,
    httpStatus: 200,
    contentType: "application/json",
    contentEncoding: "identity",
    contentTypeObservedValid: true,
    contentEncodingObservedValid: true,
    responseEndpointMatched: true,
    bodyRepresentation: "APPLICATION_LAYER_DECODED_BYTES",
    responseBodyComplete: true,
    responseBodyByteLength: result.responseBytes.byteLength,
    responseBodySha256: result.responseSha256,
    jsonParsed: true,
    schemaValidated: true,
    semanticValidated: true,
    failureStage: null,
    reasonCode: null,
  });
  await assertNon200DiagnosticCapture();
});

async function assertNon200DiagnosticCapture() {
  const config = await readJson(configPath);
  const materialBytes = Buffer.from("material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes,
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  const responseBytes = bytes({ error: { code: "service_unavailable" } });
  const result = await executeKimiK3TokenEstimate({
    config,
    estimateRequestBytes: estimate.requestBytes,
    formalRequestBytes: formal.requestBytes,
    materialBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async (url) => responseObject(url, responseBytes, 503),
  });

  assert.equal(result.ok, false);
  assert.equal(result.networkAttemptCount, 1);
  assert.deepEqual(result.diagnostic, {
    responseReceived: true,
    httpStatus: 503,
    contentType: "application/json",
    contentEncoding: "identity",
    contentTypeObservedValid: true,
    contentEncodingObservedValid: true,
    responseEndpointMatched: true,
    bodyRepresentation: "APPLICATION_LAYER_DECODED_BYTES",
    responseBodyComplete: true,
    responseBodyByteLength: responseBytes.byteLength,
    responseBodySha256: kimiK3Digests.bytes(responseBytes),
    jsonParsed: true,
    schemaValidated: false,
    semanticValidated: false,
    failureStage: "HTTP_STATUS",
    reasonCode: "KIMI_K3_RESPONSE_HTTP_INVALID",
  });
  assert.deepEqual(result.responseBytes, responseBytes);
}

async function assertTokenEstimateDiagnosticEvidence() {
  const responseBytes = bytes({ error: { code: "service_unavailable" } });
  const input = {
    requestSha256: `sha256:${"1".repeat(64)}`,
    messagesSha256: `sha256:${"2".repeat(64)}`,
    reviewMaterialSha256: `sha256:${"3".repeat(64)}`,
    sourceCommit: "4".repeat(40),
    requestedModel: "kimi-k3",
    endpoint:
      "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
    diagnostic: {
      responseReceived: true,
      httpStatus: 503,
      contentType: "application/json",
      contentEncoding: "identity",
      contentTypeObservedValid: true,
      contentEncodingObservedValid: true,
      responseEndpointMatched: true,
      bodyRepresentation: "APPLICATION_LAYER_DECODED_BYTES",
      responseBodyByteLength: responseBytes.byteLength,
      responseBodySha256: kimiK3Digests.bytes(responseBytes),
      jsonParsed: false,
      schemaValidated: false,
      semanticValidated: false,
      failureStage: "HTTP_STATUS",
      reasonCode: "KIMI_K3_RESPONSE_HTTP_INVALID",
    },
    responseArtifact: null,
    recordedAt: "2026-07-31T12:00:00.000Z",
  };
  const evidence = createKimiK3TokenEstimateDiagnosticEvidence(input);
  const validateSchema = await compileSchema(
    tokenEstimateDiagnosticSchemaV1Path,
  );

  assert.equal(validateSchema(evidence), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(
    validateKimiK3TokenEstimateDiagnosticEvidence({
      ...input,
      evidence,
      responseArtifactBytes: null,
    }),
    { ok: true, reasonCodes: [] },
  );
  const tampered = clone(evidence);
  tampered.responseBodySha256 = `sha256:${"0".repeat(64)}`;
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidence({
      ...input,
      evidence: tampered,
      responseArtifactBytes: null,
    }).ok,
    false,
  );
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidence({
      ...input,
      evidence,
      responseArtifactBytes: responseBytes,
    }).ok,
    false,
  );
  const stageMismatch = clone(evidence);
  stageMismatch.failureStage = "JSON_PARSE";
  stageMismatch.evidenceSha256 = kimiK3Digests.value({
    ...stageMismatch,
    evidenceSha256: `sha256:${"0".repeat(64)}`,
  });
  assert.equal(validateSchema(stageMismatch), false);
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidence({
      ...input,
      evidence: stageMismatch,
      responseArtifactBytes: null,
    }).ok,
    false,
  );
  const extra = { ...evidence, authorization: "forbidden" };
  assert.equal(validateSchema(extra), false);

  const noResponseInput = {
    ...input,
    diagnostic: {
      responseReceived: false,
      httpStatus: null,
      contentType: null,
      contentEncoding: null,
      contentTypeObservedValid: null,
      contentEncodingObservedValid: null,
      responseEndpointMatched: null,
      bodyRepresentation: "APPLICATION_LAYER_DECODED_BYTES",
      responseBodyByteLength: null,
      responseBodySha256: null,
      jsonParsed: false,
      schemaValidated: false,
      semanticValidated: false,
      failureStage: "TRANSPORT",
      reasonCode: "KIMI_K3_TRANSPORT_TIMEOUT",
    },
    responseArtifact: null,
  };
  const noResponseEvidence =
    createKimiK3TokenEstimateDiagnosticEvidence(noResponseInput);
  assert.equal(validateSchema(noResponseEvidence), true);
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidence({
      ...noResponseInput,
      evidence: noResponseEvidence,
    }).ok,
    true,
  );

  const successfulBytes = bytes({ data: { total_tokens: 1234 } });
  const successfulInput = {
    ...input,
    diagnostic: {
      responseReceived: true,
      httpStatus: 200,
      contentType: "application/json",
      contentEncoding: "identity",
      contentTypeObservedValid: true,
      contentEncodingObservedValid: true,
      responseEndpointMatched: true,
      bodyRepresentation: "APPLICATION_LAYER_DECODED_BYTES",
      responseBodyByteLength: successfulBytes.byteLength,
      responseBodySha256: kimiK3Digests.bytes(successfulBytes),
      jsonParsed: true,
      schemaValidated: true,
      semanticValidated: true,
      failureStage: null,
      reasonCode: null,
    },
    responseArtifact: "token-estimate-diagnostic-response.bin",
  };
  const successfulEvidence =
    createKimiK3TokenEstimateDiagnosticEvidence(successfulInput);
  assert.equal(validateSchema(successfulEvidence), true);
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidence({
      ...successfulInput,
      evidence: successfulEvidence,
      responseArtifactBytes: successfulBytes,
    }).ok,
    true,
  );
  const semanticallyInvalidBytes = bytes({ data: { total_tokens: -1 } });
  const forgedSuccess = createKimiK3TokenEstimateDiagnosticEvidence({
    ...successfulInput,
    diagnostic: {
      ...successfulInput.diagnostic,
      responseBodyByteLength: semanticallyInvalidBytes.byteLength,
      responseBodySha256: kimiK3Digests.bytes(semanticallyInvalidBytes),
    },
  });
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidence({
      ...successfulInput,
      diagnostic: {
        ...successfulInput.diagnostic,
        responseBodyByteLength: semanticallyInvalidBytes.byteLength,
        responseBodySha256: kimiK3Digests.bytes(semanticallyInvalidBytes),
      },
      evidence: forgedSuccess,
      responseArtifactBytes: semanticallyInvalidBytes,
    }).ok,
    false,
  );
  for (const diagnostic of [
    {
      ...successfulInput.diagnostic,
      failureStage: "TRANSPORT",
      reasonCode: "KIMI_K3_TRANSPORT_NETWORK_FAILED",
    },
    {
      ...successfulInput.diagnostic,
      failureStage: "REQUEST_BINDING",
      reasonCode: "KIMI_K3_TRANSPORT_CONFIGURATION_INVALID",
    },
    {
      ...input.diagnostic,
      reasonCode: "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
    },
    {
      ...successfulInput.diagnostic,
      failureStage: "RESPONSE_METADATA",
      reasonCode: "KIMI_K3_RESPONSE_CONTENT_TYPE_INVALID",
    },
  ]) {
    const impossibleInput = {
      ...input,
      diagnostic,
      responseArtifact: null,
    };
    const impossibleEvidence =
      createKimiK3TokenEstimateDiagnosticEvidence(impossibleInput);
    assert.equal(
      validateKimiK3TokenEstimateDiagnosticEvidence({
        ...impossibleInput,
        evidence: impossibleEvidence,
      }).ok,
      false,
    );
  }
}

async function assertTokenEstimateDiagnosticEvidenceV2() {
  const binding = {
    requestSha256: `sha256:${"1".repeat(64)}`,
    messagesSha256: `sha256:${"2".repeat(64)}`,
    reviewMaterialSha256: `sha256:${"3".repeat(64)}`,
    sourceCommit: "4".repeat(40),
    requestedModel: "kimi-k3",
    endpoint:
      "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
    recordedAt: "2026-08-01T00:00:00.000Z",
  };
  const validateSchema = await compileSchema(
    tokenEstimateDiagnosticSchemaV2Path,
  );
  const observedSuccessBytes = Buffer.from(
    '{"code":0,"data":{"total_tokens":333404},"scode":"0x0","status":true}',
    "utf8",
  );
  assert.equal(observedSuccessBytes.byteLength, 69);
  assert.equal(
    kimiK3Digests.bytes(observedSuccessBytes),
    "sha256:629424d9377d6af0e6083e2acd2862188032b37f8bfd14734ed74de2727289c1",
  );
  const cases = [
    {
      body: bytes({ error: { code: "service_unavailable" } }),
      diagnostic: {
        httpStatus: 503,
        progress: [true, false, false],
        failureStage: "HTTP_STATUS",
        reasonCode: "KIMI_K3_RESPONSE_HTTP_INVALID",
      },
    },
    {
      body: Buffer.from("not-json", "utf8"),
      diagnostic: {
        httpStatus: 200,
        progress: [false, false, false],
        failureStage: "JSON_PARSE",
        reasonCode: "KIMI_K3_TOKEN_ESTIMATE_JSON_INVALID",
      },
    },
    {
      body: bytes({ ...k3TokenEstimateResponse(1), extra: true }),
      diagnostic: {
        httpStatus: 200,
        progress: [true, false, false],
        failureStage: "SCHEMA_VALIDATION",
        reasonCode: "KIMI_K3_TOKEN_ESTIMATE_RESPONSE_SCHEMA_INVALID",
      },
    },
    {
      body: bytes(k3TokenEstimateResponse(-1)),
      diagnostic: {
        httpStatus: 200,
        progress: [true, true, false],
        failureStage: "SEMANTIC_VALIDATION",
        reasonCode: "KIMI_K3_TOKEN_ESTIMATE_RESPONSE_SEMANTIC_INVALID",
      },
    },
    {
      body: observedSuccessBytes,
      diagnostic: {
        httpStatus: 200,
        progress: [true, true, true],
        failureStage: null,
        reasonCode: null,
      },
    },
    {
      body: Buffer.alloc(0),
      diagnostic: {
        httpStatus: 200,
        progress: [false, false, false],
        failureStage: "BODY_CAPTURE",
        reasonCode: "KIMI_K3_RESPONSE_BYTES_UNAVAILABLE",
      },
    },
  ];
  let schemaFailurePrepared;
  for (const entry of cases) {
    const [jsonParsed, schemaValidated, semanticValidated] =
      entry.diagnostic.progress;
    const input = {
      ...binding,
      diagnostic: {
        responseReceived: true,
        httpStatus: entry.diagnostic.httpStatus,
        contentType: "application/json",
        contentEncoding: "identity",
        contentTypeObservedValid: true,
        contentEncodingObservedValid: true,
        responseEndpointMatched: true,
        bodyRepresentation: "APPLICATION_LAYER_DECODED_BYTES",
        responseBodyComplete: true,
        responseBodyByteLength: entry.body.byteLength,
        responseBodySha256: kimiK3Digests.bytes(entry.body),
        jsonParsed,
        schemaValidated,
        semanticValidated,
        failureStage: entry.diagnostic.failureStage,
        reasonCode: entry.diagnostic.reasonCode,
      },
      responseBytes: entry.body,
    };
    const prepared = createKimiK3TokenEstimateDiagnosticArtifactsV2(input);
    assert.equal(
      validateSchema(prepared.evidence),
      true,
      JSON.stringify(validateSchema.errors),
    );
    assert.deepEqual(
      prepared.artifacts["token-estimate-diagnostic-response.bin"],
      entry.body,
    );
    assert.deepEqual(
      validateKimiK3TokenEstimateDiagnosticEvidenceV2({
        ...input,
        evidence: prepared.evidence,
        responseArtifact: prepared.evidence.responseArtifact,
        responseArtifactBytes: entry.body,
      }),
      { ok: true, reasonCodes: [] },
    );
    if (entry.diagnostic.failureStage === "SCHEMA_VALIDATION") {
      schemaFailurePrepared = { input, prepared };
    }
  }

  const missingArtifact = createKimiK3TokenEstimateDiagnosticEvidenceV2({
    ...schemaFailurePrepared.input,
    responseArtifact: null,
  });
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidenceV2({
      ...schemaFailurePrepared.input,
      evidence: missingArtifact,
      responseArtifact: null,
      responseArtifactBytes: null,
    }).ok,
    false,
  );
  const incompleteSafeResponseInput = {
    ...schemaFailurePrepared.input,
    diagnostic: {
      ...schemaFailurePrepared.input.diagnostic,
      responseBodyComplete: false,
    },
  };
  const incompleteSafeResponse =
    createKimiK3TokenEstimateDiagnosticEvidenceV2({
      ...incompleteSafeResponseInput,
      responseArtifact: null,
    });
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidenceV2({
      ...incompleteSafeResponseInput,
      evidence: incompleteSafeResponse,
      responseArtifact: null,
      responseArtifactBytes: null,
    }).ok,
    false,
  );
  for (const mutate of [
    (value) => (value.responseArtifact = "other-response.bin"),
    (value) => (value.responseBodyByteLength += 1),
    (value) => (value.responseBodySha256 = `sha256:${"0".repeat(64)}`),
    (value) => (value.jsonParsed = false),
  ]) {
    const changed = clone(schemaFailurePrepared.prepared.evidence);
    mutate(changed);
    changed.evidenceSha256 = kimiK3Digests.value({
      ...changed,
      evidenceSha256: `sha256:${"0".repeat(64)}`,
    });
    assert.equal(
      validateKimiK3TokenEstimateDiagnosticEvidenceV2({
        ...schemaFailurePrepared.input,
        evidence: changed,
        responseArtifact: changed.responseArtifact,
        responseArtifactBytes: schemaFailurePrepared.input.responseBytes,
      }).ok,
      false,
    );
  }
  const changedBytes = Buffer.from(
    schemaFailurePrepared.input.responseBytes,
  );
  changedBytes[0] ^= 1;
  assert.equal(
    validateKimiK3TokenEstimateDiagnosticEvidenceV2({
      ...schemaFailurePrepared.input,
      evidence: schemaFailurePrepared.prepared.evidence,
      responseArtifact:
        schemaFailurePrepared.prepared.evidence.responseArtifact,
      responseArtifactBytes: changedBytes,
    }).ok,
    false,
  );

  const unsafeBody = bytes({ secret: "must-not-enter-git" });
  const unsafeInput = {
    ...binding,
    diagnostic: {
      responseReceived: true,
      httpStatus: 200,
      contentType: "application/json",
      contentEncoding: "identity",
      contentTypeObservedValid: true,
      contentEncodingObservedValid: true,
      responseEndpointMatched: true,
      bodyRepresentation: "APPLICATION_LAYER_DECODED_BYTES",
      responseBodyComplete: true,
      responseBodyByteLength: unsafeBody.byteLength,
      responseBodySha256: kimiK3Digests.bytes(unsafeBody),
      jsonParsed: true,
      schemaValidated: false,
      semanticValidated: false,
      failureStage: "SCHEMA_VALIDATION",
      reasonCode: "KIMI_K3_TOKEN_ESTIMATE_RESPONSE_SCHEMA_INVALID",
    },
    responseBytes: unsafeBody,
  };
  assert.throws(
    () => createKimiK3TokenEstimateDiagnosticArtifactsV2(unsafeInput),
    /diagnostic evidence v2 is invalid/u,
  );
  const escapedSensitiveKeyBody = Buffer.from(
    '{"\\u0061uthorization":"masked-value"}',
    "utf8",
  );
  assert.throws(
    () =>
      createKimiK3TokenEstimateDiagnosticArtifactsV2({
        ...unsafeInput,
        diagnostic: {
          ...unsafeInput.diagnostic,
          responseBodyByteLength: escapedSensitiveKeyBody.byteLength,
          responseBodySha256: kimiK3Digests.bytes(escapedSensitiveKeyBody),
        },
        responseBytes: escapedSensitiveKeyBody,
      }),
    /diagnostic evidence v2 is invalid/u,
  );
  for (const compoundSensitiveKeyBody of [
    bytes({ client_secret: "masked-value" }),
    Buffer.from('{"session\\u005ftoken":"masked-value"}', "utf8"),
    bytes({ clientSecret: "masked-value" }),
    Buffer.from('{"session\\u0054oken":"masked-value"}', "utf8"),
    bytes({ "request.headers": "masked-value" }),
  ]) {
    assert.throws(
      () =>
        createKimiK3TokenEstimateDiagnosticArtifactsV2({
          ...unsafeInput,
          diagnostic: {
            ...unsafeInput.diagnostic,
            responseBodyByteLength: compoundSensitiveKeyBody.byteLength,
            responseBodySha256: kimiK3Digests.bytes(
              compoundSensitiveKeyBody,
            ),
          },
          responseBytes: compoundSensitiveKeyBody,
        }),
      /diagnostic evidence v2 is invalid/u,
    );
  }
  assert.throws(
    () =>
      createKimiK3TokenEstimateDiagnosticArtifactsV2({
        ...schemaFailurePrepared.input,
        diagnostic: {
          ...schemaFailurePrepared.input.diagnostic,
          contentType: "authorization bearer forbidden",
        },
      }),
    /diagnostic evidence v2 is invalid/u,
  );
}

async function assertHttpAndParsingFailureDiagnostics() {
  const config = await readJson(configPath);
  const materialBytes = Buffer.from("material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes,
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  const apiKey = "unit-test-credential-outside-artifacts";
  const cases = [
    ...[400, 401, 403, 429, 500, 503].map((status) => ({
      status,
      body: bytes({ error: { code: `http_${status}` } }),
      stage: "HTTP_STATUS",
      progress: [true, false, false],
    })),
    {
      status: 200,
      body: Buffer.from("not-json", "utf8"),
      stage: "JSON_PARSE",
      progress: [false, false, false],
    },
    {
      status: 200,
      body: Buffer.from(
        '{"data":{"total_tokens":1,"total_tokens":2}}',
        "utf8",
      ),
      stage: "JSON_PARSE",
      progress: [false, false, false],
    },
    {
      status: 200,
      body: bytes({ ...k3TokenEstimateResponse(1), extra: true }),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    },
    {
      status: 200,
      body: bytes({
        ...k3TokenEstimateResponse(1),
        data: { total_tokens: 1, extra: true },
      }),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    },
    {
      status: 200,
      body: bytes({ ...k3TokenEstimateResponse(1), data: {} }),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    },
    ...["1", 1.5, Number.MAX_SAFE_INTEGER + 1].map((total_tokens) => ({
      status: 200,
      body: bytes({
        ...k3TokenEstimateResponse(1),
        data: { total_tokens },
      }),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    })),
    {
      status: 200,
      body: bytes(k3TokenEstimateResponse(-1)),
      stage: "SEMANTIC_VALIDATION",
      progress: [true, true, false],
    },
    ...[
      k3TokenEstimateResponse(1, { code: 1 }),
      k3TokenEstimateResponse(1, { scode: "0x1" }),
      k3TokenEstimateResponse(1, { status: false }),
    ].map((body) => ({
      status: 200,
      body: bytes(body),
      stage: "SEMANTIC_VALIDATION",
      progress: [true, true, false],
    })),
    ...[
      k3TokenEstimateResponse(1, { code: "0" }),
      k3TokenEstimateResponse(1, { scode: 0 }),
      k3TokenEstimateResponse(1, { status: "true" }),
    ].map((body) => ({
      status: 200,
      body: bytes(body),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    })),
    {
      status: 200,
      body: bytes({ data: { total_tokens: 1 } }),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    },
    {
      status: 200,
      body: bytes(k3TokenEstimateResponse(1)),
      stage: "RESPONSE_METADATA",
      headers: { "content-encoding": "gzip" },
      progress: [true, true, true],
    },
    {
      status: 200,
      body: Buffer.alloc(0),
      stage: "BODY_CAPTURE",
      progress: [false, false, false],
    },
    {
      status: 200,
      body: bytes([]),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    },
    {
      status: 200,
      body: bytes(1),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    },
    {
      status: 200,
      body: Buffer.from(
        `${"[".repeat(5_000)}0${"]".repeat(5_000)}`,
        "utf8",
      ),
      stage: "SCHEMA_VALIDATION",
      progress: [true, false, false],
    },
  ];

  for (const entry of cases) {
    let calls = 0;
    const result = await executeKimiK3TokenEstimate({
      config,
      estimateRequestBytes: estimate.requestBytes,
      formalRequestBytes: formal.requestBytes,
      materialBytes,
      apiKey,
      fetchImpl: async (url) => {
        calls += 1;
        return responseObject(
          url,
          entry.body,
          entry.status,
          entry.headers,
        );
      },
    });
    assert.equal(result.ok, false);
    assert.equal(calls, 1);
    assert.equal(result.networkAttemptCount, 1);
    assert.equal(result.diagnostic.responseReceived, true);
    assert.equal(result.diagnostic.httpStatus, entry.status);
    assert.equal(result.diagnostic.failureStage, entry.stage);
    assert.equal(
      result.diagnostic.responseBodyByteLength,
      entry.body.byteLength,
    );
    assert.equal(
      result.diagnostic.responseBodySha256,
      kimiK3Digests.bytes(entry.body),
    );
    assert.deepEqual(
      [
        result.diagnostic.jsonParsed,
        result.diagnostic.schemaValidated,
        result.diagnostic.semanticValidated,
      ],
      entry.progress,
    );
    assert.deepEqual(result.responseBytes, entry.body);
    const artifacts = createKimiK3TokenEstimateDiagnosticArtifactsV2({
      requestSha256: kimiK3Digests.bytes(estimate.requestBytes),
      messagesSha256: estimate.messagesSha256,
      reviewMaterialSha256: kimiK3Digests.bytes(materialBytes),
      sourceCommit: "4".repeat(40),
      requestedModel: "kimi-k3",
      endpoint:
        "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
      diagnostic: result.diagnostic,
      responseBytes: result.responseBytes,
      recordedAt: "2026-08-01T00:00:00.000Z",
    });
    assert.deepEqual(
      artifacts.artifacts["token-estimate-diagnostic-response.bin"],
      entry.body,
    );
  }

  for (const illegalEncoding of [
    "Bearer injected-secret",
    "identity\r\nset-cookie: forbidden",
    Symbol("throw-header-read"),
  ]) {
    const body = bytes(k3TokenEstimateResponse(1));
    const result = await executeKimiK3TokenEstimate({
      config,
      estimateRequestBytes: estimate.requestBytes,
      formalRequestBytes: formal.requestBytes,
      materialBytes,
      apiKey,
      fetchImpl: async (url) => ({
        ...responseObject(url, body),
        headers: {
          get(name) {
            if (
              name === "content-encoding" &&
              typeof illegalEncoding === "symbol"
            ) {
              throw new Error("synthetic header read failure");
            }
            return name === "content-type"
              ? "application/json"
              : illegalEncoding;
          },
        },
      }),
    });
    assert.equal(result.ok, false);
    assert.equal(result.diagnostic.failureStage, "RESPONSE_METADATA");
    assert.equal(
      result.diagnostic.reasonCode,
      "KIMI_K3_RESPONSE_CONTENT_ENCODING_INVALID",
    );
    assert.equal(result.diagnostic.contentEncoding, null);
    assert.deepEqual(result.responseBytes, body);
    assert.deepEqual(
      [
        result.diagnostic.jsonParsed,
        result.diagnostic.schemaValidated,
        result.diagnostic.semanticValidated,
      ],
      [true, true, true],
    );
  }
}

async function assertStreamAndBoundaryFailures() {
  const config = await readJson(configPath);
  const materialBytes = Buffer.from("material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes,
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  const execute = (fetchImpl, timeoutMs = 120_000) =>
    executeKimiK3TokenEstimate({
      config,
      estimateRequestBytes: estimate.requestBytes,
      formalRequestBytes: formal.requestBytes,
      materialBytes,
      apiKey: "unit-test-credential-outside-artifacts",
      fetchImpl,
      timeoutMs,
    });
  const diagnosticArtifactsFor = (result) =>
    createKimiK3TokenEstimateDiagnosticArtifactsV2({
      requestSha256: kimiK3Digests.bytes(estimate.requestBytes),
      messagesSha256: estimate.messagesSha256,
      reviewMaterialSha256: kimiK3Digests.bytes(materialBytes),
      sourceCommit: "4".repeat(40),
      requestedModel: "kimi-k3",
      endpoint:
        "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
      diagnostic: result.diagnostic,
      responseBytes: result.responseBytes,
      recordedAt: "2026-08-01T00:00:00.000Z",
    });
  const assertNoResponseArtifact = (result) => {
    const prepared = diagnosticArtifactsFor(result);
    assert.equal(prepared.evidence.responseArtifact, null);
    assert.equal(
      Object.hasOwn(
        prepared.artifacts,
        "token-estimate-diagnostic-response.bin",
      ),
      false,
    );
  };
  let calls = 0;
  const chunkedBytes = bytes(k3TokenEstimateResponse(1234));
  const chunked = await execute(async (url) => {
    calls += 1;
    return {
      ...responseObject(url, chunkedBytes),
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(chunkedBytes.subarray(0, 7));
          controller.enqueue(chunkedBytes.subarray(7));
          controller.close();
        },
      }),
    };
  });
  assert.equal(chunked.ok, true);
  assert.equal(chunked.estimatedInputTokens, 1234);
  assert.deepEqual(chunked.responseBytes, chunkedBytes);
  assert.deepEqual(
    diagnosticArtifactsFor(chunked).artifacts[
      "token-estimate-diagnostic-response.bin"
    ],
    chunkedBytes,
  );
  assert.equal(calls, 1);

  const interrupted = await execute(async (url) => {
    calls += 1;
    return {
      ...responseObject(url, Buffer.alloc(0)),
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(Buffer.from("{", "utf8"));
          controller.error(new Error("synthetic interruption"));
        },
      }),
    };
  });
  assert.equal(interrupted.ok, false);
  assert.equal(interrupted.diagnostic.responseReceived, true);
  assert.equal(interrupted.diagnostic.responseBodyByteLength, 0);
  assert.equal(
    interrupted.diagnostic.responseBodySha256,
    kimiK3Digests.bytes(Buffer.alloc(0)),
  );
  assert.equal(interrupted.responseBytes, null);
  assert.equal(interrupted.diagnostic.responseBodyComplete, false);
  assertNoResponseArtifact(interrupted);

  const oversized = await execute(async (url) => {
    calls += 1;
    return responseObject(url, Buffer.alloc(64 * 1024 + 1, 0x61));
  });
  assert.equal(oversized.ok, false);
  assert.equal(oversized.diagnostic.responseReceived, true);
  assert.equal(oversized.diagnostic.responseBodyByteLength, 64 * 1024);
  assert.equal(oversized.diagnostic.responseBodyComplete, false);
  assertNoResponseArtifact(oversized);

  const cancelRejected = await execute(async (url) => {
    calls += 1;
    let served = false;
    return {
      ...responseObject(url, Buffer.alloc(0)),
      body: {
        getReader() {
          return {
            async read() {
              if (served) return { done: true };
              served = true;
              return {
                done: false,
                value: Buffer.alloc(64 * 1024 + 1, 0x62),
              };
            },
            async cancel() {
              throw new Error("synthetic cancel rejection");
            },
            releaseLock() {},
          };
        },
      },
    };
  });
  assert.deepEqual(cancelRejected.reasonCodes, [
    "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED",
  ]);
  assert.equal(
    cancelRejected.diagnostic.responseBodyByteLength,
    64 * 1024,
  );
  assertNoResponseArtifact(cancelRejected);

  const cancelNeverSettles = await Promise.race([
    execute(async (url) => {
      calls += 1;
      return {
        ...responseObject(url, Buffer.alloc(0)),
        body: {
          getReader() {
            return {
              async read() {
                return {
                  done: false,
                  value: Buffer.alloc(64 * 1024 + 1, 0x63),
                };
              },
              cancel() {
                return new Promise(() => {});
              },
              releaseLock() {},
            };
          },
        },
      };
    }),
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error("reader.cancel blocked byte-limit evidence")),
        50,
      ),
    ),
  ]);
  assert.deepEqual(cancelNeverSettles.reasonCodes, [
    "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED",
  ]);
  assertNoResponseArtifact(cancelNeverSettles);

  const timedOut = await execute(async () => {
    calls += 1;
    return new Promise(() => {});
  }, 5);
  assert.equal(timedOut.ok, false);
  assert.equal(timedOut.diagnostic.responseReceived, false);
  assert.equal(timedOut.diagnostic.httpStatus, null);
  assertNoResponseArtifact(timedOut);

  const redirected = await execute(async () => {
    calls += 1;
    return {
      ...responseObject("https://attacker.invalid/redirect", {}),
      redirected: true,
    };
  });
  assert.equal(redirected.ok, false);
  assert.equal(redirected.diagnostic.responseReceived, true);
  assert.equal(redirected.diagnostic.failureStage, "RESPONSE_ENDPOINT");
  assert.equal(redirected.diagnostic.responseBodyByteLength, 2);
  assert.equal(redirected.responseBytes, null);
  assert.equal(redirected.diagnostic.responseBodyComplete, true);
  assertNoResponseArtifact(redirected);
  assert.equal(calls, 7);
}

async function assertSensitiveResponsePrivacy() {
  const config = await readJson(configPath);
  const materialBytes = Buffer.from("material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes,
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  const apiKey = "unit-test-credential-outside-artifacts";
  const sensitiveBodies = [
    {
      body: Buffer.from(
        JSON.stringify({ authorization: `Bearer ${apiKey}` }),
        "utf8",
      ),
      status: 200,
    },
    {
      body: Buffer.from(
        '{"error":{"message":"unit-test-credenti\\u0061l-outside-artifacts"}}',
        "utf8",
      ),
      status: 200,
    },
    {
      body: Buffer.from('{"\\u0061uthorization":"masked-value"}', "utf8"),
      status: 503,
    },
    {
      body: Buffer.from(
        '{"error":"safe","error":"unit-test-credenti\\u0061l-outside-artifacts"}',
        "utf8",
      ),
      status: 200,
    },
    ...[
      "token",
      "credential",
      "secret",
      "password",
      "client_secret",
      "session_token",
      "set_cookie",
      "authorization_header",
      "private_key",
      "service_api_key",
      "contact_email",
      "inbound_request_headers",
      "accessToken",
      "clientSecret",
      "sessionToken",
      "setCookie",
      "authorizationHeader",
      "privateKey",
      "serviceApiKey",
      "contactEmail",
      "inboundRequestHeaders",
      "request.headers",
      "account_id",
      "user_id",
      "tenant_id",
      "request_headers",
    ].map((key) => ({
      body: bytes({ [key]: "redacted-value" }),
      status: 200,
    })),
    {
      body: Buffer.from('{"client\\u005fsecret":"redacted-value"}', "utf8"),
      status: 200,
    },
    {
      body: Buffer.from('{"client\\u0053ecret":"redacted-value"}', "utf8"),
      status: 200,
    },
    { body: bytes({ session_token: "redacted-value" }), status: 503 },
    { body: bytes({ sessionToken: "redacted-value" }), status: 503 },
    { body: Buffer.from([0xff, 0xfe, 0x00]), status: 200 },
  ];
  for (const { body: echoed, status } of sensitiveBodies) {
    const result = await executeKimiK3TokenEstimate({
      config,
      estimateRequestBytes: estimate.requestBytes,
      formalRequestBytes: formal.requestBytes,
      materialBytes,
      apiKey,
      fetchImpl: async (url) => ({
        ...responseObject(url, echoed, status),
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(echoed.subarray(0, 1));
            controller.enqueue(echoed.subarray(1));
            controller.close();
          },
        }),
      }),
    });

    assert.equal(result.ok, false);
    assert.equal(result.responseBytes, null);
    assert.equal(result.diagnostic.responseBodyByteLength, echoed.byteLength);
    assert.equal(
      result.diagnostic.responseBodySha256,
      kimiK3Digests.bytes(echoed),
    );
    assert.equal(
      result.diagnostic.reasonCode,
      "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED",
    );
    assert.equal(result.diagnostic.responseBodyComplete, true);
    const prepared = createKimiK3TokenEstimateDiagnosticArtifactsV2({
      requestSha256: kimiK3Digests.bytes(estimate.requestBytes),
      messagesSha256: estimate.messagesSha256,
      reviewMaterialSha256: kimiK3Digests.bytes(materialBytes),
      sourceCommit: "4".repeat(40),
      requestedModel: "kimi-k3",
      endpoint:
        "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
      diagnostic: result.diagnostic,
      responseBytes: result.responseBytes,
      recordedAt: "2026-08-01T00:00:00.000Z",
    });
    assert.equal(prepared.evidence.responseArtifact, null);
    assert.equal(
      Object.hasOwn(
        prepared.artifacts,
        "token-estimate-diagnostic-response.bin",
      ),
      false,
    );
    assert.equal(JSON.stringify(result).includes(apiKey), false);
    assert.equal(JSON.stringify(prepared).includes(apiKey), false);
  }
}

async function assertRunnerDiagnosticMapping() {
  const responseBytes = bytes({ error: { code: "service_unavailable" } });
  const input = {
    requestSha256: `sha256:${"1".repeat(64)}`,
    messagesSha256: `sha256:${"2".repeat(64)}`,
    reviewMaterialSha256: `sha256:${"3".repeat(64)}`,
    sourceCommit: "4".repeat(40),
    requestedModel: "kimi-k3",
    endpoint:
      "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
    diagnostic: {
      responseReceived: true,
      httpStatus: 503,
      contentType: "application/json",
      contentEncoding: "identity",
      contentTypeObservedValid: true,
      contentEncodingObservedValid: true,
      responseEndpointMatched: true,
      bodyRepresentation: "APPLICATION_LAYER_DECODED_BYTES",
      responseBodyComplete: true,
      responseBodyByteLength: responseBytes.byteLength,
      responseBodySha256: kimiK3Digests.bytes(responseBytes),
      jsonParsed: true,
      schemaValidated: false,
      semanticValidated: false,
      failureStage: "HTTP_STATUS",
      reasonCode: "KIMI_K3_RESPONSE_HTTP_INVALID",
    },
    responseBytes,
    recordedAt: "2026-07-31T12:00:00.000Z",
  };
  const prepared = createKimiK3TokenEstimateDiagnosticArtifactsV2(input);
  const evidenceBytes = prepared.artifacts[
    "token-estimate-diagnostic-evidence.json"
  ];
  const parsed = JSON.parse(evidenceBytes.toString("utf8"));

  assert.deepEqual(
    prepared.artifacts["token-estimate-diagnostic-response.bin"],
    responseBytes,
  );
  assert.equal(parsed.evidenceSha256, prepared.evidence.evidenceSha256);
  assert.equal(parsed.httpStatus, 503);
  assert.equal(JSON.stringify(prepared).includes("authorization"), false);
  assert.equal(JSON.stringify(prepared).includes("apiKey"), false);
  const validateExactSchema = await compileSchema(
    tokenEstimateDiagnosticSchemaV2Path,
  );
  assert.equal(validateExactSchema(prepared.evidence), true);
  assert.deepEqual(
    validateKimiK3TokenEstimateDiagnosticEvidenceV2({
      ...input,
      evidence: prepared.evidence,
      responseArtifact: prepared.evidence.responseArtifact,
      responseArtifactBytes: responseBytes,
    }),
    { ok: true, reasonCodes: [] },
  );
  const mismatchedSchema = await readJson(tokenEstimateDiagnosticSchemaV2Path);
  mismatchedSchema.properties.requestedModel = { const: "forbidden-model" };
  const mismatchedAjv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(mismatchedAjv);
  assert.equal(mismatchedAjv.compile(mismatchedSchema)(prepared.evidence), false);
  const runnerSource = await readFile(
    resolve(root, "scripts/run-kimi-independent-review.mjs"),
    "utf8",
  );
  const prepareIndex = runnerSource.indexOf(
    "createKimiK3TokenEstimateDiagnosticArtifactsV2({",
    runnerSource.indexOf("const estimate = await executeKimiK3TokenEstimate"),
  );
  const schemaValidationIndex = runnerSource.indexOf(
    "const diagnosticSchemaValidation",
    prepareIndex,
  );
  const writeIndex = runnerSource.indexOf(
    "await writeArtifacts(exactOutputDir, diagnosticArtifacts.artifacts)",
    schemaValidationIndex,
  );
  const readbackIndex = runnerSource.indexOf(
    "await verifyArtifactReadback(",
    writeIndex,
  );
  const failureIndex = runnerSource.indexOf(
    "if (!estimate.ok)",
    prepareIndex,
  );
  assert.ok(prepareIndex > 0);
  assert.ok(schemaValidationIndex > prepareIndex);
  assert.ok(writeIndex > schemaValidationIndex);
  assert.ok(readbackIndex > writeIndex);
  assert.ok(failureIndex > readbackIndex);
  const claimIndex = runnerSource.indexOf(
    "await createVerifiedOutputDirectory(exactRepoPath, exactOutputDir)",
  );
  const credentialIndex = runnerSource.indexOf(
    "apiKey = await credentialProvider()",
  );
  assert.ok(claimIndex > 0);
  assert.ok(credentialIndex > claimIndex);
  const v2Paths = runnerSource.slice(
    runnerSource.indexOf("const K3_V2_FIXED_PATHS"),
    runnerSource.indexOf("const K3_V3_FIXED_PATHS"),
  );
  const v3Paths = runnerSource.slice(
    runnerSource.indexOf("const K3_V3_FIXED_PATHS"),
    runnerSource.indexOf("const EXECUTING_PATHS"),
  );
  assert.match(
    v2Paths,
    /moonshot-kimi-k3-token-estimate-diagnostic-evidence\.v1\.schema\.json/u,
  );
  assert.match(
    v3Paths,
    /moonshot-kimi-k3-token-estimate-diagnostic-evidence\.v2\.schema\.json/u,
  );
  assert.match(runnerSource, /tokenEstimateDiagnosticSchemaBytes/gu);
  assert.match(
    runnerSource,
    /reasonCodes:\s*\["KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED"\]/u,
  );
  assert.match(runnerSource, /chatCompletionAttemptCount:\s*0/gu);
}

async function assertFrozenK3ContractAndFailedAttempt() {
  const expected = new Map([
    [
      "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
      "d67eea5b02e683b2d899a66f851236dd380a948009429e40ce5a97cf0db7c565",
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-independent-review-config.v2.schema.json",
      "5a5c14cc479b72547848529bc4079ab8d28ab5d7d6ee521e16a61c125e5ecaab",
    ],
    [
      "implementation/governance/schemas/independent-model-review-receipt.v4.schema.json",
      "9f02f8a0e5af7165efe194dd9760c7322109272ee98c255f816557dc9e1698af",
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v1.schema.json",
      "852417a37db7cb0394d683b8d0c5ab82f14d770fdcb754e0c0164f06cf418637",
    ],
    [
      "docs/adr/0013-moonshot-kimi-k3-single-call-transport.md",
      "acc350ba628b8e7023670b485d67f21ba2408712f57f405170a0a99a3a7ef438",
    ],
    [
      "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/formal-request.json",
      "11f68ce448e836caee68ab718a9e03cacca5b643822b821e3bbd935dbc2763e0",
    ],
    [
      "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/review-bundle.v2.json",
      "7401a94fcef52a62905ba37f08fe6f1e913069f39dc6fe4476738acd2c2affb1",
    ],
    [
      "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/review-material.v3.utf8",
      "1b00dde4aff6c8feaee05df9480667d6063e0a6c50e80f38e42d246e2b4d5724",
    ],
    [
      "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/single-call-outcome.v1.json",
      "6d130f4c3819fb83b99bd5bd295272691ac010502fb2074058f070a4dc974b93",
    ],
    [
      "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/token-estimate-request.json",
      "0e2d77b325e1b92eaf8e0051a931aec235af58ead76d43c65742521a0c970ca3",
    ],
  ]);
  for (const [path, sha256] of expected) {
    assert.equal(await fileSha256(resolve(root, path)), sha256, path);
  }
}

test("invalid token estimate responses fail closed", async () => {
  const config = await readJson(configPath);
  const materialBytes = Buffer.from("material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes,
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  for (const response of [
    responseObject(
      "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
      { data: { total_tokens: 1 } },
      503,
    ),
    responseObject(
      "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
      Buffer.from("not json", "utf8"),
    ),
    responseObject(
      "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
      Buffer.from('{"data":{"total_tokens":1,"total_tokens":2}}', "utf8"),
    ),
    responseObject(
      "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
      k3TokenEstimateResponse(-1),
    ),
  ]) {
    const result = await executeKimiK3TokenEstimate({
      config,
      estimateRequestBytes: estimate.requestBytes,
      formalRequestBytes: formal.requestBytes,
      materialBytes,
      apiKey: "unit-test-credential-outside-artifacts",
      fetchImpl: async () => response,
    });
    assert.equal(result.ok, false);
    assert.equal(result.networkAttemptCount, 1);
  }
  const oversized = await executeKimiK3TokenEstimate({
    config,
    estimateRequestBytes: estimate.requestBytes,
    formalRequestBytes: formal.requestBytes,
    materialBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async (url) =>
      responseObject(url, Buffer.alloc(64 * 1024 + 1, 0x61)),
  });
  assert.equal(oversized.ok, false);
  assert.deepEqual(oversized.reasonCodes, [
    "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED",
  ]);
  const timedOut = await executeKimiK3TokenEstimate({
    config,
    estimateRequestBytes: estimate.requestBytes,
    formalRequestBytes: formal.requestBytes,
    materialBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async () => new Promise(() => {}),
    timeoutMs: 5,
  });
  assert.equal(timedOut.ok, false);
  assert.deepEqual(timedOut.reasonCodes, ["KIMI_K3_TRANSPORT_TIMEOUT"]);
  await assertHttpAndParsingFailureDiagnostics();
  await assertStreamAndBoundaryFailures();
  await assertSensitiveResponsePrivacy();
});

test("credential and balance failures retain their stable classification", async () => {
  const config = await readJson(configPath);
  const materialBytes = Buffer.from("material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes,
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  for (const status of [401, 402, 403, 429]) {
    const result = await executeKimiK3TokenEstimate({
      config,
      estimateRequestBytes: estimate.requestBytes,
      formalRequestBytes: formal.requestBytes,
      materialBytes,
      apiKey: "unit-test-credential-outside-artifacts",
      fetchImpl: async () =>
        responseObject(
          "https://api.moonshot.ai/v1/tokenizers/estimate-token-count",
          { error: { message: "redacted" } },
          status,
        ),
    });
    assert.deepEqual(result.reasonCodes, [
      "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
    ]);
    assert.equal(result.networkAttemptCount, 1);
  }
});

test("token estimate evidence is closed, byte-bound and self-hashed", async () => {
  const configBytes = await readFile(
    resolve(
      root,
      "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
    ),
  );
  const config = JSON.parse(configBytes.toString("utf8"));
  const materialBytes = Buffer.from("material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes,
    outputSchemaBytes: bytes(outputSchema),
  });
  const estimate = buildKimiK3TokenEstimateRequest({
    config,
    formalRequestBytes: formal.requestBytes,
  });
  const estimateResponseBytes = bytes({ data: { total_tokens: 1234 } });
  const source = {
    runtimeCommit: "1".repeat(40),
    sourceCommit: "2".repeat(40),
    sourceTree: "3".repeat(40),
  };
  const input = {
    evidenceId: "mk3tee_fixture_001",
    config,
    configBytes,
    source,
    reviewBundleSha256: `sha256:${"4".repeat(64)}`,
    formalRequestBytes: formal.requestBytes,
    materialBytes,
    estimateRequestBytes: estimate.requestBytes,
    estimateResponseBytes,
    estimatedInputTokens: 1234,
    coverage: "MESSAGES_ONLY",
    httpStatus: 200,
    contentType: "application/json",
    networkAttemptCount: 1,
    startedAt: "2026-07-31T10:00:00.000Z",
    finishedAt: "2026-07-31T10:00:01.000Z",
    artifactPaths: {
      request: "token-estimate-request.json",
      response: "token-estimate-response.json",
    },
  };
  const evidence = createKimiK3TokenEstimateEvidence(input);
  const validateSchema = await compileSchema(
    resolve(
      root,
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v1.schema.json",
    ),
  );
  assert.equal(validateSchema(evidence), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(
    validateKimiK3TokenEstimateEvidence({
      ...input,
      evidence,
    }),
    { ok: true, reasonCodes: [] },
  );
  assert.equal(evidence.estimate.contextProved, false);
  assert.equal(evidence.budget.budgetProved, false);
  const legacyDataOnly = await executeKimiK3TokenEstimate({
    config,
    estimateRequestBytes: estimate.requestBytes,
    formalRequestBytes: formal.requestBytes,
    materialBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async (url) =>
      responseObject(url, { data: { total_tokens: 1234 } }),
  });
  assert.equal(legacyDataOnly.ok, true);
  const legacyEnvelope = await executeKimiK3TokenEstimate({
    config,
    estimateRequestBytes: estimate.requestBytes,
    formalRequestBytes: formal.requestBytes,
    materialBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async (url) =>
      responseObject(url, k3TokenEstimateResponse(1234)),
  });
  assert.equal(legacyEnvelope.ok, false);
  const stalePriceEvidence = createKimiK3TokenEstimateEvidence({
    ...input,
    finishedAt: "2026-08-01T10:00:01.000Z",
  });
  assert.equal(stalePriceEvidence.estimate.contextProved, false);
  assert.equal(stalePriceEvidence.budget.budgetProved, false);
  for (const mutate of [
    (value) => (value.model = "kimi-k2.7-code"),
    (value) => (value.bindings.messagesSha256 = `sha256:${"0".repeat(64)}`),
    (value) => (value.response.sha256 = `sha256:${"0".repeat(64)}`),
    (value) => (value.estimate.estimatedInputTokens += 1),
    (value) => (value.evidenceSha256 = `sha256:${"0".repeat(64)}`),
  ]) {
    const changed = clone(evidence);
    mutate(changed);
    assert.equal(
      validateKimiK3TokenEstimateEvidence({ ...input, evidence: changed }).ok,
      false,
    );
  }
  await assertTokenEstimateDiagnosticEvidence();
  await assertTokenEstimateDiagnosticEvidenceV2();
});

test("K3 Chat transport is one-shot, exact-contract and fail closed", async () => {
  const config = await readJson(configPath);
  const providerTransportSchemaBytes = await readFile(
    providerTransportSchemaPath,
  );
  const canonicalOutputSchemaBytes = await readFile(
    canonicalOutputSchemaPath,
  );
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes: Buffer.from("material", "utf8"),
    outputSchemaBytes: providerTransportSchemaBytes,
  });
  const content = JSON.stringify({
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "No blocking finding in the frozen material.",
    findings: [],
    decision: "CLEAR",
  });
  const body = bytes({
    id: "chatcmpl_kimi_k3_transport",
    object: "chat.completion",
    created: 1785513600,
    model: "kimi-k3",
    choices: [
      {
        index: 0,
        message: { role: "assistant", content },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: 100,
      completion_tokens: 20,
      total_tokens: 120,
      cached_tokens: 0,
    },
  });
  let calls = 0;
  const success = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async (url) => {
      calls += 1;
      return responseObject(url, body);
    },
  });
  assert.equal(success.ok, true);
  assert.equal(success.networkAttemptCount, 1);
  assert.equal(success.actualReturnedModel, "kimi-k3");
  assert.equal(success.finishReason, "stop");
  const historicalFormal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes: Buffer.from("material", "utf8"),
    outputSchemaBytes: canonicalOutputSchemaBytes,
    enforceProviderTransportSchema: false,
  });
  let historicalCalls = 0;
  const historical = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: historicalFormal.requestBytes,
    providerTransportSchemaBytes: canonicalOutputSchemaBytes,
    canonicalOutputSchemaBytes,
    enforceProviderTransportSchema: false,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async (url) => {
      historicalCalls += 1;
      return responseObject(url, body);
    },
  });
  assert.equal(historical.ok, true);
  assert.equal(historicalCalls, 1);
  const historicalInvalidBody = bytes({
    ...JSON.parse(body.toString("utf8")),
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: "{}" },
        finish_reason: "stop",
      },
    ],
  });
  const historicalFailure = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: historicalFormal.requestBytes,
    providerTransportSchemaBytes: canonicalOutputSchemaBytes,
    canonicalOutputSchemaBytes,
    enforceProviderTransportSchema: false,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async (url) => responseObject(url, historicalInvalidBody),
  });
  assert.deepEqual(historicalFailure.reasonCodes, [
    "INDEPENDENT_REVIEW_OUTPUT_INVALID",
    "INDEPENDENT_REVIEW_SCHEMA_INSTANCE_INVALID",
    "KIMI_K3_RESPONSE_SCHEMA_OR_SEMANTIC_INVALID",
  ]);
  let rejectedHistoricalCalls = 0;
  const rejectedHistorical = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: historicalFormal.requestBytes,
    providerTransportSchemaBytes: canonicalOutputSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async () => {
      rejectedHistoricalCalls += 1;
      return responseObject(config.baseURL + config.endpoint, body);
    },
  });
  assert.equal(rejectedHistorical.ok, false);
  assert.equal(rejectedHistoricalCalls, 0);
  assert.ok(
    rejectedHistorical.reasonCodes.includes(
      "KIMI_K3_PROVIDER_TRANSPORT_SCHEMA_MFJS_INVALID",
    ),
  );
  assert.equal(calls, 1);
  const missingCanonical = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes,
    apiKey: "unit-test-credential-outside-artifacts",
    fetchImpl: async () => {
      calls += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(missingCanonical.ok, false);
  assert.equal(missingCanonical.networkAttemptCount, 0);
  assert.equal(calls, 1);
  const missingCredential = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: "",
    fetchImpl: async () => {
      calls += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(missingCredential.ok, false);
  assert.equal(missingCredential.networkAttemptCount, 0);
  assert.equal(calls, 1);
  await assertKimiK3ChatFailureDiagnosticPersistence();
  await assertKimiK3ChatFailureDiagnosticBoundaries();
});

async function assertKimiK3ChatFailureDiagnosticPersistence() {
  const configBytes = await readFile(configPath);
  const config = JSON.parse(configBytes.toString("utf8"));
  const sensitiveCredential = "unit-test-credential-outside-artifacts";
  const outputSchemaBytes = await readFile(providerTransportSchemaPath);
  const canonicalOutputSchemaBytes = await readFile(
    canonicalOutputSchemaPath,
  );
  const materialBytes = Buffer.from("frozen review material", "utf8");
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("frozen prompt", "utf8"),
    materialBytes,
    outputSchemaBytes,
  });
  const rejectedBody = bytes({
    id: "chatcmpl_kimi_k3_diagnostic",
    object: "chat.completion",
    created: 1785513600,
    model: "unexpected-model",
    choices: [],
    usage: {
      prompt_tokens: 1,
      completion_tokens: 0,
      total_tokens: 1,
      cached_tokens: 0,
    },
  });
  const failed = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes: outputSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: sensitiveCredential,
    fetchImpl: async (url) => responseObject(url, rejectedBody),
  });
  assert.equal(failed.ok, false);
  assert.equal(failed.diagnostic.responseReceived, true);
  assert.deepEqual(failed.responseBytes, rejectedBody);

  const input = {
    runtimeCommit: "c".repeat(40),
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    reviewBundleSha256: `sha256:${"1".repeat(64)}`,
    requestSha256: formal.requestSha256,
    messagesSha256: formal.messagesSha256,
    reviewMaterialSha256: formal.materialSha256,
    promptSha256: `sha256:${"2".repeat(64)}`,
    configSha256: kimiK3Digests.bytes(configBytes),
    outputSchemaSha256: `sha256:${createHash("sha256")
      .update(canonicalOutputSchemaBytes)
      .digest("hex")}`,
    tokenEstimateEvidenceSha256: `sha256:${"4".repeat(64)}`,
    requestedModel: "kimi-k3",
    endpoint: "https://api.moonshot.ai/v1/chat/completions",
    config,
    configBytes,
    outputSchemaBytes: canonicalOutputSchemaBytes,
    canonicalOutputSchemaBytes,
    sensitiveCredential,
    diagnostic: failed.diagnostic,
    reasonCodes: failed.reasonCodes,
    responseBytes: failed.responseBytes,
    networkAttemptCount: 2,
    tokenEstimateAttemptCount: 1,
    chatCompletionAttemptCount: 1,
    startedAt: "2026-08-01T08:29:00.000Z",
    finishedAt: "2026-08-01T08:30:00.000Z",
    recordedAt: "2026-08-01T08:30:00.000Z",
  };
  const diagnostic = await createKimiK3ChatDiagnosticArtifactsV1(input);
  assert.equal(
    diagnostic.evidence.responseArtifact,
    "chat-diagnostic-response.bin",
  );
  assert.deepEqual(
    diagnostic.artifacts["chat-diagnostic-response.bin"],
    rejectedBody,
  );
  const validateSchema = await compileSchema(chatDiagnosticSchemaV1Path);
  assert.equal(
    validateSchema(diagnostic.evidence),
    true,
    JSON.stringify(validateSchema.errors),
  );
  assert.deepEqual(
    await validateKimiK3ChatDiagnosticEvidenceV1({
      ...input,
      evidence: diagnostic.evidence,
      responseArtifactBytes:
        diagnostic.artifacts["chat-diagnostic-response.bin"],
    }),
    { ok: true, reasonCodes: [] },
  );
  const historicalInput = { ...input };
  delete historicalInput.canonicalOutputSchemaBytes;
  const historicalDiagnostic =
    await createKimiK3ChatDiagnosticArtifactsV1(historicalInput);
  assert.deepEqual(
    await validateKimiK3ChatDiagnosticEvidenceV1({
      ...historicalInput,
      evidence: historicalDiagnostic.evidence,
      responseArtifactBytes:
        historicalDiagnostic.artifacts["chat-diagnostic-response.bin"],
    }),
    { ok: true, reasonCodes: [] },
  );
  await assert.rejects(
    createKimiK3ChatDiagnosticArtifactsV1({
      ...input,
      canonicalOutputSchemaBytes: Buffer.from('{"type":"number"}', "utf8"),
    }),
    /diagnostic evidence is invalid/iu,
    "historical v1 diagnostics cannot substitute an unbound canonical Schema",
  );
  const tampered = Buffer.from(rejectedBody);
  tampered[0] ^= 1;
  assert.equal(
    (
      await validateKimiK3ChatDiagnosticEvidenceV1({
        ...input,
        evidence: diagnostic.evidence,
        responseArtifactBytes: tampered,
      })
    ).ok,
    false,
  );

  const providerTransportSchemaSha256 = kimiK3Digests.bytes(outputSchemaBytes);
  const canonicalOutputSchemaSha256 = kimiK3Digests.bytes(
    canonicalOutputSchemaBytes,
  );
  const v2Input = {
    ...input,
    outputSchemaBytes,
    canonicalOutputSchemaBytes,
    providerTransportSchemaPath:
      "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json",
    providerTransportSchemaSha256,
    canonicalOutputSchemaPath:
      "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    canonicalOutputSchemaSha256,
    resolveSourceCommitBytes: async ({ sourceCommit, path }) => {
      assert.equal(sourceCommit, input.sourceCommit);
      if (
        path ===
        "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json"
      ) {
        return outputSchemaBytes;
      }
      if (
        path ===
        "implementation/governance/schemas/independent-model-review-output.v2.schema.json"
      ) {
        return canonicalOutputSchemaBytes;
      }
      throw new TypeError("Unexpected source path.");
    },
  };
  delete v2Input.outputSchemaSha256;
  const diagnosticV2 = await createKimiK3ChatDiagnosticArtifactsV2(v2Input);
  const validateSchemaV2 = await compileSchema(chatDiagnosticSchemaV2Path);
  assert.equal(
    validateSchemaV2(diagnosticV2.evidence),
    true,
    JSON.stringify(validateSchemaV2.errors),
  );
  assert.deepEqual(
    await validateKimiK3ChatDiagnosticEvidenceV2({
      ...v2Input,
      evidence: diagnosticV2.evidence,
      responseArtifactBytes:
        diagnosticV2.artifacts["chat-diagnostic-response.bin"],
    }),
    { ok: true, reasonCodes: [] },
  );
  for (const mutate of [
    (value) =>
      (value.providerTransportSchemaPath = value.canonicalOutputSchemaPath),
    (value) =>
      (value.canonicalOutputSchemaPath = value.providerTransportSchemaPath),
    (value) =>
      (value.providerTransportSchemaSha256 = canonicalOutputSchemaSha256),
    (value) =>
      (value.canonicalOutputSchemaSha256 = providerTransportSchemaSha256),
  ]) {
    const changed = clone(diagnosticV2.evidence);
    mutate(changed);
    assert.equal(
      (
        await validateKimiK3ChatDiagnosticEvidenceV2({
          ...v2Input,
          evidence: changed,
          responseArtifactBytes:
            diagnosticV2.artifacts["chat-diagnostic-response.bin"],
        })
      ).ok,
      false,
    );
  }
  assert.equal(
    (
      await validateKimiK3ChatDiagnosticEvidenceV2({
        ...v2Input,
        evidence: diagnosticV2.evidence,
        canonicalOutputSchemaBytes: outputSchemaBytes,
        responseArtifactBytes:
          diagnosticV2.artifacts["chat-diagnostic-response.bin"],
      })
    ).ok,
    false,
  );
  const noResponseDiagnostic = {
    responseReceived: false,
    failureStage: "TRANSPORT",
    reasonCode: "KIMI_K3_TRANSPORT_TIMEOUT",
  };
  const fakeProviderSchemaBytes = Buffer.from('{"type":"string"}', "utf8");
  const fakeCanonicalSchemaBytes = Buffer.from('{"type":"number"}', "utf8");
  await assert.rejects(
    createKimiK3ChatDiagnosticArtifactsV2({
      ...v2Input,
      outputSchemaBytes: fakeProviderSchemaBytes,
      canonicalOutputSchemaBytes: fakeCanonicalSchemaBytes,
      providerTransportSchemaSha256: kimiK3Digests.bytes(
        fakeProviderSchemaBytes,
      ),
      canonicalOutputSchemaSha256: kimiK3Digests.bytes(
        fakeCanonicalSchemaBytes,
      ),
      diagnostic: noResponseDiagnostic,
      reasonCodes: ["KIMI_K3_TRANSPORT_TIMEOUT"],
      responseBytes: null,
    }),
    /diagnostic evidence v2 is invalid/iu,
    "v2 diagnostics must re-read both declared Schema paths from sourceCommit before accepting an early failure",
  );
  const withoutSourceResolver = { ...v2Input };
  delete withoutSourceResolver.resolveSourceCommitBytes;
  await assert.rejects(
    createKimiK3ChatDiagnosticArtifactsV2({
      ...withoutSourceResolver,
      diagnostic: noResponseDiagnostic,
      reasonCodes: ["KIMI_K3_TRANSPORT_TIMEOUT"],
      responseBytes: null,
    }),
    /diagnostic evidence v2 is invalid/iu,
    "v2 diagnostics fail closed without a sourceCommit byte resolver",
  );

  await assert.rejects(
    async () =>
      createKimiK3ChatDiagnosticArtifactsV1({
        ...input,
        responseBytes: null,
      }),
    /diagnostic evidence is invalid/iu,
    "a safe complete response artifact is mandatory",
  );

  await assert.rejects(
    async () =>
      createKimiK3ChatDiagnosticArtifactsV1({
        ...input,
        diagnostic: {
          ...failed.diagnostic,
          failureStage: "REQUEST_BINDING",
          reasonCode: "KIMI_K3_CHAT_REQUEST_BINDING_MISMATCH",
        },
        reasonCodes: ["KIMI_K3_CHAT_REQUEST_BINDING_MISMATCH"],
      }),
    /diagnostic evidence is invalid/iu,
    "response metadata cannot be paired with a pre-request failure stage",
  );

  const unresolvedContent = JSON.stringify({
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "A blocking finding remains open.",
    findings: [
      {
        findingId: "open_high_finding",
        severity: "HIGH",
        status: "OPEN",
        path: "lib/example.mjs",
        startLine: 1,
        endLine: 1,
        summary: "The blocking finding is unresolved.",
        detailsSha256: `sha256:${"5".repeat(64)}`,
        resolutionEvidenceDigests: [],
      },
    ],
    decision: "CLEAR",
  });
  const semanticBody = bytes({
    id: "chatcmpl_kimi_k3_semantic_diagnostic",
    object: "chat.completion",
    created: 1785513600,
    model: "kimi-k3",
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: unresolvedContent },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: 1,
      completion_tokens: 1,
      total_tokens: 2,
      cached_tokens: 0,
    },
  });
  const semanticFailure = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes: outputSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: sensitiveCredential,
    fetchImpl: async (url) => responseObject(url, semanticBody),
  });
  const semanticDiagnostic =
    await createKimiK3ChatDiagnosticArtifactsV1({
      ...input,
      diagnostic: semanticFailure.diagnostic,
      reasonCodes: semanticFailure.reasonCodes,
      responseBytes: semanticFailure.responseBytes,
    });
  assert.deepEqual(
    {
      failureStage: semanticDiagnostic.evidence.failureStage,
      jsonParsed: semanticDiagnostic.evidence.jsonParsed,
      protocolValidated: semanticDiagnostic.evidence.protocolValidated,
      outputSchemaValidated:
        semanticDiagnostic.evidence.outputSchemaValidated,
      semanticValidated: semanticDiagnostic.evidence.semanticValidated,
    },
    {
      failureStage: "SEMANTIC_VALIDATION",
      jsonParsed: true,
      protocolValidated: true,
      outputSchemaValidated: true,
      semanticValidated: false,
    },
  );

  const exactCredentialBody = bytes({ message: sensitiveCredential });
  const credentialDiagnostic = await createKimiK3ChatDiagnosticArtifactsV1({
    ...input,
    diagnostic: {
      ...failed.diagnostic,
      responseBodyByteLength: exactCredentialBody.byteLength,
      responseBodySha256: kimiK3Digests.bytes(exactCredentialBody),
      failureStage: "BODY_CAPTURE",
      reasonCode: "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED",
    },
    reasonCodes: ["KIMI_K3_RESPONSE_CREDENTIAL_ECHOED"],
    responseBytes: exactCredentialBody,
  });
  assert.equal(credentialDiagnostic.evidence.responseArtifact, null);

  for (const sensitiveText of [
    "api_key=unsafe-value",
    "token: unsafe-value",
    "cookie=unsafe-value",
    "password=unsafe-value",
    "Authorization: Basic dW5zYWZlOnZhbHVl",
  ]) {
    const sensitiveBytes = Buffer.from(sensitiveText, "utf8");
    const sensitiveTextDiagnostic =
      await createKimiK3ChatDiagnosticArtifactsV1({
        ...input,
        diagnostic: {
          ...failed.diagnostic,
          responseBodyByteLength: sensitiveBytes.byteLength,
          responseBodySha256: kimiK3Digests.bytes(sensitiveBytes),
          failureStage: "BODY_CAPTURE",
          reasonCode: "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED",
        },
        reasonCodes: ["KIMI_K3_RESPONSE_CREDENTIAL_ECHOED"],
        responseBytes: sensitiveBytes,
      });
    assert.equal(sensitiveTextDiagnostic.evidence.responseArtifact, null);
  }

  const sensitiveFailure = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes: outputSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: sensitiveCredential,
    fetchImpl: async (url) =>
      responseObject(url, {
        authorization: "Bearer unit-test-credential-outside-artifacts",
      }),
  });
  assert.equal(sensitiveFailure.ok, false);
  const sensitiveDiagnostic = await createKimiK3ChatDiagnosticArtifactsV1({
    ...input,
    diagnostic: sensitiveFailure.diagnostic,
    reasonCodes: sensitiveFailure.reasonCodes,
    responseBytes: sensitiveFailure.responseBytes,
  });
  assert.equal(sensitiveDiagnostic.evidence.responseArtifact, null);
  assert.deepEqual(Object.keys(sensitiveDiagnostic.artifacts), [
    "chat-diagnostic-evidence.json",
  ]);
}

async function assertKimiK3ChatFailureDiagnosticBoundaries() {
  const configBytes = await readFile(configPath);
  const config = JSON.parse(configBytes.toString("utf8"));
  const sensitiveCredential = "unit-test-credential-outside-artifacts";
  const outputSchemaBytes = await readFile(providerTransportSchemaPath);
  const canonicalOutputSchemaBytes = await readFile(
    canonicalOutputSchemaPath,
  );
  const formal = await buildKimiK3IndependentReviewRequest({
    config,
    promptBytes: Buffer.from("prompt", "utf8"),
    materialBytes: Buffer.from("material", "utf8"),
    outputSchemaBytes,
  });
  const baseInput = {
    runtimeCommit: "c".repeat(40),
    sourceCommit: "a".repeat(40),
    sourceTree: "b".repeat(40),
    reviewBundleSha256: `sha256:${"1".repeat(64)}`,
    requestSha256: formal.requestSha256,
    messagesSha256: formal.messagesSha256,
    reviewMaterialSha256: formal.materialSha256,
    promptSha256: `sha256:${"2".repeat(64)}`,
    configSha256: kimiK3Digests.bytes(configBytes),
    outputSchemaSha256: `sha256:${createHash("sha256")
      .update(canonicalOutputSchemaBytes)
      .digest("hex")}`,
    tokenEstimateEvidenceSha256: `sha256:${"4".repeat(64)}`,
    requestedModel: "kimi-k3",
    endpoint: "https://api.moonshot.ai/v1/chat/completions",
    config,
    configBytes,
    outputSchemaBytes: canonicalOutputSchemaBytes,
    canonicalOutputSchemaBytes,
    sensitiveCredential,
    networkAttemptCount: 2,
    tokenEstimateAttemptCount: 1,
    chatCompletionAttemptCount: 1,
    startedAt: "2026-08-01T08:29:00.000Z",
    finishedAt: "2026-08-01T08:30:00.000Z",
    recordedAt: "2026-08-01T08:30:00.000Z",
  };
  for (const status of [400, 401, 403, 429, 500, 503]) {
    const body = bytes({ code: `safe_${status}` });
    const result = await executeKimiK3ChatCompletion({
      config,
      formalRequestBytes: formal.requestBytes,
      providerTransportSchemaBytes: outputSchemaBytes,
      canonicalOutputSchemaBytes,
      apiKey: sensitiveCredential,
      fetchImpl: async (url) => responseObject(url, body, status),
    });
    const artifacts = await createKimiK3ChatDiagnosticArtifactsV1({
      ...baseInput,
      diagnostic: result.diagnostic,
      reasonCodes: result.reasonCodes,
      responseBytes: result.responseBytes,
    });
    assert.equal(artifacts.evidence.httpStatus, status);
    assert.deepEqual(
      artifacts.artifacts["chat-diagnostic-response.bin"],
      body,
    );
  }

  for (const body of [
    Buffer.alloc(0),
    Buffer.from("{", "utf8"),
    Buffer.from('{"id":1,"id":2}', "utf8"),
  ]) {
    const result = await executeKimiK3ChatCompletion({
      config,
      formalRequestBytes: formal.requestBytes,
      providerTransportSchemaBytes: outputSchemaBytes,
      canonicalOutputSchemaBytes,
      apiKey: sensitiveCredential,
      fetchImpl: async (url) => responseObject(url, body),
    });
    const artifacts = await createKimiK3ChatDiagnosticArtifactsV1({
      ...baseInput,
      diagnostic: result.diagnostic,
      reasonCodes: result.reasonCodes,
      responseBytes: result.responseBytes,
    });
    assert.deepEqual(
      artifacts.artifacts["chat-diagnostic-response.bin"],
      body,
    );
    assert.equal(artifacts.evidence.jsonParsed, false);
  }

  const gzipResult = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes: outputSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: sensitiveCredential,
    fetchImpl: async (url) =>
      responseObject(url, { safe: true }, 200, {
        "content-encoding": "gzip",
      }),
  });
  const gzipArtifacts = await createKimiK3ChatDiagnosticArtifactsV1({
    ...baseInput,
    diagnostic: gzipResult.diagnostic,
    reasonCodes: gzipResult.reasonCodes,
    responseBytes: gzipResult.responseBytes,
  });
  assert.equal(gzipArtifacts.evidence.contentEncoding, "gzip");
  assert.equal(
    gzipArtifacts.evidence.bodyRepresentation,
    "APPLICATION_LAYER_DECODED_BYTES",
  );
  assert.equal(gzipArtifacts.evidence.responseArtifact !== null, true);

  const redirected = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes: outputSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: sensitiveCredential,
    fetchImpl: async () =>
      responseObject("https://attacker.invalid/response", { safe: true }),
  });
  const redirectedArtifacts = await createKimiK3ChatDiagnosticArtifactsV1({
    ...baseInput,
    diagnostic: redirected.diagnostic,
    reasonCodes: redirected.reasonCodes,
    responseBytes: redirected.responseBytes,
  });
  assert.equal(redirectedArtifacts.evidence.responseArtifact, null);

  const interrupted = await executeKimiK3ChatCompletion({
    config,
    formalRequestBytes: formal.requestBytes,
    providerTransportSchemaBytes: outputSchemaBytes,
    canonicalOutputSchemaBytes,
    apiKey: sensitiveCredential,
    fetchImpl: async () => {
      throw new Error("connection interrupted");
    },
  });
  const interruptedArtifacts = await createKimiK3ChatDiagnosticArtifactsV1({
    ...baseInput,
    diagnostic: interrupted.diagnostic,
    reasonCodes: interrupted.reasonCodes,
    responseBytes: interrupted.responseBytes,
  });
  assert.equal(interruptedArtifacts.evidence.responseReceived, false);
  assert.equal(interruptedArtifacts.evidence.responseArtifact, null);

  const noResponseStageReasons = [
    ["REQUEST_BINDING", "KIMI_K3_CHAT_REQUEST_BINDING_MISMATCH"],
    ["CREDENTIAL", "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
    ["TRANSPORT", "KIMI_K3_TRANSPORT_NETWORK_FAILED"],
  ];
  for (const [failureStage, reasonCode] of noResponseStageReasons) {
    await createKimiK3ChatDiagnosticArtifactsV1({
      ...baseInput,
      diagnostic: {
        ...interrupted.diagnostic,
        failureStage,
        reasonCode,
      },
      reasonCodes: [reasonCode],
      responseBytes: null,
    });
    const crossStageReason =
      noResponseStageReasons.find(
        ([candidateStage]) => candidateStage !== failureStage,
      )[1];
    await assert.rejects(
      () =>
        createKimiK3ChatDiagnosticArtifactsV1({
          ...baseInput,
          diagnostic: {
            ...interrupted.diagnostic,
            failureStage,
            reasonCode: crossStageReason,
          },
          reasonCodes: [crossStageReason],
          responseBytes: null,
        }),
      /diagnostic evidence is invalid/iu,
    );
    await assert.rejects(
      () =>
        createKimiK3ChatDiagnosticArtifactsV1({
          ...baseInput,
          diagnostic: {
            ...interrupted.diagnostic,
            failureStage,
            reasonCode,
          },
          reasonCodes: [reasonCode, "KIMI_K3_RESPONSE_HTTP_INVALID"],
          responseBytes: null,
        }),
      /diagnostic evidence is invalid/iu,
    );
  }
}

test("formal K3 response requires exact model, stop and consistent usage", async () => {
  const config = await readJson(configPath);
  const providerTransportSchemaBytes = await readFile(
    providerTransportSchemaPath,
  );
  const canonicalOutputSchemaBytes = await readFile(
    canonicalOutputSchemaPath,
  );
  const content = JSON.stringify({
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "The frozen candidate has no blocking finding.",
    findings: [],
    decision: "CLEAR",
  });
  const response = {
    id: "chatcmpl_kimi_k3_fixture",
    object: "chat.completion",
    created: 1785513600,
    model: "kimi-k3",
    choices: [
      {
        index: 0,
        message: { role: "assistant", reasoning_content: "reviewed", content },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: 100,
      completion_tokens: 20,
      total_tokens: 120,
      cached_tokens: 0,
    },
  };
  const validate = (body) =>
    validateKimiK3ChatResponse({
      config,
      responseBytes: bytes(body),
      providerTransportSchemaBytes,
      canonicalOutputSchemaBytes,
    });
  const result = await validate(response);
  assert.equal(result.ok, true);
  assert.equal(result.actualReturnedModel, "kimi-k3");
  assert.equal(result.finishReason, "stop");
  assert.deepEqual(result.usage, response.usage);
  for (const mutate of [
    (value) => (value.model = "kimi-k2.7-code"),
    (value) => (value.choices[0].finish_reason = "length"),
    (value) => (value.usage.total_tokens = 121),
    (value) => (value.usage.completion_tokens = 32_769),
    (value) => (value.choices[0].message.tool_calls = []),
    (value) => (value.choices[0].message.refusal = "no"),
  ]) {
    const changed = clone(response);
    mutate(changed);
    const rejected = await validate(changed);
    assert.equal(rejected.ok, false);
  }
  for (const body of [
    Buffer.from("not-json", "utf8"),
    { ...response, choices: [{ ...response.choices[0], message: { role: "assistant", content: "{}" } }] },
  ]) {
    const rejected = await validateKimiK3ChatResponse({
      config,
      responseBytes: Buffer.isBuffer(body) ? body : bytes(body),
      providerTransportSchemaBytes,
      canonicalOutputSchemaBytes,
    });
    assert.equal(rejected.ok, false);
  }

  const canonicalFailure = clone(response);
  canonicalFailure.choices[0].message.content = JSON.stringify({
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "",
    findings: [],
    decision: "CLEAR",
  });
  const rejectedByCanonical = await validate(canonicalFailure);
  assert.equal(rejectedByCanonical.ok, false);
  assert.equal(
    rejectedByCanonical.reasonCodes.includes(
      "KIMI_K3_CANONICAL_OUTPUT_SCHEMA_INVALID",
    ),
    true,
  );

  const narrowedProvider = JSON.parse(
    providerTransportSchemaBytes.toString("utf8"),
  );
  narrowedProvider.properties.decision.enum = ["BLOCKED"];
  const rejectedByProvider = await validateKimiK3ChatResponse({
    config,
    responseBytes: bytes(response),
    providerTransportSchemaBytes: bytes(narrowedProvider),
    canonicalOutputSchemaBytes,
  });
  assert.equal(rejectedByProvider.ok, false);
  assert.equal(
    rejectedByProvider.reasonCodes.includes(
      "KIMI_K3_PROVIDER_TRANSPORT_OUTPUT_SCHEMA_INVALID",
    ),
    true,
  );
});
