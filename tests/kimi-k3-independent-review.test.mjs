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
  createKimiK3TokenEstimateEvidence,
  evaluateKimiK3SingleCallPreflight,
  executeKimiK3TokenEstimate,
  kimiK3Digests,
  validateKimiK3ChatResponse,
  validateKimiK3TokenEstimateEvidence,
  validateMoonshotKimiK3Config,
} from "../lib/kimi-k3-independent-review.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);
const configPath = resolve(
  root,
  "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
);
const configSchemaPath = resolve(
  root,
  "implementation/governance/schemas/moonshot-kimi-independent-review-config.v2.schema.json",
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
    decision: { enum: ["CLEAR", "BLOCKED", "INCONCLUSIVE"] },
    findings: { type: "array", items: { type: "object" } },
  },
};

test("K3 v2 config is closed, exact and self-hashed", async () => {
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
  assert.equal(config.taxExclusiveBudgetMicros, 4_000_000);
  assert.equal(config.fallbackPolicy, "DISABLED_FAIL_CLOSED");
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
  ]);
  for (const [path, sha256] of expected) {
    assert.equal(await fileSha256(resolve(root, path)), sha256, path);
  }
});

test("formal orchestration has no K2 fallback or Chat path while context proof is unavailable", async () => {
  const [runnerSource, bootstrapSource] = await Promise.all([
    readFile(resolve(root, "scripts/run-kimi-independent-review.mjs"), "utf8"),
    readFile(resolve(root, "scripts/bootstrap-kimi-independent-review.mjs"), "utf8"),
  ]);
  assert.equal(runnerSource.includes("executeKimiK3SingleCall"), false);
  assert.equal(bootstrapSource.includes("kimi-runtime-manifest.v1.json"), false);
  assert.equal(bootstrapSource.includes("kimi-runtime-manifest.v2.json"), true);
  assert.match(runnerSource, /KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED/u);
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
  const outputSchemaBytes = bytes(outputSchema);
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
  assert.equal(request.max_completion_tokens, 32_768);
  assert.equal(built.requestSha256, kimiK3Digests.bytes(built.requestBytes));
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
  await assert.rejects(
    buildKimiK3IndependentReviewRequest({
      config,
      promptBytes: Buffer.from("prompt", "utf8"),
      materialBytes: Buffer.alloc(config.maxReviewMaterialUtf8Bytes + 1, 0x61),
      outputSchemaBytes: bytes(outputSchema),
    }),
  );
  await assert.rejects(
    buildKimiK3IndependentReviewRequest({
      config,
      promptBytes: Buffer.alloc(config.maxRequestUtf8Bytes + 1, 0x61),
      materialBytes: Buffer.from("material", "utf8"),
      outputSchemaBytes: bytes(outputSchema),
    }),
  );
  assert.equal(
    (
      await validateKimiK3ChatResponse({
        config,
        responseBytes: Buffer.alloc(config.maxResponseUtf8Bytes + 1, 0x61),
        outputSchemaBytes: bytes(outputSchema),
      })
    ).ok,
    false,
  );
});

test("K3 preflight uses the safe additive context boundary", async () => {
  const config = await readJson(configPath);
  const common = {
    config,
    estimateCoverage: "FULL_MODEL_VISIBLE_INPUT_PROVED",
    estimateBindingsMatch: true,
    priceEvidenceCurrent: true,
    reasoningUsageCoveredByCompletionLimit: true,
    reasoningUsageCoveredByPublishedOutputPrice: true,
  };
  assert.equal(
    evaluateKimiK3SingleCallPreflight({
      ...common,
      estimatedInputTokens: 1_007_616,
    }).ok,
    true,
  );
  const rejected = evaluateKimiK3SingleCallPreflight({
    ...common,
    estimatedInputTokens: 1_007_617,
  });
  assert.equal(rejected.ok, false);
  assert.deepEqual(rejected.reasonCodes, [
    "KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED",
  ]);
});

test("messages-only estimate and unknown reasoning accounting fail closed", async () => {
  const config = await readJson(configPath);
  for (const override of [
    { estimateCoverage: "MESSAGES_ONLY" },
    { priceEvidenceCurrent: false },
    { reasoningUsageCoveredByCompletionLimit: false },
    { reasoningUsageCoveredByPublishedOutputPrice: false },
  ]) {
    const result = evaluateKimiK3SingleCallPreflight({
      config,
      estimatedInputTokens: 100,
      estimateCoverage: "FULL_MODEL_VISIBLE_INPUT_PROVED",
      estimateBindingsMatch: true,
      priceEvidenceCurrent: true,
      reasoningUsageCoveredByCompletionLimit: true,
      reasoningUsageCoveredByPublishedOutputPrice: true,
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
      return responseObject(url, { data: { total_tokens: 1234 } });
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
  assert.equal(result.coverage, "MESSAGES_ONLY");
});

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
      { data: { total_tokens: -1 } },
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
  const configBytes = await readFile(configPath);
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
});

test("K3 core exposes no caller-forgeable Chat execution surface", async () => {
  const loadedModule = await import("../lib/kimi-k3-independent-review.mjs");
  assert.equal(Object.hasOwn(loadedModule, "executeKimiK3SingleCall"), false);
});

test("formal K3 response requires exact model, stop and consistent usage", async () => {
  const config = await readJson(configPath);
  const outputSchemaBytes = await readFile(
    resolve(
      root,
      "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    ),
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
      outputSchemaBytes,
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
      outputSchemaBytes,
    });
    assert.equal(rejected.ok, false);
  }
});
