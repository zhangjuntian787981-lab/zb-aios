import { createHash } from "node:crypto";
import {
  parseIndependentReviewJsonBytes,
  validateIndependentModelReviewOutputArtifact,
} from "./independent-model-review.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const CONFIG_SHA_PLACEHOLDER = `sha256:${"0".repeat(64)}`;
const EVIDENCE_SHA_PLACEHOLDER = CONFIG_SHA_PLACEHOLDER;
const COMMIT = /^[a-f0-9]{40}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const CONFIG_KEYS = [
  "schemaVersion",
  "configId",
  "lifecycle",
  "reviewerProvider",
  "reviewerModel",
  "baseURL",
  "endpoint",
  "tokenEstimateEndpoint",
  "credentialEnv",
  "keychainServiceRecommendation",
  "keychainAccountRecommendation",
  "contextWindowTokens",
  "reasoningEffort",
  "thinkingOmitted",
  "toolChoice",
  "toolsOmitted",
  "responseFormat",
  "forbiddenRequestFields",
  "maxCompletionTokens",
  "safetyMarginTokens",
  "maxReviewMaterialUtf8Bytes",
  "maxRequestUtf8Bytes",
  "maxResponseUtf8Bytes",
  "contextBudgetBasis",
  "pricing",
  "taxExclusiveBudgetMicros",
  "officialContract",
  "fallbackPolicy",
  "configSha256",
];
const REQUEST_KEYS = [
  "model",
  "messages",
  "reasoning_effort",
  "tool_choice",
  "response_format",
  "max_completion_tokens",
];
const FORBIDDEN_REQUEST_FIELDS = [
  "frequency_penalty",
  "n",
  "presence_penalty",
  "temperature",
  "thinking",
  "tools",
  "top_p",
];
const OFFICIAL_CONTRACT = Object.freeze({
  modelUrl: "https://platform.kimi.ai/docs/models",
  chatUrl: "https://platform.kimi.ai/docs/api/chat",
  tokenEstimateUrl: "https://platform.kimi.ai/docs/api/estimate",
  structuredOutputUrl: "https://platform.kimi.ai/docs/guide/response_format",
  pricingUrl: "https://platform.kimi.ai/docs/pricing/chat-k3",
  researchPath:
    "docs/research/moonshot-kimi-k3-transport-contract-2026-07-31.md",
  researchSha256:
    "sha256:bb62d37a852db27a71ea13e004351c4e46256c32221036e326a13ce126cbc85b",
  queriedAt: "2026-07-31",
});

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("K3 artifact contains an unsupported value.");
}

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function sha256Value(value) {
  return sha256Bytes(Buffer.from(canonicalize(value), "utf8"));
}

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

function configDigest(config) {
  return sha256Value({ ...config, configSha256: CONFIG_SHA_PLACEHOLDER });
}

function strictUtf8(bytes) {
  if (!(bytes instanceof Uint8Array)) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function parseJsonBytes(bytes) {
  try {
    const parsed = parseIndependentReviewJsonBytes(
      bytes,
      "Kimi K3 JSON",
      16 * 1024 * 1024,
    );
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed
      : null;
  } catch {
    return null;
  }
}

function ceilDiv(numerator, denominator) {
  return Math.floor((numerator + denominator - 1) / denominator);
}

export const kimiK3Digests = Object.freeze({
  bytes: sha256Bytes,
  value: sha256Value,
  config: configDigest,
});

export const kimiK3ReviewMaterialPaths = Object.freeze({
  reviewBundle: "artifacts/independent-review-bundle.v2.json",
  patch: "artifacts/source.diff",
  prompt:
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  outputSchema:
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v4.schema.json",
  config:
    "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
  modelVisibleProtocol:
    "artifacts/moonshot-kimi-k3-model-visible-protocol.v2.json",
});

export const kimiK3ReviewMaterialGovernancePaths = Object.freeze(
  [
    "docs/adr/0013-moonshot-kimi-k3-single-call-transport.md",
    "docs/research/moonshot-kimi-k3-transport-contract-2026-07-31.md",
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    "implementation/governance/schemas/independent-model-review-receipt.v4.schema.json",
    "implementation/governance/schemas/independent-review-material.v3.schema.json",
    "implementation/governance/schemas/independent-review-runtime-manifest.v2.schema.json",
    "implementation/governance/schemas/independent-review-transport-evidence.v2.schema.json",
    "implementation/governance/schemas/moonshot-kimi-independent-review-config.v2.schema.json",
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v1.schema.json",
    "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
    "implementation/governance/independent-review/implementation-participant.v1.json",
    "lib/kimi-k3-independent-review.mjs",
    "lib/kimi-k3-review-evidence.mjs",
    "lib/kimi-independent-review.mjs",
    "scripts/build-independent-review-material.mjs",
    "scripts/bootstrap-kimi-independent-review.mjs",
    "scripts/launch-kimi-independent-review.sh",
    "scripts/run-kimi-independent-review.mjs",
    "tests/kimi-k3-independent-review.test.mjs",
    "tests/kimi-k3-review-evidence.test.mjs",
  ].sort(),
);

export function createKimiK3ModelVisibleProtocolBytes(config) {
  return Buffer.from(
    JSON.stringify({
      schemaVersion: "moonshot-kimi-k3-model-visible-protocol.v2",
      reviewerProvider: config.reviewerProvider,
      reviewerModel: config.reviewerModel,
      baseURL: config.baseURL,
      endpoint: config.endpoint,
      tokenEstimateEndpoint: config.tokenEstimateEndpoint,
      contextWindowTokens: config.contextWindowTokens,
      reasoningEffort: config.reasoningEffort,
      thinkingOmitted: config.thinkingOmitted,
      toolChoice: config.toolChoice,
      toolsOmitted: config.toolsOmitted,
      responseFormat: config.responseFormat,
      forbiddenRequestFields: config.forbiddenRequestFields,
      maxCompletionTokens: config.maxCompletionTokens,
      safetyMarginTokens: config.safetyMarginTokens,
      maxReviewMaterialUtf8Bytes: config.maxReviewMaterialUtf8Bytes,
      maxRequestUtf8Bytes: config.maxRequestUtf8Bytes,
      maxResponseUtf8Bytes: config.maxResponseUtf8Bytes,
      contextBudgetBasis: config.contextBudgetBasis,
      pricing: config.pricing,
      taxExclusiveBudgetMicros: config.taxExclusiveBudgetMicros,
      fallbackPolicy: config.fallbackPolicy,
    }),
    "utf8",
  );
}

export async function validateMoonshotKimiK3Config(config) {
  const reasonCodes = [];
  if (
    !exactKeys(config, CONFIG_KEYS) ||
    config.schemaVersion !== "moonshot-kimi-independent-review-config.v2" ||
    !/^mkirc_[a-z0-9][a-z0-9_-]{7,127}$/u.test(config.configId ?? "") ||
    config.lifecycle !== "CANDIDATE" ||
    config.reviewerProvider !== "moonshot" ||
    config.reviewerModel !== "kimi-k3" ||
    config.baseURL !== "https://api.moonshot.ai/v1" ||
    config.endpoint !== "/chat/completions" ||
    config.tokenEstimateEndpoint !== "/tokenizers/estimate-token-count" ||
    config.credentialEnv !== "MOONSHOT_API_KEY" ||
    config.keychainServiceRecommendation !== "kimi-p2-independent-review" ||
    config.keychainAccountRecommendation !== "p2-independent-review" ||
    config.contextWindowTokens !== 1_048_576 ||
    config.reasoningEffort !== "max" ||
    config.thinkingOmitted !== true ||
    config.toolChoice !== "none" ||
    config.toolsOmitted !== true ||
    !exactKeys(config.responseFormat, ["type", "strict", "name"]) ||
    config.responseFormat.type !== "json_schema" ||
    config.responseFormat.strict !== true ||
    config.responseFormat.name !== "independent_model_review_output_v2" ||
    JSON.stringify(config.forbiddenRequestFields) !==
      JSON.stringify(FORBIDDEN_REQUEST_FIELDS) ||
    config.maxCompletionTokens !== 32_768 ||
    config.safetyMarginTokens !== 8_192 ||
    config.maxReviewMaterialUtf8Bytes !== 1_048_576 ||
    config.maxRequestUtf8Bytes !== 1_572_864 ||
    config.maxResponseUtf8Bytes !== 1_048_576 ||
    config.contextBudgetBasis !== "TRANSPORT_DEFENSE_ONLY_NOT_CONTEXT_PROOF" ||
    !exactKeys(config.pricing, [
      "currency",
      "taxBasis",
      "unitTokens",
      "cacheHitInputMicrosPerMillion",
      "cacheMissInputMicrosPerMillion",
      "outputMicrosPerMillion",
      "asOf",
    ]) ||
    config.pricing.currency !== "USD" ||
    config.pricing.taxBasis !== "TAX_EXCLUSIVE" ||
    config.pricing.unitTokens !== 1_000_000 ||
    config.pricing.cacheHitInputMicrosPerMillion !== 300_000 ||
    config.pricing.cacheMissInputMicrosPerMillion !== 3_000_000 ||
    config.pricing.outputMicrosPerMillion !== 15_000_000 ||
    config.pricing.asOf !== "2026-07-31" ||
    config.taxExclusiveBudgetMicros !== 4_000_000 ||
    !exactKeys(config.officialContract, [
      "modelUrl",
      "chatUrl",
      "tokenEstimateUrl",
      "structuredOutputUrl",
      "pricingUrl",
      "researchPath",
      "researchSha256",
      "queriedAt",
    ]) ||
    canonicalize(config.officialContract) !== canonicalize(OFFICIAL_CONTRACT) ||
    config.fallbackPolicy !== "DISABLED_FAIL_CLOSED" ||
    !SHA256.test(config.configSha256 ?? "")
  ) {
    reasonCodes.push("KIMI_K3_CONFIG_INVALID");
  }
  if (
    SHA256.test(config?.configSha256 ?? "") &&
    configDigest(config) !== config.configSha256
  ) {
    reasonCodes.push("KIMI_K3_CONFIG_SELF_HASH_MISMATCH");
  }
  return {
    ok: reasonCodes.length === 0,
    reasonCodes: [...new Set(reasonCodes)].sort(),
  };
}

export async function validateMoonshotKimiK3FrozenContract({
  config,
  researchBytes,
}) {
  const configValidation = await validateMoonshotKimiK3Config(config);
  const researchValid =
    researchBytes instanceof Uint8Array &&
    sha256Bytes(researchBytes) === OFFICIAL_CONTRACT.researchSha256;
  return {
    ok: configValidation.ok && researchValid,
    reasonCodes: [
      ...configValidation.reasonCodes,
      ...(researchValid ? [] : ["KIMI_K3_OFFICIAL_RESEARCH_BINDING_MISMATCH"]),
    ].sort(),
  };
}

function fixedRequest(config, { promptBytes, materialBytes, outputSchemaBytes }) {
  const prompt = strictUtf8(promptBytes);
  const material = strictUtf8(materialBytes);
  const outputSchema = parseJsonBytes(outputSchemaBytes);
  if (prompt === null || material === null || outputSchema === null) {
    return null;
  }
  return {
    model: "kimi-k3",
    messages: [
      { role: "system", content: prompt },
      { role: "user", content: material },
    ],
    reasoning_effort: "max",
    tool_choice: "none",
    response_format: {
      type: "json_schema",
      json_schema: {
        name: config.responseFormat.name,
        strict: true,
        schema: outputSchema,
      },
    },
    max_completion_tokens: 32_768,
  };
}

function validFixedRequest(request, config) {
  return (
    exactKeys(request, REQUEST_KEYS) &&
    request.model === "kimi-k3" &&
    Array.isArray(request.messages) &&
    request.messages.length === 2 &&
    request.messages.every(
      (message, index) =>
        exactKeys(message, ["role", "content"]) &&
        message.role === (index === 0 ? "system" : "user") &&
        typeof message.content === "string" &&
        message.content.length > 0,
    ) &&
    request.reasoning_effort === "max" &&
    request.tool_choice === "none" &&
    !Object.hasOwn(request, "thinking") &&
    !Object.hasOwn(request, "tools") &&
    exactKeys(request.response_format, ["type", "json_schema"]) &&
    request.response_format.type === "json_schema" &&
    exactKeys(request.response_format.json_schema, ["name", "strict", "schema"]) &&
    request.response_format.json_schema.name === config.responseFormat.name &&
    request.response_format.json_schema.strict === true &&
    request.max_completion_tokens === 32_768
  );
}

export async function buildKimiK3IndependentReviewRequest({
  config,
  promptBytes,
  materialBytes,
  outputSchemaBytes,
}) {
  const configValidation = await validateMoonshotKimiK3Config(config);
  const request = fixedRequest(config, {
    promptBytes,
    materialBytes,
    outputSchemaBytes,
  });
  if (!configValidation.ok || request === null || !validFixedRequest(request, config)) {
    const error = new TypeError("Kimi K3 fixed request inputs are invalid.");
    error.reasonCodes = [
      ...configValidation.reasonCodes,
      "KIMI_K3_REQUEST_INVALID",
    ];
    throw error;
  }
  if (materialBytes.byteLength > config.maxReviewMaterialUtf8Bytes) {
    const error = new RangeError("Kimi K3 review material exceeds its byte limit.");
    error.reasonCodes = ["KIMI_K3_REVIEW_MATERIAL_BYTE_LIMIT_EXCEEDED"];
    throw error;
  }
  const requestBytes = Buffer.from(JSON.stringify(request), "utf8");
  const messagesBytes = Buffer.from(JSON.stringify(request.messages), "utf8");
  if (requestBytes.byteLength > config.maxRequestUtf8Bytes) {
    const error = new RangeError("Kimi K3 request exceeds its byte limit.");
    error.reasonCodes = ["KIMI_K3_REQUEST_BYTE_LIMIT_EXCEEDED"];
    throw error;
  }
  return {
    requestBytes,
    requestSha256: sha256Bytes(requestBytes),
    messagesSha256: sha256Bytes(messagesBytes),
    materialSha256: sha256Bytes(materialBytes),
    toolsAbsent: true,
    toolChoiceNone: true,
    strictSchema: true,
  };
}

export function buildKimiK3TokenEstimateRequest({
  config,
  formalRequestBytes,
}) {
  const formal = parseJsonBytes(formalRequestBytes);
  if (!formal || !validFixedRequest(formal, config)) {
    throw new TypeError("Kimi K3 formal request binding is invalid.");
  }
  const request = { model: "kimi-k3", messages: formal.messages };
  const requestBytes = Buffer.from(JSON.stringify(request), "utf8");
  const messagesBytes = Buffer.from(JSON.stringify(formal.messages), "utf8");
  return {
    requestBytes,
    requestSha256: sha256Bytes(requestBytes),
    messagesSha256: sha256Bytes(messagesBytes),
    coverage: "MESSAGES_ONLY",
  };
}

export function evaluateKimiK3SingleCallPreflight({
  config,
  estimatedInputTokens,
  estimateCoverage,
  estimateBindingsMatch,
  priceEvidenceCurrent,
  reasoningUsageCoveredByCompletionLimit,
  reasoningUsageCoveredByPublishedOutputPrice,
}) {
  const safeInteger =
    Number.isSafeInteger(estimatedInputTokens) && estimatedInputTokens >= 0;
  const requiredContextTokens = safeInteger
    ? estimatedInputTokens + config.maxCompletionTokens + config.safetyMarginTokens
    : null;
  const worstCaseInputCostMicros = safeInteger
    ? ceilDiv(
        estimatedInputTokens * config.pricing.cacheMissInputMicrosPerMillion,
        config.pricing.unitTokens,
      )
    : null;
  const worstCaseOutputCostMicros = ceilDiv(
    config.maxCompletionTokens * config.pricing.outputMicrosPerMillion,
    config.pricing.unitTokens,
  );
  const worstCaseTotalCostMicros =
    worstCaseInputCostMicros === null
      ? null
      : worstCaseInputCostMicros + worstCaseOutputCostMicros;
  const ok =
    safeInteger &&
    estimateCoverage === "FULL_MODEL_VISIBLE_INPUT_PROVED" &&
    estimateBindingsMatch === true &&
    priceEvidenceCurrent === true &&
    reasoningUsageCoveredByCompletionLimit === true &&
    reasoningUsageCoveredByPublishedOutputPrice === true &&
    requiredContextTokens <= config.contextWindowTokens &&
    worstCaseTotalCostMicros <= config.taxExclusiveBudgetMicros;
  return {
    ok,
    status: ok ? "READY" : "BLOCKED",
    reasonCodes: ok ? [] : ["KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED"],
    estimatedInputTokens: safeInteger ? estimatedInputTokens : null,
    requiredContextTokens,
    worstCaseInputCostMicros,
    worstCaseOutputCostMicros,
    worstCaseTotalCostMicros,
  };
}

function transportFailure(reasonCodes, networkAttemptCount) {
  return {
    ok: false,
    status: "BLOCKED",
    reasonCodes: [...new Set(reasonCodes)].sort(),
    networkAttemptCount,
  };
}

function containsCredential(value, credential) {
  if (typeof value === "string") return value.includes(credential);
  if (Array.isArray(value)) {
    return value.some((entry) => containsCredential(entry, credential));
  }
  if (value && typeof value === "object") {
    return Object.entries(value).some(
      ([key, entry]) =>
        key.toLowerCase().includes("authorization") ||
        containsCredential(entry, credential),
    );
  }
  return false;
}

function bytesContainCredential(bytes, credential) {
  return (
    bytes instanceof Uint8Array &&
    Buffer.from(bytes).includes(Buffer.from(credential, "utf8"))
  );
}

async function readBoundedResponseBytes({ response, maximumBytes, timeout }) {
  const reader = response?.body?.getReader?.();
  if (!reader) throw new TypeError("Kimi K3 response bytes unavailable.");
  const chunks = [];
  let byteLength = 0;
  try {
    while (true) {
      const current = await Promise.race([reader.read(), timeout]);
      if (current.done) break;
      if (!(current.value instanceof Uint8Array)) {
        throw new TypeError("Kimi K3 response contains non-byte content.");
      }
      byteLength += current.value.byteLength;
      if (byteLength > maximumBytes) {
        await reader.cancel("Kimi K3 response byte limit exceeded.");
        const error = new RangeError("Kimi K3 response byte limit exceeded.");
        error.code = "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED";
        throw error;
      }
      chunks.push(Buffer.from(current.value));
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, byteLength);
}

async function postBoundJson({
  url,
  requestBytes,
  apiKey,
  maximumResponseBytes,
  fetchImpl,
  timeoutMs,
}) {
  if (typeof apiKey !== "string" || apiKey.length < 16) {
    return transportFailure(
      ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
      0,
    );
  }
  if (
    !(requestBytes instanceof Uint8Array) ||
    bytesContainCredential(requestBytes, apiKey) ||
    typeof fetchImpl !== "function" ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 10 * 60_000
  ) {
    return transportFailure(["KIMI_K3_TRANSPORT_CONFIGURATION_INVALID"], 0);
  }
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new DOMException("Kimi K3 transport timed out.", "AbortError"));
    }, timeoutMs);
  });
  let response;
  let responseBytes;
  try {
    response = await Promise.race([
      fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "accept-encoding": "identity",
          authorization: `Bearer ${apiKey}`,
        },
        body: requestBytes,
        redirect: "error",
        signal: controller.signal,
      }),
      timeout,
    ]);
    if (response?.redirected !== false || response?.url !== url) {
      return transportFailure(["KIMI_K3_RESPONSE_ENDPOINT_MISMATCH"], 1);
    }
    if ([401, 402, 403, 429].includes(response.status)) {
      return transportFailure(
        ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
        1,
      );
    }
    const contentType = response.headers?.get?.("content-type") ?? "";
    const contentEncoding = response.headers?.get?.("content-encoding");
    if (
      response.status !== 200 ||
      !/^application\/json(?:;\s*charset=utf-8)?$/iu.test(contentType) ||
      ![null, "", "identity"].includes(contentEncoding)
    ) {
      return transportFailure(["KIMI_K3_RESPONSE_HTTP_INVALID"], 1);
    }
    responseBytes = await readBoundedResponseBytes({
      response,
      maximumBytes: maximumResponseBytes,
      timeout,
    });
  } catch (error) {
    return transportFailure(
      [
        error?.code === "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED"
          ? error.code
          : error?.name === "AbortError"
            ? "KIMI_K3_TRANSPORT_TIMEOUT"
            : "KIMI_K3_TRANSPORT_NETWORK_FAILED",
      ],
      1,
    );
  } finally {
    clearTimeout(timer);
  }
  if (
    responseBytes.byteLength === 0 ||
    bytesContainCredential(responseBytes, apiKey)
  ) {
    return transportFailure(
      [
        responseBytes.byteLength === 0
          ? "KIMI_K3_RESPONSE_BYTES_UNAVAILABLE"
          : "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED",
      ],
      1,
    );
  }
  return {
    ok: true,
    status: "CAPTURED",
    reasonCodes: [],
    networkAttemptCount: 1,
    httpStatus: 200,
    contentType:
      response.headers.get("content-type") ?? "application/json",
    responseBytes,
    responseSha256: sha256Bytes(responseBytes),
  };
}

export async function executeKimiK3TokenEstimate({
  config,
  estimateRequestBytes,
  formalRequestBytes,
  materialBytes,
  apiKey,
  fetchImpl,
  timeoutMs = 120_000,
}) {
  const configValidation = await validateMoonshotKimiK3Config(config);
  let expected;
  try {
    expected = buildKimiK3TokenEstimateRequest({
      config,
      formalRequestBytes,
    });
  } catch {
    expected = null;
  }
  if (
    !configValidation.ok ||
    !expected ||
    !(estimateRequestBytes instanceof Uint8Array) ||
    !Buffer.from(estimateRequestBytes).equals(expected.requestBytes) ||
    !(materialBytes instanceof Uint8Array)
  ) {
    return transportFailure(
      [
        ...configValidation.reasonCodes,
        "KIMI_K3_TOKEN_ESTIMATE_BINDING_MISMATCH",
      ],
      0,
    );
  }
  const transport = await postBoundJson({
    url: `${config.baseURL}${config.tokenEstimateEndpoint}`,
    requestBytes: estimateRequestBytes,
    apiKey,
    maximumResponseBytes: 64 * 1024,
    fetchImpl,
    timeoutMs,
  });
  if (!transport.ok) return transport;
  const body = parseJsonBytes(transport.responseBytes);
  if (
    !exactKeys(body, ["data"]) ||
    !exactKeys(body?.data, ["total_tokens"]) ||
    !Number.isSafeInteger(body.data.total_tokens) ||
    body.data.total_tokens < 0 ||
    containsCredential(body, apiKey)
  ) {
    return transportFailure(["KIMI_K3_TOKEN_ESTIMATE_RESPONSE_INVALID"], 1);
  }
  return {
    ...transport,
    estimatedInputTokens: body.data.total_tokens,
    estimateRequestSha256: sha256Bytes(estimateRequestBytes),
    formalRequestSha256: sha256Bytes(formalRequestBytes),
    messagesSha256: expected.messagesSha256,
    materialSha256: sha256Bytes(materialBytes),
    coverage: "MESSAGES_ONLY",
  };
}

function byteArtifact(path, bytes) {
  return {
    path,
    encoding: "UTF-8",
    byteLength: bytes.byteLength,
    sha256: sha256Bytes(bytes),
  };
}

function validDate(value) {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function tokenEstimateEvidenceDigest(evidence) {
  return sha256Value({
    ...evidence,
    evidenceSha256: EVIDENCE_SHA_PLACEHOLDER,
  });
}

export function createKimiK3TokenEstimateEvidence({
  evidenceId,
  config,
  configBytes,
  source,
  reviewBundleSha256,
  formalRequestBytes,
  materialBytes,
  estimateRequestBytes,
  estimateResponseBytes,
  estimatedInputTokens,
  coverage,
  httpStatus,
  contentType,
  networkAttemptCount,
  startedAt,
  finishedAt,
  artifactPaths,
}) {
  const preflight = evaluateKimiK3SingleCallPreflight({
    config,
    estimatedInputTokens,
    estimateCoverage: coverage,
    estimateBindingsMatch: true,
    priceEvidenceCurrent:
      typeof finishedAt === "string" &&
      finishedAt.slice(0, 10) === config.pricing.asOf,
    reasoningUsageCoveredByCompletionLimit: false,
    reasoningUsageCoveredByPublishedOutputPrice: false,
  });
  const formalRequest = parseJsonBytes(formalRequestBytes);
  const evidence = {
    schemaVersion: "moonshot-kimi-k3-token-estimate-evidence.v1",
    evidenceId,
    provider: "moonshot",
    model: "kimi-k3",
    baseURL: "https://api.moonshot.ai/v1",
    endpoint: "/tokenizers/estimate-token-count",
    source: structuredClone(source),
    bindings: {
      formalRequestSha256: sha256Bytes(formalRequestBytes),
      messagesSha256: sha256Bytes(
        Buffer.from(JSON.stringify(formalRequest?.messages), "utf8"),
      ),
      reviewMaterialSha256: sha256Bytes(materialBytes),
      reviewBundleSha256,
      configSha256: sha256Bytes(configBytes),
      requestSchemaCoverage: coverage,
    },
    request: byteArtifact(artifactPaths.request, estimateRequestBytes),
    response: {
      ...byteArtifact(artifactPaths.response, estimateResponseBytes),
      httpStatus,
      contentType,
    },
    estimate: {
      estimatedInputTokens,
      contextWindowTokens: config.contextWindowTokens,
      maxCompletionTokens: config.maxCompletionTokens,
      safetyMarginTokens: config.safetyMarginTokens,
      requiredContextTokens:
        estimatedInputTokens +
        config.maxCompletionTokens +
        config.safetyMarginTokens,
      coverage,
      contextProved: preflight.ok,
    },
    budget: {
      currency: "USD",
      taxBasis: "TAX_EXCLUSIVE",
      budgetMicros: config.taxExclusiveBudgetMicros,
      worstCaseInputMicros: preflight.worstCaseInputCostMicros,
      worstCaseOutputMicros: preflight.worstCaseOutputCostMicros,
      worstCaseTotalMicros: preflight.worstCaseTotalCostMicros,
      budgetProved:
        preflight.worstCaseTotalCostMicros !== null &&
        preflight.worstCaseTotalCostMicros <= config.taxExclusiveBudgetMicros &&
        coverage === "FULL_MODEL_VISIBLE_INPUT_PROVED",
    },
    networkAttemptCount,
    startedAt,
    finishedAt,
    evidenceSha256: EVIDENCE_SHA_PLACEHOLDER,
  };
  evidence.evidenceSha256 = tokenEstimateEvidenceDigest(evidence);
  return evidence;
}

export function validateKimiK3TokenEstimateEvidence({
  evidence,
  config,
  configBytes,
  source,
  reviewBundleSha256,
  formalRequestBytes,
  materialBytes,
  estimateRequestBytes,
  estimateResponseBytes,
}) {
  const formalRequest = parseJsonBytes(formalRequestBytes);
  let expectedEstimateRequest = null;
  try {
    expectedEstimateRequest = buildKimiK3TokenEstimateRequest({
      config,
      formalRequestBytes,
    });
  } catch {
    expectedEstimateRequest = null;
  }
  const response = parseJsonBytes(estimateResponseBytes);
  const estimatedInputTokens = response?.data?.total_tokens;
  const coverage = evidence?.estimate?.coverage;
  const expected =
    expectedEstimateRequest &&
    Number.isSafeInteger(estimatedInputTokens) &&
    estimatedInputTokens >= 0
      ? createKimiK3TokenEstimateEvidence({
          evidenceId: evidence?.evidenceId,
          config,
          configBytes,
          source,
          reviewBundleSha256,
          formalRequestBytes,
          materialBytes,
          estimateRequestBytes,
          estimateResponseBytes,
          estimatedInputTokens,
          coverage,
          httpStatus: evidence?.response?.httpStatus,
          contentType: evidence?.response?.contentType,
          networkAttemptCount: evidence?.networkAttemptCount,
          startedAt: evidence?.startedAt,
          finishedAt: evidence?.finishedAt,
          artifactPaths: {
            request: evidence?.request?.path,
            response: evidence?.response?.path,
          },
        })
      : null;
  const valid =
    expected !== null &&
    COMMIT.test(source?.runtimeCommit ?? "") &&
    COMMIT.test(source?.sourceCommit ?? "") &&
    COMMIT.test(source?.sourceTree ?? "") &&
    source.runtimeCommit !== source.sourceCommit &&
    SHA256.test(reviewBundleSha256 ?? "") &&
    SHA256.test(evidence?.evidenceSha256 ?? "") &&
    SAFE_PATH.test(evidence?.request?.path ?? "") &&
    SAFE_PATH.test(evidence?.response?.path ?? "") &&
    validDate(evidence?.startedAt) &&
    validDate(evidence?.finishedAt) &&
    Date.parse(evidence.startedAt) <= Date.parse(evidence.finishedAt) &&
    Buffer.from(estimateRequestBytes).equals(
      expectedEstimateRequest.requestBytes,
    ) &&
    parseJsonBytes(configBytes)?.configSha256 === config.configSha256 &&
    sha256Bytes(configBytes) === evidence?.bindings?.configSha256 &&
    canonicalize(evidence) === canonicalize(expected) &&
    tokenEstimateEvidenceDigest(evidence) === evidence.evidenceSha256 &&
    formalRequest?.model === "kimi-k3";
  return {
    ok: valid,
    reasonCodes: valid ? [] : ["KIMI_K3_TOKEN_ESTIMATE_EVIDENCE_INVALID"],
  };
}

function validUsage(usage, config) {
  return (
    exactKeys(usage, [
      "prompt_tokens",
      "completion_tokens",
      "total_tokens",
      "cached_tokens",
    ]) &&
    [
      usage.prompt_tokens,
      usage.completion_tokens,
      usage.total_tokens,
      usage.cached_tokens,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    usage.cached_tokens <= usage.prompt_tokens &&
    usage.total_tokens === usage.prompt_tokens + usage.completion_tokens &&
    usage.completion_tokens <= config.maxCompletionTokens &&
    usage.total_tokens <= config.contextWindowTokens
  );
}

export async function validateKimiK3ChatResponse({
  config,
  responseBytes,
  outputSchemaBytes,
}) {
  if (
    !(responseBytes instanceof Uint8Array) ||
    responseBytes.byteLength > config.maxResponseUtf8Bytes ||
    !(outputSchemaBytes instanceof Uint8Array)
  ) {
    return { ok: false, reasonCodes: ["KIMI_K3_RESPONSE_PROTOCOL_INVALID"] };
  }
  const body = parseJsonBytes(responseBytes);
  const choice = body?.choices?.[0];
  const message = choice?.message;
  const messageKeys = Object.keys(message ?? {}).sort();
  const allowedMessageKeys = [
    ["content", "role"],
    ["content", "reasoning_content", "role"],
  ];
  if (
    !exactKeys(body, ["id", "object", "created", "model", "choices", "usage"]) ||
    typeof body.id !== "string" ||
    body.id.length < 8 ||
    body.object !== "chat.completion" ||
    !Number.isSafeInteger(body.created) ||
    body.created < 0 ||
    body.model !== "kimi-k3" ||
    !Array.isArray(body.choices) ||
    body.choices.length !== 1 ||
    !exactKeys(choice, ["index", "message", "finish_reason"]) ||
    choice.index !== 0 ||
    choice.finish_reason !== "stop" ||
    !allowedMessageKeys.some(
      (keys) => JSON.stringify(keys) === JSON.stringify(messageKeys),
    ) ||
    message.role !== "assistant" ||
    typeof message.content !== "string" ||
    message.content.length === 0 ||
    (Object.hasOwn(message, "reasoning_content") &&
      typeof message.reasoning_content !== "string") ||
    Object.hasOwn(message, "tool_calls") ||
    Object.hasOwn(message, "function_call") ||
    Object.hasOwn(message, "refusal") ||
    !validUsage(body.usage, config)
  ) {
    return { ok: false, reasonCodes: ["KIMI_K3_RESPONSE_PROTOCOL_INVALID"] };
  }
  const contentBytes = Buffer.from(message.content, "utf8");
  const outputValidation =
    await validateIndependentModelReviewOutputArtifact({
      rawModelOutput: contentBytes,
      outputSchemaBytes,
      expectedOutputSchemaSha256: sha256Bytes(outputSchemaBytes),
    });
  if (!outputValidation.ok) {
    return {
      ok: false,
      reasonCodes: [
        "KIMI_K3_RESPONSE_SCHEMA_OR_SEMANTIC_INVALID",
        ...outputValidation.reasonCodes,
      ],
    };
  }
  const actualInputCostMicros = ceilDiv(
    body.usage.prompt_tokens * config.pricing.cacheMissInputMicrosPerMillion,
    config.pricing.unitTokens,
  );
  const actualOutputCostMicros = ceilDiv(
    body.usage.completion_tokens * config.pricing.outputMicrosPerMillion,
    config.pricing.unitTokens,
  );
  if (
    actualInputCostMicros + actualOutputCostMicros >
    config.taxExclusiveBudgetMicros
  ) {
    return { ok: false, reasonCodes: ["KIMI_K3_SINGLE_CALL_BUDGET_EXCEEDED"] };
  }
  return {
    ok: true,
    reasonCodes: [],
    actualReturnedModel: body.model,
    responseId: body.id,
    finishReason: choice.finish_reason,
    usage: structuredClone(body.usage),
    actualTaxExclusiveCostMicros:
      actualInputCostMicros + actualOutputCostMicros,
    responseSha256: sha256Bytes(responseBytes),
    contentBytes,
    contentSha256: sha256Bytes(contentBytes),
  };
}
