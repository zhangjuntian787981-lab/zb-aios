import { createHash } from "node:crypto";
import {
  parseIndependentReviewJsonBytes,
  validateIndependentModelReviewOutputArtifact,
  validateIndependentReviewSchemaInstance,
} from "./independent-model-review.mjs";
import { kimiK3TokenEstimateResponseArtifactIsSafe } from "./kimi-k3-independent-review.mjs";
import { validateIndependentReviewRuntimeDependencyManifest } from "./independent-review-runtime-manifest.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const EMPTY_SHA256 =
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const PLACEHOLDER = `sha256:${"0".repeat(64)}`;
const K3_PROVIDER = "moonshot";
const K3_MODEL = "kimi-k3";
const K3_BASE_URL = "https://api.moonshot.ai/v1";
const K3_CHAT_ENDPOINT = "/chat/completions";
const K3_ESTIMATE_ENDPOINT = "/tokenizers/estimate-token-count";
const K3_PROVIDER_TRANSPORT_SCHEMA_PATH =
  "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json";
const CANONICAL_OUTPUT_SCHEMA_PATH =
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json";
const TRANSPORT_V4_SCHEMA_PATH =
  "implementation/governance/schemas/independent-review-transport-evidence.v4.schema.json";
const RECEIPT_V6_SCHEMA_PATH =
  "implementation/governance/schemas/independent-model-review-receipt.v6.schema.json";
const RECEIPT_V7_SCHEMA_PATH =
  "implementation/governance/schemas/independent-model-review-receipt.v7.schema.json";
const RUNTIME_MANIFEST_V2_PATH =
  "implementation/governance/independent-review/kimi-runtime-manifest.v2.json";
const RUNTIME_MANIFEST_V3_PATH =
  "implementation/governance/independent-review/kimi-runtime-manifest.v3.json";
const RUNTIME_MANIFEST_V3_SCHEMA_PATH =
  "implementation/governance/schemas/independent-review-runtime-manifest.v3.schema.json";
const CONTEXT_TOKENS = 1_048_576;
const COMPLETION_TOKENS = 32_768;
const SAFETY_TOKENS = 8_192;
const BUDGET_MICROS = 4_000_000;

const ESTIMATE_KEYS = [
  "schemaVersion",
  "evidenceId",
  "provider",
  "model",
  "baseURL",
  "endpoint",
  "source",
  "bindings",
  "request",
  "response",
  "estimate",
  "budget",
  "networkAttemptCount",
  "startedAt",
  "finishedAt",
  "evidenceSha256",
];
const TRANSPORT_KEYS = [
  "schemaVersion",
  "evidenceId",
  "provider",
  "requestedModel",
  "actualReturnedModel",
  "responseId",
  "baseURL",
  "endpoint",
  "source",
  "bindings",
  "request",
  "response",
  "content",
  "protocol",
  "usage",
  "cost",
  "validators",
  "startedAt",
  "finishedAt",
  "transportEvidenceSha256",
];
const RECEIPT_KEYS = [
  "schemaVersion",
  "receiptId",
  "receiptSchemaVersion",
  "reviewId",
  "policyVersion",
  "policySha256",
  "assuranceLevel",
  "applicablePhase",
  "humanIndependentReviewSatisfied",
  "independentModelReviewRequired",
  "p3HumanReviewRequired",
  "bundleId",
  "bundleSha256",
  "reviewMaterialSha256",
  "reviewer",
  "source",
  "bindings",
  "artifacts",
  "contextAndBudget",
  "usage",
  "cost",
  "isolationEvidence",
  "reviewedPaths",
  "findings",
  "testEvidenceDigests",
  "decision",
  "conclusion",
  "historicalTerraEvidenceAccepted",
  "historicalK2EvidenceAccepted",
  "humanReviewClaim",
  "governanceEffect",
  "selfAuthorizing",
  "startedAt",
  "finishedAt",
  "recordedAt",
  "receiptSha256",
];

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
  throw new TypeError("K3 evidence contains an unsupported JSON value.");
}

function hashBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("K3 evidence hashing requires exact bytes.");
  }
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function hashValue(value) {
  return hashBytes(Buffer.from(canonicalize(value), "utf8"));
}

function hashJsonUtf8(value) {
  return hashBytes(Buffer.from(JSON.stringify(value), "utf8"));
}

function ceilDiv(numerator, denominator) {
  return Math.floor((numerator + denominator - 1) / denominator);
}

function hashWithout(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return hashValue(copy);
}

function estimateDigest(value) {
  return hashValue({
    ...value,
    evidenceSha256: PLACEHOLDER,
  });
}

function transportDigest(value) {
  return hashWithout(value, "transportEvidenceSha256");
}

function receiptDigest(value) {
  return hashWithout(value, "receiptSha256");
}

export const kimiK3ReviewEvidenceDigests = Object.freeze({
  bytes: hashBytes,
  value: hashValue,
  estimate: estimateDigest,
  transport: transportDigest,
  receipt: receiptDigest,
});

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalize(Object.keys(value).sort()) === canonicalize([...keys].sort())
  );
}

function validSha(value) {
  return typeof value === "string" && SHA256.test(value);
}

function validCommit(value) {
  return typeof value === "string" && COMMIT.test(value);
}

function validDate(value) {
  return (
    typeof value === "string" &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function validPath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512 &&
    SAFE_PATH.test(value)
  );
}

function validByteArtifact(value, maximum = 16 * 1024 * 1024) {
  return (
    exactKeys(value, ["path", "encoding", "byteLength", "sha256"]) &&
    validPath(value.path) &&
    value.encoding === "UTF-8" &&
    Number.isSafeInteger(value.byteLength) &&
    value.byteLength > 0 &&
    value.byteLength <= maximum &&
    validSha(value.sha256)
  );
}

function validResponseArtifact(value, maximum = 16 * 1024 * 1024) {
  return (
    exactKeys(value, [
      "path",
      "encoding",
      "byteLength",
      "sha256",
      "httpStatus",
      "contentType",
    ]) &&
    validPath(value.path) &&
    value.encoding === "UTF-8" &&
    Number.isSafeInteger(value.byteLength) &&
    value.byteLength > 0 &&
    value.byteLength <= maximum &&
    validSha(value.sha256) &&
    value.httpStatus === 200 &&
    /^application\/json(?:;\s*charset=utf-8)?$/iu.test(value.contentType)
  );
}

function result(valid, reasonCodes, extra = {}) {
  return valid
    ? { valid: true, reasonCodes: [], ...extra }
    : {
        valid: false,
        status: "REJECTED",
        reasonCodes: [...new Set(reasonCodes)].sort(),
      };
}

function parseJsonBytes(bytes) {
  if (!(bytes instanceof Uint8Array)) return null;
  try {
    const value = parseIndependentReviewJsonBytes(
      bytes,
      "K3 evidence JSON artifact",
      16 * 1024 * 1024,
    );
    return value && typeof value === "object" && !Array.isArray(value)
      ? value
      : null;
  } catch {
    return null;
  }
}

async function readArtifact(resolver, descriptor) {
  if (typeof resolver !== "function" || !validPath(descriptor?.path)) {
    return null;
  }
  try {
    const bytes = await resolver(descriptor.path, {
      sourceCommit: descriptor.sourceCommit ?? null,
    });
    return bytes instanceof Uint8Array ? Buffer.from(bytes) : null;
  } catch {
    return null;
  }
}

function artifactMatches(descriptor, bytes) {
  return (
    bytes instanceof Uint8Array &&
    bytes.byteLength === descriptor.byteLength &&
    hashBytes(bytes) === descriptor.sha256
  );
}

function uniquePaths(descriptors) {
  const paths = descriptors.map((value) => value?.path);
  return paths.every(validPath) && new Set(paths).size === paths.length;
}

function k3FormalRequestValid(request) {
  return (
    exactKeys(request, [
      "model",
      "messages",
      "reasoning_effort",
      "tool_choice",
      "response_format",
      "max_completion_tokens",
    ]) &&
    request.model === K3_MODEL &&
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
    exactKeys(request.response_format.json_schema, [
      "name",
      "strict",
      "schema",
    ]) &&
    request.response_format.json_schema.strict === true &&
    request.max_completion_tokens === COMPLETION_TOKENS
  );
}

function providerUsageValid(usage) {
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
    usage.completion_tokens <= COMPLETION_TOKENS &&
    usage.cached_tokens <= usage.prompt_tokens &&
    usage.total_tokens === usage.prompt_tokens + usage.completion_tokens &&
    usage.total_tokens <= CONTEXT_TOKENS
  );
}

function normalizedUsageValid(usage) {
  return (
    exactKeys(usage, [
      "promptTokens",
      "completionTokens",
      "totalTokens",
      "cachedTokens",
    ]) &&
    [
      usage.promptTokens,
      usage.completionTokens,
      usage.totalTokens,
      usage.cachedTokens,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    usage.completionTokens <= COMPLETION_TOKENS &&
    usage.cachedTokens <= usage.promptTokens &&
    usage.totalTokens === usage.promptTokens + usage.completionTokens &&
    usage.totalTokens <= CONTEXT_TOKENS
  );
}

function normalizedUsageMatches(normalized, provider) {
  return (
    normalized.promptTokens === provider.prompt_tokens &&
    normalized.completionTokens === provider.completion_tokens &&
    normalized.totalTokens === provider.total_tokens &&
    normalized.cachedTokens === provider.cached_tokens
  );
}

export function createKimiK3TokenEstimateEvidence(input) {
  const evidence = {
    ...structuredClone(input),
    evidenceSha256: PLACEHOLDER,
  };
  evidence.evidenceSha256 = estimateDigest(evidence);
  return evidence;
}

function estimateShapeValid(evidence) {
  return (
    exactKeys(evidence, ESTIMATE_KEYS) &&
    evidence.schemaVersion ===
      "moonshot-kimi-k3-token-estimate-evidence.v1" &&
    /^mk3tee_[a-z0-9][a-z0-9_-]{7,127}$/u.test(
      evidence.evidenceId ?? "",
    ) &&
    evidence.provider === K3_PROVIDER &&
    evidence.model === K3_MODEL &&
    evidence.baseURL === K3_BASE_URL &&
    evidence.endpoint === K3_ESTIMATE_ENDPOINT &&
    exactKeys(evidence.source, [
      "runtimeCommit",
      "sourceCommit",
      "sourceTree",
    ]) &&
    validCommit(evidence.source.runtimeCommit) &&
    validCommit(evidence.source.sourceCommit) &&
    validCommit(evidence.source.sourceTree) &&
    evidence.source.runtimeCommit !== evidence.source.sourceCommit &&
    exactKeys(evidence.bindings, [
      "formalRequestSha256",
      "messagesSha256",
      "reviewMaterialSha256",
      "reviewBundleSha256",
      "configSha256",
      "requestSchemaCoverage",
    ]) &&
    [
      evidence.bindings.formalRequestSha256,
      evidence.bindings.messagesSha256,
      evidence.bindings.reviewMaterialSha256,
      evidence.bindings.reviewBundleSha256,
      evidence.bindings.configSha256,
    ].every(validSha) &&
    evidence.bindings.requestSchemaCoverage === "MESSAGES_ONLY" &&
    validByteArtifact(evidence.request, 1_572_864) &&
    validResponseArtifact(evidence.response, 1_048_576) &&
    evidence.request.path !== evidence.response.path &&
    exactKeys(evidence.estimate, [
      "estimatedInputTokens",
      "contextWindowTokens",
      "maxCompletionTokens",
      "safetyMarginTokens",
      "requiredContextTokens",
      "coverage",
      "contextProved",
    ]) &&
    Number.isSafeInteger(evidence.estimate.estimatedInputTokens) &&
    evidence.estimate.estimatedInputTokens >= 0 &&
    evidence.estimate.contextWindowTokens === CONTEXT_TOKENS &&
    evidence.estimate.maxCompletionTokens === COMPLETION_TOKENS &&
    evidence.estimate.safetyMarginTokens === SAFETY_TOKENS &&
    Number.isSafeInteger(evidence.estimate.requiredContextTokens) &&
    evidence.estimate.coverage === "MESSAGES_ONLY" &&
    evidence.estimate.contextProved === false &&
    exactKeys(evidence.budget, [
      "currency",
      "taxBasis",
      "budgetMicros",
      "worstCaseInputMicros",
      "worstCaseOutputMicros",
      "worstCaseTotalMicros",
      "budgetProved",
    ]) &&
    evidence.budget.currency === "USD" &&
    evidence.budget.taxBasis === "TAX_EXCLUSIVE" &&
    evidence.budget.budgetMicros === BUDGET_MICROS &&
    [
      evidence.budget.worstCaseInputMicros,
      evidence.budget.worstCaseOutputMicros,
      evidence.budget.worstCaseTotalMicros,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    evidence.budget.budgetProved === false &&
    evidence.networkAttemptCount === 1 &&
    validDate(evidence.startedAt) &&
    validDate(evidence.finishedAt) &&
    validSha(evidence.evidenceSha256)
  );
}

export async function validateKimiK3TokenEstimateEvidence({
  evidence,
  evidenceResolver,
}) {
  const reasonCodes = [];
  if (!estimateShapeValid(evidence)) {
    return result(false, ["KIMI_K3_TOKEN_ESTIMATE_SHAPE_INVALID"]);
  }
  if (estimateDigest(evidence) !== evidence.evidenceSha256) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_SELF_HASH_MISMATCH");
  }
  if (Date.parse(evidence.finishedAt) < Date.parse(evidence.startedAt)) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_TIME_ORDER_INVALID");
  }
  if (
    evidence.estimate.coverage !==
      evidence.bindings.requestSchemaCoverage ||
    evidence.estimate.requiredContextTokens !==
      evidence.estimate.estimatedInputTokens +
        COMPLETION_TOKENS +
        SAFETY_TOKENS ||
    evidence.estimate.contextProved !== false
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_CONTEXT_INVALID");
  }
  if (
    evidence.budget.worstCaseTotalMicros !==
      evidence.budget.worstCaseInputMicros +
        evidence.budget.worstCaseOutputMicros ||
    evidence.budget.worstCaseInputMicros !==
      ceilDiv(
        evidence.estimate.estimatedInputTokens * 3_000_000,
        1_000_000,
      ) ||
    evidence.budget.worstCaseOutputMicros !==
      ceilDiv(COMPLETION_TOKENS * 15_000_000, 1_000_000) ||
    evidence.budget.budgetProved !== false
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_BUDGET_INVALID");
  }
  const requestBytes = await readArtifact(evidenceResolver, evidence.request);
  const responseBytes = await readArtifact(evidenceResolver, evidence.response);
  if (
    !artifactMatches(evidence.request, requestBytes) ||
    !artifactMatches(evidence.response, responseBytes)
  ) {
    return result(false, [
      ...reasonCodes,
      "KIMI_K3_TOKEN_ESTIMATE_BYTES_MISMATCH",
    ]);
  }
  const request = parseJsonBytes(requestBytes);
  const response = parseJsonBytes(responseBytes);
  if (
    !exactKeys(request, ["model", "messages"]) ||
    request.model !== K3_MODEL ||
    !Array.isArray(request.messages) ||
    request.messages.length !== 2 ||
    hashJsonUtf8(request.messages) !== evidence.bindings.messagesSha256
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_REQUEST_INVALID");
  }
  if (
    !exactKeys(response, ["data"]) ||
    !exactKeys(response?.data, ["total_tokens"]) ||
    response.data.total_tokens !== evidence.estimate.estimatedInputTokens
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_RESPONSE_INVALID");
  }
  return result(reasonCodes.length === 0, reasonCodes, {
    status: evidence.estimate.contextProved ? "PROVED" : "CAPTURED",
    contextProved: evidence.estimate.contextProved,
    budgetProved: evidence.budget.budgetProved,
  });
}

export function createKimiK3TransportEvidence(input) {
  const evidence = {
    ...structuredClone(input),
    transportEvidenceSha256: PLACEHOLDER,
  };
  evidence.transportEvidenceSha256 = transportDigest(evidence);
  return evidence;
}

function transportShapeValid(evidence) {
  return (
    exactKeys(evidence, TRANSPORT_KEYS) &&
    evidence.schemaVersion === "independent-review-transport-evidence.v2" &&
    /^irte_[a-z0-9][a-z0-9_-]{7,127}$/u.test(evidence.evidenceId ?? "") &&
    evidence.provider === K3_PROVIDER &&
    evidence.requestedModel === K3_MODEL &&
    evidence.actualReturnedModel === K3_MODEL &&
    /^chatcmpl_[A-Za-z0-9_-]{8,255}$/u.test(evidence.responseId ?? "") &&
    evidence.baseURL === K3_BASE_URL &&
    evidence.endpoint === K3_CHAT_ENDPOINT &&
    exactKeys(evidence.source, ["sourceCommit", "sourceTree"]) &&
    validCommit(evidence.source.sourceCommit) &&
    validCommit(evidence.source.sourceTree) &&
    exactKeys(evidence.bindings, [
      "reviewBundleSha256",
      "reviewerPromptSha256",
      "receiptSchemaSha256",
      "outputSchemaPath",
      "outputSchemaSha256",
      "providerConfigSha256",
      "tokenEstimateEvidenceSha256",
    ]) &&
    validSha(evidence.bindings.reviewBundleSha256) &&
    validSha(evidence.bindings.reviewerPromptSha256) &&
    validSha(evidence.bindings.receiptSchemaSha256) &&
    validPath(evidence.bindings.outputSchemaPath) &&
    validSha(evidence.bindings.outputSchemaSha256) &&
    validSha(evidence.bindings.providerConfigSha256) &&
    validSha(evidence.bindings.tokenEstimateEvidenceSha256) &&
    validByteArtifact(evidence.request, 1_572_864) &&
    validResponseArtifact(evidence.response, 1_048_576) &&
    validByteArtifact(evidence.content, 1_048_576) &&
    uniquePaths([evidence.request, evidence.response, evidence.content]) &&
    exactKeys(evidence.protocol, [
      "toolsAbsent",
      "toolChoiceNone",
      "thinkingAbsent",
      "reasoningEffort",
      "strictSchema",
      "maxCompletionTokens",
      "networkAttemptCount",
      "choiceCount",
      "finishReason",
    ]) &&
    evidence.protocol.toolsAbsent === true &&
    evidence.protocol.toolChoiceNone === true &&
    evidence.protocol.thinkingAbsent === true &&
    evidence.protocol.reasoningEffort === "max" &&
    evidence.protocol.strictSchema === true &&
    evidence.protocol.maxCompletionTokens === COMPLETION_TOKENS &&
    evidence.protocol.networkAttemptCount === 1 &&
    evidence.protocol.choiceCount === 1 &&
    evidence.protocol.finishReason === "stop" &&
    normalizedUsageValid(evidence.usage) &&
    exactKeys(evidence.cost, [
      "currency",
      "taxBasis",
      "inputMicros",
      "outputMicros",
      "totalMicros",
      "budgetMicros",
      "withinBudget",
    ]) &&
    evidence.cost.currency === "USD" &&
    evidence.cost.taxBasis === "TAX_EXCLUSIVE" &&
    [
      evidence.cost.inputMicros,
      evidence.cost.outputMicros,
      evidence.cost.totalMicros,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    evidence.cost.budgetMicros === BUDGET_MICROS &&
    evidence.cost.withinBudget === true &&
    exactKeys(evidence.validators, [
      "schemaValidatorVersion",
      "semanticValidatorVersion",
    ]) &&
    typeof evidence.validators.schemaValidatorVersion === "string" &&
    evidence.validators.schemaValidatorVersion.length > 0 &&
    typeof evidence.validators.semanticValidatorVersion === "string" &&
    evidence.validators.semanticValidatorVersion.length > 0 &&
    validDate(evidence.startedAt) &&
    validDate(evidence.finishedAt) &&
    validSha(evidence.transportEvidenceSha256)
  );
}

export async function validateKimiK3TransportEvidence({
  evidence,
  tokenEstimateEvidence,
  evidenceResolver,
}) {
  const reasonCodes = [];
  if (!transportShapeValid(evidence)) {
    return result(false, ["KIMI_K3_TRANSPORT_SHAPE_INVALID"]);
  }
  if (transportDigest(evidence) !== evidence.transportEvidenceSha256) {
    reasonCodes.push("KIMI_K3_TRANSPORT_SELF_HASH_MISMATCH");
  }
  if (Date.parse(evidence.finishedAt) < Date.parse(evidence.startedAt)) {
    reasonCodes.push("KIMI_K3_TRANSPORT_TIME_ORDER_INVALID");
  }
  const estimateValidation = await validateKimiK3TokenEstimateEvidence({
    evidence: tokenEstimateEvidence,
    evidenceResolver,
  });
  if (!estimateValidation.valid) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_EVIDENCE_INVALID");
    reasonCodes.push(...estimateValidation.reasonCodes);
  }
  if (
    evidence.bindings.tokenEstimateEvidenceSha256 !==
      tokenEstimateEvidence?.evidenceSha256 ||
    evidence.bindings.reviewBundleSha256 !==
      tokenEstimateEvidence?.bindings?.reviewBundleSha256 ||
    evidence.bindings.providerConfigSha256 !==
      tokenEstimateEvidence?.bindings?.configSha256 ||
    tokenEstimateEvidence?.estimate?.coverage !==
      "FULL_MODEL_VISIBLE_INPUT_PROVED" ||
    tokenEstimateEvidence?.estimate?.contextProved !== true ||
    tokenEstimateEvidence?.budget?.budgetProved !== true
  ) {
    reasonCodes.push("KIMI_K3_CONTEXT_NOT_PROVED");
  }
  const [requestBytes, responseBytes, contentBytes] = await Promise.all([
    readArtifact(evidenceResolver, evidence.request),
    readArtifact(evidenceResolver, evidence.response),
    readArtifact(evidenceResolver, evidence.content),
  ]);
  if (
    !artifactMatches(evidence.request, requestBytes) ||
    !artifactMatches(evidence.response, responseBytes) ||
    !artifactMatches(evidence.content, contentBytes)
  ) {
    return result(false, [
      ...reasonCodes,
      "KIMI_K3_TRANSPORT_BYTES_MISMATCH",
    ]);
  }
  const request = parseJsonBytes(requestBytes);
  const response = parseJsonBytes(responseBytes);
  const content = parseJsonBytes(contentBytes);
  const message = response?.choices?.[0]?.message;
  if (
    !k3FormalRequestValid(request) ||
    hashBytes(requestBytes) !==
      tokenEstimateEvidence?.bindings?.formalRequestSha256 ||
    hashJsonUtf8(request.messages) !==
      tokenEstimateEvidence?.bindings?.messagesSha256 ||
    hashBytes(Buffer.from(request.messages[1].content, "utf8")) !==
      tokenEstimateEvidence?.bindings?.reviewMaterialSha256
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_REQUEST_INVALID");
  }
  if (
    !response ||
    response.id !== evidence.responseId ||
    response.model !== K3_MODEL ||
    !Array.isArray(response.choices) ||
    response.choices.length !== 1 ||
    response.choices[0]?.finish_reason !== "stop" ||
    response.choices[0]?.index !== 0 ||
    message?.role !== "assistant" ||
    message?.content !== new TextDecoder().decode(contentBytes) ||
    Object.hasOwn(message ?? {}, "tool_calls") ||
    Object.hasOwn(message ?? {}, "function_call") ||
    !providerUsageValid(response.usage) ||
    !normalizedUsageMatches(evidence.usage, response.usage) ||
    !content
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_RESPONSE_INVALID");
  }
  if (
    evidence.cost.totalMicros !==
      evidence.cost.inputMicros + evidence.cost.outputMicros ||
    evidence.cost.inputMicros !==
      ceilDiv(evidence.usage.promptTokens * 3_000_000, 1_000_000) ||
    evidence.cost.outputMicros !==
      ceilDiv(
        evidence.usage.completionTokens * 15_000_000,
        1_000_000,
      ) ||
    evidence.cost.withinBudget !==
      (evidence.cost.totalMicros <= evidence.cost.budgetMicros)
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_COST_INVALID");
  }
  return result(reasonCodes.length === 0, reasonCodes, {
    status: "PROVED",
    actualReturnedModel: K3_MODEL,
  });
}

export function createKimiK3ReviewReceipt(input) {
  const receipt = {
    ...structuredClone(input),
    receiptSha256: PLACEHOLDER,
  };
  receipt.receiptSha256 = receiptDigest(receipt);
  return receipt;
}

function receiptShapeValid(receipt) {
  return (
    exactKeys(receipt, RECEIPT_KEYS) &&
    receipt.schemaVersion === "independent-model-review-receipt.v4" &&
    receipt.receiptSchemaVersion === "independent-model-review-receipt.v4" &&
    receipt.reviewId === receipt.receiptId &&
    /^imrr_[a-z0-9][a-z0-9_-]{7,127}$/u.test(receipt.receiptId ?? "") &&
    receipt.policyVersion === "2.0.0-candidate.3" &&
    validSha(receipt.policySha256) &&
    receipt.assuranceLevel === "MODEL_ONLY_PREPRODUCTION" &&
    ["P0", "P1", "P2"].includes(receipt.applicablePhase) &&
    receipt.humanIndependentReviewSatisfied === false &&
    receipt.independentModelReviewRequired === true &&
    receipt.p3HumanReviewRequired === true &&
    typeof receipt.bundleId === "string" &&
    receipt.bundleId.length >= 8 &&
    validSha(receipt.bundleSha256) &&
    validSha(receipt.reviewMaterialSha256) &&
    receipt.historicalTerraEvidenceAccepted === false &&
    receipt.historicalK2EvidenceAccepted === false &&
    receipt.humanReviewClaim === false &&
    receipt.governanceEffect === "NONE" &&
    receipt.selfAuthorizing === false &&
    validDate(receipt.startedAt) &&
    validDate(receipt.finishedAt) &&
    validDate(receipt.recordedAt) &&
    receipt.recordedAt === receipt.finishedAt &&
    validSha(receipt.receiptSha256)
  );
}

function artifactsShapeValid(artifacts) {
  return (
    exactKeys(artifacts, [
      "tokenEstimateRequest",
      "tokenEstimateResponse",
      "tokenEstimateEvidence",
      "request",
      "response",
      "content",
      "material",
      "transportEvidence",
    ]) &&
    Object.values(artifacts).every((artifact) => validByteArtifact(artifact)) &&
    uniquePaths(Object.values(artifacts))
  );
}

function snapshotValid(snapshot) {
  return (
    exactKeys(snapshot, [
      "head",
      "tree",
      "worktreeStatusSha256",
      "worktreeContentManifestSha256",
      "worktreePathCount",
      "protectedPathSetSha256",
      "protectedFilesDigest",
      "ignoredExclusionPolicySha256",
      "ignoredExcludedPathCount",
    ]) &&
    validCommit(snapshot.head) &&
    validCommit(snapshot.tree) &&
    [
      snapshot.worktreeStatusSha256,
      snapshot.worktreeContentManifestSha256,
      snapshot.protectedPathSetSha256,
      snapshot.protectedFilesDigest,
      snapshot.ignoredExclusionPolicySha256,
    ].every(validSha) &&
    Number.isSafeInteger(snapshot.worktreePathCount) &&
    snapshot.worktreePathCount >= 0 &&
    Number.isSafeInteger(snapshot.ignoredExcludedPathCount) &&
    snapshot.ignoredExcludedPathCount >= 0
  );
}

function gitDiffCheckValid(check, source) {
  return (
    exactKeys(check, [
      "schemaVersion",
      "checkId",
      "executionMode",
      "baseCommit",
      "sourceCommit",
      "sourceTree",
      "checkedPatchSha256",
      "runnerPath",
      "runnerGitBlobSha256",
      "runnerExecutedBytesSha256",
      "gitExecutable",
      "gitVersion",
      "logicalCommandSha256",
      "environmentSha256",
      "exitCode",
      "status",
      "stdoutSha256",
      "stdoutByteLength",
      "stderrSha256",
      "stderrByteLength",
      "resultSha256",
    ]) &&
    check.schemaVersion === "independent-review-git-diff-check.v1" &&
    check.checkId === "base-to-source-diff-check" &&
    check.executionMode === "TRUSTED_GIT_OBJECT_DATABASE_CONTROL_PLANE" &&
    check.baseCommit === source.baseCommit &&
    check.sourceCommit === source.sourceCommit &&
    check.sourceTree === source.tree &&
    check.checkedPatchSha256 === source.diffSha256 &&
    validPath(check.runnerPath) &&
    [
      check.runnerGitBlobSha256,
      check.runnerExecutedBytesSha256,
      check.logicalCommandSha256,
      check.environmentSha256,
      check.resultSha256,
    ].every(validSha) &&
    check.gitExecutable === "/usr/bin/git" &&
    /^git version [^\r\n]{1,128}$/u.test(check.gitVersion ?? "") &&
    check.exitCode === 0 &&
    check.status === "PASS" &&
    check.stdoutSha256 === EMPTY_SHA256 &&
    check.stdoutByteLength === 0 &&
    check.stderrSha256 === EMPTY_SHA256 &&
    check.stderrByteLength === 0
  );
}

function receiptBindingShapeValid(bindings) {
  return (
    exactKeys(bindings, [
      "reviewBundleSha256",
      "reviewMaterialSha256",
      "reviewMaterialSchemaSha256",
      "reviewMaterialSchemaVersion",
      "reviewMaterialFormat",
      "reviewerPromptSha256",
      "canonicalReceiptSchemaSha256",
      "canonicalOutputSchemaSha256",
      "providerTransportSchemaSha256",
      "transportEvidenceSchemaSha256",
      "transportEvidenceSha256",
      "tokenEstimateEvidenceSchemaSha256",
      "tokenEstimateEvidenceSha256",
      "providerConfigSha256",
      "rawTokenEstimateRequestSha256",
      "rawTokenEstimateResponseSha256",
      "rawRequestArtifactSha256",
      "rawResponseUtf8Sha256",
      "rawContentUtf8Sha256",
      "schemaValidatorVersion",
      "semanticValidatorVersion",
    ]) &&
    bindings.reviewMaterialSchemaVersion === "independent-review-material.v3" &&
    bindings.reviewMaterialFormat === "LENGTH_PREFIXED_UTF8_ENVELOPE_V1" &&
    bindings.providerTransportSchemaSha256 === null &&
    Object.entries(bindings)
      .filter(([key]) =>
        key.endsWith("Sha256") && key !== "providerTransportSchemaSha256",
      )
      .every(([, value]) => validSha(value)) &&
    bindings.schemaValidatorVersion === "ajv@8.20.0" &&
    bindings.semanticValidatorVersion ===
      "kimi-k3-independent-model-review-semantic-validator.v1"
  );
}

function isolationShapeValid(
  isolation,
  source,
  tokenEstimateEvidence,
  runtimeManifestPath = RUNTIME_MANIFEST_V2_PATH,
  runtimeManifestSchemaPath = null,
) {
  const toolKeys = [
    "fileRead",
    "fileWrite",
    "shell",
    "git",
    "browser",
    "d1",
    "sites",
    "governanceDecision",
  ];
  const trust = isolation?.runtimeTrust;
  const manifest = isolation?.runtimeDependencyManifest;
  return (
    exactKeys(isolation, [
      "mode",
      "toolsAbsent",
      "toolChoiceNone",
      "strictSchema",
      "credentialsExposedToModel",
      "implementationConversationImported",
      "modelToolCapabilities",
      "repositoryBefore",
      "repositoryAfter",
      "repositoryUnchanged",
      "runtimeTrust",
      "runtimeDependencyManifest",
    ]) &&
    isolation.mode === "API_NO_TOOLS" &&
    isolation.toolsAbsent === true &&
    isolation.toolChoiceNone === true &&
    isolation.strictSchema === true &&
    isolation.credentialsExposedToModel === false &&
    isolation.implementationConversationImported === false &&
    exactKeys(isolation.modelToolCapabilities, toolKeys) &&
    toolKeys.every((key) => isolation.modelToolCapabilities[key] === false) &&
    snapshotValid(isolation.repositoryBefore) &&
    snapshotValid(isolation.repositoryAfter) &&
    canonicalize(isolation.repositoryBefore) ===
      canonicalize(isolation.repositoryAfter) &&
    isolation.repositoryUnchanged === true &&
    exactKeys(trust, [
      "mode",
      "runtimeCommit",
      "runtimeTree",
      "subjectCommit",
      "subjectTree",
      "bootstrapSha256",
      "launcherSha256",
      "runtimeManifestGitBlobSha256",
      "runnerGitBlobSha256",
    ]) &&
    trust.mode === "ANCESTOR_RUNTIME_COMMIT" &&
    validCommit(trust.runtimeCommit) &&
    validCommit(trust.runtimeTree) &&
    trust.runtimeCommit !== trust.subjectCommit &&
    trust.runtimeCommit === tokenEstimateEvidence?.source?.runtimeCommit &&
    trust.subjectCommit === source.sourceCommit &&
    trust.subjectTree === source.tree &&
    [
      trust.bootstrapSha256,
      trust.launcherSha256,
      trust.runtimeManifestGitBlobSha256,
      trust.runnerGitBlobSha256,
    ].every(validSha) &&
    exactKeys(manifest, [
      "path",
      "gitBlobSha256",
      ...(runtimeManifestSchemaPath === null
        ? []
        : ["schemaPath", "schemaGitBlobSha256"]),
      "manifestSha256",
      "nodeExecutableSha256",
      "fullDependencyTreeSha256",
      "npmPackageTreeSha256",
    ]) &&
    manifest.path === runtimeManifestPath &&
    trust.runtimeManifestGitBlobSha256 === manifest.gitBlobSha256 &&
    (runtimeManifestSchemaPath === null ||
      (manifest.schemaPath === runtimeManifestSchemaPath &&
        validSha(manifest.schemaGitBlobSha256))) &&
    [
      manifest.gitBlobSha256,
      manifest.manifestSha256,
      manifest.nodeExecutableSha256,
      manifest.fullDependencyTreeSha256,
      manifest.npmPackageTreeSha256,
    ].every(validSha)
  );
}

export async function validateKimiK3ReviewReceipt({
  receipt,
  transportEvidence,
  tokenEstimateEvidence,
  evidenceResolver,
}) {
  const reasonCodes = [];
  if (!receiptShapeValid(receipt)) {
    return result(false, ["KIMI_K3_RECEIPT_SHAPE_INVALID"]);
  }
  if (receiptDigest(receipt) !== receipt.receiptSha256) {
    reasonCodes.push("KIMI_K3_RECEIPT_SELF_HASH_MISMATCH");
  }
  if (
    Date.parse(receipt.finishedAt) < Date.parse(receipt.startedAt) ||
    receipt.recordedAt !== receipt.finishedAt
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_TIME_ORDER_INVALID");
  }
  if (
    !exactKeys(receipt.reviewer, [
      "reviewerProvider",
      "requestedModel",
      "actualReturnedModel",
      "apiBaseURL",
      "endpoint",
      "reviewerSessionId",
      "reviewerIndependentOfImplementation",
      "implementationProvider",
      "implementationModel",
      "diversityLevel",
    ]) ||
    receipt.reviewer.reviewerProvider !== K3_PROVIDER ||
    receipt.reviewer.requestedModel !== K3_MODEL ||
    receipt.reviewer.actualReturnedModel !== K3_MODEL ||
    receipt.reviewer.reviewerSessionId !== transportEvidence?.responseId ||
    receipt.reviewer.apiBaseURL !== K3_BASE_URL ||
    receipt.reviewer.endpoint !== K3_CHAT_ENDPOINT ||
    receipt.reviewer.reviewerIndependentOfImplementation !== true ||
    receipt.reviewer.implementationProvider === K3_PROVIDER ||
    receipt.reviewer.implementationModel === K3_MODEL ||
    receipt.reviewer.diversityLevel !==
      "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER"
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_MODEL_IDENTITY_INVALID");
  }
  if (
    !exactKeys(receipt.source, [
      "baseCommit",
      "sourceCommit",
      "headCommit",
      "tree",
      "diffSha256",
      "changedPathsDigest",
      "gitDiffCheck",
    ]) ||
    !validCommit(receipt.source.baseCommit) ||
    !validCommit(receipt.source.sourceCommit) ||
    receipt.source.headCommit !== receipt.source.sourceCommit ||
    !validCommit(receipt.source.tree) ||
    !validSha(receipt.source.diffSha256) ||
    !validSha(receipt.source.changedPathsDigest) ||
    !gitDiffCheckValid(receipt.source.gitDiffCheck, receipt.source)
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_SOURCE_INVALID");
  }
  if (!receiptBindingShapeValid(receipt.bindings)) {
    reasonCodes.push("KIMI_K3_RECEIPT_BINDINGS_INVALID");
  }
  const estimateValidation = await validateKimiK3TokenEstimateEvidence({
    evidence: tokenEstimateEvidence,
    evidenceResolver,
  });
  const transportValidation = await validateKimiK3TransportEvidence({
    evidence: transportEvidence,
    tokenEstimateEvidence,
    evidenceResolver,
  });
  if (!estimateValidation.valid) {
    reasonCodes.push(...estimateValidation.reasonCodes);
  }
  if (!transportValidation.valid) {
    reasonCodes.push(...transportValidation.reasonCodes);
  }
  if (
    receipt.bindings.reviewBundleSha256 !== receipt.bundleSha256 ||
    receipt.bindings.reviewBundleSha256 !==
      transportEvidence?.bindings?.reviewBundleSha256 ||
    receipt.bindings.transportEvidenceSha256 !==
      transportEvidence?.transportEvidenceSha256 ||
    receipt.bindings.tokenEstimateEvidenceSha256 !==
      tokenEstimateEvidence?.evidenceSha256 ||
    receipt.bindings.providerConfigSha256 !==
      transportEvidence?.bindings?.providerConfigSha256 ||
    receipt.bindings.rawTokenEstimateRequestSha256 !==
      tokenEstimateEvidence?.request?.sha256 ||
    receipt.bindings.rawTokenEstimateResponseSha256 !==
      tokenEstimateEvidence?.response?.sha256 ||
    receipt.bindings.rawRequestArtifactSha256 !==
      transportEvidence?.request?.sha256 ||
    receipt.bindings.rawResponseUtf8Sha256 !==
      transportEvidence?.response?.sha256 ||
    receipt.bindings.rawContentUtf8Sha256 !==
      transportEvidence?.content?.sha256
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_EVIDENCE_BINDING_MISMATCH");
  }
  if (!artifactsShapeValid(receipt.artifacts)) {
    reasonCodes.push("KIMI_K3_RECEIPT_ARTIFACT_SHAPE_INVALID");
  } else {
    const artifactBytes = await Promise.all(
      Object.values(receipt.artifacts).map((descriptor) =>
        readArtifact(evidenceResolver, descriptor),
      ),
    );
    if (
      !Object.values(receipt.artifacts).every((descriptor, index) =>
        artifactMatches(descriptor, artifactBytes[index]),
      )
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_ARTIFACT_BYTES_MISMATCH");
    }
    const resolvedByName = Object.fromEntries(
      Object.keys(receipt.artifacts).map((name, index) => [
        name,
        artifactBytes[index],
      ]),
    );
    if (
      canonicalize(parseJsonBytes(resolvedByName.tokenEstimateEvidence)) !==
        canonicalize(tokenEstimateEvidence) ||
      canonicalize(parseJsonBytes(resolvedByName.transportEvidence)) !==
        canonicalize(transportEvidence) ||
      canonicalize(receipt.artifacts.tokenEstimateRequest) !==
        canonicalize(tokenEstimateEvidence?.request) ||
      receipt.artifacts.tokenEstimateResponse.sha256 !==
        tokenEstimateEvidence?.response?.sha256 ||
      canonicalize(receipt.artifacts.request) !==
        canonicalize(transportEvidence?.request) ||
      receipt.artifacts.response.sha256 !== transportEvidence?.response?.sha256 ||
      canonicalize(receipt.artifacts.content) !==
        canonicalize(transportEvidence?.content) ||
      receipt.artifacts.material.sha256 !==
        receipt.bindings.reviewMaterialSha256
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_ARTIFACT_BINDING_MISMATCH");
    }
    const modelContent = parseJsonBytes(resolvedByName.content);
    if (
      !exactKeys(modelContent, [
        "schemaVersion",
        "reviewSummary",
        "findings",
        "decision",
      ]) ||
      modelContent.schemaVersion !== "independent-model-review-output.v2" ||
      typeof modelContent.reviewSummary !== "string" ||
      modelContent.reviewSummary.length === 0 ||
      modelContent.decision !== receipt.decision ||
      canonicalize(modelContent.findings) !== canonicalize(receipt.findings)
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_MODEL_CONTENT_INVALID");
    }
  }
  if (
    receipt.source.sourceCommit !== transportEvidence?.source?.sourceCommit ||
    receipt.source.tree !== transportEvidence?.source?.sourceTree ||
    receipt.source.sourceCommit !== tokenEstimateEvidence?.source?.sourceCommit ||
    receipt.source.tree !== tokenEstimateEvidence?.source?.sourceTree ||
    !isolationShapeValid(
      receipt.isolationEvidence,
      receipt.source,
      tokenEstimateEvidence,
    )
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_RSE_TOPOLOGY_INVALID");
  }
  const context = receipt.contextAndBudget;
  if (
    !exactKeys(context, [
      "estimateCoverage",
      "estimatedInputTokens",
      "contextWindowTokens",
      "maxCompletionTokens",
      "safetyMarginTokens",
      "requiredContextTokens",
      "contextProved",
      "budgetMicros",
      "worstCaseTotalMicros",
      "budgetProved",
    ]) ||
    context.estimateCoverage !== "FULL_MODEL_VISIBLE_INPUT_PROVED" ||
    context.estimatedInputTokens !==
      tokenEstimateEvidence?.estimate?.estimatedInputTokens ||
    context.contextWindowTokens !== CONTEXT_TOKENS ||
    context.maxCompletionTokens !== COMPLETION_TOKENS ||
    context.safetyMarginTokens !== SAFETY_TOKENS ||
    context.requiredContextTokens !==
      tokenEstimateEvidence?.estimate?.requiredContextTokens ||
    context.contextProved !== true ||
    context.budgetMicros !== BUDGET_MICROS ||
    context.worstCaseTotalMicros !==
      tokenEstimateEvidence?.budget?.worstCaseTotalMicros ||
    context.budgetProved !== true
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_CONTEXT_OR_BUDGET_INVALID");
  }
  if (
    canonicalize(receipt.usage) !== canonicalize(transportEvidence?.usage) ||
    !normalizedUsageValid(receipt.usage) ||
    !exactKeys(receipt.cost, [
      "currency",
      "taxBasis",
      "actualInputMicros",
      "actualOutputMicros",
      "actualTotalMicros",
      "budgetMicros",
      "withinBudget",
    ]) ||
    receipt.cost.currency !== "USD" ||
    receipt.cost.taxBasis !== "TAX_EXCLUSIVE" ||
    receipt.cost.actualTotalMicros !==
      receipt.cost.actualInputMicros + receipt.cost.actualOutputMicros ||
    receipt.cost.actualInputMicros !==
      ceilDiv(receipt.usage.promptTokens * 3_000_000, 1_000_000) ||
    receipt.cost.actualOutputMicros !==
      ceilDiv(
        receipt.usage.completionTokens * 15_000_000,
        1_000_000,
      ) ||
    receipt.cost.actualInputMicros !== transportEvidence?.cost?.inputMicros ||
    receipt.cost.actualOutputMicros !== transportEvidence?.cost?.outputMicros ||
    receipt.cost.actualTotalMicros !== transportEvidence?.cost?.totalMicros ||
    receipt.cost.budgetMicros !== BUDGET_MICROS ||
    receipt.cost.withinBudget !== true
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_USAGE_OR_COST_INVALID");
  }
  const blockingFinding = (receipt.findings ?? []).some(
    (finding) =>
      ["HIGH", "CRITICAL"].includes(finding?.severity) &&
      finding?.status !== "RESOLVED",
  );
  const expectedConclusion =
    receipt.decision === "CLEAR"
      ? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
      : receipt.decision;
  if (
    !Array.isArray(receipt.reviewedPaths) ||
    receipt.reviewedPaths.length === 0 ||
    new Set(receipt.reviewedPaths).size !== receipt.reviewedPaths.length ||
    !receipt.reviewedPaths.every(validPath) ||
    !Array.isArray(receipt.findings) ||
    !Array.isArray(receipt.testEvidenceDigests) ||
    receipt.testEvidenceDigests.length === 0 ||
    !receipt.testEvidenceDigests.every(validSha) ||
    !["CLEAR", "BLOCKED", "INCONCLUSIVE"].includes(receipt.decision) ||
    receipt.conclusion !== expectedConclusion ||
    (receipt.decision === "CLEAR" && blockingFinding)
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_DECISION_INVALID");
  }
  return result(reasonCodes.length === 0, reasonCodes, {
    status: receipt.decision,
    conclusion: receipt.conclusion,
  });
}

const NON_MESSAGE_TOKEN_RESERVE = 65_536;
const NON_MESSAGE_MAX_BYTES = 16_384;
const FORMAL_REQUEST_MAX_BYTES = 8_388_608;
const MATERIAL_MAX_BYTES = 4_194_304;
const RESPONSE_MAX_BYTES = 1_048_576;
const V3_COVERAGE = "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE";

const ESTIMATE_V2_KEYS = [
  ...ESTIMATE_KEYS.slice(0, 8),
  "formalRequest",
  ...ESTIMATE_KEYS.slice(8),
];

const TRANSPORT_V3_BINDING_KEYS = [
  "reviewBundleSha256",
  "reviewMaterialSha256",
  "reviewerPromptSha256",
  "receiptSchemaSha256",
  "outputSchemaPath",
  "outputSchemaSha256",
  "providerConfigSha256",
  "providerConfigSchemaSha256",
  "tokenEstimateEvidenceSchemaSha256",
  "tokenEstimateEvidenceSha256",
  "formalRequestSha256",
  "messagesSha256",
  "nonMessageVisibleInputSha256",
];

const TRANSPORT_V4_BINDING_KEYS = [
  "reviewBundleSha256",
  "reviewMaterialSha256",
  "reviewerPromptSha256",
  "receiptSchemaSha256",
  "providerTransportSchemaPath",
  "providerTransportSchemaSha256",
  "canonicalOutputSchemaPath",
  "canonicalOutputSchemaSha256",
  "providerConfigSha256",
  "providerConfigSchemaSha256",
  "tokenEstimateEvidenceSchemaSha256",
  "tokenEstimateEvidenceSha256",
  "formalRequestSha256",
  "messagesSha256",
  "nonMessageVisibleInputSha256",
];

const RECEIPT_V5_BINDING_KEYS = [
  ...[
    "reviewBundleSha256",
    "reviewMaterialSha256",
    "reviewMaterialSchemaSha256",
    "reviewMaterialSchemaVersion",
    "reviewMaterialFormat",
    "reviewerPromptSha256",
    "canonicalReceiptSchemaSha256",
    "canonicalOutputSchemaSha256",
    "providerTransportSchemaSha256",
    "transportEvidenceSchemaSha256",
    "transportEvidenceSha256",
    "tokenEstimateEvidenceSchemaSha256",
    "tokenEstimateEvidenceSha256",
    "providerConfigSha256",
    "providerConfigSchemaSha256",
    "rawTokenEstimateRequestSha256",
    "rawTokenEstimateResponseSha256",
    "rawRequestArtifactSha256",
    "rawResponseUtf8Sha256",
    "rawContentUtf8Sha256",
    "schemaValidatorVersion",
    "semanticValidatorVersion",
  ],
];

function nonMessageVisibleBytes(formalRequest) {
  if (!k3FormalRequestValid(formalRequest)) return null;
  const nonMessage = structuredClone(formalRequest);
  delete nonMessage.messages;
  return Buffer.from(canonicalize(nonMessage), "utf8");
}

function modelOutputValid(content) {
  return (
    exactKeys(content, [
      "schemaVersion",
      "reviewSummary",
      "findings",
      "decision",
    ]) &&
    content.schemaVersion === "independent-model-review-output.v2" &&
    typeof content.reviewSummary === "string" &&
    content.reviewSummary.length > 0 &&
    Array.isArray(content.findings) &&
    ["CLEAR", "BLOCKED", "INCONCLUSIVE"].includes(content.decision)
  );
}

export function createKimiK3TokenEstimateEvidenceV2(input) {
  const evidence = {
    ...structuredClone(input),
    evidenceSha256: PLACEHOLDER,
  };
  evidence.evidenceSha256 = estimateDigest(evidence);
  return evidence;
}

function estimateV2ShapeValid(evidence) {
  const bindings = evidence?.bindings;
  const estimate = evidence?.estimate;
  const budget = evidence?.budget;
  return (
    exactKeys(evidence, ESTIMATE_V2_KEYS) &&
    evidence.schemaVersion ===
      "moonshot-kimi-k3-token-estimate-evidence.v2" &&
    /^mk3tee_[a-z0-9][a-z0-9_-]{7,127}$/u.test(evidence.evidenceId ?? "") &&
    evidence.provider === K3_PROVIDER &&
    evidence.model === K3_MODEL &&
    evidence.baseURL === K3_BASE_URL &&
    evidence.endpoint === K3_ESTIMATE_ENDPOINT &&
    exactKeys(evidence.source, [
      "runtimeCommit",
      "sourceCommit",
      "sourceTree",
    ]) &&
    validCommit(evidence.source.runtimeCommit) &&
    validCommit(evidence.source.sourceCommit) &&
    validCommit(evidence.source.sourceTree) &&
    evidence.source.runtimeCommit !== evidence.source.sourceCommit &&
    exactKeys(bindings, [
      "formalRequestSha256",
      "messagesSha256",
      "reviewMaterialSha256",
      "reviewBundleSha256",
      "configSha256",
      "configSchemaSha256",
      "outputSchemaSha256",
      "nonMessageVisibleInputSha256",
      "nonMessageVisibleInputByteLength",
      "requestSchemaCoverage",
    ]) &&
    [
      bindings.formalRequestSha256,
      bindings.messagesSha256,
      bindings.reviewMaterialSha256,
      bindings.reviewBundleSha256,
      bindings.configSha256,
      bindings.configSchemaSha256,
      bindings.outputSchemaSha256,
      bindings.nonMessageVisibleInputSha256,
    ].every(validSha) &&
    Number.isSafeInteger(bindings.nonMessageVisibleInputByteLength) &&
    bindings.nonMessageVisibleInputByteLength > 0 &&
    bindings.nonMessageVisibleInputByteLength <= NON_MESSAGE_MAX_BYTES &&
    bindings.requestSchemaCoverage === V3_COVERAGE &&
    validByteArtifact(evidence.formalRequest, FORMAL_REQUEST_MAX_BYTES) &&
    validByteArtifact(evidence.request, FORMAL_REQUEST_MAX_BYTES) &&
    validResponseArtifact(evidence.response, RESPONSE_MAX_BYTES) &&
    uniquePaths([evidence.formalRequest, evidence.request, evidence.response]) &&
    exactKeys(estimate, [
      "estimatedMessageInputTokens",
      "contextWindowTokens",
      "nonMessageVisibleTokenReserve",
      "maxCompletionTokens",
      "safetyMarginTokens",
      "requiredContextTokens",
      "coverage",
      "contextProved",
    ]) &&
    Number.isSafeInteger(estimate.estimatedMessageInputTokens) &&
    estimate.estimatedMessageInputTokens >= 0 &&
    estimate.contextWindowTokens === CONTEXT_TOKENS &&
    estimate.nonMessageVisibleTokenReserve === NON_MESSAGE_TOKEN_RESERVE &&
    estimate.maxCompletionTokens === COMPLETION_TOKENS &&
    estimate.safetyMarginTokens === SAFETY_TOKENS &&
    Number.isSafeInteger(estimate.requiredContextTokens) &&
    estimate.coverage === V3_COVERAGE &&
    estimate.contextProved === true &&
    exactKeys(budget, [
      "currency",
      "taxBasis",
      "budgetMicros",
      "cacheMissInputPriceMicrosPerMillion",
      "outputPriceMicrosPerMillion",
      "worstCaseBillableInputTokens",
      "worstCaseInputMicros",
      "worstCaseOutputMicros",
      "worstCaseTotalMicros",
      "budgetProved",
    ]) &&
    budget.currency === "USD" &&
    budget.taxBasis === "TAX_EXCLUSIVE" &&
    budget.budgetMicros === BUDGET_MICROS &&
    budget.cacheMissInputPriceMicrosPerMillion === 3_000_000 &&
    budget.outputPriceMicrosPerMillion === 15_000_000 &&
    [
      budget.worstCaseBillableInputTokens,
      budget.worstCaseInputMicros,
      budget.worstCaseOutputMicros,
      budget.worstCaseTotalMicros,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    budget.budgetProved === true &&
    evidence.networkAttemptCount === 1 &&
    validDate(evidence.startedAt) &&
    validDate(evidence.finishedAt) &&
    validSha(evidence.evidenceSha256)
  );
}

export async function validateKimiK3TokenEstimateEvidenceV2({
  evidence,
  evidenceResolver,
}) {
  if (!estimateV2ShapeValid(evidence)) {
    return result(false, ["KIMI_K3_TOKEN_ESTIMATE_V2_SHAPE_INVALID"]);
  }
  const reasonCodes = [];
  if (estimateDigest(evidence) !== evidence.evidenceSha256) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_SELF_HASH_MISMATCH");
  }
  if (Date.parse(evidence.finishedAt) < Date.parse(evidence.startedAt)) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_TIME_ORDER_INVALID");
  }
  const requiredContextTokens =
    evidence.estimate.estimatedMessageInputTokens +
    NON_MESSAGE_TOKEN_RESERVE +
    COMPLETION_TOKENS +
    SAFETY_TOKENS;
  if (
    evidence.estimate.requiredContextTokens !== requiredContextTokens ||
    requiredContextTokens > CONTEXT_TOKENS ||
    evidence.estimate.coverage !== evidence.bindings.requestSchemaCoverage
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_CONTEXT_INVALID");
  }
  const worstCaseBillableInputTokens =
    evidence.estimate.estimatedMessageInputTokens + NON_MESSAGE_TOKEN_RESERVE;
  const worstCaseInputMicros = ceilDiv(
    worstCaseBillableInputTokens * 3_000_000,
    1_000_000,
  );
  const worstCaseOutputMicros = ceilDiv(
    COMPLETION_TOKENS * 15_000_000,
    1_000_000,
  );
  const worstCaseTotalMicros =
    worstCaseInputMicros + worstCaseOutputMicros;
  if (
    evidence.budget.worstCaseBillableInputTokens !==
      worstCaseBillableInputTokens ||
    evidence.budget.worstCaseInputMicros !== worstCaseInputMicros ||
    evidence.budget.worstCaseOutputMicros !== worstCaseOutputMicros ||
    evidence.budget.worstCaseTotalMicros !== worstCaseTotalMicros ||
    worstCaseTotalMicros > BUDGET_MICROS
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_BUDGET_INVALID");
  }
  const [formalRequestBytes, requestBytes, responseBytes] = await Promise.all([
    readArtifact(evidenceResolver, evidence.formalRequest),
    readArtifact(evidenceResolver, evidence.request),
    readArtifact(evidenceResolver, evidence.response),
  ]);
  if (
    !artifactMatches(evidence.formalRequest, formalRequestBytes) ||
    !artifactMatches(evidence.request, requestBytes) ||
    !artifactMatches(evidence.response, responseBytes)
  ) {
    return result(false, [
      ...reasonCodes,
      "KIMI_K3_TOKEN_ESTIMATE_V2_BYTES_MISMATCH",
    ]);
  }
  const formalRequest = parseJsonBytes(formalRequestBytes);
  const estimateRequest = parseJsonBytes(requestBytes);
  const estimateResponse = parseJsonBytes(responseBytes);
  const nonMessageBytes = nonMessageVisibleBytes(formalRequest);
  if (
    !k3FormalRequestValid(formalRequest) ||
    hashBytes(formalRequestBytes) !== evidence.bindings.formalRequestSha256 ||
    hashJsonUtf8(formalRequest.messages) !== evidence.bindings.messagesSha256 ||
    Buffer.byteLength(formalRequest.messages[1].content, "utf8") >
      MATERIAL_MAX_BYTES ||
    hashBytes(Buffer.from(formalRequest.messages[1].content, "utf8")) !==
      evidence.bindings.reviewMaterialSha256 ||
    hashValue(formalRequest.response_format.json_schema.schema) !==
      evidence.bindings.outputSchemaSha256 ||
    !nonMessageBytes ||
    nonMessageBytes.byteLength !==
      evidence.bindings.nonMessageVisibleInputByteLength ||
    hashBytes(nonMessageBytes) !==
      evidence.bindings.nonMessageVisibleInputSha256
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_FORMAL_REQUEST_INVALID");
  }
  if (
    !exactKeys(estimateRequest, ["model", "messages"]) ||
    estimateRequest.model !== K3_MODEL ||
    canonicalize(estimateRequest.messages) !==
      canonicalize(formalRequest?.messages)
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_REQUEST_INVALID");
  }
  if (
    !kimiK3TokenEstimateResponseArtifactIsSafe(responseBytes) ||
    !exactKeys(estimateResponse, ["code", "data", "scode", "status"]) ||
    estimateResponse.code !== 0 ||
    estimateResponse.scode !== "0x0" ||
    estimateResponse.status !== true ||
    !exactKeys(estimateResponse?.data, ["total_tokens"]) ||
    !Number.isSafeInteger(estimateResponse.data.total_tokens) ||
    estimateResponse.data.total_tokens < 0 ||
    estimateResponse.data.total_tokens !==
      evidence.estimate.estimatedMessageInputTokens
  ) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_RESPONSE_INVALID");
  }
  return result(reasonCodes.length === 0, reasonCodes, {
    status: "PROVED",
    contextProved: true,
    budgetProved: true,
  });
}

export function createKimiK3TransportEvidenceV3(input) {
  const evidence = {
    ...structuredClone(input),
    transportEvidenceSha256: PLACEHOLDER,
  };
  evidence.transportEvidenceSha256 = transportDigest(evidence);
  return evidence;
}

function transportV3ShapeValid(evidence) {
  return (
    exactKeys(evidence, TRANSPORT_KEYS) &&
    evidence.schemaVersion === "independent-review-transport-evidence.v3" &&
    /^irte_[a-z0-9][a-z0-9_-]{7,127}$/u.test(evidence.evidenceId ?? "") &&
    evidence.provider === K3_PROVIDER &&
    evidence.requestedModel === K3_MODEL &&
    evidence.actualReturnedModel === K3_MODEL &&
    /^chatcmpl_[A-Za-z0-9_-]{8,255}$/u.test(evidence.responseId ?? "") &&
    evidence.baseURL === K3_BASE_URL &&
    evidence.endpoint === K3_CHAT_ENDPOINT &&
    exactKeys(evidence.source, ["sourceCommit", "sourceTree"]) &&
    validCommit(evidence.source.sourceCommit) &&
    validCommit(evidence.source.sourceTree) &&
    exactKeys(evidence.bindings, TRANSPORT_V3_BINDING_KEYS) &&
    Object.entries(evidence.bindings)
      .filter(([key]) => key.endsWith("Sha256"))
      .every(([, value]) => validSha(value)) &&
    validPath(evidence.bindings.outputSchemaPath) &&
    validByteArtifact(evidence.request, FORMAL_REQUEST_MAX_BYTES) &&
    validResponseArtifact(evidence.response, RESPONSE_MAX_BYTES) &&
    validByteArtifact(evidence.content, RESPONSE_MAX_BYTES) &&
    uniquePaths([evidence.request, evidence.response, evidence.content]) &&
    exactKeys(evidence.protocol, [
      "toolsAbsent",
      "toolChoiceNone",
      "thinkingAbsent",
      "reasoningEffort",
      "strictSchema",
      "maxCompletionTokens",
      "networkAttemptCount",
      "choiceCount",
      "finishReason",
      "outputSchemaValidated",
      "semanticValidated",
    ]) &&
    evidence.protocol.toolsAbsent === true &&
    evidence.protocol.toolChoiceNone === true &&
    evidence.protocol.thinkingAbsent === true &&
    evidence.protocol.reasoningEffort === "max" &&
    evidence.protocol.strictSchema === true &&
    evidence.protocol.maxCompletionTokens === COMPLETION_TOKENS &&
    evidence.protocol.networkAttemptCount === 1 &&
    evidence.protocol.choiceCount === 1 &&
    evidence.protocol.finishReason === "stop" &&
    evidence.protocol.outputSchemaValidated === true &&
    evidence.protocol.semanticValidated === true &&
    normalizedUsageValid(evidence.usage) &&
    exactKeys(evidence.cost, [
      "currency",
      "taxBasis",
      "inputMicros",
      "outputMicros",
      "totalMicros",
      "budgetMicros",
      "withinBudget",
    ]) &&
    evidence.cost.currency === "USD" &&
    evidence.cost.taxBasis === "TAX_EXCLUSIVE" &&
    [
      evidence.cost.inputMicros,
      evidence.cost.outputMicros,
      evidence.cost.totalMicros,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    evidence.cost.budgetMicros === BUDGET_MICROS &&
    evidence.cost.withinBudget === true &&
    exactKeys(evidence.validators, [
      "schemaValidatorVersion",
      "semanticValidatorVersion",
    ]) &&
    evidence.validators.schemaValidatorVersion === "ajv@8.20.0" &&
    evidence.validators.semanticValidatorVersion ===
      "kimi-k3-independent-review-transport-validator.v2" &&
    validDate(evidence.startedAt) &&
    validDate(evidence.finishedAt) &&
    validSha(evidence.transportEvidenceSha256)
  );
}

export async function validateKimiK3TransportEvidenceV3({
  evidence,
  tokenEstimateEvidence,
  evidenceResolver,
}) {
  if (!transportV3ShapeValid(evidence)) {
    return result(false, ["KIMI_K3_TRANSPORT_V3_SHAPE_INVALID"]);
  }
  const reasonCodes = [];
  if (transportDigest(evidence) !== evidence.transportEvidenceSha256) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V3_SELF_HASH_MISMATCH");
  }
  if (Date.parse(evidence.finishedAt) < Date.parse(evidence.startedAt)) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V3_TIME_ORDER_INVALID");
  }
  const estimateValidation = await validateKimiK3TokenEstimateEvidenceV2({
    evidence: tokenEstimateEvidence,
    evidenceResolver,
  });
  if (!estimateValidation.valid) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_EVIDENCE_INVALID");
    reasonCodes.push(...estimateValidation.reasonCodes);
  }
  if (
    evidence.bindings.tokenEstimateEvidenceSha256 !==
      tokenEstimateEvidence?.evidenceSha256 ||
    evidence.bindings.reviewBundleSha256 !==
      tokenEstimateEvidence?.bindings?.reviewBundleSha256 ||
    evidence.bindings.reviewMaterialSha256 !==
      tokenEstimateEvidence?.bindings?.reviewMaterialSha256 ||
    evidence.bindings.providerConfigSha256 !==
      tokenEstimateEvidence?.bindings?.configSha256 ||
    evidence.bindings.providerConfigSchemaSha256 !==
      tokenEstimateEvidence?.bindings?.configSchemaSha256 ||
    evidence.bindings.formalRequestSha256 !==
      tokenEstimateEvidence?.bindings?.formalRequestSha256 ||
    evidence.bindings.messagesSha256 !==
      tokenEstimateEvidence?.bindings?.messagesSha256 ||
    evidence.bindings.nonMessageVisibleInputSha256 !==
      tokenEstimateEvidence?.bindings?.nonMessageVisibleInputSha256 ||
    evidence.bindings.outputSchemaSha256 !==
      tokenEstimateEvidence?.bindings?.outputSchemaSha256
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V3_BINDING_MISMATCH");
  }
  const [requestBytes, responseBytes, contentBytes, outputSchemaBytes] =
    await Promise.all([
      readArtifact(evidenceResolver, evidence.request),
      readArtifact(evidenceResolver, evidence.response),
      readArtifact(evidenceResolver, evidence.content),
      readArtifact(evidenceResolver, {
        path: evidence.bindings.outputSchemaPath,
      }),
    ]);
  if (
    !artifactMatches(evidence.request, requestBytes) ||
    !artifactMatches(evidence.response, responseBytes) ||
    !artifactMatches(evidence.content, contentBytes)
  ) {
    return result(false, [
      ...reasonCodes,
      "KIMI_K3_TRANSPORT_V3_BYTES_MISMATCH",
    ]);
  }
  const request = parseJsonBytes(requestBytes);
  const response = parseJsonBytes(responseBytes);
  const content = parseJsonBytes(contentBytes);
  const outputSchema = parseJsonBytes(outputSchemaBytes);
  const outputValidation =
    outputSchemaBytes instanceof Uint8Array
      ? await validateIndependentModelReviewOutputArtifact({
          rawModelOutput: contentBytes,
          outputSchemaBytes,
          expectedOutputSchemaSha256: hashBytes(outputSchemaBytes),
        })
      : { ok: false };
  const message = response?.choices?.[0]?.message;
  const nonMessageBytes = nonMessageVisibleBytes(request);
  if (
    !k3FormalRequestValid(request) ||
    hashBytes(requestBytes) !== evidence.bindings.formalRequestSha256 ||
    hashJsonUtf8(request.messages) !== evidence.bindings.messagesSha256 ||
    Buffer.byteLength(request.messages[1].content, "utf8") >
      MATERIAL_MAX_BYTES ||
    hashBytes(Buffer.from(request.messages[1].content, "utf8")) !==
      evidence.bindings.reviewMaterialSha256 ||
    hashValue(request.response_format.json_schema.schema) !==
      evidence.bindings.outputSchemaSha256 ||
    !outputSchema ||
    hashValue(outputSchema) !== evidence.bindings.outputSchemaSha256 ||
    !nonMessageBytes ||
    hashBytes(nonMessageBytes) !==
      evidence.bindings.nonMessageVisibleInputSha256
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V3_REQUEST_INVALID");
  }
  if (
    !response ||
    response.id !== evidence.responseId ||
    response.model !== K3_MODEL ||
    !Array.isArray(response.choices) ||
    response.choices.length !== 1 ||
    response.choices[0]?.finish_reason !== "stop" ||
    response.choices[0]?.index !== 0 ||
    message?.role !== "assistant" ||
    message?.content !== new TextDecoder().decode(contentBytes) ||
    Object.hasOwn(message ?? {}, "tool_calls") ||
    Object.hasOwn(message ?? {}, "function_call") ||
    !providerUsageValid(response.usage) ||
    !normalizedUsageMatches(evidence.usage, response.usage) ||
    !modelOutputValid(content) ||
    outputValidation.ok !== true
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V3_RESPONSE_INVALID");
  }
  if (
    evidence.cost.totalMicros !==
      evidence.cost.inputMicros + evidence.cost.outputMicros ||
    evidence.cost.inputMicros !==
      ceilDiv(
        (evidence.usage.promptTokens - evidence.usage.cachedTokens) *
          3_000_000 +
          evidence.usage.cachedTokens * 300_000,
        1_000_000,
      ) ||
    evidence.cost.outputMicros !==
      ceilDiv(evidence.usage.completionTokens * 15_000_000, 1_000_000) ||
    evidence.cost.withinBudget !==
      (evidence.cost.totalMicros <= evidence.cost.budgetMicros)
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V3_COST_INVALID");
  }
  return result(reasonCodes.length === 0, reasonCodes, {
    status: "PROVED",
    actualReturnedModel: K3_MODEL,
  });
}

export function createKimiK3TransportEvidenceV4(input) {
  const evidence = {
    ...structuredClone(input),
    transportEvidenceSha256: PLACEHOLDER,
  };
  evidence.transportEvidenceSha256 = transportDigest(evidence);
  return evidence;
}

function transportV4ShapeValid(evidence) {
  return (
    exactKeys(evidence, TRANSPORT_KEYS) &&
    evidence.schemaVersion === "independent-review-transport-evidence.v4" &&
    /^irte_[a-z0-9][a-z0-9_-]{7,127}$/u.test(evidence.evidenceId ?? "") &&
    evidence.provider === K3_PROVIDER &&
    evidence.requestedModel === K3_MODEL &&
    evidence.actualReturnedModel === K3_MODEL &&
    /^chatcmpl_[A-Za-z0-9_-]{8,255}$/u.test(evidence.responseId ?? "") &&
    evidence.baseURL === K3_BASE_URL &&
    evidence.endpoint === K3_CHAT_ENDPOINT &&
    exactKeys(evidence.source, ["sourceCommit", "sourceTree"]) &&
    validCommit(evidence.source.sourceCommit) &&
    validCommit(evidence.source.sourceTree) &&
    exactKeys(evidence.bindings, TRANSPORT_V4_BINDING_KEYS) &&
    Object.entries(evidence.bindings)
      .filter(([key]) => key.endsWith("Sha256"))
      .every(([, value]) => validSha(value)) &&
    validPath(evidence.bindings.providerTransportSchemaPath) &&
    validPath(evidence.bindings.canonicalOutputSchemaPath) &&
    evidence.bindings.providerTransportSchemaPath ===
      K3_PROVIDER_TRANSPORT_SCHEMA_PATH &&
    evidence.bindings.canonicalOutputSchemaPath ===
      CANONICAL_OUTPUT_SCHEMA_PATH &&
    validByteArtifact(evidence.request, FORMAL_REQUEST_MAX_BYTES) &&
    validResponseArtifact(evidence.response, RESPONSE_MAX_BYTES) &&
    validByteArtifact(evidence.content, RESPONSE_MAX_BYTES) &&
    uniquePaths([evidence.request, evidence.response, evidence.content]) &&
    exactKeys(evidence.protocol, [
      "toolsAbsent",
      "toolChoiceNone",
      "thinkingAbsent",
      "reasoningEffort",
      "strictSchema",
      "maxCompletionTokens",
      "networkAttemptCount",
      "choiceCount",
      "finishReason",
      "providerTransportSchemaValidated",
      "canonicalOutputSchemaValidated",
      "semanticValidated",
    ]) &&
    evidence.protocol.toolsAbsent === true &&
    evidence.protocol.toolChoiceNone === true &&
    evidence.protocol.thinkingAbsent === true &&
    evidence.protocol.reasoningEffort === "max" &&
    evidence.protocol.strictSchema === true &&
    evidence.protocol.maxCompletionTokens === COMPLETION_TOKENS &&
    evidence.protocol.networkAttemptCount === 1 &&
    evidence.protocol.choiceCount === 1 &&
    evidence.protocol.finishReason === "stop" &&
    evidence.protocol.providerTransportSchemaValidated === true &&
    evidence.protocol.canonicalOutputSchemaValidated === true &&
    evidence.protocol.semanticValidated === true &&
    normalizedUsageValid(evidence.usage) &&
    exactKeys(evidence.cost, [
      "currency",
      "taxBasis",
      "inputMicros",
      "outputMicros",
      "totalMicros",
      "budgetMicros",
      "withinBudget",
    ]) &&
    evidence.cost.currency === "USD" &&
    evidence.cost.taxBasis === "TAX_EXCLUSIVE" &&
    [
      evidence.cost.inputMicros,
      evidence.cost.outputMicros,
      evidence.cost.totalMicros,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) &&
    evidence.cost.budgetMicros === BUDGET_MICROS &&
    evidence.cost.withinBudget === true &&
    exactKeys(evidence.validators, [
      "schemaValidatorVersion",
      "semanticValidatorVersion",
    ]) &&
    evidence.validators.schemaValidatorVersion === "ajv@8.20.0" &&
    evidence.validators.semanticValidatorVersion ===
      "kimi-k3-independent-review-transport-validator.v3" &&
    validDate(evidence.startedAt) &&
    validDate(evidence.finishedAt) &&
    validSha(evidence.transportEvidenceSha256)
  );
}

export async function validateKimiK3TransportEvidenceV4({
  evidence,
  tokenEstimateEvidence,
  evidenceResolver,
}) {
  if (!transportV4ShapeValid(evidence)) {
    return result(false, ["KIMI_K3_TRANSPORT_V4_SHAPE_INVALID"]);
  }
  const reasonCodes = [];
  if (transportDigest(evidence) !== evidence.transportEvidenceSha256) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V4_SELF_HASH_MISMATCH");
  }
  if (Date.parse(evidence.finishedAt) < Date.parse(evidence.startedAt)) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V4_TIME_ORDER_INVALID");
  }
  const estimateValidation = await validateKimiK3TokenEstimateEvidenceV2({
    evidence: tokenEstimateEvidence,
    evidenceResolver,
  });
  if (!estimateValidation.valid) {
    reasonCodes.push("KIMI_K3_TOKEN_ESTIMATE_V2_EVIDENCE_INVALID");
    reasonCodes.push(...estimateValidation.reasonCodes);
  }
  if (
    evidence.bindings.tokenEstimateEvidenceSha256 !==
      tokenEstimateEvidence?.evidenceSha256 ||
    evidence.bindings.reviewBundleSha256 !==
      tokenEstimateEvidence?.bindings?.reviewBundleSha256 ||
    evidence.bindings.reviewMaterialSha256 !==
      tokenEstimateEvidence?.bindings?.reviewMaterialSha256 ||
    evidence.bindings.providerConfigSha256 !==
      tokenEstimateEvidence?.bindings?.configSha256 ||
    evidence.bindings.providerConfigSchemaSha256 !==
      tokenEstimateEvidence?.bindings?.configSchemaSha256 ||
    evidence.bindings.formalRequestSha256 !==
      tokenEstimateEvidence?.bindings?.formalRequestSha256 ||
    evidence.bindings.messagesSha256 !==
      tokenEstimateEvidence?.bindings?.messagesSha256 ||
    evidence.bindings.nonMessageVisibleInputSha256 !==
      tokenEstimateEvidence?.bindings?.nonMessageVisibleInputSha256
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V4_BINDING_MISMATCH");
  }
  const [
    requestBytes,
    responseBytes,
    contentBytes,
    providerTransportSchemaBytes,
    canonicalOutputSchemaBytes,
  ] = await Promise.all([
    readArtifact(evidenceResolver, evidence.request),
    readArtifact(evidenceResolver, evidence.response),
    readArtifact(evidenceResolver, evidence.content),
    readArtifact(evidenceResolver, {
      path: evidence.bindings.providerTransportSchemaPath,
    }),
    readArtifact(evidenceResolver, {
      path: evidence.bindings.canonicalOutputSchemaPath,
    }),
  ]);
  if (
    !artifactMatches(evidence.request, requestBytes) ||
    !artifactMatches(evidence.response, responseBytes) ||
    !artifactMatches(evidence.content, contentBytes) ||
    !(providerTransportSchemaBytes instanceof Uint8Array) ||
    hashBytes(providerTransportSchemaBytes) !==
      evidence.bindings.providerTransportSchemaSha256 ||
    !(canonicalOutputSchemaBytes instanceof Uint8Array) ||
    hashBytes(canonicalOutputSchemaBytes) !==
      evidence.bindings.canonicalOutputSchemaSha256
  ) {
    return result(false, [
      ...reasonCodes,
      "KIMI_K3_TRANSPORT_V4_BYTES_MISMATCH",
    ]);
  }
  const request = parseJsonBytes(requestBytes);
  const response = parseJsonBytes(responseBytes);
  const content = parseJsonBytes(contentBytes);
  const providerTransportSchema = parseJsonBytes(
    providerTransportSchemaBytes,
  );
  const canonicalOutputSchema = parseJsonBytes(canonicalOutputSchemaBytes);
  const providerValidation =
    content !== null && providerTransportSchema !== null
      ? await validateIndependentReviewSchemaInstance({
          schemaBytes: providerTransportSchemaBytes,
          expectedSchemaSha256: hashBytes(providerTransportSchemaBytes),
          instance: content,
          label: "Moonshot Kimi K3 provider transport output Schema",
        })
      : { ok: false };
  const canonicalValidation =
    canonicalOutputSchema !== null
      ? await validateIndependentModelReviewOutputArtifact({
          rawModelOutput: contentBytes,
          outputSchemaBytes: canonicalOutputSchemaBytes,
          expectedOutputSchemaSha256: hashBytes(canonicalOutputSchemaBytes),
        })
      : { ok: false };
  if (providerValidation.ok !== true) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V4_PROVIDER_SCHEMA_INVALID");
  }
  if (canonicalValidation.ok !== true) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V4_CANONICAL_OUTPUT_INVALID");
  }
  const message = response?.choices?.[0]?.message;
  const nonMessageBytes = nonMessageVisibleBytes(request);
  if (
    !k3FormalRequestValid(request) ||
    hashBytes(requestBytes) !== evidence.bindings.formalRequestSha256 ||
    hashJsonUtf8(request.messages) !== evidence.bindings.messagesSha256 ||
    Buffer.byteLength(request.messages[1].content, "utf8") >
      MATERIAL_MAX_BYTES ||
    hashBytes(Buffer.from(request.messages[1].content, "utf8")) !==
      evidence.bindings.reviewMaterialSha256 ||
    !providerTransportSchema ||
    canonicalize(request.response_format.json_schema.schema) !==
      canonicalize(providerTransportSchema) ||
    hashValue(request.response_format.json_schema.schema) !==
      tokenEstimateEvidence?.bindings?.outputSchemaSha256 ||
    hashValue(providerTransportSchema) !==
      tokenEstimateEvidence?.bindings?.outputSchemaSha256 ||
    !nonMessageBytes ||
    hashBytes(nonMessageBytes) !==
      evidence.bindings.nonMessageVisibleInputSha256
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V4_REQUEST_INVALID");
  }
  if (
    !response ||
    response.id !== evidence.responseId ||
    response.model !== K3_MODEL ||
    !Array.isArray(response.choices) ||
    response.choices.length !== 1 ||
    response.choices[0]?.finish_reason !== "stop" ||
    response.choices[0]?.index !== 0 ||
    message?.role !== "assistant" ||
    message?.content !== new TextDecoder().decode(contentBytes) ||
    Object.hasOwn(message ?? {}, "tool_calls") ||
    Object.hasOwn(message ?? {}, "function_call") ||
    !providerUsageValid(response.usage) ||
    !normalizedUsageMatches(evidence.usage, response.usage) ||
    !modelOutputValid(content) ||
    providerValidation.ok !== true ||
    canonicalValidation.ok !== true
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V4_RESPONSE_INVALID");
  }
  if (
    evidence.cost.totalMicros !==
      evidence.cost.inputMicros + evidence.cost.outputMicros ||
    evidence.cost.inputMicros !==
      ceilDiv(
        (evidence.usage.promptTokens - evidence.usage.cachedTokens) *
          3_000_000 +
          evidence.usage.cachedTokens * 300_000,
        1_000_000,
      ) ||
    evidence.cost.outputMicros !==
      ceilDiv(evidence.usage.completionTokens * 15_000_000, 1_000_000) ||
    evidence.cost.withinBudget !==
      (evidence.cost.totalMicros <= evidence.cost.budgetMicros)
  ) {
    reasonCodes.push("KIMI_K3_TRANSPORT_V4_COST_INVALID");
  }
  return result(reasonCodes.length === 0, reasonCodes, {
    status: "PROVED",
    actualReturnedModel: K3_MODEL,
  });
}

export function createKimiK3ReviewReceiptV5(input) {
  const receipt = {
    ...structuredClone(input),
    receiptSha256: PLACEHOLDER,
  };
  receipt.receiptSha256 = receiptDigest(receipt);
  return receipt;
}

function receiptV5ShapeValid(receipt) {
  return (
    exactKeys(receipt, RECEIPT_KEYS) &&
    receipt.schemaVersion === "independent-model-review-receipt.v5" &&
    receipt.receiptSchemaVersion === "independent-model-review-receipt.v5" &&
    receipt.reviewId === receipt.receiptId &&
    /^imrr_[a-z0-9][a-z0-9_-]{7,127}$/u.test(receipt.receiptId ?? "") &&
    receipt.policyVersion === "2.0.0-candidate.3" &&
    validSha(receipt.policySha256) &&
    receipt.assuranceLevel === "MODEL_ONLY_PREPRODUCTION" &&
    ["P0", "P1", "P2"].includes(receipt.applicablePhase) &&
    receipt.humanIndependentReviewSatisfied === false &&
    receipt.independentModelReviewRequired === true &&
    receipt.p3HumanReviewRequired === true &&
    typeof receipt.bundleId === "string" &&
    receipt.bundleId.length >= 8 &&
    validSha(receipt.bundleSha256) &&
    validSha(receipt.reviewMaterialSha256) &&
    receipt.historicalTerraEvidenceAccepted === false &&
    receipt.historicalK2EvidenceAccepted === false &&
    receipt.humanReviewClaim === false &&
    receipt.governanceEffect === "NONE" &&
    receipt.selfAuthorizing === false &&
    validDate(receipt.startedAt) &&
    validDate(receipt.finishedAt) &&
    validDate(receipt.recordedAt) &&
    receipt.recordedAt === receipt.finishedAt &&
    validSha(receipt.receiptSha256)
  );
}

function receiptV5BindingsValid(bindings) {
  return (
    exactKeys(bindings, RECEIPT_V5_BINDING_KEYS) &&
    bindings.reviewMaterialSchemaVersion === "independent-review-material.v4" &&
    bindings.reviewMaterialFormat === "LENGTH_PREFIXED_UTF8_ENVELOPE_V1" &&
    bindings.providerTransportSchemaSha256 === null &&
    Object.entries(bindings)
      .filter(([key]) =>
        key.endsWith("Sha256") && key !== "providerTransportSchemaSha256",
      )
      .every(([, value]) => validSha(value)) &&
    bindings.schemaValidatorVersion === "ajv@8.20.0" &&
    bindings.semanticValidatorVersion ===
      "kimi-k3-independent-model-review-semantic-validator.v2"
  );
}

export async function validateKimiK3ReviewReceiptV5({
  receipt,
  transportEvidence,
  tokenEstimateEvidence,
  evidenceResolver,
}) {
  if (!receiptV5ShapeValid(receipt)) {
    return result(false, ["KIMI_K3_RECEIPT_V5_SHAPE_INVALID"]);
  }
  const reasonCodes = [];
  if (receiptDigest(receipt) !== receipt.receiptSha256) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_SELF_HASH_MISMATCH");
  }
  if (
    Date.parse(receipt.finishedAt) < Date.parse(receipt.startedAt) ||
    receipt.recordedAt !== receipt.finishedAt
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_TIME_ORDER_INVALID");
  }
  if (
    !exactKeys(receipt.reviewer, [
      "reviewerProvider",
      "requestedModel",
      "actualReturnedModel",
      "apiBaseURL",
      "endpoint",
      "reviewerSessionId",
      "reviewerIndependentOfImplementation",
      "implementationProvider",
      "implementationModel",
      "diversityLevel",
    ]) ||
    receipt.reviewer.reviewerProvider !== K3_PROVIDER ||
    receipt.reviewer.requestedModel !== K3_MODEL ||
    receipt.reviewer.actualReturnedModel !== K3_MODEL ||
    receipt.reviewer.reviewerSessionId !== transportEvidence?.responseId ||
    receipt.reviewer.apiBaseURL !== K3_BASE_URL ||
    receipt.reviewer.endpoint !== K3_CHAT_ENDPOINT ||
    receipt.reviewer.reviewerIndependentOfImplementation !== true ||
    receipt.reviewer.implementationProvider === K3_PROVIDER ||
    receipt.reviewer.implementationModel === K3_MODEL ||
    receipt.reviewer.diversityLevel !==
      "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER"
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_MODEL_IDENTITY_INVALID");
  }
  if (
    !exactKeys(receipt.source, [
      "baseCommit",
      "sourceCommit",
      "headCommit",
      "tree",
      "diffSha256",
      "changedPathsDigest",
      "gitDiffCheck",
    ]) ||
    !validCommit(receipt.source.baseCommit) ||
    !validCommit(receipt.source.sourceCommit) ||
    receipt.source.headCommit !== receipt.source.sourceCommit ||
    !validCommit(receipt.source.tree) ||
    !validSha(receipt.source.diffSha256) ||
    !validSha(receipt.source.changedPathsDigest) ||
    !gitDiffCheckValid(receipt.source.gitDiffCheck, receipt.source)
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_SOURCE_INVALID");
  }
  if (!receiptV5BindingsValid(receipt.bindings)) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_BINDINGS_INVALID");
  }
  const receiptOutputSchemaBytes = await readArtifact(evidenceResolver, {
    path: transportEvidence?.bindings?.outputSchemaPath,
  });
  const receiptOutputSchema = parseJsonBytes(receiptOutputSchemaBytes);
  const estimateValidation = await validateKimiK3TokenEstimateEvidenceV2({
    evidence: tokenEstimateEvidence,
    evidenceResolver,
  });
  const transportValidation = await validateKimiK3TransportEvidenceV3({
    evidence: transportEvidence,
    tokenEstimateEvidence,
    evidenceResolver,
  });
  if (!estimateValidation.valid) reasonCodes.push(...estimateValidation.reasonCodes);
  if (!transportValidation.valid) reasonCodes.push(...transportValidation.reasonCodes);
  if (
    receipt.reviewMaterialSha256 !== receipt.bindings.reviewMaterialSha256 ||
    receipt.bindings.reviewBundleSha256 !== receipt.bundleSha256 ||
    receipt.bindings.reviewBundleSha256 !==
      transportEvidence?.bindings?.reviewBundleSha256 ||
    receipt.bindings.reviewMaterialSha256 !==
      transportEvidence?.bindings?.reviewMaterialSha256 ||
    receipt.bindings.transportEvidenceSha256 !==
      transportEvidence?.transportEvidenceSha256 ||
    receipt.bindings.tokenEstimateEvidenceSha256 !==
      tokenEstimateEvidence?.evidenceSha256 ||
    receipt.bindings.providerConfigSha256 !==
      transportEvidence?.bindings?.providerConfigSha256 ||
    receipt.bindings.providerConfigSchemaSha256 !==
      transportEvidence?.bindings?.providerConfigSchemaSha256 ||
    !(receiptOutputSchemaBytes instanceof Uint8Array) ||
    hashBytes(receiptOutputSchemaBytes) !==
      receipt.bindings.canonicalOutputSchemaSha256 ||
    !receiptOutputSchema ||
    hashValue(receiptOutputSchema) !==
      transportEvidence?.bindings?.outputSchemaSha256 ||
    receipt.bindings.rawTokenEstimateRequestSha256 !==
      tokenEstimateEvidence?.request?.sha256 ||
    receipt.bindings.rawTokenEstimateResponseSha256 !==
      tokenEstimateEvidence?.response?.sha256 ||
    receipt.bindings.rawRequestArtifactSha256 !==
      transportEvidence?.request?.sha256 ||
    receipt.bindings.rawResponseUtf8Sha256 !==
      transportEvidence?.response?.sha256 ||
    receipt.bindings.rawContentUtf8Sha256 !==
      transportEvidence?.content?.sha256
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_EVIDENCE_BINDING_MISMATCH");
  }
  if (!artifactsShapeValid(receipt.artifacts)) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_ARTIFACT_SHAPE_INVALID");
  } else {
    const names = Object.keys(receipt.artifacts);
    const bytes = await Promise.all(
      names.map((name) => readArtifact(evidenceResolver, receipt.artifacts[name])),
    );
    if (
      !names.every((name, index) =>
        artifactMatches(receipt.artifacts[name], bytes[index]),
      )
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_V5_ARTIFACT_BYTES_MISMATCH");
    }
    const resolved = Object.fromEntries(
      names.map((name, index) => [name, bytes[index]]),
    );
    if (
      canonicalize(parseJsonBytes(resolved.tokenEstimateEvidence)) !==
        canonicalize(tokenEstimateEvidence) ||
      canonicalize(parseJsonBytes(resolved.transportEvidence)) !==
        canonicalize(transportEvidence) ||
      canonicalize(receipt.artifacts.tokenEstimateRequest) !==
        canonicalize(tokenEstimateEvidence?.request) ||
      receipt.artifacts.tokenEstimateResponse.sha256 !==
        tokenEstimateEvidence?.response?.sha256 ||
      canonicalize(receipt.artifacts.request) !==
        canonicalize(transportEvidence?.request) ||
      receipt.artifacts.response.sha256 !== transportEvidence?.response?.sha256 ||
      canonicalize(receipt.artifacts.content) !==
        canonicalize(transportEvidence?.content) ||
      receipt.artifacts.material.sha256 !==
        receipt.bindings.reviewMaterialSha256
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_V5_ARTIFACT_BINDING_MISMATCH");
    }
    const modelContent = parseJsonBytes(resolved.content);
    if (
      !modelOutputValid(modelContent) ||
      modelContent.decision !== receipt.decision ||
      canonicalize(modelContent.findings) !== canonicalize(receipt.findings)
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_V5_MODEL_CONTENT_INVALID");
    }
  }
  if (
    receipt.source.sourceCommit !== transportEvidence?.source?.sourceCommit ||
    receipt.source.tree !== transportEvidence?.source?.sourceTree ||
    receipt.source.sourceCommit !== tokenEstimateEvidence?.source?.sourceCommit ||
    receipt.source.tree !== tokenEstimateEvidence?.source?.sourceTree ||
    !isolationShapeValid(
      receipt.isolationEvidence,
      receipt.source,
      tokenEstimateEvidence,
    )
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_RSE_TOPOLOGY_INVALID");
  }
  const context = receipt.contextAndBudget;
  if (
    !exactKeys(context, [
      "estimateCoverage",
      "estimatedMessageInputTokens",
      "nonMessageVisibleTokenReserve",
      "nonMessageVisibleInputByteLength",
      "nonMessageVisibleInputSha256",
      "contextWindowTokens",
      "maxCompletionTokens",
      "safetyMarginTokens",
      "requiredContextTokens",
      "contextProved",
      "budgetMicros",
      "worstCaseBillableInputTokens",
      "worstCaseTotalMicros",
      "budgetProved",
    ]) ||
    context.estimateCoverage !== V3_COVERAGE ||
    context.estimatedMessageInputTokens !==
      tokenEstimateEvidence?.estimate?.estimatedMessageInputTokens ||
    context.nonMessageVisibleTokenReserve !== NON_MESSAGE_TOKEN_RESERVE ||
    context.nonMessageVisibleInputByteLength !==
      tokenEstimateEvidence?.bindings?.nonMessageVisibleInputByteLength ||
    context.nonMessageVisibleInputSha256 !==
      tokenEstimateEvidence?.bindings?.nonMessageVisibleInputSha256 ||
    context.contextWindowTokens !== CONTEXT_TOKENS ||
    context.maxCompletionTokens !== COMPLETION_TOKENS ||
    context.safetyMarginTokens !== SAFETY_TOKENS ||
    context.requiredContextTokens !==
      tokenEstimateEvidence?.estimate?.requiredContextTokens ||
    context.contextProved !== true ||
    context.budgetMicros !== BUDGET_MICROS ||
    context.worstCaseBillableInputTokens !==
      tokenEstimateEvidence?.budget?.worstCaseBillableInputTokens ||
    context.worstCaseTotalMicros !==
      tokenEstimateEvidence?.budget?.worstCaseTotalMicros ||
    context.budgetProved !== true
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_CONTEXT_OR_BUDGET_INVALID");
  }
  if (
    canonicalize(receipt.usage) !== canonicalize(transportEvidence?.usage) ||
    !normalizedUsageValid(receipt.usage) ||
    !exactKeys(receipt.cost, [
      "currency",
      "taxBasis",
      "actualInputMicros",
      "actualOutputMicros",
      "actualTotalMicros",
      "budgetMicros",
      "withinBudget",
    ]) ||
    receipt.cost.currency !== "USD" ||
    receipt.cost.taxBasis !== "TAX_EXCLUSIVE" ||
    receipt.cost.actualTotalMicros !==
      receipt.cost.actualInputMicros + receipt.cost.actualOutputMicros ||
    receipt.cost.actualInputMicros !== transportEvidence?.cost?.inputMicros ||
    receipt.cost.actualOutputMicros !== transportEvidence?.cost?.outputMicros ||
    receipt.cost.actualTotalMicros !== transportEvidence?.cost?.totalMicros ||
    receipt.cost.budgetMicros !== BUDGET_MICROS ||
    receipt.cost.withinBudget !== true
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_USAGE_OR_COST_INVALID");
  }
  const blockingFinding = (receipt.findings ?? []).some(
    (finding) =>
      ["HIGH", "CRITICAL"].includes(finding?.severity) &&
      finding?.status !== "RESOLVED",
  );
  const expectedConclusion =
    receipt.decision === "CLEAR"
      ? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
      : receipt.decision;
  if (
    !Array.isArray(receipt.reviewedPaths) ||
    receipt.reviewedPaths.length === 0 ||
    new Set(receipt.reviewedPaths).size !== receipt.reviewedPaths.length ||
    !receipt.reviewedPaths.every(validPath) ||
    !Array.isArray(receipt.findings) ||
    !Array.isArray(receipt.testEvidenceDigests) ||
    receipt.testEvidenceDigests.length === 0 ||
    !receipt.testEvidenceDigests.every(validSha) ||
    !["CLEAR", "BLOCKED", "INCONCLUSIVE"].includes(receipt.decision) ||
    receipt.conclusion !== expectedConclusion ||
    (receipt.decision === "CLEAR" && blockingFinding)
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V5_DECISION_INVALID");
  }
  return result(reasonCodes.length === 0, reasonCodes, {
    status: receipt.decision,
    conclusion: receipt.conclusion,
  });
}
export function createKimiK3ReviewReceiptV6(input) {
  const receipt = {
    ...structuredClone(input),
    receiptSha256: PLACEHOLDER,
  };
  receipt.receiptSha256 = receiptDigest(receipt);
  return receipt;
}

export function createKimiK3ReviewReceiptV7(input) {
  const receipt = {
    ...structuredClone(input),
    receiptSha256: PLACEHOLDER,
  };
  receipt.receiptSha256 = receiptDigest(receipt);
  return receipt;
}

function receiptV6ShapeValid(
  receipt,
  schemaVersion = "independent-model-review-receipt.v6",
) {
  return (
    exactKeys(receipt, RECEIPT_KEYS) &&
    receipt.schemaVersion === schemaVersion &&
    receipt.receiptSchemaVersion === schemaVersion &&
    receipt.reviewId === receipt.receiptId &&
    /^imrr_[a-z0-9][a-z0-9_-]{7,127}$/u.test(receipt.receiptId ?? "") &&
    receipt.policyVersion === "2.0.0-candidate.3" &&
    validSha(receipt.policySha256) &&
    receipt.assuranceLevel === "MODEL_ONLY_PREPRODUCTION" &&
    ["P0", "P1", "P2"].includes(receipt.applicablePhase) &&
    receipt.humanIndependentReviewSatisfied === false &&
    receipt.independentModelReviewRequired === true &&
    receipt.p3HumanReviewRequired === true &&
    typeof receipt.bundleId === "string" &&
    receipt.bundleId.length >= 8 &&
    validSha(receipt.bundleSha256) &&
    validSha(receipt.reviewMaterialSha256) &&
    receipt.historicalTerraEvidenceAccepted === false &&
    receipt.historicalK2EvidenceAccepted === false &&
    receipt.humanReviewClaim === false &&
    receipt.governanceEffect === "NONE" &&
    receipt.selfAuthorizing === false &&
    validDate(receipt.startedAt) &&
    validDate(receipt.finishedAt) &&
    validDate(receipt.recordedAt) &&
    receipt.recordedAt === receipt.finishedAt &&
    validSha(receipt.receiptSha256)
  );
}

function receiptV6BindingsValid(bindings) {
  return (
    exactKeys(bindings, RECEIPT_V5_BINDING_KEYS) &&
    bindings.reviewMaterialSchemaVersion === "independent-review-material.v4" &&
    bindings.reviewMaterialFormat === "LENGTH_PREFIXED_UTF8_ENVELOPE_V1" &&
    Object.entries(bindings)
      .filter(([key]) => key.endsWith("Sha256"))
      .every(([, value]) => validSha(value)) &&
    bindings.schemaValidatorVersion === "ajv@8.20.0" &&
    bindings.semanticValidatorVersion ===
      "kimi-k3-independent-model-review-semantic-validator.v3"
  );
}

async function validateKimiK3ReviewReceiptCurrent(
  {
    receipt,
    transportEvidence,
    tokenEstimateEvidence,
    evidenceResolver,
  },
  {
    schemaVersion,
    receiptSchemaPath,
    runtimeManifestPath,
    runtimeManifestSchemaPath = null,
  },
) {
  if (!receiptV6ShapeValid(receipt, schemaVersion)) {
    return result(false, ["KIMI_K3_RECEIPT_V6_SHAPE_INVALID"]);
  }
  const reasonCodes = [];
  if (receiptDigest(receipt) !== receipt.receiptSha256) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_SELF_HASH_MISMATCH");
  }
  if (
    Date.parse(receipt.finishedAt) < Date.parse(receipt.startedAt) ||
    receipt.recordedAt !== receipt.finishedAt
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_TIME_ORDER_INVALID");
  }
  if (
    !exactKeys(receipt.reviewer, [
      "reviewerProvider",
      "requestedModel",
      "actualReturnedModel",
      "apiBaseURL",
      "endpoint",
      "reviewerSessionId",
      "reviewerIndependentOfImplementation",
      "implementationProvider",
      "implementationModel",
      "diversityLevel",
    ]) ||
    receipt.reviewer.reviewerProvider !== K3_PROVIDER ||
    receipt.reviewer.requestedModel !== K3_MODEL ||
    receipt.reviewer.actualReturnedModel !== K3_MODEL ||
    receipt.reviewer.reviewerSessionId !== transportEvidence?.responseId ||
    receipt.reviewer.apiBaseURL !== K3_BASE_URL ||
    receipt.reviewer.endpoint !== K3_CHAT_ENDPOINT ||
    receipt.reviewer.reviewerIndependentOfImplementation !== true ||
    receipt.reviewer.implementationProvider === K3_PROVIDER ||
    receipt.reviewer.implementationModel === K3_MODEL ||
    receipt.reviewer.diversityLevel !==
      "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER"
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_MODEL_IDENTITY_INVALID");
  }
  if (
    !exactKeys(receipt.source, [
      "baseCommit",
      "sourceCommit",
      "headCommit",
      "tree",
      "diffSha256",
      "changedPathsDigest",
      "gitDiffCheck",
    ]) ||
    !validCommit(receipt.source.baseCommit) ||
    !validCommit(receipt.source.sourceCommit) ||
    receipt.source.headCommit !== receipt.source.sourceCommit ||
    !validCommit(receipt.source.tree) ||
    !validSha(receipt.source.diffSha256) ||
    !validSha(receipt.source.changedPathsDigest) ||
    !gitDiffCheckValid(receipt.source.gitDiffCheck, receipt.source)
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_SOURCE_INVALID");
  }
  if (!receiptV6BindingsValid(receipt.bindings)) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_BINDINGS_INVALID");
  }
  const [
    providerTransportSchemaBytes,
    canonicalOutputSchemaBytes,
    transportEvidenceSchemaBytes,
    receiptSchemaBytes,
  ] =
    await Promise.all([
      readArtifact(evidenceResolver, {
        path: transportEvidence?.bindings?.providerTransportSchemaPath,
      }),
      readArtifact(evidenceResolver, {
        path: transportEvidence?.bindings?.canonicalOutputSchemaPath,
      }),
      readArtifact(evidenceResolver, { path: TRANSPORT_V4_SCHEMA_PATH }),
      readArtifact(evidenceResolver, { path: receiptSchemaPath }),
    ]);
  const runtimeManifestBytes =
    runtimeManifestSchemaPath === null
      ? null
      : await readArtifact(evidenceResolver, {
          path: runtimeManifestPath,
          sourceCommit:
            receipt?.isolationEvidence?.runtimeTrust?.runtimeCommit,
        });
  const runtimeManifestSchemaBytes =
    runtimeManifestSchemaPath === null
      ? null
      : await readArtifact(evidenceResolver, {
          path: runtimeManifestSchemaPath,
          sourceCommit:
            receipt?.isolationEvidence?.runtimeTrust?.runtimeCommit,
        });
  if (runtimeManifestSchemaPath !== null) {
    const manifestBinding =
      receipt?.isolationEvidence?.runtimeDependencyManifest;
    const runtimeTrust = receipt?.isolationEvidence?.runtimeTrust;
    const runtimeManifest = parseJsonBytes(runtimeManifestBytes);
    const runtimeManifestSchemaValidation =
      runtimeManifest !== null &&
      runtimeManifestSchemaBytes instanceof Uint8Array
        ? await validateIndependentReviewSchemaInstance({
            schemaBytes: runtimeManifestSchemaBytes,
            expectedSchemaSha256: hashBytes(runtimeManifestSchemaBytes),
            instance: runtimeManifest,
            label: "Independent Review Runtime Manifest v3 Schema",
          })
        : { ok: false };
    if (
      !(runtimeManifestBytes instanceof Uint8Array) ||
      !(runtimeManifestSchemaBytes instanceof Uint8Array) ||
      hashBytes(runtimeManifestBytes) !== manifestBinding?.gitBlobSha256 ||
      hashBytes(runtimeManifestBytes) !==
        runtimeTrust?.runtimeManifestGitBlobSha256 ||
      hashBytes(runtimeManifestSchemaBytes) !==
        manifestBinding?.schemaGitBlobSha256 ||
      runtimeManifest?.schemaVersion !==
        "independent-review-runtime-dependency-manifest.v3" ||
      runtimeManifestSchemaValidation.ok !== true ||
      validateIndependentReviewRuntimeDependencyManifest(runtimeManifest).ok !==
        true ||
      runtimeManifest.manifestSha256 !== manifestBinding?.manifestSha256 ||
      runtimeManifest.node?.executableSha256 !==
        manifestBinding?.nodeExecutableSha256 ||
      runtimeManifest.dependencies?.fullTreeSha256 !==
        manifestBinding?.fullDependencyTreeSha256 ||
      runtimeManifest.npm?.packageTreeSha256 !==
        manifestBinding?.npmPackageTreeSha256
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_V6_RUNTIME_MANIFEST_INVALID");
    }
  }
  const estimateValidation = await validateKimiK3TokenEstimateEvidenceV2({
    evidence: tokenEstimateEvidence,
    evidenceResolver,
  });
  const transportValidation = await validateKimiK3TransportEvidenceV4({
    evidence: transportEvidence,
    tokenEstimateEvidence,
    evidenceResolver,
  });
  if (!estimateValidation.valid) reasonCodes.push(...estimateValidation.reasonCodes);
  if (!transportValidation.valid) reasonCodes.push(...transportValidation.reasonCodes);
  if (
    receipt.reviewMaterialSha256 !== receipt.bindings.reviewMaterialSha256 ||
    receipt.bindings.reviewBundleSha256 !== receipt.bundleSha256 ||
    receipt.bindings.reviewBundleSha256 !==
      transportEvidence?.bindings?.reviewBundleSha256 ||
    receipt.bindings.reviewMaterialSha256 !==
      transportEvidence?.bindings?.reviewMaterialSha256 ||
    receipt.bindings.transportEvidenceSha256 !==
      transportEvidence?.transportEvidenceSha256 ||
    receipt.bindings.tokenEstimateEvidenceSha256 !==
      tokenEstimateEvidence?.evidenceSha256 ||
    receipt.bindings.providerConfigSha256 !==
      transportEvidence?.bindings?.providerConfigSha256 ||
    receipt.bindings.providerConfigSchemaSha256 !==
      transportEvidence?.bindings?.providerConfigSchemaSha256 ||
    receipt.bindings.canonicalReceiptSchemaSha256 !==
      transportEvidence?.bindings?.receiptSchemaSha256 ||
    !(receiptSchemaBytes instanceof Uint8Array) ||
    hashBytes(receiptSchemaBytes) !==
      receipt.bindings.canonicalReceiptSchemaSha256 ||
    !(transportEvidenceSchemaBytes instanceof Uint8Array) ||
    hashBytes(transportEvidenceSchemaBytes) !==
      receipt.bindings.transportEvidenceSchemaSha256 ||
    receipt.bindings.tokenEstimateEvidenceSchemaSha256 !==
      transportEvidence?.bindings?.tokenEstimateEvidenceSchemaSha256 ||
    !(providerTransportSchemaBytes instanceof Uint8Array) ||
    hashBytes(providerTransportSchemaBytes) !==
      receipt.bindings.providerTransportSchemaSha256 ||
    receipt.bindings.providerTransportSchemaSha256 !==
      transportEvidence?.bindings?.providerTransportSchemaSha256 ||
    !(canonicalOutputSchemaBytes instanceof Uint8Array) ||
    hashBytes(canonicalOutputSchemaBytes) !==
      receipt.bindings.canonicalOutputSchemaSha256 ||
    receipt.bindings.canonicalOutputSchemaSha256 !==
      transportEvidence?.bindings?.canonicalOutputSchemaSha256 ||
    receipt.bindings.rawTokenEstimateRequestSha256 !==
      tokenEstimateEvidence?.request?.sha256 ||
    receipt.bindings.rawTokenEstimateResponseSha256 !==
      tokenEstimateEvidence?.response?.sha256 ||
    receipt.bindings.rawRequestArtifactSha256 !==
      transportEvidence?.request?.sha256 ||
    receipt.bindings.rawResponseUtf8Sha256 !==
      transportEvidence?.response?.sha256 ||
    receipt.bindings.rawContentUtf8Sha256 !==
      transportEvidence?.content?.sha256
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_EVIDENCE_BINDING_MISMATCH");
  }
  if (!artifactsShapeValid(receipt.artifacts)) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_ARTIFACT_SHAPE_INVALID");
  } else {
    const names = Object.keys(receipt.artifacts);
    const bytes = await Promise.all(
      names.map((name) => readArtifact(evidenceResolver, receipt.artifacts[name])),
    );
    if (
      !names.every((name, index) =>
        artifactMatches(receipt.artifacts[name], bytes[index]),
      )
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_V6_ARTIFACT_BYTES_MISMATCH");
    }
    const resolved = Object.fromEntries(
      names.map((name, index) => [name, bytes[index]]),
    );
    if (
      canonicalize(parseJsonBytes(resolved.tokenEstimateEvidence)) !==
        canonicalize(tokenEstimateEvidence) ||
      canonicalize(parseJsonBytes(resolved.transportEvidence)) !==
        canonicalize(transportEvidence) ||
      canonicalize(receipt.artifacts.tokenEstimateRequest) !==
        canonicalize(tokenEstimateEvidence?.request) ||
      receipt.artifacts.tokenEstimateResponse.sha256 !==
        tokenEstimateEvidence?.response?.sha256 ||
      canonicalize(receipt.artifacts.request) !==
        canonicalize(transportEvidence?.request) ||
      receipt.artifacts.response.sha256 !== transportEvidence?.response?.sha256 ||
      canonicalize(receipt.artifacts.content) !==
        canonicalize(transportEvidence?.content) ||
      receipt.artifacts.material.sha256 !==
        receipt.bindings.reviewMaterialSha256
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_V6_ARTIFACT_BINDING_MISMATCH");
    }
    const modelContent = parseJsonBytes(resolved.content);
    const providerValidation =
      modelContent !== null &&
      providerTransportSchemaBytes instanceof Uint8Array
        ? await validateIndependentReviewSchemaInstance({
            schemaBytes: providerTransportSchemaBytes,
            expectedSchemaSha256: hashBytes(providerTransportSchemaBytes),
            instance: modelContent,
            label: "Moonshot Kimi K3 provider transport output Schema",
          })
        : { ok: false };
    const canonicalValidation =
      canonicalOutputSchemaBytes instanceof Uint8Array
        ? await validateIndependentModelReviewOutputArtifact({
            rawModelOutput: resolved.content,
            outputSchemaBytes: canonicalOutputSchemaBytes,
            expectedOutputSchemaSha256: hashBytes(
              canonicalOutputSchemaBytes,
            ),
          })
        : { ok: false };
    if (
      !modelOutputValid(modelContent) ||
      providerValidation.ok !== true ||
      canonicalValidation.ok !== true ||
      modelContent.decision !== receipt.decision ||
      canonicalize(modelContent.findings) !== canonicalize(receipt.findings)
    ) {
      reasonCodes.push("KIMI_K3_RECEIPT_V6_MODEL_CONTENT_INVALID");
    }
  }
  if (
    receipt.source.sourceCommit !== transportEvidence?.source?.sourceCommit ||
    receipt.source.tree !== transportEvidence?.source?.sourceTree ||
    receipt.source.sourceCommit !== tokenEstimateEvidence?.source?.sourceCommit ||
    receipt.source.tree !== tokenEstimateEvidence?.source?.sourceTree ||
    !isolationShapeValid(
      receipt.isolationEvidence,
      receipt.source,
      tokenEstimateEvidence,
      runtimeManifestPath,
      runtimeManifestSchemaPath,
    )
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_RSE_TOPOLOGY_INVALID");
  }
  const context = receipt.contextAndBudget;
  if (
    !exactKeys(context, [
      "estimateCoverage",
      "estimatedMessageInputTokens",
      "nonMessageVisibleTokenReserve",
      "nonMessageVisibleInputByteLength",
      "nonMessageVisibleInputSha256",
      "contextWindowTokens",
      "maxCompletionTokens",
      "safetyMarginTokens",
      "requiredContextTokens",
      "contextProved",
      "budgetMicros",
      "worstCaseBillableInputTokens",
      "worstCaseTotalMicros",
      "budgetProved",
    ]) ||
    context.estimateCoverage !== V3_COVERAGE ||
    context.estimatedMessageInputTokens !==
      tokenEstimateEvidence?.estimate?.estimatedMessageInputTokens ||
    context.nonMessageVisibleTokenReserve !== NON_MESSAGE_TOKEN_RESERVE ||
    context.nonMessageVisibleInputByteLength !==
      tokenEstimateEvidence?.bindings?.nonMessageVisibleInputByteLength ||
    context.nonMessageVisibleInputSha256 !==
      tokenEstimateEvidence?.bindings?.nonMessageVisibleInputSha256 ||
    context.contextWindowTokens !== CONTEXT_TOKENS ||
    context.maxCompletionTokens !== COMPLETION_TOKENS ||
    context.safetyMarginTokens !== SAFETY_TOKENS ||
    context.requiredContextTokens !==
      tokenEstimateEvidence?.estimate?.requiredContextTokens ||
    context.contextProved !== true ||
    context.budgetMicros !== BUDGET_MICROS ||
    context.worstCaseBillableInputTokens !==
      tokenEstimateEvidence?.budget?.worstCaseBillableInputTokens ||
    context.worstCaseTotalMicros !==
      tokenEstimateEvidence?.budget?.worstCaseTotalMicros ||
    context.budgetProved !== true
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_CONTEXT_OR_BUDGET_INVALID");
  }
  if (
    canonicalize(receipt.usage) !== canonicalize(transportEvidence?.usage) ||
    !normalizedUsageValid(receipt.usage) ||
    !exactKeys(receipt.cost, [
      "currency",
      "taxBasis",
      "actualInputMicros",
      "actualOutputMicros",
      "actualTotalMicros",
      "budgetMicros",
      "withinBudget",
    ]) ||
    receipt.cost.currency !== "USD" ||
    receipt.cost.taxBasis !== "TAX_EXCLUSIVE" ||
    receipt.cost.actualTotalMicros !==
      receipt.cost.actualInputMicros + receipt.cost.actualOutputMicros ||
    receipt.cost.actualInputMicros !== transportEvidence?.cost?.inputMicros ||
    receipt.cost.actualOutputMicros !== transportEvidence?.cost?.outputMicros ||
    receipt.cost.actualTotalMicros !== transportEvidence?.cost?.totalMicros ||
    receipt.cost.budgetMicros !== BUDGET_MICROS ||
    receipt.cost.withinBudget !== true
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_USAGE_OR_COST_INVALID");
  }
  const blockingFinding = (receipt.findings ?? []).some(
    (finding) =>
      ["HIGH", "CRITICAL"].includes(finding?.severity) &&
      finding?.status !== "RESOLVED",
  );
  const expectedConclusion =
    receipt.decision === "CLEAR"
      ? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
      : receipt.decision;
  if (
    !Array.isArray(receipt.reviewedPaths) ||
    receipt.reviewedPaths.length === 0 ||
    new Set(receipt.reviewedPaths).size !== receipt.reviewedPaths.length ||
    !receipt.reviewedPaths.every(validPath) ||
    !Array.isArray(receipt.findings) ||
    !Array.isArray(receipt.testEvidenceDigests) ||
    receipt.testEvidenceDigests.length === 0 ||
    !receipt.testEvidenceDigests.every(validSha) ||
    !["CLEAR", "BLOCKED", "INCONCLUSIVE"].includes(receipt.decision) ||
    receipt.conclusion !== expectedConclusion ||
    (receipt.decision === "CLEAR" && blockingFinding)
  ) {
    reasonCodes.push("KIMI_K3_RECEIPT_V6_DECISION_INVALID");
  }
  return result(reasonCodes.length === 0, reasonCodes, {
    status: receipt.decision,
    conclusion: receipt.conclusion,
  });
}

export async function validateKimiK3ReviewReceiptV6(input) {
  return validateKimiK3ReviewReceiptCurrent(input, {
    schemaVersion: "independent-model-review-receipt.v6",
    receiptSchemaPath: RECEIPT_V6_SCHEMA_PATH,
    runtimeManifestPath: RUNTIME_MANIFEST_V2_PATH,
  });
}

export async function validateKimiK3ReviewReceiptV7(input) {
  const validation = await validateKimiK3ReviewReceiptCurrent(input, {
    schemaVersion: "independent-model-review-receipt.v7",
    receiptSchemaPath: RECEIPT_V7_SCHEMA_PATH,
    runtimeManifestPath: RUNTIME_MANIFEST_V3_PATH,
    runtimeManifestSchemaPath: RUNTIME_MANIFEST_V3_SCHEMA_PATH,
  });
  return {
    ...validation,
    reasonCodes: validation.reasonCodes.map((reasonCode) =>
      reasonCode.replace("KIMI_K3_RECEIPT_V6_", "KIMI_K3_RECEIPT_V7_"),
    ),
  };
}
