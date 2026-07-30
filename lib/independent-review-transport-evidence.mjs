import { createHash } from "node:crypto";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9._@:/+-]{0,127}$/;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const HTTPS_BASE_URL = /^https:\/\/(?![^/@\s]+@)[^\s?#]+$/u;
const ENDPOINT =
  /^\/(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\?#]{1,511}$/u;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const EVIDENCE_KEYS = [
  "schemaVersion",
  "evidenceId",
  "provider",
  "requestedModel",
  "actualReturnedModel",
  "baseURL",
  "endpoint",
  "source",
  "bindings",
  "request",
  "response",
  "content",
  "protocol",
  "validators",
  "startedAt",
  "finishedAt",
  "transportEvidenceSha256",
];
const EXPECTED_BINDING_KEYS = [
  "provider",
  "requestedModel",
  "actualReturnedModel",
  "baseURL",
  "endpoint",
  "sourceCommit",
  "sourceTree",
  "reviewBundleSha256",
  "reviewerPromptSha256",
  "receiptSchemaSha256",
  "outputSchemaPath",
  "outputSchemaSha256",
  "schemaValidatorVersion",
  "semanticValidatorVersion",
];
const CREDENTIAL_PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/iu,
  /\b(?:sk|ak)-[A-Za-z0-9_-]{16,}\b/u,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
];
const CREDENTIAL_FIELD_NAMES = new Set([
  "accesstoken",
  "apikey",
  "authorization",
  "cookie",
  "cookies",
  "password",
  "requestheaders",
  "responseheaders",
  "secret",
  "token",
]);

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Non-finite JSON number.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("Only JSON values can be canonicalized.");
}

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

function hashBytes(value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("Transport evidence hashing requires exact bytes.");
  }
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function hashValue(value) {
  return hashBytes(Buffer.from(canonicalize(value), "utf8"));
}

function evidenceDigest(evidence) {
  return hashValue(withoutField(evidence, "transportEvidenceSha256"));
}

export const independentReviewTransportEvidenceDigests = Object.freeze({
  bytes: hashBytes,
  value: hashValue,
  evidence: evidenceDigest,
  canonicalize,
});

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalize(Object.keys(value).sort()) ===
      canonicalize([...expected].sort())
  );
}

function validName(value) {
  return typeof value === "string" && NAME.test(value);
}

function validVersion(value) {
  return typeof value === "string" && VERSION.test(value);
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

function validByteBinding(value) {
  return (
    exactKeys(value, ["path", "encoding", "byteLength", "sha256"]) &&
    validPath(value.path) &&
    value.encoding === "UTF-8" &&
    Number.isInteger(value.byteLength) &&
    value.byteLength > 0 &&
    value.byteLength <= MAX_ARTIFACT_BYTES &&
    validSha(value.sha256)
  );
}

function validResponseBinding(value) {
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
    Number.isInteger(value.byteLength) &&
    value.byteLength > 0 &&
    value.byteLength <= MAX_ARTIFACT_BYTES &&
    validSha(value.sha256) &&
    value.httpStatus === 200 &&
    /^application\/json(?:;\s*charset=utf-8)?$/u.test(value.contentType)
  );
}

function validShape(evidence) {
  return (
    exactKeys(evidence, EVIDENCE_KEYS) &&
    evidence.schemaVersion ===
      "independent-review-transport-evidence.v1" &&
    typeof evidence.evidenceId === "string" &&
    /^irte_[a-z0-9][a-z0-9_-]{7,127}$/u.test(evidence.evidenceId) &&
    validName(evidence.provider) &&
    validName(evidence.requestedModel) &&
    validName(evidence.actualReturnedModel) &&
    typeof evidence.baseURL === "string" &&
    evidence.baseURL.length <= 512 &&
    HTTPS_BASE_URL.test(evidence.baseURL) &&
    typeof evidence.endpoint === "string" &&
    ENDPOINT.test(evidence.endpoint) &&
    exactKeys(evidence.source, ["sourceCommit", "sourceTree"]) &&
    validCommit(evidence.source.sourceCommit) &&
    validCommit(evidence.source.sourceTree) &&
    exactKeys(evidence.bindings, [
      "reviewBundleSha256",
      "reviewerPromptSha256",
      "receiptSchemaSha256",
      "outputSchemaPath",
      "outputSchemaSha256",
    ]) &&
    validSha(evidence.bindings.reviewBundleSha256) &&
    validSha(evidence.bindings.reviewerPromptSha256) &&
    validSha(evidence.bindings.receiptSchemaSha256) &&
    validPath(evidence.bindings.outputSchemaPath) &&
    validSha(evidence.bindings.outputSchemaSha256) &&
    validByteBinding(evidence.request) &&
    validResponseBinding(evidence.response) &&
    validByteBinding(evidence.content) &&
    evidence.request.path !== evidence.response.path &&
    evidence.request.path !== evidence.content.path &&
    evidence.response.path !== evidence.content.path &&
    evidence.request.path !== evidence.bindings.outputSchemaPath &&
    evidence.response.path !== evidence.bindings.outputSchemaPath &&
    evidence.content.path !== evidence.bindings.outputSchemaPath &&
    exactKeys(evidence.protocol, [
      "toolsAbsent",
      "toolChoiceNone",
      "strictSchema",
      "networkAttemptCount",
      "choiceCount",
      "finishReason",
    ]) &&
    evidence.protocol.toolsAbsent === true &&
    evidence.protocol.toolChoiceNone === true &&
    evidence.protocol.strictSchema === true &&
    evidence.protocol.networkAttemptCount === 1 &&
    evidence.protocol.choiceCount === 1 &&
    evidence.protocol.finishReason === "stop" &&
    exactKeys(evidence.validators, [
      "schemaValidatorVersion",
      "semanticValidatorVersion",
    ]) &&
    validVersion(evidence.validators.schemaValidatorVersion) &&
    validVersion(evidence.validators.semanticValidatorVersion) &&
    validDate(evidence.startedAt) &&
    validDate(evidence.finishedAt) &&
    validSha(evidence.transportEvidenceSha256)
  );
}

function result(valid, reasonCodes, evidence = null) {
  if (!valid) {
    return {
      valid: false,
      status: "REJECTED",
      reasonCodes: [...new Set(reasonCodes)].sort(),
    };
  }
  return {
    valid: true,
    status: "PROVED",
    reasonCodes: [],
    provider: evidence.provider,
    requestedModel: evidence.requestedModel,
    actualReturnedModel: evidence.actualReturnedModel,
    sourceCommit: evidence.source.sourceCommit,
    sourceTree: evidence.source.sourceTree,
  };
}

function decodeUtf8(bytes) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function parseJson(text) {
  if (typeof text !== "string") return null;
  try {
    const value = JSON.parse(text);
    return value !== null && typeof value === "object" ? value : null;
  } catch {
    return null;
  }
}

function containsCredentialMaterial(text) {
  return (
    typeof text === "string" &&
    CREDENTIAL_PATTERNS.some((pattern) => pattern.test(text))
  );
}

function containsCredentialField(value) {
  if (Array.isArray(value)) {
    return value.some(containsCredentialField);
  }
  if (value === null || typeof value !== "object") {
    return false;
  }
  return Object.entries(value).some(
    ([key, child]) =>
      CREDENTIAL_FIELD_NAMES.has(key.toLowerCase().replaceAll(/[_-]/gu, "")) ||
      containsCredentialField(child),
  );
}

function bindingReasonCodes(evidence, expected) {
  if (!exactKeys(expected, EXPECTED_BINDING_KEYS)) {
    return ["TRANSPORT_EXPECTED_BINDINGS_INVALID"];
  }
  const checks = [
    [
      evidence.provider,
      expected.provider,
      "TRANSPORT_PROVIDER_MISMATCH",
    ],
    [
      evidence.requestedModel,
      expected.requestedModel,
      "TRANSPORT_REQUESTED_MODEL_MISMATCH",
    ],
    [
      evidence.actualReturnedModel,
      expected.actualReturnedModel,
      "TRANSPORT_RETURNED_MODEL_MISMATCH",
    ],
    [
      evidence.baseURL,
      expected.baseURL,
      "TRANSPORT_BASE_URL_MISMATCH",
    ],
    [
      evidence.endpoint,
      expected.endpoint,
      "TRANSPORT_ENDPOINT_MISMATCH",
    ],
    [
      evidence.source.sourceCommit,
      expected.sourceCommit,
      "TRANSPORT_SOURCE_COMMIT_MISMATCH",
    ],
    [
      evidence.source.sourceTree,
      expected.sourceTree,
      "TRANSPORT_SOURCE_TREE_MISMATCH",
    ],
    [
      evidence.bindings.reviewBundleSha256,
      expected.reviewBundleSha256,
      "TRANSPORT_REVIEW_BUNDLE_MISMATCH",
    ],
    [
      evidence.bindings.reviewerPromptSha256,
      expected.reviewerPromptSha256,
      "TRANSPORT_REVIEWER_PROMPT_MISMATCH",
    ],
    [
      evidence.bindings.receiptSchemaSha256,
      expected.receiptSchemaSha256,
      "TRANSPORT_RECEIPT_SCHEMA_MISMATCH",
    ],
    [
      evidence.bindings.outputSchemaPath,
      expected.outputSchemaPath,
      "TRANSPORT_OUTPUT_SCHEMA_PATH_MISMATCH",
    ],
    [
      evidence.bindings.outputSchemaSha256,
      expected.outputSchemaSha256,
      "TRANSPORT_OUTPUT_SCHEMA_MISMATCH",
    ],
    [
      evidence.validators.schemaValidatorVersion,
      expected.schemaValidatorVersion,
      "TRANSPORT_SCHEMA_VALIDATOR_VERSION_MISMATCH",
    ],
    [
      evidence.validators.semanticValidatorVersion,
      expected.semanticValidatorVersion,
      "TRANSPORT_SEMANTIC_VALIDATOR_VERSION_MISMATCH",
    ],
  ];
  return checks
    .filter(([actual, expectedValue]) => actual !== expectedValue)
    .map(([, , code]) => code);
}

async function readArtifact(evidenceResolver, descriptor) {
  if (typeof evidenceResolver !== "function") {
    throw new TypeError("Transport evidence resolver is required.");
  }
  const bytes = await evidenceResolver(descriptor.path);
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("Transport evidence resolver must return exact bytes.");
  }
  return Buffer.from(bytes);
}

function validRequestSemantics(request, evidence) {
  return (
    request !== null &&
    request.model === evidence.requestedModel &&
    !Object.hasOwn(request, "tools") &&
    request.tool_choice === "none" &&
    request.response_format?.type === "json_schema" &&
    request.response_format?.json_schema?.strict === true
  );
}

function requestSchemaMatchesFrozenSchema(request, frozenSchema) {
  try {
    return (
      frozenSchema !== null &&
      typeof frozenSchema === "object" &&
      !Array.isArray(frozenSchema) &&
      canonicalize(request?.response_format?.json_schema?.schema) ===
        canonicalize(frozenSchema)
    );
  } catch {
    return false;
  }
}

function validResponseSemantics(response, contentText, evidence) {
  return (
    response !== null &&
    response.model === evidence.actualReturnedModel &&
    Array.isArray(response.choices) &&
    response.choices.length === 1 &&
    response.choices[0]?.finish_reason === "stop" &&
    response.choices[0]?.message?.content === contentText
  );
}

export async function validateIndependentReviewTransportEvidence({
  evidence,
  expectedBindings,
  evidenceResolver,
}) {
  const reasonCodes = [];
  if (!validShape(evidence)) {
    reasonCodes.push("TRANSPORT_EVIDENCE_SHAPE_INVALID");
    if (
      evidence?.response?.httpStatus !== 200 ||
      evidence?.protocol?.networkAttemptCount !== 1 ||
      evidence?.protocol?.choiceCount !== 1 ||
      evidence?.protocol?.finishReason !== "stop" ||
      evidence?.protocol?.toolsAbsent !== true ||
      evidence?.protocol?.toolChoiceNone !== true ||
      evidence?.protocol?.strictSchema !== true
    ) {
      reasonCodes.push("TRANSPORT_PROTOCOL_INVALID");
    }
    if (
      expectedBindings?.schemaValidatorVersion !== undefined &&
      evidence?.validators?.schemaValidatorVersion !==
        expectedBindings.schemaValidatorVersion
    ) {
      reasonCodes.push("TRANSPORT_SCHEMA_VALIDATOR_VERSION_MISMATCH");
    }
    if (
      expectedBindings?.semanticValidatorVersion !== undefined &&
      evidence?.validators?.semanticValidatorVersion !==
        expectedBindings.semanticValidatorVersion
    ) {
      reasonCodes.push("TRANSPORT_SEMANTIC_VALIDATOR_VERSION_MISMATCH");
    }
    if (
      validDate(evidence?.startedAt) &&
      validDate(evidence?.finishedAt) &&
      Date.parse(evidence.finishedAt) < Date.parse(evidence.startedAt)
    ) {
      reasonCodes.push("TRANSPORT_TIME_ORDER_INVALID");
    }
    return result(false, reasonCodes);
  }

  reasonCodes.push(...bindingReasonCodes(evidence, expectedBindings));

  if (
    evidence.transportEvidenceSha256 !== evidenceDigest(evidence)
  ) {
    reasonCodes.push("TRANSPORT_EVIDENCE_SELF_HASH_MISMATCH");
  }
  if (Date.parse(evidence.finishedAt) < Date.parse(evidence.startedAt)) {
    reasonCodes.push("TRANSPORT_TIME_ORDER_INVALID");
  }
  if (
    evidence.response.httpStatus !== 200 ||
    evidence.protocol.networkAttemptCount !== 1 ||
    evidence.protocol.choiceCount !== 1 ||
    evidence.protocol.finishReason !== "stop" ||
    evidence.protocol.toolsAbsent !== true ||
    evidence.protocol.toolChoiceNone !== true ||
    evidence.protocol.strictSchema !== true
  ) {
    reasonCodes.push("TRANSPORT_PROTOCOL_INVALID");
  }

  let requestBytes;
  let responseBytes;
  let contentBytes;
  let outputSchemaBytes;
  try {
    [requestBytes, responseBytes, contentBytes, outputSchemaBytes] =
      await Promise.all([
        readArtifact(evidenceResolver, evidence.request),
        readArtifact(evidenceResolver, evidence.response),
        readArtifact(evidenceResolver, evidence.content),
        readArtifact(evidenceResolver, {
          path: evidence.bindings.outputSchemaPath,
        }),
      ]);
  } catch {
    return result(false, [
      ...reasonCodes,
      "TRANSPORT_EVIDENCE_BYTES_UNAVAILABLE",
    ]);
  }

  for (const [label, descriptor, bytes] of [
    ["REQUEST", evidence.request, requestBytes],
    ["RESPONSE", evidence.response, responseBytes],
    ["CONTENT", evidence.content, contentBytes],
  ]) {
    if (
      bytes.byteLength !== descriptor.byteLength ||
      hashBytes(bytes) !== descriptor.sha256
    ) {
      reasonCodes.push(`TRANSPORT_${label}_BYTES_MISMATCH`);
    }
  }

  const requestText = decodeUtf8(requestBytes);
  const responseText = decodeUtf8(responseBytes);
  const contentText = decodeUtf8(contentBytes);
  const outputSchemaText = decodeUtf8(outputSchemaBytes);
  if (requestText === null) {
    reasonCodes.push("TRANSPORT_REQUEST_UTF8_INVALID");
  }
  if (responseText === null) {
    reasonCodes.push("TRANSPORT_RESPONSE_UTF8_INVALID");
  }
  if (contentText === null) {
    reasonCodes.push("TRANSPORT_CONTENT_UTF8_INVALID");
  }
  if (
    hashBytes(outputSchemaBytes) !== evidence.bindings.outputSchemaSha256
  ) {
    reasonCodes.push("TRANSPORT_OUTPUT_SCHEMA_BYTES_MISMATCH");
  }

  if (
    [canonicalize(evidence), requestText, responseText, contentText].some(
      containsCredentialMaterial,
    )
  ) {
    reasonCodes.push("TRANSPORT_CREDENTIAL_MATERIAL_DETECTED");
  }

  const request = parseJson(requestText);
  const response = parseJson(responseText);
  const outputSchema = parseJson(outputSchemaText);
  if (
    containsCredentialField(request) ||
    containsCredentialField(response)
  ) {
    reasonCodes.push("TRANSPORT_CREDENTIAL_MATERIAL_DETECTED");
  }
  if (!validRequestSemantics(request, evidence)) {
    reasonCodes.push("TRANSPORT_REQUEST_SEMANTICS_INVALID");
  }
  if (outputSchema === null) {
    reasonCodes.push("TRANSPORT_OUTPUT_SCHEMA_JSON_INVALID");
  } else if (!requestSchemaMatchesFrozenSchema(request, outputSchema)) {
    reasonCodes.push("TRANSPORT_REQUEST_SCHEMA_MISMATCH");
  }
  if (!validResponseSemantics(response, contentText, evidence)) {
    reasonCodes.push("TRANSPORT_RESPONSE_SEMANTICS_INVALID");
  }

  return result(reasonCodes.length === 0, reasonCodes, evidence);
}
