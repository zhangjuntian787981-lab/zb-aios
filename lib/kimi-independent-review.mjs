import { createHash } from "node:crypto";
import {
  deriveIndependentModelDiversity,
  independentReviewSchemaValidatorVersion,
  parseIndependentReviewJsonBytes,
  parseIndependentModelReviewOutput,
  validateIndependentModelReviewOutputArtifact,
  validateIndependentReviewBundle,
  validateIndependentReviewPolicy,
  validateIndependentReviewSchemaInstance,
} from "./independent-model-review.mjs";
import {
  validateIndependentReviewRuntimeDependencyManifest,
} from "./independent-review-runtime-manifest.mjs";
import {
  independentReviewTransportEvidenceDigests,
  validateIndependentReviewTransportEvidence,
} from "./independent-review-transport-evidence.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
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
  "credentialEnv",
  "keychainServiceRecommendation",
  "keychainAccountRecommendation",
  "thinking",
  "toolChoice",
  "toolsOmitted",
  "responseFormat",
  "forbiddenRequestFields",
  "maxReviewMaterialUtf8Bytes",
  "maxRequestUtf8Bytes",
  "maxResponseUtf8Bytes",
  "contextBudgetBasis",
  "fallbackPolicy",
  "configSha256",
];
const MATERIAL_KEYS = [
  "schemaVersion",
  "materialId",
  "source",
  "bindings",
  "sections",
  "sectionSetSha256",
  "totalSectionUtf8ByteLength",
  "contextBudgetUtf8Bytes",
  "materialSha256",
];
const SECTION_KEYS = [
  "kind",
  "path",
  "encoding",
  "byteLength",
  "sha256",
  "content",
];
const BYTE_BINDING_KEYS = ["path", "byteLength", "sha256"];
const REVIEW_BUNDLE_BINDING_KEYS = [
  "path",
  "byteLength",
  "sha256",
  "bundleDigest",
];
const SNAPSHOT_KEYS = [
  "head",
  "tree",
  "worktreeStatusSha256",
  "worktreeContentManifestSha256",
  "worktreePathCount",
  "protectedPathSetSha256",
  "protectedFilesDigest",
  "ignoredExclusionPolicySha256",
  "ignoredExcludedPathCount",
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
  "isolationEvidence",
  "reviewedPaths",
  "findings",
  "testEvidenceDigests",
  "decision",
  "conclusion",
  "historicalTerraEvidenceAccepted",
  "humanReviewClaim",
  "governanceEffect",
  "selfAuthorizing",
  "startedAt",
  "finishedAt",
  "recordedAt",
  "receiptSha256",
];
const REQUEST_KEYS = [
  "model",
  "messages",
  "thinking",
  "tool_choice",
  "response_format",
];
const FORBIDDEN_REQUEST_FIELDS = [
  "frequency_penalty",
  "n",
  "presence_penalty",
  "temperature",
  "top_p",
];
const CONFIG_SHA_PLACEHOLDER = `sha256:${"0".repeat(64)}`;
const RECEIPT_SHA_PLACEHOLDER = CONFIG_SHA_PLACEHOLDER;
const TRANSPORT_EVIDENCE_SHA_PLACEHOLDER = CONFIG_SHA_PLACEHOLDER;
const TRANSPORT_EVIDENCE_VALIDATOR_VERSION =
  "independent-review-transport-evidence-validator.v1";
const KIMI_RECEIPT_SEMANTIC_VALIDATOR_VERSION =
  "kimi-independent-model-review-semantic-validator.v2";
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MATERIAL_V2_MAGIC = Buffer.from(
  "INDEPENDENT-REVIEW-MATERIAL/2\n",
  "utf8",
);
const MATERIAL_V2_SECTION_KEYS = [
  "kind",
  "path",
  "encoding",
  "byteLength",
  "sha256",
];
const MATERIAL_SECTION_KINDS = [
  "GOVERNANCE",
  "PATCH",
  "REVIEW_BUNDLE",
  "SOURCE",
  "SPECIFICATION",
  "TEST_EVIDENCE",
];
export const kimiIndependentReviewFixedBaseCommit =
  "ab95c7aff586279062c7698749fdbc0e38e955d1";
const MATERIAL_PATHS = Object.freeze({
  reviewBundle: "artifacts/independent-review-bundle.v2.json",
  patch: "artifacts/source.diff",
  prompt:
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  outputSchema:
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json",
  config:
    "implementation/governance/independent-review/moonshot-kimi-k2.7-code.v1.json",
  modelVisibleProtocol:
    "artifacts/moonshot-kimi-model-visible-protocol.v1.json",
});

export const kimiIndependentReviewMaterialGovernancePaths = Object.freeze(
  [
    "docs/adr/0012-moonshot-kimi-independent-review-transport.md",
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json",
    "implementation/governance/schemas/independent-review-material.v1.schema.json",
    "implementation/governance/schemas/independent-review-material.v2.schema.json",
    "implementation/governance/schemas/moonshot-kimi-independent-review-config.v1.schema.json",
    "implementation/governance/independent-review/kimi-runtime-manifest.v1.json",
    "implementation/governance/independent-review/implementation-participant.v1.json",
    "lib/kimi-independent-review.mjs",
    "scripts/build-independent-review-material.mjs",
    "scripts/run-kimi-independent-review.mjs",
    "tests/independent-review-material-generator.test.mjs",
    "tests/kimi-independent-review.test.mjs",
  ].sort(),
);

export function createKimiModelVisibleProtocolBytes(config) {
  return Buffer.from(
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
      maxReviewMaterialUtf8Bytes: config.maxReviewMaterialUtf8Bytes,
      maxRequestUtf8Bytes: config.maxRequestUtf8Bytes,
      maxResponseUtf8Bytes: config.maxResponseUtf8Bytes,
      contextBudgetBasis: config.contextBudgetBasis,
      fallbackPolicy: config.fallbackPolicy,
    }),
    "utf8",
  );
}

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

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalize(Object.keys(value).sort()) ===
      canonicalize([...expected].sort())
  );
}

function sameCanonical(left, right) {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

function sha256Bytes(value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("Kimi review hashing requires exact bytes.");
  }
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function sha256Value(value) {
  return sha256Bytes(Buffer.from(canonicalize(value), "utf8"));
}

function configDigest(config) {
  return sha256Value(withoutField(config, "configSha256"));
}

function materialDigest(material) {
  return sha256Value(withoutField(material, "materialSha256"));
}

function receiptDigest(receipt) {
  return sha256Value(withoutField(receipt, "receiptSha256"));
}

export const independentKimiReviewDigests = Object.freeze({
  bytes: sha256Bytes,
  value: sha256Value,
  config: configDigest,
  material: materialDigest,
  receipt: receiptDigest,
  canonicalize,
});

function validSha(value) {
  return typeof value === "string" && SHA256.test(value);
}

function validCommit(value) {
  return typeof value === "string" && COMMIT.test(value);
}

function validPath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 512 &&
    SAFE_PATH.test(value)
  );
}

function validDate(value) {
  return (
    typeof value === "string" &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function decodeUtf8(bytes) {
  if (!(bytes instanceof Uint8Array)) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function parseJsonBytes(bytes) {
  try {
    return parseIndependentReviewJsonBytes(
      bytes,
      "Kimi JSON",
      MAX_JSON_BYTES,
    );
  } catch {
    return null;
  }
}

function containsCredential(value, apiKey) {
  const contains = (candidate) =>
    typeof candidate === "string" &&
    (candidate.includes(apiKey) ||
      candidate.includes(`Bearer ${apiKey}`));
  if (contains(value)) return true;
  if (Array.isArray(value)) {
    return value.some((item) => containsCredential(item, apiKey));
  }
  if (value !== null && typeof value === "object") {
    return Object.entries(value).some(
      ([key, item]) =>
        contains(key) || containsCredential(item, apiKey),
    );
  }
  return false;
}

function bytesContainCredential(bytes, apiKey) {
  const exactBytes = Buffer.from(bytes);
  return (
    exactBytes.includes(Buffer.from(apiKey, "utf8")) ||
    exactBytes.includes(Buffer.from(`Bearer ${apiKey}`, "utf8"))
  );
}

function unique(values) {
  return new Set(values).size === values.length;
}

function result(ok, status, reasonCodes, extra = {}) {
  return {
    ok,
    status,
    reasonCodes: [...new Set(reasonCodes)].sort(),
    ...extra,
  };
}

export async function validateMoonshotKimiConfig(config) {
  const reasonCodes = [];
  if (
    !exactKeys(config, CONFIG_KEYS) ||
    config.schemaVersion !== "moonshot-kimi-independent-review-config.v1" ||
    !/^mkirc_[a-z0-9][a-z0-9_-]{7,127}$/u.test(config.configId ?? "") ||
    config.lifecycle !== "CANDIDATE" ||
    config.reviewerProvider !== "moonshot" ||
    config.reviewerModel !== "kimi-k2.7-code" ||
    config.baseURL !== "https://api.moonshot.ai/v1" ||
    config.endpoint !== "/chat/completions" ||
    config.credentialEnv !== "MOONSHOT_API_KEY" ||
    config.keychainServiceRecommendation !== "kimi-p2-independent-review" ||
    config.keychainAccountRecommendation !== "p2-independent-review" ||
    !exactKeys(config.thinking, ["type"]) ||
    config.thinking.type !== "enabled" ||
    config.toolChoice !== "none" ||
    config.toolsOmitted !== true ||
    !exactKeys(config.responseFormat, ["type", "strict", "name"]) ||
    config.responseFormat.type !== "json_schema" ||
    config.responseFormat.strict !== true ||
    config.responseFormat.name !== "independent_model_review_output_v2" ||
    !Array.isArray(config.forbiddenRequestFields) ||
    canonicalize(config.forbiddenRequestFields) !==
      canonicalize(FORBIDDEN_REQUEST_FIELDS) ||
    !Number.isInteger(config.maxReviewMaterialUtf8Bytes) ||
    config.maxReviewMaterialUtf8Bytes < 64 * 1024 ||
    config.maxReviewMaterialUtf8Bytes !== 576 * 1024 ||
    config.maxRequestUtf8Bytes !== 768 * 1024 ||
    config.maxResponseUtf8Bytes !== 64 * 1024 ||
    config.maxReviewMaterialUtf8Bytes >= config.maxRequestUtf8Bytes ||
    config.contextBudgetBasis !==
      "TRANSPORT_DEFENSE_ONLY_NOT_CONTEXT_PROOF" ||
    config.fallbackPolicy !== "DISABLED_FAIL_CLOSED" ||
    !validSha(config.configSha256)
  ) {
    reasonCodes.push("KIMI_CONFIG_INVALID");
  }
  if (
    validSha(config?.configSha256) &&
    configDigest(config) !== config.configSha256
  ) {
    reasonCodes.push("KIMI_CONFIG_SELF_HASH_MISMATCH");
  }
  return {
    ok: reasonCodes.length === 0,
    reasonCodes: [...new Set(reasonCodes)].sort(),
  };
}

function validByteBinding(binding) {
  return (
    exactKeys(binding, BYTE_BINDING_KEYS) &&
    validPath(binding.path) &&
    Number.isInteger(binding.byteLength) &&
    binding.byteLength > 0 &&
    binding.byteLength <= MAX_JSON_BYTES &&
    validSha(binding.sha256)
  );
}

function validReviewBundleBinding(binding) {
  return (
    exactKeys(binding, REVIEW_BUNDLE_BINDING_KEYS) &&
    validPath(binding.path) &&
    Number.isInteger(binding.byteLength) &&
    binding.byteLength > 0 &&
    binding.byteLength <= MAX_JSON_BYTES &&
    validSha(binding.sha256) &&
    validSha(binding.bundleDigest)
  );
}

function materialV2SectionKey(section) {
  return `${section.kind}:${section.path}`;
}

function compareUtf8(left, right) {
  return Buffer.compare(
    Buffer.from(left, "utf8"),
    Buffer.from(right, "utf8"),
  );
}

function materialEnvelopeError(reasonCode, message) {
  const error = new TypeError(message);
  error.reasonCodes = [reasonCode];
  return error;
}

function materialV2ManifestReasonCodes(material, sectionBytes = null) {
  const reasonCodes = [];
  if (
    !exactKeys(material, MATERIAL_KEYS) ||
    material.schemaVersion !== "independent-review-material.v2" ||
    !/^irm_[a-z0-9][a-z0-9_-]{7,127}$/u.test(
      material.materialId ?? "",
    ) ||
    !exactKeys(material.source, [
      "baseCommit",
      "sourceCommit",
      "sourceTree",
      "patchSha256",
      "gitDiffCheckSha256",
    ]) ||
    !validCommit(material.source.baseCommit) ||
    !validCommit(material.source.sourceCommit) ||
    !validCommit(material.source.sourceTree) ||
    !validSha(material.source.patchSha256) ||
    !validSha(material.source.gitDiffCheckSha256) ||
    !exactKeys(material.bindings, [
      "reviewBundle",
      "reviewerPrompt",
      "canonicalOutputSchema",
      "canonicalReceiptSchema",
      "providerConfig",
    ]) ||
    !validReviewBundleBinding(material.bindings.reviewBundle) ||
    ![
      material.bindings.reviewerPrompt,
      material.bindings.canonicalOutputSchema,
      material.bindings.canonicalReceiptSchema,
      material.bindings.providerConfig,
    ].every(validByteBinding) ||
    !Array.isArray(material.sections) ||
    material.sections.length < 5 ||
    material.sections.length > 512 ||
    !validSha(material.sectionSetSha256) ||
    !Number.isInteger(material.totalSectionUtf8ByteLength) ||
    material.totalSectionUtf8ByteLength <= 0 ||
    material.totalSectionUtf8ByteLength > 1024 * 1024 ||
    material.contextBudgetUtf8Bytes !== 576 * 1024 ||
    !validSha(material.materialSha256)
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SHAPE_INVALID");
  }
  if (
    material?.source?.baseCommit !==
    kimiIndependentReviewFixedBaseCommit
  ) {
    reasonCodes.push(
      "KIMI_REVIEW_MATERIAL_FIXED_BASE_COMMIT_MISMATCH",
    );
  }

  const sectionKeys = [];
  for (const descriptor of material?.sections ?? []) {
    if (
      !exactKeys(descriptor, MATERIAL_V2_SECTION_KEYS) ||
      !MATERIAL_SECTION_KINDS.includes(descriptor.kind) ||
      !validPath(descriptor.path) ||
      descriptor.encoding !== "UTF-8" ||
      !Number.isInteger(descriptor.byteLength) ||
      descriptor.byteLength < 0 ||
      descriptor.byteLength > 1024 * 1024 ||
      !validSha(descriptor.sha256)
    ) {
      reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_INVALID");
      continue;
    }
    sectionKeys.push(materialV2SectionKey(descriptor));
  }
  if (!unique(sectionKeys)) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_DUPLICATED");
  }
  if (
    canonicalize(sectionKeys) !==
    canonicalize([...sectionKeys].sort(compareUtf8))
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_ORDER_MISMATCH");
  }
  if (
    Array.isArray(material?.sections) &&
    sha256Value(material.sections) !== material.sectionSetSha256
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_SET_MISMATCH");
  }
  if (
    validSha(material?.materialSha256) &&
    materialDigest(material) !== material.materialSha256
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SELF_HASH_MISMATCH");
  }

  if (sectionBytes !== null) {
    if (
      !Array.isArray(sectionBytes) ||
      sectionBytes.length !== (material?.sections?.length ?? -1)
    ) {
      reasonCodes.push(
        "KIMI_REVIEW_MATERIAL_SECTION_COUNT_MISMATCH",
      );
    } else {
      let totalSectionBytes = 0;
      for (let index = 0; index < sectionBytes.length; index += 1) {
        const bytes = sectionBytes[index];
        const descriptor = material.sections[index];
        if (
          !(bytes instanceof Uint8Array) ||
          decodeUtf8(bytes) === null
        ) {
          reasonCodes.push(
            "KIMI_REVIEW_MATERIAL_ENVELOPE_UTF8_INVALID",
          );
          continue;
        }
        totalSectionBytes += bytes.byteLength;
        if (
          descriptor?.byteLength !== bytes.byteLength ||
          descriptor?.sha256 !== sha256Bytes(bytes)
        ) {
          reasonCodes.push(
            "KIMI_REVIEW_MATERIAL_SECTION_BYTES_MISMATCH",
          );
        }
      }
      if (
        totalSectionBytes !==
        material?.totalSectionUtf8ByteLength
      ) {
        reasonCodes.push(
          "KIMI_REVIEW_MATERIAL_TOTAL_BYTES_MISMATCH",
        );
      }
    }
  }
  return [...new Set(reasonCodes)].sort();
}

function readEnvelopeLength(rawBytes, offset) {
  const newline = rawBytes.indexOf(0x0a, offset);
  if (newline === -1) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_TRUNCATED",
      "Independent review material envelope length is truncated.",
    );
  }
  const bytes = rawBytes.subarray(offset, newline);
  const text = bytes.toString("ascii");
  if (
    bytes.byteLength === 0 ||
    !/^(?:0|[1-9][0-9]*)$/u.test(text) ||
    !Buffer.from(text, "ascii").equals(bytes)
  ) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_LENGTH_INVALID",
      "Independent review material envelope length is invalid.",
    );
  }
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value > MAX_JSON_BYTES) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_LENGTH_INVALID",
      "Independent review material envelope length exceeds its bound.",
    );
  }
  return { value, nextOffset: newline + 1 };
}

export function encodeIndependentReviewMaterialEnvelope({
  material,
  sectionBytes,
}) {
  const reasonCodes = materialV2ManifestReasonCodes(
    material,
    sectionBytes,
  );
  if (reasonCodes.length > 0) {
    const error = new TypeError(
      "Independent review material v2 cannot be encoded.",
    );
    error.reasonCodes = reasonCodes;
    throw error;
  }
  const manifestBytes = Buffer.from(canonicalize(material), "utf8");
  const parts = [
    MATERIAL_V2_MAGIC,
    Buffer.from(`${manifestBytes.byteLength}\n`, "ascii"),
    manifestBytes,
  ];
  for (const bytes of sectionBytes) {
    parts.push(
      Buffer.from(`\n${bytes.byteLength}\n`, "ascii"),
      Buffer.from(bytes),
    );
  }
  return Buffer.concat(parts);
}

export function parseIndependentReviewMaterialEnvelope(
  rawMaterialBytes,
) {
  if (!(rawMaterialBytes instanceof Uint8Array)) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_BYTES_UNAVAILABLE",
      "Independent review material envelope bytes are unavailable.",
    );
  }
  if (
    rawMaterialBytes.byteLength === 0 ||
    rawMaterialBytes.byteLength > MAX_JSON_BYTES
  ) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_LENGTH_INVALID",
      "Independent review material envelope exceeds its parser bound.",
    );
  }
  const rawBytes = Buffer.from(rawMaterialBytes);
  if (
    rawBytes.byteLength < MATERIAL_V2_MAGIC.byteLength ||
    !rawBytes
      .subarray(0, MATERIAL_V2_MAGIC.byteLength)
      .equals(MATERIAL_V2_MAGIC)
  ) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_MAGIC_INVALID",
      "Independent review material envelope magic is invalid.",
    );
  }
  let offset = MATERIAL_V2_MAGIC.byteLength;
  const manifestLength = readEnvelopeLength(rawBytes, offset);
  if (manifestLength.value === 0) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_LENGTH_INVALID",
      "Independent review material envelope manifest is empty.",
    );
  }
  offset = manifestLength.nextOffset;
  const manifestEnd = offset + manifestLength.value;
  if (manifestEnd > rawBytes.byteLength) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_TRUNCATED",
      "Independent review material envelope manifest is truncated.",
    );
  }
  const manifestBytes = rawBytes.subarray(offset, manifestEnd);
  const manifestText = decodeUtf8(manifestBytes);
  if (manifestText === null) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_UTF8_INVALID",
      "Independent review material envelope manifest is not UTF-8.",
    );
  }
  let material;
  try {
    material = parseIndependentReviewJsonBytes(
      manifestBytes,
      "Independent review material v2 manifest",
      MAX_JSON_BYTES,
    );
  } catch {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_MANIFEST_INVALID",
      "Independent review material envelope manifest is not JSON.",
    );
  }
  if (
    material === null ||
    typeof material !== "object" ||
    Array.isArray(material) ||
    !Buffer.from(canonicalize(material), "utf8").equals(manifestBytes)
  ) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_MANIFEST_INVALID",
      "Independent review material envelope manifest is not canonical.",
    );
  }
  if (!Array.isArray(material.sections)) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_SECTION_COUNT_MISMATCH",
      "Independent review material envelope section descriptors are missing.",
    );
  }
  offset = manifestEnd;
  const sectionBytes = [];
  for (let index = 0; index < material.sections.length; index += 1) {
    if (rawBytes[offset] !== 0x0a) {
      throw materialEnvelopeError(
        "KIMI_REVIEW_MATERIAL_ENVELOPE_TRUNCATED",
        "Independent review material envelope section framing is truncated.",
      );
    }
    const sectionLength = readEnvelopeLength(rawBytes, offset + 1);
    offset = sectionLength.nextOffset;
    const sectionEnd = offset + sectionLength.value;
    if (sectionEnd > rawBytes.byteLength) {
      throw materialEnvelopeError(
        "KIMI_REVIEW_MATERIAL_ENVELOPE_TRUNCATED",
        "Independent review material envelope section is truncated.",
      );
    }
    const bytes = rawBytes.subarray(offset, sectionEnd);
    if (decodeUtf8(bytes) === null) {
      throw materialEnvelopeError(
        "KIMI_REVIEW_MATERIAL_ENVELOPE_UTF8_INVALID",
        "Independent review material envelope section is not UTF-8.",
      );
    }
    sectionBytes.push(Buffer.from(bytes));
    offset = sectionEnd;
  }
  if (offset !== rawBytes.byteLength) {
    throw materialEnvelopeError(
      "KIMI_REVIEW_MATERIAL_ENVELOPE_TRAILING_BYTES",
      "Independent review material envelope has trailing bytes.",
    );
  }
  const reasonCodes = materialV2ManifestReasonCodes(
    material,
    sectionBytes,
  );
  if (reasonCodes.length > 0) {
    const error = new TypeError(
      "Independent review material v2 envelope is invalid.",
    );
    error.reasonCodes = reasonCodes;
    throw error;
  }
  return { material, sectionBytes };
}

function sectionDescriptor(section) {
  const descriptor = structuredClone(section);
  delete descriptor.content;
  return descriptor;
}

function expectedSectionCoverage(expected, material) {
  const bundle = expected?.bundle;
  const governanceBindings = expected?.governanceSubjectBindings;
  if (
    !bundle ||
    !Array.isArray(bundle.reviewedPaths) ||
    !Array.isArray(bundle.sourceSubjects) ||
    !Array.isArray(bundle.specificationSubjects) ||
    !Array.isArray(bundle.testEvidenceSubjects) ||
    !Array.isArray(governanceBindings) ||
    governanceBindings.length !==
      kimiIndependentReviewMaterialGovernancePaths.length ||
    !validSha(expected?.modelVisibleProtocolSha256) ||
    !Number.isInteger(expected?.modelVisibleProtocolByteLength) ||
    expected.modelVisibleProtocolByteLength <= 0
  ) {
    return null;
  }
  const governance = new Map();
  for (const binding of governanceBindings) {
    if (
      !exactKeys(binding, BYTE_BINDING_KEYS) ||
      !kimiIndependentReviewMaterialGovernancePaths.includes(binding.path) ||
      !Number.isInteger(binding.byteLength) ||
      binding.byteLength <= 0 ||
      !validSha(binding.sha256) ||
      governance.has(binding.path)
    ) {
      return null;
    }
    governance.set(binding.path, binding);
  }
  if (
    canonicalize([...governance.keys()].sort()) !==
      canonicalize(kimiIndependentReviewMaterialGovernancePaths) ||
    canonicalize(bundle.reviewedPaths) !==
      canonicalize(bundle.sourceSubjects.map(({ path }) => path))
  ) {
    return null;
  }
  const sections = new Map();
  const add = (kind, path, sha256, byteLength = null) => {
    const key = `${kind}:${path}`;
    if (
      !validPath(path) ||
      !validSha(sha256) ||
      (byteLength !== null &&
        (!Number.isInteger(byteLength) || byteLength < 0))
    ) {
      return false;
    }
    const value = { sha256, byteLength };
    if (
      sections.has(key) &&
      canonicalize(sections.get(key)) !== canonicalize(value)
    ) {
      return false;
    }
    sections.set(key, value);
    return true;
  };
  if (
    !add(
      "REVIEW_BUNDLE",
      MATERIAL_PATHS.reviewBundle,
      expected.reviewBundleBytesSha256,
      expected.reviewBundleByteLength,
    ) ||
    !add("PATCH", MATERIAL_PATHS.patch, bundle.source?.diffSha256)
  ) {
    return null;
  }
  for (const subject of bundle.sourceSubjects) {
    const frozen = governance.get(subject.path);
    if (
      frozen &&
      (!add(
        "GOVERNANCE",
        subject.path,
        subject.blobSha256,
        frozen.byteLength,
      ) ||
        frozen.sha256 !== subject.blobSha256)
    ) {
      return null;
    }
  }
  for (const subject of bundle.specificationSubjects) {
    const frozen = governance.get(subject.path);
    if (
      !add(
        frozen ? "GOVERNANCE" : "SPECIFICATION",
        subject.path,
        subject.blobSha256,
        frozen?.byteLength ?? null,
      ) ||
      (frozen && frozen.sha256 !== subject.blobSha256)
    ) {
      return null;
    }
  }
  for (const subject of bundle.testEvidenceSubjects) {
    const resultSection = (material?.sections ?? []).find(
      (current) =>
        current.kind === "TEST_EVIDENCE" &&
        current.path === subject.outputRef &&
        current.sha256 === subject.outputSha256 &&
        current.byteLength === subject.outputByteLength,
    );
    const resultBytes =
      typeof resultSection?.content === "string"
        ? Buffer.from(resultSection.content, "utf8")
        : null;
    const result =
      resultBytes instanceof Uint8Array &&
      resultBytes.byteLength === subject.outputByteLength &&
      sha256Bytes(resultBytes) === subject.outputSha256
        ? parseJsonBytes(resultBytes)
        : null;
    if (
      !add(
        "TEST_EVIDENCE",
        subject.outputRef,
        subject.outputSha256,
        subject.outputByteLength,
      ) ||
      !result
    ) {
      return null;
    }
  }
  for (const binding of governance.values()) {
    if (
      !add(
        "GOVERNANCE",
        binding.path,
        binding.sha256,
        binding.byteLength,
      )
    ) {
      return null;
    }
  }
  if (
    !add(
      "GOVERNANCE",
      MATERIAL_PATHS.modelVisibleProtocol,
      expected.modelVisibleProtocolSha256,
      expected.modelVisibleProtocolByteLength,
    )
  ) {
    return null;
  }
  return sections;
}

async function validateIndependentReviewMaterialV2({
  material,
  rawMaterialBytes,
  expected,
}) {
  const reasonCodes = materialV2ManifestReasonCodes(material);
  const expectedSource =
    expected?.source ??
    (expected?.bundle
      ? {
          baseCommit: expected.bundle.source?.baseCommit,
          sourceCommit: expected.sourceCommit,
          sourceTree: expected.sourceTree,
          patchSha256: expected.bundle.source?.diffSha256,
          gitDiffCheckSha256:
            expected.bundle.source?.gitDiffCheck?.resultSha256,
        }
      : null);
  const expectedBindings =
    expected?.bindings ??
    (expected?.bundle
      ? {
          reviewBundle: {
            path: MATERIAL_PATHS.reviewBundle,
            byteLength: expected.reviewBundleByteLength,
            sha256: expected.reviewBundleBytesSha256,
            bundleDigest: expected.reviewBundleDigest,
          },
          reviewerPrompt: {
            path: MATERIAL_PATHS.prompt,
            byteLength: expected.reviewerPromptByteLength,
            sha256: expected.reviewerPromptSha256,
          },
          canonicalOutputSchema: {
            path: MATERIAL_PATHS.outputSchema,
            byteLength: expected.canonicalOutputSchemaByteLength,
            sha256: expected.canonicalOutputSchemaSha256,
          },
          canonicalReceiptSchema: {
            path: MATERIAL_PATHS.receiptSchema,
            byteLength: expected.canonicalReceiptSchemaByteLength,
            sha256: expected.canonicalReceiptSchemaSha256,
          },
          providerConfig: {
            path: MATERIAL_PATHS.config,
            byteLength: expected.providerConfigByteLength,
            sha256: expected.providerConfigSha256,
          },
        }
      : null);
  let parsed = null;
  try {
    parsed = parseIndependentReviewMaterialEnvelope(rawMaterialBytes);
  } catch (error) {
    reasonCodes.push(
      ...(Array.isArray(error?.reasonCodes)
        ? error.reasonCodes
        : ["KIMI_REVIEW_MATERIAL_ENVELOPE_INVALID"]),
    );
  }
  if (
    parsed &&
    !sameCanonical(parsed.material, material)
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_BYTES_MISMATCH");
  }
  if (
    rawMaterialBytes instanceof Uint8Array &&
    rawMaterialBytes.byteLength > material?.contextBudgetUtf8Bytes
  ) {
    reasonCodes.push(
      "KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_EXCEEDED",
    );
  }
  if (
    !expected ||
    !sameCanonical(material?.source, expectedSource) ||
    !sameCanonical(material?.bindings, expectedBindings)
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_BINDING_MISMATCH");
  }
  if (
    !Array.isArray(expected?.sectionDescriptors) ||
    !sameCanonical(material?.sections, expected.sectionDescriptors)
  ) {
    reasonCodes.push(
      "KIMI_REVIEW_MATERIAL_SECTION_COVERAGE_MISMATCH",
    );
  }
  if (
    material?.contextBudgetUtf8Bytes !==
    expected?.contextBudgetUtf8Bytes
  ) {
    reasonCodes.push(
      "KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_MISMATCH",
    );
  }
  return {
    ok: reasonCodes.length === 0,
    reasonCodes: [...new Set(reasonCodes)].sort(),
  };
}

export async function validateIndependentReviewMaterial({
  material,
  rawMaterialBytes,
  expected,
}) {
  if (material?.schemaVersion === "independent-review-material.v2") {
    return validateIndependentReviewMaterialV2({
      material,
      rawMaterialBytes,
      expected,
    });
  }
  const reasonCodes = [];
  if (
    !exactKeys(material, MATERIAL_KEYS) ||
    material.schemaVersion !== "independent-review-material.v1" ||
    !/^irm_[a-z0-9][a-z0-9_-]{7,127}$/u.test(material.materialId ?? "") ||
    !exactKeys(material.source, [
      "baseCommit",
      "sourceCommit",
      "sourceTree",
      "patchSha256",
      "gitDiffCheckSha256",
    ]) ||
    !validCommit(material.source.baseCommit) ||
    !validCommit(material.source.sourceCommit) ||
    !validCommit(material.source.sourceTree) ||
    !validSha(material.source.patchSha256) ||
    !validSha(material.source.gitDiffCheckSha256) ||
    !exactKeys(material.bindings, [
      "reviewBundle",
      "reviewerPrompt",
      "canonicalOutputSchema",
      "canonicalReceiptSchema",
      "providerConfig",
    ]) ||
    !validReviewBundleBinding(material.bindings.reviewBundle) ||
    ![
      material.bindings.reviewerPrompt,
      material.bindings.canonicalOutputSchema,
      material.bindings.canonicalReceiptSchema,
      material.bindings.providerConfig,
    ].every(validByteBinding) ||
    !Array.isArray(material.sections) ||
    material.sections.length < 5 ||
    material.sections.length > 256 ||
    !validSha(material.sectionSetSha256) ||
    !Number.isInteger(material.totalSectionUtf8ByteLength) ||
    material.totalSectionUtf8ByteLength <= 0 ||
    !Number.isInteger(material.contextBudgetUtf8Bytes) ||
    material.contextBudgetUtf8Bytes <= 0 ||
    !validSha(material.materialSha256)
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SHAPE_INVALID");
  }
  if (!(rawMaterialBytes instanceof Uint8Array)) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_BYTES_UNAVAILABLE");
  } else {
    const parsed = parseJsonBytes(rawMaterialBytes);
    if (
      parsed === null ||
      canonicalize(parsed) !== canonicalize(material)
    ) {
      reasonCodes.push("KIMI_REVIEW_MATERIAL_BYTES_MISMATCH");
    }
    if (rawMaterialBytes.byteLength > material?.contextBudgetUtf8Bytes) {
      reasonCodes.push("KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_EXCEEDED");
    }
  }
  let totalBytes = 0;
  const sectionKeys = [];
  for (const section of material?.sections ?? []) {
    if (
      !exactKeys(section, SECTION_KEYS) ||
      ![
        "GOVERNANCE",
        "PATCH",
        "REVIEW_BUNDLE",
        "SOURCE",
        "SPECIFICATION",
        "TEST_EVIDENCE",
      ].includes(section.kind) ||
      !validPath(section.path) ||
      section.encoding !== "UTF-8" ||
      !Number.isInteger(section.byteLength) ||
      section.byteLength < 0 ||
      !validSha(section.sha256) ||
      typeof section.content !== "string"
    ) {
      reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_INVALID");
      continue;
    }
    const bytes = Buffer.from(section.content, "utf8");
    totalBytes += bytes.byteLength;
    sectionKeys.push(`${section.kind}:${section.path}`);
    if (
      bytes.byteLength !== section.byteLength ||
      sha256Bytes(bytes) !== section.sha256
    ) {
      reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_BYTES_MISMATCH");
    }
  }
  if (!unique(sectionKeys)) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_DUPLICATED");
  }
  if (totalBytes !== material?.totalSectionUtf8ByteLength) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_TOTAL_BYTES_MISMATCH");
  }
  if (
    Array.isArray(material?.sections) &&
    sha256Value(material.sections.map(sectionDescriptor)) !==
      material.sectionSetSha256
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_SET_MISMATCH");
  }
  if (
    validSha(material?.materialSha256) &&
    materialDigest(material) !== material.materialSha256
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SELF_HASH_MISMATCH");
  }
  for (const [bindingName, sectionKind] of [
    ["reviewBundle", "REVIEW_BUNDLE"],
    ["canonicalOutputSchema", "GOVERNANCE"],
    ["canonicalReceiptSchema", "GOVERNANCE"],
  ]) {
    const binding = material?.bindings?.[bindingName];
    const matching = (material?.sections ?? []).filter(
      (section) =>
        section.kind === sectionKind &&
        section.path === binding?.path &&
        section.byteLength === binding?.byteLength &&
        section.sha256 === binding?.sha256,
    );
    if (matching.length !== 1) {
      reasonCodes.push("KIMI_REVIEW_MATERIAL_BINDING_UNRESOLVED");
    }
  }
  if (
    !expected ||
    !expected.bundle ||
    material?.source?.baseCommit !== expected.bundle.source?.baseCommit ||
    material?.source?.sourceCommit !== expected.sourceCommit ||
    material?.source?.sourceTree !== expected.sourceTree ||
    material?.source?.patchSha256 !== expected.bundle.source?.diffSha256 ||
    material?.source?.gitDiffCheckSha256 !==
      expected.bundle.source?.gitDiffCheck?.resultSha256 ||
    material?.bindings?.reviewBundle?.path !== MATERIAL_PATHS.reviewBundle ||
    material?.bindings?.reviewBundle?.byteLength !==
      expected.reviewBundleByteLength ||
    material?.bindings?.reviewBundle?.sha256 !==
      expected.reviewBundleBytesSha256 ||
    material?.bindings?.reviewBundle?.bundleDigest !==
      expected.reviewBundleDigest ||
    material?.bindings?.reviewerPrompt?.path !== MATERIAL_PATHS.prompt ||
    material?.bindings?.reviewerPrompt?.byteLength !==
      expected.reviewerPromptByteLength ||
    material?.bindings?.reviewerPrompt?.sha256 !==
      expected.reviewerPromptSha256 ||
    material?.bindings?.canonicalOutputSchema?.path !==
      MATERIAL_PATHS.outputSchema ||
    material?.bindings?.canonicalOutputSchema?.byteLength !==
      expected.canonicalOutputSchemaByteLength ||
    material?.bindings?.canonicalOutputSchema?.sha256 !==
      expected.canonicalOutputSchemaSha256 ||
    material?.bindings?.canonicalReceiptSchema?.path !==
      MATERIAL_PATHS.receiptSchema ||
    material?.bindings?.canonicalReceiptSchema?.byteLength !==
      expected.canonicalReceiptSchemaByteLength ||
    material?.bindings?.canonicalReceiptSchema?.sha256 !==
      expected.canonicalReceiptSchemaSha256 ||
    material?.bindings?.providerConfig?.path !== MATERIAL_PATHS.config ||
    material?.bindings?.providerConfig?.byteLength !==
      expected.providerConfigByteLength ||
    material?.bindings?.providerConfig?.sha256 !==
      expected.providerConfigSha256
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_BINDING_MISMATCH");
  }
  const requiredSections = expectedSectionCoverage(expected, material);
  const actualSectionKeys = (material?.sections ?? []).map(
    ({ kind, path }) => `${kind}:${path}`,
  );
  const requiredSectionKeys = requiredSections
    ? [...requiredSections.keys()].sort()
    : [];
  if (
    !requiredSections ||
    canonicalize(actualSectionKeys) !== canonicalize(requiredSectionKeys)
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_COVERAGE_MISMATCH");
  } else {
    for (const section of material.sections) {
      const required = requiredSections.get(
        `${section.kind}:${section.path}`,
      );
      if (
        section.sha256 !== required.sha256 ||
        (required.byteLength !== null &&
          section.byteLength !== required.byteLength)
      ) {
        reasonCodes.push("KIMI_REVIEW_MATERIAL_SECTION_COVERAGE_MISMATCH");
      }
    }
  }
  if (
    material?.contextBudgetUtf8Bytes !== undefined &&
    expected?.contextBudgetUtf8Bytes !== undefined &&
    material.contextBudgetUtf8Bytes !== expected.contextBudgetUtf8Bytes
  ) {
    reasonCodes.push("KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_MISMATCH");
  }
  return {
    ok: reasonCodes.length === 0,
    reasonCodes: [...new Set(reasonCodes)].sort(),
  };
}

function validRequestEnvelope(request, config) {
  if (
    !exactKeys(request, REQUEST_KEYS) ||
    request.model !== config.reviewerModel ||
    !Array.isArray(request.messages) ||
    request.messages.length !== 2 ||
    !exactKeys(request.messages[0], ["role", "content"]) ||
    request.messages[0].role !== "system" ||
    typeof request.messages[0].content !== "string" ||
    !exactKeys(request.messages[1], ["role", "content"]) ||
    request.messages[1].role !== "user" ||
    typeof request.messages[1].content !== "string" ||
    !exactKeys(request.thinking, ["type"]) ||
    request.thinking.type !== "enabled" ||
    request.tool_choice !== "none" ||
    Object.hasOwn(request, "tools") ||
    !exactKeys(request.response_format, ["type", "json_schema"]) ||
    request.response_format.type !== "json_schema" ||
    !exactKeys(request.response_format.json_schema, [
      "name",
      "strict",
      "schema",
    ]) ||
    request.response_format.json_schema.name !==
      config.responseFormat.name ||
    request.response_format.json_schema.strict !== true ||
    request.response_format.json_schema.schema === null ||
    typeof request.response_format.json_schema.schema !== "object" ||
    Array.isArray(request.response_format.json_schema.schema) ||
    FORBIDDEN_REQUEST_FIELDS.some((field) => Object.hasOwn(request, field))
  ) {
    return false;
  }
  return true;
}

function fixedBoundRequest(
  config,
  { promptBytes, materialBytes, outputSchemaBytes },
) {
  const prompt = decodeUtf8(promptBytes);
  const material = decodeUtf8(materialBytes);
  const outputSchema = parseJsonBytes(outputSchemaBytes);
  if (
    prompt === null ||
    material === null ||
    outputSchema === null ||
    Array.isArray(outputSchema)
  ) {
    return null;
  }
  return {
    model: config.reviewerModel,
    messages: [
      { role: "system", content: prompt },
      { role: "user", content: material },
    ],
    thinking: { type: "enabled" },
    tool_choice: "none",
    response_format: {
      type: "json_schema",
      json_schema: {
        name: config.responseFormat.name,
        strict: true,
        schema: outputSchema,
      },
    },
  };
}

function validBoundRequest(
  request,
  config,
  { requestBytes, promptBytes, materialBytes, outputSchemaBytes },
) {
  const expected = fixedBoundRequest(config, {
    promptBytes,
    materialBytes,
    outputSchemaBytes,
  });
  const expectedBytes =
    expected === null
      ? null
      : Buffer.from(JSON.stringify(expected), "utf8");
  return (
    validRequestEnvelope(request, config) &&
    expected !== null &&
    requestBytes instanceof Uint8Array &&
    requestBytes.byteLength === expectedBytes.byteLength &&
    Buffer.from(requestBytes).equals(expectedBytes)
  );
}

export async function buildKimiIndependentReviewRequest({
  config,
  configBytes,
  bundle,
  reviewBundleBytes,
  promptBytes,
  materialBytes,
  outputSchemaBytes,
  receiptSchemaBytes,
  materialSchemaBytes,
  materialSectionDescriptors,
  governanceSubjectBindings,
}) {
  const configValidation = await validateMoonshotKimiConfig(config);
  if (
    !configValidation.ok ||
    !(configBytes instanceof Uint8Array) ||
    !(reviewBundleBytes instanceof Uint8Array) ||
    !(receiptSchemaBytes instanceof Uint8Array) ||
    !(materialSchemaBytes instanceof Uint8Array) ||
    !Array.isArray(materialSectionDescriptors)
  ) {
    throw new TypeError("Moonshot Kimi configuration is invalid.");
  }
  const prompt = decodeUtf8(promptBytes);
  const materialText = decodeUtf8(materialBytes);
  const { material } =
    parseIndependentReviewMaterialEnvelope(materialBytes);
  const outputSchema = parseJsonBytes(outputSchemaBytes);
  const receiptSchema = parseJsonBytes(receiptSchemaBytes);
  const materialSchema = parseJsonBytes(materialSchemaBytes);
  const exactConfig = parseJsonBytes(configBytes);
  const exactBundle = parseJsonBytes(reviewBundleBytes);
  if (
    prompt === null ||
    prompt.length === 0 ||
    materialText === null ||
    outputSchema === null ||
    receiptSchema === null ||
    materialSchema === null ||
    exactConfig === null ||
    exactBundle === null ||
    Array.isArray(outputSchema) ||
    Array.isArray(receiptSchema) ||
    Array.isArray(materialSchema) ||
    canonicalize(exactConfig) !== canonicalize(config) ||
    canonicalize(exactBundle) !== canonicalize(bundle)
  ) {
    throw new TypeError("Kimi review request inputs are invalid UTF-8 JSON.");
  }
  const materialSchemaValidation =
    await validateIndependentReviewSchemaInstance({
      schemaBytes: materialSchemaBytes,
      expectedSchemaSha256: sha256Bytes(materialSchemaBytes),
      instance: material,
      label: "Kimi independent review Material Schema",
    });
  if (!materialSchemaValidation.ok) {
    const error = new TypeError(
      "Independent review material Schema is invalid.",
    );
    error.reasonCodes = materialSchemaValidation.reasonCodes;
    throw error;
  }
  const materialValidation = await validateIndependentReviewMaterial({
    material,
    rawMaterialBytes: materialBytes,
    expected: {
      bundle,
      governanceSubjectBindings,
      sectionDescriptors: materialSectionDescriptors,
      sourceCommit: bundle?.source?.sourceCommit,
      sourceTree: bundle?.source?.tree,
      reviewBundleBytesSha256: sha256Bytes(reviewBundleBytes),
      reviewBundleByteLength: reviewBundleBytes.byteLength,
      reviewBundleDigest: bundle?.bundleSha256,
      reviewerPromptSha256: sha256Bytes(promptBytes),
      reviewerPromptByteLength: promptBytes.byteLength,
      canonicalOutputSchemaSha256: sha256Bytes(outputSchemaBytes),
      canonicalOutputSchemaByteLength: outputSchemaBytes.byteLength,
      canonicalReceiptSchemaSha256: sha256Bytes(receiptSchemaBytes),
      canonicalReceiptSchemaByteLength: receiptSchemaBytes.byteLength,
      providerConfigSha256: sha256Bytes(configBytes),
      providerConfigByteLength: configBytes.byteLength,
      modelVisibleProtocolSha256: sha256Bytes(
        createKimiModelVisibleProtocolBytes(config),
      ),
      modelVisibleProtocolByteLength:
        createKimiModelVisibleProtocolBytes(config).byteLength,
      contextBudgetUtf8Bytes: config.maxReviewMaterialUtf8Bytes,
    },
  });
  if (!materialValidation.ok) {
    const error = new TypeError("Independent review material is invalid.");
    error.reasonCodes = materialValidation.reasonCodes;
    throw error;
  }
  const request = fixedBoundRequest(config, {
    promptBytes,
    materialBytes,
    outputSchemaBytes,
  });
  const requestBytes =
    request === null
      ? null
      : Buffer.from(JSON.stringify(request), "utf8");
  if (
    !validBoundRequest(request, config, {
      requestBytes,
      promptBytes,
      materialBytes,
      outputSchemaBytes,
    })
  ) {
    throw new TypeError("Kimi review request violates the fixed protocol.");
  }
  if (requestBytes.byteLength > config.maxRequestUtf8Bytes) {
    const error = new TypeError(
      "Kimi review request exceeds the fixed UTF-8 budget.",
    );
    error.reasonCodes = ["KIMI_REVIEW_REQUEST_CONTEXT_BUDGET_EXCEEDED"];
    throw error;
  }
  return {
    requestBytes,
    requestSha256: sha256Bytes(requestBytes),
    toolsAbsent: true,
    toolChoiceNone: true,
    strictSchema: true,
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

async function readBoundedResponseBytes({
  response,
  maxBytes,
  timeoutPromise,
  controller,
}) {
  const reader = response?.body?.getReader?.();
  if (!reader) {
    const error = new TypeError("Kimi response body is not stream-readable.");
    error.code = "KIMI_RESPONSE_BYTES_UNAVAILABLE";
    throw error;
  }
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const result = await Promise.race([reader.read(), timeoutPromise]);
      if (result.done) break;
      if (!(result.value instanceof Uint8Array)) {
        const error = new TypeError(
          "Kimi response stream returned non-byte content.",
        );
        error.code = "KIMI_RESPONSE_BYTES_UNAVAILABLE";
        throw error;
      }
      total += result.value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("Kimi response byte limit exceeded.");
        controller.abort();
        const error = new RangeError("Kimi response byte limit exceeded.");
        error.code = "KIMI_RESPONSE_BYTES_LIMIT_EXCEEDED";
        throw error;
      }
      chunks.push(Buffer.from(result.value));
    }
  } finally {
    reader.releaseLock?.();
  }
  return Buffer.concat(chunks, total);
}

export async function executeKimiIndependentReview({
  config,
  requestBytes,
  promptBytes,
  materialBytes,
  outputSchemaBytes,
  apiKey,
  fetchImpl,
  timeoutMs = 120_000,
}) {
  const configValidation = await validateMoonshotKimiConfig(config);
  const request = parseJsonBytes(requestBytes);
  if (!configValidation.ok || !validRequestEnvelope(request, config)) {
    return transportFailure(
      [...configValidation.reasonCodes, "KIMI_REQUEST_INVALID"],
      0,
    );
  }
  if (typeof apiKey !== "string" || apiKey.length < 16) {
    return {
      ok: false,
      status: "BLOCKED",
      reasonCodes: ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
      networkAttemptCount: 0,
    };
  }
  if (
    bytesContainCredential(requestBytes, apiKey) ||
    containsCredential(request, apiKey)
  ) {
    return transportFailure(["KIMI_REQUEST_CREDENTIAL_EXPOSED"], 0);
  }
  if (
    !validBoundRequest(request, config, {
      requestBytes,
      promptBytes,
      materialBytes,
      outputSchemaBytes,
    })
  ) {
    return transportFailure(["KIMI_REQUEST_BINDING_MISMATCH"], 0);
  }
  if (
    typeof fetchImpl !== "function" ||
    !(outputSchemaBytes instanceof Uint8Array) ||
    !Number.isInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 10 * 60_000
  ) {
    return transportFailure(["KIMI_TRANSPORT_CONFIGURATION_INVALID"], 0);
  }
  const controller = new AbortController();
  let timeout;
  const timeoutPromise = new Promise((_, reject) => {
    timeout = setTimeout(() => {
      controller.abort();
      reject(new DOMException("Kimi transport timed out.", "AbortError"));
    }, timeoutMs);
  });
  const requestUrl = `${config.baseURL}${config.endpoint}`;
  let response;
  let responseBytes;
  try {
    response = await Promise.race([
      fetchImpl(requestUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${apiKey}`,
        },
        body: requestBytes,
        redirect: "error",
        signal: controller.signal,
      }),
      timeoutPromise,
    ]);
    if (
      response?.redirected !== false ||
      response?.url !== requestUrl
    ) {
      return transportFailure(["KIMI_RESPONSE_ENDPOINT_MISMATCH"], 1);
    }
    if ([401, 402, 403, 429].includes(response.status)) {
      return transportFailure(
        ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
        1,
      );
    }
    const contentType = response.headers?.get?.("content-type") ?? "";
    const contentLengthHeader =
      response.headers?.get?.("content-length") ?? null;
    const contentLength =
      contentLengthHeader === null ? null : Number(contentLengthHeader);
    if (
      response.status !== 200 ||
      !/^application\/json(?:;\s*charset=utf-8)?$/iu.test(contentType) ||
      (contentLengthHeader !== null &&
        (!/^(?:0|[1-9][0-9]*)$/u.test(contentLengthHeader) ||
          !Number.isSafeInteger(contentLength) ||
          contentLength < 0))
    ) {
      return transportFailure(["KIMI_RESPONSE_HTTP_INVALID"], 1);
    }
    if (
      contentLength !== null &&
      contentLength > config.maxResponseUtf8Bytes
    ) {
      controller.abort();
      try {
        await response.body?.cancel?.(
          "Kimi response byte limit exceeded.",
        );
      } catch {
        // The transport is already aborted; cancellation is best effort.
      }
      return transportFailure(
        ["KIMI_RESPONSE_BYTES_LIMIT_EXCEEDED"],
        1,
      );
    }
    responseBytes = await readBoundedResponseBytes({
      response,
      maxBytes: config.maxResponseUtf8Bytes,
      timeoutPromise,
      controller,
    });
  } catch (error) {
    return transportFailure(
      [
        error?.code === "KIMI_RESPONSE_BYTES_LIMIT_EXCEEDED"
          ? error.code
          : error?.code === "KIMI_RESPONSE_BYTES_UNAVAILABLE"
            ? error.code
            : error?.name === "AbortError"
              ? "KIMI_TRANSPORT_TIMEOUT"
              : "KIMI_TRANSPORT_NETWORK_FAILED",
      ],
      1,
    );
  } finally {
    clearTimeout(timeout);
  }
  if (
    responseBytes.byteLength === 0 ||
    responseBytes.byteLength > config.maxResponseUtf8Bytes
  ) {
    return transportFailure(["KIMI_RESPONSE_BYTES_UNAVAILABLE"], 1);
  }
  const rawContentType =
    response.headers?.get?.("content-type") ?? "";
  const contentType = /;\s*charset=utf-8$/iu.test(rawContentType)
    ? "application/json; charset=utf-8"
    : "application/json";
  const body = parseJsonBytes(responseBytes);
  if (
    bytesContainCredential(responseBytes, apiKey) ||
    containsCredential(body, apiKey)
  ) {
    return transportFailure(["KIMI_RESPONSE_CREDENTIAL_ECHOED"], 1);
  }
  const choice = body?.choices?.[0];
  const message = choice?.message;
  if (
    body === null ||
    typeof body.id !== "string" ||
    body.id.length < 8 ||
    body.object !== "chat.completion" ||
    body.model !== config.reviewerModel ||
    !Array.isArray(body.choices) ||
    body.choices.length !== 1 ||
    choice?.index !== 0 ||
    choice?.finish_reason !== "stop" ||
    message?.role !== "assistant" ||
    Object.hasOwn(message ?? {}, "tool_calls") ||
    Object.hasOwn(message ?? {}, "function_call") ||
    typeof message?.content !== "string" ||
    message.content.length === 0
  ) {
    return transportFailure(["KIMI_RESPONSE_PROTOCOL_INVALID"], 1);
  }
  const contentBytes = Buffer.from(
    message.content,
    "utf8",
  );
  const exactOutputSchema = parseJsonBytes(outputSchemaBytes);
  if (
    exactOutputSchema === null ||
    canonicalize(exactOutputSchema) !==
      canonicalize(request.response_format.json_schema.schema)
  ) {
    return transportFailure(["KIMI_RESPONSE_SCHEMA_INVALID"], 1);
  }
  const outputValidation =
    await validateIndependentModelReviewOutputArtifact({
      rawModelOutput: contentBytes,
      outputSchemaBytes,
      expectedOutputSchemaSha256: sha256Bytes(outputSchemaBytes),
    });
  if (!outputValidation.ok) {
    return transportFailure(
      [
        "KIMI_RESPONSE_SCHEMA_INVALID",
        ...outputValidation.reasonCodes,
      ],
      1,
    );
  }
  return {
    ok: true,
    status: "CAPTURED",
    reasonCodes: [],
    networkAttemptCount: 1,
    responseId: body.id,
    actualReturnedModel: body.model,
    httpStatus: response.status,
    contentType,
    responseBytes,
    contentBytes,
    rawResponseSha256: sha256Bytes(responseBytes),
    rawContentSha256: sha256Bytes(contentBytes),
  };
}

function validSnapshot(value) {
  return (
    exactKeys(value, SNAPSHOT_KEYS) &&
    validCommit(value.head) &&
    validCommit(value.tree) &&
    validSha(value.worktreeStatusSha256) &&
    validSha(value.worktreeContentManifestSha256) &&
    Number.isInteger(value.worktreePathCount) &&
    value.worktreePathCount >= 0 &&
    value.worktreePathCount <= 100_000 &&
    validSha(value.protectedPathSetSha256) &&
    validSha(value.protectedFilesDigest) &&
    validSha(value.ignoredExclusionPolicySha256) &&
    Number.isInteger(value.ignoredExcludedPathCount) &&
    value.ignoredExcludedPathCount >= 0 &&
    value.ignoredExcludedPathCount <= 100_000
  );
}

function byteArtifact(path, bytes) {
  return {
    path,
    encoding: "UTF-8",
    byteLength: bytes.byteLength,
    sha256: sha256Bytes(bytes),
  };
}

function transportEvidenceExpectedBindings({
  config,
  bundle,
  promptBytes,
  outputSchemaBytes,
  receiptSchemaBytes,
  actualReturnedModel,
}) {
  return {
    provider: config.reviewerProvider,
    requestedModel: config.reviewerModel,
    actualReturnedModel,
    baseURL: config.baseURL,
    endpoint: config.endpoint,
    sourceCommit: bundle.source.sourceCommit,
    sourceTree: bundle.source.tree,
    reviewBundleSha256: bundle.bundleSha256,
    reviewerPromptSha256: sha256Bytes(promptBytes),
    receiptSchemaSha256: sha256Bytes(receiptSchemaBytes),
    outputSchemaPath: MATERIAL_PATHS.outputSchema,
    outputSchemaSha256: sha256Bytes(outputSchemaBytes),
    schemaValidatorVersion: independentReviewSchemaValidatorVersion(),
    semanticValidatorVersion: TRANSPORT_EVIDENCE_VALIDATOR_VERSION,
  };
}

function transportEvidenceResolver({
  evidence,
  requestBytes,
  responseBytes,
  contentBytes,
  outputSchemaBytes,
}) {
  const artifacts = new Map([
    [evidence.request.path, requestBytes],
    [evidence.response.path, responseBytes],
    [evidence.content.path, contentBytes],
    [evidence.bindings.outputSchemaPath, outputSchemaBytes],
  ]);
  return async (path) => {
    const bytes = artifacts.get(path);
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("Transport evidence bytes are unavailable.");
    }
    return bytes;
  };
}

export async function createKimiIndependentReviewTransportEvidence({
  evidenceId,
  config,
  bundle,
  promptBytes,
  outputSchemaBytes,
  receiptSchemaBytes,
  requestBytes,
  responseBytes,
  contentBytes,
  transportEvidenceSchemaBytes,
  actualReturnedModel,
  httpStatus,
  contentType,
  networkAttemptCount,
  startedAt,
  finishedAt,
  artifactPaths,
}) {
  const evidence = {
    schemaVersion: "independent-review-transport-evidence.v1",
    evidenceId,
    provider: config.reviewerProvider,
    requestedModel: config.reviewerModel,
    actualReturnedModel,
    baseURL: config.baseURL,
    endpoint: config.endpoint,
    source: {
      sourceCommit: bundle.source.sourceCommit,
      sourceTree: bundle.source.tree,
    },
    bindings: {
      reviewBundleSha256: bundle.bundleSha256,
      reviewerPromptSha256: sha256Bytes(promptBytes),
      receiptSchemaSha256: sha256Bytes(receiptSchemaBytes),
      outputSchemaPath: MATERIAL_PATHS.outputSchema,
      outputSchemaSha256: sha256Bytes(outputSchemaBytes),
    },
    request: byteArtifact(artifactPaths.request, requestBytes),
    response: {
      ...byteArtifact(artifactPaths.response, responseBytes),
      httpStatus,
      contentType,
    },
    content: byteArtifact(artifactPaths.content, contentBytes),
    protocol: {
      toolsAbsent: true,
      toolChoiceNone: true,
      strictSchema: true,
      networkAttemptCount,
      choiceCount: 1,
      finishReason: "stop",
    },
    validators: {
      schemaValidatorVersion: independentReviewSchemaValidatorVersion(),
      semanticValidatorVersion: TRANSPORT_EVIDENCE_VALIDATOR_VERSION,
    },
    startedAt,
    finishedAt,
    transportEvidenceSha256: TRANSPORT_EVIDENCE_SHA_PLACEHOLDER,
  };
  evidence.transportEvidenceSha256 =
    independentReviewTransportEvidenceDigests.evidence(evidence);
  const validation = await validateIndependentReviewTransportEvidence({
    evidence,
    expectedBindings: transportEvidenceExpectedBindings({
      config,
      bundle,
      promptBytes,
      outputSchemaBytes,
      receiptSchemaBytes,
      actualReturnedModel,
    }),
    evidenceResolver: transportEvidenceResolver({
      evidence,
      requestBytes,
      responseBytes,
      contentBytes,
      outputSchemaBytes,
    }),
  });
  if (!validation.valid) {
    const error = new TypeError(
      "Kimi independent review transport evidence is invalid.",
    );
    error.reasonCodes = validation.reasonCodes;
    throw error;
  }
  const schemaValidation =
    await validateIndependentReviewSchemaInstance({
      schemaBytes: transportEvidenceSchemaBytes,
      expectedSchemaSha256: sha256Bytes(
        transportEvidenceSchemaBytes,
      ),
      instance: evidence,
      label: "Kimi transport evidence Schema",
    });
  if (!schemaValidation.ok) {
    const error = new TypeError(
      "Kimi independent review transport evidence Schema is invalid.",
    );
    error.reasonCodes = schemaValidation.reasonCodes;
    throw error;
  }
  return evidence;
}

async function validateBoundKimiTransportEvidence({
  evidence,
  evidenceBytes,
  evidenceSchemaBytes,
  config,
  bundle,
  promptBytes,
  outputSchemaBytes,
  receiptSchemaBytes,
  requestBytes,
  responseBytes,
  contentBytes,
  actualReturnedModel,
}) {
  const reasonCodes = [];
  let parsedEvidence = null;
  try {
    parsedEvidence = parseIndependentReviewJsonBytes(
      evidenceBytes,
      "Kimi transport evidence",
      1024 * 1024,
    );
  } catch {
    reasonCodes.push("KIMI_TRANSPORT_EVIDENCE_BYTES_INVALID");
  }
  let evidenceBytesMatch = false;
  try {
    evidenceBytesMatch =
      parsedEvidence !== null &&
      canonicalize(parsedEvidence) === canonicalize(evidence);
  } catch {
    evidenceBytesMatch = false;
  }
  if (!evidenceBytesMatch) {
    reasonCodes.push("KIMI_TRANSPORT_EVIDENCE_BYTES_MISMATCH");
  }
  const schemaValidation =
    evidenceSchemaBytes instanceof Uint8Array
      ? await validateIndependentReviewSchemaInstance({
          schemaBytes: evidenceSchemaBytes,
          expectedSchemaSha256: sha256Bytes(evidenceSchemaBytes),
          instance: evidence,
          label: "Kimi transport evidence Schema",
        })
      : {
          ok: false,
          reasonCodes: [
            "INDEPENDENT_REVIEW_SCHEMA_BYTES_INVALID",
          ],
        };
  if (!schemaValidation.ok) {
    reasonCodes.push("KIMI_TRANSPORT_EVIDENCE_SCHEMA_INVALID");
    reasonCodes.push(...schemaValidation.reasonCodes);
  }
  let semanticValidation;
  try {
    semanticValidation =
      await validateIndependentReviewTransportEvidence({
        evidence,
        expectedBindings: transportEvidenceExpectedBindings({
          config,
          bundle,
          promptBytes,
          outputSchemaBytes,
          receiptSchemaBytes,
          actualReturnedModel,
        }),
        evidenceResolver: transportEvidenceResolver({
          evidence,
          requestBytes,
          responseBytes,
          contentBytes,
          outputSchemaBytes,
        }),
      });
  } catch {
    semanticValidation = {
      valid: false,
      reasonCodes: ["TRANSPORT_EVIDENCE_SHAPE_INVALID"],
    };
  }
  if (!semanticValidation.valid) {
    reasonCodes.push("KIMI_TRANSPORT_EVIDENCE_INVALID");
    reasonCodes.push(...semanticValidation.reasonCodes);
  }
  return {
    ok: reasonCodes.length === 0,
    reasonCodes: [...new Set(reasonCodes)].sort(),
  };
}

function artifactsFrom({
  artifactPaths,
  requestBytes,
  responseBytes,
  contentBytes,
  rawMaterialBytes,
  transportEvidenceBytes,
}) {
  return {
    request: byteArtifact(artifactPaths.request, requestBytes),
    response: byteArtifact(artifactPaths.response, responseBytes),
    content: byteArtifact(artifactPaths.content, contentBytes),
    material: byteArtifact(artifactPaths.material, rawMaterialBytes),
    transportEvidence: byteArtifact(
      artifactPaths.transportEvidence,
      transportEvidenceBytes,
    ),
  };
}

function conclusionFor(decision) {
  return decision === "CLEAR"
    ? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
    : decision;
}

export async function createKimiIndependentModelReviewReceipt(input) {
  const {
    receiptId,
    policy,
    bundle,
    config,
    material,
    rawMaterialBytes,
    reviewBundleBytes,
    configBytes,
    promptBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
    materialSchemaBytes,
    transportEvidenceSchemaBytes,
    materialSectionDescriptors,
    runtimeManifestBytes,
    requestBytes,
    responseBytes,
    contentBytes,
    transportEvidence,
    transportEvidenceBytes,
    responseId,
    actualReturnedModel,
    startedAt,
    finishedAt,
    snapshots,
    artifactPaths,
    runtimeTrust,
  } = input;
  if (
    !(configBytes instanceof Uint8Array) ||
    !(reviewBundleBytes instanceof Uint8Array) ||
    !(materialSchemaBytes instanceof Uint8Array) ||
    !(transportEvidenceSchemaBytes instanceof Uint8Array) ||
    !(transportEvidenceBytes instanceof Uint8Array) ||
    !Array.isArray(materialSectionDescriptors) ||
    !(runtimeManifestBytes instanceof Uint8Array) ||
    !runtimeTrust
  ) {
    throw new TypeError("Kimi Receipt requires frozen exact bytes.");
  }
  const transportEvidenceValidation =
    await validateBoundKimiTransportEvidence({
      evidence: transportEvidence,
      evidenceBytes: transportEvidenceBytes,
      evidenceSchemaBytes: transportEvidenceSchemaBytes,
      config,
      bundle,
      promptBytes,
      outputSchemaBytes,
      receiptSchemaBytes,
      requestBytes,
      responseBytes,
      contentBytes,
      actualReturnedModel,
    });
  if (!transportEvidenceValidation.ok) {
    const error = new TypeError(
      "Kimi Receipt transport evidence is invalid.",
    );
    error.reasonCodes = transportEvidenceValidation.reasonCodes;
    throw error;
  }
  const runtimeManifest = parseIndependentReviewJsonBytes(
    runtimeManifestBytes,
    "Independent Review Runtime Manifest",
    4 * 1024 * 1024,
  );
  if (
    !validateIndependentReviewRuntimeDependencyManifest(runtimeManifest).ok
  ) {
    throw new TypeError("Kimi Receipt runtime manifest is invalid.");
  }
  const output = parseIndependentModelReviewOutput(contentBytes);
  const artifacts = artifactsFrom({
    artifactPaths,
    requestBytes,
    responseBytes,
    contentBytes,
    rawMaterialBytes,
    transportEvidenceBytes,
  });
  const diversityLevel = deriveIndependentModelDiversity({
    implementationProvider: bundle.implementationIdentity.provider,
    implementationModel: bundle.implementationIdentity.modelId,
    reviewerProvider: config.reviewerProvider,
    reviewerModel: config.reviewerModel,
  });
  if (diversityLevel !== "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER") {
    throw new TypeError(
      "Kimi candidate requires a different implementation provider.",
    );
  }
  const receipt = {
    schemaVersion: "independent-model-review-receipt.v3",
    receiptId,
    receiptSchemaVersion: "independent-model-review-receipt.v3",
    reviewId: receiptId,
    policyVersion: policy.policyVersion,
    policySha256: policy.policySha256,
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    applicablePhase: bundle.applicablePhase,
    humanIndependentReviewSatisfied: false,
    independentModelReviewRequired: true,
    p3HumanReviewRequired: true,
    bundleId: bundle.bundleId,
    bundleSha256: bundle.bundleSha256,
    reviewMaterialSha256: material.materialSha256,
    reviewer: {
      reviewerProvider: config.reviewerProvider,
      requestedModel: config.reviewerModel,
      actualReturnedModel,
      apiBaseURL: config.baseURL,
      endpoint: config.endpoint,
      reviewerSessionId: responseId,
      reviewerIndependentOfImplementation: true,
      implementationProvider: bundle.implementationIdentity.provider,
      implementationModel: bundle.implementationIdentity.modelId,
      diversityLevel,
    },
    source: structuredClone(bundle.source),
    bindings: {
      reviewBundleSha256: bundle.bundleSha256,
      reviewMaterialSha256: sha256Bytes(rawMaterialBytes),
      reviewMaterialSchemaSha256: sha256Bytes(materialSchemaBytes),
      reviewMaterialSchemaVersion: "independent-review-material.v2",
      reviewMaterialFormat: "LENGTH_PREFIXED_UTF8_ENVELOPE_V1",
      reviewerPromptSha256: sha256Bytes(promptBytes),
      canonicalReceiptSchemaSha256: sha256Bytes(receiptSchemaBytes),
      canonicalOutputSchemaSha256: sha256Bytes(outputSchemaBytes),
      providerTransportSchemaSha256: null,
      transportEvidenceSchemaSha256:
        sha256Bytes(transportEvidenceSchemaBytes),
      transportEvidenceSha256:
        transportEvidence.transportEvidenceSha256,
      providerConfigSha256: sha256Bytes(configBytes),
      rawRequestArtifactSha256: sha256Bytes(requestBytes),
      rawResponseUtf8Sha256: sha256Bytes(responseBytes),
      rawContentUtf8Sha256: sha256Bytes(contentBytes),
      schemaValidatorVersion: independentReviewSchemaValidatorVersion(),
      semanticValidatorVersion:
        KIMI_RECEIPT_SEMANTIC_VALIDATOR_VERSION,
    },
    artifacts,
    isolationEvidence: {
      mode: "API_NO_TOOLS",
      toolsAbsent: true,
      toolChoiceNone: true,
      strictSchema: true,
      credentialsExposedToModel: false,
      implementationConversationImported: false,
      modelToolCapabilities: {
        fileRead: false,
        fileWrite: false,
        shell: false,
        git: false,
        browser: false,
        d1: false,
        sites: false,
        governanceDecision: false,
      },
      repositoryBefore: structuredClone(snapshots.before),
      repositoryAfter: structuredClone(snapshots.after),
      repositoryUnchanged:
        canonicalize(snapshots.before) === canonicalize(snapshots.after),
      runtimeTrust: structuredClone(runtimeTrust),
      runtimeDependencyManifest: {
        path:
          "implementation/governance/independent-review/kimi-runtime-manifest.v1.json",
        gitBlobSha256: sha256Bytes(runtimeManifestBytes),
        manifestSha256: runtimeManifest.manifestSha256,
        nodeExecutableSha256: runtimeManifest.node.executableSha256,
        fullDependencyTreeSha256:
          runtimeManifest.dependencies.fullTreeSha256,
        npmPackageTreeSha256: runtimeManifest.npm.packageTreeSha256,
      },
    },
    reviewedPaths: structuredClone(bundle.reviewedPaths),
    findings: structuredClone(output?.findings ?? []),
    testEvidenceDigests: (bundle.testEvidenceSubjects ?? []).map(
      (evidence) => evidence.outputSha256,
    ),
    decision: output?.decision ?? "INCONCLUSIVE",
    conclusion: conclusionFor(output?.decision ?? "INCONCLUSIVE"),
    historicalTerraEvidenceAccepted: false,
    humanReviewClaim: false,
    governanceEffect: "NONE",
    selfAuthorizing: false,
    startedAt,
    finishedAt,
    recordedAt: finishedAt,
    receiptSha256: RECEIPT_SHA_PLACEHOLDER,
  };
  receipt.receiptSha256 = receiptDigest(receipt);
  const validation = await validateKimiIndependentModelReviewReceipt({
    ...input,
    receipt,
  });
  if (
    validation.reasonCodes.length > 0 ||
    validation.status !== receipt.decision ||
    validation.conclusion !== receipt.conclusion
  ) {
    const error = new TypeError("Kimi independent model Receipt is invalid.");
    error.reasonCodes = validation.reasonCodes;
    throw error;
  }
  return receipt;
}

function receiptShapeValid(receipt) {
  return (
    exactKeys(receipt, RECEIPT_KEYS) &&
    receipt.schemaVersion === "independent-model-review-receipt.v3" &&
    receipt.receiptSchemaVersion === "independent-model-review-receipt.v3" &&
    receipt.reviewId === receipt.receiptId &&
    /^imrr_[a-z0-9][a-z0-9_-]{7,127}$/u.test(receipt.receiptId ?? "") &&
    receipt.assuranceLevel === "MODEL_ONLY_PREPRODUCTION" &&
    ["P0", "P1", "P2"].includes(receipt.applicablePhase) &&
    receipt.humanIndependentReviewSatisfied === false &&
    receipt.independentModelReviewRequired === true &&
    receipt.p3HumanReviewRequired === true &&
    receipt.historicalTerraEvidenceAccepted === false &&
    receipt.humanReviewClaim === false &&
    receipt.governanceEffect === "NONE" &&
    receipt.selfAuthorizing === false &&
    validDate(receipt.startedAt) &&
    validDate(receipt.finishedAt) &&
    validDate(receipt.recordedAt) &&
    receipt.recordedAt === receipt.finishedAt &&
    Date.parse(receipt.startedAt) <= Date.parse(receipt.finishedAt) &&
    validSha(receipt.receiptSha256)
  );
}

export async function validateKimiIndependentModelReviewReceipt(input) {
  const {
    receipt,
    policy,
    bundle,
    config,
    material,
    rawMaterialBytes,
    reviewBundleBytes,
    configBytes,
    promptBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
    materialSchemaBytes,
    transportEvidenceSchemaBytes,
    materialSectionDescriptors,
    runtimeManifestBytes,
    requestBytes,
    responseBytes,
    contentBytes,
    transportEvidence,
    transportEvidenceBytes,
    snapshots,
    governanceSubjectBindings,
    runtimeTrust,
  } = input;
  const reasonCodes = [];
  if (!receiptShapeValid(receipt)) {
    reasonCodes.push("KIMI_RECEIPT_SHAPE_INVALID");
  }
  const configValidation = await validateMoonshotKimiConfig(config);
  reasonCodes.push(...configValidation.reasonCodes);
  let output = null;
  try {
    output = parseIndependentModelReviewOutput(contentBytes);
  } catch {
    output = null;
  }
  const request = parseJsonBytes(requestBytes);
  const response = parseJsonBytes(responseBytes);
  const receiptSchemaValidation =
    await validateIndependentReviewSchemaInstance({
      schemaBytes: receiptSchemaBytes,
      expectedSchemaSha256: sha256Bytes(receiptSchemaBytes),
      instance: receipt,
      label: "Kimi independent model review Receipt Schema",
    });
  const materialSchemaValidation =
    materialSchemaBytes instanceof Uint8Array
      ? await validateIndependentReviewSchemaInstance({
          schemaBytes: materialSchemaBytes,
          expectedSchemaSha256: sha256Bytes(materialSchemaBytes),
          instance: material,
          label: "Kimi independent review Material Schema",
        })
      : {
          ok: false,
          reasonCodes: [
            "INDEPENDENT_REVIEW_SCHEMA_BYTES_INVALID",
          ],
        };
  const outputValidation =
    await validateIndependentModelReviewOutputArtifact({
      rawModelOutput: contentBytes,
      outputSchemaBytes,
      expectedOutputSchemaSha256: sha256Bytes(outputSchemaBytes),
    });
  const transportEvidenceValidation =
    await validateBoundKimiTransportEvidence({
      evidence: transportEvidence,
      evidenceBytes: transportEvidenceBytes,
      evidenceSchemaBytes: transportEvidenceSchemaBytes,
      config,
      bundle,
      promptBytes,
      outputSchemaBytes,
      receiptSchemaBytes,
      requestBytes,
      responseBytes,
      contentBytes,
      actualReturnedModel: receipt?.reviewer?.actualReturnedModel,
    });
  if (
    !receiptSchemaValidation.ok ||
    !materialSchemaValidation.ok ||
    !outputValidation.ok ||
    !transportEvidenceValidation.ok
  ) {
    reasonCodes.push("KIMI_RECEIPT_SCHEMA_INVALID");
    reasonCodes.push(
      ...receiptSchemaValidation.reasonCodes,
      ...materialSchemaValidation.reasonCodes,
      ...outputValidation.reasonCodes,
      ...transportEvidenceValidation.reasonCodes,
    );
  }
  if (!validRequestEnvelope(request, config)) {
    reasonCodes.push("KIMI_REQUEST_INVALID");
  } else if (
    !validBoundRequest(request, config, {
      requestBytes,
      promptBytes,
      materialBytes: rawMaterialBytes,
      outputSchemaBytes,
    })
  ) {
    reasonCodes.push("KIMI_REQUEST_BINDING_MISMATCH");
  }
  if (
    response === null ||
    response.object !== "chat.completion" ||
    response.model !== config?.reviewerModel ||
    response.id !== receipt?.reviewer?.reviewerSessionId ||
    response.choices?.length !== 1 ||
    response.choices[0]?.index !== 0 ||
    response.choices[0]?.finish_reason !== "stop" ||
    response.choices[0]?.message?.role !== "assistant" ||
    Object.hasOwn(response.choices[0]?.message ?? {}, "tool_calls") ||
    Object.hasOwn(response.choices[0]?.message ?? {}, "function_call") ||
    response.choices[0]?.message?.content !== decodeUtf8(contentBytes)
  ) {
    reasonCodes.push("KIMI_RESPONSE_BINDING_INVALID");
  }
  if (
    !(configBytes instanceof Uint8Array) ||
    !(reviewBundleBytes instanceof Uint8Array) ||
    !(materialSchemaBytes instanceof Uint8Array) ||
    !(transportEvidenceSchemaBytes instanceof Uint8Array) ||
    !(transportEvidenceBytes instanceof Uint8Array) ||
    !Array.isArray(materialSectionDescriptors) ||
    !(runtimeManifestBytes instanceof Uint8Array)
  ) {
    reasonCodes.push("KIMI_RECEIPT_ARTIFACT_BINDING_MISMATCH");
  }
  let runtimeManifest = null;
  try {
    runtimeManifest = parseIndependentReviewJsonBytes(
      runtimeManifestBytes,
      "Independent Review Runtime Manifest",
      4 * 1024 * 1024,
    );
  } catch {
    runtimeManifest = null;
  }
  if (
    !runtimeManifest ||
    !validateIndependentReviewRuntimeDependencyManifest(runtimeManifest).ok
  ) {
    reasonCodes.push("KIMI_RECEIPT_RUNTIME_CLOSURE_NOT_PROVED");
  }
  const configBytesSha256 =
    configBytes instanceof Uint8Array ? sha256Bytes(configBytes) : null;
  const reviewBundleBytesSha256 =
    reviewBundleBytes instanceof Uint8Array
      ? sha256Bytes(reviewBundleBytes)
      : null;
  const materialSchemaBytesSha256 =
    materialSchemaBytes instanceof Uint8Array
      ? sha256Bytes(materialSchemaBytes)
      : null;
  const materialValidation = await validateIndependentReviewMaterial({
    material,
    rawMaterialBytes,
    expected: {
      bundle,
      governanceSubjectBindings,
      sectionDescriptors: materialSectionDescriptors,
      sourceCommit: bundle?.source?.sourceCommit,
      sourceTree: bundle?.source?.tree,
      reviewBundleBytesSha256,
      reviewBundleByteLength: reviewBundleBytes?.byteLength,
      reviewBundleDigest: bundle?.bundleSha256,
      reviewerPromptSha256: sha256Bytes(promptBytes),
      reviewerPromptByteLength: promptBytes?.byteLength,
      canonicalOutputSchemaSha256: sha256Bytes(outputSchemaBytes),
      canonicalOutputSchemaByteLength: outputSchemaBytes?.byteLength,
      canonicalReceiptSchemaSha256: sha256Bytes(receiptSchemaBytes),
      canonicalReceiptSchemaByteLength: receiptSchemaBytes?.byteLength,
      providerConfigSha256: configBytesSha256,
      providerConfigByteLength: configBytes?.byteLength,
      modelVisibleProtocolSha256: sha256Bytes(
        createKimiModelVisibleProtocolBytes(config),
      ),
      modelVisibleProtocolByteLength:
        createKimiModelVisibleProtocolBytes(config).byteLength,
      contextBudgetUtf8Bytes: config?.maxReviewMaterialUtf8Bytes,
    },
  });
  reasonCodes.push(...materialValidation.reasonCodes);
  if (
    receipt?.policyVersion !== policy?.policyVersion ||
    receipt?.policySha256 !== policy?.policySha256 ||
    receipt?.bundleId !== bundle?.bundleId ||
    receipt?.bundleSha256 !== bundle?.bundleSha256 ||
    receipt?.reviewMaterialSha256 !== material?.materialSha256 ||
    receipt?.applicablePhase !== bundle?.applicablePhase ||
    canonicalize(receipt?.source) !== canonicalize(bundle?.source) ||
    canonicalize(receipt?.reviewedPaths) !==
      canonicalize(bundle?.reviewedPaths) ||
    canonicalize(receipt?.testEvidenceDigests) !==
      canonicalize(
        (bundle?.testEvidenceSubjects ?? []).map(
          (evidence) => evidence.outputSha256,
        ),
      )
  ) {
    reasonCodes.push("KIMI_RECEIPT_GOVERNANCE_BINDING_MISMATCH");
  }
  if (
    receipt?.reviewer?.reviewerProvider !== "moonshot" ||
    receipt?.reviewer?.requestedModel !== "kimi-k2.7-code" ||
    receipt?.reviewer?.actualReturnedModel !== "kimi-k2.7-code" ||
    receipt?.reviewer?.apiBaseURL !== "https://api.moonshot.ai/v1" ||
    receipt?.reviewer?.endpoint !== "/chat/completions" ||
    receipt?.reviewer?.reviewerIndependentOfImplementation !== true ||
    receipt?.reviewer?.implementationProvider !==
      bundle?.implementationIdentity?.provider ||
    receipt?.reviewer?.implementationModel !==
      bundle?.implementationIdentity?.modelId ||
    receipt?.reviewer?.diversityLevel !==
      "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER"
  ) {
    reasonCodes.push("KIMI_RECEIPT_MODEL_IDENTITY_INVALID");
  }
  const artifacts = artifactsFrom({
    artifactPaths: {
      request: receipt?.artifacts?.request?.path,
      response: receipt?.artifacts?.response?.path,
      content: receipt?.artifacts?.content?.path,
      material: receipt?.artifacts?.material?.path,
      transportEvidence:
        receipt?.artifacts?.transportEvidence?.path,
    },
    requestBytes,
    responseBytes,
    contentBytes,
    rawMaterialBytes,
    transportEvidenceBytes,
  });
  if (
    canonicalize(receipt?.artifacts) !== canonicalize(artifacts) ||
    receipt?.bindings?.reviewBundleSha256 !== bundle?.bundleSha256 ||
    receipt?.bindings?.reviewMaterialSha256 !==
      sha256Bytes(rawMaterialBytes) ||
    receipt?.bindings?.reviewMaterialSchemaSha256 !==
      materialSchemaBytesSha256 ||
    receipt?.bindings?.reviewMaterialSchemaVersion !==
      "independent-review-material.v2" ||
    receipt?.bindings?.reviewMaterialFormat !==
      "LENGTH_PREFIXED_UTF8_ENVELOPE_V1" ||
    receipt?.bindings?.reviewerPromptSha256 !== sha256Bytes(promptBytes) ||
    receipt?.bindings?.canonicalReceiptSchemaSha256 !==
      sha256Bytes(receiptSchemaBytes) ||
    receipt?.bindings?.canonicalOutputSchemaSha256 !==
      sha256Bytes(outputSchemaBytes) ||
    receipt?.bindings?.providerTransportSchemaSha256 !== null ||
    receipt?.bindings?.transportEvidenceSchemaSha256 !==
      sha256Bytes(transportEvidenceSchemaBytes) ||
    receipt?.bindings?.transportEvidenceSha256 !==
      transportEvidence?.transportEvidenceSha256 ||
    receipt?.bindings?.providerConfigSha256 !==
      configBytesSha256 ||
    receipt?.bindings?.rawRequestArtifactSha256 !==
      sha256Bytes(requestBytes) ||
    receipt?.bindings?.rawResponseUtf8Sha256 !==
      sha256Bytes(responseBytes) ||
    receipt?.bindings?.rawContentUtf8Sha256 !==
      sha256Bytes(contentBytes) ||
    receipt?.bindings?.schemaValidatorVersion !==
      independentReviewSchemaValidatorVersion() ||
    receipt?.bindings?.semanticValidatorVersion !==
      KIMI_RECEIPT_SEMANTIC_VALIDATOR_VERSION
  ) {
    reasonCodes.push("KIMI_RECEIPT_ARTIFACT_BINDING_MISMATCH");
  }
  if (
    !validSnapshot(snapshots?.before) ||
    !validSnapshot(snapshots?.after) ||
    canonicalize(snapshots.before) !== canonicalize(snapshots.after) ||
    canonicalize(receipt?.isolationEvidence?.repositoryBefore) !==
      canonicalize(snapshots.before) ||
    canonicalize(receipt?.isolationEvidence?.repositoryAfter) !==
      canonicalize(snapshots.after) ||
    receipt?.isolationEvidence?.mode !== "API_NO_TOOLS" ||
    receipt?.isolationEvidence?.toolsAbsent !== true ||
    receipt?.isolationEvidence?.toolChoiceNone !== true ||
    receipt?.isolationEvidence?.strictSchema !== true ||
    receipt?.isolationEvidence?.credentialsExposedToModel !== false ||
    receipt?.isolationEvidence?.implementationConversationImported !==
      false ||
    receipt?.isolationEvidence?.repositoryUnchanged !== true ||
    canonicalize(receipt?.isolationEvidence?.runtimeTrust) !==
      canonicalize(runtimeTrust) ||
    !exactKeys(runtimeTrust, [
      "bootstrapSha256",
      "launcherSha256",
      "mode",
      "runnerGitBlobSha256",
      "runtimeCommit",
      "runtimeManifestGitBlobSha256",
      "runtimeTree",
      "subjectCommit",
      "subjectTree",
    ]) ||
    runtimeTrust?.mode !== "ANCESTOR_RUNTIME_COMMIT" ||
    !validCommit(runtimeTrust?.runtimeCommit) ||
    !validCommit(runtimeTrust?.runtimeTree) ||
    !validCommit(runtimeTrust?.subjectCommit) ||
    !validCommit(runtimeTrust?.subjectTree) ||
    runtimeTrust?.runtimeCommit === runtimeTrust?.subjectCommit ||
    runtimeTrust?.subjectCommit !== bundle?.source?.sourceCommit ||
    runtimeTrust?.subjectTree !== bundle?.source?.tree ||
    !validSha(runtimeTrust?.bootstrapSha256) ||
    !validSha(runtimeTrust?.launcherSha256) ||
    !validSha(runtimeTrust?.runtimeManifestGitBlobSha256) ||
    !validSha(runtimeTrust?.runnerGitBlobSha256) ||
    runtimeTrust?.runtimeManifestGitBlobSha256 !==
      (runtimeManifestBytes instanceof Uint8Array
        ? sha256Bytes(runtimeManifestBytes)
        : null) ||
    receipt?.isolationEvidence?.runtimeDependencyManifest?.path !==
      "implementation/governance/independent-review/kimi-runtime-manifest.v1.json" ||
    receipt?.isolationEvidence?.runtimeDependencyManifest?.gitBlobSha256 !==
      (runtimeManifestBytes instanceof Uint8Array
        ? sha256Bytes(runtimeManifestBytes)
        : null) ||
    receipt?.isolationEvidence?.runtimeDependencyManifest?.manifestSha256 !==
      runtimeManifest?.manifestSha256 ||
    receipt?.isolationEvidence?.runtimeDependencyManifest
      ?.nodeExecutableSha256 !== runtimeManifest?.node?.executableSha256 ||
    receipt?.isolationEvidence?.runtimeDependencyManifest
      ?.fullDependencyTreeSha256 !==
      runtimeManifest?.dependencies?.fullTreeSha256 ||
    receipt?.isolationEvidence?.runtimeDependencyManifest
      ?.npmPackageTreeSha256 !== runtimeManifest?.npm?.packageTreeSha256 ||
    Object.values(
      receipt?.isolationEvidence?.modelToolCapabilities ?? {},
    ).some((value) => value !== false)
  ) {
    reasonCodes.push("KIMI_RECEIPT_ISOLATION_NOT_PROVED");
  }
  if (
    validSha(receipt?.receiptSha256) &&
    receiptDigest(receipt) !== receipt.receiptSha256
  ) {
    reasonCodes.push("KIMI_RECEIPT_SELF_HASH_MISMATCH");
  }
  if (
    receipt?.findings !== undefined &&
    canonicalize(receipt.findings) !== canonicalize(output?.findings)
  ) {
    reasonCodes.push("KIMI_RECEIPT_OUTPUT_BINDING_MISMATCH");
  }
  if (
    receipt?.decision !== output?.decision ||
    receipt?.conclusion !== conclusionFor(output?.decision)
  ) {
    reasonCodes.push("KIMI_RECEIPT_OUTPUT_BINDING_MISMATCH");
  }
  const openBlockingFinding = outputValidation.reasonCodes.includes(
    "INDEPENDENT_REVIEW_UNRESOLVED_BLOCKING_FINDING",
  );
  if (receipt?.decision === "CLEAR" && openBlockingFinding) {
    reasonCodes.push("KIMI_RECEIPT_OPEN_BLOCKING_FINDING");
  }
  const [policyValidation, bundleValidation] = await Promise.all([
    validateIndependentReviewPolicy(policy),
    validateIndependentReviewBundle(bundle, { policy }),
  ]);
  reasonCodes.push(
    ...policyValidation.reasonCodes,
    ...bundleValidation.reasonCodes,
  );
  const uniqueReasonCodes = [...new Set(reasonCodes)].sort();
  if (
    receipt?.decision === "INCONCLUSIVE" ||
    uniqueReasonCodes.includes("KIMI_RECEIPT_ISOLATION_NOT_PROVED")
  ) {
    return result(false, "INCONCLUSIVE", uniqueReasonCodes, {
      conclusion: "INCONCLUSIVE",
    });
  }
  if (
    receipt?.decision === "BLOCKED" ||
    openBlockingFinding ||
    uniqueReasonCodes.length > 0
  ) {
    return result(false, "BLOCKED", uniqueReasonCodes, {
      conclusion: "BLOCKED",
    });
  }
  return result(true, "CLEAR", [], {
    conclusion: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  });
}
