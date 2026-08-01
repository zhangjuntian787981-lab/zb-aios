import { createHash } from "node:crypto";
import {
  parseIndependentReviewJsonBytes,
  validateIndependentModelReviewOutputArtifact,
  validateIndependentReviewSchemaInstance,
} from "./independent-model-review.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const CONFIG_SHA_PLACEHOLDER = `sha256:${"0".repeat(64)}`;
const EVIDENCE_SHA_PLACEHOLDER = CONFIG_SHA_PLACEHOLDER;
const COMMIT = /^[a-f0-9]{40}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const CONFIG_KEYS_V2 = [
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
const CONFIG_KEYS_V3 = [
  ...CONFIG_KEYS_V2.slice(0, CONFIG_KEYS_V2.indexOf("maxReviewMaterialUtf8Bytes")),
  "nonMessageVisibleTokenReserve",
  "nonMessageVisibleInputMaxUtf8Bytes",
  "nonMessageVisibleInputCanonicalization",
  "tokenEstimateCoverage",
  ...CONFIG_KEYS_V2.slice(CONFIG_KEYS_V2.indexOf("maxReviewMaterialUtf8Bytes")),
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
const OFFICIAL_CONTRACT_V2 = Object.freeze({
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
const OFFICIAL_CONTRACT_V3 = Object.freeze({
  modelUrl: "https://platform.kimi.ai/docs/models",
  chatUrl: "https://platform.kimi.ai/docs/api/chat",
  tokenEstimateUrl: "https://platform.kimi.ai/docs/api/estimate",
  structuredOutputUrl: "https://platform.kimi.ai/docs/guide/response_format",
  pricingUrl: "https://platform.kimi.ai/",
  researchPath:
    "docs/research/moonshot-kimi-k3-transport-contract-v3-2026-08-01.md",
  researchSha256:
    "sha256:fad98df32d8e9e5755a3e8030be1c883deeae7fabf277425ad01389f0259f76d",
  queriedAt: "2026-08-01",
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

function sameBytes(left, right) {
  return (
    left instanceof Uint8Array &&
    right instanceof Uint8Array &&
    left.byteLength === right.byteLength &&
    Buffer.compare(Buffer.from(left), Buffer.from(right)) === 0
  );
}

function compareUtf8(left, right) {
  return Buffer.compare(
    Buffer.from(left, "utf8"),
    Buffer.from(right, "utf8"),
  );
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

function validateKimiK3TokenEstimateResponseBody(body, { enveloped }) {
  const dataValidated =
    exactKeys(body?.data, ["total_tokens"]) &&
    Number.isSafeInteger(body.data.total_tokens);
  const schemaValidated = enveloped
    ? exactKeys(body, ["code", "data", "scode", "status"]) &&
      Number.isSafeInteger(body.code) &&
      typeof body.scode === "string" &&
      typeof body.status === "boolean" &&
      dataValidated
    : exactKeys(body, ["data"]) && dataValidated;
  const semanticValidated =
    schemaValidated &&
    (!enveloped ||
      (body.code === 0 && body.scode === "0x0" && body.status === true)) &&
    body.data.total_tokens >= 0;
  return {
    schemaValidated,
    semanticValidated,
    estimatedInputTokens: dataValidated ? body.data.total_tokens : null,
  };
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

function parseJsonValueBytes(bytes) {
  try {
    return {
      ok: true,
      value: parseIndependentReviewJsonBytes(
        bytes,
        "Kimi K3 JSON",
        16 * 1024 * 1024,
      ),
    };
  } catch {
    return { ok: false, value: null };
  }
}

const MFJS_TYPES = new Set([
  "null",
  "boolean",
  "object",
  "array",
  "number",
  "integer",
  "string",
]);
const MFJS_KEYS = new Set([
  "type",
  "enum",
  "properties",
  "required",
  "additionalProperties",
  "items",
  "anyOf",
  "$defs",
  "$ref",
  "description",
  "default",
]);

function mfjsNodeValid(node, root = false) {
  if (node === null || typeof node !== "object" || Array.isArray(node)) {
    return false;
  }
  if (
    Object.keys(node).some((key) => !MFJS_KEYS.has(key)) ||
    (!root && Object.hasOwn(node, "$defs"))
  ) {
    return false;
  }
  if (Object.hasOwn(node, "$ref")) {
    return (
      exactKeys(node, ["$ref"]) &&
      (node.$ref === "#" || /^#\/\$defs\/[A-Za-z0-9_-]+$/u.test(node.$ref))
    );
  }
  const hasObjectKeyword = [
    "properties",
    "required",
    "additionalProperties",
  ].some((key) => Object.hasOwn(node, key));
  if (
    (root && node.type !== "object") ||
    (hasObjectKeyword && node.type !== "object") ||
    (Object.hasOwn(node, "items") && node.type !== "array") ||
    (node.type === "array" && !Object.hasOwn(node, "items")) ||
    (!Object.hasOwn(node, "type") &&
      !Object.hasOwn(node, "anyOf") &&
      !Object.hasOwn(node, "$ref"))
  ) {
    return false;
  }
  if (
    Object.hasOwn(node, "type") &&
    (typeof node.type !== "string" || !MFJS_TYPES.has(node.type))
  ) {
    return false;
  }
  if (Object.hasOwn(node, "enum")) {
    if (
      typeof node.type !== "string" ||
      !Array.isArray(node.enum) ||
      node.enum.length === 0
    ) {
      return false;
    }
    const enumType = typeof node.enum[0];
    if (
      !["string", "number"].includes(enumType) ||
      node.enum.some((value) => typeof value !== enumType) ||
      (enumType === "string" && node.type !== "string") ||
      (enumType === "number" && !["number", "integer"].includes(node.type))
    ) {
      return false;
    }
  }
  if (
    Object.hasOwn(node, "description") &&
    typeof node.description !== "string"
  ) {
    return false;
  }
  if (
    Object.hasOwn(node, "properties") &&
    (node.properties === null ||
      typeof node.properties !== "object" ||
      Array.isArray(node.properties) ||
      Object.keys(node.properties).length === 0 ||
      !Object.values(node.properties).every((value) => mfjsNodeValid(value)))
  ) {
    return false;
  }
  if (Object.hasOwn(node, "required")) {
    if (
      !Array.isArray(node.required) ||
      new Set(node.required).size !== node.required.length ||
      node.required.some((value) => typeof value !== "string") ||
      node.required.some(
        (value) => !Object.hasOwn(node.properties ?? {}, value),
      )
    ) {
      return false;
    }
  }
  if (
    Object.hasOwn(node, "additionalProperties") &&
    node.additionalProperties !== false
  ) {
    return false;
  }
  if (
    node.type === "object" &&
    (!Object.hasOwn(node, "properties") ||
      !Object.hasOwn(node, "required") ||
      node.additionalProperties !== false ||
      node.required.length !== Object.keys(node.properties).length)
  ) {
    return false;
  }
  if (Object.hasOwn(node, "items") && !mfjsNodeValid(node.items)) {
    return false;
  }
  if (
    Object.hasOwn(node, "anyOf") &&
    (!Array.isArray(node.anyOf) ||
      node.anyOf.length === 0 ||
      !node.anyOf.every((value) => mfjsNodeValid(value)))
  ) {
    return false;
  }
  if (
    Object.hasOwn(node, "$defs") &&
    (node.$defs === null ||
      typeof node.$defs !== "object" ||
      Array.isArray(node.$defs) ||
      !Object.values(node.$defs).every((value) => mfjsNodeValid(value)))
  ) {
    return false;
  }
  return true;
}

function mfjsReferences(node, references = []) {
  if (Object.hasOwn(node, "$ref")) {
    references.push(node.$ref);
    return references;
  }
  for (const value of Object.values(node.properties ?? {})) {
    mfjsReferences(value, references);
  }
  for (const value of Object.values(node.$defs ?? {})) {
    mfjsReferences(value, references);
  }
  if (node.items) mfjsReferences(node.items, references);
  for (const value of node.anyOf ?? []) mfjsReferences(value, references);
  return references;
}

function mfjsReferencesValid(schema) {
  const definitions = schema.$defs ?? {};
  const definitionNames = new Set(Object.keys(definitions));
  const referenceName = (reference) =>
    typeof reference === "string" && reference.startsWith("#/$defs/")
      ? reference.slice("#/$defs/".length)
      : null;
  const allReferences = mfjsReferences(schema);
  if (
    allReferences.some((reference) => {
      const name = referenceName(reference);
      return name === null || !definitionNames.has(name);
    })
  ) {
    return false;
  }
  const graph = new Map(
    Object.entries(definitions).map(([name, definition]) => [
      name,
      mfjsReferences(definition, []).map(referenceName),
    ]),
  );
  const visiting = new Set();
  const visited = new Set();
  const acyclic = (name) => {
    if (visiting.has(name)) return false;
    if (visited.has(name)) return true;
    visiting.add(name);
    for (const dependency of graph.get(name) ?? []) {
      if (!acyclic(dependency)) return false;
    }
    visiting.delete(name);
    visited.add(name);
    return true;
  };
  return [...definitionNames].every(acyclic);
}

export function validateMoonshotKimiK3TransportSchema(schemaBytes) {
  const schema = parseJsonBytes(schemaBytes);
  const valid =
    schema !== null &&
    mfjsNodeValid(schema, true) &&
    mfjsReferencesValid(schema);
  return {
    ok: valid,
    reasonCodes: valid
      ? []
      : ["KIMI_K3_PROVIDER_TRANSPORT_SCHEMA_MFJS_INVALID"],
  };
}

function ceilDiv(numerator, denominator) {
  return Math.floor((numerator + denominator - 1) / denominator);
}

export const kimiK3Digests = Object.freeze({
  bytes: sha256Bytes,
  value: sha256Value,
  config: configDigest,
});

export const kimiK3ReviewMaterialPathsV2 = Object.freeze({
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
  materialSchema:
    "implementation/governance/schemas/independent-review-material.v3.schema.json",
  modelVisibleProtocol:
    "artifacts/moonshot-kimi-k3-model-visible-protocol.v2.json",
});

export const kimiK3ReviewMaterialPathsV3 = Object.freeze({
  reviewBundle: "artifacts/independent-review-bundle.v2.json",
  patch: "artifacts/source.diff",
  prompt:
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  outputSchema:
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v5.schema.json",
  config:
    "implementation/governance/independent-review/moonshot-kimi-k3.v3.json",
  materialSchema:
    "implementation/governance/schemas/independent-review-material.v4.schema.json",
  historicalEvidenceIndexSchema:
    "implementation/governance/schemas/independent-review-historical-evidence-index.v1.schema.json",
  historicalEvidenceIndex:
    "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/historical-evidence-index.v1.json",
  modelVisibleProtocol:
    "artifacts/moonshot-kimi-k3-model-visible-protocol.v3.json",
});

export const kimiK3ReviewMaterialPathsV4 = Object.freeze({
  ...kimiK3ReviewMaterialPathsV3,
  providerTransportSchema:
    "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json",
  chatDiagnosticSchema:
    "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v2.schema.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v6.schema.json",
});

export const kimiK3ReviewMaterialPathsV5 = Object.freeze({
  ...kimiK3ReviewMaterialPathsV4,
  tokenEstimateDiagnosticSchema:
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v3.schema.json",
  chatDiagnosticSchema:
    "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v3.schema.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v7.schema.json",
});

// Current candidate paths. Historical readers must select V5, V4, V3, then V2
// from the exact source commit rather than inheriting the runtime's version.
export const kimiK3ReviewMaterialPaths = kimiK3ReviewMaterialPathsV5;

const HISTORICAL_EVIDENCE_DIRECTORY =
  "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731";
const HISTORICAL_REVIEW_ID_PROVENANCE =
  "INDEX_LOCAL_LINEAGE_ONLY_NO_RECEIPT";
const historicalEntry = (
  artifactType,
  name,
  byteLength,
  sha256,
  artifactSchemaVersion,
  semanticDigestField,
  semanticDigest,
  validationContract,
) =>
  Object.freeze({
    artifactType,
    path: `${HISTORICAL_EVIDENCE_DIRECTORY}/${name}`,
    byteLength,
    sha256,
    artifactSchemaVersion,
    semanticDigestField,
    semanticDigest,
    validationContract,
  });
const HISTORICAL_REVIEW_EVIDENCE = Object.freeze(
  [
    historicalEntry(
      "FORMAL_REQUEST",
      "formal-request.json",
      1_014_092,
      "sha256:11f68ce448e836caee68ab718a9e03cacca5b643822b821e3bbd935dbc2763e0",
      null,
      null,
      null,
      "KIMI_K3_FORMAL_REQUEST_V1",
    ),
    historicalEntry(
      "REVIEW_BUNDLE",
      "review-bundle.v2.json",
      28_183,
      "sha256:7401a94fcef52a62905ba37f08fe6f1e913069f39dc6fe4476738acd2c2affb1",
      "independent-review-bundle.v2",
      "bundleSha256",
      "sha256:ac81098a12529d8ec5da0c58c9b04cc18e67a405a28fb40440590dfb5bb7627c",
      "INDEPENDENT_REVIEW_BUNDLE_V2",
    ),
    historicalEntry(
      "REVIEW_MATERIAL",
      "review-material.v3.utf8",
      957_096,
      "sha256:1b00dde4aff6c8feaee05df9480667d6063e0a6c50e80f38e42d246e2b4d5724",
      "independent-review-material.v3",
      "materialSha256",
      "sha256:e13bcb6a65e3509641f62ed05510bbdffba655a31ae2535fb230628374a7997f",
      "INDEPENDENT_REVIEW_MATERIAL_V3",
    ),
    historicalEntry(
      "SINGLE_CALL_OUTCOME",
      "single-call-outcome.v1.json",
      3_967,
      "sha256:6d130f4c3819fb83b99bd5bd295272691ac010502fb2074058f070a4dc974b93",
      "kimi-k3-single-call-outcome.v1",
      "outcomeSha256",
      "sha256:a76ed3a215b13f92ad3161c9d47795efbe45fefeca445f8a8b634aa22b0f0528",
      "KIMI_K3_SINGLE_CALL_OUTCOME_V1",
    ),
    historicalEntry(
      "TOKEN_ESTIMATE_REQUEST",
      "token-estimate-request.json",
      1_012_452,
      "sha256:0e2d77b325e1b92eaf8e0051a931aec235af58ead76d43c65742521a0c970ca3",
      null,
      null,
      null,
      "KIMI_K3_TOKEN_ESTIMATE_REQUEST_V1",
    ),
  ].sort((left, right) => compareUtf8(left.path, right.path)),
);
export const kimiK3HistoricalReviewEvidencePaths = Object.freeze(
  HISTORICAL_REVIEW_EVIDENCE.map(({ path }) => path),
);
export const kimiK3HistoricalReviewEvidenceContract = Object.freeze({
  indexPath: kimiK3ReviewMaterialPaths.historicalEvidenceIndex,
  indexSchemaPath: kimiK3ReviewMaterialPaths.historicalEvidenceIndexSchema,
  indexBytesSha256:
    "sha256:d3a7869f0bdd32ee46ea8116170aa434c928eab73849e43f9028ef46b1876a6b",
  indexSchemaBytesSha256:
    "sha256:ab4fb9b7870d9b23d0024d02297d47b1b1d523152fb116b158b40a579340407c",
  evidenceOriginCommit: "e40dd122ba323b825906e3362aea2cc37748ef7a",
  evidenceOriginTree: "ecc0c179792aa244037bd283a326da58d90f49e3",
  entries: HISTORICAL_REVIEW_EVIDENCE,
});
const HISTORICAL_REFERENCE_KEYS = [
  "kind",
  "reviewId",
  "reviewIdProvenance",
  "path",
  "evidenceOriginCommit",
  "evidenceOriginTree",
  "gitMode",
  "byteLength",
  "sha256",
  "indexEntrySha256",
];
const HISTORICAL_ENTRY_SHA256 = Object.freeze({
  FORMAL_REQUEST:
    "sha256:d6da7a214bdd5a3349ce8b7e2352b60b32bfda6cf3722619ed35d5991324e37a",
  REVIEW_BUNDLE:
    "sha256:937987d8103fae0c2681f27eeb38a8419dcc550e003d6b6f7b4152364325a48e",
  REVIEW_MATERIAL:
    "sha256:12718eb268b2d9ac6ef36b9afbb88f4e54fba0b49401b3aecbdb35e25446bb2f",
  SINGLE_CALL_OUTCOME:
    "sha256:6319bd002044790ed59439e93ed51d06050eee394ed2208350e042348f3edfed",
  TOKEN_ESTIMATE_REQUEST:
    "sha256:787702ec5fb740933d5b48a50561e55264c36cb24e1fc2de2252e700ea8b7b1d",
});

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

function sameValue(left, right) {
  try {
    return canonicalize(left) === canonicalize(right);
  } catch {
    return false;
  }
}

export function validateKimiK3HistoricalEvidenceReferences(references) {
  const expected = HISTORICAL_REVIEW_EVIDENCE.map((entry) => ({
    kind: "PRIOR_REVIEW_EVIDENCE_REFERENCE",
    reviewId: "imrr_kimi_k3_20260731_attempt_001",
    reviewIdProvenance: HISTORICAL_REVIEW_ID_PROVENANCE,
    path: entry.path,
    evidenceOriginCommit:
      kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit,
    evidenceOriginTree:
      kimiK3HistoricalReviewEvidenceContract.evidenceOriginTree,
    gitMode: "100644",
    byteLength: entry.byteLength,
    sha256: entry.sha256,
    indexEntrySha256: HISTORICAL_ENTRY_SHA256[entry.artifactType],
  }));
  const ok =
    Array.isArray(references) &&
    references.length === expected.length &&
    references.every((reference) =>
      exactKeys(reference, HISTORICAL_REFERENCE_KEYS),
    ) &&
    sameValue(references, expected);
  return {
    ok,
    reasonCodes: ok
      ? []
      : ["KIMI_REVIEW_MATERIAL_HISTORICAL_EVIDENCE_REFERENCE_INVALID"],
  };
}

function expectedHistoricalLineage(entries) {
  const byType = new Map(entries.map((entry) => [entry.artifactType, entry]));
  const link = (artifactType, relationship) => ({
    path: byType.get(artifactType)?.path,
    relationship,
    sha256: byType.get(artifactType)?.sha256,
  });
  return new Map([
    ["REVIEW_BUNDLE", []],
    ["REVIEW_MATERIAL", [link("REVIEW_BUNDLE", "EMBEDS_FULL_BYTES_AS_REVIEW_BUNDLE_SECTION")]],
    ["FORMAL_REQUEST", [link("REVIEW_MATERIAL", "EMBEDS_FULL_BYTES_AS_USER_CONTENT")]],
    ["TOKEN_ESTIMATE_REQUEST", [link("FORMAL_REQUEST", "REUSES_EXACT_MESSAGES")]],
    [
      "SINGLE_CALL_OUTCOME",
      ["FORMAL_REQUEST", "REVIEW_BUNDLE", "REVIEW_MATERIAL", "TOKEN_ESTIMATE_REQUEST"]
        .map((type) => link(type, "BINDS_ARTIFACT_BYTES"))
        .sort((left, right) =>
          compareUtf8(String(left.path), String(right.path)),
        ),
    ],
  ]);
}

function lineageIsAcyclic(entries) {
  const graph = new Map(
    entries.map((entry) => [
      entry?.path,
      Array.isArray(entry?.derivedFrom)
        ? entry.derivedFrom.map(({ path }) => path)
        : [],
    ]),
  );
  const visited = new Set();
  const active = new Set();
  const visit = (path) => {
    if (active.has(path)) return false;
    if (visited.has(path)) return true;
    active.add(path);
    if ((graph.get(path) ?? []).some((dependency) => !graph.has(dependency) || !visit(dependency))) {
      return false;
    }
    active.delete(path);
    visited.add(path);
    return true;
  };
  return [...graph.keys()].every(visit);
}

export function validateIndependentReviewHistoricalEvidenceIndex({
  index,
  expected = {},
}) {
  const reasons = [];
  const entries = Array.isArray(index?.entries) ? index.entries : [];
  const paths = entries.map(({ path }) => path);
  const fixed = new Map(HISTORICAL_REVIEW_EVIDENCE.map((entry) => [entry.path, entry]));
  const requiredIndexKeys = [
    "schemaVersion", "indexId", "lifecycle", "purpose", "reviewId",
    "reviewIdProvenance", "coverageBaseCommit", "evidenceOrigin",
    "priorReview", "baseCommitCorrection", "entries", "entrySetSha256",
    "pathSetSha256", "governanceBoundary", "recordedAt", "indexSha256",
  ];
  if (
    !exactKeys(index, requiredIndexKeys) ||
    index.schemaVersion !== "independent-review-historical-evidence-index.v1" ||
    !/^irhei_[a-z0-9][a-z0-9_-]{7,127}$/u.test(index.indexId ?? "") ||
    index.lifecycle !== "CANDIDATE" ||
    index.purpose !== "MODEL_MATERIAL_RECURSION_PREVENTION_ONLY" ||
    !/^imrr_[a-z0-9][a-z0-9_-]{7,127}$/u.test(index.reviewId ?? "") ||
    index.reviewIdProvenance !== HISTORICAL_REVIEW_ID_PROVENANCE ||
    index.coverageBaseCommit !== "ab95c7aff586279062c7698749fdbc0e38e955d1" ||
    !exactKeys(index.evidenceOrigin, ["commit", "tree", "directory", "currentSourceBytesMustMatchOrigin"]) ||
    index.evidenceOrigin.commit !== kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit ||
    index.evidenceOrigin.tree !== kimiK3HistoricalReviewEvidenceContract.evidenceOriginTree ||
    index.evidenceOrigin.directory !== HISTORICAL_EVIDENCE_DIRECTORY ||
    index.evidenceOrigin.currentSourceBytesMustMatchOrigin !== true ||
    !validDate(index.recordedAt) ||
    entries.length !== 5 ||
    new Set(paths).size !== 5 ||
    canonicalize(paths) !== canonicalize(kimiK3HistoricalReviewEvidencePaths)
  ) reasons.push("KIMI_REVIEW_HISTORICAL_EVIDENCE_INDEX_INVALID");

  const lineage = expectedHistoricalLineage(entries);
  for (const entry of entries) {
    const contract = fixed.get(entry?.path);
    const subject = contract && {
      artifactType: entry.artifactType,
      path: entry.path,
      byteLength: entry.byteLength,
      sha256: entry.sha256,
      artifactSchemaVersion: entry.artifactSchemaVersion,
      semanticDigestField: entry.semanticDigestField,
      semanticDigest: entry.semanticDigest,
      validationContract: entry.validationContract,
    };
    if (
      !exactKeys(entry, [
        "artifactType", "path", "gitMode", "byteLength", "sha256",
        "artifactSchemaVersion", "semanticDigestField", "semanticDigest",
        "validationContract", "derivedFrom", "entrySha256",
      ]) ||
      entry.gitMode !== "100644" ||
      !sameValue(subject, contract) ||
      !sameValue(entry.derivedFrom, lineage.get(entry.artifactType)) ||
      entry.entrySha256 !== sha256Value(withoutField(entry, "entrySha256"))
    ) reasons.push("KIMI_REVIEW_HISTORICAL_EVIDENCE_ENTRY_INVALID");
  }
  if (!lineageIsAcyclic(entries)) reasons.push("KIMI_REVIEW_HISTORICAL_EVIDENCE_LINEAGE_INVALID");
  if (
    index?.entrySetSha256 !== sha256Value(entries) ||
    index?.pathSetSha256 !== sha256Value(paths) ||
    index?.indexSha256 !== sha256Value(withoutField(index, "indexSha256"))
  ) reasons.push("KIMI_REVIEW_HISTORICAL_EVIDENCE_DIGEST_MISMATCH");

  const correction = index?.baseCommitCorrection;
  const boundary = index?.governanceBoundary;
  const prior = index?.priorReview;
  if (
    !exactKeys(prior, [
      "bundleId", "bundleDigest", "materialId", "materialDigest",
      "sourceCommit", "sourceTree", "patchSha256", "conclusion",
      "clearReceiptExists",
    ]) ||
    prior?.bundleId !== "imrb_kimi_k3_20260731_004" ||
    prior?.bundleDigest !== "sha256:ac81098a12529d8ec5da0c58c9b04cc18e67a405a28fb40440590dfb5bb7627c" ||
    prior?.materialId !== "irm_kimi_k3_20260731_002" ||
    prior?.materialDigest !== "sha256:e13bcb6a65e3509641f62ed05510bbdffba655a31ae2535fb230628374a7997f" ||
    prior?.sourceCommit !== "cd8b7623c34e346fd3460fed465f6c1998ee8443" ||
    prior?.sourceTree !== "9ea01d46aae781265826d659ae5059c6b71c60c2" ||
    prior?.patchSha256 !== "sha256:3ecae62f9e2a26b72646d10b2f6147113ecbe01f3bf4f7a208d0a0520227c01c" ||
    prior?.conclusion !== "INCONCLUSIVE" || prior?.clearReceiptExists !== false ||
    !exactKeys(correction, [
      "outcomePath", "recordedBaseCommit", "correctedCoverageBaseCommit",
      "authorityPaths", "historicalArtifactMutated", "confersClearStatus",
      "governanceEffect",
    ]) ||
    correction?.outcomePath !== `${HISTORICAL_EVIDENCE_DIRECTORY}/single-call-outcome.v1.json` ||
    correction?.recordedBaseCommit !== "ab95d8a18d80a74631e31d6a060dcf19019b098e" ||
    correction?.correctedCoverageBaseCommit !== "ab95c7aff586279062c7698749fdbc0e38e955d1" ||
    !sameValue(correction?.authorityPaths, [
      `${HISTORICAL_EVIDENCE_DIRECTORY}/review-bundle.v2.json`,
      `${HISTORICAL_EVIDENCE_DIRECTORY}/review-material.v3.utf8`,
    ]) ||
    correction?.historicalArtifactMutated !== false ||
    correction?.confersClearStatus !== false || correction?.governanceEffect !== "NONE" ||
    !exactKeys(boundary, [
      "historicalConclusion", "clearReceiptExists", "coverageBaseAdvanced",
      "rawEvidencePreserved", "governanceEffect",
    ]) ||
    boundary?.historicalConclusion !== "INCONCLUSIVE" ||
    boundary?.clearReceiptExists !== false || boundary?.coverageBaseAdvanced !== false ||
    boundary?.rawEvidencePreserved !== true || boundary?.governanceEffect !== "NONE"
  ) reasons.push("KIMI_REVIEW_HISTORICAL_EVIDENCE_OUTCOME_CORRECTION_INVALID");
  if (expected.indexBytesSha256 !== undefined && expected.indexBytesSha256 !== expected.actualIndexBytesSha256) {
    reasons.push("KIMI_REVIEW_HISTORICAL_EVIDENCE_INDEX_BYTES_MISMATCH");
  }
  if (
    (expected.evidenceOriginCommit !== undefined && expected.evidenceOriginCommit !== index?.evidenceOrigin?.commit) ||
    (expected.evidenceOriginTree !== undefined && expected.evidenceOriginTree !== index?.evidenceOrigin?.tree)
  ) reasons.push("KIMI_REVIEW_HISTORICAL_EVIDENCE_ORIGIN_MISMATCH");
  return {
    ok: reasons.length === 0,
    reasonCodes: [...new Set(reasons)].sort(),
    references: entries.map((entry) => ({
      kind: "PRIOR_REVIEW_EVIDENCE_REFERENCE",
      reviewId: index.reviewId,
      reviewIdProvenance: index.reviewIdProvenance,
      path: entry.path,
      evidenceOriginCommit: index.evidenceOrigin.commit,
      evidenceOriginTree: index.evidenceOrigin.tree,
      gitMode: entry.gitMode,
      byteLength: entry.byteLength,
      sha256: entry.sha256,
      indexEntrySha256: entry.entrySha256,
    })),
  };
}

export const kimiK3ReviewMaterialGovernancePathsV2 = Object.freeze(
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

export const kimiK3ReviewMaterialGovernancePathsV3 = Object.freeze(
  [
    "docs/adr/0014-k3-historical-evidence-materialization-checkpoint.md",
    "docs/adr/0015-kimi-k3-transport-contract-v3.md",
    "docs/adr/0013-moonshot-kimi-k3-single-call-transport.md",
    "docs/research/moonshot-kimi-k3-transport-contract-2026-07-31.md",
    "docs/research/moonshot-kimi-k3-transport-contract-v3-2026-08-01.md",
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    "implementation/governance/schemas/independent-model-review-receipt.v4.schema.json",
    "implementation/governance/schemas/independent-model-review-receipt.v5.schema.json",
    "implementation/governance/schemas/independent-review-material.v3.schema.json",
    "implementation/governance/schemas/independent-review-material.v4.schema.json",
    "implementation/governance/schemas/independent-review-historical-evidence-index.v1.schema.json",
    "implementation/governance/schemas/independent-review-runtime-manifest.v2.schema.json",
    "implementation/governance/schemas/independent-review-transport-evidence.v2.schema.json",
    "implementation/governance/schemas/independent-review-transport-evidence.v3.schema.json",
    "implementation/governance/schemas/moonshot-kimi-independent-review-config.v2.schema.json",
    "implementation/governance/schemas/moonshot-kimi-independent-review-config.v3.schema.json",
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v1.schema.json",
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v2.schema.json",
    "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v2.schema.json",
    "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v1.schema.json",
    "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
    "implementation/governance/independent-review/moonshot-kimi-k3.v3.json",
    "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
    "implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/historical-evidence-index.v1.json",
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

export const kimiK3ReviewMaterialGovernancePathsV4 = Object.freeze(
  [
    ...new Set([
      ...kimiK3ReviewMaterialGovernancePathsV3,
      "docs/adr/0016-kimi-k3-mfjs-provider-transport-adapter.md",
      "implementation/governance/schemas/independent-model-review-receipt.v6.schema.json",
      "implementation/governance/schemas/independent-review-transport-evidence.v4.schema.json",
      "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v2.schema.json",
      "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json",
    ]),
  ].sort(),
);

export const kimiK3ReviewMaterialGovernancePathsV5 = Object.freeze(
  [
    ...new Set([
      ...kimiK3ReviewMaterialGovernancePathsV4,
      "docs/adr/0017-kimi-k3-explicit-undici-timeout-contract.md",
      "implementation/governance/independent-review/kimi-runtime-manifest.v3.json",
      "implementation/governance/schemas/independent-model-review-receipt.v7.schema.json",
      "implementation/governance/schemas/independent-review-runtime-manifest.v3.schema.json",
      "implementation/governance/schemas/moonshot-kimi-k3-chat-diagnostic-evidence.v3.schema.json",
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-diagnostic-evidence.v3.schema.json",
    ]),
  ].sort(),
);

export const kimiK3ReviewMaterialGovernancePaths =
  kimiK3ReviewMaterialGovernancePathsV5;

export function createKimiK3ModelVisibleProtocolBytes(config) {
  const v3 = config?.schemaVersion === "moonshot-kimi-independent-review-config.v3";
  return Buffer.from(
    JSON.stringify({
      schemaVersion: v3
        ? "moonshot-kimi-k3-model-visible-protocol.v3"
        : "moonshot-kimi-k3-model-visible-protocol.v2",
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
      ...(v3
        ? {
            nonMessageVisibleTokenReserve:
              config.nonMessageVisibleTokenReserve,
            nonMessageVisibleInputMaxUtf8Bytes:
              config.nonMessageVisibleInputMaxUtf8Bytes,
            nonMessageVisibleInputCanonicalization:
              config.nonMessageVisibleInputCanonicalization,
            tokenEstimateCoverage: config.tokenEstimateCoverage,
          }
        : {}),
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
  const v2 =
    config?.schemaVersion === "moonshot-kimi-independent-review-config.v2";
  const v3 =
    config?.schemaVersion === "moonshot-kimi-independent-review-config.v3";
  const officialContract = v3 ? OFFICIAL_CONTRACT_V3 : OFFICIAL_CONTRACT_V2;
  const versionFieldsValid = v3
    ? exactKeys(config, CONFIG_KEYS_V3) &&
      config.nonMessageVisibleTokenReserve === 65_536 &&
      config.nonMessageVisibleInputMaxUtf8Bytes === 16_384 &&
      config.nonMessageVisibleInputCanonicalization ===
        "JSON_UTF8_FIXED_REQUEST_WITHOUT_MESSAGES_V1" &&
      config.tokenEstimateCoverage ===
        "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE" &&
      config.maxReviewMaterialUtf8Bytes === 4_194_304 &&
      config.maxRequestUtf8Bytes === 8_388_608 &&
      config.contextBudgetBasis ===
        "TRANSPORT_RESOURCE_CEILING_ONLY_NOT_CONTEXT_PROOF" &&
      config.pricing?.asOf === "2026-08-01"
    : v2 &&
      exactKeys(config, CONFIG_KEYS_V2) &&
      config.maxReviewMaterialUtf8Bytes === 1_048_576 &&
      config.maxRequestUtf8Bytes === 1_572_864 &&
      config.contextBudgetBasis ===
        "TRANSPORT_DEFENSE_ONLY_NOT_CONTEXT_PROOF" &&
      config.pricing?.asOf === "2026-07-31";
  if (
    !versionFieldsValid ||
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
    config.maxResponseUtf8Bytes !== 1_048_576 ||
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
    canonicalize(config.officialContract) !== canonicalize(officialContract) ||
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
  const officialContract =
    config?.schemaVersion === "moonshot-kimi-independent-review-config.v3"
      ? OFFICIAL_CONTRACT_V3
      : OFFICIAL_CONTRACT_V2;
  const researchValid =
    researchBytes instanceof Uint8Array &&
    sha256Bytes(researchBytes) === officialContract.researchSha256;
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

function canonicalNonMessageVisibleInput(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return null;
  }
  const nonMessageVisibleInput = { ...request };
  delete nonMessageVisibleInput.messages;
  try {
    const bytes = Buffer.from(canonicalize(nonMessageVisibleInput), "utf8");
    return {
      bytes,
      byteLength: bytes.byteLength,
      sha256: sha256Bytes(bytes),
    };
  } catch {
    return null;
  }
}

export async function buildKimiK3IndependentReviewRequest({
  config,
  promptBytes,
  materialBytes,
  outputSchemaBytes,
  enforceProviderTransportSchema = true,
}) {
  const configValidation = await validateMoonshotKimiK3Config(config);
  const transportSchemaValidation =
    enforceProviderTransportSchema === true
      ? validateMoonshotKimiK3TransportSchema(outputSchemaBytes)
      : enforceProviderTransportSchema === false
        ? { ok: true, reasonCodes: [] }
        : {
            ok: false,
            reasonCodes: ["KIMI_K3_PROVIDER_TRANSPORT_SCHEMA_MODE_INVALID"],
          };
  const request = fixedRequest(config, {
    promptBytes,
    materialBytes,
    outputSchemaBytes,
  });
  if (
    !configValidation.ok ||
    !transportSchemaValidation.ok ||
    request === null ||
    !validFixedRequest(request, config)
  ) {
    const error = new TypeError("Kimi K3 fixed request inputs are invalid.");
    error.reasonCodes = [
      ...configValidation.reasonCodes,
      ...transportSchemaValidation.reasonCodes,
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
  const nonMessageVisibleInput = canonicalNonMessageVisibleInput(request);
  if (
    config.schemaVersion === "moonshot-kimi-independent-review-config.v3" &&
    (!nonMessageVisibleInput ||
      nonMessageVisibleInput.byteLength >
        config.nonMessageVisibleInputMaxUtf8Bytes)
  ) {
    const error = new RangeError(
      "Kimi K3 non-message model-visible input exceeds its byte limit.",
    );
    error.reasonCodes = [
      "KIMI_K3_NON_MESSAGE_VISIBLE_INPUT_BYTE_LIMIT_EXCEEDED",
    ];
    throw error;
  }
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
    nonMessageVisibleInputBytes: nonMessageVisibleInput?.bytes ?? null,
    nonMessageVisibleInputByteLength:
      nonMessageVisibleInput?.byteLength ?? null,
    nonMessageVisibleInputSha256: nonMessageVisibleInput?.sha256 ?? null,
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
  const nonMessageVisibleInput = canonicalNonMessageVisibleInput(formal);
  return {
    requestBytes,
    requestSha256: sha256Bytes(requestBytes),
    messagesSha256: sha256Bytes(messagesBytes),
    coverage:
      config.schemaVersion === "moonshot-kimi-independent-review-config.v3"
        ? "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE"
        : "MESSAGES_ONLY",
    nonMessageVisibleInputByteLength:
      nonMessageVisibleInput?.byteLength ?? null,
    nonMessageVisibleInputSha256: nonMessageVisibleInput?.sha256 ?? null,
  };
}

export function evaluateKimiK3SingleCallPreflight({
  config,
  estimatedInputTokens,
  estimatedMessageInputTokens,
  estimateCoverage,
  estimateBindingsMatch,
  priceEvidenceCurrent,
  reasoningUsageCoveredByCompletionLimit,
  reasoningUsageCoveredByPublishedOutputPrice,
  estimateBindings,
  expectedBindings,
  pricingObservedAt,
}) {
  if (config?.schemaVersion === "moonshot-kimi-independent-review-config.v3") {
    const safeInteger =
      Number.isSafeInteger(estimatedMessageInputTokens) &&
      estimatedMessageInputTokens >= 0;
    const bindingsShape = [estimateBindings, expectedBindings].every(
      (value) =>
        exactKeys(value, [
          "formalRequestSha256",
          "messagesSha256",
          "materialSha256",
          "nonMessageVisibleInputSha256",
          "nonMessageVisibleInputByteLength",
        ]) &&
        [
          value.formalRequestSha256,
          value.messagesSha256,
          value.materialSha256,
          value.nonMessageVisibleInputSha256,
        ].every((digest) => SHA256.test(digest ?? "")) &&
        Number.isSafeInteger(value.nonMessageVisibleInputByteLength) &&
        value.nonMessageVisibleInputByteLength > 0 &&
        value.nonMessageVisibleInputByteLength <=
          config.nonMessageVisibleInputMaxUtf8Bytes,
    );
    const exactBindings =
      bindingsShape &&
      canonicalize(estimateBindings) === canonicalize(expectedBindings);
    const priceEvidenceCurrent =
      typeof pricingObservedAt === "string" &&
      Number.isFinite(Date.parse(pricingObservedAt)) &&
      new Date(pricingObservedAt).toISOString() === pricingObservedAt &&
      pricingObservedAt.slice(0, 10) === config.pricing.asOf;
    const requiredContextTokens = safeInteger
      ? estimatedMessageInputTokens +
        config.nonMessageVisibleTokenReserve +
        config.maxCompletionTokens +
        config.safetyMarginTokens
      : null;
    const worstCaseInputCostMicros = safeInteger
      ? ceilDiv(
          (estimatedMessageInputTokens +
            config.nonMessageVisibleTokenReserve) *
            config.pricing.cacheMissInputMicrosPerMillion,
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
      estimateCoverage === config.tokenEstimateCoverage &&
      exactBindings &&
      priceEvidenceCurrent &&
      requiredContextTokens <= config.contextWindowTokens &&
      worstCaseTotalCostMicros <= config.taxExclusiveBudgetMicros;
    return {
      ok,
      status: ok ? "READY" : "BLOCKED",
      reasonCodes: ok ? [] : ["KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED"],
      estimatedMessageInputTokens: safeInteger
        ? estimatedMessageInputTokens
        : null,
      nonMessageVisibleTokenReserve: config.nonMessageVisibleTokenReserve,
      requiredContextTokens,
      worstCaseInputCostMicros,
      worstCaseOutputCostMicros,
      worstCaseTotalCostMicros,
    };
  }
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

const TOKEN_ESTIMATE_DIAGNOSTIC_SCHEMA_VERSION =
  "moonshot-kimi-k3-token-estimate-diagnostic-evidence.v1";
const TOKEN_ESTIMATE_DIAGNOSTIC_SCHEMA_VERSION_V2 =
  "moonshot-kimi-k3-token-estimate-diagnostic-evidence.v2";
const TOKEN_ESTIMATE_DIAGNOSTIC_SCHEMA_VERSION_V3 =
  "moonshot-kimi-k3-token-estimate-diagnostic-evidence.v3";
const TOKEN_ESTIMATE_ENDPOINT =
  "https://api.moonshot.ai/v1/tokenizers/estimate-token-count";
const APPLICATION_DECODED_BYTES = "APPLICATION_LAYER_DECODED_BYTES";

function emptyTransportDiagnostic(overrides = {}) {
  return {
    responseReceived: false,
    httpStatus: null,
    contentType: null,
    contentEncoding: null,
    contentTypeObservedValid: null,
    contentEncodingObservedValid: null,
    responseEndpointMatched: null,
    bodyRepresentation: APPLICATION_DECODED_BYTES,
    responseBodyComplete: null,
    responseBodyByteLength: null,
    responseBodySha256: null,
    jsonParsed: false,
    schemaValidated: false,
    semanticValidated: false,
    failureStage: "TRANSPORT",
    reasonCode: "KIMI_K3_TRANSPORT_NETWORK_FAILED",
    ...overrides,
  };
}

function transportFailure(
  reasonCodes,
  networkAttemptCount,
  diagnostic = emptyTransportDiagnostic({ reasonCode: reasonCodes[0] }),
  responseBytes = null,
) {
  return {
    ok: false,
    status: "BLOCKED",
    reasonCodes: [...new Set(reasonCodes)].sort(),
    networkAttemptCount,
    diagnostic,
    responseBytes,
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

const SENSITIVE_VALUE_TEXT =
  /\b(?:bearer|basic)\s+[a-z0-9._~+\-/]+=*|\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b|\b(?:authorization|cookies?|api[_-]?keys?|access[_-]?tokens?|refresh[_-]?tokens?|tokens?|credentials?|secrets?|passwords?|emails?|request[_-]?headers?)\s*[:=]\s*\S+/iu;
const SENSITIVE_JSON_KEY_WORD =
  /^(?:authorization|cookies?|tokens?|credentials?|secrets?|passwords?|emails?)$/u;
const SAFE_JSON_KEYS = new Set([
  "cached_tokens",
  "completion_tokens",
  "prompt_tokens",
  "total_tokens",
]);

function isSensitiveJsonKey(key) {
  if (typeof key !== "string") return false;
  if (SAFE_JSON_KEYS.has(key)) return false;
  const normalized = key
    .normalize("NFKC")
    .replace(/([a-z0-9])([A-Z])/gu, "$1_$2")
    .toLowerCase();
  const words = normalized.split(/[^a-z0-9]+/u).filter(Boolean);
  if (words.some((word) => SENSITIVE_JSON_KEY_WORD.test(word))) return true;
  const collapsed = words.join("");
  return (
    /(?:authorization|cookies?|tokens?|credentials?|secrets?|passwords?|emails?)/u.test(
      collapsed,
    ) ||
    /(?:api|private)key/u.test(collapsed) ||
    /requestheaders?/u.test(collapsed) ||
    /^(?:account|user|tenant)id$/u.test(collapsed)
  );
}

function textContainsSensitiveMaterial(text) {
  if (SENSITIVE_VALUE_TEXT.test(text)) return true;
  for (const match of text.matchAll(/"((?:\\.|[^"\\])*)"\s*:/gu)) {
    if (isSensitiveJsonKey(match[1])) return true;
  }
  return false;
}

function decodedJsonContainsSensitiveMaterial(value, credential) {
  const pending = [value];
  let inspectedValues = 0;
  while (pending.length > 0) {
    inspectedValues += 1;
    if (inspectedValues > 65_536) return true;
    const current = pending.pop();
    if (typeof current === "string") {
      if (
        (typeof credential === "string" &&
          credential.length > 0 &&
          current.includes(credential)) ||
        textContainsSensitiveMaterial(current)
      ) {
        return true;
      }
      continue;
    }
    if (Array.isArray(current)) {
      for (const entry of current) pending.push(entry);
      continue;
    }
    if (current && typeof current === "object") {
      for (const [key, entry] of Object.entries(current)) {
        if (isSensitiveJsonKey(key)) return true;
        pending.push(entry);
      }
    }
  }
  return false;
}

function bytesContainSensitiveMaterial(bytes, credential = null) {
  if (!(bytes instanceof Uint8Array)) return false;
  if (
    typeof credential === "string" &&
    credential.length > 0 &&
    bytesContainCredential(bytes, credential)
  ) {
    return true;
  }
  const text = strictUtf8(bytes);
  if (text === null) return true;
  const unicodeExpanded = text.replace(
    /\\u([a-f0-9]{4})/giu,
    (_match, codePoint) => String.fromCharCode(Number.parseInt(codePoint, 16)),
  );
  const parsed = parseJsonValueBytes(bytes);
  return (
    textContainsSensitiveMaterial(text) ||
    textContainsSensitiveMaterial(unicodeExpanded) ||
    (typeof credential === "string" &&
      credential.length > 0 &&
      unicodeExpanded.includes(credential)) ||
    (parsed.ok &&
      decodedJsonContainsSensitiveMaterial(parsed.value, credential))
  );
}

export function kimiK3TokenEstimateResponseArtifactIsSafe(bytes) {
  return (
    bytes instanceof Uint8Array &&
    !bytesContainSensitiveMaterial(bytes)
  );
}

export function classifyKimiK3V5ContractPresence({
  v4Presence,
  v5AdditivePresence,
}) {
  if (
    !Array.isArray(v4Presence) ||
    v4Presence.length === 0 ||
    !v4Presence.every((value) => typeof value === "boolean") ||
    !Array.isArray(v5AdditivePresence) ||
    v5AdditivePresence.length === 0 ||
    !v5AdditivePresence.every((value) => typeof value === "boolean")
  ) {
    throw new TypeError("Kimi K3 contract presence is invalid.");
  }
  const v4Complete = v4Presence.every(Boolean);
  const v5Any = v5AdditivePresence.some(Boolean);
  if (v5Any) {
    return v4Complete && v5AdditivePresence.every(Boolean)
      ? "K3_V5_COMPLETE"
      : "K3_V5_INCOMPLETE";
  }
  if (v4Complete) return "K3_V4_COMPLETE";
  return v4Presence.some(Boolean) ? "K3_V4_INCOMPLETE" : "NO_V4_OR_V5";
}

function boundedResponseHeader(response, name) {
  let value;
  try {
    value = response?.headers?.get?.(name);
  } catch {
    return { value: null, valid: false };
  }
  if (value === null || value === undefined || value === "") {
    return { value: null, valid: true };
  }
  if (
    typeof value !== "string" ||
    value.length > 256 ||
    !/^[\u0020-\u007e]+$/u.test(value) ||
    /authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|token|credential|secret|password|email|bearer|account[_-]?id|user[_-]?id|tenant[_-]?id|request[_-]?headers/iu.test(
      value,
    )
  ) {
    return { value: null, valid: false };
  }
  const normalized = value.trim().toLowerCase();
  return normalized.length > 0
    ? { value: normalized, valid: true }
    : { value: null, valid: false };
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
      const priorByteLength = byteLength;
      byteLength += current.value.byteLength;
      if (byteLength > maximumBytes) {
        const remaining = Math.max(maximumBytes - priorByteLength, 0);
        const bounded = Buffer.concat(
          [...chunks, Buffer.from(current.value.subarray(0, remaining))],
          maximumBytes,
        );
        try {
          Promise.resolve(
            reader.cancel("Kimi K3 response byte limit exceeded."),
          ).catch(() => {});
        } catch {
          // The byte-limit classification must not be replaced by cancel failure.
        }
        const error = new RangeError("Kimi K3 response byte limit exceeded.");
        error.code = "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED";
        error.capturedResponseBytes = bounded;
        throw error;
      }
      chunks.push(Buffer.from(current.value));
    }
  } catch (error) {
    if (!(error?.capturedResponseBytes instanceof Uint8Array)) {
      error.capturedResponseBytes = Buffer.concat(chunks, byteLength);
    }
    throw error;
  } finally {
    try {
      reader.releaseLock?.();
    } catch {
      // A cleanup failure cannot replace the bounded capture classification.
    }
  }
  return Buffer.concat(chunks, byteLength);
}

function transportErrorIsTimeout(error) {
  const code = error?.code ?? error?.cause?.code;
  return (
    error?.name === "AbortError" ||
    code === "UND_ERR_CONNECT_TIMEOUT" ||
    code === "UND_ERR_HEADERS_TIMEOUT" ||
    code === "UND_ERR_BODY_TIMEOUT"
  );
}

async function closeDispatcherBeforeDeadline(dispatcher, deadline) {
  const remaining = deadline - performance.now();
  if (remaining <= 0) {
    try {
      Promise.resolve(dispatcher.close()).catch(() => {});
    } catch {
      // The result is already fail closed because the deadline elapsed.
    }
    return false;
  }
  let timer;
  try {
    await Promise.race([
      Promise.resolve().then(() => dispatcher.close()),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Kimi K3 dispatcher close timed out.")),
          remaining,
        );
      }),
    ]);
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function postBoundJson({
  url,
  requestBytes,
  apiKey,
  maximumResponseBytes,
  fetchImpl,
  dispatcherFactory = null,
  timeoutMs,
}) {
  if (typeof apiKey !== "string" || apiKey.length < 16) {
    return transportFailure(
      ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
      0,
      emptyTransportDiagnostic({
        failureStage: "CREDENTIAL",
        reasonCode: "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
      }),
    );
  }
  if (
    !(requestBytes instanceof Uint8Array) ||
    bytesContainCredential(requestBytes, apiKey) ||
    typeof fetchImpl !== "function" ||
    (dispatcherFactory !== null && typeof dispatcherFactory !== "function") ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 10 * 60_000
  ) {
    return transportFailure(
      ["KIMI_K3_TRANSPORT_CONFIGURATION_INVALID"],
      0,
      emptyTransportDiagnostic({
        failureStage: "REQUEST_BINDING",
        reasonCode: "KIMI_K3_TRANSPORT_CONFIGURATION_INVALID",
      }),
    );
  }
  const deadline = performance.now() + timeoutMs;
  let dispatcher = null;
  if (dispatcherFactory !== null) {
    try {
      dispatcher = dispatcherFactory();
    } catch {
      dispatcher = null;
    }
    if (
      dispatcher === null ||
      typeof dispatcher?.dispatch !== "function" ||
      typeof dispatcher?.close !== "function"
    ) {
      return transportFailure(
        ["KIMI_K3_TRANSPORT_CONFIGURATION_INVALID"],
        0,
        emptyTransportDiagnostic({
          failureStage: "REQUEST_BINDING",
          reasonCode: "KIMI_K3_TRANSPORT_CONFIGURATION_INVALID",
        }),
      );
    }
  }
  const remainingTransportTime = Math.floor(deadline - performance.now());
  if (remainingTransportTime <= 0) {
    if (dispatcher !== null) {
      await closeDispatcherBeforeDeadline(dispatcher, deadline);
    }
    return transportFailure(
      ["KIMI_K3_TRANSPORT_TIMEOUT"],
      0,
      emptyTransportDiagnostic({ reasonCode: "KIMI_K3_TRANSPORT_TIMEOUT" }),
    );
  }
  let result;
  try {
    result = await postBoundJsonWithDispatcher({
      url,
      requestBytes,
      apiKey,
      maximumResponseBytes,
      fetchImpl,
      dispatcher,
      timeoutMs: remainingTransportTime,
    });
  } catch {
    result = transportFailure(
      ["KIMI_K3_TRANSPORT_NETWORK_FAILED"],
      1,
      emptyTransportDiagnostic({
        reasonCode: "KIMI_K3_TRANSPORT_NETWORK_FAILED",
      }),
    );
  }
  if (dispatcher !== null) {
    const closed = await closeDispatcherBeforeDeadline(dispatcher, deadline);
    if (!closed && result.ok === true) {
      return { ...result, postResponseCleanupFailed: true };
    }
  }
  return result;
}

async function postBoundJsonWithDispatcher({
  url,
  requestBytes,
  apiKey,
  maximumResponseBytes,
  fetchImpl,
  dispatcher,
  timeoutMs,
}) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new DOMException("Kimi K3 transport timed out.", "AbortError"));
    }, timeoutMs);
  });
  let response;
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
        ...(dispatcher === null ? {} : { dispatcher }),
      }),
      timeout,
    ]);
  } catch (error) {
    clearTimeout(timer);
    const reasonCode = transportErrorIsTimeout(error)
      ? "KIMI_K3_TRANSPORT_TIMEOUT"
      : "KIMI_K3_TRANSPORT_NETWORK_FAILED";
    return transportFailure(
      [reasonCode],
      1,
      emptyTransportDiagnostic({ reasonCode }),
    );
  }
  const contentType = boundedResponseHeader(response, "content-type");
  const contentEncoding = boundedResponseHeader(
    response,
    "content-encoding",
  );
  let responseEndpointMatched = false;
  try {
    responseEndpointMatched =
      response?.redirected === false && response?.url === url;
  } catch {
    responseEndpointMatched = false;
  }
  const responseMetadata = {
    responseReceived: true,
    httpStatus: Number.isInteger(response?.status) ? response.status : null,
    contentType: contentType.value,
    contentEncoding: contentEncoding.value,
    contentTypeObservedValid: contentType.valid,
    contentEncodingObservedValid: contentEncoding.valid,
    responseEndpointMatched,
  };
  let responseBytes;
  try {
    responseBytes = await readBoundedResponseBytes({
      response,
      maximumBytes: maximumResponseBytes,
      timeout,
    });
  } catch (error) {
    const captured =
      error?.capturedResponseBytes instanceof Uint8Array
        ? error.capturedResponseBytes
        : Buffer.alloc(0);
    const reasonCode =
      error?.code === "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED"
        ? error.code
        : transportErrorIsTimeout(error)
          ? "KIMI_K3_TRANSPORT_TIMEOUT"
          : "KIMI_K3_RESPONSE_BYTES_UNAVAILABLE";
    return transportFailure(
      [reasonCode],
      1,
      emptyTransportDiagnostic({
        ...responseMetadata,
        responseBodyComplete: false,
        responseBodyByteLength: captured.byteLength,
        responseBodySha256: sha256Bytes(captured),
        failureStage: "BODY_CAPTURE",
        reasonCode,
      }),
    );
  } finally {
    clearTimeout(timer);
  }
  const capturedDiagnostic = emptyTransportDiagnostic({
    ...responseMetadata,
    responseBodyComplete: true,
    responseBodyByteLength: responseBytes.byteLength,
    responseBodySha256: sha256Bytes(responseBytes),
    failureStage: null,
    reasonCode: null,
  });
  if (!responseEndpointMatched) {
    return transportFailure(
      ["KIMI_K3_RESPONSE_ENDPOINT_MISMATCH"],
      1,
      {
        ...capturedDiagnostic,
        failureStage: "RESPONSE_ENDPOINT",
        reasonCode: "KIMI_K3_RESPONSE_ENDPOINT_MISMATCH",
      },
    );
  }
  if (bytesContainSensitiveMaterial(responseBytes, apiKey)) {
    return transportFailure(
      ["KIMI_K3_RESPONSE_CREDENTIAL_ECHOED"],
      1,
      {
        ...capturedDiagnostic,
        failureStage: "BODY_CAPTURE",
        reasonCode: "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED",
      },
    );
  }
  return {
    ok: true,
    status: "CAPTURED",
    reasonCodes: [],
    networkAttemptCount: 1,
    diagnostic: capturedDiagnostic,
    metadataValidity: {
      contentType: contentType.valid,
      contentEncoding: contentEncoding.valid,
    },
    responseBytes,
    responseSha256: capturedDiagnostic.responseBodySha256,
  };
}

export async function executeKimiK3TokenEstimate({
  config,
  estimateRequestBytes,
  formalRequestBytes,
  materialBytes,
  apiKey,
  fetchImpl,
  dispatcherFactory = null,
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
      emptyTransportDiagnostic({
        failureStage: "REQUEST_BINDING",
        reasonCode: "KIMI_K3_TOKEN_ESTIMATE_BINDING_MISMATCH",
      }),
    );
  }
  const transport = await postBoundJson({
    url: `${config.baseURL}${config.tokenEstimateEndpoint}`,
    requestBytes: estimateRequestBytes,
    apiKey,
    maximumResponseBytes: 64 * 1024,
    fetchImpl,
    dispatcherFactory,
    timeoutMs,
  });
  if (!transport.ok) return transport;
  const parsed = parseJsonValueBytes(transport.responseBytes);
  const body = parsed.value;
  const jsonParsed = parsed.ok;
  const responseValidation = validateKimiK3TokenEstimateResponseBody(body, {
    enveloped:
      config.schemaVersion === "moonshot-kimi-independent-review-config.v3",
  });
  const { schemaValidated } = responseValidation;
  const semanticValidated =
    responseValidation.semanticValidated && !containsCredential(body, apiKey);
  const contentTypeValid =
    transport.metadataValidity.contentType &&
    typeof transport.diagnostic.contentType === "string" &&
    /^application\/json(?:;\s*charset=utf-8)?$/iu.test(
      transport.diagnostic.contentType,
    );
  const contentEncodingValid =
    transport.metadataValidity.contentEncoding &&
    [null, "identity"].includes(transport.diagnostic.contentEncoding);
  let failureStage = null;
  let reasonCode = null;
  if (transport.diagnostic.httpStatus !== 200) {
    failureStage = "HTTP_STATUS";
    reasonCode = [401, 402, 403, 429].includes(
      transport.diagnostic.httpStatus,
    )
      ? "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"
      : "KIMI_K3_RESPONSE_HTTP_INVALID";
  } else if (!contentTypeValid) {
    failureStage = "RESPONSE_METADATA";
    reasonCode = "KIMI_K3_RESPONSE_CONTENT_TYPE_INVALID";
  } else if (!contentEncodingValid) {
    failureStage = "RESPONSE_METADATA";
    reasonCode = "KIMI_K3_RESPONSE_CONTENT_ENCODING_INVALID";
  } else if (transport.responseBytes.byteLength === 0) {
    failureStage = "BODY_CAPTURE";
    reasonCode = "KIMI_K3_RESPONSE_BYTES_UNAVAILABLE";
  } else if (!jsonParsed) {
    failureStage = "JSON_PARSE";
    reasonCode = "KIMI_K3_TOKEN_ESTIMATE_JSON_INVALID";
  } else if (!schemaValidated) {
    failureStage = "SCHEMA_VALIDATION";
    reasonCode = "KIMI_K3_TOKEN_ESTIMATE_RESPONSE_SCHEMA_INVALID";
  } else if (!semanticValidated) {
    failureStage = "SEMANTIC_VALIDATION";
    reasonCode = "KIMI_K3_TOKEN_ESTIMATE_RESPONSE_SEMANTIC_INVALID";
  } else if (transport.postResponseCleanupFailed === true) {
    failureStage = "POST_RESPONSE_CLEANUP";
    reasonCode = "KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED";
  }
  const diagnostic = {
    ...transport.diagnostic,
    jsonParsed:
      config.schemaVersion === "moonshot-kimi-independent-review-config.v3"
        ? jsonParsed
        : failureStage === null && jsonParsed,
    schemaValidated:
      config.schemaVersion === "moonshot-kimi-independent-review-config.v3"
        ? schemaValidated
        : failureStage === null && schemaValidated,
    semanticValidated:
      config.schemaVersion === "moonshot-kimi-independent-review-config.v3"
        ? semanticValidated
        : failureStage === null && semanticValidated,
    failureStage,
    reasonCode,
  };
  if (failureStage !== null) {
    return transportFailure(
      [reasonCode],
      1,
      diagnostic,
      config.schemaVersion === "moonshot-kimi-independent-review-config.v3"
        ? transport.responseBytes
        : null,
    );
  }
  return {
    ...transport,
    diagnostic,
    httpStatus: diagnostic.httpStatus,
    contentType: diagnostic.contentType,
    estimatedInputTokens: responseValidation.estimatedInputTokens,
    estimateRequestSha256: sha256Bytes(estimateRequestBytes),
    formalRequestSha256: sha256Bytes(formalRequestBytes),
    messagesSha256: expected.messagesSha256,
    materialSha256: sha256Bytes(materialBytes),
    coverage: expected.coverage,
    nonMessageVisibleInputByteLength:
      expected.nonMessageVisibleInputByteLength,
    nonMessageVisibleInputSha256: expected.nonMessageVisibleInputSha256,
  };
}

export async function executeKimiK3ChatCompletion({
  config,
  formalRequestBytes,
  providerTransportSchemaBytes,
  canonicalOutputSchemaBytes,
  enforceProviderTransportSchema = true,
  apiKey,
  fetchImpl,
  dispatcherFactory = null,
  timeoutMs = 10 * 60_000,
}) {
  const configValidation = await validateMoonshotKimiK3Config(config);
  const formalRequest = parseJsonBytes(formalRequestBytes);
  const providerTransportSchema = parseJsonBytes(
    providerTransportSchemaBytes,
  );
  const canonicalOutputSchema = parseJsonBytes(canonicalOutputSchemaBytes);
  const providerTransportSchemaValidation =
    enforceProviderTransportSchema === true
      ? validateMoonshotKimiK3TransportSchema(providerTransportSchemaBytes)
      : enforceProviderTransportSchema === false
        ? { ok: true, reasonCodes: [] }
        : {
            ok: false,
            reasonCodes: ["KIMI_K3_PROVIDER_TRANSPORT_SCHEMA_MODE_INVALID"],
          };
  if (
    !configValidation.ok ||
    config?.schemaVersion !== "moonshot-kimi-independent-review-config.v3" ||
    !validFixedRequest(formalRequest, config) ||
    !(formalRequestBytes instanceof Uint8Array) ||
    formalRequestBytes.byteLength > config.maxRequestUtf8Bytes ||
    !providerTransportSchemaValidation.ok ||
    providerTransportSchema === null ||
    canonicalOutputSchema === null ||
    canonicalize(formalRequest?.response_format?.json_schema?.schema) !==
      canonicalize(providerTransportSchema)
  ) {
    return transportFailure(
      [
        ...configValidation.reasonCodes,
        ...providerTransportSchemaValidation.reasonCodes,
        "KIMI_K3_CHAT_REQUEST_BINDING_MISMATCH",
      ],
      0,
      emptyTransportDiagnostic({
        failureStage: "REQUEST_BINDING",
        reasonCode: "KIMI_K3_CHAT_REQUEST_BINDING_MISMATCH",
      }),
    );
  }
  const transport = await postBoundJson({
    url: `${config.baseURL}${config.endpoint}`,
    requestBytes: formalRequestBytes,
    apiKey,
    maximumResponseBytes: config.maxResponseUtf8Bytes,
    fetchImpl,
    dispatcherFactory,
    timeoutMs,
  });
  if (!transport.ok) return transport;
  const contentTypeValid =
    transport.metadataValidity.contentType &&
    /^application\/json(?:;\s*charset=utf-8)?$/iu.test(
      transport.diagnostic.contentType ?? "",
    );
  const contentEncodingValid =
    transport.metadataValidity.contentEncoding &&
    [null, "identity"].includes(transport.diagnostic.contentEncoding);
  if (
    transport.diagnostic.httpStatus !== 200 ||
    !contentTypeValid ||
    !contentEncodingValid
  ) {
    const reasonCode =
      transport.diagnostic.httpStatus !== 200
        ? "KIMI_K3_RESPONSE_HTTP_INVALID"
        : !contentTypeValid
          ? "KIMI_K3_RESPONSE_CONTENT_TYPE_INVALID"
          : "KIMI_K3_RESPONSE_CONTENT_ENCODING_INVALID";
    return transportFailure(
      [reasonCode],
      1,
      {
        ...transport.diagnostic,
        failureStage:
          transport.diagnostic.httpStatus !== 200
            ? "HTTP_STATUS"
            : "RESPONSE_METADATA",
        reasonCode,
      },
      transport.responseBytes,
    );
  }
  const validation = await validateKimiK3ChatResponse({
    config,
    responseBytes: transport.responseBytes,
    providerTransportSchemaBytes,
    canonicalOutputSchemaBytes,
    enforceProviderTransportSchema,
  });
  if (!validation.ok) {
    return transportFailure(
      validation.reasonCodes,
      1,
      {
        ...transport.diagnostic,
        failureStage: "SCHEMA_OR_SEMANTIC_VALIDATION",
        reasonCode: validation.reasonCodes[0],
      },
      transport.responseBytes,
    );
  }
  if (transport.postResponseCleanupFailed === true) {
    return transportFailure(
      ["KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED"],
      1,
      {
        ...transport.diagnostic,
        failureStage: "POST_RESPONSE_CLEANUP",
        reasonCode: "KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED",
      },
      transport.responseBytes,
    );
  }
  return {
    ...transport,
    ...validation,
    httpStatus: transport.diagnostic.httpStatus,
    contentType: transport.diagnostic.contentType,
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

const TOKEN_ESTIMATE_DIAGNOSTIC_KEYS = [
  "schemaVersion",
  "requestSha256",
  "messagesSha256",
  "reviewMaterialSha256",
  "sourceCommit",
  "requestedModel",
  "endpoint",
  "responseReceived",
  "httpStatus",
  "contentType",
  "contentEncoding",
  "contentTypeObservedValid",
  "contentEncodingObservedValid",
  "responseEndpointMatched",
  "bodyRepresentation",
  "responseBodyByteLength",
  "responseBodySha256",
  "responseArtifact",
  "jsonParsed",
  "schemaValidated",
  "semanticValidated",
  "failureStage",
  "reasonCode",
  "recordedAt",
  "evidenceSha256",
];
const TOKEN_ESTIMATE_DIAGNOSTIC_KEYS_V2 = [
  ...TOKEN_ESTIMATE_DIAGNOSTIC_KEYS.slice(0, 15),
  "responseBodyComplete",
  ...TOKEN_ESTIMATE_DIAGNOSTIC_KEYS.slice(15),
];
const TOKEN_ESTIMATE_DIAGNOSTIC_REASONS = Object.freeze({
  REQUEST_BINDING: [
    "KIMI_K3_TOKEN_ESTIMATE_BINDING_MISMATCH",
    "KIMI_K3_TRANSPORT_CONFIGURATION_INVALID",
  ],
  CREDENTIAL: ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
  TRANSPORT: [
    "KIMI_K3_TRANSPORT_NETWORK_FAILED",
    "KIMI_K3_TRANSPORT_TIMEOUT",
  ],
  RESPONSE_ENDPOINT: ["KIMI_K3_RESPONSE_ENDPOINT_MISMATCH"],
  HTTP_STATUS: [
    "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED",
    "KIMI_K3_RESPONSE_HTTP_INVALID",
  ],
  RESPONSE_METADATA: [
    "KIMI_K3_RESPONSE_CONTENT_TYPE_INVALID",
    "KIMI_K3_RESPONSE_CONTENT_ENCODING_INVALID",
  ],
  BODY_CAPTURE: [
    "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED",
    "KIMI_K3_RESPONSE_BYTES_UNAVAILABLE",
    "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED",
    "KIMI_K3_TRANSPORT_TIMEOUT",
  ],
  JSON_PARSE: ["KIMI_K3_TOKEN_ESTIMATE_JSON_INVALID"],
  SCHEMA_VALIDATION: [
    "KIMI_K3_TOKEN_ESTIMATE_RESPONSE_SCHEMA_INVALID",
  ],
  SEMANTIC_VALIDATION: [
    "KIMI_K3_TOKEN_ESTIMATE_RESPONSE_SEMANTIC_INVALID",
  ],
});

function tokenEstimateDiagnosticEvidenceDigest(evidence) {
  return sha256Value({
    ...evidence,
    evidenceSha256: EVIDENCE_SHA_PLACEHOLDER,
  });
}

export function createKimiK3TokenEstimateDiagnosticEvidence({
  requestSha256,
  messagesSha256,
  reviewMaterialSha256,
  sourceCommit,
  requestedModel,
  endpoint,
  diagnostic,
  responseArtifact,
  recordedAt,
}) {
  const evidence = {
    schemaVersion: TOKEN_ESTIMATE_DIAGNOSTIC_SCHEMA_VERSION,
    requestSha256,
    messagesSha256,
    reviewMaterialSha256,
    sourceCommit,
    requestedModel,
    endpoint,
    responseReceived: diagnostic?.responseReceived ?? false,
    httpStatus: diagnostic?.httpStatus ?? null,
    contentType: diagnostic?.contentType ?? null,
    contentEncoding: diagnostic?.contentEncoding ?? null,
    contentTypeObservedValid:
      diagnostic?.contentTypeObservedValid ?? null,
    contentEncodingObservedValid:
      diagnostic?.contentEncodingObservedValid ?? null,
    responseEndpointMatched:
      diagnostic?.responseEndpointMatched ?? null,
    bodyRepresentation:
      diagnostic?.bodyRepresentation ?? APPLICATION_DECODED_BYTES,
    responseBodyByteLength:
      diagnostic?.responseBodyByteLength ?? null,
    responseBodySha256: diagnostic?.responseBodySha256 ?? null,
    responseArtifact: responseArtifact ?? null,
    jsonParsed: diagnostic?.jsonParsed ?? false,
    schemaValidated: diagnostic?.schemaValidated ?? false,
    semanticValidated: diagnostic?.semanticValidated ?? false,
    failureStage: diagnostic?.failureStage ?? null,
    reasonCode: diagnostic?.reasonCode ?? null,
    recordedAt,
    evidenceSha256: EVIDENCE_SHA_PLACEHOLDER,
  };
  evidence.evidenceSha256 = tokenEstimateDiagnosticEvidenceDigest(evidence);
  return evidence;
}

function validTokenEstimateDiagnosticCause(evidence) {
  const stage = evidence?.failureStage;
  const reason = evidence?.reasonCode;
  const received = evidence?.responseReceived === true;
  if (!received) {
    return ["REQUEST_BINDING", "CREDENTIAL", "TRANSPORT"].includes(stage);
  }
  if (
    ["REQUEST_BINDING", "CREDENTIAL", "TRANSPORT"].includes(stage) ||
    typeof evidence?.responseEndpointMatched !== "boolean" ||
    typeof evidence?.contentTypeObservedValid !== "boolean" ||
    typeof evidence?.contentEncodingObservedValid !== "boolean"
  ) {
    return false;
  }
  if (stage === "RESPONSE_ENDPOINT") {
    return evidence.responseEndpointMatched === false;
  }
  if (
    stage !== "BODY_CAPTURE" &&
    evidence.responseEndpointMatched === false
  ) {
    return false;
  }
  if (stage === "HTTP_STATUS") {
    if (evidence.httpStatus === 200) return false;
    return [401, 402, 403, 429].includes(evidence.httpStatus)
      ? reason === "KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"
      : reason === "KIMI_K3_RESPONSE_HTTP_INVALID";
  }
  const contentTypeValid =
    evidence.contentTypeObservedValid === true &&
    /^application\/json(?:;\s*charset=utf-8)?$/iu.test(
      evidence.contentType ?? "",
    );
  const contentEncodingValid =
    evidence.contentEncodingObservedValid === true &&
    [null, "identity"].includes(evidence.contentEncoding);
  if (stage === "RESPONSE_METADATA") {
    return (
      evidence.httpStatus === 200 &&
      evidence.responseEndpointMatched === true &&
      (reason === "KIMI_K3_RESPONSE_CONTENT_TYPE_INVALID"
        ? !contentTypeValid
        : contentTypeValid && !contentEncodingValid)
    );
  }
  if (stage === "BODY_CAPTURE") {
    if (reason === "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED") {
      return (
        evidence.responseEndpointMatched === true &&
        evidence.responseBodyByteLength > 0
      );
    }
    return [
      "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED",
      "KIMI_K3_RESPONSE_BYTES_UNAVAILABLE",
      "KIMI_K3_TRANSPORT_TIMEOUT",
    ].includes(reason);
  }
  if (
    evidence.httpStatus !== 200 ||
    evidence.responseEndpointMatched !== true ||
    !contentTypeValid ||
    !contentEncodingValid
  ) {
    return false;
  }
  return [
    null,
    "JSON_PARSE",
    "SCHEMA_VALIDATION",
    "SEMANTIC_VALIDATION",
  ].includes(stage);
}

export function validateKimiK3TokenEstimateDiagnosticEvidence({
  evidence,
  requestSha256,
  messagesSha256,
  reviewMaterialSha256,
  sourceCommit,
  requestedModel,
  endpoint,
  diagnostic,
  responseArtifact,
  recordedAt,
  responseArtifactBytes = null,
}) {
  let expected = null;
  try {
    expected = createKimiK3TokenEstimateDiagnosticEvidence({
      requestSha256,
      messagesSha256,
      reviewMaterialSha256,
      sourceCommit,
      requestedModel,
      endpoint,
      diagnostic,
      responseArtifact,
      recordedAt,
    });
  } catch {
    expected = null;
  }
  const responseReceived = evidence?.responseReceived === true;
  const bodyCaptured = Number.isSafeInteger(
    evidence?.responseBodyByteLength,
  );
  const artifactBound = typeof evidence?.responseArtifact === "string";
  const artifactJson = artifactBound
    ? parseJsonValueBytes(responseArtifactBytes)
    : { ok: false, value: null };
  const artifactSchemaValid =
    artifactJson.ok &&
    exactKeys(artifactJson.value, ["data"]) &&
    exactKeys(artifactJson.value?.data, ["total_tokens"]) &&
    Number.isSafeInteger(artifactJson.value.data.total_tokens);
  const artifactSemanticValid =
    artifactSchemaValid && artifactJson.value.data.total_tokens >= 0;
  const artifactBytesValid = artifactBound
    ? responseArtifactBytes instanceof Uint8Array &&
      responseArtifactBytes.byteLength ===
        evidence.responseBodyByteLength &&
      sha256Bytes(responseArtifactBytes) === evidence.responseBodySha256
    : responseArtifactBytes === null;
  const failurePairValid =
    (evidence?.failureStage === null && evidence?.reasonCode === null) ||
    (typeof evidence?.failureStage === "string" &&
      TOKEN_ESTIMATE_DIAGNOSTIC_REASONS[
        evidence.failureStage
      ]?.includes(evidence.reasonCode));
  const missingResponseValid = responseReceived
    ? Number.isInteger(evidence?.httpStatus) &&
      evidence.httpStatus >= 100 &&
      evidence.httpStatus <= 599 &&
      typeof evidence?.contentTypeObservedValid === "boolean" &&
      typeof evidence?.contentEncodingObservedValid === "boolean" &&
      typeof evidence?.responseEndpointMatched === "boolean" &&
      bodyCaptured
    : evidence?.httpStatus === null &&
      evidence?.contentType === null &&
      evidence?.contentEncoding === null &&
      evidence?.contentTypeObservedValid === null &&
      evidence?.contentEncodingObservedValid === null &&
      evidence?.responseEndpointMatched === null &&
      evidence?.responseBodyByteLength === null &&
      evidence?.responseBodySha256 === null &&
      evidence?.responseArtifact === null &&
      evidence?.jsonParsed === false &&
      evidence?.schemaValidated === false &&
      evidence?.semanticValidated === false &&
      ["REQUEST_BINDING", "CREDENTIAL", "TRANSPORT"].includes(
        evidence?.failureStage,
      );
  const bodyBindingValid = bodyCaptured
    ? evidence.responseBodyByteLength >= 0 &&
      evidence.responseBodyByteLength <= 64 * 1024 &&
      SHA256.test(evidence?.responseBodySha256 ?? "") &&
      (evidence?.failureStage === null ? artifactBound : !artifactBound)
    : evidence?.responseBodySha256 === null &&
      evidence?.responseArtifact === null &&
      [
        "REQUEST_BINDING",
        "CREDENTIAL",
        "TRANSPORT",
        "RESPONSE_ENDPOINT",
        "BODY_CAPTURE",
      ].includes(evidence?.failureStage);
  const validationOrderValid =
    (evidence?.failureStage === null
      ? evidence?.jsonParsed === true &&
        evidence?.schemaValidated === true &&
        evidence?.semanticValidated === true
      : evidence?.jsonParsed === false &&
        evidence?.schemaValidated === false &&
        evidence?.semanticValidated === false) &&
    (!evidence?.semanticValidated || evidence?.schemaValidated) &&
    (!evidence?.schemaValidated || evidence?.jsonParsed);
  const successValid =
    evidence?.failureStage !== null ||
    (responseReceived &&
      evidence.httpStatus === 200 &&
      /^application\/json(?:;\s*charset=utf-8)?$/iu.test(
        evidence.contentType ?? "",
      ) &&
      [null, "identity"].includes(evidence.contentEncoding) &&
      artifactBound &&
      artifactJson.ok &&
      artifactSchemaValid &&
      artifactSemanticValid &&
      evidence.jsonParsed === artifactJson.ok &&
      evidence.schemaValidated === artifactSchemaValid &&
      evidence.semanticValidated === artifactSemanticValid);
  const diagnosticHeadersValid = [
    evidence?.contentType,
    evidence?.contentEncoding,
  ].every(
    (value) =>
      value === null ||
      (typeof value === "string" &&
        value.length <= 256 &&
        /^[\u0020-\u007e]+$/u.test(value) &&
        !/authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|token|credential|secret|password|email|bearer|account[_-]?id|user[_-]?id|tenant[_-]?id|request[_-]?headers/iu.test(
          value,
        )),
  );
  const valid =
    expected !== null &&
    exactKeys(evidence, TOKEN_ESTIMATE_DIAGNOSTIC_KEYS) &&
    SHA256.test(evidence?.requestSha256 ?? "") &&
    SHA256.test(evidence?.messagesSha256 ?? "") &&
    SHA256.test(evidence?.reviewMaterialSha256 ?? "") &&
    COMMIT.test(evidence?.sourceCommit ?? "") &&
    evidence?.requestedModel === "kimi-k3" &&
    evidence?.endpoint === TOKEN_ESTIMATE_ENDPOINT &&
    evidence?.bodyRepresentation === APPLICATION_DECODED_BYTES &&
    diagnosticHeadersValid &&
    (evidence?.responseArtifact === null ||
      SAFE_PATH.test(evidence.responseArtifact)) &&
    validDate(evidence?.recordedAt) &&
    missingResponseValid &&
    bodyBindingValid &&
    validationOrderValid &&
    failurePairValid &&
    validTokenEstimateDiagnosticCause(evidence) &&
    successValid &&
    artifactBytesValid &&
    canonicalize(evidence) === canonicalize(expected) &&
    tokenEstimateDiagnosticEvidenceDigest(evidence) ===
      evidence.evidenceSha256;
  return {
    ok: valid,
    reasonCodes: valid
      ? []
      : ["KIMI_K3_TOKEN_ESTIMATE_DIAGNOSTIC_EVIDENCE_INVALID"],
  };
}

export function createKimiK3TokenEstimateDiagnosticArtifacts({
  responseBytes = null,
  ...input
}) {
  const responseArtifact =
    input.diagnostic?.failureStage === null &&
    responseBytes instanceof Uint8Array
      ? "token-estimate-diagnostic-response.bin"
      : null;
  const evidence = createKimiK3TokenEstimateDiagnosticEvidence({
    ...input,
    responseArtifact,
  });
  const validation = validateKimiK3TokenEstimateDiagnosticEvidence({
    ...input,
    evidence,
    responseArtifact,
    responseArtifactBytes: responseArtifact === null ? null : responseBytes,
  });
  if (!validation.ok) {
    throw new TypeError(
      "Kimi K3 Token Estimate diagnostic evidence is invalid.",
    );
  }
  const artifacts = {
    "token-estimate-diagnostic-evidence.json": Buffer.from(
      JSON.stringify(evidence),
      "utf8",
    ),
  };
  if (responseArtifact !== null) {
    artifacts[responseArtifact] = Buffer.from(responseBytes);
  }
  return { evidence, artifacts };
}

function tokenEstimateDiagnosticResponseCanBePersisted({
  diagnostic,
  responseBytes,
}) {
  return (
    responseBytes instanceof Uint8Array &&
    diagnostic?.responseReceived === true &&
    diagnostic?.responseEndpointMatched === true &&
    diagnostic?.responseBodyByteLength === responseBytes.byteLength &&
    diagnostic?.responseBodySha256 === sha256Bytes(responseBytes) &&
    !bytesContainSensitiveMaterial(responseBytes) &&
    tokenEstimateDiagnosticRequiresResponseArtifact(diagnostic)
  );
}

function tokenEstimateDiagnosticRequiresResponseArtifact(diagnostic) {
  if (
    diagnostic?.responseReceived !== true ||
    diagnostic?.responseEndpointMatched !== true ||
    diagnostic?.responseBodyComplete !== true ||
    diagnostic?.reasonCode === "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED"
  ) {
    return false;
  }
  if (
    diagnostic.failureStage === null ||
    [
      "HTTP_STATUS",
      "RESPONSE_METADATA",
      "JSON_PARSE",
      "SCHEMA_VALIDATION",
      "SEMANTIC_VALIDATION",
      "POST_RESPONSE_CLEANUP",
    ].includes(diagnostic.failureStage)
  ) {
    return true;
  }
  return diagnostic.failureStage === "BODY_CAPTURE";
}

export function createKimiK3TokenEstimateDiagnosticEvidenceV2({
  requestSha256,
  messagesSha256,
  reviewMaterialSha256,
  sourceCommit,
  requestedModel,
  endpoint,
  diagnostic,
  responseArtifact,
  recordedAt,
}) {
  const evidence = createKimiK3TokenEstimateDiagnosticEvidence({
    requestSha256,
    messagesSha256,
    reviewMaterialSha256,
    sourceCommit,
    requestedModel,
    endpoint,
    diagnostic,
    responseArtifact,
    recordedAt,
  });
  evidence.schemaVersion = TOKEN_ESTIMATE_DIAGNOSTIC_SCHEMA_VERSION_V2;
  evidence.responseBodyComplete = diagnostic?.responseBodyComplete ?? null;
  evidence.evidenceSha256 = tokenEstimateDiagnosticEvidenceDigest(evidence);
  return evidence;
}

export function validateKimiK3TokenEstimateDiagnosticEvidenceV2({
  evidence,
  requestSha256,
  messagesSha256,
  reviewMaterialSha256,
  sourceCommit,
  requestedModel,
  endpoint,
  diagnostic,
  responseArtifact,
  recordedAt,
  responseArtifactBytes = null,
}) {
  let expected = null;
  try {
    expected = createKimiK3TokenEstimateDiagnosticEvidenceV2({
      requestSha256,
      messagesSha256,
      reviewMaterialSha256,
      sourceCommit,
      requestedModel,
      endpoint,
      diagnostic,
      responseArtifact,
      recordedAt,
    });
  } catch {
    expected = null;
  }
  const artifactBound =
    evidence?.responseArtifact ===
    "token-estimate-diagnostic-response.bin";
  const artifactBytesValid = artifactBound
    ? responseArtifactBytes instanceof Uint8Array &&
      responseArtifactBytes.byteLength === evidence.responseBodyByteLength &&
      sha256Bytes(responseArtifactBytes) === evidence.responseBodySha256
    : responseArtifactBytes === null;
  const parsed = artifactBound
    ? parseJsonValueBytes(responseArtifactBytes)
    : { ok: false, value: null };
  const responseValidation = validateKimiK3TokenEstimateResponseBody(
    parsed.value,
    { enveloped: true },
  );
  const schemaValidated = parsed.ok && responseValidation.schemaValidated;
  const semanticValidated =
    parsed.ok && responseValidation.semanticValidated;
  const validationProgressValid = artifactBound
    ? evidence?.jsonParsed === parsed.ok &&
      evidence?.schemaValidated === schemaValidated &&
      evidence?.semanticValidated === semanticValidated
    : evidence?.jsonParsed === false &&
      evidence?.schemaValidated === false &&
      evidence?.semanticValidated === false;
  const artifactPolicyValid =
    artifactBound ===
      tokenEstimateDiagnosticRequiresResponseArtifact(evidence) &&
    (!artifactBound ||
      tokenEstimateDiagnosticResponseCanBePersisted({
        diagnostic: evidence,
        responseBytes: responseArtifactBytes,
      }));
  const receivedBindingValid = evidence?.responseReceived
    ? Number.isInteger(evidence.httpStatus) &&
      evidence.httpStatus >= 100 &&
      evidence.httpStatus <= 599 &&
      typeof evidence.contentTypeObservedValid === "boolean" &&
      typeof evidence.contentEncodingObservedValid === "boolean" &&
      typeof evidence.responseEndpointMatched === "boolean" &&
      typeof evidence.responseBodyComplete === "boolean" &&
      Number.isSafeInteger(evidence.responseBodyByteLength) &&
      evidence.responseBodyByteLength >= 0 &&
      evidence.responseBodyByteLength <= 64 * 1024 &&
      SHA256.test(evidence.responseBodySha256 ?? "")
    : evidence?.httpStatus === null &&
      evidence?.contentType === null &&
      evidence?.contentEncoding === null &&
      evidence?.contentTypeObservedValid === null &&
      evidence?.contentEncodingObservedValid === null &&
      evidence?.responseEndpointMatched === null &&
      evidence?.responseBodyComplete === null &&
      evidence?.responseBodyByteLength === null &&
      evidence?.responseBodySha256 === null &&
      evidence?.responseArtifact === null;
  const failurePairValid =
    (evidence?.failureStage === null && evidence?.reasonCode === null) ||
    (typeof evidence?.failureStage === "string" &&
      TOKEN_ESTIMATE_DIAGNOSTIC_REASONS[
        evidence.failureStage
      ]?.includes(evidence.reasonCode));
  const responseCompletenessValid = evidence?.responseReceived
    ? evidence.failureStage === "BODY_CAPTURE"
      ? evidence.reasonCode === "KIMI_K3_RESPONSE_CREDENTIAL_ECHOED"
        ? evidence.responseBodyComplete === true
        : evidence.reasonCode === "KIMI_K3_RESPONSE_BYTES_UNAVAILABLE"
          ? evidence.responseBodyComplete === false ||
            (evidence.responseBodyComplete === true &&
              evidence.responseBodyByteLength === 0 &&
              artifactBound)
          : evidence.responseBodyComplete === false
      : evidence.responseBodyComplete === true
    : evidence?.responseBodyComplete === null;
  const diagnosticHeadersValid = [
    evidence?.contentType,
    evidence?.contentEncoding,
  ].every(
    (value) =>
      value === null ||
      (typeof value === "string" &&
        value.length <= 256 &&
        /^[\u0020-\u007e]+$/u.test(value) &&
        !/authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|token|credential|secret|password|email|bearer|account[_-]?id|user[_-]?id|tenant[_-]?id|request[_-]?headers/iu.test(
          value,
        )),
  );
  const valid =
    expected !== null &&
    exactKeys(evidence, TOKEN_ESTIMATE_DIAGNOSTIC_KEYS_V2) &&
    evidence.schemaVersion === TOKEN_ESTIMATE_DIAGNOSTIC_SCHEMA_VERSION_V2 &&
    SHA256.test(evidence.requestSha256 ?? "") &&
    SHA256.test(evidence.messagesSha256 ?? "") &&
    SHA256.test(evidence.reviewMaterialSha256 ?? "") &&
    COMMIT.test(evidence.sourceCommit ?? "") &&
    evidence.requestedModel === "kimi-k3" &&
    evidence.endpoint === TOKEN_ESTIMATE_ENDPOINT &&
    evidence.bodyRepresentation === APPLICATION_DECODED_BYTES &&
    diagnosticHeadersValid &&
    validDate(evidence.recordedAt) &&
    receivedBindingValid &&
    failurePairValid &&
    responseCompletenessValid &&
    validTokenEstimateDiagnosticCause(evidence) &&
    validationProgressValid &&
    artifactPolicyValid &&
    artifactBytesValid &&
    canonicalize(evidence) === canonicalize(expected) &&
    tokenEstimateDiagnosticEvidenceDigest(evidence) ===
      evidence.evidenceSha256;
  return {
    ok: valid,
    reasonCodes: valid
      ? []
      : ["KIMI_K3_TOKEN_ESTIMATE_DIAGNOSTIC_EVIDENCE_INVALID"],
  };
}

export function createKimiK3TokenEstimateDiagnosticArtifactsV2({
  responseBytes = null,
  ...input
}) {
  const responseArtifact = tokenEstimateDiagnosticResponseCanBePersisted({
    diagnostic: input.diagnostic,
    responseBytes,
  })
    ? "token-estimate-diagnostic-response.bin"
    : null;
  const evidence = createKimiK3TokenEstimateDiagnosticEvidenceV2({
    ...input,
    responseArtifact,
  });
  const validation = validateKimiK3TokenEstimateDiagnosticEvidenceV2({
    ...input,
    evidence,
    responseArtifact,
    responseArtifactBytes: responseArtifact === null ? null : responseBytes,
  });
  if (!validation.ok) {
    throw new TypeError(
      "Kimi K3 Token Estimate diagnostic evidence v2 is invalid.",
    );
  }
  const artifacts = {
    "token-estimate-diagnostic-evidence.json": Buffer.from(
      JSON.stringify(evidence),
      "utf8",
    ),
  };
  if (responseArtifact !== null) {
    artifacts[responseArtifact] = Buffer.from(responseBytes);
  }
  return { evidence, artifacts };
}

export function createKimiK3TokenEstimateDiagnosticEvidenceV3(input) {
  const evidence = createKimiK3TokenEstimateDiagnosticEvidenceV2(input);
  evidence.schemaVersion = TOKEN_ESTIMATE_DIAGNOSTIC_SCHEMA_VERSION_V3;
  evidence.evidenceSha256 = tokenEstimateDiagnosticEvidenceDigest(evidence);
  return evidence;
}

export function validateKimiK3TokenEstimateDiagnosticEvidenceV3(candidate) {
  try {
  const { evidence, diagnostic, ...input } = candidate;
  const cleanupFailed =
    evidence?.failureStage === "POST_RESPONSE_CLEANUP" &&
    evidence?.reasonCode === "KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED";
  const shadowDiagnostic = cleanupFailed
    ? { ...diagnostic, failureStage: null, reasonCode: null }
    : diagnostic;
  let shadowValidation = { ok: false };
  try {
    const shadowEvidence = createKimiK3TokenEstimateDiagnosticEvidenceV2({
      ...input,
      diagnostic: shadowDiagnostic,
    });
    shadowValidation = validateKimiK3TokenEstimateDiagnosticEvidenceV2({
      ...input,
      diagnostic: shadowDiagnostic,
      evidence: shadowEvidence,
    });
  } catch {
    shadowValidation = { ok: false };
  }
  let expected = null;
  try {
    expected = createKimiK3TokenEstimateDiagnosticEvidenceV3({
      ...input,
      diagnostic,
    });
  } catch {
    expected = null;
  }
  const valid =
    shadowValidation.ok &&
    expected !== null &&
    exactKeys(evidence, TOKEN_ESTIMATE_DIAGNOSTIC_KEYS_V2) &&
    evidence.schemaVersion === TOKEN_ESTIMATE_DIAGNOSTIC_SCHEMA_VERSION_V3 &&
    (cleanupFailed
      ? evidence.responseReceived === true &&
        evidence.httpStatus === 200 &&
        evidence.contentTypeObservedValid === true &&
        evidence.contentEncodingObservedValid === true &&
        evidence.responseEndpointMatched === true &&
        evidence.responseBodyComplete === true &&
        evidence.responseArtifact ===
          "token-estimate-diagnostic-response.bin" &&
        evidence.jsonParsed === true &&
        evidence.schemaValidated === true &&
        evidence.semanticValidated === true
      : evidence.failureStage !== "POST_RESPONSE_CLEANUP") &&
    canonicalize(evidence) === canonicalize(expected) &&
    tokenEstimateDiagnosticEvidenceDigest(evidence) ===
      evidence.evidenceSha256;
  return {
    ok: valid,
    reasonCodes: valid
      ? []
      : ["KIMI_K3_TOKEN_ESTIMATE_DIAGNOSTIC_EVIDENCE_V3_INVALID"],
  };
  } catch {
    return {
      ok: false,
      reasonCodes: [
        "KIMI_K3_TOKEN_ESTIMATE_DIAGNOSTIC_EVIDENCE_V3_INVALID",
      ],
    };
  }
}

export function createKimiK3TokenEstimateDiagnosticArtifactsV3({
  responseBytes = null,
  ...input
}) {
  const responseArtifact = tokenEstimateDiagnosticResponseCanBePersisted({
    diagnostic: input.diagnostic,
    responseBytes,
  })
    ? "token-estimate-diagnostic-response.bin"
    : null;
  const evidence = createKimiK3TokenEstimateDiagnosticEvidenceV3({
    ...input,
    responseArtifact,
  });
  const validation = validateKimiK3TokenEstimateDiagnosticEvidenceV3({
    ...input,
    evidence,
    responseArtifact,
    responseArtifactBytes: responseArtifact === null ? null : responseBytes,
  });
  if (!validation.ok) {
    throw new TypeError(
      "Kimi K3 Token Estimate diagnostic evidence v3 is invalid.",
    );
  }
  const artifacts = {
    "token-estimate-diagnostic-evidence.json": Buffer.from(
      JSON.stringify(evidence),
      "utf8",
    ),
  };
  if (responseArtifact !== null) {
    artifacts[responseArtifact] = Buffer.from(responseBytes);
  }
  return { evidence, artifacts };
}

const CHAT_DIAGNOSTIC_SCHEMA_VERSION =
  "moonshot-kimi-k3-chat-diagnostic-evidence.v1";
const CHAT_DIAGNOSTIC_SCHEMA_VERSION_V2 =
  "moonshot-kimi-k3-chat-diagnostic-evidence.v2";
const CHAT_DIAGNOSTIC_SCHEMA_VERSION_V3 =
  "moonshot-kimi-k3-chat-diagnostic-evidence.v3";
const CHAT_ENDPOINT = "https://api.moonshot.ai/v1/chat/completions";
const CHAT_DIAGNOSTIC_KEYS = [
  "schemaVersion",
  "runtimeCommit",
  "sourceCommit",
  "sourceTree",
  "reviewBundleSha256",
  "requestSha256",
  "messagesSha256",
  "reviewMaterialSha256",
  "promptSha256",
  "configSha256",
  "outputSchemaSha256",
  "tokenEstimateEvidenceSha256",
  "requestedModel",
  "endpoint",
  "responseReceived",
  "httpStatus",
  "contentType",
  "contentEncoding",
  "contentTypeObservedValid",
  "contentEncodingObservedValid",
  "responseEndpointMatched",
  "bodyRepresentation",
  "responseBodyComplete",
  "responseBodyByteLength",
  "responseBodySha256",
  "responseArtifact",
  "jsonParsed",
  "protocolValidated",
  "outputSchemaValidated",
  "semanticValidated",
  "failureStage",
  "reasonCodes",
  "networkAttemptCount",
  "tokenEstimateAttemptCount",
  "chatCompletionAttemptCount",
  "startedAt",
  "finishedAt",
  "recordedAt",
  "evidenceSha256",
];
const CHAT_DIAGNOSTIC_KEYS_V2 = [
  ...CHAT_DIAGNOSTIC_KEYS.filter((key) => key !== "outputSchemaSha256"),
  "providerTransportSchemaPath",
  "providerTransportSchemaSha256",
  "canonicalOutputSchemaPath",
  "canonicalOutputSchemaSha256",
];
const CHAT_DIAGNOSTIC_STAGES = new Set([
  "REQUEST_BINDING",
  "CREDENTIAL",
  "TRANSPORT",
  "RESPONSE_ENDPOINT",
  "HTTP_STATUS",
  "RESPONSE_METADATA",
  "BODY_CAPTURE",
  "PROTOCOL_VALIDATION",
  "OUTPUT_SCHEMA_VALIDATION",
  "SEMANTIC_VALIDATION",
]);
const CHAT_DIAGNOSTIC_STAGES_V3 = new Set([
  ...CHAT_DIAGNOSTIC_STAGES,
  "POST_RESPONSE_CLEANUP",
]);
const CHAT_DIAGNOSTIC_NO_RESPONSE_REASONS = Object.freeze({
  REQUEST_BINDING: [
    "KIMI_K3_CHAT_REQUEST_BINDING_MISMATCH",
    "KIMI_K3_TRANSPORT_CONFIGURATION_INVALID",
  ],
  CREDENTIAL: ["KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED"],
  TRANSPORT: [
    "KIMI_K3_TRANSPORT_NETWORK_FAILED",
    "KIMI_K3_TRANSPORT_TIMEOUT",
  ],
});

function chatDiagnosticResponseCanBePersisted({
  diagnostic,
  responseBytes,
  sensitiveCredential,
}) {
  return (
    responseBytes instanceof Uint8Array &&
    diagnostic?.responseReceived === true &&
    diagnostic?.responseEndpointMatched === true &&
    diagnostic?.responseBodyComplete === true &&
    Number.isSafeInteger(diagnostic.responseBodyByteLength) &&
    diagnostic.responseBodyByteLength <= 1024 * 1024 &&
    diagnostic.responseBodyByteLength === responseBytes.byteLength &&
    diagnostic.responseBodySha256 === sha256Bytes(responseBytes) &&
    strictUtf8(responseBytes) !== null &&
    !bytesContainSensitiveMaterial(responseBytes, sensitiveCredential)
  );
}

function equalReasonCodes(left, right) {
  return (
    Array.isArray(left) &&
    JSON.stringify([...new Set(left)].sort()) ===
      JSON.stringify([...new Set(right)].sort())
  );
}

function responseDiagnosticShapeIsValid(diagnostic, maximumBytes) {
  return (
    diagnostic?.responseReceived === true &&
    Number.isInteger(diagnostic.httpStatus) &&
    diagnostic.httpStatus >= 100 &&
    diagnostic.httpStatus <= 599 &&
    typeof diagnostic.contentTypeObservedValid === "boolean" &&
    typeof diagnostic.contentEncodingObservedValid === "boolean" &&
    typeof diagnostic.responseEndpointMatched === "boolean" &&
    typeof diagnostic.responseBodyComplete === "boolean" &&
    Number.isSafeInteger(diagnostic.responseBodyByteLength) &&
    diagnostic.responseBodyByteLength >= 0 &&
    diagnostic.responseBodyByteLength <= maximumBytes &&
    SHA256.test(diagnostic.responseBodySha256 ?? "")
  );
}

async function analyzeKimiK3ChatDiagnostic({
  config,
  configBytes,
  configSha256,
  outputSchemaBytes,
  canonicalOutputSchemaBytes,
  outputSchemaSha256,
  requestedModel,
  endpoint,
  diagnostic,
  reasonCodes,
  responseBytes,
  sensitiveCredential,
  enforceProviderTransportSchema = false,
  allowPostResponseCleanup = false,
}) {
  const exactReasonCodes = [...new Set(reasonCodes ?? [])].sort();
  const parsedConfig = parseJsonBytes(configBytes);
  const configValidation = await validateMoonshotKimiK3Config(config);
  const schemaModeValid = enforceProviderTransportSchema
    ? validateMoonshotKimiK3TransportSchema(outputSchemaBytes).ok
    : sameBytes(outputSchemaBytes, canonicalOutputSchemaBytes);
  const bindingsValid =
    configValidation.ok &&
    parsedConfig !== null &&
    canonicalize(parsedConfig) === canonicalize(config) &&
    sha256Bytes(configBytes) === configSha256 &&
    outputSchemaBytes instanceof Uint8Array &&
    sha256Bytes(outputSchemaBytes) === outputSchemaSha256 &&
    canonicalOutputSchemaBytes instanceof Uint8Array &&
    parseJsonBytes(canonicalOutputSchemaBytes) !== null &&
    schemaModeValid &&
    requestedModel === config.reviewerModel &&
    endpoint === `${config.baseURL}${config.endpoint}` &&
    typeof sensitiveCredential === "string" &&
    sensitiveCredential.length >= 16 &&
    exactReasonCodes.length > 0;
  const invalid = {
    valid: false,
    persistResponse: false,
    failureStage: "REQUEST_BINDING",
    reasonCodes: exactReasonCodes,
    progress: {
      jsonParsed: false,
      protocolValidated: false,
      outputSchemaValidated: false,
      semanticValidated: false,
    },
  };
  if (!bindingsValid || !diagnostic || typeof diagnostic !== "object") {
    return invalid;
  }

  if (diagnostic.responseReceived !== true) {
    const allowedReasons =
      CHAT_DIAGNOSTIC_NO_RESPONSE_REASONS[diagnostic.failureStage];
    return {
      ...invalid,
      valid:
        responseBytes === null &&
        Array.isArray(allowedReasons) &&
        typeof diagnostic.reasonCode === "string" &&
        exactReasonCodes.length === 1 &&
        exactReasonCodes[0] === diagnostic.reasonCode &&
        allowedReasons.includes(diagnostic.reasonCode),
      failureStage: diagnostic.failureStage,
    };
  }

  if (!responseDiagnosticShapeIsValid(diagnostic, config.maxResponseUtf8Bytes)) {
    return invalid;
  }
  const exactResponseBytes = responseBytes instanceof Uint8Array;
  const responseBytesMatch =
    exactResponseBytes &&
    responseBytes.byteLength === diagnostic.responseBodyByteLength &&
    sha256Bytes(responseBytes) === diagnostic.responseBodySha256;
  const jsonParsed = responseBytesMatch
    ? parseJsonValueBytes(responseBytes).ok
    : false;
  const earlyProgress = {
    jsonParsed,
    protocolValidated: false,
    outputSchemaValidated: false,
    semanticValidated: false,
  };
  const result = ({
    valid,
    persistResponse,
    failureStage,
    expectedReasonCodes,
    progress = earlyProgress,
  }) => ({
    valid:
      valid &&
      equalReasonCodes(exactReasonCodes, expectedReasonCodes) &&
      diagnostic.reasonCode === expectedReasonCodes[0],
    persistResponse,
    failureStage,
    reasonCodes: exactReasonCodes,
    progress,
  });

  if (diagnostic.responseEndpointMatched !== true) {
    return result({
      valid:
        responseBytes === null &&
        diagnostic.failureStage === "RESPONSE_ENDPOINT",
      persistResponse: false,
      failureStage: "RESPONSE_ENDPOINT",
      expectedReasonCodes: ["KIMI_K3_RESPONSE_ENDPOINT_MISMATCH"],
    });
  }
  if (diagnostic.responseBodyComplete !== true) {
    const allowedReasons = new Set([
      "KIMI_K3_RESPONSE_BYTE_LIMIT_EXCEEDED",
      "KIMI_K3_RESPONSE_BYTES_UNAVAILABLE",
      "KIMI_K3_TRANSPORT_TIMEOUT",
    ]);
    return {
      ...invalid,
      valid:
        responseBytes === null &&
        diagnostic.failureStage === "BODY_CAPTURE" &&
        exactReasonCodes.length === 1 &&
        allowedReasons.has(exactReasonCodes[0]) &&
        diagnostic.reasonCode === exactReasonCodes[0],
      failureStage: "BODY_CAPTURE",
      reasonCodes: exactReasonCodes,
    };
  }

  const sensitiveResponse =
    responseBytesMatch &&
    bytesContainSensitiveMaterial(responseBytes, sensitiveCredential);
  if (
    sensitiveResponse ||
    exactReasonCodes.includes("KIMI_K3_RESPONSE_CREDENTIAL_ECHOED")
  ) {
    return result({
      valid:
        (responseBytes === null || responseBytesMatch) &&
        diagnostic.failureStage === "BODY_CAPTURE",
      persistResponse: false,
      failureStage: "BODY_CAPTURE",
      expectedReasonCodes: ["KIMI_K3_RESPONSE_CREDENTIAL_ECHOED"],
      progress: invalid.progress,
    });
  }

  if (!responseBytesMatch) return invalid;
  const persistResponse = chatDiagnosticResponseCanBePersisted({
    diagnostic,
    responseBytes,
    sensitiveCredential,
  });
  if (!persistResponse) return invalid;
  if (diagnostic.httpStatus !== 200) {
    return result({
      valid: diagnostic.failureStage === "HTTP_STATUS",
      persistResponse: true,
      failureStage: "HTTP_STATUS",
      expectedReasonCodes: ["KIMI_K3_RESPONSE_HTTP_INVALID"],
    });
  }
  const contentTypeValid =
    diagnostic.contentTypeObservedValid === true &&
    /^application\/json(?:;\s*charset=utf-8)?$/iu.test(
      diagnostic.contentType ?? "",
    );
  const contentEncodingValid =
    diagnostic.contentEncodingObservedValid === true &&
    [null, "identity"].includes(diagnostic.contentEncoding);
  if (!contentTypeValid || !contentEncodingValid) {
    return result({
      valid: diagnostic.failureStage === "RESPONSE_METADATA",
      persistResponse: true,
      failureStage: "RESPONSE_METADATA",
      expectedReasonCodes: [
        contentTypeValid
          ? "KIMI_K3_RESPONSE_CONTENT_ENCODING_INVALID"
          : "KIMI_K3_RESPONSE_CONTENT_TYPE_INVALID",
      ],
    });
  }

  const responseAnalysis = await analyzeKimiK3ChatResponse({
    config,
    responseBytes,
    providerTransportSchemaBytes: outputSchemaBytes,
    canonicalOutputSchemaBytes,
    enforceProviderTransportSchema,
  });
  if (
    responseAnalysis.ok &&
    allowPostResponseCleanup &&
    diagnostic.failureStage === "POST_RESPONSE_CLEANUP"
  ) {
    return result({
      valid: true,
      persistResponse: true,
      failureStage: "POST_RESPONSE_CLEANUP",
      expectedReasonCodes: [
        "KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED",
      ],
      progress: responseAnalysis.progress,
    });
  }
  if (responseAnalysis.ok) return invalid;
  return result({
    valid: diagnostic.failureStage === "SCHEMA_OR_SEMANTIC_VALIDATION",
    persistResponse: true,
    failureStage: responseAnalysis.failureStage,
    expectedReasonCodes: responseAnalysis.reasonCodes,
    progress: responseAnalysis.progress,
  });
}

async function validateKimiK3ChatDiagnosticSchemaSourceBindingsV2({
  sourceCommit,
  providerTransportSchemaPath,
  providerTransportSchemaSha256,
  canonicalOutputSchemaPath,
  canonicalOutputSchemaSha256,
  outputSchemaBytes,
  canonicalOutputSchemaBytes,
  resolveSourceCommitBytes,
}) {
  if (
    !COMMIT.test(sourceCommit ?? "") ||
    providerTransportSchemaPath !==
      kimiK3ReviewMaterialPathsV4.providerTransportSchema ||
    canonicalOutputSchemaPath !== kimiK3ReviewMaterialPathsV4.outputSchema ||
    typeof resolveSourceCommitBytes !== "function"
  ) {
    return false;
  }
  try {
    const [providerSourceBytes, canonicalSourceBytes] = await Promise.all([
      resolveSourceCommitBytes({
        sourceCommit,
        path: providerTransportSchemaPath,
      }),
      resolveSourceCommitBytes({
        sourceCommit,
        path: canonicalOutputSchemaPath,
      }),
    ]);
    return (
      sameBytes(providerSourceBytes, outputSchemaBytes) &&
      sameBytes(canonicalSourceBytes, canonicalOutputSchemaBytes) &&
      providerTransportSchemaSha256 === sha256Bytes(providerSourceBytes) &&
      canonicalOutputSchemaSha256 === sha256Bytes(canonicalSourceBytes) &&
      validateMoonshotKimiK3TransportSchema(providerSourceBytes).ok &&
      parseJsonBytes(canonicalSourceBytes) !== null
    );
  } catch {
    return false;
  }
}

function chatDiagnosticEvidenceDigest(evidence) {
  return sha256Value({
    ...evidence,
    evidenceSha256: EVIDENCE_SHA_PLACEHOLDER,
  });
}

function createKimiK3ChatDiagnosticEvidenceV1({
  runtimeCommit,
  sourceCommit,
  sourceTree,
  reviewBundleSha256,
  requestSha256,
  messagesSha256,
  reviewMaterialSha256,
  promptSha256,
  configSha256,
  outputSchemaSha256,
  tokenEstimateEvidenceSha256,
  requestedModel,
  endpoint,
  analysis,
  diagnostic,
  responseArtifact,
  networkAttemptCount,
  tokenEstimateAttemptCount,
  chatCompletionAttemptCount,
  startedAt,
  finishedAt,
  recordedAt,
}) {
  const exactReasonCodes = analysis.reasonCodes;
  const evidence = {
    schemaVersion: CHAT_DIAGNOSTIC_SCHEMA_VERSION,
    runtimeCommit,
    sourceCommit,
    sourceTree,
    reviewBundleSha256,
    requestSha256,
    messagesSha256,
    reviewMaterialSha256,
    promptSha256,
    configSha256,
    outputSchemaSha256,
    tokenEstimateEvidenceSha256,
    requestedModel,
    endpoint,
    responseReceived: diagnostic?.responseReceived === true,
    httpStatus: diagnostic?.httpStatus ?? null,
    contentType: diagnostic?.contentType ?? null,
    contentEncoding: diagnostic?.contentEncoding ?? null,
    contentTypeObservedValid:
      diagnostic?.contentTypeObservedValid ?? null,
    contentEncodingObservedValid:
      diagnostic?.contentEncodingObservedValid ?? null,
    responseEndpointMatched:
      diagnostic?.responseEndpointMatched ?? null,
    bodyRepresentation: APPLICATION_DECODED_BYTES,
    responseBodyComplete: diagnostic?.responseBodyComplete ?? null,
    responseBodyByteLength: diagnostic?.responseBodyByteLength ?? null,
    responseBodySha256: diagnostic?.responseBodySha256 ?? null,
    responseArtifact,
    ...analysis.progress,
    failureStage: analysis.failureStage,
    reasonCodes: exactReasonCodes,
    networkAttemptCount,
    tokenEstimateAttemptCount,
    chatCompletionAttemptCount,
    startedAt,
    finishedAt,
    recordedAt,
    evidenceSha256: EVIDENCE_SHA_PLACEHOLDER,
  };
  evidence.evidenceSha256 = chatDiagnosticEvidenceDigest(evidence);
  return evidence;
}

export async function validateKimiK3ChatDiagnosticEvidenceV1({
  evidence,
  runtimeCommit,
  sourceCommit,
  sourceTree,
  reviewBundleSha256,
  requestSha256,
  messagesSha256,
  reviewMaterialSha256,
  promptSha256,
  configSha256,
  outputSchemaSha256,
  tokenEstimateEvidenceSha256,
  requestedModel,
  endpoint,
  config,
  configBytes,
  outputSchemaBytes,
  canonicalOutputSchemaBytes,
  sensitiveCredential,
  diagnostic,
  reasonCodes,
  responseArtifactBytes = null,
  networkAttemptCount,
  tokenEstimateAttemptCount,
  chatCompletionAttemptCount,
  startedAt,
  finishedAt,
  recordedAt,
}) {
  const analysis = await analyzeKimiK3ChatDiagnostic({
    config,
    configBytes,
    configSha256,
    outputSchemaBytes,
    canonicalOutputSchemaBytes:
      canonicalOutputSchemaBytes ?? outputSchemaBytes,
    outputSchemaSha256,
    requestedModel,
    endpoint,
    diagnostic,
    reasonCodes,
    responseBytes: responseArtifactBytes,
    sensitiveCredential,
  });
  const responseArtifact = analysis.persistResponse
    ? "chat-diagnostic-response.bin"
    : null;
  let expected = null;
  try {
    expected = createKimiK3ChatDiagnosticEvidenceV1({
      runtimeCommit,
      sourceCommit,
      sourceTree,
      reviewBundleSha256,
      requestSha256,
      messagesSha256,
      reviewMaterialSha256,
      promptSha256,
      configSha256,
      outputSchemaSha256,
      tokenEstimateEvidenceSha256,
      requestedModel,
      endpoint,
      analysis,
      diagnostic,
      responseArtifact,
      responseArtifactBytes,
      networkAttemptCount,
      tokenEstimateAttemptCount,
      chatCompletionAttemptCount,
      startedAt,
      finishedAt,
      recordedAt,
    });
  } catch {
    expected = null;
  }
  const artifactBound =
    evidence?.responseArtifact === "chat-diagnostic-response.bin";
  const artifactBytesValid = artifactBound
    ? responseArtifactBytes instanceof Uint8Array &&
      responseArtifactBytes.byteLength === evidence.responseBodyByteLength &&
      sha256Bytes(responseArtifactBytes) === evidence.responseBodySha256 &&
      chatDiagnosticResponseCanBePersisted({
        diagnostic: evidence,
        responseBytes: responseArtifactBytes,
        sensitiveCredential,
      })
    : responseArtifactBytes === null;
  const receivedBindingValid = evidence?.responseReceived
    ? Number.isInteger(evidence.httpStatus) &&
      evidence.httpStatus >= 100 &&
      evidence.httpStatus <= 599 &&
      typeof evidence.contentTypeObservedValid === "boolean" &&
      typeof evidence.contentEncodingObservedValid === "boolean" &&
      typeof evidence.responseEndpointMatched === "boolean" &&
      typeof evidence.responseBodyComplete === "boolean" &&
      Number.isSafeInteger(evidence.responseBodyByteLength) &&
      evidence.responseBodyByteLength >= 0 &&
      evidence.responseBodyByteLength <= 1024 * 1024 &&
      SHA256.test(evidence.responseBodySha256 ?? "")
    : evidence?.httpStatus === null &&
      evidence?.contentType === null &&
      evidence?.contentEncoding === null &&
      evidence?.contentTypeObservedValid === null &&
      evidence?.contentEncodingObservedValid === null &&
      evidence?.responseEndpointMatched === null &&
      evidence?.responseBodyComplete === null &&
      evidence?.responseBodyByteLength === null &&
      evidence?.responseBodySha256 === null &&
      evidence?.responseArtifact === null;
  const diagnosticHeadersValid = [
    evidence?.contentType,
    evidence?.contentEncoding,
  ].every(
    (value) =>
      value === null ||
      (typeof value === "string" &&
        value.length <= 256 &&
        /^[\u0020-\u007e]+$/u.test(value) &&
        !/authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|token|credential|secret|password|email|bearer|account[_-]?id|user[_-]?id|tenant[_-]?id|request[_-]?headers/iu.test(
          value,
        )),
  );
  const valid =
    analysis.valid &&
    expected !== null &&
    exactKeys(evidence, CHAT_DIAGNOSTIC_KEYS) &&
    evidence.schemaVersion === CHAT_DIAGNOSTIC_SCHEMA_VERSION &&
    COMMIT.test(evidence.runtimeCommit ?? "") &&
    COMMIT.test(evidence.sourceCommit ?? "") &&
    COMMIT.test(evidence.sourceTree ?? "") &&
    SHA256.test(evidence.reviewBundleSha256 ?? "") &&
    SHA256.test(evidence.requestSha256 ?? "") &&
    SHA256.test(evidence.messagesSha256 ?? "") &&
    SHA256.test(evidence.reviewMaterialSha256 ?? "") &&
    SHA256.test(evidence.promptSha256 ?? "") &&
    SHA256.test(evidence.configSha256 ?? "") &&
    SHA256.test(evidence.outputSchemaSha256 ?? "") &&
    SHA256.test(evidence.tokenEstimateEvidenceSha256 ?? "") &&
    evidence.requestedModel === "kimi-k3" &&
    evidence.endpoint === CHAT_ENDPOINT &&
    evidence.bodyRepresentation === APPLICATION_DECODED_BYTES &&
    CHAT_DIAGNOSTIC_STAGES.has(evidence.failureStage) &&
    Array.isArray(evidence.reasonCodes) &&
    evidence.reasonCodes.length > 0 &&
    evidence.networkAttemptCount === 2 &&
    evidence.tokenEstimateAttemptCount === 1 &&
    evidence.chatCompletionAttemptCount === 1 &&
    validDate(evidence.startedAt) &&
    validDate(evidence.finishedAt) &&
    Date.parse(evidence.startedAt) <= Date.parse(evidence.finishedAt) &&
    validDate(evidence.recordedAt) &&
    diagnosticHeadersValid &&
    receivedBindingValid &&
    artifactBytesValid &&
    canonicalize(evidence) === canonicalize(expected) &&
    chatDiagnosticEvidenceDigest(evidence) === evidence.evidenceSha256;
  return {
    ok: valid,
    reasonCodes: valid
      ? []
      : ["KIMI_K3_CHAT_DIAGNOSTIC_EVIDENCE_INVALID"],
  };
}

export async function createKimiK3ChatDiagnosticArtifactsV1({
  responseBytes = null,
  ...input
}) {
  const analysis = await analyzeKimiK3ChatDiagnostic({
    ...input,
    canonicalOutputSchemaBytes:
      input.canonicalOutputSchemaBytes ?? input.outputSchemaBytes,
    responseBytes,
  });
  if (!analysis.valid) {
    throw new TypeError("Kimi K3 Chat diagnostic evidence is invalid.");
  }
  const responseArtifact = analysis.persistResponse
    ? "chat-diagnostic-response.bin"
    : null;
  const responseArtifactBytes = analysis.persistResponse ? responseBytes : null;
  const evidence = createKimiK3ChatDiagnosticEvidenceV1({
    ...input,
    analysis,
    responseArtifact,
    responseArtifactBytes,
  });
  const validation = await validateKimiK3ChatDiagnosticEvidenceV1({
    ...input,
    evidence,
    responseArtifactBytes,
  });
  if (!validation.ok) {
    throw new TypeError("Kimi K3 Chat diagnostic evidence is invalid.");
  }
  const artifacts = {
    "chat-diagnostic-evidence.json": Buffer.from(
      JSON.stringify(evidence),
      "utf8",
    ),
  };
  if (responseArtifact !== null) {
    artifacts[responseArtifact] = Buffer.from(responseBytes);
  }
  return { evidence, artifacts };
}

function createKimiK3ChatDiagnosticEvidenceV2({
  providerTransportSchemaPath,
  providerTransportSchemaSha256,
  canonicalOutputSchemaPath,
  canonicalOutputSchemaSha256,
  ...input
}) {
  const historical = createKimiK3ChatDiagnosticEvidenceV1({
    ...input,
    outputSchemaSha256: providerTransportSchemaSha256,
  });
  const shared = structuredClone(historical);
  delete shared.schemaVersion;
  delete shared.outputSchemaSha256;
  delete shared.evidenceSha256;
  const evidence = {
    schemaVersion: CHAT_DIAGNOSTIC_SCHEMA_VERSION_V2,
    ...shared,
    providerTransportSchemaPath,
    providerTransportSchemaSha256,
    canonicalOutputSchemaPath,
    canonicalOutputSchemaSha256,
    evidenceSha256: EVIDENCE_SHA_PLACEHOLDER,
  };
  evidence.evidenceSha256 = chatDiagnosticEvidenceDigest(evidence);
  return evidence;
}

function createKimiK3ChatDiagnosticEvidenceV3(input) {
  const evidence = createKimiK3ChatDiagnosticEvidenceV2(input);
  evidence.schemaVersion = CHAT_DIAGNOSTIC_SCHEMA_VERSION_V3;
  evidence.evidenceSha256 = chatDiagnosticEvidenceDigest(evidence);
  return evidence;
}

async function validateKimiK3ChatDiagnosticEvidenceVersion(
  {
    evidence,
    providerTransportSchemaPath,
    providerTransportSchemaSha256,
    canonicalOutputSchemaPath,
    canonicalOutputSchemaSha256,
    outputSchemaBytes,
    canonicalOutputSchemaBytes,
    responseArtifactBytes = null,
    sensitiveCredential,
    resolveSourceCommitBytes,
    ...input
  },
  { expectedSchemaVersion, allowedStages, allowPostResponseCleanup },
) {
  const sourceBindingsValid =
    await validateKimiK3ChatDiagnosticSchemaSourceBindingsV2({
      sourceCommit: input.sourceCommit,
      providerTransportSchemaPath,
      providerTransportSchemaSha256,
      canonicalOutputSchemaPath,
      canonicalOutputSchemaSha256,
      outputSchemaBytes,
      canonicalOutputSchemaBytes,
      resolveSourceCommitBytes,
    });
  const schemaBindingsValid =
    providerTransportSchemaPath ===
      kimiK3ReviewMaterialPathsV4.providerTransportSchema &&
    canonicalOutputSchemaPath === kimiK3ReviewMaterialPathsV4.outputSchema &&
    outputSchemaBytes instanceof Uint8Array &&
    canonicalOutputSchemaBytes instanceof Uint8Array &&
    providerTransportSchemaSha256 === sha256Bytes(outputSchemaBytes) &&
    canonicalOutputSchemaSha256 ===
      sha256Bytes(canonicalOutputSchemaBytes) &&
    evidence?.providerTransportSchemaPath ===
      providerTransportSchemaPath &&
    evidence?.providerTransportSchemaSha256 ===
      providerTransportSchemaSha256 &&
    evidence?.canonicalOutputSchemaPath === canonicalOutputSchemaPath &&
    evidence?.canonicalOutputSchemaSha256 === canonicalOutputSchemaSha256;
  const analysis = await analyzeKimiK3ChatDiagnostic({
    ...input,
    outputSchemaBytes,
    canonicalOutputSchemaBytes,
    outputSchemaSha256: providerTransportSchemaSha256,
    responseBytes: responseArtifactBytes,
    sensitiveCredential,
    enforceProviderTransportSchema: true,
    allowPostResponseCleanup,
  });
  const responseArtifact = analysis.persistResponse
    ? "chat-diagnostic-response.bin"
    : null;
  let expected = null;
  try {
    const createEvidence =
      expectedSchemaVersion === CHAT_DIAGNOSTIC_SCHEMA_VERSION_V3
        ? createKimiK3ChatDiagnosticEvidenceV3
        : createKimiK3ChatDiagnosticEvidenceV2;
    expected = createEvidence({
      ...input,
      providerTransportSchemaPath,
      providerTransportSchemaSha256,
      canonicalOutputSchemaPath,
      canonicalOutputSchemaSha256,
      analysis,
      responseArtifact,
    });
  } catch {
    expected = null;
  }
  const artifactBound =
    evidence?.responseArtifact === "chat-diagnostic-response.bin";
  const artifactBytesValid = artifactBound
    ? responseArtifactBytes instanceof Uint8Array &&
      responseArtifactBytes.byteLength === evidence.responseBodyByteLength &&
      sha256Bytes(responseArtifactBytes) === evidence.responseBodySha256 &&
      chatDiagnosticResponseCanBePersisted({
        diagnostic: evidence,
        responseBytes: responseArtifactBytes,
        sensitiveCredential,
      })
    : responseArtifactBytes === null;
  const receivedBindingValid = evidence?.responseReceived
    ? Number.isInteger(evidence.httpStatus) &&
      evidence.httpStatus >= 100 &&
      evidence.httpStatus <= 599 &&
      typeof evidence.contentTypeObservedValid === "boolean" &&
      typeof evidence.contentEncodingObservedValid === "boolean" &&
      typeof evidence.responseEndpointMatched === "boolean" &&
      typeof evidence.responseBodyComplete === "boolean" &&
      Number.isSafeInteger(evidence.responseBodyByteLength) &&
      evidence.responseBodyByteLength >= 0 &&
      evidence.responseBodyByteLength <= 1024 * 1024 &&
      SHA256.test(evidence.responseBodySha256 ?? "")
    : evidence?.httpStatus === null &&
      evidence?.contentType === null &&
      evidence?.contentEncoding === null &&
      evidence?.contentTypeObservedValid === null &&
      evidence?.contentEncodingObservedValid === null &&
      evidence?.responseEndpointMatched === null &&
      evidence?.responseBodyComplete === null &&
      evidence?.responseBodyByteLength === null &&
      evidence?.responseBodySha256 === null &&
      evidence?.responseArtifact === null;
  const diagnosticHeadersValid = [
    evidence?.contentType,
    evidence?.contentEncoding,
  ].every(
    (value) =>
      value === null ||
      (typeof value === "string" &&
        value.length <= 256 &&
        /^[\u0020-\u007e]+$/u.test(value) &&
        !/authorization|cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|token|credential|secret|password|email|bearer|account[_-]?id|user[_-]?id|tenant[_-]?id|request[_-]?headers/iu.test(
          value,
        )),
  );
  const valid =
    sourceBindingsValid &&
    schemaBindingsValid &&
    analysis.valid &&
    expected !== null &&
    exactKeys(evidence, CHAT_DIAGNOSTIC_KEYS_V2) &&
    evidence.schemaVersion === expectedSchemaVersion &&
    COMMIT.test(evidence.runtimeCommit ?? "") &&
    COMMIT.test(evidence.sourceCommit ?? "") &&
    COMMIT.test(evidence.sourceTree ?? "") &&
    SHA256.test(evidence.reviewBundleSha256 ?? "") &&
    SHA256.test(evidence.requestSha256 ?? "") &&
    SHA256.test(evidence.messagesSha256 ?? "") &&
    SHA256.test(evidence.reviewMaterialSha256 ?? "") &&
    SHA256.test(evidence.promptSha256 ?? "") &&
    SHA256.test(evidence.configSha256 ?? "") &&
    SHA256.test(evidence.providerTransportSchemaSha256 ?? "") &&
    SHA256.test(evidence.canonicalOutputSchemaSha256 ?? "") &&
    SHA256.test(evidence.tokenEstimateEvidenceSha256 ?? "") &&
    evidence.requestedModel === "kimi-k3" &&
    evidence.endpoint === CHAT_ENDPOINT &&
    evidence.bodyRepresentation === APPLICATION_DECODED_BYTES &&
    allowedStages.has(evidence.failureStage) &&
    Array.isArray(evidence.reasonCodes) &&
    evidence.reasonCodes.length > 0 &&
    evidence.networkAttemptCount === 2 &&
    evidence.tokenEstimateAttemptCount === 1 &&
    evidence.chatCompletionAttemptCount === 1 &&
    validDate(evidence.startedAt) &&
    validDate(evidence.finishedAt) &&
    Date.parse(evidence.startedAt) <= Date.parse(evidence.finishedAt) &&
    validDate(evidence.recordedAt) &&
    diagnosticHeadersValid &&
    receivedBindingValid &&
    artifactBytesValid &&
    canonicalize(evidence) === canonicalize(expected) &&
    chatDiagnosticEvidenceDigest(evidence) === evidence.evidenceSha256;
  return {
    ok: valid,
    reasonCodes: valid
      ? []
      : [
          expectedSchemaVersion === CHAT_DIAGNOSTIC_SCHEMA_VERSION_V3
            ? "KIMI_K3_CHAT_DIAGNOSTIC_EVIDENCE_V3_INVALID"
            : "KIMI_K3_CHAT_DIAGNOSTIC_EVIDENCE_V2_INVALID",
        ],
  };
}

export async function validateKimiK3ChatDiagnosticEvidenceV2(input) {
  return validateKimiK3ChatDiagnosticEvidenceVersion(input, {
    expectedSchemaVersion: CHAT_DIAGNOSTIC_SCHEMA_VERSION_V2,
    allowedStages: CHAT_DIAGNOSTIC_STAGES,
    allowPostResponseCleanup: false,
  });
}

export async function validateKimiK3ChatDiagnosticEvidenceV3(input) {
  try {
    return await validateKimiK3ChatDiagnosticEvidenceVersion(input, {
      expectedSchemaVersion: CHAT_DIAGNOSTIC_SCHEMA_VERSION_V3,
      allowedStages: CHAT_DIAGNOSTIC_STAGES_V3,
      allowPostResponseCleanup: true,
    });
  } catch {
    return {
      ok: false,
      reasonCodes: ["KIMI_K3_CHAT_DIAGNOSTIC_EVIDENCE_V3_INVALID"],
    };
  }
}

export async function createKimiK3ChatDiagnosticArtifactsV2({
  responseBytes = null,
  resolveSourceCommitBytes,
  ...input
}) {
  const sourceBindingsValid =
    await validateKimiK3ChatDiagnosticSchemaSourceBindingsV2({
      sourceCommit: input.sourceCommit,
      providerTransportSchemaPath: input.providerTransportSchemaPath,
      providerTransportSchemaSha256:
        input.providerTransportSchemaSha256,
      canonicalOutputSchemaPath: input.canonicalOutputSchemaPath,
      canonicalOutputSchemaSha256: input.canonicalOutputSchemaSha256,
      outputSchemaBytes: input.outputSchemaBytes,
      canonicalOutputSchemaBytes: input.canonicalOutputSchemaBytes,
      resolveSourceCommitBytes,
    });
  if (!sourceBindingsValid) {
    throw new TypeError("Kimi K3 Chat diagnostic evidence v2 is invalid.");
  }
  const analysis = await analyzeKimiK3ChatDiagnostic({
    ...input,
    outputSchemaSha256: input.providerTransportSchemaSha256,
    responseBytes,
    enforceProviderTransportSchema: true,
  });
  if (!analysis.valid) {
    throw new TypeError("Kimi K3 Chat diagnostic evidence v2 is invalid.");
  }
  const responseArtifact = analysis.persistResponse
    ? "chat-diagnostic-response.bin"
    : null;
  const responseArtifactBytes = analysis.persistResponse ? responseBytes : null;
  const evidence = createKimiK3ChatDiagnosticEvidenceV2({
    ...input,
    analysis,
    responseArtifact,
  });
  const validation = await validateKimiK3ChatDiagnosticEvidenceV2({
    ...input,
    evidence,
    responseArtifactBytes,
    resolveSourceCommitBytes,
  });
  if (!validation.ok) {
    throw new TypeError("Kimi K3 Chat diagnostic evidence v2 is invalid.");
  }
  const artifacts = {
    "chat-diagnostic-evidence.json": Buffer.from(
      JSON.stringify(evidence),
      "utf8",
    ),
  };
  if (responseArtifact !== null) {
    artifacts[responseArtifact] = Buffer.from(responseBytes);
  }
  return { evidence, artifacts };
}

export async function createKimiK3ChatDiagnosticArtifactsV3({
  responseBytes = null,
  resolveSourceCommitBytes,
  ...input
}) {
  const sourceBindingsValid =
    await validateKimiK3ChatDiagnosticSchemaSourceBindingsV2({
      sourceCommit: input.sourceCommit,
      providerTransportSchemaPath: input.providerTransportSchemaPath,
      providerTransportSchemaSha256:
        input.providerTransportSchemaSha256,
      canonicalOutputSchemaPath: input.canonicalOutputSchemaPath,
      canonicalOutputSchemaSha256: input.canonicalOutputSchemaSha256,
      outputSchemaBytes: input.outputSchemaBytes,
      canonicalOutputSchemaBytes: input.canonicalOutputSchemaBytes,
      resolveSourceCommitBytes,
    });
  if (!sourceBindingsValid) {
    throw new TypeError("Kimi K3 Chat diagnostic evidence v3 is invalid.");
  }
  const analysis = await analyzeKimiK3ChatDiagnostic({
    ...input,
    outputSchemaSha256: input.providerTransportSchemaSha256,
    responseBytes,
    enforceProviderTransportSchema: true,
    allowPostResponseCleanup: true,
  });
  if (!analysis.valid) {
    throw new TypeError("Kimi K3 Chat diagnostic evidence v3 is invalid.");
  }
  const responseArtifact = analysis.persistResponse
    ? "chat-diagnostic-response.bin"
    : null;
  const responseArtifactBytes = analysis.persistResponse ? responseBytes : null;
  const evidence = createKimiK3ChatDiagnosticEvidenceV3({
    ...input,
    analysis,
    responseArtifact,
  });
  const validation = await validateKimiK3ChatDiagnosticEvidenceV3({
    ...input,
    evidence,
    responseArtifactBytes,
    resolveSourceCommitBytes,
  });
  if (!validation.ok) {
    throw new TypeError("Kimi K3 Chat diagnostic evidence v3 is invalid.");
  }
  const artifacts = {
    "chat-diagnostic-evidence.json": Buffer.from(
      JSON.stringify(evidence),
      "utf8",
    ),
  };
  if (responseArtifact !== null) {
    artifacts[responseArtifact] = Buffer.from(responseBytes);
  }
  return { evidence, artifacts };
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

function kimiK3ChatProtocolBody(body, config) {
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
    return null;
  }
  return { body, choice, message };
}

async function analyzeKimiK3ChatResponse({
  config,
  responseBytes,
  providerTransportSchemaBytes,
  canonicalOutputSchemaBytes,
  enforceProviderTransportSchema = true,
}) {
  const parsed = parseJsonValueBytes(responseBytes);
  const protocol =
    responseBytes instanceof Uint8Array &&
    responseBytes.byteLength <= config.maxResponseUtf8Bytes &&
    providerTransportSchemaBytes instanceof Uint8Array &&
    canonicalOutputSchemaBytes instanceof Uint8Array &&
    parsed.ok
      ? kimiK3ChatProtocolBody(parsed.value, config)
      : null;
  if (protocol === null) {
    return {
      ok: false,
      reasonCodes: ["KIMI_K3_RESPONSE_PROTOCOL_INVALID"],
      failureStage: "PROTOCOL_VALIDATION",
      progress: {
        jsonParsed: parsed.ok,
        protocolValidated: false,
        outputSchemaValidated: false,
        semanticValidated: false,
      },
    };
  }
  const { body, choice, message } = protocol;
  const contentBytes = Buffer.from(message.content, "utf8");
  const parsedContent = parseJsonValueBytes(contentBytes);
  if (enforceProviderTransportSchema) {
    const providerValidation = await validateIndependentReviewSchemaInstance({
      schemaBytes: providerTransportSchemaBytes,
      expectedSchemaSha256: sha256Bytes(providerTransportSchemaBytes),
      instance: parsedContent.ok ? parsedContent.value : null,
      label: "Moonshot Kimi K3 provider transport output Schema",
    });
    if (!parsedContent.ok || !providerValidation.ok) {
      return {
        ok: false,
        reasonCodes: [
          "KIMI_K3_PROVIDER_TRANSPORT_OUTPUT_SCHEMA_INVALID",
          ...providerValidation.reasonCodes,
        ],
        failureStage: "OUTPUT_SCHEMA_VALIDATION",
        progress: {
          jsonParsed: true,
          protocolValidated: true,
          outputSchemaValidated: false,
          semanticValidated: false,
        },
      };
    }
  }
  const canonicalValidation =
    await validateIndependentModelReviewOutputArtifact({
      rawModelOutput: contentBytes,
      outputSchemaBytes: canonicalOutputSchemaBytes,
      expectedOutputSchemaSha256: sha256Bytes(canonicalOutputSchemaBytes),
    });
  if (!canonicalValidation.ok) {
    const outputSchemaValidated = canonicalValidation.reasonCodes.every(
      (reasonCode) =>
        reasonCode === "INDEPENDENT_REVIEW_UNRESOLVED_BLOCKING_FINDING",
    );
    return {
      ok: false,
      reasonCodes: [
        "KIMI_K3_RESPONSE_SCHEMA_OR_SEMANTIC_INVALID",
        ...(!enforceProviderTransportSchema || outputSchemaValidated
          ? []
          : ["KIMI_K3_CANONICAL_OUTPUT_SCHEMA_INVALID"]),
        ...canonicalValidation.reasonCodes,
      ],
      failureStage: outputSchemaValidated
        ? "SEMANTIC_VALIDATION"
        : "OUTPUT_SCHEMA_VALIDATION",
      progress: {
        jsonParsed: true,
        protocolValidated: true,
        outputSchemaValidated,
        semanticValidated: false,
      },
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
    return {
      ok: false,
      reasonCodes: ["KIMI_K3_SINGLE_CALL_BUDGET_EXCEEDED"],
      failureStage: "SEMANTIC_VALIDATION",
      progress: {
        jsonParsed: true,
        protocolValidated: true,
        outputSchemaValidated: true,
        semanticValidated: false,
      },
    };
  }
  return {
    ok: true,
    reasonCodes: [],
    failureStage: null,
    progress: {
      jsonParsed: true,
      protocolValidated: true,
      outputSchemaValidated: true,
      semanticValidated: true,
    },
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

export async function validateKimiK3ChatResponse(input) {
  return analyzeKimiK3ChatResponse(input);
}
