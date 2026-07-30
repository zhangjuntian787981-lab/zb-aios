import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  independentReviewTransportEvidenceDigests,
  validateIndependentReviewTransportEvidence,
} from "../lib/independent-review-transport-evidence.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);
const schemaPath =
  "implementation/governance/schemas/independent-review-transport-evidence.v1.schema.json";
const SHA256 = /^sha256:[a-f0-9]{64}$/;

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function exactJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function clone(value) {
  return structuredClone(value);
}

async function fixture() {
  const outputSchemaBytes = await readFile(
    resolve(
      root,
      "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    ),
  );
  const outputSchema = JSON.parse(outputSchemaBytes.toString("utf8"));
  const rawRequest = exactJson({
    model: "kimi-k2.7-code",
    messages: [
      {
        role: "system",
        content: "Review the frozen bundle and return only the required JSON.",
      },
      {
        role: "user",
        content: "bundle=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
    ],
    thinking: { type: "enabled" },
    tool_choice: "none",
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "independent_model_review_output_v2",
        strict: true,
        schema: outputSchema,
      },
    },
  });
  const rawContent = exactJson({
    decision: "CLEAR",
  });
  const rawResponse = exactJson({
    id: "cmpl_fixture_001",
    object: "chat.completion",
    model: "kimi-k2.7-code",
    choices: [
      {
        index: 0,
        finish_reason: "stop",
        message: {
          role: "assistant",
          content: new TextDecoder().decode(rawContent),
        },
      },
    ],
  });
  const bytes = new Map([
    ["evidence/request.json", rawRequest],
    ["evidence/response.json", rawResponse],
    ["evidence/content.json", rawContent],
    ["evidence/output-schema.json", outputSchemaBytes],
  ]);
  const evidence = {
    schemaVersion: "independent-review-transport-evidence.v1",
    evidenceId: "irte_fixture_001",
    provider: "moonshot",
    requestedModel: "kimi-k2.7-code",
    actualReturnedModel: "kimi-k2.7-code",
    baseURL: "https://api.moonshot.ai/v1",
    endpoint: "/chat/completions",
    source: {
      sourceCommit: "1".repeat(40),
      sourceTree: "2".repeat(40),
    },
    bindings: {
      reviewBundleSha256: `sha256:${"3".repeat(64)}`,
      reviewerPromptSha256: `sha256:${"4".repeat(64)}`,
      receiptSchemaSha256: `sha256:${"5".repeat(64)}`,
      outputSchemaPath: "evidence/output-schema.json",
      outputSchemaSha256: sha256Bytes(outputSchemaBytes),
    },
    request: {
      path: "evidence/request.json",
      encoding: "UTF-8",
      byteLength: rawRequest.byteLength,
      sha256: sha256Bytes(rawRequest),
    },
    response: {
      path: "evidence/response.json",
      encoding: "UTF-8",
      byteLength: rawResponse.byteLength,
      sha256: sha256Bytes(rawResponse),
      httpStatus: 200,
      contentType: "application/json",
    },
    content: {
      path: "evidence/content.json",
      encoding: "UTF-8",
      byteLength: rawContent.byteLength,
      sha256: sha256Bytes(rawContent),
    },
    protocol: {
      toolsAbsent: true,
      toolChoiceNone: true,
      strictSchema: true,
      networkAttemptCount: 1,
      choiceCount: 1,
      finishReason: "stop",
    },
    validators: {
      schemaValidatorVersion: "ajv@8.17.1",
      semanticValidatorVersion:
        "independent-review-transport-semantic-validator.v1",
    },
    startedAt: "2026-07-30T01:00:00.000Z",
    finishedAt: "2026-07-30T01:00:01.000Z",
    transportEvidenceSha256: `sha256:${"0".repeat(64)}`,
  };
  evidence.transportEvidenceSha256 =
    await independentReviewTransportEvidenceDigests.evidence(evidence);
  return {
    evidence,
    bytes,
    expectedBindings: {
      provider: "moonshot",
      requestedModel: "kimi-k2.7-code",
      actualReturnedModel: "kimi-k2.7-code",
      baseURL: "https://api.moonshot.ai/v1",
      endpoint: "/chat/completions",
      sourceCommit: "1".repeat(40),
      sourceTree: "2".repeat(40),
      reviewBundleSha256: `sha256:${"3".repeat(64)}`,
      reviewerPromptSha256: `sha256:${"4".repeat(64)}`,
      receiptSchemaSha256: `sha256:${"5".repeat(64)}`,
      outputSchemaPath: "evidence/output-schema.json",
      outputSchemaSha256: sha256Bytes(outputSchemaBytes),
      schemaValidatorVersion: "ajv@8.17.1",
      semanticValidatorVersion:
        "independent-review-transport-semantic-validator.v1",
    },
  };
}

async function validate(current, overrides = {}) {
  const resolved = [];
  const evidenceResolver =
    overrides.evidenceResolver ??
    (async (path) => {
      resolved.push(path);
      const value = current.bytes.get(path);
      if (!(value instanceof Uint8Array)) {
        throw new TypeError("Fixture evidence does not exist.");
      }
      return value;
    });
  const result = await validateIndependentReviewTransportEvidence({
    evidence: overrides.evidence ?? current.evidence,
    expectedBindings:
      overrides.expectedBindings ?? current.expectedBindings,
    evidenceResolver,
  });
  return { result, resolved };
}

async function rehash(evidence) {
  evidence.transportEvidenceSha256 =
    await independentReviewTransportEvidenceDigests.evidence(evidence);
  return evidence;
}

test("transport evidence schema is closed and compiles under JSON Schema 2020-12", async () => {
  const schema = JSON.parse(await readFile(resolve(root, schemaPath), "utf8"));
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const validateSchema = ajv.compile(schema);
  const current = await fixture();

  assert.equal(
    validateSchema(current.evidence),
    true,
    ajv.errorsText(validateSchema.errors),
  );
  assert.equal(schema.additionalProperties, false);

  const extra = { ...current.evidence, ready: true };
  assert.equal(validateSchema(extra), false);
});

test("valid transport evidence re-reads exact request, response and content bytes", async () => {
  const current = await fixture();
  const { result, resolved } = await validate(current);

  assert.deepEqual(result, {
    valid: true,
    status: "PROVED",
    reasonCodes: [],
    provider: "moonshot",
    requestedModel: "kimi-k2.7-code",
    actualReturnedModel: "kimi-k2.7-code",
    sourceCommit: "1".repeat(40),
    sourceTree: "2".repeat(40),
  });
  assert.deepEqual(resolved, [
    "evidence/request.json",
    "evidence/response.json",
    "evidence/content.json",
    "evidence/output-schema.json",
  ]);
  assert.match(current.evidence.transportEvidenceSha256, SHA256);
});

test("hash and byte-length drift in any raw artifact fails closed", async () => {
  for (const [part, field, replacement] of [
    ["request", "sha256", `sha256:${"a".repeat(64)}`],
    ["response", "byteLength", 1],
    ["content", "sha256", `sha256:${"b".repeat(64)}`],
  ]) {
    const current = await fixture();
    const tampered = clone(current.evidence);
    tampered[part][field] = replacement;
    await rehash(tampered);
    const { result } = await validate(current, { evidence: tampered });
    assert.equal(result.valid, false, `${part}.${field}`);
    assert.ok(
      result.reasonCodes.includes(
        `TRANSPORT_${part.toUpperCase()}_BYTES_MISMATCH`,
      ),
      JSON.stringify(result),
    );
  }
});

test("raw bytes changed behind an unchanged descriptor fail closed", async () => {
  const current = await fixture();
  current.bytes.set(
    "evidence/response.json",
    Buffer.from('{"tampered":true}', "utf8"),
  );
  const { result } = await validate(current);

  assert.equal(result.valid, false);
  assert.ok(
    result.reasonCodes.includes("TRANSPORT_RESPONSE_BYTES_MISMATCH"),
    JSON.stringify(result),
  );
});

test("provider, model, URL, source and frozen artifact binding drift fail closed", async () => {
  const mutationCases = [
    ["provider", "other", "TRANSPORT_PROVIDER_MISMATCH"],
    ["requestedModel", "other-model", "TRANSPORT_REQUESTED_MODEL_MISMATCH"],
    [
      "actualReturnedModel",
      "other-model",
      "TRANSPORT_RETURNED_MODEL_MISMATCH",
    ],
    ["baseURL", "https://proxy.invalid/v1", "TRANSPORT_BASE_URL_MISMATCH"],
    ["endpoint", "/other", "TRANSPORT_ENDPOINT_MISMATCH"],
  ];
  for (const [field, replacement, code] of mutationCases) {
    const current = await fixture();
    const expectedBindings = {
      ...current.expectedBindings,
      [field]: replacement,
    };
    const { result } = await validate(current, { expectedBindings });
    assert.equal(result.valid, false, field);
    assert.ok(result.reasonCodes.includes(code), JSON.stringify(result));
  }

  for (const [field, replacement, code] of [
    ["sourceCommit", "f".repeat(40), "TRANSPORT_SOURCE_COMMIT_MISMATCH"],
    ["sourceTree", "e".repeat(40), "TRANSPORT_SOURCE_TREE_MISMATCH"],
    [
      "reviewBundleSha256",
      `sha256:${"a".repeat(64)}`,
      "TRANSPORT_REVIEW_BUNDLE_MISMATCH",
    ],
    [
      "reviewerPromptSha256",
      `sha256:${"b".repeat(64)}`,
      "TRANSPORT_REVIEWER_PROMPT_MISMATCH",
    ],
    [
      "receiptSchemaSha256",
      `sha256:${"c".repeat(64)}`,
      "TRANSPORT_RECEIPT_SCHEMA_MISMATCH",
    ],
    [
      "outputSchemaSha256",
      `sha256:${"d".repeat(64)}`,
      "TRANSPORT_OUTPUT_SCHEMA_MISMATCH",
    ],
  ]) {
    const current = await fixture();
    const expectedBindings = {
      ...current.expectedBindings,
      [field]: replacement,
    };
    const { result } = await validate(current, { expectedBindings });
    assert.equal(result.valid, false, field);
    assert.ok(result.reasonCodes.includes(code), JSON.stringify(result));
  }
});

test("raw request semantics prove tools absent, tool_choice none and strict JSON Schema", async () => {
  for (const mutate of [
    (request) => {
      request.tools = [];
    },
    (request) => {
      request.tool_choice = "auto";
    },
    (request) => {
      request.response_format.json_schema.strict = false;
    },
  ]) {
    const current = await fixture();
    const request = JSON.parse(
      new TextDecoder().decode(current.bytes.get("evidence/request.json")),
    );
    mutate(request);
    const bytes = exactJson(request);
    current.bytes.set("evidence/request.json", bytes);
    current.evidence.request.byteLength = bytes.byteLength;
    current.evidence.request.sha256 = sha256Bytes(bytes);
    await rehash(current.evidence);

    const { result } = await validate(current);
    assert.equal(result.valid, false);
    assert.ok(
      result.reasonCodes.includes("TRANSPORT_REQUEST_SEMANTICS_INVALID"),
      JSON.stringify(result),
    );
  }
});

test("request strict Schema must equal the exact frozen output Schema bytes", async () => {
  const current = await fixture();
  const request = JSON.parse(
    new TextDecoder().decode(current.bytes.get("evidence/request.json")),
  );
  request.response_format.json_schema.schema = {
    type: "object",
    additionalProperties: false,
    required: ["decision"],
    properties: {
      decision: {
        enum: ["CLEAR", "FINDINGS", "INCONCLUSIVE"],
      },
    },
  };
  const bytes = exactJson(request);
  current.bytes.set("evidence/request.json", bytes);
  current.evidence.request.byteLength = bytes.byteLength;
  current.evidence.request.sha256 = sha256Bytes(bytes);
  await rehash(current.evidence);

  const { result } = await validate(current);
  assert.equal(result.valid, false);
  assert.ok(
    result.reasonCodes.includes("TRANSPORT_REQUEST_SCHEMA_MISMATCH"),
    JSON.stringify(result),
  );
});

test("raw response proves returned model, one choice, stop finish and exact content", async () => {
  const cases = [
    (response) => {
      response.model = "fallback-model";
    },
    (response) => {
      response.choices.push(structuredClone(response.choices[0]));
    },
    (response) => {
      response.choices[0].finish_reason = "length";
    },
    (response) => {
      response.choices[0].message.content = '{"decision":"BLOCKED"}';
    },
  ];
  for (const mutate of cases) {
    const current = await fixture();
    const response = JSON.parse(
      new TextDecoder().decode(current.bytes.get("evidence/response.json")),
    );
    mutate(response);
    const bytes = exactJson(response);
    current.bytes.set("evidence/response.json", bytes);
    current.evidence.response.byteLength = bytes.byteLength;
    current.evidence.response.sha256 = sha256Bytes(bytes);
    await rehash(current.evidence);

    const { result } = await validate(current);
    assert.equal(result.valid, false);
    assert.ok(
      result.reasonCodes.includes("TRANSPORT_RESPONSE_SEMANTICS_INVALID"),
      JSON.stringify(result),
    );
  }
});

test("network count, HTTP status, protocol flags, validator versions and time order fail closed", async () => {
  const cases = [
    [
      (evidence) => {
        evidence.protocol.networkAttemptCount = 2;
      },
      "TRANSPORT_PROTOCOL_INVALID",
    ],
    [
      (evidence) => {
        evidence.response.httpStatus = 503;
      },
      "TRANSPORT_PROTOCOL_INVALID",
    ],
    [
      (evidence) => {
        evidence.protocol.toolsAbsent = false;
      },
      "TRANSPORT_PROTOCOL_INVALID",
    ],
    [
      (evidence) => {
        evidence.validators.schemaValidatorVersion = "other";
      },
      "TRANSPORT_SCHEMA_VALIDATOR_VERSION_MISMATCH",
    ],
    [
      (evidence) => {
        evidence.finishedAt = "2026-07-30T00:59:59.000Z";
      },
      "TRANSPORT_TIME_ORDER_INVALID",
    ],
  ];
  for (const [mutate, code] of cases) {
    const current = await fixture();
    const tampered = clone(current.evidence);
    mutate(tampered);
    await rehash(tampered);
    const { result } = await validate(current, { evidence: tampered });
    assert.equal(result.valid, false, code);
    assert.ok(result.reasonCodes.includes(code), JSON.stringify(result));
  }
});

test("self-hash mismatch, invalid UTF-8 and credential material fail closed", async () => {
  const selfHash = await fixture();
  selfHash.evidence.transportEvidenceSha256 = `sha256:${"f".repeat(64)}`;
  assert.ok(
    (await validate(selfHash)).result.reasonCodes.includes(
      "TRANSPORT_EVIDENCE_SELF_HASH_MISMATCH",
    ),
  );

  const invalidUtf8 = await fixture();
  invalidUtf8.bytes.set(
    "evidence/content.json",
    Uint8Array.from([0xc3, 0x28]),
  );
  invalidUtf8.evidence.content.byteLength = 2;
  invalidUtf8.evidence.content.sha256 = sha256Bytes(
    invalidUtf8.bytes.get("evidence/content.json"),
  );
  await rehash(invalidUtf8.evidence);
  assert.ok(
    (await validate(invalidUtf8)).result.reasonCodes.includes(
      "TRANSPORT_CONTENT_UTF8_INVALID",
    ),
  );

  const credential = await fixture();
  const request = JSON.parse(
    new TextDecoder().decode(credential.bytes.get("evidence/request.json")),
  );
  request.authorization = "fixture-value-that-must-not-be-persisted";
  const requestBytes = exactJson(request);
  credential.bytes.set("evidence/request.json", requestBytes);
  credential.evidence.request.byteLength = requestBytes.byteLength;
  credential.evidence.request.sha256 = sha256Bytes(requestBytes);
  await rehash(credential.evidence);
  assert.ok(
    (await validate(credential)).result.reasonCodes.includes(
      "TRANSPORT_CREDENTIAL_MATERIAL_DETECTED",
    ),
  );
});

test("resolver failures and non-byte resolver values fail closed", async () => {
  const current = await fixture();
  for (const evidenceResolver of [
    async () => {
      throw new Error("not found");
    },
    async () => "not bytes",
  ]) {
    const { result } = await validate(current, { evidenceResolver });
    assert.equal(result.valid, false);
    assert.ok(
      result.reasonCodes.includes("TRANSPORT_EVIDENCE_BYTES_UNAVAILABLE"),
      JSON.stringify(result),
    );
  }
});

test("transport evidence validator contains no network, Git, D1 or Sites capability", async () => {
  const source = await readFile(
    resolve(root, "lib/independent-review-transport-evidence.mjs"),
    "utf8",
  );
  for (const forbidden of [
    "fetch(",
    "node:http",
    "node:https",
    "node:net",
    "node:dns",
    "node:child_process",
    "execFile",
    "spawn(",
    "journal.append",
    "seedIfNeeded",
    "control.execute",
    "sites",
  ]) {
    assert.equal(source.toLowerCase().includes(forbidden.toLowerCase()), false);
  }
});
