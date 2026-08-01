import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  createKimiK3ReviewReceipt,
  createKimiK3ReviewReceiptV5,
  createKimiK3ReviewReceiptV6,
  createKimiK3ReviewReceiptV7,
  createKimiK3ReviewReceiptV8,
  createKimiK3TokenEstimateEvidence,
  createKimiK3TokenEstimateEvidenceV2,
  createKimiK3TransportEvidence,
  createKimiK3TransportEvidenceV3,
  createKimiK3TransportEvidenceV4,
  kimiK3ReviewEvidenceDigests,
  validateKimiK3ReviewReceipt,
  validateKimiK3ReviewReceiptV5,
  validateKimiK3ReviewReceiptV6,
  validateKimiK3ReviewReceiptV7,
  validateKimiK3ReviewReceiptV8,
  validateKimiK3TokenEstimateEvidence,
  validateKimiK3TokenEstimateEvidenceV2,
  validateKimiK3TransportEvidence,
  validateKimiK3TransportEvidenceV3,
  validateKimiK3TransportEvidenceV4,
} from "../lib/kimi-k3-review-evidence.mjs";
import {
  createKimiK3TokenEstimateEvidence as createCoreTokenEstimateEvidence,
  validateKimiK3TokenEstimateEvidence as validateCoreTokenEstimateEvidence,
} from "../lib/kimi-k3-independent-review.mjs";

const sha = (label) =>
  kimiK3ReviewEvidenceDigests.bytes(Buffer.from(label, "utf8"));
const commit = (character) => character.repeat(40);
const startedAt = "2026-07-31T08:00:00.000Z";
const finishedAt = "2026-07-31T08:01:00.000Z";
const root = resolve(new URL("../", import.meta.url).pathname);

function bytes(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

async function schemaValidator(relativePath) {
  const schema = JSON.parse(
    await readFile(resolve(root, relativePath), "utf8"),
  );
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

function byteArtifact(path, bytes) {
  return {
    path,
    encoding: "UTF-8",
    byteLength: bytes.byteLength,
    sha256: kimiK3ReviewEvidenceDigests.bytes(bytes),
  };
}

function responseArtifact(path, bytes) {
  return {
    ...byteArtifact(path, bytes),
    httpStatus: 200,
    contentType: "application/json; charset=utf-8",
  };
}

function artifactResolver(artifacts) {
  return async (path) => artifacts.get(path);
}

function fixtures() {
  const prompt = "review frozen material";
  const material = "frozen material bytes";
  const outputSchemaBytes = readFileSync(
    resolve(
      root,
      "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    ),
  );
  const outputSchema = JSON.parse(outputSchemaBytes.toString("utf8"));
  const request = {
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
        name: "independent_model_review_output_v2",
        strict: true,
        schema: outputSchema,
      },
    },
    max_completion_tokens: 32768,
  };
  const content = {
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "Frozen preproduction review fixture.",
    decision: "CLEAR",
    findings: [],
  };
  const contentBytes = Buffer.from(JSON.stringify(content), "utf8");
  const usage = {
    prompt_tokens: 1000,
    completion_tokens: 200,
    total_tokens: 1200,
    cached_tokens: 0,
  };
  const response = {
    id: "chatcmpl_kimi_k3_review_001",
    object: "chat.completion",
    created: 1785484800,
    model: "kimi-k3",
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          reasoning_content: "reviewed",
          content: contentBytes.toString("utf8"),
        },
        finish_reason: "stop",
      },
    ],
    usage,
  };
  const requestBytes = Buffer.from(JSON.stringify(request), "utf8");
  const responseBytes = Buffer.from(JSON.stringify(response), "utf8");
  const estimateRequest = {
    model: "kimi-k3",
    messages: request.messages,
  };
  const estimateResponse = { data: { total_tokens: 1000 } };
  const estimateRequestBytes = Buffer.from(
    JSON.stringify(estimateRequest),
    "utf8",
  );
  const estimateResponseBytes = Buffer.from(
    JSON.stringify(estimateResponse),
    "utf8",
  );
  const materialBytes = Buffer.from(material, "utf8");
  const artifacts = new Map([
    ["evidence/token-estimate-request.json", estimateRequestBytes],
    ["evidence/token-estimate-response.json", estimateResponseBytes],
    ["evidence/request.json", requestBytes],
    ["evidence/response.json", responseBytes],
    ["evidence/content.json", contentBytes],
    ["evidence/material.bin", materialBytes],
    ["implementation/output-schema.json", outputSchemaBytes],
  ]);
  const source = {
    runtimeCommit: commit("a"),
    sourceCommit: commit("b"),
    sourceTree: commit("c"),
  };
  const tokenEstimate = createKimiK3TokenEstimateEvidence({
    schemaVersion: "moonshot-kimi-k3-token-estimate-evidence.v1",
    evidenceId: "mk3tee_fixture_001",
    provider: "moonshot",
    model: "kimi-k3",
    baseURL: "https://api.moonshot.ai/v1",
    endpoint: "/tokenizers/estimate-token-count",
    source,
    bindings: {
      formalRequestSha256:
        kimiK3ReviewEvidenceDigests.bytes(requestBytes),
      messagesSha256: kimiK3ReviewEvidenceDigests.bytes(
        Buffer.from(JSON.stringify(request.messages), "utf8"),
      ),
      reviewMaterialSha256:
        kimiK3ReviewEvidenceDigests.bytes(materialBytes),
      reviewBundleSha256: sha("review-bundle"),
      configSha256: sha("config"),
      requestSchemaCoverage: "MESSAGES_ONLY",
    },
    request: byteArtifact(
      "evidence/token-estimate-request.json",
      estimateRequestBytes,
    ),
    response: responseArtifact(
      "evidence/token-estimate-response.json",
      estimateResponseBytes,
    ),
    estimate: {
      estimatedInputTokens: 1000,
      contextWindowTokens: 1048576,
      maxCompletionTokens: 32768,
      safetyMarginTokens: 8192,
      requiredContextTokens: 41960,
      coverage: "MESSAGES_ONLY",
      contextProved: false,
    },
    budget: {
      currency: "USD",
      taxBasis: "TAX_EXCLUSIVE",
      budgetMicros: 4000000,
      worstCaseInputMicros: 3000,
      worstCaseOutputMicros: 491520,
      worstCaseTotalMicros: 494520,
      budgetProved: false,
    },
    networkAttemptCount: 1,
    startedAt,
    finishedAt,
  });
  const transport = createKimiK3TransportEvidence({
    schemaVersion: "independent-review-transport-evidence.v2",
    evidenceId: "irte_kimi_k3_fixture_001",
    provider: "moonshot",
    requestedModel: "kimi-k3",
    actualReturnedModel: "kimi-k3",
    responseId: "chatcmpl_kimi_k3_review_001",
    baseURL: "https://api.moonshot.ai/v1",
    endpoint: "/chat/completions",
    source: {
      sourceCommit: source.sourceCommit,
      sourceTree: source.sourceTree,
    },
    bindings: {
      reviewBundleSha256: sha("review-bundle"),
      reviewerPromptSha256: sha("prompt"),
      receiptSchemaSha256: sha("receipt-schema"),
      outputSchemaPath: "implementation/output-schema.json",
      outputSchemaSha256: sha("output-schema"),
      providerConfigSha256: sha("config"),
      tokenEstimateEvidenceSha256: tokenEstimate.evidenceSha256,
    },
    request: byteArtifact("evidence/request.json", requestBytes),
    response: responseArtifact("evidence/response.json", responseBytes),
    content: byteArtifact("evidence/content.json", contentBytes),
    protocol: {
      toolsAbsent: true,
      toolChoiceNone: true,
      thinkingAbsent: true,
      reasoningEffort: "max",
      strictSchema: true,
      maxCompletionTokens: 32768,
      networkAttemptCount: 1,
      choiceCount: 1,
      finishReason: "stop",
    },
    usage: {
      promptTokens: 1000,
      completionTokens: 200,
      totalTokens: 1200,
      cachedTokens: 0,
    },
    cost: {
      currency: "USD",
      taxBasis: "TAX_EXCLUSIVE",
      inputMicros: 3000,
      outputMicros: 3000,
      totalMicros: 6000,
      budgetMicros: 4000000,
      withinBudget: true,
    },
    validators: {
      schemaValidatorVersion: "ajv@8.20.0",
      semanticValidatorVersion:
        "kimi-k3-independent-review-transport-validator.v1",
    },
    startedAt,
    finishedAt,
  });
  artifacts.set(
    "evidence/token-estimate-evidence.json",
    Buffer.from(JSON.stringify(tokenEstimate), "utf8"),
  );
  artifacts.set(
    "evidence/transport-evidence.json",
    Buffer.from(JSON.stringify(transport), "utf8"),
  );
  return {
    artifacts,
    source,
    request,
    response,
    content,
    materialBytes,
    tokenEstimate,
    transport,
  };
}

function receiptFixture(fixture) {
  const { artifacts, source, tokenEstimate, transport } = fixture;
  const transportBytes = artifacts.get("evidence/transport-evidence.json");
  const tokenEstimateBytes = artifacts.get(
    "evidence/token-estimate-evidence.json",
  );
  return createKimiK3ReviewReceipt({
    schemaVersion: "independent-model-review-receipt.v4",
    receiptId: "imrr_kimi_k3_fixture_001",
    receiptSchemaVersion: "independent-model-review-receipt.v4",
    reviewId: "imrr_kimi_k3_fixture_001",
    policyVersion: "2.0.0-candidate.3",
    policySha256: sha("policy"),
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    applicablePhase: "P2",
    humanIndependentReviewSatisfied: false,
    independentModelReviewRequired: true,
    p3HumanReviewRequired: true,
    bundleId: "imrb_kimi_k3_fixture_001",
    bundleSha256: sha("review-bundle"),
    reviewMaterialSha256: sha("review-material-manifest"),
    reviewer: {
      reviewerProvider: "moonshot",
      requestedModel: "kimi-k3",
      actualReturnedModel: "kimi-k3",
      apiBaseURL: "https://api.moonshot.ai/v1",
      endpoint: "/chat/completions",
      reviewerSessionId: "chatcmpl_kimi_k3_review_001",
      reviewerIndependentOfImplementation: true,
      implementationProvider: "openai",
      implementationModel: "gpt-5.6-sol",
      diversityLevel: "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER",
    },
    source: {
      baseCommit: commit("d"),
      sourceCommit: source.sourceCommit,
      headCommit: source.sourceCommit,
      tree: source.sourceTree,
      diffSha256: sha("diff"),
      changedPathsDigest: sha("changed-paths"),
      gitDiffCheck: {
        schemaVersion: "independent-review-git-diff-check.v1",
        checkId: "base-to-source-diff-check",
        executionMode: "TRUSTED_GIT_OBJECT_DATABASE_CONTROL_PLANE",
        baseCommit: commit("d"),
        sourceCommit: source.sourceCommit,
        sourceTree: source.sourceTree,
        checkedPatchSha256: sha("diff"),
        runnerPath: "scripts/verify-independent-review-git-diff.mjs",
        runnerGitBlobSha256: sha("diff-runner-blob"),
        runnerExecutedBytesSha256: sha("diff-runner-bytes"),
        gitExecutable: "/usr/bin/git",
        gitVersion: "git version 2.50.1",
        logicalCommandSha256: sha("diff-command"),
        environmentSha256: sha("diff-env"),
        exitCode: 0,
        status: "PASS",
        stdoutSha256:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        stdoutByteLength: 0,
        stderrSha256:
          "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        stderrByteLength: 0,
        resultSha256: sha("diff-result"),
      },
    },
    bindings: {
      reviewBundleSha256: sha("review-bundle"),
      reviewMaterialSha256:
        kimiK3ReviewEvidenceDigests.bytes(fixture.materialBytes),
      reviewMaterialSchemaSha256: sha("material-schema-v3"),
      reviewMaterialSchemaVersion: "independent-review-material.v3",
      reviewMaterialFormat: "LENGTH_PREFIXED_UTF8_ENVELOPE_V1",
      reviewerPromptSha256: sha("prompt"),
      canonicalReceiptSchemaSha256: sha("receipt-schema"),
      canonicalOutputSchemaSha256: sha("output-schema"),
      providerTransportSchemaSha256: null,
      transportEvidenceSchemaSha256: sha("transport-schema-v2"),
      transportEvidenceSha256: transport.transportEvidenceSha256,
      tokenEstimateEvidenceSchemaSha256: sha("estimate-schema-v1"),
      tokenEstimateEvidenceSha256: tokenEstimate.evidenceSha256,
      providerConfigSha256: sha("config"),
      rawTokenEstimateRequestSha256:
        tokenEstimate.request.sha256,
      rawTokenEstimateResponseSha256:
        tokenEstimate.response.sha256,
      rawRequestArtifactSha256: transport.request.sha256,
      rawResponseUtf8Sha256: transport.response.sha256,
      rawContentUtf8Sha256: transport.content.sha256,
      schemaValidatorVersion: "ajv@8.20.0",
      semanticValidatorVersion:
        "kimi-k3-independent-model-review-semantic-validator.v1",
    },
    artifacts: {
      tokenEstimateRequest: tokenEstimate.request,
      tokenEstimateResponse: {
        path: tokenEstimate.response.path,
        encoding: tokenEstimate.response.encoding,
        byteLength: tokenEstimate.response.byteLength,
        sha256: tokenEstimate.response.sha256,
      },
      tokenEstimateEvidence: byteArtifact(
        "evidence/token-estimate-evidence.json",
        tokenEstimateBytes,
      ),
      request: transport.request,
      response: {
        path: transport.response.path,
        encoding: transport.response.encoding,
        byteLength: transport.response.byteLength,
        sha256: transport.response.sha256,
      },
      content: transport.content,
      material: byteArtifact("evidence/material.bin", fixture.materialBytes),
      transportEvidence: byteArtifact(
        "evidence/transport-evidence.json",
        transportBytes,
      ),
    },
    contextAndBudget: {
      estimateCoverage: "FULL_MODEL_VISIBLE_INPUT_PROVED",
      estimatedInputTokens: 1000,
      contextWindowTokens: 1048576,
      maxCompletionTokens: 32768,
      safetyMarginTokens: 8192,
      requiredContextTokens: 41960,
      contextProved: true,
      budgetMicros: 4000000,
      worstCaseTotalMicros: 494520,
      budgetProved: true,
    },
    usage: transport.usage,
    cost: {
      currency: "USD",
      taxBasis: "TAX_EXCLUSIVE",
      actualInputMicros: 3000,
      actualOutputMicros: 3000,
      actualTotalMicros: 6000,
      budgetMicros: 4000000,
      withinBudget: true,
    },
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
      repositoryBefore: {
        head: source.sourceCommit,
        tree: source.sourceTree,
        worktreeStatusSha256: sha("status"),
        worktreeContentManifestSha256: sha("worktree"),
        worktreePathCount: 100,
        protectedPathSetSha256: sha("protected-set"),
        protectedFilesDigest: sha("protected-files"),
        ignoredExclusionPolicySha256: sha("ignored-policy"),
        ignoredExcludedPathCount: 5,
      },
      repositoryAfter: {
        head: source.sourceCommit,
        tree: source.sourceTree,
        worktreeStatusSha256: sha("status"),
        worktreeContentManifestSha256: sha("worktree"),
        worktreePathCount: 100,
        protectedPathSetSha256: sha("protected-set"),
        protectedFilesDigest: sha("protected-files"),
        ignoredExclusionPolicySha256: sha("ignored-policy"),
        ignoredExcludedPathCount: 5,
      },
      repositoryUnchanged: true,
      runtimeTrust: {
        mode: "ANCESTOR_RUNTIME_COMMIT",
        runtimeCommit: source.runtimeCommit,
        runtimeTree: commit("e"),
        subjectCommit: source.sourceCommit,
        subjectTree: source.sourceTree,
        bootstrapSha256: sha("bootstrap"),
        launcherSha256: sha("launcher"),
        runtimeManifestGitBlobSha256: sha("runtime-manifest-blob"),
        runnerGitBlobSha256: sha("runner-blob"),
      },
      runtimeDependencyManifest: {
        path: "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
        gitBlobSha256: sha("runtime-manifest-blob"),
        manifestSha256: sha("runtime-manifest"),
        nodeExecutableSha256: sha("node"),
        fullDependencyTreeSha256: sha("dependencies"),
        npmPackageTreeSha256: sha("npm"),
      },
    },
    reviewedPaths: ["lib/kimi-k3-review-evidence.mjs"],
    findings: [],
    testEvidenceDigests: [sha("tests")],
    decision: "CLEAR",
    conclusion: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
    historicalTerraEvidenceAccepted: false,
    historicalK2EvidenceAccepted: false,
    humanReviewClaim: false,
    governanceEffect: "NONE",
    selfAuthorizing: false,
    startedAt,
    finishedAt,
    recordedAt: finishedAt,
  });
}

function fixturesV3() {
  const fixture = fixtures();
  const requestBytes = fixture.artifacts.get("evidence/request.json");
  const estimateRequestBytes = fixture.artifacts.get(
    "evidence/token-estimate-request.json",
  );
  const estimateResponseBytes = Buffer.from(
    JSON.stringify({
      code: 0,
      data: { total_tokens: 1000 },
      scode: "0x0",
      status: true,
    }),
    "utf8",
  );
  fixture.artifacts.set(
    "evidence/token-estimate-response.json",
    estimateResponseBytes,
  );
  const nonMessageVisibleInput = structuredClone(fixture.request);
  delete nonMessageVisibleInput.messages;
  const nonMessageBytes = Buffer.from(
    canonicalJson(nonMessageVisibleInput),
    "utf8",
  );
  const estimatedMessageInputTokens = 1000;
  const nonMessageVisibleTokenReserve = 65536;
  const worstCaseBillableInputTokens =
    estimatedMessageInputTokens + nonMessageVisibleTokenReserve;
  const worstCaseInputMicros = worstCaseBillableInputTokens * 3;
  const worstCaseOutputMicros = 32768 * 15;
  const tokenEstimate = createKimiK3TokenEstimateEvidenceV2({
    schemaVersion: "moonshot-kimi-k3-token-estimate-evidence.v2",
    evidenceId: "mk3tee_fixture_v2_001",
    provider: "moonshot",
    model: "kimi-k3",
    baseURL: "https://api.moonshot.ai/v1",
    endpoint: "/tokenizers/estimate-token-count",
    source: fixture.source,
    bindings: {
      formalRequestSha256: kimiK3ReviewEvidenceDigests.bytes(requestBytes),
      messagesSha256: kimiK3ReviewEvidenceDigests.bytes(
        Buffer.from(JSON.stringify(fixture.request.messages), "utf8"),
      ),
      reviewMaterialSha256: kimiK3ReviewEvidenceDigests.bytes(
        fixture.materialBytes,
      ),
      reviewBundleSha256: sha("review-bundle"),
      configSha256: sha("config-v3"),
      configSchemaSha256: sha("config-schema-v3"),
      outputSchemaSha256: kimiK3ReviewEvidenceDigests.value(
        fixture.request.response_format.json_schema.schema,
      ),
      nonMessageVisibleInputSha256:
        kimiK3ReviewEvidenceDigests.bytes(nonMessageBytes),
      nonMessageVisibleInputByteLength: nonMessageBytes.byteLength,
      requestSchemaCoverage:
        "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE",
    },
    formalRequest: byteArtifact("evidence/request.json", requestBytes),
    request: byteArtifact(
      "evidence/token-estimate-request.json",
      estimateRequestBytes,
    ),
    response: responseArtifact(
      "evidence/token-estimate-response.json",
      estimateResponseBytes,
    ),
    estimate: {
      estimatedMessageInputTokens,
      contextWindowTokens: 1048576,
      nonMessageVisibleTokenReserve,
      maxCompletionTokens: 32768,
      safetyMarginTokens: 8192,
      requiredContextTokens:
        estimatedMessageInputTokens +
        nonMessageVisibleTokenReserve +
        32768 +
        8192,
      coverage: "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE",
      contextProved: true,
    },
    budget: {
      currency: "USD",
      taxBasis: "TAX_EXCLUSIVE",
      budgetMicros: 4000000,
      cacheMissInputPriceMicrosPerMillion: 3000000,
      outputPriceMicrosPerMillion: 15000000,
      worstCaseBillableInputTokens,
      worstCaseInputMicros,
      worstCaseOutputMicros,
      worstCaseTotalMicros:
        worstCaseInputMicros + worstCaseOutputMicros,
      budgetProved: true,
    },
    networkAttemptCount: 1,
    startedAt,
    finishedAt,
  });
  const transport = createKimiK3TransportEvidenceV3({
    ...structuredClone(fixture.transport),
    schemaVersion: "independent-review-transport-evidence.v3",
    evidenceId: "irte_kimi_k3_fixture_v3_001",
    bindings: {
      reviewBundleSha256: sha("review-bundle"),
      reviewMaterialSha256: kimiK3ReviewEvidenceDigests.bytes(
        fixture.materialBytes,
      ),
      reviewerPromptSha256: sha("prompt"),
      receiptSchemaSha256: sha("receipt-schema-v5"),
      outputSchemaPath: "implementation/output-schema.json",
      outputSchemaSha256: tokenEstimate.bindings.outputSchemaSha256,
      providerConfigSha256: sha("config-v3"),
      providerConfigSchemaSha256: sha("config-schema-v3"),
      tokenEstimateEvidenceSchemaSha256: sha("estimate-schema-v2"),
      tokenEstimateEvidenceSha256: tokenEstimate.evidenceSha256,
      formalRequestSha256: tokenEstimate.bindings.formalRequestSha256,
      messagesSha256: tokenEstimate.bindings.messagesSha256,
      nonMessageVisibleInputSha256:
        tokenEstimate.bindings.nonMessageVisibleInputSha256,
    },
    protocol: {
      ...structuredClone(fixture.transport.protocol),
      outputSchemaValidated: true,
      semanticValidated: true,
    },
    validators: {
      schemaValidatorVersion: "ajv@8.20.0",
      semanticValidatorVersion:
        "kimi-k3-independent-review-transport-validator.v2",
    },
  });
  fixture.artifacts.set(
    "evidence/token-estimate-evidence-v2.json",
    Buffer.from(JSON.stringify(tokenEstimate), "utf8"),
  );
  fixture.artifacts.set(
    "evidence/transport-evidence-v3.json",
    Buffer.from(JSON.stringify(transport), "utf8"),
  );
  return {
    ...fixture,
    nonMessageBytes,
    tokenEstimateV2: tokenEstimate,
    transportV3: transport,
  };
}

function fixturesV4() {
  const fixture = fixturesV3();
  const providerTransportSchemaPath =
    "implementation/governance/schemas/moonshot-kimi-k3-independent-model-review-output.mfjs.v1.schema.json";
  const canonicalOutputSchemaPath =
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json";
  const transportEvidenceSchemaPath =
    "implementation/governance/schemas/independent-review-transport-evidence.v4.schema.json";
  const receiptSchemaPath =
    "implementation/governance/schemas/independent-model-review-receipt.v6.schema.json";
  const providerTransportSchemaBytes = readFileSync(
    resolve(root, providerTransportSchemaPath),
  );
  const canonicalOutputSchemaBytes = readFileSync(
    resolve(root, canonicalOutputSchemaPath),
  );
  const transportEvidenceSchemaBytes = readFileSync(
    resolve(root, transportEvidenceSchemaPath),
  );
  const receiptSchemaBytes = readFileSync(resolve(root, receiptSchemaPath));
  const request = structuredClone(fixture.request);
  request.response_format.json_schema.schema = JSON.parse(
    providerTransportSchemaBytes.toString("utf8"),
  );
  const requestBytes = bytes(request);
  fixture.artifacts.set("evidence/request.json", requestBytes);
  fixture.artifacts.set(
    providerTransportSchemaPath,
    providerTransportSchemaBytes,
  );
  fixture.artifacts.set(
    canonicalOutputSchemaPath,
    canonicalOutputSchemaBytes,
  );
  fixture.artifacts.set(
    transportEvidenceSchemaPath,
    transportEvidenceSchemaBytes,
  );
  fixture.artifacts.set(receiptSchemaPath, receiptSchemaBytes);
  const nonMessage = structuredClone(request);
  delete nonMessage.messages;
  const nonMessageBytes = Buffer.from(canonicalJson(nonMessage), "utf8");
  const tokenEstimate = createKimiK3TokenEstimateEvidenceV2({
    ...structuredClone(fixture.tokenEstimateV2),
    bindings: {
      ...structuredClone(fixture.tokenEstimateV2.bindings),
      formalRequestSha256: kimiK3ReviewEvidenceDigests.bytes(requestBytes),
      outputSchemaSha256: kimiK3ReviewEvidenceDigests.value(
        request.response_format.json_schema.schema,
      ),
      nonMessageVisibleInputSha256:
        kimiK3ReviewEvidenceDigests.bytes(nonMessageBytes),
      nonMessageVisibleInputByteLength: nonMessageBytes.byteLength,
    },
    formalRequest: byteArtifact("evidence/request.json", requestBytes),
  });
  const transport = createKimiK3TransportEvidenceV4({
    ...structuredClone(fixture.transportV3),
    schemaVersion: "independent-review-transport-evidence.v4",
    evidenceId: "irte_kimi_k3_fixture_v4_001",
    bindings: {
      reviewBundleSha256: sha("review-bundle"),
      reviewMaterialSha256: kimiK3ReviewEvidenceDigests.bytes(
        fixture.materialBytes,
      ),
      reviewerPromptSha256: sha("prompt"),
      receiptSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(receiptSchemaBytes),
      providerTransportSchemaPath,
      providerTransportSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(providerTransportSchemaBytes),
      canonicalOutputSchemaPath,
      canonicalOutputSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(canonicalOutputSchemaBytes),
      providerConfigSha256: sha("config-v3"),
      providerConfigSchemaSha256: sha("config-schema-v3"),
      tokenEstimateEvidenceSchemaSha256: sha("estimate-schema-v2"),
      tokenEstimateEvidenceSha256: tokenEstimate.evidenceSha256,
      formalRequestSha256: tokenEstimate.bindings.formalRequestSha256,
      messagesSha256: tokenEstimate.bindings.messagesSha256,
      nonMessageVisibleInputSha256:
        tokenEstimate.bindings.nonMessageVisibleInputSha256,
    },
    request: byteArtifact("evidence/request.json", requestBytes),
    protocol: {
      toolsAbsent: true,
      toolChoiceNone: true,
      thinkingAbsent: true,
      reasoningEffort: "max",
      strictSchema: true,
      maxCompletionTokens: 32768,
      networkAttemptCount: 1,
      choiceCount: 1,
      finishReason: "stop",
      providerTransportSchemaValidated: true,
      canonicalOutputSchemaValidated: true,
      semanticValidated: true,
    },
    validators: {
      schemaValidatorVersion: "ajv@8.20.0",
      semanticValidatorVersion:
        "kimi-k3-independent-review-transport-validator.v3",
    },
  });
  fixture.artifacts.set(
    "evidence/token-estimate-evidence-v2.json",
    Buffer.from(JSON.stringify(tokenEstimate), "utf8"),
  );
  fixture.artifacts.set(
    "evidence/transport-evidence-v4.json",
    Buffer.from(JSON.stringify(transport), "utf8"),
  );
  return {
    ...fixture,
    request,
    nonMessageBytes,
    providerTransportSchemaPath,
    providerTransportSchemaBytes,
    canonicalOutputSchemaPath,
    canonicalOutputSchemaBytes,
    transportEvidenceSchemaPath,
    transportEvidenceSchemaBytes,
    receiptSchemaPath,
    receiptSchemaBytes,
    tokenEstimateV2: tokenEstimate,
    transportV4: transport,
  };
}

function receiptFixtureV5(fixture) {
  const receipt = receiptFixture(fixture);
  const estimate = fixture.tokenEstimateV2;
  const transport = fixture.transportV3;
  const estimateBytes = fixture.artifacts.get(
    "evidence/token-estimate-evidence-v2.json",
  );
  const transportBytes = fixture.artifacts.get(
    "evidence/transport-evidence-v3.json",
  );
  return createKimiK3ReviewReceiptV5({
    ...receipt,
    schemaVersion: "independent-model-review-receipt.v5",
    receiptSchemaVersion: "independent-model-review-receipt.v5",
    reviewMaterialSha256: kimiK3ReviewEvidenceDigests.bytes(
      fixture.materialBytes,
    ),
    bindings: {
      ...receipt.bindings,
      reviewMaterialSchemaSha256: sha("material-schema-v4"),
      reviewMaterialSchemaVersion: "independent-review-material.v4",
      canonicalReceiptSchemaSha256: sha("receipt-schema-v5"),
      canonicalOutputSchemaSha256: kimiK3ReviewEvidenceDigests.bytes(
        fixture.artifacts.get("implementation/output-schema.json"),
      ),
      transportEvidenceSchemaSha256: sha("transport-schema-v3"),
      transportEvidenceSha256: transport.transportEvidenceSha256,
      tokenEstimateEvidenceSchemaSha256: sha("estimate-schema-v2"),
      tokenEstimateEvidenceSha256: estimate.evidenceSha256,
      providerConfigSha256: sha("config-v3"),
      providerConfigSchemaSha256: sha("config-schema-v3"),
      rawTokenEstimateRequestSha256: estimate.request.sha256,
      rawTokenEstimateResponseSha256: estimate.response.sha256,
      rawRequestArtifactSha256: transport.request.sha256,
      rawResponseUtf8Sha256: transport.response.sha256,
      rawContentUtf8Sha256: transport.content.sha256,
      semanticValidatorVersion:
        "kimi-k3-independent-model-review-semantic-validator.v2",
    },
    artifacts: {
      ...receipt.artifacts,
      tokenEstimateRequest: estimate.request,
      tokenEstimateResponse: {
        path: estimate.response.path,
        encoding: estimate.response.encoding,
        byteLength: estimate.response.byteLength,
        sha256: estimate.response.sha256,
      },
      tokenEstimateEvidence: byteArtifact(
        "evidence/token-estimate-evidence-v2.json",
        estimateBytes,
      ),
      request: transport.request,
      response: {
        path: transport.response.path,
        encoding: transport.response.encoding,
        byteLength: transport.response.byteLength,
        sha256: transport.response.sha256,
      },
      content: transport.content,
      transportEvidence: byteArtifact(
        "evidence/transport-evidence-v3.json",
        transportBytes,
      ),
    },
    contextAndBudget: {
      estimateCoverage: "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE",
      estimatedMessageInputTokens: estimate.estimate.estimatedMessageInputTokens,
      nonMessageVisibleTokenReserve: 65536,
      nonMessageVisibleInputByteLength:
        estimate.bindings.nonMessageVisibleInputByteLength,
      nonMessageVisibleInputSha256:
        estimate.bindings.nonMessageVisibleInputSha256,
      contextWindowTokens: 1048576,
      maxCompletionTokens: 32768,
      safetyMarginTokens: 8192,
      requiredContextTokens: estimate.estimate.requiredContextTokens,
      contextProved: true,
      budgetMicros: 4000000,
      worstCaseBillableInputTokens:
        estimate.budget.worstCaseBillableInputTokens,
      worstCaseTotalMicros: estimate.budget.worstCaseTotalMicros,
      budgetProved: true,
    },
  });
}

function receiptFixtureV6(fixture) {
  const receipt = receiptFixtureV5(fixture);
  const transport = fixture.transportV4;
  const transportBytes = fixture.artifacts.get(
    "evidence/transport-evidence-v4.json",
  );
  return createKimiK3ReviewReceiptV6({
    ...receipt,
    schemaVersion: "independent-model-review-receipt.v6",
    receiptSchemaVersion: "independent-model-review-receipt.v6",
    bindings: {
      ...receipt.bindings,
      canonicalReceiptSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(fixture.receiptSchemaBytes),
      canonicalOutputSchemaSha256:
        transport.bindings.canonicalOutputSchemaSha256,
      providerTransportSchemaSha256:
        transport.bindings.providerTransportSchemaSha256,
      transportEvidenceSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(
          fixture.transportEvidenceSchemaBytes,
        ),
      transportEvidenceSha256: transport.transportEvidenceSha256,
      rawRequestArtifactSha256: transport.request.sha256,
      rawResponseUtf8Sha256: transport.response.sha256,
      rawContentUtf8Sha256: transport.content.sha256,
      semanticValidatorVersion:
        "kimi-k3-independent-model-review-semantic-validator.v3",
    },
    artifacts: {
      ...receipt.artifacts,
      request: transport.request,
      response: {
        path: transport.response.path,
        encoding: transport.response.encoding,
        byteLength: transport.response.byteLength,
        sha256: transport.response.sha256,
      },
      content: transport.content,
      transportEvidence: byteArtifact(
        "evidence/transport-evidence-v4.json",
        transportBytes,
      ),
    },
  });
}

function fixturesV5() {
  const fixture = fixturesV4();
  const receiptSchemaPathV7 =
    "implementation/governance/schemas/independent-model-review-receipt.v7.schema.json";
  const runtimeManifestPathV3 =
    "implementation/governance/independent-review/kimi-runtime-manifest.v3.json";
  const runtimeManifestSchemaPathV3 =
    "implementation/governance/schemas/independent-review-runtime-manifest.v3.schema.json";
  const receiptSchemaBytesV7 = readFileSync(
    resolve(root, receiptSchemaPathV7),
  );
  const runtimeManifestBytesV3 = readFileSync(
    resolve(root, runtimeManifestPathV3),
  );
  const runtimeManifestSchemaBytesV3 = readFileSync(
    resolve(root, runtimeManifestSchemaPathV3),
  );
  const runtimeManifestV3 = JSON.parse(runtimeManifestBytesV3.toString("utf8"));
  const transport = createKimiK3TransportEvidenceV4({
    ...structuredClone(fixture.transportV4),
    bindings: {
      ...structuredClone(fixture.transportV4.bindings),
      receiptSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(receiptSchemaBytesV7),
    },
  });
  const transportBytes = Buffer.from(JSON.stringify(transport), "utf8");
  fixture.artifacts.set(receiptSchemaPathV7, receiptSchemaBytesV7);
  fixture.artifacts.set(runtimeManifestPathV3, runtimeManifestBytesV3);
  fixture.artifacts.set(
    runtimeManifestSchemaPathV3,
    runtimeManifestSchemaBytesV3,
  );
  fixture.artifacts.set(
    "evidence/transport-evidence-v4.json",
    transportBytes,
  );
  return {
    ...fixture,
    receiptSchemaPathV7,
    receiptSchemaBytesV7,
    runtimeManifestPathV3,
    runtimeManifestBytesV3,
    runtimeManifestSchemaPathV3,
    runtimeManifestSchemaBytesV3,
    runtimeManifestV3,
    transportV4: transport,
  };
}

function receiptFixtureV7(fixture) {
  const receipt = receiptFixtureV6(fixture);
  const transportBytes = fixture.artifacts.get(
    "evidence/transport-evidence-v4.json",
  );
  return createKimiK3ReviewReceiptV7({
    ...receipt,
    schemaVersion: "independent-model-review-receipt.v7",
    receiptSchemaVersion: "independent-model-review-receipt.v7",
    bindings: {
      ...receipt.bindings,
      canonicalReceiptSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(fixture.receiptSchemaBytesV7),
      transportEvidenceSha256:
        fixture.transportV4.transportEvidenceSha256,
    },
    artifacts: {
      ...receipt.artifacts,
      transportEvidence: byteArtifact(
        "evidence/transport-evidence-v4.json",
        transportBytes,
      ),
    },
    isolationEvidence: {
      ...receipt.isolationEvidence,
      runtimeTrust: {
        ...receipt.isolationEvidence.runtimeTrust,
        runtimeManifestGitBlobSha256:
          kimiK3ReviewEvidenceDigests.bytes(fixture.runtimeManifestBytesV3),
      },
      runtimeDependencyManifest: {
        path: fixture.runtimeManifestPathV3,
        gitBlobSha256:
          kimiK3ReviewEvidenceDigests.bytes(fixture.runtimeManifestBytesV3),
        schemaPath: fixture.runtimeManifestSchemaPathV3,
        schemaGitBlobSha256:
          kimiK3ReviewEvidenceDigests.bytes(
            fixture.runtimeManifestSchemaBytesV3,
          ),
        manifestSha256: fixture.runtimeManifestV3.manifestSha256,
        nodeExecutableSha256:
          fixture.runtimeManifestV3.node.executableSha256,
        fullDependencyTreeSha256:
          fixture.runtimeManifestV3.dependencies.fullTreeSha256,
        npmPackageTreeSha256:
          fixture.runtimeManifestV3.npm.packageTreeSha256,
      },
    },
  });
}

function fixturesV6() {
  const fixture = fixturesV5();
  const receiptSchemaPathV8 =
    "implementation/governance/schemas/independent-model-review-receipt.v8.schema.json";
  const runtimeManifestPathV4 =
    "implementation/governance/independent-review/kimi-runtime-manifest.v4.json";
  const runtimeManifestSchemaPathV4 =
    "implementation/governance/schemas/independent-review-runtime-manifest.v4.schema.json";
  const receiptSchemaBytesV8 = readFileSync(
    resolve(root, receiptSchemaPathV8),
  );
  const runtimeManifestBytesV4 = readFileSync(
    resolve(root, runtimeManifestPathV4),
  );
  const runtimeManifestSchemaBytesV4 = readFileSync(
    resolve(root, runtimeManifestSchemaPathV4),
  );
  const runtimeManifestV4 = JSON.parse(runtimeManifestBytesV4.toString("utf8"));
  const transport = createKimiK3TransportEvidenceV4({
    ...structuredClone(fixture.transportV4),
    bindings: {
      ...structuredClone(fixture.transportV4.bindings),
      receiptSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(receiptSchemaBytesV8),
    },
  });
  const transportBytes = Buffer.from(JSON.stringify(transport), "utf8");
  fixture.artifacts.set(receiptSchemaPathV8, receiptSchemaBytesV8);
  fixture.artifacts.set(runtimeManifestPathV4, runtimeManifestBytesV4);
  fixture.artifacts.set(
    runtimeManifestSchemaPathV4,
    runtimeManifestSchemaBytesV4,
  );
  fixture.artifacts.set(
    "evidence/transport-evidence-v4.json",
    transportBytes,
  );
  return {
    ...fixture,
    receiptSchemaPathV8,
    receiptSchemaBytesV8,
    runtimeManifestPathV4,
    runtimeManifestBytesV4,
    runtimeManifestSchemaPathV4,
    runtimeManifestSchemaBytesV4,
    runtimeManifestV4,
    transportV4: transport,
  };
}

function receiptFixtureV8(fixture) {
  const receipt = receiptFixtureV7(fixture);
  const transportBytes = fixture.artifacts.get(
    "evidence/transport-evidence-v4.json",
  );
  return createKimiK3ReviewReceiptV8({
    ...receipt,
    schemaVersion: "independent-model-review-receipt.v8",
    receiptSchemaVersion: "independent-model-review-receipt.v8",
    bindings: {
      ...receipt.bindings,
      canonicalReceiptSchemaSha256:
        kimiK3ReviewEvidenceDigests.bytes(fixture.receiptSchemaBytesV8),
      transportEvidenceSha256:
        fixture.transportV4.transportEvidenceSha256,
    },
    artifacts: {
      ...receipt.artifacts,
      transportEvidence: byteArtifact(
        "evidence/transport-evidence-v4.json",
        transportBytes,
      ),
    },
    isolationEvidence: {
      ...receipt.isolationEvidence,
      runtimeTrust: {
        ...receipt.isolationEvidence.runtimeTrust,
        runtimeManifestGitBlobSha256:
          kimiK3ReviewEvidenceDigests.bytes(fixture.runtimeManifestBytesV4),
      },
      runtimeDependencyManifest: {
        path: fixture.runtimeManifestPathV4,
        gitBlobSha256:
          kimiK3ReviewEvidenceDigests.bytes(fixture.runtimeManifestBytesV4),
        schemaPath: fixture.runtimeManifestSchemaPathV4,
        schemaGitBlobSha256:
          kimiK3ReviewEvidenceDigests.bytes(
            fixture.runtimeManifestSchemaBytesV4,
          ),
        manifestSha256: fixture.runtimeManifestV4.manifestSha256,
        nodeExecutableSha256:
          fixture.runtimeManifestV4.node.executableSha256,
        fullDependencyTreeSha256:
          fixture.runtimeManifestV4.dependencies.fullTreeSha256,
        npmPackageTreeSha256:
          fixture.runtimeManifestV4.npm.packageTreeSha256,
      },
    },
  });
}

test("current K3 estimate is captured but Transport and Receipt fail closed", async () => {
  const fixture = fixtures();
  const resolver = artifactResolver(fixture.artifacts);
  assert.equal(
    (await validateKimiK3TokenEstimateEvidence({
      evidence: fixture.tokenEstimate,
      evidenceResolver: resolver,
    })).valid,
    true,
  );
  const transport = await validateKimiK3TransportEvidence({
      evidence: fixture.transport,
      tokenEstimateEvidence: fixture.tokenEstimate,
      evidenceResolver: resolver,
    });
  assert.equal(transport.valid, false);
  assert.ok(transport.reasonCodes.includes("KIMI_K3_CONTEXT_NOT_PROVED"));
  const receipt = receiptFixture(fixture);
  const result = await validateKimiK3ReviewReceipt({
    receipt,
    transportEvidence: fixture.transport,
    tokenEstimateEvidence: fixture.tokenEstimate,
    evidenceResolver: resolver,
  });
  assert.equal(result.valid, false);
  assert.ok(result.reasonCodes.includes("KIMI_K3_CONTEXT_NOT_PROVED"));

  const v3 = fixturesV3();
  const v3Resolver = artifactResolver(v3.artifacts);
  assert.equal(
    (await validateKimiK3TokenEstimateEvidenceV2({
      evidence: v3.tokenEstimateV2,
      evidenceResolver: v3Resolver,
    })).valid,
    true,
  );
  assert.equal(
    (await validateKimiK3TransportEvidenceV3({
      evidence: v3.transportV3,
      tokenEstimateEvidence: v3.tokenEstimateV2,
      evidenceResolver: v3Resolver,
    })).valid,
    true,
  );
  const receiptV5Validation = await validateKimiK3ReviewReceiptV5({
      receipt: receiptFixtureV5(v3),
      transportEvidence: v3.transportV3,
      tokenEstimateEvidence: v3.tokenEstimateV2,
      evidenceResolver: v3Resolver,
    });
  assert.equal(
    receiptV5Validation.valid,
    true,
    JSON.stringify(receiptV5Validation),
  );
  const v4 = fixturesV4();
  const v4Resolver = artifactResolver(v4.artifacts);
  const transportV4Validation = await validateKimiK3TransportEvidenceV4({
    evidence: v4.transportV4,
    tokenEstimateEvidence: v4.tokenEstimateV2,
    evidenceResolver: v4Resolver,
  });
  assert.equal(
    transportV4Validation.valid,
    true,
    JSON.stringify(transportV4Validation),
  );
  const receiptV6Validation = await validateKimiK3ReviewReceiptV6({
    receipt: receiptFixtureV6(v4),
    transportEvidence: v4.transportV4,
    tokenEstimateEvidence: v4.tokenEstimateV2,
    evidenceResolver: v4Resolver,
  });
  assert.equal(
    receiptV6Validation.valid,
    true,
    JSON.stringify(receiptV6Validation),
  );

  for (const invalidBytes of [
    Buffer.from(
      '{"code":1,"code":0,"data":{"total_tokens":999,"total_tokens":1000},"scode":"0x0","status":true}',
      "utf8",
    ),
    Buffer.from(
      '{"c\\u006fde":1,"code":0,"data":{"total_tokens":1000},"scode":"0x0","status":true}',
      "utf8",
    ),
    bytes({ data: { total_tokens: 1000 } }),
    bytes({
      code: 1,
      data: { total_tokens: 1000 },
      scode: "0x0",
      status: true,
    }),
    bytes({
      code: 0,
      data: { total_tokens: 1000 },
      scode: "0x1",
      status: true,
    }),
    bytes({
      code: 0,
      data: { total_tokens: 1000 },
      scode: "0x0",
      status: false,
    }),
    bytes({
      code: 0,
      data: { total_tokens: 1000 },
      scode: "0x0",
      status: true,
      extra: true,
    }),
    bytes({
      code: 0,
      data: { total_tokens: 1000 },
      scode: "0x0",
      status: true,
      authorization: "Bearer must-not-enter-evidence",
    }),
  ]) {
    const invalid = fixturesV3();
    invalid.artifacts.set(
      "evidence/token-estimate-response.json",
      invalidBytes,
    );
    invalid.tokenEstimateV2.response = responseArtifact(
      "evidence/token-estimate-response.json",
      invalidBytes,
    );
    invalid.tokenEstimateV2.evidenceSha256 =
      kimiK3ReviewEvidenceDigests.estimate(invalid.tokenEstimateV2);
    const validation = await validateKimiK3TokenEstimateEvidenceV2({
      evidence: invalid.tokenEstimateV2,
      evidenceResolver: artifactResolver(invalid.artifacts),
    });
    assert.equal(validation.valid, false);
    assert.ok(
      validation.reasonCodes.includes(
        "KIMI_K3_TOKEN_ESTIMATE_V2_RESPONSE_INVALID",
      ),
    );
  }
});

test("core MESSAGES_ONLY evidence is accepted by the evidence layer byte-for-byte", async () => {
  const fixture = fixtures();
  const configBytes = await readFile(
    resolve(
      root,
      "implementation/governance/independent-review/moonshot-kimi-k3.v2.json",
    ),
  );
  const config = JSON.parse(configBytes.toString("utf8"));
  const formalRequestBytes = fixture.artifacts.get("evidence/request.json");
  const materialBytes = fixture.artifacts.get("evidence/material.bin");
  const estimateRequestBytes = fixture.artifacts.get(
    "evidence/token-estimate-request.json",
  );
  const estimateResponseBytes = fixture.artifacts.get(
    "evidence/token-estimate-response.json",
  );
  const coreEvidence = createCoreTokenEstimateEvidence({
    evidenceId: "mk3tee_core_cross_module_001",
    config,
    configBytes,
    source: fixture.source,
    reviewBundleSha256: sha("review-bundle"),
    formalRequestBytes,
    materialBytes,
    estimateRequestBytes,
    estimateResponseBytes,
    estimatedInputTokens: 1000,
    coverage: "MESSAGES_ONLY",
    httpStatus: 200,
    contentType: "application/json; charset=utf-8",
    networkAttemptCount: 1,
    startedAt,
    finishedAt,
    artifactPaths: {
      request: "evidence/token-estimate-request.json",
      response: "evidence/token-estimate-response.json",
    },
  });
  assert.equal(
    validateCoreTokenEstimateEvidence({
      evidence: coreEvidence,
      config,
      configBytes,
      source: fixture.source,
      reviewBundleSha256: sha("review-bundle"),
      formalRequestBytes,
      materialBytes,
      estimateRequestBytes,
      estimateResponseBytes,
    }).ok,
    true,
  );
  assert.equal(
    coreEvidence.bindings.messagesSha256,
    kimiK3ReviewEvidenceDigests.bytes(
      Buffer.from(JSON.stringify(fixture.request.messages), "utf8"),
    ),
  );
  assert.equal(
    (await validateKimiK3TokenEstimateEvidence({
      evidence: coreEvidence,
      evidenceResolver: artifactResolver(fixture.artifacts),
    })).valid,
    true,
  );
});

test("created K3 evidence matches every frozen closed-field Schema", async () => {
  const fixture = fixtures();
  const receipt = receiptFixture(fixture);
  const v3 = fixturesV3();
  const receiptV5 = receiptFixtureV5(v3);
  const v4 = fixturesV4();
  const receiptV6 = receiptFixtureV6(v4);
  const v5 = fixturesV5();
  const receiptV7 = receiptFixtureV7(v5);
  const v6 = fixturesV6();
  const receiptV8 = receiptFixtureV8(v6);
  for (const [path, value] of [
    [
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v1.schema.json",
      fixture.tokenEstimate,
    ],
    [
      "implementation/governance/schemas/independent-review-transport-evidence.v2.schema.json",
      fixture.transport,
    ],
    [
      "implementation/governance/schemas/independent-model-review-receipt.v4.schema.json",
      receipt,
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v2.schema.json",
      v3.tokenEstimateV2,
    ],
    [
      "implementation/governance/schemas/independent-review-transport-evidence.v3.schema.json",
      v3.transportV3,
    ],
    [
      "implementation/governance/schemas/independent-model-review-receipt.v5.schema.json",
      receiptV5,
    ],
    [
      "implementation/governance/schemas/independent-review-transport-evidence.v4.schema.json",
      v4.transportV4,
    ],
    [
      "implementation/governance/schemas/independent-model-review-receipt.v6.schema.json",
      receiptV6,
    ],
    [
      "implementation/governance/schemas/independent-model-review-receipt.v7.schema.json",
      receiptV7,
    ],
    [
      "implementation/governance/schemas/independent-model-review-receipt.v8.schema.json",
      receiptV8,
    ],
  ]) {
    const validate = await schemaValidator(path);
    assert.equal(validate(value), true, JSON.stringify(validate.errors));
  }
  const v6Validation = await validateKimiK3ReviewReceiptV6({
    receipt: receiptV6,
    transportEvidence: v4.transportV4,
    tokenEstimateEvidence: v4.tokenEstimateV2,
    evidenceResolver: artifactResolver(v4.artifacts),
  });
  assert.equal(v6Validation.valid, true, JSON.stringify(v6Validation));
  assert.equal(
    receiptV6.isolationEvidence.runtimeDependencyManifest.path,
    "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
  );
  const v7Validation = await validateKimiK3ReviewReceiptV7({
    receipt: receiptV7,
    transportEvidence: v5.transportV4,
    tokenEstimateEvidence: v5.tokenEstimateV2,
    evidenceResolver: artifactResolver(v5.artifacts),
  });
  assert.equal(v7Validation.valid, true, JSON.stringify(v7Validation));
  assert.equal(receiptV7.schemaVersion, "independent-model-review-receipt.v7");
  assert.equal(
    receiptV7.isolationEvidence.runtimeDependencyManifest.path,
    "implementation/governance/independent-review/kimi-runtime-manifest.v3.json",
  );
  const v8Validation = await validateKimiK3ReviewReceiptV8({
    receipt: receiptV8,
    transportEvidence: v6.transportV4,
    tokenEstimateEvidence: v6.tokenEstimateV2,
    evidenceResolver: artifactResolver(v6.artifacts),
  });
  assert.equal(v8Validation.valid, true, JSON.stringify(v8Validation));
  assert.equal(receiptV8.schemaVersion, "independent-model-review-receipt.v8");
  assert.equal(
    receiptV8.isolationEvidence.runtimeDependencyManifest.path,
    "implementation/governance/independent-review/kimi-runtime-manifest.v4.json",
  );
  const v8WithHistoricalRuntime = createKimiK3ReviewReceiptV8({
    ...receiptV8,
    isolationEvidence: {
      ...receiptV8.isolationEvidence,
      runtimeDependencyManifest: {
        ...receiptV8.isolationEvidence.runtimeDependencyManifest,
        path: v5.runtimeManifestPathV3,
      },
    },
  });
  const v8HistoricalRuntimeValidation = await validateKimiK3ReviewReceiptV8({
    receipt: v8WithHistoricalRuntime,
    transportEvidence: v6.transportV4,
    tokenEstimateEvidence: v6.tokenEstimateV2,
    evidenceResolver: artifactResolver(v6.artifacts),
  });
  assert.equal(v8HistoricalRuntimeValidation.valid, false);
  assert.ok(
    v8HistoricalRuntimeValidation.reasonCodes.includes(
      "KIMI_K3_RECEIPT_V8_RSE_TOPOLOGY_INVALID",
    ),
  );
  const v7WithFutureRuntime = createKimiK3ReviewReceiptV7({
    ...receiptV7,
    isolationEvidence: {
      ...receiptV7.isolationEvidence,
      runtimeDependencyManifest: {
        ...receiptV7.isolationEvidence.runtimeDependencyManifest,
        path: v6.runtimeManifestPathV4,
      },
    },
  });
  const v7FutureRuntimeValidation = await validateKimiK3ReviewReceiptV7({
    receipt: v7WithFutureRuntime,
    transportEvidence: v5.transportV4,
    tokenEstimateEvidence: v5.tokenEstimateV2,
    evidenceResolver: artifactResolver(v5.artifacts),
  });
  assert.equal(v7FutureRuntimeValidation.valid, false);
  assert.ok(
    v7FutureRuntimeValidation.reasonCodes.includes(
      "KIMI_K3_RECEIPT_V7_RSE_TOPOLOGY_INVALID",
    ),
  );
  const historicalRuntimeBytes = readFileSync(
    resolve(
      root,
      "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
    ),
  );
  const historicalRuntime = JSON.parse(historicalRuntimeBytes.toString("utf8"));
  const forgedRuntimeArtifacts = new Map(v5.artifacts);
  forgedRuntimeArtifacts.set(v5.runtimeManifestPathV3, historicalRuntimeBytes);
  const v7WithHistoricalRuntimeBytes = createKimiK3ReviewReceiptV7({
    ...receiptV7,
    isolationEvidence: {
      ...receiptV7.isolationEvidence,
      runtimeTrust: {
        ...receiptV7.isolationEvidence.runtimeTrust,
        runtimeManifestGitBlobSha256:
          kimiK3ReviewEvidenceDigests.bytes(historicalRuntimeBytes),
      },
      runtimeDependencyManifest: {
        ...receiptV7.isolationEvidence.runtimeDependencyManifest,
        gitBlobSha256:
          kimiK3ReviewEvidenceDigests.bytes(historicalRuntimeBytes),
        manifestSha256: historicalRuntime.manifestSha256,
        nodeExecutableSha256: historicalRuntime.node.executableSha256,
        fullDependencyTreeSha256:
          historicalRuntime.dependencies.fullTreeSha256,
        npmPackageTreeSha256: historicalRuntime.npm.packageTreeSha256,
      },
    },
  });
  const historicalRuntimeBytesValidation =
    await validateKimiK3ReviewReceiptV7({
      receipt: v7WithHistoricalRuntimeBytes,
      transportEvidence: v5.transportV4,
      tokenEstimateEvidence: v5.tokenEstimateV2,
      evidenceResolver: artifactResolver(forgedRuntimeArtifacts),
    });
  assert.equal(historicalRuntimeBytesValidation.valid, false);
  assert.ok(
    historicalRuntimeBytesValidation.reasonCodes.includes(
      "KIMI_K3_RECEIPT_V7_RUNTIME_MANIFEST_INVALID",
    ),
  );
  const v7WithSplitRuntimeTrust = createKimiK3ReviewReceiptV7({
    ...receiptV7,
    isolationEvidence: {
      ...receiptV7.isolationEvidence,
      runtimeTrust: {
        ...receiptV7.isolationEvidence.runtimeTrust,
        runtimeManifestGitBlobSha256: `sha256:${"0".repeat(64)}`,
      },
    },
  });
  const splitRuntimeTrustValidation = await validateKimiK3ReviewReceiptV7({
    receipt: v7WithSplitRuntimeTrust,
    transportEvidence: v5.transportV4,
    tokenEstimateEvidence: v5.tokenEstimateV2,
    evidenceResolver: artifactResolver(v5.artifacts),
  });
  assert.equal(splitRuntimeTrustValidation.valid, false);
  assert.ok(
    splitRuntimeTrustValidation.reasonCodes.includes(
      "KIMI_K3_RECEIPT_V7_RSE_TOPOLOGY_INVALID",
    ),
  );
  const tamperedRuntimeSchemaBytes = Buffer.concat([
    v5.runtimeManifestSchemaBytesV3,
    Buffer.from("\n", "utf8"),
  ]);
  const tamperedRuntimeSchemaArtifacts = new Map(v5.artifacts);
  tamperedRuntimeSchemaArtifacts.set(
    v5.runtimeManifestSchemaPathV3,
    tamperedRuntimeSchemaBytes,
  );
  const tamperedRuntimeSchemaValidation =
    await validateKimiK3ReviewReceiptV7({
      receipt: receiptV7,
      transportEvidence: v5.transportV4,
      tokenEstimateEvidence: v5.tokenEstimateV2,
      evidenceResolver: artifactResolver(tamperedRuntimeSchemaArtifacts),
    });
  assert.equal(tamperedRuntimeSchemaValidation.valid, false);
  assert.ok(
    tamperedRuntimeSchemaValidation.reasonCodes.includes(
      "KIMI_K3_RECEIPT_V7_RUNTIME_MANIFEST_INVALID",
    ),
  );
  const v7WithHistoricalRuntime = createKimiK3ReviewReceiptV7({
    ...receiptV7,
    isolationEvidence: {
      ...receiptV7.isolationEvidence,
      runtimeDependencyManifest: {
        ...receiptV7.isolationEvidence.runtimeDependencyManifest,
        path: "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
      },
    },
  });
  const v7HistoricalRuntimeValidation =
    await validateKimiK3ReviewReceiptV7({
      receipt: v7WithHistoricalRuntime,
      transportEvidence: v5.transportV4,
      tokenEstimateEvidence: v5.tokenEstimateV2,
      evidenceResolver: artifactResolver(v5.artifacts),
    });
  assert.equal(v7HistoricalRuntimeValidation.valid, false);
  assert.ok(
    v7HistoricalRuntimeValidation.reasonCodes.includes(
      "KIMI_K3_RECEIPT_V7_RSE_TOPOLOGY_INVALID",
    ),
  );
  const v6WithFutureRuntime = createKimiK3ReviewReceiptV6({
    ...receiptV6,
    isolationEvidence: {
      ...receiptV6.isolationEvidence,
      runtimeDependencyManifest: {
        ...receiptV6.isolationEvidence.runtimeDependencyManifest,
        path: "implementation/governance/independent-review/kimi-runtime-manifest.v3.json",
      },
    },
  });
  const v6FutureRuntimeValidation = await validateKimiK3ReviewReceiptV6({
    receipt: v6WithFutureRuntime,
    transportEvidence: v4.transportV4,
    tokenEstimateEvidence: v4.tokenEstimateV2,
    evidenceResolver: artifactResolver(v4.artifacts),
  });
  assert.equal(v6FutureRuntimeValidation.valid, false);
  assert.ok(
    v6FutureRuntimeValidation.reasonCodes.includes(
      "KIMI_K3_RECEIPT_V6_RSE_TOPOLOGY_INVALID",
    ),
  );
  const validateReceiptV5 = await schemaValidator(
    "implementation/governance/schemas/independent-model-review-receipt.v5.schema.json",
  );
  const receiptWithUnknownNestedField = structuredClone(receiptV5);
  receiptWithUnknownNestedField.source.callerSuppliedReady = true;
  assert.equal(validateReceiptV5(receiptWithUnknownNestedField), false);
  const validateReceiptV6 = await schemaValidator(
    "implementation/governance/schemas/independent-model-review-receipt.v6.schema.json",
  );
  const receiptV6WithUnknownNestedField = structuredClone(receiptV6);
  receiptV6WithUnknownNestedField.source.callerSuppliedReady = true;
  assert.equal(validateReceiptV6(receiptV6WithUnknownNestedField), false);
});

test("K3 transport rejects old-model impersonation, truncation and usage drift", async () => {
  for (const mutate of [
    (value) => (value.actualReturnedModel = "kimi-k2.7-code"),
    (value) => (value.protocol.finishReason = "length"),
    (value) => (value.usage.totalTokens = 1201),
    (value) => (value.cost.totalMicros = 6001),
    (value) => (value.protocol.thinkingAbsent = false),
  ]) {
    const fixture = fixtures();
    const changed = structuredClone(fixture.transport);
    mutate(changed);
    changed.transportEvidenceSha256 =
      kimiK3ReviewEvidenceDigests.transport(changed);
    const result = await validateKimiK3TransportEvidence({
      evidence: changed,
      tokenEstimateEvidence: fixture.tokenEstimate,
      evidenceResolver: artifactResolver(fixture.artifacts),
    });
    assert.equal(result.valid, false);
  }
  for (const mutate of [
    (value) => (value.actualReturnedModel = "kimi-k2.7-code"),
    (value) => (value.protocol.providerTransportSchemaValidated = false),
    (value) => (value.protocol.canonicalOutputSchemaValidated = false),
    (value) =>
      (value.bindings.providerTransportSchemaSha256 = sha("wrong-provider")),
    (value) =>
      (value.bindings.canonicalOutputSchemaSha256 = sha("wrong-canonical")),
    (value) => {
      const providerPath = value.bindings.providerTransportSchemaPath;
      value.bindings.providerTransportSchemaPath =
        value.bindings.canonicalOutputSchemaPath;
      value.bindings.canonicalOutputSchemaPath = providerPath;
    },
  ]) {
    const fixture = fixturesV4();
    const changed = structuredClone(fixture.transportV4);
    mutate(changed);
    changed.transportEvidenceSha256 =
      kimiK3ReviewEvidenceDigests.transport(changed);
    const result = await validateKimiK3TransportEvidenceV4({
      evidence: changed,
      tokenEstimateEvidence: fixture.tokenEstimateV2,
      evidenceResolver: artifactResolver(fixture.artifacts),
    });
    assert.equal(result.valid, false);
  }
  for (const mutate of [
    (value) => (value.actualReturnedModel = "kimi-k2.7-code"),
    (value) => (value.protocol.finishReason = "length"),
    (value) => (value.protocol.outputSchemaValidated = false),
    (value) => (value.protocol.semanticValidated = false),
    (value) => (value.bindings.nonMessageVisibleInputSha256 = sha("wrong")),
  ]) {
    const fixture = fixturesV3();
    const changed = structuredClone(fixture.transportV3);
    mutate(changed);
    changed.transportEvidenceSha256 =
      kimiK3ReviewEvidenceDigests.transport(changed);
    const result = await validateKimiK3TransportEvidenceV3({
      evidence: changed,
      tokenEstimateEvidence: fixture.tokenEstimateV2,
      evidenceResolver: artifactResolver(fixture.artifacts),
    });
    assert.equal(result.valid, false);
  }

  const fixture = fixturesV3();
  const response = structuredClone(fixture.response);
  response.usage.cached_tokens = 400;
  const responseBytes = Buffer.from(JSON.stringify(response), "utf8");
  fixture.artifacts.set("evidence/response.json", responseBytes);

  const transport = structuredClone(fixture.transportV3);
  transport.response = responseArtifact("evidence/response.json", responseBytes);
  transport.usage.cachedTokens = 400;
  transport.cost.inputMicros = 1920;
  transport.cost.totalMicros = 4920;
  transport.transportEvidenceSha256 =
    kimiK3ReviewEvidenceDigests.transport(transport);

  const result = await validateKimiK3TransportEvidenceV3({
    evidence: transport,
    tokenEstimateEvidence: fixture.tokenEstimateV2,
    evidenceResolver: artifactResolver(fixture.artifacts),
  });
  assert.equal(result.valid, true, JSON.stringify(result));

  const malformed = fixturesV3();
  const malformedContent = {
    schemaVersion: "independent-model-review-output.v2",
    reviewSummary: "Malformed finding must not pass independent revalidation.",
    decision: "CLEAR",
    findings: [{}],
  };
  const malformedContentBytes = Buffer.from(
    JSON.stringify(malformedContent),
    "utf8",
  );
  const malformedResponse = structuredClone(malformed.response);
  malformedResponse.choices[0].message.content =
    malformedContentBytes.toString("utf8");
  const malformedResponseBytes = Buffer.from(
    JSON.stringify(malformedResponse),
    "utf8",
  );
  malformed.artifacts.set("evidence/content.json", malformedContentBytes);
  malformed.artifacts.set("evidence/response.json", malformedResponseBytes);
  const malformedTransport = structuredClone(malformed.transportV3);
  malformedTransport.content = byteArtifact(
    "evidence/content.json",
    malformedContentBytes,
  );
  malformedTransport.response = responseArtifact(
    "evidence/response.json",
    malformedResponseBytes,
  );
  malformedTransport.transportEvidenceSha256 =
    kimiK3ReviewEvidenceDigests.transport(malformedTransport);
  assert.equal(
    (await validateKimiK3TransportEvidenceV3({
      evidence: malformedTransport,
      tokenEstimateEvidence: malformed.tokenEstimateV2,
      evidenceResolver: artifactResolver(malformed.artifacts),
    })).valid,
    false,
  );

  const substitutedSchema = fixturesV3();
  substitutedSchema.artifacts.set(
    "implementation/output-schema.json",
    Buffer.from("{}", "utf8"),
  );
  assert.equal(
    (await validateKimiK3TransportEvidenceV3({
      evidence: substitutedSchema.transportV3,
      tokenEstimateEvidence: substitutedSchema.tokenEstimateV2,
      evidenceResolver: artifactResolver(substitutedSchema.artifacts),
    })).valid,
    false,
  );

  const receiptFixtureValue = fixturesV3();
  const receipt = receiptFixtureV5(receiptFixtureValue);
  receipt.bindings.canonicalOutputSchemaSha256 = sha("wrong-output-schema");
  receipt.receiptSha256 = kimiK3ReviewEvidenceDigests.receipt(receipt);
  assert.equal(
    (await validateKimiK3ReviewReceiptV5({
      receipt,
      transportEvidence: receiptFixtureValue.transportV3,
      tokenEstimateEvidence: receiptFixtureValue.tokenEstimateV2,
      evidenceResolver: artifactResolver(receiptFixtureValue.artifacts),
    })).valid,
    false,
  );

  const receiptV6FixtureValue = fixturesV4();
  for (const mutate of [
    (value) =>
      (value.bindings.providerTransportSchemaSha256 = sha("wrong-provider")),
    (value) =>
      (value.bindings.canonicalOutputSchemaSha256 = sha("wrong-canonical")),
    (value) =>
      (value.bindings.transportEvidenceSchemaSha256 = sha("wrong-transport")),
  ]) {
    const receiptV6 = receiptFixtureV6(receiptV6FixtureValue);
    mutate(receiptV6);
    receiptV6.receiptSha256 =
      kimiK3ReviewEvidenceDigests.receipt(receiptV6);
    assert.equal(
      (await validateKimiK3ReviewReceiptV6({
        receipt: receiptV6,
        transportEvidence: receiptV6FixtureValue.transportV4,
        tokenEstimateEvidence: receiptV6FixtureValue.tokenEstimateV2,
        evidenceResolver: artifactResolver(receiptV6FixtureValue.artifacts),
      })).valid,
      false,
    );
  }
});

test("K3 evidence rejects self-hash and exact artifact byte tampering", async () => {
  const fixture = fixtures();
  const changed = structuredClone(fixture.tokenEstimate);
  changed.evidenceSha256 = sha("wrong");
  assert.equal(
    (await validateKimiK3TokenEstimateEvidence({
      evidence: changed,
      evidenceResolver: artifactResolver(fixture.artifacts),
    })).valid,
    false,
  );
  const bytesChanged = new Map(fixture.artifacts);
  bytesChanged.set("evidence/content.json", Buffer.from("{}", "utf8"));
  assert.equal(
    (await validateKimiK3TransportEvidence({
      evidence: fixture.transport,
      tokenEstimateEvidence: fixture.tokenEstimate,
      evidenceResolver: artifactResolver(bytesChanged),
    })).valid,
    false,
  );
  const evidenceChanged = new Map(fixture.artifacts);
  const differentEstimate = structuredClone(fixture.tokenEstimate);
  differentEstimate.evidenceId = "mk3tee_different_001";
  differentEstimate.evidenceSha256 =
    kimiK3ReviewEvidenceDigests.estimate(differentEstimate);
  evidenceChanged.set(
    "evidence/token-estimate-evidence.json",
    Buffer.from(JSON.stringify(differentEstimate), "utf8"),
  );
  const receipt = receiptFixture(fixture);
  receipt.artifacts.tokenEstimateEvidence = byteArtifact(
    "evidence/token-estimate-evidence.json",
    evidenceChanged.get("evidence/token-estimate-evidence.json"),
  );
  receipt.receiptSha256 = kimiK3ReviewEvidenceDigests.receipt(receipt);
  assert.equal(
    (await validateKimiK3ReviewReceipt({
      receipt,
      transportEvidence: fixture.transport,
      tokenEstimateEvidence: fixture.tokenEstimate,
      evidenceResolver: artifactResolver(evidenceChanged),
    })).valid,
    false,
  );

  const v4 = fixturesV4();
  for (const path of [
    v4.providerTransportSchemaPath,
    v4.canonicalOutputSchemaPath,
    v4.transportEvidenceSchemaPath,
    v4.receiptSchemaPath,
  ]) {
    const tamperedArtifacts = new Map(v4.artifacts);
    tamperedArtifacts.set(path, Buffer.from("{}\n", "utf8"));
    const transportValidation = await validateKimiK3TransportEvidenceV4({
      evidence: v4.transportV4,
      tokenEstimateEvidence: v4.tokenEstimateV2,
      evidenceResolver: artifactResolver(tamperedArtifacts),
    });
    const receiptValidation = await validateKimiK3ReviewReceiptV6({
      receipt: receiptFixtureV6(v4),
      transportEvidence: v4.transportV4,
      tokenEstimateEvidence: v4.tokenEstimateV2,
      evidenceResolver: artifactResolver(tamperedArtifacts),
    });
    assert.equal(
      transportValidation.valid && receiptValidation.valid,
      false,
      `tampered frozen Schema bytes must fail closed: ${path}`,
    );
  }
});

test("FULL coverage is rejected rather than self-asserted", async () => {
  const fixture = fixtures();
  const changed = structuredClone(fixture.tokenEstimate);
  changed.bindings.requestSchemaCoverage = "FULL_MODEL_VISIBLE_INPUT_PROVED";
  changed.estimate.coverage = "FULL_MODEL_VISIBLE_INPUT_PROVED";
  changed.estimate.contextProved = true;
  changed.budget.budgetProved = true;
  changed.evidenceSha256 = kimiK3ReviewEvidenceDigests.estimate(changed);
  const result = await validateKimiK3TokenEstimateEvidence({
    evidence: changed,
    evidenceResolver: artifactResolver(fixture.artifacts),
  });
  assert.equal(result.valid, false);

  for (const mutate of [
    (value) => (value.estimate.nonMessageVisibleTokenReserve = 0),
    (value) => (value.bindings.nonMessageVisibleInputByteLength = 16385),
    (value) => (value.bindings.nonMessageVisibleInputSha256 = sha("wrong")),
    (value) => (value.estimate.requiredContextTokens = 1048577),
    (value) => (value.budget.worstCaseTotalMicros = 4000001),
  ]) {
    const v3 = fixturesV3();
    const changedV3 = structuredClone(v3.tokenEstimateV2);
    mutate(changedV3);
    changedV3.evidenceSha256 = kimiK3ReviewEvidenceDigests.estimate(changedV3);
    const validation = await validateKimiK3TokenEstimateEvidenceV2({
      evidence: changedV3,
      evidenceResolver: artifactResolver(v3.artifacts),
    });
    assert.equal(validation.valid, false);
  }
});

test("arbitrary model content cannot substantiate a CLEAR Receipt", async () => {
  const fixture = fixtures();
  const arbitrary = Buffer.from('{"anything":"clear"}', "utf8");
  fixture.artifacts.set("evidence/content.json", arbitrary);
  const receipt = receiptFixture(fixture);
  receipt.artifacts.content = byteArtifact("evidence/content.json", arbitrary);
  receipt.bindings.rawContentUtf8Sha256 = receipt.artifacts.content.sha256;
  receipt.receiptSha256 = kimiK3ReviewEvidenceDigests.receipt(receipt);
  const result = await validateKimiK3ReviewReceipt({
    receipt,
    transportEvidence: fixture.transport,
    tokenEstimateEvidence: fixture.tokenEstimate,
    evidenceResolver: artifactResolver(fixture.artifacts),
  });
  assert.equal(result.valid, false);
  assert.ok(
    result.reasonCodes.includes("KIMI_K3_RECEIPT_MODEL_CONTENT_INVALID"),
  );
});

test("Receipt rejects blocking findings, R/S drift and history impersonation", async () => {
  for (const mutate of [
    (value) =>
      value.findings.push({
        findingId: "critical_open_001",
        severity: "CRITICAL",
        status: "OPEN",
        path: "lib/kimi-k3-review-evidence.mjs",
        startLine: 1,
        endLine: 1,
        summary: "blocking",
        detailsSha256: sha("finding"),
        resolutionEvidenceDigests: [],
      }),
    (value) => (value.isolationEvidence.runtimeTrust.subjectTree = commit("f")),
    (value) => (value.historicalK2EvidenceAccepted = true),
    (value) => (value.reviewer.actualReturnedModel = "kimi-k2.7-code"),
    (value) => (value.reviewer.reviewerSessionId = "chatcmpl_forged_session"),
  ]) {
    const fixture = fixtures();
    const receipt = receiptFixture(fixture);
    mutate(receipt);
    receipt.receiptSha256 = kimiK3ReviewEvidenceDigests.receipt(receipt);
    const result = await validateKimiK3ReviewReceipt({
      receipt,
      transportEvidence: fixture.transport,
      tokenEstimateEvidence: fixture.tokenEstimate,
      evidenceResolver: artifactResolver(fixture.artifacts),
    });
    assert.equal(result.valid, false);
  }
});

test("Receipt self-hash tampering and non-human governance claims fail closed", async () => {
  const fixture = fixtures();
  for (const mutate of [
    (value) => (value.receiptSha256 = sha("wrong")),
    (value) => (value.humanReviewClaim = true),
    (value) => (value.governanceEffect = "D1_APPROVED"),
    (value) => (value.selfAuthorizing = true),
  ]) {
    const receipt = receiptFixture(fixture);
    mutate(receipt);
    const result = await validateKimiK3ReviewReceipt({
      receipt,
      transportEvidence: fixture.transport,
      tokenEstimateEvidence: fixture.tokenEstimate,
      evidenceResolver: artifactResolver(fixture.artifacts),
    });
    assert.equal(result.valid, false);
  }
});
