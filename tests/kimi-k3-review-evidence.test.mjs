import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  createKimiK3ReviewReceipt,
  createKimiK3TokenEstimateEvidence,
  createKimiK3TransportEvidence,
  kimiK3ReviewEvidenceDigests,
  validateKimiK3ReviewReceipt,
  validateKimiK3TokenEstimateEvidence,
  validateKimiK3TransportEvidence,
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
  const outputSchema = {
    type: "object",
    additionalProperties: false,
    required: ["decision", "findings"],
    properties: {
      decision: { enum: ["CLEAR", "BLOCKED", "INCONCLUSIVE"] },
      findings: { type: "array" },
    },
  };
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
  ]) {
    const validate = await schemaValidator(path);
    assert.equal(validate(value), true, JSON.stringify(validate.errors));
  }
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
