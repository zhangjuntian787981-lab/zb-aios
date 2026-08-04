import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  createKimiK3TokenEstimateEvidenceV2,
  kimiK3ReviewEvidenceDigests,
} from "../lib/kimi-k3-review-evidence.mjs";
import {
  validateIndependentReviewSchemaInstance,
} from "../lib/independent-model-review.mjs";
import {
  buildKimiIntegrationReviewMaterial,
  buildKimiSegmentReviewMaterials,
  createKimiAggregateReceipt,
  createKimiIntegrationReceipt,
  createKimiSegmentedTransportEvidence,
  createKimiSegmentReceipt,
  createKimiSegmentReviewPlan,
  evaluateKimiAggregateDecision,
  evaluateKimiAggregateInputs,
  parseKimiIntegrationReviewMaterial,
  parseKimiSegmentReviewMaterial,
  segmentedKimiReviewDigests,
  validateKimiAggregateReceipt,
  validateKimiIntegrationReviewMaterial,
  validateKimiIntegrationReceipt,
  validateKimiSegmentReviewMaterial,
  validateKimiSegmentReceipt,
  validateKimiSegmentReviewPlan,
  verifyKimiReviewReceiptSet,
  verifyKimiSegmentedModelExecution,
  verifyKimiSegmentReceiptSet,
} from "../lib/kimi-segmented-independent-review.mjs";

const commit = (character) => character.repeat(40);
const sha = (value) =>
  segmentedKimiReviewDigests.bytes(Buffer.from(value, "utf8"));
const now = "2026-08-02T00:00:00.000Z";

const paths = Object.freeze({
  governance: "docs/adr/0020-kimi-k3-segmented-review.md",
  schema:
    "implementation/governance/schemas/independent-review-segment-plan.v1.schema.json",
  runtime: "lib/kimi-segmented-independent-review.mjs",
  test: "tests/kimi-segmented-independent-review.test.mjs",
});
const historicalPaths = Object.freeze(
  [
    "formal-request.json",
    "review-bundle.v2.json",
    "review-material.v3.utf8",
    "single-call-outcome.v1.json",
    "token-estimate-request.json",
  ].map(
    (name) =>
      `implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/${name}`,
  ),
);
const requiredIntegrationPaths = Object.freeze([
  "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
  "docs/adr/0020-kimi-k3-segmented-independent-review.md",
  "CONTEXT.md",
]);

function fixture() {
  const sourceBytes = new Map(
    [...Object.values(paths), ...historicalPaths].map((path) => [
      path,
      historicalPaths.includes(path)
        ? readFileSync(path)
        : Buffer.from(`exact bytes for ${path}`, "utf8"),
    ]),
  );
  const reviewedPaths = [...Object.values(paths), ...historicalPaths].sort();
  const sourceSubjects = reviewedPaths.map((path) => ({
    path,
    gitMode: "100644",
    blobSha256: segmentedKimiReviewDigests.bytes(sourceBytes.get(path)),
  }));
  const bundle = {
    schemaVersion: "independent-review-bundle.v2",
    bundleId: "imrb_segmented_fixture_001",
    bundleSha256: sha("bundle semantic digest"),
    source: {
      baseCommit: commit("a"),
      sourceCommit: commit("b"),
      headCommit: commit("b"),
      tree: commit("c"),
      diffSha256: sha("exact full git patch\n"),
      changedPathsDigest: segmentedKimiReviewDigests.value(reviewedPaths),
    },
    reviewedPaths,
    sourceSubjects,
  };
  const bundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const promptBytes = Buffer.from("review this exact segment", "utf8");
  const integrationPromptBytes = Buffer.from(
    "review cross-cutting integration from validated receipts and exact patch",
    "utf8",
  );
  const commonBytes = new Map([
    ["AGENTS.md", Buffer.from("frozen agent rules", "utf8")],
    [
      "formal-tests.result.json",
      Buffer.from('{"status":"PASS"}', "utf8"),
    ],
    ...requiredIntegrationPaths.map((path) => [path, readFileSync(path)]),
  ]);
  const schemaBytes = (path) => readFileSync(path);
  const bindingBytes = new Map([
    ["artifacts/review-bundle.v2.json", bundleBytes],
    ["implementation/reviewer-prompt.md", promptBytes],
    ["implementation/integration-prompt.md", integrationPromptBytes],
    [
      "implementation/governance/schemas/independent-model-segmented-review-output.v1.schema.json",
      schemaBytes("implementation/governance/schemas/independent-model-segmented-review-output.v1.schema.json"),
    ],
    [
      "implementation/governance/schemas/moonshot-kimi-k3-segmented-review-output.mfjs.v1.schema.json",
      schemaBytes("implementation/governance/schemas/moonshot-kimi-k3-segmented-review-output.mfjs.v1.schema.json"),
    ],
    ["implementation/provider-config.json", Buffer.from("{}", "utf8")],
    ["implementation/provider-config-schema.json", Buffer.from("{}", "utf8")],
    [
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v2.schema.json",
      schemaBytes("implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v2.schema.json"),
    ],
    [
      "implementation/governance/schemas/independent-review-segmented-transport-evidence.v1.schema.json",
      schemaBytes("implementation/governance/schemas/independent-review-segmented-transport-evidence.v1.schema.json"),
    ],
    [
      "implementation/governance/schemas/independent-model-segment-review-receipt.v1.schema.json",
      schemaBytes("implementation/governance/schemas/independent-model-segment-review-receipt.v1.schema.json"),
    ],
    [
      "implementation/governance/schemas/independent-model-integration-review-receipt.v1.schema.json",
      schemaBytes("implementation/governance/schemas/independent-model-integration-review-receipt.v1.schema.json"),
    ],
    [
      "implementation/governance/schemas/independent-model-aggregate-review-receipt.v1.schema.json",
      schemaBytes("implementation/governance/schemas/independent-model-aggregate-review-receipt.v1.schema.json"),
    ],
  ]);
  const descriptor = (path, bytes) => ({
    path,
    byteLength: bytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(bytes),
  });
  const bindings = {
    reviewBundle: descriptor(
      "artifacts/review-bundle.v2.json",
      bundleBytes,
    ),
    segmentReviewerPrompt: descriptor(
      "implementation/reviewer-prompt.md",
      promptBytes,
    ),
    integrationReviewerPrompt: descriptor(
      "implementation/integration-prompt.md",
      integrationPromptBytes,
    ),
    canonicalOutputSchema: descriptor(
      "implementation/governance/schemas/independent-model-segmented-review-output.v1.schema.json",
      bindingBytes.get("implementation/governance/schemas/independent-model-segmented-review-output.v1.schema.json"),
    ),
    providerTransportSchema: descriptor(
      "implementation/governance/schemas/moonshot-kimi-k3-segmented-review-output.mfjs.v1.schema.json",
      bindingBytes.get("implementation/governance/schemas/moonshot-kimi-k3-segmented-review-output.mfjs.v1.schema.json"),
    ),
    providerConfig: descriptor(
      "implementation/provider-config.json",
      bindingBytes.get("implementation/provider-config.json"),
    ),
    providerConfigSchema: descriptor(
      "implementation/provider-config-schema.json",
      bindingBytes.get("implementation/provider-config-schema.json"),
    ),
    tokenEstimateEvidenceSchema: descriptor(
      "implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v2.schema.json",
      bindingBytes.get("implementation/governance/schemas/moonshot-kimi-k3-token-estimate-evidence.v2.schema.json"),
    ),
    segmentedTransportEvidenceSchema: descriptor(
      "implementation/governance/schemas/independent-review-segmented-transport-evidence.v1.schema.json",
      bindingBytes.get("implementation/governance/schemas/independent-review-segmented-transport-evidence.v1.schema.json"),
    ),
    segmentReceiptSchema: descriptor(
      "implementation/governance/schemas/independent-model-segment-review-receipt.v1.schema.json",
      bindingBytes.get("implementation/governance/schemas/independent-model-segment-review-receipt.v1.schema.json"),
    ),
    integrationReceiptSchema: descriptor(
      "implementation/governance/schemas/independent-model-integration-review-receipt.v1.schema.json",
      bindingBytes.get("implementation/governance/schemas/independent-model-integration-review-receipt.v1.schema.json"),
    ),
    aggregateReceiptSchema: descriptor(
      "implementation/governance/schemas/independent-model-aggregate-review-receipt.v1.schema.json",
      bindingBytes.get("implementation/governance/schemas/independent-model-aggregate-review-receipt.v1.schema.json"),
    ),
  };
  const commonSections = [...commonBytes]
    .filter(([path]) => !requiredIntegrationPaths.includes(path))
    .map(([path, bytes]) => ({
      kind: path === "AGENTS.md" ? "SPECIFICATION" : "TEST_EVIDENCE",
      ...descriptor(path, bytes),
    }));
  const integrationSections = requiredIntegrationPaths.map((path) => ({
    kind: path.startsWith("docs/adr/") || path.endsWith(".json")
      ? "GOVERNANCE"
      : "SPECIFICATION",
    ...descriptor(path, commonBytes.get(path)),
  }));
  return {
    bundle,
    bundleBytes,
    promptBytes,
    integrationPromptBytes,
    sourceBytes,
    commonBytes,
    bindingBytes,
    bindings,
    commonSections,
    integrationSections,
    sourceBytesResolver: async (path) => sourceBytes.get(path) ?? null,
    commonBytesResolver: async (path) =>
      commonBytes.get(path) ?? bindingBytes.get(path) ?? null,
  };
}

async function planFixture() {
  const values = fixture();
  const plan = await createKimiSegmentReviewPlan({
    planId: "imsrp_fixture_001",
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    bindings: values.bindings,
    commonSections: values.commonSections,
    integrationSections: values.integrationSections,
    sourceBytesResolver: values.sourceBytesResolver,
  });
  return { ...values, plan };
}

test("Segment Plan closes four role-based segments over every reviewed path exactly once", async () => {
  const { plan, bundle, sourceBytesResolver } = await planFixture();
  assert.equal(plan.segments.length, 4);
  assert.deepEqual(
    plan.segments.map(({ segmentId, pathCount }) => ({ segmentId, pathCount })),
    [
      { segmentId: "GOVERNANCE_LINEAGE", pathCount: 6 },
      { segmentId: "SCHEMAS_WIRE_CONTRACTS", pathCount: 1 },
      { segmentId: "RUNTIME_ORCHESTRATION", pathCount: 1 },
      { segmentId: "TESTS_VERIFICATION", pathCount: 1 },
    ],
  );
  assert.equal(plan.coverage.expectedPathCount, 9);
  assert.equal(plan.coverage.actualPathCount, 9);
  assert.deepEqual(plan.coverage.missingPaths, []);
  assert.deepEqual(plan.coverage.duplicatePaths, []);
  assert.deepEqual(plan.coverage.unexpectedPaths, []);
  assert.equal(
    plan.coverage.unionPathSetSha256,
    bundle.source.changedPathsDigest,
  );
  assert.equal(
    (
      await validateKimiSegmentReviewPlan({
        plan,
        bundle,
        sourceBytesResolver,
      })
    ).ok,
    true,
  );
});

test("unknown paths, duplicates, source-byte drift, and caller-authored plan changes fail closed", async () => {
  const values = fixture();
  const unknown = structuredClone(values.bundle);
  unknown.reviewedPaths.push("unknown/unclassified.txt");
  unknown.reviewedPaths.sort();
  unknown.sourceSubjects.push({
    path: "unknown/unclassified.txt",
    gitMode: "100644",
    blobSha256: sha("unknown"),
  });
  unknown.sourceSubjects.sort(({ path: a }, { path: b }) => a.localeCompare(b));
  unknown.source.changedPathsDigest = segmentedKimiReviewDigests.value(
    unknown.reviewedPaths,
  );
  const unknownBundleBytes = Buffer.from(JSON.stringify(unknown), "utf8");
  const unknownBindings = structuredClone(values.bindings);
  unknownBindings.reviewBundle = {
    path: "artifacts/review-bundle.v2.json",
    byteLength: unknownBundleBytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(unknownBundleBytes),
  };
  await assert.rejects(
    createKimiSegmentReviewPlan({
      planId: "imsrp_unknown_001",
      bundle: unknown,
      bundleBytes: unknownBundleBytes,
      bindings: unknownBindings,
      commonSections: values.commonSections,
      integrationSections: values.integrationSections,
      sourceBytesResolver: async (path) =>
        path === "unknown/unclassified.txt"
          ? Buffer.from("unknown", "utf8")
          : values.sourceBytesResolver(path),
    }),
    /SEGMENT_PATH_UNCLASSIFIED/u,
  );

  const { plan, bundle, sourceBytesResolver } = await planFixture();
  const duplicate = structuredClone(plan);
  duplicate.segments[1].ownedPaths.push(
    structuredClone(duplicate.segments[0].ownedPaths[0]),
  );
  duplicate.segments[1].pathCount += 1;
  assert.equal(
    (
      await validateKimiSegmentReviewPlan({
        plan: duplicate,
        bundle,
        sourceBytesResolver,
      })
    ).ok,
    false,
  );

  const tampered = structuredClone(plan);
  tampered.segments[0].ownedPaths[0].contentSha256 = sha("tampered");
  assert.equal(
    (
      await validateKimiSegmentReviewPlan({
        plan: tampered,
        bundle,
        sourceBytesResolver,
      })
    ).ok,
    false,
  );

  const callerExtended = structuredClone(plan);
  callerExtended.callerReady = true;
  callerExtended.planSha256 = segmentedKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(callerExtended).filter(([key]) => key !== "planSha256"),
    ),
  );
  assert.equal(
    (
      await validateKimiSegmentReviewPlan({
        plan: callerExtended,
        bundle,
        sourceBytesResolver,
      })
    ).ok,
    false,
  );

  const nestedExtended = structuredClone(plan);
  nestedExtended.segments[0].ownedPaths[0].callerReady = true;
  nestedExtended.planSha256 = segmentedKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(nestedExtended).filter(([key]) => key !== "planSha256"),
    ),
  );
  assert.equal(
    (
      await validateKimiSegmentReviewPlan({
        plan: nestedExtended,
        bundle,
        sourceBytesResolver,
      })
    ).ok,
    false,
  );

  const missingHistory = fixture();
  const removedPath = historicalPaths[0];
  missingHistory.bundle.reviewedPaths = missingHistory.bundle.reviewedPaths.filter(
    (path) => path !== removedPath,
  );
  missingHistory.bundle.sourceSubjects = missingHistory.bundle.sourceSubjects.filter(
    ({ path }) => path !== removedPath,
  );
  missingHistory.bundle.source.changedPathsDigest = segmentedKimiReviewDigests.value(
    missingHistory.bundle.reviewedPaths,
  );
  missingHistory.bundleBytes = Buffer.from(
    JSON.stringify(missingHistory.bundle),
    "utf8",
  );
  missingHistory.bindings.reviewBundle = {
    path: "artifacts/review-bundle.v2.json",
    byteLength: missingHistory.bundleBytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(missingHistory.bundleBytes),
  };
  await assert.rejects(
    createKimiSegmentReviewPlan({
      planId: "imsrp_missing_history_001",
      bundle: missingHistory.bundle,
      bundleBytes: missingHistory.bundleBytes,
      bindings: missingHistory.bindings,
      commonSections: missingHistory.commonSections,
      integrationSections: missingHistory.integrationSections,
      sourceBytesResolver: missingHistory.sourceBytesResolver,
    }),
    /SEGMENT_HISTORICAL_EVIDENCE_INCOMPLETE/u,
  );

  const contradictoryBundleBytes = Buffer.from(
    JSON.stringify({ ...bundle, reviewedPaths: ["evil/not-reviewed"] }),
    "utf8",
  );
  const contradictoryBindings = structuredClone(plan.bindings);
  contradictoryBindings.reviewBundle = {
    path: "artifacts/review-bundle.v2.json",
    byteLength: contradictoryBundleBytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(contradictoryBundleBytes),
  };
  await assert.rejects(
    createKimiSegmentReviewPlan({
      planId: "imsrp_bundle_mismatch_001",
      bundle,
      bundleBytes: contradictoryBundleBytes,
      bindings: contradictoryBindings,
      commonSections: values.commonSections,
      integrationSections: values.integrationSections,
      sourceBytesResolver: values.sourceBytesResolver,
    }),
    /SEGMENT_BUNDLE_BYTES_MISMATCH/u,
  );

  const duplicateKeyBundleBytes = Buffer.from(
    `{"schemaVersion":"bogus",${values.bundleBytes.toString("utf8").slice(1)}`,
    "utf8",
  );
  const duplicateKeyBindings = structuredClone(values.bindings);
  duplicateKeyBindings.reviewBundle = {
    path: "artifacts/review-bundle.v2.json",
    byteLength: duplicateKeyBundleBytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(duplicateKeyBundleBytes),
  };
  await assert.rejects(
    createKimiSegmentReviewPlan({
      planId: "imsrp_duplicate_bundle_key_001",
      bundle: values.bundle,
      bundleBytes: duplicateKeyBundleBytes,
      bindings: duplicateKeyBindings,
      commonSections: values.commonSections,
      integrationSections: values.integrationSections,
      sourceBytesResolver: values.sourceBytesResolver,
    }),
    /SEGMENT_BUNDLE_BYTES_MISMATCH/u,
  );
});

test("each Segment Material contains the same Bundle/common context and full owned bytes", async () => {
  const values = await planFixture();
  const built = await buildKimiSegmentReviewMaterials({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: values.commonBytesResolver,
  });
  assert.equal(built.length, 4);
  for (const item of built) {
    const parsed = parseKimiSegmentReviewMaterial(item.materialBytes);
    assert.equal(parsed.material.segmentPlanSha256, values.plan.planSha256);
    assert.equal(parsed.material.bindings.reviewBundle.sha256, values.bindings.reviewBundle.sha256);
    assert.deepEqual(
      parsed.material.commonSections,
      values.plan.commonSections,
    );
    assert.deepEqual(
      parsed.material.reviewedSections.map(({ path }) => path),
      values.plan.segments[item.segmentOrdinal - 1].ownedPaths.map(
        ({ path }) => path,
      ),
    );
    for (const section of parsed.reviewedSectionBytes) {
      assert.ok(section.byteLength > 0);
    }
    assert.equal(
      (
        await validateKimiSegmentReviewMaterial({
          materialBytes: item.materialBytes,
          plan: values.plan,
          bundle: values.bundle,
          sourceBytesResolver: values.sourceBytesResolver,
        })
      ).ok,
      true,
    );
  }
  const tamperedBytes = Buffer.from(built[0].materialBytes);
  tamperedBytes[tamperedBytes.length - 1] ^= 1;
  assert.equal(
    (
      await validateKimiSegmentReviewMaterial({
        materialBytes: tamperedBytes,
        plan: values.plan,
        bundle: values.bundle,
        sourceBytesResolver: values.sourceBytesResolver,
      })
    ).ok,
    false,
  );
  const materialBytes = built[0].materialBytes;
  const magicEnd = materialBytes.indexOf(10) + 1;
  const lengthEnd = magicEnd + 13;
  const headerLength = Number.parseInt(
    materialBytes.subarray(magicEnd, lengthEnd).toString("ascii").slice(0, 12),
    16,
  );
  const headerEnd = lengthEnd + headerLength;
  const header = materialBytes.subarray(lengthEnd, headerEnd).toString("utf8");
  const duplicateHeader = Buffer.from(
    `{"schemaVersion":"bogus",${header.slice(1)}`,
    "utf8",
  );
  const duplicateHeaderMaterial = Buffer.concat([
    materialBytes.subarray(0, magicEnd),
    Buffer.from(
      `${duplicateHeader.byteLength.toString(16).padStart(12, "0")}\n`,
      "ascii",
    ),
    duplicateHeader,
    materialBytes.subarray(headerEnd),
  ]);
  assert.equal(
    (
      await validateKimiSegmentReviewMaterial({
        materialBytes: duplicateHeaderMaterial,
        plan: values.plan,
        bundle: values.bundle,
        sourceBytesResolver: values.sourceBytesResolver,
      })
    ).ok,
    false,
  );
});

test("all five historical review artifacts are complete governance source bytes, never summary references", async () => {
  const values = await planFixture();
  const materials = await buildKimiSegmentReviewMaterials({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: values.commonBytesResolver,
  });
  const governance = parseKimiSegmentReviewMaterial(materials[0].materialBytes);
  for (const historicalPath of historicalPaths) {
    const index = governance.material.reviewedSections.findIndex(
      ({ path }) => path === historicalPath,
    );
    assert.notEqual(index, -1);
    assert.equal(governance.material.reviewedSections[index].kind, "SOURCE");
    assert.deepEqual(
      governance.reviewedSectionBytes[index],
      values.sourceBytes.get(historicalPath),
    );
  }
});

function byteArtifact(path, bytes) {
  return {
    path,
    encoding: "UTF-8",
    byteLength: bytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(bytes),
  };
}

function responseArtifact(path, bytes) {
  return {
    ...byteArtifact(path, bytes),
    httpStatus: 200,
    contentType: "application/json; charset=utf-8",
  };
}

async function verifiedExecutionFixture({
  values,
  reviewKind,
  materialBytes,
  label,
  decision = "CLEAR",
  findings = [],
  verifiedSegmentReceiptSet,
  repositorySnapshot,
}) {
  const promptBytes =
    reviewKind === "SEGMENT"
      ? values.promptBytes
      : values.integrationPromptBytes;
  const output = {
    schemaVersion: "independent-model-segmented-review-output.v1",
    reviewSummary: `${label} exact frozen review fixture.`,
    findings,
    decision,
  };
  const contentBytes = Buffer.from(JSON.stringify(output), "utf8");
  const providerSchema = JSON.parse(
    values.bindingBytes
      .get(values.plan.bindings.providerTransportSchema.path)
      .toString("utf8"),
  );
  const request = {
    model: "kimi-k3",
    messages: [
      { role: "system", content: promptBytes.toString("utf8") },
      { role: "user", content: materialBytes.toString("utf8") },
    ],
    reasoning_effort: "max",
    tool_choice: "none",
    response_format: {
      type: "json_schema",
      json_schema: {
        name: "independent_model_segmented_review_output_v1",
        strict: true,
        schema: providerSchema,
      },
    },
    max_completion_tokens: 32768,
  };
  const requestBytes = Buffer.from(JSON.stringify(request), "utf8");
  const responseId = `chatcmpl_${label}_fixture_001`;
  const providerUsage = {
    prompt_tokens: 100,
    completion_tokens: 10,
    total_tokens: 110,
    cached_tokens: 0,
  };
  const responseBytes = Buffer.from(
    JSON.stringify({
      id: responseId,
      object: "chat.completion",
      created: 1785628800,
      model: "kimi-k3",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            reasoning_content: "reviewed exact material",
            content: contentBytes.toString("utf8"),
          },
          finish_reason: "stop",
        },
      ],
      usage: providerUsage,
    }),
    "utf8",
  );
  const estimateRequestBytes = Buffer.from(
    JSON.stringify({ model: "kimi-k3", messages: request.messages }),
    "utf8",
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
  const nonMessage = structuredClone(request);
  delete nonMessage.messages;
  const nonMessageBytes = Buffer.from(
    segmentedKimiReviewDigests.canonicalize(nonMessage),
    "utf8",
  );
  const prefix = `evidence/${label}`;
  const materialArtifact = byteArtifact(`${prefix}/material.utf8`, materialBytes);
  const requestArtifact = byteArtifact(`${prefix}/request.json`, requestBytes);
  const estimateRequestArtifact = byteArtifact(
    `${prefix}/token-estimate-request.json`,
    estimateRequestBytes,
  );
  const estimateResponseArtifact = responseArtifact(
    `${prefix}/token-estimate-response.json`,
    estimateResponseBytes,
  );
  const estimatedMessageInputTokens = 1000;
  const worstCaseBillableInputTokens = 1000 + 65536;
  const tokenEstimateEvidence = createKimiK3TokenEstimateEvidenceV2({
    schemaVersion: "moonshot-kimi-k3-token-estimate-evidence.v2",
    evidenceId: `mk3tee_${label}_fixture_001`,
    provider: "moonshot",
    model: "kimi-k3",
    baseURL: "https://api.moonshot.ai/v1",
    endpoint: "/tokenizers/estimate-token-count",
    source: {
      runtimeCommit: commit("d"),
      sourceCommit: values.plan.source.sourceCommit,
      sourceTree: values.plan.source.tree,
    },
    bindings: {
      formalRequestSha256: requestArtifact.sha256,
      messagesSha256: kimiK3ReviewEvidenceDigests.bytes(
        Buffer.from(JSON.stringify(request.messages), "utf8"),
      ),
      reviewMaterialSha256: materialArtifact.sha256,
      reviewBundleSha256: values.plan.bindings.reviewBundle.sha256,
      configSha256: values.plan.bindings.providerConfig.sha256,
      configSchemaSha256: values.plan.bindings.providerConfigSchema.sha256,
      outputSchemaSha256: kimiK3ReviewEvidenceDigests.value(providerSchema),
      nonMessageVisibleInputSha256:
        kimiK3ReviewEvidenceDigests.bytes(nonMessageBytes),
      nonMessageVisibleInputByteLength: nonMessageBytes.byteLength,
      requestSchemaCoverage:
        "EXACT_MESSAGES_PLUS_FIXED_NON_MESSAGE_RESERVE",
    },
    formalRequest: requestArtifact,
    request: estimateRequestArtifact,
    response: estimateResponseArtifact,
    estimate: {
      estimatedMessageInputTokens,
      contextWindowTokens: 1048576,
      nonMessageVisibleTokenReserve: 65536,
      maxCompletionTokens: 32768,
      safetyMarginTokens: 8192,
      requiredContextTokens: 107496,
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
      worstCaseInputMicros: worstCaseBillableInputTokens * 3,
      worstCaseOutputMicros: 32768 * 15,
      worstCaseTotalMicros:
        worstCaseBillableInputTokens * 3 + 32768 * 15,
      budgetProved: true,
    },
    networkAttemptCount: 1,
    startedAt: now,
    finishedAt: now,
  });
  const repositoryBytes = Buffer.from(
    JSON.stringify(repositorySnapshot ?? {
      head: values.plan.source.sourceCommit,
      tree: values.plan.source.tree,
      worktreeStatusSha256: sha("worktree status"),
      worktreeContentManifestSha256: sha("worktree content manifest"),
      worktreePathCount: 128,
      protectedPathSetSha256: sha("protected path set"),
      protectedFilesDigest: sha("protected files"),
      ignoredExclusionPolicySha256: sha("ignored exclusions"),
      ignoredExcludedPathCount: 4,
    }),
    "utf8",
  );
  const transportEvidence = createKimiSegmentedTransportEvidence({
    schemaVersion: "independent-review-segmented-transport-evidence.v1",
    evidenceId: `irste_${label}_fixture_001`,
    reviewKind,
    provider: "moonshot",
    requestedModel: "kimi-k3",
    actualReturnedModel: "kimi-k3",
    responseId,
    baseURL: "https://api.moonshot.ai/v1",
    endpoint: "/chat/completions",
    source: {
      sourceCommit: values.plan.source.sourceCommit,
      sourceTree: values.plan.source.tree,
    },
    bindings: {
      segmentPlanSha256: values.plan.planSha256,
      reviewBundleSha256: values.plan.bindings.reviewBundle.sha256,
      reviewMaterialSha256: materialArtifact.sha256,
      reviewerPromptSha256:
        reviewKind === "SEGMENT"
          ? values.plan.bindings.segmentReviewerPrompt.sha256
          : values.plan.bindings.integrationReviewerPrompt.sha256,
      canonicalOutputSchemaSha256:
        values.plan.bindings.canonicalOutputSchema.sha256,
      providerTransportSchemaSha256:
        values.plan.bindings.providerTransportSchema.sha256,
      providerConfigSha256: values.plan.bindings.providerConfig.sha256,
      receiptSchemaSha256:
        reviewKind === "SEGMENT"
          ? values.plan.bindings.segmentReceiptSchema.sha256
          : values.plan.bindings.integrationReceiptSchema.sha256,
      tokenEstimateEvidenceSchemaSha256:
        values.plan.bindings.tokenEstimateEvidenceSchema.sha256,
      tokenEstimateEvidenceSha256: tokenEstimateEvidence.evidenceSha256,
      segmentedTransportEvidenceSchemaSha256:
        values.plan.bindings.segmentedTransportEvidenceSchema.sha256,
      formalRequestSha256: requestArtifact.sha256,
      messagesSha256: tokenEstimateEvidence.bindings.messagesSha256,
      nonMessageVisibleInputSha256:
        tokenEstimateEvidence.bindings.nonMessageVisibleInputSha256,
    },
    request: requestArtifact,
    response: responseArtifact(`${prefix}/response.json`, responseBytes),
    content: byteArtifact(`${prefix}/content.json`, contentBytes),
    repositoryBefore: byteArtifact(
      `${prefix}/repository-before.json`,
      repositoryBytes,
    ),
    repositoryAfter: byteArtifact(
      `${prefix}/repository-after.json`,
      repositoryBytes,
    ),
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
    usage: {
      promptTokens: 100,
      completionTokens: 10,
      totalTokens: 110,
      cachedTokens: 0,
    },
    cost: {
      currency: "USD",
      taxBasis: "TAX_EXCLUSIVE",
      inputMicros: 300,
      outputMicros: 150,
      totalMicros: 450,
      budgetMicros: 4000000,
      withinBudget: true,
    },
    validators: {
      schemaValidatorVersion: "ajv@8.20.0",
      semanticValidatorVersion:
        "kimi-k3-segmented-independent-review-validator.v1",
    },
    startedAt: now,
    finishedAt: now,
  });
  const tokenBytes = Buffer.from(JSON.stringify(tokenEstimateEvidence), "utf8");
  const transportBytes = Buffer.from(JSON.stringify(transportEvidence), "utf8");
  const tokenArtifact = byteArtifact(
    `${prefix}/token-estimate-evidence.json`,
    tokenBytes,
  );
  const transportArtifact = byteArtifact(
    `${prefix}/transport-evidence.json`,
    transportBytes,
  );
  const artifacts = new Map([
    ...values.bindingBytes,
    [materialArtifact.path, materialBytes],
    [requestArtifact.path, requestBytes],
    [estimateRequestArtifact.path, estimateRequestBytes],
    [estimateResponseArtifact.path, estimateResponseBytes],
    [transportEvidence.response.path, responseBytes],
    [transportEvidence.content.path, contentBytes],
    [transportEvidence.repositoryBefore.path, repositoryBytes],
    [transportEvidence.repositoryAfter.path, repositoryBytes],
    [tokenArtifact.path, tokenBytes],
    [transportArtifact.path, transportBytes],
  ]);
  const evidenceResolver = async (path) => artifacts.get(path) ?? null;
  const input = {
    reviewKind,
    plan: values.plan,
    bundle: values.bundle,
    reviewMaterialArtifact: materialArtifact,
    tokenEstimateEvidence,
    tokenEstimateEvidenceArtifact: tokenArtifact,
    transportEvidence,
    transportEvidenceArtifact: transportArtifact,
    evidenceResolver,
    sourceBytesResolver: values.sourceBytesResolver,
  };
  if (reviewKind === "INTEGRATION") {
    input.verifiedSegmentReceiptSet = verifiedSegmentReceiptSet;
  }
  return {
    proof: await verifyKimiSegmentedModelExecution(input),
    input,
    artifacts,
    output,
  };
}

async function verifiedSegmentReviewSet(values, materials, decisions = {}) {
  const executions = [];
  const receipts = [];
  for (let index = 0; index < values.plan.segments.length; index += 1) {
    const segment = values.plan.segments[index];
    const decision = decisions[segment.segmentId] ?? "CLEAR";
    const findings = decisions[`${segment.segmentId}:findings`] ?? [];
    const execution = await verifiedExecutionFixture({
      values,
      reviewKind: "SEGMENT",
      materialBytes: materials[index].materialBytes,
      label: `segment_${segment.ordinal}_${decision.toLowerCase()}`,
      decision,
      findings,
    });
    executions.push(execution);
    receipts.push(
      createKimiSegmentReceipt({
        receiptId: `imsrr_${segment.ordinal}_${decision.toLowerCase()}_001`,
        plan: values.plan,
        verifiedExecution: execution.proof,
      }),
    );
  }
  return {
    executions,
    receipts,
    verifiedSet: verifyKimiSegmentReceiptSet({
      plan: values.plan,
      segmentReceipts: receipts,
      verifiedExecutions: executions.map(({ proof }) => proof),
    }),
  };
}

test("Segment Receipt binds only its owned paths and cannot claim global clearance", async () => {
  const values = await planFixture();
  const materials = await buildKimiSegmentReviewMaterials({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: values.commonBytesResolver,
  });
  assert.throws(
    () =>
      createKimiSegmentReceipt({
        receiptId: "imsrr_caller_forgery_001",
        plan: values.plan,
        decision: "CLEAR",
        findings: [],
        reviewerSessionId: "chatcmpl_forged",
      }),
    /MODEL_EXECUTION_PROOF_REQUIRED/u,
    "caller-authored outcome fields and self-reported hashes are not evidence",
  );
  const execution = await verifiedExecutionFixture({
    values,
    reviewKind: "SEGMENT",
    materialBytes: materials[0].materialBytes,
    label: "segment_1_clear",
  });
  const receipt = createKimiSegmentReceipt({
    receiptId: "imsrr_1_clear_001",
    plan: values.plan,
    verifiedExecution: execution.proof,
  });
  const validation = await validateKimiSegmentReceipt({
    receipt,
    plan: values.plan,
    verifiedExecution: execution.proof,
  });
  assert.equal(validation.ok, true);
  assert.equal(receipt.conclusion, "SEGMENT_REVIEW_CLEAR");
  assert.equal(receipt.modelReviewClearForPreproduction, false);
  assert.equal(receipt.humanReviewClaim, false);
  assert.equal(receipt.governanceEffect, "NONE");

  await assert.rejects(
    verifiedExecutionFixture({
      values,
      reviewKind: "SEGMENT",
      materialBytes: materials[0].materialBytes,
      label: "segment_1_outside",
      decision: "BLOCKED",
      findings: [
        {
          findingId: "outside-path",
          severity: "HIGH",
          status: "OPEN",
          path: paths.schema,
          relatedPaths: [paths.schema],
          startLine: 1,
          endLine: 1,
          summary: "outside",
          detailsSha256: sha("outside"),
          resolutionEvidenceDigests: [],
        },
      ],
    }),
    /MODEL_EXECUTION_RESPONSE_INVALID/u,
  );
  const extended = structuredClone(receipt);
  extended.reviewerApproval = true;
  extended.receiptSha256 = segmentedKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(extended).filter(([key]) => key !== "receiptSha256"),
    ),
  );
  assert.equal(
    (
      await validateKimiSegmentReceipt({
        receipt: extended,
        plan: values.plan,
        verifiedExecution: execution.proof,
      })
    ).ok,
    false,
  );
  const emptyArtifacts = structuredClone(receipt);
  emptyArtifacts.artifacts = {};
  emptyArtifacts.receiptSha256 = segmentedKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(emptyArtifacts).filter(([key]) => key !== "receiptSha256"),
    ),
  );
  assert.equal(
    (
      await validateKimiSegmentReceipt({
        receipt: emptyArtifacts,
        plan: values.plan,
        verifiedExecution: execution.proof,
      })
    ).ok,
    false,
  );

  const reviewerBypass = structuredClone(receipt);
  reviewerBypass.reviewer.bypass = true;
  reviewerBypass.receiptSha256 = segmentedKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(reviewerBypass).filter(([key]) => key !== "receiptSha256"),
    ),
  );
  assert.equal(
    (
      await validateKimiSegmentReceipt({
        receipt: reviewerBypass,
        plan: values.plan,
        verifiedExecution: execution.proof,
      })
    ).ok,
    false,
  );

  const tamperedEvidence = {
    ...execution.input,
    tokenEstimateEvidence: structuredClone(
      execution.input.tokenEstimateEvidence,
    ),
  };
  tamperedEvidence.tokenEstimateEvidence.bindings.reviewMaterialSha256 =
    sha("nonexistent material");
  await assert.rejects(
    verifyKimiSegmentedModelExecution(tamperedEvidence),
    /MODEL_EXECUTION_ARTIFACT_MISMATCH|MODEL_EXECUTION_TOKEN_EVIDENCE_INVALID/u,
  );
});

test("Integration Material reads validated receipts, exact patch, Bundle relationships, and fixed contracts", async () => {
  const values = await planFixture();
  const materials = await buildKimiSegmentReviewMaterials({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: values.commonBytesResolver,
  });
  const segmentSet = await verifiedSegmentReviewSet(values, materials);
  const patchBytes = Buffer.from("exact full git patch\n", "utf8");
  const built = await buildKimiIntegrationReviewMaterial({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    patchBytes,
    bytesResolver: values.commonBytesResolver,
    sourceBytesResolver: values.sourceBytesResolver,
  });
  const parsed = parseKimiIntegrationReviewMaterial(built.materialBytes);
  assert.equal(parsed.material.segmentReceiptBindings.length, 4);
  assert.equal(parsed.material.fullPatch.sha256, sha("exact full git patch\n"));
  assert.equal(parsed.material.bindings.reviewBundle.sha256, values.bindings.reviewBundle.sha256);
  assert.equal(parsed.material.source.sourceCommit, values.bundle.source.sourceCommit);
  assert.deepEqual(
    parsed.material.segmentReceiptBindings.map(({ receiptSha256 }) => receiptSha256),
    segmentSet.receipts.map(({ receiptSha256 }) => receiptSha256),
  );
  assert.equal(parsed.patchBytes.toString("utf8"), "exact full git patch\n");
  assert.equal(
    (
      await validateKimiIntegrationReviewMaterial({
        materialBytes: built.materialBytes,
        plan: values.plan,
        bundle: values.bundle,
        verifiedSegmentReceiptSet: segmentSet.verifiedSet,
        sourceBytesResolver: values.sourceBytesResolver,
      })
    ).ok,
    true,
  );
  const tamperedBytes = Buffer.from(built.materialBytes);
  tamperedBytes[tamperedBytes.length - 1] ^= 1;
  assert.equal(
    (
      await validateKimiIntegrationReviewMaterial({
        materialBytes: tamperedBytes,
        plan: values.plan,
        bundle: values.bundle,
        verifiedSegmentReceiptSet: segmentSet.verifiedSet,
        sourceBytesResolver: values.sourceBytesResolver,
      })
    ).ok,
    false,
  );
  assert.equal(
    (
      await validateKimiIntegrationReviewMaterial({
        materialBytes: built.materialBytes,
        plan: values.plan,
        bundle: values.bundle,
        verifiedSegmentReceiptSet: Object.freeze({ kind: "forged" }),
        sourceBytesResolver: values.sourceBytesResolver,
      })
    ).ok,
    false,
  );
});

test("Integration Receipt is a fifth model review and cannot claim global clearance", async () => {
  const values = await planFixture();
  const materials = await buildKimiSegmentReviewMaterials({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: values.commonBytesResolver,
  });
  const segmentSet = await verifiedSegmentReviewSet(values, materials);
  const integrationMaterial = await buildKimiIntegrationReviewMaterial({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    patchBytes: Buffer.from("exact full git patch\n", "utf8"),
    bytesResolver: values.commonBytesResolver,
    sourceBytesResolver: values.sourceBytesResolver,
  });
  const clearExecution = await verifiedExecutionFixture({
    values,
    reviewKind: "INTEGRATION",
    materialBytes: integrationMaterial.materialBytes,
    label: "integration_clear",
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
  });
  const integration = createKimiIntegrationReceipt({
    receiptId: "imir_integration_clear_001",
    plan: values.plan,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    verifiedExecution: clearExecution.proof,
  });
  assert.equal(
    (
      await validateKimiIntegrationReceipt({
        receipt: integration,
        plan: values.plan,
        verifiedSegmentReceiptSet: segmentSet.verifiedSet,
        verifiedExecution: clearExecution.proof,
      })
    ).ok,
    true,
  );
  assert.equal(integration.conclusion, "INTEGRATION_REVIEW_CLEAR");
  assert.equal(integration.modelReviewClearForPreproduction, false);
  assert.equal(integration.humanReviewClaim, false);
  assert.equal(integration.governanceEffect, "NONE");

  const blockedExecution = await verifiedExecutionFixture({
    values,
    reviewKind: "INTEGRATION",
    materialBytes: integrationMaterial.materialBytes,
    label: "integration_blocked",
    decision: "BLOCKED",
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    findings: [
      {
        findingId: "cross-segment-contract",
        severity: "HIGH",
        status: "OPEN",
        path: paths.runtime,
        relatedPaths: [paths.runtime, paths.schema],
        startLine: 1,
        endLine: 1,
        summary: "Runtime and wire Schema disagree.",
        detailsSha256: sha("cross segment details"),
        resolutionEvidenceDigests: [],
      },
    ],
  });
  const crossSegment = createKimiIntegrationReceipt({
    receiptId: "imir_integration_blocked_001",
    plan: values.plan,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    verifiedExecution: blockedExecution.proof,
  });
  assert.equal(
    (
      await validateKimiIntegrationReceipt({
        receipt: crossSegment,
        plan: values.plan,
        verifiedSegmentReceiptSet: segmentSet.verifiedSet,
        verifiedExecution: blockedExecution.proof,
      })
    ).ok,
    true,
  );
  const unknownPath = structuredClone(crossSegment);
  unknownPath.findings[0].relatedPaths.push("unknown/path.mjs");
  unknownPath.findingsSha256 = segmentedKimiReviewDigests.value(
    unknownPath.findings,
  );
  unknownPath.receiptSha256 = segmentedKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(unknownPath).filter(([key]) => key !== "receiptSha256"),
    ),
  );
  assert.equal(
    (
      await validateKimiIntegrationReceipt({
        receipt: unknownPath,
        plan: values.plan,
        verifiedSegmentReceiptSet: segmentSet.verifiedSet,
        verifiedExecution: blockedExecution.proof,
      })
    ).ok,
    false,
  );

  const reusedExecution = await verifiedExecutionFixture({
    values,
    reviewKind: "INTEGRATION",
    materialBytes: integrationMaterial.materialBytes,
    label: "segment_1_clear",
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
  });
  assert.throws(
    () =>
      createKimiIntegrationReceipt({
        receiptId: "imir_reused_session_001",
        plan: values.plan,
        verifiedSegmentReceiptSet: segmentSet.verifiedSet,
        verifiedExecution: reusedExecution.proof,
      }),
    /INTEGRATION_REVIEWER_SESSION_REUSED/u,
  );
});

async function completedReviewSet({
  values,
  segmentDecisions = {},
  integrationDecision = "CLEAR",
  integrationFindings = [],
  label = "aggregate",
}) {
  const materials = await buildKimiSegmentReviewMaterials({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: values.commonBytesResolver,
  });
  const segmentSet = await verifiedSegmentReviewSet(
    values,
    materials,
    segmentDecisions,
  );
  const integrationMaterial = await buildKimiIntegrationReviewMaterial({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    patchBytes: Buffer.from("exact full git patch\n", "utf8"),
    bytesResolver: values.commonBytesResolver,
    sourceBytesResolver: values.sourceBytesResolver,
  });
  const integrationExecution = await verifiedExecutionFixture({
    values,
    reviewKind: "INTEGRATION",
    materialBytes: integrationMaterial.materialBytes,
    label: `${label}_integration_${integrationDecision.toLowerCase()}`,
    decision: integrationDecision,
    findings: integrationFindings,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
  });
  const integrationReceipt = createKimiIntegrationReceipt({
    receiptId: `imir_${label}_${integrationDecision.toLowerCase()}_001`,
    plan: values.plan,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    verifiedExecution: integrationExecution.proof,
  });
  const verifiedReviewReceiptSet = verifyKimiReviewReceiptSet({
    plan: values.plan,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    integrationReceipt,
    verifiedIntegrationExecution: integrationExecution.proof,
  });
  return {
    materials,
    segmentSet,
    integrationMaterial,
    integrationExecution,
    integrationReceipt,
    verifiedReviewReceiptSet,
  };
}

test("Aggregate is local and deterministic: no reviewer session, transport, model output, or finding rewrite", async () => {
  assert.equal(evaluateKimiAggregateDecision(["CLEAR", "CLEAR", "CLEAR", "CLEAR", "CLEAR"]), "CLEAR");
  assert.equal(evaluateKimiAggregateDecision(["CLEAR", "BLOCKED", "CLEAR", "CLEAR", "CLEAR"]), "BLOCKED");
  assert.equal(evaluateKimiAggregateDecision(["BLOCKED", "INCONCLUSIVE", "CLEAR", "CLEAR", "CLEAR"]), "INCONCLUSIVE");
  assert.equal(evaluateKimiAggregateDecision(["CLEAR", "CLEAR", "CLEAR"]), "INCONCLUSIVE");

  const values = await planFixture();
  const clear = await completedReviewSet({ values, label: "clear" });
  const aggregate = createKimiAggregateReceipt({
    receiptId: "imarr_fixture_clear_001",
    plan: values.plan,
    verifiedReviewReceiptSet: clear.verifiedReviewReceiptSet,
  });
  const validation = await validateKimiAggregateReceipt({
    receipt: aggregate,
    plan: values.plan,
    verifiedReviewReceiptSet: clear.verifiedReviewReceiptSet,
  });
  assert.equal(validation.ok, true);
  assert.equal(aggregate.conclusion, "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION");
  assert.equal(aggregate.modelReviewClearForPreproduction, true);
  assert.equal("reviewerSessionId" in aggregate, false);
  assert.equal("tokenEstimateEvidenceSha256" in aggregate, false);
  assert.equal("transportEvidenceSha256" in aggregate, false);
  assert.equal("modelOutput" in aggregate, false);
  assert.deepEqual(aggregate.findings, []);
  const aggregateWithModelEvidence = structuredClone(aggregate);
  aggregateWithModelEvidence.reviewerSessionId = "forbidden";
  aggregateWithModelEvidence.receiptSha256 = segmentedKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(aggregateWithModelEvidence).filter(
        ([key]) => key !== "receiptSha256",
      ),
    ),
  );
  assert.equal(
    (
      await validateKimiAggregateReceipt({
        receipt: aggregateWithModelEvidence,
        plan: values.plan,
        verifiedReviewReceiptSet: clear.verifiedReviewReceiptSet,
      })
    ).ok,
    false,
  );

  const blocked = await completedReviewSet({
    values,
    label: "blocked",
    segmentDecisions: {
      RUNTIME_ORCHESTRATION: "BLOCKED",
      "RUNTIME_ORCHESTRATION:findings": [
        {
          findingId: "runtime-blocker",
          severity: "HIGH",
          status: "OPEN",
          path: paths.runtime,
          relatedPaths: [paths.runtime],
          startLine: 1,
          endLine: 1,
          summary: "Runtime blocker",
          detailsSha256: sha("runtime blocker"),
          resolutionEvidenceDigests: [],
        },
      ],
    },
  });
  const blockedAggregate = createKimiAggregateReceipt({
    receiptId: "imarr_fixture_blocked_001",
    plan: values.plan,
    verifiedReviewReceiptSet: blocked.verifiedReviewReceiptSet,
  });
  assert.equal(blockedAggregate.decision, "BLOCKED");
  assert.deepEqual(
    blockedAggregate.findings.map(({ finding }) => finding),
    blocked.segmentSet.receipts.flatMap(({ findings }) => findings),
  );

  const inconclusive = await completedReviewSet({
    values,
    label: "inconclusive",
    integrationDecision: "INCONCLUSIVE",
  });
  const inconclusiveAggregate = createKimiAggregateReceipt({
    receiptId: "imarr_fixture_inconclusive_001",
    plan: values.plan,
    verifiedReviewReceiptSet: inconclusive.verifiedReviewReceiptSet,
  });
  assert.equal(inconclusiveAggregate.decision, "INCONCLUSIVE");

  assert.throws(
    () =>
      createKimiAggregateReceipt({
        receiptId: "imarr_missing_001",
        plan: values.plan,
        verifiedReviewReceiptSet: Object.freeze({ kind: "forged" }),
      }),
    /AGGREGATE_INPUT_INVALID/u,
  );
  assert.equal(
    (
      await evaluateKimiAggregateInputs({
        plan: values.plan,
        verifiedReviewReceiptSet: Object.freeze({ kind: "forged" }),
      })
    ).decision,
    "INCONCLUSIVE",
  );

  const invalidResult = await evaluateKimiAggregateInputs({
    plan: values.plan,
    verifiedReviewReceiptSet: {
      kind: "caller-authored-clear-set",
      receipts: ["CLEAR", "CLEAR", "CLEAR", "CLEAR", "CLEAR"],
    },
  });
  assert.equal(invalidResult.decision, "INCONCLUSIVE");
  assert.equal(invalidResult.aggregateReceipt, null);
});

test("all segmented-review artifacts pass closed Schemas and unknown fields are rejected", async () => {
  const values = await planFixture();
  const completed = await completedReviewSet({ values, label: "schema" });
  const materials = completed.materials;
  const segmentReceipts = completed.segmentSet.receipts;
  const integrationMaterial = completed.integrationMaterial;
  const integrationReceipt = completed.integrationReceipt;
  const aggregate = createKimiAggregateReceipt({
    receiptId: "imarr_schema_fixture_001",
    plan: values.plan,
    verifiedReviewReceiptSet: completed.verifiedReviewReceiptSet,
  });
  const artifacts = [
    [
      "implementation/governance/schemas/independent-review-segment-plan.v1.schema.json",
      values.plan,
    ],
    [
      "implementation/governance/schemas/independent-review-segment-material.v1.schema.json",
      materials[0].material,
    ],
    [
      "implementation/governance/schemas/independent-model-segment-review-receipt.v1.schema.json",
      segmentReceipts[0],
    ],
    [
      "implementation/governance/schemas/independent-review-integration-material.v1.schema.json",
      integrationMaterial.material,
    ],
    [
      "implementation/governance/schemas/independent-model-integration-review-receipt.v1.schema.json",
      integrationReceipt,
    ],
    [
      "implementation/governance/schemas/independent-model-aggregate-review-receipt.v1.schema.json",
      aggregate,
    ],
    [
      "implementation/governance/schemas/independent-model-segmented-review-output.v1.schema.json",
      completed.segmentSet.executions[0].output,
    ],
    [
      "implementation/governance/schemas/independent-review-segmented-transport-evidence.v1.schema.json",
      completed.segmentSet.executions[0].input.transportEvidence,
    ],
  ];
  for (const [path, instance] of artifacts) {
    const schemaBytes = await readFile(path);
    const expectedSchemaSha256 = segmentedKimiReviewDigests.bytes(schemaBytes);
    const valid = await validateIndependentReviewSchemaInstance({
      schemaBytes,
      expectedSchemaSha256,
      instance,
      label: path,
    });
    assert.equal(valid.ok, true, `${path} accepts its artifact`);
    const withUnknownField = { ...structuredClone(instance), bypass: true };
    const invalid = await validateIndependentReviewSchemaInstance({
      schemaBytes,
      expectedSchemaSha256,
      instance: withUnknownField,
      label: path,
    });
    assert.equal(invalid.ok, false, `${path} rejects unknown fields`);
  }
});

test("content segments expose each reviewed Git path exactly once and reject common overlap", async () => {
  const values = fixture();
  const overlapBytes = values.sourceBytes.get(paths.runtime);
  const bindings = structuredClone(values.bindings);
  bindings.providerConfig = {
    path: paths.runtime,
    byteLength: overlapBytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(overlapBytes),
  };
  const plan = await createKimiSegmentReviewPlan({
    planId: "imsrp_binding_overlap_fixture",
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    bindings,
    commonSections: values.commonSections,
    integrationSections: values.integrationSections,
    sourceBytesResolver: values.sourceBytesResolver,
  });
  const materials = await buildKimiSegmentReviewMaterials({
    plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: async (path) =>
      values.sourceBytes.get(path) ?? values.commonBytesResolver(path),
  });
  const visibleReviewedPaths = materials.flatMap(({ materialBytes }) => {
    const parsed = parseKimiSegmentReviewMaterial(materialBytes).material;
    return [
      ...parsed.bindingSections,
      ...parsed.commonSections,
      ...parsed.reviewedSections,
    ]
      .map(({ path }) => path)
      .filter((path) => values.bundle.reviewedPaths.includes(path));
  });
  assert.deepEqual(
    visibleReviewedPaths.sort(),
    [...values.bundle.reviewedPaths].sort(),
  );
  const materialSchemaBytes = await readFile(
    "implementation/governance/schemas/independent-review-segment-material.v1.schema.json",
  );
  const materialSchemaSha256 = segmentedKimiReviewDigests.bytes(
    materialSchemaBytes,
  );
  for (const { material } of materials) {
    const validation = await validateIndependentReviewSchemaInstance({
      schemaBytes: materialSchemaBytes,
      expectedSchemaSha256: materialSchemaSha256,
      instance: material,
      label: "deduplicated segment material",
    });
    assert.equal(validation.ok, true);
  }

  const duplicateBindingPath = structuredClone(values.bindings);
  duplicateBindingPath.aggregateReceiptSchema = structuredClone(
    duplicateBindingPath.providerConfig,
  );
  await assert.rejects(
    () =>
      createKimiSegmentReviewPlan({
        planId: "imsrp_duplicate_binding_path_fixture",
        bundle: values.bundle,
        bundleBytes: values.bundleBytes,
        bindings: duplicateBindingPath,
        commonSections: values.commonSections,
        integrationSections: values.integrationSections,
        sourceBytesResolver: values.sourceBytesResolver,
      }),
    /SEGMENT_PLAN_BINDING_PATH_DUPLICATE/u,
  );

  const bindingCommonOverlap = structuredClone(values.bindings);
  bindingCommonOverlap.providerConfig = {
    path: values.commonSections[0].path,
    byteLength: values.commonSections[0].byteLength,
    sha256: values.commonSections[0].sha256,
  };
  await assert.rejects(
    () =>
      createKimiSegmentReviewPlan({
        planId: "imsrp_binding_common_overlap_fixture",
        bundle: values.bundle,
        bundleBytes: values.bundleBytes,
        bindings: bindingCommonOverlap,
        commonSections: values.commonSections,
        integrationSections: values.integrationSections,
        sourceBytesResolver: values.sourceBytesResolver,
      }),
    /SEGMENT_PLAN_BINDING_COMMON_OVERLAP/u,
  );

  const bindingIntegrationOverlap = structuredClone(values.bindings);
  bindingIntegrationOverlap.providerConfig = {
    path: values.integrationSections[0].path,
    byteLength: values.integrationSections[0].byteLength,
    sha256: values.integrationSections[0].sha256,
  };
  await assert.rejects(
    () =>
      createKimiSegmentReviewPlan({
        planId: "imsrp_binding_integration_overlap_fixture",
        bundle: values.bundle,
        bundleBytes: values.bundleBytes,
        bindings: bindingIntegrationOverlap,
        commonSections: values.commonSections,
        integrationSections: values.integrationSections,
        sourceBytesResolver: values.sourceBytesResolver,
      }),
    /SEGMENT_PLAN_BINDING_INTEGRATION_OVERLAP/u,
  );

  await assert.rejects(
    () =>
      createKimiSegmentReviewPlan({
        planId: "imsrp_common_overlap_fixture",
        bundle: values.bundle,
        bundleBytes: values.bundleBytes,
        bindings: values.bindings,
        commonSections: [
          {
            kind: "SPECIFICATION",
            path: paths.runtime,
            byteLength: overlapBytes.byteLength,
            sha256: segmentedKimiReviewDigests.bytes(overlapBytes),
          },
        ],
        integrationSections: values.integrationSections,
        sourceBytesResolver: values.sourceBytesResolver,
      }),
    /SEGMENT_PLAN_COMMON_SECTION_OVERLAP/u,
  );
});

test("integration contract set and historical artifact bytes are exact and fail closed", async () => {
  const values = fixture();
  await assert.rejects(
    () =>
      createKimiSegmentReviewPlan({
        planId: "imsrp_missing_integration_contract_fixture",
        bundle: values.bundle,
        bundleBytes: values.bundleBytes,
        bindings: values.bindings,
        commonSections: values.commonSections,
        integrationSections: values.integrationSections.slice(0, -1),
        sourceBytesResolver: values.sourceBytesResolver,
      }),
    /SEGMENT_PLAN_INTEGRATION_CONTRACT_INVALID/u,
  );

  const historicalPath = historicalPaths[0];
  const replacement = Buffer.from("historical evidence replaced by a summary", "utf8");
  const sourceBytes = new Map(values.sourceBytes);
  sourceBytes.set(historicalPath, replacement);
  const bundle = structuredClone(values.bundle);
  bundle.sourceSubjects.find(({ path }) => path === historicalPath).blobSha256 =
    segmentedKimiReviewDigests.bytes(replacement);
  const bundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const bindings = structuredClone(values.bindings);
  bindings.reviewBundle = {
    path: values.bindings.reviewBundle.path,
    byteLength: bundleBytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(bundleBytes),
  };
  await assert.rejects(
    () =>
      createKimiSegmentReviewPlan({
        planId: "imsrp_historical_summary_fixture",
        bundle,
        bundleBytes,
        bindings,
        commonSections: values.commonSections,
        integrationSections: values.integrationSections,
        sourceBytesResolver: async (path) => sourceBytes.get(path) ?? null,
      }),
    /SEGMENT_HISTORICAL_EVIDENCE_BYTES_MISMATCH/u,
  );
});

test("verified receipt sets snapshot immutable Plan and Receipt bytes", async () => {
  const values = await planFixture();
  const completed = await completedReviewSet({
    values,
    label: "immutable",
    segmentDecisions: {
      RUNTIME_ORCHESTRATION: "BLOCKED",
      "RUNTIME_ORCHESTRATION:findings": [
        {
          findingId: "immutable-runtime-blocker",
          severity: "HIGH",
          status: "OPEN",
          path: paths.runtime,
          relatedPaths: [paths.runtime],
          startLine: 1,
          endLine: 1,
          summary: "Immutable runtime blocker",
          detailsSha256: sha("immutable runtime blocker"),
          resolutionEvidenceDigests: [],
        },
      ],
    },
  });
  const mutableReceipt = completed.segmentSet.receipts[2];
  mutableReceipt.decision = "CLEAR";
  mutableReceipt.findings = [];
  mutableReceipt.findingsSha256 = segmentedKimiReviewDigests.value([]);
  mutableReceipt.receiptSha256 = segmentedKimiReviewDigests.value(
    Object.fromEntries(
      Object.entries(mutableReceipt).filter(([key]) => key !== "receiptSha256"),
    ),
  );
  const aggregate = createKimiAggregateReceipt({
    receiptId: "imarr_immutable_snapshot_001",
    plan: values.plan,
    verifiedReviewReceiptSet: completed.verifiedReviewReceiptSet,
  });
  assert.equal(aggregate.decision, "BLOCKED");
  assert.equal(
    aggregate.findings.some(
      ({ finding }) => finding.findingId === "immutable-runtime-blocker",
    ),
    true,
  );

  values.plan.source.sourceCommit = commit("e");
  assert.throws(
    () =>
      createKimiAggregateReceipt({
        receiptId: "imarr_mutated_plan_001",
        plan: values.plan,
        verifiedReviewReceiptSet: completed.verifiedReviewReceiptSet,
      }),
    /AGGREGATE_INPUT_INVALID/u,
  );
});

test("finding IDs are unique across all model Receipts", async () => {
  const values = await planFixture();
  const materials = await buildKimiSegmentReviewMaterials({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: values.commonBytesResolver,
  });
  await assert.rejects(
    () =>
      verifiedSegmentReviewSet(values, materials, {
        "GOVERNANCE_LINEAGE:findings": [
          {
            findingId: "duplicate-finding-id",
            severity: "LOW",
            status: "OPEN",
            path: paths.governance,
            relatedPaths: [paths.governance],
            startLine: 1,
            endLine: 1,
            summary: "Governance duplicate",
            detailsSha256: sha("governance duplicate"),
            resolutionEvidenceDigests: [],
          },
        ],
        "SCHEMAS_WIRE_CONTRACTS:findings": [
          {
            findingId: "duplicate-finding-id",
            severity: "LOW",
            status: "OPEN",
            path: paths.schema,
            relatedPaths: [paths.schema],
            startLine: 1,
            endLine: 1,
            summary: "Schema duplicate",
            detailsSha256: sha("schema duplicate"),
            resolutionEvidenceDigests: [],
          },
        ],
      }),
    /SEGMENT_RECEIPT_SET_INVALID/u,
  );

  const segmentSet = await verifiedSegmentReviewSet(values, materials, {
    "GOVERNANCE_LINEAGE:findings": [
      {
        findingId: "cross-receipt-duplicate-id",
        severity: "LOW",
        status: "OPEN",
        path: paths.governance,
        relatedPaths: [paths.governance],
        startLine: 1,
        endLine: 1,
        summary: "Segment finding",
        detailsSha256: sha("segment finding"),
        resolutionEvidenceDigests: [],
      },
    ],
  });
  const integrationMaterial = await buildKimiIntegrationReviewMaterial({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    patchBytes: Buffer.from("exact full git patch\n", "utf8"),
    bytesResolver: values.commonBytesResolver,
    sourceBytesResolver: values.sourceBytesResolver,
  });
  const integrationExecution = await verifiedExecutionFixture({
    values,
    reviewKind: "INTEGRATION",
    materialBytes: integrationMaterial.materialBytes,
    label: "cross_receipt_duplicate",
    findings: [
      {
        findingId: "cross-receipt-duplicate-id",
        severity: "LOW",
        status: "OPEN",
        path: null,
        relatedPaths: [paths.governance, paths.schema],
        startLine: null,
        endLine: null,
        summary: "Integration duplicate",
        detailsSha256: sha("integration duplicate"),
        resolutionEvidenceDigests: [],
      },
    ],
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
  });
  const integrationReceipt = createKimiIntegrationReceipt({
    receiptId: "imir_cross_receipt_duplicate_001",
    plan: values.plan,
    verifiedSegmentReceiptSet: segmentSet.verifiedSet,
    verifiedExecution: integrationExecution.proof,
  });
  assert.throws(
    () =>
      verifyKimiReviewReceiptSet({
        plan: values.plan,
        verifiedSegmentReceiptSet: segmentSet.verifiedSet,
        integrationReceipt,
        verifiedIntegrationExecution: integrationExecution.proof,
      }),
    /AGGREGATE_INPUT_INVALID/u,
  );
});

test("repository snapshots bind exact source commit and tree semantics", async () => {
  const values = await planFixture();
  const materials = await buildKimiSegmentReviewMaterials({
    plan: values.plan,
    bundle: values.bundle,
    bundleBytes: values.bundleBytes,
    sourceBytesResolver: values.sourceBytesResolver,
    commonBytesResolver: values.commonBytesResolver,
  });
  await assert.rejects(
    () =>
      verifiedExecutionFixture({
        values,
        reviewKind: "SEGMENT",
        materialBytes: materials[0].materialBytes,
        label: "wrong_repository_snapshot",
        repositorySnapshot: {
          head: commit("f"),
          tree: values.plan.source.tree,
          worktreeStatusSha256: sha("worktree status"),
          worktreeContentManifestSha256: sha("worktree content manifest"),
          worktreePathCount: 128,
          protectedPathSetSha256: sha("protected path set"),
          protectedFilesDigest: sha("protected files"),
          ignoredExclusionPolicySha256: sha("ignored exclusions"),
          ignoredExcludedPathCount: 4,
        },
      }),
    /MODEL_EXECUTION_REPOSITORY_SNAPSHOT_INVALID/u,
  );
});
