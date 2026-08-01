#!/usr/bin/env node

import { execFile } from "node:child_process";
import { readFile, realpath, stat, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  createKimiModelVisibleProtocolBytes,
  encodeIndependentReviewMaterialEnvelope,
  independentKimiReviewDigests,
  kimiIndependentReviewFixedBaseCommit,
  kimiIndependentReviewMaterialGovernancePaths,
  parseIndependentReviewMaterialEnvelope,
  validateIndependentReviewMaterial,
  validateMoonshotKimiConfig,
} from "../lib/kimi-independent-review.mjs";
import {
  classifyKimiK3V7ContractPresence,
  createKimiK3ModelVisibleProtocolBytes,
  kimiK3HistoricalReviewEvidenceContract,
  kimiK3HistoricalReviewEvidencePaths,
  kimiK3ReviewMaterialGovernancePathsV2,
  kimiK3ReviewMaterialGovernancePathsV3,
  kimiK3ReviewMaterialGovernancePathsV4,
  kimiK3ReviewMaterialGovernancePathsV5,
  kimiK3ReviewMaterialGovernancePathsV6,
  kimiK3ReviewMaterialGovernancePathsV7,
  kimiK3ReviewMaterialPathsV2,
  kimiK3ReviewMaterialPathsV3,
  kimiK3ReviewMaterialPathsV4,
  kimiK3ReviewMaterialPathsV5,
  kimiK3ReviewMaterialPathsV6,
  kimiK3ReviewMaterialPathsV7,
  validateIndependentReviewHistoricalEvidenceIndex,
  validateMoonshotKimiK3FrozenContract,
} from "../lib/kimi-k3-independent-review.mjs";
import {
  independentModelReviewFixedSpecificationPaths,
  parseIndependentReviewJsonBytes,
  validateIndependentReviewBundle,
  validateIndependentReviewPolicy,
  validateIndependentReviewSchemaInstance,
  validateIndependentReviewTestEvidenceClosure,
} from "../lib/independent-model-review.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const K2_FIXED_PATHS = Object.freeze({
  policy:
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  prompt:
    "implementation/governance/independent-review/independent-model-review-prompt.v2.md",
  outputSchema:
    "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
  receiptSchema:
    "implementation/governance/schemas/independent-model-review-receipt.v3.schema.json",
  config:
    "implementation/governance/independent-review/moonshot-kimi-k2.7-code.v1.json",
  testPlan:
    "implementation/governance/independent-review/independent-review-test-plan.v2.json",
  testEvidenceCollector:
    "scripts/run-independent-review-test-evidence.mjs",
  testResultSchema:
    "implementation/governance/schemas/independent-review-test-result.v3.schema.json",
  sandboxPolicyTemplate:
    "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in",
  governanceSubjects: kimiIndependentReviewMaterialGovernancePaths,
});
const K3_V2_FIXED_PATHS = Object.freeze({
  policy:
    "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  prompt: kimiK3ReviewMaterialPathsV2.prompt,
  outputSchema: kimiK3ReviewMaterialPathsV2.outputSchema,
  receiptSchema: kimiK3ReviewMaterialPathsV2.receiptSchema,
  config: kimiK3ReviewMaterialPathsV2.config,
  modelVisibleProtocol: kimiK3ReviewMaterialPathsV2.modelVisibleProtocol,
  research:
    "docs/research/moonshot-kimi-k3-transport-contract-2026-07-31.md",
  testPlan:
    "implementation/governance/independent-review/independent-review-test-plan.v2.json",
  testEvidenceCollector:
    "scripts/run-independent-review-test-evidence.mjs",
  testResultSchema:
    "implementation/governance/schemas/independent-review-test-result.v3.schema.json",
  sandboxPolicyTemplate:
    "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in",
  governanceSubjects: kimiK3ReviewMaterialGovernancePathsV2,
});
const K3_V4_FIXED_PATHS = Object.freeze({
  ...K3_V2_FIXED_PATHS,
  prompt: kimiK3ReviewMaterialPathsV3.prompt,
  outputSchema: kimiK3ReviewMaterialPathsV3.outputSchema,
  receiptSchema: kimiK3ReviewMaterialPathsV3.receiptSchema,
  config: kimiK3ReviewMaterialPathsV3.config,
  modelVisibleProtocol: kimiK3ReviewMaterialPathsV3.modelVisibleProtocol,
  research:
    "docs/research/moonshot-kimi-k3-transport-contract-v3-2026-08-01.md",
  materialSchema:
    "implementation/governance/schemas/independent-review-material.v4.schema.json",
  historicalEvidenceIndex:
    kimiK3HistoricalReviewEvidenceContract.indexPath,
  historicalEvidenceIndexSchema:
    kimiK3HistoricalReviewEvidenceContract.indexSchemaPath,
  governanceSubjects: Object.freeze(
    [
      ...new Set([
        ...kimiK3ReviewMaterialGovernancePathsV3,
        "implementation/governance/schemas/independent-review-material.v4.schema.json",
        kimiK3HistoricalReviewEvidenceContract.indexPath,
        kimiK3HistoricalReviewEvidenceContract.indexSchemaPath,
      ]),
    ].sort(),
  ),
});
const K3_MFJS_V4_FIXED_PATHS = Object.freeze({
  ...K3_V4_FIXED_PATHS,
  providerTransportSchema:
    kimiK3ReviewMaterialPathsV4.providerTransportSchema,
  chatDiagnosticSchema: kimiK3ReviewMaterialPathsV4.chatDiagnosticSchema,
  receiptSchema: kimiK3ReviewMaterialPathsV4.receiptSchema,
  governanceSubjects: kimiK3ReviewMaterialGovernancePathsV4,
});
const K3_MFJS_V4_REQUIRED_PATHS = Object.freeze([
  kimiK3ReviewMaterialPathsV4.providerTransportSchema,
  kimiK3ReviewMaterialPathsV4.chatDiagnosticSchema,
  kimiK3ReviewMaterialPathsV4.receiptSchema,
  "implementation/governance/schemas/independent-review-transport-evidence.v4.schema.json",
  "docs/adr/0016-kimi-k3-mfjs-provider-transport-adapter.md",
]);
const K3_V5_FIXED_PATHS = Object.freeze({
  ...K3_MFJS_V4_FIXED_PATHS,
  tokenEstimateDiagnosticSchema:
    kimiK3ReviewMaterialPathsV5.tokenEstimateDiagnosticSchema,
  chatDiagnosticSchema: kimiK3ReviewMaterialPathsV5.chatDiagnosticSchema,
  receiptSchema: kimiK3ReviewMaterialPathsV5.receiptSchema,
  governanceSubjects: kimiK3ReviewMaterialGovernancePathsV5,
});
const K3_V5_ADDITIVE_REQUIRED_PATHS = Object.freeze([
  kimiK3ReviewMaterialPathsV5.tokenEstimateDiagnosticSchema,
  kimiK3ReviewMaterialPathsV5.chatDiagnosticSchema,
  kimiK3ReviewMaterialPathsV5.receiptSchema,
  "implementation/governance/independent-review/kimi-runtime-manifest.v3.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v3.schema.json",
  "docs/adr/0017-kimi-k3-explicit-undici-timeout-contract.md",
]);
const K3_V6_FIXED_PATHS = Object.freeze({
  ...K3_V5_FIXED_PATHS,
  receiptSchema: kimiK3ReviewMaterialPathsV6.receiptSchema,
  governanceSubjects: kimiK3ReviewMaterialGovernancePathsV6,
});
const K3_V6_ADDITIVE_REQUIRED_PATHS = Object.freeze([
  kimiK3ReviewMaterialPathsV6.receiptSchema,
  "implementation/governance/independent-review/kimi-runtime-manifest.v4.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v4.schema.json",
  "docs/adr/0018-kimi-k3-extended-chat-deadline-contract.md",
]);
const K3_V7_FIXED_PATHS = Object.freeze({
  ...K3_V6_FIXED_PATHS,
  chatDiagnosticSchema: kimiK3ReviewMaterialPathsV7.chatDiagnosticSchema,
  receiptSchema: kimiK3ReviewMaterialPathsV7.receiptSchema,
  governanceSubjects: kimiK3ReviewMaterialGovernancePathsV7,
});
const K3_V7_ADDITIVE_REQUIRED_PATHS = Object.freeze([
  kimiK3ReviewMaterialPathsV7.chatDiagnosticSchema,
  kimiK3ReviewMaterialPathsV7.receiptSchema,
  "implementation/governance/independent-review/kimi-runtime-manifest.v5.json",
  "implementation/governance/schemas/independent-review-runtime-manifest.v5.schema.json",
  "docs/adr/0019-kimi-k3-chat-response-sensitive-material-contract.md",
]);
const EXECUTING_PATHS = Object.freeze([
  "lib/independent-model-review.mjs",
  "lib/kimi-independent-review.mjs",
  "scripts/build-independent-review-material.mjs",
]);
const K3_EXECUTING_PATHS = Object.freeze(
  [...EXECUTING_PATHS, "lib/kimi-k3-independent-review.mjs"].sort(),
);
const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
  ...(process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
    "DENY_ALL_OFFLINE_ALTERNATIVES" &&
  typeof process.env.xcrun_db === "string" &&
  process.env.xcrun_db.startsWith("/") &&
  !process.env.xcrun_db.includes("\0")
    ? { xcrun_db: process.env.xcrun_db }
    : {}),
});

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

async function git(repoPath, args, encoding = "buffer") {
  return execFileAsync(
    "/usr/bin/git",
    ["--no-replace-objects", "-C", repoPath, ...args],
    {
      encoding,
      env: gitEnvironment,
      maxBuffer: 64 * 1024 * 1024,
    },
  );
}

async function requireCommit(repoPath, commit) {
  if (!COMMIT.test(commit)) {
    throw new TypeError("Review Material sourceCommit is invalid.");
  }
  const { stdout } = await git(
    repoPath,
    ["cat-file", "-t", commit],
    "utf8",
  );
  if (stdout.trim() !== "commit") {
    throw new TypeError("Review Material sourceCommit is not a commit.");
  }
}

async function commitBytes(repoPath, sourceCommit, path) {
  if (!SAFE_PATH.test(path)) {
    throw new TypeError("Review Material Git path is unsafe.");
  }
  const { stdout } = await git(repoPath, [
    "cat-file",
    "blob",
    `${sourceCommit}:${path}`,
  ]);
  return Buffer.from(stdout);
}

async function verifyExecutingBytes(repoPath, sourceCommit, k3) {
  for (const path of k3 ? K3_EXECUTING_PATHS : EXECUTING_PATHS) {
    const [currentBytes, frozenBytes] = await Promise.all([
      readFile(resolve(scriptRoot(), path)),
      commitBytes(repoPath, sourceCommit, path),
    ]);
    if (
      independentKimiReviewDigests.bytes(currentBytes) !==
      independentKimiReviewDigests.bytes(frozenBytes)
    ) {
      throw new TypeError(
        `Running Review Material component is not frozen: ${path}`,
      );
    }
  }
}

function scriptRoot() {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

function utf8Content(bytes, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new TypeError(`${label} is not valid UTF-8.`);
  }
}

function section(kind, path, bytes) {
  if (
    ![
      "GOVERNANCE",
      "PATCH",
      "REVIEW_BUNDLE",
      "SOURCE",
      "SPECIFICATION",
      "TEST_EVIDENCE",
    ].includes(kind) ||
    !SAFE_PATH.test(path) ||
    !(bytes instanceof Uint8Array) ||
    (bytes.byteLength === 0 && kind !== "TEST_EVIDENCE")
  ) {
    throw new TypeError("Review Material section is invalid.");
  }
  return {
    descriptor: {
      kind,
      path,
      encoding: "UTF-8",
      byteLength: bytes.byteLength,
      sha256: independentKimiReviewDigests.bytes(bytes),
    },
    bytes: Buffer.from(bytes),
  };
}

function byteBinding(path, bytes) {
  return {
    path,
    byteLength: bytes.byteLength,
    sha256: independentKimiReviewDigests.bytes(bytes),
  };
}

async function evidenceBytes(evidenceRoot, ref) {
  if (!SAFE_PATH.test(ref)) {
    throw new TypeError("Test evidence reference is unsafe.");
  }
  const exactRoot = await realpath(resolve(evidenceRoot));
  const exactPath = await realpath(resolve(exactRoot, ref));
  if (
    exactPath !== exactRoot &&
    !exactPath.startsWith(`${exactRoot}${sep}`)
  ) {
    throw new TypeError("Test evidence reference escapes its root.");
  }
  if (!(await stat(exactPath)).isFile()) {
    throw new TypeError("Test evidence reference is not a file.");
  }
  return readFile(exactPath);
}

function descriptor(sectionValue) {
  return structuredClone(sectionValue.descriptor);
}

function materialEnvelopeByteLength(material, sectionBytes) {
  const manifestByteLength = Buffer.byteLength(
    JSON.stringify(material),
    "utf8",
  );
  return sectionBytes.reduce(
    (total, bytes) =>
      total + Buffer.byteLength(`\n${bytes.byteLength}\n`, "ascii") +
      bytes.byteLength,
    Buffer.byteLength("INDEPENDENT-REVIEW-MATERIAL/2\n", "utf8") +
      Buffer.byteLength(`${manifestByteLength}\n`, "ascii") +
      manifestByteLength,
  );
}

async function commitPathExists(repoPath, commit, path) {
  return (await commitTreeEntry(repoPath, commit, path, false)) !== null;
}

async function commitTreeEntry(
  repoPath,
  commit,
  path,
  required = true,
) {
  if (!SAFE_PATH.test(path)) {
    throw new TypeError("Review Material Git path is unsafe.");
  }
  const { stdout } = await git(repoPath, [
    "ls-tree",
    "-z",
    commit,
    "--",
    path,
  ]);
  const bytes = Buffer.from(stdout);
  if (bytes.byteLength === 0) {
    if (!required) return null;
    throw new TypeError(`Review Material tree entry is missing: ${path}`);
  }
  const value = utf8Content(bytes, "Review Material tree entry");
  const match =
    /^(100644|100755|120000|160000) (blob|commit) ([a-f0-9]{40})\t([^\0]+)\0$/u.exec(
      value,
    );
  if (!match || match[4] !== path) {
    throw new TypeError(
      `Review Material tree entry is ambiguous: ${path}`,
    );
  }
  return { mode: match[1], type: match[2], objectId: match[3], path };
}

async function perPathPatchBytes(
  repoPath,
  baseCommit,
  sourceCommit,
  path,
) {
  const { stdout } = await git(repoPath, [
    "diff",
    "--unified=0",
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    baseCommit,
    sourceCommit,
    "--",
    path,
  ]);
  const bytes = Buffer.from(stdout);
  if (bytes.byteLength === 0) {
    throw new TypeError(
      `Review Material path patch is empty: ${path}`,
    );
  }
  return bytes;
}

function isStrictUtf8(bytes) {
  try {
    utf8Content(bytes, "Review Material source");
    return true;
  } catch {
    return false;
  }
}

function historicalEvidenceError(reasonCode, message) {
  const error = new TypeError(message);
  error.reasonCodes = [reasonCode];
  return error;
}

function digestWithoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return independentKimiReviewDigests.value(copy);
}

function exactJsonBytes(bytes, label) {
  const value = parseIndependentReviewJsonBytes(
    bytes,
    label,
    2 * 1024 * 1024,
  );
  if (!Buffer.from(JSON.stringify(value), "utf8").equals(bytes)) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_ARTIFACT_INVALID",
      `${label} is not exact canonical request JSON.`,
    );
  }
  return value;
}

function fixedRequestMessages(request, kind) {
  if (
    request?.model !== "kimi-k3" ||
    !Array.isArray(request.messages) ||
    request.messages.length !== 2 ||
    request.messages.some(
      (message, index) =>
        !exactKeys(message, ["role", "content"]) ||
        message.role !== (index === 0 ? "system" : "user") ||
        typeof message.content !== "string" ||
        message.content.length === 0,
    ) ||
    (kind === "FORMAL_REQUEST" &&
      (!exactKeys(request, [
        "model",
        "messages",
        "reasoning_effort",
        "tool_choice",
        "response_format",
        "max_completion_tokens",
      ]) ||
        request.reasoning_effort !== "max" ||
        request.tool_choice !== "none" ||
        Object.hasOwn(request, "tools") ||
        Object.hasOwn(request, "thinking") ||
        request.response_format?.type !== "json_schema" ||
        request.response_format?.json_schema?.strict !== true ||
        request.max_completion_tokens !== 32_768)) ||
    (kind === "TOKEN_ESTIMATE_REQUEST" &&
      !exactKeys(request, ["model", "messages"]))
  ) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_ARTIFACT_INVALID",
      `Historical ${kind} is not the frozen Kimi K3 request.`,
    );
  }
  return Buffer.from(JSON.stringify(request.messages), "utf8");
}

async function historicalReviewEvidenceReferences({
  repoPath,
  sourceCommit,
  bundle,
  policy,
  indexBytes,
  indexSchemaBytes,
}) {
  const index = parseIndependentReviewJsonBytes(
    indexBytes,
    "Independent review historical evidence index",
    1024 * 1024,
  );
  if (
    independentKimiReviewDigests.bytes(indexSchemaBytes) !==
    kimiK3HistoricalReviewEvidenceContract.indexSchemaBytesSha256
  ) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_INDEX_INVALID",
      "Historical independent-review evidence index Schema bytes drifted.",
    );
  }
  const indexSchemaValidation =
    await validateIndependentReviewSchemaInstance({
      schemaBytes: indexSchemaBytes,
      expectedSchemaSha256:
        independentKimiReviewDigests.bytes(indexSchemaBytes),
      instance: index,
      label: "Independent review historical evidence index Schema",
    });
  const semanticValidation =
    validateIndependentReviewHistoricalEvidenceIndex({
      index,
      expected: {
        indexBytesSha256:
          kimiK3HistoricalReviewEvidenceContract.indexBytesSha256,
        actualIndexBytesSha256: independentKimiReviewDigests.bytes(indexBytes),
        evidenceOriginCommit:
          kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit,
        evidenceOriginTree:
          kimiK3HistoricalReviewEvidenceContract.evidenceOriginTree,
      },
    });
  if (!indexSchemaValidation.ok || !semanticValidation.ok) {
    const error = historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_INDEX_INVALID",
      "Historical independent-review evidence index is invalid.",
    );
    error.reasonCodes = [
      ...indexSchemaValidation.reasonCodes,
      ...semanticValidation.reasonCodes,
    ];
    throw error;
  }
  const { stdout: originTreeText } = await git(
    repoPath,
    [
      "rev-parse",
      `${kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit}^{tree}`,
    ],
    "utf8",
  );
  if (
    originTreeText.trim() !==
    kimiK3HistoricalReviewEvidenceContract.evidenceOriginTree
  ) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_ORIGIN_MISMATCH",
      "Historical evidence origin tree does not match Git.",
    );
  }
  const sourceSubjects = new Map(
    bundle.sourceSubjects.map((subject) => [subject.path, subject]),
  );
  const entries = new Map(index.entries.map((entry) => [entry.path, entry]));
  const artifacts = new Map();
  for (const fixed of kimiK3HistoricalReviewEvidenceContract.entries) {
    const entry = entries.get(fixed.path);
    const subject = sourceSubjects.get(fixed.path);
    const [originEntry, sourceEntry, originBytes, sourceBytes] =
      await Promise.all([
        commitTreeEntry(
          repoPath,
          kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit,
          fixed.path,
        ),
        commitTreeEntry(repoPath, sourceCommit, fixed.path),
        commitBytes(
          repoPath,
          kimiK3HistoricalReviewEvidenceContract.evidenceOriginCommit,
          fixed.path,
        ),
        commitBytes(repoPath, sourceCommit, fixed.path),
      ]);
    if (
      !entry ||
      !subject ||
      originEntry.mode !== "100644" ||
      originEntry.type !== "blob" ||
      sourceEntry.mode !== "100644" ||
      sourceEntry.type !== "blob" ||
      subject.gitMode !== "100644" ||
      subject.blobSha256 !== fixed.sha256 ||
      !originBytes.equals(sourceBytes) ||
      originBytes.byteLength !== fixed.byteLength ||
      independentKimiReviewDigests.bytes(originBytes) !== fixed.sha256
    ) {
      throw historicalEvidenceError(
        "KIMI_REVIEW_HISTORICAL_EVIDENCE_ARTIFACT_MISMATCH",
        `Historical review evidence bytes or mode drifted: ${fixed.path}`,
      );
    }
    artifacts.set(fixed.artifactType, originBytes);
  }
  const historicalBundle = parseIndependentReviewJsonBytes(
    artifacts.get("REVIEW_BUNDLE"),
    "Historical independent review Bundle",
    1024 * 1024,
  );
  const historicalBundleValidation = await validateIndependentReviewBundle(
    historicalBundle,
    { policy },
  );
  if (
    !historicalBundleValidation.ok ||
    historicalBundle.bundleId !== index.priorReview.bundleId ||
    historicalBundle.bundleSha256 !== index.priorReview.bundleDigest ||
    historicalBundle.source.baseCommit !==
      kimiIndependentReviewFixedBaseCommit ||
    historicalBundle.source.sourceCommit !== index.priorReview.sourceCommit ||
    historicalBundle.source.tree !== index.priorReview.sourceTree ||
    historicalBundle.source.diffSha256 !== index.priorReview.patchSha256
  ) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_ARTIFACT_INVALID",
      "Historical review Bundle binding is invalid.",
    );
  }
  const historicalMaterialBytes = artifacts.get("REVIEW_MATERIAL");
  let historicalMaterial;
  try {
    historicalMaterial = parseIndependentReviewMaterialEnvelope(
      historicalMaterialBytes,
    );
  } catch {
    historicalMaterial = null;
  }
  const embeddedBundleIndex = historicalMaterial?.material?.sections?.findIndex(
    ({ kind, path }) =>
      kind === "REVIEW_BUNDLE" &&
      path === "artifacts/independent-review-bundle.v2.json",
  );
  if (
    historicalMaterial?.material?.schemaVersion !==
      "independent-review-material.v3" ||
    historicalMaterial.material.materialId !== index.priorReview.materialId ||
    historicalMaterial.material.materialSha256 !==
      index.priorReview.materialDigest ||
    !Number.isInteger(embeddedBundleIndex) ||
    embeddedBundleIndex < 0 ||
    !historicalMaterial.sectionBytes[embeddedBundleIndex].equals(
      artifacts.get("REVIEW_BUNDLE"),
    )
  ) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_ARTIFACT_INVALID",
      "Historical review Material lineage is invalid.",
    );
  }
  const formalRequest = exactJsonBytes(
    artifacts.get("FORMAL_REQUEST"),
    "Historical Kimi K3 formal request",
  );
  const tokenEstimateRequest = exactJsonBytes(
    artifacts.get("TOKEN_ESTIMATE_REQUEST"),
    "Historical Kimi K3 token estimate request",
  );
  const formalMessages = fixedRequestMessages(
    formalRequest,
    "FORMAL_REQUEST",
  );
  const tokenMessages = fixedRequestMessages(
    tokenEstimateRequest,
    "TOKEN_ESTIMATE_REQUEST",
  );
  if (
    !formalMessages.equals(tokenMessages) ||
    formalRequest.messages[1].content !==
      utf8Content(historicalMaterialBytes, "Historical review Material")
  ) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_LINEAGE_INVALID",
      "Historical Kimi K3 request lineage is invalid.",
    );
  }
  const outcome = parseIndependentReviewJsonBytes(
    artifacts.get("SINGLE_CALL_OUTCOME"),
    "Historical Kimi K3 outcome",
    1024 * 1024,
  );
  if (
    outcome?.schemaVersion !== "kimi-k3-single-call-outcome.v1" ||
    outcome.source?.baseCommit !==
      index.baseCommitCorrection.recordedBaseCommit ||
    outcome.execution?.status !== "BLOCKED" ||
    outcome.execution?.conclusion !== "INCONCLUSIVE" ||
    outcome.execution?.chatCompletionAttemptCount !== 0 ||
    outcome.execution?.receiptArtifact !== null ||
    outcome.execution?.modelReviewClearForPreproduction !== false ||
    outcome.boundary?.formalChatAttempted !== false ||
    outcome.boundary?.fallbackAttempted !== false ||
    outcome.boundary?.segmentedReviewAttempted !== false ||
    outcome.bindings?.messagesSha256 !==
      independentKimiReviewDigests.bytes(formalMessages) ||
    digestWithoutField(outcome, "outcomeSha256") !== outcome.outcomeSha256 ||
    !kimiK3HistoricalReviewEvidencePaths.every((path) => {
      const entry = entries.get(path);
      if (entry.artifactType === "SINGLE_CALL_OUTCOME") return true;
      const artifactNames = {
        FORMAL_REQUEST: "formalRequest",
        REVIEW_BUNDLE: "reviewBundle",
        REVIEW_MATERIAL: "reviewMaterial",
        TOKEN_ESTIMATE_REQUEST: "tokenEstimateRequest",
      };
      const binding = outcome.artifacts?.[artifactNames[entry.artifactType]];
      return (
        binding?.path === path &&
        binding?.byteLength === entry.byteLength &&
        binding?.sha256 === entry.sha256
      );
    })
  ) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_HISTORICAL_EVIDENCE_OUTCOME_CORRECTION_INVALID",
      "Historical Kimi K3 blocked outcome binding is invalid.",
    );
  }
  return { index, references: semanticValidation.references };
}

export async function buildIndependentReviewMaterialFromGit(input) {
  if (
    !exactKeys(input, [
      "repoPath",
      "reviewBundleBytes",
      "testEvidenceRoot",
      "materialId",
    ]) ||
    !(input.reviewBundleBytes instanceof Uint8Array) ||
    !/^irm_[a-z0-9][a-z0-9_-]{7,127}$/u.test(input.materialId ?? "")
  ) {
    throw new TypeError("Review Material builder input is invalid.");
  }
  const repoPath = resolve(input.repoPath);
  const bundle = parseIndependentReviewJsonBytes(
    input.reviewBundleBytes,
    "Independent Review Bundle",
    16 * 1024 * 1024,
  );
  await requireCommit(repoPath, bundle?.source?.sourceCommit);
  if (
    bundle?.source?.baseCommit !==
    kimiIndependentReviewFixedBaseCommit
  ) {
    throw new TypeError(
      "Review Material baseCommit is not the frozen Kimi review base.",
    );
  }
  await requireCommit(repoPath, kimiIndependentReviewFixedBaseCommit);
  const k3V3 = await commitPathExists(
    repoPath,
    bundle.source.sourceCommit,
    kimiK3ReviewMaterialPathsV3.config,
  );
  const k3V2 =
    !k3V3 &&
    (await commitPathExists(
      repoPath,
      bundle.source.sourceCommit,
      kimiK3ReviewMaterialPathsV2.config,
    ));
  const k3 = k3V3 || k3V2;
  const k3V4ContractComplete =
    k3V3 &&
    (await commitPathExists(
      repoPath,
      bundle.source.sourceCommit,
      kimiK3HistoricalReviewEvidenceContract.indexPath,
    ));
  if (k3V3 && !k3V4ContractComplete) {
    throw historicalEvidenceError(
      "KIMI_K3_MATERIAL_V4_CONTRACT_INCOMPLETE",
      "Kimi K3 v3 config requires the complete Material v4 contract.",
    );
  }
  const k3V4 = k3V3;
  const [
    k3MfjsV4Presence,
    k3V5AdditivePresence,
    k3V6AdditivePresence,
    k3V7AdditivePresence,
  ] = k3V4
    ? await Promise.all([
        Promise.all(
          K3_MFJS_V4_REQUIRED_PATHS.map((path) =>
            commitPathExists(repoPath, bundle.source.sourceCommit, path),
          ),
        ),
        Promise.all(
          K3_V5_ADDITIVE_REQUIRED_PATHS.map((path) =>
            commitPathExists(repoPath, bundle.source.sourceCommit, path),
          ),
        ),
        Promise.all(
          K3_V6_ADDITIVE_REQUIRED_PATHS.map((path) =>
            commitPathExists(repoPath, bundle.source.sourceCommit, path),
          ),
        ),
        Promise.all(
          K3_V7_ADDITIVE_REQUIRED_PATHS.map((path) =>
            commitPathExists(repoPath, bundle.source.sourceCommit, path),
          ),
        ),
      ])
    : [[], [], [], []];
  const k3Contract = k3V4
    ? classifyKimiK3V7ContractPresence({
        v4Presence: k3MfjsV4Presence,
        v5AdditivePresence: k3V5AdditivePresence,
        v6AdditivePresence: k3V6AdditivePresence,
        v7AdditivePresence: k3V7AdditivePresence,
      })
    : "NO_V4_OR_V5";
  if (k3Contract === "K3_V7_INCOMPLETE") {
    throw historicalEvidenceError(
      "KIMI_K3_RUNTIME_V7_CONTRACT_INCOMPLETE",
      "Kimi K3 runtime v7 requires its complete append-only contract.",
    );
  }
  if (k3Contract === "K3_V6_INCOMPLETE") {
    throw historicalEvidenceError(
      "KIMI_K3_RUNTIME_V6_CONTRACT_INCOMPLETE",
      "Kimi K3 runtime v6 requires its complete append-only contract.",
    );
  }
  if (k3Contract === "K3_V5_INCOMPLETE") {
    throw historicalEvidenceError(
      "KIMI_K3_RUNTIME_V5_CONTRACT_INCOMPLETE",
      "Kimi K3 runtime v5 requires its complete append-only contract.",
    );
  }
  if (k3Contract === "K3_V4_INCOMPLETE") {
    throw historicalEvidenceError(
      "KIMI_K3_MFJS_V4_CONTRACT_INCOMPLETE",
      "Kimi K3 MFJS v4 requires its complete append-only contract.",
    );
  }
  const k3V7 = k3Contract === "K3_V7_COMPLETE";
  const k3V6 = k3V7 || k3Contract === "K3_V6_COMPLETE";
  const k3V5 = k3V6 || k3Contract === "K3_V5_COMPLETE";
  const k3MfjsV4 =
    k3V5 || k3Contract === "K3_V4_COMPLETE";
  await verifyExecutingBytes(repoPath, bundle.source.sourceCommit, k3);
  const fixedPaths = k3V7
    ? K3_V7_FIXED_PATHS
    : k3V6
      ? K3_V6_FIXED_PATHS
    : k3V5
      ? K3_V5_FIXED_PATHS
      : k3MfjsV4
        ? K3_MFJS_V4_FIXED_PATHS
        : k3V4
          ? K3_V4_FIXED_PATHS
          : k3V2
            ? K3_V2_FIXED_PATHS
            : K2_FIXED_PATHS;
  const policyBytes = await commitBytes(
    repoPath,
    bundle.source.sourceCommit,
    fixedPaths.policy,
  );
  const policy = parseIndependentReviewJsonBytes(
    policyBytes,
    "Independent Review Policy",
    1024 * 1024,
  );
  const [policyValidation, bundleValidation] = await Promise.all([
    validateIndependentReviewPolicy(policy),
    validateIndependentReviewBundle(bundle, { policy }),
  ]);
  if (!policyValidation.ok || !bundleValidation.ok) {
    throw new TypeError("Review Material Bundle or Policy is invalid.");
  }
  if (
    JSON.stringify(
      bundle.specificationSubjects.map(({ path }) => path),
    ) !== JSON.stringify(independentModelReviewFixedSpecificationPaths) ||
    bundle.artifacts.testPlanPath !== fixedPaths.testPlan ||
    bundle.artifacts.testEvidenceCollectorPath !==
      fixedPaths.testEvidenceCollector ||
    bundle.artifacts.testResultSchemaPath !==
      fixedPaths.testResultSchema ||
    bundle.artifacts.sandboxPolicyTemplatePath !==
      fixedPaths.sandboxPolicyTemplate
  ) {
    throw new TypeError(
      "Review Material frozen specification or test scope is invalid.",
    );
  }
  const [
    testPlanBytes,
    collectorBytes,
    testResultSchemaBytes,
    sandboxPolicyTemplateBytes,
  ] = await Promise.all([
    commitBytes(repoPath, bundle.source.sourceCommit, fixedPaths.testPlan),
    commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      fixedPaths.testEvidenceCollector,
    ),
    commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      fixedPaths.testResultSchema,
    ),
    commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      fixedPaths.sandboxPolicyTemplate,
    ),
  ]);
  const testEvidenceClosure =
    await validateIndependentReviewTestEvidenceClosure({
      bundle,
      testPlanBytes,
      collectorBytes,
      testResultSchemaBytes,
      sandboxPolicyTemplateBytes,
      evidenceResolver: (ref) =>
        evidenceBytes(input.testEvidenceRoot, ref),
    });
  if (!testEvidenceClosure.ok) {
    throw new TypeError(
      "Review Material test evidence closure is invalid.",
    );
  }
  if (
    !SHA256.test(bundle.bundleSha256)
  ) {
    throw new TypeError("Review Material Bundle digest is invalid.");
  }
  const { stdout: sourceTreeText } = await git(
    repoPath,
    ["rev-parse", `${bundle.source.sourceCommit}^{tree}`],
    "utf8",
  );
  if (sourceTreeText.trim() !== bundle.source.tree) {
    throw new TypeError("Review Material source tree does not match Git.");
  }
  const { stdout: patchBytesValue } = await git(repoPath, [
    "diff",
    "--binary",
    "--full-index",
    "--no-ext-diff",
    "--no-textconv",
    bundle.source.baseCommit,
    bundle.source.sourceCommit,
    "--",
  ]);
  const patchBytes = Buffer.from(patchBytesValue);
  if (
    independentKimiReviewDigests.bytes(patchBytes) !==
    bundle.source.diffSha256
  ) {
    throw new TypeError("Review Material patch does not match the Bundle.");
  }

  const [
    promptBytes,
    outputSchemaBytes,
    receiptSchemaBytes,
    configBytes,
    researchBytes,
  ] =
    await Promise.all(
      [
        fixedPaths.prompt,
        fixedPaths.outputSchema,
        fixedPaths.receiptSchema,
        fixedPaths.config,
        ...(k3 ? [fixedPaths.research] : []),
      ].map((path) => commitBytes(repoPath, bundle.source.sourceCommit, path)),
    );
  const config = parseIndependentReviewJsonBytes(
    configBytes,
    "Moonshot Kimi configuration",
    1024 * 1024,
  );
  const configValidation = k3
    ? await validateMoonshotKimiK3FrozenContract({ config, researchBytes })
    : await validateMoonshotKimiConfig(config);
  if (!configValidation.ok) {
    throw new TypeError("Frozen Moonshot Kimi configuration is invalid.");
  }

  let historicalEvidence = null;
  let historicalEvidenceIndexBytes = null;
  let historicalEvidenceIndexSchemaBytes = null;
  let materialSchemaBytes = null;
  if (k3V4) {
    [
      historicalEvidenceIndexBytes,
      historicalEvidenceIndexSchemaBytes,
      materialSchemaBytes,
    ] = await Promise.all([
      commitBytes(
        repoPath,
        bundle.source.sourceCommit,
        fixedPaths.historicalEvidenceIndex,
      ),
      commitBytes(
        repoPath,
        bundle.source.sourceCommit,
        fixedPaths.historicalEvidenceIndexSchema,
      ),
      commitBytes(
        repoPath,
        bundle.source.sourceCommit,
        fixedPaths.materialSchema,
      ),
    ]);
    const [indexEntry, indexSchemaEntry, materialSchemaEntry] =
      await Promise.all([
        commitTreeEntry(
          repoPath,
          bundle.source.sourceCommit,
          fixedPaths.historicalEvidenceIndex,
        ),
        commitTreeEntry(
          repoPath,
          bundle.source.sourceCommit,
          fixedPaths.historicalEvidenceIndexSchema,
        ),
        commitTreeEntry(
          repoPath,
          bundle.source.sourceCommit,
          fixedPaths.materialSchema,
        ),
      ]);
    if (
      [indexEntry, indexSchemaEntry, materialSchemaEntry].some(
        (entry) => entry.mode !== "100644" || entry.type !== "blob",
      )
    ) {
      throw historicalEvidenceError(
        "KIMI_REVIEW_HISTORICAL_EVIDENCE_ARTIFACT_MISMATCH",
        "Historical evidence index or Schema is not a regular Git blob.",
      );
    }
    historicalEvidence = await historicalReviewEvidenceReferences({
      repoPath,
      sourceCommit: bundle.source.sourceCommit,
      bundle,
      policy,
      indexBytes: historicalEvidenceIndexBytes,
      indexSchemaBytes: historicalEvidenceIndexSchemaBytes,
    });
  }

  const sectionEntries = [
    section(
      "REVIEW_BUNDLE",
      "artifacts/independent-review-bundle.v2.json",
      input.reviewBundleBytes,
    ),
  ];
  const governancePaths = new Set(fixedPaths.governanceSubjects);
  const reviewedPaths = new Set(bundle.reviewedPaths);
  const sourceSubjects = new Map(
    bundle.sourceSubjects.map((subject) => [subject.path, subject]),
  );
  for (const path of bundle.reviewedPaths) {
    const subject = sourceSubjects.get(path);
    if (!subject) {
      throw new TypeError(
        "Review Material source subject is missing.",
      );
    }
    if (
      k3V4 &&
      kimiK3HistoricalReviewEvidencePaths.includes(path)
    ) {
      continue;
    }
    const bytes = await commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      path,
    );
    if (independentKimiReviewDigests.bytes(bytes) !== subject.blobSha256) {
      throw new TypeError("Review Material source subject bytes drifted.");
    }
    const added =
      !(await commitPathExists(
        repoPath,
        kimiIndependentReviewFixedBaseCommit,
        path,
      ));
    if (added && isStrictUtf8(bytes)) {
      sectionEntries.push(section("SOURCE", path, bytes));
    } else {
      sectionEntries.push(
        section(
          "PATCH",
          path,
          await perPathPatchBytes(
            repoPath,
            kimiIndependentReviewFixedBaseCommit,
            bundle.source.sourceCommit,
            path,
          ),
        ),
      );
    }
  }
  for (const subject of bundle.specificationSubjects) {
    const bytes = await commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      subject.path,
    );
    if (independentKimiReviewDigests.bytes(bytes) !== subject.blobSha256) {
      throw new TypeError("Review Material specification bytes drifted.");
    }
    if (
      !governancePaths.has(subject.path) &&
      !reviewedPaths.has(subject.path)
    ) {
      sectionEntries.push(section("SPECIFICATION", subject.path, bytes));
    }
  }
  const includedEvidencePaths = new Set();
  for (const subject of bundle.testEvidenceSubjects) {
    const resultBytes = await evidenceBytes(
      input.testEvidenceRoot,
      subject.outputRef,
    );
    if (
      independentKimiReviewDigests.bytes(resultBytes) !==
        subject.outputSha256 ||
      resultBytes.byteLength !== subject.outputByteLength
    ) {
      throw new TypeError("Review Material test evidence bytes drifted.");
    }
    const result = parseIndependentReviewJsonBytes(
      resultBytes,
      "Review Material test result",
      1024 * 1024,
    );
    const evidenceBindings = [
      {
        path: subject.outputRef,
        bytes: resultBytes,
        sha256: subject.outputSha256,
        byteLength: subject.outputByteLength,
        modelVisible: true,
      },
      {
        path: result.stdoutRef,
        bytes: await evidenceBytes(
          input.testEvidenceRoot,
          result.stdoutRef,
        ),
        sha256: result.stdoutSha256,
        byteLength: result.stdoutByteLength,
        modelVisible: false,
      },
      {
        path: result.stderrRef,
        bytes: await evidenceBytes(
          input.testEvidenceRoot,
          result.stderrRef,
        ),
        sha256: result.stderrSha256,
        byteLength: result.stderrByteLength,
        modelVisible: false,
      },
      {
        path: result.runtimeBinding.artifactRef,
        bytes: await evidenceBytes(
          input.testEvidenceRoot,
          result.runtimeBinding.artifactRef,
        ),
        sha256: result.runtimeBinding.artifactSha256,
        byteLength: result.runtimeBinding.artifactByteLength,
        modelVisible: false,
      },
    ];
    for (const binding of evidenceBindings) {
      if (
        !SAFE_PATH.test(binding.path) ||
        independentKimiReviewDigests.bytes(binding.bytes) !==
          binding.sha256 ||
        binding.bytes.byteLength !== binding.byteLength
      ) {
        throw new TypeError(
          "Review Material test transcript bytes drifted.",
        );
      }
      if (
        binding.modelVisible &&
        !includedEvidencePaths.has(binding.path)
      ) {
        includedEvidencePaths.add(binding.path);
        sectionEntries.push(
          section("TEST_EVIDENCE", binding.path, binding.bytes),
        );
      }
    }
  }
  const governanceSubjectBindings = [];
  for (const path of fixedPaths.governanceSubjects) {
    const bytes = await commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      path,
    );
    if (!reviewedPaths.has(path)) {
      sectionEntries.push(section("GOVERNANCE", path, bytes));
    }
    governanceSubjectBindings.push(byteBinding(path, bytes));
  }
  const modelVisibleProtocolBytes = k3
    ? createKimiK3ModelVisibleProtocolBytes(config)
    : createKimiModelVisibleProtocolBytes(config);
  sectionEntries.push(
    section(
      "GOVERNANCE",
      k3
        ? fixedPaths.modelVisibleProtocol
        : "artifacts/moonshot-kimi-model-visible-protocol.v1.json",
      modelVisibleProtocolBytes,
    ),
  );
  sectionEntries.sort((left, right) =>
    Buffer.compare(
      Buffer.from(
        `${left.descriptor.kind}:${left.descriptor.path}`,
        "utf8",
      ),
      Buffer.from(
        `${right.descriptor.kind}:${right.descriptor.path}`,
        "utf8",
      ),
    ),
  );
  const sections = sectionEntries.map(descriptor);
  const sectionBytes = sectionEntries.map(({ bytes }) => bytes);
  const sectionKeys = sections.map(
    (current) => `${current.kind}:${current.path}`,
  );
  if (new Set(sectionKeys).size !== sectionKeys.length) {
    throw new TypeError("Review Material contains duplicate sections.");
  }
  const totalSectionUtf8ByteLength = sections.reduce(
    (total, current) => total + current.byteLength,
    0,
  );
  const priorReviewEvidenceReferences = k3V4
    ? historicalEvidence.references
    : [];
  const reviewedPathCoverage = [
    ...sections
      .filter(
        ({ kind, path }) =>
          (kind === "SOURCE" || kind === "PATCH") &&
          reviewedPaths.has(path),
      )
      .map(({ kind, path }) => ({
      path,
      coverageKind: kind,
      sourceBlobSha256: sourceSubjects.get(path).blobSha256,
    })),
    ...priorReviewEvidenceReferences.map(({ path }) => ({
      path,
      coverageKind: "PRIOR_REVIEW_EVIDENCE_REFERENCE",
      sourceBlobSha256: sourceSubjects.get(path).blobSha256,
    })),
  ].sort((left, right) =>
    Buffer.compare(
      Buffer.from(left.path, "utf8"),
      Buffer.from(right.path, "utf8"),
    ),
  );
  const coveredPaths = reviewedPathCoverage.map(({ path }) => path);
  if (
    new Set(coveredPaths).size !== coveredPaths.length ||
    JSON.stringify(coveredPaths) !== JSON.stringify(bundle.reviewedPaths) ||
    (k3V4 &&
      sectionEntries.some(({ descriptor: { path } }) =>
        kimiK3HistoricalReviewEvidencePaths.includes(path),
      ))
  ) {
    throw historicalEvidenceError(
      "KIMI_REVIEW_MATERIAL_REVIEWED_PATH_COVERAGE_MISMATCH",
      "Review Material raw and historical reference path coverage is invalid.",
    );
  }
  const reviewBundleSection = sectionEntries.find(
    (current) => current.descriptor.kind === "REVIEW_BUNDLE",
  );
  const material = {
    schemaVersion: k3V4
      ? "independent-review-material.v4"
      : k3
        ? "independent-review-material.v3"
        : "independent-review-material.v2",
    materialId: input.materialId,
    source: {
      baseCommit: bundle.source.baseCommit,
      sourceCommit: bundle.source.sourceCommit,
      sourceTree: bundle.source.tree,
      patchSha256: bundle.source.diffSha256,
      gitDiffCheckSha256: bundle.source.gitDiffCheck.resultSha256,
    },
    bindings: {
      reviewBundle: byteBinding(
        reviewBundleSection.descriptor.path,
        input.reviewBundleBytes,
      ),
      reviewerPrompt: byteBinding(fixedPaths.prompt, promptBytes),
      canonicalOutputSchema: byteBinding(
        fixedPaths.outputSchema,
        outputSchemaBytes,
      ),
      canonicalReceiptSchema: byteBinding(
        fixedPaths.receiptSchema,
        receiptSchemaBytes,
      ),
      providerConfig: byteBinding(fixedPaths.config, configBytes),
      ...(k3V4
        ? {
            historicalEvidenceIndex: {
              ...byteBinding(
                fixedPaths.historicalEvidenceIndex,
                historicalEvidenceIndexBytes,
              ),
              indexDigest: historicalEvidence.index.indexSha256,
            },
            historicalEvidenceIndexSchema: byteBinding(
              fixedPaths.historicalEvidenceIndexSchema,
              historicalEvidenceIndexSchemaBytes,
            ),
          }
        : {}),
    },
    sections,
    ...(k3V4
      ? {
          priorReviewEvidenceReferences,
          priorReviewEvidenceReferenceSetSha256:
            independentKimiReviewDigests.value(
              priorReviewEvidenceReferences,
            ),
          reviewedPathCoverageSha256:
            independentKimiReviewDigests.value(reviewedPathCoverage),
        }
      : {}),
    sectionSetSha256:
      independentKimiReviewDigests.value(sections),
    totalSectionUtf8ByteLength,
    contextBudgetUtf8Bytes: config.maxReviewMaterialUtf8Bytes,
    ...(k3V4
      ? {
          resourceCeilingBasis:
            "TRANSPORT_RESOURCE_CEILING_ONLY_NOT_CONTEXT_PROOF",
        }
      : {}),
    materialSha256: `sha256:${"0".repeat(64)}`,
  };
  material.bindings.reviewBundle.bundleDigest = bundle.bundleSha256;
  material.materialSha256 =
    independentKimiReviewDigests.material(material);
  const completeMaterialByteLength = materialEnvelopeByteLength(
    material,
    sectionBytes,
  );
  if (
    !k3V4 &&
    completeMaterialByteLength > config.maxReviewMaterialUtf8Bytes
  ) {
    const error = new TypeError(
      "Complete Review Material exceeds its context byte budget.",
    );
    error.reasonCodes = [
      "KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_EXCEEDED",
    ];
    error.actualByteLength = completeMaterialByteLength;
    error.contextBudgetUtf8Bytes = config.maxReviewMaterialUtf8Bytes;
    throw error;
  }
  if (
    k3V4 &&
    completeMaterialByteLength > config.maxReviewMaterialUtf8Bytes
  ) {
    const error = historicalEvidenceError(
      "KIMI_K3_SINGLE_CALL_COMPLETE_SCOPE_EXCEEDS_BYTE_DEFENSE",
      "Complete Kimi K3 Review Material exceeds its byte defense.",
    );
    error.actualByteLength = completeMaterialByteLength;
    error.contextBudgetUtf8Bytes = config.maxReviewMaterialUtf8Bytes;
    error.resourceCeilingBasis =
      "TRANSPORT_RESOURCE_CEILING_ONLY_NOT_CONTEXT_PROOF";
    error.totalSectionUtf8ByteLength = totalSectionUtf8ByteLength;
    throw error;
  }
  if (k3V4) {
    const materialSchemaValidation =
      await validateIndependentReviewSchemaInstance({
        schemaBytes: materialSchemaBytes,
        expectedSchemaSha256:
          independentKimiReviewDigests.bytes(materialSchemaBytes),
        instance: material,
        label: "Independent review Material v4 Schema",
      });
    if (!materialSchemaValidation.ok) {
      const error = historicalEvidenceError(
        "KIMI_REVIEW_MATERIAL_V4_SCHEMA_INVALID",
        "Generated Review Material v4 does not match its frozen Schema.",
      );
      error.reasonCodes = materialSchemaValidation.reasonCodes;
      throw error;
    }
  }
  const materialBytes = encodeIndependentReviewMaterialEnvelope({
    material,
    sectionBytes,
  });
  const materialValidation = await validateIndependentReviewMaterial({
    material,
    rawMaterialBytes: materialBytes,
    expected: {
      source: material.source,
      bindings: material.bindings,
      sectionDescriptors: sections,
      contextBudgetUtf8Bytes: config.maxReviewMaterialUtf8Bytes,
      ...(k3V4
        ? {
            resourceCeilingBasis:
              "TRANSPORT_RESOURCE_CEILING_ONLY_NOT_CONTEXT_PROOF",
          }
        : {}),
      bundle,
      governanceSubjectBindings,
      sourceCommit: bundle.source.sourceCommit,
      sourceTree: bundle.source.tree,
      reviewBundleBytesSha256:
        independentKimiReviewDigests.bytes(input.reviewBundleBytes),
      reviewBundleByteLength: input.reviewBundleBytes.byteLength,
      reviewBundleDigest: bundle.bundleSha256,
      reviewerPromptSha256:
        independentKimiReviewDigests.bytes(promptBytes),
      reviewerPromptByteLength: promptBytes.byteLength,
      canonicalOutputSchemaSha256:
        independentKimiReviewDigests.bytes(outputSchemaBytes),
      canonicalOutputSchemaByteLength: outputSchemaBytes.byteLength,
      canonicalReceiptSchemaSha256:
        independentKimiReviewDigests.bytes(receiptSchemaBytes),
      canonicalReceiptSchemaByteLength: receiptSchemaBytes.byteLength,
      providerConfigSha256:
        independentKimiReviewDigests.bytes(configBytes),
      providerConfigByteLength: configBytes.byteLength,
      ...(k3V4
        ? {
            priorReviewEvidenceReferences,
            historicalEvidenceIndexBytesSha256:
              independentKimiReviewDigests.bytes(
                historicalEvidenceIndexBytes,
              ),
            historicalEvidenceIndexByteLength:
              historicalEvidenceIndexBytes.byteLength,
            historicalEvidenceIndexDigest:
              historicalEvidence.index.indexSha256,
            historicalEvidenceIndexSchemaBytesSha256:
              independentKimiReviewDigests.bytes(
                historicalEvidenceIndexSchemaBytes,
              ),
            historicalEvidenceIndexSchemaByteLength:
              historicalEvidenceIndexSchemaBytes.byteLength,
          }
        : {}),
      modelVisibleProtocolSha256:
        independentKimiReviewDigests.bytes(modelVisibleProtocolBytes),
      modelVisibleProtocolByteLength:
        modelVisibleProtocolBytes.byteLength,
    },
  });
  if (!materialValidation.ok) {
    const error = new TypeError("Generated Review Material is invalid.");
    error.reasonCodes = materialValidation.reasonCodes;
    error.actualByteLength = materialBytes.byteLength;
    error.contextBudgetUtf8Bytes = config.maxReviewMaterialUtf8Bytes;
    throw error;
  }
  return { material, materialBytes };
}

function parseArguments(values) {
  const allowed = new Set([
    "repo",
    "bundle",
    "test-evidence-root",
    "material-id",
    "output",
  ]);
  const args = {};
  for (let index = 0; index < values.length; index += 2) {
    const key = values[index];
    const value = values[index + 1];
    const name = key?.slice(2);
    if (
      !key?.startsWith("--") ||
      value === undefined ||
      !allowed.has(name) ||
      Object.hasOwn(args, name)
    ) {
      throw new TypeError("Review Material CLI arguments are invalid.");
    }
    args[name] = value;
  }
  if (
    Object.keys(args).length !== allowed.size ||
    [...allowed].some((name) => !Object.hasOwn(args, name))
  ) {
    throw new TypeError("Review Material CLI arguments are incomplete.");
  }
  return args;
}

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const reviewBundleBytes = await readFile(resolve(args.bundle));
  const { materialBytes } = await buildIndependentReviewMaterialFromGit({
    repoPath: args.repo,
    reviewBundleBytes,
    testEvidenceRoot: args["test-evidence-root"],
    materialId: args["material-id"],
  });
  await writeFile(resolve(args.output), materialBytes, { flag: "wx" });
  process.stdout.write(
    `${JSON.stringify({
      status: "CREATED",
      outputSha256: independentKimiReviewDigests.bytes(materialBytes),
      outputByteLength: materialBytes.byteLength,
    })}\n`,
  );
}

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(
      `${JSON.stringify({
        status: "BLOCKED",
        code:
          error?.reasonCodes?.[0] ??
          "INDEPENDENT_REVIEW_MATERIAL_BUILD_FAILED",
      })}\n`,
    );
    process.exitCode = 2;
  });
}
