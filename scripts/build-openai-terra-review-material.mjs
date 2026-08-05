#!/usr/bin/env node

import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { promisify } from "node:util";
import {
  OPENAI_TERRA_ADDITIONAL_REVIEW_PATHS,
  OPENAI_TERRA_CORE_REVIEW_PATHS,
  OPENAI_TERRA_MAX_MODEL_VISIBLE_BYTES,
  openAiTerraDigests,
  parseOpenAiTerraReviewSubjectEnvelope,
  validateOpenAiTerraConfig,
} from "../lib/openai-terra-independent-review.mjs";
import {
  buildIndependentReviewBundleFromGit,
} from "./build-independent-review-bundle.mjs";
import {
  validateIndependentReviewBundle,
  validateIndependentReviewPolicy,
} from "../lib/independent-model-review.mjs";

const execFileAsync = promisify(execFile);
const MAGIC = Buffer.from("OPENAI-TERRA-SCOPED-REVIEW/1\n", "ascii");
const COMMIT = /^[a-f0-9]{40}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const gitEnvironment = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
});

function hexLength(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffffff) {
    throw new TypeError("Review Subject length is out of range.");
  }
  return value.toString(16).padStart(12, "0");
}

async function git(repoPath, args, encoding = "buffer") {
  return execFileAsync("/usr/bin/git", ["--no-replace-objects", "-C", repoPath, ...args], {
    encoding,
    env: gitEnvironment,
    maxBuffer: 32 * 1024 * 1024,
  });
}

async function requireCommit(repoPath, value, label) {
  if (!COMMIT.test(value)) throw new TypeError(`${label} is not a commit.`);
  const { stdout } = await git(repoPath, ["cat-file", "-t", value], "utf8");
  if (stdout.trim() !== "commit") throw new TypeError(`${label} is not a commit object.`);
}

async function blobRecord(repoPath, sourceCommit, path) {
  if (!SAFE_PATH.test(path)) throw new TypeError("Review Subject path is unsafe.");
  const { stdout: treeText } = await git(repoPath, ["ls-tree", "-z", sourceCommit, "--", path], "utf8");
  const tree = treeText.replace(/\0$/u, "");
  const match = /^(100644|100755|120000) blob [a-f0-9]{40}\t(.+)$/u.exec(tree);
  if (!match || match[2] !== path || match[1] !== "100644") {
    throw new TypeError(`Review Subject path is missing or not a regular non-executable file: ${path}`);
  }
  const { stdout } = await git(repoPath, ["cat-file", "blob", `${sourceCommit}:${path}`]);
  const bytes = Buffer.from(stdout);
  new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return {
    descriptor: {
      kind: "GIT_BLOB",
      path,
      gitMode: match[1],
      byteLength: bytes.byteLength,
      sha256: openAiTerraDigests.bytes(bytes),
    },
    bytes,
  };
}

async function changedPaths(repoPath, base, source) {
  const { stdout } = await git(repoPath, ["diff-tree", "--no-commit-id", "--name-only", "--no-renames", "-r", "-z", base, source]);
  const paths = Buffer.from(stdout).toString("utf8").split("\0").filter(Boolean).sort();
  if (paths.length === 0 || new Set(paths).size !== paths.length || paths.some((path) => !SAFE_PATH.test(path))) {
    throw new TypeError("Coverage path set is empty, duplicated, or unsafe.");
  }
  return paths;
}

function encodeSection(bytes) {
  return Buffer.concat([Buffer.from(hexLength(bytes.byteLength), "ascii"), bytes]);
}

export function encodeOpenAiTerraReviewSubject({ manifest, sections }) {
  const gitSections = sections?.filter(({ descriptor }) => descriptor?.kind === "GIT_BLOB") ?? [];
  const promptSections = sections?.filter(({ descriptor }) => descriptor?.kind === "USER_AUTHORIZATION_PROMPT") ?? [];
  const bundleSections = sections?.filter(({ descriptor }) => descriptor?.kind === "PROVIDER_NEUTRAL_REVIEW_BUNDLE") ?? [];
  let reviewBundle = null;
  try {
    const bundleText = new TextDecoder("utf-8", { fatal: true }).decode(bundleSections[0].bytes);
    reviewBundle = JSON.parse(bundleText);
    if (bundleText !== openAiTerraDigests.canonicalize(reviewBundle)) reviewBundle = null;
  } catch {
    reviewBundle = null;
  }
  const sourceSubjects = [...gitSections, ...promptSections]
    .map(({ descriptor }) => ({
      path: descriptor.path,
      gitMode: descriptor.gitMode,
      blobSha256: descriptor.sha256,
    }))
    .sort(({ path: left }, { path: right }) => left.localeCompare(right));
  if (manifest?.schemaVersion !== "openai-terra-scoped-review-subject.v1" ||
      manifest?.format !== "LENGTH_PREFIXED_UTF8_SECTIONS_V1" ||
      manifest?.claimBoundary !== "CORE_SUBJECT_ONLY_NOT_FULL_REPOSITORY_CLEARANCE" ||
      manifest?.duplicatePathPolicy !== "EACH_REVIEWED_GIT_PATH_EXACTLY_ONCE" ||
      manifest?.recursiveK3EvidencePolicy !== "REFERENCE_ONLY_NO_MODEL_VISIBLE_BYTES" ||
      !reviewBundle || !Array.isArray(reviewBundle.reviewedPaths) || reviewBundle.reviewedPaths.length === 0 ||
      new Set(reviewBundle.reviewedPaths).size !== reviewBundle.reviewedPaths.length ||
      reviewBundle.reviewedPaths.some((path) => !SAFE_PATH.test(path)) ||
      gitSections.length + promptSections.length !== reviewBundle.reviewedPaths.length ||
      promptSections.length !== 1 || bundleSections.length !== 1 ||
      openAiTerraDigests.canonicalize(sourceSubjects) !==
        openAiTerraDigests.canonicalize(reviewBundle.sourceSubjects) ||
      openAiTerraDigests.value(reviewBundle.reviewedPaths) !== reviewBundle.source.changedPathsDigest ||
      openAiTerraDigests.canonicalize(promptSections[0]?.descriptor) !==
        openAiTerraDigests.canonicalize(manifest?.authorizationPrompt) ||
      openAiTerraDigests.canonicalize(bundleSections[0]?.descriptor) !==
        openAiTerraDigests.canonicalize(manifest?.reviewBundle) ||
      manifest?.historyReferences?.some((entry) => entry.modelVisibleBytes !== false) ||
      openAiTerraDigests.value(manifest?.historyReferences) !== manifest?.historyReferenceSetSha256 ||
      new Set(sections.map(({ descriptor }) => descriptor.path)).size !== sections.length) {
    throw new TypeError("OpenAI Terra Review Subject coverage closure is invalid.");
  }
  for (const { descriptor, bytes } of sections) {
    if (!(bytes instanceof Uint8Array) || descriptor.byteLength !== bytes.byteLength ||
        descriptor.sha256 !== openAiTerraDigests.bytes(bytes)) {
      throw new TypeError("OpenAI Terra Review Subject bytes are stale.");
    }
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }
  const manifestBytes = Buffer.from(openAiTerraDigests.canonicalize(manifest), "utf8");
  const byPath = new Map(sections.map((entry) => [entry.descriptor.path, entry]));
  const orderedSections = [
    byPath.get(manifest.reviewBundle.path),
    ...reviewBundle.sourceSubjects.map(({ path }) => byPath.get(path)),
  ];
  if (orderedSections.some((entry) => !entry)) {
    throw new TypeError("OpenAI Terra Review Subject ordered coverage is incomplete.");
  }
  const encodedSections = orderedSections.map(({ bytes }) => encodeSection(bytes));
  const bytes = Buffer.concat([
    MAGIC,
    Buffer.from(`${hexLength(manifestBytes.byteLength)}\n`, "ascii"),
    manifestBytes,
    ...encodedSections,
  ]);
  if (bytes.byteLength > OPENAI_TERRA_MAX_MODEL_VISIBLE_BYTES) {
    throw new TypeError("OPENAI_TERRA_REVIEW_SCOPE_OR_CONTEXT_NOT_PROVED");
  }
  return { bytes, manifest, subjectSha256: openAiTerraDigests.bytes(bytes) };
}

export async function buildOpenAiTerraReviewSubjectFromGit(input) {
  const repoPath = resolve(input.repoPath);
  for (const [label, value] of [["coverageBase", input.coverageBase], ["coreFreezeCommit", input.coreFreezeCommit], ["sourceCommit", input.sourceCommit], ["sourceParent", input.sourceParent]]) {
    await requireCommit(repoPath, value, label);
  }
  const { stdout: actualParent } = await git(repoPath, ["rev-parse", `${input.sourceCommit}^`], "utf8");
  const { stdout: sourceTreeText } = await git(repoPath, ["rev-parse", `${input.sourceCommit}^{tree}`], "utf8");
  if (actualParent.trim() !== input.sourceParent) throw new TypeError("Source parent binding is stale.");
  for (const ancestor of [input.coverageBase, input.coreFreezeCommit]) {
    try { await git(repoPath, ["merge-base", "--is-ancestor", ancestor, input.sourceCommit]); }
    catch { throw new TypeError("Review coverage commit is not an ancestor of sourceCommit."); }
  }
  const corePaths = await changedPaths(repoPath, input.coverageBase, input.coreFreezeCommit);
  if (openAiTerraDigests.canonicalize(corePaths) !== openAiTerraDigests.canonicalize(OPENAI_TERRA_CORE_REVIEW_PATHS)) {
    throw new TypeError("The frozen 22-path core scope drifted.");
  }
  const reviewedPaths = [...new Set([...OPENAI_TERRA_CORE_REVIEW_PATHS, ...OPENAI_TERRA_ADDITIONAL_REVIEW_PATHS])].sort();
  const allRecords = [];
  for (const path of reviewedPaths) allRecords.push(await blobRecord(repoPath, input.sourceCommit, path));
  const configRecord = allRecords.find(({ descriptor }) =>
    descriptor.path === "implementation/governance/independent-review/openai-codex-terra.v1.json");
  let config = null;
  try {
    config = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(configRecord?.bytes));
  } catch {
    config = null;
  }
  if (!config || !validateOpenAiTerraConfig(config).ok) {
    throw new TypeError("Frozen OpenAI Terra Config is invalid.");
  }
  const promptRecord = allRecords.find(({ descriptor }) =>
    descriptor.path === config.authorizationPrompt.path);
  if (!promptRecord || promptRecord.bytes.byteLength !== config.authorizationPrompt.byteLength ||
      openAiTerraDigests.bytes(promptRecord.bytes) !== config.authorizationPrompt.sha256) {
    throw new TypeError("Authorization Prompt bytes do not match the frozen digest.");
  }
  new TextDecoder("utf-8", { fatal: true }).decode(promptRecord.bytes);
  const authorizationDescriptor = {
    kind: "USER_AUTHORIZATION_PROMPT",
    path: config.authorizationPrompt.path,
    gitMode: promptRecord.descriptor.gitMode,
    byteLength: promptRecord.bytes.byteLength,
    sha256: config.authorizationPrompt.sha256,
  };
  const records = allRecords.filter(({ descriptor }) =>
    descriptor.path !== config.authorizationPrompt.path);
  const historyReferences = [];
  const { stdout: patchBytes } = await git(repoPath, ["diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", input.coverageBase, input.sourceCommit, "--"]);
  const completeBundle = await buildIndependentReviewBundleFromGit({
    repoPath,
    baseCommit: input.coverageBase,
    sourceCommit: input.sourceCommit,
    generatedAt: input.generatedAt,
    bundleId: input.bundleId,
    applicablePhase: "P2",
    testEvidenceRoot: input.testEvidenceRoot,
  });
  const reviewBundle = structuredClone(completeBundle);
  reviewBundle.reviewedPaths = reviewedPaths;
  reviewBundle.sourceSubjects = allRecords.map(({ descriptor }) => ({
    path: descriptor.path,
    gitMode: descriptor.gitMode,
    blobSha256: descriptor.sha256,
  }));
  reviewBundle.source.changedPathsDigest = openAiTerraDigests.value(reviewedPaths);
  reviewBundle.bundleSha256 = openAiTerraDigests.self(reviewBundle, "bundleSha256");
  const policyRecord = allRecords.find(({ descriptor }) =>
    descriptor.path === "implementation/governance/independent-review/independent-review-policy.v2.candidate.json");
  let policy = null;
  try { policy = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(policyRecord?.bytes)); }
  catch { policy = null; }
  if (reviewBundle.sourceSubjects.length !== reviewedPaths.length || !policy ||
      !(await validateIndependentReviewPolicy(policy)).ok ||
      !(await validateIndependentReviewBundle(reviewBundle, { policy })).ok) {
    throw new TypeError("Projected provider-neutral Review Bundle is invalid.");
  }
  const reviewBundleBytes = Buffer.from(openAiTerraDigests.canonicalize(reviewBundle), "utf8");
  const reviewBundleDescriptor = {
    kind: "PROVIDER_NEUTRAL_REVIEW_BUNDLE",
    path: "bundle/review-bundle.v2.json",
    gitMode: null,
    byteLength: reviewBundleBytes.byteLength,
    sha256: openAiTerraDigests.bytes(reviewBundleBytes),
    bundleId: reviewBundle.bundleId,
    bundleSha256: reviewBundle.bundleSha256,
  };
  const manifest = {
    schemaVersion: "openai-terra-scoped-review-subject.v1",
    format: "LENGTH_PREFIXED_UTF8_SECTIONS_V1",
    claimBoundary: "CORE_SUBJECT_ONLY_NOT_FULL_REPOSITORY_CLEARANCE",
    source: {
      coverageBase: input.coverageBase,
      coreFreezeCommit: input.coreFreezeCommit,
      sourceCommit: input.sourceCommit,
      sourceParent: input.sourceParent,
      sourceTree: sourceTreeText.trim(),
      fullPatchByteLength: Buffer.from(patchBytes).byteLength,
      fullPatchSha256: openAiTerraDigests.bytes(Buffer.from(patchBytes)),
    },
    authorizationPrompt: authorizationDescriptor,
    reviewBundle: reviewBundleDescriptor,
    historyReferences,
    historyReferenceSetSha256: openAiTerraDigests.value(historyReferences),
    duplicatePathPolicy: "EACH_REVIEWED_GIT_PATH_EXACTLY_ONCE",
    recursiveK3EvidencePolicy: "REFERENCE_ONLY_NO_MODEL_VISIBLE_BYTES",
  };
  return encodeOpenAiTerraReviewSubject({
    manifest,
    sections: [
      ...records,
      { descriptor: authorizationDescriptor, bytes: promptRecord.bytes },
      { descriptor: reviewBundleDescriptor, bytes: reviewBundleBytes },
    ],
  });
}

export function parseOpenAiTerraReviewSubject(bytes) {
  const parsed = parseOpenAiTerraReviewSubjectEnvelope(bytes);
  return {
    manifest: parsed.manifest,
    reviewBundle: parsed.reviewBundle,
    sections: parsed.sections.map(({ descriptor, bytes: content }) => ({
      ...descriptor,
      bytes: content,
    })),
  };
}
