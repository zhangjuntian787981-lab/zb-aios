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
  validateIndependentReviewMaterial,
  validateMoonshotKimiConfig,
} from "../lib/kimi-independent-review.mjs";
import {
  independentModelReviewFixedSpecificationPaths,
  parseIndependentReviewJsonBytes,
  validateIndependentReviewBundle,
  validateIndependentReviewPolicy,
  validateIndependentReviewTestEvidenceClosure,
} from "../lib/independent-model-review.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/u;
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const FIXED_PATHS = Object.freeze({
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
const EXECUTING_PATHS = Object.freeze([
  "lib/independent-model-review.mjs",
  "lib/kimi-independent-review.mjs",
  "scripts/build-independent-review-material.mjs",
]);
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

async function verifyExecutingBytes(repoPath, sourceCommit) {
  for (const path of EXECUTING_PATHS) {
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

async function commitPathExists(repoPath, commit, path) {
  const { stdout } = await git(repoPath, [
    "ls-tree",
    "-z",
    commit,
    "--",
    path,
  ]);
  const bytes = Buffer.from(stdout);
  if (bytes.byteLength === 0) {
    return false;
  }
  const value = utf8Content(bytes, "Review Material tree entry");
  const match =
    /^(100644|100755|120000|160000) (blob|commit) [a-f0-9]{40}\t([^\0]+)\0$/u.exec(
      value,
    );
  if (!match || match[3] !== path) {
    throw new TypeError(
      `Review Material base tree entry is ambiguous: ${path}`,
    );
  }
  return true;
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
  await verifyExecutingBytes(repoPath, bundle.source.sourceCommit);
  const policyBytes = await commitBytes(
    repoPath,
    bundle.source.sourceCommit,
    FIXED_PATHS.policy,
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
    bundle.artifacts.testPlanPath !== FIXED_PATHS.testPlan ||
    bundle.artifacts.testEvidenceCollectorPath !==
      FIXED_PATHS.testEvidenceCollector ||
    bundle.artifacts.testResultSchemaPath !==
      FIXED_PATHS.testResultSchema ||
    bundle.artifacts.sandboxPolicyTemplatePath !==
      FIXED_PATHS.sandboxPolicyTemplate
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
    commitBytes(repoPath, bundle.source.sourceCommit, FIXED_PATHS.testPlan),
    commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      FIXED_PATHS.testEvidenceCollector,
    ),
    commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      FIXED_PATHS.testResultSchema,
    ),
    commitBytes(
      repoPath,
      bundle.source.sourceCommit,
      FIXED_PATHS.sandboxPolicyTemplate,
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

  const [promptBytes, outputSchemaBytes, receiptSchemaBytes, configBytes] =
    await Promise.all(
      [
        FIXED_PATHS.prompt,
        FIXED_PATHS.outputSchema,
        FIXED_PATHS.receiptSchema,
        FIXED_PATHS.config,
      ].map((path) => commitBytes(repoPath, bundle.source.sourceCommit, path)),
    );
  const config = parseIndependentReviewJsonBytes(
    configBytes,
    "Moonshot Kimi configuration",
    1024 * 1024,
  );
  const configValidation = await validateMoonshotKimiConfig(config);
  if (!configValidation.ok) {
    throw new TypeError("Frozen Moonshot Kimi configuration is invalid.");
  }

  const sectionEntries = [
    section(
      "REVIEW_BUNDLE",
      "artifacts/independent-review-bundle.v2.json",
      input.reviewBundleBytes,
    ),
  ];
  const governancePaths = new Set(FIXED_PATHS.governanceSubjects);
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
  for (const path of FIXED_PATHS.governanceSubjects) {
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
  const modelVisibleProtocolBytes =
    createKimiModelVisibleProtocolBytes(config);
  sectionEntries.push(
    section(
      "GOVERNANCE",
      "artifacts/moonshot-kimi-model-visible-protocol.v1.json",
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
  const reviewBundleSection = sectionEntries.find(
    (current) => current.descriptor.kind === "REVIEW_BUNDLE",
  );
  const material = {
    schemaVersion: "independent-review-material.v2",
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
      reviewerPrompt: byteBinding(FIXED_PATHS.prompt, promptBytes),
      canonicalOutputSchema: byteBinding(
        FIXED_PATHS.outputSchema,
        outputSchemaBytes,
      ),
      canonicalReceiptSchema: byteBinding(
        FIXED_PATHS.receiptSchema,
        receiptSchemaBytes,
      ),
      providerConfig: byteBinding(FIXED_PATHS.config, configBytes),
    },
    sections,
    sectionSetSha256:
      independentKimiReviewDigests.value(sections),
    totalSectionUtf8ByteLength,
    contextBudgetUtf8Bytes: config.maxReviewMaterialUtf8Bytes,
    materialSha256: `sha256:${"0".repeat(64)}`,
  };
  material.bindings.reviewBundle.bundleDigest = bundle.bundleSha256;
  material.materialSha256 =
    independentKimiReviewDigests.material(material);
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
