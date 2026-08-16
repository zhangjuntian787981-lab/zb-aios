#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS,
  validateActiveIndependentReviewPolicy,
  validateTargetedRemediationModelReviewEvidence,
} from "../lib/independent-review-artifact-validation.mjs";
import {
  independentModelReviewDigests,
  mapIndependentModelReviewCheckResult,
  parseIndependentReviewJsonBytes,
  validateIndependentModelReviewOutputArtifact,
} from "../lib/independent-model-review.mjs";

const EXPECTED_PROVIDER = "ALIBABA_CLOUD_MODEL_STUDIO";
const EXPECTED_REGION = "CHINA_BEIJING";
const EXPECTED_BASE_URL =
  "https://ws-lkkcajn7d1l4okvo.cn-beijing.maas.aliyuncs.com/compatible-mode/v1";
const EXPECTED_MODEL = "qwen3.7-max-2026-05-20";
const EXPECTED_ASSURANCE = "PLATFORM_TCB_PROMPT_BOUND_MODEL_REVIEW";
const MAXIMUM_MATERIAL_BYTES = 96 * 1024;
const MAXIMUM_MODEL_OUTPUT_BYTES = 64 * 1024;
const SHA1 = /^[a-f0-9]{40}$/u;
const FIXED_ARTIFACTS = Object.freeze({
  policy: Object.freeze({
    path: "implementation/governance/independent-review/independent-review-policy.v2.json",
    sha256:
      "sha256:1bc70e243ccf1d3dc0d202a300469f0e169b40632712f12d0910573e03ccff8d",
  }),
  policySchema: Object.freeze({
    path: INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS.activePolicy.path,
    sha256: INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS.activePolicy.sha256,
  }),
  evidence: Object.freeze({
    path: "implementation/governance/independent-review/evidence/terra-targeted-remediation-ec8315c/targeted-remediation-model-review-evidence.v1.json",
    sha256:
      "sha256:710c3295b3863a3ad48bd21821e19156a1b318b83c1014629652bd7b1ddc2789",
  }),
  evidenceSchema: Object.freeze({
    path: INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS.targetedRemediationEvidence.path,
    sha256:
      INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS.targetedRemediationEvidence.sha256,
  }),
  outputSchema: Object.freeze({
    path: "implementation/governance/schemas/independent-model-review-output.v3.schema.json",
    sha256:
      "sha256:0acd5dc464efaaa428267a9c72d5be61b39416c8b1ce19c91619067cac3ceea6",
  }),
  prompt: Object.freeze({
    path: "implementation/governance/independent-review/github-required-check-prompt.v3.md",
    sha256:
      "sha256:7e9457d5f3fcee68f68fa633b178b51c5278ff2906baa7343ce489cc504b9771",
  }),
});
const MATERIAL_PATHS = Object.freeze([
  FIXED_ARTIFACTS.prompt.path,
  FIXED_ARTIFACTS.policy.path,
  FIXED_ARTIFACTS.evidence.path,
  FIXED_ARTIFACTS.outputSchema.path,
  ".github/workflows/independent-model-review.yml",
  "scripts/validate-independent-model-review-check.mjs",
  "tests/independent-model-required-check.cases.mjs",
  "docs/adr/0023-qwen-independent-model-required-check.md",
  "implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v1.json",
  "implementation/p1/c13/github/c13-protected-review-ruleset.candidate.v2.json",
  "implementation/p1/c13/p1-b11-protected-review-preparation-evidence.v1.json",
]);
const FORBIDDEN_CLAIMS = Object.freeze([
  "INDEPENDENT_HUMAN_REVIEW_COMPLETE",
  "P3_OR_PRODUCTION_RELEASE_APPROVED",
  "PROFILE_APPROVED",
  "D1_APPROVED",
  "O02_OR_O03_AUTHORIZED",
]);
const REQUIRED_ARGUMENTS = Object.freeze([
  "--repository",
  "--output-file",
  "--expected-head",
  "--expected-tree",
  "--expected-base",
  "--requested-provider",
  "--requested-region",
  "--base-url",
  "--requested-model",
  "--assurance-level",
  "--material-file",
  "--event-name",
]);
const BUILD_ARGUMENTS = Object.freeze([
  "--repository",
  "--expected-head",
  "--expected-tree",
  "--expected-base",
  "--material-file",
]);

const sha256Bytes = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

function parseArguments(requiredArguments, argv) {
  if (argv.length !== requiredArguments.length * 2) {
    throw new TypeError("Independent model review check arguments are incomplete.");
  }
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      !requiredArguments.includes(name) ||
      typeof value !== "string" ||
      value.length === 0 ||
      values.has(name)
    ) {
      throw new TypeError("Independent model review check arguments are invalid.");
    }
    values.set(name, value);
  }
  return Object.fromEntries(
    requiredArguments.map((name) => [name, values.get(name)]),
  );
}

function gitObject(repository, expression) {
  return gitText(repository, ["rev-parse", "--verify", expression], 1024);
}

function gitBytes(repository, args, maximumBytes = MAXIMUM_MATERIAL_BYTES) {
  return execFileSync("/usr/bin/git", ["--no-replace-objects", "-C", repository, ...args], {
    encoding: "buffer",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      PATH: "/usr/bin:/bin",
    },
    maxBuffer: maximumBytes,
    stdio: ["ignore", "pipe", "ignore"],
  });
}

function materialBindingSummary({
  expectedHead,
  expectedTree,
  materialSha256,
}) {
  return [
    `head=${expectedHead}`,
    `tree=${expectedTree}`,
    `model=${EXPECTED_MODEL}`,
    `policySha256=${FIXED_ARTIFACTS.policy.sha256}`,
    `evidenceSha256=${FIXED_ARTIFACTS.evidence.sha256}`,
    `materialSha256=${materialSha256}`,
    `assuranceLevel=${EXPECTED_ASSURANCE}`,
    "toolCalls=0",
  ].join(";");
}

const REQUIRED_CHECK_CONTRACT_PATH =
  "docs/adr/0028-required-check-authoritative-output-contract.md";
const REQUIRED_CHECK_CONTRACT_SHA256 =
  "sha256:6f885730b8adf3a1a7bccaecb0156345db5cad396c1bbd0cf3fd552869e0d511";
export const containsSelfReference = (bytes, ...values) =>
  values.some((value) => bytes.includes(Buffer.from(value)));
export { adaptQwenSummaryTransport };
function failRequiredCheck(reason) {
  throw new TypeError(`INDEPENDENT_MODEL_REVIEW_${reason}`);
}
function gitText(repository, args, maximumBytes = 1 << 22) {
  return gitBytes(repository, args, maximumBytes).toString("utf8").trim();
}
export async function buildPromptBoundReviewMaterial({
  repository,
  expectedHead,
  expectedTree,
  expectedBase,
}) {
  const { buildEnvelope } = await import("../lib/independent-model-review.mjs");
  const {
    buildFindingCoverageIndex,
    envelopeSchemaMatches,
    prepareRequiredCheckEnvelopeInputs,
  } = await import("./run-independent-review-test-evidence.mjs");
  const prepared = await prepareRequiredCheckEnvelopeInputs({
    repository: resolve(repository),
    expectedHead,
    expectedTree,
    expectedBase,
    materialPaths: MATERIAL_PATHS,
    contractPath: REQUIRED_CHECK_CONTRACT_PATH,
    contractSha256: REQUIRED_CHECK_CONTRACT_SHA256,
  });
  const {
    contract: materialContract,
    reviewBinding,
    lineage,
    testWhitelist,
    commandSummaries,
    staticInputs,
    evidenceFiles,
    digestSubjects,
    findingDigestSubjects,
    fullFiles,
    patches,
    fullFileByteLength,
    patchByteLength,
  } = prepared;
  const { envelope, envelopeBytes } = await buildEnvelope({
    contract: materialContract,
    reviewBinding,
    lineage,
    testWhitelist,
    commands: commandSummaries,
    inputs: staticInputs,
    evidence: evidenceFiles,
    subjects: digestSubjects,
    fullFiles,
    patches,
  });
  const findingSubjects = buildFindingCoverageIndex({
    generatedEnvelopePath: materialContract.generatedEnvelopePath,
    envelopeSha256: envelope.envelopeSha256,
    fullFiles,
    patches,
    digestSubjects: findingDigestSubjects,
  });
  if (envelopeBytes.length > materialContract.caps.envelope) {
    failRequiredCheck("ENVELOPE_BUDGET_EXCEEDED");
  }
  const envelopeSchema = fullFiles[2];
  if (!(await envelopeSchemaMatches({
    envelope,
    schema: envelopeSchema,
    expectedSha256: materialContract.envelopeSchemaSha,
  }))) failRequiredCheck("ENVELOPE_SCHEMA_MISMATCH");
  const manifest = {
    schemaVersion: "prompt-bound-independent-model-review-material.v2",
    assuranceLevel: EXPECTED_ASSURANCE,
    provider: EXPECTED_PROVIDER,
    region: EXPECTED_REGION,
    requestedModel: EXPECTED_MODEL,
    baseCommit: expectedBase,
    sourceCommit: expectedHead,
    sourceTree: expectedTree,
    implementationCommit: reviewBinding.implementationCommit,
    implementationTree: reviewBinding.implementationTree,
    coverageMode: materialContract.mode,
    envelopeSha256: envelope.envelopeSha256,
    artifacts: fullFiles.map((entry) => ({
      path: entry.path,
      gitMode: entry.gitMode,
      byteLength: entry.byteLength,
      sha256: entry.rawSha256,
    })),
  };
  const chunks = [
    Buffer.from(`${JSON.stringify(manifest)}\n`, "utf8"),
    Buffer.from("\n<<<BEGIN:DYNAMIC_MATERIAL_ENVELOPE>>>\n", "utf8"),
    envelopeBytes,
    Buffer.from("\n<<<END:DYNAMIC_MATERIAL_ENVELOPE>>>\n", "utf8"),
    ...fullFiles.flatMap((entry) => [
      Buffer.from(`\n<<<BEGIN:${entry.path}>>>\n`, "utf8"),
      entry.bytes,
      Buffer.from(`\n<<<END:${entry.path}>>>\n`, "utf8"),
    ]),
    ...patches.flatMap((entry) => [
      Buffer.from(`\n<<<BEGIN_GIT_PATCH:${entry.path}>>>\n`, "utf8"),
      entry.bytes,
      Buffer.from(`\n<<<END_GIT_PATCH:${entry.path}>>>\n`, "utf8"),
    ]),
  ];
  const unboundBytes = Buffer.concat(chunks);
  const materialSha256 = sha256Bytes(unboundBytes);
  const bindingSummary = `${materialBindingSummary({
    expectedHead,
    expectedTree,
    materialSha256,
  })};envelopeSha256=${envelope.envelopeSha256};coverageMode=${materialContract.mode};${materialContract.claims[3][1]}`;
  const reviewBindingContract = {
    sourceCommit: reviewBinding.finalHead,
    sourceTree: reviewBinding.finalTree,
    materialSha256,
    envelopeSha256: envelope.envelopeSha256,
  };
  const coverageContract = {
    coverageMode: materialContract.mode,
    verbatimFullFileManifestSha256:
      envelope.verbatimCoverage.fullFileManifestSha256,
    verbatimPatchManifestSha256:
      envelope.verbatimCoverage.patchManifestSha256,
    digestOnlyManifestSha256: envelope.digestOnlyCoverage.manifestSha256,
    digestOnlyNotByteReviewed: true,
  };
  const authoritativePrompt = fullFiles.find(
    ({ path }) => path === FIXED_ARTIFACTS.prompt.path,
  );
  const authoritativeOutputSchema = fullFiles.find(
    ({ path }) => path === FIXED_ARTIFACTS.outputSchema.path,
  );
  if (!authoritativePrompt || !authoritativeOutputSchema) {
    failRequiredCheck("SUBJECT_SET_INVALID");
  }
  const replacements = new Map([
    ["{promptPath}", authoritativePrompt.path],
    ["{promptSha256}", authoritativePrompt.rawSha256],
    ["{outputSchemaPath}", authoritativeOutputSchema.path],
    ["{outputSchemaSha256}", authoritativeOutputSchema.rawSha256],
    ["{reviewBindingJson}", independentModelReviewDigests.canonicalize(reviewBindingContract)],
    ["{coverageJson}", independentModelReviewDigests.canonicalize(coverageContract)],
    ["{binding}", bindingSummary],
  ]);
  const renderFraming = (line) => {
    let rendered = line;
    for (const [placeholder, value] of replacements) {
      rendered = rendered.replaceAll(placeholder, value);
    }
    return rendered;
  };
  const terminalOutputContract = Buffer.from(
    materialContract.framing.terminal.map(renderFraming).join("\n"),
    "utf8",
  );
  const bytes = Buffer.concat([
    Buffer.from(
      `${materialContract.framing.prefix.map(renderFraming).join("\n")}\n`,
      "utf8",
    ),
    unboundBytes,
    terminalOutputContract,
  ]);
  const wrapperByteLength=bytes.length-envelopeBytes.length-fullFileByteLength-patchByteLength;
  if(bytes.length>materialContract.caps.material||MAXIMUM_MATERIAL_BYTES-bytes.length<materialContract.caps.reserve||
    wrapperByteLength>materialContract.caps.wrapper)failRequiredCheck("MATERIAL_TOO_LARGE");
  const requiredCheckContract={reviewSummaryPrefix:bindingSummary,
    reviewBinding:reviewBindingContract,coverage:coverageContract,
    findingSubjects,overclaimPattern:materialContract.overclaimPattern};
  return {
    bytes,
    byteLength: bytes.byteLength,
    materialSha256,
    bindingSummary,
    coverageMode:materialContract.mode,
    envelope,
    envelopeBytes,
    envelopeByteLength:envelopeBytes.length,
    envelopeSha256:envelope.envelopeSha256,
    requiredCheckContract,
  };
}

async function buildMaterialFromArguments(args) {
  const material = await buildPromptBoundReviewMaterial({
    repository: args["--repository"],
    expectedHead: args["--expected-head"],
    expectedTree: args["--expected-tree"],
    expectedBase: args["--expected-base"],
  });
  await writeFile(resolve(args["--material-file"]), material.bytes, {
    mode: 0o600,
  });
  return material;
}

async function readFixedArtifact(repository, artifact, reasonCodes) {
  const bytes = gitBytes(repository, ["show", `HEAD:${artifact.path}`]);
  if (sha256Bytes(bytes) !== artifact.sha256) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_FIXED_ARTIFACT_MISMATCH");
  }
  return bytes;
}

function containsForbiddenClaim(output) {
  const rendered = JSON.stringify(output);
  return (
    FORBIDDEN_CLAIMS.some((claim) => rendered.includes(claim)) ||
    /humanIndependentReviewSatisfied\s*[:=]\s*true/iu.test(rendered)
  );
}

function failedCheck(status, reasonCodes) {
  return mapIndependentModelReviewCheckResult({
    ok: false,
    status,
    conclusion: status,
    reasonCodes: [...new Set(reasonCodes)],
  });
}

export async function validateIndependentModelRequiredCheck({
  repository,
  outputFile,
  expectedHead,
  expectedTree,
  expectedBase,
  requestedProvider,
  requestedRegion,
  baseUrl,
  requestedModel,
  assuranceLevel,
  materialFile,
  eventName,
}) {
  const reasonCodes = [];
  const repositoryPath = resolve(repository);
  const outputPath = resolve(outputFile);
  const materialPath = resolve(materialFile);
  const outputRelativePath = relative(repositoryPath, outputPath);
  const materialRelativePath = relative(repositoryPath, materialPath);
  if (
    outputRelativePath === "" ||
    (!outputRelativePath.startsWith("..") && !isAbsolute(outputRelativePath))
  ) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_OUTPUT_LOCATION_INVALID");
  }
  if (
    materialRelativePath === "" ||
    (!materialRelativePath.startsWith("..") &&
      !isAbsolute(materialRelativePath))
  ) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_MATERIAL_LOCATION_INVALID");
  }
  if (
    !SHA1.test(expectedHead) ||
    !SHA1.test(expectedTree) ||
    !SHA1.test(expectedBase)
  ) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_GIT_BINDING_INVALID");
  } else {
    try {
      if (
        gitObject(repositoryPath, "HEAD") !== expectedHead ||
        gitObject(repositoryPath, "HEAD^{tree}") !== expectedTree
      ) {
        reasonCodes.push("INDEPENDENT_MODEL_REVIEW_GIT_BINDING_MISMATCH");
      }
    } catch {
      reasonCodes.push("INDEPENDENT_MODEL_REVIEW_GIT_BINDING_INVALID");
    }
  }
  if (requestedProvider !== EXPECTED_PROVIDER) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_PROVIDER_MISMATCH");
  }
  if (requestedRegion !== EXPECTED_REGION) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_REGION_MISMATCH");
  }
  if (baseUrl !== EXPECTED_BASE_URL) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_ENDPOINT_MISMATCH");
  }
  if (requestedModel !== EXPECTED_MODEL) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_MODEL_MISMATCH");
  }
  if (assuranceLevel !== EXPECTED_ASSURANCE) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_ASSURANCE_MISMATCH");
  }
  if (!["pull_request", "merge_group"].includes(eventName)) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_EVENT_INVALID");
  }

  let policyBytes;
  let policySchemaBytes;
  let evidenceBytes;
  let evidenceSchemaBytes;
  let outputSchemaBytes;
  let outputBytes;
  let promptBytes;
  let materialBytes;
  try {
    [
      policyBytes,
      policySchemaBytes,
      evidenceBytes,
      evidenceSchemaBytes,
      outputSchemaBytes,
      outputBytes,
      promptBytes,
      materialBytes,
    ] = await Promise.all([
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.policy, reasonCodes),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.policySchema, reasonCodes),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.evidence, reasonCodes),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.evidenceSchema, reasonCodes),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.outputSchema, reasonCodes),
      readFile(outputPath),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.prompt, reasonCodes),
      readFile(materialPath),
    ]);
  } catch {
    return failedCheck("INCONCLUSIVE", [
      ...reasonCodes,
      "INDEPENDENT_MODEL_REVIEW_INPUT_INCOMPLETE",
    ]);
  }

  let policy;
  let evidence;
  try {
    policy = parseIndependentReviewJsonBytes(policyBytes, "Active Policy v2");
    evidence = parseIndependentReviewJsonBytes(
      evidenceBytes,
      "Targeted remediation Review Evidence",
    );
  } catch {
    return failedCheck("BLOCKED", [
      ...reasonCodes,
      "INDEPENDENT_MODEL_REVIEW_FIXED_ARTIFACT_INVALID",
    ]);
  }
  void promptBytes;
  const real=(await import("node:fs/promises")).realpath,root=await real(repositoryPath);
  for(const [path,reason] of [[outputPath,"OUTPUT"],[materialPath,"MATERIAL"]]){
    const name=relative(root,await real(path));
    if(name===""||(!name.startsWith("..")&&!isAbsolute(name)))reasonCodes.push(`INDEPENDENT_MODEL_REVIEW_${reason}_LOCATION_INVALID`);
  }
  const validatorOutputBytes = adaptQwenSummaryTransport(outputBytes);
  let expectedMaterial;
  try {
    expectedMaterial = await buildPromptBoundReviewMaterial({
      repository: repositoryPath,
      expectedHead,
      expectedTree,
      expectedBase,
    });
    if (!Buffer.from(materialBytes).equals(expectedMaterial.bytes)) {
      reasonCodes.push("INDEPENDENT_MODEL_REVIEW_MATERIAL_BINDING_MISMATCH");
    }
  } catch {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_MATERIAL_BINDING_INVALID");
  }

  const [policyResult, evidenceResult, outputResult] = await Promise.all([
    validateActiveIndependentReviewPolicy({
      policy,
      schemaBytes: policySchemaBytes,
    }),
    validateTargetedRemediationModelReviewEvidence({
      evidence,
      schemaBytes: evidenceSchemaBytes,
    }),
    validateIndependentModelReviewOutputArtifact({
      rawModelOutput: validatorOutputBytes,
      outputSchemaBytes,
      expectedOutputSchemaSha256: FIXED_ARTIFACTS.outputSchema.sha256,
      expectedRequiredCheckContract:
        expectedMaterial?.requiredCheckContract ?? null,
    }),
  ]);
  if (!policyResult.ok || !evidenceResult.ok) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_VALIDATION_FAILED");
  }
  reasonCodes.push(...outputResult.reasonCodes);
  if (containsForbiddenClaim(outputResult.output)) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_SCOPE_OVERCLAIM");
  }
  if (outputResult.status !== "CLEAR") {
    return failedCheck(outputResult.status, reasonCodes);
  }
  if (reasonCodes.length > 0) {
    return failedCheck("BLOCKED", reasonCodes);
  }
  return mapIndependentModelReviewCheckResult({
    ok: outputResult.ok,
    status: outputResult.status,
    conclusion: outputResult.conclusion,
    reasonCodes: [],
  });
}

function adaptQwenSummaryTransport(outputBytes) {
  if (
    !(outputBytes instanceof Uint8Array) ||
    outputBytes.byteLength > MAXIMUM_MODEL_OUTPUT_BYTES ||
    (outputBytes.byteLength >= 3 &&
      outputBytes[0] === 0xef &&
      outputBytes[1] === 0xbb &&
      outputBytes[2] === 0xbf)
  ) {
    return outputBytes;
  }
  let output;
  try {
    output = new TextDecoder("utf-8", { fatal: true }).decode(outputBytes);
  } catch {
    return outputBytes;
  }
  const fenced = /^[\u0020\t\r\n]*```json[\t ]*\r?\n([\s\S]*?)\r?\n```[\t ]*[\u0020\t\r\n]*$/u.exec(output);
  if (fenced === null || !fenced[1].startsWith("{") || !fenced[1].endsWith("}")) {
    return outputBytes;
  }
  return Buffer.from(fenced[1], "utf8");
}

async function main() {
  if (process.argv[2] === "build-material") {
    try {
      const args = parseArguments(BUILD_ARGUMENTS, process.argv.slice(3));
      const material = await buildMaterialFromArguments(args);
      process.stdout.write(
        `${JSON.stringify({
          byteLength: material.byteLength,
          materialSha256: material.materialSha256,
          bindingSummary: material.bindingSummary,
        })}\n`,
      );
      return;
    } catch {
      process.exitCode = 3;
      return;
    }
  }
  let check;
  try {
    const args = parseArguments(REQUIRED_ARGUMENTS, process.argv.slice(2));
    check = await validateIndependentModelRequiredCheck({
      repository: args["--repository"],
      outputFile: args["--output-file"],
      expectedHead: args["--expected-head"],
      expectedTree: args["--expected-tree"],
      expectedBase: args["--expected-base"],
      requestedProvider: args["--requested-provider"],
      requestedRegion: args["--requested-region"],
      baseUrl: args["--base-url"],
      requestedModel: args["--requested-model"],
      assuranceLevel: args["--assurance-level"],
      materialFile: args["--material-file"],
      eventName: args["--event-name"],
    });
  } catch {
    check = failedCheck("INCONCLUSIVE", [
      "INDEPENDENT_MODEL_REVIEW_CHECK_VALIDATION_ERROR",
    ]);
  }
  process.stdout.write(`${JSON.stringify(check)}\n`);
  process.exitCode = check.exitCode;
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  await main();
}
