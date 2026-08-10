#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS,
  validateActiveIndependentReviewPolicy,
  validateTargetedRemediationModelReviewEvidence,
} from "../lib/independent-review-artifact-validation.mjs";
import {
  mapIndependentModelReviewCheckResult,
  parseIndependentReviewJsonBytes,
  validateIndependentModelReviewOutputArtifact,
} from "../lib/independent-model-review.mjs";

const EXPECTED_MODEL = "gpt-5.6-terra";
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
    path: "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
    sha256:
      "sha256:72c10b7e0399a2b7001a6453760210537d7a6bc4ae0acf42732c1a789364bbf0",
  }),
  prompt: Object.freeze({
    path: "implementation/governance/independent-review/github-required-check-prompt.v1.md",
    sha256:
      "sha256:2d6a9bcc76f592c3ed90f76efb24117a674b64e84e38fc75872526b5475ad497",
  }),
});
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
  "--requested-model",
  "--event-name",
]);

const sha256Bytes = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

function parseArguments(argv) {
  if (argv.length !== REQUIRED_ARGUMENTS.length * 2) {
    throw new TypeError("Independent model review check arguments are incomplete.");
  }
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      !REQUIRED_ARGUMENTS.includes(name) ||
      typeof value !== "string" ||
      value.length === 0 ||
      values.has(name)
    ) {
      throw new TypeError("Independent model review check arguments are invalid.");
    }
    values.set(name, value);
  }
  return Object.fromEntries(REQUIRED_ARGUMENTS.map((name) => [name, values.get(name)]));
}

function gitObject(repository, expression) {
  return execFileSync(
    "git",
    ["-C", repository, "rev-parse", "--verify", expression],
    {
      encoding: "utf8",
      env: {
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_CONFIG_NOSYSTEM: "1",
        PATH: process.env.PATH,
      },
      maxBuffer: 1024,
      stdio: ["ignore", "pipe", "ignore"],
    },
  ).trim();
}

async function readFixedArtifact(repository, artifact, reasonCodes) {
  const bytes = await readFile(resolve(repository, artifact.path));
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
  requestedModel,
  eventName,
}) {
  const reasonCodes = [];
  const repositoryPath = resolve(repository);
  const outputPath = resolve(outputFile);
  const outputRelativePath = relative(repositoryPath, outputPath);
  if (
    outputRelativePath === "" ||
    (!outputRelativePath.startsWith("..") && !isAbsolute(outputRelativePath))
  ) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_OUTPUT_LOCATION_INVALID");
  }
  if (!SHA1.test(expectedHead) || !SHA1.test(expectedTree)) {
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
  if (requestedModel !== EXPECTED_MODEL) {
    reasonCodes.push("INDEPENDENT_MODEL_REVIEW_MODEL_MISMATCH");
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
  try {
    [
      policyBytes,
      policySchemaBytes,
      evidenceBytes,
      evidenceSchemaBytes,
      outputSchemaBytes,
      outputBytes,
      promptBytes,
    ] = await Promise.all([
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.policy, reasonCodes),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.policySchema, reasonCodes),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.evidence, reasonCodes),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.evidenceSchema, reasonCodes),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.outputSchema, reasonCodes),
      readFile(outputPath),
      readFixedArtifact(repositoryPath, FIXED_ARTIFACTS.prompt, reasonCodes),
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
      rawModelOutput: outputBytes,
      outputSchemaBytes,
      expectedOutputSchemaSha256: FIXED_ARTIFACTS.outputSchema.sha256,
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

async function main() {
  let check;
  try {
    const args = parseArguments(process.argv.slice(2));
    check = await validateIndependentModelRequiredCheck({
      repository: args["--repository"],
      outputFile: args["--output-file"],
      expectedHead: args["--expected-head"],
      expectedTree: args["--expected-tree"],
      requestedModel: args["--requested-model"],
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
