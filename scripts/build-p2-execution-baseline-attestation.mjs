#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import {
  p2AcceptanceDigests,
} from "../lib/p2-acceptance-receipt-validator.mjs";
import { canonicalizeProjectJson } from "../lib/project-control.mjs";

const execFileAsync = promisify(execFile);
const TRUSTED_GIT_EXECUTABLE = "/usr/bin/git";
const CANONICAL_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_OBJECT_ID = /^[a-f0-9]{40}$/;
const RECIPE_PATH =
  "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json";

const FROZEN_BASELINE = Object.freeze({
  sourceCommit: "bc718bc1a069deaa388b9a00e0135c8e9427dd91",
  sourceTree: "2fa1d5a511215a78ce324b61c585a4d4bb9697e0",
  executionBaselineDigest:
    "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec",
  recipeSha256:
    "sha256:fa35085d2d18131920d932b3321fd77bc370c1d44cfb927feb91c34604c0c89e",
  subjects: Object.freeze([
    Object.freeze({
      kind: "PROFILE",
      name: "p2-acceptance-profile-v2",
      path:
        "implementation/p2/acceptance/p2-acceptance-profile.v2.json",
      version: "p2-acceptance-profile.v2",
      sha256:
        "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5",
    }),
    Object.freeze({
      kind: "SCHEMA",
      name: "p2-acceptance-receipt-v2-schema",
      path:
        "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
      version: "p2-acceptance-receipt.v2",
      sha256:
        "sha256:f995310688c620b24c42b058fb6305b00876e0dfa0b8a755f41f827bfcb700bf",
    }),
    Object.freeze({
      kind: "VALIDATOR",
      name: "p2-acceptance-receipt-semantic-validator",
      path: "lib/p2-acceptance-receipt-validator.mjs",
      version: "p2-acceptance-validator.v2",
      sha256:
        "sha256:ff8da36988ace70213e58368b8b3894677e732e0c0e262f87ba8824fac6347a7",
    }),
    Object.freeze({
      kind: "FIXTURE",
      name: "c06-synthetic-authorization-fixtures",
      path:
        "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
      version: "c06-authorization-fixtures-v1",
      sha256:
        "sha256:2c46d1c46eafaf5aebbfe7382cd16a9138a1c2cf142ca581ae101b254ebda130",
    }),
    Object.freeze({
      kind: "TOOL_LOCK",
      name: "npm-package-lock",
      path: "package-lock.json",
      version: "3",
      sha256:
        "sha256:8a7e27bd052d9f6fa1371cc23c153ca40a5a6299a31bdc321169b4ebf68abdcf",
    }),
  ]),
});
export const P2_BUILD_ATTESTATION_BASELINE = FROZEN_BASELINE;

function fail(message) {
  throw new Error(message);
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function validCanonicalInstant(value) {
  const milliseconds = Date.parse(value);
  return (
    CANONICAL_INSTANT.test(value ?? "") &&
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object.`);
  }
  if (
    canonicalizeProjectJson(Object.keys(value).sort()) !==
    canonicalizeProjectJson([...expected].sort())
  ) {
    fail(`${label} contains missing or unknown fields.`);
  }
}

function controlledGitEnvironment() {
  const environment = {};
  for (const key of ["SYSTEMROOT", "TEMP", "TMP", "TMPDIR"]) {
    if (typeof process.env[key] === "string") {
      environment[key] = process.env[key];
    }
  }
  return {
    ...environment,
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_COUNT: "0",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_DISCOVERY_ACROSS_FILESYSTEM: "0",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    LC_ALL: "C",
  };
}

function safeGitPath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.split("/").includes("..") &&
    !value.split("/").includes(".")
  );
}

function createLocalGitReader(repositoryPath) {
  if (typeof repositoryPath !== "string" || !repositoryPath) {
    fail("repositoryPath is required.");
  }
  const environment = controlledGitEnvironment();

  async function run(args, encoding = "utf8") {
    return execFileAsync(
      TRUSTED_GIT_EXECUTABLE,
      ["--no-replace-objects", ...args],
      {
        cwd: repositoryPath,
        encoding,
        env: environment,
        maxBuffer: 16 * 1024 * 1024,
      },
    );
  }

  return Object.freeze({
    async objectType(objectId) {
      if (!GIT_OBJECT_ID.test(objectId ?? "")) return null;
      try {
        const { stdout } = await run(["cat-file", "-t", objectId]);
        return stdout.trim();
      } catch {
        return null;
      }
    },
    async sourceTree(commit) {
      const { stdout } = await run(["show", "-s", "--format=%T", commit]);
      return stdout.trim();
    },
    async commitTime(commit) {
      const { stdout } = await run(["show", "-s", "--format=%cI", commit]);
      const value = stdout.trim();
      if (!Number.isFinite(Date.parse(value))) {
        fail("source commit time is invalid.");
      }
      return value;
    },
    async readBlob(commit, path) {
      if (!GIT_OBJECT_ID.test(commit ?? "") || !safeGitPath(path)) {
        fail("Git blob reference is invalid.");
      }
      const { stdout } = await run(
        ["cat-file", "blob", `${commit}:${path}`],
        null,
      );
      return Buffer.from(stdout);
    },
  });
}

function expectedRecipeFromBaseline(baseline) {
  const [profile, receiptSchema, validator, fixture, toolLock] =
    baseline.subjects;
  return {
    schemaVersion: "p2-execution-baseline-recipe.v1",
    acceptanceProfile: {
      path: profile.path,
      sha256: profile.sha256,
    },
    receiptSchema: {
      path: receiptSchema.path,
      version: receiptSchema.version,
      sha256: receiptSchema.sha256,
    },
    semanticValidator: {
      path: validator.path,
      version: validator.version,
      sha256: validator.sha256,
    },
    fixtures: [
      {
        name: fixture.name,
        path: fixture.path,
        sha256: fixture.sha256,
      },
    ],
    toolLocks: [
      {
        name: toolLock.name,
        path: toolLock.path,
        version: toolLock.version,
        sha256: toolLock.sha256,
      },
    ],
  };
}

function baselineDescriptor(sourceCommit, recipe) {
  return {
    schemaVersion: "p2-execution-baseline.v1",
    sourceCommit,
    acceptanceProfile: structuredClone(recipe.acceptanceProfile),
    receiptSchema: structuredClone(recipe.receiptSchema),
    semanticValidator: structuredClone(recipe.semanticValidator),
    fixtures: structuredClone(recipe.fixtures),
    toolLocks: recipe.toolLocks.map(({ name, sha256, version }) => ({
      name,
      version,
      digest: sha256,
    })),
  };
}

async function buildAttestation({
  baseline,
  generatedAt,
  git,
}) {
  if (
    !validCanonicalInstant(generatedAt)
  ) {
    fail("generatedAt must be an explicit canonical UTC instant.");
  }
  if (
    !GIT_OBJECT_ID.test(baseline.sourceCommit ?? "") ||
    !GIT_OBJECT_ID.test(baseline.sourceTree ?? "") ||
    !SHA256.test(baseline.executionBaselineDigest ?? "") ||
    !SHA256.test(baseline.recipeSha256 ?? "")
  ) {
    fail("Frozen baseline identifiers are invalid.");
  }
  if ((await git.objectType(baseline.sourceCommit)) !== "commit") {
    fail("sourceCommit must exist as a commit object.");
  }
  if ((await git.sourceTree(baseline.sourceCommit)) !== baseline.sourceTree) {
    fail("sourceTree does not match sourceCommit.");
  }
  const commitTime = await git.commitTime(baseline.sourceCommit);
  if (Date.parse(generatedAt) < Date.parse(commitTime)) {
    fail("generatedAt cannot precede the verified source commit.");
  }

  let recipeBytes;
  try {
    recipeBytes = await git.readBlob(
      baseline.sourceCommit,
      RECIPE_PATH,
    );
  } catch {
    fail("Recipe is absent from sourceCommit.");
  }
  if (sha256Bytes(recipeBytes) !== baseline.recipeSha256) {
    fail("Recipe bytes do not match the frozen digest.");
  }
  const recipe = JSON.parse(recipeBytes.toString("utf8"));
  exactKeys(
    recipe,
    [
      "acceptanceProfile",
      "fixtures",
      "receiptSchema",
      "schemaVersion",
      "semanticValidator",
      "toolLocks",
    ],
    "Recipe",
  );
  if (
    canonicalizeProjectJson(recipe) !==
    canonicalizeProjectJson(expectedRecipeFromBaseline(baseline))
  ) {
    fail("Recipe does not name the fixed subjects.");
  }

  const subjectBytes = await Promise.all(
    baseline.subjects.map(async (subject) => {
      try {
        return {
          bytes: await git.readBlob(
            baseline.sourceCommit,
            subject.path,
          ),
          subject,
        };
      } catch {
        fail("A subject is absent from sourceCommit.");
      }
    }),
  );
  if (
    subjectBytes.some(
      ({ bytes, subject }) => sha256Bytes(bytes) !== subject.sha256,
    )
  ) {
    fail("A subject does not match its frozen digest.");
  }

  const profile = JSON.parse(subjectBytes[0].bytes.toString("utf8"));
  if (
    profile?.schemaVersion !== baseline.subjects[0].version ||
    !validCanonicalInstant(profile?.recordedAt) ||
    Date.parse(profile.recordedAt) > Date.parse(commitTime)
  ) {
    fail("Profile recordedAt is not bound before sourceCommit.");
  }
  const computedDigest = p2AcceptanceDigests.executionBaseline(
    baselineDescriptor(baseline.sourceCommit, recipe),
  );
  if (computedDigest !== baseline.executionBaselineDigest) {
    fail("executionBaselineDigest does not match the Git subjects.");
  }

  return {
    schemaVersion: "p2-execution-baseline-attestation.v1",
    attestationId: `p2eba_${baseline.sourceCommit.slice(0, 12)}_${
      baseline.executionBaselineDigest.slice(7, 19)
    }`,
    predicateType:
      "urn:multi-enterprise-ai-platform:p2-execution-baseline-attestation:v1",
    canonicalization: "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785",
    source: {
      commit: baseline.sourceCommit,
      tree: baseline.sourceTree,
      objectType: "commit",
    },
    executionBaseline: {
      recipePath: RECIPE_PATH,
      recipeSha256: baseline.recipeSha256,
      digest: baseline.executionBaselineDigest,
    },
    subjects: baseline.subjects.map((subject) => structuredClone(subject)),
    buildVerification: {
      method: "BUILD_TIME_LOCAL_GIT_OBJECT_READ",
      builderId:
        "multi-enterprise-ai-platform/p2-execution-baseline-attestation-builder",
      builderVersion: "1.0.0",
      result: "VERIFIED",
      verifiedAt: generatedAt,
    },
    generatedAt,
  };
}

export async function buildFrozenP2ExecutionBaselineAttestation({
  repositoryPath,
  generatedAt,
}) {
  return createP2ExecutionBaselineAttestationBuilder({
    repositoryPath,
    expectedBaseline: FROZEN_BASELINE,
  })({ generatedAt });
}

export function createP2ExecutionBaselineAttestationBuilder({
  repositoryPath,
  expectedBaseline,
}) {
  const baseline = structuredClone(expectedBaseline);
  const git = createLocalGitReader(repositoryPath);
  return async function build({ generatedAt }) {
    return buildAttestation({
      baseline,
      generatedAt,
      git,
    });
  };
}

function parseCommandLine(arguments_) {
  const options = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !["--generated-at", "--repository-path"].includes(name) ||
      value === undefined
    ) {
      fail("Only --generated-at and --repository-path are accepted.");
    }
    if (Object.hasOwn(options, name)) {
      fail(`${name} may be provided only once.`);
    }
    options[name] = value;
  }
  if (!options["--generated-at"]) {
    fail("--generated-at is required.");
  }
  if (!options["--repository-path"]) {
    fail("--repository-path is required.");
  }
  return {
    generatedAt: options["--generated-at"],
    repositoryPath: options["--repository-path"],
  };
}

async function runCommandLine() {
  const attestation =
    await buildFrozenP2ExecutionBaselineAttestation(
      parseCommandLine(process.argv.slice(2)),
    );
  process.stdout.write(`${JSON.stringify(attestation, null, 2)}\n`);
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  runCommandLine().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
