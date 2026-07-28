import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { posix as path } from "node:path";
import { promisify } from "node:util";
import { canonicalizeProjectJson } from "./project-control.mjs";

const execFileAsync = promisify(execFile);
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const CANONICAL_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const EVIDENCE_ID = /^p2e_[a-z0-9][a-z0-9_-]{7,127}$/;
const EXECUTION_BASELINE_RECIPE_PATH =
  "implementation/p2/acceptance/p2-execution-baseline-recipe.v1.json";
const TRUSTED_GIT_EXECUTABLE = "/usr/bin/git";
const EXECUTION_BASELINE_RECIPE_KEYS = [
  "acceptanceProfile",
  "fixtures",
  "receiptSchema",
  "schemaVersion",
  "semanticValidator",
  "toolLocks",
];
const EXECUTION_BASELINE_KEYS = [
  "acceptanceProfile",
  "fixtures",
  "receiptSchema",
  "schemaVersion",
  "semanticValidator",
  "sourceCommit",
  "toolLocks",
];
const FINAL_RELEASE_KEYS = [
  "artifactManifestDigest",
  "evidenceIndexDigest",
  "executionBaselineDigest",
];
const ARTIFACT_KINDS = new Set([
  "FIXTURE",
  "PROFILE",
  "RAW_EVIDENCE",
  "SCHEMA",
  "SOURCE",
  "TEST",
  "TOOL_LOCK",
  "VALIDATOR",
]);

function fail(message) {
  throw new Error(message);
}

function assertExactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object.`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (canonicalizeProjectJson(actual) !== canonicalizeProjectJson(wanted)) {
    fail(`${label} contains missing, unknown, or forbidden fields.`);
  }
}

function assertDigest(value, label) {
  if (!SHA256.test(value ?? "")) fail(`${label} must be a SHA-256 digest.`);
}

function assertSubject(subject, label, versionRequired = false) {
  const keys = versionRequired
    ? ["path", "sha256", "version"]
    : ["path", "sha256"];
  assertExactKeys(subject, keys, label);
  if (typeof subject.path !== "string" || !subject.path) {
    fail(`${label}.path is required.`);
  }
  assertDigest(subject.sha256, `${label}.sha256`);
  if (
    versionRequired &&
    (typeof subject.version !== "string" || !subject.version)
  ) {
    fail(`${label}.version is required.`);
  }
}

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function executionBaseline(descriptor) {
  assertExactKeys(descriptor, EXECUTION_BASELINE_KEYS, "Execution baseline");
  if (descriptor.schemaVersion !== "p2-execution-baseline.v1") {
    fail("Execution baseline schemaVersion is invalid.");
  }
  if (!GIT_COMMIT.test(descriptor.sourceCommit ?? "")) {
    fail("Execution baseline sourceCommit is invalid.");
  }
  assertSubject(descriptor.acceptanceProfile, "acceptanceProfile");
  assertSubject(descriptor.receiptSchema, "receiptSchema", true);
  assertSubject(descriptor.semanticValidator, "semanticValidator", true);
  if (!Array.isArray(descriptor.fixtures) || descriptor.fixtures.length === 0) {
    fail("Execution baseline fixtures are required.");
  }
  if (!Array.isArray(descriptor.toolLocks) || descriptor.toolLocks.length === 0) {
    fail("Execution baseline tool locks are required.");
  }
  const fixtures = descriptor.fixtures.map((fixture, index) => {
    assertExactKeys(fixture, ["name", "path", "sha256"], `fixtures[${index}]`);
    if (typeof fixture.name !== "string" || !fixture.name) {
      fail(`fixtures[${index}].name is required.`);
    }
    assertSubject(
      { path: fixture.path, sha256: fixture.sha256 },
      `fixtures[${index}]`,
    );
    return structuredClone(fixture);
  });
  const toolLocks = descriptor.toolLocks.map((tool, index) => {
    assertExactKeys(tool, ["digest", "name", "version"], `toolLocks[${index}]`);
    if (
      typeof tool.name !== "string" ||
      !tool.name ||
      typeof tool.version !== "string" ||
      !tool.version
    ) {
      fail(`toolLocks[${index}] name and version are required.`);
    }
    assertDigest(tool.digest, `toolLocks[${index}].digest`);
    return structuredClone(tool);
  });
  fixtures.sort((left, right) =>
    `${left.name}\0${left.path}`.localeCompare(`${right.name}\0${right.path}`),
  );
  toolLocks.sort((left, right) =>
    `${left.name}\0${left.version}`.localeCompare(
      `${right.name}\0${right.version}`,
    ),
  );
  return sha256Bytes(
    canonicalizeProjectJson({
      ...descriptor,
      fixtures,
      toolLocks,
    }),
  );
}

function executionBaselineRecipe(bytes) {
  if (
    !(
      typeof bytes === "string" ||
      bytes instanceof Uint8Array ||
      Buffer.isBuffer(bytes)
    )
  ) {
    fail("Execution baseline recipe must be exact bytes.");
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    fail("Execution baseline recipe must be valid JSON bytes.");
  }
  assertExactKeys(
    parsed,
    EXECUTION_BASELINE_RECIPE_KEYS,
    "Execution baseline recipe",
  );
  if (parsed.schemaVersion !== "p2-execution-baseline-recipe.v1") {
    fail("Execution baseline recipe schemaVersion is invalid.");
  }
  assertSubject(parsed.acceptanceProfile, "acceptanceProfile");
  assertSubject(parsed.receiptSchema, "receiptSchema", true);
  assertSubject(parsed.semanticValidator, "semanticValidator", true);
  if (!Array.isArray(parsed.fixtures) || parsed.fixtures.length === 0) {
    fail("Execution baseline recipe fixtures are required.");
  }
  if (!Array.isArray(parsed.toolLocks) || parsed.toolLocks.length === 0) {
    fail("Execution baseline recipe tool locks are required.");
  }
  for (const [index, fixture] of parsed.fixtures.entries()) {
    assertExactKeys(fixture, ["name", "path", "sha256"], `fixtures[${index}]`);
    if (
      typeof fixture.name !== "string" ||
      !fixture.name ||
      !safeEvidencePath(fixture.path)
    ) {
      fail(`fixtures[${index}] name or path is invalid.`);
    }
    assertDigest(fixture.sha256, `fixtures[${index}].sha256`);
  }
  for (const [index, toolLock] of parsed.toolLocks.entries()) {
    assertExactKeys(
      toolLock,
      ["name", "path", "sha256", "version"],
      `toolLocks[${index}]`,
    );
    if (
      typeof toolLock.name !== "string" ||
      !toolLock.name ||
      typeof toolLock.version !== "string" ||
      !toolLock.version ||
      !safeEvidencePath(toolLock.path)
    ) {
      fail(`toolLocks[${index}] name, version, or path is invalid.`);
    }
    assertDigest(toolLock.sha256, `toolLocks[${index}].sha256`);
  }
  for (const subject of [
    parsed.acceptanceProfile,
    parsed.receiptSchema,
    parsed.semanticValidator,
  ]) {
    if (!safeEvidencePath(subject.path)) {
      fail("Execution baseline recipe subject path is invalid.");
    }
  }
  return parsed;
}

function evidenceIndex(bytes) {
  if (
    !(
      typeof bytes === "string" ||
      bytes instanceof Uint8Array ||
      Buffer.isBuffer(bytes)
    )
  ) {
    fail("Evidence index must be exact bytes.");
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
  } catch {
    fail("Evidence index must be valid JSON bytes.");
  }
  assertExactKeys(
    parsed,
    ["entries", "executionBaselineDigest", "schemaVersion"],
    "Evidence index",
  );
  if (
    parsed?.schemaVersion !== "p2-evidence-index.v1" ||
    !SHA256.test(parsed?.executionBaselineDigest ?? "") ||
    !Array.isArray(parsed?.entries)
  ) {
    fail("Evidence index contract is invalid.");
  }
  const evidenceIds = new Set();
  for (const [index, entry] of parsed.entries.entries()) {
    const keys = [
      "acceptanceProfileSha256",
      "criterionId",
      "evidenceId",
      "executionBaselineDigest",
      "freezeCommit",
      "mediaType",
      "path",
      "sha256",
    ];
    if (Object.hasOwn(entry ?? {}, "applicabilityPredicate")) {
      keys.push("applicabilityPredicate");
    }
    assertExactKeys(entry, keys, `entries[${index}]`);
    if (
      !EVIDENCE_ID.test(entry.evidenceId ?? "") ||
      evidenceIds.has(entry.evidenceId) ||
      !safeEvidencePath(entry.path) ||
      !SHA256.test(entry.sha256 ?? "") ||
      !GIT_COMMIT.test(entry.freezeCommit ?? "") ||
      typeof entry.mediaType !== "string" ||
      !entry.mediaType ||
      typeof entry.criterionId !== "string" ||
      !entry.criterionId ||
      !SHA256.test(entry.acceptanceProfileSha256 ?? "") ||
      entry.executionBaselineDigest !== parsed.executionBaselineDigest
    ) {
      fail("Evidence index entry is not bound only to its execution baseline.");
    }
    if (Object.hasOwn(entry, "applicabilityPredicate")) {
      assertExactKeys(
        entry.applicabilityPredicate,
        ["predicateRef", "value"],
        `entries[${index}].applicabilityPredicate`,
      );
      if (
        typeof entry.applicabilityPredicate.predicateRef !== "string" ||
        !entry.applicabilityPredicate.predicateRef ||
        typeof entry.applicabilityPredicate.value !== "boolean"
      ) {
        fail("Evidence index applicability predicate is invalid.");
      }
    }
    evidenceIds.add(entry.evidenceId);
  }
  return sha256Bytes(bytes);
}

function artifactManifest(manifest) {
  assertExactKeys(
    manifest,
    ["artifacts", "schemaVersion"],
    "Artifact manifest",
  );
  if (
    manifest.schemaVersion !== "p2-artifact-manifest.v1" ||
    !Array.isArray(manifest.artifacts) ||
    manifest.artifacts.length === 0
  ) {
    fail("Artifact manifest contract is invalid.");
  }
  const artifacts = manifest.artifacts.map((artifact, index) => {
    assertExactKeys(
      artifact,
      ["freezeCommit", "kind", "path", "sha256"],
      `artifacts[${index}]`,
    );
    if (!ARTIFACT_KINDS.has(artifact.kind)) {
      fail(
        "Receipt, final release descriptor, evidence index, and unknown artifact kinds are excluded.",
      );
    }
    if (!GIT_COMMIT.test(artifact.freezeCommit ?? "")) {
      fail(`artifacts[${index}].freezeCommit is invalid.`);
    }
    assertSubject(
      { path: artifact.path, sha256: artifact.sha256 },
      `artifacts[${index}]`,
    );
    return structuredClone(artifact);
  });
  artifacts.sort((left, right) => left.path.localeCompare(right.path));
  return sha256Bytes(
    canonicalizeProjectJson({
      schemaVersion: manifest.schemaVersion,
      artifacts,
    }),
  );
}

function finalRelease(inputs) {
  assertExactKeys(inputs, FINAL_RELEASE_KEYS, "Final release");
  for (const key of FINAL_RELEASE_KEYS) {
    assertDigest(inputs[key], key);
  }
  return sha256Bytes(
    canonicalizeProjectJson({
      schemaVersion: "p2-final-release-subject.v1",
      ...inputs,
    }),
  );
}

export const p2AcceptanceDigests = Object.freeze({
  executionBaseline,
  evidenceIndex,
  artifactManifest,
  finalRelease,
});

function controlledGitEnvironment() {
  const environment = {};
  for (const key of [
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
  ]) {
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

function createLocalGitObjectReader({ repositoryPath }) {
  if (typeof repositoryPath !== "string" || !repositoryPath) {
    fail("Git repository path is required.");
  }
  const environment = controlledGitEnvironment();

  return Object.freeze({
    async commitExists(commit) {
      if (!GIT_COMMIT.test(commit ?? "")) return false;
      try {
        const { stdout } = await execFileAsync(
          TRUSTED_GIT_EXECUTABLE,
          ["--no-replace-objects", "cat-file", "-t", commit],
          {
            cwd: repositoryPath,
            encoding: "utf8",
            env: environment,
          },
        );
        return stdout.trim() === "commit";
      } catch {
        return false;
      }
    },
    async readBlob(commit, repositoryPathWithinGit) {
      if (
        !GIT_COMMIT.test(commit ?? "") ||
        !safeEvidencePath(repositoryPathWithinGit)
      ) {
        fail("Git blob reference is invalid.");
      }
      const { stdout } = await execFileAsync(
        TRUSTED_GIT_EXECUTABLE,
        [
          "--no-replace-objects",
          "cat-file",
          "blob",
          `${commit}:${repositoryPathWithinGit}`,
        ],
        {
          cwd: repositoryPath,
          encoding: null,
          env: environment,
          maxBuffer: 16 * 1024 * 1024,
        },
      );
      return Buffer.from(stdout);
    },
    async readCommitTime(commit) {
      if (!GIT_COMMIT.test(commit ?? "")) {
        fail("Git commit reference is invalid.");
      }
      const { stdout } = await execFileAsync(
        TRUSTED_GIT_EXECUTABLE,
        ["--no-replace-objects", "show", "-s", "--format=%cI", commit],
        {
          cwd: repositoryPath,
          encoding: "utf8",
          env: environment,
        },
      );
      const value = stdout.trim();
      if (!Number.isFinite(Date.parse(value))) {
        fail("Git commit time is invalid.");
      }
      return value;
    },
  });
}

export function createP2ExecutionBaselineVerifier({
  repositoryPath,
} = {}) {
  const git = createLocalGitObjectReader({ repositoryPath });
  return async function verify({
    executionBaselineDigest,
    sourceCommit,
    policy,
  }) {
    try {
      if (
        !SHA256.test(executionBaselineDigest ?? "") ||
        !GIT_COMMIT.test(sourceCommit ?? "") ||
        policy?.executionBaselineRecipe?.path !==
          EXECUTION_BASELINE_RECIPE_PATH ||
        policy.executionBaselineRecipe.schemaVersion !==
          "p2-execution-baseline-recipe.v1" ||
        !SHA256.test(policy.executionBaselineRecipe.sha256 ?? "") ||
        (await git.commitExists(sourceCommit)) !== true
      ) {
        return false;
      }
      const [recipeBytes, commitTime] = await Promise.all([
        git.readBlob(sourceCommit, policy.executionBaselineRecipe.path),
        git.readCommitTime(sourceCommit),
      ]);
      if (sha256Bytes(recipeBytes) !== policy.executionBaselineRecipe.sha256) {
        return false;
      }
      const recipe = executionBaselineRecipe(recipeBytes);
      if (
        recipe.schemaVersion !==
          policy.executionBaselineRecipe.schemaVersion ||
        recipe.acceptanceProfile.path !== policy?.profile?.path ||
        recipe.acceptanceProfile.sha256 !== policy?.profile?.sha256 ||
        recipe.receiptSchema.path !== policy?.receiptSchema?.path ||
        recipe.receiptSchema.version !== policy?.receiptSchema?.version ||
        recipe.receiptSchema.sha256 !== policy?.receiptSchema?.sha256 ||
        recipe.semanticValidator.path !== policy?.validator?.path ||
        recipe.semanticValidator.version !== policy?.validator?.version ||
        recipe.semanticValidator.sha256 !== policy?.validator?.sha256
      ) {
        return false;
      }
      const subjects = [
        recipe.acceptanceProfile,
        recipe.receiptSchema,
        recipe.semanticValidator,
        ...recipe.fixtures,
        ...recipe.toolLocks,
      ];
      const subjectBytes = await Promise.all(
        subjects.map(async (subject) => ({
          bytes: await git.readBlob(sourceCommit, subject.path),
          subject,
        })),
      );
      if (
        subjectBytes.some(
          ({ bytes, subject }) => sha256Bytes(bytes) !== subject.sha256,
        )
      ) {
        return false;
      }
      const profileBytes = subjectBytes[0].bytes;
      const profile = JSON.parse(Buffer.from(profileBytes).toString("utf8"));
      if (
        profile?.schemaVersion !== policy.profile.schemaVersion ||
        !CANONICAL_INSTANT.test(profile?.recordedAt ?? "") ||
        Date.parse(profile.recordedAt) > Date.parse(commitTime)
      ) {
        return false;
      }
      const descriptor = {
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
      return (
        p2AcceptanceDigests.executionBaseline(descriptor) ===
        executionBaselineDigest
      );
    } catch {
      return false;
    }
  };
}

function issue(code, field, message) {
  return { code, field, message };
}

function safeEvidencePath(value) {
  return (
    typeof value === "string" &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    path.normalize(value) === value &&
    !value.split("/").includes("..")
  );
}

function releaseControlDocumentKind(bytes) {
  try {
    const parsed = JSON.parse(Buffer.from(bytes).toString("utf8"));
    const schemaVersion = parsed?.schemaVersion ?? "";
    if (/^p2-acceptance-receipt\.v[0-9]+$/.test(schemaVersion)) {
      return "RECEIPT";
    }
    if (schemaVersion === "p2-evidence-index.v1") {
      return "EVIDENCE_INDEX";
    }
    if (
      ["p2-final-release.v1", "p2-final-release-subject.v1"].includes(
        schemaVersion,
      )
    ) {
      return "FINAL_RELEASE_DESCRIPTOR";
    }
    if (schemaVersion === "p2-artifact-manifest.v1") {
      return "ARTIFACT_MANIFEST";
    }
    return null;
  } catch {
    return null;
  }
}

function nearlyEqual(left, right) {
  return Math.abs(left - right) <= 1e-9 * Math.max(1, Math.abs(left), Math.abs(right));
}

function calculateMetric(policy, result) {
  if (policy.calculation === "RATIO_PERCENT") {
    return (result.numerator / result.denominator) * 100;
  }
  if (policy.calculation === "RATIO") {
    return result.numerator / result.denominator;
  }
  if (policy.calculation === "COUNT") {
    return result.numerator;
  }
  return null;
}

function metricPasses(operator, value, threshold) {
  return {
    EQ: nearlyEqual(value, threshold),
    NE: !nearlyEqual(value, threshold),
    LT: value < threshold,
    LTE: value <= threshold,
    GT: value > threshold,
    GTE: value >= threshold,
  }[operator];
}

export function createP2AcceptanceReceiptValidator({
  validateStructure,
  resolveApprovedProfile,
  resolveFinalRelease,
  resolveExecutionBaseline,
  resolveEvidenceIndex,
  resolveArtifactManifest,
  resolveOwnerAssignment,
  resolveReviewerConflicts,
  readGitBlob,
  now = () => new Date().toISOString(),
}) {
  const dependencies = [
    validateStructure,
    resolveApprovedProfile,
    resolveFinalRelease,
    resolveExecutionBaseline,
    resolveEvidenceIndex,
    resolveArtifactManifest,
    resolveOwnerAssignment,
    resolveReviewerConflicts,
    readGitBlob,
    now,
  ];
  if (dependencies.some((dependency) => typeof dependency !== "function")) {
    fail("P2 Receipt validator dependencies must be functions.");
  }

  async function validate(receipt) {
    const structural = validateStructure(receipt);
    if (!structural?.valid) {
      return {
        receiptValid: false,
        declaredDecision: receipt?.decision ?? null,
        derivedDecision: null,
        observedOutcome: "UNKNOWN",
        completionEligible: false,
        errors: [
          issue(
            "RECEIPT_SCHEMA_INVALID",
            "$",
            JSON.stringify(structural?.errors ?? []),
          ),
        ],
        blockers: [],
      };
    }

    const errors = [];
    const blockers = [];
    let observedOutcome = "PASS";

    const approved = await resolveApprovedProfile(
      receipt.acceptanceProfileSha256,
    );
    if (!approved) {
      errors.push(
        issue(
          "PROFILE_NOT_ACTIVATED",
          "acceptanceProfileSha256",
          "No approved Profile is bound to this Receipt.",
        ),
      );
    }
    const profileBytes = approved?.profileBytes;
    const profile = approved?.profile;
    const profileHash =
      profileBytes === undefined ? null : sha256Bytes(profileBytes);
    if (
      profileHash !== receipt.acceptanceProfileSha256 ||
      approved?.approval?.profile_sha256 !== receipt.acceptanceProfileSha256
    ) {
      errors.push(
        issue(
          "PROFILE_HASH_MISMATCH",
          "acceptanceProfileSha256",
          "The Receipt does not bind the approved Profile raw bytes.",
        ),
      );
    }

    const criterion = [...(profile?.criteria ?? []), ...(profile?.crossStageCriteria ?? [])]
      .find(({ criterionId }) => criterionId === receipt.criterionId);
    if (!criterion) {
      errors.push(
        issue(
          "CRITERION_NOT_IN_PROFILE",
          "criterionId",
          "The criterion is not declared by the approved Profile.",
        ),
      );
    } else {
      if (criterion.receiptKind !== receipt.receiptKind) {
        errors.push(
          issue(
            "RECEIPT_KIND_MISMATCH",
            "receiptKind",
            "The Receipt kind does not match the Profile.",
          ),
        );
      }
      if (criterion.ownerRole !== receipt.owner.role) {
        errors.push(
          issue(
            "OWNER_ROLE_MISMATCH",
            "owner.role",
            "The Owner role does not exactly match the Profile.",
          ),
        );
      }
      if (
        criterion.applicability !== "REQUIRED" &&
        !criterion.applicability?.startsWith("REQUIRED_") &&
        !criterion.applicability?.startsWith("CONDITIONAL_")
      ) {
        blockers.push(
          issue(
            "APPLICABILITY_POLICY_UNRESOLVED",
            "applicabilityAssertion",
            "The Profile applicability policy is unresolved.",
          ),
        );
      }
      if (
        (criterion.applicability === "REQUIRED" ||
          criterion.applicability?.startsWith("REQUIRED_")) &&
        receipt.applicabilityAssertion.status === "NOT_APPLICABLE"
      ) {
        errors.push(
          issue(
            "NOT_APPLICABLE_FOR_REQUIRED_CRITERION",
            "applicabilityAssertion.status",
            "A required criterion cannot be marked not applicable.",
          ),
        );
      }
      if (receipt.applicabilityAssertion.status === "UNKNOWN") {
        blockers.push(
          issue(
            "APPLICABILITY_FACT_UNKNOWN",
            "applicabilityAssertion.status",
            "Applicability is not yet proven.",
          ),
        );
      }
    }

    const release = await resolveFinalRelease(receipt.finalReleaseDigest);
    if (!release) {
      errors.push(
        issue(
          "FINAL_RELEASE_NOT_ISSUED",
          "finalReleaseDigest",
          "The final release descriptor is unavailable.",
        ),
      );
    } else {
      let recomputedFinalRelease = null;
      try {
        recomputedFinalRelease = p2AcceptanceDigests.finalRelease({
          executionBaselineDigest: release.executionBaselineDigest,
          evidenceIndexDigest: release.evidenceIndexDigest,
          artifactManifestDigest: release.artifactManifestDigest,
        });
      } catch {
        errors.push(
          issue(
            "FINAL_RELEASE_DIGEST_MISMATCH",
            "finalReleaseDigest",
            "The final release descriptor is malformed.",
          ),
        );
      }
      if (
        release.schemaVersion !== "p2-final-release.v1" ||
        release.finalReleaseDigest !== receipt.finalReleaseDigest ||
        recomputedFinalRelease !== receipt.finalReleaseDigest
      ) {
        errors.push(
          issue(
            "FINAL_RELEASE_DIGEST_MISMATCH",
            "finalReleaseDigest",
            "The final release digest cannot be reproduced.",
          ),
        );
      }
      if (
        release.executionBaselineDigest !==
        approved?.approval?.execution_baseline_digest
      ) {
        errors.push(
          issue(
            "EXECUTION_BASELINE_DIGEST_MISMATCH",
            "finalReleaseDigest",
            "The final release and approved Profile use different execution baselines.",
          ),
        );
      }

      const executionBaseline = await resolveExecutionBaseline(
        release.executionBaselineDigest,
      );
      let actualExecutionBaselineDigest = null;
      try {
        actualExecutionBaselineDigest =
          p2AcceptanceDigests.executionBaseline(executionBaseline);
      } catch {
        // The stable mismatch below covers missing and malformed descriptors.
      }
      if (
        actualExecutionBaselineDigest !== release.executionBaselineDigest ||
        executionBaseline?.acceptanceProfile?.sha256 !==
          receipt.acceptanceProfileSha256
      ) {
        errors.push(
          issue(
            "EXECUTION_BASELINE_DIGEST_MISMATCH",
            "finalReleaseDigest",
            "The execution baseline digest cannot be reproduced.",
          ),
        );
      }

      const artifactManifest = await resolveArtifactManifest(
        release.artifactManifestDigest,
      );
      let actualArtifactManifestDigest = null;
      try {
        actualArtifactManifestDigest =
          p2AcceptanceDigests.artifactManifest(artifactManifest);
      } catch {
        // The stable mismatch below covers missing and malformed manifests.
      }
      if (
        actualArtifactManifestDigest !== release.artifactManifestDigest
      ) {
        errors.push(
          issue(
            "ARTIFACT_MANIFEST_DIGEST_MISMATCH",
            "finalReleaseDigest",
            "The artifact manifest digest cannot be reproduced.",
          ),
        );
      } else {
        for (const artifact of artifactManifest.artifacts) {
          const bytes = await readGitBlob(artifact);
          if (bytes === null || bytes === undefined) {
            errors.push(
              issue(
                "ARTIFACT_NOT_IN_GIT_FREEZE",
                "finalReleaseDigest",
                `Artifact ${artifact.path} is absent from its Git freeze.`,
              ),
            );
          } else {
            if (sha256Bytes(bytes) !== artifact.sha256) {
              errors.push(
                issue(
                  "ARTIFACT_HASH_MISMATCH",
                  "finalReleaseDigest",
                  `Artifact ${artifact.path} bytes do not match its SHA-256.`,
                ),
              );
            }
            const forbiddenKind = releaseControlDocumentKind(bytes);
            if (forbiddenKind) {
              errors.push(
                issue(
                  forbiddenKind === "RECEIPT"
                    ? "RECEIPT_INCLUDED_IN_RELEASE"
                    : "RELEASE_CONTROL_DOCUMENT_INCLUDED",
                  "finalReleaseDigest",
                  `${forbiddenKind} content is forbidden in artifact ${artifact.path}.`,
                ),
              );
            }
          }
        }
      }
    }

    const resolvedIndex = release
      ? await resolveEvidenceIndex(release.evidenceIndexDigest)
      : null;
    let evidenceIndexDocument = null;
    let actualIndexDigest = null;
    if (!resolvedIndex) {
      errors.push(
        issue(
          "EVIDENCE_INDEX_NOT_FOUND",
          "rawEvidence",
          "The final release evidence index is unavailable.",
        ),
      );
    } else {
      try {
        actualIndexDigest = p2AcceptanceDigests.evidenceIndex(
          resolvedIndex.bytes,
        );
        evidenceIndexDocument = JSON.parse(
          Buffer.from(resolvedIndex.bytes).toString("utf8"),
        );
      } catch {
        errors.push(
          issue(
            "EVIDENCE_INDEX_DIGEST_MISMATCH",
            "rawEvidence",
            "The evidence index contract is invalid.",
          ),
        );
      }
      if (actualIndexDigest !== release?.evidenceIndexDigest) {
        errors.push(
          issue(
            "EVIDENCE_INDEX_DIGEST_MISMATCH",
            "rawEvidence",
            "The evidence index bytes do not match the final release.",
          ),
        );
      }
    }

    const indexedEvidenceBytes = new Map();
    if (
      evidenceIndexDocument &&
      actualIndexDigest === release?.evidenceIndexDigest
    ) {
      for (const indexed of evidenceIndexDocument.entries) {
        const bytes = await readGitBlob(indexed);
        indexedEvidenceBytes.set(indexed.evidenceId, bytes);
        if (bytes === null || bytes === undefined) {
          errors.push(
            issue(
              "EVIDENCE_NOT_IN_GIT_FREEZE",
              "rawEvidence",
              `Indexed evidence ${indexed.evidenceId} is absent from its Git freeze.`,
            ),
          );
          continue;
        }
        if (sha256Bytes(bytes) !== indexed.sha256) {
          errors.push(
            issue(
              "EVIDENCE_HASH_MISMATCH",
              "rawEvidence",
              `Indexed evidence ${indexed.evidenceId} bytes do not match its SHA-256.`,
            ),
          );
        }
        const forbiddenKind = releaseControlDocumentKind(bytes);
        if (forbiddenKind) {
          errors.push(
            issue(
              forbiddenKind === "RECEIPT"
                ? "RECEIPT_INCLUDED_IN_RELEASE"
                : "RELEASE_CONTROL_DOCUMENT_INCLUDED",
              "rawEvidence",
              `${forbiddenKind} content is forbidden in evidence ${indexed.evidenceId}.`,
            ),
          );
        }
      }
    }

    const evidenceById = new Map();
    for (const entry of receipt.rawEvidence) {
      if (evidenceById.has(entry.evidenceId)) {
        errors.push(
          issue(
            "DUPLICATE_EVIDENCE_ID",
            "rawEvidence",
            `Duplicate evidence id: ${entry.evidenceId}.`,
          ),
        );
        continue;
      }
      evidenceById.set(entry.evidenceId, entry);
      if (!safeEvidencePath(entry.path)) {
        errors.push(
          issue(
            "UNSAFE_EVIDENCE_PATH",
            "rawEvidence",
            `Unsafe evidence path: ${entry.path}.`,
          ),
        );
      }
      if (
        entry.executionBaselineDigest !== release?.executionBaselineDigest
      ) {
        errors.push(
          issue(
            "EVIDENCE_BASELINE_MISMATCH",
            "rawEvidence",
            `Evidence ${entry.evidenceId} uses another execution baseline.`,
          ),
        );
      }
      const indexed = evidenceIndexDocument?.entries?.find(
        ({ evidenceId }) => evidenceId === entry.evidenceId,
      );
      const indexedBindingMatches =
        indexed &&
        Object.entries({
          ...entry,
          criterionId: receipt.criterionId,
          acceptanceProfileSha256: receipt.acceptanceProfileSha256,
        }).every(
          ([key, value]) =>
            canonicalizeProjectJson(indexed[key]) ===
            canonicalizeProjectJson(value),
        );
      if (
        !indexedBindingMatches
      ) {
        errors.push(
          issue(
            "EVIDENCE_NOT_IN_INDEX",
            "rawEvidence",
            `Evidence ${entry.evidenceId} does not match the frozen index.`,
          ),
        );
      }
      const bytes = indexedEvidenceBytes.get(entry.evidenceId);
      if (
        bytes !== null &&
        bytes !== undefined &&
        sha256Bytes(bytes) !== entry.sha256
      ) {
        errors.push(
          issue(
            "EVIDENCE_HASH_MISMATCH",
            "rawEvidence",
            `Evidence ${entry.evidenceId} bytes do not match its SHA-256.`,
          ),
        );
      }
    }

    if (criterion?.applicability?.startsWith("CONDITIONAL_")) {
      const rule = criterion.applicabilityRule;
      if (
        !rule ||
        typeof rule.predicateRef !== "string" ||
        typeof rule.notApplicableWhen !== "boolean"
      ) {
        blockers.push(
          issue(
            "APPLICABILITY_POLICY_UNRESOLVED",
            "applicabilityAssertion",
            "The conditional criterion has no machine-executable rule.",
          ),
        );
      } else if (
        receipt.applicabilityAssertion.predicateRef !== rule.predicateRef
      ) {
        errors.push(
          issue(
            "APPLICABILITY_PREDICATE_MISMATCH",
            "applicabilityAssertion.predicateRef",
            "The Receipt names another applicability predicate.",
          ),
        );
      } else {
        const indexedPredicates = receipt.applicabilityAssertion.evidenceIds
          .map((evidenceId) =>
            evidenceIndexDocument?.entries?.find(
              (entry) => entry.evidenceId === evidenceId,
            ),
          )
          .map((entry) => entry?.applicabilityPredicate)
          .filter(
            (predicate) =>
              predicate?.predicateRef === rule.predicateRef &&
              typeof predicate.value === "boolean",
          );
        if (
          receipt.applicabilityAssertion.evidenceIds.some(
            (evidenceId) => !evidenceById.has(evidenceId),
          ) ||
          indexedPredicates.length === 0
        ) {
          blockers.push(
            issue(
              "APPLICABILITY_FACT_UNKNOWN",
              "applicabilityAssertion.evidenceIds",
              "No frozen evidence establishes the applicability fact.",
            ),
          );
        } else {
          const values = new Set(
            indexedPredicates.map(({ value }) => value),
          );
          if (values.size !== 1) {
            blockers.push(
              issue(
                "APPLICABILITY_FACT_UNKNOWN",
                "applicabilityAssertion.evidenceIds",
                "Frozen applicability facts conflict.",
              ),
            );
          } else {
            const [fact] = values;
            const shouldBeNotApplicable =
              fact === rule.notApplicableWhen;
            if (
              receipt.applicabilityAssertion.status === "NOT_APPLICABLE" &&
              !shouldBeNotApplicable
            ) {
              errors.push(
                issue(
                  "NOT_APPLICABLE_PREDICATE_MISMATCH",
                  "applicabilityAssertion.status",
                  "The frozen predicate proves that the criterion is applicable.",
                ),
              );
            }
            if (
              receipt.applicabilityAssertion.status === "APPLICABLE" &&
              shouldBeNotApplicable
            ) {
              errors.push(
                issue(
                  "APPLICABILITY_PREDICATE_MISMATCH",
                  "applicabilityAssertion.status",
                  "The frozen predicate proves that the criterion is not applicable.",
                ),
              );
            }
          }
        }
      }
    }

    const ownerAssignment = await resolveOwnerAssignment(receipt.owner);
    if (!ownerAssignment) {
      blockers.push(
        issue(
          "OWNER_ASSIGNMENT_UNVERIFIED",
          "owner",
          "The Owner assignment is not independently verifiable.",
        ),
      );
    } else if (
      ownerAssignment.principalRef !== receipt.owner.principalRef ||
      ownerAssignment.role !== receipt.owner.role ||
      ownerAssignment.assignmentEvidenceId !==
        receipt.owner.assignmentEvidenceId
    ) {
      errors.push(
        issue(
          "OWNER_ASSIGNMENT_MISMATCH",
          "owner",
          "The Receipt Owner does not match the authoritative assignment.",
        ),
      );
    } else if (
      !evidenceById.has(receipt.owner.assignmentEvidenceId) ||
      ownerAssignment.validFrom > receipt.startedAt ||
      (ownerAssignment.validUntil &&
        ownerAssignment.validUntil < receipt.finishedAt)
    ) {
      blockers.push(
        issue(
          "OWNER_ASSIGNMENT_UNVERIFIED",
          "owner",
          "The Owner assignment is missing frozen evidence or was not valid for the run.",
        ),
      );
    }

    if (!receipt.reviewer) {
      blockers.push(
        issue(
          "INDEPENDENT_REVIEW_UNAVAILABLE",
          "reviewer",
          "No independent reviewer is available.",
        ),
      );
    } else {
      const review = await resolveReviewerConflicts({
        owner: receipt.owner,
        reviewer: receipt.reviewer,
        criterionId: receipt.criterionId,
      });
      if (
        receipt.reviewer.principalRef === receipt.owner.principalRef ||
        receipt.reviewer.independentOfImplementation !== true ||
        review?.independent !== true ||
        (review?.conflicts?.length ?? 0) > 0
      ) {
        errors.push(
          issue(
            "REVIEWER_CONFLICT_OF_INTEREST",
            "reviewer",
            "The reviewer is not independent of implementation or evidence.",
          ),
        );
      } else if (
        receipt.reviewer.independenceEvidenceIds.some(
          (evidenceId) => !evidenceById.has(evidenceId),
        )
      ) {
        blockers.push(
          issue(
            "INDEPENDENCE_EVIDENCE_UNVERIFIED",
            "reviewer.independenceEvidenceIds",
            "Reviewer independence evidence is not frozen.",
          ),
        );
      }
    }

    const startedAt = Date.parse(receipt.startedAt);
    const finishedAt = Date.parse(receipt.finishedAt);
    const validationTime = Date.parse(now());
    if (
      !Number.isFinite(startedAt) ||
      !Number.isFinite(finishedAt) ||
      finishedAt < startedAt
    ) {
      errors.push(
        issue(
          "INVALID_TIME_ORDER",
          "finishedAt",
          "finishedAt must not precede startedAt.",
        ),
      );
    }
    if (!Number.isFinite(validationTime) || finishedAt > validationTime) {
      errors.push(
        issue(
          "FUTURE_TIMESTAMP",
          "finishedAt",
          "finishedAt must not be later than validator time.",
        ),
      );
    }

    const metricPolicies = criterion?.metricPolicy;
    if (!Array.isArray(metricPolicies)) {
      blockers.push(
        issue(
          "METRIC_POLICY_UNRESOLVED",
          "metricResults",
          "The Profile has no machine-executable metric policy.",
        ),
      );
    } else {
      const resultsById = new Map();
      for (const result of receipt.metricResults) {
        if (resultsById.has(result.metricId)) {
          errors.push(
            issue(
              "DUPLICATE_METRIC",
              "metricResults",
              `Duplicate metric: ${result.metricId}.`,
            ),
          );
        }
        resultsById.set(result.metricId, result);
      }
      for (const result of receipt.metricResults) {
        if (!metricPolicies.some(({ metricId }) => metricId === result.metricId)) {
          errors.push(
            issue(
              "UNEXPECTED_METRIC",
              "metricResults",
              `Unexpected metric: ${result.metricId}.`,
            ),
          );
        }
      }
      for (const policy of metricPolicies) {
        const result = resultsById.get(policy.metricId);
        if (!result) {
          blockers.push(
            issue(
              "REQUIRED_METRIC_MISSING",
              "metricResults",
              `Required metric is missing: ${policy.metricId}.`,
            ),
          );
          continue;
        }
        if (
          Number.isFinite(policy.expectedAttemptCount) &&
          result.denominator !== policy.expectedAttemptCount
        ) {
          errors.push(
            issue(
              "ATTEMPT_DENOMINATOR_INCOMPLETE",
              "metricResults",
              `Metric ${policy.metricId} omits required attempts.`,
            ),
          );
        }
        const calculated = calculateMetric(policy, result);
        if (calculated === null || !nearlyEqual(calculated, result.value)) {
          errors.push(
            issue(
              "METRIC_VALUE_MISMATCH",
              "metricResults",
              `Metric ${policy.metricId} value cannot be reproduced.`,
            ),
          );
          continue;
        }
        const passes = metricPasses(
          policy.operator,
          calculated,
          policy.threshold,
        );
        if (!passes) observedOutcome = "FAIL";
        if (result.result !== (passes ? "PASS" : "FAIL")) {
          errors.push(
            issue(
              "METRIC_RESULT_MISMATCH",
              "metricResults",
              `Metric ${policy.metricId} result does not match the Profile threshold.`,
            ),
          );
        }
        if (
          result.evidenceIds.some(
            (evidenceId) => !evidenceById.has(evidenceId),
          )
        ) {
          blockers.push(
            issue(
              "METRIC_EVIDENCE_UNVERIFIED",
              "metricResults",
              `Metric ${policy.metricId} lacks frozen evidence.`,
            ),
          );
        }
      }
    }

    const actualZeroToleranceCount = receipt.findings.filter(
      ({ zeroTolerance }) => zeroTolerance,
    ).length;
    if (actualZeroToleranceCount !== receipt.zeroToleranceFindingCount) {
      errors.push(
        issue(
          "ZERO_TOLERANCE_COUNT_MISMATCH",
          "zeroToleranceFindingCount",
          "The zero-tolerance count does not match findings.",
        ),
      );
    }
    if (actualZeroToleranceCount > 0) observedOutcome = "FAIL";
    for (const finding of receipt.findings) {
      if (
        finding.evidenceIds.some(
          (evidenceId) => !evidenceById.has(evidenceId),
        )
      ) {
        blockers.push(
          issue(
            "FINDING_EVIDENCE_UNVERIFIED",
            "findings",
            `Finding ${finding.findingId} lacks frozen evidence.`,
          ),
        );
      }
    }

    let derivedDecision = null;
    if (errors.length === 0) {
      if (blockers.length > 0) {
        derivedDecision = "INCONCLUSIVE";
      } else if (
        receipt.applicabilityAssertion.status === "NOT_APPLICABLE"
      ) {
        derivedDecision = "NOT_APPLICABLE";
      } else if (observedOutcome === "FAIL") {
        derivedDecision = "FAIL";
      } else {
        derivedDecision = "PASS";
      }
      if (receipt.decision !== derivedDecision) {
        errors.push(
          issue(
            "DECLARED_DECISION_MISMATCH",
            "decision",
            `Declared ${receipt.decision}; derived ${derivedDecision}.`,
          ),
        );
      }
    }

    const receiptValid = errors.length === 0;
    return {
      receiptValid,
      declaredDecision: receipt.decision,
      derivedDecision,
      observedOutcome,
      completionEligible:
        receiptValid &&
        ["PASS", "NOT_APPLICABLE"].includes(derivedDecision),
      errors,
      blockers,
    };
  }

  return Object.freeze({ validate });
}
