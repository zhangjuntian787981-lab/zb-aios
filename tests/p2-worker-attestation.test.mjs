import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  createP2ExecutionBaselineAttestationBuilder,
  P2_BUILD_ATTESTATION_BASELINE,
  buildFrozenP2ExecutionBaselineAttestation,
} from "../scripts/build-p2-execution-baseline-attestation.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "../lib/p2-start-authorization.mjs";
import {
  createP2WorkerAttestationVerifier,
  verifyP2ExecutionBaselineFromBuildAttestation,
} from "../lib/p2-worker-attestation-verifier.mjs";
import {
  P2_WORKER_ATTESTATION_PIN_POLICY,
  P2_LEGACY_WORKER_ATTESTATION_PIN_POLICY,
  P2_PROFILE_V2_WORKER_ATTESTATION_PIN_POLICY,
} from "../lib/p2-worker-attestation-policy.mjs";
import { canonicalizeProjectJson } from "../lib/project-control.mjs";
import { p2AcceptanceDigests } from "../lib/p2-acceptance-receipt-validator.mjs";

const execFileAsync = promisify(execFile);
const REPOSITORY_PATH = new URL("../", import.meta.url).pathname;
const BUILD_SCRIPT_PATH = new URL(
  "../scripts/build-p2-execution-baseline-attestation.mjs",
  import.meta.url,
).pathname;
const GENERATED_AT = "2026-08-13T08:10:00.000Z";
const SOURCE_COMMIT = "bc718bc1a069deaa388b9a00e0135c8e9427dd91";
const SOURCE_TREE = "2fa1d5a511215a78ce324b61c585a4d4bb9697e0";
const EXECUTION_BASELINE_DIGEST =
  "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec";
const SCHEMA_URL = new URL(
  "../implementation/p2/attestations/p2-execution-baseline-attestation.v1.schema.json",
  import.meta.url,
);
const ATTESTATION_URL = new URL(
  "../implementation/p2/attestations/p2-execution-baseline-attestation.bc718b.v1.json",
  import.meta.url,
);
const ATTESTATION_PATH =
  "implementation/p2/attestations/p2-execution-baseline-attestation.bc718b.v1.json";
const LEGACY_ATTESTATION_URL = new URL(
  "../implementation/p2/attestations/p2-execution-baseline-attestation.48a4e4.v1.json",
  import.meta.url,
);
const SUCCESSOR_ADR_PATH =
  "docs/adr/0024-p2-worker-attestation-pin-revision-supersession.md";
const RECIPE_PATH =
  "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json";

const LEGACY_START_POLICY = Object.freeze({
  protectedWorkPackages: Object.freeze(["O02", "O03"]),
  executionBaselineRecipe: Object.freeze({
    path: "implementation/p2/acceptance/p2-execution-baseline-recipe.v1.json",
    schemaVersion: "p2-execution-baseline-recipe.v1",
    sha256:
      "sha256:43289d9784888585ad427b723370e89debc3a67bf14e424b4bfb41e101bc37ef",
  }),
  profile: Object.freeze({
    path: "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
    schemaVersion: "p2-acceptance-profile.v2",
    sha256:
      "sha256:90a9741d6ae39012458f073523da0c7b4dc8e4eef53ea759b32d6640e6aaef32",
  }),
  receiptSchema: Object.freeze({
    path: "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
    version: "p2-acceptance-receipt.v2",
    sha256:
      "sha256:f995310688c620b24c42b058fb6305b00876e0dfa0b8a755f41f827bfcb700bf",
  }),
  validator: Object.freeze({
    path: "lib/p2-acceptance-receipt-validator.mjs",
    version: "p2-acceptance-validator.v2",
    sha256:
      "sha256:ae2b169b81f7769dfa952d0393b770e7a547f378989ab25a75ef62276f349200",
  }),
});

async function readJson(url) {
  return JSON.parse(await readFile(url, "utf8"));
}

function fixedBinding(overrides = {}) {
  return {
    executionBaselineDigest: EXECUTION_BASELINE_DIGEST,
    sourceCommit: SOURCE_COMMIT,
    policy: P2_V2_CANDIDATE_START_POLICY,
    ...overrides,
  };
}

async function trustedGit(repositoryPath, arguments_, options = {}) {
  return execFileAsync(
    "/usr/bin/git",
    ["--no-replace-objects", ...arguments_],
    {
      cwd: repositoryPath,
      encoding: "utf8",
      ...options,
    },
  );
}

async function cloneRepository(t) {
  const temporaryPath = await mkdtemp(
    join(tmpdir(), "p2-build-attestation-"),
  );
  const repositoryPath = join(temporaryPath, "repository");
  await execFileAsync(
    "/usr/bin/git",
    ["clone", "-q", "--no-hardlinks", REPOSITORY_PATH, repositoryPath],
    { encoding: "utf8" },
  );
  t.after(() => rm(temporaryPath, { recursive: true, force: true }));
  return repositoryPath;
}

function digestForSourceCommit(sourceCommit, subjects) {
  const [profile, receiptSchema, validator, fixture, toolLock] = subjects;
  return p2AcceptanceDigests.executionBaseline({
    schemaVersion: "p2-execution-baseline.v1",
    sourceCommit,
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
        version: toolLock.version,
        digest: toolLock.sha256,
      },
    ],
  });
}

async function commitDeletion(repositoryPath, path) {
  await trustedGit(repositoryPath, ["rm", "-q", "--", path]);
  return commitCurrentTree(repositoryPath, `remove ${path}`);
}

async function commitCurrentTree(repositoryPath, message) {
  await trustedGit(repositoryPath, ["add", "--all"]);
  await trustedGit(
    repositoryPath,
    [
      "-c",
      "user.name=P2 Attestation Test",
      "-c",
      "user.email=p2-attestation@example.invalid",
      "commit",
      "-q",
      "-m",
      message,
    ],
    {
      env: {
        ...process.env,
        GIT_AUTHOR_DATE: "2026-07-28T07:00:00Z",
        GIT_COMMITTER_DATE: "2026-07-28T07:00:00Z",
      },
    },
  );
  const sourceCommit = (
    await trustedGit(repositoryPath, ["rev-parse", "HEAD"])
  ).stdout.trim();
  const sourceTree = (
    await trustedGit(repositoryPath, [
      "show",
      "-s",
      "--format=%T",
      sourceCommit,
    ])
  ).stdout.trim();
  return { sourceCommit, sourceTree };
}

test("the build-time Git attestation binds the current fixed baseline", async () => {
  const attestation = await buildFrozenP2ExecutionBaselineAttestation({
    repositoryPath: REPOSITORY_PATH,
    generatedAt: GENERATED_AT,
  });

  assert.deepEqual(attestation, {
    schemaVersion: "p2-execution-baseline-attestation.v1",
    attestationId: "p2eba_bc718bc1a069_36cfdf3f36d5",
    predicateType:
      "urn:multi-enterprise-ai-platform:p2-execution-baseline-attestation:v1",
    canonicalization: "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785",
    source: {
      commit: SOURCE_COMMIT,
      tree: SOURCE_TREE,
      objectType: "commit",
    },
    executionBaseline: {
      recipePath:
        "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json",
      recipeSha256:
        "sha256:fa35085d2d18131920d932b3321fd77bc370c1d44cfb927feb91c34604c0c89e",
      digest: EXECUTION_BASELINE_DIGEST,
    },
    subjects: [
      {
        kind: "PROFILE",
        name: "p2-acceptance-profile-v2",
        path:
          "implementation/p2/acceptance/p2-acceptance-profile.v2.json",
        version: "p2-acceptance-profile.v2",
        sha256:
          "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5",
      },
      {
        kind: "SCHEMA",
        name: "p2-acceptance-receipt-v2-schema",
        path:
          "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
        version: "p2-acceptance-receipt.v2",
        sha256:
          "sha256:f995310688c620b24c42b058fb6305b00876e0dfa0b8a755f41f827bfcb700bf",
      },
      {
        kind: "VALIDATOR",
        name: "p2-acceptance-receipt-semantic-validator",
        path: "lib/p2-acceptance-receipt-validator.mjs",
        version: "p2-acceptance-validator.v2",
        sha256:
          "sha256:ff8da36988ace70213e58368b8b3894677e732e0c0e262f87ba8824fac6347a7",
      },
      {
        kind: "FIXTURE",
        name: "c06-synthetic-authorization-fixtures",
        path:
          "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
        version: "c06-authorization-fixtures-v1",
        sha256:
          "sha256:2c46d1c46eafaf5aebbfe7382cd16a9138a1c2cf142ca581ae101b254ebda130",
      },
      {
        kind: "TOOL_LOCK",
        name: "npm-package-lock",
        path: "package-lock.json",
        version: "3",
        sha256:
          "sha256:8a7e27bd052d9f6fa1371cc23c153ca40a5a6299a31bdc321169b4ebf68abdcf",
      },
    ],
    buildVerification: {
      method: "BUILD_TIME_LOCAL_GIT_OBJECT_READ",
      builderId:
        "multi-enterprise-ai-platform/p2-execution-baseline-attestation-builder",
      builderVersion: "1.0.0",
      result: "VERIFIED",
      verifiedAt: GENERATED_AT,
    },
    generatedAt: GENERATED_AT,
  });
  assert.deepEqual(attestation, await readJson(ATTESTATION_URL));
});

test("the build-time attestation rejects a nonexistent source commit", async () => {
  const build = createP2ExecutionBaselineAttestationBuilder({
    repositoryPath: REPOSITORY_PATH,
    expectedBaseline: {
      ...P2_BUILD_ATTESTATION_BASELINE,
      sourceCommit: "1111111111111111111111111111111111111111",
    },
  });

  await assert.rejects(
    build({ generatedAt: GENERATED_AT }),
    /sourceCommit must exist as a commit object/,
  );
});

test("the build-time attestation rejects a non-commit object", async () => {
  const build = createP2ExecutionBaselineAttestationBuilder({
    repositoryPath: REPOSITORY_PATH,
    expectedBaseline: {
      ...P2_BUILD_ATTESTATION_BASELINE,
      sourceCommit: SOURCE_TREE,
    },
  });

  await assert.rejects(
    build({ generatedAt: GENERATED_AT }),
    /sourceCommit must exist as a commit object/,
  );
});

test("the build-time attestation rejects the wrong source tree", async () => {
  const build = createP2ExecutionBaselineAttestationBuilder({
    repositoryPath: REPOSITORY_PATH,
    expectedBaseline: {
      ...P2_BUILD_ATTESTATION_BASELINE,
      sourceTree: "2222222222222222222222222222222222222222",
    },
  });

  await assert.rejects(
    build({ generatedAt: GENERATED_AT }),
    /sourceTree does not match sourceCommit/,
  );
});

test("the build-time attestation rejects changed Recipe bytes", async () => {
  const build = createP2ExecutionBaselineAttestationBuilder({
    repositoryPath: REPOSITORY_PATH,
    expectedBaseline: {
      ...P2_BUILD_ATTESTATION_BASELINE,
      recipeSha256: `sha256:${"3".repeat(64)}`,
    },
  });

  await assert.rejects(
    build({ generatedAt: GENERATED_AT }),
    /Recipe bytes do not match the frozen digest/,
  );
});

test("the build-time attestation rejects a Recipe absent from the source commit", async (t) => {
  const repositoryPath = await cloneRepository(t);
  const { sourceCommit, sourceTree } = await commitDeletion(
    repositoryPath,
    RECIPE_PATH,
  );
  const build = createP2ExecutionBaselineAttestationBuilder({
    repositoryPath,
    expectedBaseline: {
      ...P2_BUILD_ATTESTATION_BASELINE,
      sourceCommit,
      sourceTree,
      executionBaselineDigest: digestForSourceCommit(
        sourceCommit,
        P2_BUILD_ATTESTATION_BASELINE.subjects,
      ),
    },
  });

  await assert.rejects(
    build({ generatedAt: GENERATED_AT }),
    /Recipe is absent from sourceCommit/,
  );
});

test("the build-time attestation rejects changed subject bytes from the source commit", async (t) => {
  const repositoryPath = await cloneRepository(t);
  const changedSubject = P2_BUILD_ATTESTATION_BASELINE.subjects[3];
  await writeFile(
    join(repositoryPath, changedSubject.path),
    '{"changed":"source-commit-bytes"}\n',
  );
  const { sourceCommit, sourceTree } = await commitCurrentTree(
    repositoryPath,
    "change subject bytes",
  );
  const build = createP2ExecutionBaselineAttestationBuilder({
    repositoryPath,
    expectedBaseline: {
      ...P2_BUILD_ATTESTATION_BASELINE,
      sourceCommit,
      sourceTree,
      executionBaselineDigest: digestForSourceCommit(
        sourceCommit,
        P2_BUILD_ATTESTATION_BASELINE.subjects,
      ),
    },
  });

  await assert.rejects(
    build({ generatedAt: GENERATED_AT }),
    /A subject does not match its frozen digest/,
  );
});

test("the build-time attestation rejects a subject absent from the source commit", async (t) => {
  const repositoryPath = await cloneRepository(t);
  const missingSubject = P2_BUILD_ATTESTATION_BASELINE.subjects[3];
  const { sourceCommit, sourceTree } = await commitDeletion(
    repositoryPath,
    missingSubject.path,
  );
  const build = createP2ExecutionBaselineAttestationBuilder({
    repositoryPath,
    expectedBaseline: {
      ...P2_BUILD_ATTESTATION_BASELINE,
      sourceCommit,
      sourceTree,
      executionBaselineDigest: digestForSourceCommit(
        sourceCommit,
        P2_BUILD_ATTESTATION_BASELINE.subjects,
      ),
    },
  });

  await assert.rejects(
    build({ generatedAt: GENERATED_AT }),
    /A subject is absent from sourceCommit/,
  );
});

test("the build-time attestation rejects the wrong execution baseline digest", async () => {
  const build = createP2ExecutionBaselineAttestationBuilder({
    repositoryPath: REPOSITORY_PATH,
    expectedBaseline: {
      ...P2_BUILD_ATTESTATION_BASELINE,
      executionBaselineDigest: `sha256:${"5".repeat(64)}`,
    },
  });

  await assert.rejects(
    build({ generatedAt: GENERATED_AT }),
    /executionBaselineDigest does not match the Git subjects/,
  );
});

test("one explicit UTC time reproduces identical Attestation content", async () => {
  const first = await buildFrozenP2ExecutionBaselineAttestation({
    repositoryPath: REPOSITORY_PATH,
    generatedAt: GENERATED_AT,
  });
  const second = await buildFrozenP2ExecutionBaselineAttestation({
    repositoryPath: REPOSITORY_PATH,
    generatedAt: GENERATED_AT,
  });

  assert.deepEqual(second, first);
});

test("modified working-tree files cannot replace source-commit bytes", async (t) => {
  const repositoryPath = await cloneRepository(t);
  await writeFile(
    join(
      repositoryPath,
      P2_BUILD_ATTESTATION_BASELINE.subjects[0].path,
    ),
    '{"forged":"working-tree-only"}\n',
  );

  const actual = await buildFrozenP2ExecutionBaselineAttestation({
    repositoryPath,
    generatedAt: GENERATED_AT,
  });

  assert.deepEqual(actual, await readJson(ATTESTATION_URL));
});

test("ambient PATH cannot replace the trusted Git executable", async (t) => {
  const fakeBin = await mkdtemp(join(tmpdir(), "p2-attestation-fake-git-"));
  const fakeGit = join(fakeBin, "git");
  await writeFile(
    fakeGit,
    "#!/bin/sh\nprintf 'forged git was invoked\\n' >&2\nexit 97\n",
  );
  await chmod(fakeGit, 0o755);
  t.after(() => rm(fakeBin, { recursive: true, force: true }));
  const previousPath = process.env.PATH;
  process.env.PATH = fakeBin;
  t.after(() => {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
  });

  const actual = await buildFrozenP2ExecutionBaselineAttestation({
    repositoryPath: REPOSITORY_PATH,
    generatedAt: GENERATED_AT,
  });

  assert.deepEqual(actual, await readJson(ATTESTATION_URL));
});

test("the build-time attestation requires an explicit canonical UTC time", async () => {
  await assert.rejects(
    buildFrozenP2ExecutionBaselineAttestation({
      repositoryPath: REPOSITORY_PATH,
    }),
    /explicit canonical UTC instant/,
  );
});

test("the build-time attestation rejects a nonexistent canonical UTC calendar date", async () => {
  await assert.rejects(
    buildFrozenP2ExecutionBaselineAttestation({
      repositoryPath: REPOSITORY_PATH,
      generatedAt: "2026-09-31T08:07:06.000Z",
    }),
    /explicit canonical UTC instant/,
  );
});

test("the build CLI requires an explicit canonical UTC time", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [
      BUILD_SCRIPT_PATH,
      "--repository-path",
      REPOSITORY_PATH,
    ]),
    (error) => {
      assert.match(error.stderr, /--generated-at is required/);
      return true;
    },
  );
});

test("the build CLI reproduces the frozen Attestation and rejects baseline overrides", async () => {
  const arguments_ = [
    BUILD_SCRIPT_PATH,
    "--generated-at",
    GENERATED_AT,
    "--repository-path",
    REPOSITORY_PATH,
  ];
  const first = await execFileAsync(process.execPath, arguments_);
  const second = await execFileAsync(process.execPath, arguments_);

  assert.deepEqual(JSON.parse(first.stdout), await readJson(ATTESTATION_URL));
  assert.equal(second.stdout, first.stdout);
  await assert.rejects(
    execFileAsync(process.execPath, [
      ...arguments_,
      "--source-commit",
      "1111111111111111111111111111111111111111",
    ]),
    (error) => {
      assert.match(error.stderr, /Only --generated-at/);
      return true;
    },
  );
});

test("the frozen Attestation satisfies its closed JSON Schema", async () => {
  const [schema, attestation] = await Promise.all([
    readJson(SCHEMA_URL),
    readJson(ATTESTATION_URL),
  ]);
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);

  assert.equal(validate(attestation), true, JSON.stringify(validate.errors));
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.source.additionalProperties, false);
  assert.equal(
    schema.properties.executionBaseline.additionalProperties,
    false,
  );
  assert.equal(
    schema.properties.buildVerification.additionalProperties,
    false,
  );
  for (const subject of schema.properties.subjects.prefixItems) {
    assert.equal(subject.additionalProperties, false);
  }
});

test("the Worker default verifier accepts only the frozen execution baseline binding", async () => {
  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation(fixedBinding()),
    true,
  );
});

test("the closed Schema rejects unknown, missing, duplicate, reordered and extra subjects", async () => {
  const [schema, attestation] = await Promise.all([
    readJson(SCHEMA_URL),
    readJson(ATTESTATION_URL),
  ]);
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  const cases = [];

  const unknown = structuredClone(attestation);
  unknown.unexpected = true;
  cases.push(unknown);

  for (const mutate of [
    (value) => {
      value.source.unexpected = true;
    },
    (value) => {
      value.executionBaseline.unexpected = true;
    },
    (value) => {
      value.subjects[0].unexpected = true;
    },
    (value) => {
      value.buildVerification.unexpected = true;
    },
  ]) {
    const nestedUnknown = structuredClone(attestation);
    mutate(nestedUnknown);
    cases.push(nestedUnknown);
  }

  const missing = structuredClone(attestation);
  missing.subjects.pop();
  cases.push(missing);

  const duplicate = structuredClone(attestation);
  duplicate.subjects[1] = structuredClone(duplicate.subjects[0]);
  cases.push(duplicate);

  const reordered = structuredClone(attestation);
  [reordered.subjects[0], reordered.subjects[1]] = [
    reordered.subjects[1],
    reordered.subjects[0],
  ];
  cases.push(reordered);

  const extra = structuredClone(attestation);
  extra.subjects.push(structuredClone(extra.subjects.at(-1)));
  cases.push(extra);

  for (const value of cases) {
    assert.equal(validate(value), false);
  }
});

test("the Attestation pin revisions remain replayable and cannot be crossed", async () => {
  const [attestation, legacyAttestation] = await Promise.all([
    readJson(ATTESTATION_URL),
    readJson(LEGACY_ATTESTATION_URL),
  ]);
  const actual = `sha256:${createHash("sha256")
    .update(canonicalizeProjectJson(attestation))
    .digest("hex")}`;
  const legacyActual = `sha256:${createHash("sha256")
    .update(canonicalizeProjectJson(legacyAttestation))
    .digest("hex")}`;

  assert.equal(
    actual,
    "sha256:83f63243386d179cf3facc59e24eb7bcbcfb7e7960f42d8d38c7d83aef787220",
  );
  assert.equal(
    legacyActual,
    "sha256:46fe858b866f16a97c9a9e0d10dc604412feceed85e03201da7ed75c7a85f298",
  );
  assert.equal(
    P2_PROFILE_V2_WORKER_ATTESTATION_PIN_POLICY.attestationSha256,
    actual,
  );
  assert.equal(
    P2_LEGACY_WORKER_ATTESTATION_PIN_POLICY.attestationSha256,
    legacyActual,
  );
  assert.equal(
    P2_WORKER_ATTESTATION_PIN_POLICY,
    P2_PROFILE_V2_WORKER_ATTESTATION_PIN_POLICY,
  );

  const verifyLegacy = createP2WorkerAttestationVerifier({
    attestation: legacyAttestation,
    pinPolicy: P2_LEGACY_WORKER_ATTESTATION_PIN_POLICY,
    startPolicy: LEGACY_START_POLICY,
  });
  assert.equal(
    await verifyLegacy({
      sourceCommit: legacyAttestation.source.commit,
      executionBaselineDigest: legacyAttestation.executionBaseline.digest,
      policy: LEGACY_START_POLICY,
    }),
    true,
  );

  for (const assets of [
    {
      attestation,
      pinPolicy: P2_LEGACY_WORKER_ATTESTATION_PIN_POLICY,
    },
    {
      attestation: legacyAttestation,
      pinPolicy: P2_PROFILE_V2_WORKER_ATTESTATION_PIN_POLICY,
    },
  ]) {
    const verify = createP2WorkerAttestationVerifier(assets);
    assert.equal(await verify(fixedBinding()), false);
  }
});

test("the Worker verifier fails closed for Attestation, pin and canonicalization tampering", async () => {
  const attestation = await readJson(ATTESTATION_URL);
  const mutations = [
    {
      attestation: { ...attestation, unexpected: true },
      pinPolicy: P2_WORKER_ATTESTATION_PIN_POLICY,
    },
    {
      attestation,
      pinPolicy: {
        ...P2_WORKER_ATTESTATION_PIN_POLICY,
        attestationSha256: `sha256:${"6".repeat(64)}`,
      },
    },
    {
      attestation: {
        ...attestation,
        canonicalization: "RFC8785",
      },
      pinPolicy: P2_WORKER_ATTESTATION_PIN_POLICY,
    },
  ];

  for (const assets of mutations) {
    const verify = createP2WorkerAttestationVerifier(assets);
    assert.equal(await verify(fixedBinding()), false);
  }
});

test("the Worker verifier rejects a nonexistent canonical UTC calendar date even with a matching test pin", async () => {
  const attestation = await readJson(ATTESTATION_URL);
  attestation.buildVerification.verifiedAt =
    "2026-09-31T08:07:06.000Z";
  attestation.generatedAt = "2026-09-31T08:07:06.000Z";
  const pinPolicy = {
    ...P2_WORKER_ATTESTATION_PIN_POLICY,
    attestationSha256: `sha256:${createHash("sha256")
      .update(canonicalizeProjectJson(attestation))
      .digest("hex")}`,
  };
  const verify = createP2WorkerAttestationVerifier({
    attestation,
    pinPolicy,
  });

  assert.equal(await verify(fixedBinding()), false);
});

test("the Worker verifier rejects fixed source tree, Profile, Schema and Validator mismatches", async () => {
  const attestation = await readJson(ATTESTATION_URL);
  const mutations = [
    (value) => {
      value.source.commit = "a".repeat(40);
    },
    (value) => {
      value.source.tree = "b".repeat(40);
    },
    (value) => {
      value.subjects[0].sha256 = `sha256:${"c".repeat(64)}`;
    },
    (value) => {
      value.subjects[1].sha256 = `sha256:${"d".repeat(64)}`;
    },
    (value) => {
      value.subjects[2].sha256 = `sha256:${"e".repeat(64)}`;
    },
  ];

  for (const mutate of mutations) {
    const changed = structuredClone(attestation);
    mutate(changed);
    const verify = createP2WorkerAttestationVerifier({
      attestation: changed,
      pinPolicy: P2_WORKER_ATTESTATION_PIN_POLICY,
    });
    assert.equal(await verify(fixedBinding()), false);
  }
});

test("the Worker default verifier rejects source, digest and P2 policy mismatches", async () => {
  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation(
      fixedBinding({
        sourceCommit: "7777777777777777777777777777777777777777",
      }),
    ),
    false,
  );
  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation(
      fixedBinding({
        executionBaselineDigest: `sha256:${"8".repeat(64)}`,
      }),
    ),
    false,
  );
  for (const key of ["profile", "receiptSchema", "validator"]) {
    const policy = structuredClone(P2_V2_CANDIDATE_START_POLICY);
    policy[key].sha256 = `sha256:${"9".repeat(64)}`;
    assert.equal(
      await verifyP2ExecutionBaselineFromBuildAttestation(
        fixedBinding({ policy }),
      ),
      false,
    );
  }
  const policyMutations = [
    (policy) => {
      policy.protectedWorkPackages = ["X99"];
    },
    (policy) => {
      delete policy.protectedWorkPackages;
    },
    (policy) => {
      policy.unexpected = true;
    },
    (policy) => {
      policy.profile.unexpected = true;
    },
  ];
  for (const mutate of policyMutations) {
    const policy = structuredClone(P2_V2_CANDIDATE_START_POLICY);
    mutate(policy);
    assert.equal(
      await verifyP2ExecutionBaselineFromBuildAttestation(
        fixedBinding({ policy }),
      ),
      false,
    );
  }
});

test("the Worker default verifier does not accept caller-supplied proof replacements", async () => {
  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation({
      ...fixedBinding(),
      attestation: await readJson(ATTESTATION_URL),
    }),
    false,
  );
  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation({
      ...fixedBinding(),
      pinPolicy: P2_WORKER_ATTESTATION_PIN_POLICY,
    }),
    false,
  );
  for (const field of ["builder", "sourceTree", "subjects"]) {
    assert.equal(
      await verifyP2ExecutionBaselineFromBuildAttestation({
        ...fixedBinding(),
        [field]: "caller-supplied",
      }),
      false,
    );
  }
});

test("the Worker verifier dependency closure has no Node, Git, network, environment or Token dependency", async () => {
  const moduleUrls = [
    new URL("../lib/p2-worker-attestation-verifier.mjs", import.meta.url),
    new URL("../lib/p2-worker-attestation-policy.mjs", import.meta.url),
    new URL("../lib/project-control.mjs", import.meta.url),
    new URL("../lib/p2-start-authorization.mjs", import.meta.url),
  ];
  const forbidden = [
    /\bfrom\s+["']node:/u,
    /\bimport\s*\(\s*["']node:/u,
    /\/usr\/bin\/git/u,
    /\bfetch\s*\(/u,
    /\bXMLHttpRequest\b/u,
    /\bWebSocket\b/u,
    /\bGitHub\b/iu,
    /\bprocess\.env\b/u,
    /\brequest\.headers?\b/iu,
    /\bheaders?\.get\s*\(/iu,
    /\bTOKEN\b/iu,
  ];

  for (const url of moduleUrls) {
    const source = await readFile(url, "utf8");
    for (const pattern of forbidden) {
      assert.doesNotMatch(source, pattern, `${url.pathname}: ${pattern}`);
    }
  }
});

test("the Attestation contains evidence only, not governance state or its own pin", async () => {
  const attestation = await readJson(ATTESTATION_URL);
  const keys = new Set();
  const visit = (value) => {
    if (Array.isArray(value)) {
      for (const child of value) visit(child);
    } else if (value && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) {
        keys.add(key);
        visit(child);
      }
    }
  };
  visit(attestation);

  for (const forbiddenKey of [
    "attestationSha256",
    "revision",
    "gate",
    "gates",
    "profileApproval",
    "profileApprovalStatus",
    "workPackages",
    "startAuthorization",
    "O02",
    "O03",
  ]) {
    assert.equal(keys.has(forbiddenKey), false);
  }
  const canonical = canonicalizeProjectJson(attestation);
  for (const forbiddenValue of [
    "P2_ACCEPTANCE_PROFILE_APPROVED",
    "P2_WORK_PACKAGE_START_AUTHORIZED",
    "GateSubmission",
    "GateDecision",
  ]) {
    assert.equal(canonical.includes(forbiddenValue), false);
  }
});

test("the source commit predates its pin revision while preserving the original ADR and pin lineage", async () => {
  for (const path of [ATTESTATION_PATH, SUCCESSOR_ADR_PATH]) {
    await assert.rejects(
      trustedGit(REPOSITORY_PATH, [
        "cat-file",
        "-e",
        `${SOURCE_COMMIT}:${path}`,
      ]),
    );
  }

  const originalAdrPath =
    "docs/adr/0005-worker-verifies-build-time-git-attestation.md";
  const originalPinPath = "lib/p2-worker-attestation-policy.mjs";
  const [{ stdout: originalAdr }, { stdout: originalPin }] = await Promise.all([
    trustedGit(REPOSITORY_PATH, [
      "cat-file",
      "blob",
      `${SOURCE_COMMIT}:${originalAdrPath}`,
    ]),
    trustedGit(REPOSITORY_PATH, [
      "cat-file",
      "blob",
      `${SOURCE_COMMIT}:${originalPinPath}`,
    ]),
  ]);
  assert.equal(
    createHash("sha256").update(originalAdr).digest("hex"),
    "f16661f933a17b8b8d1f0bfed6356b1342423b2a83cccc9652b300f487092fc6",
  );
  assert.equal(
    createHash("sha256").update(originalPin).digest("hex"),
    "32579a767eda9923c04c96f7f951520770e5d31bdcad355869343add1e9c8bfc",
  );
  assert.deepEqual(
    await readFile(new URL(`../${originalAdrPath}`, import.meta.url)),
    Buffer.from(originalAdr),
  );
  const successorAdr = await readFile(
    new URL(`../${SUCCESSOR_ADR_PATH}`, import.meta.url),
    "utf8",
  );
  assert.match(
    successorAdr,
    /does not satisfy or alter the Reference Review hard gate/u,
  );
  assert.match(
    successorAdr,
    /advance\s+P3 or authorize production/u,
  );
});
