import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  deriveIndependentReviewProbeResults,
  sha256RuntimeValue,
} from "../lib/independent-review-runtime-evidence.mjs";
import {
  collectIndependentReviewControlPlaneEvidence,
  validateIndependentModelRuntimeEvidence,
} from "../scripts/run-independent-review-control-plane.mjs";

const execFileAsync = promisify(execFile);
const root = resolve(new URL("../", import.meta.url).pathname);
const CONTROL_PLANE_PATH = "scripts/run-independent-review-control-plane.mjs";
const VALIDATOR_PATH = "lib/independent-review-runtime-evidence.mjs";
const SANDBOX_PATH =
  "implementation/governance/independent-review/macos-independent-review-readonly.sb.in";
const RUNTIME_SCHEMA_PATH =
  "implementation/governance/schemas/independent-model-runtime-evidence.v2.schema.json";
const TEST_SCHEMA_PATH =
  "implementation/governance/schemas/independent-review-test-result.v2.schema.json";
const PROMPT_PATH =
  "implementation/governance/independent-review/independent-model-review-prompt.v2.md";
const OUTPUT_SCHEMA_PATH =
  "implementation/governance/schemas/independent-model-review-output.v2.schema.json";
const TEST_COLLECTOR_PATH =
  "scripts/run-independent-review-test-evidence.mjs";
const PROTECTED_PATHS = Object.freeze([OUTPUT_SCHEMA_PATH, PROMPT_PATH].sort());
const nestedSandboxUnavailable =
  process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
  "DENY_ALL_OFFLINE_ALTERNATIVES";
const NESTED_SANDBOX_REASON_CODES = Object.freeze([
  "NESTED_SEATBELT_UNAVAILABLE",
]);

const hashBytes = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

async function git(repo, args) {
  const { stdout } = await execFileAsync("/usr/bin/git", ["-C", repo, ...args], {
    encoding: "utf8",
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_SYSTEM: "/dev/null",
      GIT_CONFIG_GLOBAL: "/dev/null",
      ...(process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
        "DENY_ALL_OFFLINE_ALTERNATIVES" &&
      typeof process.env.xcrun_db === "string"
        ? { xcrun_db: process.env.xcrun_db }
        : {}),
    },
  });
  return stdout.trim();
}

async function copy(repo, path) {
  const destination = join(repo, path);
  await mkdir(dirname(destination), { recursive: true });
  await cp(join(root, path), destination);
}

async function fixture() {
  const parent = await mkdtemp(join(tmpdir(), "zb-review-control-plane-"));
  const repo = join(parent, "repo");
  const evidenceRoot = join(parent, "evidence");
  const bundlePath = join(parent, "review-bundle.json");
  await mkdir(repo);
  await Promise.all(
    [
      CONTROL_PLANE_PATH,
      VALIDATOR_PATH,
      SANDBOX_PATH,
      RUNTIME_SCHEMA_PATH,
      TEST_SCHEMA_PATH,
      PROMPT_PATH,
      OUTPUT_SCHEMA_PATH,
      TEST_COLLECTOR_PATH,
    ].map((path) => copy(repo, path)),
  );
  await writeFile(
    bundlePath,
    `${JSON.stringify({
      schemaVersion: "independent-review-bundle.v2",
      fixture: "exact-read-only",
      repositoryProtection: {
        protectedPaths: PROTECTED_PATHS,
        protectedPathSetSha256: sha256RuntimeValue(PROTECTED_PATHS),
      },
    })}\n`,
    "utf8",
  );
  await git(repo, ["init", "-q"]);
  await git(repo, ["config", "user.name", "Fixture"]);
  await git(repo, ["config", "user.email", "fixture@example.invalid"]);
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-qm", "fixture"]);
  const sourceCommit = await git(repo, ["rev-parse", "HEAD"]);
  const sourceTree = await git(repo, ["rev-parse", "HEAD^{tree}"]);
  return {
    parent,
    repo,
    evidenceRoot,
    bundlePath,
    sourceCommit,
    sourceTree,
  };
}

async function collect(current) {
  return collectIndependentReviewControlPlaneEvidence({
    repoPath: current.repo,
    sourceCommit: current.sourceCommit,
    sourceTree: current.sourceTree,
    reviewBundlePath: current.bundlePath,
    reviewerPromptPath: PROMPT_PATH,
    outputSchemaPath: OUTPUT_SCHEMA_PATH,
    testEvidenceCollectorPath: TEST_COLLECTOR_PATH,
    sandboxTemplatePath: SANDBOX_PATH,
    controlPlanePath: CONTROL_PLANE_PATH,
    runtimeValidatorPath: VALIDATOR_PATH,
    evidenceRoot: current.evidenceRoot,
  });
}

test("runtime evidence schemas are closed and compile under JSON Schema 2020-12", async () => {
  const [runtimeSchema, testResultSchema] = await Promise.all([
    readFile(join(root, RUNTIME_SCHEMA_PATH), "utf8").then(JSON.parse),
    readFile(join(root, TEST_SCHEMA_PATH), "utf8").then(JSON.parse),
  ]);
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    validateFormats: true,
  });
  addFormats(ajv);
  assert.equal(ajv.compile(runtimeSchema).schema.$id, runtimeSchema.$id);
  assert.equal(
    ajv.compile(testResultSchema).schema.$id,
    testResultSchema.$id,
  );
  assert.equal(runtimeSchema.additionalProperties, false);
  assert.equal(testResultSchema.additionalProperties, false);
});

test(
  "frozen local control plane derives all twelve read-only probes from raw observations",
  {
    skip: process.platform !== "darwin" || nestedSandboxUnavailable,
    timeout: 30_000,
  },
  async (t) => {
    const current = await fixture();
    t.after(() => rm(current.parent, { recursive: true, force: true }));
    const beforeStatus = await git(current.repo, ["status", "--porcelain=v1"]);

    const evidence = await collect(current);
    const runtimeSchema = JSON.parse(
      await readFile(join(root, RUNTIME_SCHEMA_PATH), "utf8"),
    );
    const runtimeAjv = new Ajv2020({
      strict: true,
      allErrors: true,
      validateFormats: true,
    });
    addFormats(runtimeAjv);
    const validateRuntimeEvidence = runtimeAjv.compile(runtimeSchema);
    assert.equal(
      validateRuntimeEvidence(evidence),
      true,
      JSON.stringify(validateRuntimeEvidence.errors),
    );
    const result = await validateIndependentModelRuntimeEvidence({
      evidence,
      expectedBindings: {
        sourceCommit: current.sourceCommit,
        sourceTree: current.sourceTree,
        reviewBundleSha256: hashBytes(await readFile(current.bundlePath)),
        reviewerPromptSha256: hashBytes(
          await readFile(join(current.repo, PROMPT_PATH)),
        ),
        outputSchemaSha256: hashBytes(
          await readFile(join(current.repo, OUTPUT_SCHEMA_PATH)),
        ),
        protectedPathSetSha256: sha256RuntimeValue(PROTECTED_PATHS),
      },
      evidenceRoot: current.evidenceRoot,
    });

    assert.equal(result.valid, true, JSON.stringify(result));
    assert.equal(result.assuranceClaim, "LOCAL_CONTROL_PLANE_OBSERVED_OS_ENFORCEMENT");
    assert.equal(result.formalReviewCompleted, false);
    assert.equal(evidence.reviewerInvocation.state, "NOT_INVOKED_PROBE_ONLY");
    assert.deepEqual(evidence.reviewerInvocation.declaredModelTools, []);
    assert.equal(evidence.isolationProbeResults.allPassed, true);
    assert.equal(evidence.isolationProbeResults.results.length, 12);
    assert.deepEqual(
      evidence.isolationProbeResults.results.map(({ probeId }) => probeId).sort(),
      [
        "APPLY_PATCH_DENIED",
        "BINDING_MISMATCH_FAIL_CLOSED",
        "CREATE_FILE_DENIED",
        "DELETE_FILE_DENIED",
        "D1_SITES_GOVERNANCE_WRITE_UNAVAILABLE",
        "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
        "MODIFY_FILE_DENIED",
        "MODEL_READ_OUTSIDE_BUNDLE_UNAVAILABLE",
        "MOVE_RENAME_DENIED",
        "REPOSITORY_UNCHANGED",
        "REVIEW_BUNDLE_EXACT_READ_ONLY",
        "SANITIZED_ENVIRONMENT_CREDENTIAL_NAMES_ABSENT",
      ].sort(),
    );
    assert.deepEqual(
      evidence.repositoryUnchangedBeforeAfter.before.protectedFiles.map(
        ({ path }) => path,
      ),
      PROTECTED_PATHS,
    );
    assert.equal(
      evidence.repositoryUnchangedBeforeAfter.unchanged,
      true,
    );
    assert.equal(
      await git(current.repo, ["status", "--porcelain=v1"]),
      beforeStatus,
    );
  },
);

test(
  "formal outer Seatbelt records nested control-plane unavailability as one infrastructure failure",
  {
    skip:
      process.platform !== "darwin" || !nestedSandboxUnavailable,
    timeout: 30_000,
  },
  async (t) => {
    const current = await fixture();
    t.after(() => rm(current.parent, { recursive: true, force: true }));
    const beforeStatus = await git(current.repo, ["status", "--porcelain=v1"]);

    await assert.rejects(
      collect(current),
      (error) => {
        assert.deepEqual(error.reasonCodes, NESTED_SANDBOX_REASON_CODES);
        return true;
      },
    );
    assert.equal(
      await git(current.repo, ["status", "--porcelain=v1"]),
      beforeStatus,
    );
  },
);

test("sandbox reads are deny-first and the outside canary is not path-special-cased", async () => {
  const template = await readFile(
    join(
      root,
      "implementation/governance/independent-review/macos-independent-review-readonly.sb.in",
    ),
    "utf8",
  );

  assert.match(template, /\(deny default\)/u);
  assert.equal(template.includes("(allow default)"), false);
  assert.equal(template.includes("@@OUTSIDE_ROOT@@"), false);
  assert.match(
    template,
    /\(allow file-read\*[\s\S]*@@NODE_DIR@@[\s\S]*@@REVIEW_ROOT@@/u,
  );
});

test("a failed nested sandbox application cannot impersonate an operation-level denial", async (t) => {
  const evidenceRoot = await mkdtemp(
    join(tmpdir(), "zb-nested-sandbox-observation-"),
  );
  t.after(() => rm(evidenceRoot, { recursive: true, force: true }));
  const stdout = Buffer.alloc(0);
  const stderr = Buffer.from(
    "sandbox-exec: sandbox_apply: Operation not permitted\n",
    "utf8",
  );
  await Promise.all([
    writeFile(join(evidenceRoot, "stdout"), stdout),
    writeFile(join(evidenceRoot, "stderr"), stderr),
  ]);
  const results = await deriveIndependentReviewProbeResults({
    evidence: {
      repositoryUnchangedBeforeAfter: {
        before: {},
        after: {},
        unchanged: true,
      },
      observations: [
        {
          probeId: "CREATE_FILE_DENIED",
          operation: "CREATE_FILE_ATTEMPT",
          attempted: true,
          exitCode: 1,
          signal: null,
          timedOut: false,
          stdoutRef: "stdout",
          stdoutSha256: hashBytes(stdout),
          stdoutByteLength: stdout.byteLength,
          stderrRef: "stderr",
          stderrSha256: hashBytes(stderr),
          stderrByteLength: stderr.byteLength,
        },
      ],
    },
    evidenceRoot,
  });
  assert.equal(
    results.find(({ probeId }) => probeId === "CREATE_FILE_DENIED").status,
    "FAIL",
  );
});

test(
  "protected paths come from the exact Bundle and a forged set digest fails closed",
  { skip: process.platform !== "darwin", timeout: 30_000 },
  async (t) => {
    const current = await fixture();
    t.after(() => rm(current.parent, { recursive: true, force: true }));
    const bundle = JSON.parse(await readFile(current.bundlePath, "utf8"));
    bundle.repositoryProtection.protectedPathSetSha256 = hashBytes(
      Buffer.from("forged protected path set", "utf8"),
    );
    await writeFile(current.bundlePath, `${JSON.stringify(bundle)}\n`, "utf8");

    await assert.rejects(
      collect(current),
      /protected path set|Bundle protection/u,
    );
  },
);

test(
  "a caller-authored PASS cannot override a raw observation that did not show OS denial",
  {
    skip: process.platform !== "darwin" || nestedSandboxUnavailable,
    timeout: 30_000,
  },
  async (t) => {
    const current = await fixture();
    t.after(() => rm(current.parent, { recursive: true, force: true }));
    const evidence = await collect(current);
    const createObservation = evidence.observations.find(
      ({ probeId }) => probeId === "CREATE_FILE_DENIED",
    );
    createObservation.exitCode = 0;
    createObservation.stderrSha256 = hashBytes(Buffer.alloc(0));
    createObservation.stderrByteLength = 0;
    evidence.isolationProbeResults.results.find(
      ({ probeId }) => probeId === "CREATE_FILE_DENIED",
    ).status = "PASS";

    const result = await validateIndependentModelRuntimeEvidence({
      evidence,
      expectedBindings: {
        sourceCommit: current.sourceCommit,
        sourceTree: current.sourceTree,
        reviewBundleSha256: evidence.bindings.reviewBundle.sha256,
        reviewerPromptSha256: evidence.bindings.reviewerPrompt.sha256,
        outputSchemaSha256: evidence.bindings.outputSchema.sha256,
        protectedPathSetSha256:
          evidence.repositoryUnchangedBeforeAfter.protectedPathSetSha256,
      },
      evidenceRoot: current.evidenceRoot,
    });

    assert.equal(result.valid, false);
    assert.ok(result.reasonCodes.includes("RUNTIME_EVIDENCE_SELF_HASH_MISMATCH"));
    assert.ok(result.reasonCodes.includes("CREATE_FILE_DENIAL_NOT_OBSERVED"));
  },
);

test(
  "tampered raw evidence and binding drift fail closed",
  {
    skip: process.platform !== "darwin" || nestedSandboxUnavailable,
    timeout: 30_000,
  },
  async (t) => {
    const current = await fixture();
    t.after(() => rm(current.parent, { recursive: true, force: true }));
    const evidence = await collect(current);
    const observation = evidence.observations[0];
    await writeFile(
      join(current.evidenceRoot, observation.stdoutRef),
      "tampered\n",
      "utf8",
    );

    const result = await validateIndependentModelRuntimeEvidence({
      evidence,
      expectedBindings: {
        sourceCommit: "f".repeat(40),
        sourceTree: current.sourceTree,
        reviewBundleSha256: evidence.bindings.reviewBundle.sha256,
        reviewerPromptSha256: evidence.bindings.reviewerPrompt.sha256,
        outputSchemaSha256: evidence.bindings.outputSchema.sha256,
        protectedPathSetSha256:
          evidence.repositoryUnchangedBeforeAfter.protectedPathSetSha256,
      },
      evidenceRoot: current.evidenceRoot,
    });

    assert.equal(result.valid, false);
    assert.ok(result.reasonCodes.includes("RUNTIME_SOURCE_COMMIT_MISMATCH"));
    assert.ok(result.reasonCodes.includes("RUNTIME_OBSERVATION_BYTES_MISMATCH"));
  },
);

test(
  "a protected byte change cannot hide behind an unchanged dirty status",
  {
    skip: process.platform !== "darwin" || nestedSandboxUnavailable,
    timeout: 30_000,
  },
  async (t) => {
    const current = await fixture();
    t.after(() => rm(current.parent, { recursive: true, force: true }));
    const evidence = await collect(current);
    evidence.repositoryUnchangedBeforeAfter.after.protectedFiles[0].sha256 =
      hashBytes(Buffer.from("changed protected bytes", "utf8"));
    evidence.evidenceSha256 = sha256RuntimeValue(
      Object.fromEntries(
        Object.entries(evidence).filter(
          ([key]) => key !== "evidenceSha256",
        ),
      ),
    );

    const result = await validateIndependentModelRuntimeEvidence({
      evidence,
      expectedBindings: {
        sourceCommit: current.sourceCommit,
        sourceTree: current.sourceTree,
        reviewBundleSha256: evidence.bindings.reviewBundle.sha256,
        reviewerPromptSha256: evidence.bindings.reviewerPrompt.sha256,
        outputSchemaSha256: evidence.bindings.outputSchema.sha256,
        protectedPathSetSha256:
          evidence.repositoryUnchangedBeforeAfter.protectedPathSetSha256,
      },
      evidenceRoot: current.evidenceRoot,
    });

    assert.equal(result.valid, false);
    assert.ok(result.reasonCodes.includes("RUNTIME_REPOSITORY_CHANGED"));
    assert.ok(result.reasonCodes.includes("REPOSITORY_UNCHANGED_NOT_PROVED"));
  },
);

test("control plane contains no model invocation or network client", async () => {
  const source = await readFile(join(root, CONTROL_PLANE_PATH), "utf8");
  for (const forbidden of [
    "fetch(",
    "node:http",
    "node:https",
    "node:net",
    "node:dns",
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});
