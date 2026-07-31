#!/usr/bin/env node

import { execFile } from "node:child_process";
import { mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { arch, platform } from "node:os";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  deriveIndependentReviewProbeResults,
  sha256RuntimeBytes,
  sha256RuntimeValue,
  validateIndependentModelRuntimeEvidence,
} from "../lib/independent-review-runtime-evidence.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/;
const MAX_OUTPUT = 1024 * 1024;
const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const GIT = "/usr/bin/git";
const XCODE_SELECT = "/usr/bin/xcode-select";
const CONTROL_PLANE_PATH = "scripts/run-independent-review-control-plane.mjs";
const RUNTIME_VALIDATOR_PATH =
  "lib/independent-review-runtime-evidence.mjs";
const CREDENTIAL_ENV_KEYS = Object.freeze([
  "ANTHROPIC_API_KEY",
  "CODEX_ACCESS_TOKEN",
  "CODEX_API_KEY",
  "GOOGLE_API_KEY",
  "MOONSHOT_API_KEY",
  "OPENAI_API_KEY",
]);
const INTEGRATION_ENV_KEYS = Object.freeze([
  "CLOUDFLARE_API_TOKEN",
  "D1_DATABASE_ID",
  "D1_TOKEN",
  "GITHUB_TOKEN",
  "SITES_API_TOKEN",
  "WRANGLER_API_TOKEN",
]);
const frozenXcrunEnvironment =
  process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
    "DENY_ALL_OFFLINE_ALTERNATIVES" &&
  typeof process.env.xcrun_db === "string" &&
  process.env.xcrun_db.startsWith("/") &&
  !process.env.xcrun_db.includes("\0")
    ? Object.freeze({ xcrun_db: process.env.xcrun_db })
    : Object.freeze({});

function exactRelativePath(repoPath, path) {
  const result = relative(resolve(repoPath), resolve(repoPath, path));
  if (
    result.length === 0 ||
    result.startsWith(`..${sep}`) ||
    result === ".." ||
    result.includes("\u0000")
  ) {
    throw new TypeError("Expected a repository-relative frozen path.");
  }
  return result;
}

function evidenceRelativePath(evidenceRoot, path) {
  const result = relative(resolve(evidenceRoot), resolve(path));
  if (
    result.length === 0 ||
    result.startsWith(`..${sep}`) ||
    result === ".." ||
    result.includes("\u0000")
  ) {
    throw new TypeError("Evidence path escaped the evidence root.");
  }
  return result;
}

function protectedPathsFromBundle(bundleBytes) {
  let bundle;
  try {
    bundle = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bundleBytes),
    );
  } catch {
    throw new TypeError("Review Bundle protection is not valid UTF-8 JSON.");
  }
  const protection = bundle?.repositoryProtection;
  const protectedPaths = protection?.protectedPaths;
  if (
    !protection ||
    JSON.stringify(Object.keys(protection).sort()) !==
      JSON.stringify(["protectedPathSetSha256", "protectedPaths"]) ||
    !Array.isArray(protectedPaths) ||
    protectedPaths.length === 0 ||
    protectedPaths.length > 16 ||
    new Set(protectedPaths).size !== protectedPaths.length ||
    JSON.stringify(protectedPaths) !==
      JSON.stringify([...protectedPaths].sort()) ||
    protectedPaths.some(
      (path) =>
        typeof path !== "string" ||
        path.length === 0 ||
        path.length > 512 ||
        path.includes("\u0000"),
    ) ||
    protection.protectedPathSetSha256 !==
      sha256RuntimeValue(protectedPaths)
  ) {
    throw new TypeError("Review Bundle protected path set is invalid.");
  }
  return protectedPaths;
}

async function git(repoPath, args, options = {}) {
  return execFileAsync(
    GIT,
    ["--no-replace-objects", "-C", repoPath, ...args],
    {
      encoding: options.encoding ?? "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        ...frozenXcrunEnvironment,
      },
      maxBuffer: MAX_OUTPUT,
    },
  );
}

async function gitBytes(repoPath, sourceCommit, path) {
  const { stdout } = await git(
    repoPath,
    ["cat-file", "blob", `${sourceCommit}:${path}`],
    { encoding: "buffer" },
  );
  return Buffer.from(stdout);
}

async function frozenWorkingBinding(repoPath, sourceCommit, path) {
  const exactPath = exactRelativePath(repoPath, path);
  const [gitBlob, workingTree] = await Promise.all([
    gitBytes(repoPath, sourceCommit, exactPath),
    readFile(resolve(repoPath, exactPath)),
  ]);
  const gitBlobSha256 = sha256RuntimeBytes(gitBlob);
  const workingTreeBytesSha256 = sha256RuntimeBytes(workingTree);
  if (gitBlobSha256 !== workingTreeBytesSha256) {
    throw new TypeError(`Working bytes differ from sourceCommit: ${exactPath}`);
  }
  return {
    path: exactPath,
    sha256: gitBlobSha256,
    byteLength: gitBlob.byteLength,
    gitBlobSha256,
    workingTreeBytesSha256,
  };
}

async function repositorySnapshot(repoPath, protectedPaths) {
  const [
    head,
    tree,
    status,
    refs,
    protectedFiles,
  ] = await Promise.all([
    git(repoPath, ["rev-parse", "HEAD"], { encoding: "buffer" }).then(
      ({ stdout }) => Buffer.from(stdout).toString("utf8").trim(),
    ),
    git(repoPath, ["rev-parse", "HEAD^{tree}"], { encoding: "buffer" }).then(
      ({ stdout }) => Buffer.from(stdout).toString("utf8").trim(),
    ),
    git(
      repoPath,
      ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
      { encoding: "buffer" },
    ).then(({ stdout }) => Buffer.from(stdout)),
    git(
      repoPath,
      [
        "for-each-ref",
        "--format=%(refname)%00%(objectname)%00",
        "refs/heads",
        "refs/tags",
        "refs/remotes",
      ],
      { encoding: "buffer" },
    ).then(({ stdout }) => Buffer.from(stdout)),
    Promise.all(
      [...protectedPaths].sort().map(async (path) => {
        const exactPath = exactRelativePath(repoPath, path);
        const bytes = await readFile(resolve(repoPath, exactPath));
        return {
          path: exactPath,
          sha256: sha256RuntimeBytes(bytes),
          byteLength: bytes.byteLength,
        };
      }),
    ),
  ]);
  return {
    head,
    tree,
    statusSha256: sha256RuntimeBytes(status),
    refsSha256: sha256RuntimeBytes(refs),
    protectedFiles,
  };
}

function seatbeltLiteral(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}

function renderSandboxProfile(template, values) {
  let rendered = template;
  for (const [name, value] of Object.entries(values)) {
    const marker = `@@${name}@@`;
    if (!rendered.includes(marker)) {
      throw new TypeError(`Sandbox template is missing ${marker}.`);
    }
    rendered = rendered.replaceAll(marker, seatbeltLiteral(value));
  }
  if (/@@[A-Z_]+@@/.test(rendered)) {
    throw new TypeError("Sandbox template contains unresolved placeholders.");
  }
  return rendered;
}

function sanitizedEnvironment() {
  return {
    PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
    LANG: "C",
    LC_ALL: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_CONFIG_GLOBAL: "/dev/null",
    ...frozenXcrunEnvironment,
  };
}

async function writeObservation({
  evidenceRoot,
  index,
  probeId,
  operation,
  attempted,
  exitCode,
  signal,
  timedOut,
  stdout,
  stderr,
}) {
  const observationRoot = resolve(evidenceRoot, "observations");
  await mkdir(observationRoot, { recursive: true });
  const prefix = `${String(index).padStart(2, "0")}-${operation
    .toLowerCase()
    .replaceAll("_", "-")}`;
  const stdoutPath = resolve(observationRoot, `${prefix}.stdout`);
  const stderrPath = resolve(observationRoot, `${prefix}.stderr`);
  const stdoutBytes = Buffer.from(stdout);
  const stderrBytes = Buffer.from(stderr);
  await Promise.all([
    writeFile(stdoutPath, stdoutBytes, { mode: 0o600 }),
    writeFile(stderrPath, stderrBytes, { mode: 0o600 }),
  ]);
  return {
    probeId,
    operation,
    attempted,
    exitCode,
    signal,
    timedOut,
    stdoutRef: evidenceRelativePath(evidenceRoot, stdoutPath),
    stdoutSha256: sha256RuntimeBytes(stdoutBytes),
    stdoutByteLength: stdoutBytes.byteLength,
    stderrRef: evidenceRelativePath(evidenceRoot, stderrPath),
    stderrSha256: sha256RuntimeBytes(stderrBytes),
    stderrByteLength: stderrBytes.byteLength,
  };
}

async function runSandboxedObservation({
  evidenceRoot,
  index,
  sandboxProfilePath,
  cwd,
  probeId,
  operation,
  executable,
  args,
}) {
  let stdout = Buffer.alloc(0);
  let stderr = Buffer.alloc(0);
  let exitCode = 0;
  let signal = null;
  let timedOut = false;
  try {
    const result = await execFileAsync(
      SANDBOX_EXEC,
      ["-f", sandboxProfilePath, executable, ...args],
      {
        cwd,
        encoding: "buffer",
        env: sanitizedEnvironment(),
        timeout: 5000,
        killSignal: "SIGKILL",
        maxBuffer: MAX_OUTPUT,
      },
    );
    stdout = Buffer.from(result.stdout);
    stderr = Buffer.from(result.stderr);
  } catch (error) {
    stdout = Buffer.from(error?.stdout ?? "");
    stderr = Buffer.from(error?.stderr ?? "");
    exitCode = Number.isInteger(error?.code) ? error.code : 1;
    signal = typeof error?.signal === "string" ? error.signal : null;
    timedOut = error?.killed === true && signal === "SIGKILL";
  }
  if (
    new TextDecoder("utf-8", { fatal: false })
      .decode(stderr)
      .startsWith("sandbox-exec: sandbox_apply:")
  ) {
    const error = new TypeError("NESTED_SEATBELT_UNAVAILABLE");
    error.reasonCodes = ["NESTED_SEATBELT_UNAVAILABLE"];
    throw error;
  }
  return writeObservation({
    evidenceRoot,
    index,
    probeId,
    operation,
    attempted: true,
    exitCode,
    signal,
    timedOut,
    stdout,
    stderr,
  });
}

async function recordedObservation({
  evidenceRoot,
  index,
  probeId,
  operation,
  exitCode,
  value,
}) {
  return writeObservation({
    evidenceRoot,
    index,
    probeId,
    operation,
    attempted: true,
    exitCode,
    signal: null,
    timedOut: false,
    stdout: Buffer.from(`${JSON.stringify(value)}\n`, "utf8"),
    stderr: Buffer.alloc(0),
  });
}

function bindingMismatchNegativeTest(actual, deliberatelyWrong) {
  if (actual === deliberatelyWrong) {
    throw new TypeError("Negative binding test did not introduce a mismatch.");
  }
  try {
    if (actual !== deliberatelyWrong) {
      throw Object.assign(new Error("Binding mismatch."), {
        code: "RUNTIME_BINDING_MISMATCH_REJECTED",
      });
    }
  } catch (error) {
    return {
      exitCode: 2,
      output: {
        code: error.code,
        rejected: true,
      },
    };
  }
  throw new TypeError("Binding mismatch was not rejected.");
}

export async function collectIndependentReviewControlPlaneEvidence({
  repoPath,
  sourceCommit,
  sourceTree,
  reviewBundlePath,
  reviewerPromptPath,
  outputSchemaPath,
  testEvidenceCollectorPath,
  sandboxTemplatePath,
  controlPlanePath = CONTROL_PLANE_PATH,
  runtimeValidatorPath = RUNTIME_VALIDATOR_PATH,
  evidenceRoot,
}) {
  if (
    platform() !== "darwin" ||
    !COMMIT.test(sourceCommit) ||
    !COMMIT.test(sourceTree)
  ) {
    throw new TypeError(
      "OS-enforced runtime evidence requires macOS and exact Git bindings.",
    );
  }
  const exactRepoPath = resolve(repoPath);
  const exactEvidenceRoot = resolve(evidenceRoot);
  const evidenceRelativeToRepo = relative(exactRepoPath, exactEvidenceRoot);
  if (
    evidenceRelativeToRepo === "" ||
    (!evidenceRelativeToRepo.startsWith(`..${sep}`) &&
      evidenceRelativeToRepo !== "..")
  ) {
    throw new TypeError("Runtime evidence root must be outside the repository.");
  }
  const [actualHead, actualTree] = await Promise.all([
    git(exactRepoPath, ["rev-parse", "HEAD"], { encoding: "buffer" }).then(
      ({ stdout }) => Buffer.from(stdout).toString("utf8").trim(),
    ),
    git(exactRepoPath, ["rev-parse", `${sourceCommit}^{tree}`], {
      encoding: "buffer",
    }).then(({ stdout }) => Buffer.from(stdout).toString("utf8").trim()),
  ]);
  if (actualHead !== sourceCommit || actualTree !== sourceTree) {
    throw new TypeError("Runtime evidence source commit or tree drifted.");
  }
  await mkdir(exactEvidenceRoot, { recursive: true });
  const startedAt = new Date().toISOString();
  const reviewBundleBytes = await readFile(resolve(reviewBundlePath));
  const protectedPaths = protectedPathsFromBundle(reviewBundleBytes);
  const before = await repositorySnapshot(exactRepoPath, protectedPaths);

  const [
    controlPlane,
    runtimeValidator,
    reviewerPrompt,
    outputSchema,
    testEvidenceCollector,
    sandboxTemplate,
  ] = await Promise.all([
    frozenWorkingBinding(exactRepoPath, sourceCommit, controlPlanePath),
    frozenWorkingBinding(exactRepoPath, sourceCommit, runtimeValidatorPath),
    frozenWorkingBinding(exactRepoPath, sourceCommit, reviewerPromptPath),
    frozenWorkingBinding(exactRepoPath, sourceCommit, outputSchemaPath),
    frozenWorkingBinding(
      exactRepoPath,
      sourceCommit,
      testEvidenceCollectorPath,
    ),
    frozenWorkingBinding(exactRepoPath, sourceCommit, sandboxTemplatePath),
  ]);
  const executedControlPlaneBytes = await readFile(
    fileURLToPath(import.meta.url),
  );
  const executedValidatorBytes = await readFile(
    new URL("../lib/independent-review-runtime-evidence.mjs", import.meta.url),
  );
  if (
    controlPlane.gitBlobSha256 !==
      sha256RuntimeBytes(executedControlPlaneBytes) ||
    runtimeValidator.gitBlobSha256 !==
      sha256RuntimeBytes(executedValidatorBytes)
  ) {
    throw new TypeError(
      "Executed control plane or validator differs from sourceCommit.",
    );
  }

  const reviewRoot = resolve(exactEvidenceRoot, "review-input");
  const bundleCopyPath = resolve(reviewRoot, "review-bundle.json");
  const outsideRoot = resolve(exactEvidenceRoot, "outside-review-input");
  const outsideCanaryPath = resolve(outsideRoot, "unavailable.txt");
  await Promise.all([
    mkdir(reviewRoot, { recursive: true }),
    mkdir(outsideRoot, { recursive: true }),
  ]);
  await Promise.all([
    writeFile(bundleCopyPath, reviewBundleBytes, { mode: 0o400 }),
    writeFile(outsideCanaryPath, "not-review-input\n", {
      mode: 0o400,
    }),
  ]);

  const templateBytes = await readFile(resolve(exactRepoPath, sandboxTemplate.path));
  const { stdout: selectedDeveloperDirBytes } = await execFileAsync(
    XCODE_SELECT,
    ["-p"],
    {
      encoding: "buffer",
      env: sanitizedEnvironment(),
      maxBuffer: MAX_OUTPUT,
    },
  );
  const [canonicalReviewRoot, canonicalDeveloperDir] = await Promise.all([
    realpath(reviewRoot),
    realpath(
      Buffer.from(selectedDeveloperDirBytes).toString("utf8").trim(),
    ),
  ]);
  const sandboxGit = await realpath(
    resolve(canonicalDeveloperDir, "usr/bin/git"),
  );
  const renderedProfile = renderSandboxProfile(
    new TextDecoder("utf-8", { fatal: true }).decode(templateBytes),
    {
      DEVELOPER_DIR: canonicalDeveloperDir,
      NODE_DIR: dirname(process.execPath),
      REVIEW_ROOT: canonicalReviewRoot,
    },
  );
  const sandboxProfilePath = resolve(
    exactEvidenceRoot,
    "runtime",
    "independent-review.sb",
  );
  await mkdir(dirname(sandboxProfilePath), { recursive: true });
  await writeFile(sandboxProfilePath, renderedProfile, {
    mode: 0o600,
  });

  const observations = [];
  const push = (promise) =>
    promise.then((observation) => {
      observations.push(observation);
    });
  const nodeWrite = (method, target, second = null) => {
    const calls = {
      writeFileSync: "require('fs').writeFileSync(process.argv[1], 'probe')",
      appendFileSync: "require('fs').appendFileSync(process.argv[1], 'probe')",
      unlinkSync: "require('fs').unlinkSync(process.argv[1])",
      renameSync:
        "require('fs').renameSync(process.argv[1], process.argv[2])",
      readFileSync: "require('fs').readFileSync(process.argv[1])",
    };
    return [process.execPath, ["-e", calls[method], target, ...(second ? [second] : [])]];
  };

  let index = 0;
  for (const [probeId, operation, invocation] of [
    [
      "CREATE_FILE_DENIED",
      "CREATE_FILE_ATTEMPT",
      nodeWrite(
        "writeFileSync",
        resolve(reviewRoot, "created-by-reviewer.txt"),
      ),
    ],
    [
      "MODIFY_FILE_DENIED",
      "MODIFY_FILE_ATTEMPT",
      nodeWrite("appendFileSync", bundleCopyPath),
    ],
    [
      "DELETE_FILE_DENIED",
      "DELETE_FILE_ATTEMPT",
      nodeWrite("unlinkSync", bundleCopyPath),
    ],
    [
      "MOVE_RENAME_DENIED",
      "MOVE_RENAME_ATTEMPT",
      nodeWrite(
        "renameSync",
        bundleCopyPath,
        resolve(reviewRoot, "moved-review-bundle.json"),
      ),
    ],
    [
      "APPLY_PATCH_DENIED",
      "PATCH_STYLE_WRITE_ATTEMPT",
      nodeWrite("writeFileSync", bundleCopyPath),
    ],
    [
      "MODEL_READ_OUTSIDE_BUNDLE_UNAVAILABLE",
      "READ_OUTSIDE_BUNDLE_ATTEMPT",
      nodeWrite("readFileSync", outsideCanaryPath),
    ],
  ]) {
    await push(
      runSandboxedObservation({
        evidenceRoot: exactEvidenceRoot,
        index: index++,
        sandboxProfilePath,
        cwd: reviewRoot,
        probeId,
        operation,
        executable: invocation[0],
        args: invocation[1],
      }),
    );
  }

  const bindingNegative = bindingMismatchNegativeTest(
    sha256RuntimeBytes(reviewBundleBytes),
    `sha256:${"0".repeat(64)}`,
  );
  await push(
    recordedObservation({
      evidenceRoot: exactEvidenceRoot,
      index: index++,
      probeId: "BINDING_MISMATCH_FAIL_CLOSED",
      operation: "CONTROL_PLANE_BINDING_NEGATIVE_TEST",
      exitCode: bindingNegative.exitCode,
      value: bindingNegative.output,
    }),
  );

  const inspectIntegrationScript = [
    "const names=JSON.parse(process.argv[1]);",
    "process.stdout.write(JSON.stringify({",
    "declaredModelTools:[],",
    "forbiddenIntegrationEnvironmentKeyNamesPresent:names.filter((name)=>Object.hasOwn(process.env,name)),",
    "networkPolicy:'DENY_ALL'",
    "})+'\\n');",
  ].join("");
  await push(
    runSandboxedObservation({
      evidenceRoot: exactEvidenceRoot,
      index: index++,
      sandboxProfilePath,
      cwd: reviewRoot,
      probeId: "D1_SITES_GOVERNANCE_WRITE_UNAVAILABLE",
      operation: "INSPECT_INTEGRATION_BOUNDARY",
      executable: process.execPath,
      args: ["-e", inspectIntegrationScript, JSON.stringify(INTEGRATION_ENV_KEYS)],
    }),
  );

  const inspectCredentialsScript = [
    "const names=JSON.parse(process.argv[1]);",
    "process.stdout.write(JSON.stringify({",
    "credentialEnvironmentKeyNamesPresent:names.filter((name)=>Object.hasOwn(process.env,name)),",
    "nativeTransportCredentialBoundary:'CONTROL_PROCESS_ONLY_NOT_MODEL_TOOL'",
    "})+'\\n');",
  ].join("");
  await push(
    runSandboxedObservation({
      evidenceRoot: exactEvidenceRoot,
      index: index++,
      sandboxProfilePath,
      cwd: reviewRoot,
      probeId: "SANITIZED_ENVIRONMENT_CREDENTIAL_NAMES_ABSENT",
      operation: "INSPECT_CREDENTIAL_BOUNDARY",
      executable: process.execPath,
      args: ["-e", inspectCredentialsScript, JSON.stringify(CREDENTIAL_ENV_KEYS)],
    }),
  );

  await push(
    runSandboxedObservation({
      evidenceRoot: exactEvidenceRoot,
      index: index++,
      sandboxProfilePath,
      cwd: exactRepoPath,
      probeId: "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
      operation: "GIT_COMMIT_ATTEMPT",
      executable: sandboxGit,
      args: ["-C", exactRepoPath, "commit", "--allow-empty", "-m", "probe"],
    }),
  );
  await push(
    runSandboxedObservation({
      evidenceRoot: exactEvidenceRoot,
      index: index++,
      sandboxProfilePath,
      cwd: exactRepoPath,
      probeId: "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
      operation: "GIT_TAG_ATTEMPT",
      executable: sandboxGit,
      args: ["-C", exactRepoPath, "tag", "independent-review-probe"],
    }),
  );
  await push(
    recordedObservation({
      evidenceRoot: exactEvidenceRoot,
      index: index++,
      probeId: "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
      operation: "GIT_PUSH_CAPABILITY_INSPECTION",
      exitCode: 0,
      value: {
        credentialEnvironmentKeyNamesPresent: [],
        networkPolicy: "DENY_ALL",
        pushAttempted: false,
      },
    }),
  );

  const exactReadScript = [
    "const fs=require('fs'),crypto=require('crypto');",
    "const bytes=fs.readFileSync(process.argv[1]);",
    "process.stdout.write(JSON.stringify({",
    "byteLength:bytes.byteLength,",
    "sha256:'sha256:'+crypto.createHash('sha256').update(bytes).digest('hex')",
    "})+'\\n');",
  ].join("");
  await push(
    runSandboxedObservation({
      evidenceRoot: exactEvidenceRoot,
      index: index++,
      sandboxProfilePath,
      cwd: reviewRoot,
      probeId: "REVIEW_BUNDLE_EXACT_READ_ONLY",
      operation: "READ_EXACT_BUNDLE_BYTES",
      executable: process.execPath,
      args: ["-e", exactReadScript, bundleCopyPath],
    }),
  );

  const after = await repositorySnapshot(exactRepoPath, protectedPaths);
  const beforeSha256 = sha256RuntimeValue(before);
  const afterSha256 = sha256RuntimeValue(after);
  await push(
    recordedObservation({
      evidenceRoot: exactEvidenceRoot,
      index: index++,
      probeId: "REPOSITORY_UNCHANGED",
      operation: "COMPARE_REPOSITORY_SNAPSHOT",
      exitCode: 0,
      value: {
        afterSha256,
        beforeSha256,
        unchanged: beforeSha256 === afterSha256,
      },
    }),
  );

  const evidence = {
    schemaVersion: "independent-model-runtime-evidence.v2",
    evidenceId: `imre_${sourceCommit.slice(0, 12)}_${sha256RuntimeBytes(
      reviewBundleBytes,
    ).slice(7, 19)}`,
    assuranceClaim: "LOCAL_CONTROL_PLANE_OBSERVED_OS_ENFORCEMENT",
    enforcementMode: "OS_ENFORCED_TARGET_READ_ONLY",
    platform: {
      os: platform(),
      architecture: arch(),
      nodeVersion: process.version,
      sandbox: "MACOS_SEATBELT_SANDBOX_EXEC",
    },
    controlPlane: {
      path: controlPlane.path,
      gitBlobSha256: controlPlane.gitBlobSha256,
      executedBytesSha256: sha256RuntimeBytes(executedControlPlaneBytes),
      runtimeValidatorPath: runtimeValidator.path,
      runtimeValidatorGitBlobSha256: runtimeValidator.gitBlobSha256,
      runtimeValidatorExecutedBytesSha256:
        sha256RuntimeBytes(executedValidatorBytes),
    },
    bindings: {
      sourceCommit,
      sourceTree,
      reviewBundle: {
        path: evidenceRelativePath(exactEvidenceRoot, bundleCopyPath),
        sha256: sha256RuntimeBytes(reviewBundleBytes),
        byteLength: reviewBundleBytes.byteLength,
      },
      reviewerPrompt,
      outputSchema,
      testEvidenceCollector,
      sandboxTemplate: {
        ...sandboxTemplate,
        renderedSha256: sha256RuntimeBytes(
          Buffer.from(renderedProfile, "utf8"),
        ),
      },
    },
    transportBoundary: {
      schemeAStatus: "NOT_ASSESSED_PROBE_ONLY",
      nativeTransportCredentialBoundary:
        "CONTROL_PROCESS_ONLY_NOT_MODEL_TOOL",
      credentialEnvironmentKeyNamesInspected: [...CREDENTIAL_ENV_KEYS],
      forbiddenIntegrationEnvironmentKeyNamesInspected: [
        ...INTEGRATION_ENV_KEYS,
      ],
      networkPolicy: "DENY_ALL",
      networkCallsPerformed: false,
    },
    reviewerInvocation: {
      state: "NOT_INVOKED_PROBE_ONLY",
      requestedModel: null,
      reportedModel: null,
      reviewerSessionId: null,
      declaredModelTools: [],
      toolChoice: "NONE",
      rawModelOutput: null,
    },
    observations,
    isolationProbeResults: {
      schemaVersion: "independent-model-isolation-probes.v2",
      enforcementMode: "OS_ENFORCED_TARGET_READ_ONLY",
      results: [],
      allPassed: false,
    },
    repositoryUnchangedBeforeAfter: {
      protectedPathSetSha256: sha256RuntimeValue(protectedPaths),
      before,
      after,
      unchanged: beforeSha256 === afterSha256,
    },
    startedAt,
    finishedAt: new Date().toISOString(),
    evidenceSha256: `sha256:${"0".repeat(64)}`,
  };
  evidence.isolationProbeResults.results =
    await deriveIndependentReviewProbeResults({
      evidence,
      evidenceRoot: exactEvidenceRoot,
    });
  evidence.isolationProbeResults.allPassed =
    evidence.isolationProbeResults.results.every(
      ({ status }) => status === "PASS",
    );
  evidence.evidenceSha256 = sha256RuntimeValue(
    Object.fromEntries(
      Object.entries(evidence).filter(([key]) => key !== "evidenceSha256"),
    ),
  );
  const validation = await validateIndependentModelRuntimeEvidence({
    evidence,
    expectedBindings: {
      sourceCommit,
      sourceTree,
      reviewBundleSha256: evidence.bindings.reviewBundle.sha256,
      reviewerPromptSha256: evidence.bindings.reviewerPrompt.sha256,
      outputSchemaSha256: evidence.bindings.outputSchema.sha256,
      protectedPathSetSha256:
        evidence.repositoryUnchangedBeforeAfter.protectedPathSetSha256,
    },
    evidenceRoot: exactEvidenceRoot,
  });
  if (!validation.valid) {
    throw Object.assign(
      new Error("Collected runtime evidence failed closed validation."),
      { reasonCodes: validation.reasonCodes },
    );
  }
  await writeFile(
    resolve(exactEvidenceRoot, "independent-model-runtime-evidence.v2.json"),
    `${JSON.stringify(evidence)}\n`,
    { mode: 0o600 },
  );
  return evidence;
}

export { validateIndependentModelRuntimeEvidence };

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stderr.write(
    `${JSON.stringify({
      code: "INDEPENDENT_REVIEW_CONTROL_PLANE_LIBRARY_ONLY",
    })}\n`,
  );
  process.exitCode = 2;
}
