#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  sha256ProjectValue,
} from "../lib/project-control.mjs";
import {
  captureIndependentReviewRuntimeBinding,
  independentReviewRuntimeBinding,
  serializeIndependentReviewRuntimeBinding,
} from "../lib/independent-review-runtime-binding.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const COMMAND_ID = /^[a-z0-9][a-z0-9_-]{2,63}$/;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const MAX_OUTPUT = 64 * 1024 * 1024;
const RUNNER_PATH = "scripts/run-independent-review-test-evidence.mjs";
const RUNTIME_BINDING_GENERATOR_PATH =
  "lib/independent-review-runtime-binding.mjs";
const TEST_SANDBOX_POLICY_PATH =
  "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in";
const SANDBOX_EXEC = "/usr/bin/sandbox-exec";
const SANDBOX_VERSION =
  "isolation=macos-sandbox-exec-git-archive-readonly-network-denied";
const NETWORK_TEST_MODE =
  "network-test-mode=frozen-deterministic-offline-alternatives";
const DEVELOPER_TOOLCHAIN_ROOT =
  "/Library/Developer/CommandLineTools";
const BUILD_OUTPUT_DIRS = Object.freeze([
  ".next",
  ".vinext",
  ".wrangler",
  "dist",
]);
const WRITABLE_WORK_ROOTS = Object.freeze([
  ...BUILD_OUTPUT_DIRS,
  "node_modules/.vite-temp",
]);
const RESERVED_SOURCE_ROOTS = new Set([
  ...BUILD_OUTPUT_DIRS,
  ".git",
  "node_modules",
]);

const hashBytes = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

function transcriptContainsActiveMoonshotCredential(stdout, stderr) {
  const credential = process.env.MOONSHOT_API_KEY;
  if (typeof credential !== "string" || credential.length === 0) {
    return false;
  }
  const credentialBytes = Buffer.from(credential, "utf8");
  return (
    Buffer.from(stdout).includes(credentialBytes) ||
    Buffer.from(stderr).includes(credentialBytes)
  );
}

async function validatePlan(plan) {
  if (
    !exactKeys(plan, [
      "schemaVersion",
      "planId",
      "commands",
      "planSha256",
    ]) ||
    plan.schemaVersion !== "independent-review-test-plan.v2" ||
    !COMMAND_ID.test(plan.planId) ||
    !Array.isArray(plan.commands) ||
    plan.commands.length === 0 ||
    new Set(plan.commands.map(({ commandId }) => commandId)).size !==
      plan.commands.length ||
    plan.commands.some(
      (command) =>
        !exactKeys(command, [
          "commandId",
          "executable",
          "args",
          "timeoutMs",
        ]) ||
        !COMMAND_ID.test(command.commandId) ||
        !["NODE", "NPM"].includes(command.executable) ||
        !Array.isArray(command.args) ||
        command.args.length === 0 ||
        command.args.some(
          (value) =>
            typeof value !== "string" ||
            value.length === 0 ||
            value.includes("\u0000"),
        ) ||
        !Number.isInteger(command.timeoutMs) ||
        command.timeoutMs < 1000 ||
        command.timeoutMs > 900000,
    ) ||
    !SHA256.test(plan.planSha256) ||
    plan.planSha256 !==
      (await sha256ProjectValue(withoutField(plan, "planSha256")))
  ) {
    throw new TypeError("Independent review test plan is invalid.");
  }
}

async function gitBytes(repoPath, sourceCommit, path) {
  const { stdout } = await execFileAsync(
    "/usr/bin/git",
    [
      "--no-replace-objects",
      "-C",
      repoPath,
      "cat-file",
      "blob",
      `${sourceCommit}:${path}`,
    ],
    {
      encoding: "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
      },
      maxBuffer: MAX_OUTPUT,
    },
  );
  return Buffer.from(stdout);
}

async function git(repoPath, args, options = {}) {
  return execFileAsync(
    "/usr/bin/git",
    ["--no-replace-objects", "-C", repoPath, ...args],
    {
      encoding: options.encoding ?? "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
      },
      maxBuffer: MAX_OUTPUT,
    },
  );
}

async function expectedGitSourceRecords(repoPath, sourceCommit) {
  const { stdout } = await git(repoPath, [
    "ls-tree",
    "-r",
    "-z",
    "--full-tree",
    sourceCommit,
  ]);
  const raw = Buffer.from(stdout);
  const records = [];
  let offset = 0;
  let previousPathBytes = null;
  while (offset < raw.byteLength) {
    const terminator = raw.indexOf(0, offset);
    if (terminator === -1) {
      throw new TypeError("Git tree output is not NUL terminated.");
    }
    const recordBytes = raw.subarray(offset, terminator);
    offset = terminator + 1;
    const tab = recordBytes.indexOf(9);
    if (tab === -1) {
      throw new TypeError("Git tree record is malformed.");
    }
    const header = recordBytes.subarray(0, tab).toString("ascii");
    const match =
      /^(100644|100755|120000) blob ([a-f0-9]{40})$/u.exec(header);
    if (!match) {
      throw new TypeError(
        "Git tree contains an unsupported entry type.",
      );
    }
    const pathBytes = recordBytes.subarray(tab + 1);
    let path;
    try {
      path = new TextDecoder("utf-8", { fatal: true }).decode(pathBytes);
    } catch {
      throw new TypeError("Git tree path is not valid UTF-8.");
    }
    const root = path.split("/", 1)[0];
    if (
      !SAFE_PATH.test(path) ||
      RESERVED_SOURCE_ROOTS.has(root) ||
      (previousPathBytes && Buffer.compare(previousPathBytes, pathBytes) >= 0)
    ) {
      throw new TypeError(
        "Git tree path is unsafe, duplicated, or reserved.",
      );
    }
    previousPathBytes = Buffer.from(pathBytes);
    const bytes = await gitBytes(repoPath, sourceCommit, path);
    records.push({
      path,
      type: match[1] === "120000" ? "SYMLINK" : "FILE",
      gitMode: match[1],
      byteLength: bytes.byteLength,
      sha256: hashBytes(bytes),
    });
  }
  if (records.length === 0) {
    throw new TypeError("Git source tree is empty.");
  }
  return records;
}

async function actualSourceRecords(rootPath) {
  const entries = [];
  const visit = async (directory, relativeDirectory = "") => {
    const children = (await readdir(directory, { withFileTypes: true })).sort(
      ({ name: left }, { name: right }) =>
        Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
    );
    for (const child of children) {
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${child.name}`
        : child.name;
      if (
        relativeDirectory === "" &&
        RESERVED_SOURCE_ROOTS.has(child.name)
      ) {
        continue;
      }
      const absolutePath = join(directory, child.name);
      const metadata = await lstat(absolutePath);
      if (child.isDirectory()) {
        await visit(absolutePath, relativePath);
      } else if (child.isSymbolicLink()) {
        const bytes = await readlink(absolutePath, { encoding: "buffer" });
        entries.push({
          path: relativePath,
          type: "SYMLINK",
          gitMode: "120000",
          byteLength: bytes.byteLength,
          sha256: hashBytes(bytes),
        });
      } else if (child.isFile()) {
        const bytes = await readFile(absolutePath);
        entries.push({
          path: relativePath,
          type: "FILE",
          gitMode: metadata.mode & 0o111 ? "100755" : "100644",
          byteLength: bytes.byteLength,
          sha256: hashBytes(bytes),
        });
      } else {
        throw new TypeError(
          "Git archive contains an unsupported filesystem entry.",
        );
      }
    }
  };
  await visit(rootPath);
  entries.sort(({ path: left }, { path: right }) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (
    entries.some(({ path }) => !SAFE_PATH.test(path)) ||
    new Set(entries.map(({ path }) => path)).size !== entries.length
  ) {
    throw new TypeError(
      "Git archive contains an unsafe or duplicated path.",
    );
  }
  return entries;
}

async function executionSnapshot(
  rootPath,
  sourceCommit,
  sourceTree,
  expectedRecords,
) {
  const actualRecords = await actualSourceRecords(rootPath);
  if (JSON.stringify(actualRecords) !== JSON.stringify(expectedRecords)) {
    throw new TypeError(
      "Git archive bytes do not match the frozen source tree.",
    );
  }
  return {
    head: sourceCommit,
    tree: sourceTree,
    sourceManifestSha256: await sha256ProjectValue(expectedRecords),
  };
}

async function validateExecutionInfrastructure({
  source,
  dependencyRoot,
  dependencyOverlayEntries,
}) {
  try {
    await lstat(resolve(source, ".git"));
    throw new TypeError("Git metadata exists in the source export.");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  for (const buildOutput of BUILD_OUTPUT_DIRS) {
    const path = resolve(source, buildOutput);
    const metadata = await lstat(path);
    const exactPath = await realpath(path);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      exactPath !== path ||
      !exactPath.startsWith(`${source}${sep}`)
    ) {
      throw new TypeError("Build output root escaped the source export.");
    }
  }
  const dependencyLink = resolve(source, "node_modules");
  if (dependencyRoot === null) {
    try {
      await lstat(dependencyLink);
      throw new TypeError("Unexpected node_modules exists in source export.");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    return;
  }
  const metadata = await lstat(dependencyLink);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    (await realpath(dependencyLink)) !== dependencyLink
  ) {
    throw new TypeError("Dependency overlay is invalid.");
  }
  const children = (await readdir(dependencyLink, {
    withFileTypes: true,
  })).sort(({ name: left }, { name: right }) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (
    JSON.stringify(children.map(({ name }) => name)) !==
      JSON.stringify([".vite-temp", ...dependencyOverlayEntries].sort()) ||
    !children.find(({ name }) => name === ".vite-temp")?.isDirectory()
  ) {
    throw new TypeError("Dependency overlay entries are invalid.");
  }
  for (const name of dependencyOverlayEntries) {
    const entry = children.find((child) => child.name === name);
    if (
      !entry?.isSymbolicLink() ||
      (await realpath(resolve(dependencyLink, name))) !==
        (await realpath(resolve(dependencyRoot, name)))
    ) {
      throw new TypeError("Dependency overlay target is invalid.");
    }
  }
  const viteTempPath = resolve(dependencyLink, ".vite-temp");
  const viteTempMetadata = await lstat(viteTempPath);
  if (
    !viteTempMetadata.isDirectory() ||
    viteTempMetadata.isSymbolicLink() ||
    (await realpath(viteTempPath)) !== viteTempPath
  ) {
    throw new TypeError("Vite temporary output root is invalid.");
  }
}

async function makeSourceReadOnly(rootPath) {
  const visit = async (directory, relativeDirectory = "") => {
    const children = await readdir(directory, { withFileTypes: true });
    for (const child of children) {
      if (
        relativeDirectory === "" &&
        (child.name === "node_modules" ||
          BUILD_OUTPUT_DIRS.includes(child.name))
      ) {
        continue;
      }
      const absolutePath = join(directory, child.name);
      if (child.isDirectory()) {
        await visit(absolutePath, relativeDirectory
          ? `${relativeDirectory}/${child.name}`
          : child.name);
        await chmod(absolutePath, 0o555);
      } else if (child.isFile()) {
        const metadata = await lstat(absolutePath);
        await chmod(
          absolutePath,
          metadata.mode & 0o111 ? 0o555 : 0o444,
        );
      }
    }
  };
  await visit(rootPath);
  await chmod(rootPath, 0o555);
}

async function makeSourceDisposable(rootPath) {
  const visit = async (directory) => {
    await chmod(directory, 0o700);
    const children = await readdir(directory, { withFileTypes: true });
    for (const child of children) {
      const absolutePath = join(directory, child.name);
      if (child.isDirectory()) {
        await visit(absolutePath);
      } else if (child.isFile()) {
        await chmod(absolutePath, 0o600);
      }
    }
  };
  try {
    await visit(rootPath);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

async function isolatedSourceExport(repoPath, sourceCommit, sourceTree) {
  const parent = await mkdtemp(
    join(
      tmpdir(),
      `zb-independent-review-test-export-${sourceCommit}-`,
    ),
  );
  const source = join(parent, "source");
  const archive = join(parent, "source.tar");
  try {
    const expectedRecords = await expectedGitSourceRecords(
      repoPath,
      sourceCommit,
    );
    const { stdout: actualTreeBytes } = await git(repoPath, [
      "rev-parse",
      `${sourceCommit}^{tree}`,
    ]);
    const actualTree = Buffer.from(actualTreeBytes)
      .toString("utf8")
      .trim();
    if (actualTree !== sourceTree) {
      throw new TypeError("Git source tree does not match sourceCommit.");
    }
    await mkdir(source, { mode: 0o700 });
    await execFileAsync(
      "/usr/bin/git",
      [
        "--no-replace-objects",
        "-C",
        repoPath,
        "archive",
        "--format=tar",
        `--output=${archive}`,
        sourceCommit,
      ],
      {
        encoding: "buffer",
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_ATTR_NOSYSTEM: "1",
        },
        maxBuffer: MAX_OUTPUT,
      },
    );
    await execFileAsync("/usr/bin/tar", ["-xf", archive, "-C", source], {
      encoding: "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
      },
      maxBuffer: MAX_OUTPUT,
    });
    await rm(archive, { force: true });
    for (const buildOutput of BUILD_OUTPUT_DIRS) {
      const target = resolve(source, buildOutput);
      try {
        await lstat(target);
        throw new TypeError(
          "A reserved build-output path is tracked by sourceCommit.",
        );
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
      await mkdir(target, { mode: 0o700 });
    }
    let dependencyRoot = null;
    let dependencyOverlayEntries = [];
    const dependencyCandidate = resolve(repoPath, "node_modules");
    const dependencyOverlay = resolve(source, "node_modules");
    try {
      await lstat(dependencyOverlay);
      throw new TypeError("Git archive contains a reserved node_modules.");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    try {
      const dependencyMetadata = await stat(dependencyCandidate);
      if (!dependencyMetadata.isDirectory()) {
        throw new TypeError("Repository node_modules is not a directory.");
      }
      dependencyRoot = await realpath(dependencyCandidate);
      dependencyOverlayEntries = (
        await readdir(dependencyRoot, { withFileTypes: true })
      )
        .map(({ name }) => name)
        .filter((name) => name !== ".vite-temp")
        .sort((left, right) =>
          Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
        );
      if (
        dependencyOverlayEntries.length === 0 ||
        dependencyOverlayEntries.some(
          (name) =>
            name.length === 0 ||
            name === "." ||
            name === ".." ||
            name.includes("/") ||
            name.includes("\u0000"),
        )
      ) {
        throw new TypeError("Dependency overlay source is invalid.");
      }
      await mkdir(dependencyOverlay, { mode: 0o700 });
      for (const name of dependencyOverlayEntries) {
        await symlink(
          resolve(dependencyRoot, name),
          resolve(dependencyOverlay, name),
        );
      }
      await mkdir(resolve(dependencyOverlay, ".vite-temp"), {
        mode: 0o700,
      });
      await chmod(dependencyOverlay, 0o555);
    } catch (error) {
      // A frozen command that needs dependencies will fail closed without them.
      if (error?.code !== "ENOENT") throw error;
    }
    const exactSource = await realpath(source);
    await validateExecutionInfrastructure({
      source: exactSource,
      dependencyRoot,
      dependencyOverlayEntries,
    });
    await makeSourceReadOnly(exactSource);
    const before = await executionSnapshot(
      exactSource,
      sourceCommit,
      sourceTree,
      expectedRecords,
    );
    return {
      parent,
      source: exactSource,
      dependencyRoot,
      dependencyOverlayEntries,
      expectedRecords,
      before,
    };
  } catch (error) {
    await makeSourceDisposable(source);
    await rm(parent, { recursive: true, force: true });
    throw error;
  }
}

function executableFor(symbol) {
  if (symbol === "NODE") return process.execPath;
  if (symbol === "NPM") {
    return resolve(dirname(process.execPath), "npm");
  }
  throw new TypeError("Unknown independent review test executable.");
}

async function executeSandboxedCommand({
  isolated,
  command,
  sandboxTemplateBytes,
}) {
  if (!(await stat(SANDBOX_EXEC)).isFile()) {
    throw new TypeError(
      "macOS sandbox-exec is required for independent review tests.",
    );
  }
  const scratchRoot = await mkdtemp(
    join(tmpdir(), "zb-independent-review-test-scratch-"),
  );
  try {
    const exactScratchRoot = await realpath(scratchRoot);
    const exactNodeRuntimeRoot = await realpath(
      resolve(dirname(process.execPath), ".."),
    );
    const sandboxTemplate = new TextDecoder("utf-8", { fatal: true }).decode(
      sandboxTemplateBytes,
    );
    if (
      sandboxTemplate.length === 0 ||
      sandboxTemplateBytes.byteLength > 64 * 1024
    ) {
      throw new TypeError("Frozen test sandbox template is invalid.");
    }
    const dependencyRoot =
      isolated.dependencyRoot ?? exactNodeRuntimeRoot;
    const sandboxTemplateSha256 = hashBytes(sandboxTemplateBytes);
    const sandboxParameterSetSha256 = await sha256ProjectValue({
      WORK_ROOT: hashBytes(Buffer.from(isolated.source, "utf8")),
      TMP_ROOT: hashBytes(Buffer.from(exactScratchRoot, "utf8")),
      NODE_RUNTIME_ROOT: hashBytes(
        Buffer.from(exactNodeRuntimeRoot, "utf8"),
      ),
      DEPENDENCY_ROOT: hashBytes(Buffer.from(dependencyRoot, "utf8")),
      DEVELOPER_TOOLCHAIN_ROOT: hashBytes(
        Buffer.from(DEVELOPER_TOOLCHAIN_ROOT, "utf8"),
      ),
      WRITABLE_WORK_ROOTS: await sha256ProjectValue(
        WRITABLE_WORK_ROOTS,
      ),
    });
    const sandboxInvocationSha256 = await sha256ProjectValue({
      executable: SANDBOX_EXEC,
      templateSha256: sandboxTemplateSha256,
      parameterSetSha256: sandboxParameterSetSha256,
    });
    const sandboxBinding = {
      templateSha256: sandboxTemplateSha256,
      parameterSetSha256: sandboxParameterSetSha256,
      invocationSha256: sandboxInvocationSha256,
    };
    try {
      const result = await execFileAsync(
        SANDBOX_EXEC,
        [
          "-D",
          `WORK_ROOT=${isolated.source}`,
          "-D",
          `TMP_ROOT=${exactScratchRoot}`,
          "-D",
          `NODE_RUNTIME_ROOT=${exactNodeRuntimeRoot}`,
          "-D",
          `DEPENDENCY_ROOT=${dependencyRoot}`,
          "-D",
          `DEVELOPER_TOOLCHAIN_ROOT=${DEVELOPER_TOOLCHAIN_ROOT}`,
          "-p",
          sandboxTemplate,
          executableFor(command.executable),
          ...command.args,
        ],
        {
          cwd: isolated.source,
          encoding: "buffer",
          env: {
            PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
            LANG: "C",
            LC_ALL: "C",
            HOME: exactScratchRoot,
            TMPDIR: exactScratchRoot,
            TMP: exactScratchRoot,
            TEMP: exactScratchRoot,
            XDG_CACHE_HOME: exactScratchRoot,
            DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
            npm_config_cache: exactScratchRoot,
            npm_config_audit: "false",
            npm_config_fund: "false",
            npm_config_update_notifier: "false",
            CI: "1",
            INDEPENDENT_REVIEW_NETWORK_MODE:
              "DENY_ALL_OFFLINE_ALTERNATIVES",
            WRANGLER_SEND_METRICS: "false",
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
          },
          maxBuffer: MAX_OUTPUT,
          timeout: command.timeoutMs,
          killSignal: "SIGKILL",
        },
      );
      return { ...result, sandboxBinding };
    } catch (error) {
      error.sandboxBinding = sandboxBinding;
      throw error;
    }
  } finally {
    await rm(scratchRoot, { recursive: true, force: true });
  }
}

export async function collectIndependentReviewTestEvidence({
  repoPath,
  sourceCommit,
  sourceTree,
  planPath,
  evidenceRoot,
}) {
  if (!COMMIT.test(sourceCommit) || !COMMIT.test(sourceTree)) {
    throw new TypeError("Test evidence requires exact Git source bindings.");
  }
  const [
    planBytes,
    frozenRunnerBytes,
    executedRunnerBytes,
    frozenRuntimeBindingGeneratorBytes,
    executedRuntimeBindingGeneratorBytes,
    sandboxTemplateBytes,
  ] = await Promise.all([
    gitBytes(repoPath, sourceCommit, planPath),
    gitBytes(repoPath, sourceCommit, RUNNER_PATH),
    readFile(fileURLToPath(import.meta.url)),
    gitBytes(repoPath, sourceCommit, RUNTIME_BINDING_GENERATOR_PATH),
    readFile(
      new URL(
        "../lib/independent-review-runtime-binding.mjs",
        import.meta.url,
      ),
    ),
    gitBytes(repoPath, sourceCommit, TEST_SANDBOX_POLICY_PATH),
  ]);
  if (
    hashBytes(frozenRunnerBytes) !== hashBytes(executedRunnerBytes) ||
    hashBytes(frozenRuntimeBindingGeneratorBytes) !==
      hashBytes(executedRuntimeBindingGeneratorBytes)
  ) {
    throw new TypeError("Executed test collector differs from sourceCommit.");
  }
  let plan;
  try {
    plan = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(planBytes),
    );
  } catch {
    throw new TypeError("Independent review test plan is not valid UTF-8 JSON.");
  }
  await validatePlan(plan);
  const exactRepoPath = await realpath(resolve(repoPath));
  const exactEvidenceRoot = await realpath(resolve(evidenceRoot));
  if (!(await stat(exactEvidenceRoot)).isDirectory()) {
    throw new TypeError("Test evidence root is not a directory.");
  }
  const overlaps = (left, right) =>
    left === right ||
    left.startsWith(`${right}${sep}`) ||
    right.startsWith(`${left}${sep}`);
  let exactDependencyRoot = null;
  try {
    exactDependencyRoot = await realpath(
      resolve(exactRepoPath, "node_modules"),
    );
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (
    overlaps(exactEvidenceRoot, exactRepoPath) ||
    (exactDependencyRoot !== null &&
      overlaps(exactEvidenceRoot, exactDependencyRoot))
  ) {
    throw new TypeError(
      "Test evidence root overlaps the repository or shared dependencies.",
    );
  }
  const runtimeBinding =
    await captureIndependentReviewRuntimeBinding();
  const runtimeBindingBytes =
    serializeIndependentReviewRuntimeBinding(runtimeBinding);
  const runtimeBindingDescriptor = {
    artifactRef: independentReviewRuntimeBinding.artifactRef,
    artifactSha256: hashBytes(runtimeBindingBytes),
    artifactByteLength: runtimeBindingBytes.byteLength,
    bindingSha256: runtimeBinding.bindingSha256,
    nodeExecutableSha256: runtimeBinding.nodeExecutable.sha256,
    dependencySetSha256: runtimeBinding.dependencySetSha256,
    gitToolchainSha256: runtimeBinding.gitToolchain.bindingSha256,
    generator: {
      path: RUNTIME_BINDING_GENERATOR_PATH,
      gitBlobSha256: hashBytes(frozenRuntimeBindingGeneratorBytes),
      executedBytesSha256: hashBytes(executedRuntimeBindingGeneratorBytes),
    },
  };
  await writeFile(
    resolve(
      exactEvidenceRoot,
      independentReviewRuntimeBinding.artifactRef,
    ),
    runtimeBindingBytes,
    { mode: 0o600 },
  );
  const summaries = [];

  for (const command of plan.commands) {
    const isolated = await isolatedSourceExport(
      repoPath,
      sourceCommit,
      sourceTree,
    );
    const startedAt = new Date().toISOString();
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let exitCode = 0;
    let signal = null;
    let timedOut = false;
    let sandboxBinding = null;
    try {
      const result = await executeSandboxedCommand({
        isolated,
        command,
        sandboxTemplateBytes,
      });
      stdout = Buffer.from(result.stdout);
      stderr = Buffer.from(result.stderr);
      sandboxBinding = result.sandboxBinding;
    } catch (error) {
      stdout = Buffer.from(error?.stdout ?? "");
      stderr = Buffer.from(error?.stderr ?? "");
      exitCode = Number.isInteger(error?.code) ? error.code : 1;
      signal = typeof error?.signal === "string" ? error.signal : null;
      timedOut = error?.killed === true && signal === "SIGKILL";
      sandboxBinding =
        error?.sandboxBinding &&
        typeof error.sandboxBinding === "object"
          ? error.sandboxBinding
          : null;
    }
    const finishedAt = new Date().toISOString();
    let after;
    try {
      if (transcriptContainsActiveMoonshotCredential(stdout, stderr)) {
        throw new TypeError(
          "Independent review test transcript contains an active credential.",
        );
      }
      after = await executionSnapshot(
        isolated.source,
        sourceCommit,
        sourceTree,
        isolated.expectedRecords,
      );
      await validateExecutionInfrastructure(isolated);
    } finally {
      await makeSourceDisposable(isolated.source);
      await rm(isolated.parent, { recursive: true, force: true });
    }
    const executionUnchanged =
      JSON.stringify(isolated.before) === JSON.stringify(after);
    if (
      JSON.stringify(await captureIndependentReviewRuntimeBinding()) !==
      JSON.stringify(runtimeBinding)
    ) {
      throw new TypeError(
        "Independent review runtime changed during test execution.",
      );
    }
    const stdoutRef = `${command.commandId}.stdout.log`;
    const stderrRef = `${command.commandId}.stderr.log`;
    const resultRef = `${command.commandId}.result.json`;
    await Promise.all([
      writeFile(resolve(exactEvidenceRoot, stdoutRef), stdout, { mode: 0o600 }),
      writeFile(resolve(exactEvidenceRoot, stderrRef), stderr, { mode: 0o600 }),
    ]);
    const result = {
      schemaVersion: "independent-review-test-result.v3",
      evidenceId: command.commandId,
      testPlanSha256: plan.planSha256,
      sourceCommit,
      sourceTree,
      runner: {
        path: RUNNER_PATH,
        gitBlobSha256: hashBytes(frozenRunnerBytes),
        executedBytesSha256: hashBytes(executedRunnerBytes),
      },
      runtimeBinding: structuredClone(runtimeBindingDescriptor),
      executionSource: {
        mode: "MACOS_SEATBELT_GIT_ARCHIVE_V2",
        cloneMode: "GIT_ARCHIVE_NO_METADATA",
        before: isolated.before,
        after,
        unchanged: executionUnchanged,
        sourceExportRemoved: true,
        sandbox: {
          executable: SANDBOX_EXEC,
          templatePath: TEST_SANDBOX_POLICY_PATH,
          templateSha256:
            sandboxBinding?.templateSha256 ??
            hashBytes(sandboxTemplateBytes),
          parameterSetSha256:
            sandboxBinding?.parameterSetSha256 ??
            `sha256:${"0".repeat(64)}`,
          invocationSha256:
            sandboxBinding?.invocationSha256 ??
            `sha256:${"0".repeat(64)}`,
          sourceWritable: false,
          buildOutputsWritable: true,
          writableWorkRoots: [...WRITABLE_WORK_ROOTS],
          scratchWritable: true,
          gitMetadataPresent: false,
          sharedDependenciesWritable: false,
          networkPolicy: "DENY_ALL",
          networkDependentTestMode:
            "FROZEN_DETERMINISTIC_OFFLINE_ALTERNATIVES",
        },
      },
      commandId: command.commandId,
      argvSha256: await sha256ProjectValue({
        executable: command.executable,
        args: command.args,
      }),
      observation: {
        exitCode,
        signal,
        timedOut,
        startedAt,
        finishedAt,
      },
      stdoutRef,
      stdoutSha256: hashBytes(stdout),
      stdoutByteLength: stdout.byteLength,
      stderrRef,
      stderrSha256: hashBytes(stderr),
      stderrByteLength: stderr.byteLength,
      resultSha256: `sha256:${"0".repeat(64)}`,
    };
    result.resultSha256 = await sha256ProjectValue(
      withoutField(result, "resultSha256"),
    );
    const resultBytes = Buffer.from(`${JSON.stringify(result)}\n`, "utf8");
    await writeFile(resolve(exactEvidenceRoot, resultRef), resultBytes, {
      mode: 0o600,
    });
    summaries.push({
      evidenceId: result.evidenceId,
      command: `${command.executable} ${command.args.join(" ")}`,
      status:
        result.observation.exitCode === 0 &&
        result.observation.signal === null &&
        result.observation.timedOut === false &&
        executionUnchanged
          ? "PASS"
          : "FAIL",
      exitCode: result.observation.exitCode,
      outputRef: resultRef,
      outputSha256: hashBytes(resultBytes),
      outputByteLength: resultBytes.byteLength,
      truncated: false,
      sourceCommit,
      runner: "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE",
      toolVersions: [
        `node=${process.version}`,
        `runner=${basename(RUNNER_PATH)}`,
        `runtime-binding=${runtimeBinding.bindingSha256}`,
        `node-executable=${runtimeBinding.nodeExecutable.sha256}`,
        `dependency-set=${runtimeBinding.dependencySetSha256}`,
        `git-toolchain=${runtimeBinding.gitToolchain.bindingSha256}`,
        SANDBOX_VERSION,
        NETWORK_TEST_MODE,
        `sandbox-template=${result.executionSource.sandbox.templateSha256}`,
        `sandbox-invocation=${result.executionSource.sandbox.invocationSha256}`,
      ],
    });
  }
  return summaries;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.stderr.write(
    `${JSON.stringify({
      code: "INDEPENDENT_REVIEW_TEST_COLLECTOR_LIBRARY_ONLY",
    })}\n`,
  );
  process.exitCode = 2;
}
