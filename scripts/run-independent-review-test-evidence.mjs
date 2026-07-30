#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  sha256ProjectValue,
} from "../lib/project-control.mjs";

const execFileAsync = promisify(execFile);
const COMMIT = /^[a-f0-9]{40}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const COMMAND_ID = /^[a-z0-9][a-z0-9_-]{2,63}$/;
const MAX_OUTPUT = 64 * 1024 * 1024;
const RUNNER_PATH = "scripts/run-independent-review-test-evidence.mjs";

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
        !["GIT", "NODE", "NPM"].includes(command.executable) ||
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
      },
      maxBuffer: MAX_OUTPUT,
    },
  );
}

async function executionSnapshot(repoPath) {
  const [head, tree, statusBytes] = await Promise.all([
    git(repoPath, ["rev-parse", "HEAD"]).then(({ stdout }) =>
      Buffer.from(stdout).toString("utf8").trim(),
    ),
    git(repoPath, ["rev-parse", "HEAD^{tree}"]).then(({ stdout }) =>
      Buffer.from(stdout).toString("utf8").trim(),
    ),
    git(repoPath, [
      "status",
      "--porcelain=v1",
      "-z",
      "--untracked-files=all",
    ]).then(({ stdout }) => Buffer.from(stdout)),
  ]);
  return {
    head,
    tree,
    worktreeStatusSha256: hashBytes(statusBytes),
  };
}

async function isolatedSourceClone(repoPath, sourceCommit, sourceTree) {
  const parent = await mkdtemp(
    join(tmpdir(), "zb-independent-review-test-source-"),
  );
  const checkout = join(parent, "source");
  try {
    await execFileAsync(
      "/usr/bin/git",
      [
        "clone",
        "--quiet",
        "--local",
        "--no-checkout",
        "--no-hardlinks",
        repoPath,
        checkout,
      ],
      {
        encoding: "buffer",
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: "/dev/null",
        },
        maxBuffer: MAX_OUTPUT,
      },
    );
    await git(checkout, ["checkout", "--quiet", "--detach", sourceCommit]);
    const dependencyRoot = resolve(repoPath, "node_modules");
    try {
      if ((await stat(dependencyRoot)).isDirectory()) {
        await symlink(dependencyRoot, resolve(checkout, "node_modules"), "dir");
      }
    } catch {
      // A frozen command that needs dependencies will fail closed without them.
    }
    const before = await executionSnapshot(checkout);
    if (before.head !== sourceCommit || before.tree !== sourceTree) {
      throw new TypeError("Isolated test source does not match sourceCommit.");
    }
    return { parent, checkout, before };
  } catch (error) {
    await rm(parent, { recursive: true, force: true });
    throw error;
  }
}

function executableFor(symbol) {
  if (symbol === "NODE") return process.execPath;
  if (symbol === "NPM") {
    return resolve(dirname(process.execPath), "npm");
  }
  if (symbol === "GIT") return "/usr/bin/git";
  throw new TypeError("Unknown independent review test executable.");
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
  const [planBytes, frozenRunnerBytes, executedRunnerBytes] = await Promise.all([
    gitBytes(repoPath, sourceCommit, planPath),
    gitBytes(repoPath, sourceCommit, RUNNER_PATH),
    readFile(fileURLToPath(import.meta.url)),
  ]);
  if (hashBytes(frozenRunnerBytes) !== hashBytes(executedRunnerBytes)) {
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
  const exactEvidenceRoot = resolve(evidenceRoot);
  await mkdir(exactEvidenceRoot, { recursive: true });
  const summaries = [];

  for (const command of plan.commands) {
    const isolated = await isolatedSourceClone(
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
    try {
      const result = await execFileAsync(
        executableFor(command.executable),
        command.args,
        {
          cwd: isolated.checkout,
          encoding: "buffer",
          env: {
            PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
            LANG: "C",
            LC_ALL: "C",
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: "/dev/null",
          },
          maxBuffer: MAX_OUTPUT,
          timeout: command.timeoutMs,
          killSignal: "SIGKILL",
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
    const finishedAt = new Date().toISOString();
    let after;
    try {
      after = await executionSnapshot(isolated.checkout);
    } finally {
      await rm(isolated.parent, { recursive: true, force: true });
    }
    const executionUnchanged =
      JSON.stringify(isolated.before) === JSON.stringify(after);
    const stdoutRef = `${command.commandId}.stdout.log`;
    const stderrRef = `${command.commandId}.stderr.log`;
    const resultRef = `${command.commandId}.result.json`;
    await Promise.all([
      writeFile(resolve(exactEvidenceRoot, stdoutRef), stdout, { mode: 0o600 }),
      writeFile(resolve(exactEvidenceRoot, stderrRef), stderr, { mode: 0o600 }),
    ]);
    const result = {
      schemaVersion: "independent-review-test-result.v2",
      evidenceId: command.commandId,
      testPlanSha256: plan.planSha256,
      sourceCommit,
      sourceTree,
      runner: {
        path: RUNNER_PATH,
        gitBlobSha256: hashBytes(frozenRunnerBytes),
        executedBytesSha256: hashBytes(executedRunnerBytes),
      },
      executionSource: {
        mode: "ISOLATED_LOCAL_CLONE",
        before: isolated.before,
        after,
        unchanged: executionUnchanged,
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
      runner: "GIT_FROZEN_ISOLATED_CLONE_CONTROL_PLANE",
      toolVersions: [
        `node=${process.version}`,
        `runner=${basename(RUNNER_PATH)}`,
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
