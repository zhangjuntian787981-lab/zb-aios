import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  bootstrapFailureResult,
  validateKimiRuntimeTrustAnchor,
} from "../scripts/bootstrap-kimi-independent-review.mjs";
import {
  clearKeychainProcessBuffers,
  decodeAndClearKeychainCredential,
} from "../scripts/run-kimi-independent-review.mjs";

const execFileAsync = promisify(execFile);
const root = resolve(new URL("../", import.meta.url).pathname);
const bootstrapPath = resolve(
  root,
  "scripts/bootstrap-kimi-independent-review.mjs",
);
const runnerPath = resolve(
  root,
  "scripts/run-kimi-independent-review.mjs",
);
const launcherPath = resolve(
  root,
  "scripts/launch-kimi-independent-review.sh",
);

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

async function git(repo, args, encoding = "utf8") {
  return execFileAsync("/usr/bin/git", ["-C", repo, ...args], {
    encoding,
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
}

test("bootstrap has a node-builtins-only static import boundary", async () => {
  const source = await readFile(bootstrapPath, "utf8");
  const imports = [...source.matchAll(/from\s+["']([^"']+)["']/gu)].map(
    (match) => match[1],
  );
  assert.ok(imports.length > 0);
  assert.equal(imports.every((value) => value.startsWith("node:")), true);
  assert.equal(source.includes("../lib/"), false);
  assert.match(source, /await import\(/u);
});

test("direct runner CLI refuses before it can use a credential or network", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [runnerPath], {
      cwd: root,
      env: {
        PATH: process.env.PATH,
        MOONSHOT_API_KEY: "not-a-real-secret",
      },
      encoding: "utf8",
    }),
    (error) => {
      assert.match(error.stdout, /KIMI_BOOTSTRAP_REQUIRED/u);
      assert.doesNotMatch(error.stdout, /not-a-real-secret/u);
      assert.equal(error.stderr, "");
      return true;
    },
  );
});

test("formal bootstrap runner has no caller-overridable credential, transport, clock or closure seam", async () => {
  const [bootstrapSource, runnerSource] = await Promise.all([
    readFile(bootstrapPath, "utf8"),
    readFile(runnerPath, "utf8"),
  ]);
  const formalStart = runnerSource.indexOf(
    "export async function runKimiIndependentReviewFromFrozenBootstrap",
  );
  const cliStart = runnerSource.indexOf(
    "const invokedPath",
    formalStart,
  );
  assert.notEqual(formalStart, -1);
  assert.notEqual(cliStart, -1);
  const formalSource = runnerSource.slice(formalStart, cliStart);
  for (const forbidden of [
    "input.apiKey",
    "input.fetchImpl",
    "input.now",
    "input.verifyRuntimeClosure",
    "input.credentialProvider",
  ]) {
    assert.equal(formalSource.includes(forbidden), false);
  }
  assert.match(formalSource, /readKimiCredentialFromKeychain/u);
  assert.match(
    runnerSource,
    /const KEYCHAIN_ACCOUNT = "p2-independent-review";/u,
  );
  assert.match(
    runnerSource,
    /"find-generic-password",[\s\S]*"-s",[\s\S]*KEYCHAIN_SERVICE,[\s\S]*"-a",[\s\S]*KEYCHAIN_ACCOUNT,[\s\S]*"-w"/u,
  );
  assert.match(formalSource, /fixedFetch/u);
  assert.match(formalSource, /createFormalRuntimeClosure/u);
  assert.equal(bootstrapSource.includes("readKimiCredential"), false);
  assert.equal(bootstrapSource.includes("/usr/bin/security"), false);
  assert.match(
    bootstrapSource,
    /runKimiIndependentReviewFromFrozenBootstrap/u,
  );
});

test("bootstrap awaits the frozen runner before removing its isolated source", async () => {
  const source = await readFile(bootstrapPath, "utf8");
  assert.match(
    source,
    /return await runnerModule\.runKimiIndependentReviewFromFrozenBootstrap\(/u,
  );
});

test("formal credential lookup reads Keychain exactly once without logging the secret", async () => {
  const source = await readFile(runnerPath, "utf8");
  const start = source.indexOf(
    "async function readKimiCredentialFromKeychain()",
  );
  const end = source.indexOf(
    "\nasync function runKimiIndependentReviewCore",
    start,
  );
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const credentialSource = source.slice(start, end);
  assert.equal(
    [...credentialSource.matchAll(/await execFileAsync\(/gu)].length,
    1,
  );
  const secretRead = credentialSource.indexOf(
    '"find-generic-password",\n        "-s",\n        KEYCHAIN_SERVICE,\n        "-a",\n        KEYCHAIN_ACCOUNT,\n        "-w",',
  );
  assert.ok(secretRead >= 0);
});

test("bootstrap failure output preserves the real network attempt count", () => {
  const afterNetwork = new TypeError("network failed");
  afterNetwork.reasonCodes = ["KIMI_NETWORK_FAILED"];
  afterNetwork.networkAttemptCount = 1;
  assert.deepEqual(bootstrapFailureResult(afterNetwork), {
    ok: false,
    status: "BLOCKED",
    reasonCodes: ["KIMI_NETWORK_FAILED"],
    networkAttemptCount: 1,
    tokenEstimateAttemptCount: 0,
    chatCompletionAttemptCount: 0,
  });

  const afterBothCalls = new TypeError("receipt failed");
  afterBothCalls.reasonCodes = ["KIMI_RECEIPT_INVALID"];
  afterBothCalls.networkAttemptCount = 2;
  afterBothCalls.tokenEstimateAttemptCount = 1;
  afterBothCalls.chatCompletionAttemptCount = 1;
  assert.deepEqual(bootstrapFailureResult(afterBothCalls), {
    ok: false,
    status: "BLOCKED",
    reasonCodes: ["KIMI_RECEIPT_INVALID"],
    networkAttemptCount: 2,
    tokenEstimateAttemptCount: 1,
    chatCompletionAttemptCount: 1,
  });

  assert.deepEqual(bootstrapFailureResult(new TypeError("preflight failed")), {
    ok: false,
    status: "BLOCKED",
    reasonCodes: ["INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED"],
    networkAttemptCount: 0,
    tokenEstimateAttemptCount: 0,
    chatCompletionAttemptCount: 0,
  });
});

test("Keychain credential decoding wipes original stdout and stderr buffers", () => {
  const stdout = Buffer.from("moonshot-test-credential\n", "utf8");
  const stderr = Buffer.from("non-secret diagnostic", "utf8");
  assert.equal(
    decodeAndClearKeychainCredential({ stdout, stderr }),
    "moonshot-test-credential",
  );
  assert.equal(stdout.every((value) => value === 0), true);
  assert.equal(stderr.every((value) => value === 0), true);

  const invalidStdout = Buffer.from([0xff, 0xfe]);
  const invalidStderr = Buffer.from("diagnostic", "utf8");
  assert.throws(
    () =>
      decodeAndClearKeychainCredential({
        stdout: invalidStdout,
        stderr: invalidStderr,
      }),
    /KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED/u,
  );
  assert.equal(invalidStdout.every((value) => value === 0), true);
  assert.equal(invalidStderr.every((value) => value === 0), true);
});

test("Keychain lookup failures wipe child-process stdout and stderr buffers", () => {
  const error = new Error("security failed");
  error.stdout = Buffer.from("unexpected secret output", "utf8");
  error.stderr = Buffer.from("diagnostic", "utf8");
  clearKeychainProcessBuffers(error);
  assert.equal(error.stdout.every((value) => value === 0), true);
  assert.equal(error.stderr.every((value) => value === 0), true);
});

test("formal Receipt is atomically published only after final repository and runtime checks", async () => {
  const source = await readFile(runnerPath, "utf8");
  const pendingWrite = source.indexOf('"receipt.pending.json": receiptBytes');
  const finalSnapshot = source.indexOf(
    "const finalSnapshot = await captureKimiReviewRepositorySnapshot",
    pendingWrite,
  );
  const finalClosure = source.indexOf(
    "await runtimeClosureIsProved(verifyRuntimeClosure)",
    finalSnapshot,
  );
  const atomicRename = source.indexOf(
    "await rename(",
    finalClosure,
  );
  assert.ok(pendingWrite > 0);
  assert.ok(finalSnapshot > pendingWrite);
  assert.ok(finalClosure > finalSnapshot);
  assert.ok(atomicRename > finalClosure);
  assert.equal(
    source.includes('writeArtifacts(exactOutputDir, { "receipt.json"'),
    false,
  );
});

test("bootstrap rejects module-resolution injection before argument parsing", async () => {
  await assert.rejects(
    execFileAsync(process.execPath, [bootstrapPath], {
      cwd: root,
      env: {
        PATH: process.env.PATH,
        NODE_PATH: "/tmp/untrusted-modules",
      },
      encoding: "utf8",
    }),
    (error) => {
      assert.match(
        error.stdout,
        /INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED/u,
      );
      assert.equal(error.stderr, "");
      return true;
    },
  );
});

test("bootstrap accepts only a complete macOS text-encoding environment format", async () => {
  for (const value of [
    "0x1F5:0:0",
    "0x1F5:0x0:0x0",
  ]) {
    await assert.rejects(
      execFileAsync(process.execPath, [bootstrapPath], {
        cwd: root,
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          ZB_KIMI_SANITIZED_LAUNCHER: "1",
          __CF_USER_TEXT_ENCODING: value,
        },
        encoding: "utf8",
      }),
      (error) => {
        assert.match(error.stdout, /KIMI_BOOTSTRAP_ARGUMENTS_INVALID/u);
        assert.equal(error.stderr, "");
        return true;
      },
    );
  }

  for (const value of [
    "0x1F5:0x0:0",
    "0x1F5:0:0x0",
  ]) {
    await assert.rejects(
      execFileAsync(process.execPath, [bootstrapPath], {
        cwd: root,
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          ZB_KIMI_SANITIZED_LAUNCHER: "1",
          __CF_USER_TEXT_ENCODING: value,
        },
        encoding: "utf8",
      }),
      (error) => {
        assert.match(
          error.stdout,
          /INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED/u,
        );
        assert.equal(error.stderr, "");
        return true;
      },
    );
  }
});

test("bootstrap rejects a safe-looking review ID that cannot become a Receipt before runtime access", async () => {
  const args = [
    "--repo",
    root,
    "--bundle",
    "/tmp/nonexistent-review-bundle.json",
    "--material",
    "/tmp/nonexistent-review-material.utf8",
    "--output-dir",
    "/tmp/nonexistent-review-output",
    "--review-id",
    "review-safe-20260731",
    "--runtime-commit",
    "1".repeat(40),
    "--runtime-tree",
    "2".repeat(40),
    "--bootstrap-sha256",
    `sha256:${"3".repeat(64)}`,
    "--launcher-sha256",
    `sha256:${"4".repeat(64)}`,
  ];

  await assert.rejects(
    execFileAsync(process.execPath, [bootstrapPath, ...args], {
      cwd: root,
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        ZB_KIMI_SANITIZED_LAUNCHER: "1",
      },
      encoding: "utf8",
    }),
    (error) => {
      assert.match(error.stdout, /KIMI_BOOTSTRAP_ARGUMENTS_INVALID/u);
      assert.equal(error.stderr, "");
      return true;
    },
  );
});

test("external launcher removes preload variables before Node starts", async (t) => {
  const probeRoot = await mkdtemp(join(tmpdir(), "zb-kimi-launcher-"));
  t.after(() => rm(probeRoot, { recursive: true, force: true }));
  const marker = join(probeRoot, "preload-marker");
  const preload = join(probeRoot, "preload.cjs");
  await writeFile(
    preload,
    `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran");\n`,
  );

  await assert.rejects(
    execFileAsync(
      "/usr/bin/env",
      [
        "-i",
        "PATH=/usr/bin:/bin",
        "LANG=C",
        "LC_ALL=C",
        "/bin/sh",
        launcherPath,
        process.execPath,
      ],
      {
        cwd: root,
        env: {
          ...process.env,
          NODE_OPTIONS: `--require=${preload}`,
          BASH_ENV: preload,
        },
        encoding: "utf8",
      },
    ),
    (error) => {
      assert.match(error.stdout, /KIMI_BOOTSTRAP_ARGUMENTS_INVALID/u);
      assert.equal(error.stderr, "");
      return true;
    },
  );
  await assert.rejects(access(marker));
});

test("runtime trust anchor is a separate ancestor commit with exact launcher and bootstrap bytes", async (t) => {
  const repo = await mkdtemp(join(tmpdir(), "zb-kimi-runtime-trust-"));
  t.after(() => rm(repo, { recursive: true, force: true }));
  await git(repo, ["init", "-q"]);
  await git(repo, ["config", "user.name", "Runtime Trust Test"]);
  await git(repo, [
    "config",
    "user.email",
    "runtime-trust@example.invalid",
  ]);
  await mkdir(join(repo, "scripts"), { recursive: true });
  const [bootstrapBytes, launcherBytes] = await Promise.all([
    readFile(bootstrapPath),
    readFile(launcherPath),
  ]);
  await Promise.all([
    writeFile(
      join(repo, "scripts/bootstrap-kimi-independent-review.mjs"),
      bootstrapBytes,
    ),
    writeFile(
      join(repo, "scripts/launch-kimi-independent-review.sh"),
      launcherBytes,
    ),
  ]);
  await git(repo, ["add", "."]);
  await git(repo, ["commit", "-q", "-m", "runtime trust"]);
  const { stdout: runtimeCommitText } = await git(repo, [
    "rev-parse",
    "HEAD",
  ]);
  const { stdout: runtimeTreeText } = await git(repo, [
    "rev-parse",
    "HEAD^{tree}",
  ]);
  await writeFile(join(repo, "subject.txt"), "review subject\n");
  await git(repo, ["add", "subject.txt"]);
  await git(repo, ["commit", "-q", "-m", "subject"]);
  const { stdout: subjectCommitText } = await git(repo, [
    "rev-parse",
    "HEAD",
  ]);
  const { stdout: subjectTreeText } = await git(repo, [
    "rev-parse",
    "HEAD^{tree}",
  ]);
  const anchor = {
    runtimeCommit: runtimeCommitText.trim(),
    runtimeTree: runtimeTreeText.trim(),
    bootstrapSha256: sha256Bytes(bootstrapBytes),
    launcherSha256: sha256Bytes(launcherBytes),
  };

  const result = await validateKimiRuntimeTrustAnchor({
    repoPath: repo,
    subjectCommit: subjectCommitText.trim(),
    subjectTree: subjectTreeText.trim(),
    anchor,
    executingBootstrapPath: bootstrapPath,
    executingLauncherPath: launcherPath,
  });
  assert.equal(result.ok, true);
  assert.equal(result.runtimeCommit, anchor.runtimeCommit);
  assert.equal(result.subjectCommit, subjectCommitText.trim());

  for (const changed of [
    { ...anchor, runtimeCommit: subjectCommitText.trim() },
    { ...anchor, runtimeTree: "0".repeat(40) },
    { ...anchor, bootstrapSha256: `sha256:${"0".repeat(64)}` },
    { ...anchor, launcherSha256: `sha256:${"0".repeat(64)}` },
  ]) {
    await assert.rejects(
      validateKimiRuntimeTrustAnchor({
        repoPath: repo,
        subjectCommit: subjectCommitText.trim(),
        subjectTree: subjectTreeText.trim(),
        anchor: changed,
        executingBootstrapPath: bootstrapPath,
        executingLauncherPath: launcherPath,
      }),
      /RUNTIME_TRUST_NOT_PROVED/u,
    );
  }
});
