import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const runner = new URL(
  "../scripts/run-g1-frozen-verification.sh",
  import.meta.url,
).pathname;

function run(command, args, cwd) {
  return spawnSync(command, args, {
    cwd,
    encoding: "utf8",
  });
}

async function createRepository({ lintExitCode = 0, withLock = true } = {}) {
  const cwd = await mkdtemp(join(tmpdir(), "g1-frozen-runner-"));
  const packageJson = {
    name: "g1-frozen-runner-fixture",
    version: "1.0.0",
    private: true,
    scripts: {
      lint: `node -e "process.exit(${lintExitCode})"`,
    },
  };
  await writeFile(
    join(cwd, "package.json"),
    `${JSON.stringify(packageJson, null, 2)}\n`,
  );
  if (withLock) {
    const packageLock = {
      name: packageJson.name,
      version: packageJson.version,
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": {
          name: packageJson.name,
          version: packageJson.version,
        },
      },
    };
    await writeFile(
      join(cwd, "package-lock.json"),
      `${JSON.stringify(packageLock, null, 2)}\n`,
    );
  }
  assert.equal(run("git", ["init", "-q"], cwd).status, 0);
  assert.equal(
    run("git", ["config", "user.email", "g1-runner@example.invalid"], cwd)
      .status,
    0,
  );
  assert.equal(
    run("git", ["config", "user.name", "G1 Runner Test"], cwd).status,
    0,
  );
  assert.equal(run("git", ["add", "."], cwd).status, 0);
  assert.equal(
    run("git", ["commit", "-qm", "fixture"], cwd).status,
    0,
  );
  return cwd;
}

function records(stdout) {
  return stdout
    .split("\n")
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line));
}

test("rejects an unknown verification mode", async (t) => {
  const cwd = await createRepository();
  t.after(() => rm(cwd, { recursive: true, force: true }));

  const result = run("sh", [runner, "unknown"], cwd);

  assert.equal(result.status, 64);
  assert.match(result.stderr, /Usage:/);
});

test("rejects tracked changes before emitting a start record", async (t) => {
  const cwd = await createRepository();
  t.after(() => rm(cwd, { recursive: true, force: true }));
  await writeFile(join(cwd, "package.json"), "{}\n");

  const result = run("sh", [runner, "lint"], cwd);

  assert.notEqual(result.status, 0);
  assert.equal(records(result.stdout).length, 0);
  assert.match(result.stderr, /Tracked worktree changes/);
});

test("fails closed when package-lock.json is unavailable", async (t) => {
  const cwd = await createRepository({ withLock: false });
  t.after(() => rm(cwd, { recursive: true, force: true }));

  const result = run("sh", [runner, "lint"], cwd);

  assert.notEqual(result.status, 0);
  assert.equal(records(result.stdout).length, 0);
  assert.match(result.stderr, /valid package-lock\.json SHA-256/);
});

test("rejects a pre-existing dependency installation", async (t) => {
  const cwd = await createRepository();
  t.after(() => rm(cwd, { recursive: true, force: true }));
  await mkdir(join(cwd, "node_modules"));

  const result = run("sh", [runner, "lint"], cwd);

  assert.notEqual(result.status, 0);
  assert.equal(records(result.stdout).length, 0);
  assert.match(result.stderr, /node_modules must be absent/);
});

test("rejects other untracked content at run start", async (t) => {
  const cwd = await createRepository();
  t.after(() => rm(cwd, { recursive: true, force: true }));
  await writeFile(join(cwd, "untracked.txt"), "not part of the candidate\n");

  const result = run("sh", [runner, "lint"], cwd);

  assert.notEqual(result.status, 0);
  assert.equal(records(result.stdout).length, 0);
  assert.match(result.stderr, /Untracked or ignored worktree content/);
});

test("rejects ignored content at run start", async (t) => {
  const cwd = await createRepository();
  t.after(() => rm(cwd, { recursive: true, force: true }));
  await writeFile(join(cwd, ".gitignore"), "ignored.txt\n");
  assert.equal(run("git", ["add", ".gitignore"], cwd).status, 0);
  assert.equal(
    run("git", ["commit", "-qm", "ignore fixture"], cwd).status,
    0,
  );
  await writeFile(join(cwd, "ignored.txt"), "can affect the run\n");

  const result = run("sh", [runner, "lint"], cwd);

  assert.notEqual(result.status, 0);
  assert.equal(records(result.stdout).length, 0);
  assert.match(result.stderr, /Untracked or ignored worktree content/);
});

test("binds a successful command to one fresh dependency install", async (t) => {
  const cwd = await createRepository();
  t.after(() => rm(cwd, { recursive: true, force: true }));

  const result = run("sh", [runner, "lint"], cwd);

  assert.equal(result.status, 0, result.stderr);
  const runRecords = records(result.stdout);
  assert.equal(runRecords.length, 3);
  const [start, dependencies, complete] = runRecords;
  assert.deepEqual(
    [start.schemaVersion, dependencies.schemaVersion, complete.schemaVersion],
    [
      "g1-frozen-verification-start.v1",
      "g1-frozen-verification-dependencies-complete.v1",
      "g1-frozen-verification-complete.v1",
    ],
  );
  assert.equal(start.runId, dependencies.runId);
  assert.equal(start.runId, complete.runId);
  for (const record of [dependencies, complete]) {
    assert.equal(record.candidateCommit, start.candidateCommit);
    assert.equal(record.candidateTree, start.candidateTree);
    assert.equal(record.packageLockSha256, start.packageLockSha256);
    assert.equal(record.verificationCommand, start.verificationCommand);
    assert.equal(
      record.dependencyInstallCommand,
      start.dependencyInstallCommand,
    );
    assert.equal(record.nodeVersion, start.nodeVersion);
    assert.equal(record.npmVersion, start.npmVersion);
    assert.equal(record.operatingSystem, start.operatingSystem);
    assert.equal(record.architecture, start.architecture);
  }
  assert.equal(start.verificationCommand, "npm run lint");
  assert.equal(start.nodeModulesPresentAtStart, false);
  assert.equal(start.freshDependencyInstallCompleted, false);
  assert.equal(start.npmDependencyTreeSha256, null);
  assert.equal(dependencies.freshDependencyInstallCompleted, true);
  assert.match(dependencies.npmDependencyTreeSha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    dependencies.npmDependencyTreeSha256,
    complete.npmDependencyTreeSha256,
  );
  assert.equal(complete.exitCode, 0);
  assert.equal(complete.trackedWorktreeClean, true);
  assert.match(complete.npmVersion, /^\d+\./);
});

test("does not emit completion when the verification command fails", async (t) => {
  const cwd = await createRepository({ lintExitCode: 7 });
  t.after(() => rm(cwd, { recursive: true, force: true }));

  const result = run("sh", [runner, "lint"], cwd);

  assert.equal(result.status, 7);
  const runRecords = records(result.stdout);
  assert.deepEqual(
    runRecords.map((record) => record.schemaVersion),
    [
      "g1-frozen-verification-start.v1",
      "g1-frozen-verification-dependencies-complete.v1",
    ],
  );
});
