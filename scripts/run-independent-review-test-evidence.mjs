#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  copyFile,
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
  assertIndependentReviewGitCollectionUnchanged,
  parseIndependentReviewTapSummary,
  tapSummaryMatchesExpectation,
  validateIndependentReviewTestPlan,
} from "../lib/independent-model-review.mjs";
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
  "isolation=macos-sandbox-exec-git-archive-readonly-history-network-denied";
const NETWORK_TEST_MODE =
  "network-test-mode=frozen-deterministic-offline-alternatives";
const FORMAL_NPM_TEST_SCRIPT =
  "npm run build && node --test --test-reporter=tap tests/*.test.mjs";
const FORMAL_NPM_SCRIPT_CLOSURE = Object.freeze({
  test: FORMAL_NPM_TEST_SCRIPT,
  build:
    "npm run f02:gate:prebuild && npm run build:app && npm run f02:gate:release",
  "build:app": "WRANGLER_LOG_PATH=.wrangler/wrangler.log vinext build",
  "postbuild:app": "npm run p2:verify:worker-bundle",
  "f02:gate:prebuild":
    "node scripts/f02-protected-surface-gate.mjs --stage PREBUILD",
  "f02:gate:release":
    "node scripts/f02-protected-surface-gate.mjs --stage RELEASE",
  "p2:verify:worker-bundle":
    "node scripts/verify-p2-worker-runtime-bundle.mjs",
  lint: "eslint . --ignore-pattern dist --ignore-pattern .next",
});
const FORBIDDEN_NPM_LIFECYCLE_SCRIPTS = Object.freeze(
  Object.keys(FORMAL_NPM_SCRIPT_CLOSURE)
    .flatMap((name) => [`pre${name}`, `post${name}`])
    .filter((name) => name !== "postbuild:app")
    .sort(),
);
const DEVELOPER_TOOLCHAIN_ROOT =
  "/Library/Developer/CommandLineTools";
const SYSTEM_GIT_SHIM = "/usr/bin/git";
const SYSTEM_XCRUN = "/usr/bin/xcrun";
const SYSTEM_SHASUM = "/usr/bin/shasum";
const SYSTEM_PERL = "/usr/bin/perl";
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
const frozenXcrunEnvironment =
  process.env.INDEPENDENT_REVIEW_NETWORK_MODE ===
    "DENY_ALL_OFFLINE_ALTERNATIVES" &&
  typeof process.env.xcrun_db === "string" &&
  process.env.xcrun_db.startsWith("/") &&
  !process.env.xcrun_db.includes("\0")
    ? Object.freeze({ xcrun_db: process.env.xcrun_db })
    : Object.freeze({});

const hashBytes = (value) =>
  `sha256:${createHash("sha256").update(value).digest("hex")}`;

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
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
  if (!(await validateIndependentReviewTestPlan(plan))) {
    throw new TypeError("Independent review test plan is invalid.");
  }
}

export function validateIndependentReviewNpmPackageBoundary({
  packageJson,
  projectNpmrcPaths,
}) {
  return (
    packageJson !== null &&
    typeof packageJson === "object" &&
    !Array.isArray(packageJson) &&
    packageJson.scripts !== null &&
    typeof packageJson.scripts === "object" &&
    !Array.isArray(packageJson.scripts) &&
    Array.isArray(projectNpmrcPaths) &&
    projectNpmrcPaths.length === 0 &&
    Object.entries(FORMAL_NPM_SCRIPT_CLOSURE).every(
      ([name, command]) => packageJson.scripts[name] === command,
    ) &&
    FORBIDDEN_NPM_LIFECYCLE_SCRIPTS.every(
      (name) => !Object.hasOwn(packageJson.scripts, name),
    )
  );
}

function asciiCaseFold(value) {
  return value.replace(/[A-Z]/gu, (character) =>
    String.fromCharCode(character.charCodeAt(0) + 32),
  );
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
        DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
        GIT_OPTIONAL_LOCKS: "0",
        ...frozenXcrunEnvironment,
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
        DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
        GIT_OPTIONAL_LOCKS: "0",
        ...frozenXcrunEnvironment,
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

async function filesystemManifest(rootPath) {
  const records = [];
  const visit = async (directory, relativeDirectory = "") => {
    const children = (await readdir(directory, { withFileTypes: true })).sort(
      ({ name: left }, { name: right }) =>
        Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
    );
    for (const child of children) {
      const relativePath = relativeDirectory
        ? `${relativeDirectory}/${child.name}`
        : child.name;
      if (!SAFE_PATH.test(relativePath)) {
        throw new TypeError("Git history metadata path is unsafe.");
      }
      const absolutePath = join(directory, child.name);
      const metadata = await lstat(absolutePath);
      if (child.isDirectory()) {
        records.push({
          path: relativePath,
          type: "DIRECTORY",
          mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
          byteLength: 0,
          sha256: hashBytes(Buffer.alloc(0)),
        });
        await visit(absolutePath, relativePath);
        continue;
      }
      let bytes;
      if (child.isFile()) {
        if (metadata.nlink !== 1) {
          throw new TypeError("Git history contains a hard-linked file.");
        }
        bytes = await readFile(absolutePath);
      } else if (child.isSymbolicLink()) {
        throw new TypeError("Git history contains a symbolic link.");
      } else {
        throw new TypeError("Git history contains a special file.");
      }
      records.push({
        path: relativePath,
        type: "FILE",
        mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
        byteLength: bytes.byteLength,
        sha256: hashBytes(bytes),
      });
    }
  };
  await visit(rootPath);
  records.sort(({ path: left }, { path: right }) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (records.length === 0) {
    throw new TypeError("Git history metadata is empty.");
  }
  return sha256ProjectValue(records);
}

async function reachableGitObjects(repoPath, rootObjectIds) {
  if (
    !Array.isArray(rootObjectIds) ||
    rootObjectIds.length === 0 ||
    rootObjectIds.length > 4097 ||
    rootObjectIds.some((objectId) => !COMMIT.test(objectId))
  ) {
    throw new TypeError("Git reachable roots are invalid.");
  }
  const { stdout } = await git(repoPath, [
    "rev-list",
    "--objects",
    "--no-object-names",
    ...[...new Set(rootObjectIds)].sort(),
  ]);
  const objects = Buffer.from(stdout)
    .toString("ascii")
    .trim()
    .split("\n")
    .filter(Boolean)
    .sort();
  if (
    objects.length === 0 ||
    objects.some((objectId) => !COMMIT.test(objectId)) ||
    new Set(objects).size !== objects.length
  ) {
    throw new TypeError("Git reachable object set is invalid.");
  }
  return objects;
}

async function exactGitRefTips(repoPath) {
  const { stdout } = await git(repoPath, [
    "for-each-ref",
    "--sort=refname",
    "--format=%(refname)%00%(objectname)%00",
  ]);
  const fields = Buffer.from(stdout)
    .toString("utf8")
    .split("\0")
    .map((value) => value.replace(/^\n+|\n+$/gu, ""))
    .filter(Boolean);
  if (
    fields.length === 0 ||
    fields.length % 2 !== 0 ||
    fields.length / 2 > 4096
  ) {
    throw new TypeError("Git ref-tip set is invalid.");
  }
  const records = [];
  for (let index = 0; index < fields.length; index += 2) {
    const refName = fields[index];
    const objectId = fields[index + 1];
    if (
      !/^refs\/[^\u0000-\u001f ~^:?*[\\]+$/u.test(refName) ||
      !COMMIT.test(objectId)
    ) {
      throw new TypeError("Git ref-tip record is invalid.");
    }
    records.push({ refName, objectId });
  }
  if (
    new Set(records.map(({ refName }) => refName)).size !== records.length ||
    JSON.stringify(records) !==
      JSON.stringify(
        [...records].sort(({ refName: left }, { refName: right }) =>
          Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
        ),
      )
  ) {
    throw new TypeError("Git ref-tip ordering is invalid.");
  }
  return records;
}

async function allGitObjects(repoPath) {
  const { stdout } = await git(repoPath, [
    "cat-file",
    "--batch-all-objects",
    "--batch-check=%(objectname)",
  ]);
  const objects = Buffer.from(stdout)
    .toString("ascii")
    .trim()
    .split("\n")
    .filter(Boolean)
    .sort();
  if (
    objects.length === 0 ||
    objects.some((objectId) => !COMMIT.test(objectId)) ||
    new Set(objects).size !== objects.length
  ) {
    throw new TypeError("Git object inventory is invalid.");
  }
  return objects;
}

async function assertNoGitObjectAlternates(gitHistoryRoot) {
  for (const name of ["alternates", "http-alternates"]) {
    try {
      await lstat(resolve(gitHistoryRoot, "objects", "info", name));
      throw new TypeError("Git history uses an external object alternate.");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
}

async function gitDirectory(gitDirectory, args) {
  return execFileAsync(
    "/usr/bin/git",
    [
      "--no-replace-objects",
      `--git-dir=${gitDirectory}`,
      ...args,
    ],
    {
      encoding: "buffer",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
        GIT_OPTIONAL_LOCKS: "0",
        ...frozenXcrunEnvironment,
      },
      maxBuffer: MAX_OUTPUT,
    },
  );
}

async function makeDirectoryTreeReadOnly(rootPath) {
  const visit = async (directory) => {
    const children = await readdir(directory, { withFileTypes: true });
    for (const child of children) {
      const absolutePath = join(directory, child.name);
      if (child.isDirectory()) {
        await visit(absolutePath);
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

async function createGitHistorySnapshot({
  repoPath,
  parent,
  source,
  sourceCommit,
  sourceTree,
  expectedXcrunCacheSha256,
  expectedRefTips,
  expectedObjects,
}) {
  const requestedGitHistoryRoot = resolve(parent, "git-history");
  const refTipsBefore = await exactGitRefTips(repoPath);
  await assertIndependentReviewGitCollectionUnchanged(
    expectedRefTips,
    refTipsBefore,
  );
  const rootObjectIds = [
    sourceCommit,
    ...expectedRefTips.map(({ objectId }) => objectId),
  ];
  if (
    JSON.stringify(
      await reachableGitObjects(repoPath, rootObjectIds),
    ) !== JSON.stringify(expectedObjects)
  ) {
    throw new TypeError(
      "Independent review reachable object set changed during collection.",
    );
  }
  await mkdir(requestedGitHistoryRoot, { mode: 0o700 });
  const gitHistoryRoot = await realpath(requestedGitHistoryRoot);
  await gitDirectory(gitHistoryRoot, ["init", "--bare", "-q"]);
  await gitDirectory(gitHistoryRoot, [
    "fetch",
    "--no-tags",
    "--no-write-fetch-head",
    repoPath,
    ...[...new Set(rootObjectIds)]
      .sort()
      .map(
        (objectId, index) =>
          `+${objectId}:refs/review-snapshot/${String(index).padStart(4, "0")}`,
      ),
  ]);
  await gitDirectory(gitHistoryRoot, [
    "update-ref",
    "refs/heads/review-source",
    sourceCommit,
  ]);
  await gitDirectory(gitHistoryRoot, [
    "symbolic-ref",
    "HEAD",
    "refs/heads/review-source",
  ]);
  await gitDirectory(gitHistoryRoot, ["config", "core.bare", "false"]);
  await gitDirectory(gitHistoryRoot, [
    "config",
    "core.worktree",
    source,
  ]);
  await gitDirectory(gitHistoryRoot, ["read-tree", sourceCommit]);

  const { stdout: cachePathStdout } = await execFileAsync(
    SYSTEM_XCRUN,
    ["--show-cache-path"],
    {
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
        ...frozenXcrunEnvironment,
      },
      maxBuffer: 1024 * 1024,
    },
  );
  const xcrunCacheSource = cachePathStdout.trim();
  const xcrunDb = resolve(gitHistoryRoot, "xcrun_db");
  await copyFile(xcrunCacheSource, xcrunDb);
  if (hashBytes(await readFile(xcrunDb)) !== expectedXcrunCacheSha256) {
    throw new TypeError("Frozen xcrun cache bytes changed.");
  }

  const pointerBytes = Buffer.from(
    `gitdir: ${gitHistoryRoot}\n`,
    "utf8",
  );
  await writeFile(resolve(source, ".git"), pointerBytes, { mode: 0o400 });

  const refTipsAfter = await exactGitRefTips(repoPath);
  await assertIndependentReviewGitCollectionUnchanged(
    expectedRefTips,
    refTipsAfter,
  );
  const actualObjects = await reachableGitObjects(source, rootObjectIds);
  const allObjects = await allGitObjects(source);
  const { stdout: actualTreeBytes } = await git(source, [
    "rev-parse",
    `${sourceCommit}^{tree}`,
  ]);
  if (
    JSON.stringify(actualObjects) !== JSON.stringify(expectedObjects) ||
    JSON.stringify(allObjects) !== JSON.stringify(expectedObjects) ||
    Buffer.from(actualTreeBytes).toString("utf8").trim() !== sourceTree
  ) {
    throw new TypeError("Read-only Git history snapshot is incomplete.");
  }
  await assertNoGitObjectAlternates(gitHistoryRoot);

  await makeDirectoryTreeReadOnly(gitHistoryRoot);
  return {
    root: gitHistoryRoot,
    xcrunDb,
    rootObjectIds,
    binding: {
      mode: "READ_ONLY_ALL_REF_REACHABLE_OBJECT_SNAPSHOT",
      sourceCommit,
      sourceTree,
      refTipCount: expectedRefTips.length,
      refTipSetSha256: await sha256ProjectValue(expectedRefTips),
      reachableObjectCount: expectedObjects.length,
      reachableObjectSetSha256:
        await sha256ProjectValue(expectedObjects),
      pointerSha256: hashBytes(pointerBytes),
      beforeManifestSha256:
        await filesystemManifest(gitHistoryRoot),
      afterManifestSha256: `sha256:${"0".repeat(64)}`,
      unchanged: false,
      metadataWritable: false,
    },
  };
}

async function finishGitHistorySnapshot(source, gitHistory) {
  const pointerBytes = await readFile(resolve(source, ".git"));
  const actualObjects = await reachableGitObjects(
    source,
    gitHistory.rootObjectIds,
  );
  const allObjects = await allGitObjects(source);
  return {
    ...gitHistory.binding,
    reachableObjectCount: actualObjects.length,
    reachableObjectSetSha256: await sha256ProjectValue(actualObjects),
    pointerSha256: hashBytes(pointerBytes),
    afterManifestSha256:
      await filesystemManifest(gitHistory.root),
    unchanged:
      hashBytes(pointerBytes) === gitHistory.binding.pointerSha256 &&
      actualObjects.length ===
        gitHistory.binding.reachableObjectCount &&
      JSON.stringify(allObjects) === JSON.stringify(actualObjects) &&
      (await sha256ProjectValue(actualObjects)) ===
        gitHistory.binding.reachableObjectSetSha256 &&
      (await filesystemManifest(gitHistory.root)) ===
        gitHistory.binding.beforeManifestSha256,
  };
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
  gitHistory,
}) {
  const gitPointerPath = resolve(source, ".git");
  const gitPointerMetadata = await lstat(gitPointerPath);
  const gitPointerBytes = await readFile(gitPointerPath);
  if (
    !gitPointerMetadata.isFile() ||
    gitPointerMetadata.isSymbolicLink() ||
    hashBytes(gitPointerBytes) !== gitHistory.binding.pointerSha256 ||
    (await realpath(gitHistory.root)) !== gitHistory.root ||
    !(await lstat(gitHistory.root)).isDirectory()
  ) {
    throw new TypeError("Read-only Git history binding is invalid.");
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
        await chmod(absolutePath, 0o755);
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
  await chmod(rootPath, 0o755);
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

async function isolatedSourceExport(
  repoPath,
  sourceCommit,
  sourceTree,
  expectedXcrunCacheSha256,
  expectedRefTips,
  expectedObjects,
) {
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
          DEVELOPER_DIR: DEVELOPER_TOOLCHAIN_ROOT,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_SYSTEM: "/dev/null",
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_ATTR_NOSYSTEM: "1",
          GIT_OPTIONAL_LOCKS: "0",
          ...frozenXcrunEnvironment,
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
    try {
      await lstat(resolve(source, ".npmrc"));
      throw new TypeError(
        "Git archive contains a case-aliased project npm configuration.",
      );
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
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
    const gitHistory = await createGitHistorySnapshot({
      repoPath,
      parent,
      source: exactSource,
      sourceCommit,
      sourceTree,
      expectedXcrunCacheSha256,
      expectedRefTips,
      expectedObjects,
    });
    await validateExecutionInfrastructure({
      source: exactSource,
      dependencyRoot,
      dependencyOverlayEntries,
      gitHistory,
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
      gitHistory,
      expectedRecords,
      before,
    };
  } catch (error) {
    await makeSourceDisposable(source);
    await makeSourceDisposable(resolve(parent, "git-history"));
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
  const npmConfigRoot = await mkdtemp(
    join(isolated.parent, "npm-config-"),
  );
  try {
    const exactScratchRoot = await realpath(scratchRoot);
    const exactNpmConfigRoot = await realpath(npmConfigRoot);
    const npmUserConfig = resolve(exactNpmConfigRoot, "user.npmrc");
    const npmGlobalConfig = resolve(exactNpmConfigRoot, "global.npmrc");
    const emptyNpmConfigBytes = Buffer.alloc(0);
    await Promise.all([
      writeFile(npmUserConfig, emptyNpmConfigBytes, { mode: 0o400 }),
      writeFile(npmGlobalConfig, emptyNpmConfigBytes, { mode: 0o400 }),
    ]);
    await chmod(exactNpmConfigRoot, 0o500);
    const npmConfigSha256 = hashBytes(emptyNpmConfigBytes);
    const assertNpmConfigsUnchanged = async () => {
      const [userBytes, globalBytes] = await Promise.all([
        readFile(npmUserConfig),
        readFile(npmGlobalConfig),
      ]);
      if (
        hashBytes(userBytes) !== npmConfigSha256 ||
        hashBytes(globalBytes) !== npmConfigSha256
      ) {
        throw new TypeError(
          "Frozen npm configuration changed during test execution.",
        );
      }
    };
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
      GIT_HISTORY_ROOT: hashBytes(
        Buffer.from(isolated.gitHistory.root, "utf8"),
      ),
      XCRUN_DB: hashBytes(
        Buffer.from(isolated.gitHistory.xcrunDb, "utf8"),
      ),
      SYSTEM_GIT_SHIM: hashBytes(
        Buffer.from(SYSTEM_GIT_SHIM, "utf8"),
      ),
      SYSTEM_XCRUN: hashBytes(Buffer.from(SYSTEM_XCRUN, "utf8")),
      SYSTEM_SHASUM: hashBytes(Buffer.from(SYSTEM_SHASUM, "utf8")),
      SYSTEM_PERL: hashBytes(Buffer.from(SYSTEM_PERL, "utf8")),
      DEVELOPER_TOOLCHAIN_ROOT: hashBytes(
        Buffer.from(DEVELOPER_TOOLCHAIN_ROOT, "utf8"),
      ),
      WRITABLE_WORK_ROOTS: await sha256ProjectValue(
        WRITABLE_WORK_ROOTS,
      ),
      NPM_USER_CONFIG: hashBytes(
        Buffer.from(npmUserConfig, "utf8"),
      ),
      NPM_USER_CONFIG_SHA256: npmConfigSha256,
      NPM_GLOBAL_CONFIG: hashBytes(Buffer.from(npmGlobalConfig, "utf8")),
      NPM_GLOBAL_CONFIG_SHA256: npmConfigSha256,
      NPM_SCRIPT_SHELL: hashBytes(Buffer.from("/bin/sh", "utf8")),
      NPM_NODE_OPTIONS: hashBytes(Buffer.alloc(0)),
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
          `GIT_HISTORY_ROOT=${isolated.gitHistory.root}`,
          "-D",
          `NPM_USER_CONFIG=${npmUserConfig}`,
          "-D",
          `NPM_GLOBAL_CONFIG=${npmGlobalConfig}`,
          "-D",
          `XCRUN_DB=${isolated.gitHistory.xcrunDb}`,
          "-D",
          `SYSTEM_GIT_SHIM=${SYSTEM_GIT_SHIM}`,
          "-D",
          `SYSTEM_XCRUN=${SYSTEM_XCRUN}`,
          "-D",
          `SYSTEM_SHASUM=${SYSTEM_SHASUM}`,
          "-D",
          `SYSTEM_PERL=${SYSTEM_PERL}`,
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
            xcrun_db: isolated.gitHistory.xcrunDb,
            npm_config_cache: exactScratchRoot,
            npm_config_userconfig: npmUserConfig,
            npm_config_globalconfig: npmGlobalConfig,
            npm_config_script_shell: "/bin/sh",
            npm_config_node_options: "",
            npm_config_ignore_scripts: "false",
            npm_config_prefix: resolve(exactScratchRoot, "prefix"),
            npm_config_audit: "false",
            npm_config_fund: "false",
            npm_config_update_notifier: "false",
            CI: "1",
            INDEPENDENT_REVIEW_NETWORK_MODE:
              "DENY_ALL_OFFLINE_ALTERNATIVES",
            WRANGLER_SEND_METRICS: "false",
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_SYSTEM: "/dev/null",
            GIT_CONFIG_GLOBAL: "/dev/null",
            GIT_ATTR_NOSYSTEM: "1",
            GIT_OPTIONAL_LOCKS: "0",
          },
          maxBuffer: MAX_OUTPUT,
          timeout: command.timeoutMs,
          killSignal: "SIGKILL",
        },
      );
      await assertNpmConfigsUnchanged();
      return { ...result, sandboxBinding };
    } catch (error) {
      await assertNpmConfigsUnchanged();
      error.sandboxBinding = sandboxBinding;
      throw error;
    }
  } finally {
    await rm(scratchRoot, { recursive: true, force: true });
    await chmod(npmConfigRoot, 0o700).catch(() => {});
    await rm(npmConfigRoot, { recursive: true, force: true });
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
  if (plan.commands.some(({ executable }) => executable === "NPM")) {
    let packageJson;
    let projectNpmrcPaths;
    try {
      const [packageJsonBytes, rootTree] = await Promise.all([
        gitBytes(repoPath, sourceCommit, "package.json"),
        git(repoPath, [
          "ls-tree",
          "-z",
          "--name-only",
          sourceCommit,
        ]),
      ]);
      packageJson = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(packageJsonBytes),
      );
      projectNpmrcPaths = new TextDecoder("utf-8", { fatal: true })
        .decode(Buffer.from(rootTree.stdout))
        .split("\0")
        .filter((name) => asciiCaseFold(name) === ".npmrc");
    } catch {
      throw new TypeError(
        "Frozen npm execution boundary is invalid.",
      );
    }
    if (
      !validateIndependentReviewNpmPackageBoundary({
        packageJson,
        projectNpmrcPaths,
      })
    ) {
      throw new TypeError(
        "Frozen npm execution boundary is invalid.",
      );
    }
  }
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
  const frozenRefTips = await exactGitRefTips(exactRepoPath);
  const frozenRootObjectIds = [
    sourceCommit,
    ...frozenRefTips.map(({ objectId }) => objectId),
  ];
  const frozenReachableObjects = await reachableGitObjects(
    exactRepoPath,
    frozenRootObjectIds,
  );
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
    systemToolchainSha256:
      runtimeBinding.systemToolchain.bindingSha256,
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
      runtimeBinding.gitToolchain.xcrunCache.sha256,
      frozenRefTips,
      frozenReachableObjects,
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
    if (
      new TextDecoder("utf-8", { fatal: false })
        .decode(stderr)
        .startsWith("sandbox-exec: sandbox_apply:")
    ) {
      try {
        await makeSourceDisposable(isolated.source);
        await makeSourceDisposable(isolated.gitHistory.root);
      } finally {
        await rm(isolated.parent, { recursive: true, force: true });
      }
      const error = new TypeError(
        "NESTED_TEST_COLLECTOR_SEATBELT_UNAVAILABLE",
      );
      error.reasonCodes = [
        "NESTED_TEST_COLLECTOR_SEATBELT_UNAVAILABLE",
      ];
      throw error;
    }
    const finishedAt = new Date().toISOString();
    let after;
    let gitHistoryAfter;
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
      gitHistoryAfter = await finishGitHistorySnapshot(
        isolated.source,
        isolated.gitHistory,
      );
      await validateExecutionInfrastructure(isolated);
    } finally {
      await makeSourceDisposable(isolated.source);
      await makeSourceDisposable(isolated.gitHistory.root);
      await rm(isolated.parent, { recursive: true, force: true });
    }
    const executionUnchanged =
      JSON.stringify(isolated.before) === JSON.stringify(after) &&
      gitHistoryAfter.unchanged === true;
    const testSummary = Object.hasOwn(command, "testExpectation")
      ? await parseIndependentReviewTapSummary(stdout)
      : null;
    const testExpectationMatched = Object.hasOwn(
      command,
      "testExpectation",
    )
      ? await tapSummaryMatchesExpectation(
          testSummary,
          command.testExpectation,
        )
      : true;
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
        mode: "MACOS_SEATBELT_GIT_ARCHIVE_READONLY_HISTORY_V3",
        cloneMode:
          "GIT_ARCHIVE_WITH_READ_ONLY_HISTORY_SNAPSHOT",
        before: isolated.before,
        after,
        unchanged: executionUnchanged,
        gitHistory: gitHistoryAfter,
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
          gitMetadataPresent: true,
          gitMetadataWritable: false,
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
      testSummary,
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
        executionUnchanged &&
        testExpectationMatched
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
        `system-toolchain=${runtimeBinding.systemToolchain.bindingSha256}`,
        SANDBOX_VERSION,
        NETWORK_TEST_MODE,
        `sandbox-template=${result.executionSource.sandbox.templateSha256}`,
        `sandbox-invocation=${result.executionSource.sandbox.invocationSha256}`,
      ],
    });
  }
  await assertIndependentReviewGitCollectionUnchanged(
    frozenRefTips,
    await exactGitRefTips(exactRepoPath),
  );
  if (
    JSON.stringify(
      await reachableGitObjects(exactRepoPath, frozenRootObjectIds),
    ) !== JSON.stringify(frozenReachableObjects)
  ) {
    throw new TypeError(
      "Independent review reachable object set changed during collection.",
    );
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
