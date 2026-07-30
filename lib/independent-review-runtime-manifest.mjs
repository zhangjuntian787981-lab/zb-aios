import { createHash } from "node:crypto";
import {
  lstat,
  readFile,
  readdir,
  readlink,
  realpath,
  stat,
} from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const MAX_TREE_ENTRIES = 100_000;
const MAX_TREE_BYTES = 2 * 1024 * 1024 * 1024;
const PACKAGE_VERSIONS = Object.freeze({
  ajv: "8.20.0",
  "ajv-formats": "2.1.1",
  "fast-deep-equal": "3.1.3",
  "fast-uri": "3.1.2",
  "json-schema-traverse": "1.0.0",
  "require-from-string": "2.0.2",
});
const PACKAGE_ENTRYPOINTS = Object.freeze({
  ajv: "dist/2020.js",
  "ajv-formats": "dist/index.js",
  "fast-deep-equal": "index.js",
  "fast-uri": "index.js",
  "json-schema-traverse": "index.js",
  "require-from-string": "index.js",
});
const PACKAGE_NAMES = Object.freeze(Object.keys(PACKAGE_VERSIONS).sort());

export const independentReviewRuntimeLocalModulePaths = Object.freeze([
  "lib/independent-model-review.mjs",
  "lib/independent-review-runtime-binding.mjs",
  "lib/independent-review-runtime-manifest.mjs",
  "lib/kimi-independent-review.mjs",
  "lib/p2-start-authorization.mjs",
  "lib/project-control.mjs",
  "scripts/build-independent-review-bundle.mjs",
  "scripts/build-independent-review-material.mjs",
  "scripts/bootstrap-kimi-independent-review.mjs",
  "scripts/launch-kimi-independent-review.sh",
  "scripts/run-independent-review-test-evidence.mjs",
  "scripts/run-kimi-independent-review.mjs",
]);

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("Runtime manifest contains an unsupported value.");
}

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function sha256Value(value) {
  return sha256Bytes(Buffer.from(canonicalize(value), "utf8"));
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort())
  );
}

function inside(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${sep}`);
}

export async function captureIndependentReviewTreeManifest(rootPath) {
  const exactRoot = await realpath(resolve(rootPath));
  if (!(await stat(exactRoot)).isDirectory()) {
    throw new TypeError("Runtime manifest root is not a directory.");
  }
  const records = [];
  let totalByteLength = 0;
  const visit = async (directory, relativeDirectory = "") => {
    const children = (await readdir(directory, { withFileTypes: true })).sort(
      ({ name: left }, { name: right }) =>
        Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
    );
    for (const child of children) {
      const path = relativeDirectory
        ? `${relativeDirectory}/${child.name}`
        : child.name;
      if (!SAFE_PATH.test(path)) {
        throw new TypeError("Runtime manifest path is unsafe.");
      }
      const absolutePath = join(directory, child.name);
      const metadata = await lstat(absolutePath);
      if (child.isDirectory()) {
        await visit(absolutePath, path);
        continue;
      }
      let bytes;
      let type;
      if (child.isFile()) {
        bytes = await readFile(absolutePath);
        type = "FILE";
      } else if (child.isSymbolicLink()) {
        bytes = await readlink(absolutePath, { encoding: "buffer" });
        const target = await realpath(absolutePath);
        if (!inside(exactRoot, target)) {
          throw new TypeError("Runtime manifest symlink escapes its root.");
        }
        type = "SYMLINK";
      } else {
        throw new TypeError("Runtime manifest contains a special file.");
      }
      totalByteLength += bytes.byteLength;
      records.push({
        path,
        type,
        mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
        byteLength: bytes.byteLength,
        sha256: sha256Bytes(bytes),
      });
      if (
        records.length > MAX_TREE_ENTRIES ||
        totalByteLength > MAX_TREE_BYTES
      ) {
        throw new TypeError("Runtime manifest tree exceeds its bounds.");
      }
    }
  };
  await visit(exactRoot);
  records.sort(({ path: left }, { path: right }) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  if (records.length === 0) {
    throw new TypeError("Runtime manifest tree is empty.");
  }
  return {
    entryCount: records.length,
    totalByteLength,
    manifestSha256: sha256Value(records),
  };
}

export function assertIndependentReviewBootstrapEnvironment({
  env = process.env,
  execArgv = process.execArgv,
  requiredExecArgv = [],
} = {}) {
  if (
    Object.hasOwn(env, "NODE_OPTIONS") ||
    Object.hasOwn(env, "NODE_PATH") ||
    JSON.stringify(execArgv) !== JSON.stringify(requiredExecArgv)
  ) {
    const error = new TypeError(
      "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
    );
    error.reasonCodes = [
      "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
    ];
    throw error;
  }
}

async function exactFileSubject(root, path) {
  if (!SAFE_PATH.test(path)) {
    throw new TypeError("Runtime source path is unsafe.");
  }
  const absolutePath = resolve(root, path);
  const exactRoot = await realpath(root);
  const exactPath = await realpath(absolutePath);
  if (!inside(exactRoot, exactPath)) {
    throw new TypeError("Runtime source path escapes its root.");
  }
  const metadata = await lstat(absolutePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new TypeError("Runtime source path is not a regular file.");
  }
  const bytes = await readFile(absolutePath);
  return {
    path,
    mode: (metadata.mode & 0o7777).toString(8).padStart(4, "0"),
    byteLength: bytes.byteLength,
    sha256: sha256Bytes(bytes),
  };
}

export async function captureIndependentReviewRuntimeDependencyManifest({
  sourceRoot,
  dependencyRoot,
  nodeExecutablePath = process.execPath,
  npmRoot = resolve(
    dirname(process.execPath),
    "..",
    "lib",
    "node_modules",
    "npm",
  ),
  requiredExecArgv = [],
} = {}) {
  assertIndependentReviewBootstrapEnvironment({
    requiredExecArgv,
  });
  const exactSourceRoot = await realpath(resolve(sourceRoot));
  const exactDependencyRoot = await realpath(resolve(dependencyRoot));
  const exactNodeExecutable = await realpath(resolve(nodeExecutablePath));
  const exactNpmRoot = await realpath(resolve(npmRoot));
  const nodeBytes = await readFile(exactNodeExecutable);
  const packageJsonBytes = await readFile(
    resolve(exactSourceRoot, "package.json"),
  );
  const packageLockBytes = await readFile(
    resolve(exactSourceRoot, "package-lock.json"),
  );
  const packageLock = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(packageLockBytes),
  );
  const npmPackageJsonBytes = await readFile(
    resolve(exactNpmRoot, "package.json"),
  );
  const npmPackageJson = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(npmPackageJsonBytes),
  );
  const npmLauncher = resolve(dirname(exactNodeExecutable), "npm");
  const npmLauncherTargetBytes = await readlink(npmLauncher, {
    encoding: "buffer",
  });
  const npmCli = await realpath(npmLauncher);
  if (!inside(exactNpmRoot, npmCli)) {
    throw new TypeError("npm launcher escapes its package root.");
  }
  const npmCliBytes = await readFile(npmCli);
  const [dependencyTree, npmTree] = await Promise.all([
    captureIndependentReviewTreeManifest(exactDependencyRoot),
    captureIndependentReviewTreeManifest(exactNpmRoot),
  ]);
  const criticalPackages = [];
  for (const name of PACKAGE_NAMES) {
    const packagePath = resolve(exactDependencyRoot, name);
    const exactPackagePath = await realpath(packagePath);
    if (!inside(exactDependencyRoot, exactPackagePath)) {
      throw new TypeError("Critical dependency escapes its root.");
    }
    const packageBytes = await readFile(
      resolve(exactPackagePath, "package.json"),
    );
    const packageValue = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(packageBytes),
    );
    const lockValue = packageLock?.packages?.[`node_modules/${name}`];
    if (
      packageValue?.name !== name ||
      packageValue?.version !== PACKAGE_VERSIONS[name] ||
      lockValue?.version !== PACKAGE_VERSIONS[name] ||
      typeof lockValue?.integrity !== "string" ||
      lockValue.integrity.length === 0
    ) {
      throw new TypeError("Critical dependency lock binding is invalid.");
    }
    const entryPath = `${name}/${PACKAGE_ENTRYPOINTS[name]}`;
    const entryBytes = await readFile(
      resolve(exactDependencyRoot, entryPath),
    );
    const tree = await captureIndependentReviewTreeManifest(
      exactPackagePath,
    );
    criticalPackages.push({
      name,
      version: packageValue.version,
      integrity: lockValue.integrity,
      packageJsonSha256: sha256Bytes(packageBytes),
      entryPath,
      entrySha256: sha256Bytes(entryBytes),
      ...tree,
    });
  }
  const localModuleSubjects = await Promise.all(
    independentReviewRuntimeLocalModulePaths.map((path) =>
      exactFileSubject(exactSourceRoot, path),
    ),
  );
  const manifest = {
    schemaVersion: "independent-review-runtime-dependency-manifest.v1",
    platform: {
      os: process.platform,
      arch: process.arch,
    },
    environment: {
      nodeOptionsRequiredAbsent: true,
      nodePathRequiredAbsent: true,
      requiredExecArgv: [...requiredExecArgv],
    },
    node: {
      version: process.version,
      executablePathSha256: sha256Bytes(
        Buffer.from(exactNodeExecutable, "utf8"),
      ),
      executableByteLength: nodeBytes.byteLength,
      executableSha256: sha256Bytes(nodeBytes),
    },
    npm: {
      version: npmPackageJson.version,
      launcherTargetSha256: sha256Bytes(npmLauncherTargetBytes),
      cliPathSha256: sha256Bytes(
        Buffer.from(relative(exactNpmRoot, npmCli), "utf8"),
      ),
      cliByteLength: npmCliBytes.byteLength,
      cliSha256: sha256Bytes(npmCliBytes),
      packageJsonSha256: sha256Bytes(npmPackageJsonBytes),
      packageTreeEntryCount: npmTree.entryCount,
      packageTreeByteLength: npmTree.totalByteLength,
      packageTreeSha256: npmTree.manifestSha256,
    },
    source: {
      packageJsonSha256: sha256Bytes(packageJsonBytes),
      packageLockSha256: sha256Bytes(packageLockBytes),
      localModuleSubjects,
      localClosureSha256: sha256Value(localModuleSubjects),
    },
    dependencies: {
      rootKind: "REPOSITORY_NODE_MODULES",
      fullTreeEntryCount: dependencyTree.entryCount,
      fullTreeByteLength: dependencyTree.totalByteLength,
      fullTreeSha256: dependencyTree.manifestSha256,
      criticalPackages,
      criticalPackageSetSha256: sha256Value(criticalPackages),
    },
    manifestSha256: `sha256:${"0".repeat(64)}`,
  };
  manifest.manifestSha256 = sha256Value(
    Object.fromEntries(
      Object.entries(manifest).filter(
        ([key]) => key !== "manifestSha256",
      ),
    ),
  );
  if (!validateIndependentReviewRuntimeDependencyManifest(manifest).ok) {
    throw new TypeError("Independent review runtime manifest is invalid.");
  }
  return manifest;
}

export function validateIndependentReviewRuntimeDependencyManifest(
  manifest,
) {
  const valid =
    exactKeys(manifest, [
      "schemaVersion",
      "platform",
      "environment",
      "node",
      "npm",
      "source",
      "dependencies",
      "manifestSha256",
    ]) &&
    manifest.schemaVersion ===
      "independent-review-runtime-dependency-manifest.v1" &&
    exactKeys(manifest.platform, ["os", "arch"]) &&
    ["darwin", "linux"].includes(manifest.platform.os) &&
    ["arm64", "x64"].includes(manifest.platform.arch) &&
    exactKeys(manifest.environment, [
      "nodeOptionsRequiredAbsent",
      "nodePathRequiredAbsent",
      "requiredExecArgv",
    ]) &&
    manifest.environment.nodeOptionsRequiredAbsent === true &&
    manifest.environment.nodePathRequiredAbsent === true &&
    Array.isArray(manifest.environment.requiredExecArgv) &&
    manifest.environment.requiredExecArgv.every(
      (value) => typeof value === "string" && value.length > 0,
    ) &&
    exactKeys(manifest.node, [
      "version",
      "executablePathSha256",
      "executableByteLength",
      "executableSha256",
    ]) &&
    /^v[0-9]+\.[0-9]+\.[0-9]+$/u.test(manifest.node.version ?? "") &&
    SHA256.test(manifest.node.executablePathSha256 ?? "") &&
    Number.isInteger(manifest.node.executableByteLength) &&
    manifest.node.executableByteLength > 0 &&
    SHA256.test(manifest.node.executableSha256 ?? "") &&
    exactKeys(manifest.npm, [
      "version",
      "launcherTargetSha256",
      "cliPathSha256",
      "cliByteLength",
      "cliSha256",
      "packageJsonSha256",
      "packageTreeEntryCount",
      "packageTreeByteLength",
      "packageTreeSha256",
    ]) &&
    /^[0-9]+\.[0-9]+\.[0-9]+$/u.test(manifest.npm.version ?? "") &&
    [
      manifest.npm.launcherTargetSha256,
      manifest.npm.cliPathSha256,
      manifest.npm.cliSha256,
      manifest.npm.packageJsonSha256,
      manifest.npm.packageTreeSha256,
    ].every((value) => SHA256.test(value ?? "")) &&
    [manifest.npm.cliByteLength, manifest.npm.packageTreeEntryCount].every(
      (value) => Number.isInteger(value) && value > 0,
    ) &&
    Number.isInteger(manifest.npm.packageTreeByteLength) &&
    manifest.npm.packageTreeByteLength > 0 &&
    exactKeys(manifest.source, [
      "packageJsonSha256",
      "packageLockSha256",
      "localModuleSubjects",
      "localClosureSha256",
    ]) &&
    SHA256.test(manifest.source.packageJsonSha256 ?? "") &&
    SHA256.test(manifest.source.packageLockSha256 ?? "") &&
    Array.isArray(manifest.source.localModuleSubjects) &&
    manifest.source.localModuleSubjects.length ===
      independentReviewRuntimeLocalModulePaths.length &&
    JSON.stringify(
      manifest.source.localModuleSubjects.map(({ path }) => path),
    ) === JSON.stringify(independentReviewRuntimeLocalModulePaths) &&
    manifest.source.localModuleSubjects.every(
      (subject) =>
        exactKeys(subject, [
          "path",
          "mode",
          "byteLength",
          "sha256",
        ]) &&
        SAFE_PATH.test(subject.path ?? "") &&
        /^[0-7]{4}$/u.test(subject.mode ?? "") &&
        Number.isInteger(subject.byteLength) &&
        subject.byteLength > 0 &&
        SHA256.test(subject.sha256 ?? ""),
    ) &&
    manifest.source.localClosureSha256 ===
      sha256Value(manifest.source.localModuleSubjects) &&
    exactKeys(manifest.dependencies, [
      "rootKind",
      "fullTreeEntryCount",
      "fullTreeByteLength",
      "fullTreeSha256",
      "criticalPackages",
      "criticalPackageSetSha256",
    ]) &&
    manifest.dependencies.rootKind === "REPOSITORY_NODE_MODULES" &&
    Number.isInteger(manifest.dependencies.fullTreeEntryCount) &&
    manifest.dependencies.fullTreeEntryCount > 0 &&
    Number.isInteger(manifest.dependencies.fullTreeByteLength) &&
    manifest.dependencies.fullTreeByteLength > 0 &&
    SHA256.test(manifest.dependencies.fullTreeSha256 ?? "") &&
    Array.isArray(manifest.dependencies.criticalPackages) &&
    JSON.stringify(
      manifest.dependencies.criticalPackages.map(({ name }) => name),
    ) === JSON.stringify(PACKAGE_NAMES) &&
    manifest.dependencies.criticalPackages.every(
      (entry) =>
        exactKeys(entry, [
          "name",
          "version",
          "integrity",
          "packageJsonSha256",
          "entryPath",
          "entrySha256",
          "entryCount",
          "totalByteLength",
          "manifestSha256",
        ]) &&
        PACKAGE_VERSIONS[entry.name] === entry.version &&
        typeof entry.integrity === "string" &&
        entry.integrity.length > 0 &&
        SAFE_PATH.test(entry.entryPath ?? "") &&
        [
          entry.packageJsonSha256,
          entry.entrySha256,
          entry.manifestSha256,
        ].every((value) => SHA256.test(value ?? "")) &&
        Number.isInteger(entry.entryCount) &&
        entry.entryCount > 0 &&
        Number.isInteger(entry.totalByteLength) &&
        entry.totalByteLength > 0,
    ) &&
    manifest.dependencies.criticalPackageSetSha256 ===
      sha256Value(manifest.dependencies.criticalPackages) &&
    SHA256.test(manifest.manifestSha256 ?? "") &&
    manifest.manifestSha256 ===
      sha256Value(
        Object.fromEntries(
          Object.entries(manifest).filter(
            ([key]) => key !== "manifestSha256",
          ),
        ),
      );
  return valid
    ? { ok: true, reasonCodes: [] }
    : {
        ok: false,
        reasonCodes: [
          "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
        ],
      };
}

export function serializeIndependentReviewRuntimeDependencyManifest(
  manifest,
) {
  if (!validateIndependentReviewRuntimeDependencyManifest(manifest).ok) {
    throw new TypeError("Independent review runtime manifest is invalid.");
  }
  return Buffer.from(`${JSON.stringify(manifest)}\n`, "utf8");
}
