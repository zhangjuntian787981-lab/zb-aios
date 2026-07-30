import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import {
  lstat,
  readFile,
  readdir,
  readlink,
  realpath,
  stat,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const MAX_PACKAGE_ENTRIES = 10_000;
const MAX_PACKAGE_BYTES = 64 * 1024 * 1024;
const PACKAGE_VERSIONS = Object.freeze({
  ajv: "8.20.0",
  "ajv-formats": "2.1.1",
  "fast-deep-equal": "3.1.3",
  "fast-uri": "3.1.2",
  "json-schema-traverse": "1.0.0",
  "require-from-string": "2.0.2",
});
const PACKAGE_NAMES = Object.freeze(Object.keys(PACKAGE_VERSIONS).sort());
const GIT_TOOLCHAIN = Object.freeze({
  developerDirectory: "/Library/Developer/CommandLineTools",
  shimExecutable: "/usr/bin/git",
  resolvedExecutable:
    "/Library/Developer/CommandLineTools/usr/bin/git",
  xcrunLibrary:
    "/Library/Developer/CommandLineTools/usr/lib/libxcrun.dylib",
});
const moduleRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
);

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("Runtime binding contains a non-finite number.");
    }
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
  throw new TypeError("Runtime binding contains an unsupported value.");
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

async function executableBinding(path) {
  const exactPath = await realpath(path);
  const metadata = await stat(exactPath);
  if (!metadata.isFile()) {
    throw new TypeError("Independent review toolchain file is invalid.");
  }
  const bytes = await readFile(exactPath);
  return {
    pathSha256: sha256Bytes(Buffer.from(exactPath, "utf8")),
    byteLength: bytes.byteLength,
    sha256: sha256Bytes(bytes),
  };
}

async function captureGitToolchainBinding() {
  if (process.platform !== "darwin") {
    throw new TypeError(
      "Independent review Git toolchain requires the frozen macOS path.",
    );
  }
  const [
    shimExecutable,
    resolvedExecutable,
    xcrunLibrary,
    { stdout: versionStdout },
  ] = await Promise.all([
    executableBinding(GIT_TOOLCHAIN.shimExecutable),
    executableBinding(GIT_TOOLCHAIN.resolvedExecutable),
    executableBinding(GIT_TOOLCHAIN.xcrunLibrary),
    execFileAsync(GIT_TOOLCHAIN.shimExecutable, ["--version"], {
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        DEVELOPER_DIR: GIT_TOOLCHAIN.developerDirectory,
      },
      maxBuffer: 1024 * 1024,
    }),
  ]);
  const binding = {
    version: versionStdout.trim(),
    developerDirectoryPathSha256: sha256Bytes(
      Buffer.from(GIT_TOOLCHAIN.developerDirectory, "utf8"),
    ),
    shimExecutable,
    resolvedExecutable,
    xcrunLibrary,
    bindingSha256: `sha256:${"0".repeat(64)}`,
  };
  binding.bindingSha256 = sha256Value(
    Object.fromEntries(
      Object.entries(binding).filter(
        ([key]) => key !== "bindingSha256",
      ),
    ),
  );
  return binding;
}

async function packageRecords(packageRoot) {
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
        throw new TypeError("Runtime dependency path is unsafe.");
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
        type = "SYMLINK";
      } else {
        throw new TypeError(
          "Runtime dependency contains an unsupported entry.",
        );
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
        records.length > MAX_PACKAGE_ENTRIES ||
        totalByteLength > MAX_PACKAGE_BYTES
      ) {
        throw new TypeError("Runtime dependency package exceeds its bounds.");
      }
    }
  };
  await visit(packageRoot);
  if (records.length === 0) {
    throw new TypeError("Runtime dependency package is empty.");
  }
  records.sort(({ path: left }, { path: right }) =>
    Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
  );
  return { records, totalByteLength };
}

export async function captureIndependentReviewRuntimeBinding({
  nodeExecutablePath = process.execPath,
  dependencyRoot = resolve(moduleRoot, "node_modules"),
} = {}) {
  const exactNodeExecutable = await realpath(resolve(nodeExecutablePath));
  if (!(await stat(exactNodeExecutable)).isFile()) {
    throw new TypeError("Independent review Node executable is not a file.");
  }
  const nodeBytes = await readFile(exactNodeExecutable);
  const exactDependencyRoot = await realpath(resolve(dependencyRoot));
  if (!(await stat(exactDependencyRoot)).isDirectory()) {
    throw new TypeError("Independent review dependency root is invalid.");
  }
  const dependencyPackages = [];
  for (const name of PACKAGE_NAMES) {
    const packageRoot = await realpath(join(exactDependencyRoot, name));
    if (
      packageRoot !== exactDependencyRoot &&
      !packageRoot.startsWith(`${exactDependencyRoot}/`)
    ) {
      throw new TypeError("Runtime dependency package escapes its root.");
    }
    const packageJson = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(
        await readFile(join(packageRoot, "package.json")),
      ),
    );
    if (
      packageJson?.name !== name ||
      packageJson?.version !== PACKAGE_VERSIONS[name]
    ) {
      throw new TypeError("Runtime dependency package version is invalid.");
    }
    const { records, totalByteLength } =
      await packageRecords(packageRoot);
    dependencyPackages.push({
      name,
      version: packageJson.version,
      entryCount: records.length,
      totalByteLength,
      manifestSha256: sha256Value(records),
    });
  }
  const gitToolchain = await captureGitToolchainBinding();
  const binding = {
    schemaVersion: "independent-review-runtime-binding.v1",
    nodeExecutable: {
      version: process.version,
      pathSha256: sha256Bytes(
        Buffer.from(exactNodeExecutable, "utf8"),
      ),
      byteLength: nodeBytes.byteLength,
      sha256: sha256Bytes(nodeBytes),
    },
    dependencyPackages,
    dependencySetSha256: sha256Value(dependencyPackages),
    gitToolchain,
    bindingSha256: `sha256:${"0".repeat(64)}`,
  };
  binding.bindingSha256 = sha256Value(
    Object.fromEntries(
      Object.entries(binding).filter(([key]) => key !== "bindingSha256"),
    ),
  );
  const validation = validateIndependentReviewRuntimeBinding(binding);
  if (!validation.ok) {
    throw new TypeError("Independent review runtime binding is invalid.");
  }
  return binding;
}

export function validateIndependentReviewRuntimeBinding(binding) {
  const validToolchainFile = (entry) =>
    exactKeys(entry, ["pathSha256", "byteLength", "sha256"]) &&
    SHA256.test(entry.pathSha256 ?? "") &&
    Number.isInteger(entry.byteLength) &&
    entry.byteLength > 0 &&
    entry.byteLength <= 64 * 1024 * 1024 &&
    SHA256.test(entry.sha256 ?? "");
  const validGitToolchain =
    exactKeys(binding?.gitToolchain, [
      "version",
      "developerDirectoryPathSha256",
      "shimExecutable",
      "resolvedExecutable",
      "xcrunLibrary",
      "bindingSha256",
    ]) &&
    /^git version [^\u0000-\u001f]{1,128}$/u.test(
      binding.gitToolchain.version ?? "",
    ) &&
    SHA256.test(
      binding.gitToolchain.developerDirectoryPathSha256 ?? "",
    ) &&
    validToolchainFile(binding.gitToolchain.shimExecutable) &&
    validToolchainFile(binding.gitToolchain.resolvedExecutable) &&
    validToolchainFile(binding.gitToolchain.xcrunLibrary) &&
    SHA256.test(binding.gitToolchain.bindingSha256 ?? "") &&
    binding.gitToolchain.bindingSha256 ===
      sha256Value(
        Object.fromEntries(
          Object.entries(binding.gitToolchain).filter(
            ([key]) => key !== "bindingSha256",
          ),
        ),
      );
  const validNode =
    exactKeys(binding?.nodeExecutable, [
      "version",
      "pathSha256",
      "byteLength",
      "sha256",
    ]) &&
    /^v[0-9]+\.[0-9]+\.[0-9]+$/u.test(
      binding.nodeExecutable.version ?? "",
    ) &&
    SHA256.test(binding.nodeExecutable.pathSha256 ?? "") &&
    Number.isInteger(binding.nodeExecutable.byteLength) &&
    binding.nodeExecutable.byteLength > 0 &&
    binding.nodeExecutable.byteLength <= 512 * 1024 * 1024 &&
    SHA256.test(binding.nodeExecutable.sha256 ?? "");
  const validPackages =
    Array.isArray(binding?.dependencyPackages) &&
    binding.dependencyPackages.length === PACKAGE_NAMES.length &&
    JSON.stringify(binding.dependencyPackages.map(({ name }) => name)) ===
      JSON.stringify(PACKAGE_NAMES) &&
    binding.dependencyPackages.every(
      (entry) =>
        exactKeys(entry, [
          "name",
          "version",
          "entryCount",
          "totalByteLength",
          "manifestSha256",
        ]) &&
        PACKAGE_VERSIONS[entry.name] === entry.version &&
        Number.isInteger(entry.entryCount) &&
        entry.entryCount > 0 &&
        entry.entryCount <= MAX_PACKAGE_ENTRIES &&
        Number.isInteger(entry.totalByteLength) &&
        entry.totalByteLength > 0 &&
        entry.totalByteLength <= MAX_PACKAGE_BYTES &&
        SHA256.test(entry.manifestSha256 ?? ""),
    );
  const valid =
    exactKeys(binding, [
      "schemaVersion",
      "nodeExecutable",
      "dependencyPackages",
      "dependencySetSha256",
      "gitToolchain",
      "bindingSha256",
    ]) &&
    binding.schemaVersion === "independent-review-runtime-binding.v1" &&
    validNode &&
    validPackages &&
    validGitToolchain &&
    binding.dependencySetSha256 ===
      sha256Value(binding.dependencyPackages) &&
    SHA256.test(binding.bindingSha256 ?? "") &&
    binding.bindingSha256 ===
      sha256Value(
        Object.fromEntries(
          Object.entries(binding).filter(
            ([key]) => key !== "bindingSha256",
          ),
        ),
      );
  return valid
    ? { ok: true, reasonCodes: [] }
    : {
        ok: false,
        reasonCodes: ["INDEPENDENT_REVIEW_RUNTIME_BINDING_INVALID"],
      };
}

export function serializeIndependentReviewRuntimeBinding(binding) {
  if (!validateIndependentReviewRuntimeBinding(binding).ok) {
    throw new TypeError("Independent review runtime binding is invalid.");
  }
  return Buffer.from(`${JSON.stringify(binding)}\n`, "utf8");
}

export const independentReviewRuntimeBinding = Object.freeze({
  artifactRef: "runtime-binding.v1.json",
  dependencyPackages: PACKAGE_NAMES,
  schemaVersion: "independent-review-runtime-binding.v1",
});
