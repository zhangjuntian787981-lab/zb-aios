import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import {
  assertIndependentReviewBootstrapEnvironment,
  captureIndependentReviewRuntimeDependencyManifest,
  captureKimiK3IndependentReviewRuntimeDependencyManifest,
  captureKimiK3IndependentReviewRuntimeDependencyManifestV3,
  captureKimiK3IndependentReviewRuntimeDependencyManifestV4,
  captureKimiK3IndependentReviewRuntimeDependencyManifestV5,
  captureIndependentReviewTreeManifest,
  independentReviewRuntimeLocalModulePaths,
  kimiK3IndependentReviewRuntimeLocalModulePaths,
  serializeIndependentReviewRuntimeDependencyManifest,
  validateIndependentReviewRuntimeDependencyManifest,
} from "../lib/independent-review-runtime-manifest.mjs";
import {
  buildIndependentReviewRuntimeManifest,
  runtimeManifestBuildContractFromArguments,
} from "../scripts/build-independent-review-runtime-manifest.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);
const execFile = promisify(execFileCallback);

function sha256Bytes(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

async function git(repo, args, encoding = "buffer") {
  return execFile(
    "/usr/bin/git",
    ["--no-replace-objects", "-C", repo, ...args],
    {
      encoding,
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_SYSTEM: "/dev/null",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
      },
      maxBuffer: 64 * 1024 * 1024,
    },
  );
}

test("historical K2 runtime manifest v1 remains byte-exact and valid", async () => {
  const expectedSha256 = new Map([
    [
      "implementation/governance/schemas/independent-review-runtime-manifest.v1.schema.json",
      "2c00d28b1db923a21c7130ed4e952990d7dbe4e86e04f6ab6e16fbd2ed8f1c87",
    ],
    [
      "implementation/governance/schemas/independent-review-runtime-manifest.v2.schema.json",
      "1379fdddb9e553a17126bab56b1e2ec31e1d54dd10b9cc190ea0e092cb941035",
    ],
    [
      "implementation/governance/independent-review/kimi-runtime-manifest.v1.json",
      "9b7a9135bacd92594f734607ffad8ff326eb57541afd7ecb65eb9fde45973d62",
    ],
    [
      "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
      "585a8e5fe0f8d34b0c67db5662aa47258b60feed628bfbeb0d2c47a94b89816a",
    ],
  ]);
  for (const [path, expected] of expectedSha256) {
    const bytes = await readFile(resolve(root, path));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), expected);
  }
  const bytes = await readFile(
    resolve(
      root,
      "implementation/governance/independent-review/kimi-runtime-manifest.v1.json",
    ),
  );
  assert.equal(
    `sha256:${(await import("node:crypto"))
      .createHash("sha256")
      .update(bytes)
      .digest("hex")}`,
    "sha256:9b7a9135bacd92594f734607ffad8ff326eb57541afd7ecb65eb9fde45973d62",
  );
  const manifest = JSON.parse(bytes);
  assert.equal(
    validateIndependentReviewRuntimeDependencyManifest(manifest).ok,
    true,
  );
  assert.equal(manifest.source.localModuleSubjects.length, 13);
  assert.equal(
    manifest.source.localModuleSubjects.some(
      ({ path }) => path === "lib/kimi-k3-independent-review.mjs",
    ),
    false,
  );
});

test("K3 runtime manifest v2 closes the exact executable module set without changing v1", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "zb-k3-runtime-manifest-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const destination = join(directory, "kimi-runtime-manifest.v2.json");

  const captured =
    await captureKimiK3IndependentReviewRuntimeDependencyManifest({
      sourceRoot: root,
      dependencyRoot: resolve(root, "node_modules"),
      requiredExecArgv: process.execArgv,
    });
  assert.equal(
    captured.schemaVersion,
    "independent-review-runtime-dependency-manifest.v2",
  );
  assert.deepEqual(
    captured.source.localModuleSubjects.map(({ path }) => path),
    kimiK3IndependentReviewRuntimeLocalModulePaths,
  );
  assert.equal(captured.source.localModuleSubjects.length, 15);
  assert.equal(
    captured.source.localModuleSubjects.filter(
      ({ path }) => path === "lib/kimi-k3-independent-review.mjs",
    ).length,
    1,
  );
  assert.equal(
    captured.source.localModuleSubjects.filter(
      ({ path }) => path === "lib/kimi-k3-review-evidence.mjs",
    ).length,
    1,
  );
  assert.equal(
    captured.source.localModuleSubjects.some(
      ({ path }) =>
        path ===
        "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
    ),
    false,
  );
  assert.deepEqual(
    captured.dependencies.criticalPackages.map(({ name }) => name),
    [
      "ajv",
      "ajv-formats",
      "fast-deep-equal",
      "fast-uri",
      "json-schema-traverse",
      "require-from-string",
    ],
  );
  assert.equal(
    validateIndependentReviewRuntimeDependencyManifest(captured).ok,
    true,
  );
  const schema = JSON.parse(
    await readFile(
      resolve(
        root,
        "implementation/governance/schemas/independent-review-runtime-manifest.v2.schema.json",
      ),
      "utf8",
    ),
  );
  const validateSchema = new Ajv2020({
    strict: true,
    allErrors: true,
  }).compile(schema);
  assert.equal(
    validateSchema(captured),
    true,
    JSON.stringify(validateSchema.errors),
  );
  const historicalManifest = JSON.parse(
    await readFile(
      resolve(
        root,
        "implementation/governance/independent-review/kimi-runtime-manifest.v1.json",
      ),
      "utf8",
    ),
  );
  assert.equal(validateSchema(historicalManifest), false);
  assert.deepEqual(independentReviewRuntimeLocalModulePaths, [
    "lib/independent-model-review.mjs",
    "lib/independent-review-runtime-binding.mjs",
    "lib/independent-review-runtime-manifest.mjs",
    "lib/independent-review-transport-evidence.mjs",
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

  const built = await buildIndependentReviewRuntimeManifest({
    contract: "K3_V2",
    sourceRoot: root,
    destination,
  });
  assert.equal(built.destination, destination);
  assert.deepEqual(built.manifest, captured);
  assert.deepEqual(await readFile(destination), built.bytes);

  const v3Directory = await mkdtemp(
    join(tmpdir(), "zb-k3-runtime-manifest-v3-"),
  );
  t.after(() => rm(v3Directory, { recursive: true, force: true }));
  const v3Destination = join(v3Directory, "kimi-runtime-manifest.v3.json");
  const capturedV3 =
    await captureKimiK3IndependentReviewRuntimeDependencyManifestV3({
      sourceRoot: root,
      dependencyRoot: resolve(root, "node_modules"),
      requiredExecArgv: process.execArgv,
    });
  assert.equal(
    capturedV3.schemaVersion,
    "independent-review-runtime-dependency-manifest.v3",
  );
  assert.deepEqual(
    capturedV3.dependencies.criticalPackages.map(({ name }) => name),
    [
      "ajv",
      "ajv-formats",
      "fast-deep-equal",
      "fast-uri",
      "json-schema-traverse",
      "require-from-string",
      "undici",
    ],
  );
  const v3Schema = JSON.parse(
    await readFile(
      resolve(
        root,
        "implementation/governance/schemas/independent-review-runtime-manifest.v3.schema.json",
      ),
      "utf8",
    ),
  );
  const validateV3Schema = new Ajv2020({
    strict: true,
    allErrors: true,
  }).compile(v3Schema);
  assert.equal(
    validateV3Schema(capturedV3),
    true,
    JSON.stringify(validateV3Schema.errors),
  );
  const builtV3 = await buildIndependentReviewRuntimeManifest({
    contract: "K3_V3",
    sourceRoot: root,
    destination: v3Destination,
  });
  assert.deepEqual(builtV3.manifest, capturedV3);
  assert.deepEqual(await readFile(v3Destination), builtV3.bytes);

  const v4Directory = await mkdtemp(
    join(tmpdir(), "zb-k3-runtime-manifest-v4-"),
  );
  t.after(() => rm(v4Directory, { recursive: true, force: true }));
  const v4Destination = join(v4Directory, "kimi-runtime-manifest.v4.json");
  const capturedV4 =
    await captureKimiK3IndependentReviewRuntimeDependencyManifestV4({
      sourceRoot: root,
      dependencyRoot: resolve(root, "node_modules"),
      requiredExecArgv: process.execArgv,
    });
  const {
    schemaVersion: v3SchemaVersion,
    manifestSha256: v3ManifestSha256,
    ...v3Contract
  } = capturedV3;
  const {
    schemaVersion: v4SchemaVersion,
    manifestSha256: v4ManifestSha256,
    ...v4Contract
  } = capturedV4;
  assert.equal(
    v4SchemaVersion,
    "independent-review-runtime-dependency-manifest.v4",
  );
  assert.equal(
    v3SchemaVersion,
    "independent-review-runtime-dependency-manifest.v3",
  );
  assert.notEqual(v4ManifestSha256, v3ManifestSha256);
  assert.deepEqual(v4Contract, v3Contract);
  const runtimeManifestModule = capturedV4.source.localModuleSubjects.find(
    ({ path }) => path === "lib/independent-review-runtime-manifest.mjs",
  );
  assert.equal(
    runtimeManifestModule.sha256,
    `sha256:${createHash("sha256")
      .update(
        await readFile(
          resolve(root, "lib/independent-review-runtime-manifest.mjs"),
        ),
      )
      .digest("hex")}`,
  );
  assert.equal(
    validateIndependentReviewRuntimeDependencyManifest(capturedV4).ok,
    true,
  );
  const v4Schema = JSON.parse(
    await readFile(
      resolve(
        root,
        "implementation/governance/schemas/independent-review-runtime-manifest.v4.schema.json",
      ),
      "utf8",
    ),
  );
  const validateV4Schema = new Ajv2020({
    strict: true,
    allErrors: true,
  }).compile(v4Schema);
  assert.equal(
    validateV4Schema(capturedV4),
    true,
    JSON.stringify(validateV4Schema.errors),
  );
  assert.equal(validateV4Schema(capturedV3), false);
  assert.equal(validateV3Schema(capturedV4), false);
  const builtV4 = await buildIndependentReviewRuntimeManifest({
    contract: "K3_V4",
    sourceRoot: root,
    destination: v4Destination,
  });
  assert.deepEqual(builtV4.manifest, capturedV4);
  assert.deepEqual(await readFile(v4Destination), builtV4.bytes);

  const v5Directory = await mkdtemp(
    join(tmpdir(), "zb-k3-runtime-manifest-v5-"),
  );
  t.after(() => rm(v5Directory, { recursive: true, force: true }));
  const v5Destination = join(v5Directory, "kimi-runtime-manifest.v5.json");
  const capturedV5 =
    await captureKimiK3IndependentReviewRuntimeDependencyManifestV5({
      sourceRoot: root,
      dependencyRoot: resolve(root, "node_modules"),
      requiredExecArgv: process.execArgv,
    });
  const {
    schemaVersion: capturedV4SchemaVersion,
    manifestSha256: capturedV4ManifestSha256,
    ...capturedV4Contract
  } = capturedV4;
  const {
    schemaVersion: v5SchemaVersion,
    manifestSha256: v5ManifestSha256,
    ...v5Contract
  } = capturedV5;
  assert.equal(
    capturedV4SchemaVersion,
    "independent-review-runtime-dependency-manifest.v4",
  );
  assert.equal(
    v5SchemaVersion,
    "independent-review-runtime-dependency-manifest.v5",
  );
  assert.notEqual(v5ManifestSha256, capturedV4ManifestSha256);
  assert.deepEqual(v5Contract, capturedV4Contract);
  const v5Schema = JSON.parse(
    await readFile(
      resolve(
        root,
        "implementation/governance/schemas/independent-review-runtime-manifest.v5.schema.json",
      ),
      "utf8",
    ),
  );
  const validateV5Schema = new Ajv2020({
    strict: true,
    allErrors: true,
  }).compile(v5Schema);
  assert.equal(
    validateV5Schema(capturedV5),
    true,
    JSON.stringify(validateV5Schema.errors),
  );
  assert.equal(validateV5Schema(capturedV4), false);
  assert.equal(validateV4Schema(capturedV5), false);
  const builtV5 = await buildIndependentReviewRuntimeManifest({
    contract: "K3_V5",
    sourceRoot: root,
    destination: v5Destination,
  });
  assert.deepEqual(builtV5.manifest, capturedV5);
  assert.deepEqual(await readFile(v5Destination), builtV5.bytes);
  const freezeCommit = "4172a6036e86780cfa5e1f34ce5dcd8dc8c05321";
  const freezeTree = "7b9fb46f944569b3bcb1871adca8f5229787c9dd";
  const manifestPath =
    "implementation/governance/independent-review/kimi-runtime-manifest.v5.json";
  const manifestSchemaPath =
    "implementation/governance/schemas/independent-review-runtime-manifest.v5.schema.json";
  const receiptSchemaPath =
    "implementation/governance/schemas/independent-model-review-receipt.v9.schema.json";
  const { stdout: exactFreezeTree } = await git(
    root,
    ["rev-parse", `${freezeCommit}^{tree}`],
    "utf8",
  );
  assert.equal(exactFreezeTree.trim(), freezeTree);
  const [
    { stdout: frozenV5Bytes },
    { stdout: frozenV5SchemaBytes },
    { stdout: frozenReceiptSchemaBytes },
  ] =
    await Promise.all([
      git(root, ["cat-file", "blob", `${freezeCommit}:${manifestPath}`]),
      git(root, ["cat-file", "blob", `${freezeCommit}:${manifestSchemaPath}`]),
      git(root, ["cat-file", "blob", `${freezeCommit}:${receiptSchemaPath}`]),
    ]);
  assert.equal(
    sha256Bytes(frozenV5Bytes),
    "sha256:fb140178df068d95eb23c30f70f51d1a00995300bce906e8613d436216add7eb",
  );
  assert.equal(
    sha256Bytes(frozenV5SchemaBytes),
    "sha256:78a70a5af4aa62a8a4cd747252b90422982b099be239b6ebca933d31b763b028",
  );
  assert.equal(
    sha256Bytes(frozenReceiptSchemaBytes),
    "sha256:3714ef2012099ff725c3e26bf695226eab5a543a2d07ff5bf6fbceadfdffb634",
  );
  const frozenV5 = JSON.parse(frozenV5Bytes);
  assert.deepEqual(
    frozenV5.source.localModuleSubjects.map(({ path }) => path),
    kimiK3IndependentReviewRuntimeLocalModulePaths,
  );
  assert.equal(
    frozenV5.manifestSha256,
    "sha256:7db6d061b1d2418a8c7b639ba3c1b34ad2e2b232a2c1129490f6a71dbbca3495",
  );
  assert.equal(
    validateIndependentReviewRuntimeDependencyManifest(frozenV5).ok,
    true,
  );
  const frozenV5Schema = JSON.parse(frozenV5SchemaBytes);
  const validateFrozenV5Schema = new Ajv2020({
    strict: true,
    allErrors: true,
  }).compile(frozenV5Schema);
  assert.equal(
    validateFrozenV5Schema(frozenV5),
    true,
    JSON.stringify(validateFrozenV5Schema.errors),
  );
  const formalCaptureScript = join(v5Directory, "capture-v5.mjs");
  const formalSourceRoot = join(v5Directory, "formal-source");
  const frozenV5Path = resolve(
    root,
    manifestPath,
  );
  assert.deepEqual(await readFile(frozenV5Path), frozenV5Bytes);
  assert.deepEqual(
    await readFile(resolve(root, manifestSchemaPath)),
    frozenV5SchemaBytes,
  );
  assert.deepEqual(
    await readFile(resolve(root, receiptSchemaPath)),
    frozenReceiptSchemaBytes,
  );
  for (const path of [
    "package.json",
    "package-lock.json",
    manifestPath,
    ...kimiK3IndependentReviewRuntimeLocalModulePaths,
  ]) {
    const target = join(formalSourceRoot, path);
    await mkdir(dirname(target), { recursive: true });
    const { stdout: sourceBytes } = await git(root, [
      "cat-file",
      "blob",
      `${freezeCommit}:${path}`,
    ]);
    await writeFile(target, sourceBytes);
    const frozenSubject = frozenV5.source.localModuleSubjects.find(
      ({ path: subjectPath }) => subjectPath === path,
    );
    if (frozenSubject) {
      const { stdout: treeEntry } = await git(
        root,
        ["ls-tree", freezeCommit, "--", path],
        "utf8",
      );
      const [gitMode] = treeEntry.trim().split(/\s+/u);
      assert.equal(frozenSubject.mode, gitMode.slice(-4));
      assert.equal(frozenSubject.byteLength, sourceBytes.byteLength);
      assert.equal(frozenSubject.sha256, sha256Bytes(sourceBytes));
    }
    await chmod(
      target,
      frozenSubject ? Number.parseInt(frozenSubject.mode, 8) : 0o644,
    );
  }
  await symlink(
    resolve(root, "node_modules"),
    join(formalSourceRoot, "node_modules"),
    "dir",
  );
  await writeFile(
    formalCaptureScript,
    `import { realpath } from "node:fs/promises";\n` +
      `import { dirname, resolve } from "node:path";\n` +
      `import { pathToFileURL } from "node:url";\n` +
      `const sourceRoot = process.argv[2];\n` +
      `const dependencyRoot = dirname(await realpath(resolve(sourceRoot, "node_modules", "ajv")));\n` +
      `const runtime = await import(pathToFileURL(resolve(sourceRoot, "lib/independent-review-runtime-manifest.mjs")).href);\n` +
      `const manifest = await runtime.captureKimiK3IndependentReviewRuntimeDependencyManifestV5({ sourceRoot, dependencyRoot, requiredExecArgv: [] });\n` +
      `process.stdout.write(runtime.serializeIndependentReviewRuntimeDependencyManifest(manifest));\n`,
  );
  const { stdout: formalV5Bytes } = await execFile(
    process.execPath,
    [formalCaptureScript, formalSourceRoot],
    { encoding: "buffer", maxBuffer: 1024 * 1024 },
  );
  assert.deepEqual(
    frozenV5Bytes,
    formalV5Bytes,
    "the frozen Runtime Manifest v5 must equal a trusted capture reconstructed from its freeze commit",
  );
  assert.notDeepEqual(
    serializeIndependentReviewRuntimeDependencyManifest(capturedV5),
    frozenV5Bytes,
    "current working-tree bytes must not impersonate historical Runtime Manifest v5",
  );
  const currentAuthorizationSubject = capturedV5.source.localModuleSubjects.find(
    ({ path }) => path === "lib/p2-start-authorization.mjs",
  );
  const frozenAuthorizationSubject = frozenV5.source.localModuleSubjects.find(
    ({ path }) => path === "lib/p2-start-authorization.mjs",
  );
  const currentAuthorizationBytes = await readFile(
    resolve(root, "lib/p2-start-authorization.mjs"),
  );
  assert.equal(
    currentAuthorizationSubject.byteLength,
    currentAuthorizationBytes.byteLength,
  );
  assert.equal(
    currentAuthorizationSubject.sha256,
    sha256Bytes(currentAuthorizationBytes),
  );
  assert.notEqual(
    currentAuthorizationSubject.sha256,
    frozenAuthorizationSubject.sha256,
  );

  const bootstrapPath = resolve(
    root,
    "scripts/bootstrap-kimi-independent-review.mjs",
  );
  const launcherPath = resolve(
    root,
    "scripts/launch-kimi-independent-review.sh",
  );
  const driftRepository = join(v5Directory, "runtime-drift-repository");
  await cp(formalSourceRoot, driftRepository, { recursive: true });
  await writeFile(
    join(driftRepository, "lib/p2-start-authorization.mjs"),
    currentAuthorizationBytes,
  );
  await git(driftRepository, ["init", "-q"]);
  await git(driftRepository, ["config", "user.name", "Runtime Manifest Test"]);
  await git(driftRepository, [
    "config",
    "user.email",
    "runtime-manifest@example.invalid",
  ]);
  await git(driftRepository, [
    "add",
    "package.json",
    "package-lock.json",
    manifestPath,
    ...kimiK3IndependentReviewRuntimeLocalModulePaths,
  ]);
  await git(driftRepository, ["commit", "-q", "-m", "runtime with stale v5"]);
  const [{ stdout: runtimeCommit }, { stdout: runtimeTree }] =
    await Promise.all([
      git(driftRepository, ["rev-parse", "HEAD"], "utf8"),
      git(driftRepository, ["rev-parse", "HEAD^{tree}"], "utf8"),
    ]);
  await writeFile(join(driftRepository, "subject.txt"), "subject\n");
  await git(driftRepository, ["add", "subject.txt"]);
  await git(driftRepository, ["commit", "-q", "-m", "subject"]);
  const [{ stdout: subjectCommit }, { stdout: subjectTree }] =
    await Promise.all([
      git(driftRepository, ["rev-parse", "HEAD"], "utf8"),
      git(driftRepository, ["rev-parse", "HEAD^{tree}"], "utf8"),
    ]);
  const bundlePath = join(v5Directory, "runtime-drift-bundle.json");
  const materialPath = join(v5Directory, "runtime-drift-material.utf8");
  await writeFile(
    bundlePath,
    JSON.stringify({
      source: {
        sourceCommit: subjectCommit.trim(),
        tree: subjectTree.trim(),
      },
    }),
  );
  await writeFile(materialPath, "runtime drift material\n");
  await assert.rejects(
    execFile(
      process.execPath,
      [
        bootstrapPath,
        "--repo",
        driftRepository,
        "--bundle",
        bundlePath,
        "--material",
        materialPath,
        "--output-dir",
        join(v5Directory, "runtime-drift-output"),
        "--review-id",
        "imrr_runtime_drift_test_001",
        "--runtime-commit",
        runtimeCommit.trim(),
        "--runtime-tree",
        runtimeTree.trim(),
        "--bootstrap-sha256",
        sha256Bytes(await readFile(bootstrapPath)),
        "--launcher-sha256",
        sha256Bytes(await readFile(launcherPath)),
      ],
      {
        cwd: root,
        encoding: "utf8",
        env: {
          PATH: "/usr/bin:/bin",
          LANG: "C",
          LC_ALL: "C",
          ZB_KIMI_SANITIZED_LAUNCHER: "1",
        },
      },
    ),
    (error) => {
      const result = JSON.parse(error.stdout);
      assert.deepEqual(result.reasonCodes, [
        "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
      ]);
      assert.equal(result.networkAttemptCount, 0);
      assert.equal(result.tokenEstimateAttemptCount, 0);
      assert.equal(result.chatCompletionAttemptCount, 0);
      assert.equal(error.stderr, "");
      return true;
    },
  );

  const rootPinDirectory = await mkdtemp(
    join(tmpdir(), "zb-k3-runtime-root-pin-"),
  );
  t.after(() => rm(rootPinDirectory, { recursive: true, force: true }));
  const packageJson = JSON.parse(
    await readFile(resolve(root, "package.json"), "utf8"),
  );
  for (const pin of [undefined, "^7.24.8", "7.24.9"]) {
    const changed = structuredClone(packageJson);
    if (pin === undefined) {
      delete changed.devDependencies.undici;
    } else {
      changed.devDependencies.undici = pin;
    }
    await writeFile(
      join(rootPinDirectory, "package.json"),
      `${JSON.stringify(changed, null, 2)}\n`,
    );
    await assert.rejects(
      captureKimiK3IndependentReviewRuntimeDependencyManifestV3({
        sourceRoot: rootPinDirectory,
        dependencyRoot: resolve(root, "node_modules"),
        requiredExecArgv: process.execArgv,
      }),
      /Required runtime dependency is not directly pinned/u,
    );
  }
});

test("runtime manifest contracts reject cross-version module sets and non-closed CLI arguments", async () => {
  assert.equal(runtimeManifestBuildContractFromArguments([]), "K2_V1");
  assert.equal(
    runtimeManifestBuildContractFromArguments([
      "--contract",
      "K3_V2",
    ]),
    "K3_V2",
  );
  assert.equal(
    runtimeManifestBuildContractFromArguments([
      "--contract",
      "K3_V3",
    ]),
    "K3_V3",
  );
  assert.equal(
    runtimeManifestBuildContractFromArguments([
      "--contract",
      "K3_V4",
    ]),
    "K3_V4",
  );
  assert.equal(
    runtimeManifestBuildContractFromArguments([
      "--contract",
      "K3_V5",
    ]),
    "K3_V5",
  );
  for (const values of [
    ["--contract", "K2_V1"],
    ["--contract", "kimi-k3"],
    ["--contract", "K3_V2", "--output", "/tmp/manifest"],
    ["--unknown", "K3_V2"],
  ]) {
    assert.throws(
      () => runtimeManifestBuildContractFromArguments(values),
      /INDEPENDENT_REVIEW_RUNTIME_MANIFEST_ARGUMENTS_INVALID/u,
    );
  }

  const manifest =
    await captureKimiK3IndependentReviewRuntimeDependencyManifest({
      sourceRoot: root,
      dependencyRoot: resolve(root, "node_modules"),
      requiredExecArgv: process.execArgv,
    });
  for (const mutate of [
    (value) => value.source.localModuleSubjects.pop(),
    (value) =>
      value.source.localModuleSubjects.push(
        structuredClone(value.source.localModuleSubjects[0]),
      ),
    (value) => value.source.localModuleSubjects.reverse(),
    (value) => {
      value.schemaVersion =
        "independent-review-runtime-dependency-manifest.v1";
    },
  ]) {
    const changed = structuredClone(manifest);
    mutate(changed);
    assert.deepEqual(
      validateIndependentReviewRuntimeDependencyManifest(changed),
      {
        ok: false,
        reasonCodes: [
          "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
        ],
      },
    );
  }
});

test("runtime dependency manifest closes Node, npm, lockfile, source and the full dependency tree", async () => {
  const manifest = await captureIndependentReviewRuntimeDependencyManifest({
    sourceRoot: root,
    dependencyRoot: resolve(root, "node_modules"),
    requiredExecArgv: process.execArgv,
  });
  assert.equal(
    validateIndependentReviewRuntimeDependencyManifest(manifest).ok,
    true,
  );
  assert.equal(manifest.environment.nodeOptionsRequiredAbsent, true);
  assert.equal(manifest.environment.nodePathRequiredAbsent, true);
  assert.deepEqual(
    manifest.environment.requiredExecArgv,
    process.execArgv,
  );
  assert.ok(manifest.dependencies.fullTreeEntryCount > 1_000);
  assert.ok(manifest.dependencies.fullTreeByteLength > 1_000_000);
  assert.match(manifest.dependencies.fullTreeSha256, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(
    manifest.source.packageLockSha256,
    `sha256:${(await import("node:crypto"))
      .createHash("sha256")
      .update(await readFile(resolve(root, "package-lock.json")))
      .digest("hex")}`,
  );
  assert.equal(
    serializeIndependentReviewRuntimeDependencyManifest(manifest)
      .toString("utf8")
      .endsWith("\n"),
    true,
  );
  assert.equal(
    independentReviewRuntimeLocalModulePaths.includes(
      "lib/independent-review-transport-evidence.mjs",
    ),
    true,
  );
  assert.equal(
    manifest.source.localModuleSubjects.some(
      ({ path }) =>
        path === "lib/independent-review-transport-evidence.mjs",
    ),
    true,
  );
  const schema = JSON.parse(
    await readFile(
      resolve(
        root,
        "implementation/governance/schemas/independent-review-runtime-manifest.v1.schema.json",
      ),
      "utf8",
    ),
  );
  const validateSchema = new Ajv2020({
    strict: true,
    allErrors: true,
  }).compile(schema);
  assert.equal(
    validateSchema(manifest),
    true,
    JSON.stringify(validateSchema.errors),
  );
  const tampered = structuredClone(manifest);
  tampered.dependencies.fullTreeSha256 = `sha256:${"0".repeat(64)}`;
  assert.deepEqual(
    validateIndependentReviewRuntimeDependencyManifest(tampered),
    {
      ok: false,
      reasonCodes: ["INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED"],
    },
  );
  const transportValidatorTampered = structuredClone(manifest);
  const transportValidator =
    transportValidatorTampered.source.localModuleSubjects.find(
      ({ path }) =>
        path === "lib/independent-review-transport-evidence.mjs",
    );
  transportValidator.sha256 = `sha256:${"0".repeat(64)}`;
  assert.deepEqual(
    validateIndependentReviewRuntimeDependencyManifest(
      transportValidatorTampered,
    ),
    {
      ok: false,
      reasonCodes: ["INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED"],
    },
  );
});

test("tree manifest changes for file, symlink and mode-visible dependency bytes", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "zb-runtime-tree-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(join(directory, "file.mjs"), "export default 1;\n");
  await symlink("file.mjs", join(directory, "link"));
  const before = await captureIndependentReviewTreeManifest(directory);
  await writeFile(join(directory, "file.mjs"), "export default 2;\n");
  const after = await captureIndependentReviewTreeManifest(directory);
  assert.notEqual(before.manifestSha256, after.manifestSha256);
  assert.equal(before.entryCount, 2);
  assert.equal(after.entryCount, 2);
});

test("bootstrap environment rejects preload and module-resolution injection", () => {
  assert.doesNotThrow(() =>
    assertIndependentReviewBootstrapEnvironment({
      env: {},
      execArgv: [],
    }),
  );
  for (const value of [
    { env: { NODE_OPTIONS: "--import=data:text/javascript,0" }, execArgv: [] },
    { env: { NODE_PATH: "/tmp/attacker" }, execArgv: [] },
    { env: {}, execArgv: ["--require=/tmp/attacker.cjs"] },
  ]) {
    assert.throws(
      () => assertIndependentReviewBootstrapEnvironment(value),
      /INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED/u,
    );
  }
});

test("runtime manifest resolves a package-symlink overlay to the same frozen dependency tree", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "zb-runtime-overlay-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const overlayRoot = join(directory, "node_modules");
  await mkdir(overlayRoot);
  for (const entry of await readdir(resolve(root, "node_modules"), {
    withFileTypes: true,
  })) {
    if (entry.name === ".vite-temp") continue;
    await symlink(
      resolve(root, "node_modules", entry.name),
      join(overlayRoot, entry.name),
    );
  }
  await mkdir(join(overlayRoot, ".vite-temp"));

  const direct = await captureIndependentReviewRuntimeDependencyManifest({
    sourceRoot: root,
    dependencyRoot: resolve(root, "node_modules"),
    requiredExecArgv: process.execArgv,
  });
  const overlay =
    await captureIndependentReviewRuntimeDependencyManifest({
      sourceRoot: root,
      dependencyRoot: overlayRoot,
      requiredExecArgv: process.execArgv,
    });

  assert.deepEqual(overlay.dependencies, direct.dependencies);

  await rm(join(overlayRoot, "ajv-formats"));
  await symlink(
    resolve(root, "node_modules", "ajv"),
    join(overlayRoot, "ajv-formats"),
  );
  await assert.rejects(
    captureIndependentReviewRuntimeDependencyManifest({
      sourceRoot: root,
      dependencyRoot: overlayRoot,
      requiredExecArgv: process.execArgv,
    }),
    /one frozen content root/u,
  );

  await rm(join(overlayRoot, "ajv-formats"));
  const outsideRoot = join(directory, "outside", "node_modules");
  await cp(
    resolve(root, "node_modules", "ajv-formats"),
    join(outsideRoot, "ajv-formats"),
    { recursive: true, dereference: true },
  );
  await symlink(
    join(outsideRoot, "ajv-formats"),
    join(overlayRoot, "ajv-formats"),
  );
  await assert.rejects(
    captureIndependentReviewRuntimeDependencyManifest({
      sourceRoot: root,
      dependencyRoot: overlayRoot,
      requiredExecArgv: process.execArgv,
    }),
    /one frozen content root/u,
  );
});
