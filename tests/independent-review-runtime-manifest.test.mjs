import assert from "node:assert/strict";
import {
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
import { join, resolve } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {
  assertIndependentReviewBootstrapEnvironment,
  captureIndependentReviewRuntimeDependencyManifest,
  captureIndependentReviewTreeManifest,
  independentReviewRuntimeLocalModulePaths,
  serializeIndependentReviewRuntimeDependencyManifest,
  validateIndependentReviewRuntimeDependencyManifest,
} from "../lib/independent-review-runtime-manifest.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);

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
