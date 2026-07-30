import assert from "node:assert/strict";
import {
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  captureIndependentReviewRuntimeBinding,
  serializeIndependentReviewRuntimeBinding,
  validateIndependentReviewRuntimeBinding,
} from "../lib/independent-review-runtime-binding.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);
const packages = [
  "ajv",
  "ajv-formats",
  "fast-deep-equal",
  "fast-uri",
  "json-schema-traverse",
  "require-from-string",
];

async function runtimeFixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "zb-runtime-binding-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const dependencyRoot = join(directory, "node_modules");
  for (const name of packages) {
    await cp(join(root, "node_modules", name), join(dependencyRoot, name), {
      recursive: true,
      dereference: true,
    });
  }
  const nodeExecutablePath = join(directory, "node");
  await writeFile(nodeExecutablePath, "fixture node executable\n");
  return { directory, dependencyRoot, nodeExecutablePath };
}

test("runtime binding closes the Node executable and exact dependency package bytes", async (t) => {
  const fixture = await runtimeFixture(t);
  const first = await captureIndependentReviewRuntimeBinding(fixture);
  assert.deepEqual(validateIndependentReviewRuntimeBinding(first), {
    ok: true,
    reasonCodes: [],
  });
  assert.equal(first.dependencyPackages.length, packages.length);
  assert.ok(first.dependencyPackages.every(({ entryCount }) => entryCount > 0));
  assert.ok(first.nodeExecutable.byteLength > 0);
  assert.match(first.gitToolchain.version, /^git version /u);
  assert.match(
    first.gitToolchain.resolvedExecutable.sha256,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.match(
    first.gitToolchain.xcrunLibrary.sha256,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.match(
    first.gitToolchain.xcrunCache.sha256,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.match(
    first.systemToolchain.shasumExecutable.sha256,
    /^sha256:[a-f0-9]{64}$/u,
  );
  assert.match(
    first.systemToolchain.perlExecutable.sha256,
    /^sha256:[a-f0-9]{64}$/u,
  );

  await writeFile(
    join(fixture.dependencyRoot, "ajv", "dist", "2020.js"),
    "tampered same-version Ajv bytes\n",
  );
  const changedDependency =
    await captureIndependentReviewRuntimeBinding(fixture);
  assert.notEqual(
    changedDependency.dependencySetSha256,
    first.dependencySetSha256,
  );
  assert.notEqual(changedDependency.bindingSha256, first.bindingSha256);

  await writeFile(fixture.nodeExecutablePath, "changed node executable\n");
  const changedNode = await captureIndependentReviewRuntimeBinding(fixture);
  assert.notEqual(
    changedNode.nodeExecutable.sha256,
    changedDependency.nodeExecutable.sha256,
  );
  assert.notEqual(changedNode.bindingSha256, changedDependency.bindingSha256);
});

test("runtime binding serialization and self-hash reject field tampering", async (t) => {
  const fixture = await runtimeFixture(t);
  const binding = await captureIndependentReviewRuntimeBinding(fixture);
  const bytes = serializeIndependentReviewRuntimeBinding(binding);
  assert.deepEqual(JSON.parse(bytes.toString("utf8")), binding);

  const tampered = structuredClone(binding);
  tampered.dependencyPackages[0].manifestSha256 =
    `sha256:${"f".repeat(64)}`;
  assert.equal(validateIndependentReviewRuntimeBinding(tampered).ok, false);
  const changedToolchain = structuredClone(binding);
  changedToolchain.gitToolchain.resolvedExecutable.sha256 =
    `sha256:${"e".repeat(64)}`;
  assert.equal(
    validateIndependentReviewRuntimeBinding(changedToolchain).ok,
    false,
  );

  const reparsed = JSON.parse(await readFile(
    new URL(
      "../implementation/governance/schemas/independent-review-test-result.v3.schema.json",
      import.meta.url,
    ),
    "utf8",
  ));
  assert.ok(reparsed.properties.runtimeBinding);
});

test("runtime binding normalizes a package-symlink overlay to one frozen dependency root", async (t) => {
  const fixture = await runtimeFixture(t);
  const overlayRoot = join(fixture.directory, "overlay", "node_modules");
  await mkdir(overlayRoot, { recursive: true });
  for (const name of packages) {
    await symlink(
      join(fixture.dependencyRoot, name),
      join(overlayRoot, name),
    );
  }
  await mkdir(join(overlayRoot, ".vite-temp"));

  const direct = await captureIndependentReviewRuntimeBinding(fixture);
  const overlay = await captureIndependentReviewRuntimeBinding({
    ...fixture,
    dependencyRoot: overlayRoot,
  });

  assert.equal(
    overlay.dependencySetSha256,
    direct.dependencySetSha256,
  );
  assert.deepEqual(overlay.dependencyPackages, direct.dependencyPackages);

  await rm(join(overlayRoot, "ajv-formats"));
  await symlink(
    join(fixture.dependencyRoot, "ajv"),
    join(overlayRoot, "ajv-formats"),
  );
  await assert.rejects(
    captureIndependentReviewRuntimeBinding({
      ...fixture,
      dependencyRoot: overlayRoot,
    }),
    /one frozen root/u,
  );

  await rm(join(overlayRoot, "ajv-formats"));
  const outsideRoot = join(fixture.directory, "outside", "node_modules");
  await cp(
    join(fixture.dependencyRoot, "ajv-formats"),
    join(outsideRoot, "ajv-formats"),
    { recursive: true, dereference: true },
  );
  await symlink(
    join(outsideRoot, "ajv-formats"),
    join(overlayRoot, "ajv-formats"),
  );
  await assert.rejects(
    captureIndependentReviewRuntimeBinding({
      ...fixture,
      dependencyRoot: overlayRoot,
    }),
    /one frozen root/u,
  );
});
