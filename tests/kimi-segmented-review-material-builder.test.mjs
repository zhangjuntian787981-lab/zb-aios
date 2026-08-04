import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  parseKimiSegmentReviewMaterial,
  segmentedKimiReviewDigests,
} from "../lib/kimi-segmented-independent-review.mjs";
import {
  buildKimiSegmentedContentMaterialsFromGit,
  collectKimiSegmentedReviewInventoryFromGit,
} from "../scripts/build-kimi-segmented-review-materials.mjs";

const execFileAsync = promisify(execFile);
const requiredIntegrationPaths = Object.freeze([
  "implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
  "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
  "docs/adr/0020-kimi-k3-segmented-independent-review.md",
  "CONTEXT.md",
]);

async function git(repoPath, args) {
  return execFileAsync("/usr/bin/git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    env: {
      PATH: "/usr/bin:/bin",
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_SYSTEM: "/dev/null",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_AUTHOR_NAME: "Segment Fixture",
      GIT_AUTHOR_EMAIL: "segment-fixture@example.invalid",
      GIT_COMMITTER_NAME: "Segment Fixture",
      GIT_COMMITTER_EMAIL: "segment-fixture@example.invalid",
    },
  });
}

async function put(repoPath, path, value) {
  await mkdir(join(repoPath, path, ".."), { recursive: true });
  await writeFile(join(repoPath, path), value);
}

function descriptor(path, bytes) {
  return {
    path,
    byteLength: bytes.byteLength,
    sha256: segmentedKimiReviewDigests.bytes(bytes),
  };
}

async function frozenGitFixture() {
  const repoPath = await mkdtemp(join(tmpdir(), "kimi-segments-"));
  await git(repoPath, ["init", "-q"]);
  const fixed = new Map([
    ["AGENTS.md", Buffer.from("frozen common specification\n", "utf8")],
    ["fixtures/segment-prompt.md", Buffer.from("segment prompt\n", "utf8")],
    ["fixtures/integration-prompt.md", Buffer.from("integration prompt\n", "utf8")],
    ["fixtures/output-schema.json", Buffer.from("{}\n", "utf8")],
    ["fixtures/provider-schema.json", Buffer.from("{}\n", "utf8")],
    ["fixtures/provider-config.json", Buffer.from("{}\n", "utf8")],
    ["fixtures/provider-config-schema.json", Buffer.from("{}\n", "utf8")],
    ["fixtures/token-estimate-schema.json", Buffer.from("{}\n", "utf8")],
    ["fixtures/segmented-transport-schema.json", Buffer.from("{}\n", "utf8")],
    ["fixtures/segment-receipt-schema.json", Buffer.from("{}\n", "utf8")],
    ["fixtures/integration-receipt-schema.json", Buffer.from("{}\n", "utf8")],
    ["fixtures/aggregate-receipt-schema.json", Buffer.from("{}\n", "utf8")],
    ...await Promise.all(
      requiredIntegrationPaths.map(async (path) => [path, await readFile(path)]),
    ),
  ]);
  for (const [path, bytes] of fixed) await put(repoPath, path, bytes);
  await git(repoPath, ["add", "."]);
  await git(repoPath, ["commit", "-q", "-m", "base"]);
  const baseCommit = (await git(repoPath, ["rev-parse", "HEAD"])).stdout.trim();

  const subjects = new Map([
    ["docs/adr/0020-kimi-k3-segmented-review.md", Buffer.from("governance bytes\n", "utf8")],
    ["implementation/governance/schemas/segment-subject.json", Buffer.from('{"schema":true}\n', "utf8")],
    ["lib/segment-subject.mjs", Buffer.from("export const frozen = true;\n", "utf8")],
    ["tests/segment-subject.test.mjs", Buffer.from("// frozen test bytes\n", "utf8")],
    ...await Promise.all([
      "formal-request.json",
      "review-bundle.v2.json",
      "review-material.v3.utf8",
      "single-call-outcome.v1.json",
      "token-estimate-request.json",
    ].map(async (name) => {
      const path =
        `implementation/governance/independent-review/evidence/kimi-k3-single-call-20260731/${name}`;
      return [path, await readFile(path)];
    })),
  ]);
  for (const [path, bytes] of subjects) await put(repoPath, path, bytes);
  await git(repoPath, ["add", "."]);
  await git(repoPath, ["commit", "-q", "-m", "source"]);
  const sourceCommit = (await git(repoPath, ["rev-parse", "HEAD"])).stdout.trim();
  return { repoPath, baseCommit, sourceCommit, fixed, subjects };
}

test("frozen Git inventory and four materials ignore dirty worktree bytes", async () => {
  const values = await frozenGitFixture();
  const inventory = await collectKimiSegmentedReviewInventoryFromGit({
    repoPath: values.repoPath,
    baseCommit: values.baseCommit,
    sourceCommit: values.sourceCommit,
  });
  assert.deepEqual(inventory.segmentPathCounts, {
    GOVERNANCE_LINEAGE: 6,
    SCHEMAS_WIRE_CONTRACTS: 1,
    RUNTIME_ORCHESTRATION: 1,
    TESTS_VERIFICATION: 1,
  });
  assert.equal(inventory.networkCalls, 0);
  await put(
    values.repoPath,
    "lib/segment-subject.mjs",
    Buffer.from("DIRTY WORKTREE MUST NOT ENTER MATERIAL\n", "utf8"),
  );
  const afterDirty = await collectKimiSegmentedReviewInventoryFromGit({
    repoPath: values.repoPath,
    baseCommit: values.baseCommit,
    sourceCommit: values.sourceCommit,
  });
  assert.deepEqual(afterDirty, inventory);

  const bundle = {
    schemaVersion: "independent-review-bundle.v2",
    bundleId: "imrb_git_fixture_001",
    bundleSha256: segmentedKimiReviewDigests.value({ fixture: true }),
    source: inventory.source,
    reviewedPaths: inventory.reviewedPaths,
    sourceSubjects: inventory.sourceSubjects,
  };
  const bundleBytes = Buffer.from(JSON.stringify(bundle), "utf8");
  const bindings = {
    reviewBundle: descriptor("artifacts/review-bundle.v2.json", bundleBytes),
    segmentReviewerPrompt: descriptor("fixtures/segment-prompt.md", values.fixed.get("fixtures/segment-prompt.md")),
    integrationReviewerPrompt: descriptor("fixtures/integration-prompt.md", values.fixed.get("fixtures/integration-prompt.md")),
    canonicalOutputSchema: descriptor("fixtures/output-schema.json", values.fixed.get("fixtures/output-schema.json")),
    providerTransportSchema: descriptor("fixtures/provider-schema.json", values.fixed.get("fixtures/provider-schema.json")),
    providerConfig: descriptor("fixtures/provider-config.json", values.fixed.get("fixtures/provider-config.json")),
    providerConfigSchema: descriptor("fixtures/provider-config-schema.json", values.fixed.get("fixtures/provider-config-schema.json")),
    tokenEstimateEvidenceSchema: descriptor("fixtures/token-estimate-schema.json", values.fixed.get("fixtures/token-estimate-schema.json")),
    segmentedTransportEvidenceSchema: descriptor("fixtures/segmented-transport-schema.json", values.fixed.get("fixtures/segmented-transport-schema.json")),
    segmentReceiptSchema: descriptor("fixtures/segment-receipt-schema.json", values.fixed.get("fixtures/segment-receipt-schema.json")),
    integrationReceiptSchema: descriptor("fixtures/integration-receipt-schema.json", values.fixed.get("fixtures/integration-receipt-schema.json")),
    aggregateReceiptSchema: descriptor("fixtures/aggregate-receipt-schema.json", values.fixed.get("fixtures/aggregate-receipt-schema.json")),
  };
  const commonSections = [
    { kind: "SPECIFICATION", ...descriptor("AGENTS.md", values.fixed.get("AGENTS.md")) },
  ];
  const integrationSections = requiredIntegrationPaths.map((path) => ({
    kind: path.startsWith("docs/adr/") || path.endsWith(".json")
      ? "GOVERNANCE"
      : "SPECIFICATION",
    ...descriptor(path, values.fixed.get(path)),
  }));
  const built = await buildKimiSegmentedContentMaterialsFromGit({
    repoPath: values.repoPath,
    planId: "imsrp_git_fixture_001",
    bundle,
    bundleBytes,
    bindings,
    commonSections,
    integrationSections,
  });
  assert.equal(built.materials.length, 4);
  const runtime = parseKimiSegmentReviewMaterial(
    built.materials.find(({ segmentId }) => segmentId === "RUNTIME_ORCHESTRATION").materialBytes,
  );
  assert.equal(
    runtime.reviewedSectionBytes[0].toString("utf8"),
    "export const frozen = true;\n",
  );
  assert.equal(
    runtime.reviewedSectionBytes[0].includes(Buffer.from("DIRTY")),
    false,
  );
});

test("offline segmented builder exposes no model, credential, network, or governance-write seam", async () => {
  const [builder, core, projectControl, progressRoute] = await Promise.all([
    readFile("scripts/build-kimi-segmented-review-materials.mjs", "utf8"),
    readFile("lib/kimi-segmented-independent-review.mjs", "utf8"),
    readFile("lib/project-control.mjs", "utf8"),
    readFile("app/api/progress/route.ts", "utf8"),
  ]);
  for (const source of [builder, core]) {
    assert.doesNotMatch(source, /(?:\b|\.)fetch\s*\(/u);
    assert.doesNotMatch(source, /Keychain|security find-generic-password/u);
    assert.doesNotMatch(source, /journal\.append|control\.execute/u);
    assert.doesNotMatch(source, /executeKimiK3|readKimiCredential/u);
    assert.doesNotMatch(
      source,
      /node:(?:http|https|http2|net|tls|dgram|undici|fs)|writeFile|appendFile|createWriteStream|rename\s*\(|unlink\s*\(|rm\s*\(/u,
    );
  }
  const importSpecifiers = (source) =>
    [...source.matchAll(/from\s+"([^"]+)"/gu)].map(([, specifier]) => specifier);
  assert.deepEqual(importSpecifiers(core), [
    "node:crypto",
    "./independent-model-review.mjs",
    "./kimi-k3-review-evidence.mjs",
  ]);
  assert.deepEqual(importSpecifiers(builder), [
    "node:child_process",
    "node:path",
    "node:util",
    "../lib/kimi-segmented-independent-review.mjs",
  ]);
  assert.equal((builder.match(/execFileAsync\(/gu) ?? []).length, 1);
  assert.match(builder, /execFileAsync\(\s*"\/usr\/bin\/git"/u);
  assert.doesNotMatch(projectControl, /kimi-segmented-independent-review/u);
  assert.doesNotMatch(progressRoute, /kimi-segmented-independent-review/u);
});
