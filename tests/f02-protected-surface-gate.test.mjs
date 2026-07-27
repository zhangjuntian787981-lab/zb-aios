import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { scanProtectedSurfaceInventory } from "../scripts/f02-protected-surface-gate.mjs";

const repositoryRoot = new URL("../", import.meta.url);

async function readJson(relativePath) {
  return JSON.parse(
    await readFile(new URL(relativePath, repositoryRoot), "utf8"),
  );
}

async function write(relativePath, contents, root) {
  const target = path.join(root, relativePath);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, contents);
}

function testInventory() {
  return {
    schema_version: "1.0.0",
    scope: "P0_P2_SYNTHETIC_ONLY",
    enterprise_data_used: false,
    protected_surfaces: [
      {
        id: "SOURCE_CODE",
        stage: "PREBUILD",
        files: ["source/app.mjs"],
        synthetic_marker_required: false,
      },
      {
        id: "SYNTHETIC_FIXTURES",
        stage: "PREBUILD",
        files: ["fixtures/fixture.json"],
        synthetic_marker_required: true,
      },
      {
        id: "EVALUATION_GROUND_TRUTH",
        stage: "PREBUILD",
        files: ["evaluation/cases.json"],
        synthetic_marker_required: true,
      },
      {
        id: "RUNTIME_STORE",
        stage: "PREBUILD",
        files: ["runtime/state.json"],
        synthetic_marker_required: true,
      },
      {
        id: "RUNTIME_LOG",
        stage: "PREBUILD",
        files: ["logs/runtime.jsonl"],
        synthetic_marker_required: true,
      },
      {
        id: "TRACE",
        stage: "PREBUILD",
        files: ["traces/trace.json"],
        synthetic_marker_required: true,
      },
      {
        id: "RELEASE_PACKAGE",
        stage: "RELEASE",
        files: ["release/index.js"],
        synthetic_marker_required: false,
      },
    ],
  };
}

async function writePassingSurfaceFiles(root) {
  await write("source/app.mjs", 'export const mode = "safe";\n', root);
  await write("fixtures/fixture.json", '{"watermark":"SYNTHETIC"}\n', root);
  await write(
    "evaluation/cases.json",
    '{"tenant_kind":"SYNTHETIC"}\n',
    root,
  );
  await write(
    "runtime/state.json",
    '{"data_classification":"SYNTHETIC_ONLY"}\n',
    root,
  );
  await write(
    "logs/runtime.jsonl",
    '{"data_classification":"SYNTHETIC","event":"START"}\n',
    root,
  );
  await write(
    "traces/trace.json",
    '{"phase":"P1_SYNTHETIC_ONLY","trace_id":"synthetic-trace"}\n',
    root,
  );
  await write("release/index.js", 'export const mode = "safe";\n', root);
}

test("all seven registered protected surfaces pass with explicit Synthetic markers", async () => {
  const policy = await readJson(
    "implementation/p0/f02/protected-surface-policy.v2.json",
  );
  const temporaryRoot = await mkdtemp(
    path.join(os.tmpdir(), "f02-surface-pass-"),
  );

  try {
    await writePassingSurfaceFiles(temporaryRoot);
    const result = await scanProtectedSurfaceInventory({
      repositoryRoot: temporaryRoot,
      inventory: testInventory(),
      policy,
      stage: "ALL",
    });

    assert.equal(result.status, "PASS");
    assert.deepEqual(result.findings, []);
    assert.equal(result.surface_count, 7);
    assert.equal(result.scanned_file_count, 7);
    assert.equal(result.synthetic_marker_required_file_count, 5);
    assert.equal(result.synthetic_marker_missing_file_count, 0);
    assert.equal(result.enterprise_data_or_credential_finding_count, 0);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("the repository inventory freezes the exact seven-surface denominator", async () => {
  const inventory = await readJson(
    "implementation/p0/f02/protected-surface-inventory.v1.json",
  );
  assert.deepEqual(
    inventory.protected_surfaces.map(
      ({ id, stage, synthetic_marker_required }) => [
        id,
        stage,
        synthetic_marker_required,
      ],
    ),
    [
      ["SOURCE_CODE", "PREBUILD", false],
      ["SYNTHETIC_FIXTURES", "PREBUILD", true],
      ["EVALUATION_GROUND_TRUTH", "PREBUILD", true],
      ["RUNTIME_STORE", "PREBUILD", true],
      ["RUNTIME_LOG", "PREBUILD", true],
      ["TRACE", "PREBUILD", true],
      ["RELEASE_PACKAGE", "RELEASE", false],
    ],
  );
  assert.equal(inventory.enterprise_data_used, false);
});

test("surface deletion, stage drift, and content-rule deletion fail configuration closed", async () => {
  const policy = await readJson(
    "implementation/p0/f02/protected-surface-policy.v2.json",
  );
  const temporaryRoot = await mkdtemp(
    path.join(os.tmpdir(), "f02-surface-config-"),
  );
  try {
    await writePassingSurfaceFiles(temporaryRoot);
    const cases = [
      {
        inventory: {
          ...testInventory(),
          protected_surfaces:
            testInventory().protected_surfaces.slice(1),
        },
        policy,
      },
      {
        inventory: {
          ...testInventory(),
          protected_surfaces: testInventory().protected_surfaces.map(
            (surface) =>
              surface.id === "TRACE"
                ? { ...surface, stage: "RELEASE" }
                : surface,
          ),
        },
        policy,
      },
      {
        inventory: testInventory(),
        policy: {
          ...policy,
          content_rules: policy.content_rules.slice(1),
        },
      },
    ];
    for (const current of cases) {
      await assert.rejects(
        scanProtectedSurfaceInventory({
          repositoryRoot: temporaryRoot,
          inventory: current.inventory,
          policy: current.policy,
          stage: "ALL",
        }),
        /F02 protected-surface/,
      );
    }
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("every data-bearing surface fails closed when its Synthetic marker is removed", async () => {
  const policy = await readJson(
    "implementation/p0/f02/protected-surface-policy.v2.json",
  );
  const inventory = testInventory();

  for (const surface of inventory.protected_surfaces.filter(
    ({ synthetic_marker_required }) => synthetic_marker_required,
  )) {
    const temporaryRoot = await mkdtemp(
      path.join(os.tmpdir(), "f02-surface-watermark-"),
    );
    try {
      await writePassingSurfaceFiles(temporaryRoot);
      await write(surface.files[0], '{"classification":"UNMARKED"}\n', temporaryRoot);

      const result = await scanProtectedSurfaceInventory({
        repositoryRoot: temporaryRoot,
        inventory,
        policy,
        stage: "ALL",
      });

      assert.equal(result.status, "BLOCKED", surface.id);
      assert.ok(
        result.findings.some(
          ({ code, surface_id }) =>
            code === "MISSING_SYNTHETIC_MARKER" &&
            surface_id === surface.id,
        ),
        surface.id,
      );
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }
});

test("enterprise identifier, Token, private key, and connection-string canaries block every surface", async () => {
  const policy = await readJson(
    "implementation/p0/f02/protected-surface-policy.v2.json",
  );
  const inventory = testInventory();
  const canaries = [
    ["ENTERPRISE_IDENTIFIER", "FORBIDDEN_REAL_ENTERPRISE_SENTINEL"],
    ["TOKEN", "sk-synthetic-canary-1234567890"],
    [
      "PRIVATE_KEY",
      "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-CANARY\n-----END PRIVATE KEY-----",
    ],
    [
      "CONNECTION_STRING",
      "postgresql://synthetic-user:synthetic-pass@db.example.invalid:5432/canary",
    ],
  ];

  for (const surface of inventory.protected_surfaces) {
    for (const [expectedRule, canary] of canaries) {
      const temporaryRoot = await mkdtemp(
        path.join(os.tmpdir(), "f02-surface-canary-"),
      );
      try {
        await writePassingSurfaceFiles(temporaryRoot);
        await write(surface.files[0], `${canary}\n`, temporaryRoot);

        const result = await scanProtectedSurfaceInventory({
          repositoryRoot: temporaryRoot,
          inventory,
          policy,
          stage: "ALL",
        });

        assert.equal(result.status, "BLOCKED", `${surface.id}:${expectedRule}`);
        assert.ok(
          result.findings.some(
            ({ rule_id, surface_id }) =>
              rule_id === expectedRule && surface_id === surface.id,
          ),
          `${surface.id}:${expectedRule}`,
        );
      } finally {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }
  }
});

test("the formal build and hosted-CI definition invoke the protected-surface gate", async () => {
  const packageJson = await readJson("package.json");
  const workflow = await readFile(
    new URL(
      "../.github/workflows/f02-protected-surface-gate.yml",
      import.meta.url,
    ),
    "utf8",
  );

  assert.equal(
    packageJson.scripts["f02:gate:prebuild"],
    "node scripts/f02-protected-surface-gate.mjs --stage PREBUILD",
  );
  assert.equal(
    packageJson.scripts["f02:gate:release"],
    "node scripts/f02-protected-surface-gate.mjs --stage RELEASE",
  );
  assert.equal(
    packageJson.scripts.build,
    "npm run f02:gate:prebuild && npm run build:app && npm run f02:gate:release",
  );
  assert.match(workflow, /npm ci --ignore-scripts --no-audit --no-fund/);
  assert.match(workflow, /npm run build/);
});
