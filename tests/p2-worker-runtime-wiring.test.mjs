import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import manifest from "../implementation/governance/work-package-manifest.v1.json" with { type: "json" };
import {
  createMemoryJournal,
  createProjectControl,
} from "../lib/project-control.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "../lib/p2-start-authorization.mjs";
import { verifyP2ExecutionBaselineFromBuildAttestation } from "../lib/p2-worker-attestation-verifier.mjs";

const REPOSITORY_ROOT = new URL("../", import.meta.url).pathname;
const PACKAGE_URL = new URL("../package.json", import.meta.url);
const PROGRESS_ROUTE_URL = new URL(
  "../app/api/progress/route.ts",
  import.meta.url,
);
const READINESS_ROUTE_URL = new URL(
  "../app/api/governance/p2-readiness/route.ts",
  import.meta.url,
);
const PROJECT_CONTROL_URL = new URL(
  "../lib/project-control.mjs",
  import.meta.url,
);
const BUNDLE_VERIFIER_URL = new URL(
  "../scripts/verify-p2-worker-runtime-bundle.mjs",
  import.meta.url,
);
const CURRENT_PROGRESS_ACTIONS = [
  "decide_gate",
  "submit_gate",
  "update_connector",
  "update_task",
  "validate_human_baseline",
];
const REQUIRED_SERVER_MARKERS = {
  verifier:
    "async function verifyP2ExecutionBaselineFromBuildAttestation",
  compositionBinding:
    "verifyP2ExecutionBaseline: verifyP2ExecutionBaselineFromBuildAttestation",
  attestationId: "p2eba_48a4e4eac1f2_e6282c301d6e",
  canonicalPin:
    "sha256:46fe858b866f16a97c9a9e0d10dc604412feceed85e03201da7ed75c7a85f298",
  sourceCommit: "48a4e4eac1f2fc2404d21ca5ab9a2d014a0e20e5",
  executionBaselineDigest:
    "sha256:e6282c301d6eb05cace8361f5974143897db59c3770d4c8856211f0635599bee",
};
const FORBIDDEN_SERVER_MARKERS = {
  gitExecutable: "/usr/bin/git",
  childProcess: "node:child_process",
  attestationBuildScript: "build-p2-execution-baseline-attestation",
  githubApi: "api.github.com",
  rawGithub: "raw.githubusercontent.com",
  githubToken: "GITHUB_TOKEN",
  githubTokenCamel: "githubToken",
  githubTokenSnake: "github_token",
  ghToken: "GH_TOKEN",
  gitNoReplaceObjects: "GIT_NO_REPLACE_OBJECTS",
  gitTerminalPrompt: "GIT_TERMINAL_PROMPT",
  gitNoReplaceFlag: "--no-replace-objects",
  gitCatFile: "cat-file",
  gitRevParse: "rev-parse",
};

async function source(url) {
  return readFile(url, "utf8");
}

async function temporaryBundle(t) {
  const repositoryRoot = await mkdtemp(
    join(tmpdir(), "p2-worker-runtime-bundle-"),
  );
  t.after(() => rm(repositoryRoot, { recursive: true, force: true }));
  await mkdir(join(repositoryRoot, "dist/server"), { recursive: true });
  await mkdir(join(repositoryRoot, "dist/client/assets/nested"), {
    recursive: true,
  });
  return repositoryRoot;
}

function countedJournal() {
  const memory = createMemoryJournal();
  const counts = { append: 0 };
  return {
    counts,
    journal: {
      load: (...arguments_) => memory.load(...arguments_),
      append: (...arguments_) => {
        counts.append += 1;
        return memory.append(...arguments_);
      },
    },
  };
}

test("the progress composition root injects the default frozen Worker verifier", async () => {
  const route = await source(PROGRESS_ROUTE_URL);
  const compositionRoot = route.slice(
    route.indexOf("async function controlSnapshot"),
    route.indexOf("async function dashboardData"),
  );

  assert.match(
    route,
    /import \{\s*verifyP2ExecutionBaselineFromBuildAttestation\s*\} from "\.\.\/\.\.\/\.\.\/lib\/p2-worker-attestation-verifier\.mjs";/,
  );
  assert.match(
    compositionRoot,
    /verifyP2ExecutionBaseline:\s*verifyP2ExecutionBaselineFromBuildAttestation/,
  );
});

test("Project Control does not reverse-import the Worker verifier", async () => {
  const projectControl = await source(PROJECT_CONTROL_URL);

  assert.doesNotMatch(
    projectControl,
    /p2-worker-attestation-verifier/,
  );
});

test("snapshot does not call the execution-baseline verifier or append to the journal", async () => {
  const { counts, journal } = countedJournal();
  let verifierCalls = 0;
  const control = createProjectControl({
    manifest,
    journal,
    verifyP2ExecutionBaseline: async () => {
      verifierCalls += 1;
      return true;
    },
  });

  const snapshot = await control.snapshot();
  const o02 = snapshot.workPackages.find(({ id }) => id === "O02");
  const o03 = snapshot.workPackages.find(({ id }) => id === "O03");

  assert.equal(verifierCalls, 0);
  assert.equal(counts.append, 0);
  assert.deepEqual(
    [o02, o03].map((item) => ({
      id: item.id,
      implementationStatus: item.implementationStatus,
      verificationStatus: item.verificationStatus,
      allowedToStart: item.allowedToStart,
    })),
    [
      {
        id: "O02",
        implementationStatus: "NOT_STARTED",
        verificationStatus: "NOT_VERIFIED",
        allowedToStart: false,
      },
      {
        id: "O03",
        implementationStatus: "NOT_STARTED",
        verificationStatus: "NOT_VERIFIED",
        allowedToStart: false,
      },
    ],
  );
});

test("an ordinary non-Profile governance command never calls the verifier", async () => {
  const { counts, journal } = countedJournal();
  let verifierCalls = 0;
  const control = createProjectControl({
    manifest,
    journal,
    verifyP2ExecutionBaseline: async () => {
      verifierCalls += 1;
      return true;
    },
  });

  await control.execute(
    {
      actorId: "external_product_owner",
      roles: ["PRODUCT_OWNER"],
    },
    {
      kind: "RECORD_WORK_PACKAGE",
      workPackageId: "F01",
      implementationStatus: "IN_PROGRESS",
      verificationStatus: "NOT_VERIFIED",
      evidenceRefs: [],
      evidenceHashes: [],
      note: "Synthetic wiring boundary check.",
      expectedRevision: 0,
      idempotencyKey: "p2-runtime-wiring-ordinary-command",
    },
  );

  assert.equal(verifierCalls, 0);
  assert.equal(counts.append, 1);
});

test("the progress HTTP action surface remains the exact existing five actions", async () => {
  const route = await source(PROGRESS_ROUTE_URL);
  const actions = [
    ...route.matchAll(/payload\.action === "([^"]+)"/g),
  ]
    .map((match) => match[1])
    .sort();

  assert.deepEqual(actions, CURRENT_PROGRESS_ACTIONS);
  assert.doesNotMatch(
    route,
    /approve_p2_acceptance_profile|authorize_p2_work_package_start|revoke_p2_work_package_start_authorization/i,
  );
  assert.doesNotMatch(
    route,
    /APPROVE_P2_ACCEPTANCE_PROFILE|AUTHORIZE_P2_WORK_PACKAGE_START|REVOKE_P2_WORK_PACKAGE_START_AUTHORIZATION/,
  );
  assert.doesNotMatch(route, /payload\.(command|kind)/);
});

test("the P2 readiness route remains GET-only", async () => {
  const route = await source(READINESS_ROUTE_URL);
  const methods = [
    ...route.matchAll(
      /export (?:async function|const) (GET|POST|PUT|PATCH|DELETE)\b/g,
    ),
  ].map((match) => match[1]);

  assert.deepEqual(methods, ["GET"]);
});

test("the bundle verifier accepts one server-only frozen verifier set", async () => {
  const { verifyP2WorkerRuntimeBundleContents } =
    await import(BUNDLE_VERIFIER_URL);
  const result = verifyP2WorkerRuntimeBundleContents({
    serverJavaScript: Object.values(REQUIRED_SERVER_MARKERS).join("\n"),
    clientJavaScriptFiles: [
      {
        path: "dist/client/assets/client.js",
        contents: "console.log('public client');",
      },
    ],
  });

  assert.deepEqual(result, {
    schemaVersion: "p2-worker-runtime-bundle-verification.v1",
    status: "PASS",
    serverMarkerCount: 6,
    clientJavaScriptFileCount: 1,
    forbiddenRuntimeMarkerCount: 0,
  });
});

test("the bundle verifier fails closed when the Worker verifier is absent", async () => {
  const { verifyP2WorkerRuntimeBundleContents } =
    await import(BUNDLE_VERIFIER_URL);
  const serverJavaScript = Object.entries(REQUIRED_SERVER_MARKERS)
    .filter(([name]) => name !== "verifier")
    .map(([, marker]) => marker)
    .join("\n");

  assert.throws(
    () =>
      verifyP2WorkerRuntimeBundleContents({
        serverJavaScript,
        clientJavaScriptFiles: [
          {
            path: "dist/client/assets/client.js",
            contents: "console.log('public client');",
          },
        ],
      }),
    {
      message: "SERVER_REQUIRED_MARKER_MISSING:verifier",
    },
  );
});

test("the bundle verifier rejects every missing or changed frozen marker", async () => {
  const { verifyP2WorkerRuntimeBundleContents } =
    await import(BUNDLE_VERIFIER_URL);

  for (const [missingName] of Object.entries(REQUIRED_SERVER_MARKERS)) {
    const serverJavaScript = Object.entries(REQUIRED_SERVER_MARKERS)
      .filter(([name]) => name !== missingName)
      .map(([, marker]) => marker)
      .join("\n");
    const changedServerJavaScript = Object.entries(
      REQUIRED_SERVER_MARKERS,
    )
      .map(([name, marker]) =>
        name === missingName ? "incorrect-frozen-marker" : marker,
      )
      .join("\n");

    for (const contents of [
      serverJavaScript,
      changedServerJavaScript,
    ]) {
      assert.throws(
        () =>
          verifyP2WorkerRuntimeBundleContents({
            serverJavaScript: contents,
            clientJavaScriptFiles: [
              {
                path: "dist/client/assets/client.js",
                contents: "console.log('public client');",
              },
            ],
          }),
        {
          message: `SERVER_REQUIRED_MARKER_MISSING:${missingName}`,
        },
      );
    }
  }
});

test("the bundle verifier rejects frozen evidence in every client bundle", async () => {
  const { verifyP2WorkerRuntimeBundleContents } =
    await import(BUNDLE_VERIFIER_URL);
  const serverJavaScript = Object.values(REQUIRED_SERVER_MARKERS).join(
    "\n",
  );

  for (const [leakedName, marker] of Object.entries(
    REQUIRED_SERVER_MARKERS,
  )) {
    assert.throws(
      () =>
        verifyP2WorkerRuntimeBundleContents({
          serverJavaScript,
          clientJavaScriptFiles: [
            {
              path: "dist/client/assets/leaked.js",
              contents: marker,
            },
          ],
        }),
      {
        message:
          `CLIENT_EVIDENCE_LEAK:${leakedName}:` +
          "dist/client/assets/leaked.js",
      },
    );
  }
});

test("the bundle verifier rejects explicit runtime Git and network proof dependencies", async () => {
  const { verifyP2WorkerRuntimeBundleContents } =
    await import(BUNDLE_VERIFIER_URL);
  const required = Object.values(REQUIRED_SERVER_MARKERS).join("\n");

  for (const [forbiddenName, marker] of Object.entries(
    FORBIDDEN_SERVER_MARKERS,
  )) {
    assert.throws(
      () =>
        verifyP2WorkerRuntimeBundleContents({
          serverJavaScript: `${required}\n${marker}`,
          clientJavaScriptFiles: [
            {
              path: "dist/client/assets/client.js",
              contents: "console.log('public client');",
            },
          ],
        }),
      {
        message: `SERVER_FORBIDDEN_RUNTIME_MARKER:${forbiddenName}`,
      },
    );
  }
});

test("the bundle verifier fails closed when there is no client JavaScript", async () => {
  const { verifyP2WorkerRuntimeBundleContents } =
    await import(BUNDLE_VERIFIER_URL);

  assert.throws(
    () =>
      verifyP2WorkerRuntimeBundleContents({
        serverJavaScript: Object.values(REQUIRED_SERVER_MARKERS).join(
          "\n",
        ),
        clientJavaScriptFiles: [],
      }),
    {
      message: "CLIENT_JAVASCRIPT_EMPTY",
    },
  );
});

test("the filesystem bundle verifier reads the fixed server entry and recursive client JavaScript", async (t) => {
  const { verifyP2WorkerRuntimeBundle } = await import(BUNDLE_VERIFIER_URL);
  const repositoryRoot = await temporaryBundle(t);
  await writeFile(
    join(repositoryRoot, "dist/server/index.js"),
    Object.values(REQUIRED_SERVER_MARKERS).join("\n"),
  );
  await writeFile(
    join(repositoryRoot, "dist/client/assets/client.js"),
    "console.log('client');",
  );
  await writeFile(
    join(repositoryRoot, "dist/client/assets/nested/chunk.mjs"),
    "console.log('nested client');",
  );
  await writeFile(
    join(repositoryRoot, "dist/client/assets/style.css"),
    Object.values(REQUIRED_SERVER_MARKERS).join("\n"),
  );

  assert.deepEqual(
    await verifyP2WorkerRuntimeBundle({ repositoryRoot }),
    {
      schemaVersion: "p2-worker-runtime-bundle-verification.v1",
      status: "PASS",
      serverMarkerCount: 6,
      clientJavaScriptFileCount: 2,
      forbiddenRuntimeMarkerCount: 0,
    },
  );
});

test("the filesystem bundle verifier rejects a forbidden dependency in the server SSR closure", async (t) => {
  const { verifyP2WorkerRuntimeBundle } = await import(BUNDLE_VERIFIER_URL);
  const repositoryRoot = await temporaryBundle(t);
  await mkdir(join(repositoryRoot, "dist/server/ssr"), {
    recursive: true,
  });
  await writeFile(
    join(repositoryRoot, "dist/server/index.js"),
    Object.values(REQUIRED_SERVER_MARKERS).join("\n"),
  );
  await writeFile(
    join(repositoryRoot, "dist/server/ssr/index.js"),
    "import 'node:child_process';",
  );
  await writeFile(
    join(repositoryRoot, "dist/client/assets/client.js"),
    "console.log('client');",
  );

  await assert.rejects(
    verifyP2WorkerRuntimeBundle({ repositoryRoot }),
    {
      message: "SERVER_FORBIDDEN_RUNTIME_MARKER:childProcess",
    },
  );
});

test("the filesystem bundle verifier fails closed when its fixed server entry is unavailable", async (t) => {
  const { verifyP2WorkerRuntimeBundle } = await import(BUNDLE_VERIFIER_URL);
  const repositoryRoot = await temporaryBundle(t);
  await writeFile(
    join(repositoryRoot, "dist/client/assets/client.js"),
    "console.log('client');",
  );

  await assert.rejects(
    verifyP2WorkerRuntimeBundle({ repositoryRoot }),
    {
      message: "SERVER_BUNDLE_UNAVAILABLE",
    },
  );
});

test("the app build lifecycle verifies the Worker bundle before RELEASE", async () => {
  const packageJson = JSON.parse(await source(PACKAGE_URL));

  assert.equal(
    packageJson.scripts.build,
    "npm run f02:gate:prebuild && npm run build:app && npm run f02:gate:release",
  );
  assert.equal(
    packageJson.scripts["postbuild:app"],
    "npm run p2:verify:worker-bundle",
  );
  assert.equal(
    packageJson.scripts["p2:verify:worker-bundle"],
    "node scripts/verify-p2-worker-runtime-bundle.mjs",
  );
});

test("the real Worker bundle contains the frozen verifier evidence only on the server", async () => {
  const { verifyP2WorkerRuntimeBundle } = await import(BUNDLE_VERIFIER_URL);
  const result = await verifyP2WorkerRuntimeBundle({
    repositoryRoot: REPOSITORY_ROOT,
  });

  assert.equal(
    result.schemaVersion,
    "p2-worker-runtime-bundle-verification.v1",
  );
  assert.equal(result.status, "PASS");
  assert.equal(result.serverMarkerCount, 6);
  assert.ok(result.clientJavaScriptFileCount > 0);
  assert.equal(result.forbiddenRuntimeMarkerCount, 0);
});

test("the production default verifier accepts only the fixed build binding", async () => {
  const binding = {
    sourceCommit: REQUIRED_SERVER_MARKERS.sourceCommit,
    executionBaselineDigest:
      REQUIRED_SERVER_MARKERS.executionBaselineDigest,
    policy: P2_V2_CANDIDATE_START_POLICY,
  };

  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation(binding),
    true,
  );
  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation({
      ...binding,
      sourceCommit: "7".repeat(40),
    }),
    false,
  );
  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation({
      ...binding,
      executionBaselineDigest: `sha256:${"8".repeat(64)}`,
    }),
    false,
  );
  const wrongPolicy = structuredClone(P2_V2_CANDIDATE_START_POLICY);
  wrongPolicy.profile.sha256 = `sha256:${"9".repeat(64)}`;
  assert.equal(
    await verifyP2ExecutionBaselineFromBuildAttestation({
      ...binding,
      policy: wrongPolicy,
    }),
    false,
  );
});
