import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readdir,
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
  attestationId: "p2eba_bc718bc1a069_36cfdf3f36d5",
  canonicalPin:
    "sha256:83f63243386d179cf3facc59e24eb7bcbcfb7e7960f42d8d38c7d83aef787220",
  sourceCommit: "bc718bc1a069deaa388b9a00e0135c8e9427dd91",
  executionBaselineDigest:
    "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec",
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
const GOVERNANCE_READINESS_SERVER_MARKERS = [
  "P2_PROFILE_READINESS_NOT_PROVED",
  "P2_WORK_PACKAGE_START_READINESS_NOT_PROVED",
  "P0-B04",
  "O02_SECRETS_SYSTEM",
  "O03_ADMISSION_CONTROLLER",
];

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

async function collectJavaScriptText(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const contents = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      contents.push(await collectJavaScriptText(path));
    } else if (
      entry.isFile() &&
      /\.(?:cjs|js|mjs)$/u.test(entry.name)
    ) {
      contents.push(await readFile(path, "utf8"));
    }
  }
  return contents.join("\n");
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
  assert.doesNotMatch(
    route,
    /P2_(?:LEGACY|PROFILE_V2)_WORKER_ATTESTATION_PIN_POLICY/u,
  );
  assert.match(
    route,
    /from "\.\.\/\.\.\/\.\.\/lib\/p2-governance-readiness\.mjs";/,
  );
  assert.match(
    compositionRoot,
    /verifyP2ProfileReadiness:\s*verifyP2ProfileReadinessFromFrozenEvidence/,
  );
  assert.match(
    compositionRoot,
    /verifyP2WorkPackageStartReadiness:\s*verifyP2WorkPackageStartReadinessFromFrozenProfile/,
  );
  assert.match(
    compositionRoot,
    /p2ProfileReadinessPolicy:\s*P2_V2_CANDIDATE_PROFILE_READINESS_POLICY/,
  );
  assert.match(
    route,
    /reference-candidate-catalog\.v1\.json/,
  );
  assert.match(
    route,
    /reference-review-policy\.v1\.json/,
  );
  assert.match(
    route,
    /createReferenceReviewReadinessVerifier/,
  );
  assert.match(
    compositionRoot,
    /verifyReferenceReviewReadiness/,
  );
  assert.match(
    compositionRoot,
    /referenceReviewPolicy/,
  );
});

test("Project Control does not reverse-import the Worker verifier", async () => {
  const projectControl = await source(PROJECT_CONTROL_URL);

  assert.doesNotMatch(
    projectControl,
    /p2-worker-attestation-verifier/,
  );
  assert.doesNotMatch(projectControl, /p2-governance-readiness/);
  assert.doesNotMatch(projectControl, /reference-review-readiness/);
});

test("snapshot does not call any P2 verifier or append to the journal", async () => {
  const { counts, journal } = countedJournal();
  const verifierCalls = {
    executionBaseline: 0,
    profileReadiness: 0,
    referenceReview: 0,
    startReadiness: 0,
  };
  const control = createProjectControl({
    manifest,
    journal,
    verifyP2ExecutionBaseline: async () => {
      verifierCalls.executionBaseline += 1;
      return true;
    },
    verifyP2ProfileReadiness: async () => {
      verifierCalls.profileReadiness += 1;
      return true;
    },
    verifyP2WorkPackageStartReadiness: async () => {
      verifierCalls.startReadiness += 1;
      return true;
    },
    verifyReferenceReviewReadiness: async () => {
      verifierCalls.referenceReview += 1;
      return true;
    },
    referenceReviewPolicy: {
      schemaVersion: "reference-review-policy.v1",
    },
  });

  const snapshot = await control.snapshot();
  const o02 = snapshot.workPackages.find(({ id }) => id === "O02");
  const o03 = snapshot.workPackages.find(({ id }) => id === "O03");

  assert.deepEqual(verifierCalls, {
    executionBaseline: 0,
    profileReadiness: 0,
    referenceReview: 0,
    startReadiness: 0,
  });
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

test("a work-package start fails closed when Reference policy is missing", async () => {
  const { counts, journal } = countedJournal();
  const verifierCalls = {
    executionBaseline: 0,
    profileReadiness: 0,
    referenceReview: 0,
    startReadiness: 0,
  };
  const control = createProjectControl({
    manifest,
    journal,
    verifyP2ExecutionBaseline: async () => {
      verifierCalls.executionBaseline += 1;
      return true;
    },
    verifyP2ProfileReadiness: async () => {
      verifierCalls.profileReadiness += 1;
      return true;
    },
    verifyP2WorkPackageStartReadiness: async () => {
      verifierCalls.startReadiness += 1;
      return true;
    },
    verifyReferenceReviewReadiness: async () => {
      verifierCalls.referenceReview += 1;
      return false;
    },
  });

  await assert.rejects(
    control.execute(
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
        idempotencyKey: "p2-runtime-wiring-reference-start",
      },
    ),
    (error) => error.code === "REFERENCE_REVIEW_NOT_PROVED",
  );

  assert.deepEqual(verifierCalls, {
    executionBaseline: 0,
    profileReadiness: 0,
    referenceReview: 0,
    startReadiness: 0,
  });
  assert.equal(counts.append, 0);
});

test("a non-boundary work-package record does not call the Reference verifier", async () => {
  const { counts, journal } = countedJournal();
  let referenceCalls = 0;
  const control = createProjectControl({
    manifest,
    journal,
    referenceReviewPolicy: {
      schemaVersion: "reference-review-policy.v1",
    },
    verifyReferenceReviewReadiness: async () => {
      referenceCalls += 1;
      return false;
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
      implementationStatus: "NOT_STARTED",
      verificationStatus: "NOT_VERIFIED",
      evidenceRefs: [],
      evidenceHashes: [],
      note: "No lifecycle boundary crossed.",
      expectedRevision: 0,
      idempotencyKey: "reference-review-non-boundary-record",
    },
  );

  assert.equal(referenceCalls, 0);
  assert.equal(counts.append, 1);
});

test("VERIFIED fails closed before append when implementation conformance is not proved", async () => {
  const memory = createMemoryJournal([
    {
      id: "f01-in-progress",
      type: "WORK_PACKAGE_RECORDED",
      actorId: "external_product_owner",
      createdAt: "2026-07-29T01:00:00.000Z",
      payload: {
        workPackageId: "F01",
        implementationStatus: "IN_PROGRESS",
        verificationStatus: "NOT_VERIFIED",
        evidenceRefs: [],
        evidenceHashes: [],
        note: "Synthetic start.",
      },
    },
  ]);
  let appendCalls = 0;
  const bindings = [];
  const control = createProjectControl({
    manifest,
    journal: {
      load: (...arguments_) => memory.load(...arguments_),
      append: (...arguments_) => {
        appendCalls += 1;
        return memory.append(...arguments_);
      },
    },
    verifyFrozenEvidence: async () => true,
    referenceReviewPolicy: {
      schemaVersion: "reference-review-policy.v1",
    },
    verifyReferenceReviewReadiness: async (binding) => {
      bindings.push(binding);
      return false;
    },
  });

  await assert.rejects(
    control.execute(
      {
        actorId: "external_product_owner",
        roles: ["PRODUCT_OWNER"],
      },
      {
        kind: "RECORD_WORK_PACKAGE",
        workPackageId: "F01",
        implementationStatus: "IMPLEMENTED",
        verificationStatus: "VERIFIED",
        evidenceRefs: ["synthetic/f01-verification.json"],
        evidenceHashes: [`sha256:${"1".repeat(64)}`],
        note: "Must prove implementation conformance.",
        expectedRevision: 1,
        idempotencyKey: "reference-review-conformance-denied",
      },
    ),
    (error) => error.code === "REFERENCE_REVIEW_NOT_PROVED",
  );

  assert.equal(appendCalls, 0);
  assert.equal((await control.snapshot()).revision, 1);
  assert.deepEqual(
    bindings.map(({ boundary, workPackageId }) => ({
      boundary,
      workPackageId,
    })),
    [
      {
        boundary: "IMPLEMENTATION_CONFORMANCE",
        workPackageId: "F01",
      },
    ],
  );
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
    /payload\.(?:referenceReviewReceipt|referenceReviewReady|referenceReviewPolicy)/i,
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

test("the real Worker bundle keeps Profile and start readiness evidence server-only", async () => {
  const [serverJavaScript, clientJavaScript] = await Promise.all([
    collectJavaScriptText(join(REPOSITORY_ROOT, "dist/server")),
    collectJavaScriptText(join(REPOSITORY_ROOT, "dist/client")),
  ]);

  for (const marker of GOVERNANCE_READINESS_SERVER_MARKERS) {
    assert.equal(serverJavaScript.includes(marker), true, marker);
    assert.equal(clientJavaScript.includes(marker), false, marker);
  }
});

test("the real Worker bundle keeps Reference Review policy and verifier server-only", async () => {
  const [serverJavaScript, clientJavaScript] = await Promise.all([
    collectJavaScriptText(join(REPOSITORY_ROOT, "dist/server")),
    collectJavaScriptText(join(REPOSITORY_ROOT, "dist/client")),
  ]);
  const markers = [
    "reference-candidate-catalog.v1",
    "reference-review-policy.v1",
    "REFERENCE_REVIEW_NOT_PROVED",
  ];

  for (const marker of markers) {
    assert.equal(serverJavaScript.includes(marker), true, marker);
    assert.equal(clientJavaScript.includes(marker), false, marker);
  }
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
