import { readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const REQUIRED_SERVER_MARKERS = Object.freeze({
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
});
const FORBIDDEN_SERVER_MARKERS = Object.freeze({
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
});

export function verifyP2WorkerRuntimeBundleContents({
  serverJavaScript,
  serverJavaScriptFiles = [
    {
      path: "dist/server/index.js",
      contents: serverJavaScript,
    },
  ],
  clientJavaScriptFiles,
}) {
  if (typeof serverJavaScript !== "string") {
    throw new Error("SERVER_BUNDLE_UNAVAILABLE");
  }
  if (
    !Array.isArray(serverJavaScriptFiles) ||
    serverJavaScriptFiles.length === 0
  ) {
    throw new Error("SERVER_BUNDLE_UNAVAILABLE");
  }
  if (!Array.isArray(clientJavaScriptFiles)) {
    throw new Error("CLIENT_BUNDLE_UNAVAILABLE");
  }
  if (clientJavaScriptFiles.length === 0) {
    throw new Error("CLIENT_JAVASCRIPT_EMPTY");
  }
  for (const [name, marker] of Object.entries(REQUIRED_SERVER_MARKERS)) {
    if (!serverJavaScript.includes(marker)) {
      throw new Error(`SERVER_REQUIRED_MARKER_MISSING:${name}`);
    }
  }
  for (const file of serverJavaScriptFiles) {
    if (
      !file ||
      typeof file.path !== "string" ||
      typeof file.contents !== "string"
    ) {
      throw new Error("SERVER_BUNDLE_UNAVAILABLE");
    }
    for (const [name, marker] of Object.entries(
      FORBIDDEN_SERVER_MARKERS,
    )) {
      if (file.contents.includes(marker)) {
        throw new Error(`SERVER_FORBIDDEN_RUNTIME_MARKER:${name}`);
      }
    }
  }
  for (const file of clientJavaScriptFiles) {
    if (
      !file ||
      typeof file.path !== "string" ||
      typeof file.contents !== "string"
    ) {
      throw new Error("CLIENT_BUNDLE_UNAVAILABLE");
    }
    for (const [name, marker] of Object.entries(REQUIRED_SERVER_MARKERS)) {
      if (file.contents.includes(marker)) {
        throw new Error(`CLIENT_EVIDENCE_LEAK:${name}:${file.path}`);
      }
    }
  }

  return {
    schemaVersion: "p2-worker-runtime-bundle-verification.v1",
    status: "PASS",
    serverMarkerCount: Object.keys(REQUIRED_SERVER_MARKERS).length,
    clientJavaScriptFileCount: clientJavaScriptFiles.length,
    forbiddenRuntimeMarkerCount: 0,
  };
}

async function collectJavaScript(
  directory,
  repositoryRoot,
  unavailableCode,
) {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch {
    throw new Error(unavailableCode);
  }
  const files = [];
  for (const entry of entries.sort((left, right) =>
    left.name.localeCompare(right.name),
  )) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(
        ...(await collectJavaScript(
          path,
          repositoryRoot,
          unavailableCode,
        )),
      );
    } else if (
      entry.isFile() &&
      /\.(?:cjs|js|mjs)$/u.test(entry.name)
    ) {
      let contents;
      try {
        contents = await readFile(path, "utf8");
      } catch {
        throw new Error(unavailableCode);
      }
      files.push({
        path: relative(repositoryRoot, path),
        contents,
      });
    }
  }
  return files;
}

export async function verifyP2WorkerRuntimeBundle({
  repositoryRoot = process.cwd(),
} = {}) {
  const root = resolve(repositoryRoot);
  const [serverJavaScriptFiles, clientJavaScriptFiles] = await Promise.all([
    collectJavaScript(
      join(root, "dist/server"),
      root,
      "SERVER_BUNDLE_UNAVAILABLE",
    ),
    collectJavaScript(
      join(root, "dist/client"),
      root,
      "CLIENT_BUNDLE_UNAVAILABLE",
    ),
  ]);
  const serverEntry = serverJavaScriptFiles.find(
    ({ path }) => path === "dist/server/index.js",
  );
  if (!serverEntry) throw new Error("SERVER_BUNDLE_UNAVAILABLE");
  return verifyP2WorkerRuntimeBundleContents({
    serverJavaScript: serverEntry.contents,
    serverJavaScriptFiles,
    clientJavaScriptFiles,
  });
}

async function runCli() {
  try {
    console.log(
      JSON.stringify(await verifyP2WorkerRuntimeBundle()),
    );
  } catch (error) {
    console.error(
      JSON.stringify({
        schemaVersion: "p2-worker-runtime-bundle-verification.v1",
        status: "FAIL",
        reasonCode:
          error instanceof Error
            ? error.message
            : "BUNDLE_VERIFICATION_FAILED",
      }),
    );
    process.exitCode = 1;
  }
}

if (
  process.argv[1] &&
  pathToFileURL(resolve(process.argv[1])).href === import.meta.url
) {
  await runCli();
}
