#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  captureIndependentReviewRuntimeDependencyManifest,
  serializeIndependentReviewRuntimeDependencyManifest,
} from "../lib/independent-review-runtime-manifest.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);
const outputPath =
  "implementation/governance/independent-review/kimi-runtime-manifest.v1.json";

export async function buildIndependentReviewRuntimeManifest({
  sourceRoot = root,
  destination = resolve(root, outputPath),
} = {}) {
  const manifest = await captureIndependentReviewRuntimeDependencyManifest({
    sourceRoot,
    dependencyRoot: resolve(sourceRoot, "node_modules"),
    requiredExecArgv: process.execArgv,
  });
  const bytes =
    serializeIndependentReviewRuntimeDependencyManifest(manifest);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, bytes, { mode: 0o644 });
  return { manifest, bytes, destination };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  buildIndependentReviewRuntimeManifest()
    .then(({ manifest }) => {
      process.stdout.write(
        `${JSON.stringify({
          ok: true,
          path: outputPath,
          manifestSha256: manifest.manifestSha256,
        })}\n`,
      );
    })
    .catch((error) => {
      process.stdout.write(
        `${JSON.stringify({
          ok: false,
          reasonCodes: [
            error?.reasonCodes?.[0] ??
              "INDEPENDENT_REVIEW_RUNTIME_CLOSURE_NOT_PROVED",
          ],
        })}\n`,
      );
      process.exitCode = 2;
    });
}
