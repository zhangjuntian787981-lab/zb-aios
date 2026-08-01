#!/usr/bin/env node

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  captureIndependentReviewRuntimeDependencyManifest,
  captureKimiK3IndependentReviewRuntimeDependencyManifest,
  captureKimiK3IndependentReviewRuntimeDependencyManifestV3,
  captureKimiK3IndependentReviewRuntimeDependencyManifestV4,
  serializeIndependentReviewRuntimeDependencyManifest,
} from "../lib/independent-review-runtime-manifest.mjs";

const root = resolve(new URL("../", import.meta.url).pathname);
const OUTPUT_PATHS = Object.freeze({
  K2_V1:
    "implementation/governance/independent-review/kimi-runtime-manifest.v1.json",
  K3_V2:
    "implementation/governance/independent-review/kimi-runtime-manifest.v2.json",
  K3_V3:
    "implementation/governance/independent-review/kimi-runtime-manifest.v3.json",
  K3_V4:
    "implementation/governance/independent-review/kimi-runtime-manifest.v4.json",
});

export function runtimeManifestBuildContractFromArguments(values) {
  if (values.length === 0) return "K2_V1";
  if (
    values.length === 2 &&
    values[0] === "--contract" &&
    ["K3_V2", "K3_V3", "K3_V4"].includes(values[1])
  ) {
    return values[1];
  }
  throw new TypeError(
    "INDEPENDENT_REVIEW_RUNTIME_MANIFEST_ARGUMENTS_INVALID",
  );
}

export async function buildIndependentReviewRuntimeManifest({
  contract = "K2_V1",
  sourceRoot = root,
  destination,
} = {}) {
  const outputPath = OUTPUT_PATHS[contract];
  if (!outputPath) {
    throw new TypeError(
      "INDEPENDENT_REVIEW_RUNTIME_MANIFEST_ARGUMENTS_INVALID",
    );
  }
  const exactDestination = destination ?? resolve(root, outputPath);
  const capture = {
    K2_V1: captureIndependentReviewRuntimeDependencyManifest,
    K3_V2: captureKimiK3IndependentReviewRuntimeDependencyManifest,
    K3_V3: captureKimiK3IndependentReviewRuntimeDependencyManifestV3,
    K3_V4: captureKimiK3IndependentReviewRuntimeDependencyManifestV4,
  }[contract];
  const manifest = await capture({
    sourceRoot,
    dependencyRoot: resolve(sourceRoot, "node_modules"),
    requiredExecArgv: process.execArgv,
  });
  const bytes =
    serializeIndependentReviewRuntimeDependencyManifest(manifest);
  await mkdir(dirname(exactDestination), { recursive: true });
  await writeFile(exactDestination, bytes, { mode: 0o644 });
  return {
    manifest,
    bytes,
    destination: exactDestination,
    outputPath,
  };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  let contract;
  try {
    contract = runtimeManifestBuildContractFromArguments(
      process.argv.slice(2),
    );
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({
        ok: false,
        reasonCodes: [error.message],
      })}\n`,
    );
    process.exitCode = 2;
  }
  if (contract) buildIndependentReviewRuntimeManifest({ contract })
    .then(({ manifest, outputPath }) => {
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
