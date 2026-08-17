import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { parseIndependentReviewJsonBytes } from "../lib/independent-model-review.mjs";

const FORMULA_PATH = join(
  homedir(),
  "Library/Caches/Homebrew/api/formula/postgresql@17.json",
);
const BOTTLE_PATH = join(
  homedir(),
  "Library/Caches/Homebrew/downloads/88180e301b4588d4bfad742a382230b8e77d994e25606227bf6524028230cc5d--postgresql@17--17.10.arm64_tahoe.bottle.tar.gz",
);
const BINARY_PATH =
  "/opt/homebrew/Cellar/postgresql@17/17.10/bin/postgres";

export const POSTGRESQL_17_10_BINDINGS = Object.freeze({
  formulaSnapshot: Object.freeze({
    byteLength: 6360,
    sha256:
      "sha256:1c83838dd97105b99fdbb0ece2ea0a155efae237bb91c13a5d1ceb95292932b9",
    stableVersion: "17.10",
    sourceUrl:
      "https://ftp.postgresql.org/pub/source/v17.10/postgresql-17.10.tar.bz2",
    sourceSha256:
      "sha256:078a03516dcdbdb705fecaf415ea3d13a956c589e46f09fed68a06fb00598c90",
    bottleUrl:
      "https://ghcr.io/v2/homebrew/core/postgresql/17/blobs/sha256:a98e3797d28b5e1d95a0d60e542e529789ed35812d780260eb722206fbda06a8",
    bottleSha256:
      "sha256:a98e3797d28b5e1d95a0d60e542e529789ed35812d780260eb722206fbda06a8",
    name: "postgresql@17",
    fullName: "postgresql@17",
    tap: "homebrew/core",
    license: "PostgreSQL",
    revision: 0,
    versionScheme: 0,
    sourceTag: null,
    sourceRevision: null,
    sourceUsing: null,
    bottleRootUrl: "https://ghcr.io/v2/homebrew/core",
    bottleRebuild: 0,
    bottleCellar: "/opt/homebrew/Cellar",
  }),
  bottle: Object.freeze({
    byteLength: 19977384,
    sha256:
      "sha256:a98e3797d28b5e1d95a0d60e542e529789ed35812d780260eb722206fbda06a8",
  }),
  binary: Object.freeze({
    byteLength: 8793120,
    sha256:
      "sha256:88cc6ac80ecea2fbcebb9b5adef29e7214ccb6301633f677279677a7c15f35d9",
  }),
  versionOutput: "postgres (PostgreSQL) 17.10 (Homebrew)",
});

function captureMismatch() {
  const error = new TypeError(
    "The local PostgreSQL 17.10 capture input does not match the frozen binding.",
  );
  error.code = "POSTGRESQL_17_10_CAPTURE_INPUT_MISMATCH";
  return error;
}

const sha256 = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

async function readStableRegularFile(path) {
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink()) {
    throw captureMismatch();
  }
  const bytes = await readFile(path);
  const after = await stat(path);
  if (
    !after.isFile() ||
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeMs !== after.mtimeMs ||
    bytes.byteLength !== after.size
  ) {
    throw captureMismatch();
  }
  return bytes;
}

export function buildPostgresqlDistributionLock(input) {
  if (!isDeepStrictEqual(input, POSTGRESQL_17_10_BINDINGS)) {
    throw captureMismatch();
  }
  return {
    schemaVersion: "c07-postgresql-distribution-lock.v1",
    referenceId: "R12.POSTGRESQL_RLS",
    component: "PostgreSQL Row Security",
    version: "17.10",
    phase: "P1_SYNTHETIC_ONLY",
    dataClassification: "SYNTHETIC_ONLY",
    productionVerificationStatus: "NOT_VERIFIED",
    p3VerificationStatus: "NOT_VERIFIED",
    distribution: {
      futureReceiptAdoptedArtifactDigest:
        input.formulaSnapshot.sourceSha256,
      upstreamSourceArchive: {
        artifactType: "OFFICIAL_UPSTREAM_SOURCE_ARCHIVE",
        url: input.formulaSnapshot.sourceUrl,
        sha256: input.formulaSnapshot.sourceSha256,
      },
      homebrewFormulaSnapshot: {
        artifactType: "LOCAL_METADATA_SNAPSHOT",
        logicalPath: "homebrew-api/formula/postgresql@17.json",
        byteLength: input.formulaSnapshot.byteLength,
        sha256: input.formulaSnapshot.sha256,
        tap: input.formulaSnapshot.tap,
        license: input.formulaSnapshot.license,
        formulaName: input.formulaSnapshot.name,
        formulaFullName: input.formulaSnapshot.fullName,
        revision: input.formulaSnapshot.revision,
        versionScheme: input.formulaSnapshot.versionScheme,
      },
      homebrewBottle: {
        artifactType: "LOCAL_BUILD_DISTRIBUTION",
        platform: "arm64_tahoe",
        logicalPath:
          "homebrew-cache/postgresql@17--17.10.arm64_tahoe.bottle.tar.gz",
        url: input.formulaSnapshot.bottleUrl,
        byteLength: input.bottle.byteLength,
        sha256: input.bottle.sha256,
      },
    },
    localCapture: {
      installedExecutable: {
        artifactType: "LOCAL_INSTALLED_EXECUTABLE",
        logicalPath:
          "homebrew-cellar/postgresql@17/17.10/bin/postgres",
        byteLength: input.binary.byteLength,
        sha256: input.binary.sha256,
      },
      versionObservation: {
        command: "postgres --version",
        stdout: input.versionOutput,
        stderr: "",
        exitCode: 0,
      },
    },
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    productionAdoptionClaim: false,
  };
}

export async function capturePostgresqlDistributionLock() {
  let formulaBytes;
  let bottleBytes;
  let binaryBytes;
  try {
    [formulaBytes, bottleBytes, binaryBytes] = await Promise.all([
      readStableRegularFile(FORMULA_PATH),
      readStableRegularFile(BOTTLE_PATH),
      readStableRegularFile(BINARY_PATH),
    ]);
  } catch {
    throw captureMismatch();
  }
  let formula;
  try {
    formula = parseIndependentReviewJsonBytes(
      formulaBytes,
      "PostgreSQL Homebrew formula snapshot",
      64 * 1024,
    );
  } catch {
    throw captureMismatch();
  }
  const bottle = formula?.bottle?.stable?.files?.arm64_tahoe;
  const stable = formula?.urls?.stable;
  const version = spawnSync(BINARY_PATH, ["--version"], {
    encoding: "utf8",
    env: { LANG: "C", LC_ALL: "C" },
    timeout: 5000,
    maxBuffer: 4096,
    shell: false,
  });
  if (
    version.error ||
    version.signal !== null ||
    version.status !== 0 ||
    version.stderr !== "" ||
    version.stdout !== `${POSTGRESQL_17_10_BINDINGS.versionOutput}\n`
  ) {
    throw captureMismatch();
  }
  return buildPostgresqlDistributionLock({
    formulaSnapshot: {
      byteLength: formulaBytes.byteLength,
      sha256: sha256(formulaBytes),
      stableVersion: formula?.versions?.stable,
      sourceUrl: stable?.url,
      sourceSha256: `sha256:${stable?.checksum}`,
      bottleUrl: bottle?.url,
      bottleSha256: `sha256:${bottle?.sha256}`,
      name: formula?.name,
      fullName: formula?.full_name,
      tap: formula?.tap,
      license: formula?.license,
      revision: formula?.revision,
      versionScheme: formula?.version_scheme,
      sourceTag: stable?.tag,
      sourceRevision: stable?.revision,
      sourceUsing: stable?.using,
      bottleRootUrl: formula?.bottle?.stable?.root_url,
      bottleRebuild: formula?.bottle?.stable?.rebuild,
      bottleCellar: bottle?.cellar,
    },
    bottle: {
      byteLength: bottleBytes.byteLength,
      sha256: sha256(bottleBytes),
    },
    binary: {
      byteLength: binaryBytes.byteLength,
      sha256: sha256(binaryBytes),
    },
    versionOutput: version.stdout.trimEnd(),
  });
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  try {
    const lock = await capturePostgresqlDistributionLock();
    process.stdout.write(`${JSON.stringify(lock, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(
      `${error?.code ?? "POSTGRESQL_17_10_CAPTURE_INPUT_MISMATCH"}\n`,
    );
    process.exitCode = 4;
  }
}
