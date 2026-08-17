import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { parseIndependentReviewJsonBytes } from "../lib/independent-model-review.mjs";
import { sha256ProjectValue } from "../lib/project-control.mjs";

const PREPARATION_PATH =
  "implementation/governance/reference-review/p2-profile-backfill-preparation.v1.json";
const RESEARCH_PATH =
  "implementation/governance/reference-review/p2-profile-backfill-official-research.v1.md";
const ADR_PATH = "docs/adr/0009-p1-reference-backfill-preparation.md";
const POSTGRESQL_DISTRIBUTION_LOCK_PATH =
  "implementation/p1/c07/postgresql/postgresql-distribution.lock.json";
const RETROSPECTIVE_SCAN_ADR_PATH =
  "docs/adr/0025-reference-review-retrospective-scan-freeze-separation.md";
const FORMAL_DECISION_ADR_PATH =
  "docs/adr/0026-p1-reference-backfill-formal-decisions.md";
const FORMAL_POLICY_PATH =
  "implementation/governance/reference-review/reference-review-policy.profile-v2.v1.json";
const FINAL_PROFILE_SHA256 =
  "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5";
const EXECUTION_BASELINE_DIGEST =
  "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec";
const FORMAL_BACKFILL = Object.freeze([
  {
    workPackageId: "C04",
    candidateReferenceIds: ["R09.KEYCLOAK"],
    sourceRoots: ["lib/keycloak-scim-provisioning-adapter.mjs"],
    reportPath:
      "implementation/governance/reference-review/p2-profile-backfill/c04/applicability-evidence.v2.json",
    integrations: [
      {
        referenceName: "Keycloak",
        officialSourceUri: "https://github.com/keycloak/keycloak",
        integrationKind: "API_CLIENT",
        sourcePath: "lib/keycloak-scim-provisioning-adapter.mjs",
        sourceCommitSha256:
          "sha256:aa35e65310130d69337ef4de503803831cc73cd94ad5305b517c21e516fa3d15",
        implementationEvidenceRef:
          "implementation/p1/c04/c04-verification-evidence.v1.json",
        implementationEvidenceSha256:
          "sha256:554df39362987342eaab88b5146b04a70bc3db8b566a81c6af5b1866816063de",
      },
    ],
    dependencies: [
      {
        packageName: "Keycloak",
        resolvedUri: "https://github.com/keycloak/keycloak",
        version: "26.7.0",
        artifactDigest:
          "sha256:f771df0aa1e4820f57d56f7d6d015beb6415487b43f8de7e5a6d48f8a7fe118a",
        toolLockDomain: null,
      },
    ],
  },
  {
    workPackageId: "C06",
    candidateReferenceIds: ["R11.OPENFGA"],
    sourceRoots: ["lib/openfga-pdp.mjs"],
    reportPath:
      "implementation/governance/reference-review/p2-profile-backfill/c06/applicability-evidence.v2.json",
    integrations: [
      {
        referenceName: "OpenFGA",
        officialSourceUri: "https://github.com/openfga/openfga",
        integrationKind: "API_CLIENT",
        sourcePath: "lib/openfga-pdp.mjs",
        sourceCommitSha256:
          "sha256:b9fed3071e397ad9e2a745300b42084b31493caee896652b4319c15db80ed37c",
        implementationEvidenceRef:
          "implementation/p1/c06/c06-verification-evidence.v1.json",
        implementationEvidenceSha256:
          "sha256:1d1b8c57e2ebc4507c2408e397f9d818eae67e18b022f067840ce328e71c2682",
      },
    ],
    dependencies: [
      {
        packageName: "OpenFGA",
        resolvedUri: "https://github.com/openfga/openfga",
        version: "v1.18.1",
        artifactDigest:
          "sha256:d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94",
        toolLockDomain: null,
      },
    ],
  },
  {
    workPackageId: "C07",
    candidateReferenceIds: [
      "R12.PGVECTOR",
      "R12.POSTGRESQL_RLS",
    ],
    sourceRoots: [
      "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
      "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    ],
    reportPath:
      "implementation/governance/reference-review/p2-profile-backfill/c07/applicability-evidence.v2.json",
    integrations: [
      {
        referenceName: "PostgreSQL Row Security",
        officialSourceUri:
          "https://git.postgresql.org/gitweb/?p=postgresql.git",
        integrationKind: "IMPORT",
        sourcePath:
          "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
        sourceCommitSha256:
          "sha256:3ec52cc75571e863ffa01e6dddb256c174652375138cb1622baef798fbbfd41c",
        implementationEvidenceRef:
          "implementation/p1/c07/c07-verification-evidence.v1.json",
        implementationEvidenceSha256:
          "sha256:0d9b53b93966859a91fc3f7a8cf73d0ded84d3760cd5d46c3d3696e4424ceeb3",
      },
      {
        referenceName: "pgvector",
        officialSourceUri: "https://github.com/pgvector/pgvector",
        integrationKind: "IMPORT",
        sourcePath:
          "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
        sourceCommitSha256:
          "sha256:06350029d5d99dd0b57681cd0c19ecfce87a4da7c61a74911ea2837c983e1f46",
        implementationEvidenceRef:
          "implementation/p1/c07/c07-verification-evidence.v1.json",
        implementationEvidenceSha256:
          "sha256:0d9b53b93966859a91fc3f7a8cf73d0ded84d3760cd5d46c3d3696e4424ceeb3",
      },
    ],
    dependencies: [
      {
        packageName: "PostgreSQL Row Security",
        resolvedUri:
          "https://git.postgresql.org/gitweb/?p=postgresql.git",
        version: "17.10",
        artifactDigest:
          "sha256:078a03516dcdbdb705fecaf415ea3d13a956c589e46f09fed68a06fb00598c90",
        toolLockDomain: null,
      },
      {
        packageName: "pgvector",
        resolvedUri: "https://github.com/pgvector/pgvector",
        version: "0.8.5",
        artifactDigest:
          "sha256:6f88a5cbdde31666f4b6c1a6b75c51dcbeffe58f9a7d2b26e502d5a6e5e14d44",
        toolLockDomain: null,
      },
    ],
  },
]);
const PROFILE_SOURCE_COMMIT =
  "bc718bc1a069deaa388b9a00e0135c8e9427dd91";
const PROFILE_SOURCE_TREE =
  "2fa1d5a511215a78ce324b61c585a4d4bb9697e0";
const INSPECTED_SOURCE_COMMIT =
  "817ab47674dd7a312aeaf386063acdec559a7fa1";
const INSPECTED_SOURCE_TREE =
  "141bd74abf86b7c16b08062f1ef10a49b010f6b0";

const sha256 = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

const readText = (path) =>
  readFile(new URL(`../${path}`, import.meta.url), "utf8");

const readJson = async (path) => JSON.parse(await readText(path));

const gitShow = (commit, path) =>
  execFileSync("/usr/bin/git", ["show", `${commit}:${path}`]);

const gitTree = (commit) =>
  execFileSync("/usr/bin/git", ["rev-parse", `${commit}^{tree}`], {
    encoding: "utf8",
  }).trim();

const withoutSelfHash = (value) => {
  const copy = structuredClone(value);
  delete copy.preparationSha256;
  return copy;
};

const withoutReportHash = (value) => {
  const copy = structuredClone(value);
  delete copy.reportSha256;
  return copy;
};

const assertCanonicalRepositoryPath = (path) => {
  assert.equal(typeof path, "string");
  assert.equal(path.startsWith("/"), false, path);
  assert.equal(path.includes("\\"), false, path);
  assert.equal(/[\u0000-\u001f\u007f]/u.test(path), false, path);
  assert.equal(
    path.split("/").some((segment) =>
      ["", ".", ".."].includes(segment),
    ),
    false,
    path,
  );
};

const assertCanonicalPaths = (value, key = null) => {
  if (Array.isArray(value)) {
    if (["evidenceRefs", "inputRefs", "sourceRoots", "sourceExclusions"].includes(key)) {
      value.forEach(assertCanonicalRepositoryPath);
      return;
    }
    value.forEach((entry) => assertCanonicalPaths(entry));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [entryKey, entryValue] of Object.entries(value)) {
    if (
      typeof entryValue === "string" &&
      [
        "adrRef",
        "bundlePath",
        "contentEvidenceRef",
        "evidenceRef",
        "implementationEvidenceRef",
        "notesRef",
        "path",
        "policyPath",
        "sourcePath",
      ].includes(entryKey)
    ) {
      assertCanonicalRepositoryPath(entryValue);
    } else {
      assertCanonicalPaths(entryValue, entryKey);
    }
  }
};

test("Profile backfill preparation fixes the exact retrospective reference set", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const retrospectiveScanAdr = await readText(
    RETROSPECTIVE_SCAN_ADR_PATH,
  );
  const formalDecisionAdr = await readText(FORMAL_DECISION_ADR_PATH);
  const formalPolicy = await readJson(FORMAL_POLICY_PATH);

  const formalJsonPaths = [FORMAL_POLICY_PATH];
  for (const { reportPath } of FORMAL_BACKFILL) {
    const basePath = reportPath.replace(
      /\/applicability-evidence\.v2\.json$/u,
      "",
    );
    for (const name of await readdir(
      new URL(`../${basePath}`, import.meta.url),
    )) {
      if (name === "reference-review-freeze-attestation.v1.json") {
        continue;
      }
      formalJsonPaths.push(`${basePath}/${name}`);
    }
  }
  assert.equal(formalJsonPaths.length, 36);
  for (const path of formalJsonPaths.sort()) {
    const raw = new Uint8Array(
      await readFile(new URL(`../${path}`, import.meta.url)),
    );
    const parsed = parseIndependentReviewJsonBytes(
      raw,
      `R1 Reference Review artifact ${path}`,
    );
    assert.deepEqual(
      parsed,
      JSON.parse(new TextDecoder().decode(raw)),
    );
    assertCanonicalPaths(parsed);
  }
  const duplicateRootKey = new TextEncoder().encode(
    `${JSON.stringify({ schemaVersion: "duplicate" }).slice(0, -1)},${await readText(FORMAL_POLICY_PATH).then((value) => value.trimStart().slice(1))}`,
  );
  assert.throws(
    () =>
      parseIndependentReviewJsonBytes(
        duplicateRootKey,
        "R1 duplicate-key mutation",
      ),
    /duplicate/u,
  );

  assert.equal(
    preparation.schemaVersion,
    "p2-profile-reference-backfill-preparation.v1",
  );
  assert.equal(preparation.status, "GIT_FROZEN_INPUT_ONLY");
  assert.equal(preparation.reviewMode, "RETROSPECTIVE_BACKFILL");
  assert.equal(preparation.dataBoundary, "P1_SYNTHETIC_ONLY");
  assert.deepEqual(preparation.inspectedSource, {
    commit: INSPECTED_SOURCE_COMMIT,
    tree: INSPECTED_SOURCE_TREE,
  });
  assert.equal(gitTree(INSPECTED_SOURCE_COMMIT), INSPECTED_SOURCE_TREE);
  assert.equal(gitTree(PROFILE_SOURCE_COMMIT), PROFILE_SOURCE_TREE);

  const profileSourceAnchors = [
    {
      path: "lib/keycloak-scim-provisioning-adapter.mjs",
      mode: "100644",
      byteLength: 14358,
      sha256:
        "sha256:aa35e65310130d69337ef4de503803831cc73cd94ad5305b517c21e516fa3d15",
    },
    {
      path: "lib/openfga-pdp.mjs",
      mode: "100644",
      byteLength: 14409,
      sha256:
        "sha256:b9fed3071e397ad9e2a745300b42084b31493caee896652b4319c15db80ed37c",
    },
    {
      path: "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
      mode: "100644",
      byteLength: 12355,
      sha256:
        "sha256:06350029d5d99dd0b57681cd0c19ecfce87a4da7c61a74911ea2837c983e1f46",
    },
    {
      path: "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
      mode: "100644",
      byteLength: 5828,
      sha256:
        "sha256:3ec52cc75571e863ffa01e6dddb256c174652375138cb1622baef798fbbfd41c",
    },
  ];
  assert.ok(retrospectiveScanAdr.includes(PROFILE_SOURCE_COMMIT));
  assert.ok(retrospectiveScanAdr.includes(PROFILE_SOURCE_TREE));
  for (const anchor of profileSourceAnchors) {
    const bytes = gitShow(PROFILE_SOURCE_COMMIT, anchor.path);
    const treeEntry = execFileSync(
      "/usr/bin/git",
      ["ls-tree", "-l", PROFILE_SOURCE_COMMIT, "--", anchor.path],
      { encoding: "utf8" },
    ).trim();
    assert.match(
      treeEntry,
      new RegExp(
        `^${anchor.mode} blob [a-f0-9]{40} +${anchor.byteLength}\\t`,
      ),
    );
    assert.equal(bytes.byteLength, anchor.byteLength);
    assert.equal(sha256(bytes), anchor.sha256);
    assert.ok(retrospectiveScanAdr.includes(anchor.path));
    assert.ok(retrospectiveScanAdr.includes(anchor.sha256));
  }

  assert.deepEqual(
    preparation.references.map(
      ({ workPackageId, referenceId, decision }) => ({
        workPackageId,
        referenceId,
        decision,
      }),
    ),
    [
      {
        workPackageId: "C04",
        referenceId: "R09.KEYCLOAK",
        decision: "ADOPT",
      },
      {
        workPackageId: "C06",
        referenceId: "R11.OPENFGA",
        decision: "ADOPT",
      },
      {
        workPackageId: "C07",
        referenceId: "R12.PGVECTOR",
        decision: "ADOPT",
      },
      {
        workPackageId: "C07",
        referenceId: "R12.POSTGRESQL_RLS",
        decision: "ADOPT",
      },
    ],
  );

  assert.deepEqual(formalPolicy.profileBinding, {
    profileSha256: FINAL_PROFILE_SHA256,
    sourceCommit: PROFILE_SOURCE_COMMIT,
    executionBaselineDigest: EXECUTION_BASELINE_DIGEST,
    bindingStatus: "BOUND_IN_PROFILE_AND_EXECUTION_BASELINE",
    requiredBackfillWorkPackageIds: ["C04", "C06", "C07"],
  });
  assert.equal(formalPolicy.policyPath, FORMAL_POLICY_PATH);
  assert.equal(formalPolicy.governanceEffect, "NONE");
  assert.equal(formalPolicy.isProgressTracker, false);
  assert.equal(formalPolicy.selfAuthorizing, false);

  for (const expected of FORMAL_BACKFILL) {
    const workPackagePolicy = formalPolicy.workPackagePolicies.find(
      ({ workPackageId }) => workPackageId === expected.workPackageId,
    );
    assert.ok(workPackagePolicy, expected.workPackageId);
    assert.equal(workPackagePolicy.reviewMode, "RETROSPECTIVE_BACKFILL");
    assert.equal(workPackagePolicy.requiredBefore, "PROFILE_APPROVAL");
    assert.deepEqual(
      workPackagePolicy.applicableReferenceIds,
      expected.candidateReferenceIds,
    );
    assert.deepEqual(workPackagePolicy.applicabilityEvidence.sourceRoots, expected.sourceRoots);
    assert.deepEqual(workPackagePolicy.applicabilityEvidence.sourceExclusions, []);
    assert.equal(workPackagePolicy.applicabilityEvidence.status, "COMPLETE");
    assert.deepEqual(workPackagePolicy.applicabilityEvidence.evidenceRefs, [expected.reportPath]);
    assert.equal(workPackagePolicy.applicabilityEvidence.evidenceHashes.length, 1);

    const reportBytes = await readFile(
      new URL(`../${expected.reportPath}`, import.meta.url),
    );
    const report = JSON.parse(reportBytes);
    assert.equal(report.schemaVersion, "reference-applicability-evidence.v2");
    assert.equal(report.workPackageId, expected.workPackageId);
    assert.equal(report.sourceCommit, PROFILE_SOURCE_COMMIT);
    assert.deepEqual(report.candidateReferenceIds, expected.candidateReferenceIds);
    assert.equal(report.reportSha256, await sha256ProjectValue(withoutReportHash(report)));
    assert.equal(workPackagePolicy.applicabilityEvidence.evidenceHashes[0], sha256(reportBytes));
    assert.deepEqual(
      report.scans.map(({ scanKind, methodVersion, result }) => ({
        scanKind,
        methodVersion,
        result,
      })),
      [
        { scanKind: "DEPENDENCY_LOCK_SCAN", methodVersion: "v2", result: "COMPLETE" },
        { scanKind: "MANUAL_SUPPLEMENT", methodVersion: "v1", result: "COMPLETE" },
        { scanKind: "REFERENCE_MATRIX", methodVersion: "v1", result: "COMPLETE" },
        { scanKind: "SOURCE_INTEGRATION_SCAN", methodVersion: "v2", result: "COMPLETE" },
      ],
    );

    const basePath = expected.reportPath.replace(
      /\/applicability-evidence\.v2\.json$/u,
      "",
    );
    const sourceIndex = await readJson(
      `${basePath}/source-integration-index.v2.json`,
    );
    const dependencyLock = await readJson(
      `${basePath}/dependency-lock.v1.json`,
    );
    assert.deepEqual(sourceIndex.integrations, expected.integrations);
    assert.deepEqual(dependencyLock.dependencies, expected.dependencies);
    for (const integration of expected.integrations) {
      assert.equal(
        sha256(gitShow(PROFILE_SOURCE_COMMIT, integration.sourcePath)),
        integration.sourceCommitSha256,
      );
      const sourceEvidence = gitShow(
        PROFILE_SOURCE_COMMIT,
        integration.implementationEvidenceRef,
      );
      assert.equal(
        sha256(sourceEvidence),
        integration.implementationEvidenceSha256,
      );
      const parsedEvidence = JSON.parse(sourceEvidence);
      assert.equal(parsedEvidence.work_package_id, expected.workPackageId);
      execFileSync("/usr/bin/git", [
        "merge-base",
        "--is-ancestor",
        parsedEvidence.verified_source_commit,
        PROFILE_SOURCE_COMMIT,
      ]);
      assert.equal(
        parsedEvidence.artifacts.filter(
          ({ path, sha256: artifactSha256 }) =>
            path === integration.sourcePath &&
            artifactSha256 === integration.sourceCommitSha256,
        ).length,
        1,
      );
    }
  }

  for (const workPackageId of ["O02", "O03"]) {
    const prospective = formalPolicy.workPackagePolicies.find(
      (entry) => entry.workPackageId === workPackageId,
    );
    assert.equal(prospective.reviewMode, "PROSPECTIVE");
    assert.equal(prospective.applicabilityEvidence.status, "UNPROVED");
    assert.deepEqual(prospective.applicabilityEvidence.evidenceRefs, []);
    assert.deepEqual(prospective.applicabilityEvidence.evidenceHashes, []);
  }
  assert.ok(formalDecisionAdr.includes(PROFILE_SOURCE_COMMIT));
  assert.ok(formalDecisionAdr.includes(FINAL_PROFILE_SHA256));
  assert.ok(formalDecisionAdr.includes(EXECUTION_BASELINE_DIGEST));
  assert.match(formalDecisionAdr, /does not approve (?:the )?P2 Profile/iu);
  assert.match(formalDecisionAdr, /does not (?:append|write) D1/iu);
});

test("each proposed ADOPT is pinned to exact existing P1 bytes and remains non-production", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const byReference = new Map(
    preparation.references.map((reference) => [
      reference.referenceId,
      reference,
    ]),
  );

  const expected = {
    "R09.KEYCLOAK": {
      version: "26.7.0",
      artifactDigest:
        "sha256:f771df0aa1e4820f57d56f7d6d015beb6415487b43f8de7e5a6d48f8a7fe118a",
      evidencePath: "implementation/p1/c04/c04-verification-evidence.v1.json",
      evidenceFreezeCommit: "93772e891ab032ac6ea88bd6dec5847a2c748420",
      evidenceSha256:
        "sha256:554df39362987342eaab88b5146b04a70bc3db8b566a81c6af5b1866816063de",
    },
    "R11.OPENFGA": {
      version: "v1.18.1",
      artifactDigest:
        "sha256:d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94",
      evidencePath: "implementation/p1/c06/c06-verification-evidence.v3.json",
      evidenceFreezeCommit: "9aab0cb19d14848dfd837729dd7df07828043258",
      evidenceSha256:
        "sha256:b80fe8d28b8c4b2ea8caa33f6685af0ab1c00b7f127b736600cd5e82feef83de",
    },
    "R12.PGVECTOR": {
      version: "0.8.5",
      artifactDigest:
        "sha256:6f88a5cbdde31666f4b6c1a6b75c51dcbeffe58f9a7d2b26e502d5a6e5e14d44",
      evidencePath: "implementation/p1/c07/c07-verification-evidence.v1.json",
      evidenceFreezeCommit: "23d400e7b56512975ecc2d0f1189322414e75de3",
      evidenceSha256:
        "sha256:0d9b53b93966859a91fc3f7a8cf73d0ded84d3760cd5d46c3d3696e4424ceeb3",
    },
    "R12.POSTGRESQL_RLS": {
      version: "17.10",
      artifactDigest: null,
      evidencePath: "implementation/p1/c07/c07-verification-evidence.v1.json",
      evidenceFreezeCommit: "23d400e7b56512975ecc2d0f1189322414e75de3",
      evidenceSha256:
        "sha256:0d9b53b93966859a91fc3f7a8cf73d0ded84d3760cd5d46c3d3696e4424ceeb3",
    },
  };

  for (const [referenceId, binding] of Object.entries(expected)) {
    const reference = byReference.get(referenceId);
    assert.ok(reference, referenceId);
    assert.equal(reference.exactVersion.version, binding.version);
    assert.equal(
      reference.exactVersion.artifactDigest,
      binding.artifactDigest,
    );
    assert.equal(reference.verification.scope, "P1_SYNTHETIC_ONLY");
    assert.equal(reference.verification.productionStatus, "NOT_VERIFIED");
    assert.equal(reference.productionAdoptionClaim, false);
    assert.equal(reference.futureReceiptRequired, true);
    assert.equal(reference.verification.evidence.path, binding.evidencePath);
    assert.equal(
      reference.verification.evidence.freezeCommit,
      binding.evidenceFreezeCommit,
    );
    assert.equal(
      reference.verification.evidence.sha256,
      binding.evidenceSha256,
    );
    assert.equal(
      sha256(gitShow(binding.evidenceFreezeCommit, binding.evidencePath)),
      binding.evidenceSha256,
    );
    assert.ok(reference.adoptedScope.length > 0);
    assert.ok(reference.deferredProductionScope.length > 0);
  }

  const postgresqlPreparation = byReference.get(
    "R12.POSTGRESQL_RLS",
  );
  assert.equal(postgresqlPreparation.exactVersion.artifactDigest, null);

  const postgresqlLock = await readJson(
    POSTGRESQL_DISTRIBUTION_LOCK_PATH,
  );
  const capture = await import(
    "../scripts/capture-c07-postgresql-distribution-lock.mjs"
  );
  assert.deepEqual(
    capture.buildPostgresqlDistributionLock({
      formulaSnapshot: {
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
      },
      bottle: {
        byteLength: 19977384,
        sha256:
          "sha256:a98e3797d28b5e1d95a0d60e542e529789ed35812d780260eb722206fbda06a8",
      },
      binary: {
        byteLength: 8793120,
        sha256:
          "sha256:88cc6ac80ecea2fbcebb9b5adef29e7214ccb6301633f677279677a7c15f35d9",
      },
      versionOutput: "postgres (PostgreSQL) 17.10 (Homebrew)",
    }),
    postgresqlLock,
  );
  assert.deepEqual(Object.keys(postgresqlLock).sort(), [
    "component",
    "dataClassification",
    "distribution",
    "governanceEffect",
    "isProgressTracker",
    "localCapture",
    "p3VerificationStatus",
    "phase",
    "productionAdoptionClaim",
    "productionVerificationStatus",
    "referenceId",
    "schemaVersion",
    "selfAuthorizing",
    "version",
  ]);
  assert.equal(
    postgresqlLock.distribution.futureReceiptAdoptedArtifactDigest,
    "sha256:078a03516dcdbdb705fecaf415ea3d13a956c589e46f09fed68a06fb00598c90",
  );
  assert.equal(postgresqlLock.productionAdoptionClaim, false);
  assert.equal(postgresqlLock.governanceEffect, "NONE");
  assert.equal(
    JSON.stringify(postgresqlLock).includes("/Users/"),
    false,
  );
  assert.throws(() => {
    capture.POSTGRESQL_17_10_BINDINGS.formulaSnapshot.sourceSha256 =
      `sha256:${"0".repeat(64)}`;
  }, TypeError);
  assert.equal(
    capture.POSTGRESQL_17_10_BINDINGS.formulaSnapshot.sourceSha256,
    "sha256:078a03516dcdbdb705fecaf415ea3d13a956c589e46f09fed68a06fb00598c90",
  );

  const missingHome = await mkdtemp(
    `${tmpdir()}/postgresql-capture-missing-`,
  );
  try {
    const missingCapture = spawnSync(
      process.execPath,
      [
        fileURLToPath(
          new URL(
            "../scripts/capture-c07-postgresql-distribution-lock.mjs",
            import.meta.url,
          ),
        ),
      ],
      {
        encoding: "utf8",
        env: { ...process.env, HOME: missingHome },
      },
    );
    assert.equal(missingCapture.status, 4);
    assert.equal(missingCapture.stdout, "");
    assert.equal(
      missingCapture.stderr,
      "POSTGRESQL_17_10_CAPTURE_INPUT_MISMATCH\n",
    );
  } finally {
    await rm(missingHome, { recursive: true, force: true });
  }

  for (const measurement of [
    ["formulaSnapshot", "byteLength", 6359],
    ["formulaSnapshot", "sha256", `sha256:${"0".repeat(64)}`],
    ["formulaSnapshot", "stableVersion", "17.9"],
    ["formulaSnapshot", "sourceSha256", `sha256:${"0".repeat(64)}`],
    ["formulaSnapshot", "bottleCellar", "/usr/local/Cellar"],
    ["bottle", "byteLength", 19977383],
    ["bottle", "sha256", `sha256:${"0".repeat(64)}`],
    ["binary", "byteLength", 8793119],
    ["binary", "sha256", `sha256:${"0".repeat(64)}`],
    ["versionOutput", null, "postgres (PostgreSQL) 17.9 (Homebrew)"],
  ]) {
    const input = structuredClone(capture.POSTGRESQL_17_10_BINDINGS);
    if (measurement[1] === null) {
      input[measurement[0]] = measurement[2];
    } else {
      input[measurement[0]][measurement[1]] = measurement[2];
    }
    assert.throws(
      () => capture.buildPostgresqlDistributionLock(input),
      (error) =>
        error?.code === "POSTGRESQL_17_10_CAPTURE_INPUT_MISMATCH",
    );
  }
});

test("every implementation binding is frozen before the inspected source and every source is official", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const officialRoots = new Map([
    [
      "R09.KEYCLOAK",
      [
        "https://github.com/keycloak/keycloak",
        "https://www.keycloak.org",
      ],
    ],
    [
      "R11.OPENFGA",
      [
        "https://github.com/openfga/openfga",
        "https://openfga.dev",
      ],
    ],
    [
      "R12.PGVECTOR",
      ["https://github.com/pgvector/pgvector"],
    ],
    [
      "R12.POSTGRESQL_RLS",
      ["https://www.postgresql.org"],
    ],
  ]);

  for (const reference of preparation.references) {
    for (const binding of reference.implementationBindings) {
      assert.equal(
        sha256(gitShow(binding.freezeCommit, binding.path)),
        binding.sha256,
        `${reference.referenceId}:${binding.path}`,
      );
      execFileSync("/usr/bin/git", [
        "merge-base",
        "--is-ancestor",
        binding.freezeCommit,
        INSPECTED_SOURCE_COMMIT,
      ]);
    }

    for (const source of reference.officialSources) {
      assert.ok(
        officialRoots
          .get(reference.referenceId)
          .some(
            (root) =>
              source.uri === root || source.uri.startsWith(`${root}/`),
          ),
        `${reference.referenceId}:${source.uri}`,
      );
      assert.ok(source.reviewedSections.length > 0, source.uri);
    }
  }
});

test("the preparation binds official research and a candidate ADR without claiming a Receipt", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const research = await readText(RESEARCH_PATH);
  const adr = await readText(ADR_PATH);

  for (const inputName of ["referenceCatalog", "referencePolicy"]) {
    const input = preparation.trustInputs[inputName];
    const bytes = await readText(input.path);
    assert.equal(input.fileSha256, sha256(Buffer.from(bytes)));
    assert.equal(
      input.canonicalSha256,
      await sha256ProjectValue(JSON.parse(bytes)),
    );
  }

  assert.equal(
    preparation.trustInputs.officialResearch.path,
    RESEARCH_PATH,
  );
  assert.equal(
    preparation.trustInputs.officialResearch.sha256,
    sha256(Buffer.from(research)),
  );
  assert.equal(preparation.trustInputs.architectureDecision.path, ADR_PATH);
  assert.equal(
    preparation.trustInputs.architectureDecision.sha256,
    sha256(Buffer.from(adr)),
  );

  assert.match(adr, /状态：Candidate/);
  assert.match(adr, /Keycloak 26\.7\.0/);
  assert.match(adr, /OpenFGA v1\.18\.1/);
  assert.match(adr, /PostgreSQL 17\.10/);
  assert.match(adr, /pgvector 0\.8\.5/);
  assert.match(adr, /RETROSPECTIVE_BACKFILL/);
  assert.match(adr, /does not claim production adoption/i);
  assert.match(adr, /does not create D1, Gate, Profile, or start-authorization state/i);

  assert.equal(preparation.futureReceiptBinding.profileSha256, "PENDING");
  assert.equal(
    preparation.futureReceiptBinding.executionBaselineDigest,
    "PENDING",
  );
  assert.equal(preparation.futureReceiptBinding.formalReceiptCreated, false);
  assert.equal(preparation.futureReceiptBinding.formalBundleCreated, false);
  assert.equal(preparation.futureReceiptBinding.freezeAttestationCreated, false);
});

test("the preparation is self-hashed and cannot authorize governance", async () => {
  const preparation = await readJson(PREPARATION_PATH);

  assert.equal(
    await sha256ProjectValue(withoutSelfHash(preparation)),
    preparation.preparationSha256,
  );
  assert.deepEqual(preparation.governanceBoundary, {
    createsSecondStateTruth: false,
    d1Written: false,
    workPackageStatusChanged: false,
    gateStatusChanged: false,
    manifestChanged: false,
    profileApproved: false,
    startAuthorized: false,
    profileReadinessEffect: "NONE",
  });

  const tampered = structuredClone(preparation);
  tampered.references[0].productionAdoptionClaim = true;
  assert.notEqual(
    await sha256ProjectValue(withoutSelfHash(tampered)),
    preparation.preparationSha256,
  );
});
