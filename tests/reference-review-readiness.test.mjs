import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { referenceReviewDigests } from "../lib/reference-review-receipt-validator.mjs";
import {
  createReferenceReviewReadinessVerifier,
  referenceReviewBundleDigests,
  validateReferenceReviewBundle,
} from "../lib/reference-review-readiness.mjs";
import { createReferenceReviewFixture } from "./reference-review-fixtures.mjs";

const ajv = new Ajv2020({
  strict: true,
  allErrors: true,
  validateFormats: true,
});
addFormats(ajv);
const catalogSchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-candidate-catalog.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const applicabilityEvidenceSchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-applicability-evidence.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const applicabilityEvidenceV2Schema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-applicability-evidence.v2.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const dependencyLockScanInputV2Schema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-dependency-lock-scan-input.v2.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const sourceIntegrationScanInputV2Schema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-source-integration-scan-input.v2.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const sourceIntegrationIndexV2Schema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-source-integration-index.v2.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const bundleSchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-review-bundle.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const freezeAttestationSchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-review-freeze-attestation.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const implementationConformanceSchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-implementation-conformance.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const policySchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/reference-review-policy.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const validateCatalogSchema = ajv.compile(catalogSchema);
const validateApplicabilityEvidenceSchema = ajv.compile(
  applicabilityEvidenceSchema,
);
const validateApplicabilityEvidenceV2Schema = ajv.compile(
  applicabilityEvidenceV2Schema,
);
const validateDependencyLockScanInputV2Schema = ajv.compile(
  dependencyLockScanInputV2Schema,
);
const validateSourceIntegrationScanInputV2Schema = ajv.compile(
  sourceIntegrationScanInputV2Schema,
);
const validateSourceIntegrationIndexV2Schema = ajv.compile(
  sourceIntegrationIndexV2Schema,
);
const validateBundleSchema = ajv.compile(bundleSchema);
const validateFreezeAttestationSchema = ajv.compile(
  freezeAttestationSchema,
);
const validateImplementationConformanceSchema = ajv.compile(
  implementationConformanceSchema,
);
const validatePolicySchema = ajv.compile(policySchema);
const frozenCatalog = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/reference-review/reference-candidate-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const frozenPolicy = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/reference-review/reference-review-policy.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const FORMAL_POLICY_PATH =
  "implementation/governance/reference-review/reference-review-policy.profile-v2.v1.json";
const FORMAL_PROFILE_SHA256 =
  "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5";
const FORMAL_SOURCE_COMMIT =
  "bc718bc1a069deaa388b9a00e0135c8e9427dd91";
const FORMAL_EXECUTION_BASELINE_DIGEST =
  "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec";
const FORMAL_BACKFILL_PACKAGES = Object.freeze([
  {
    workPackageId: "C04",
    basePath:
      "implementation/governance/reference-review/p2-profile-backfill/c04",
    referenceIds: ["R09.KEYCLOAK"],
    receiptNames: ["r09-keycloak-reference-review-receipt.v1.json"],
    conformanceNames: ["r09-keycloak-implementation-conformance.v1.json"],
  },
  {
    workPackageId: "C06",
    basePath:
      "implementation/governance/reference-review/p2-profile-backfill/c06",
    referenceIds: ["R11.OPENFGA"],
    receiptNames: ["r11-openfga-reference-review-receipt.v1.json"],
    conformanceNames: ["r11-openfga-implementation-conformance.v1.json"],
  },
  {
    workPackageId: "C07",
    basePath:
      "implementation/governance/reference-review/p2-profile-backfill/c07",
    referenceIds: ["R12.PGVECTOR", "R12.POSTGRESQL_RLS"],
    receiptNames: [
      "r12-pgvector-reference-review-receipt.v1.json",
      "r12-postgresql-rls-reference-review-receipt.v1.json",
    ],
    conformanceNames: [
      "r12-pgvector-implementation-conformance.v1.json",
      "r12-postgresql-rls-implementation-conformance.v1.json",
    ],
  },
]);

const readRepoJson = async (path) =>
  JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );

const FORMAL_FREEZE_COMMIT = "f".repeat(40);
const FORMAL_FREEZE_TREE = "e".repeat(40);

const readRepoBytes = async (path) =>
  new Uint8Array(
    await readFile(new URL(`../${path}`, import.meta.url)),
  );

function addReceiptEvidencePaths(paths, receipt) {
  for (const source of receipt.officialSources ?? []) {
    paths.add(source.contentEvidenceRef);
  }
  for (const section of receipt.reviewedSections ?? []) {
    paths.add(section.notesRef);
  }
  paths.add(receipt.capabilityGap.evidenceRef);
  for (const path of receipt.currentImplementation.evidenceRefs ?? []) {
    paths.add(path);
  }
  for (const path of receipt.pocResult?.evidenceRefs ?? []) {
    paths.add(path);
  }
  for (const path of receipt.evidenceRefs ?? []) {
    paths.add(path);
  }
  if (receipt.adrRef) paths.add(receipt.adrRef);
}

async function createFormalBackfillHarness() {
  const manifest = await readRepoJson(
    "implementation/governance/work-package-manifest.v1.json",
  );
  const catalog = await readRepoJson(
    "implementation/governance/reference-review/reference-candidate-catalog.v1.json",
  );
  const policy = await readRepoJson(FORMAL_POLICY_PATH);
  const bundlesByWorkPackage = {};
  const receiptsByPath = {};
  for (const expected of FORMAL_BACKFILL_PACKAGES) {
    const bundle = await readRepoJson(
      `${expected.basePath}/reference-review-bundle.v1.json`,
    );
    bundlesByWorkPackage[expected.workPackageId] = bundle;
    for (const receiptEntry of bundle.receipts) {
      receiptsByPath[receiptEntry.path] = await readRepoJson(
        receiptEntry.path,
      );
    }
  }

  const manifestSha256 = await referenceReviewDigests.value(manifest);
  const referenceCatalogSha256 =
    await referenceReviewBundleDigests.catalog(catalog);
  const referencePolicySha256 =
    await referenceReviewBundleDigests.policy(policy);
  const trustedBinding = {
    candidateSourceBaselineSha256:
      policy.candidateSourceBaseline.sha256,
    manifestProjectId: manifest.project_id,
    manifestSha256,
    manifestVersion: manifest.manifest_version,
    manifestWorkPackageIdsSha256:
      await referenceReviewDigests.value(
        manifest.work_packages.map(({ id }) => id).sort(),
      ),
    referenceCatalogSha256,
    referencePolicySha256,
  };
  const frozenBytes = new Map();
  const frozenEvidenceByWorkPackage = {};
  const trustedFreezeRoots = [];

  for (const expected of FORMAL_BACKFILL_PACKAGES) {
    const { workPackageId } = expected;
    const bundle = bundlesByWorkPackage[workPackageId];
    const workPackagePolicy = policy.workPackagePolicies.find(
      (entry) => entry.workPackageId === workPackageId,
    );
    const paths = new Set([
      policy.manifest.path,
      policy.catalog.path,
      policy.policyPath,
      policy.candidateSourceBaseline.path,
    ]);
    for (const entry of await readdir(
      new URL(`../${expected.basePath}`, import.meta.url),
      { withFileTypes: true },
    )) {
      if (
        entry.isFile() &&
        entry.name !== "reference-review-freeze-attestation.v1.json"
      ) {
        paths.add(`${expected.basePath}/${entry.name}`);
      }
    }
    const sourceIndex = await readRepoJson(
      `${expected.basePath}/source-integration-index.v2.json`,
    );
    for (const integration of sourceIndex.integrations) {
      paths.add(integration.sourcePath);
      paths.add(integration.implementationEvidenceRef);
    }
    for (const receiptEntry of bundle.receipts) {
      paths.add(receiptEntry.path);
      addReceiptEvidencePaths(
        paths,
        receiptsByPath[receiptEntry.path],
      );
    }
    for (const binding of bundle.implementationBindings) {
      paths.add(binding.evidenceRef);
    }
    for (const path of paths) {
      if (!frozenBytes.has(path)) {
        frozenBytes.set(path, await readRepoBytes(path));
      }
    }
    const evidenceSubjects = await Promise.all(
      [...paths]
        .sort()
        .map(async (path) => ({
          path,
          sha256: await referenceReviewBundleDigests.bytes(
            frozenBytes.get(path),
          ),
        })),
    );
    const frozenEvidence = {
      schemaVersion: "reference-review-freeze-attestation.v1",
      attestationId:
        `rrfa_${workPackageId.toLowerCase()}_formal_synthetic_r2`,
      evidenceFreezeCommit: FORMAL_FREEZE_COMMIT,
      evidenceFreezeTree: FORMAL_FREEZE_TREE,
      sourceCommit: FORMAL_SOURCE_COMMIT,
      profileSha256: FORMAL_PROFILE_SHA256,
      executionBaselineDigest: FORMAL_EXECUTION_BASELINE_DIGEST,
      referenceCatalogSha256,
      referencePolicySha256,
      bundleSubjects: [
        {
          workPackageId,
          path: bundle.bundlePath,
          sha256: bundle.bundleSha256,
        },
      ],
      evidenceSubjects,
      upstreamProfileIncludesReferenceReviewDigests: false,
      upstreamExecutionBaselineIncludesReferenceReviewDigests: false,
      attestationIncludedInEvidenceFreeze: false,
      governanceEffect: "NONE",
      isProgressTracker: false,
      selfAuthorizing: false,
      attestationSha256: `sha256:${"0".repeat(64)}`,
    };
    frozenEvidence.attestationSha256 =
      await referenceReviewBundleDigests.freezeAttestation(
        frozenEvidence,
      );
    frozenEvidenceByWorkPackage[workPackageId] = frozenEvidence;
    trustedFreezeRoots.push({
      evidenceSubjectsSha256: await referenceReviewDigests.value(
        evidenceSubjects,
      ),
      sourceRoots: structuredClone(
        workPackagePolicy.applicabilityEvidence.sourceRoots,
      ),
      sourceExclusions: structuredClone(
        workPackagePolicy.applicabilityEvidence.sourceExclusions,
      ),
    });
  }

  const sourceBytes = new Map();
  const readGitBytes = async ({ commit, path }) => {
    if (commit === FORMAL_FREEZE_COMMIT) {
      const bytes = frozenBytes.get(path);
      return bytes ? new Uint8Array(bytes) : null;
    }
    if (commit !== FORMAL_SOURCE_COMMIT) return null;
    if (!sourceBytes.has(path)) {
      try {
        sourceBytes.set(
          path,
          new Uint8Array(
            execFileSync("/usr/bin/git", [
              "show",
              `${FORMAL_SOURCE_COMMIT}:${path}`,
            ]),
          ),
        );
      } catch {
        sourceBytes.set(path, null);
      }
    }
    const bytes = sourceBytes.get(path);
    return bytes ? new Uint8Array(bytes) : null;
  };
  const same = (left, right) =>
    referenceReviewDigests.canonicalize(left) ===
    referenceReviewDigests.canonicalize(right);
  const verifyFreezeRoot = async (binding) =>
    binding.evidenceFreezeCommit === FORMAL_FREEZE_COMMIT &&
    binding.evidenceFreezeTree === FORMAL_FREEZE_TREE &&
    binding.sourceCommit === FORMAL_SOURCE_COMMIT &&
    binding.manifestSha256 === manifestSha256 &&
    trustedFreezeRoots.some(
      (root) =>
        root.evidenceSubjectsSha256 ===
          binding.evidenceSubjectsSha256 &&
        same(root.sourceRoots, binding.sourceRoots) &&
        same(root.sourceExclusions, binding.sourceExclusions),
    );
  const listFrozenPaths = async ({
    evidenceFreezeCommit,
    evidenceFreezeTree,
    sourceRoots,
    sourceExclusions,
  }) =>
    evidenceFreezeCommit === FORMAL_FREEZE_COMMIT &&
    evidenceFreezeTree === FORMAL_FREEZE_TREE
      ? [...frozenBytes.keys()]
          .filter(
            (path) =>
              sourceRoots.some(
                (root) =>
                  path === root || path.startsWith(`${root}/`),
              ) &&
              !sourceExclusions.some(
                (excluded) =>
                  path === excluded ||
                  path.startsWith(`${excluded}/`),
              ),
          )
          .sort()
      : null;

  return {
    manifest,
    catalog,
    policy,
    bundlesByWorkPackage,
    receiptsByPath,
    frozenEvidenceByWorkPackage,
    trustedBinding,
    selectedToolLocks: [],
    readGitBytes,
    verifyFreezeRoot,
    listFrozenPaths,
  };
}

async function validate(fixture) {
  return validateReferenceReviewBundle({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundle: fixture.bundle,
    receiptsByPath: fixture.receiptsByPath,
    expectedBinding: fixture.expectedBinding,
    trustedBinding: fixture.trustedBinding,
    frozenEvidence: fixture.frozenEvidence,
    selectedToolLocks: fixture.selectedToolLocks,
    readGitBytes: fixture.readGitBytes,
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });
}

async function rehashAndFreeze(fixture) {
  fixture.bundle.bundleSha256 =
    await referenceReviewBundleDigests.bundle(fixture.bundle);
  await fixture.freeze();
}

async function bindSharedProfilePolicy(fixtures) {
  const sharedPolicy = structuredClone(fixtures[0].policy);
  sharedPolicy.profileBinding.requiredBackfillWorkPackageIds =
    fixtures.map(({ bundle }) => bundle.workPackageId).sort();
  sharedPolicy.workPackagePolicies = fixtures
    .map(({ policy }) =>
      structuredClone(policy.workPackagePolicies[0]),
    )
    .sort((left, right) =>
      left.workPackageId < right.workPackageId ? -1 : 1,
    );
  const policySha256 =
    await referenceReviewBundleDigests.policy(sharedPolicy);
  for (const fixture of fixtures) {
    for (const key of Object.keys(fixture.policy)) {
      delete fixture.policy[key];
    }
    Object.assign(fixture.policy, structuredClone(sharedPolicy));
    fixture.trustedBinding.referencePolicySha256 = policySha256;
    fixture.bundle.referencePolicySha256 = policySha256;
    fixture.bundle.applicableReferenceSetDigest =
      await referenceReviewBundleDigests.applicableSet({
        workPackageId: fixture.bundle.workPackageId,
        applicableReferenceIds:
          fixture.policy.workPackagePolicies.find(
            ({ workPackageId }) =>
              workPackageId === fixture.bundle.workPackageId,
          ).applicableReferenceIds,
        referenceCatalogSha256:
          fixture.bundle.referenceCatalogSha256,
        referencePolicySha256: policySha256,
      });
    for (const entry of fixture.bundle.receipts) {
      const receipt = fixture.receiptsByPath[entry.path];
      receipt.referencePolicySha256 = policySha256;
      receipt.applicableReferenceSetDigest =
        fixture.bundle.applicableReferenceSetDigest;
      receipt.receiptSha256 =
        await referenceReviewDigests.receipt(receipt);
      entry.sha256 = receipt.receiptSha256;
    }
    await rehashAndFreeze(fixture);
  }
}

async function validateWith({
  fixture,
  readGitBytes = fixture.readGitBytes,
  verifyFreezeRoot,
  listFrozenPaths = fixture.listFrozenPaths,
}) {
  return validateReferenceReviewBundle({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundle: fixture.bundle,
    receiptsByPath: fixture.receiptsByPath,
    expectedBinding: fixture.expectedBinding,
    trustedBinding: fixture.trustedBinding,
    frozenEvidence: fixture.frozenEvidence,
    selectedToolLocks: fixture.selectedToolLocks,
    readGitBytes,
    verifyFreezeRoot:
      verifyFreezeRoot ?? fixture.verifyFreezeRoot,
    listFrozenPaths,
  });
}

async function replaceApplicabilityScanInputWithArbitraryBytes(
  fixture,
  scanKind,
) {
  const applicability =
    fixture.policy.workPackagePolicies[0].applicabilityEvidence;
  const [applicabilityPath] = applicability.evidenceRefs;
  const originalReport = JSON.parse(
    new TextDecoder().decode(
      await fixture.readGitBytes({
        commit: fixture.frozenEvidence.evidenceFreezeCommit,
        path: applicabilityPath,
      }),
    ),
  );
  const scan = originalReport.scans.find(
    (candidate) => candidate.scanKind === scanKind,
  );
  const [inputPath] = scan.inputRefs;
  const attackerBytes = new TextEncoder().encode("x");
  const attackerHash =
    await referenceReviewBundleDigests.bytes(attackerBytes);
  scan.inputHashes = [attackerHash];
  originalReport.reportSha256 =
    await referenceReviewBundleDigests.applicabilityReport(
      originalReport,
    );
  const reportBytes = new TextEncoder().encode(
    JSON.stringify(originalReport),
  );
  const reportHash =
    await referenceReviewBundleDigests.bytes(reportBytes);
  applicability.evidenceHashes = [reportHash];

  const policySha256 =
    await referenceReviewBundleDigests.policy(fixture.policy);
  fixture.bundle.referencePolicySha256 = policySha256;
  fixture.bundle.applicableReferenceSetDigest =
    await referenceReviewBundleDigests.applicableSet({
      workPackageId: fixture.bundle.workPackageId,
      applicableReferenceIds:
        fixture.policy.workPackagePolicies[0]
          .applicableReferenceIds,
      referenceCatalogSha256:
        fixture.bundle.referenceCatalogSha256,
      referencePolicySha256: policySha256,
    });
  for (const entry of fixture.bundle.receipts) {
    const receipt = fixture.receiptsByPath[entry.path];
    receipt.referencePolicySha256 = policySha256;
    receipt.applicableReferenceSetDigest =
      fixture.bundle.applicableReferenceSetDigest;
    receipt.receiptSha256 =
      await referenceReviewDigests.receipt(receipt);
    entry.sha256 = receipt.receiptSha256;
  }
  await rehashAndFreeze(fixture);
  fixture.frozenEvidence.evidenceSubjects.find(
    ({ path }) => path === applicabilityPath,
  ).sha256 = reportHash;
  fixture.frozenEvidence.evidenceSubjects.find(
    ({ path }) => path === inputPath,
  ).sha256 = attackerHash;
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );
  const originalReadGitBytes = fixture.readGitBytes;
  return {
    readGitBytes: async ({ commit, path }) => {
      if (path === applicabilityPath) {
        return structuredClone(reportBytes);
      }
      if (path === inputPath) {
        return structuredClone(attackerBytes);
      }
      return originalReadGitBytes({ commit, path });
    },
  };
}

async function replaceFrozenSourceIntegrationBytes(
  fixture,
  replacementBytes,
) {
  const decodeJson = (bytes) =>
    JSON.parse(new TextDecoder().decode(bytes));
  const encodeJson = (value) =>
    new TextEncoder().encode(JSON.stringify(value));
  const applicability =
    fixture.policy.workPackagePolicies[0].applicabilityEvidence;
  const [reportPath] = applicability.evidenceRefs;
  const report = decodeJson(
    await fixture.readGitBytes({
      commit: fixture.frozenEvidence.evidenceFreezeCommit,
      path: reportPath,
    }),
  );
  const sourceScan = report.scans.find(
    ({ scanKind }) => scanKind === "SOURCE_INTEGRATION_SCAN",
  );
  const [inputPath] = sourceScan.inputRefs;
  const input = decodeJson(
    await fixture.readGitBytes({
      commit: fixture.frozenEvidence.evidenceFreezeCommit,
      path: inputPath,
    }),
  );
  const [indexSubject] = input.inventory.files;
  const indexPath = indexSubject.path;
  const index = decodeJson(
    await fixture.readGitBytes({
      commit: fixture.frozenEvidence.evidenceFreezeCommit,
      path: indexPath,
    }),
  );
  const [integration] = index.integrations;
  const sourcePath = integration.sourcePath;
  const sourceHash =
    await referenceReviewBundleDigests.bytes(replacementBytes);
  integration.sourceHash = sourceHash;

  const indexBytes = encodeJson(index);
  const indexHash =
    await referenceReviewBundleDigests.bytes(indexBytes);
  indexSubject.sha256 = indexHash;
  const inputBytes = encodeJson(input);
  const inputHash =
    await referenceReviewBundleDigests.bytes(inputBytes);
  sourceScan.inputHashes = [inputHash];
  report.reportSha256 =
    await referenceReviewBundleDigests.applicabilityReport(report);
  const reportBytes = encodeJson(report);
  const reportHash =
    await referenceReviewBundleDigests.bytes(reportBytes);
  applicability.evidenceHashes = [reportHash];

  const policySha256 =
    await referenceReviewBundleDigests.policy(fixture.policy);
  fixture.bundle.referencePolicySha256 = policySha256;
  fixture.bundle.applicableReferenceSetDigest =
    await referenceReviewBundleDigests.applicableSet({
      workPackageId: fixture.bundle.workPackageId,
      applicableReferenceIds:
        fixture.policy.workPackagePolicies[0]
          .applicableReferenceIds,
      referenceCatalogSha256:
        fixture.bundle.referenceCatalogSha256,
      referencePolicySha256: policySha256,
    });
  for (const entry of fixture.bundle.receipts) {
    const receipt = fixture.receiptsByPath[entry.path];
    receipt.referencePolicySha256 = policySha256;
    receipt.applicableReferenceSetDigest =
      fixture.bundle.applicableReferenceSetDigest;
    receipt.receiptSha256 =
      await referenceReviewDigests.receipt(receipt);
    entry.sha256 = receipt.receiptSha256;
  }
  await rehashAndFreeze(fixture);

  const replacements = new Map([
    [sourcePath, replacementBytes],
    [indexPath, indexBytes],
    [inputPath, inputBytes],
    [reportPath, reportBytes],
  ]);
  const replacementHashes = new Map([
    [sourcePath, sourceHash],
    [indexPath, indexHash],
    [inputPath, inputHash],
    [reportPath, reportHash],
  ]);
  for (const subject of fixture.frozenEvidence.evidenceSubjects) {
    if (replacementHashes.has(subject.path)) {
      subject.sha256 = replacementHashes.get(subject.path);
    }
  }
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );
  const originalReadGitBytes = fixture.readGitBytes;
  return {
    readGitBytes: async ({ commit, path }) =>
      replacements.has(path)
        ? structuredClone(replacements.get(path))
        : originalReadGitBytes({ commit, path }),
  };
}

async function replaceFrozenDependencyLockDigest(
  fixture,
  artifactDigest,
  { syncImplementationEvidence = false } = {},
) {
  const decodeJson = (bytes) =>
    JSON.parse(new TextDecoder().decode(bytes));
  const encodeJson = (value) =>
    new TextEncoder().encode(JSON.stringify(value));
  const applicability =
    fixture.policy.workPackagePolicies[0].applicabilityEvidence;
  const [reportPath] = applicability.evidenceRefs;
  const report = decodeJson(
    await fixture.readGitBytes({
      commit: fixture.frozenEvidence.evidenceFreezeCommit,
      path: reportPath,
    }),
  );
  const dependencyScan = report.scans.find(
    ({ scanKind }) => scanKind === "DEPENDENCY_LOCK_SCAN",
  );
  const [inputPath] = dependencyScan.inputRefs;
  const input = decodeJson(
    await fixture.readGitBytes({
      commit: fixture.frozenEvidence.evidenceFreezeCommit,
      path: inputPath,
    }),
  );
  const [lockSubject] = input.inventory.files;
  const lockPath = lockSubject.path;
  const lock = decodeJson(
    await fixture.readGitBytes({
      commit: fixture.frozenEvidence.evidenceFreezeCommit,
      path: lockPath,
    }),
  );
  lock.dependencies[0].artifactDigest = artifactDigest;

  const lockBytes = encodeJson(lock);
  const lockHash =
    await referenceReviewBundleDigests.bytes(lockBytes);
  lockSubject.sha256 = lockHash;
  const inputBytes = encodeJson(input);
  const inputHash =
    await referenceReviewBundleDigests.bytes(inputBytes);
  dependencyScan.inputHashes = [inputHash];
  report.reportSha256 =
    await referenceReviewBundleDigests.applicabilityReport(report);
  const reportBytes = encodeJson(report);
  const reportHash =
    await referenceReviewBundleDigests.bytes(reportBytes);
  applicability.evidenceHashes = [reportHash];

  const policySha256 =
    await referenceReviewBundleDigests.policy(fixture.policy);
  fixture.bundle.referencePolicySha256 = policySha256;
  fixture.bundle.applicableReferenceSetDigest =
    await referenceReviewBundleDigests.applicableSet({
      workPackageId: fixture.bundle.workPackageId,
      applicableReferenceIds:
        fixture.policy.workPackagePolicies[0]
          .applicableReferenceIds,
      referenceCatalogSha256:
        fixture.bundle.referenceCatalogSha256,
      referencePolicySha256: policySha256,
    });
  for (const entry of fixture.bundle.receipts) {
    const receipt = fixture.receiptsByPath[entry.path];
    receipt.referencePolicySha256 = policySha256;
    receipt.applicableReferenceSetDigest =
      fixture.bundle.applicableReferenceSetDigest;
    receipt.receiptSha256 =
      await referenceReviewDigests.receipt(receipt);
    entry.sha256 = receipt.receiptSha256;
  }
  await rehashAndFreeze(fixture);

  const replacements = new Map([
    [lockPath, lockBytes],
    [inputPath, inputBytes],
    [reportPath, reportBytes],
  ]);
  const replacementHashes = new Map([
    [lockPath, lockHash],
    [inputPath, inputHash],
    [reportPath, reportHash],
  ]);
  if (syncImplementationEvidence) {
    const [binding] = fixture.bundle.implementationBindings;
    const evidence = decodeJson(
      await fixture.readGitBytes({
        commit: fixture.frozenEvidence.evidenceFreezeCommit,
        path: binding.evidenceRef,
      }),
    );
    evidence.dependencyLock = {
      ...evidence.dependencyLock,
      artifactDigest,
      evidenceRef: lockPath,
      evidenceHash: lockHash,
    };
    const evidenceBytes = encodeJson(evidence);
    const evidenceHash =
      await referenceReviewBundleDigests.bytes(evidenceBytes);
    binding.evidenceHash = evidenceHash;
    fixture.bundle.bundleSha256 =
      await referenceReviewBundleDigests.bundle(fixture.bundle);
    await fixture.freeze();
    replacements.set(binding.evidenceRef, evidenceBytes);
    replacementHashes.set(binding.evidenceRef, evidenceHash);
  }
  for (const subject of fixture.frozenEvidence.evidenceSubjects) {
    if (replacementHashes.has(subject.path)) {
      subject.sha256 = replacementHashes.get(subject.path);
    }
  }
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );
  const originalReadGitBytes = fixture.readGitBytes;
  return {
    readGitBytes: async ({ commit, path }) =>
      replacements.has(path)
        ? structuredClone(replacements.get(path))
        : originalReadGitBytes({ commit, path }),
  };
}

function sourceIntegrationBytes({
  identifier = "OPENBAO",
  officialSourceUri = "https://example.invalid/r26_openbao",
  integrationKind = "RUNTIME_PLUGIN",
  duplicateMarker = false,
} = {}) {
  const marker = `// @reference-integration-v1 ${JSON.stringify({
    schemaVersion: "reference-integration-marker.v1",
    identifier,
    officialSourceUri,
    integrationKind,
  })}`;
  return new TextEncoder().encode(
    `${marker}\n${duplicateMarker ? `${marker}\n` : ""}export const reference = "OPENBAO";\n`,
  );
}

test("a complete Reference Review Bundle passes schemas and semantics", async () => {
  const fixture = await createReferenceReviewFixture();
  const [freezeBuilder, frozenAssetsModule, runtimeProofSchema] =
    await Promise.all([
      import(
        "../scripts/build-reference-review-freeze-attestations.mjs"
      ),
      import("../lib/reference-review-frozen-assets.mjs"),
      readRepoJson(
        "implementation/governance/schemas/reference-review-runtime-proof.v1.schema.json",
      ),
    ]);
  const {
    REFERENCE_REVIEW_FROZEN_ASSETS,
    REFERENCE_REVIEW_RUNTIME_PROOF,
    verifyReferenceReviewReadinessFromFrozenAssets,
  } = frozenAssetsModule;
  const validateRuntimeProofSchema = ajv.compile(runtimeProofSchema);

  assert.equal(
    validateCatalogSchema(fixture.catalog),
    true,
    ajv.errorsText(validateCatalogSchema.errors),
  );
  assert.equal(
    validateBundleSchema(fixture.bundle),
    true,
    ajv.errorsText(validateBundleSchema.errors),
  );
  assert.equal(
    validateFreezeAttestationSchema(fixture.frozenEvidence),
    true,
    ajv.errorsText(validateFreezeAttestationSchema.errors),
  );
  const applicabilityPath =
    fixture.policy.workPackagePolicies[0].applicabilityEvidence
      .evidenceRefs[0];
  const applicabilityReport = JSON.parse(
    new TextDecoder().decode(
      await fixture.readGitBytes({
        commit: fixture.frozenEvidence.evidenceFreezeCommit,
        path: applicabilityPath,
      }),
    ),
  );
  assert.equal(
    validateApplicabilityEvidenceSchema(applicabilityReport),
    true,
    ajv.errorsText(validateApplicabilityEvidenceSchema.errors),
  );
  assert.deepEqual(await validate(fixture), {
    ok: true,
    status: "READY",
    reasonCodes: [],
    bundleSha256: fixture.bundle.bundleSha256,
    applicableReferenceSetDigest:
      fixture.bundle.applicableReferenceSetDigest,
  });

  const formalPolicy = await readRepoJson(FORMAL_POLICY_PATH);
  assert.equal(
    validatePolicySchema(formalPolicy),
    true,
    ajv.errorsText(validatePolicySchema.errors),
  );
  for (const expected of FORMAL_BACKFILL_PACKAGES) {
    const report = await readRepoJson(
      `${expected.basePath}/applicability-evidence.v2.json`,
    );
    const bundle = await readRepoJson(
      `${expected.basePath}/reference-review-bundle.v1.json`,
    );
    assert.equal(
      validateApplicabilityEvidenceV2Schema(report),
      true,
      `${expected.workPackageId}: ${ajv.errorsText(validateApplicabilityEvidenceV2Schema.errors)}`,
    );
    assert.equal(
      report.reportSha256,
      await referenceReviewBundleDigests.applicabilityReport(report),
    );
    assert.equal(
      validateBundleSchema(bundle),
      true,
      `${expected.workPackageId}: ${ajv.errorsText(validateBundleSchema.errors)}`,
    );
    assert.equal(
      bundle.bundleSha256,
      await referenceReviewBundleDigests.bundle(bundle),
    );
    assert.equal(bundle.workPackageId, expected.workPackageId);
    assert.equal(bundle.reviewMode, "RETROSPECTIVE_BACKFILL");
    assert.equal(bundle.reviewBoundary, "IMPLEMENTATION_CONFORMANCE");
    assert.equal(bundle.profileSha256, FORMAL_PROFILE_SHA256);
    assert.equal(bundle.sourceCommit, FORMAL_SOURCE_COMMIT);
    assert.equal(
      bundle.executionBaselineDigest,
      FORMAL_EXECUTION_BASELINE_DIGEST,
    );
    assert.deepEqual(bundle.candidateReferenceIds, expected.referenceIds);
    assert.deepEqual(
      bundle.receipts.map(({ referenceId }) => referenceId),
      expected.referenceIds,
    );
    assert.equal(bundle.implementationBindings.length, expected.referenceIds.length);
    assert.equal(bundle.governanceEffect, "NONE");
    assert.equal(bundle.productionAdoptionClaim, false);
    for (const name of expected.conformanceNames) {
      const conformance = await readRepoJson(`${expected.basePath}/${name}`);
      assert.equal(
        validateImplementationConformanceSchema(conformance),
        true,
        `${name}: ${ajv.errorsText(validateImplementationConformanceSchema.errors)}`,
      );
      assert.equal(conformance.workPackageId, expected.workPackageId);
      assert.equal(conformance.sourceCommit, FORMAL_SOURCE_COMMIT);
      assert.equal(conformance.governanceEffect, "NONE");
      assert.equal(conformance.productionAdoptionClaim, false);
    }
  }

  const formalHarness = await createFormalBackfillHarness();
  assert.deepEqual(
    Object.keys(formalHarness.bundlesByWorkPackage),
    ["C04", "C06", "C07"],
  );
  const expectedBinding = {
    profileSha256: FORMAL_PROFILE_SHA256,
    sourceCommit: FORMAL_SOURCE_COMMIT,
    executionBaselineDigest: FORMAL_EXECUTION_BASELINE_DIGEST,
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  };
  const validateFormalPackage = (workPackageId, overrides = {}) =>
    validateReferenceReviewBundle({
      manifest: formalHarness.manifest,
      catalog: formalHarness.catalog,
      policy: formalHarness.policy,
      bundle:
        formalHarness.bundlesByWorkPackage[workPackageId],
      receiptsByPath: formalHarness.receiptsByPath,
      expectedBinding,
      trustedBinding: formalHarness.trustedBinding,
      frozenEvidence:
        formalHarness.frozenEvidenceByWorkPackage[
          workPackageId
        ],
      selectedToolLocks: formalHarness.selectedToolLocks,
      readGitBytes: formalHarness.readGitBytes,
      verifyFreezeRoot: formalHarness.verifyFreezeRoot,
      listFrozenPaths: formalHarness.listFrozenPaths,
      ...overrides,
    });
  for (const workPackageId of ["C04", "C06", "C07"]) {
    const bundle =
      formalHarness.bundlesByWorkPackage[workPackageId];
    assert.deepEqual(await validateFormalPackage(workPackageId), {
      ok: true,
      status: "READY",
      reasonCodes: [],
      bundleSha256: bundle.bundleSha256,
      applicableReferenceSetDigest:
        bundle.applicableReferenceSetDigest,
    });
    const workPackagePolicy =
      formalHarness.policy.workPackagePolicies.find(
        (entry) => entry.workPackageId === workPackageId,
      );
    assert.deepEqual(
      await formalHarness.listFrozenPaths({
        evidenceFreezeCommit: FORMAL_FREEZE_COMMIT,
        evidenceFreezeTree: FORMAL_FREEZE_TREE,
        sourceRoots:
          workPackagePolicy.applicabilityEvidence.sourceRoots,
        sourceExclusions:
          workPackagePolicy.applicabilityEvidence.sourceExclusions,
      }),
      workPackagePolicy.applicabilityEvidence.sourceRoots,
    );
  }

  const profileBinding = {
    boundary: "PROFILE_APPROVAL",
    executionBaselineDigest: FORMAL_EXECUTION_BASELINE_DIGEST,
    profileApprovalId: null,
    profileSha256: FORMAL_PROFILE_SHA256,
    sourceCommit: FORMAL_SOURCE_COMMIT,
    workPackageId: null,
  };
  const formalVerifier =
    createReferenceReviewReadinessVerifier(formalHarness);
  assert.equal(await formalVerifier(profileBinding), true);
  const noAttestationVerifier =
    createReferenceReviewReadinessVerifier({
      ...formalHarness,
      frozenEvidenceByWorkPackage: null,
    });
  assert.equal(
    await noAttestationVerifier(profileBinding),
    false,
  );

  const r1FreezeCommit =
    "feeda1ac6a8c236f11d3b80b240ffc757a261c56";
  const r1FreezeTree =
    "626a30ef25b68d4a24d296a2dfbae89ce72d21cc";
  const attestationPaths = Object.fromEntries(
    FORMAL_BACKFILL_PACKAGES.map(({ workPackageId, basePath }) => [
      workPackageId,
      `${basePath}/reference-review-freeze-attestation.v1.json`,
    ]),
  );
  const realAttestations = Object.fromEntries(
    await Promise.all(
      Object.entries(attestationPaths).map(async ([workPackageId, path]) => [
        workPackageId,
        await readRepoJson(path),
      ]),
    ),
  );
  const generated =
    await freezeBuilder.buildReferenceReviewFreezeArtifacts({
      repositoryPath: new URL("../", import.meta.url).pathname,
    });

  assert.equal(
    validateRuntimeProofSchema(REFERENCE_REVIEW_RUNTIME_PROOF),
    true,
    ajv.errorsText(validateRuntimeProofSchema.errors),
  );
  assert.deepEqual(generated.runtimeProof, REFERENCE_REVIEW_RUNTIME_PROOF);
  assert.equal(
    await readFile(
      new URL(
        "../implementation/governance/reference-review/p2-profile-backfill/reference-review-runtime-proof.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
    `${JSON.stringify(generated.runtimeProof, null, 2)}\n`,
  );
  assert.deepEqual(
    generated.attestationsByWorkPackage,
    realAttestations,
  );
  assert.deepEqual(
    REFERENCE_REVIEW_FROZEN_ASSETS.frozenEvidenceByWorkPackage,
    realAttestations,
  );
  assert.equal(
    REFERENCE_REVIEW_FROZEN_ASSETS.policy.policyPath,
    FORMAL_POLICY_PATH,
  );

  const r2ArtifactPaths = new Set([
    ...Object.values(attestationPaths),
    "implementation/governance/reference-review/p2-profile-backfill/reference-review-runtime-proof.v1.json",
    "implementation/governance/schemas/reference-review-runtime-proof.v1.schema.json",
    "lib/reference-review-frozen-assets.mjs",
    "scripts/build-reference-review-freeze-attestations.mjs",
  ]);
  const attestationIds = new Set();
  const attestationHashes = new Set();
  for (const [workPackageId, attestation] of Object.entries(
    realAttestations,
  )) {
    assert.equal(
      await readFile(
        new URL(`../${attestationPaths[workPackageId]}`, import.meta.url),
        "utf8",
      ),
      `${JSON.stringify(
        generated.attestationsByWorkPackage[workPackageId],
        null,
        2,
      )}\n`,
    );
    assert.equal(
      validateFreezeAttestationSchema(attestation),
      true,
      `${workPackageId}: ${ajv.errorsText(validateFreezeAttestationSchema.errors)}`,
    );
    assert.equal(attestation.evidenceFreezeCommit, r1FreezeCommit);
    assert.equal(attestation.evidenceFreezeTree, r1FreezeTree);
    assert.equal(attestation.sourceCommit, FORMAL_SOURCE_COMMIT);
    assert.equal(attestation.profileSha256, FORMAL_PROFILE_SHA256);
    assert.equal(
      attestation.executionBaselineDigest,
      FORMAL_EXECUTION_BASELINE_DIGEST,
    );
    assert.equal(attestation.attestationIncludedInEvidenceFreeze, false);
    assert.equal(attestation.governanceEffect, "NONE");
    assert.equal(attestation.isProgressTracker, false);
    assert.equal(attestation.selfAuthorizing, false);
    assert.equal(
      attestation.attestationSha256,
      await referenceReviewBundleDigests.freezeAttestation(attestation),
    );
    assert.equal(attestationIds.has(attestation.attestationId), false);
    assert.equal(
      attestationHashes.has(attestation.attestationSha256),
      false,
    );
    attestationIds.add(attestation.attestationId);
    attestationHashes.add(attestation.attestationSha256);
    assert.equal(
      attestation.evidenceSubjects.some(({ path }) =>
        r2ArtifactPaths.has(path),
      ),
      false,
      `${workPackageId} must not include an R2 artifact in the R1 freeze`,
    );
  }

  const runtimeBinding = {
    boundary: "PROFILE_APPROVAL",
    executionBaselineDigest: FORMAL_EXECUTION_BASELINE_DIGEST,
    profileApprovalId: null,
    profileSha256: FORMAL_PROFILE_SHA256,
    sourceCommit: FORMAL_SOURCE_COMMIT,
    workPackageId: null,
  };
  const runtimeAssets = REFERENCE_REVIEW_FROZEN_ASSETS;
  const createRuntimeVerifier = (overrides = {}) =>
    createReferenceReviewReadinessVerifier({
      ...runtimeAssets,
      ...overrides,
    });
  for (const workPackageId of ["C04", "C06", "C07"]) {
    const bundle = runtimeAssets.bundlesByWorkPackage[workPackageId];
    assert.deepEqual(
      await validateReferenceReviewBundle({
        manifest: runtimeAssets.manifest,
        catalog: runtimeAssets.catalog,
        policy: runtimeAssets.policy,
        bundle,
        receiptsByPath: runtimeAssets.receiptsByPath,
        expectedBinding: {
          profileSha256: FORMAL_PROFILE_SHA256,
          sourceCommit: FORMAL_SOURCE_COMMIT,
          executionBaselineDigest: FORMAL_EXECUTION_BASELINE_DIGEST,
          reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
        },
        trustedBinding: runtimeAssets.trustedBinding,
        frozenEvidence:
          runtimeAssets.frozenEvidenceByWorkPackage[workPackageId],
        selectedToolLocks: runtimeAssets.selectedToolLocks,
        readGitBytes: runtimeAssets.readGitBytes,
        verifyFreezeRoot: runtimeAssets.verifyFreezeRoot,
        listFrozenPaths: runtimeAssets.listFrozenPaths,
      }),
      {
        ok: true,
        status: "READY",
        reasonCodes: [],
        bundleSha256: bundle.bundleSha256,
        applicableReferenceSetDigest:
          bundle.applicableReferenceSetDigest,
      },
    );
  }
  assert.equal(
    await verifyReferenceReviewReadinessFromFrozenAssets(runtimeBinding),
    true,
  );
  assert.equal(
    await createRuntimeVerifier({
      frozenEvidenceByWorkPackage: null,
    })(runtimeBinding),
    false,
  );
  assert.equal(
    await createReferenceReviewReadinessVerifier({})(runtimeBinding),
    false,
  );

  for (const [field, value] of [
    ["profileSha256", `sha256:${"1".repeat(64)}`],
    ["sourceCommit", "1".repeat(40)],
    ["executionBaselineDigest", `sha256:${"2".repeat(64)}`],
  ]) {
    assert.equal(
      await verifyReferenceReviewReadinessFromFrozenAssets({
        ...runtimeBinding,
        [field]: value,
      }),
      false,
      field,
    );
  }

  const changedPolicy = structuredClone(runtimeAssets.policy);
  changedPolicy.profileBinding.profileSha256 =
    `sha256:${"3".repeat(64)}`;
  assert.equal(
    await createRuntimeVerifier({ policy: changedPolicy })(runtimeBinding),
    false,
  );
  const changedCatalog = structuredClone(runtimeAssets.catalog);
  changedCatalog.references[0].name += " changed";
  assert.equal(
    await createRuntimeVerifier({ catalog: changedCatalog })(runtimeBinding),
    false,
  );

  const appendNewline = async (reader, request, targetPath) => {
    const bytes = await reader(request);
    if (
      request.commit !== r1FreezeCommit ||
      request.path !== targetPath ||
      bytes === null
    ) {
      return bytes;
    }
    const changed = new Uint8Array(bytes.byteLength + 1);
    changed.set(bytes);
    changed[bytes.byteLength] = 0x0a;
    return changed;
  };
  const c04Policy = runtimeAssets.policy.workPackagePolicies.find(
    ({ workPackageId }) => workPackageId === "C04",
  );
  const c04Bundle = runtimeAssets.bundlesByWorkPackage.C04;
  const tamperedFrozenPaths = [
    c04Policy.applicabilityEvidence.evidenceRefs[0],
    c04Bundle.receipts[0].path,
    c04Bundle.bundlePath,
    c04Bundle.implementationBindings[0].evidenceRef,
  ];
  for (const targetPath of tamperedFrozenPaths) {
    assert.equal(
      await createRuntimeVerifier({
        readGitBytes: (request) =>
          appendNewline(
            runtimeAssets.readGitBytes,
            request,
            targetPath,
          ),
      })(runtimeBinding),
      false,
      targetPath,
    );
  }

  const runtimeWrongSourcePath =
    "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql";
  const runtimeReplacementSourcePath =
    "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql";
  assert.equal(
    await createRuntimeVerifier({
      readGitBytes: (request) =>
        request.commit === FORMAL_SOURCE_COMMIT &&
        request.path === runtimeWrongSourcePath
          ? runtimeAssets.readGitBytes({
              commit: FORMAL_SOURCE_COMMIT,
              path: runtimeReplacementSourcePath,
            })
          : runtimeAssets.readGitBytes(request),
    })(runtimeBinding),
    false,
  );
  assert.equal(
    await createRuntimeVerifier({
      verifyFreezeRoot: (binding) =>
        runtimeAssets.verifyFreezeRoot({
          ...binding,
          sourceRoots: ["lib"],
        }),
    })(runtimeBinding),
    false,
  );

  for (const field of ["evidenceFreezeCommit", "evidenceFreezeTree"]) {
    const changedAttestations = structuredClone(
      runtimeAssets.frozenEvidenceByWorkPackage,
    );
    changedAttestations.C04[field] =
      field === "evidenceFreezeCommit"
        ? "4".repeat(40)
        : "5".repeat(40);
    changedAttestations.C04.attestationSha256 =
      await referenceReviewBundleDigests.freezeAttestation(
        changedAttestations.C04,
      );
    assert.equal(
      await createRuntimeVerifier({
        frozenEvidenceByWorkPackage: changedAttestations,
      })(runtimeBinding),
      false,
      field,
    );
  }

  const missingSubjectAttestations = structuredClone(
    runtimeAssets.frozenEvidenceByWorkPackage,
  );
  missingSubjectAttestations.C04.evidenceSubjects.pop();
  missingSubjectAttestations.C04.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      missingSubjectAttestations.C04,
    );
  assert.equal(
    await createRuntimeVerifier({
      frozenEvidenceByWorkPackage: missingSubjectAttestations,
    })(runtimeBinding),
    false,
  );

  const c04ReportPath =
    formalHarness.policy.workPackagePolicies.find(
      ({ workPackageId }) => workPackageId === "C04",
    ).applicabilityEvidence.evidenceRefs[0];
  const wrongSubject = await validateFormalPackage("C04", {
    readGitBytes: async (request) => {
      const bytes = await formalHarness.readGitBytes(request);
      if (
        request.commit !== FORMAL_FREEZE_COMMIT ||
        request.path !== c04ReportPath ||
        bytes === null
      ) {
        return bytes;
      }
      const changed = new Uint8Array(bytes.byteLength + 1);
      changed.set(bytes);
      changed[bytes.byteLength] = 0x0a;
      return changed;
    },
  });
  assert.equal(wrongSubject.ok, false);
  assert.ok(
    wrongSubject.reasonCodes.includes(
      "REFERENCE_APPLICABILITY_NOT_PROVED",
    ),
    wrongSubject.reasonCodes,
  );

  const wrongRoot = await validateFormalPackage("C04", {
    verifyFreezeRoot: (binding) =>
      formalHarness.verifyFreezeRoot({
        ...binding,
        sourceRoots: ["lib"],
      }),
  });
  assert.equal(wrongRoot.ok, false);
  assert.ok(
    wrongRoot.reasonCodes.includes(
      "REFERENCE_FREEZE_ATTESTATION_INVALID",
    ),
    wrongRoot.reasonCodes,
  );

  const c07SourceIndex = await readRepoJson(
    `${FORMAL_BACKFILL_PACKAGES[2].basePath}/source-integration-index.v2.json`,
  );
  assert.deepEqual(
    c07SourceIndex.integrations.map(
      ({ referenceName, sourcePath }) => [referenceName, sourcePath],
    ),
    [
      [
        "PostgreSQL Row Security",
        "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
      ],
      [
        "pgvector",
        "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
      ],
    ],
  );
  const c07DependencyLock = await readRepoJson(
    `${FORMAL_BACKFILL_PACKAGES[2].basePath}/dependency-lock.v1.json`,
  );
  assert.deepEqual(
    c07DependencyLock.dependencies.map(
      ({ packageName, version, artifactDigest }) =>
        [packageName, version, artifactDigest],
    ),
    [
      [
        "PostgreSQL Row Security",
        "17.10",
          "sha256:078a03516dcdbdb705fecaf415ea3d13a956c589e46f09fed68a06fb00598c90",
      ],
      [
        "pgvector",
        "0.8.5",
          "sha256:6f88a5cbdde31666f4b6c1a6b75c51dcbeffe58f9a7d2b26e502d5a6e5e14d44",
      ],
    ],
  );
  const formalWrongSourcePath =
    "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql";
  const formalReplacementSourcePath =
    "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql";
  const wrongSource = await validateFormalPackage("C07", {
    readGitBytes: async (request) =>
      request.commit === FORMAL_SOURCE_COMMIT &&
      request.path === formalWrongSourcePath
        ? formalHarness.readGitBytes({
            commit: FORMAL_SOURCE_COMMIT,
            path: formalReplacementSourcePath,
          })
        : formalHarness.readGitBytes(request),
  });
  assert.equal(wrongSource.ok, false);
  assert.ok(
    wrongSource.reasonCodes.includes(
      "REFERENCE_APPLICABILITY_NOT_PROVED",
    ),
    wrongSource.reasonCodes,
  );

  const v2Scans = [
    {
      scanKind: "DEPENDENCY_LOCK_SCAN",
      method: "deterministic-dependency-lock-parser",
      methodVersion: "v2",
      inputRefs: ["synthetic/dependency-input.v2.json"],
      inputHashes: [`sha256:${"1".repeat(64)}`],
      discoveredReferenceIds: ["R09.KEYCLOAK"],
      result: "COMPLETE",
    },
    {
      scanKind: "MANUAL_SUPPLEMENT",
      method: "deterministic-manual-supplement-parser",
      methodVersion: "v1",
      inputRefs: ["synthetic/manual-input.v1.json"],
      inputHashes: [`sha256:${"2".repeat(64)}`],
      discoveredReferenceIds: ["R09.KEYCLOAK"],
      result: "COMPLETE",
    },
    {
      scanKind: "REFERENCE_MATRIX",
      method: "deterministic-reference-matrix-parser",
      methodVersion: "v1",
      inputRefs: ["synthetic/matrix-input.v1.json"],
      inputHashes: [`sha256:${"3".repeat(64)}`],
      discoveredReferenceIds: ["R09.KEYCLOAK"],
      result: "COMPLETE",
    },
    {
      scanKind: "SOURCE_INTEGRATION_SCAN",
      method: "deterministic-source-integration-parser",
      methodVersion: "v2",
      inputRefs: ["synthetic/source-input.v2.json"],
      inputHashes: [`sha256:${"4".repeat(64)}`],
      discoveredReferenceIds: ["R09.KEYCLOAK"],
      result: "COMPLETE",
    },
  ];
  const v2Report = {
    schemaVersion: "reference-applicability-evidence.v2",
    workPackageId: "C04",
    sourceCommit: "8".repeat(40),
    candidateReferenceIds: ["R09.KEYCLOAK"],
    scans: v2Scans,
    reviewedAt: "2026-08-14T00:00:00.000Z",
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    productionAdoptionClaim: false,
    reportSha256: `sha256:${"5".repeat(64)}`,
  };
  const dependencyInput = {
    schemaVersion: "reference-dependency-lock-scan-input.v2",
    workPackageId: "C04",
    sourceCommit: "8".repeat(40),
    referenceCatalogSha256: `sha256:${"6".repeat(64)}`,
    scanKind: "DEPENDENCY_LOCK_SCAN",
    inventory: {
      files: [
        {
          format: "PROJECT_TOOL_LOCK_V1",
          path: "synthetic/dependency-lock.json",
          sha256: `sha256:${"7".repeat(64)}`,
        },
      ],
    },
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    productionAdoptionClaim: false,
  };
  const sourceIndex = {
    schemaVersion: "reference-source-integration-index.v2",
    workPackageId: "C04",
    integrations: [
      {
        referenceName: "Keycloak",
        officialSourceUri: "https://github.com/keycloak/keycloak",
        integrationKind: "RUNTIME_PLUGIN",
        sourcePath: "lib/keycloak-scim-provisioning-adapter.mjs",
        sourceCommitSha256: `sha256:${"8".repeat(64)}`,
        implementationEvidenceRef:
          "implementation/p1/c04/c04-verification-evidence.v1.json",
        implementationEvidenceSha256: `sha256:${"9".repeat(64)}`,
      },
    ],
  };
  const sourceInput = {
    schemaVersion: "reference-source-integration-scan-input.v2",
    workPackageId: "C04",
    sourceCommit: "8".repeat(40),
    referenceCatalogSha256: `sha256:${"6".repeat(64)}`,
    scanKind: "SOURCE_INTEGRATION_SCAN",
    inventory: {
      files: [
        {
          format: "REFERENCE_SOURCE_INTEGRATION_INDEX_V2",
          path: "synthetic/source-index.v2.json",
          sha256: `sha256:${"a".repeat(64)}`,
        },
      ],
    },
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    productionAdoptionClaim: false,
  };

  for (const [validator, value] of [
    [validateApplicabilityEvidenceV2Schema, v2Report],
    [validateDependencyLockScanInputV2Schema, dependencyInput],
    [validateSourceIntegrationScanInputV2Schema, sourceInput],
    [validateSourceIntegrationIndexV2Schema, sourceIndex],
  ]) {
    assert.equal(validator(value), true, ajv.errorsText(validator.errors));
    assert.equal(validator({ ...value, ready: true }), false);
    const missingSchemaVersion = structuredClone(value);
    delete missingSchemaVersion.schemaVersion;
    assert.equal(validator(missingSchemaVersion), false);
  }
  const nestedUnknowns = [
    [
      validateApplicabilityEvidenceV2Schema,
      {
        ...v2Report,
        scans: [{ ...v2Report.scans[0], ready: true }, ...v2Report.scans.slice(1)],
      },
    ],
    [
      validateDependencyLockScanInputV2Schema,
      {
        ...dependencyInput,
        inventory: { ...dependencyInput.inventory, ready: true },
      },
    ],
    [
      validateSourceIntegrationScanInputV2Schema,
      {
        ...sourceInput,
        inventory: {
          files: [{ ...sourceInput.inventory.files[0], ready: true }],
        },
      },
    ],
    [
      validateSourceIntegrationIndexV2Schema,
      {
        ...sourceIndex,
        integrations: [{ ...sourceIndex.integrations[0], ready: true }],
      },
    ],
  ];
  for (const [validator, value] of nestedUnknowns) {
    assert.equal(validator(value), false);
  }
  assert.equal("evidenceFreezeTree" in dependencyInput.inventory, false);
  assert.equal("evidenceFreezeTree" in sourceInput.inventory, false);

  const retrospectiveV2 = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
  });
  assert.equal((await validate(retrospectiveV2)).ok, true);

  const broadV2SourceRoot = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
  });
  broadV2SourceRoot.policy.workPackagePolicies[0].applicabilityEvidence
    .sourceRoots = ["synthetic/applicability/source/C04"];
  await rehashAndFreeze(broadV2SourceRoot);
  assert.equal((await validate(broadV2SourceRoot)).ok, false);

  const v2ApplicabilityPath =
    retrospectiveV2.policy.workPackagePolicies[0]
      .applicabilityEvidence.evidenceRefs[0];
  const v2ApplicabilityReport = JSON.parse(
    new TextDecoder().decode(
      await retrospectiveV2.readGitBytes({
        commit:
          retrospectiveV2.frozenEvidence.evidenceFreezeCommit,
        path: v2ApplicabilityPath,
      }),
    ),
  );
  assert.equal(
    await referenceReviewBundleDigests.applicabilityReport(
      v2ApplicabilityReport,
    ),
    v2ApplicabilityReport.reportSha256,
  );
  const tamperedV2Report = structuredClone(v2ApplicabilityReport);
  tamperedV2Report.reviewedAt = "2026-08-14T00:00:01.000Z";
  assert.notEqual(
    await referenceReviewBundleDigests.applicabilityReport(
      tamperedV2Report,
    ),
    tamperedV2Report.reportSha256,
  );
  const sourceScan = v2ApplicabilityReport.scans.find(
    ({ scanKind }) => scanKind === "SOURCE_INTEGRATION_SCAN",
  );
  const sourceInputPath = sourceScan.inputRefs[0];
  const sourceInputValue = JSON.parse(
    new TextDecoder().decode(
      await retrospectiveV2.readGitBytes({
        commit:
          retrospectiveV2.frozenEvidence.evidenceFreezeCommit,
        path: sourceInputPath,
      }),
    ),
  );
  const sourceIndexPath = sourceInputValue.inventory.files[0].path;
  const sourceIndexValue = JSON.parse(
    new TextDecoder().decode(
      await retrospectiveV2.readGitBytes({
        commit:
          retrospectiveV2.frozenEvidence.evidenceFreezeCommit,
        path: sourceIndexPath,
      }),
    ),
  );
  const sourceIntegration = sourceIndexValue.integrations[0];
  const originalReadGitBytes = retrospectiveV2.readGitBytes;
  for (const [label, readGitBytes] of [
    [
      "missing source commit bytes",
      ({ commit, path }) =>
        commit === retrospectiveV2.bundle.sourceCommit &&
        path === sourceIntegration.sourcePath
          ? null
          : originalReadGitBytes({ commit, path }),
    ],
    [
      "source resolver exception",
      ({ commit, path }) => {
        if (
          commit === retrospectiveV2.bundle.sourceCommit &&
          path === sourceIntegration.sourcePath
        ) {
          throw new TypeError("synthetic source resolver failure");
        }
        return originalReadGitBytes({ commit, path });
      },
    ],
    [
      "changed frozen source bytes",
      ({ commit, path }) =>
        commit ===
          retrospectiveV2.frozenEvidence.evidenceFreezeCommit &&
        path === sourceIntegration.sourcePath
          ? new TextEncoder().encode("changed\n")
          : originalReadGitBytes({ commit, path }),
    ],
    [
      "missing implementation evidence",
      ({ commit, path }) =>
        commit ===
          retrospectiveV2.frozenEvidence.evidenceFreezeCommit &&
        path === sourceIntegration.implementationEvidenceRef
          ? null
          : originalReadGitBytes({ commit, path }),
    ],
    [
      "implementation evidence invented only at the freeze commit",
      ({ commit, path }) =>
        commit === retrospectiveV2.bundle.sourceCommit &&
        path === sourceIntegration.implementationEvidenceRef
          ? null
          : originalReadGitBytes({ commit, path }),
    ],
    [
      "implementation evidence changed after the source commit",
      ({ commit, path }) =>
        commit === retrospectiveV2.bundle.sourceCommit &&
        path === sourceIntegration.implementationEvidenceRef
          ? new TextEncoder().encode("changed historical evidence\n")
          : originalReadGitBytes({ commit, path }),
    ],
    [
      "wrong source hash",
      ({ commit, path }) =>
        commit === retrospectiveV2.bundle.sourceCommit &&
        path === sourceIntegration.sourcePath
          ? new TextEncoder().encode("wrong source hash\n")
          : originalReadGitBytes({ commit, path }),
    ],
  ]) {
    const result = await validateWith({
      fixture: retrospectiveV2,
      readGitBytes,
    });
    assert.equal(result.ok, false, label);
    assert.ok(
      result.reasonCodes.includes(
        "REFERENCE_APPLICABILITY_NOT_PROVED",
      ),
      `${label}:${result.reasonCodes.join(",")}`,
    );
  }

  const wrongEvidenceIdentity = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
    implementationEvidenceWorkPackageId: "C06",
  });
  assert.equal((await validate(wrongEvidenceIdentity)).ok, false);

  const wrongEvidenceArtifactPath = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
    implementationEvidenceArtifactPath:
      "synthetic/applicability/source/C04/other.mjs",
  });
  assert.equal((await validate(wrongEvidenceArtifactPath)).ok, false);

  const wrongEvidenceArtifactHash = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
    implementationEvidenceArtifactSha256: `sha256:${"0".repeat(64)}`,
  });
  assert.equal((await validate(wrongEvidenceArtifactHash)).ok, false);

  const wrongCatalogUri = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
    sourceIntegrationOfficialSourceUri:
      "https://example.invalid/not-keycloak",
  });
  assert.equal((await validate(wrongCatalogUri)).ok, false);

  const wrongSourcePath = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
  });
  wrongSourcePath.policy.workPackagePolicies[0].applicabilityEvidence
    .sourceRoots = ["synthetic/applicability/source/C04/missing.mjs"];
  assert.equal((await validate(wrongSourcePath)).ok, false);

  const wrongCatalog = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
  });
  wrongCatalog.catalog.references[0].referenceName = "NOT_KEYCLOAK";
  assert.equal((await validate(wrongCatalog)).ok, false);

  const wrongFreezeCommit = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
    applicabilityVersion: "v2",
  });
  wrongFreezeCommit.frozenEvidence.evidenceFreezeCommit = "7".repeat(40);
  wrongFreezeCommit.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      wrongFreezeCommit.frozenEvidence,
    );
  assert.equal((await validate(wrongFreezeCommit)).ok, false);

  for (const [reportVersion, inputVersion] of [
    ["v1", "v2"],
    ["v2", "v1"],
  ]) {
    const crossed = await createReferenceReviewFixture({
      workPackageId: "C04",
      referenceIds: ["R09.KEYCLOAK"],
      reviewMode: "RETROSPECTIVE_BACKFILL",
      reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
      applicabilityVersion: reportVersion,
      applicabilityInputVersion: inputVersion,
    });
    assert.equal(
      (await validate(crossed)).ok,
      false,
      `${reportVersion} report with ${inputVersion} inputs`,
    );
  }

  const treeRepository = await mkdtemp(
    join(tmpdir(), "reference-review-tree-cycle-"),
  );
  try {
    execFileSync("/usr/bin/git", ["init", "-q"], {
      cwd: treeRepository,
    });
    await mkdir(join(treeRepository, "evidence"));
    const cyclePath = join(treeRepository, "evidence/input.json");
    const claimedTree = "a".repeat(40);
    await writeFile(
      cyclePath,
      `${JSON.stringify({
        inventory: { evidenceFreezeTree: claimedTree, files: [] },
      })}\n`,
    );
    execFileSync("/usr/bin/git", ["add", "evidence/input.json"], {
      cwd: treeRepository,
    });
    const firstTree = execFileSync(
      "/usr/bin/git",
      ["write-tree"],
      { cwd: treeRepository, encoding: "utf8" },
    ).trim();
    assert.notEqual(firstTree, claimedTree);
    await writeFile(
      cyclePath,
      `${JSON.stringify({
        inventory: { evidenceFreezeTree: firstTree, files: [] },
      })}\n`,
    );
    execFileSync("/usr/bin/git", ["add", "evidence/input.json"], {
      cwd: treeRepository,
    });
    const secondTree = execFileSync(
      "/usr/bin/git",
      ["write-tree"],
      { cwd: treeRepository, encoding: "utf8" },
    ).trim();
    assert.notEqual(secondTree, firstTree);
  } finally {
    await rm(treeRepository, { recursive: true, force: true });
  }

  const prospectiveV2 = await createReferenceReviewFixture({
    applicabilityVersion: "v2",
  });
  const prospectiveV2Result = await validate(prospectiveV2);
  assert.equal(prospectiveV2Result.ok, false);
  assert.ok(
    prospectiveV2Result.reasonCodes.includes(
      "REFERENCE_APPLICABILITY_NOT_PROVED",
    ),
    prospectiveV2Result.reasonCodes,
  );

  for (const workPackageId of ["O02", "O03"]) {
    const relabeledProspectiveV2 = await createReferenceReviewFixture({
      workPackageId,
      reviewMode: "RETROSPECTIVE_BACKFILL",
      reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
      applicabilityVersion: "v2",
    });
    const result = await validate(relabeledProspectiveV2);
    assert.equal(result.ok, false, workPackageId);
    assert.ok(
      result.reasonCodes.includes(
        "REFERENCE_APPLICABILITY_NOT_PROVED",
      ),
      `${workPackageId}:${result.reasonCodes.join(",")}`,
    );
  }
});

test("the frozen candidate catalog is structurally valid and remains candidate-only", async () => {
  assert.equal(
    validateCatalogSchema(frozenCatalog),
    true,
    ajv.errorsText(validateCatalogSchema.errors),
  );
  assert.equal(
    await referenceReviewBundleDigests.catalog(frozenCatalog),
    frozenPolicy.catalog.canonicalSha256,
  );
  assert.equal(
    validatePolicySchema(frozenPolicy),
    true,
    ajv.errorsText(validatePolicySchema.errors),
  );
  assert.equal(frozenCatalog.candidateOnly, true);
  assert.equal(frozenCatalog.productionAdoptionClaim, false);
  assert.ok(
    frozenCatalog.references.every(
      (reference) =>
        reference.candidateOnly === true &&
        reference.productionAdoptionClaim === false &&
        reference.versionStatus === "UNPINNED_REQUIRES_RECEIPT",
    ),
  );
  const catalogIds = new Set(
    frozenCatalog.references.map(({ referenceId }) => referenceId),
  );
  for (const workPackagePolicy of frozenPolicy.workPackagePolicies) {
    assert.deepEqual(
      workPackagePolicy.applicableReferenceIds,
      [...workPackagePolicy.applicableReferenceIds].sort(),
      workPackagePolicy.workPackageId,
    );
    assert.ok(
      workPackagePolicy.applicableReferenceIds.every((referenceId) =>
        catalogIds.has(referenceId),
      ),
      workPackagePolicy.workPackageId,
    );
  }
  assert.equal(
    frozenPolicy.profileBinding.bindingStatus,
    "REQUIRES_NEW_PROFILE_AND_EXECUTION_BASELINE",
  );
  assert.ok(
    frozenPolicy.workPackagePolicies.every(
      ({ applicabilityEvidence }) =>
        applicabilityEvidence.status === "UNPROVED",
    ),
  );
});

test("the current v2 Candidate cannot satisfy Reference Review readiness", async () => {
  const verifier = createReferenceReviewReadinessVerifier({
    catalog: frozenCatalog,
    policy: frozenPolicy,
  });

  assert.equal(
    await verifier({
      boundary: "PROFILE_APPROVAL",
      executionBaselineDigest:
        frozenPolicy.profileBinding.executionBaselineDigest,
      profileApprovalId: null,
      profileSha256: frozenPolicy.profileBinding.profileSha256,
      sourceCommit: "48a4e4eac1f2fc2404d21ca5ab9a2d014a0e20e5",
      workPackageId: null,
    }),
    false,
  );
});

test("a fully rehashed replacement Manifest cannot replace the trusted work-definition anchor", async () => {
  const trusted = await createReferenceReviewFixture({
    workPackageId: "F01",
    manifestWorkPackageIds: ["F01"],
  });
  const attacker = await createReferenceReviewFixture({
    workPackageId: "F99",
    manifestWorkPackageIds: ["F99"],
  });
  attacker.trustedBinding = {
    ...attacker.trustedBinding,
    manifestProjectId: trusted.trustedBinding.manifestProjectId,
    manifestSha256: trusted.trustedBinding.manifestSha256,
    manifestVersion: trusted.trustedBinding.manifestVersion,
    manifestWorkPackageIdsSha256:
      trusted.trustedBinding.manifestWorkPackageIdsSha256,
  };

  const result = await validate(attacker);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_TRUSTED_BINDING_INVALID",
    ),
    result.reasonCodes,
  );
});

test("an empty self-consistent Catalog and matrix cannot replace the trusted candidate-source anchor", async () => {
  const trusted = await createReferenceReviewFixture({
    workPackageId: "O02",
    referenceIds: ["R26.OPENBAO"],
  });
  const attacker = await createReferenceReviewFixture({
    workPackageId: "O02",
    referenceIds: [],
    decisions: [],
    reviewBoundary: "PRE_START",
  });
  attacker.trustedBinding = structuredClone(
    trusted.trustedBinding,
  );

  const result = await validate(attacker);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_TRUSTED_BINDING_INVALID",
    ),
    result.reasonCodes,
  );
});

test("an omitted applicable candidate is rejected", async () => {
  const fixture = await createReferenceReviewFixture({
    referenceIds: ["R26.OPENBAO", "R26.SPIRE"],
    decisions: ["ADOPT", "REJECT"],
  });
  const removed = fixture.bundle.receipts.pop();
  fixture.bundle.candidateReferenceIds.pop();
  delete fixture.receiptsByPath[removed.path];
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_CANDIDATE_SET_INCOMPLETE"),
    result.reasonCodes,
  );
});

test("a handwritten candidate set without frozen applicability evidence is rejected", async () => {
  const fixture = await createReferenceReviewFixture();
  fixture.policy.workPackagePolicies[0].applicabilityEvidence.status =
    "UNPROVED";
  await fixture.freeze();

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_APPLICABILITY_NOT_PROVED"),
    result.reasonCodes,
  );
});

test("arbitrary frozen bytes cannot masquerade as applicability coverage", async () => {
  const fixture = await createReferenceReviewFixture();
  const applicability =
    fixture.policy.workPackagePolicies[0].applicabilityEvidence;
  const [applicabilityPath] = applicability.evidenceRefs;
  const attackerBytes = new TextEncoder().encode("x");
  const attackerHash =
    await referenceReviewBundleDigests.bytes(attackerBytes);
  applicability.evidenceHashes = [attackerHash];
  const policySha256 =
    await referenceReviewBundleDigests.policy(fixture.policy);
  fixture.bundle.referencePolicySha256 = policySha256;
  fixture.bundle.applicableReferenceSetDigest =
    await referenceReviewBundleDigests.applicableSet({
      workPackageId: fixture.bundle.workPackageId,
      applicableReferenceIds:
        fixture.policy.workPackagePolicies[0]
          .applicableReferenceIds,
      referenceCatalogSha256:
        fixture.bundle.referenceCatalogSha256,
      referencePolicySha256: policySha256,
    });
  for (const entry of fixture.bundle.receipts) {
    const receipt = fixture.receiptsByPath[entry.path];
    receipt.referencePolicySha256 = policySha256;
    receipt.applicableReferenceSetDigest =
      fixture.bundle.applicableReferenceSetDigest;
    receipt.receiptSha256 =
      await referenceReviewDigests.receipt(receipt);
    entry.sha256 = receipt.receiptSha256;
  }
  await rehashAndFreeze(fixture);
  fixture.frozenEvidence.evidenceSubjects.find(
    ({ path }) => path === applicabilityPath,
  ).sha256 = attackerHash;
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );
  const originalReadGitBytes = fixture.readGitBytes;

  const result = await validateReferenceReviewBundle({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundle: fixture.bundle,
    receiptsByPath: fixture.receiptsByPath,
    expectedBinding: fixture.expectedBinding,
    trustedBinding: fixture.trustedBinding,
    frozenEvidence: fixture.frozenEvidence,
    selectedToolLocks: fixture.selectedToolLocks,
    readGitBytes: async ({ commit, path }) =>
      path === applicabilityPath
        ? structuredClone(attackerBytes)
        : originalReadGitBytes({ commit, path }),
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_APPLICABILITY_NOT_PROVED",
    ),
    result.reasonCodes,
  );
});

for (const scanKind of [
  "DEPENDENCY_LOCK_SCAN",
  "MANUAL_SUPPLEMENT",
  "REFERENCE_MATRIX",
  "SOURCE_INTEGRATION_SCAN",
]) {
  test(`${scanKind} rejects arbitrary frozen input bytes even when every digest is recomputed`, async () => {
    const fixture = await createReferenceReviewFixture();
    const attack =
      await replaceApplicabilityScanInputWithArbitraryBytes(
        fixture,
        scanKind,
      );

    const result = await validateWith({
      fixture,
      readGitBytes: attack.readGitBytes,
      verifyFreezeRoot: async () => true,
    });

    assert.equal(result.ok, false);
    assert.ok(
      result.reasonCodes.includes(
        "REFERENCE_APPLICABILITY_NOT_PROVED",
      ),
      result.reasonCodes,
    );
  });
}

test("SOURCE_INTEGRATION_SCAN rejects arbitrary source bytes after the entire frozen chain is recomputed", async () => {
  const fixture = await createReferenceReviewFixture();
  const attack = await replaceFrozenSourceIntegrationBytes(
    fixture,
    new TextEncoder().encode("x"),
  );

  const result = await validateWith({
    fixture,
    readGitBytes: attack.readGitBytes,
    verifyFreezeRoot: async () => true,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_APPLICABILITY_NOT_PROVED",
    ),
    result.reasonCodes,
  );
});

for (const [label, replacementBytes] of [
  [
    "a marker identity that differs from the frozen index",
    sourceIntegrationBytes({ identifier: "SPIRE" }),
  ],
  [
    "an official URI that differs from the frozen index",
    sourceIntegrationBytes({
      officialSourceUri: "https://example.invalid/r26_spire",
    }),
  ],
  [
    "an integration kind that differs from the frozen index",
    sourceIntegrationBytes({ integrationKind: "API_CLIENT" }),
  ],
  [
    "duplicate integration markers",
    sourceIntegrationBytes({ duplicateMarker: true }),
  ],
  ["invalid UTF-8", new Uint8Array([0xff])],
]) {
  test(`SOURCE_INTEGRATION_SCAN rejects ${label} after the entire frozen chain is recomputed`, async () => {
    const fixture = await createReferenceReviewFixture();
    const attack = await replaceFrozenSourceIntegrationBytes(
      fixture,
      replacementBytes,
    );

    const result = await validateWith({
      fixture,
      readGitBytes: attack.readGitBytes,
      verifyFreezeRoot: async () => true,
    });

    assert.equal(result.ok, false);
    assert.ok(
      result.reasonCodes.includes(
        "REFERENCE_APPLICABILITY_NOT_PROVED",
      ),
      result.reasonCodes,
    );
  });
}

test("SOURCE_INTEGRATION_SCAN rejects an unindexed frozen integration marker", async () => {
  const fixture = await createReferenceReviewFixture();
  const hiddenPath =
    "synthetic/applicability/source/O02/R26.SPIRE.mjs";
  const hiddenBytes = sourceIntegrationBytes({
    identifier: "SPIRE",
    officialSourceUri: "https://example.invalid/r26_spire",
  });
  const hiddenHash =
    await referenceReviewBundleDigests.bytes(hiddenBytes);
  fixture.frozenEvidence.evidenceSubjects.push({
    path: hiddenPath,
    sha256: hiddenHash,
  });
  fixture.frozenEvidence.evidenceSubjects.sort((left, right) =>
    left.path === right.path ? 0 : left.path < right.path ? -1 : 1,
  );
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );
  const originalReadGitBytes = fixture.readGitBytes;

  const result = await validateWith({
    fixture,
    readGitBytes: ({ commit, path }) =>
      path === hiddenPath
        ? structuredClone(hiddenBytes)
        : originalReadGitBytes({ commit, path }),
    verifyFreezeRoot: async () => true,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_APPLICABILITY_NOT_PROVED",
    ),
    result.reasonCodes,
  );
});

test("the trusted freeze-tree enumeration rejects a root marker omitted from Attestation subjects", async () => {
  const fixture = await createReferenceReviewFixture();
  const hiddenPath =
    "synthetic/applicability/source/O02/hidden-spire.mjs";
  let hiddenReads = 0;
  const sourcePaths = await fixture.listFrozenPaths({
    evidenceFreezeCommit:
      fixture.frozenEvidence.evidenceFreezeCommit,
    evidenceFreezeTree: fixture.frozenEvidence.evidenceFreezeTree,
    sourceRoots:
      fixture.policy.workPackagePolicies[0].applicabilityEvidence
        .sourceRoots,
    sourceExclusions: [],
  });

  const result = await validateWith({
    fixture,
    readGitBytes: ({ commit, path }) => {
      if (path === hiddenPath) {
        hiddenReads += 1;
        return sourceIntegrationBytes({
          identifier: "SPIRE",
          officialSourceUri: "https://example.invalid/r26_spire",
        });
      }
      return fixture.readGitBytes({ commit, path });
    },
    listFrozenPaths: async () =>
      [...sourcePaths, hiddenPath].sort(),
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_FREEZE_ROOT_PATH_SET_MISMATCH",
    ),
    result.reasonCodes,
  );
  assert.equal(hiddenReads, 0);
});

test("the freeze Attestation rejects every unconsumed evidence subject", async () => {
  const fixture = await createReferenceReviewFixture();
  const hiddenPath = "synthetic/unconsumed-evidence.txt";
  const hiddenBytes = new TextEncoder().encode("unconsumed");
  fixture.frozenEvidence.evidenceSubjects.push({
    path: hiddenPath,
    sha256: await referenceReviewBundleDigests.bytes(hiddenBytes),
  });
  fixture.frozenEvidence.evidenceSubjects.sort((left, right) =>
    left.path === right.path ? 0 : left.path < right.path ? -1 : 1,
  );
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );
  const originalReadGitBytes = fixture.readGitBytes;

  const result = await validateWith({
    fixture,
    readGitBytes: ({ commit, path }) =>
      path === hiddenPath
        ? structuredClone(hiddenBytes)
        : originalReadGitBytes({ commit, path }),
    verifyFreezeRoot: async () => true,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_FREEZE_SUBJECT_SET_MISMATCH",
    ),
    result.reasonCodes,
  );
});

test("an unknown candidate is rejected", async () => {
  const fixture = await createReferenceReviewFixture();
  fixture.bundle.candidateReferenceIds[0] = "R26.UNKNOWN";
  fixture.bundle.receipts[0].referenceId = "R26.UNKNOWN";
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_UNKNOWN_CANDIDATE"),
    result.reasonCodes,
  );
});

test("a source that is not in the frozen official catalog is rejected", async () => {
  const fixture = await createReferenceReviewFixture();
  const entry = fixture.bundle.receipts[0];
  const receipt = fixture.receiptsByPath[entry.path];
  receipt.officialSources[0].uri =
    "https://unofficial.example.invalid/repackaged-docs";
  receipt.receiptSha256 =
    await referenceReviewDigests.receipt(receipt);
  entry.sha256 = receipt.receiptSha256;
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_OFFICIAL_SOURCE_NOT_CATALOGED",
    ),
    result.reasonCodes,
  );
});

test("Receipt and Bundle hash tampering is rejected", async () => {
  const receiptTamper = await createReferenceReviewFixture();
  const [path] = Object.keys(receiptTamper.receiptsByPath);
  receiptTamper.receiptsByPath[path].decisionReason = "tampered";
  await receiptTamper.freeze();
  const bundleTamper = await createReferenceReviewFixture();
  bundleTamper.bundle.zeroSetReason = "tampered";
  await bundleTamper.freeze();

  assert.ok(
    (await validate(receiptTamper)).reasonCodes.includes(
      "REFERENCE_RECEIPT_HASH_MISMATCH",
    ),
  );
  assert.ok(
    (await validate(bundleTamper)).reasonCodes.includes(
      "REFERENCE_BUNDLE_HASH_MISMATCH",
    ),
  );
});

test("Git-frozen evidence must match the exact commit-bound JSON", async () => {
  const fixture = await createReferenceReviewFixture();
  const readGitBytes = async ({ commit, path }) =>
    commit === fixture.frozenEvidence.evidenceFreezeCommit &&
    path === fixture.bundle.bundlePath
      ? new TextEncoder().encode(
          JSON.stringify({
            ...fixture.bundle,
            bundleId: "rrb_wrong_frozen_bytes",
          }),
        )
      : fixture.readGitBytes({ commit, path });

  const result = await validateReferenceReviewBundle({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundle: fixture.bundle,
    receiptsByPath: fixture.receiptsByPath,
    expectedBinding: fixture.expectedBinding,
    trustedBinding: fixture.trustedBinding,
    frozenEvidence: fixture.frozenEvidence,
    readGitBytes,
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_GIT_EVIDENCE_NOT_FROZEN"),
    result.reasonCodes,
  );
});

test("Git evidence freeze uses a later external commit and rejects a missing commit", async () => {
  const fixture = await createReferenceReviewFixture();

  assert.notEqual(
    fixture.frozenEvidence.evidenceFreezeCommit,
    fixture.bundle.sourceCommit,
  );
  assert.equal((await validate(fixture)).ok, true);

  fixture.frozenEvidence.evidenceFreezeCommit = "f".repeat(40);
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );
  const result = await validate(fixture);
  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_GIT_EVIDENCE_NOT_FROZEN"),
    result.reasonCodes,
  );
});

test("a legal but incorrect evidenceFreezeTree is rejected after all Attestation digests are recomputed", async () => {
  const fixture = await createReferenceReviewFixture();
  fixture.frozenEvidence.evidenceFreezeTree = "f".repeat(40);
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );

  const result = await validateWith({
    fixture,
    verifyFreezeRoot: async ({ evidenceFreezeTree }) =>
      evidenceFreezeTree === "a".repeat(40),
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_FREEZE_ATTESTATION_INVALID",
    ),
    result.reasonCodes,
  );
});

test("a nonexistent freeze commit is rejected even when a byte resolver serves matching content", async () => {
  const fixture = await createReferenceReviewFixture();
  const originalCommit =
    fixture.frozenEvidence.evidenceFreezeCommit;
  const missingCommit = "f".repeat(40);
  fixture.frozenEvidence.evidenceFreezeCommit = missingCommit;
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );

  const result = await validateWith({
    fixture,
    readGitBytes: ({ commit, path }) =>
      commit === missingCommit
        ? fixture.readGitBytes({
            commit: originalCommit,
            path,
          })
        : null,
    verifyFreezeRoot: async ({ evidenceFreezeCommit }) =>
      evidenceFreezeCommit === originalCommit,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_FREEZE_ATTESTATION_INVALID",
    ),
    result.reasonCodes,
  );
});

test("Attestation cycle flags cannot replace trusted source-to-freeze ancestry proof", async () => {
  const fixture = await createReferenceReviewFixture();

  const result = await validateWith({
    fixture,
    verifyFreezeRoot: async () => false,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_FREEZE_ATTESTATION_INVALID",
    ),
    result.reasonCodes,
  );
});

test("every Receipt, applicability and implementation evidence ref is byte-verified", async () => {
  const fixture = await createReferenceReviewFixture({
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const entry = fixture.bundle.receipts[0];
  const receipt = fixture.receiptsByPath[entry.path];
  receipt.capabilityGap.evidenceRef = "synthetic/missing-gap.json";
  receipt.capabilityGap.evidenceHash = `sha256:${"a".repeat(64)}`;
  receipt.currentImplementation.evidenceRefs = [
    "synthetic/missing-current.json",
  ];
  receipt.currentImplementation.evidenceHashes = [
    `sha256:${"b".repeat(64)}`,
  ];
  receipt.pocResult.evidenceRefs = ["synthetic/missing-poc.json"];
  receipt.pocResult.evidenceHashes = [`sha256:${"c".repeat(64)}`];
  receipt.evidenceRefs = ["synthetic/missing-review.json"];
  receipt.evidenceHashes = [`sha256:${"d".repeat(64)}`];
  receipt.receiptSha256 =
    await referenceReviewDigests.receipt(receipt);
  entry.sha256 = receipt.receiptSha256;
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_GIT_EVIDENCE_NOT_FROZEN"),
    result.reasonCodes,
  );
});

test("Catalog PoC policy cannot be downgraded by an ADOPT Receipt", async () => {
  const fixture = await createReferenceReviewFixture();
  const entry = fixture.bundle.receipts[0];
  const receipt = fixture.receiptsByPath[entry.path];
  receipt.pocRequired = false;
  receipt.pocResult = {
    status: "NOT_REQUIRED",
    summary: "Attacker-controlled downgrade.",
    evidenceRefs: [],
    evidenceHashes: [],
  };
  receipt.receiptSha256 =
    await referenceReviewDigests.receipt(receipt);
  entry.sha256 = receipt.receiptSha256;
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_ADOPT_POC_POLICY_MISMATCH",
    ),
    result.reasonCodes,
  );
});

test("candidate catalog, Profile and source commit drift make old evidence STALE", async () => {
  const catalogDrift = await createReferenceReviewFixture();
  catalogDrift.catalog.references[0].referenceName = "Changed candidate";
  const profileDrift = await createReferenceReviewFixture();
  profileDrift.expectedBinding.profileSha256 =
    `sha256:${"9".repeat(64)}`;
  const sourceDrift = await createReferenceReviewFixture();
  sourceDrift.expectedBinding.sourceCommit = "9".repeat(40);

  const catalogResult = await validate(catalogDrift);
  const profileResult = await validate(profileDrift);
  const sourceResult = await validate(sourceDrift);

  assert.equal(catalogResult.status, "STALE");
  assert.ok(catalogResult.reasonCodes.includes("REFERENCE_CATALOG_STALE"));
  assert.equal(profileResult.status, "STALE");
  assert.ok(
    profileResult.reasonCodes.includes("REFERENCE_BASELINE_BINDING_STALE"),
  );
  assert.equal(sourceResult.status, "STALE");
  assert.ok(
    sourceResult.reasonCodes.includes("REFERENCE_BASELINE_BINDING_STALE"),
  );
});

test("an adopted version change makes the old Receipt STALE", async () => {
  const fixture = await createReferenceReviewFixture();
  fixture.bundle.receipts[0].adoptedArtifactDigest =
    `sha256:${"f".repeat(64)}`;
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.status, "STALE");
  assert.ok(
    result.reasonCodes.includes("REFERENCE_ADOPTED_VERSION_STALE"),
    result.reasonCodes,
  );
});

test("DEFER becomes STALE at or after its mandatory re-review boundary", async () => {
  const fixture = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    decisions: ["DEFER"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.equal(result.status, "STALE");
  assert.ok(
    result.reasonCodes.includes("REFERENCE_DEFER_REVIEW_STALE"),
    result.reasonCodes,
  );
});

test("an explicitly empty applicable set does not block unrelated work", async () => {
  const fixture = await createReferenceReviewFixture({
    workPackageId: "T08",
    referenceIds: [],
    decisions: [],
    reviewBoundary: "PRE_START",
  });

  assert.equal((await validate(fixture)).ok, true);
});

test("a frozen implementation conformance record passes its closed schema and semantics", async () => {
  const fixture = await createReferenceReviewFixture({
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const [binding] = fixture.bundle.implementationBindings;
  const record = JSON.parse(
    new TextDecoder().decode(
      await fixture.readGitBytes({
        commit: fixture.frozenEvidence.evidenceFreezeCommit,
        path: binding.evidenceRef,
      }),
    ),
  );

  assert.equal(
    validateImplementationConformanceSchema(record),
    true,
    ajv.errorsText(validateImplementationConformanceSchema.errors),
  );
  assert.equal((await validate(fixture)).ok, true);
});

test("IMPLEMENTATION_CONFORMANCE rejects implementation that diverges from ADOPT", async () => {
  const fixture = await createReferenceReviewFixture({
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  fixture.bundle.implementationBindings[0].artifactDigest =
    `sha256:${"f".repeat(64)}`;
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_IMPLEMENTATION_DIVERGES_FROM_DECISION",
    ),
    result.reasonCodes,
  );
});

test("implementation digest must equal the Bundle approved digest, not another material pin", async () => {
  const fixture = await createReferenceReviewFixture({
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const entry = fixture.bundle.receipts[0];
  const receipt = fixture.receiptsByPath[entry.path];
  const otherPinnedDigest = `sha256:${"b".repeat(64)}`;
  receipt.reviewedMaterials[0].imageDigest = otherPinnedDigest;
  receipt.receiptSha256 =
    await referenceReviewDigests.receipt(receipt);
  entry.sha256 = receipt.receiptSha256;
  fixture.bundle.implementationBindings[0].artifactDigest =
    otherPinnedDigest;
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_IMPLEMENTATION_DIVERGES_FROM_DECISION",
    ),
    result.reasonCodes,
  );
});

test("IMPLEMENTATION_CONFORMANCE rejects arbitrary frozen evidence bytes after the chain is recomputed", async () => {
  const fixture = await createReferenceReviewFixture({
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const [binding] = fixture.bundle.implementationBindings;
  const attackerBytes = new TextEncoder().encode("x");
  const attackerHash =
    await referenceReviewBundleDigests.bytes(attackerBytes);
  binding.evidenceHash = attackerHash;
  await rehashAndFreeze(fixture);
  fixture.frozenEvidence.evidenceSubjects.find(
    ({ path }) => path === binding.evidenceRef,
  ).sha256 = attackerHash;
  fixture.frozenEvidence.attestationSha256 =
    await referenceReviewBundleDigests.freezeAttestation(
      fixture.frozenEvidence,
    );
  const originalReadGitBytes = fixture.readGitBytes;

  const result = await validateWith({
    fixture,
    readGitBytes: ({ commit, path }) =>
      path === binding.evidenceRef
        ? structuredClone(attackerBytes)
        : originalReadGitBytes({ commit, path }),
    verifyFreezeRoot: async () => true,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_IMPLEMENTATION_EVIDENCE_INVALID",
    ),
    result.reasonCodes,
  );
});

test("IMPLEMENTATION_CONFORMANCE rejects an actual dependency pin that differs from the ADOPT decision", async () => {
  const fixture = await createReferenceReviewFixture({
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const attack = await replaceFrozenDependencyLockDigest(
    fixture,
    `sha256:${"f".repeat(64)}`,
  );

  const result = await validateWith({
    fixture,
    readGitBytes: attack.readGitBytes,
    verifyFreezeRoot: async () => true,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_ACTUAL_PIN_MISMATCH"),
    result.reasonCodes,
  );
});

test("IMPLEMENTATION_CONFORMANCE rejects a fully rehashed dependency pin that diverges from ADOPT without a tool-lock domain", async () => {
  const fixture = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    decisions: ["ADOPT"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const attack = await replaceFrozenDependencyLockDigest(
    fixture,
    `sha256:${"f".repeat(64)}`,
    { syncImplementationEvidence: true },
  );

  const result = await validateWith({
    fixture,
    readGitBytes: attack.readGitBytes,
    verifyFreezeRoot: async () => true,
  });

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_ACTUAL_PIN_MISMATCH"),
    result.reasonCodes,
  );
});

test("IMPLEMENTATION_CONFORMANCE rejects a non-adopted integration found in frozen inputs", async () => {
  const fixture = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    decisions: ["REJECT"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_NON_ADOPT_IMPLEMENTATION_PRESENT",
    ),
    result.reasonCodes,
  );
});

test("Profile retrospective backfill requires IMPLEMENTATION_CONFORMANCE", async () => {
  const fixture = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    decisions: ["ADOPT"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "PRE_START",
  });
  const verifier = createReferenceReviewReadinessVerifier({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundlesByWorkPackage: { C04: fixture.bundle },
    receiptsByPath: fixture.receiptsByPath,
    frozenEvidence: fixture.frozenEvidence,
    trustedBinding: fixture.trustedBinding,
    readGitBytes: fixture.readGitBytes,
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });

  assert.equal(
    await verifier({
      ...fixture.verifierBinding,
      boundary: "PROFILE_APPROVAL",
      profileApprovalId: null,
      workPackageId: null,
    }),
    false,
  );
});

test("Profile backfill validates each work package against its own exact-closure Attestation", async () => {
  const manifestWorkPackageIds = ["C04", "C06"];
  const catalogReferenceIds = [
    "R09.KEYCLOAK",
    "R11.OPENFGA",
  ];
  const c04 = await createReferenceReviewFixture({
    workPackageId: "C04",
    manifestWorkPackageIds,
    referenceIds: ["R09.KEYCLOAK"],
    catalogReferenceIds,
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const c06 = await createReferenceReviewFixture({
    workPackageId: "C06",
    manifestWorkPackageIds,
    referenceIds: ["R11.OPENFGA"],
    catalogReferenceIds,
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  await bindSharedProfilePolicy([c04, c06]);
  const fixtures = [c04, c06];
  const readGitBytes = async (request) => {
    for (const fixture of fixtures) {
      const bytes = await fixture.readGitBytes(request);
      if (bytes !== null) return bytes;
    }
    return null;
  };
  const verifyFreezeRoot = async (binding) => {
    for (const fixture of fixtures) {
      if (await fixture.verifyFreezeRoot(binding)) return true;
    }
    return false;
  };
  const listFrozenPaths = async (binding) => {
    const paths = new Set();
    for (const fixture of fixtures) {
      for (const path of
        (await fixture.listFrozenPaths(binding)) ?? []) {
        paths.add(path);
      }
    }
    return [...paths].sort();
  };
  const verifier = createReferenceReviewReadinessVerifier({
    manifest: c04.manifest,
    catalog: c04.catalog,
    policy: c04.policy,
    bundlesByWorkPackage: {
      C04: c04.bundle,
      C06: c06.bundle,
    },
    receiptsByPath: {
      ...c04.receiptsByPath,
      ...c06.receiptsByPath,
    },
    frozenEvidenceByWorkPackage: {
      C04: c04.frozenEvidence,
      C06: c06.frozenEvidence,
    },
    trustedBinding: c04.trustedBinding,
    readGitBytes,
    verifyFreezeRoot,
    listFrozenPaths,
  });
  const legacyVerifier =
    createReferenceReviewReadinessVerifier({
      manifest: c04.manifest,
      catalog: c04.catalog,
      policy: c04.policy,
      bundlesByWorkPackage: {
        C04: c04.bundle,
        C06: c06.bundle,
      },
      receiptsByPath: {
        ...c04.receiptsByPath,
        ...c06.receiptsByPath,
      },
      frozenEvidence: c04.frozenEvidence,
      trustedBinding: c04.trustedBinding,
      readGitBytes,
      verifyFreezeRoot,
      listFrozenPaths,
    });
  const reusedAttestationVerifier =
    createReferenceReviewReadinessVerifier({
      manifest: c04.manifest,
      catalog: c04.catalog,
      policy: c04.policy,
      bundlesByWorkPackage: {
        C04: c04.bundle,
        C06: c06.bundle,
      },
      receiptsByPath: {
        ...c04.receiptsByPath,
        ...c06.receiptsByPath,
      },
      frozenEvidenceByWorkPackage: {
        C04: c04.frozenEvidence,
        C06: c04.frozenEvidence,
      },
      trustedBinding: c04.trustedBinding,
      readGitBytes,
      verifyFreezeRoot,
      listFrozenPaths,
    });
  const binding = {
    ...c04.verifierBinding,
    boundary: "PROFILE_APPROVAL",
    profileApprovalId: null,
    workPackageId: null,
  };

  assert.equal(
    (await validateWith({ fixture: c04 })).ok,
    true,
  );
  assert.equal(
    (await validateWith({ fixture: c06 })).ok,
    true,
  );
  assert.equal(await verifier(binding), true);
  assert.equal(await legacyVerifier(binding), false);
  assert.equal(await reusedAttestationVerifier(binding), false);
});

test("Profile backfill rejects a Policy work package that is absent from the Manifest", async () => {
  const fixture = await createReferenceReviewFixture({
    workPackageId: "F99",
    manifestWorkPackageIds: ["F01"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const verifier = createReferenceReviewReadinessVerifier({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundlesByWorkPackage: { F99: fixture.bundle },
    receiptsByPath: fixture.receiptsByPath,
    frozenEvidence: fixture.frozenEvidence,
    trustedBinding: fixture.trustedBinding,
    selectedToolLocks: fixture.selectedToolLocks,
    readGitBytes: fixture.readGitBytes,
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });

  assert.equal(
    await verifier({
      ...fixture.verifierBinding,
      boundary: "PROFILE_APPROVAL",
      profileApprovalId: null,
      workPackageId: null,
    }),
    false,
  );
});

test("a Bundle stored under another work-package key cannot satisfy Profile backfill", async () => {
  const fixture = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    reviewMode: "RETROSPECTIVE_BACKFILL",
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  });
  const wrongBundle = structuredClone(fixture.bundle);
  wrongBundle.workPackageId = "C06";
  const verifier = createReferenceReviewReadinessVerifier({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundlesByWorkPackage: { C04: wrongBundle },
    receiptsByPath: fixture.receiptsByPath,
    frozenEvidence: fixture.frozenEvidence,
    trustedBinding: fixture.trustedBinding,
    selectedToolLocks: fixture.selectedToolLocks,
    readGitBytes: fixture.readGitBytes,
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });

  assert.equal(
    await verifier({
      ...fixture.verifierBinding,
      boundary: "PROFILE_APPROVAL",
      profileApprovalId: null,
      workPackageId: null,
    }),
    false,
  );
});

test("dependency adoption must bind each Profile tool lock to an ADOPT Receipt", async () => {
  const fixture = await createReferenceReviewFixture({
    decisions: ["REJECT"],
  });
  const verifier = createReferenceReviewReadinessVerifier({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundlesByWorkPackage: { O02: fixture.bundle },
    receiptsByPath: fixture.receiptsByPath,
    frozenEvidence: fixture.frozenEvidence,
    trustedBinding: fixture.trustedBinding,
    selectedToolLocks: fixture.selectedToolLocks,
    readGitBytes: fixture.readGitBytes,
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });

  assert.equal(await verifier(fixture.verifierBinding), false);
});

test("DEPENDENCY_ADOPTION rejects a frozen dependency and source integration for a REJECT decision", async () => {
  const fixture = await createReferenceReviewFixture({
    workPackageId: "C04",
    referenceIds: ["R09.KEYCLOAK"],
    decisions: ["REJECT"],
    reviewBoundary: "DEPENDENCY_ADOPTION",
  });

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes(
      "REFERENCE_NON_ADOPT_IMPLEMENTATION_PRESENT",
    ),
    result.reasonCodes,
  );
});

test("the readiness verifier is default-deny unless the frozen binding is complete", async () => {
  const fixture = await createReferenceReviewFixture();
  const verifier = createReferenceReviewReadinessVerifier({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: fixture.policy,
    bundlesByWorkPackage: {
      O02: fixture.bundle,
    },
    receiptsByPath: fixture.receiptsByPath,
    frozenEvidence: fixture.frozenEvidence,
    trustedBinding: fixture.trustedBinding,
    selectedToolLocks: fixture.selectedToolLocks,
    readGitBytes: fixture.readGitBytes,
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });

  assert.equal(await verifier(fixture.verifierBinding), true);
  assert.equal(
    await verifier({
      ...fixture.verifierBinding,
      sourceCommit: "9".repeat(40),
    }),
    false,
  );
  const unboundPolicy = structuredClone(fixture.policy);
  unboundPolicy.profileBinding.bindingStatus =
    "REQUIRES_NEW_PROFILE_AND_EXECUTION_BASELINE";
  const unboundVerifier = createReferenceReviewReadinessVerifier({
    manifest: fixture.manifest,
    catalog: fixture.catalog,
    policy: unboundPolicy,
    bundlesByWorkPackage: {
      O02: fixture.bundle,
    },
    receiptsByPath: fixture.receiptsByPath,
    frozenEvidence: fixture.frozenEvidence,
    trustedBinding: fixture.trustedBinding,
    selectedToolLocks: fixture.selectedToolLocks,
    readGitBytes: fixture.readGitBytes,
    verifyFreezeRoot: fixture.verifyFreezeRoot,
    listFrozenPaths: fixture.listFrozenPaths,
  });
  assert.equal(await unboundVerifier(fixture.verifierBinding), false);
  const missingTreeEnumeration =
    createReferenceReviewReadinessVerifier({
      manifest: fixture.manifest,
      catalog: fixture.catalog,
      policy: fixture.policy,
      bundlesByWorkPackage: { O02: fixture.bundle },
      receiptsByPath: fixture.receiptsByPath,
      frozenEvidence: fixture.frozenEvidence,
      trustedBinding: fixture.trustedBinding,
      selectedToolLocks: fixture.selectedToolLocks,
      readGitBytes: fixture.readGitBytes,
      verifyFreezeRoot: fixture.verifyFreezeRoot,
    });
  const missingTrustedBinding =
    createReferenceReviewReadinessVerifier({
      manifest: fixture.manifest,
      catalog: fixture.catalog,
      policy: fixture.policy,
      bundlesByWorkPackage: { O02: fixture.bundle },
      receiptsByPath: fixture.receiptsByPath,
      frozenEvidence: fixture.frozenEvidence,
      selectedToolLocks: fixture.selectedToolLocks,
      readGitBytes: fixture.readGitBytes,
      verifyFreezeRoot: fixture.verifyFreezeRoot,
      listFrozenPaths: fixture.listFrozenPaths,
    });
  assert.equal(
    await missingTreeEnumeration(fixture.verifierBinding),
    false,
  );
  assert.equal(
    await missingTrustedBinding(fixture.verifierBinding),
    false,
  );
});

test("closed schemas reject caller-supplied READY or governance state", async () => {
  const fixture = await createReferenceReviewFixture();
  fixture.catalog.ready = true;
  fixture.bundle.startAuthorized = true;

  assert.equal(validateCatalogSchema(fixture.catalog), false);
  assert.equal(validateBundleSchema(fixture.bundle), false);
});

test("the runtime Bundle validator rejects nested caller-owned state", async () => {
  const fixture = await createReferenceReviewFixture();
  fixture.bundle.receipts[0].callerReady = true;
  await rehashAndFreeze(fixture);

  const result = await validate(fixture);

  assert.equal(result.ok, false);
  assert.ok(
    result.reasonCodes.includes("REFERENCE_BUNDLE_INVALID"),
    result.reasonCodes,
  );
});
