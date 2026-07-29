import {
  referenceReviewDigests,
} from "../lib/reference-review-receipt-validator.mjs";
import {
  referenceReviewBundleDigests,
} from "../lib/reference-review-readiness.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;
const PROFILE_SHA256 = digest("d");
const EXECUTION_BASELINE_DIGEST = digest("8");
const SOURCE_COMMIT = "8".repeat(40);
const FREEZE_COMMIT = "9".repeat(40);
const FREEZE_TREE = "a".repeat(40);
const sortedBy = (items, keyFor) =>
  [...items].sort((left, right) => {
    const leftKey = keyFor(left);
    const rightKey = keyFor(right);
    return leftKey === rightKey ? 0 : leftKey < rightKey ? -1 : 1;
  });

function toolLockDomains(referenceId) {
  if (referenceId === "R26.OPENBAO") {
    return ["O02_SECRETS_SYSTEM"];
  }
  if (referenceId === "R26.SPIRE") {
    return ["O02_WORKLOAD_IDENTITY"];
  }
  return [];
}

function catalogReference(referenceId) {
  const slug = referenceId.toLowerCase().replaceAll(".", "_");
  return {
    referenceId,
    referenceKind: "OPEN_SOURCE_PROJECT",
    referenceName: referenceId.split(".").at(-1),
    matrixReferenceId: referenceId.split(".")[0],
    officialSources: [
      {
        sourceId: `src_${slug}`,
        uri: `https://example.invalid/${slug}`,
        sourceKind: "OFFICIAL_DOCUMENTATION",
      },
    ],
    applicableToolLockDomains: toolLockDomains(referenceId),
    pocRequirement: "REQUIRED_FOR_ADOPT",
    versionStatus: "UNPINNED_REQUIRES_RECEIPT",
    candidateOnly: true,
    productionAdoptionClaim: false,
  };
}

function basePolicy({
  catalogSha256,
  manifestSha256,
  candidateSourceBaselineRef,
  candidateSourceBaselineHash,
  catalogReferenceIds,
  workPackageId,
  applicableReferenceIds,
  requiredToolLockDomains,
  applicabilityEvidenceRef,
  applicabilityEvidenceHash,
  reviewMode,
}) {
  return {
    schemaVersion: "reference-review-policy.v1",
    policyId: "rrp_synthetic_reference_review",
    policyPath: "synthetic/reference-policy.json",
    authorityBoundaries: {
      workDefinition: "WORK_PACKAGE_MANIFEST_V1",
      governanceState: "ONLINE_D1_APPEND_ONLY_GOVERNANCE_LEDGER",
      engineeringEvidence: "GIT_FROZEN_EVIDENCE",
      createsSecondStateTruth: false,
    },
    catalog: {
      path: "synthetic/reference-catalog.json",
      canonicalSha256: catalogSha256,
      coverage: "INITIAL_P0_P1_BACKFILL_AND_P2_O02_O03",
      uncoveredWorkPackagesFailClosed: true,
    },
    manifest: {
      path: "synthetic/work-package-manifest.json",
      canonicalSha256: manifestSha256,
    },
    candidateSourceBaseline: {
      path: candidateSourceBaselineRef,
      sha256: candidateSourceBaselineHash,
      catalogReferenceIds: [...catalogReferenceIds],
    },
    profileBinding: {
      profileSha256: PROFILE_SHA256,
      sourceCommit: SOURCE_COMMIT,
      executionBaselineDigest: EXECUTION_BASELINE_DIGEST,
      bindingStatus: "BOUND_IN_PROFILE_AND_EXECUTION_BASELINE",
      requiredBackfillWorkPackageIds:
        reviewMode === "RETROSPECTIVE_BACKFILL"
          ? [workPackageId]
          : [],
    },
    workPackagePolicies: [
      {
        workPackageId,
        reviewMode,
        applicableReferenceIds: [...applicableReferenceIds],
        requiredToolLockDomains: [...requiredToolLockDomains],
        applicabilityEvidence: {
          status: "COMPLETE",
          evidenceRefs: [applicabilityEvidenceRef],
          evidenceHashes: [applicabilityEvidenceHash],
          sourceRoots: [
            `synthetic/applicability/source/${workPackageId}`,
          ],
          sourceExclusions: [],
        },
        requiredBefore:
          reviewMode === "RETROSPECTIVE_BACKFILL"
            ? "PROFILE_APPROVAL"
            : "START_AUTHORIZATION",
      },
    ],
    boundaryRules: [
      {
        boundary: "PRE_START",
        requirement: "Synthetic candidate identification and review.",
      },
      {
        boundary: "DEPENDENCY_ADOPTION",
        requirement: "Synthetic adoption evidence.",
      },
      {
        boundary: "IMPLEMENTATION_CONFORMANCE",
        requirement: "Synthetic implementation conformance.",
      },
      {
        boundary: "RELEASE",
        requirement: "Synthetic O03 release review.",
      },
    ],
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
  };
}

async function receiptFor({
  reference,
  workPackageId,
  reviewMode,
  reviewBoundary,
  applicableReferenceSetDigest,
  referenceCatalogSha256,
  referencePolicySha256,
  decision,
  index,
  putEvidence,
}) {
  const source = reference.officialSources[0];
  const slug = reference.referenceId
    .toLowerCase()
    .replaceAll(".", "_");
  const artifactDigest = digest(String((index + 1) % 10));
  const sourceEvidenceRef = `synthetic/evidence/${slug}-source.txt`;
  const sourceContentSha256 = await putEvidence(
    sourceEvidenceRef,
    `official source bytes for ${reference.referenceId}`,
  );
  const notesRef = `synthetic/evidence/${slug}-notes.txt`;
  const notesDigest = await putEvidence(
    notesRef,
    `review notes for ${reference.referenceId}`,
  );
  const gapRef = `synthetic/evidence/${slug}-gap.json`;
  const gapHash = await putEvidence(
    gapRef,
    JSON.stringify({ gap: reference.referenceId }),
  );
  const currentRef = `synthetic/evidence/${slug}-current.json`;
  const currentHash = await putEvidence(
    currentRef,
    JSON.stringify({ current: reference.referenceId }),
  );
  const reviewRef = `synthetic/evidence/${slug}-review.json`;
  const reviewHash = await putEvidence(
    reviewRef,
    JSON.stringify({ review: reference.referenceId }),
  );
  const pocRef =
    decision === "ADOPT"
      ? `synthetic/evidence/${slug}-poc.json`
      : null;
  const pocHash =
    decision === "ADOPT"
      ? await putEvidence(
          pocRef,
          JSON.stringify({
            poc: reference.referenceId,
            status: "PASS",
          }),
        )
      : null;
  const adrRef =
    decision === "ADOPT"
      ? "docs/adr/0006-reference-review-before-work-start.md"
      : null;
  const adrHash =
    decision === "ADOPT"
      ? await putEvidence(
          adrRef,
          "# Synthetic ADR\n\nReference Review test fixture.\n",
        )
      : null;
  const receipt = {
    schemaVersion: "reference-review-receipt.v1",
    receiptId: `rrr_${workPackageId.toLowerCase()}_${slug}_${decision.toLowerCase()}`,
    workPackageId,
    reviewMode,
    reviewBoundary,
    applicableReferenceSetDigest,
    referenceCatalogSha256,
    referencePolicySha256,
    profileSha256: PROFILE_SHA256,
    referenceId: reference.referenceId,
    referenceKind: reference.referenceKind,
    referenceName: reference.referenceName,
    officialSources: [
      {
        ...source,
        authority: reference.referenceName,
        observedAt: "2026-07-29T01:00:00.000Z",
        contentEvidenceRef: sourceEvidenceRef,
        contentSha256: sourceContentSha256,
      },
    ],
    reviewedMaterials: [
      {
        materialId: `mat_${slug}`,
        sourceId: source.sourceId,
        materialKind: "RELEASE",
        documentationVersion: "synthetic-v1",
        sourceCommit: "1".repeat(40),
        release: "synthetic-v1.0.0",
        imageDigest: null,
        artifactDigest,
      },
    ],
    reviewedSections: [
      {
        sourceId: source.sourceId,
        locator: "synthetic/official/section",
        topic: "Synthetic capability and boundary review",
        notesRef,
        notesDigest,
      },
    ],
    reviewedAt: "2026-07-29T01:10:00.000Z",
    capabilityGap: {
      summary: "A synthetic capability gap is fixed for this test.",
      currentMeasure: "The synthetic baseline does not provide the capability.",
      targetMeasure: "The synthetic boundary requires the capability.",
      evidenceRef: gapRef,
      evidenceHash: gapHash,
    },
    currentImplementation: {
      status: "CANDIDATE",
      summary: "The synthetic implementation has no production adoption.",
      evidenceRefs: [currentRef],
      evidenceHashes: [currentHash],
    },
    alternativesCompared: [
      {
        alternativeId: "alt_current_synthetic",
        name: "Current synthetic implementation",
        kind: "CURRENT_IMPLEMENTATION",
        versionOrStandard: "synthetic-baseline",
        advantages: ["No new dependency."],
        risks: ["Capability gap remains."],
        disposition: decision === "ADOPT" ? "FALLBACK" : "SELECTED",
      },
      {
        alternativeId: `alt_${slug}`,
        name: reference.referenceName,
        kind: reference.referenceKind,
        versionOrStandard: "synthetic-v1.0.0",
        advantages: ["Closes the synthetic capability gap."],
        risks: ["Adds a synthetic operational dependency."],
        disposition: decision === "ADOPT" ? "SELECTED" : "NOT_SELECTED",
      },
    ],
    licenseAndRedistributionAssessment: {
      licenseId: "MIT",
      licenseSourceId: source.sourceId,
      reviewedVersion: "synthetic-v1.0.0",
      usageMode: "SYNTHETIC_TEST",
      distributionMode: "NOT_DISTRIBUTED",
      obligations: ["Preserve the synthetic notice."],
      brandRestrictions: [],
      commercialRestrictions: [],
      conclusion: "ACCEPTABLE",
      rationale: "The synthetic fixture models a completed license review.",
    },
    securityAndDataFlowAssessment: {
      dataClasses: ["SYNTHETIC"],
      ingress: ["synthetic input"],
      egress: ["synthetic output"],
      storage: ["synthetic isolated state"],
      networkAccess: ["none"],
      privileges: ["unprivileged"],
      secretHandling: ["no secret"],
      trustBoundaries: ["synthetic test boundary"],
      knownRisks: ["fixture drift"],
      conclusion: "ACCEPTABLE",
      rationale: "The synthetic fixture models a completed security review.",
    },
    maintenanceAndExitAssessment: {
      operationalOwnerRole: "SYNTHETIC_OWNER",
      upstreamHealth: "Synthetic release monitoring.",
      upgradeCadence: "Synthetic release cadence.",
      onCallResponsibility: "Synthetic owner.",
      backupAndRecoveryResponsibility: "Synthetic owner.",
      costResponsibility: "Synthetic budget.",
      exitPlanStatus: "DEFINED",
      exitPlan: "Remove the synthetic adapter.",
      migrationTarget: "Current synthetic implementation.",
      stopMaintenanceTrigger: "Synthetic upstream becomes unavailable.",
    },
    decision,
    decisionReason: "The synthetic decision follows the fixed comparison.",
    alternativePath:
      decision === "REJECT"
        ? "Retain the current synthetic implementation."
        : null,
    reReviewTrigger:
      decision === "DEFER"
        ? {
            triggerKind: "CAPABILITY_GAP_REACHED",
            condition: "Re-review before synthetic dependency adoption.",
            beforeBoundary: "DEPENDENCY_ADOPTION",
          }
        : null,
    notApplicableReason:
      decision === "NOT_APPLICABLE"
        ? "The synthetic variant does not use this capability."
        : null,
    pocRequired: decision === "ADOPT",
    pocResult:
      decision === "ADOPT"
        ? {
            status: "PASS",
            summary: "The fixed synthetic PoC passed.",
            evidenceRefs: [pocRef],
            evidenceHashes: [pocHash],
          }
        : {
            status: "NOT_REQUIRED",
            summary: "The fixed decision does not require a PoC.",
            evidenceRefs: [],
            evidenceHashes: [],
          },
    adrRef,
    ownerRole: "SYNTHETIC_OWNER",
    evidenceRefs:
      decision === "ADOPT" ? [adrRef, reviewRef] : [reviewRef],
    evidenceHashes:
      decision === "ADOPT" ? [adrHash, reviewHash] : [reviewHash],
    sourceCommit: SOURCE_COMMIT,
    supersedesReceiptId: null,
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    productionAdoptionClaim: false,
    receiptSha256: digest("0"),
  };
  receipt.receiptSha256 =
    await referenceReviewDigests.receipt(receipt);
  return { receipt, artifactDigest };
}

export async function createReferenceReviewFixture({
  workPackageId = "O02",
  manifestWorkPackageIds = [workPackageId],
  referenceIds = ["R26.OPENBAO"],
  catalogReferenceIds = referenceIds,
  decisions = ["ADOPT"],
  reviewMode = "PROSPECTIVE",
  reviewBoundary = "DEPENDENCY_ADOPTION",
} = {}) {
  const frozenBytes = new Map();
  const putEvidence = async (path, content) => {
    const bytes = new TextEncoder().encode(content);
    frozenBytes.set(path, bytes);
    return referenceReviewBundleDigests.bytes(bytes);
  };
  const manifest = {
    manifest_version: "1.0.0",
    project_id: "synthetic-reference-review",
    work_packages: [...manifestWorkPackageIds]
      .sort()
      .map((id) => ({ id })),
  };
  const manifestSha256 =
    await referenceReviewDigests.value(manifest);
  const sortedReferenceIds = [...referenceIds].sort();
  const sortedCatalogReferenceIds =
    [...catalogReferenceIds].sort();
  const catalog = {
    schemaVersion: "reference-candidate-catalog.v1",
    catalogId: "rrc_synthetic_reference_candidates",
    catalogScope: "INITIAL_P0_P1_BACKFILL_AND_P2_O02_O03",
    candidateOnly: true,
    productionAdoptionClaim: false,
    references: sortedCatalogReferenceIds.map(catalogReference),
  };
  const applicableReferences = sortedReferenceIds.map(
    (referenceId) =>
      catalog.references.find(
        (reference) => reference.referenceId === referenceId,
      ),
  );
  if (applicableReferences.some((reference) => !reference)) {
    throw new TypeError(
      "Every applicable reference must exist in the synthetic Catalog.",
    );
  }
  const catalogSha256 =
    await referenceReviewBundleDigests.catalog(catalog);
  const candidateSourceBaselineRef =
    "synthetic/reference-source-baseline.json";
  const candidateSourceBaselineHash = await putEvidence(
    candidateSourceBaselineRef,
    JSON.stringify({
      schemaVersion: "synthetic-reference-source-baseline.v1",
      catalogReferenceIds: [...sortedCatalogReferenceIds],
    }),
  );
  const requiredToolLockDomains = [
    ...new Set(
      applicableReferences.flatMap(
        ({ applicableToolLockDomains }) =>
          applicableToolLockDomains,
      ),
    ),
  ].sort();
  const applicabilityScans = [];
  const dependencyPins = new Map();
  const sourceIntegrations = new Map();
  for (const scanKind of [
    "DEPENDENCY_LOCK_SCAN",
    "MANUAL_SUPPLEMENT",
    "REFERENCE_MATRIX",
    "SOURCE_INTEGRATION_SCAN",
  ]) {
    const scanMethod = {
      DEPENDENCY_LOCK_SCAN:
        "deterministic-dependency-lock-parser",
      MANUAL_SUPPLEMENT:
        "deterministic-manual-supplement-parser",
      REFERENCE_MATRIX:
        "deterministic-reference-matrix-parser",
      SOURCE_INTEGRATION_SCAN:
        "deterministic-source-integration-parser",
    }[scanKind];
    const inputRef =
      `synthetic/applicability/inputs/${workPackageId}-${scanKind.toLowerCase()}.json`;
    const inputHeader = {
      workPackageId,
      sourceCommit: SOURCE_COMMIT,
      referenceCatalogSha256: catalogSha256,
      scanKind,
      governanceEffect: "NONE",
      isProgressTracker: false,
      selfAuthorizing: false,
      productionAdoptionClaim: false,
    };
    let input;
    if (scanKind === "DEPENDENCY_LOCK_SCAN") {
      const lockRef =
        `synthetic/applicability/inventory/${workPackageId}-dependency-lock.json`;
      const dependencies = sortedBy(
        applicableReferences.map((reference, index) => ({
          packageName: reference.referenceName,
          resolvedUri: reference.officialSources[0].uri,
          version: "synthetic-v1.0.0",
          artifactDigest: digest(String((index + 1) % 10)),
          toolLockDomain:
            reference.applicableToolLockDomains[0] ?? null,
        })),
        ({ packageName, resolvedUri, toolLockDomain }) =>
          `${packageName}\n${resolvedUri}\n${toolLockDomain ?? ""}`,
      );
      const lockHash = await putEvidence(
        lockRef,
        JSON.stringify({
          schemaVersion: "reference-dependency-lock.v1",
          workPackageId,
          dependencies,
        }),
      );
      for (const dependency of dependencies) {
        const reference = catalog.references.find(
          ({ referenceName, officialSources }) =>
            referenceName === dependency.packageName &&
            officialSources.some(
              ({ uri }) => uri === dependency.resolvedUri,
            ),
        );
        dependencyPins.set(reference.referenceId, {
          version: dependency.version,
          artifactDigest: dependency.artifactDigest,
          toolLockDomain: dependency.toolLockDomain,
          evidenceRef: lockRef,
          evidenceHash: lockHash,
        });
      }
      input = {
        schemaVersion:
          "reference-dependency-lock-scan-input.v1",
        ...inputHeader,
        inventory: {
          evidenceFreezeTree: FREEZE_TREE,
          files: [
            {
              path: lockRef,
              sha256: lockHash,
              format: "PROJECT_TOOL_LOCK_V1",
            },
          ],
        },
      };
    } else if (scanKind === "MANUAL_SUPPLEMENT") {
      input = {
        schemaVersion: "reference-manual-supplement-input.v1",
        ...inputHeader,
        reviewerRole: "REFERENCE_REVIEWER",
        reviewedAt: "2026-07-29T01:15:00.000Z",
        scopeStatement:
          "Review candidate sources outside deterministic scans.",
        observations: sortedBy(
          await Promise.all(
            applicableReferences.map(async (reference) => {
              const referenceId = reference.referenceId;
              const officialSourceUri =
                reference.officialSources[0].uri;
              const evidenceRef =
                `synthetic/applicability/manual/${workPackageId}-${referenceId}.txt`;
              return {
                officialSourceUri,
                relevance: "APPLICABLE",
                reason:
                  "Synthetic manual review confirms applicability.",
                evidenceRef,
                evidenceHash: await putEvidence(
                  evidenceRef,
                  `manual applicability evidence for ${referenceId}`,
                ),
              };
            }),
          ),
          ({ officialSourceUri }) => officialSourceUri,
        ),
      };
    } else if (scanKind === "REFERENCE_MATRIX") {
      const matrixRef =
        `synthetic/applicability/matrix/${workPackageId}.json`;
      const findings = sortedBy(
        applicableReferences.map((reference) => ({
          matrixReferenceId: reference.matrixReferenceId,
          referenceName: reference.referenceName,
          officialSourceUri: reference.officialSources[0].uri,
        })),
        ({
          matrixReferenceId,
          officialSourceUri,
          referenceName,
        }) =>
          `${matrixReferenceId}\n${referenceName}\n${officialSourceUri}`,
      );
      const matrixHash = await putEvidence(
        matrixRef,
        JSON.stringify({
          schemaVersion: "reference-matrix-slice.v1",
          workPackageId,
          findings,
        }),
      );
      input = {
        schemaVersion: "reference-matrix-scan-input.v1",
        ...inputHeader,
        matrix: {
          path: matrixRef,
          sha256: matrixHash,
          format: "REFERENCE_MATRIX_SLICE_V1",
        },
      };
    } else {
      const integrations = sortedBy(
        await Promise.all(
          applicableReferences.map(async (reference) => {
            const referenceId = reference.referenceId;
            const sourcePath =
              `synthetic/applicability/source/${workPackageId}/${referenceId}.mjs`;
            const integrationKind = "RUNTIME_PLUGIN";
            const marker = {
              schemaVersion: "reference-integration-marker.v1",
              identifier: reference.referenceName,
              officialSourceUri: reference.officialSources[0].uri,
              integrationKind,
            };
            return {
              identifier: reference.referenceName,
              officialSourceUri: reference.officialSources[0].uri,
              integrationKind,
              sourceFormat: "REFERENCE_INTEGRATION_MARKER_V1",
              sourcePath,
              sourceHash: await putEvidence(
                sourcePath,
                `// @reference-integration-v1 ${JSON.stringify(marker)}\nexport const reference = ${JSON.stringify(reference.referenceName)};\n`,
              ),
            };
          }),
        ),
        ({ identifier, officialSourceUri, sourcePath }) =>
          `${identifier}\n${officialSourceUri}\n${sourcePath}`,
      );
      const integrationRef =
        `synthetic/applicability/inventory/${workPackageId}-source-integrations.json`;
      const integrationHash = await putEvidence(
        integrationRef,
        JSON.stringify({
          schemaVersion:
            "reference-source-integration-index.v1",
          workPackageId,
          integrations,
        }),
      );
      for (const integration of integrations) {
        const reference = catalog.references.find(
          ({ referenceName, officialSources }) =>
            referenceName === integration.identifier &&
            officialSources.some(
              ({ uri }) => uri === integration.officialSourceUri,
            ),
        );
        sourceIntegrations.set(reference.referenceId, {
          identifier: integration.identifier,
          officialSourceUri: integration.officialSourceUri,
          integrationKind: integration.integrationKind,
          sourcePath: integration.sourcePath,
          sourceHash: integration.sourceHash,
        });
      }
      input = {
        schemaVersion:
          "reference-source-integration-scan-input.v1",
        ...inputHeader,
        inventory: {
          evidenceFreezeTree: FREEZE_TREE,
          files: [
            {
              path: integrationRef,
              sha256: integrationHash,
              format:
                "REFERENCE_SOURCE_INTEGRATION_INDEX_V1",
            },
          ],
        },
      };
    }
    const inputHash = await putEvidence(
      inputRef,
      JSON.stringify(input),
    );
    applicabilityScans.push({
      scanKind,
      method: scanMethod,
      methodVersion: "v1",
      inputRefs: [inputRef],
      inputHashes: [inputHash],
      discoveredReferenceIds: [...sortedReferenceIds],
      result: "COMPLETE",
    });
  }
  const applicabilityEvidenceRef =
    `synthetic/applicability/${workPackageId}.json`;
  const applicabilityReport = {
    schemaVersion: "reference-applicability-evidence.v1",
    workPackageId,
    sourceCommit: SOURCE_COMMIT,
    candidateReferenceIds: [...sortedReferenceIds],
    scans: applicabilityScans,
    reviewedAt: "2026-07-29T01:20:00.000Z",
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    productionAdoptionClaim: false,
    reportSha256: digest("0"),
  };
  applicabilityReport.reportSha256 =
    await referenceReviewBundleDigests.applicabilityReport(
      applicabilityReport,
    );
  const applicabilityEvidenceHash = await putEvidence(
    applicabilityEvidenceRef,
    JSON.stringify(applicabilityReport),
  );
  const policy = basePolicy({
    catalogSha256,
    manifestSha256,
    candidateSourceBaselineRef,
    candidateSourceBaselineHash,
    catalogReferenceIds: sortedCatalogReferenceIds,
    workPackageId,
    applicableReferenceIds: sortedReferenceIds,
    requiredToolLockDomains,
    applicabilityEvidenceRef,
    applicabilityEvidenceHash,
    reviewMode,
  });
  const policySha256 =
    await referenceReviewBundleDigests.policy(policy);
  const trustedBinding = {
    candidateSourceBaselineSha256:
      candidateSourceBaselineHash,
    manifestProjectId: manifest.project_id,
    manifestSha256,
    manifestVersion: manifest.manifest_version,
    manifestWorkPackageIdsSha256:
      await referenceReviewDigests.value(
        [...manifestWorkPackageIds].sort(),
      ),
    referenceCatalogSha256: catalogSha256,
    referencePolicySha256: policySha256,
  };
  const applicableReferenceSetDigest =
    await referenceReviewBundleDigests.applicableSet({
      workPackageId,
      applicableReferenceIds: sortedReferenceIds,
      referenceCatalogSha256: catalogSha256,
      referencePolicySha256: policySha256,
    });
  const receiptsByPath = {};
  const entries = [];
  for (const [index, reference] of applicableReferences.entries()) {
    const decision = decisions[index] ?? "REJECT";
    const { receipt, artifactDigest } = await receiptFor({
      reference,
      workPackageId,
      reviewMode,
      reviewBoundary,
      applicableReferenceSetDigest,
      referenceCatalogSha256: catalogSha256,
      referencePolicySha256: policySha256,
      decision,
      index,
      putEvidence,
    });
    const path = `synthetic/receipts/${reference.referenceId}.json`;
    receiptsByPath[path] = receipt;
    entries.push({
      referenceId: reference.referenceId,
      path,
      sha256: receipt.receiptSha256,
      decision,
      adoptedArtifactDigest:
        decision === "ADOPT" ? artifactDigest : null,
    });
  }
  const selectedToolLocks = [];
  const dependencyBindings = [];
  if (
    ["DEPENDENCY_ADOPTION", "IMPLEMENTATION_CONFORMANCE"].includes(
      reviewBoundary,
    )
  ) {
    for (const domain of requiredToolLockDomains) {
      const reference = catalog.references.find(
        (candidate, index) =>
          candidate.applicableToolLockDomains.includes(domain) &&
          entries[index]?.decision === "ADOPT",
      );
      if (!reference) continue;
      const entry = entries.find(
        ({ referenceId }) => referenceId === reference.referenceId,
      );
      selectedToolLocks.push({
        domain,
        selection: "SELECTED",
        referenceId: reference.referenceId,
        version: "synthetic-v1.0.0",
        sha256: entry.adoptedArtifactDigest,
      });
      dependencyBindings.push({
        domain,
        referenceId: reference.referenceId,
        version: "synthetic-v1.0.0",
        artifactDigest: entry.adoptedArtifactDigest,
      });
    }
  }
  const implementationBindings =
    reviewBoundary === "IMPLEMENTATION_CONFORMANCE"
      ? await Promise.all(
          entries
            .filter(({ decision }) => decision === "ADOPT")
            .map(async (entry) => {
              const evidenceRef =
                `synthetic/implementation/${entry.referenceId}.json`;
              const evidenceHash = await putEvidence(
                evidenceRef,
                JSON.stringify({
                  schemaVersion:
                    "reference-implementation-conformance.v1",
                  workPackageId,
                  sourceCommit: SOURCE_COMMIT,
                  referenceId: entry.referenceId,
                  artifactDigest: entry.adoptedArtifactDigest,
                  dependencyLock:
                    dependencyPins.get(entry.referenceId) ?? null,
                  sourceIntegration:
                    sourceIntegrations.get(entry.referenceId) ?? null,
                  governanceEffect: "NONE",
                  isProgressTracker: false,
                  selfAuthorizing: false,
                  productionAdoptionClaim: false,
                }),
              );
              return {
                referenceId: entry.referenceId,
                artifactDigest: entry.adoptedArtifactDigest,
                evidenceRef,
                evidenceHash,
              };
            }),
        )
      : [];
  const bundle = {
    schemaVersion: "reference-review-bundle.v1",
    bundleId: `rrb_${workPackageId.toLowerCase()}_synthetic_review`,
    bundlePath: `synthetic/bundles/${workPackageId}.json`,
    workPackageId,
    reviewMode,
    reviewBoundary,
    applicableReferenceSetDigest,
    referenceCatalogSha256: catalogSha256,
    referencePolicySha256: policySha256,
    profileSha256: PROFILE_SHA256,
    sourceCommit: SOURCE_COMMIT,
    executionBaselineDigest: EXECUTION_BASELINE_DIGEST,
    candidateReferenceIds: [...sortedReferenceIds],
    receipts: entries,
    zeroSetReason:
      sortedReferenceIds.length === 0
        ? "The frozen policy explicitly has no applicable candidate."
        : null,
    dependencyBindings,
    implementationBindings,
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    productionAdoptionClaim: false,
    bundleSha256: digest("0"),
  };
  bundle.bundleSha256 =
    await referenceReviewBundleDigests.bundle(bundle);
  const frozenEvidence = {
    schemaVersion: "reference-review-freeze-attestation.v1",
    attestationId:
      `rrfa_${workPackageId.toLowerCase()}_synthetic_review`,
    evidenceFreezeCommit: FREEZE_COMMIT,
    evidenceFreezeTree: FREEZE_TREE,
    sourceCommit: SOURCE_COMMIT,
    profileSha256: PROFILE_SHA256,
    executionBaselineDigest: EXECUTION_BASELINE_DIGEST,
    referenceCatalogSha256: catalogSha256,
    referencePolicySha256: policySha256,
    bundleSubjects: [],
    evidenceSubjects: [],
    upstreamProfileIncludesReferenceReviewDigests: false,
    upstreamExecutionBaselineIncludesReferenceReviewDigests: false,
    attestationIncludedInEvidenceFreeze: false,
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    attestationSha256: digest("0"),
  };
  const freeze = async () => {
    const jsonValues = new Map([
      [policy.manifest.path, manifest],
      [policy.catalog.path, catalog],
      [policy.policyPath, policy],
      [bundle.bundlePath, bundle],
      ...Object.entries(receiptsByPath),
    ]);
    for (const [path, value] of jsonValues) {
      frozenBytes.set(
        path,
        new TextEncoder().encode(JSON.stringify(value)),
      );
    }
    frozenEvidence.referenceCatalogSha256 =
      await referenceReviewBundleDigests.catalog(catalog);
    frozenEvidence.referencePolicySha256 =
      await referenceReviewBundleDigests.policy(policy);
    frozenEvidence.profileSha256 = bundle.profileSha256;
    frozenEvidence.executionBaselineDigest =
      bundle.executionBaselineDigest;
    frozenEvidence.sourceCommit = bundle.sourceCommit;
    frozenEvidence.bundleSubjects = [
      {
        workPackageId: bundle.workPackageId,
        path: bundle.bundlePath,
        sha256: bundle.bundleSha256,
      },
    ];
    frozenEvidence.evidenceSubjects = await Promise.all(
      [...frozenBytes.entries()]
        .sort(([left], [right]) =>
          left === right ? 0 : left < right ? -1 : 1,
        )
        .map(async ([path, bytes]) => ({
          path,
          sha256:
            await referenceReviewBundleDigests.bytes(bytes),
        })),
    );
    frozenEvidence.attestationSha256 =
      await referenceReviewBundleDigests.freezeAttestation(
        frozenEvidence,
      );
  };
  await freeze();
  return {
    manifest,
    catalog,
    policy,
    bundle,
    receiptsByPath,
    frozenEvidence,
    trustedBinding,
    selectedToolLocks,
    freeze,
    readGitBytes: async ({ commit, path }) =>
      commit === FREEZE_COMMIT
        ? structuredClone(frozenBytes.get(path) ?? null)
        : null,
    verifyFreezeRoot: async ({
      evidenceFreezeCommit,
      evidenceFreezeTree,
      sourceCommit,
      evidenceSubjectsSha256,
      manifestSha256: actualManifestSha256,
      sourceRoots,
      sourceExclusions,
    }) =>
      evidenceFreezeCommit === FREEZE_COMMIT &&
      evidenceFreezeTree === FREEZE_TREE &&
      sourceCommit === SOURCE_COMMIT &&
      evidenceSubjectsSha256 ===
        (await referenceReviewDigests.value(
          frozenEvidence.evidenceSubjects,
        )) &&
      actualManifestSha256 ===
        (await referenceReviewDigests.value(manifest)) &&
      policy.workPackagePolicies.some(
        ({ applicabilityEvidence }) =>
          referenceReviewDigests.canonicalize(sourceRoots) ===
            referenceReviewDigests.canonicalize(
              applicabilityEvidence.sourceRoots,
            ) &&
          referenceReviewDigests.canonicalize(
            sourceExclusions,
          ) ===
            referenceReviewDigests.canonicalize(
              applicabilityEvidence.sourceExclusions,
            ),
      ),
    listFrozenPaths: async ({
      evidenceFreezeCommit,
      evidenceFreezeTree,
      sourceRoots,
      sourceExclusions,
    }) =>
      evidenceFreezeCommit === FREEZE_COMMIT &&
      evidenceFreezeTree === FREEZE_TREE
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
        : null,
    expectedBinding: {
      profileSha256: PROFILE_SHA256,
      sourceCommit: SOURCE_COMMIT,
      executionBaselineDigest: EXECUTION_BASELINE_DIGEST,
      reviewBoundary,
    },
    verifierBinding: {
      boundary: reviewBoundary,
      executionBaselineDigest: EXECUTION_BASELINE_DIGEST,
      profileApprovalId: "p2pa_synthetic_profile_approval",
      profileSha256: PROFILE_SHA256,
      sourceCommit: SOURCE_COMMIT,
      workPackageId,
    },
  };
}
