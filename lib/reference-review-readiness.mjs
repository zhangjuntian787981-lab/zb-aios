import catalogSchema from "../implementation/governance/schemas/reference-candidate-catalog.v1.schema.json" with { type: "json" };
import applicabilityEvidenceSchema from "../implementation/governance/schemas/reference-applicability-evidence.v1.schema.json" with { type: "json" };
import bundleSchema from "../implementation/governance/schemas/reference-review-bundle.v1.schema.json" with { type: "json" };
import freezeAttestationSchema from "../implementation/governance/schemas/reference-review-freeze-attestation.v1.schema.json" with { type: "json" };
import implementationConformanceSchema from "../implementation/governance/schemas/reference-implementation-conformance.v1.schema.json" with { type: "json" };
import policySchema from "../implementation/governance/schemas/reference-review-policy.v1.schema.json" with { type: "json" };
import {
  referenceReviewDigests,
  validateReferenceReviewReceipt,
  validateReferenceReviewSchema,
} from "./reference-review-receipt-validator.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const RECEIPT_BOUNDARY_ORDER = Object.freeze({
  PRE_START: 0,
  DEPENDENCY_ADOPTION: 1,
  IMPLEMENTATION_CONFORMANCE: 2,
  RELEASE: 3,
});
const APPLICABILITY_SCAN_KINDS = Object.freeze([
  "DEPENDENCY_LOCK_SCAN",
  "MANUAL_SUPPLEMENT",
  "REFERENCE_MATRIX",
  "SOURCE_INTEGRATION_SCAN",
]);
const APPLICABILITY_SCAN_METHODS = Object.freeze({
  DEPENDENCY_LOCK_SCAN: Object.freeze({
    method: "deterministic-dependency-lock-parser",
    methodVersion: "v1",
  }),
  MANUAL_SUPPLEMENT: Object.freeze({
    method: "deterministic-manual-supplement-parser",
    methodVersion: "v1",
  }),
  REFERENCE_MATRIX: Object.freeze({
    method: "deterministic-reference-matrix-parser",
    methodVersion: "v1",
  }),
  SOURCE_INTEGRATION_SCAN: Object.freeze({
    method: "deterministic-source-integration-parser",
    methodVersion: "v1",
  }),
});
const SOURCE_INTEGRATION_KINDS = Object.freeze([
  "API_CLIENT",
  "BUILD_PLUGIN",
  "IMAGE",
  "IMPORT",
  "RUNTIME_PLUGIN",
  "SERVICE_ENDPOINT",
]);
const SOURCE_INTEGRATION_MARKER_PREFIX =
  "// @reference-integration-v1 ";
const SOURCE_INTEGRATION_MARKER_KEYS = Object.freeze([
  "identifier",
  "integrationKind",
  "officialSourceUri",
  "schemaVersion",
]);
const BUNDLE_KEYS = Object.freeze([
  "applicableReferenceSetDigest",
  "bundleId",
  "bundlePath",
  "bundleSha256",
  "candidateReferenceIds",
  "dependencyBindings",
  "executionBaselineDigest",
  "governanceEffect",
  "implementationBindings",
  "isProgressTracker",
  "productionAdoptionClaim",
  "profileSha256",
  "receipts",
  "referenceCatalogSha256",
  "referencePolicySha256",
  "reviewBoundary",
  "reviewMode",
  "schemaVersion",
  "selfAuthorizing",
  "sourceCommit",
  "workPackageId",
  "zeroSetReason",
]);
const POLICY_KEYS = Object.freeze([
  "authorityBoundaries",
  "boundaryRules",
  "candidateSourceBaseline",
  "catalog",
  "governanceEffect",
  "isProgressTracker",
  "manifest",
  "policyId",
  "policyPath",
  "profileBinding",
  "schemaVersion",
  "selfAuthorizing",
  "workPackagePolicies",
]);
const VERIFY_BINDING_KEYS = Object.freeze([
  "boundary",
  "executionBaselineDigest",
  "profileApprovalId",
  "profileSha256",
  "sourceCommit",
  "workPackageId",
]);
const TRUSTED_BINDING_KEYS = Object.freeze([
  "candidateSourceBaselineSha256",
  "manifestProjectId",
  "manifestSha256",
  "manifestVersion",
  "manifestWorkPackageIdsSha256",
  "referenceCatalogSha256",
  "referencePolicySha256",
]);
const FROZEN_EVIDENCE_KEYS = Object.freeze([
  "attestationId",
  "attestationIncludedInEvidenceFreeze",
  "attestationSha256",
  "bundleSubjects",
  "evidenceFreezeCommit",
  "evidenceFreezeTree",
  "evidenceSubjects",
  "executionBaselineDigest",
  "governanceEffect",
  "isProgressTracker",
  "profileSha256",
  "referenceCatalogSha256",
  "referencePolicySha256",
  "schemaVersion",
  "selfAuthorizing",
  "sourceCommit",
  "upstreamExecutionBaselineIncludesReferenceReviewDigests",
  "upstreamProfileIncludesReferenceReviewDigests",
]);
const SCAN_INPUT_KEYS = Object.freeze({
  DEPENDENCY_LOCK_SCAN: Object.freeze([
    "governanceEffect",
    "inventory",
    "isProgressTracker",
    "productionAdoptionClaim",
    "referenceCatalogSha256",
    "scanKind",
    "schemaVersion",
    "selfAuthorizing",
    "sourceCommit",
    "workPackageId",
  ]),
  MANUAL_SUPPLEMENT: Object.freeze([
    "governanceEffect",
    "isProgressTracker",
    "observations",
    "productionAdoptionClaim",
    "referenceCatalogSha256",
    "reviewedAt",
    "reviewerRole",
    "scanKind",
    "schemaVersion",
    "scopeStatement",
    "selfAuthorizing",
    "sourceCommit",
    "workPackageId",
  ]),
  REFERENCE_MATRIX: Object.freeze([
    "governanceEffect",
    "isProgressTracker",
    "matrix",
    "productionAdoptionClaim",
    "referenceCatalogSha256",
    "scanKind",
    "schemaVersion",
    "selfAuthorizing",
    "sourceCommit",
    "workPackageId",
  ]),
  SOURCE_INTEGRATION_SCAN: Object.freeze([
    "governanceEffect",
    "inventory",
    "isProgressTracker",
    "productionAdoptionClaim",
    "referenceCatalogSha256",
    "scanKind",
    "schemaVersion",
    "selfAuthorizing",
    "sourceCommit",
    "workPackageId",
  ]),
});
const validateApplicabilityEvidenceSchema = (value) =>
  validateReferenceReviewSchema(applicabilityEvidenceSchema, value);
const validateCatalogSchema = (value) =>
  validateReferenceReviewSchema(catalogSchema, value);
const validateBundleSchema = (value) =>
  validateReferenceReviewSchema(bundleSchema, value);
const validateFreezeAttestationSchema = (value) =>
  validateReferenceReviewSchema(freezeAttestationSchema, value);
const validateImplementationConformanceSchema = (value) =>
  validateReferenceReviewSchema(implementationConformanceSchema, value);
const validatePolicySchema = (value) =>
  validateReferenceReviewSchema(policySchema, value);

function keysExactly(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

function sortedUniqueStrings(value) {
  return (
    Array.isArray(value) &&
    value.every(
      (item, index) =>
        typeof item === "string" &&
        item.length > 0 &&
        value.indexOf(item) === index,
    ) &&
    [...value].sort().every((item, index) => item === value[index])
  );
}

function matchingEvidenceArrays(refs, hashes) {
  return (
    Array.isArray(refs) &&
    Array.isArray(hashes) &&
    refs.length === hashes.length &&
    refs.every((path) => safePath(path)) &&
    hashes.every((hash) => SHA256.test(hash))
  );
}

function safePath(path) {
  return (
    typeof path === "string" &&
    path.length > 0 &&
    !path.startsWith("/") &&
    !path.includes("\\") &&
    !path.split("/").includes("..")
  );
}

function pathWithin(path, root) {
  return path === root || path.startsWith(`${root}/`);
}

function manifestWorkPackageIds(manifest) {
  if (
    !manifest ||
    typeof manifest !== "object" ||
    Array.isArray(manifest) ||
    typeof manifest.manifest_version !== "string" ||
    typeof manifest.project_id !== "string" ||
    !Array.isArray(manifest.work_packages)
  ) {
    return null;
  }
  const ids = manifest.work_packages.map(({ id } = {}) => id);
  return sortedUniqueStrings([...ids].sort()) &&
    ids.every((id) => /^(F|C|O|T)[0-9]{2}$/.test(id))
    ? new Set(ids)
    : null;
}

function requiredProfileBackfillIds(policy) {
  return (policy?.workPackagePolicies ?? [])
    .filter(
      ({ reviewMode, requiredBefore }) =>
        reviewMode === "RETROSPECTIVE_BACKFILL" &&
        requiredBefore === "PROFILE_APPROVAL",
    )
    .map(({ workPackageId }) => workPackageId)
    .sort();
}

async function trustedBindingMatches({
  trustedBinding,
  manifest,
  manifestIds,
  actualManifestSha256,
  actualCatalogSha256,
  actualPolicySha256,
  policy,
}) {
  if (
    !keysExactly(trustedBinding, TRUSTED_BINDING_KEYS) ||
    !SHA256.test(
      trustedBinding?.candidateSourceBaselineSha256 ?? "",
    ) ||
    !SHA256.test(trustedBinding?.manifestSha256 ?? "") ||
    !SHA256.test(
      trustedBinding?.manifestWorkPackageIdsSha256 ?? "",
    ) ||
    !SHA256.test(
      trustedBinding?.referenceCatalogSha256 ?? "",
    ) ||
    !SHA256.test(
      trustedBinding?.referencePolicySha256 ?? "",
    ) ||
    manifestIds === null
  ) {
    return false;
  }
  const workPackageIds = [...manifestIds].sort();
  return (
    trustedBinding.manifestProjectId === manifest.project_id &&
    trustedBinding.manifestVersion === manifest.manifest_version &&
    trustedBinding.manifestSha256 === actualManifestSha256 &&
    trustedBinding.manifestWorkPackageIdsSha256 ===
      (await referenceReviewDigests.value(workPackageIds)) &&
    trustedBinding.referenceCatalogSha256 ===
      actualCatalogSha256 &&
    trustedBinding.referencePolicySha256 === actualPolicySha256 &&
    trustedBinding.candidateSourceBaselineSha256 ===
      policy?.candidateSourceBaseline?.sha256
  );
}

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

async function bundleDigest(bundle) {
  return referenceReviewDigests.value(
    withoutField(bundle, "bundleSha256"),
  );
}

async function policyDigest(policy) {
  return referenceReviewDigests.value(policy);
}

async function catalogDigest(catalog) {
  return referenceReviewDigests.value(catalog);
}

async function applicableSetDigest({
  workPackageId,
  applicableReferenceIds,
  referenceCatalogSha256,
  referencePolicySha256,
}) {
  return referenceReviewDigests.value({
    workPackageId,
    applicableReferenceIds,
    referenceCatalogSha256,
    referencePolicySha256,
  });
}

async function applicabilityReportDigest(report) {
  return referenceReviewDigests.value(
    withoutField(report, "reportSha256"),
  );
}

async function freezeAttestationDigest(attestation) {
  return referenceReviewDigests.value(
    withoutField(attestation, "attestationSha256"),
  );
}

async function byteDigest(value) {
  const bytes =
    typeof value === "string"
      ? new TextEncoder().encode(value)
      : value instanceof Uint8Array
        ? value
        : value instanceof ArrayBuffer
          ? new Uint8Array(value)
          : ArrayBuffer.isView(value)
            ? new Uint8Array(
                value.buffer,
                value.byteOffset,
                value.byteLength,
              )
            : null;
  if (!bytes) return null;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return `sha256:${Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
}

function parseJsonBytes(value) {
  try {
    const bytes =
      typeof value === "string"
        ? new TextEncoder().encode(value)
        : value instanceof Uint8Array
          ? value
          : value instanceof ArrayBuffer
            ? new Uint8Array(value)
            : ArrayBuffer.isView(value)
              ? new Uint8Array(
                  value.buffer,
                  value.byteOffset,
                  value.byteLength,
                )
              : null;
    return bytes ? JSON.parse(new TextDecoder().decode(bytes)) : null;
  } catch {
    return null;
  }
}

function policyFor(policy, workPackageId) {
  const matches = (policy?.workPackagePolicies ?? []).filter(
    (item) => item?.workPackageId === workPackageId,
  );
  return matches.length === 1 ? matches[0] : null;
}

function receiptMap(receiptsByPath) {
  if (receiptsByPath instanceof Map) return receiptsByPath;
  if (
    receiptsByPath &&
    typeof receiptsByPath === "object" &&
    !Array.isArray(receiptsByPath)
  ) {
    return new Map(Object.entries(receiptsByPath));
  }
  return new Map();
}

function frozenValueMatches(actual, expected) {
  try {
    return (
      actual !== null &&
      actual !== undefined &&
      referenceReviewDigests.canonicalize(actual) ===
        referenceReviewDigests.canonicalize(expected)
    );
  } catch {
    return false;
  }
}

function evidenceSubjectMap(attestation) {
  const entries = attestation?.evidenceSubjects;
  if (!Array.isArray(entries)) return null;
  const paths = entries.map(({ path }) => path);
  if (
    !entries.every(
      (entry) =>
        keysExactly(entry, ["path", "sha256"]) &&
        safePath(entry.path) &&
        SHA256.test(entry.sha256 ?? ""),
    ) ||
    !sortedUniqueStrings(paths)
  ) {
    return null;
  }
  return new Map(
    entries.map(({ path, sha256 }) => [path, sha256]),
  );
}

async function freezeAttestationValid({
  attestation,
  bundle,
  actualCatalogSha256,
  actualPolicySha256,
  actualManifestSha256,
  expectedBinding,
  sourceRoots,
  sourceExclusions,
  verifyFreezeRoot,
}) {
  if (
    !keysExactly(attestation, FROZEN_EVIDENCE_KEYS) ||
    !validateFreezeAttestationSchema(attestation) ||
    !GIT_COMMIT.test(attestation.evidenceFreezeCommit ?? "") ||
    !GIT_COMMIT.test(attestation.evidenceFreezeTree ?? "") ||
    attestation.evidenceFreezeCommit === attestation.sourceCommit ||
    attestation.sourceCommit !== bundle?.sourceCommit ||
    attestation.profileSha256 !== bundle?.profileSha256 ||
    attestation.executionBaselineDigest !==
      bundle?.executionBaselineDigest ||
    attestation.referenceCatalogSha256 !== actualCatalogSha256 ||
    attestation.referencePolicySha256 !== actualPolicySha256 ||
    attestation.profileSha256 !== expectedBinding?.profileSha256 ||
    attestation.executionBaselineDigest !==
      expectedBinding?.executionBaselineDigest ||
    attestation.upstreamProfileIncludesReferenceReviewDigests !==
      false ||
    attestation
        .upstreamExecutionBaselineIncludesReferenceReviewDigests !==
      false ||
    attestation.attestationIncludedInEvidenceFreeze !== false ||
    attestation.governanceEffect !== "NONE" ||
    attestation.isProgressTracker !== false ||
    attestation.selfAuthorizing !== false ||
    (await freezeAttestationDigest(attestation)) !==
      attestation.attestationSha256 ||
    evidenceSubjectMap(attestation) === null
  ) {
    return false;
  }
  let freezeRootVerified = false;
  try {
    const evidenceSubjectsSha256 =
      await referenceReviewDigests.value(attestation.evidenceSubjects);
    freezeRootVerified =
      (await verifyFreezeRoot({
        evidenceFreezeCommit: attestation.evidenceFreezeCommit,
        evidenceFreezeTree: attestation.evidenceFreezeTree,
        sourceCommit: attestation.sourceCommit,
        evidenceSubjectsSha256,
        manifestSha256: actualManifestSha256,
        sourceRoots,
        sourceExclusions,
      })) === true;
  } catch {
    freezeRootVerified = false;
  }
  if (!freezeRootVerified) return false;
  const bundleSubjects = attestation.bundleSubjects;
  if (
    !Array.isArray(bundleSubjects) ||
    bundleSubjects.length !== 1 ||
    bundleSubjects.some(
      (subject, index) =>
        !keysExactly(subject, [
          "path",
          "sha256",
          "workPackageId",
        ]) ||
        !safePath(subject.path) ||
        !SHA256.test(subject.sha256 ?? "") ||
        bundleSubjects.findIndex(
          (candidate) =>
            candidate.workPackageId === subject.workPackageId,
        ) !== index,
    )
  ) {
    return false;
  }
  const bundleSubject = bundleSubjects.find(
    ({ workPackageId }) =>
      workPackageId === bundle?.workPackageId,
  );
  return (
    bundleSubject?.path === bundle?.bundlePath &&
    bundleSubject?.sha256 === bundle?.bundleSha256
  );
}

function entriesAreSortedUnique(entries, keyFor) {
  if (!Array.isArray(entries)) return false;
  try {
    const keys = entries.map((entry) =>
      entry &&
      typeof entry === "object" &&
      !Array.isArray(entry)
        ? keyFor(entry)
        : null,
    );
    return sortedUniqueStrings(keys);
  } catch {
    return false;
  }
}

function catalogReferenceFor({
  catalogByReferenceId,
  matrixReferenceId = null,
  referenceName = null,
  officialSourceUri = null,
  toolLockDomain = null,
}) {
  const matches = [...catalogByReferenceId.values()].filter(
    (reference) =>
      (matrixReferenceId === null ||
        reference.matrixReferenceId === matrixReferenceId) &&
      (referenceName === null ||
        reference.referenceName === referenceName) &&
      (officialSourceUri === null ||
        (reference.officialSources ?? []).some(
          ({ uri }) => uri === officialSourceUri,
        )) &&
      (toolLockDomain === null ||
        (reference.applicableToolLockDomains ?? []).includes(
          toolLockDomain,
        )),
  );
  return matches.length === 1 ? matches[0] : null;
}

async function readFrozenScanBytes({
  frozenEvidence,
  readGitBytes,
  pairs,
  path,
  hash,
}) {
  if (
    !addEvidencePair(pairs, path, hash) ||
    !(await verifyFrozenPath({
      frozenEvidence,
      readGitBytes,
      path,
      declaredHash: hash,
    }))
  ) {
    return null;
  }
  try {
    return await readGitBytes({
      commit: frozenEvidence.evidenceFreezeCommit,
      path,
    });
  } catch {
    return null;
  }
}

async function readFrozenScanJson(options) {
  const bytes = await readFrozenScanBytes(options);
  if (bytes === null) return null;
  try {
    return parseJsonBytes(bytes);
  } catch {
    return null;
  }
}

function parseSourceIntegrationMarker(bytes) {
  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  if (!source.endsWith("\n")) return null;
  const lines = source.split("\n");
  if (
    !lines[0].startsWith(SOURCE_INTEGRATION_MARKER_PREFIX) ||
    lines.filter((line) =>
      line.startsWith(SOURCE_INTEGRATION_MARKER_PREFIX),
    ).length !== 1 ||
    lines.slice(1).join("\n").trim().length === 0
  ) {
    return null;
  }
  const serialized = lines[0].slice(
    SOURCE_INTEGRATION_MARKER_PREFIX.length,
  );
  let marker;
  try {
    marker = JSON.parse(serialized);
  } catch {
    return null;
  }
  if (
    !keysExactly(marker, SOURCE_INTEGRATION_MARKER_KEYS) ||
    marker.schemaVersion !== "reference-integration-marker.v1" ||
    typeof marker.identifier !== "string" ||
    marker.identifier.length === 0 ||
    typeof marker.officialSourceUri !== "string" ||
    marker.officialSourceUri.length === 0 ||
    !SOURCE_INTEGRATION_KINDS.includes(marker.integrationKind)
  ) {
    return null;
  }
  const canonical = JSON.stringify({
    schemaVersion: marker.schemaVersion,
    identifier: marker.identifier,
    officialSourceUri: marker.officialSourceUri,
    integrationKind: marker.integrationKind,
  });
  return serialized === canonical ? marker : null;
}

function containsSourceIntegrationMarker(bytes) {
  try {
    return new TextDecoder("utf-8", { fatal: true })
      .decode(bytes)
      .includes(SOURCE_INTEGRATION_MARKER_PREFIX);
  } catch {
    return false;
  }
}

function scanInputHeaderValid({
  input,
  scanKind,
  workPackageId,
  sourceCommit,
  actualCatalogSha256,
}) {
  return (
    !keysExactly(input, SCAN_INPUT_KEYS[scanKind] ?? []) ||
    input.scanKind !== scanKind ||
    input.workPackageId !== workPackageId ||
    input.sourceCommit !== sourceCommit ||
    input.referenceCatalogSha256 !== actualCatalogSha256 ||
    input.governanceEffect !== "NONE" ||
    input.isProgressTracker !== false ||
    input.selfAuthorizing !== false ||
    input.productionAdoptionClaim !== false
  )
    ? false
    : true;
}

async function scanInputReferenceIds({
  input,
  scanKind,
  workPackageId,
  sourceCommit,
  actualCatalogSha256,
  catalogByReferenceId,
  frozenEvidence,
  readGitBytes,
  pairs,
  dependencyPins,
  sourceIntegrations,
}) {
  if (
    !scanInputHeaderValid({
      input,
      scanKind,
      workPackageId,
      sourceCommit,
      actualCatalogSha256,
    })
  ) {
    return null;
  }
  const references = [];
  switch (scanKind) {
    case "DEPENDENCY_LOCK_SCAN": {
      if (
        input.schemaVersion !==
          "reference-dependency-lock-scan-input.v1" ||
        !keysExactly(input.inventory, [
          "evidenceFreezeTree",
          "files",
        ]) ||
        input.inventory.evidenceFreezeTree !==
          frozenEvidence.evidenceFreezeTree ||
        !entriesAreSortedUnique(
          input.inventory.files,
          ({ path }) => path,
        )
      ) {
        return null;
      }
      for (const file of input.inventory.files) {
        if (
          !keysExactly(file, ["format", "path", "sha256"]) ||
          file.format !== "PROJECT_TOOL_LOCK_V1"
        ) {
          return null;
        }
        const lock = await readFrozenScanJson({
          frozenEvidence,
          readGitBytes,
          pairs,
          path: file.path,
          hash: file.sha256,
        });
        if (
          !keysExactly(lock, [
            "dependencies",
            "schemaVersion",
            "workPackageId",
          ]) ||
          lock.schemaVersion !== "reference-dependency-lock.v1" ||
          lock.workPackageId !== workPackageId ||
          !entriesAreSortedUnique(
            lock.dependencies,
            ({ packageName, resolvedUri, toolLockDomain }) =>
              `${packageName}\n${resolvedUri}\n${toolLockDomain ?? ""}`,
          )
        ) {
          return null;
        }
        for (const dependency of lock.dependencies) {
          if (
            !keysExactly(dependency, [
              "artifactDigest",
              "packageName",
              "resolvedUri",
              "toolLockDomain",
              "version",
            ]) ||
            typeof dependency.packageName !== "string" ||
            dependency.packageName.length === 0 ||
            typeof dependency.resolvedUri !== "string" ||
            dependency.resolvedUri.length === 0 ||
            typeof dependency.version !== "string" ||
            dependency.version.length === 0 ||
            !SHA256.test(dependency.artifactDigest ?? "") ||
            (dependency.toolLockDomain !== null &&
              (typeof dependency.toolLockDomain !== "string" ||
                dependency.toolLockDomain.length === 0))
          ) {
            return null;
          }
          const reference = catalogReferenceFor({
            catalogByReferenceId,
            referenceName: dependency.packageName,
            officialSourceUri: dependency.resolvedUri,
            toolLockDomain: dependency.toolLockDomain,
          });
          if (
            !reference ||
            dependencyPins.has(reference.referenceId)
          ) {
            return null;
          }
          dependencyPins.set(reference.referenceId, {
            version: dependency.version,
            artifactDigest: dependency.artifactDigest,
            toolLockDomain: dependency.toolLockDomain,
            evidenceRef: file.path,
            evidenceHash: file.sha256,
          });
          references.push(reference.referenceId);
        }
      }
      break;
    }
    case "MANUAL_SUPPLEMENT": {
      if (
        input.schemaVersion !==
          "reference-manual-supplement-input.v1" ||
        input.reviewerRole !== "REFERENCE_REVIEWER" ||
        typeof input.reviewedAt !== "string" ||
        !Number.isFinite(Date.parse(input.reviewedAt)) ||
        typeof input.scopeStatement !== "string" ||
        input.scopeStatement.trim().length === 0 ||
        !entriesAreSortedUnique(
          input.observations,
          ({ officialSourceUri }) => officialSourceUri,
        )
      ) {
        return null;
      }
      for (const observation of input.observations) {
        if (
          !keysExactly(observation, [
            "evidenceHash",
            "evidenceRef",
            "officialSourceUri",
            "reason",
            "relevance",
          ]) ||
          !["APPLICABLE", "NOT_APPLICABLE"].includes(
            observation.relevance,
          ) ||
          typeof observation.reason !== "string" ||
          observation.reason.trim().length === 0 ||
          !addEvidencePair(
            pairs,
            observation.evidenceRef,
            observation.evidenceHash,
          )
        ) {
          return null;
        }
        const reference = catalogReferenceFor({
          catalogByReferenceId,
          officialSourceUri: observation.officialSourceUri,
        });
        if (!reference) return null;
        if (observation.relevance === "APPLICABLE") {
          references.push(reference.referenceId);
        }
      }
      break;
    }
    case "REFERENCE_MATRIX": {
      if (
        input.schemaVersion !==
          "reference-matrix-scan-input.v1" ||
        !keysExactly(input.matrix, ["format", "path", "sha256"]) ||
        input.matrix.format !== "REFERENCE_MATRIX_SLICE_V1"
      ) {
        return null;
      }
      const matrix = await readFrozenScanJson({
        frozenEvidence,
        readGitBytes,
        pairs,
        path: input.matrix.path,
        hash: input.matrix.sha256,
      });
      if (
        !keysExactly(matrix, [
          "findings",
          "schemaVersion",
          "workPackageId",
        ]) ||
        matrix.schemaVersion !== "reference-matrix-slice.v1" ||
        matrix.workPackageId !== workPackageId ||
        !entriesAreSortedUnique(
          matrix.findings,
          ({
            matrixReferenceId,
            officialSourceUri,
            referenceName,
          }) =>
            `${matrixReferenceId}\n${referenceName}\n${officialSourceUri}`,
        )
      ) {
        return null;
      }
      for (const finding of matrix.findings) {
        if (
          !keysExactly(finding, [
            "matrixReferenceId",
            "officialSourceUri",
            "referenceName",
          ]) ||
          typeof finding.matrixReferenceId !== "string" ||
          typeof finding.referenceName !== "string" ||
          typeof finding.officialSourceUri !== "string"
        ) {
          return null;
        }
        const reference = catalogReferenceFor({
          catalogByReferenceId,
          matrixReferenceId: finding.matrixReferenceId,
          referenceName: finding.referenceName,
          officialSourceUri: finding.officialSourceUri,
        });
        if (!reference) return null;
        references.push(reference.referenceId);
      }
      break;
    }
    case "SOURCE_INTEGRATION_SCAN": {
      if (
        input.schemaVersion !==
          "reference-source-integration-scan-input.v1" ||
        !keysExactly(input.inventory, [
          "evidenceFreezeTree",
          "files",
        ]) ||
        input.inventory.evidenceFreezeTree !==
          frozenEvidence.evidenceFreezeTree ||
        !entriesAreSortedUnique(
          input.inventory.files,
          ({ path }) => path,
        )
      ) {
        return null;
      }
      for (const file of input.inventory.files) {
        if (
          !keysExactly(file, ["format", "path", "sha256"]) ||
          file.format !==
            "REFERENCE_SOURCE_INTEGRATION_INDEX_V1"
        ) {
          return null;
        }
        const index = await readFrozenScanJson({
          frozenEvidence,
          readGitBytes,
          pairs,
          path: file.path,
          hash: file.sha256,
        });
        if (
          !keysExactly(index, [
            "integrations",
            "schemaVersion",
            "workPackageId",
          ]) ||
          index.schemaVersion !==
            "reference-source-integration-index.v1" ||
          index.workPackageId !== workPackageId ||
          !entriesAreSortedUnique(
            index.integrations,
            ({
              identifier,
              officialSourceUri,
              sourcePath,
            }) =>
              `${identifier}\n${officialSourceUri}\n${sourcePath}`,
          )
        ) {
          return null;
        }
        for (const integration of index.integrations) {
          if (
            !keysExactly(integration, [
              "identifier",
              "integrationKind",
              "officialSourceUri",
              "sourceFormat",
              "sourceHash",
              "sourcePath",
            ]) ||
            !SOURCE_INTEGRATION_KINDS.includes(
              integration.integrationKind,
            ) ||
            integration.sourceFormat !==
              "REFERENCE_INTEGRATION_MARKER_V1"
          ) {
            return null;
          }
          const marker = parseSourceIntegrationMarker(
            await readFrozenScanBytes({
              frozenEvidence,
              readGitBytes,
              pairs,
              path: integration.sourcePath,
              hash: integration.sourceHash,
            }),
          );
          if (
            marker === null ||
            marker.identifier !== integration.identifier ||
            marker.officialSourceUri !==
              integration.officialSourceUri ||
            marker.integrationKind !== integration.integrationKind
          ) {
            return null;
          }
          const reference = catalogReferenceFor({
            catalogByReferenceId,
            referenceName: integration.identifier,
            officialSourceUri:
              integration.officialSourceUri,
          });
          if (
            !reference ||
            sourceIntegrations.has(reference.referenceId)
          ) {
            return null;
          }
          sourceIntegrations.set(reference.referenceId, {
            identifier: integration.identifier,
            officialSourceUri: integration.officialSourceUri,
            integrationKind: integration.integrationKind,
            sourcePath: integration.sourcePath,
            sourceHash: integration.sourceHash,
          });
          references.push(reference.referenceId);
        }
      }
      break;
    }
    default:
      return null;
  }
  const referenceIds = [...new Set(references)].sort();
  return referenceIds.length === references.length
    ? referenceIds
    : null;
}

function statusFor(reasonCodes) {
  return reasonCodes.some((code) => code.endsWith("_STALE"))
    ? "STALE"
    : "INVALID";
}

function receiptVersionPins(receipt) {
  return new Set(
    (receipt.reviewedMaterials ?? []).flatMap((material) =>
      [
        material.documentationVersion,
        material.sourceCommit,
        material.release,
      ].filter(
        (value) => typeof value === "string" && value.length > 0,
      ),
    ),
  );
}

function receiptArtifactDigests(receipt) {
  return new Set(
    (receipt.reviewedMaterials ?? []).flatMap((material) =>
      [material.imageDigest, material.artifactDigest].filter(
        (value) => typeof value === "string" && value.length > 0,
      ),
    ),
  );
}

function addEvidencePair(pairs, path, hash) {
  if (!safePath(path) || !SHA256.test(hash ?? "")) return false;
  const previous = pairs.get(path);
  if (previous && previous !== hash) return false;
  pairs.set(path, hash);
  return true;
}

function addEvidenceArrays(pairs, refs, hashes) {
  if (!matchingEvidenceArrays(refs, hashes)) return false;
  return refs.every((path, index) =>
    addEvidencePair(pairs, path, hashes[index]),
  );
}

function receiptEvidencePairs(receipt) {
  const pairs = new Map();
  let valid = true;
  for (const source of receipt?.officialSources ?? []) {
    valid =
      addEvidencePair(
        pairs,
        source.contentEvidenceRef,
        source.contentSha256,
      ) && valid;
  }
  for (const section of receipt?.reviewedSections ?? []) {
    valid =
      addEvidencePair(pairs, section.notesRef, section.notesDigest) &&
      valid;
  }
  valid =
    addEvidencePair(
      pairs,
      receipt?.capabilityGap?.evidenceRef,
      receipt?.capabilityGap?.evidenceHash,
    ) && valid;
  valid =
    addEvidenceArrays(
      pairs,
      receipt?.currentImplementation?.evidenceRefs,
      receipt?.currentImplementation?.evidenceHashes,
    ) && valid;
  valid =
    addEvidenceArrays(
      pairs,
      receipt?.pocResult?.evidenceRefs,
      receipt?.pocResult?.evidenceHashes,
    ) && valid;
  valid =
    addEvidenceArrays(
      pairs,
      receipt?.evidenceRefs,
      receipt?.evidenceHashes,
    ) && valid;
  if (
    receipt?.decision === "ADOPT" &&
    (!safePath(receipt.adrRef) || !pairs.has(receipt.adrRef))
  ) {
    valid = false;
  }
  return { valid, pairs };
}

async function implementationConformanceReason({
  bundle,
  receiptByReferenceId,
  entryByReferenceId,
  catalogByReferenceId,
  applicability,
  frozenEvidence,
  readGitBytes,
}) {
  const bindings = new Map();
  for (const binding of bundle.implementationBindings ?? []) {
    if (
      !binding ||
      typeof binding.referenceId !== "string" ||
      bindings.has(binding.referenceId)
    ) {
      return "REFERENCE_IMPLEMENTATION_DIVERGES_FROM_DECISION";
    }
    bindings.set(binding.referenceId, binding);
  }
  for (const [referenceId, receipt] of receiptByReferenceId) {
    const binding = bindings.get(referenceId);
    const approved = entryByReferenceId.get(referenceId);
    const dependencyLock =
      applicability.dependencyPins.get(referenceId) ?? null;
    const sourceIntegration =
      applicability.sourceIntegrations.get(referenceId) ?? null;
    if (receipt.decision === "ADOPT") {
      if (
        !binding ||
        !approved ||
        !SHA256.test(binding.artifactDigest ?? "") ||
        !SHA256.test(binding.evidenceHash ?? "") ||
        binding.artifactDigest !== approved.adoptedArtifactDigest ||
        !receiptArtifactDigests(receipt).has(
          binding.artifactDigest,
        )
      ) {
        return "REFERENCE_IMPLEMENTATION_DIVERGES_FROM_DECISION";
      }
      const catalogReference =
        catalogByReferenceId.get(referenceId);
      if (
        catalogReference?.referenceKind ===
          "OPEN_SOURCE_PROJECT" &&
        (!dependencyLock || !sourceIntegration)
      ) {
        return "REFERENCE_ACTUAL_PIN_MISMATCH";
      }
      if (
        dependencyLock &&
        (dependencyLock.artifactDigest !==
          binding.artifactDigest ||
          !receiptVersionPins(receipt).has(
            dependencyLock.version,
          ))
      ) {
        return "REFERENCE_ACTUAL_PIN_MISMATCH";
      }
      let bytes;
      if (
        !(await verifyFrozenPath({
          frozenEvidence,
          readGitBytes,
          path: binding.evidenceRef,
          declaredHash: binding.evidenceHash,
        }))
      ) {
        return "REFERENCE_IMPLEMENTATION_EVIDENCE_INVALID";
      }
      try {
        bytes = await readGitBytes({
          commit: frozenEvidence.evidenceFreezeCommit,
          path: binding.evidenceRef,
        });
      } catch {
        return "REFERENCE_IMPLEMENTATION_EVIDENCE_INVALID";
      }
      const evidence = parseJsonBytes(bytes);
      if (
        !validateImplementationConformanceSchema(evidence) ||
        evidence.workPackageId !== bundle.workPackageId ||
        evidence.sourceCommit !== bundle.sourceCommit ||
        evidence.referenceId !== referenceId ||
        evidence.artifactDigest !== binding.artifactDigest
      ) {
        return "REFERENCE_IMPLEMENTATION_EVIDENCE_INVALID";
      }
      if (
        !frozenValueMatches(
          evidence.dependencyLock,
          dependencyLock,
        ) ||
        !frozenValueMatches(
          evidence.sourceIntegration,
          sourceIntegration,
        )
      ) {
        return "REFERENCE_ACTUAL_PIN_MISMATCH";
      }
    } else if (binding || dependencyLock || sourceIntegration) {
      return binding
        ? "REFERENCE_IMPLEMENTATION_DIVERGES_FROM_DECISION"
        : "REFERENCE_NON_ADOPT_IMPLEMENTATION_PRESENT";
    }
  }
  return bindings.size ===
    [...receiptByReferenceId.values()].filter(
      ({ decision }) => decision === "ADOPT",
    ).length
    ? null
    : "REFERENCE_IMPLEMENTATION_DIVERGES_FROM_DECISION";
}

function actualAdoptionReason({
  receiptByReferenceId,
  entryByReferenceId,
  catalogByReferenceId,
  dependencyPins,
  sourceIntegrations,
}) {
  for (const [referenceId, receipt] of receiptByReferenceId) {
    const dependencyPin = dependencyPins.get(referenceId) ?? null;
    const sourceIntegration =
      sourceIntegrations.get(referenceId) ?? null;
    if (
      receipt.decision !== "ADOPT" &&
      (dependencyPin || sourceIntegration)
    ) {
      return "REFERENCE_NON_ADOPT_IMPLEMENTATION_PRESENT";
    }
    if (receipt.decision !== "ADOPT") continue;
    const entry = entryByReferenceId.get(referenceId);
    if (
      catalogByReferenceId.get(referenceId)?.referenceKind ===
        "OPEN_SOURCE_PROJECT" &&
      (!dependencyPin || !sourceIntegration)
    ) {
      return "REFERENCE_ACTUAL_PIN_MISMATCH";
    }
    if (
      dependencyPin &&
      (dependencyPin.artifactDigest !==
        entry?.adoptedArtifactDigest ||
        !receiptArtifactDigests(receipt).has(
          dependencyPin.artifactDigest,
        ) ||
        !receiptVersionPins(receipt).has(dependencyPin.version))
    ) {
      return "REFERENCE_ACTUAL_PIN_MISMATCH";
    }
  }
  for (const referenceId of [
    ...dependencyPins.keys(),
    ...sourceIntegrations.keys(),
  ]) {
    if (!receiptByReferenceId.has(referenceId)) {
      return "REFERENCE_UNKNOWN_CANDIDATE";
    }
  }
  return null;
}

function dependencyBindingsConform({
  bundle,
  workPackagePolicy,
  catalogByReferenceId,
  receiptByReferenceId,
  entryByReferenceId,
  selectedToolLocks,
  dependencyPins,
}) {
  const requiredDomains =
    workPackagePolicy?.requiredToolLockDomains ?? [];
  const bindings = new Map();
  for (const binding of bundle?.dependencyBindings ?? []) {
    if (
      !binding ||
      typeof binding.domain !== "string" ||
      bindings.has(binding.domain)
    ) {
      return false;
    }
    bindings.set(binding.domain, binding);
  }
  const locks = new Map();
  for (const lock of selectedToolLocks ?? []) {
    if (
      !lock ||
      typeof lock.domain !== "string" ||
      locks.has(lock.domain)
    ) {
      return false;
    }
    locks.set(lock.domain, lock);
  }
  if (
    bindings.size !== requiredDomains.length ||
    requiredDomains.some(
      (domain) => !bindings.has(domain) || !locks.has(domain),
    )
  ) {
    return false;
  }
  for (const domain of requiredDomains) {
    const binding = bindings.get(domain);
    const lock = locks.get(domain);
    const receipt = receiptByReferenceId.get(binding.referenceId);
    const entry = entryByReferenceId.get(binding.referenceId);
    const catalogReference = catalogByReferenceId.get(
      binding.referenceId,
    );
    const actualPin = dependencyPins.get(binding.referenceId);
    if (
      lock.selection !== "SELECTED" ||
      lock.referenceId !== binding.referenceId ||
      lock.version !== binding.version ||
      lock.sha256 !== binding.artifactDigest ||
      receipt?.decision !== "ADOPT" ||
      entry?.adoptedArtifactDigest !== binding.artifactDigest ||
      !catalogReference?.applicableToolLockDomains?.includes(domain) ||
      !receiptVersionPins(receipt).has(binding.version) ||
      !receiptArtifactDigests(receipt).has(
        binding.artifactDigest,
      ) ||
      actualPin?.version !== binding.version ||
      actualPin?.artifactDigest !== binding.artifactDigest ||
      actualPin?.toolLockDomain !== domain
    ) {
      return false;
    }
  }
  return true;
}

async function verifyFrozenPath({
  frozenEvidence,
  readGitBytes,
  path,
  declaredHash = null,
  expectedJson = null,
}) {
  const subjects = evidenceSubjectMap(frozenEvidence);
  if (!safePath(path) || subjects === null) return false;
  const subjectHash = subjects.get(path);
  if (
    !SHA256.test(subjectHash ?? "") ||
    (declaredHash !== null && subjectHash !== declaredHash)
  ) {
    return false;
  }
  let bytes;
  try {
    bytes = await readGitBytes({
      commit: frozenEvidence.evidenceFreezeCommit,
      path,
    });
  } catch {
    return false;
  }
  if ((await byteDigest(bytes)) !== subjectHash) return false;
  return (
    expectedJson === null ||
    frozenValueMatches(parseJsonBytes(bytes), expectedJson)
  );
}

async function enumerateFrozenSourcePaths({
  frozenEvidence,
  sourceRoots,
  sourceExclusions,
  listFrozenPaths,
}) {
  let paths;
  try {
    paths = await listFrozenPaths({
      evidenceFreezeCommit: frozenEvidence?.evidenceFreezeCommit,
      evidenceFreezeTree: frozenEvidence?.evidenceFreezeTree,
      sourceRoots: [...sourceRoots],
      sourceExclusions: [...sourceExclusions],
    });
  } catch {
    return null;
  }
  if (
    !sortedUniqueStrings(paths) ||
    paths.some(
      (path) =>
        !safePath(path) ||
        !sourceRoots.some((root) => pathWithin(path, root)) ||
        sourceExclusions.some((excluded) =>
          pathWithin(path, excluded),
        ),
    )
  ) {
    return null;
  }
  const subjects = evidenceSubjectMap(frozenEvidence);
  if (subjects === null) return null;
  const attestedPaths = [...subjects.keys()]
    .filter(
      (path) =>
        sourceRoots.some((root) => pathWithin(path, root)) &&
        !sourceExclusions.some((excluded) =>
          pathWithin(path, excluded),
        ),
    )
    .sort();
  return referenceReviewDigests.canonicalize(paths) ===
    referenceReviewDigests.canonicalize(attestedPaths)
    ? paths
    : null;
}

async function validateApplicabilityEvidence({
  workPackagePolicy,
  bundle,
  actualCatalogSha256,
  catalogByReferenceId,
  frozenEvidence,
  readGitBytes,
  frozenSourcePaths,
}) {
  const invalid = () => ({
    valid: false,
    pairs: new Map(),
    dependencyPins: new Map(),
    sourceIntegrations: new Map(),
  });
  const refs =
    workPackagePolicy?.applicabilityEvidence?.evidenceRefs;
  const hashes =
    workPackagePolicy?.applicabilityEvidence?.evidenceHashes;
  const sourceRoots =
    workPackagePolicy?.applicabilityEvidence?.sourceRoots;
  const sourceExclusions =
    workPackagePolicy?.applicabilityEvidence?.sourceExclusions;
  if (
    workPackagePolicy?.applicabilityEvidence?.status !== "COMPLETE" ||
    !matchingEvidenceArrays(refs, hashes) ||
    refs.length !== 1 ||
    !sortedUniqueStrings(sourceRoots) ||
    sourceRoots.length === 0 ||
    sourceRoots.some((path) => !safePath(path)) ||
    !sortedUniqueStrings(sourceExclusions) ||
    sourceExclusions.some(
      (path) =>
        !safePath(path) ||
        !sourceRoots.some((root) => pathWithin(path, root)),
    ) ||
    !(await verifyFrozenPath({
      frozenEvidence,
      readGitBytes,
      path: refs[0],
      declaredHash: hashes[0],
    }))
  ) {
    return invalid();
  }
  let bytes;
  try {
    bytes = await readGitBytes({
      commit: frozenEvidence.evidenceFreezeCommit,
      path: refs[0],
    });
  } catch {
    return invalid();
  }
  const report = parseJsonBytes(bytes);
  const expectedReferenceIds =
    workPackagePolicy.applicableReferenceIds;
  if (
    !validateApplicabilityEvidenceSchema(report) ||
    report.workPackageId !== bundle.workPackageId ||
    report.sourceCommit !== bundle.sourceCommit ||
    !sortedUniqueStrings(report.candidateReferenceIds) ||
    referenceReviewDigests.canonicalize(
      report.candidateReferenceIds,
    ) !== referenceReviewDigests.canonicalize(expectedReferenceIds) ||
    (await applicabilityReportDigest(report)) !==
      report.reportSha256
  ) {
    return invalid();
  }
  const scanKinds = report.scans.map(({ scanKind }) => scanKind);
  const discovered = new Set();
  const pairs = new Map();
  const dependencyPins = new Map();
  const sourceIntegrations = new Map();
  for (const scan of report.scans) {
    const expectedMethod =
      APPLICABILITY_SCAN_METHODS[scan.scanKind];
    if (
      !expectedMethod ||
      scan.method !== expectedMethod.method ||
      scan.methodVersion !== expectedMethod.methodVersion ||
      !matchingEvidenceArrays(scan.inputRefs, scan.inputHashes) ||
      scan.inputRefs.length !== 1 ||
      !sortedUniqueStrings(scan.discoveredReferenceIds) ||
      scan.discoveredReferenceIds.some(
        (referenceId) => !catalogByReferenceId.has(referenceId),
      ) ||
      !addEvidenceArrays(
        pairs,
        scan.inputRefs,
        scan.inputHashes,
      )
    ) {
      return invalid();
    }
    const [inputPath] = scan.inputRefs;
    const [inputHash] = scan.inputHashes;
    if (
      !(await verifyFrozenPath({
        frozenEvidence,
        readGitBytes,
        path: inputPath,
        declaredHash: inputHash,
      }))
    ) {
      return invalid();
    }
    let inputBytes;
    try {
      inputBytes = await readGitBytes({
        commit: frozenEvidence.evidenceFreezeCommit,
        path: inputPath,
      });
    } catch {
      return invalid();
    }
    const derivedReferenceIds = await scanInputReferenceIds({
      input: parseJsonBytes(inputBytes),
      scanKind: scan.scanKind,
      workPackageId: bundle.workPackageId,
      sourceCommit: bundle.sourceCommit,
      actualCatalogSha256,
      catalogByReferenceId,
      frozenEvidence,
      readGitBytes,
      pairs,
      dependencyPins,
      sourceIntegrations,
    });
    if (
      derivedReferenceIds === null ||
      referenceReviewDigests.canonicalize(
        derivedReferenceIds,
      ) !==
        referenceReviewDigests.canonicalize(
          scan.discoveredReferenceIds,
        )
    ) {
      return invalid();
    }
    derivedReferenceIds.forEach((referenceId) =>
      discovered.add(referenceId),
    );
  }
  if (
    referenceReviewDigests.canonicalize(scanKinds) !==
      referenceReviewDigests.canonicalize(
        APPLICABILITY_SCAN_KINDS,
      ) ||
    referenceReviewDigests.canonicalize(
      [...discovered].sort(),
    ) !== referenceReviewDigests.canonicalize(expectedReferenceIds)
  ) {
    return invalid();
  }
  const markerPaths = [];
  const subjects = evidenceSubjectMap(frozenEvidence);
  for (const path of frozenSourcePaths ?? []) {
    const hash = subjects?.get(path);
    const bytes = await readFrozenScanBytes({
      frozenEvidence,
      readGitBytes,
      pairs,
      path,
      hash,
    });
    if (bytes === null) return invalid();
    if (containsSourceIntegrationMarker(bytes)) {
      if (parseSourceIntegrationMarker(bytes) === null) {
        return invalid();
      }
      markerPaths.push(path);
    }
  }
  const indexedMarkerPaths = [...sourceIntegrations.values()]
    .map(({ sourcePath }) => sourcePath)
    .sort();
  if (
    !sortedUniqueStrings(markerPaths.sort()) ||
    referenceReviewDigests.canonicalize(markerPaths) !==
      referenceReviewDigests.canonicalize(indexedMarkerPaths)
  ) {
    return invalid();
  }
  return {
    valid: true,
    pairs,
    dependencyPins,
    sourceIntegrations,
  };
}

export const REFERENCE_REVIEW_STATES = Object.freeze({
  candidateIdentified: "CANDIDATE_IDENTIFIED",
  receiptValid: "RECEIPT_VALID",
  gitFrozen: "GIT_FROZEN",
  readyForStart: "READY_FOR_START",
  readyForDependencyLock: "READY_FOR_DEPENDENCY_LOCK",
  implementationConformant: "IMPLEMENTATION_CONFORMANT",
  releaseCheckedByO03: "RELEASE_CHECKED_BY_O03",
  stale: "STALE",
});

export const referenceReviewBundleDigests = Object.freeze({
  bundle: bundleDigest,
  policy: policyDigest,
  catalog: catalogDigest,
  applicableSet: applicableSetDigest,
  applicabilityReport: applicabilityReportDigest,
  freezeAttestation: freezeAttestationDigest,
  bytes: byteDigest,
});

export async function validateReferenceReviewBundle({
  manifest,
  catalog,
  policy,
  bundle,
  receiptsByPath,
  expectedBinding,
  trustedBinding,
  frozenEvidence,
  selectedToolLocks = [],
  readGitBytes = async () => null,
  verifyFreezeRoot = async () => false,
  listFrozenPaths = async () => null,
}) {
  const reasonCodes = [];
  if (
    !keysExactly(bundle, BUNDLE_KEYS) ||
    !validateBundleSchema(bundle) ||
    bundle?.governanceEffect !== "NONE" ||
    bundle?.isProgressTracker !== false ||
    bundle?.selfAuthorizing !== false
  ) {
    reasonCodes.push("REFERENCE_BUNDLE_INVALID");
  }
  if (bundle?.productionAdoptionClaim !== false) {
    reasonCodes.push("REFERENCE_PRODUCTION_ADOPTION_CLAIM_FORBIDDEN");
  }
  if (
    !keysExactly(policy, POLICY_KEYS) ||
    !validatePolicySchema(policy) ||
    policy?.governanceEffect !== "NONE" ||
    policy?.isProgressTracker !== false ||
    policy?.selfAuthorizing !== false ||
    policy?.authorityBoundaries?.createsSecondStateTruth !== false
  ) {
    reasonCodes.push("REFERENCE_POLICY_INVALID");
  }
  if (!validateCatalogSchema(catalog)) {
    reasonCodes.push("REFERENCE_CATALOG_INVALID");
  }
  const actualCatalogSha256 = await catalogDigest(catalog);
  const actualPolicySha256 = await policyDigest(policy);
  const actualManifestSha256 =
    manifest && typeof manifest === "object"
      ? await referenceReviewDigests.value(manifest)
      : null;
  const manifestIds = manifestWorkPackageIds(manifest);
  const policyWorkPackageIds = (
    policy?.workPackagePolicies ?? []
  )
    .map(({ workPackageId }) => workPackageId)
    .sort();
  if (
    !(await trustedBindingMatches({
      trustedBinding,
      manifest,
      manifestIds,
      actualManifestSha256,
      actualCatalogSha256,
      actualPolicySha256,
      policy,
    }))
  ) {
    reasonCodes.push("REFERENCE_TRUSTED_BINDING_INVALID");
  }
  if (
    manifestIds === null ||
    policy?.manifest?.canonicalSha256 !== actualManifestSha256 ||
    !safePath(policy?.manifest?.path) ||
    !sortedUniqueStrings(policyWorkPackageIds) ||
    policyWorkPackageIds.some((id) => !manifestIds.has(id)) ||
    !sortedUniqueStrings(
      policy?.profileBinding?.requiredBackfillWorkPackageIds,
    ) ||
    !frozenValueMatches(
      policy?.profileBinding?.requiredBackfillWorkPackageIds,
      requiredProfileBackfillIds(policy),
    )
  ) {
    reasonCodes.push("REFERENCE_MANIFEST_BINDING_INVALID");
  }
  if (
    policy?.catalog?.canonicalSha256 !== actualCatalogSha256 ||
    bundle?.referenceCatalogSha256 !== actualCatalogSha256
  ) {
    reasonCodes.push("REFERENCE_CATALOG_STALE");
  }
  if (bundle?.referencePolicySha256 !== actualPolicySha256) {
    reasonCodes.push("REFERENCE_POLICY_STALE");
  }

  const catalogByReferenceId = new Map();
  for (const reference of catalog?.references ?? []) {
    if (
      catalogByReferenceId.has(reference?.referenceId) ||
      !sortedUniqueStrings(
        reference?.applicableToolLockDomains ?? [],
      )
    ) {
      reasonCodes.push("REFERENCE_CATALOG_INVALID");
    } else {
      catalogByReferenceId.set(reference.referenceId, reference);
    }
  }
  const catalogReferenceIds = [...catalogByReferenceId.keys()].sort();
  if (
    !safePath(policy?.candidateSourceBaseline?.path) ||
    !SHA256.test(policy?.candidateSourceBaseline?.sha256 ?? "") ||
    !sortedUniqueStrings(
      policy?.candidateSourceBaseline?.catalogReferenceIds,
    ) ||
    referenceReviewDigests.canonicalize(
      policy?.candidateSourceBaseline?.catalogReferenceIds,
    ) !==
      referenceReviewDigests.canonicalize(catalogReferenceIds)
  ) {
    reasonCodes.push("REFERENCE_CANDIDATE_SOURCE_BASELINE_INVALID");
  }
  const workPackagePolicy = policyFor(policy, bundle?.workPackageId);
  const expectedReferenceIds =
    workPackagePolicy?.applicableReferenceIds ?? null;
  if (
    !workPackagePolicy ||
    !manifestIds?.has(bundle?.workPackageId) ||
    !sortedUniqueStrings(expectedReferenceIds) ||
    !sortedUniqueStrings(
      workPackagePolicy?.requiredToolLockDomains ?? [],
    ) ||
    bundle?.reviewMode !== workPackagePolicy?.reviewMode
  ) {
    reasonCodes.push("REFERENCE_APPLICABILITY_NOT_PROVED");
  }
  if (
    !sortedUniqueStrings(bundle?.candidateReferenceIds) ||
    bundle.candidateReferenceIds.some(
      (referenceId) => !catalogByReferenceId.has(referenceId),
    )
  ) {
    reasonCodes.push("REFERENCE_UNKNOWN_CANDIDATE");
  }
  if (
    expectedReferenceIds &&
    referenceReviewDigests.canonicalize(
      bundle?.candidateReferenceIds,
    ) !== referenceReviewDigests.canonicalize(expectedReferenceIds)
  ) {
    reasonCodes.push("REFERENCE_CANDIDATE_SET_INCOMPLETE");
  }
  const expectedSetDigest = workPackagePolicy
    ? await applicableSetDigest({
        workPackageId: bundle.workPackageId,
        applicableReferenceIds:
          workPackagePolicy.applicableReferenceIds,
        referenceCatalogSha256: actualCatalogSha256,
        referencePolicySha256: actualPolicySha256,
      })
    : null;
  if (bundle?.applicableReferenceSetDigest !== expectedSetDigest) {
    reasonCodes.push("REFERENCE_CANDIDATE_SET_STALE");
  }
  if (
    !expectedBinding ||
    bundle?.profileSha256 !== expectedBinding.profileSha256 ||
    bundle?.sourceCommit !== expectedBinding.sourceCommit ||
    bundle?.executionBaselineDigest !==
      expectedBinding.executionBaselineDigest ||
    frozenEvidence?.sourceCommit !== bundle?.sourceCommit
  ) {
    reasonCodes.push("REFERENCE_BASELINE_BINDING_STALE");
  }
  if (
    !GIT_COMMIT.test(bundle?.sourceCommit ?? "") ||
    (bundle?.profileSha256 !== null &&
      !SHA256.test(bundle?.profileSha256 ?? "")) ||
    (bundle?.executionBaselineDigest !== null &&
      !SHA256.test(bundle?.executionBaselineDigest ?? ""))
  ) {
    reasonCodes.push("REFERENCE_BASELINE_BINDING_INVALID");
  }
  if (
    !Object.hasOwn(RECEIPT_BOUNDARY_ORDER, bundle?.reviewBoundary) ||
    bundle?.reviewBoundary !== expectedBinding?.reviewBoundary
  ) {
    reasonCodes.push("REFERENCE_BOUNDARY_MISMATCH");
  }
  if (
    !SHA256.test(bundle?.bundleSha256 ?? "") ||
    (await bundleDigest(bundle)) !== bundle?.bundleSha256
  ) {
    reasonCodes.push("REFERENCE_BUNDLE_HASH_MISMATCH");
  }
  const sourceRoots =
    workPackagePolicy?.applicabilityEvidence?.sourceRoots ?? [];
  const sourceExclusions =
    workPackagePolicy?.applicabilityEvidence?.sourceExclusions ?? [];
  if (
    !(await freezeAttestationValid({
      attestation: frozenEvidence,
      bundle,
      actualCatalogSha256,
      actualPolicySha256,
      actualManifestSha256,
      expectedBinding,
      sourceRoots,
      sourceExclusions,
      verifyFreezeRoot,
    }))
  ) {
    reasonCodes.push("REFERENCE_FREEZE_ATTESTATION_INVALID");
  }
  const frozenSourcePaths = await enumerateFrozenSourcePaths({
    frozenEvidence,
    sourceRoots,
    sourceExclusions,
    listFrozenPaths,
  });
  if (frozenSourcePaths === null) {
    reasonCodes.push("REFERENCE_FREEZE_ROOT_PATH_SET_MISMATCH");
  }
  const applicability = await validateApplicabilityEvidence({
    workPackagePolicy,
    bundle,
    actualCatalogSha256,
    catalogByReferenceId,
    frozenEvidence,
    readGitBytes,
    frozenSourcePaths,
  });
  if (!applicability.valid) {
    reasonCodes.push("REFERENCE_APPLICABILITY_NOT_PROVED");
  }

  const receipts = receiptMap(receiptsByPath);
  const receiptByReferenceId = new Map();
  const entryByReferenceId = new Map();
  if (
    !Array.isArray(bundle?.receipts) ||
    bundle.receipts.length !==
      (bundle?.candidateReferenceIds ?? []).length
  ) {
    reasonCodes.push("REFERENCE_RECEIPT_SET_INCOMPLETE");
  } else {
    for (const entry of bundle.receipts) {
      const receipt = receipts.get(entry?.path);
      if (
        !entry ||
        typeof entry !== "object" ||
        Array.isArray(entry) ||
        receiptByReferenceId.has(entry.referenceId) ||
        !receipt ||
        receipt.referenceId !== entry.referenceId ||
        receipt.workPackageId !== bundle.workPackageId ||
        receipt.receiptSha256 !== entry.sha256 ||
        receipt.decision !== entry.decision
      ) {
        reasonCodes.push("REFERENCE_RECEIPT_SET_INCOMPLETE");
        continue;
      }
      const validation = await validateReferenceReviewReceipt(receipt);
      if (!validation.ok) reasonCodes.push(...validation.reasonCodes);
      const catalogReference = catalogByReferenceId.get(
        entry.referenceId,
      );
      const catalogSources = new Set(
        (catalogReference?.officialSources ?? []).map(
          ({ sourceId, uri, sourceKind }) =>
            `${sourceId}\n${uri}\n${sourceKind}`,
        ),
      );
      if (
        receipt.referenceName !== catalogReference?.referenceName ||
        receipt.referenceKind !== catalogReference?.referenceKind ||
        (receipt.officialSources ?? []).some(
          ({ sourceId, uri, sourceKind }) =>
            !catalogSources.has(
              `${sourceId}\n${uri}\n${sourceKind}`,
            ),
        )
      ) {
        reasonCodes.push(
          "REFERENCE_OFFICIAL_SOURCE_NOT_CATALOGED",
        );
      }
      if (
        receipt.decision === "ADOPT" &&
        catalogReference?.pocRequirement ===
          "REQUIRED_FOR_ADOPT" &&
        receipt.pocRequired !== true
      ) {
        reasonCodes.push("REFERENCE_ADOPT_POC_POLICY_MISMATCH");
      }
      if (
        receipt.applicableReferenceSetDigest !==
          bundle.applicableReferenceSetDigest ||
        receipt.referenceCatalogSha256 !==
          bundle.referenceCatalogSha256 ||
        receipt.referencePolicySha256 !==
          bundle.referencePolicySha256 ||
        receipt.profileSha256 !== bundle.profileSha256 ||
        receipt.sourceCommit !== bundle.sourceCommit
      ) {
        reasonCodes.push("REFERENCE_RECEIPT_BINDING_STALE");
      }
      if (
        !Object.hasOwn(
          RECEIPT_BOUNDARY_ORDER,
          receipt.reviewBoundary,
        ) ||
        RECEIPT_BOUNDARY_ORDER[receipt.reviewBoundary] <
          RECEIPT_BOUNDARY_ORDER[bundle.reviewBoundary]
      ) {
        reasonCodes.push("REFERENCE_RECEIPT_BOUNDARY_INSUFFICIENT");
      }
      if (
        receipt.decision === "DEFER" &&
        Object.hasOwn(
          RECEIPT_BOUNDARY_ORDER,
          receipt.reReviewTrigger?.beforeBoundary,
        ) &&
        RECEIPT_BOUNDARY_ORDER[bundle.reviewBoundary] >=
          RECEIPT_BOUNDARY_ORDER[
            receipt.reReviewTrigger.beforeBoundary
          ]
      ) {
        reasonCodes.push("REFERENCE_DEFER_REVIEW_STALE");
      }
      if (
        entry.decision === "ADOPT" &&
        (!SHA256.test(entry.adoptedArtifactDigest ?? "") ||
          !receiptArtifactDigests(receipt).has(
            entry.adoptedArtifactDigest,
          ))
      ) {
        reasonCodes.push("REFERENCE_ADOPTED_VERSION_STALE");
      }
      if (
        entry.decision !== "ADOPT" &&
        entry.adoptedArtifactDigest !== null
      ) {
        reasonCodes.push("REFERENCE_NON_ADOPT_VERSION_FORBIDDEN");
      }
      receiptByReferenceId.set(entry.referenceId, receipt);
      entryByReferenceId.set(entry.referenceId, entry);
    }
  }
  if (
    expectedReferenceIds &&
    expectedReferenceIds.some(
      (referenceId) => !receiptByReferenceId.has(referenceId),
    )
  ) {
    reasonCodes.push("REFERENCE_RECEIPT_SET_INCOMPLETE");
  }
  if (
    ["DEPENDENCY_ADOPTION", "IMPLEMENTATION_CONFORMANCE"].includes(
      bundle?.reviewBoundary,
    )
  ) {
    const adoptionReason = actualAdoptionReason({
      receiptByReferenceId,
      entryByReferenceId,
      catalogByReferenceId,
      dependencyPins: applicability.dependencyPins,
      sourceIntegrations: applicability.sourceIntegrations,
    });
    if (adoptionReason) reasonCodes.push(adoptionReason);
  }
  if (bundle?.reviewBoundary === "IMPLEMENTATION_CONFORMANCE") {
    const implementationReason =
      await implementationConformanceReason({
        bundle,
        receiptByReferenceId,
        entryByReferenceId,
        catalogByReferenceId,
        applicability,
        frozenEvidence,
        readGitBytes,
      });
    if (implementationReason) {
      reasonCodes.push(implementationReason);
    }
  }
  if (
    bundle?.reviewBoundary !== "IMPLEMENTATION_CONFORMANCE" &&
    Array.isArray(bundle?.implementationBindings) &&
    bundle.implementationBindings.length > 0
  ) {
    reasonCodes.push(
      "REFERENCE_IMPLEMENTATION_BINDING_OUT_OF_SCOPE",
    );
  }
  if (
    ["DEPENDENCY_ADOPTION", "IMPLEMENTATION_CONFORMANCE"].includes(
      bundle?.reviewBoundary,
    )
  ) {
    if (
      !dependencyBindingsConform({
        bundle,
        workPackagePolicy,
        catalogByReferenceId,
        receiptByReferenceId,
        entryByReferenceId,
        selectedToolLocks,
        dependencyPins: applicability.dependencyPins,
      })
    ) {
      reasonCodes.push(
        "REFERENCE_TOOL_LOCK_BINDING_NOT_PROVED",
      );
    }
  } else if ((bundle?.dependencyBindings ?? []).length > 0) {
    reasonCodes.push("REFERENCE_DEPENDENCY_BINDING_OUT_OF_SCOPE");
  }
  if (expectedReferenceIds?.length === 0) {
    if (
      typeof bundle?.zeroSetReason !== "string" ||
      bundle.zeroSetReason.trim().length === 0 ||
      bundle.receipts.length !== 0
    ) {
      reasonCodes.push("REFERENCE_ZERO_SET_REASON_MISSING");
    }
  } else if (bundle?.zeroSetReason !== null) {
    reasonCodes.push("REFERENCE_ZERO_SET_REASON_INVALID");
  }

  const evidencePairs = new Map();
  let evidencePairsValid = true;
  evidencePairsValid =
    addEvidencePair(
      evidencePairs,
      policy?.candidateSourceBaseline?.path,
      policy?.candidateSourceBaseline?.sha256,
    ) && evidencePairsValid;
  evidencePairsValid =
    addEvidenceArrays(
      evidencePairs,
      workPackagePolicy?.applicabilityEvidence?.evidenceRefs,
      workPackagePolicy?.applicabilityEvidence?.evidenceHashes,
    ) && evidencePairsValid;
  for (const [path, hash] of applicability.pairs) {
    evidencePairsValid =
      addEvidencePair(evidencePairs, path, hash) &&
      evidencePairsValid;
  }
  for (const receipt of receiptByReferenceId.values()) {
    const receiptEvidence = receiptEvidencePairs(receipt);
    evidencePairsValid =
      receiptEvidence.valid && evidencePairsValid;
    for (const [path, hash] of receiptEvidence.pairs) {
      evidencePairsValid =
        addEvidencePair(evidencePairs, path, hash) &&
        evidencePairsValid;
    }
  }
  for (const binding of bundle?.implementationBindings ?? []) {
    evidencePairsValid =
      addEvidencePair(
        evidencePairs,
        binding?.evidenceRef,
        binding?.evidenceHash,
      ) && evidencePairsValid;
  }
  if (!evidencePairsValid) {
    reasonCodes.push("REFERENCE_EVIDENCE_INCOMPLETE");
  }

  const frozenJson = [
    [policy?.manifest?.path, manifest],
    [policy?.catalog?.path, catalog],
    [policy?.policyPath, policy],
    [bundle?.bundlePath, bundle],
    ...(bundle?.receipts ?? []).map((entry) => [
      entry.path,
      receipts.get(entry.path),
    ]),
  ];
  for (const [path, expectedJson] of frozenJson) {
    if (
      !(await verifyFrozenPath({
        frozenEvidence,
        readGitBytes,
        path,
        expectedJson,
      }))
    ) {
      reasonCodes.push("REFERENCE_GIT_EVIDENCE_NOT_FROZEN");
    }
  }
  for (const [path, hash] of evidencePairs) {
    if (
      !(await verifyFrozenPath({
        frozenEvidence,
        readGitBytes,
        path,
        declaredHash: hash,
      }))
    ) {
      reasonCodes.push("REFERENCE_GIT_EVIDENCE_NOT_FROZEN");
    }
  }
  const consumedPaths = new Set([
    ...frozenJson.map(([path]) => path),
    ...evidencePairs.keys(),
  ]);
  const frozenSubjectPaths = [
    ...(evidenceSubjectMap(frozenEvidence)?.keys() ?? []),
  ];
  if (
    consumedPaths.size !== frozenSubjectPaths.length ||
    frozenSubjectPaths.some((path) => !consumedPaths.has(path))
  ) {
    reasonCodes.push("REFERENCE_FREEZE_SUBJECT_SET_MISMATCH");
  }

  const uniqueReasonCodes = [...new Set(reasonCodes)];
  return uniqueReasonCodes.length === 0
    ? {
        ok: true,
        status: "READY",
        reasonCodes: [],
        bundleSha256: bundle.bundleSha256,
        applicableReferenceSetDigest:
          bundle.applicableReferenceSetDigest,
      }
    : {
        ok: false,
        status: statusFor(uniqueReasonCodes),
        reasonCodes: uniqueReasonCodes,
        bundleSha256: bundle?.bundleSha256 ?? null,
        applicableReferenceSetDigest:
          bundle?.applicableReferenceSetDigest ?? null,
      };
}

export function createReferenceReviewReadinessVerifier({
  manifest,
  catalog,
  policy,
  bundlesByWorkPackage = {},
  receiptsByPath = {},
  frozenEvidence = null,
  frozenEvidenceByWorkPackage = null,
  trustedBinding = null,
  selectedToolLocks = [],
  readGitBytes = async () => null,
  verifyFreezeRoot = async () => false,
  listFrozenPaths = async () => null,
}) {
  let assets = null;
  try {
    if (
      frozenEvidence !== null &&
      frozenEvidenceByWorkPackage !== null
    ) {
      throw new TypeError("Ambiguous freeze Attestation source.");
    }
    assets = {
      manifest: structuredClone(manifest),
      catalog: structuredClone(catalog),
      policy: structuredClone(policy),
      bundlesByWorkPackage: structuredClone(
        bundlesByWorkPackage,
      ),
      receiptsByPath: structuredClone(receiptsByPath),
      frozenEvidence: structuredClone(frozenEvidence),
      frozenEvidenceByWorkPackage: structuredClone(
        frozenEvidenceByWorkPackage,
      ),
      trustedBinding: structuredClone(trustedBinding),
      selectedToolLocks: structuredClone(selectedToolLocks),
      readGitBytes,
      verifyFreezeRoot,
      listFrozenPaths,
    };
  } catch {
    assets = null;
  }
  return async function verify(binding) {
    try {
      if (
        assets === null ||
        !keysExactly(binding, VERIFY_BINDING_KEYS) ||
        !validatePolicySchema(assets.policy) ||
        manifestWorkPackageIds(assets.manifest) === null ||
        assets.policy.profileBinding.bindingStatus !==
          "BOUND_IN_PROFILE_AND_EXECUTION_BASELINE" ||
        binding.profileSha256 !==
          assets.policy.profileBinding.profileSha256 ||
        binding.sourceCommit !==
          assets.policy.profileBinding.sourceCommit ||
        binding.executionBaselineDigest !==
          assets.policy.profileBinding.executionBaselineDigest
      ) {
        return false;
      }
      const profileApproval =
        binding.boundary === "PROFILE_APPROVAL";
      const workPackageIds = profileApproval
        ? assets.policy.profileBinding.requiredBackfillWorkPackageIds
        : [binding.workPackageId];
      if (
        !Array.isArray(workPackageIds) ||
        workPackageIds.length === 0
      ) {
        return false;
      }
      const policyWorkPackageIds = new Set(
        assets.policy.workPackagePolicies.map(
          ({ workPackageId }) => workPackageId,
        ),
      );
      const attestationMap =
        assets.frozenEvidenceByWorkPackage;
      if (
        attestationMap !== null &&
        (!attestationMap ||
          typeof attestationMap !== "object" ||
          Array.isArray(attestationMap) ||
          Object.keys(attestationMap).some(
            (workPackageId) =>
              !policyWorkPackageIds.has(workPackageId),
          ))
      ) {
        return false;
      }
      if (
        workPackageIds.length > 1 &&
        attestationMap === null
      ) {
        return false;
      }
      const usedAttestationIds = new Set();
      const usedAttestationHashes = new Set();
      for (const workPackageId of workPackageIds) {
        const bundle =
          assets.bundlesByWorkPackage[workPackageId];
        const attestation =
          attestationMap === null
            ? assets.frozenEvidence
            : Object.hasOwn(attestationMap, workPackageId)
              ? attestationMap[workPackageId]
              : null;
        if (
          !bundle ||
          bundle.workPackageId !== workPackageId ||
          !attestation ||
          usedAttestationIds.has(attestation.attestationId) ||
          usedAttestationHashes.has(attestation.attestationSha256)
        ) {
          return false;
        }
        usedAttestationIds.add(attestation.attestationId);
        usedAttestationHashes.add(attestation.attestationSha256);
        const result = await validateReferenceReviewBundle({
          manifest: assets.manifest,
          catalog: assets.catalog,
          policy: assets.policy,
          bundle,
          receiptsByPath: assets.receiptsByPath,
          expectedBinding: {
            profileSha256: binding.profileSha256,
            sourceCommit: binding.sourceCommit,
            executionBaselineDigest:
              binding.executionBaselineDigest,
            reviewBoundary: profileApproval
              ? "IMPLEMENTATION_CONFORMANCE"
              : binding.boundary,
          },
          trustedBinding: assets.trustedBinding,
          frozenEvidence: attestation,
          selectedToolLocks: assets.selectedToolLocks,
          readGitBytes: assets.readGitBytes,
          verifyFreezeRoot: assets.verifyFreezeRoot,
          listFrozenPaths: assets.listFrozenPaths,
        });
        if (!result.ok) return false;
      }
      return true;
    } catch {
      return false;
    }
  };
}

export function createDefaultDenyReferenceReviewVerifier() {
  return async function verify(binding) {
    void binding;
    return false;
  };
}
