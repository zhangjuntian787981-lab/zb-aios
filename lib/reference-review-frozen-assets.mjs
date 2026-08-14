import runtimeProofJson from "../implementation/governance/reference-review/p2-profile-backfill/reference-review-runtime-proof.v1.json" with { type: "json" };
import {
  createReferenceReviewReadinessVerifier,
  referenceReviewBundleDigests,
} from "./reference-review-readiness.mjs";
import { referenceReviewDigests } from "./reference-review-receipt-validator.mjs";

const EXPECTED_PROOF_SHA256 =
  "sha256:6dff749b0620d7c036e8be332020942466ae456df18b5e1d1d4ddb366ad3370b";
const SOURCE_COMMIT =
  "bc718bc1a069deaa388b9a00e0135c8e9427dd91";
const SOURCE_TREE =
  "2fa1d5a511215a78ce324b61c585a4d4bb9697e0";
const EVIDENCE_FREEZE_COMMIT =
  "feeda1ac6a8c236f11d3b80b240ffc757a261c56";
const EVIDENCE_FREEZE_TREE =
  "626a30ef25b68d4a24d296a2dfbae89ce72d21cc";
const PROFILE_SHA256 =
  "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5";
const EXECUTION_BASELINE_DIGEST =
  "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec";
const MANIFEST_PATH =
  "implementation/governance/work-package-manifest.v1.json";
const CATALOG_PATH =
  "implementation/governance/reference-review/reference-candidate-catalog.v1.json";
const POLICY_PATH =
  "implementation/governance/reference-review/reference-review-policy.profile-v2.v1.json";
const WORK_PACKAGE_IDS = Object.freeze(["C04", "C06", "C07"]);
const TOP_LEVEL_KEYS = Object.freeze([
  "ancestry",
  "attestationSubjects",
  "canonicalization",
  "evidenceFreezeGitObject",
  "evidenceFreezeSubjects",
  "governanceEffect",
  "isProgressTracker",
  "packages",
  "proofId",
  "proofSha256",
  "schemaVersion",
  "selfAuthorizing",
  "sourceGitObject",
  "sourceSubjects",
  "trustedBinding",
]);
const GIT_OBJECT_KEYS = Object.freeze([
  "commit",
  "commitObjectType",
  "tree",
  "treeObjectType",
]);
const GIT_SUBJECT_KEYS = Object.freeze([
  "byteLength",
  "bytesBase64",
  "mode",
  "path",
  "rawSha256",
]);
const PACKAGE_KEYS = Object.freeze([
  "attestationSubject",
  "bundleSubject",
  "evidenceSubjects",
  "frozenSourcePaths",
  "sourceExclusions",
  "sourceRoots",
  "workPackageId",
]);
const TRUSTED_BINDING_KEYS = Object.freeze([
  "candidateSourceBaselineSha256",
  "executionBaselineDigest",
  "manifestProjectId",
  "manifestSha256",
  "manifestVersion",
  "manifestWorkPackageIdsSha256",
  "profileSha256",
  "referenceCatalogSha256",
  "referencePolicySha256",
]);
const VERIFIER_TRUSTED_BINDING_KEYS = Object.freeze([
  "candidateSourceBaselineSha256",
  "manifestProjectId",
  "manifestSha256",
  "manifestVersion",
  "manifestWorkPackageIdsSha256",
  "referenceCatalogSha256",
  "referencePolicySha256",
]);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function keysExactly(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

function sameValue(left, right) {
  try {
    return (
      referenceReviewDigests.canonicalize(left) ===
      referenceReviewDigests.canonicalize(right)
    );
  } catch {
    return false;
  }
}

function sortedUniqueStrings(values) {
  return (
    Array.isArray(values) &&
    values.every((value) => typeof value === "string") &&
    values.every(
      (value, index) =>
        index === 0 || values[index - 1].localeCompare(value) < 0,
    )
  );
}

function canonicalBase64(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.byteLength; index += 8192) {
    binary += String.fromCharCode(
      ...bytes.subarray(index, index + 8192),
    );
  }
  return btoa(binary);
}

function decodeBase64(value) {
  try {
    if (typeof value !== "string" || value.length === 0) return null;
    const binary = atob(value);
    const bytes = Uint8Array.from(
      binary,
      (character) => character.charCodeAt(0),
    );
    return canonicalBase64(bytes) === value ? bytes : null;
  } catch {
    return null;
  }
}

function parseJsonBytes(bytes) {
  try {
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
  } catch {
    return null;
  }
}

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

function createSubjectIndex(subjects) {
  const index = new Map();
  let structurallyValid = Array.isArray(subjects);
  for (const subject of subjects ?? []) {
    const bytes = decodeBase64(subject?.bytesBase64);
    if (
      !keysExactly(subject, GIT_SUBJECT_KEYS) ||
      subject.mode !== "100644" ||
      !Number.isSafeInteger(subject.byteLength) ||
      subject.byteLength <= 0 ||
      bytes === null ||
      bytes.byteLength !== subject.byteLength ||
      index.has(subject.path)
    ) {
      structurallyValid = false;
      continue;
    }
    index.set(subject.path, { bytes, subject });
  }
  if (
    !sortedUniqueStrings((subjects ?? []).map(({ path }) => path))
  ) {
    structurallyValid = false;
  }
  return { index, structurallyValid };
}

function parseSubject(index, path) {
  const record = index.get(path);
  return record ? parseJsonBytes(record.bytes) : null;
}

export const REFERENCE_REVIEW_RUNTIME_PROOF = deepFreeze(
  structuredClone(runtimeProofJson),
);

const sourceState = createSubjectIndex(
  REFERENCE_REVIEW_RUNTIME_PROOF.sourceSubjects,
);
const freezeState = createSubjectIndex(
  REFERENCE_REVIEW_RUNTIME_PROOF.evidenceFreezeSubjects,
);
const attestationState = createSubjectIndex(
  REFERENCE_REVIEW_RUNTIME_PROOF.attestationSubjects,
);
const manifest = parseSubject(freezeState.index, MANIFEST_PATH);
const catalog = parseSubject(freezeState.index, CATALOG_PATH);
const policy = parseSubject(freezeState.index, POLICY_PATH);
const bundlesByWorkPackage = {};
const receiptsByPath = {};
const frozenEvidenceByWorkPackage = {};

for (const packageProof of REFERENCE_REVIEW_RUNTIME_PROOF.packages ?? []) {
  const bundle = parseSubject(
    freezeState.index,
    packageProof?.bundleSubject?.path,
  );
  const attestation = parseSubject(
    attestationState.index,
    packageProof?.attestationSubject?.path,
  );
  if (typeof packageProof?.workPackageId === "string") {
    bundlesByWorkPackage[packageProof.workPackageId] = bundle;
    frozenEvidenceByWorkPackage[packageProof.workPackageId] =
      attestation;
  }
  for (const receipt of bundle?.receipts ?? []) {
    receiptsByPath[receipt.path] = parseSubject(
      freezeState.index,
      receipt.path,
    );
  }
}

const verifierTrustedBinding = Object.fromEntries(
  VERIFIER_TRUSTED_BINDING_KEYS.map((key) => [
    key,
    REFERENCE_REVIEW_RUNTIME_PROOF.trustedBinding?.[key],
  ]),
);

async function subjectsValid(state) {
  if (!state.structurallyValid) return false;
  for (const { bytes, subject } of state.index.values()) {
    if (
      (await referenceReviewBundleDigests.bytes(bytes)) !==
      subject.rawSha256
    ) {
      return false;
    }
  }
  return true;
}

async function runtimeProofValid() {
  const proof = REFERENCE_REVIEW_RUNTIME_PROOF;
  if (
    !keysExactly(proof, TOP_LEVEL_KEYS) ||
    proof.schemaVersion !== "reference-review-runtime-proof.v1" ||
    proof.proofId !== "rrrp_feeda1ac6a8c_bc718bc1a069" ||
    proof.canonicalization !==
      "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785" ||
    proof.proofSha256 !== EXPECTED_PROOF_SHA256 ||
    (await referenceReviewDigests.value(
      withoutField(proof, "proofSha256"),
    )) !== EXPECTED_PROOF_SHA256 ||
    !keysExactly(proof.sourceGitObject, GIT_OBJECT_KEYS) ||
    proof.sourceGitObject.commit !== SOURCE_COMMIT ||
    proof.sourceGitObject.tree !== SOURCE_TREE ||
    proof.sourceGitObject.commitObjectType !== "commit" ||
    proof.sourceGitObject.treeObjectType !== "tree" ||
    !keysExactly(proof.evidenceFreezeGitObject, GIT_OBJECT_KEYS) ||
    proof.evidenceFreezeGitObject.commit !== EVIDENCE_FREEZE_COMMIT ||
    proof.evidenceFreezeGitObject.tree !== EVIDENCE_FREEZE_TREE ||
    proof.evidenceFreezeGitObject.commitObjectType !== "commit" ||
    proof.evidenceFreezeGitObject.treeObjectType !== "tree" ||
    !keysExactly(proof.ancestry, ["relationship", "verifiedBy"]) ||
    proof.ancestry.relationship !== "STRICT_ANCESTOR" ||
    proof.ancestry.verifiedBy !==
      "BUILD_TIME_LOCAL_GIT_OBJECT_READ" ||
    !keysExactly(proof.trustedBinding, TRUSTED_BINDING_KEYS) ||
    proof.trustedBinding.profileSha256 !== PROFILE_SHA256 ||
    proof.trustedBinding.executionBaselineDigest !==
      EXECUTION_BASELINE_DIGEST ||
    proof.trustedBinding.manifestSha256 !==
      "sha256:5ff440dc9d437b874a024f74593e09748fa778cae8ea2dfc3ee8653d731ea2bd" ||
    proof.trustedBinding.manifestWorkPackageIdsSha256 !==
      "sha256:d3817551b0b8e193758749dc468e4e9daecc4b4cb4945ba209ec2887237d5093" ||
    proof.trustedBinding.referenceCatalogSha256 !==
      "sha256:db37fa9e04dfe5468ef97e13de55c7702b919040fc78755d33a8db7d1018523a" ||
    proof.trustedBinding.referencePolicySha256 !==
      "sha256:6402d72d3d7c0a88c362a2dbb376645dabc13c2aceb47825cb02fa031428836d" ||
    proof.trustedBinding.candidateSourceBaselineSha256 !==
      "sha256:d326404ed55b43eccdba01287793ea64812aaafa83f02596bd58b3f83ccdad7a" ||
    proof.trustedBinding.manifestProjectId !==
      "generic-multi-enterprise-ai-platform-v5" ||
    proof.trustedBinding.manifestVersion !== "1.0.0" ||
    proof.governanceEffect !== "NONE" ||
    proof.isProgressTracker !== false ||
    proof.selfAuthorizing !== false ||
    !(await subjectsValid(sourceState)) ||
    !(await subjectsValid(freezeState)) ||
    !(await subjectsValid(attestationState))
  ) {
    return null;
  }

  if (
    (await referenceReviewDigests.value(manifest)) !==
      proof.trustedBinding.manifestSha256 ||
    (await referenceReviewBundleDigests.catalog(catalog)) !==
      proof.trustedBinding.referenceCatalogSha256 ||
    (await referenceReviewBundleDigests.policy(policy)) !==
      proof.trustedBinding.referencePolicySha256 ||
    policy?.policyPath !== POLICY_PATH ||
    policy?.profileBinding?.sourceCommit !== SOURCE_COMMIT ||
    policy?.profileBinding?.profileSha256 !== PROFILE_SHA256 ||
    policy?.profileBinding?.executionBaselineDigest !==
      EXECUTION_BASELINE_DIGEST ||
    !Array.isArray(proof.packages) ||
    proof.packages.length !== WORK_PACKAGE_IDS.length ||
    !sameValue(
      proof.packages.map(({ workPackageId }) => workPackageId),
      WORK_PACKAGE_IDS,
    ) ||
    attestationState.index.size !== WORK_PACKAGE_IDS.length
  ) {
    return null;
  }

  const usedFreezePaths = new Set();
  const expectedSourcePaths = new Set();
  const freezeRoots = [];
  for (const packageProof of proof.packages) {
    if (
      !keysExactly(packageProof, PACKAGE_KEYS) ||
      !sortedUniqueStrings(packageProof.sourceRoots) ||
      !sortedUniqueStrings(packageProof.sourceExclusions) ||
      !sortedUniqueStrings(packageProof.frozenSourcePaths) ||
      packageProof.sourceExclusions.length !== 0 ||
      !sameValue(
        packageProof.sourceRoots,
        packageProof.frozenSourcePaths,
      ) ||
      !sortedUniqueStrings(
        (packageProof.evidenceSubjects ?? []).map(({ path }) => path),
      ) ||
      !(packageProof.evidenceSubjects ?? []).every((subject) =>
        keysExactly(subject, ["path", "sha256"]),
      )
    ) {
      return null;
    }

    for (const evidenceSubject of packageProof.evidenceSubjects) {
      const frozen = freezeState.index.get(evidenceSubject.path);
      if (
        !frozen ||
        frozen.subject.rawSha256 !== evidenceSubject.sha256
      ) {
        return null;
      }
      usedFreezePaths.add(evidenceSubject.path);
    }

    const bundle = bundlesByWorkPackage[packageProof.workPackageId];
    const bundleRecord = freezeState.index.get(
      packageProof.bundleSubject?.path,
    );
    const attestation =
      frozenEvidenceByWorkPackage[packageProof.workPackageId];
    const attestationRecord = attestationState.index.get(
      packageProof.attestationSubject?.path,
    );
    if (
      !keysExactly(packageProof.bundleSubject, [
        "bundleSha256",
        "path",
        "rawSha256",
      ]) ||
      !keysExactly(packageProof.attestationSubject, [
        "attestationId",
        "attestationSha256",
        "path",
        "rawSha256",
      ]) ||
      !bundleRecord ||
      bundleRecord.subject.rawSha256 !==
        packageProof.bundleSubject.rawSha256 ||
      bundle?.workPackageId !== packageProof.workPackageId ||
      bundle?.bundlePath !== packageProof.bundleSubject.path ||
      bundle?.bundleSha256 !== packageProof.bundleSubject.bundleSha256 ||
      (await referenceReviewBundleDigests.bundle(bundle)) !==
        packageProof.bundleSubject.bundleSha256 ||
      !attestationRecord ||
      attestationRecord.subject.rawSha256 !==
        packageProof.attestationSubject.rawSha256 ||
      attestation?.attestationId !==
        packageProof.attestationSubject.attestationId ||
      attestation?.attestationSha256 !==
        packageProof.attestationSubject.attestationSha256 ||
      (await referenceReviewBundleDigests.freezeAttestation(
        attestation,
      )) !== attestation?.attestationSha256 ||
      attestation?.evidenceFreezeCommit !== EVIDENCE_FREEZE_COMMIT ||
      attestation?.evidenceFreezeTree !== EVIDENCE_FREEZE_TREE ||
      attestation?.sourceCommit !== SOURCE_COMMIT ||
      attestation?.profileSha256 !== PROFILE_SHA256 ||
      attestation?.executionBaselineDigest !==
        EXECUTION_BASELINE_DIGEST ||
      attestation?.referenceCatalogSha256 !==
        proof.trustedBinding.referenceCatalogSha256 ||
      attestation?.referencePolicySha256 !==
        proof.trustedBinding.referencePolicySha256 ||
      !sameValue(
        attestation?.evidenceSubjects,
        packageProof.evidenceSubjects,
      ) ||
      attestation?.attestationIncludedInEvidenceFreeze !== false ||
      attestation?.upstreamProfileIncludesReferenceReviewDigests !==
        false ||
      attestation
          ?.upstreamExecutionBaselineIncludesReferenceReviewDigests !==
        false ||
      attestation?.governanceEffect !== "NONE" ||
      attestation?.isProgressTracker !== false ||
      attestation?.selfAuthorizing !== false ||
      freezeState.index.has(packageProof.attestationSubject.path)
    ) {
      return null;
    }

    const basePath = packageProof.bundleSubject.path.replace(
      /\/reference-review-bundle\.v1\.json$/u,
      "",
    );
    const sourceIndex = parseSubject(
      freezeState.index,
      `${basePath}/source-integration-index.v2.json`,
    );
    const integratedSourcePaths = (sourceIndex?.integrations ?? [])
      .map(({ sourcePath }) => sourcePath)
      .sort();
    if (!sameValue(integratedSourcePaths, packageProof.sourceRoots)) {
      return null;
    }
    for (const integration of sourceIndex?.integrations ?? []) {
      expectedSourcePaths.add(integration.sourcePath);
      expectedSourcePaths.add(integration.implementationEvidenceRef);
    }

    freezeRoots.push({
      evidenceSubjectsSha256: await referenceReviewDigests.value(
        packageProof.evidenceSubjects,
      ),
      sourceRoots: structuredClone(packageProof.sourceRoots),
      sourceExclusions: structuredClone(
        packageProof.sourceExclusions,
      ),
      frozenSourcePaths: structuredClone(
        packageProof.frozenSourcePaths,
      ),
    });
  }

  if (
    !sameValue(
      [...usedFreezePaths].sort(),
      [...freezeState.index.keys()].sort(),
    ) ||
    !sameValue(
      [...expectedSourcePaths].sort(),
      [...sourceState.index.keys()].sort(),
    )
  ) {
    return null;
  }
  for (const [path, source] of sourceState.index) {
    const frozen = freezeState.index.get(path);
    if (
      !frozen ||
      source.subject.mode !== frozen.subject.mode ||
      source.subject.byteLength !== frozen.subject.byteLength ||
      source.subject.rawSha256 !== frozen.subject.rawSha256 ||
      !sameValue([...source.bytes], [...frozen.bytes])
    ) {
      return null;
    }
  }

  return Object.freeze({ freezeRoots });
}

const runtimeStatePromise = runtimeProofValid().catch(() => null);

async function readGitBytes(request) {
  if (
    (await runtimeStatePromise) === null ||
    !keysExactly(request, ["commit", "path"])
  ) {
    return null;
  }
  const state =
    request.commit === SOURCE_COMMIT
      ? sourceState
      : request.commit === EVIDENCE_FREEZE_COMMIT
        ? freezeState
        : null;
  const bytes = state?.index.get(request.path)?.bytes;
  return bytes ? new Uint8Array(bytes) : null;
}

async function verifyFreezeRoot(binding) {
  const state = await runtimeStatePromise;
  if (
    state === null ||
    !keysExactly(binding, [
      "evidenceFreezeCommit",
      "evidenceFreezeTree",
      "evidenceSubjectsSha256",
      "manifestSha256",
      "sourceCommit",
      "sourceExclusions",
      "sourceRoots",
    ]) ||
    binding.evidenceFreezeCommit !== EVIDENCE_FREEZE_COMMIT ||
    binding.evidenceFreezeTree !== EVIDENCE_FREEZE_TREE ||
    binding.sourceCommit !== SOURCE_COMMIT ||
    binding.manifestSha256 !==
      REFERENCE_REVIEW_RUNTIME_PROOF.trustedBinding.manifestSha256
  ) {
    return false;
  }
  return (
    state.freezeRoots.filter(
      (root) =>
        root.evidenceSubjectsSha256 ===
          binding.evidenceSubjectsSha256 &&
        sameValue(root.sourceRoots, binding.sourceRoots) &&
        sameValue(root.sourceExclusions, binding.sourceExclusions),
    ).length === 1
  );
}

async function listFrozenPaths(binding) {
  const state = await runtimeStatePromise;
  if (
    state === null ||
    !keysExactly(binding, [
      "evidenceFreezeCommit",
      "evidenceFreezeTree",
      "sourceExclusions",
      "sourceRoots",
    ]) ||
    binding.evidenceFreezeCommit !== EVIDENCE_FREEZE_COMMIT ||
    binding.evidenceFreezeTree !== EVIDENCE_FREEZE_TREE
  ) {
    return null;
  }
  const matches = state.freezeRoots.filter(
    (root) =>
      sameValue(root.sourceRoots, binding.sourceRoots) &&
      sameValue(root.sourceExclusions, binding.sourceExclusions),
  );
  return matches.length === 1
    ? [...matches[0].frozenSourcePaths]
    : null;
}

export const REFERENCE_REVIEW_FROZEN_ASSETS = deepFreeze({
  manifest,
  catalog,
  policy,
  bundlesByWorkPackage,
  receiptsByPath,
  frozenEvidenceByWorkPackage,
  trustedBinding: verifierTrustedBinding,
  selectedToolLocks: [],
  readGitBytes,
  verifyFreezeRoot,
  listFrozenPaths,
});

export const verifyReferenceReviewReadinessFromFrozenAssets =
  createReferenceReviewReadinessVerifier(
    REFERENCE_REVIEW_FROZEN_ASSETS,
  );
