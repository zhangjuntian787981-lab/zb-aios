#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import {
  referenceReviewDigests,
} from "../lib/reference-review-receipt-validator.mjs";
import {
  createReferenceReviewReadinessVerifier,
  referenceReviewBundleDigests,
  validateReferenceReviewBundle,
} from "../lib/reference-review-readiness.mjs";

const execFileAsync = promisify(execFile);
const TRUSTED_GIT_EXECUTABLE = "/usr/bin/git";
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_OBJECT_ID = /^[a-f0-9]{40}$/;
const GIT_TREE_ENTRY = /^(\d{6}) (blob|tree) ([a-f0-9]{40})\t(.+)$/;

const MANIFEST_PATH =
  "implementation/governance/work-package-manifest.v1.json";
const CATALOG_PATH =
  "implementation/governance/reference-review/reference-candidate-catalog.v1.json";
const POLICY_PATH =
  "implementation/governance/reference-review/reference-review-policy.profile-v2.v1.json";
const CANDIDATE_SOURCE_PATH =
  "docs/plans/通用多企业AI员工平台_v5.2最小验收项与开源参考矩阵_v1.0.md";

const COMMON_EVIDENCE_PATHS = Object.freeze([
  "docs/adr/0026-p1-reference-backfill-formal-decisions.md",
  CANDIDATE_SOURCE_PATH,
  "implementation/governance/reference-review/p2-profile-backfill-official-research.v1.md",
  "implementation/governance/reference-review/p2-profile-backfill-preparation.v1.json",
  CATALOG_PATH,
  POLICY_PATH,
  MANIFEST_PATH,
]);

const PACKAGE_BASE =
  "implementation/governance/reference-review/p2-profile-backfill";

function packagePath(packageName, name) {
  return `${PACKAGE_BASE}/${packageName}/${name}`;
}

const PACKAGE_DEFINITIONS = Object.freeze([
  Object.freeze({
    workPackageId: "C04",
    attestationId: "rrfa_c04_profile_v2_backfill_feeda1ac",
    attestationPath: packagePath(
      "c04",
      "reference-review-freeze-attestation.v1.json",
    ),
    bundlePath: packagePath("c04", "reference-review-bundle.v1.json"),
    bundleSha256:
      "sha256:5ecba3bd23b210a8238c4a6f4a04dee9b022fff7d0c2b64641ff8e414a4c9ec3",
    sourceRoots: Object.freeze([
      "lib/keycloak-scim-provisioning-adapter.mjs",
    ]),
    sourceSubjectPaths: Object.freeze([
      "implementation/p1/c04/c04-verification-evidence.v1.json",
      "lib/keycloak-scim-provisioning-adapter.mjs",
    ]),
    packageEvidencePaths: Object.freeze([
      packagePath("c04", "applicability-evidence.v2.json"),
      packagePath("c04", "dependency-lock-scan-input.v2.json"),
      packagePath("c04", "dependency-lock.v1.json"),
      packagePath("c04", "manual-supplement-scan-input.v1.json"),
      packagePath(
        "c04",
        "r09-keycloak-implementation-conformance.v1.json",
      ),
      packagePath(
        "c04",
        "r09-keycloak-reference-review-receipt.v1.json",
      ),
      packagePath("c04", "reference-matrix-scan-input.v1.json"),
      packagePath("c04", "reference-matrix-slice.v1.json"),
      packagePath("c04", "reference-review-bundle.v1.json"),
      packagePath("c04", "source-integration-index.v2.json"),
      packagePath("c04", "source-integration-scan-input.v2.json"),
      "implementation/p1/c04/c04-verification-evidence.v1.json",
      "implementation/p1/c04/keycloak/keycloak-distribution.lock.json",
      "lib/keycloak-scim-provisioning-adapter.mjs",
    ]),
  }),
  Object.freeze({
    workPackageId: "C06",
    attestationId: "rrfa_c06_profile_v2_backfill_feeda1ac",
    attestationPath: packagePath(
      "c06",
      "reference-review-freeze-attestation.v1.json",
    ),
    bundlePath: packagePath("c06", "reference-review-bundle.v1.json"),
    bundleSha256:
      "sha256:c4726b6c27ed19ea73bc01c068d39c5216f1a6a8ca2adfd1b85ab1c5e7edecf9",
    sourceRoots: Object.freeze([
      "lib/openfga-pdp.mjs",
    ]),
    sourceSubjectPaths: Object.freeze([
      "implementation/p1/c06/c06-verification-evidence.v1.json",
      "lib/openfga-pdp.mjs",
    ]),
    packageEvidencePaths: Object.freeze([
      packagePath("c06", "applicability-evidence.v2.json"),
      packagePath("c06", "dependency-lock-scan-input.v2.json"),
      packagePath("c06", "dependency-lock.v1.json"),
      packagePath("c06", "manual-supplement-scan-input.v1.json"),
      packagePath(
        "c06",
        "r11-openfga-implementation-conformance.v1.json",
      ),
      packagePath(
        "c06",
        "r11-openfga-reference-review-receipt.v1.json",
      ),
      packagePath("c06", "reference-matrix-scan-input.v1.json"),
      packagePath("c06", "reference-matrix-slice.v1.json"),
      packagePath("c06", "reference-review-bundle.v1.json"),
      packagePath("c06", "source-integration-index.v2.json"),
      packagePath("c06", "source-integration-scan-input.v2.json"),
      "implementation/p1/c06/c06-verification-evidence.v1.json",
      "implementation/p1/c06/openfga/openfga-distribution.lock.json",
      "lib/openfga-pdp.mjs",
    ]),
  }),
  Object.freeze({
    workPackageId: "C07",
    attestationId: "rrfa_c07_profile_v2_backfill_feeda1ac",
    attestationPath: packagePath(
      "c07",
      "reference-review-freeze-attestation.v1.json",
    ),
    bundlePath: packagePath("c07", "reference-review-bundle.v1.json"),
    bundleSha256:
      "sha256:a450c479d9fd0f39a066254afc4cdc72317a9f907548ada51fa7b347f879e1e4",
    sourceRoots: Object.freeze([
      "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
      "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    ]),
    sourceSubjectPaths: Object.freeze([
      "implementation/p1/c07/c07-verification-evidence.v1.json",
      "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
      "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
    ]),
    packageEvidencePaths: Object.freeze([
      packagePath("c07", "applicability-evidence.v2.json"),
      packagePath("c07", "dependency-lock-scan-input.v2.json"),
      packagePath("c07", "dependency-lock.v1.json"),
      packagePath("c07", "manual-supplement-scan-input.v1.json"),
      packagePath(
        "c07",
        "r12-pgvector-implementation-conformance.v1.json",
      ),
      packagePath(
        "c07",
        "r12-pgvector-reference-review-receipt.v1.json",
      ),
      packagePath(
        "c07",
        "r12-postgresql-rls-implementation-conformance.v1.json",
      ),
      packagePath(
        "c07",
        "r12-postgresql-rls-reference-review-receipt.v1.json",
      ),
      packagePath("c07", "reference-matrix-scan-input.v1.json"),
      packagePath("c07", "reference-matrix-slice.v1.json"),
      packagePath("c07", "reference-review-bundle.v1.json"),
      packagePath("c07", "source-integration-index.v2.json"),
      packagePath("c07", "source-integration-scan-input.v2.json"),
      "implementation/p1/c07/c07-verification-evidence.v1.json",
      "implementation/p1/c07/pgvector/pgvector-distribution.lock.json",
      "implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql",
      "implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql",
      "implementation/p1/c07/postgresql/postgresql-distribution.lock.json",
    ]),
  }),
]);

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

const REFERENCE_REVIEW_FREEZE_BASELINE = deepFreeze({
  proofId: "rrrp_feeda1ac6a8c_bc718bc1a069",
  sourceCommit: "bc718bc1a069deaa388b9a00e0135c8e9427dd91",
  sourceTree: "2fa1d5a511215a78ce324b61c585a4d4bb9697e0",
  evidenceFreezeCommit: "feeda1ac6a8c236f11d3b80b240ffc757a261c56",
  evidenceFreezeTree: "626a30ef25b68d4a24d296a2dfbae89ce72d21cc",
  profileSha256:
    "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5",
  executionBaselineDigest:
    "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec",
  manifestSha256:
    "sha256:5ff440dc9d437b874a024f74593e09748fa778cae8ea2dfc3ee8653d731ea2bd",
  referenceCatalogSha256:
    "sha256:db37fa9e04dfe5468ef97e13de55c7702b919040fc78755d33a8db7d1018523a",
  referencePolicySha256:
    "sha256:6402d72d3d7c0a88c362a2dbb376645dabc13c2aceb47825cb02fa031428836d",
  packages: PACKAGE_DEFINITIONS,
});

function fail(message) {
  throw new Error(message);
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function safeGitPath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.split("/").includes("..") &&
    !value.split("/").includes(".")
  );
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

function sameValue(left, right) {
  return (
    referenceReviewDigests.canonicalize(left) ===
    referenceReviewDigests.canonicalize(right)
  );
}

function controlledGitEnvironment() {
  const environment = {};
  for (const key of ["SYSTEMROOT", "TEMP", "TMP", "TMPDIR"]) {
    if (typeof process.env[key] === "string") {
      environment[key] = process.env[key];
    }
  }
  return {
    ...environment,
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_COUNT: "0",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_DISCOVERY_ACROSS_FILESYSTEM: "0",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    LC_ALL: "C",
  };
}

function createLocalGitReader(repositoryPath) {
  if (typeof repositoryPath !== "string" || repositoryPath.length === 0) {
    fail("repositoryPath is required.");
  }
  const environment = controlledGitEnvironment();

  async function run(args, encoding = "utf8") {
    return execFileAsync(
      TRUSTED_GIT_EXECUTABLE,
      ["--no-replace-objects", ...args],
      {
        cwd: repositoryPath,
        encoding,
        env: environment,
        maxBuffer: 32 * 1024 * 1024,
      },
    );
  }

  async function readBlob(commit, path) {
    if (!GIT_OBJECT_ID.test(commit ?? "") || !safeGitPath(path)) {
      fail("Git blob reference is invalid.");
    }
    const { stdout } = await run(
      ["cat-file", "blob", `${commit}:${path}`],
      null,
    );
    return Buffer.from(stdout);
  }

  return Object.freeze({
    async objectType(objectId) {
      if (!GIT_OBJECT_ID.test(objectId ?? "")) return null;
      try {
        const { stdout } = await run(["cat-file", "-t", objectId]);
        return stdout.trim();
      } catch {
        return null;
      }
    },
    async commitTree(commit) {
      if (!GIT_OBJECT_ID.test(commit ?? "")) return null;
      try {
        const { stdout } = await run([
          "show",
          "-s",
          "--format=%T",
          commit,
        ]);
        return stdout.trim();
      } catch {
        return null;
      }
    },
    async isStrictAncestor(ancestor, descendant) {
      if (
        !GIT_OBJECT_ID.test(ancestor ?? "") ||
        !GIT_OBJECT_ID.test(descendant ?? "") ||
        ancestor === descendant
      ) {
        return false;
      }
      try {
        await run(["merge-base", "--is-ancestor", ancestor, descendant]);
        return true;
      } catch {
        return false;
      }
    },
    readBlob,
    async readSubject(commit, path) {
      if (!GIT_OBJECT_ID.test(commit ?? "") || !safeGitPath(path)) {
        fail("Git subject reference is invalid.");
      }
      const { stdout } = await run([
        "ls-tree",
        "-z",
        commit,
        "--",
        path,
      ]);
      const entries = stdout.split("\0").filter(Boolean);
      if (entries.length !== 1) fail(`Git subject is absent: ${path}`);
      const match = GIT_TREE_ENTRY.exec(entries[0]);
      if (
        !match ||
        match[1] !== "100644" ||
        match[2] !== "blob" ||
        match[4] !== path
      ) {
        fail(`Git subject mode or type is invalid: ${path}`);
      }
      const bytes = await readBlob(commit, path);
      return {
        path,
        mode: match[1],
        byteLength: bytes.byteLength,
        rawSha256: sha256Bytes(bytes),
        bytesBase64: bytes.toString("base64"),
      };
    },
    async listPaths(commit, roots, exclusions) {
      if (
        !GIT_OBJECT_ID.test(commit ?? "") ||
        !sortedUniqueStrings(roots) ||
        roots.length === 0 ||
        roots.some((path) => !safeGitPath(path)) ||
        !sortedUniqueStrings(exclusions) ||
        exclusions.some((path) => !safeGitPath(path))
      ) {
        fail("Git path enumeration binding is invalid.");
      }
      const { stdout } = await run([
        "ls-tree",
        "-r",
        "--name-only",
        "-z",
        commit,
        "--",
        ...roots,
      ]);
      return stdout
        .split("\0")
        .filter(Boolean)
        .filter(
          (path) =>
            !exclusions.some(
              (excluded) =>
                path === excluded || path.startsWith(`${excluded}/`),
            ),
        )
        .sort();
    },
    async pathExists(commit, path) {
      try {
        await readBlob(commit, path);
        return true;
      } catch {
        return false;
      }
    },
  });
}

function parseJson(bytes, path) {
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch {
    fail(`Frozen JSON is invalid: ${path}`);
  }
}

function serializedJson(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function inMemorySubject(path, bytes) {
  return {
    path,
    mode: "100644",
    byteLength: bytes.byteLength,
    rawSha256: sha256Bytes(bytes),
    bytesBase64: bytes.toString("base64"),
  };
}

function evidenceSubject(subject) {
  return {
    path: subject.path,
    sha256: subject.rawSha256,
  };
}

function exactEvidencePaths(definition) {
  const paths = [
    ...COMMON_EVIDENCE_PATHS,
    ...definition.packageEvidencePaths,
  ].sort();
  if (!sortedUniqueStrings(paths)) {
    fail(`${definition.workPackageId} evidence paths are not unique.`);
  }
  return paths;
}

async function frozenJson(git, commit, path) {
  return parseJson(await git.readBlob(commit, path), path);
}

async function buildArtifacts({ baseline, git }) {
  for (const value of [
    baseline.sourceCommit,
    baseline.sourceTree,
    baseline.evidenceFreezeCommit,
    baseline.evidenceFreezeTree,
  ]) {
    if (!GIT_OBJECT_ID.test(value ?? "")) {
      fail("Frozen Git identifiers are invalid.");
    }
  }
  for (const value of [
    baseline.profileSha256,
    baseline.executionBaselineDigest,
    baseline.manifestSha256,
    baseline.referenceCatalogSha256,
    baseline.referencePolicySha256,
  ]) {
    if (!SHA256.test(value ?? "")) {
      fail("Frozen digest binding is invalid.");
    }
  }
  if (
    (await git.objectType(baseline.sourceCommit)) !== "commit" ||
    (await git.objectType(baseline.evidenceFreezeCommit)) !== "commit" ||
    (await git.objectType(baseline.sourceTree)) !== "tree" ||
    (await git.objectType(baseline.evidenceFreezeTree)) !== "tree"
  ) {
    fail("Source and evidence freeze commit/tree object types are invalid.");
  }
  if (
    (await git.commitTree(baseline.sourceCommit)) !== baseline.sourceTree ||
    (await git.commitTree(baseline.evidenceFreezeCommit)) !==
      baseline.evidenceFreezeTree
  ) {
    fail("A frozen commit does not match its declared tree.");
  }
  if (
    !(await git.isStrictAncestor(
      baseline.sourceCommit,
      baseline.evidenceFreezeCommit,
    ))
  ) {
    fail("sourceCommit must be a strict ancestor of evidenceFreezeCommit.");
  }

  const manifest = await frozenJson(
    git,
    baseline.evidenceFreezeCommit,
    MANIFEST_PATH,
  );
  const catalog = await frozenJson(
    git,
    baseline.evidenceFreezeCommit,
    CATALOG_PATH,
  );
  const policy = await frozenJson(
    git,
    baseline.evidenceFreezeCommit,
    POLICY_PATH,
  );
  const manifestSha256 = await referenceReviewDigests.value(manifest);
  const referenceCatalogSha256 =
    await referenceReviewBundleDigests.catalog(catalog);
  const referencePolicySha256 =
    await referenceReviewBundleDigests.policy(policy);
  if (
    manifestSha256 !== baseline.manifestSha256 ||
    referenceCatalogSha256 !== baseline.referenceCatalogSha256 ||
    referencePolicySha256 !== baseline.referencePolicySha256 ||
    policy?.manifest?.path !== MANIFEST_PATH ||
    policy?.manifest?.canonicalSha256 !== manifestSha256 ||
    policy?.catalog?.path !== CATALOG_PATH ||
    policy?.catalog?.canonicalSha256 !== referenceCatalogSha256 ||
    policy?.policyPath !== POLICY_PATH ||
    policy?.candidateSourceBaseline?.path !== CANDIDATE_SOURCE_PATH ||
    policy?.profileBinding?.sourceCommit !== baseline.sourceCommit ||
    policy?.profileBinding?.profileSha256 !== baseline.profileSha256 ||
    policy?.profileBinding?.executionBaselineDigest !==
      baseline.executionBaselineDigest
  ) {
    fail("Reference Review trusted binding is stale.");
  }

  const manifestWorkPackageIds = manifest.work_packages
    .map(({ id }) => id)
    .sort();
  const trustedBinding = {
    candidateSourceBaselineSha256:
      policy.candidateSourceBaseline.sha256,
    manifestProjectId: manifest.project_id,
    manifestSha256,
    manifestVersion: manifest.manifest_version,
    manifestWorkPackageIdsSha256:
      await referenceReviewDigests.value(manifestWorkPackageIds),
    referenceCatalogSha256,
    referencePolicySha256,
    profileSha256: baseline.profileSha256,
    executionBaselineDigest: baseline.executionBaselineDigest,
  };
  const verifierTrustedBinding = {
    candidateSourceBaselineSha256:
      trustedBinding.candidateSourceBaselineSha256,
    manifestProjectId: trustedBinding.manifestProjectId,
    manifestSha256: trustedBinding.manifestSha256,
    manifestVersion: trustedBinding.manifestVersion,
    manifestWorkPackageIdsSha256:
      trustedBinding.manifestWorkPackageIdsSha256,
    referenceCatalogSha256:
      trustedBinding.referenceCatalogSha256,
    referencePolicySha256: trustedBinding.referencePolicySha256,
  };

  const frozenSubjectCache = new Map();
  async function getFrozenSubject(path) {
    if (!frozenSubjectCache.has(path)) {
      frozenSubjectCache.set(
        path,
        await git.readSubject(baseline.evidenceFreezeCommit, path),
      );
    }
    return frozenSubjectCache.get(path);
  }

  const bundlesByWorkPackage = {};
  const receiptsByPath = {};
  const attestationsByWorkPackage = {};
  const packageProofs = [];
  const freezeRoots = [];
  const attestationSubjects = [];

  for (const definition of baseline.packages) {
    if (
      await git.pathExists(
        baseline.evidenceFreezeCommit,
        definition.attestationPath,
      )
    ) {
      fail("A Freeze Attestation is included in evidenceFreezeCommit.");
    }
    const workPackagePolicy = policy.workPackagePolicies.find(
      ({ workPackageId }) =>
        workPackageId === definition.workPackageId,
    );
    if (
      !workPackagePolicy ||
      !sameValue(
        workPackagePolicy.applicabilityEvidence.sourceRoots,
        definition.sourceRoots,
      ) ||
      workPackagePolicy.applicabilityEvidence.sourceExclusions.length !== 0
    ) {
      fail(`${definition.workPackageId} source roots are stale.`);
    }
    const bundle = await frozenJson(
      git,
      baseline.evidenceFreezeCommit,
      definition.bundlePath,
    );
    if (
      bundle?.workPackageId !== definition.workPackageId ||
      bundle?.bundlePath !== definition.bundlePath ||
      bundle?.bundleSha256 !== definition.bundleSha256 ||
      (await referenceReviewBundleDigests.bundle(bundle)) !==
        definition.bundleSha256 ||
      bundle?.sourceCommit !== baseline.sourceCommit ||
      bundle?.profileSha256 !== baseline.profileSha256 ||
      bundle?.executionBaselineDigest !==
        baseline.executionBaselineDigest ||
      bundle?.referenceCatalogSha256 !== referenceCatalogSha256 ||
      bundle?.referencePolicySha256 !== referencePolicySha256
    ) {
      fail(`${definition.workPackageId} Bundle binding is stale.`);
    }
    bundlesByWorkPackage[definition.workPackageId] = bundle;
    for (const receipt of bundle.receipts) {
      receiptsByPath[receipt.path] = await frozenJson(
        git,
        baseline.evidenceFreezeCommit,
        receipt.path,
      );
    }

    const evidenceSubjects = [];
    for (const path of exactEvidencePaths(definition)) {
      evidenceSubjects.push(evidenceSubject(await getFrozenSubject(path)));
    }
    const attestation = {
      schemaVersion: "reference-review-freeze-attestation.v1",
      attestationId: definition.attestationId,
      evidenceFreezeCommit: baseline.evidenceFreezeCommit,
      evidenceFreezeTree: baseline.evidenceFreezeTree,
      sourceCommit: baseline.sourceCommit,
      profileSha256: baseline.profileSha256,
      executionBaselineDigest: baseline.executionBaselineDigest,
      referenceCatalogSha256,
      referencePolicySha256,
      bundleSubjects: [
        {
          workPackageId: definition.workPackageId,
          path: definition.bundlePath,
          sha256: definition.bundleSha256,
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
    attestation.attestationSha256 =
      await referenceReviewBundleDigests.freezeAttestation(attestation);
    const attestationBytes = serializedJson(attestation);
    const attestationSubject = inMemorySubject(
      definition.attestationPath,
      attestationBytes,
    );
    attestationsByWorkPackage[definition.workPackageId] = attestation;
    attestationSubjects.push(attestationSubject);

    const frozenSourcePaths = await git.listPaths(
      baseline.evidenceFreezeCommit,
      definition.sourceRoots,
      [],
    );
    if (!sameValue(frozenSourcePaths, definition.sourceRoots)) {
      fail(`${definition.workPackageId} frozen source paths are incomplete.`);
    }
    const evidenceSubjectsSha256 =
      await referenceReviewDigests.value(evidenceSubjects);
    freezeRoots.push({
      evidenceSubjectsSha256,
      sourceRoots: structuredClone(definition.sourceRoots),
      sourceExclusions: [],
    });
    const bundleRawSha256 = (
      await getFrozenSubject(definition.bundlePath)
    ).rawSha256;
    packageProofs.push({
      workPackageId: definition.workPackageId,
      sourceRoots: structuredClone(definition.sourceRoots),
      sourceExclusions: [],
      frozenSourcePaths,
      bundleSubject: {
        path: definition.bundlePath,
        rawSha256: bundleRawSha256,
        bundleSha256: definition.bundleSha256,
      },
      attestationSubject: {
        path: definition.attestationPath,
        rawSha256: attestationSubject.rawSha256,
        attestationId: definition.attestationId,
        attestationSha256: attestation.attestationSha256,
      },
      evidenceSubjects: structuredClone(evidenceSubjects),
    });
  }

  const sourceSubjectPaths = [
    ...new Set(
      baseline.packages.flatMap(
        ({ sourceSubjectPaths }) => sourceSubjectPaths,
      ),
    ),
  ].sort();
  const sourceSubjects = [];
  for (const path of sourceSubjectPaths) {
    const sourceSubject = await git.readSubject(
      baseline.sourceCommit,
      path,
    );
    const frozenSubject = await getFrozenSubject(path);
    if (
      sourceSubject.mode !== frozenSubject.mode ||
      sourceSubject.byteLength !== frozenSubject.byteLength ||
      sourceSubject.rawSha256 !== frozenSubject.rawSha256 ||
      sourceSubject.bytesBase64 !== frozenSubject.bytesBase64
    ) {
      fail(`Source subject changed before evidence freeze: ${path}`);
    }
    sourceSubjects.push(sourceSubject);
  }

  const evidenceFreezeSubjects = [
    ...frozenSubjectCache.values(),
  ].sort((left, right) => left.path.localeCompare(right.path));
  attestationSubjects.sort((left, right) =>
    left.path.localeCompare(right.path),
  );

  const readGitBytes = async ({ commit, path }) => {
    if (
      ![baseline.sourceCommit, baseline.evidenceFreezeCommit].includes(
        commit,
      )
    ) {
      return null;
    }
    try {
      return new Uint8Array(await git.readBlob(commit, path));
    } catch {
      return null;
    }
  };
  const verifyFreezeRoot = async (binding) =>
    binding?.evidenceFreezeCommit === baseline.evidenceFreezeCommit &&
    binding?.evidenceFreezeTree === baseline.evidenceFreezeTree &&
    binding?.sourceCommit === baseline.sourceCommit &&
    binding?.manifestSha256 === manifestSha256 &&
    freezeRoots.some(
      (root) =>
        root.evidenceSubjectsSha256 ===
          binding.evidenceSubjectsSha256 &&
        sameValue(root.sourceRoots, binding.sourceRoots) &&
        sameValue(root.sourceExclusions, binding.sourceExclusions),
    );
  const listFrozenPaths = async ({
    evidenceFreezeCommit,
    evidenceFreezeTree,
    sourceRoots,
    sourceExclusions,
  }) =>
    evidenceFreezeCommit === baseline.evidenceFreezeCommit &&
    evidenceFreezeTree === baseline.evidenceFreezeTree
      ? git.listPaths(
          evidenceFreezeCommit,
          sourceRoots,
          sourceExclusions,
        )
      : null;
  const expectedBinding = {
    profileSha256: baseline.profileSha256,
    sourceCommit: baseline.sourceCommit,
    executionBaselineDigest: baseline.executionBaselineDigest,
    reviewBoundary: "IMPLEMENTATION_CONFORMANCE",
  };
  for (const definition of baseline.packages) {
    const result = await validateReferenceReviewBundle({
      manifest,
      catalog,
      policy,
      bundle: bundlesByWorkPackage[definition.workPackageId],
      receiptsByPath,
      expectedBinding,
      trustedBinding: verifierTrustedBinding,
      frozenEvidence:
        attestationsByWorkPackage[definition.workPackageId],
      selectedToolLocks: [],
      readGitBytes,
      verifyFreezeRoot,
      listFrozenPaths,
    });
    if (!result.ok) {
      fail(
        `${definition.workPackageId} Attestation fails closed: ${result.reasonCodes.join(",")}`,
      );
    }
  }
  const verifyProfileReferenceReview =
    createReferenceReviewReadinessVerifier({
      manifest,
      catalog,
      policy,
      bundlesByWorkPackage,
      receiptsByPath,
      frozenEvidenceByWorkPackage: attestationsByWorkPackage,
      trustedBinding: verifierTrustedBinding,
      selectedToolLocks: [],
      readGitBytes,
      verifyFreezeRoot,
      listFrozenPaths,
    });
  if (
    !(await verifyProfileReferenceReview({
      boundary: "PROFILE_APPROVAL",
      executionBaselineDigest: baseline.executionBaselineDigest,
      profileApprovalId: null,
      profileSha256: baseline.profileSha256,
      sourceCommit: baseline.sourceCommit,
      workPackageId: null,
    }))
  ) {
    fail("The three exact-closure Attestations do not aggregate.");
  }

  const runtimeProof = {
    schemaVersion: "reference-review-runtime-proof.v1",
    proofId: baseline.proofId,
    canonicalization: "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785",
    sourceGitObject: {
      commit: baseline.sourceCommit,
      tree: baseline.sourceTree,
      commitObjectType: "commit",
      treeObjectType: "tree",
    },
    evidenceFreezeGitObject: {
      commit: baseline.evidenceFreezeCommit,
      tree: baseline.evidenceFreezeTree,
      commitObjectType: "commit",
      treeObjectType: "tree",
    },
    ancestry: {
      relationship: "STRICT_ANCESTOR",
      verifiedBy: "BUILD_TIME_LOCAL_GIT_OBJECT_READ",
    },
    trustedBinding,
    packages: packageProofs,
    sourceSubjects,
    evidenceFreezeSubjects,
    attestationSubjects,
    governanceEffect: "NONE",
    isProgressTracker: false,
    selfAuthorizing: false,
    proofSha256: `sha256:${"0".repeat(64)}`,
  };
  const proofForDigest = structuredClone(runtimeProof);
  delete proofForDigest.proofSha256;
  runtimeProof.proofSha256 =
    await referenceReviewDigests.value(proofForDigest);

  return {
    attestationsByWorkPackage,
    runtimeProof,
  };
}

export async function buildReferenceReviewFreezeArtifacts({ repositoryPath }) {
  const baseline = structuredClone(REFERENCE_REVIEW_FREEZE_BASELINE);
  return buildArtifacts({
    baseline,
    git: createLocalGitReader(repositoryPath),
  });
}

function parseCommandLine(arguments_) {
  const options = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !["--artifact", "--repository-path"].includes(name) ||
      value === undefined
    ) {
      fail("Only --artifact and --repository-path are accepted.");
    }
    if (Object.hasOwn(options, name)) {
      fail(`${name} may be provided only once.`);
    }
    options[name] = value;
  }
  if (!options["--repository-path"]) {
    fail("--repository-path is required.");
  }
  if (
    !["C04", "C06", "C07", "RUNTIME_PROOF", "ALL"].includes(
      options["--artifact"],
    )
  ) {
    fail("--artifact must be C04, C06, C07, RUNTIME_PROOF or ALL.");
  }
  return {
    artifact: options["--artifact"],
    repositoryPath: options["--repository-path"],
  };
}

async function runCommandLine() {
  const { artifact, repositoryPath } = parseCommandLine(
    process.argv.slice(2),
  );
  const built = await buildReferenceReviewFreezeArtifacts({
    repositoryPath,
  });
  const output =
    artifact === "RUNTIME_PROOF"
      ? built.runtimeProof
      : artifact === "ALL"
        ? built
        : built.attestationsByWorkPackage[artifact];
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  runCommandLine().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
