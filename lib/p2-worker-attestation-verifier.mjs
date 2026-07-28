import frozenAttestation from "../implementation/p2/attestations/p2-execution-baseline-attestation.48a4e4.v1.json" with { type: "json" };
import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";
import { P2_WORKER_ATTESTATION_PIN_POLICY } from "./p2-worker-attestation-policy.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "./p2-start-authorization.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_OBJECT_ID = /^[a-f0-9]{40}$/;
const CANONICAL_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ATTESTATION_KEYS = [
  "attestationId",
  "buildVerification",
  "canonicalization",
  "executionBaseline",
  "generatedAt",
  "predicateType",
  "schemaVersion",
  "source",
  "subjects",
];
const SUBJECT_KEYS = ["kind", "name", "path", "sha256", "version"];
const SUBJECT_KINDS = [
  "PROFILE",
  "SCHEMA",
  "VALIDATOR",
  "FIXTURE",
  "TOOL_LOCK",
];
const PIN_POLICY_KEYS = [
  "attestationId",
  "attestationPath",
  "attestationSha256",
  "buildVerification",
  "canonicalization",
  "executionBaseline",
  "predicateType",
  "schemaVersion",
  "source",
  "subjects",
];

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalizeProjectJson(Object.keys(value).sort()) ===
      canonicalizeProjectJson([...expected].sort())
  );
}

function exactValue(left, right) {
  return canonicalizeProjectJson(left) === canonicalizeProjectJson(right);
}

function validCanonicalInstant(value) {
  const milliseconds = Date.parse(value);
  return (
    CANONICAL_INSTANT.test(value ?? "") &&
    Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value
  );
}

function validSubject(subject, expectedKind) {
  return (
    exactKeys(subject, SUBJECT_KEYS) &&
    subject.kind === expectedKind &&
    typeof subject.name === "string" &&
    subject.name.length > 0 &&
    typeof subject.path === "string" &&
    subject.path.length > 0 &&
    typeof subject.version === "string" &&
    subject.version.length > 0 &&
    SHA256.test(subject.sha256 ?? "")
  );
}

function validPinPolicy(policy) {
  return (
    exactKeys(policy, PIN_POLICY_KEYS) &&
    policy.schemaVersion === "p2-worker-attestation-pin-policy.v1" &&
    policy.canonicalization ===
      "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785" &&
    typeof policy.attestationPath === "string" &&
    policy.attestationPath.length > 0 &&
    SHA256.test(policy.attestationSha256 ?? "") &&
    typeof policy.attestationId === "string" &&
    policy.attestationId.length > 0 &&
    typeof policy.predicateType === "string" &&
    policy.predicateType.length > 0 &&
    exactKeys(policy.source, ["commit", "objectType", "tree"]) &&
    GIT_OBJECT_ID.test(policy.source.commit ?? "") &&
    GIT_OBJECT_ID.test(policy.source.tree ?? "") &&
    policy.source.objectType === "commit" &&
    exactKeys(policy.executionBaseline, [
      "digest",
      "recipePath",
      "recipeSha256",
    ]) &&
    typeof policy.executionBaseline.recipePath === "string" &&
    policy.executionBaseline.recipePath.length > 0 &&
    SHA256.test(policy.executionBaseline.recipeSha256 ?? "") &&
    SHA256.test(policy.executionBaseline.digest ?? "") &&
    Array.isArray(policy.subjects) &&
    policy.subjects.length === SUBJECT_KINDS.length &&
    policy.subjects.every((subject, index) =>
      validSubject(subject, SUBJECT_KINDS[index]),
    ) &&
    exactKeys(policy.buildVerification, [
      "builderId",
      "builderVersion",
      "method",
      "result",
    ]) &&
    policy.buildVerification.method ===
      "BUILD_TIME_LOCAL_GIT_OBJECT_READ" &&
    typeof policy.buildVerification.builderId === "string" &&
    policy.buildVerification.builderId.length > 0 &&
    typeof policy.buildVerification.builderVersion === "string" &&
    policy.buildVerification.builderVersion.length > 0 &&
    policy.buildVerification.result === "VERIFIED"
  );
}

function validAttestation(attestation, pinPolicy) {
  if (
    !exactKeys(attestation, ATTESTATION_KEYS) ||
    attestation.schemaVersion !==
      "p2-execution-baseline-attestation.v1" ||
    attestation.attestationId !== pinPolicy.attestationId ||
    attestation.predicateType !== pinPolicy.predicateType ||
    attestation.canonicalization !== pinPolicy.canonicalization ||
    !exactKeys(attestation.source, ["commit", "objectType", "tree"]) ||
    !exactValue(attestation.source, pinPolicy.source) ||
    !exactKeys(attestation.executionBaseline, [
      "digest",
      "recipePath",
      "recipeSha256",
    ]) ||
    !exactValue(
      attestation.executionBaseline,
      pinPolicy.executionBaseline,
    ) ||
    !Array.isArray(attestation.subjects) ||
    attestation.subjects.length !== SUBJECT_KINDS.length ||
    !attestation.subjects.every((subject, index) =>
      validSubject(subject, SUBJECT_KINDS[index]),
    ) ||
    !exactValue(attestation.subjects, pinPolicy.subjects) ||
    !exactKeys(attestation.buildVerification, [
      "builderId",
      "builderVersion",
      "method",
      "result",
      "verifiedAt",
    ]) ||
    !validCanonicalInstant(attestation.buildVerification.verifiedAt) ||
    !validCanonicalInstant(attestation.generatedAt) ||
    attestation.buildVerification.verifiedAt !== attestation.generatedAt ||
    !exactValue(
      {
        method: attestation.buildVerification.method,
        builderId: attestation.buildVerification.builderId,
        builderVersion: attestation.buildVerification.builderVersion,
        result: attestation.buildVerification.result,
      },
      pinPolicy.buildVerification,
    )
  ) {
    return false;
  }
  return (
    attestation.attestationId ===
    `p2eba_${attestation.source.commit.slice(0, 12)}_${
      attestation.executionBaseline.digest.slice(7, 19)
    }`
  );
}

function bindingMatchesAttestation(binding, attestation) {
  if (
    !exactKeys(binding, [
      "executionBaselineDigest",
      "policy",
      "sourceCommit",
    ]) ||
    !exactValue(binding.policy, P2_V2_CANDIDATE_START_POLICY) ||
    binding.sourceCommit !== attestation.source.commit ||
    binding.executionBaselineDigest !==
      attestation.executionBaseline.digest
  ) {
    return false;
  }
  const [profile, receiptSchema, validator] = attestation.subjects;
  const policy = binding.policy;
  return (
    policy?.executionBaselineRecipe?.path ===
      attestation.executionBaseline.recipePath &&
    policy.executionBaselineRecipe.schemaVersion ===
      "p2-execution-baseline-recipe.v1" &&
    policy.executionBaselineRecipe.sha256 ===
      attestation.executionBaseline.recipeSha256 &&
    policy?.profile?.path === profile.path &&
    policy.profile.schemaVersion === profile.version &&
    policy.profile.sha256 === profile.sha256 &&
    policy?.receiptSchema?.path === receiptSchema.path &&
    policy.receiptSchema.version === receiptSchema.version &&
    policy.receiptSchema.sha256 === receiptSchema.sha256 &&
    policy?.validator?.path === validator.path &&
    policy.validator.version === validator.version &&
    policy.validator.sha256 === validator.sha256
  );
}

export function createP2WorkerAttestationVerifier({
  attestation,
  pinPolicy,
}) {
  let assets = null;
  try {
    assets = deepFreeze({
      attestation: structuredClone(attestation),
      pinPolicy: structuredClone(pinPolicy),
    });
  } catch {
    assets = null;
  }
  return async function verify(binding) {
    try {
      return (
        assets !== null &&
        validPinPolicy(assets.pinPolicy) &&
        validAttestation(assets.attestation, assets.pinPolicy) &&
        (await sha256ProjectValue(assets.attestation)) ===
          assets.pinPolicy.attestationSha256 &&
        bindingMatchesAttestation(binding, assets.attestation)
      );
    } catch {
      return false;
    }
  };
}

const verifyFrozenAttestation = createP2WorkerAttestationVerifier({
  attestation: frozenAttestation,
  pinPolicy: P2_WORKER_ATTESTATION_PIN_POLICY,
});

export async function verifyP2ExecutionBaselineFromBuildAttestation(binding) {
  return verifyFrozenAttestation(binding);
}

export default verifyP2ExecutionBaselineFromBuildAttestation;
