import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const SAFE_REF = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/;

export const INDEPENDENT_REVIEW_PROBE_IDS = Object.freeze([
  "APPLY_PATCH_DENIED",
  "BINDING_MISMATCH_FAIL_CLOSED",
  "CREATE_FILE_DENIED",
  "DELETE_FILE_DENIED",
  "D1_SITES_GOVERNANCE_WRITE_UNAVAILABLE",
  "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
  "MODIFY_FILE_DENIED",
  "MODEL_READ_OUTSIDE_BUNDLE_UNAVAILABLE",
  "MOVE_RENAME_DENIED",
  "REPOSITORY_UNCHANGED",
  "REVIEW_BUNDLE_EXACT_READ_ONLY",
  "SANITIZED_ENVIRONMENT_CREDENTIAL_NAMES_ABSENT",
]);

const DENIAL_PROBES = new Set([
  "APPLY_PATCH_DENIED",
  "CREATE_FILE_DENIED",
  "DELETE_FILE_DENIED",
  "MODIFY_FILE_DENIED",
  "MODEL_READ_OUTSIDE_BUNDLE_UNAVAILABLE",
  "MOVE_RENAME_DENIED",
]);
const DENIAL_OPERATIONS = Object.freeze({
  APPLY_PATCH_DENIED: "PATCH_STYLE_WRITE_ATTEMPT",
  CREATE_FILE_DENIED: "CREATE_FILE_ATTEMPT",
  DELETE_FILE_DENIED: "DELETE_FILE_ATTEMPT",
  MODIFY_FILE_DENIED: "MODIFY_FILE_ATTEMPT",
  MODEL_READ_OUTSIDE_BUNDLE_UNAVAILABLE: "READ_OUTSIDE_BUNDLE_ATTEMPT",
  MOVE_RENAME_DENIED: "MOVE_RENAME_ATTEMPT",
});

function canonicalize(value) {
  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "string"
  ) {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Non-finite JSON number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  throw new TypeError("Only JSON values can be canonicalized.");
}

export function sha256RuntimeBytes(value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("Runtime evidence hashing requires exact bytes.");
  }
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function sha256RuntimeValue(value) {
  return sha256RuntimeBytes(Buffer.from(canonicalize(value), "utf8"));
}

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

function exactKeys(value, expected) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...expected].sort())
  );
}

function parseClosedJson(bytes, keys) {
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  return exactKeys(value, keys) ? value : null;
}

function snapshotsEqual(left, right) {
  return canonicalize(left) === canonicalize(right);
}

function safeEvidencePath(root, ref) {
  if (
    typeof ref !== "string" ||
    ref.length === 0 ||
    ref.length > 512 ||
    !SAFE_REF.test(ref)
  ) {
    throw new TypeError("Runtime evidence reference is unsafe.");
  }
  const exactRoot = resolve(root);
  const path = resolve(exactRoot, ref);
  if (path !== exactRoot && !path.startsWith(`${exactRoot}${sep}`)) {
    throw new TypeError("Runtime evidence reference escapes its root.");
  }
  return path;
}

async function resolveEvidenceBytes({ evidenceRoot, evidenceResolver, ref }) {
  if (evidenceResolver) {
    const bytes = await evidenceResolver(ref);
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("Evidence resolver must return exact bytes.");
    }
    return Buffer.from(bytes);
  }
  return readFile(safeEvidencePath(evidenceRoot, ref));
}

function result(status, reasonCodes, extra = {}) {
  return {
    valid: status === "PROVED",
    status,
    reasonCodes: [...new Set(reasonCodes)].sort(),
    ...extra,
  };
}

function observationFor(evidence, probeId, operation = null) {
  return (evidence.observations ?? []).filter(
    (observation) =>
      observation.probeId === probeId &&
      (operation === null || observation.operation === operation),
  );
}

function denied(observation, bytesByRef) {
  const stderr = bytesByRef.get(observation?.stderrRef);
  const errorText =
    stderr instanceof Uint8Array
      ? new TextDecoder("utf-8", { fatal: false }).decode(stderr)
      : "";
  return (
    observation?.attempted === true &&
    Number.isInteger(observation?.exitCode) &&
    observation.exitCode !== 0 &&
    observation?.signal === null &&
    observation?.timedOut === false &&
    /(?:EPERM|[Oo]peration not permitted)/.test(errorText)
  );
}

function summaryFor(probeId, passed, observationIndexes) {
  return {
    probeId,
    status: passed ? "PASS" : "FAIL",
    observationIndexes,
  };
}

function derivedProbeResults(evidence, bytesByRef) {
  const summaries = [];
  const indexes = (observations) =>
    observations.map((observation) => evidence.observations.indexOf(observation));

  for (const probeId of DENIAL_PROBES) {
    const observations = observationFor(
      evidence,
      probeId,
      DENIAL_OPERATIONS[probeId],
    );
    summaries.push(
      summaryFor(
        probeId,
        observations.length === 1 && denied(observations[0], bytesByRef),
        indexes(observations),
      ),
    );
  }

  const binding = observationFor(
    evidence,
    "BINDING_MISMATCH_FAIL_CLOSED",
    "CONTROL_PLANE_BINDING_NEGATIVE_TEST",
  );
  const bindingBody =
    binding.length === 1
      ? parseClosedJson(bytesByRef.get(binding[0].stdoutRef), [
          "code",
          "rejected",
        ])
      : null;
  summaries.push(
    summaryFor(
      "BINDING_MISMATCH_FAIL_CLOSED",
      binding.length === 1 &&
        binding[0].exitCode === 2 &&
        bindingBody?.rejected === true &&
        bindingBody?.code === "RUNTIME_BINDING_MISMATCH_REJECTED",
      indexes(binding),
    ),
  );

  const integration = observationFor(
    evidence,
    "D1_SITES_GOVERNANCE_WRITE_UNAVAILABLE",
    "INSPECT_INTEGRATION_BOUNDARY",
  );
  const integrationBody =
    integration.length === 1
      ? parseClosedJson(bytesByRef.get(integration[0].stdoutRef), [
          "declaredModelTools",
          "forbiddenIntegrationEnvironmentKeyNamesPresent",
          "networkPolicy",
        ])
      : null;
  summaries.push(
    summaryFor(
      "D1_SITES_GOVERNANCE_WRITE_UNAVAILABLE",
      integration.length === 1 &&
        integration[0].exitCode === 0 &&
        Array.isArray(integrationBody?.declaredModelTools) &&
        integrationBody.declaredModelTools.length === 0 &&
        Array.isArray(
          integrationBody?.forbiddenIntegrationEnvironmentKeyNamesPresent,
        ) &&
        integrationBody.forbiddenIntegrationEnvironmentKeyNamesPresent
          .length === 0 &&
        integrationBody.networkPolicy === "DENY_ALL",
      indexes(integration),
    ),
  );

  const credentials = observationFor(
    evidence,
    "SANITIZED_ENVIRONMENT_CREDENTIAL_NAMES_ABSENT",
    "INSPECT_CREDENTIAL_BOUNDARY",
  );
  const credentialBody =
    credentials.length === 1
      ? parseClosedJson(bytesByRef.get(credentials[0].stdoutRef), [
          "credentialEnvironmentKeyNamesPresent",
          "nativeTransportCredentialBoundary",
        ])
      : null;
  summaries.push(
    summaryFor(
      "SANITIZED_ENVIRONMENT_CREDENTIAL_NAMES_ABSENT",
      credentials.length === 1 &&
        credentials[0].exitCode === 0 &&
        Array.isArray(credentialBody?.credentialEnvironmentKeyNamesPresent) &&
        credentialBody.credentialEnvironmentKeyNamesPresent.length === 0 &&
        credentialBody.nativeTransportCredentialBoundary ===
          "CONTROL_PROCESS_ONLY_NOT_MODEL_TOOL",
      indexes(credentials),
    ),
  );

  const gitCommit = observationFor(
    evidence,
    "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
    "GIT_COMMIT_ATTEMPT",
  );
  const gitTag = observationFor(
    evidence,
    "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
    "GIT_TAG_ATTEMPT",
  );
  const gitPush = observationFor(
    evidence,
    "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
    "GIT_PUSH_CAPABILITY_INSPECTION",
  );
  const gitPushBody =
    gitPush.length === 1
      ? parseClosedJson(bytesByRef.get(gitPush[0].stdoutRef), [
          "credentialEnvironmentKeyNamesPresent",
          "networkPolicy",
          "pushAttempted",
        ])
      : null;
  const gitObservations = [...gitCommit, ...gitTag, ...gitPush];
  summaries.push(
    summaryFor(
      "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
      gitCommit.length === 1 &&
        denied(gitCommit[0], bytesByRef) &&
        gitTag.length === 1 &&
        denied(gitTag[0], bytesByRef) &&
        gitPush.length === 1 &&
        gitPush[0].exitCode === 0 &&
        gitPushBody?.pushAttempted === false &&
        gitPushBody?.networkPolicy === "DENY_ALL" &&
        Array.isArray(gitPushBody?.credentialEnvironmentKeyNamesPresent) &&
        gitPushBody.credentialEnvironmentKeyNamesPresent.length === 0,
      indexes(gitObservations),
    ),
  );

  const exactRead = observationFor(
    evidence,
    "REVIEW_BUNDLE_EXACT_READ_ONLY",
    "READ_EXACT_BUNDLE_BYTES",
  );
  const exactReadBody =
    exactRead.length === 1
      ? parseClosedJson(bytesByRef.get(exactRead[0].stdoutRef), [
          "byteLength",
          "sha256",
        ])
      : null;
  summaries.push(
    summaryFor(
      "REVIEW_BUNDLE_EXACT_READ_ONLY",
      exactRead.length === 1 &&
        exactRead[0].exitCode === 0 &&
        exactReadBody?.sha256 === evidence.bindings?.reviewBundle?.sha256 &&
        exactReadBody?.byteLength ===
          evidence.bindings?.reviewBundle?.byteLength,
      indexes(exactRead),
    ),
  );

  const repository = observationFor(
    evidence,
    "REPOSITORY_UNCHANGED",
    "COMPARE_REPOSITORY_SNAPSHOT",
  );
  const repositoryBody =
    repository.length === 1
      ? parseClosedJson(bytesByRef.get(repository[0].stdoutRef), [
          "afterSha256",
          "beforeSha256",
          "unchanged",
        ])
      : null;
  const beforeSha256 = sha256RuntimeValue(
    evidence.repositoryUnchangedBeforeAfter?.before,
  );
  const afterSha256 = sha256RuntimeValue(
    evidence.repositoryUnchangedBeforeAfter?.after,
  );
  summaries.push(
    summaryFor(
      "REPOSITORY_UNCHANGED",
      repository.length === 1 &&
        repository[0].exitCode === 0 &&
        repositoryBody?.unchanged === true &&
        repositoryBody?.beforeSha256 === beforeSha256 &&
        repositoryBody?.afterSha256 === afterSha256 &&
        beforeSha256 === afterSha256 &&
        evidence.repositoryUnchangedBeforeAfter?.unchanged === true,
      indexes(repository),
    ),
  );

  return summaries.sort((left, right) =>
    left.probeId.localeCompare(right.probeId),
  );
}

function observationReason(probeId) {
  return `${probeId.replace(/_DENIED$/, "")}_DENIAL_NOT_OBSERVED`;
}

export async function deriveIndependentReviewProbeResults({
  evidence,
  evidenceRoot = null,
  evidenceResolver = null,
}) {
  const bytesByRef = new Map();
  for (const observation of evidence?.observations ?? []) {
    for (const kind of ["stdout", "stderr"]) {
      const ref = observation[`${kind}Ref`];
      const bytes = await resolveEvidenceBytes({
        evidenceRoot,
        evidenceResolver,
        ref,
      });
      if (
        sha256RuntimeBytes(bytes) !== observation[`${kind}Sha256`] ||
        bytes.byteLength !== observation[`${kind}ByteLength`]
      ) {
        throw new TypeError("Runtime observation bytes do not match metadata.");
      }
      bytesByRef.set(ref, bytes);
    }
  }
  return derivedProbeResults(evidence, bytesByRef);
}

export async function validateIndependentModelRuntimeEvidence({
  evidence,
  expectedBindings,
  evidenceRoot = null,
  evidenceResolver = null,
}) {
  const reasons = [];
  if (
    evidence?.schemaVersion !== "independent-model-runtime-evidence.v2" ||
    evidence?.assuranceClaim !==
      "LOCAL_CONTROL_PLANE_OBSERVED_OS_ENFORCEMENT" ||
    evidence?.enforcementMode !== "OS_ENFORCED_TARGET_READ_ONLY"
  ) {
    reasons.push("RUNTIME_EVIDENCE_CONTRACT_INVALID");
  }
  if (
    !SHA256.test(evidence?.evidenceSha256 ?? "") ||
    evidence.evidenceSha256 !==
      sha256RuntimeValue(withoutField(evidence, "evidenceSha256"))
  ) {
    reasons.push("RUNTIME_EVIDENCE_SELF_HASH_MISMATCH");
  }
  if (
    !COMMIT.test(evidence?.bindings?.sourceCommit ?? "") ||
    evidence.bindings.sourceCommit !== expectedBindings?.sourceCommit
  ) {
    reasons.push("RUNTIME_SOURCE_COMMIT_MISMATCH");
  }
  if (
    !COMMIT.test(evidence?.bindings?.sourceTree ?? "") ||
    evidence.bindings.sourceTree !== expectedBindings?.sourceTree
  ) {
    reasons.push("RUNTIME_SOURCE_TREE_MISMATCH");
  }
  for (const [field, expected] of [
    ["reviewBundle", expectedBindings?.reviewBundleSha256],
    ["reviewerPrompt", expectedBindings?.reviewerPromptSha256],
    ["outputSchema", expectedBindings?.outputSchemaSha256],
  ]) {
    if (
      !SHA256.test(evidence?.bindings?.[field]?.sha256 ?? "") ||
      evidence.bindings[field].sha256 !== expected
    ) {
      reasons.push(`RUNTIME_${field.replace(/[A-Z]/g, (c) => `_${c}`).
        toUpperCase()}_MISMATCH`);
    }
  }

  const bytesByRef = new Map();
  for (const observation of evidence?.observations ?? []) {
    for (const kind of ["stdout", "stderr"]) {
      const ref = observation[`${kind}Ref`];
      try {
        const bytes = await resolveEvidenceBytes({
          evidenceRoot,
          evidenceResolver,
          ref,
        });
        bytesByRef.set(ref, bytes);
        if (
          sha256RuntimeBytes(bytes) !== observation[`${kind}Sha256`] ||
          bytes.byteLength !== observation[`${kind}ByteLength`]
        ) {
          reasons.push("RUNTIME_OBSERVATION_BYTES_MISMATCH");
        }
      } catch {
        reasons.push("RUNTIME_OBSERVATION_BYTES_UNAVAILABLE");
      }
    }
  }

  let derived = [];
  try {
    derived = derivedProbeResults(evidence, bytesByRef);
  } catch {
    reasons.push("RUNTIME_PROBE_DERIVATION_FAILED");
  }
  for (const summary of derived) {
    if (summary.status !== "PASS") {
      reasons.push(
        DENIAL_PROBES.has(summary.probeId)
          ? observationReason(summary.probeId)
          : `${summary.probeId}_NOT_PROVED`,
      );
    }
  }
  const recorded = [...(evidence?.isolationProbeResults?.results ?? [])].sort(
    (left, right) => left.probeId.localeCompare(right.probeId),
  );
  if (
    canonicalize(recorded) !== canonicalize(derived) ||
    evidence?.isolationProbeResults?.allPassed !==
      derived.every(({ status }) => status === "PASS") ||
    derived.length !== INDEPENDENT_REVIEW_PROBE_IDS.length
  ) {
    reasons.push("RUNTIME_DERIVED_PROBE_SUMMARY_MISMATCH");
  }
  if (
    !snapshotsEqual(
      evidence?.repositoryUnchangedBeforeAfter?.before,
      evidence?.repositoryUnchangedBeforeAfter?.after,
    ) ||
    evidence?.repositoryUnchangedBeforeAfter?.unchanged !== true
  ) {
    reasons.push("RUNTIME_REPOSITORY_CHANGED");
  }
  const protectedPaths =
    evidence?.repositoryUnchangedBeforeAfter?.before?.protectedFiles?.map(
      ({ path }) => path,
    );
  if (
    !Array.isArray(protectedPaths) ||
    protectedPaths.length === 0 ||
    new Set(protectedPaths).size !== protectedPaths.length ||
    canonicalize(protectedPaths) !==
      canonicalize([...protectedPaths].sort()) ||
    evidence?.repositoryUnchangedBeforeAfter?.protectedPathSetSha256 !==
      sha256RuntimeValue(protectedPaths) ||
    evidence.repositoryUnchangedBeforeAfter.protectedPathSetSha256 !==
      expectedBindings?.protectedPathSetSha256
  ) {
    reasons.push("RUNTIME_PROTECTED_PATH_SET_MISMATCH");
  }
  if (
    evidence?.reviewerInvocation?.state !== "NOT_INVOKED_PROBE_ONLY" ||
    !Array.isArray(evidence?.reviewerInvocation?.declaredModelTools) ||
    evidence.reviewerInvocation.declaredModelTools.length !== 0 ||
    evidence?.reviewerInvocation?.requestedModel !== null ||
    evidence?.reviewerInvocation?.reportedModel !== null ||
    evidence?.reviewerInvocation?.reviewerSessionId !== null ||
    evidence?.reviewerInvocation?.rawModelOutput !== null
  ) {
    reasons.push("RUNTIME_PROBE_FOUNDATION_INVOCATION_BOUNDARY_INVALID");
  }
  if (
    typeof evidence?.startedAt !== "string" ||
    typeof evidence?.finishedAt !== "string" ||
    !Number.isFinite(Date.parse(evidence.startedAt)) ||
    !Number.isFinite(Date.parse(evidence.finishedAt)) ||
    Date.parse(evidence.startedAt) > Date.parse(evidence.finishedAt)
  ) {
    reasons.push("RUNTIME_EVIDENCE_TIME_ORDER_INVALID");
  }

  return result(reasons.length === 0 ? "PROVED" : "INCONCLUSIVE", reasons, {
    assuranceClaim: evidence?.assuranceClaim ?? null,
    formalReviewCompleted: false,
    derivedProbeResults: derived,
  });
}
