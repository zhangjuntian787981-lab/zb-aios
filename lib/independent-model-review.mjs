import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "./project-control.mjs";
import { createRequire } from "node:module";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  independentReviewRuntimeBinding,
  validateIndependentReviewRuntimeBinding,
} from "./independent-review-runtime-binding.mjs";

const require = createRequire(import.meta.url);
const AJV_VERSION = require("ajv/package.json").version;

const SHA256 = /^sha256:[a-f0-9]{64}$/;
const GIT_COMMIT = /^[a-f0-9]{40}$/;
const COMMAND_ID = /^[a-z0-9][a-z0-9_-]{2,63}$/;
const FINDING_ID = /^[a-z0-9][a-z0-9_-]{2,127}$/;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*[\u0000-\u001f\\]).+$/u;
const BLOCKING_SEVERITIES = new Set(["HIGH", "CRITICAL"]);
const DECISIONS = new Set(["CLEAR", "BLOCKED", "INCONCLUSIVE"]);
const CONCLUSIONS = Object.freeze({
  CLEAR: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  BLOCKED: "BLOCKED",
  INCONCLUSIVE: "INCONCLUSIVE",
});
const ALLOWED_REVIEW_SCOPES = [
  "CHECK_ISSUER_OR_MAPPER",
  "INDEPENDENCE_VALIDATOR",
  "JSON_SCHEMA",
  "ORDINARY_PREPRODUCTION_CODE",
  "POLICY",
  "RULESET_CONFIGURATION",
  "SEMANTIC_VALIDATOR",
];
const ALLOWED_INPUTS = [
  "SPECIFICATION",
  "SOURCE_COMMIT",
  "DIFF",
  "TEST_EVIDENCE",
  "ACCEPTANCE_EVIDENCE",
  "RELEVANT_FILES",
];
const FORBIDDEN_CAPABILITIES = [
  "COMMIT",
  "D1_WRITE",
  "DEPLOY",
  "FILE_WRITE",
  "GOVERNANCE_DECISION",
  "PUSH",
];
const APPROVED_ISOLATION_MODES = [
  "API_NO_TOOLS",
  "OS_ENFORCED_TARGET_READ_ONLY",
];
const REQUIRED_ISOLATION_PROBES = [
  "APPLY_PATCH_DENIED",
  "BINDING_MISMATCH_FAIL_CLOSED",
  "CREATE_FILE_DENIED",
  "DELETE_FILE_DENIED",
  "D1_SITES_GOVERNANCE_WRITE_UNAVAILABLE",
  "GIT_COMMIT_AND_TAG_DENIED_PUSH_NOT_ATTEMPTED",
  "MODIFY_FILE_DENIED",
  "MOVE_RENAME_DENIED",
  "MODEL_READ_OUTSIDE_BUNDLE_UNAVAILABLE",
  "REPOSITORY_UNCHANGED",
  "REVIEW_BUNDLE_EXACT_READ_ONLY",
  "SANITIZED_ENVIRONMENT_CREDENTIAL_NAMES_ABSENT",
];
const P3_HUMAN_REVIEW_PHASES = ["P3"];
const P3_HUMAN_REVIEW_DATA_BOUNDARIES = [
  "PRODUCTION",
  "REAL_ENTERPRISE_DATA",
];
const P3_HUMAN_REVIEW_HIGH_RISK_SCOPES = [
  "CODE_EXECUTION_SANDBOX_AND_NETWORK_EGRESS",
  "D1_GATE_PROFILE_START_AUTHORIZATION",
  "ENTERPRISE_CONNECTORS_AND_DATA",
  "IDENTITY_AUTHORIZATION_TENANT_ISOLATION",
  "PRODUCTION_DEPLOYMENT_ROLLBACK_AND_WRITEBACK",
  "SECRETS",
];
const INDEPENDENT_REVIEW_TEST_RESULT_SCHEMA_PATH =
  "implementation/governance/schemas/independent-review-test-result.v3.schema.json";
const INDEPENDENT_REVIEW_TEST_SANDBOX_PATH =
  "implementation/governance/independent-review/macos-independent-review-test-execution.sb.in";
const INDEPENDENT_REVIEW_TEST_ISOLATION_VERSION =
  "isolation=macos-sandbox-exec-git-archive-readonly-network-denied";
const INDEPENDENT_REVIEW_NETWORK_TEST_MODE =
  "network-test-mode=frozen-deterministic-offline-alternatives";
const EMPTY_SHA256 =
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const TRUSTED_GIT_ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
});

export const independentModelReviewFixedSpecificationPaths = Object.freeze([
  "AGENTS.md",
  "CONTEXT.md",
  "docs/agents/issue-tracker.md",
  "docs/adr/0008-c13-protected-source-review.md",
  "docs/adr/0011-independent-model-review-policy-v2-candidate.md",
]);

function withoutField(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

async function hashBytes(value) {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("Exact bytes must be a Uint8Array.");
  }
  const digest = await crypto.subtle.digest("SHA-256", value);
  return `sha256:${Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")}`;
}

const policyDigest = (policy) =>
  sha256ProjectValue(withoutField(policy, "policySha256"));
const bundleDigest = (bundle) =>
  sha256ProjectValue(withoutField(bundle, "bundleSha256"));
const receiptDigest = (receipt) =>
  sha256ProjectValue(withoutField(receipt, "receiptSha256"));
const runtimeDigest = (runtimeAttestation) =>
  sha256ProjectValue(runtimeAttestation);
const modelOutputDigest = (rawModelOutput) => hashBytes(rawModelOutput);

export function parseIndependentReviewJsonBytes(
  rawBytes,
  label = "Independent review JSON",
  maximumBytes = 1024 * 1024,
) {
  if (
    !(rawBytes instanceof Uint8Array) ||
    rawBytes.byteLength === 0 ||
    rawBytes.byteLength > maximumBytes
  ) {
    throw new TypeError(`${label} must be bounded Uint8Array JSON.`);
  }
  if (
    rawBytes.byteLength >= 3 &&
    rawBytes[0] === 0xef &&
    rawBytes[1] === 0xbb &&
    rawBytes[2] === 0xbf
  ) {
    throw new TypeError(`${label} must not contain a UTF-8 BOM.`);
  }
  let raw;
  try {
    raw = new TextDecoder("utf-8", { fatal: true }).decode(rawBytes);
  } catch {
    throw new TypeError(`${label} is not valid UTF-8.`);
  }
  let index = 0;
  const skipWhitespace = () => {
    while (index < raw.length && /[\u0020\t\r\n]/u.test(raw[index])) index += 1;
  };
  const requireUnicodeScalars = (value) => {
    for (let offset = 0; offset < value.length; offset += 1) {
      const codeUnit = value.charCodeAt(offset);
      if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
        const nextCodeUnit = value.charCodeAt(offset + 1);
        if (!(nextCodeUnit >= 0xdc00 && nextCodeUnit <= 0xdfff)) {
          throw new TypeError(
            `${label} strings must contain only Unicode scalar values.`,
          );
        }
        offset += 1;
      } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
        throw new TypeError(
          `${label} strings must contain only Unicode scalar values.`,
        );
      }
    }
    return value;
  };
  const parseString = () => {
    const start = index;
    if (raw[index] !== '"') throw new TypeError(`${label} expected a JSON string.`);
    index += 1;
    while (index < raw.length) {
      if (raw[index] === '"') {
        index += 1;
        return requireUnicodeScalars(JSON.parse(raw.slice(start, index)));
      }
      if (raw[index] === "\\") {
        index += 2;
      } else {
        index += 1;
      }
    }
    throw new TypeError(`${label} has an unterminated JSON string.`);
  };
  const parseValue = () => {
    skipWhitespace();
    if (raw[index] === "{") {
      index += 1;
      const keys = new Set();
      skipWhitespace();
      if (raw[index] === "}") {
        index += 1;
        return;
      }
      while (index < raw.length) {
        skipWhitespace();
        const key = parseString();
        if (keys.has(key)) {
          throw new TypeError(`${label} has duplicate keys.`);
        }
        keys.add(key);
        skipWhitespace();
        if (raw[index] !== ":") throw new TypeError(`${label} expected JSON colon.`);
        index += 1;
        parseValue();
        skipWhitespace();
        if (raw[index] === "}") {
          index += 1;
          return;
        }
        if (raw[index] !== ",") throw new TypeError(`${label} expected JSON comma.`);
        index += 1;
      }
    } else if (raw[index] === "[") {
      index += 1;
      skipWhitespace();
      if (raw[index] === "]") {
        index += 1;
        return;
      }
      while (index < raw.length) {
        parseValue();
        skipWhitespace();
        if (raw[index] === "]") {
          index += 1;
          return;
        }
        if (raw[index] !== ",") throw new TypeError(`${label} expected JSON comma.`);
        index += 1;
      }
    } else if (raw[index] === '"') {
      parseString();
    } else {
      const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(
        raw.slice(index),
      )?.[0];
      if (!token) throw new TypeError(`${label} has an invalid JSON value.`);
      index += token.length;
    }
  };
  parseValue();
  skipWhitespace();
  if (index !== raw.length) {
    throw new TypeError(`${label} has trailing content.`);
  }
  return JSON.parse(raw);
}

async function frozenSchemaValidators({
  bundle,
  receiptSchemaBytes,
  outputSchemaBytes,
}) {
  if (
    !(receiptSchemaBytes instanceof Uint8Array) ||
    !(outputSchemaBytes instanceof Uint8Array) ||
    (await hashBytes(receiptSchemaBytes)) !==
      bundle?.artifacts?.receiptSchemaSha256 ||
    (await hashBytes(outputSchemaBytes)) !==
      bundle?.artifacts?.outputSchemaSha256
  ) {
    throw new TypeError("Independent review frozen Schema bytes do not match the Bundle.");
  }
  const receiptSchema = parseIndependentReviewJsonBytes(
    receiptSchemaBytes,
    "Independent review Receipt Schema",
    1024 * 1024,
  );
  const outputSchema = parseIndependentReviewJsonBytes(
    outputSchemaBytes,
    "Independent review output Schema",
    1024 * 1024,
  );
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    validateFormats: true,
  });
  addFormats(ajv);
  ajv.addSchema(outputSchema);
  return {
    receipt: ajv.compile(receiptSchema),
    output: ajv.getSchema(outputSchema.$id),
  };
}

export const independentModelReviewDigests = Object.freeze({
  policy: policyDigest,
  bundle: bundleDigest,
  receipt: receiptDigest,
  runtime: runtimeDigest,
  modelOutput: modelOutputDigest,
  value: sha256ProjectValue,
  bytes: hashBytes,
  canonicalize: canonicalizeProjectJson,
});

function keysExactly(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    canonicalizeProjectJson(Object.keys(value).sort()) ===
      canonicalizeProjectJson([...expected].sort())
  );
}

function unique(values) {
  return Array.isArray(values) && new Set(values).size === values.length;
}

function sorted(values) {
  return (
    Array.isArray(values) &&
    canonicalizeProjectJson(values) ===
      canonicalizeProjectJson([...values].sort())
  );
}

function safePath(value) {
  return typeof value === "string" && SAFE_PATH.test(value);
}

function validDate(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

async function validIsolationProbeResults(value, evidenceResolver) {
  if (
    typeof evidenceResolver !== "function" ||
    !(
    keysExactly(value, [
      "schemaVersion",
      "enforcementMode",
      "results",
      "allPassed",
    ]) &&
    value.schemaVersion === "independent-model-isolation-probes.v1" &&
    APPROVED_ISOLATION_MODES.includes(value.enforcementMode) &&
    value.allPassed === true &&
    Array.isArray(value.results) &&
    value.results.length === REQUIRED_ISOLATION_PROBES.length &&
    canonicalizeProjectJson(value.results.map(({ probeId }) => probeId)) ===
      canonicalizeProjectJson(REQUIRED_ISOLATION_PROBES) &&
    value.results.every(
      (probe) =>
        keysExactly(probe, [
          "probeId",
          "status",
          "evidenceRef",
          "evidenceSha256",
          "evidenceByteLength",
        ]) &&
        probe.status === "PASS" &&
        safePath(probe.evidenceRef) &&
        SHA256.test(probe.evidenceSha256) &&
        Number.isInteger(probe.evidenceByteLength) &&
        probe.evidenceByteLength > 0 &&
        probe.evidenceByteLength <= 1024 * 1024,
    )
    )
  ) {
    return false;
  }
  try {
    for (const probe of value.results) {
      const bytes = await evidenceResolver(probe.evidenceRef);
      if (
        !(bytes instanceof Uint8Array) ||
        bytes.byteLength !== probe.evidenceByteLength ||
        (await hashBytes(bytes)) !== probe.evidenceSha256
      ) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

async function validRepositoryUnchangedProof(value, bundle) {
  const validSnapshot = (snapshot) =>
    keysExactly(snapshot, [
      "head",
      "tree",
      "statusSha256",
      "protectedFilesDigest",
    ]) &&
    GIT_COMMIT.test(snapshot.head) &&
    GIT_COMMIT.test(snapshot.tree) &&
    SHA256.test(snapshot.statusSha256) &&
    SHA256.test(snapshot.protectedFilesDigest);
  return (
    keysExactly(value, [
      "schemaVersion",
      "before",
      "after",
      "unchanged",
      "evidenceSha256",
    ]) &&
    value.schemaVersion === "repository-unchanged-proof.v1" &&
    validSnapshot(value.before) &&
    validSnapshot(value.after) &&
    value.before.head === bundle?.source?.sourceCommit &&
    value.after.head === bundle?.source?.sourceCommit &&
    value.before.tree === bundle?.source?.tree &&
    value.after.tree === bundle?.source?.tree &&
    canonicalizeProjectJson(value.before) ===
      canonicalizeProjectJson(value.after) &&
    value.unchanged === true &&
    SHA256.test(value.evidenceSha256) &&
    value.evidenceSha256 ===
      (await sha256ProjectValue(withoutField(value, "evidenceSha256")))
  );
}

function boundedString(value, minimum, maximum) {
  if (typeof value !== "string") return false;
  const length = Array.from(value).length;
  return length >= minimum && length <= maximum;
}

function result(ok, status, reasonCodes, extra = {}) {
  return {
    ok,
    status,
    reasonCodes: [...new Set(reasonCodes)],
    ...extra,
  };
}

export async function validateIndependentReviewTestEvidenceClosure({
  bundle,
  testPlanBytes,
  collectorBytes,
  testResultSchemaBytes,
  sandboxPolicyTemplateBytes,
  evidenceResolver,
  expectedRuntimeBinding = null,
}) {
  const fail = () =>
    result(false, "BLOCKED", [
      "INDEPENDENT_REVIEW_TEST_EVIDENCE_MISMATCH",
    ]);
  if (
    !(testPlanBytes instanceof Uint8Array) ||
    !(collectorBytes instanceof Uint8Array) ||
    !(testResultSchemaBytes instanceof Uint8Array) ||
    !(sandboxPolicyTemplateBytes instanceof Uint8Array) ||
    typeof evidenceResolver !== "function"
  ) {
    return fail();
  }
  let plan;
  try {
    plan = parseIndependentReviewJsonBytes(
      testPlanBytes,
      "Independent review test plan",
      1024 * 1024,
    );
  } catch {
    return fail();
  }
  if (
    !keysExactly(plan, [
      "schemaVersion",
      "planId",
      "commands",
      "planSha256",
    ]) ||
    plan.schemaVersion !== "independent-review-test-plan.v2" ||
    !COMMAND_ID.test(plan.planId ?? "") ||
    !Array.isArray(plan.commands) ||
    plan.commands.length === 0 ||
    !unique(plan.commands.map(({ commandId }) => commandId)) ||
    plan.commands.some(
      (command) =>
        !keysExactly(command, [
          "commandId",
          "executable",
          "args",
          "timeoutMs",
        ]) ||
        !COMMAND_ID.test(command.commandId ?? "") ||
        !["NODE", "NPM"].includes(command.executable) ||
        !Array.isArray(command.args) ||
        command.args.length === 0 ||
        command.args.some(
          (value) =>
            typeof value !== "string" ||
            value.length === 0 ||
            value.includes("\u0000"),
        ) ||
        !Number.isInteger(command.timeoutMs) ||
        command.timeoutMs < 1000 ||
        command.timeoutMs > 900000,
    ) ||
    !SHA256.test(plan.planSha256 ?? "") ||
    plan.planSha256 !==
      (await sha256ProjectValue(withoutField(plan, "planSha256"))) ||
    (await hashBytes(testPlanBytes)) !==
      bundle?.artifacts?.testPlanSha256 ||
    (await hashBytes(collectorBytes)) !==
      bundle?.artifacts?.testEvidenceCollectorSha256 ||
    bundle?.artifacts?.testResultSchemaPath !==
      INDEPENDENT_REVIEW_TEST_RESULT_SCHEMA_PATH ||
    (await hashBytes(testResultSchemaBytes)) !==
      bundle?.artifacts?.testResultSchemaSha256 ||
    bundle?.artifacts?.sandboxPolicyTemplatePath !==
      INDEPENDENT_REVIEW_TEST_SANDBOX_PATH ||
    (await hashBytes(sandboxPolicyTemplateBytes)) !==
      bundle?.artifacts?.sandboxPolicyTemplateSha256 ||
    !Array.isArray(bundle?.testEvidenceSubjects) ||
    bundle.testEvidenceSubjects.length !== plan.commands.length
  ) {
    return fail();
  }
  const claimedRefs = new Set();
  let acceptedRuntimeBindingDescriptor = null;
  try {
    for (let index = 0; index < plan.commands.length; index += 1) {
      const command = plan.commands[index];
      const evidence = bundle.testEvidenceSubjects[index];
      const resultRef = `${command.commandId}.result.json`;
      const stdoutRef = `${command.commandId}.stdout.log`;
      const stderrRef = `${command.commandId}.stderr.log`;
      if (
        !keysExactly(evidence, [
          "evidenceId",
          "command",
          "status",
          "exitCode",
          "outputRef",
          "outputSha256",
          "outputByteLength",
          "truncated",
          "sourceCommit",
          "runner",
          "toolVersions",
        ]) ||
        evidence.evidenceId !== command.commandId ||
        evidence.command !==
          `${command.executable} ${command.args.join(" ")}` ||
        evidence.status !== "PASS" ||
        evidence.exitCode !== 0 ||
        evidence.outputRef !== resultRef ||
        !SHA256.test(evidence.outputSha256 ?? "") ||
        !Number.isInteger(evidence.outputByteLength) ||
        evidence.outputByteLength <= 0 ||
        evidence.outputByteLength > 1024 * 1024 ||
        evidence.truncated !== false ||
        evidence.sourceCommit !== bundle?.source?.sourceCommit ||
        evidence.runner !==
          "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE" ||
        !Array.isArray(evidence.toolVersions) ||
        evidence.toolVersions.length === 0 ||
        !evidence.toolVersions.includes(
          INDEPENDENT_REVIEW_TEST_ISOLATION_VERSION,
        ) ||
        evidence.toolVersions.filter((version) =>
          /^sandbox-template=sha256:[a-f0-9]{64}$/u.test(version),
        ).length !== 1 ||
        evidence.toolVersions.filter((version) =>
          /^sandbox-invocation=sha256:[a-f0-9]{64}$/u.test(version),
        ).length !== 1 ||
        evidence.toolVersions.some(
          (version) =>
            typeof version !== "string" ||
            version.length === 0 ||
            version.length > 256,
        )
      ) {
        return fail();
      }
      const resultBytes = await evidenceResolver(resultRef);
      if (
        !(resultBytes instanceof Uint8Array) ||
        resultBytes.byteLength !== evidence.outputByteLength ||
        (await hashBytes(resultBytes)) !== evidence.outputSha256
      ) {
        return fail();
      }
      const attestation = parseIndependentReviewJsonBytes(
        resultBytes,
        "Independent review test result",
        1024 * 1024,
      );
      const schemaValidation =
        await validateIndependentReviewSchemaInstance({
          schemaBytes: testResultSchemaBytes,
          expectedSchemaSha256:
            bundle.artifacts.testResultSchemaSha256,
          instance: attestation,
          label: "Independent review test result Schema",
        });
      if (
        !schemaValidation.ok ||
        !keysExactly(attestation, [
          "schemaVersion",
          "evidenceId",
          "testPlanSha256",
          "sourceCommit",
          "sourceTree",
          "runner",
          "runtimeBinding",
          "executionSource",
          "commandId",
          "argvSha256",
          "observation",
          "stdoutRef",
          "stdoutSha256",
          "stdoutByteLength",
          "stderrRef",
          "stderrSha256",
          "stderrByteLength",
          "resultSha256",
        ]) ||
        attestation.schemaVersion !==
          "independent-review-test-result.v3" ||
        attestation.evidenceId !== command.commandId ||
        attestation.testPlanSha256 !== plan.planSha256 ||
        attestation.sourceCommit !== bundle.source.sourceCommit ||
        attestation.sourceTree !== bundle.source.tree ||
        !keysExactly(attestation.runner, [
          "path",
          "gitBlobSha256",
          "executedBytesSha256",
        ]) ||
        attestation.runner.path !==
          bundle.artifacts.testEvidenceCollectorPath ||
        attestation.runner.gitBlobSha256 !==
          bundle.artifacts.testEvidenceCollectorSha256 ||
        attestation.runner.executedBytesSha256 !==
          bundle.artifacts.testEvidenceCollectorSha256 ||
        !keysExactly(attestation.runtimeBinding, [
          "artifactRef",
          "artifactSha256",
          "artifactByteLength",
          "bindingSha256",
          "nodeExecutableSha256",
          "dependencySetSha256",
          "gitToolchainSha256",
          "generator",
        ]) ||
        attestation.runtimeBinding.artifactRef !==
          independentReviewRuntimeBinding.artifactRef ||
        !SHA256.test(attestation.runtimeBinding.artifactSha256 ?? "") ||
        !Number.isInteger(
          attestation.runtimeBinding.artifactByteLength,
        ) ||
        attestation.runtimeBinding.artifactByteLength <= 0 ||
        attestation.runtimeBinding.artifactByteLength > 1024 * 1024 ||
        !SHA256.test(attestation.runtimeBinding.bindingSha256 ?? "") ||
        !SHA256.test(
          attestation.runtimeBinding.nodeExecutableSha256 ?? "",
        ) ||
        !SHA256.test(
          attestation.runtimeBinding.dependencySetSha256 ?? "",
        ) ||
        !SHA256.test(
          attestation.runtimeBinding.gitToolchainSha256 ?? "",
        ) ||
        !keysExactly(attestation.runtimeBinding.generator, [
          "path",
          "gitBlobSha256",
          "executedBytesSha256",
        ]) ||
        attestation.runtimeBinding.generator.path !==
          "lib/independent-review-runtime-binding.mjs" ||
        !SHA256.test(
          attestation.runtimeBinding.generator.gitBlobSha256 ?? "",
        ) ||
        attestation.runtimeBinding.generator.gitBlobSha256 !==
          attestation.runtimeBinding.generator.executedBytesSha256 ||
        !keysExactly(attestation.executionSource, [
          "mode",
          "cloneMode",
          "before",
          "after",
          "unchanged",
          "sourceExportRemoved",
          "sandbox",
        ]) ||
        attestation.executionSource.mode !==
          "MACOS_SEATBELT_GIT_ARCHIVE_V2" ||
        attestation.executionSource.cloneMode !==
          "GIT_ARCHIVE_NO_METADATA" ||
        !keysExactly(attestation.executionSource.before, [
          "head",
          "tree",
          "sourceManifestSha256",
        ]) ||
        !keysExactly(attestation.executionSource.after, [
          "head",
          "tree",
          "sourceManifestSha256",
        ]) ||
        attestation.executionSource.before.head !==
          bundle.source.sourceCommit ||
        attestation.executionSource.after.head !==
          bundle.source.sourceCommit ||
        attestation.executionSource.before.tree !== bundle.source.tree ||
        attestation.executionSource.after.tree !== bundle.source.tree ||
        !SHA256.test(
          attestation.executionSource.before.sourceManifestSha256 ?? "",
        ) ||
        attestation.executionSource.before.sourceManifestSha256 !==
          attestation.executionSource.after.sourceManifestSha256 ||
        attestation.executionSource.unchanged !== true ||
        attestation.executionSource.sourceExportRemoved !== true ||
        !keysExactly(attestation.executionSource.sandbox, [
          "executable",
          "templatePath",
          "templateSha256",
          "parameterSetSha256",
          "invocationSha256",
          "sourceWritable",
          "buildOutputsWritable",
          "writableWorkRoots",
          "scratchWritable",
          "gitMetadataPresent",
          "sharedDependenciesWritable",
          "networkPolicy",
          "networkDependentTestMode",
        ]) ||
        attestation.executionSource.sandbox.executable !==
          "/usr/bin/sandbox-exec" ||
        attestation.executionSource.sandbox.templatePath !==
          bundle.artifacts.sandboxPolicyTemplatePath ||
        attestation.executionSource.sandbox.templateSha256 !==
          bundle.artifacts.sandboxPolicyTemplateSha256 ||
        !SHA256.test(
          attestation.executionSource.sandbox.parameterSetSha256 ?? "",
        ) ||
        attestation.executionSource.sandbox.invocationSha256 !==
          (await sha256ProjectValue({
            executable: "/usr/bin/sandbox-exec",
            templateSha256:
              attestation.executionSource.sandbox.templateSha256,
            parameterSetSha256:
              attestation.executionSource.sandbox.parameterSetSha256,
          })) ||
        attestation.executionSource.sandbox.sourceWritable !== false ||
        attestation.executionSource.sandbox.buildOutputsWritable !== true ||
        canonicalizeProjectJson(
          attestation.executionSource.sandbox.writableWorkRoots,
        ) !==
          canonicalizeProjectJson([
            ".next",
            ".vinext",
            ".wrangler",
            "dist",
            "node_modules/.vite-temp",
          ]) ||
        attestation.executionSource.sandbox.scratchWritable !== true ||
        attestation.executionSource.sandbox.gitMetadataPresent !== false ||
        attestation.executionSource.sandbox.sharedDependenciesWritable !==
          false ||
        attestation.executionSource.sandbox.networkPolicy !==
          "DENY_ALL" ||
        attestation.executionSource.sandbox.networkDependentTestMode !==
          "FROZEN_DETERMINISTIC_OFFLINE_ALTERNATIVES" ||
        !evidence.toolVersions.includes(
          INDEPENDENT_REVIEW_NETWORK_TEST_MODE,
        ) ||
        !evidence.toolVersions.includes(
          `sandbox-template=${attestation.executionSource.sandbox.templateSha256}`,
        ) ||
        !evidence.toolVersions.includes(
          `sandbox-invocation=${attestation.executionSource.sandbox.invocationSha256}`,
        ) ||
        !evidence.toolVersions.includes(
          `runtime-binding=${attestation.runtimeBinding.bindingSha256}`,
        ) ||
        !evidence.toolVersions.includes(
          `node-executable=${attestation.runtimeBinding.nodeExecutableSha256}`,
        ) ||
        !evidence.toolVersions.includes(
          `dependency-set=${attestation.runtimeBinding.dependencySetSha256}`,
        ) ||
        !evidence.toolVersions.includes(
          `git-toolchain=${attestation.runtimeBinding.gitToolchainSha256}`,
        ) ||
        attestation.commandId !== command.commandId ||
        attestation.argvSha256 !==
          (await sha256ProjectValue({
            executable: command.executable,
            args: command.args,
          })) ||
        !keysExactly(attestation.observation, [
          "exitCode",
          "signal",
          "timedOut",
          "startedAt",
          "finishedAt",
        ]) ||
        attestation.observation.exitCode !== 0 ||
        attestation.observation.signal !== null ||
        attestation.observation.timedOut !== false ||
        !validDate(attestation.observation.startedAt) ||
        !validDate(attestation.observation.finishedAt) ||
        Date.parse(attestation.observation.startedAt) >
          Date.parse(attestation.observation.finishedAt) ||
        attestation.stdoutRef !== stdoutRef ||
        attestation.stderrRef !== stderrRef ||
        !SHA256.test(attestation.stdoutSha256 ?? "") ||
        !SHA256.test(attestation.stderrSha256 ?? "") ||
        !Number.isInteger(attestation.stdoutByteLength) ||
        !Number.isInteger(attestation.stderrByteLength) ||
        attestation.stdoutByteLength < 0 ||
        attestation.stderrByteLength < 0 ||
        attestation.stdoutByteLength > 64 * 1024 * 1024 ||
        attestation.stderrByteLength > 64 * 1024 * 1024 ||
        !SHA256.test(attestation.resultSha256 ?? "") ||
        attestation.resultSha256 !==
          (await sha256ProjectValue(
            withoutField(attestation, "resultSha256"),
          ))
      ) {
        return fail();
      }
      if (
        acceptedRuntimeBindingDescriptor !== null &&
        canonicalizeProjectJson(acceptedRuntimeBindingDescriptor) !==
          canonicalizeProjectJson(attestation.runtimeBinding)
      ) {
        return fail();
      }
      acceptedRuntimeBindingDescriptor =
        structuredClone(attestation.runtimeBinding);
      const runtimeBindingBytes = await evidenceResolver(
        attestation.runtimeBinding.artifactRef,
      );
      if (
        !(runtimeBindingBytes instanceof Uint8Array) ||
        runtimeBindingBytes.byteLength !==
          attestation.runtimeBinding.artifactByteLength ||
        (await hashBytes(runtimeBindingBytes)) !==
          attestation.runtimeBinding.artifactSha256
      ) {
        return fail();
      }
      const runtimeBinding = parseIndependentReviewJsonBytes(
        runtimeBindingBytes,
        "Independent review runtime binding",
        1024 * 1024,
      );
      if (
        !validateIndependentReviewRuntimeBinding(runtimeBinding).ok ||
        runtimeBinding.bindingSha256 !==
          attestation.runtimeBinding.bindingSha256 ||
        runtimeBinding.nodeExecutable.sha256 !==
          attestation.runtimeBinding.nodeExecutableSha256 ||
        runtimeBinding.dependencySetSha256 !==
          attestation.runtimeBinding.dependencySetSha256 ||
        runtimeBinding.gitToolchain.bindingSha256 !==
          attestation.runtimeBinding.gitToolchainSha256 ||
        (expectedRuntimeBinding !== null &&
          canonicalizeProjectJson(runtimeBinding) !==
            canonicalizeProjectJson(expectedRuntimeBinding))
      ) {
        return fail();
      }
      for (const [ref, digest, byteLength] of [
        [
          attestation.stdoutRef,
          attestation.stdoutSha256,
          attestation.stdoutByteLength,
        ],
        [
          attestation.stderrRef,
          attestation.stderrSha256,
          attestation.stderrByteLength,
        ],
      ]) {
        if (claimedRefs.has(ref)) return fail();
        claimedRefs.add(ref);
        const transcriptBytes = await evidenceResolver(ref);
        if (
          !(transcriptBytes instanceof Uint8Array) ||
          transcriptBytes.byteLength !== byteLength ||
          (await hashBytes(transcriptBytes)) !== digest
        ) {
          return fail();
        }
      }
    }
  } catch {
    return fail();
  }
  return result(true, "VERIFIED", []);
}

function fixedPolicyReasonCodes(policy) {
  const reasonCodes = [];
  if (
    !keysExactly(policy, [
      "schemaVersion",
      "policyId",
      "policyVersion",
      "lifecycle",
      "assuranceLevel",
      "applicablePhases",
      "dataBoundary",
      "humanIndependentReviewSatisfied",
      "independentModelReviewRequired",
      "p3HumanReviewRequired",
      "allowedModelConclusion",
      "forbiddenHumanConclusion",
      "allowedReviewScopes",
      "reviewerIndependence",
      "p3HumanReviewBoundary",
      "historicalTreatment",
      "requiredCheck",
      "localTrustBoundary",
      "canonicalization",
      "governanceBoundary",
      "policySha256",
    ])
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    policy?.schemaVersion !== "independent-review-policy.v2" ||
    policy?.lifecycle !== "CANDIDATE_NOT_ACTIVATED" ||
    policy?.assuranceLevel !== "MODEL_ONLY_PREPRODUCTION" ||
    canonicalizeProjectJson(policy?.applicablePhases) !==
      canonicalizeProjectJson(["P0", "P1", "P2"]) ||
    policy?.dataBoundary !== "SYNTHETIC_ONLY" ||
    policy?.independentModelReviewRequired !== true ||
    policy?.p3HumanReviewRequired !== true ||
    policy?.allowedModelConclusion !==
      "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    !keysExactly(policy?.localTrustBoundary, [
      "acceptedAssuranceClaim",
      "externalNonRepudiationProvided",
      "hostOwnerCanForgeEvidence",
      "providerModelInternalsAttested",
      "transportCredentialAccessibleAsModelTool",
      "sufficientFor",
      "forbiddenClaims",
    ]) ||
    policy?.localTrustBoundary?.acceptedAssuranceClaim !==
      "LOCAL_CONTROL_PLANE_OBSERVED_OS_ENFORCEMENT" ||
    policy?.localTrustBoundary?.externalNonRepudiationProvided !== false ||
    policy?.localTrustBoundary?.hostOwnerCanForgeEvidence !== true ||
    policy?.localTrustBoundary?.providerModelInternalsAttested !== false ||
    policy?.localTrustBoundary?.transportCredentialAccessibleAsModelTool !==
      false ||
    canonicalizeProjectJson(policy?.localTrustBoundary?.sufficientFor) !==
      canonicalizeProjectJson([
        "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
      ]) ||
    canonicalizeProjectJson(policy?.localTrustBoundary?.forbiddenClaims) !==
      canonicalizeProjectJson([
        "CRYPTOGRAPHICALLY_UNFORGEABLE",
        "INDEPENDENT_HUMAN_REVIEW_COMPLETE",
        "PRODUCTION_GRADE",
      ])
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_LOCAL_TRUST_BOUNDARY_INVALID");
  }
  if (
    policy?.humanIndependentReviewSatisfied !== false ||
    policy?.forbiddenHumanConclusion !==
      "INDEPENDENT_HUMAN_REVIEW_COMPLETE" ||
    policy?.governanceBoundary?.githubHumanApprovalClaimAllowed !== false
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_HUMAN_CLAIM_FORBIDDEN");
  }
  if (
    canonicalizeProjectJson([...(policy?.allowedReviewScopes ?? [])].sort()) !==
      canonicalizeProjectJson(ALLOWED_REVIEW_SCOPES) ||
    !keysExactly(policy?.reviewerIndependence, [
      "differentModelIdRequired",
      "differentProviderOrFamilyPreferred",
      "freshIsolatedContextRequired",
      "fullImplementationHistoryAllowed",
      "implementationParticipationAllowed",
      "approvedIsolationModes",
      "allowedInputs",
      "promptInjectionIsUntrustedData",
      "forbiddenCapabilities",
    ]) ||
    policy?.reviewerIndependence?.differentModelIdRequired !== true ||
    policy?.reviewerIndependence?.differentProviderOrFamilyPreferred !== true ||
    policy?.reviewerIndependence?.freshIsolatedContextRequired !== true ||
    policy?.reviewerIndependence?.fullImplementationHistoryAllowed !== false ||
    policy?.reviewerIndependence?.implementationParticipationAllowed !== false ||
    canonicalizeProjectJson(
      policy?.reviewerIndependence?.approvedIsolationModes,
    ) !== canonicalizeProjectJson(APPROVED_ISOLATION_MODES) ||
    canonicalizeProjectJson(policy?.reviewerIndependence?.allowedInputs) !==
      canonicalizeProjectJson(ALLOWED_INPUTS) ||
    policy?.reviewerIndependence?.promptInjectionIsUntrustedData !== true ||
    canonicalizeProjectJson(
      policy?.reviewerIndependence?.forbiddenCapabilities,
    ) !== canonicalizeProjectJson(FORBIDDEN_CAPABILITIES)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    policy?.historicalTreatment?.preserveHistoricalRecords !== true ||
    policy?.historicalTreatment?.retroactiveSatisfaction !== false ||
    policy?.historicalTreatment?.p1B11ReevaluationMode !== "APPEND_ONLY" ||
    !policy?.historicalTreatment?.preservedReasonCodes?.includes(
      "INCONCLUSIVE_INDEPENDENT_REVIEWER_MISSING",
    ) ||
    !policy?.historicalTreatment?.preservedReasonCodes?.includes(
      "INCONCLUSIVE_INDEPENDENT_HUMAN_REVIEWER_MISSING",
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_HISTORICAL_RECORD_MUTATION");
  }
  if (
    !keysExactly(policy?.p3HumanReviewBoundary, [
      "phases",
      "dataBoundaries",
      "highRiskScopes",
      "modelReviewSubstitutionAllowed",
    ]) ||
    policy?.p3HumanReviewBoundary?.modelReviewSubstitutionAllowed !== false ||
    canonicalizeProjectJson(policy?.p3HumanReviewBoundary?.phases) !==
      canonicalizeProjectJson(P3_HUMAN_REVIEW_PHASES) ||
    canonicalizeProjectJson(policy?.p3HumanReviewBoundary?.dataBoundaries) !==
      canonicalizeProjectJson(P3_HUMAN_REVIEW_DATA_BOUNDARIES) ||
    canonicalizeProjectJson(policy?.p3HumanReviewBoundary?.highRiskScopes) !==
      canonicalizeProjectJson(P3_HUMAN_REVIEW_HIGH_RISK_SCOPES)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_P3_HUMAN_REVIEW_REQUIRED");
  }
  if (
    policy?.governanceBoundary?.d1RemainsStateTruth !== true ||
    policy?.governanceBoundary?.gitRemainsEvidenceTruth !== true ||
    policy?.governanceBoundary?.secondStatusTruthAllowed !== false ||
    policy?.governanceBoundary?.governanceEffect !== "NONE" ||
    policy?.governanceBoundary?.isProgressTracker !== false ||
    policy?.governanceBoundary?.selfAuthorizing !== false
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    !keysExactly(policy?.requiredCheck, [
      "context",
      "clearConclusion",
      "blockedConclusion",
      "inconclusiveConclusion",
      "githubHumanApproveCreated",
      "remotePublicationAuthorized",
    ]) ||
    policy?.requiredCheck?.context !== "independent-model-review" ||
    policy?.requiredCheck?.clearConclusion !== "success" ||
    policy?.requiredCheck?.blockedConclusion !== "failure" ||
    policy?.requiredCheck?.inconclusiveConclusion !== "failure" ||
    policy?.requiredCheck?.githubHumanApproveCreated !== false ||
    policy?.requiredCheck?.remotePublicationAuthorized !== false ||
    policy?.canonicalization !== "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  return reasonCodes;
}

export async function validateIndependentReviewPolicy(policy) {
  const reasonCodes = fixedPolicyReasonCodes(policy);
  if (
    !SHA256.test(policy?.policySha256 ?? "") ||
    (SHA256.test(policy?.policySha256 ?? "") &&
      (await policyDigest(policy)) !== policy.policySha256)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_HASH_MISMATCH");
  }
  return reasonCodes.length === 0
    ? result(true, "VALID_CANDIDATE", [])
    : result(false, "INVALID", reasonCodes);
}

const BUNDLE_INPUT_KEYS = [
  "bundleId",
  "generatedAt",
  "applicablePhase",
  "policyPath",
  "policy",
  "artifacts",
  "source",
  "repositoryProtection",
  "reviewedPaths",
  "sourceSubjects",
  "specificationSubjects",
  "testEvidenceSubjects",
  "implementationIdentity",
];

export async function createIndependentReviewBundle(input) {
  if (!keysExactly(input, BUNDLE_INPUT_KEYS)) {
    throw new TypeError(
      "Independent Review Bundle input contains missing or unknown fields.",
    );
  }
  const policyValidation = await validateIndependentReviewPolicy(input.policy);
  if (!policyValidation.ok) {
    throw new TypeError("Independent Review Policy candidate is invalid.");
  }
  const bundle = {
    schemaVersion: "independent-review-bundle.v2",
    bundleId: input.bundleId,
    lifecycle: "CANDIDATE",
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    applicablePhase: input.applicablePhase,
    dataBoundary: "SYNTHETIC_ONLY",
    enterpriseDataUsed: false,
    productionEffect: false,
    policy: {
      path: input.policyPath,
      version: input.policy.policyVersion,
      sha256: input.policy.policySha256,
    },
    artifacts: structuredClone(input.artifacts),
    source: structuredClone(input.source),
    repositoryProtection: structuredClone(input.repositoryProtection),
    reviewedPaths: structuredClone(input.reviewedPaths),
    sourceSubjects: structuredClone(input.sourceSubjects),
    specificationSubjects: structuredClone(input.specificationSubjects),
    testEvidenceSubjects: structuredClone(input.testEvidenceSubjects),
    implementationIdentity: structuredClone(input.implementationIdentity),
    requiredRuntimeConstraints: {
      differentModelIdRequired: true,
      differentProviderOrFamilyPreferred: true,
      freshIsolatedContextRequired: true,
      fullImplementationHistoryAllowed: false,
      implementationParticipationAllowed: false,
      allowedInputsOnly: true,
      promptInjectionTreatedAsData: true,
      approvedIsolationModes: APPROVED_ISOLATION_MODES,
      reviewMaterialAccess: "EXACT_HASH_BOUND_BUNDLE_READ_ONLY",
      runtimeScratchPolicy: "ISOLATED_NON_GOVERNANCE_SCRATCH_ONLY",
      ephemeral: true,
      forbiddenCapabilities: [
        "COMMIT",
        "D1_WRITE",
        "DEPLOY",
        "FILE_WRITE",
        "GOVERNANCE_DECISION",
        "PUSH",
      ],
    },
    governanceBoundary: {
      governanceEffect: "NONE",
      isProgressTracker: false,
      selfAuthorizing: false,
      humanIndependentReviewSatisfied: false,
      remoteCheckPublished: false,
      p1B11StatusChanged: false,
    },
    generatedAt: input.generatedAt,
    bundleSha256: `sha256:${"0".repeat(64)}`,
  };
  bundle.bundleSha256 = await bundleDigest(bundle);
  const validation = await validateIndependentReviewBundle(bundle, {
    policy: input.policy,
  });
  if (!validation.ok) {
    throw new TypeError(
      `Independent Review Bundle is invalid: ${validation.reasonCodes.join(",")}`,
    );
  }
  return bundle;
}

async function bundleBaseReasonCodes(bundle, policy) {
  const reasonCodes = [];
  if (
    !keysExactly(bundle, [
      "schemaVersion",
      "bundleId",
      "lifecycle",
      "assuranceLevel",
      "applicablePhase",
      "dataBoundary",
      "enterpriseDataUsed",
      "productionEffect",
      "policy",
      "artifacts",
      "source",
      "repositoryProtection",
      "reviewedPaths",
      "sourceSubjects",
      "specificationSubjects",
      "testEvidenceSubjects",
      "implementationIdentity",
      "requiredRuntimeConstraints",
      "governanceBoundary",
      "generatedAt",
      "bundleSha256",
    ]) ||
    bundle?.schemaVersion !== "independent-review-bundle.v2" ||
    bundle?.lifecycle !== "CANDIDATE" ||
    bundle?.assuranceLevel !== "MODEL_ONLY_PREPRODUCTION" ||
    bundle?.dataBoundary !== "SYNTHETIC_ONLY"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_BUNDLE_INVALID");
  }
  if (
    bundle?.applicablePhase === "P3" ||
    bundle?.enterpriseDataUsed !== false ||
    bundle?.productionEffect !== false
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_P3_HUMAN_REVIEW_REQUIRED");
  } else if (!["P0", "P1", "P2"].includes(bundle?.applicablePhase)) {
    reasonCodes.push("INDEPENDENT_REVIEW_BUNDLE_INVALID");
  }
  if (
    !keysExactly(bundle?.policy, ["path", "version", "sha256"]) ||
    bundle?.policy?.sha256 !== policy?.policySha256 ||
    bundle?.policy?.version !== policy?.policyVersion ||
    !safePath(bundle?.policy?.path)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (
    !keysExactly(bundle?.artifacts, [
      "policySchemaPath",
      "policySchemaSha256",
      "bundleSchemaPath",
      "bundleSchemaSha256",
      "receiptSchemaPath",
      "receiptSchemaSha256",
      "outputSchemaPath",
      "outputSchemaSha256",
      "runtimeEvidenceSchemaPath",
      "runtimeEvidenceSchemaSha256",
      "transportEvidenceSchemaPath",
      "transportEvidenceSchemaSha256",
      "testResultSchemaPath",
      "testResultSchemaSha256",
      "semanticValidatorPath",
      "semanticValidatorSha256",
      "independenceValidatorPath",
      "independenceValidatorSha256",
      "runtimeEvidenceValidatorPath",
      "runtimeEvidenceValidatorSha256",
      "transportEvidenceValidatorPath",
      "transportEvidenceValidatorSha256",
      "checkMapperPath",
      "checkMapperSha256",
      "bundleGeneratorPath",
      "bundleGeneratorSha256",
      "testPlanPath",
      "testPlanSha256",
      "testEvidenceCollectorPath",
      "testEvidenceCollectorSha256",
      "runtimeControlPlanePath",
      "runtimeControlPlaneSha256",
      "sandboxPolicyTemplatePath",
      "sandboxPolicyTemplateSha256",
      "promptPath",
      "promptSha256",
    ]) ||
    Object.entries(bundle?.artifacts ?? {}).some(([key, value]) =>
      key.endsWith("Path") ? !safePath(value) : !SHA256.test(value),
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_BUNDLE_INVALID");
  }
  if (
    !keysExactly(bundle?.source, [
      "baseCommit",
      "sourceCommit",
      "headCommit",
      "tree",
      "diffSha256",
      "changedPathsDigest",
      "gitDiffCheck",
    ]) ||
    !GIT_COMMIT.test(bundle?.source?.baseCommit ?? "") ||
    !GIT_COMMIT.test(bundle?.source?.sourceCommit ?? "") ||
    !GIT_COMMIT.test(bundle?.source?.headCommit ?? "") ||
    !GIT_COMMIT.test(bundle?.source?.tree ?? "") ||
    bundle?.source?.sourceCommit !== bundle?.source?.headCommit
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_BASE_HEAD_TREE_MISMATCH");
  }
  if (
    !SHA256.test(bundle?.source?.diffSha256 ?? "") ||
    !SHA256.test(bundle?.source?.changedPathsDigest ?? "")
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_DIFF_DIGEST_MISMATCH");
  }
  const gitDiffCheck = bundle?.source?.gitDiffCheck;
  const gitDiffCheckSubject =
    gitDiffCheck && typeof gitDiffCheck === "object"
      ? withoutField(gitDiffCheck, "resultSha256")
      : null;
  if (
    !keysExactly(gitDiffCheck, [
      "schemaVersion",
      "checkId",
      "executionMode",
      "baseCommit",
      "sourceCommit",
      "sourceTree",
      "checkedPatchSha256",
      "runnerPath",
      "runnerGitBlobSha256",
      "runnerExecutedBytesSha256",
      "gitExecutable",
      "gitVersion",
      "logicalCommandSha256",
      "environmentSha256",
      "exitCode",
      "status",
      "stdoutSha256",
      "stdoutByteLength",
      "stderrSha256",
      "stderrByteLength",
      "resultSha256",
    ]) ||
    gitDiffCheck?.schemaVersion !==
      "independent-review-git-diff-check.v1" ||
    gitDiffCheck?.checkId !== "base-to-source-diff-check" ||
    gitDiffCheck?.executionMode !==
      "TRUSTED_GIT_OBJECT_DATABASE_CONTROL_PLANE" ||
    gitDiffCheck?.baseCommit !== bundle?.source?.baseCommit ||
    gitDiffCheck?.sourceCommit !== bundle?.source?.sourceCommit ||
    gitDiffCheck?.sourceTree !== bundle?.source?.tree ||
    gitDiffCheck?.checkedPatchSha256 !== bundle?.source?.diffSha256 ||
    gitDiffCheck?.runnerPath !== bundle?.artifacts?.bundleGeneratorPath ||
    gitDiffCheck?.runnerGitBlobSha256 !==
      bundle?.artifacts?.bundleGeneratorSha256 ||
    gitDiffCheck?.runnerExecutedBytesSha256 !==
      bundle?.artifacts?.bundleGeneratorSha256 ||
    gitDiffCheck?.gitExecutable !== "/usr/bin/git" ||
    !/^git version [^\r\n]{1,128}$/u.test(
      gitDiffCheck?.gitVersion ?? "",
    ) ||
    gitDiffCheck?.logicalCommandSha256 !==
      (await sha256ProjectValue({
        executable: "/usr/bin/git",
        fixedArguments: [
          "--no-replace-objects",
          "-C",
          "<TRUSTED_REPOSITORY>",
          "diff",
          "--check",
          "--no-ext-diff",
          "--no-textconv",
        ],
        baseCommit: bundle?.source?.baseCommit,
        sourceCommit: bundle?.source?.sourceCommit,
        terminator: "--",
      })) ||
    gitDiffCheck?.environmentSha256 !==
      (await sha256ProjectValue(TRUSTED_GIT_ENVIRONMENT)) ||
    gitDiffCheck?.exitCode !== 0 ||
    gitDiffCheck?.status !== "PASS" ||
    gitDiffCheck?.stdoutSha256 !== EMPTY_SHA256 ||
    gitDiffCheck?.stdoutByteLength !== 0 ||
    gitDiffCheck?.stderrSha256 !== EMPTY_SHA256 ||
    gitDiffCheck?.stderrByteLength !== 0 ||
    !SHA256.test(gitDiffCheck?.resultSha256 ?? "") ||
    gitDiffCheck?.resultSha256 !==
      (await sha256ProjectValue(gitDiffCheckSubject ?? {}))
  ) {
    reasonCodes.push(
      "INDEPENDENT_REVIEW_GIT_DIFF_CHECK_BINDING_MISMATCH",
    );
  }
  if (
    !keysExactly(bundle?.repositoryProtection, [
      "protectedPaths",
      "protectedPathSetSha256",
    ]) ||
    !Array.isArray(bundle?.repositoryProtection?.protectedPaths) ||
    bundle.repositoryProtection.protectedPaths.length === 0 ||
    !bundle.repositoryProtection.protectedPaths.every(safePath) ||
    !unique(bundle.repositoryProtection.protectedPaths) ||
    !sorted(bundle.repositoryProtection.protectedPaths) ||
    !SHA256.test(
      bundle?.repositoryProtection?.protectedPathSetSha256 ?? "",
    ) ||
    bundle.repositoryProtection.protectedPathSetSha256 !==
      (await sha256ProjectValue(bundle.repositoryProtection.protectedPaths))
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_REPOSITORY_PROTECTION_INVALID");
  }
  if (
    !Array.isArray(bundle?.reviewedPaths) ||
    bundle.reviewedPaths.length === 0 ||
    !bundle.reviewedPaths.every(safePath) ||
    !unique(bundle.reviewedPaths) ||
    !sorted(bundle.reviewedPaths)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_CHANGED_PATHS_MISMATCH");
  }
  const subjectPaths = bundle?.sourceSubjects?.map((subject) => subject.path);
  if (
    !Array.isArray(subjectPaths) ||
    canonicalizeProjectJson(subjectPaths) !==
      canonicalizeProjectJson(bundle?.reviewedPaths) ||
    !bundle.sourceSubjects.every(
      (subject) =>
        keysExactly(subject, ["path", "gitMode", "blobSha256"]) &&
        safePath(subject.path) &&
        /^(100644|100755|120000|160000)$/u.test(subject.gitMode) &&
        SHA256.test(subject.blobSha256),
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_SCOPE_INCOMPLETE");
  }
  if (
    !bundle?.specificationSubjects?.length ||
    !bundle.specificationSubjects.every(
      (subject) =>
        keysExactly(subject, ["path", "blobSha256"]) &&
        safePath(subject.path) &&
        SHA256.test(subject.blobSha256),
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_SCOPE_INCOMPLETE");
  }
  if (
    !bundle?.testEvidenceSubjects?.length ||
    !bundle.testEvidenceSubjects.every(
      (evidence) =>
        keysExactly(evidence, [
          "evidenceId",
          "command",
          "status",
          "exitCode",
          "outputRef",
          "outputSha256",
          "outputByteLength",
          "truncated",
          "sourceCommit",
          "runner",
          "toolVersions",
        ]) &&
        evidence.status === "PASS" &&
        evidence.exitCode === 0 &&
        safePath(evidence.outputRef) &&
        SHA256.test(evidence.outputSha256) &&
        Number.isInteger(evidence.outputByteLength) &&
        evidence.outputByteLength > 0 &&
        evidence.truncated === false &&
        evidence.sourceCommit === bundle?.source?.sourceCommit &&
        evidence.runner === "GIT_FROZEN_ARCHIVE_READONLY_CONTROL_PLANE" &&
        Array.isArray(evidence.toolVersions) &&
        evidence.toolVersions.length > 0,
    )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_TEST_EVIDENCE_MISMATCH");
  }
  if (
    !keysExactly(bundle?.implementationIdentity, [
      "provider",
      "modelId",
      "modelVersion",
      "participantManifestSha256",
      "sessionIdSha256",
    ]) ||
    typeof bundle?.implementationIdentity?.provider !== "string" ||
    typeof bundle?.implementationIdentity?.modelId !== "string" ||
    typeof bundle?.implementationIdentity?.modelVersion !== "string" ||
    !SHA256.test(
      bundle?.implementationIdentity?.participantManifestSha256 ?? "",
    ) ||
    !SHA256.test(bundle?.implementationIdentity?.sessionIdSha256 ?? "")
  ) {
    reasonCodes.push(
      "INDEPENDENT_REVIEW_IMPLEMENTATION_PARTICIPATION_NOT_PROVED",
    );
  }
  if (
    !SHA256.test(bundle?.artifacts?.promptSha256 ?? "") ||
    !safePath(bundle?.artifacts?.promptPath)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_PROMPT_DIGEST_MISMATCH");
  }
  if (
    !keysExactly(bundle?.requiredRuntimeConstraints, [
      "differentModelIdRequired",
      "differentProviderOrFamilyPreferred",
      "freshIsolatedContextRequired",
      "fullImplementationHistoryAllowed",
      "implementationParticipationAllowed",
      "allowedInputsOnly",
      "promptInjectionTreatedAsData",
      "approvedIsolationModes",
      "reviewMaterialAccess",
      "runtimeScratchPolicy",
      "ephemeral",
      "forbiddenCapabilities",
    ]) ||
    bundle?.requiredRuntimeConstraints?.differentModelIdRequired !== true ||
    bundle?.requiredRuntimeConstraints?.freshIsolatedContextRequired !== true ||
    bundle?.requiredRuntimeConstraints?.fullImplementationHistoryAllowed !==
      false ||
    bundle?.requiredRuntimeConstraints?.implementationParticipationAllowed !==
      false ||
    bundle?.requiredRuntimeConstraints?.promptInjectionTreatedAsData !== true ||
    bundle?.requiredRuntimeConstraints?.allowedInputsOnly !== true ||
    canonicalizeProjectJson(
      bundle?.requiredRuntimeConstraints?.approvedIsolationModes,
    ) !== canonicalizeProjectJson(APPROVED_ISOLATION_MODES) ||
    bundle?.requiredRuntimeConstraints?.reviewMaterialAccess !==
      "EXACT_HASH_BOUND_BUNDLE_READ_ONLY" ||
    bundle?.requiredRuntimeConstraints?.runtimeScratchPolicy !==
      "ISOLATED_NON_GOVERNANCE_SCRATCH_ONLY" ||
    bundle?.requiredRuntimeConstraints?.ephemeral !== true ||
    canonicalizeProjectJson(
      bundle?.requiredRuntimeConstraints?.forbiddenCapabilities,
    ) !== canonicalizeProjectJson(FORBIDDEN_CAPABILITIES)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_CONTEXT_ISOLATION_NOT_PROVED");
  }
  if (
    bundle?.governanceBoundary?.governanceEffect !== "NONE" ||
    bundle?.governanceBoundary?.isProgressTracker !== false ||
    bundle?.governanceBoundary?.selfAuthorizing !== false ||
    bundle?.governanceBoundary?.humanIndependentReviewSatisfied !== false ||
    bundle?.governanceBoundary?.remoteCheckPublished !== false ||
    bundle?.governanceBoundary?.p1B11StatusChanged !== false
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_HUMAN_CLAIM_FORBIDDEN");
  }
  return reasonCodes;
}

export async function validateIndependentReviewBundle(bundle, { policy }) {
  const reasonCodes = await bundleBaseReasonCodes(bundle, policy);
  if (
    !SHA256.test(bundle?.bundleSha256 ?? "") ||
    (SHA256.test(bundle?.bundleSha256 ?? "") &&
      (await bundleDigest(bundle)) !== bundle.bundleSha256)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_BUNDLE_HASH_MISMATCH");
  }
  return reasonCodes.length === 0
    ? result(true, "VALID", [])
    : result(false, "INVALID", reasonCodes);
}

const RUNTIME_KEYS = [
  "schemaVersion",
  "runtime",
  "cliVersion",
  "provider",
  "modelId",
  "modelFamily",
  "modelVersion",
  "modelVersionEvidence",
  "backendBuildId",
  "diversityLevel",
  "reviewerSessionId",
  "implementationModelIds",
  "ephemeral",
  "sandbox",
  "networkAccess",
  "userConfigLoaded",
  "projectRulesLoaded",
  "fullImplementationConversationImported",
  "implementationConclusionsProvided",
  "allowedInputsOnly",
  "promptInjectionTreatedAsData",
  "capabilities",
  "isolationProbeResults",
  "repositoryUnchangedBeforeAfter",
  "inputBundleSha256",
  "outputSchemaSha256",
  "rawModelOutputSha256",
  "rawModelOutputByteLength",
  "startedAt",
  "finishedAt",
];

export async function validateIndependentModelIndependence({
  policy,
  bundle,
  runtimeAttestation,
  isolationEvidenceResolver,
}) {
  const blocked = [];
  const inconclusive = [];
  if (
    !keysExactly(runtimeAttestation, RUNTIME_KEYS) ||
    runtimeAttestation?.schemaVersion !==
      "independent-model-runtime-attestation.v1"
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_IMPLEMENTATION_PARTICIPATION_NOT_PROVED");
  } else {
    inconclusive.push(
      "INDEPENDENT_REVIEW_LEGACY_RUNTIME_ATTESTATION_UNTRUSTED",
    );
  }
  const implementationModelIds = bundle?.implementationIdentity?.modelId
    ? [bundle.implementationIdentity.modelId]
    : [];
  if (
    runtimeAttestation?.modelId === bundle?.implementationIdentity?.modelId
  ) {
    blocked.push("INDEPENDENT_REVIEW_MODEL_IDENTITY_NOT_DISTINCT");
  }
  if (
    runtimeAttestation?.implementationModelIds?.includes(
      runtimeAttestation?.modelId,
    )
  ) {
    blocked.push("INDEPENDENT_REVIEW_IMPLEMENTATION_PARTICIPATION_CONFLICT");
  }
  if (
    !unique(runtimeAttestation?.implementationModelIds) ||
    canonicalizeProjectJson(runtimeAttestation?.implementationModelIds) !==
      canonicalizeProjectJson(implementationModelIds)
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_IMPLEMENTATION_PARTICIPATION_NOT_PROVED");
  }
  if (
    typeof runtimeAttestation?.modelId !== "string" ||
    typeof runtimeAttestation?.modelVersion !== "string" ||
    runtimeAttestation.modelId.length === 0 ||
    runtimeAttestation.modelVersion.length === 0 ||
    runtimeAttestation?.modelVersionEvidence !==
      "CLI_REQUEST_AND_RUNTIME_REPORTED_MODEL_ID"
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_MODEL_IDENTITY_UNPINNED");
  }
  if (!boundedString(runtimeAttestation?.reviewerSessionId, 8, 128)) {
    inconclusive.push("INDEPENDENT_REVIEW_CONTEXT_ISOLATION_NOT_PROVED");
  }
  const expectedDiversity =
    runtimeAttestation?.provider !== bundle?.implementationIdentity?.provider
      ? "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER"
      : "DIFFERENT_MODEL_ID_SAME_PROVIDER";
  if (
    runtimeAttestation?.diversityLevel !== expectedDiversity &&
    !(
      runtimeAttestation?.provider === bundle?.implementationIdentity?.provider &&
      runtimeAttestation?.diversityLevel ===
        "DIFFERENT_MODEL_ID_DIFFERENT_FAMILY"
    )
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_MODEL_IDENTITY_UNPINNED");
  }
  if (
    runtimeAttestation?.ephemeral !== true ||
    runtimeAttestation?.userConfigLoaded !== false ||
    runtimeAttestation?.projectRulesLoaded !== false ||
    runtimeAttestation?.fullImplementationConversationImported !== false ||
    runtimeAttestation?.implementationConclusionsProvided !== false ||
    runtimeAttestation?.allowedInputsOnly !== true ||
    runtimeAttestation?.promptInjectionTreatedAsData !== true
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_CONTEXT_ISOLATION_NOT_PROVED");
  }
  if (
    !(
      (runtimeAttestation?.sandbox === "no-local-tools" &&
        runtimeAttestation?.networkAccess === "NO_MODEL_TOOLS_EXPOSED" &&
        runtimeAttestation?.isolationProbeResults?.enforcementMode ===
          "API_NO_TOOLS") ||
      (runtimeAttestation?.sandbox === "os-enforced-target-read-only" &&
        runtimeAttestation?.networkAccess ===
          "CONTROL_PLANE_MODEL_TRANSPORT_ONLY_NO_NETWORK_TOOL" &&
        runtimeAttestation?.isolationProbeResults?.enforcementMode ===
          "OS_ENFORCED_TARGET_READ_ONLY")
    ) ||
    !keysExactly(runtimeAttestation?.capabilities, [
      "fileWrite",
      "fileReadOutsideBundle",
      "commit",
      "push",
      "d1Write",
      "deploy",
      "governanceDecision",
    ]) ||
    Object.values(runtimeAttestation?.capabilities ?? {}).some(
      (allowed) => allowed !== false,
    ) ||
    !(await validIsolationProbeResults(
      runtimeAttestation?.isolationProbeResults,
      isolationEvidenceResolver,
    )) ||
    !(await validRepositoryUnchangedProof(
      runtimeAttestation?.repositoryUnchangedBeforeAfter,
      bundle,
    ))
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_READ_ONLY_PERMISSION_NOT_PROVED");
  }
  if (
    runtimeAttestation?.inputBundleSha256 !== bundle?.bundleSha256 ||
    runtimeAttestation?.outputSchemaSha256 !==
      bundle?.artifacts?.outputSchemaSha256
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_SCOPE_INCOMPLETE");
  }
  if (
    !validDate(runtimeAttestation?.startedAt) ||
    !validDate(runtimeAttestation?.finishedAt) ||
    Date.parse(runtimeAttestation.startedAt) >
      Date.parse(runtimeAttestation.finishedAt)
  ) {
    inconclusive.push("INDEPENDENT_REVIEW_TIME_ORDER_INVALID");
  }
  if (policy?.assuranceLevel !== "MODEL_ONLY_PREPRODUCTION") {
    inconclusive.push("INDEPENDENT_REVIEW_POLICY_INVALID");
  }
  if (blocked.length > 0) {
    return result(false, "BLOCKED", blocked, {
      diversityLevel: runtimeAttestation?.diversityLevel ?? "UNPROVED",
    });
  }
  if (inconclusive.length > 0) {
    return result(false, "INCONCLUSIVE", inconclusive, {
      diversityLevel: runtimeAttestation?.diversityLevel ?? "UNPROVED",
    });
  }
  return result(true, "PROVED", [], {
    diversityLevel: runtimeAttestation.diversityLevel,
  });
}

function outputIsClosed(output) {
  const findingIds = output?.findings?.map((finding) => finding.findingId);
  return (
    keysExactly(output, [
      "schemaVersion",
      "reviewSummary",
      "findings",
      "decision",
    ]) &&
    output.schemaVersion === "independent-model-review-output.v2" &&
    DECISIONS.has(output.decision) &&
    boundedString(output.reviewSummary, 1, 4000) &&
    Array.isArray(output.findings) &&
    output.findings.length <= 100 &&
    unique(findingIds) &&
    output.findings.every(
      (finding) =>
        keysExactly(finding, [
          "findingId",
          "severity",
          "status",
          "path",
          "startLine",
          "endLine",
          "summary",
          "detailsSha256",
          "resolutionEvidenceDigests",
        ]) &&
        ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(
          finding.severity,
        ) &&
        ["OPEN", "RESOLVED"].includes(finding.status) &&
        FINDING_ID.test(finding.findingId) &&
        (finding.path === null ||
          (boundedString(finding.path, 1, 512) && safePath(finding.path))) &&
        boundedString(finding.summary, 1, 1000) &&
        SHA256.test(finding.detailsSha256) &&
        (finding.startLine === null ||
          (Number.isInteger(finding.startLine) && finding.startLine > 0)) &&
        (finding.endLine === null ||
          (Number.isInteger(finding.endLine) && finding.endLine > 0)) &&
        (finding.startLine === null ||
          finding.endLine === null ||
          finding.startLine <= finding.endLine) &&
        Array.isArray(finding.resolutionEvidenceDigests) &&
        finding.resolutionEvidenceDigests.length <= 32 &&
        unique(finding.resolutionEvidenceDigests) &&
        finding.resolutionEvidenceDigests.every((value) => SHA256.test(value)),
    )
  );
}

export function parseIndependentModelReviewOutput(rawBytes) {
  return parseIndependentReviewJsonBytes(
    rawBytes,
    "Independent model review output",
    64 * 1024,
  );
}

export function independentReviewSchemaValidatorVersion() {
  return `ajv@${AJV_VERSION}`;
}

export function deriveIndependentModelDiversity({
  implementationProvider,
  implementationModel,
  reviewerProvider,
  reviewerModel,
}) {
  if (
    !boundedString(implementationProvider, 1, 64) ||
    !boundedString(implementationModel, 1, 128) ||
    !boundedString(reviewerProvider, 1, 64) ||
    !boundedString(reviewerModel, 1, 128) ||
    implementationModel === reviewerModel
  ) {
    throw new TypeError("Independent review model identity is invalid.");
  }
  return implementationProvider === reviewerProvider
    ? "DIFFERENT_MODEL_ID_SAME_PROVIDER"
    : "DIFFERENT_MODEL_ID_DIFFERENT_PROVIDER";
}

export async function validateIndependentReviewSchemaInstance({
  schemaBytes,
  expectedSchemaSha256,
  instance,
  label,
  maximumBytes = 1024 * 1024,
}) {
  const reasonCodes = [];
  if (
    !(schemaBytes instanceof Uint8Array) ||
    !SHA256.test(expectedSchemaSha256 ?? "") ||
    (await hashBytes(schemaBytes)) !== expectedSchemaSha256
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_SCHEMA_BYTES_MISMATCH");
    return result(false, "BLOCKED", reasonCodes);
  }
  let schema = null;
  try {
    schema = parseIndependentReviewJsonBytes(
      schemaBytes,
      label,
      maximumBytes,
    );
  } catch {
    schema = null;
  }
  if (schema === null) {
    return result(false, "BLOCKED", [
      "INDEPENDENT_REVIEW_SCHEMA_INVALID",
    ]);
  }
  try {
    const ajv = new Ajv2020({
      strict: true,
      allErrors: true,
      validateFormats: true,
    });
    addFormats(ajv);
    if (ajv.compile(schema)(instance) !== true) {
      reasonCodes.push("INDEPENDENT_REVIEW_SCHEMA_INSTANCE_INVALID");
    }
  } catch {
    reasonCodes.push("INDEPENDENT_REVIEW_SCHEMA_INVALID");
  }
  return result(
    reasonCodes.length === 0,
    reasonCodes.length === 0 ? "VALID" : "BLOCKED",
    reasonCodes,
  );
}

export async function validateIndependentModelReviewOutputArtifact({
  rawModelOutput,
  outputSchemaBytes,
  expectedOutputSchemaSha256,
}) {
  let output = null;
  try {
    output = parseIndependentModelReviewOutput(rawModelOutput);
  } catch {
    output = null;
  }
  const schemaValidation = await validateIndependentReviewSchemaInstance({
    schemaBytes: outputSchemaBytes,
    expectedSchemaSha256: expectedOutputSchemaSha256,
    instance: output,
    label: "Independent model review output Schema",
  });
  const reasonCodes = [...schemaValidation.reasonCodes];
  if (!outputIsClosed(output)) {
    reasonCodes.push("INDEPENDENT_REVIEW_OUTPUT_INVALID");
  }
  const openBlockingFinding = output?.findings?.some(
    (finding) =>
      BLOCKING_SEVERITIES.has(finding.severity) &&
      finding.status === "OPEN",
  );
  if (output?.decision === "CLEAR" && openBlockingFinding) {
    reasonCodes.push("INDEPENDENT_REVIEW_UNRESOLVED_BLOCKING_FINDING");
  }
  return result(
    reasonCodes.length === 0,
    reasonCodes.length === 0
      ? output.decision
      : openBlockingFinding
        ? "BLOCKED"
        : "INCONCLUSIVE",
    [...new Set(reasonCodes)].sort(),
    {
      output,
      conclusion:
        reasonCodes.length === 0
          ? CONCLUSIONS[output.decision]
          : openBlockingFinding
            ? "BLOCKED"
            : "INCONCLUSIVE",
    },
  );
}

export async function createIndependentModelReviewReceipt({
  receiptId,
  policy,
  bundle,
  runtimeAttestationPath,
  runtimeAttestation,
  modelOutputPath,
  rawModelOutput,
  isolationEvidenceResolver,
  receiptSchemaBytes,
  outputSchemaBytes,
}) {
  const modelOutput = parseIndependentModelReviewOutput(rawModelOutput);
  const schemaValidators = await frozenSchemaValidators({
    bundle,
    receiptSchemaBytes,
    outputSchemaBytes,
  });
  const bundleValidation = await validateIndependentReviewBundle(bundle, {
    policy,
  });
  if (
    !bundleValidation.ok ||
    !outputIsClosed(modelOutput) ||
    schemaValidators.output?.(modelOutput) !== true
  ) {
    throw new TypeError("Independent model review inputs are invalid.");
  }
  const independence = await validateIndependentModelIndependence({
    policy,
    bundle,
    runtimeAttestation,
    isolationEvidenceResolver,
  });
  if (!independence.ok) {
    throw new TypeError("Independent model review independence is not proved.");
  }
  if (
    runtimeAttestation.rawModelOutputSha256 !==
      (await modelOutputDigest(rawModelOutput)) ||
    runtimeAttestation.rawModelOutputByteLength !== rawModelOutput.byteLength
  ) {
    throw new TypeError("Independent model review runtime evidence is stale.");
  }
  const receipt = {
    schemaVersion: "independent-model-review-receipt.v2",
    receiptId,
    receiptSchemaVersion: "independent-model-review-receipt.v2",
    reviewId: receiptId,
    policyVersion: policy.policyVersion,
    policySha256: policy.policySha256,
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    applicablePhase: bundle.applicablePhase,
    humanIndependentReviewSatisfied: false,
    independentModelReviewRequired: true,
    p3HumanReviewRequired: true,
    bundleId: bundle.bundleId,
    bundleSha256: bundle.bundleSha256,
    reviewBundleDigest: bundle.bundleSha256,
    reviewer: {
      provider: runtimeAttestation.provider,
      modelId: runtimeAttestation.modelId,
      modelFamily: runtimeAttestation.modelFamily,
      modelVersion: runtimeAttestation.modelVersion,
      modelVersionEvidence: runtimeAttestation.modelVersionEvidence,
      backendBuildId: runtimeAttestation.backendBuildId,
      diversityLevel: runtimeAttestation.diversityLevel,
    },
    reviewerModel: runtimeAttestation.modelId,
    reviewerSessionId: runtimeAttestation.reviewerSessionId,
    reviewerIndependentOfImplementation: true,
    source: structuredClone(bundle.source),
    sourceCommit: bundle.source.sourceCommit,
    sourceTree: bundle.source.tree,
    patchSha256: bundle.source.diffSha256,
    promptSha256: bundle.artifacts.promptSha256,
    reviewerPromptSha256: bundle.artifacts.promptSha256,
    reviewedPaths: structuredClone(bundle.reviewedPaths),
    findings: structuredClone(modelOutput.findings),
    testEvidenceDigests: bundle.testEvidenceSubjects.map(
      (evidence) => evidence.outputSha256,
    ),
    runtimeAttestationPath,
    runtimeAttestationSha256: await runtimeDigest(runtimeAttestation),
    modelOutputPath,
    modelOutputSha256: await modelOutputDigest(rawModelOutput),
    modelOutputByteLength: rawModelOutput.byteLength,
    isolationProbeResults: structuredClone(
      runtimeAttestation.isolationProbeResults,
    ),
    repositoryUnchangedBeforeAfter: structuredClone(
      runtimeAttestation.repositoryUnchangedBeforeAfter,
    ),
    decision: modelOutput.decision,
    conclusion: CONCLUSIONS[modelOutput.decision],
    humanReviewClaim: false,
    governanceEffect: "NONE",
    selfAuthorizing: false,
    startedAt: runtimeAttestation.startedAt,
    finishedAt: runtimeAttestation.finishedAt,
    reviewStartedAt: runtimeAttestation.startedAt,
    reviewFinishedAt: runtimeAttestation.finishedAt,
    receiptSha256: `sha256:${"0".repeat(64)}`,
  };
  receipt.receiptSha256 = await receiptDigest(receipt);
  if (schemaValidators.receipt(receipt) !== true) {
    throw new TypeError("Independent model review Receipt Schema is invalid.");
  }
  return receipt;
}

function receiptBindingReasonCodes({
  policy,
  bundle,
  receipt,
  runtimeAttestation,
  modelOutput,
}) {
  const reasonCodes = [];
  if (
    !keysExactly(receipt, [
      "schemaVersion",
      "receiptId",
      "receiptSchemaVersion",
      "reviewId",
      "policyVersion",
      "policySha256",
      "assuranceLevel",
      "applicablePhase",
      "humanIndependentReviewSatisfied",
      "independentModelReviewRequired",
      "p3HumanReviewRequired",
      "bundleId",
      "bundleSha256",
      "reviewBundleDigest",
      "reviewer",
      "reviewerModel",
      "reviewerSessionId",
      "reviewerIndependentOfImplementation",
      "source",
      "sourceCommit",
      "sourceTree",
      "patchSha256",
      "promptSha256",
      "reviewerPromptSha256",
      "reviewedPaths",
      "findings",
      "testEvidenceDigests",
      "runtimeAttestationPath",
      "runtimeAttestationSha256",
      "modelOutputPath",
      "modelOutputSha256",
      "modelOutputByteLength",
      "isolationProbeResults",
      "repositoryUnchangedBeforeAfter",
      "decision",
      "conclusion",
      "humanReviewClaim",
      "governanceEffect",
      "selfAuthorizing",
      "startedAt",
      "finishedAt",
      "reviewStartedAt",
      "reviewFinishedAt",
      "receiptSha256",
    ]) ||
    receipt?.schemaVersion !== "independent-model-review-receipt.v2" ||
    receipt?.receiptSchemaVersion !==
      "independent-model-review-receipt.v2" ||
    receipt?.reviewId !== receipt?.receiptId
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_INVALID");
  }
  if (
    !keysExactly(receipt?.reviewer, [
      "provider",
      "modelId",
      "modelFamily",
      "modelVersion",
      "modelVersionEvidence",
      "backendBuildId",
      "diversityLevel",
    ]) ||
    !keysExactly(receipt?.source, [
      "baseCommit",
      "sourceCommit",
      "headCommit",
      "tree",
      "diffSha256",
      "changedPathsDigest",
      "gitDiffCheck",
    ])
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_INVALID");
  }
  if (
    receipt?.humanIndependentReviewSatisfied !== false ||
    receipt?.reviewerIndependentOfImplementation !== true ||
    receipt?.humanReviewClaim !== false ||
    receipt?.governanceEffect !== "NONE" ||
    receipt?.selfAuthorizing !== false ||
    receipt?.conclusion === "INDEPENDENT_HUMAN_REVIEW_COMPLETE"
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_HUMAN_CLAIM_FORBIDDEN");
  }
  if (
    receipt?.policyVersion !== policy?.policyVersion ||
    receipt?.policySha256 !== policy?.policySha256 ||
    receipt?.assuranceLevel !== "MODEL_ONLY_PREPRODUCTION" ||
    receipt?.bundleId !== bundle?.bundleId ||
    receipt?.bundleSha256 !== bundle?.bundleSha256 ||
    receipt?.reviewBundleDigest !== bundle?.bundleSha256 ||
    receipt?.applicablePhase !== bundle?.applicablePhase
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (
    canonicalizeProjectJson(receipt?.source) !==
      canonicalizeProjectJson(bundle?.source) ||
    receipt?.sourceCommit !== bundle?.source?.sourceCommit ||
    receipt?.sourceTree !== bundle?.source?.tree ||
    receipt?.patchSha256 !== bundle?.source?.diffSha256 ||
    receipt?.promptSha256 !== bundle?.artifacts?.promptSha256 ||
    receipt?.reviewerPromptSha256 !== bundle?.artifacts?.promptSha256 ||
    canonicalizeProjectJson(receipt?.reviewedPaths) !==
      canonicalizeProjectJson(bundle?.reviewedPaths) ||
    canonicalizeProjectJson(receipt?.testEvidenceDigests) !==
      canonicalizeProjectJson(
        bundle?.testEvidenceSubjects?.map(
          (evidence) => evidence.outputSha256,
        ),
      )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (
    receipt?.reviewerModel !== runtimeAttestation?.modelId ||
    receipt?.reviewerSessionId !== runtimeAttestation?.reviewerSessionId ||
    canonicalizeProjectJson(receipt?.isolationProbeResults) !==
      canonicalizeProjectJson(runtimeAttestation?.isolationProbeResults) ||
    canonicalizeProjectJson(receipt?.repositoryUnchangedBeforeAfter) !==
      canonicalizeProjectJson(
        runtimeAttestation?.repositoryUnchangedBeforeAfter,
      )
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (
    receipt?.reviewer?.provider !== runtimeAttestation?.provider ||
    receipt?.reviewer?.modelId !== runtimeAttestation?.modelId ||
    receipt?.reviewer?.modelFamily !== runtimeAttestation?.modelFamily ||
    receipt?.reviewer?.modelVersion !== runtimeAttestation?.modelVersion ||
    receipt?.reviewer?.modelVersionEvidence !==
      runtimeAttestation?.modelVersionEvidence ||
    receipt?.reviewer?.backendBuildId !==
      runtimeAttestation?.backendBuildId ||
    receipt?.reviewer?.diversityLevel !==
      runtimeAttestation?.diversityLevel
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_MODEL_IDENTITY_UNPINNED");
  }
  if (
    canonicalizeProjectJson(receipt?.findings) !==
      canonicalizeProjectJson(modelOutput?.findings) ||
    receipt?.decision !== modelOutput?.decision ||
    receipt?.conclusion !== CONCLUSIONS[modelOutput?.decision]
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (
    !safePath(receipt?.runtimeAttestationPath) ||
    !safePath(receipt?.modelOutputPath)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_INVALID");
  }
  if (
    !validDate(receipt?.startedAt) ||
    !validDate(receipt?.finishedAt) ||
    !validDate(receipt?.reviewStartedAt) ||
    !validDate(receipt?.reviewFinishedAt) ||
    receipt?.startedAt !== receipt?.reviewStartedAt ||
    receipt?.finishedAt !== receipt?.reviewFinishedAt ||
    Date.parse(receipt.startedAt) > Date.parse(receipt.finishedAt)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_TIME_ORDER_INVALID");
  }
  return reasonCodes;
}

export async function validateIndependentModelReviewReceipt({
  policy,
  bundle,
  receipt,
  runtimeAttestation,
  rawModelOutput,
  isolationEvidenceResolver,
  receiptSchemaBytes,
  outputSchemaBytes,
}) {
  let modelOutput = null;
  try {
    modelOutput = parseIndependentModelReviewOutput(rawModelOutput);
  } catch {
    modelOutput = null;
  }
  const policyValidation = await validateIndependentReviewPolicy(policy);
  const bundleValidation = await validateIndependentReviewBundle(bundle, {
    policy,
  });
  const reasonCodes = [
    ...policyValidation.reasonCodes,
    ...bundleValidation.reasonCodes,
    ...receiptBindingReasonCodes({
      policy,
      bundle,
      receipt,
      runtimeAttestation,
      modelOutput,
    }),
  ];
  let schemaValidators = null;
  try {
    schemaValidators = await frozenSchemaValidators({
      bundle,
      receiptSchemaBytes,
      outputSchemaBytes,
    });
  } catch {
    schemaValidators = null;
  }
  if (
    schemaValidators?.receipt?.(receipt) !== true ||
    schemaValidators?.output?.(modelOutput) !== true
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_SCHEMA_INVALID");
  }
  if (
    !SHA256.test(receipt?.receiptSha256 ?? "") ||
    (SHA256.test(receipt?.receiptSha256 ?? "") &&
      (await receiptDigest(receipt)) !== receipt.receiptSha256)
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_HASH_MISMATCH");
  }
  if (
    receipt?.runtimeAttestationSha256 !==
      (await runtimeDigest(runtimeAttestation)) ||
    receipt?.modelOutputSha256 !== (await modelOutputDigest(rawModelOutput)) ||
    receipt?.modelOutputByteLength !== rawModelOutput.byteLength ||
    runtimeAttestation?.rawModelOutputSha256 !==
      (await modelOutputDigest(rawModelOutput)) ||
    runtimeAttestation?.rawModelOutputByteLength !== rawModelOutput.byteLength
  ) {
    reasonCodes.push("INDEPENDENT_REVIEW_STALE");
  }
  if (!outputIsClosed(modelOutput)) {
    reasonCodes.push("INDEPENDENT_REVIEW_RECEIPT_INVALID");
  }
  const independence = await validateIndependentModelIndependence({
    policy,
    bundle,
    runtimeAttestation,
    isolationEvidenceResolver,
  });
  reasonCodes.push(...independence.reasonCodes);
  const openBlockingFinding = modelOutput?.findings?.some(
    (finding) =>
      BLOCKING_SEVERITIES.has(finding.severity) && finding.status === "OPEN",
  );
  if (receipt?.decision === "CLEAR" && openBlockingFinding) {
    reasonCodes.push("INDEPENDENT_REVIEW_UNRESOLVED_BLOCKING_FINDING");
  }
  const uniqueReasonCodes = [...new Set(reasonCodes)];
  if (independence.status === "BLOCKED" || receipt?.decision === "BLOCKED") {
    return result(false, "BLOCKED", uniqueReasonCodes, {
      conclusion: "BLOCKED",
    });
  }
  if (openBlockingFinding) {
    return result(false, "BLOCKED", uniqueReasonCodes, {
      conclusion: "BLOCKED",
    });
  }
  if (
    independence.status === "INCONCLUSIVE" ||
    receipt?.decision === "INCONCLUSIVE"
  ) {
    return result(false, "INCONCLUSIVE", uniqueReasonCodes, {
      conclusion: "INCONCLUSIVE",
    });
  }
  if (uniqueReasonCodes.length > 0) {
    return result(false, "BLOCKED", uniqueReasonCodes, {
      conclusion: "BLOCKED",
    });
  }
  return result(true, "CLEAR", [], {
    conclusion: "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION",
  });
}

export function mapIndependentModelReviewCheckResult(validation) {
  if (
    !keysExactly(validation, [
      "ok",
      "status",
      "conclusion",
      "reasonCodes",
    ]) ||
    !["CLEAR", "BLOCKED", "INCONCLUSIVE"].includes(validation.status) ||
    !Array.isArray(validation.reasonCodes)
  ) {
    throw new TypeError(
      "Independent model review check requires a validated result.",
    );
  }
  const clear =
    validation.ok === true &&
    validation.status === "CLEAR" &&
    validation.conclusion === "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION";
  const title = clear
    ? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
    : validation.status;
  return {
    schemaVersion: "independent-model-review-check-result.v2",
    context: "independent-model-review",
    conclusion: clear ? "success" : "failure",
    title,
    exitCode: clear ? 0 : validation.status === "BLOCKED" ? 2 : 3,
    remotePublished: false,
    governanceEffect: "NONE",
    humanIndependentReviewSatisfied: false,
    assuranceLevel: "MODEL_ONLY_PREPRODUCTION",
    reasonCodes: structuredClone(validation.reasonCodes),
  };
}
