import { createHash } from "node:crypto";
import {
	validateIndependentReviewBundle,
	validateIndependentReviewPolicy,
	validateIndependentReviewSchemaInstance,
	validateIndependentModelReviewOutputArtifact,
	parseIndependentReviewJsonBytes,
} from "./independent-model-review.mjs";

const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[^\u0000-\u001f\\]+$/u;
const DECISIONS = new Set(["CLEAR", "BLOCKED", "INCONCLUSIVE"]);
const BLOCKING_SEVERITIES = new Set(["HIGH", "CRITICAL"]);
const DIAGNOSTIC_LIMITS = Object.freeze({
	jsonl: 2 * 1024 * 1024,
	stderr: 256 * 1024,
	outputLastMessage: 1024 * 1024,
});
const AUTHORIZATION_PROMPT = Object.freeze({
	path: "implementation/governance/independent-review/openai-terra-authorization-prompt.v1.txt",
	byteLength: 16491,
	sha256: "sha256:4765206b6e08214325f626822aeba9087e61d9f1dae97bcb0104b9177eb84693",
});
const CLI_IDENTITY = Object.freeze({
	path: "/Applications/ChatGPT.app/Contents/Resources/codex",
	version: "codex-cli 0.146.0-alpha.9.2",
	byteLength: 270605984,
	sha256: "sha256:68474c6192406b8a0278243c8283b87a84798a69fb498f30c3715861f8082542",
});
const SCHEMA_PATHS = Object.freeze({
	output: "implementation/governance/schemas/independent-model-review-output.v2.schema.json",
	reviewBundle: "implementation/governance/schemas/independent-review-bundle.v2.schema.json",
	subject: "implementation/governance/schemas/openai-terra-scoped-review-subject.v1.schema.json",
	runtimeEvidence: "implementation/governance/schemas/openai-terra-runtime-transport-evidence.v1.schema.json",
	diagnostic: "implementation/governance/schemas/openai-terra-cli-diagnostic.v1.schema.json",
	receipt: "implementation/governance/schemas/independent-model-review-receipt.v10.schema.json",
});
const RUNTIME_SOURCE_KEYS = Object.freeze([
	"coverageBase", "coreFreezeCommit", "sourceCommit", "sourceParent", "sourceTree",
	"fullPatchByteLength", "fullPatchSha256", "reviewPathSetSha256",
]);
const RUNTIME_BINDING_KEYS = Object.freeze([
	"reviewSubjectSha256", "reviewSubjectByteLength", "reviewBundleSha256", "reviewerPromptSha256",
	"authorizationPromptByteLength", "authorizationPromptSha256", "configSha256", "policySha256",
	"subjectSchemaSha256", "outputSchemaSha256", "evidenceSchemaSha256", "diagnosticSchemaSha256",
	"receiptSchemaSha256", "testEvidenceSetSha256",
]);
const SENSITIVE_PATTERNS = Object.freeze([
	/-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/u,
	/\b(?:X-API-Key|Api-Key|API-Key)\s*:\s*(?!(?:REDACTED|<redacted>|<token>)[ \t]*(?:\r?$))[^\r\n]+/imu,
	/\b(?:Cookie|Set-Cookie)\s*:(?![ \t]*(?:REDACTED|<redacted>)[ \t]*(?:\r?$))[ \t]*[^\r\n]+/imu,
	/\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b/u,
	/\b(?:sk_live_[A-Za-z0-9_-]{16,}|glpat-[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9_-]{16,}|ASIA[A-Z0-9]{16}|AGE-SECRET-KEY-1[A-Z0-9]{16,})\b/u,
	/\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
	/\bxox[baprs]-[A-Za-z0-9-]{16,}\b/u,
	/\bAKIA[A-Z0-9]{16}\b/u,
	/\bmachine\s+\S+\s+login\s+\S+\s+password\s+(?!(?:REDACTED|<redacted>|<token>)\b)\S+/iu,
	/^(?:[^:\r\n]+:){4}(?!(?:REDACTED|<redacted>|<token>)[ \t]*$)[^:\r\n]+$/mu,
	/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
	/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/iu,
]);
const SENSITIVE_KEY_SUFFIXES = Object.freeze([
	"apikey", "token", "secret", "secretaccesskey", "privatekey", "signingkey",
	"credential", "credentials", "password", "passphrase",
	"apikeys", "tokens", "secrets", "secretaccesskeys", "privatekeys", "signingkeys",
		"passwords", "passphrases", "auth", "authkey", "subscriptionkey",
		"accesskey", "accesskeyid", "accesskeyids", "accountkey", "sharedaccesskey",
		"sharedaccesssignature",
]);
const ALLOWED_SENSITIVE_PLACEHOLDERS = new Set(["redacted", "<redacted>", "<token>"]);
const SAFE_TYPE_WORDS = new Set(["string", "number", "boolean", "null", "undefined", "unknown", "never"]);
const SAFE_SCHEMA_KEYS = new Set(["type", "description", "title", "format", "pattern", "minLength", "maxLength"]);
const SAFE_SCHEMA_LIST_KEYS = new Set(["required", "enum", "type"]);
const SAFE_AUTHORIZATION_WORDS = new Set([
	...ALLOWED_SENSITIVE_PLACEHOLDERS, "token", "credential", "credentials",
	"authentication", "authorization",
]);
const ALLOWED_EVENT_TYPES = new Set([
	"thread.started",
	"turn.started",
	"item.started",
	"item.completed",
	"turn.completed",
]);
const ALLOWED_ITEM_TYPES = new Set(["agent_message", "reasoning"]);
const TOOL_EVENT_TYPES = new Set([
	"exec_command_begin",
	"exec_command_end",
	"patch_apply_begin",
	"patch_apply_updated",
	"patch_apply_end",
	"web_search_begin",
	"web_search_end",
	"mcp_tool_call_begin",
	"mcp_tool_call_end",
	"dynamic_tool_call_request",
	"dynamic_tool_call_response",
]);
const TOOL_ITEM_TYPES = new Set([
	"command_execution",
	"file_change",
	"web_search",
	"mcp_tool_call",
	"dynamic_tool_call",
	"tool_call",
]);
const REQUIRED_OS_PROBES = Object.freeze([
	"createFileDenied",
	"modifyFileDenied",
	"deleteFileDenied",
	"moveRenameDenied",
	"applyPatchDenied",
	"readOutsideBundleDenied",
	"gitCommitDenied",
	"gitTagDenied",
	"gitPushNotAttempted",
	"networkToolUnavailable",
	"d1SitesGovernanceWriteUnavailable",
	"credentialsUnavailableToReviewer",
]);
const SUBJECT_MAGIC = Buffer.from("OPENAI-TERRA-SCOPED-REVIEW/1\n", "ascii");

export const OPENAI_TERRA_MAX_MODEL_VISIBLE_BYTES = 768 * 1024;

export const OPENAI_TERRA_CORE_REVIEW_PATHS = Object.freeze([
	"docs/adr/0011-independent-model-review-policy-v2-candidate.md",
	"implementation/governance/independent-review/independent-model-review-prompt.v2.md",
	"implementation/governance/independent-review/independent-review-policy.v2.candidate.json",
	"implementation/governance/independent-review/independent-review-test-plan.v2.json",
	"implementation/governance/independent-review/macos-independent-review-readonly.sb.in",
	"implementation/governance/schemas/independent-model-review-output.v2.schema.json",
	"implementation/governance/schemas/independent-model-review-receipt.v2.schema.json",
	"implementation/governance/schemas/independent-model-runtime-evidence.v2.schema.json",
	"implementation/governance/schemas/independent-review-bundle.v2.schema.json",
	"implementation/governance/schemas/independent-review-policy.v2.schema.json",
	"implementation/governance/schemas/independent-review-test-result.v2.schema.json",
	"implementation/governance/schemas/independent-review-transport-evidence.v1.schema.json",
	"lib/independent-model-review.mjs",
	"lib/independent-review-runtime-evidence.mjs",
	"lib/independent-review-transport-evidence.mjs",
	"scripts/build-independent-review-bundle.mjs",
	"scripts/run-independent-review-control-plane.mjs",
	"scripts/run-independent-review-test-evidence.mjs",
	"tests/independent-model-review.test.mjs",
	"tests/independent-review-bundle-generator.test.mjs",
	"tests/independent-review-control-plane.test.mjs",
	"tests/independent-review-transport-evidence.test.mjs",
]);

export const OPENAI_TERRA_ADDITIONAL_REVIEW_PATHS = Object.freeze([
	"AGENTS.md",
	"CONTEXT.md",
	"docs/adr/0008-c13-protected-source-review.md",
	"docs/adr/0021-openai-terra-independent-review-pivot.md",
	"implementation/governance/independent-review/openai-codex-terra.v1.json",
	"implementation/governance/independent-review/openai-terra-authorization-prompt.v1.txt",
	"implementation/governance/independent-review/implementation-participant.v1.json",
	"implementation/governance/schemas/independent-model-review-receipt.v10.schema.json",
	"implementation/governance/schemas/openai-codex-terra-config.v1.schema.json",
	"implementation/governance/schemas/independent-review-test-result.v3.schema.json",
	"implementation/governance/schemas/openai-terra-cli-diagnostic.v1.schema.json",
	"implementation/governance/schemas/openai-terra-runtime-transport-evidence.v1.schema.json",
	"implementation/governance/schemas/openai-terra-scoped-review-subject.v1.schema.json",
	"lib/openai-terra-independent-review.mjs",
	"scripts/build-openai-terra-review-material.mjs",
	"scripts/run-openai-terra-independent-review.mjs",
	"implementation/governance/independent-review/macos-independent-review-test-execution.sb.in",
	"docs/agents/issue-tracker.md",
	"tests/openai-terra-independent-review.cases.mjs",
]);

function canonicalize(value) {
	if (value === null || typeof value === "boolean" || typeof value === "string") {
		return JSON.stringify(value);
	}
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new TypeError("Non-finite JSON number.");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
	if (value && typeof value === "object") {
		return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
	}
	throw new TypeError("Only JSON values can be canonicalized.");
}

function bytesDigest(bytes) {
	if (!(bytes instanceof Uint8Array)) throw new TypeError("Exact bytes are required.");
	return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function valueDigest(value) {
	return bytesDigest(Buffer.from(canonicalize(value), "utf8"));
}

function selfDigest(value, field) {
	const copy = structuredClone(value);
	delete copy[field];
	return valueDigest(copy);
}

export const openAiTerraDigests = Object.freeze({
	bytes: bytesDigest,
	value: valueDigest,
	self: selfDigest,
	canonicalize,
});

function readHexLength(bytes, offset, label) {
	const value = bytes.subarray(offset, offset + 12).toString("ascii");
	if (!/^[a-f0-9]{12}$/u.test(value)) {
		throw new TypeError(`${label} length is invalid.`);
	}
	return Number.parseInt(value, 16);
}

export function parseOpenAiTerraReviewSubjectEnvelope(bytes) {
	const exact = Buffer.from(bytes);
	if (exact.byteLength > OPENAI_TERRA_MAX_MODEL_VISIBLE_BYTES ||
			!exact.subarray(0, SUBJECT_MAGIC.byteLength).equals(SUBJECT_MAGIC)) {
		throw new TypeError("OpenAI Terra Review Subject envelope is invalid.");
	}
	let offset = SUBJECT_MAGIC.byteLength;
	const manifestLength = readHexLength(exact, offset, "Review Subject manifest");
	offset += 12;
	if (exact[offset] !== 0x0a) throw new TypeError("Review Subject manifest separator is invalid.");
	offset += 1;
	const manifestBytes = exact.subarray(offset, offset + manifestLength);
	offset += manifestLength;
	let manifest;
	try {
		manifest = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(manifestBytes));
	} catch {
		throw new TypeError("Review Subject manifest is not strict UTF-8 JSON.");
	}
	if (!manifestBytes.equals(Buffer.from(canonicalize(manifest), "utf8"))) {
		throw new TypeError("Review Subject manifest is not canonical.");
	}
	const readContent = (label) => {
		const contentLength = readHexLength(exact, offset, label);
		offset += 12;
		const content = exact.subarray(offset, offset + contentLength);
		offset += contentLength;
		if (content.byteLength !== contentLength) throw new TypeError(`${label} is truncated.`);
		new TextDecoder("utf-8", { fatal: true }).decode(content);
		return content;
	};
	const bundleBytes = readContent("Review Bundle content");
	let reviewBundle = null;
	try {
		const text = new TextDecoder("utf-8", { fatal: true }).decode(bundleBytes);
		reviewBundle = parseIndependentReviewJsonBytes(bundleBytes, "Provider-neutral Review Bundle");
		if (text !== canonicalize(reviewBundle)) reviewBundle = null;
	} catch {
		reviewBundle = null;
	}
	if (!reviewBundle || !Array.isArray(reviewBundle.sourceSubjects)) {
		throw new TypeError("Review Subject Review Bundle is invalid.");
	}
	const sections = [{ descriptor: manifest.reviewBundle, bytes: bundleBytes }];
	for (const source of reviewBundle.sourceSubjects) {
		const content = readContent(`Review Subject ${source.path}`);
		const descriptor = {
			kind: source.path === manifest.authorizationPrompt?.path ? "USER_AUTHORIZATION_PROMPT" : "GIT_BLOB",
			path: source.path,
			gitMode: source.gitMode,
			byteLength: content.byteLength,
			sha256: source.blobSha256,
		};
		if (descriptor.sha256 !== bytesDigest(content)) throw new TypeError("Review Subject section bytes are stale.");
		sections.push({ descriptor, bytes: content });
	}
	if (offset !== exact.byteLength || manifest.reviewBundle?.byteLength !== bundleBytes.byteLength ||
			manifest.reviewBundle?.sha256 !== bytesDigest(bundleBytes)) {
		throw new TypeError("Review Subject section framing is stale.");
	}
	const gitSections = sections.filter(({ descriptor }) => descriptor.kind === "GIT_BLOB");
	const promptSections = sections.filter(({ descriptor }) => descriptor.kind === "USER_AUTHORIZATION_PROMPT");
	const bundleSections = sections.filter(({ descriptor }) => descriptor.kind === "PROVIDER_NEUTRAL_REVIEW_BUNDLE");
	const sourceSubjects = reviewBundle.sourceSubjects;
	if (manifest?.schemaVersion !== "openai-terra-scoped-review-subject.v1" ||
			manifest?.format !== "LENGTH_PREFIXED_UTF8_SECTIONS_V1" ||
			manifest?.claimBoundary !== "CORE_SUBJECT_ONLY_NOT_FULL_REPOSITORY_CLEARANCE" ||
			manifest?.duplicatePathPolicy !== "EACH_REVIEWED_GIT_PATH_EXACTLY_ONCE" ||
			manifest?.recursiveK3EvidencePolicy !== "REFERENCE_ONLY_NO_MODEL_VISIBLE_BYTES" ||
			!reviewBundle || !Array.isArray(reviewBundle.reviewedPaths) || reviewBundle.reviewedPaths.length === 0 ||
			gitSections.length + promptSections.length !== reviewBundle.reviewedPaths.length || promptSections.length !== 1 ||
			bundleSections.length !== 1 || sections.length !== reviewBundle.reviewedPaths.length + 1 ||
			new Set(sections.map(({ descriptor }) => descriptor.path)).size !== sections.length ||
			canonicalize(sourceSubjects) !== canonicalize(reviewBundle.sourceSubjects) ||
			valueDigest(reviewBundle.reviewedPaths) !== reviewBundle.source.changedPathsDigest ||
			canonicalize(promptSections[0].descriptor) !== canonicalize(manifest.authorizationPrompt) ||
			canonicalize(bundleSections[0].descriptor) !== canonicalize(manifest.reviewBundle) ||
			!Array.isArray(manifest.historyReferences) ||
			manifest.historyReferences.some((entry) => entry.modelVisibleBytes !== false) ||
			valueDigest(manifest.historyReferences) !== manifest.historyReferenceSetSha256) {
		throw new TypeError("Review Subject coverage closure is invalid.");
	}
	return {
		manifest,
		sections,
		reviewBundle,
		subjectSha256: bytesDigest(exact),
		subjectByteLength: exact.byteLength,
	};
}

function exactKeys(value, keys) {
	return value && typeof value === "object" && !Array.isArray(value) &&
		canonicalize(Object.keys(value).sort()) === canonicalize([...keys].sort());
}

function result(ok, reasonCodes, extra = {}) {
	return { ok, reasonCodes: [...new Set(reasonCodes)].sort(), ...extra };
}

function validArtifact(value, bytes) {
	return exactKeys(value, ["path", "byteLength", "sha256"]) &&
		typeof value.path === "string" && SAFE_PATH.test(value.path) &&
		Number.isInteger(value.byteLength) && value.byteLength >= 0 &&
		value.byteLength === bytes.byteLength && value.sha256 === bytesDigest(bytes);
}

function configReasons(config) {
	const reasons = [];
	if (!exactKeys(config, ["schemaVersion", "configId", "lifecycle", "implementation", "reviewer", "coverage", "cli", "invocation", "reviewerPrompt", "schemas", "authorizationPrompt", "configSha256"]) ||
			config.schemaVersion !== "openai-codex-terra-config.v1" || config.lifecycle !== "CANDIDATE" ||
			!/^octc_[a-z0-9_-]{8,127}$/u.test(config.configId ?? "")) reasons.push("OPENAI_TERRA_CONFIG_INVALID");
	if (!exactKeys(config?.implementation, ["provider", "model"]) || config?.implementation?.provider !== "openai" || config?.implementation?.model !== "gpt-5.6-sol") reasons.push("OPENAI_TERRA_IMPLEMENTATION_IDENTITY_INVALID");
	if (!exactKeys(config?.reviewer, ["provider", "requestedModel", "reasoningEffort", "maximumFormalAttempts", "fallbackPolicy"]) ||
			config?.reviewer?.provider !== "openai" || config?.reviewer?.requestedModel !== "gpt-5.6-terra" ||
			config?.reviewer?.reasoningEffort !== "high" || config?.reviewer?.maximumFormalAttempts !== 1 ||
			config?.reviewer?.fallbackPolicy !== "DISABLED_FAIL_CLOSED" ||
			config?.reviewer?.requestedModel === config?.implementation?.model) reasons.push("OPENAI_TERRA_REVIEWER_CONTRACT_INVALID");
	if (!exactKeys(config?.coverage, ["baseCommit", "coreFreezeCommit", "claimBoundary", "maximumModelVisibleUtf8Bytes", "recursiveK3EvidencePolicy"]) ||
			config?.coverage?.baseCommit !== "340b8900dda62fa57ee185b9a43cfe472e7eaed7" ||
			config?.coverage?.coreFreezeCommit !== "ab95c7aff586279062c7698749fdbc0e38e955d1" ||
			config?.coverage?.claimBoundary !== "CORE_SUBJECT_ONLY_NOT_FULL_REPOSITORY_CLEARANCE" ||
			config?.coverage?.maximumModelVisibleUtf8Bytes !== OPENAI_TERRA_MAX_MODEL_VISIBLE_BYTES ||
			config?.coverage?.recursiveK3EvidencePolicy !== "REFERENCE_ONLY_NO_MODEL_VISIBLE_BYTES") reasons.push("OPENAI_TERRA_SCOPE_CONTRACT_INVALID");
	if (canonicalize(config?.cli) !== canonicalize(CLI_IDENTITY)) reasons.push("OPENAI_TERRA_CLI_IDENTITY_INVALID");
	if (!exactKeys(config?.invocation, ["ephemeral", "ignoreUserConfig", "ignoreRules", "skipGitRepoCheck", "json", "outputLastMessage", "allowedIsolationModes"]) ||
			["ephemeral", "ignoreUserConfig", "ignoreRules", "skipGitRepoCheck", "json", "outputLastMessage"].some((key) => config?.invocation?.[key] !== true) ||
			canonicalize(config?.invocation?.allowedIsolationModes) !== canonicalize(["API_NO_TOOLS", "OS_ENFORCED_TARGET_READ_ONLY"])) reasons.push("OPENAI_TERRA_INVOCATION_CONTRACT_INVALID");
	if (!exactKeys(config?.reviewerPrompt, ["path"]) ||
			config?.reviewerPrompt?.path !== "implementation/governance/independent-review/independent-model-review-prompt.v2.md" ||
			canonicalize(config?.schemas) !== canonicalize(SCHEMA_PATHS)) reasons.push("OPENAI_TERRA_SCHEMA_BINDING_INVALID");
	if (!exactKeys(config?.authorizationPrompt, ["path", "byteLength", "sha256"]) ||
			config?.authorizationPrompt?.path !== AUTHORIZATION_PROMPT.path ||
			config?.authorizationPrompt?.byteLength !== AUTHORIZATION_PROMPT.byteLength ||
			config?.authorizationPrompt?.sha256 !== AUTHORIZATION_PROMPT.sha256) reasons.push("OPENAI_TERRA_AUTHORIZATION_PROMPT_INVALID");
	if (!SHA256.test(config?.configSha256 ?? "") || selfDigest(config, "configSha256") !== config?.configSha256) reasons.push("OPENAI_TERRA_CONFIG_HASH_MISMATCH");
	return [...new Set(reasons)].sort();
}

export function validateOpenAiTerraConfig(config) {
	const reasonCodes = configReasons(config);
	return result(reasonCodes.length === 0, reasonCodes);
}

export function parseOpenAiTerraFrozenJsonSection(section, label) {
	if (!section) throw new TypeError(`${label} is missing from the Review Subject.`);
	const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(section.bytes);
	const value = JSON.parse(text);
	const canonical = canonicalize(value);
	if (text !== canonical && text !== `${canonical}\n` && text !== `${JSON.stringify(value, null, 2)}\n`) {
		throw new TypeError(`${label} bytes are not an accepted frozen JSON representation.`);
	}
	return value;
}

function pathShas(parsed) {
	return new Map(parsed.sections.map(({ descriptor }) => [descriptor.path, descriptor.sha256]));
}

export async function validateOpenAiTerraReviewSubject({
	subjectBytes,
	subjectSchemaBytes,
	expectedSubjectSchemaSha256,
}) {
	const reasons = [];
	let parsed = null;
	try {
		parsed = parseOpenAiTerraReviewSubjectEnvelope(subjectBytes);
	} catch {
		return result(false, ["OPENAI_TERRA_REVIEW_SUBJECT_INVALID"]);
	}
	const subjectSchemaValidation = await validateIndependentReviewSchemaInstance({
		schemaBytes: subjectSchemaBytes,
		expectedSchemaSha256: expectedSubjectSchemaSha256,
		instance: parsed.manifest,
		label: "OpenAI Terra Scoped Review Subject Schema",
	});
	if (!subjectSchemaValidation.ok) reasons.push("OPENAI_TERRA_REVIEW_SUBJECT_SCHEMA_INVALID");
	const expectedPaths = [...new Set([
		...OPENAI_TERRA_CORE_REVIEW_PATHS,
		...OPENAI_TERRA_ADDITIONAL_REVIEW_PATHS,
	])].sort();
	if (canonicalize(parsed.reviewBundle?.reviewedPaths) !== canonicalize(expectedPaths)) {
		reasons.push("OPENAI_TERRA_REVIEW_SCOPE_OR_CONTEXT_NOT_PROVED");
	}
	const sections = new Map(parsed.sections.map((entry) => [entry.descriptor.path, entry]));
	const descriptorShas = pathShas(parsed);
	let config = null;
	let policy = null;
	let reviewBundle = parsed.reviewBundle;
	try {
		config = parseOpenAiTerraFrozenJsonSection(
			sections.get("implementation/governance/independent-review/openai-codex-terra.v1.json"),
			"OpenAI Terra Config",
		);
		policy = parseOpenAiTerraFrozenJsonSection(
			sections.get("implementation/governance/independent-review/independent-review-policy.v2.candidate.json"),
			"Independent Review Policy",
		);
	} catch {
		reasons.push("OPENAI_TERRA_TRUSTED_SUBJECT_ARTIFACT_INVALID");
	}
	if (!config || !validateOpenAiTerraConfig(config).ok) {
		reasons.push("OPENAI_TERRA_CONFIG_INVALID");
	}
	const policyValidation = policy
		? await validateIndependentReviewPolicy(policy)
		: { ok: false };
	if (!policyValidation.ok) reasons.push("OPENAI_TERRA_POLICY_INVALID");
	const bundleValidation = reviewBundle && policy
		? await validateIndependentReviewBundle(reviewBundle, { policy })
		: { ok: false };
	if (!bundleValidation.ok) reasons.push("OPENAI_TERRA_REVIEW_BUNDLE_INVALID");
	if (reviewBundle && canonicalize(reviewBundle) !==
			new TextDecoder("utf-8", { fatal: true }).decode(sections.get("bundle/review-bundle.v2.json")?.bytes ?? [])) {
		reasons.push("OPENAI_TERRA_REVIEW_BUNDLE_BYTES_NONCANONICAL");
	}
	if (config) {
		for (const path of Object.values(config.schemas)) {
			if (!sections.has(path)) reasons.push("OPENAI_TERRA_SCHEMA_BINDING_INVALID");
		}
		if (descriptorShas.get(config.schemas.subject) !== expectedSubjectSchemaSha256 ||
				bytesDigest(subjectSchemaBytes) !== expectedSubjectSchemaSha256 ||
				parsed.manifest.authorizationPrompt.path !== config.authorizationPrompt.path ||
				parsed.manifest.authorizationPrompt.byteLength !== config.authorizationPrompt.byteLength ||
				parsed.manifest.authorizationPrompt.sha256 !== config.authorizationPrompt.sha256) {
			reasons.push("OPENAI_TERRA_ARTIFACT_BINDING_MISMATCH");
		}
	}
	if (reviewBundle && policy) {
		const source = parsed.manifest.source;
		if (reviewBundle.policy.path !== "implementation/governance/independent-review/independent-review-policy.v2.candidate.json" ||
				reviewBundle.policy.sha256 !== policy.policySha256 ||
				reviewBundle.source.baseCommit !== source.coverageBase ||
				reviewBundle.source.sourceCommit !== source.sourceCommit ||
				reviewBundle.source.headCommit !== source.sourceCommit ||
				reviewBundle.source.tree !== source.sourceTree ||
				reviewBundle.source.diffSha256 !== source.fullPatchSha256 ||
				reviewBundle.source.changedPathsDigest !== valueDigest(reviewBundle.reviewedPaths) ||
				parsed.manifest.reviewBundle.bundleId !== reviewBundle.bundleId ||
				parsed.manifest.reviewBundle.bundleSha256 !== reviewBundle.bundleSha256) {
			reasons.push("OPENAI_TERRA_REVIEW_BUNDLE_BINDING_MISMATCH");
		}
		const modelVisibleSourceSubjects = parsed.sections
			.filter(({ descriptor }) => descriptor.kind === "GIT_BLOB" || descriptor.kind === "USER_AUTHORIZATION_PROMPT")
			.map(({ descriptor }) => ({
				path: descriptor.path,
				gitMode: descriptor.gitMode,
				blobSha256: descriptor.sha256,
			}))
			.sort(({ path: left }, { path: right }) => left.localeCompare(right));
		if (canonicalize(modelVisibleSourceSubjects) !== canonicalize(reviewBundle.sourceSubjects) ||
				canonicalize(reviewBundle.reviewedPaths) !== canonicalize(expectedPaths)) {
			reasons.push("OPENAI_TERRA_REVIEW_BUNDLE_SCOPE_MISMATCH");
		}
		for (const specification of reviewBundle.specificationSubjects ?? []) {
			if (descriptorShas.get(specification.path) !== specification.blobSha256) {
				reasons.push("OPENAI_TERRA_REVIEW_BUNDLE_SPECIFICATION_MISMATCH");
			}
		}
		for (const [key, path] of Object.entries(reviewBundle.artifacts ?? {}).filter(([key]) => key.endsWith("Path"))) {
			const digestKey = `${key.slice(0, -4)}Sha256`;
			if (descriptorShas.get(path) !== reviewBundle.artifacts[digestKey]) {
				reasons.push("OPENAI_TERRA_REVIEW_BUNDLE_ARTIFACT_MISMATCH");
			}
		}
		const participantPath = "implementation/governance/independent-review/implementation-participant.v1.json";
		if (descriptorShas.get(participantPath) !== reviewBundle.implementationIdentity.participantManifestSha256) {
			reasons.push("OPENAI_TERRA_IMPLEMENTATION_IDENTITY_NOT_PROVED");
		}
	}
	return result(reasons.length === 0, reasons, {
		parsed,
		config,
		policy,
		reviewBundle,
	});
}

export function buildOpenAiTerraCliArguments({ config, outputSchemaPath, outputLastMessagePath }) {
	const validation = validateOpenAiTerraConfig(config);
	if (!validation.ok || typeof outputSchemaPath !== "string" || typeof outputLastMessagePath !== "string") {
		throw new TypeError("OpenAI Terra CLI invocation is not frozen.");
	}
	return [
		"exec", "--model", "gpt-5.6-terra", "--ephemeral", "--ignore-user-config",
		"--ignore-rules", "--skip-git-repo-check", "--sandbox", "read-only",
		"--ask-for-approval", "never", "--config", 'model_reasoning_effort="high"',
		"--output-schema", outputSchemaPath, "--json", "--output-last-message",
		outputLastMessagePath, "-",
	];
}

function safeText(bytes) {
	try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
	catch { return null; }
}

function isSensitiveKey(key) {
	const normalizedKey = key.replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
	return SENSITIVE_KEY_SUFFIXES.some((suffix) => normalizedKey.endsWith(suffix));
}

function sensitivePair(key, assigned) {
	const keyNorm = String(key).replace(/[^A-Za-z0-9]/gu, "").toLowerCase();
	const valueNorm = String(assigned).trim().toLowerCase();
	const authorization = keyNorm.endsWith("authorization");
	return (authorization || isSensitiveKey(key)) && valueNorm !== "" &&
		!(authorization && safeAuthorization(valueNorm)) &&
		!ALLOWED_SENSITIVE_PLACEHOLDERS.has(valueNorm);
}

function safeSource(value) {
	return /^process\.env(?:\.[A-Z][A-Z0-9_]{0,127}|\[["'][A-Z][A-Z0-9_]{0,127}["']\])$/u
		.test(String(value).trim());
}

function safeSchema(value) {
	const keys = Object.keys(value);
	const types = Array.isArray(value.type) ? value.type : [value.type];
	const allowedTypes = new Set(["array", "boolean", "integer", "null", "number", "object", "string"]);
	return keys.length > 0 && keys.every((key) => SAFE_SCHEMA_KEYS.has(key)) &&
		types.length > 0 && types.every((type) => allowedTypes.has(type));
}

function scanJson(value) {
	let parsed;
	try { parsed = JSON.parse(value); } catch { return null; }
	try {
		parsed = parseIndependentReviewJsonBytes(
			Buffer.from(value, "utf8"), "OpenAI Terra diagnostic JSON", DIAGNOSTIC_LIMITS.jsonl,
		);
	} catch { return true; }
	let visited = 0;
	const walk = (entry, depth, parentKey = null) => {
		visited += 1;
		if (visited > 4096 || depth > 32) return true;
		if (Array.isArray(entry)) {
			for (let index = 0; !SAFE_SCHEMA_LIST_KEYS.has(parentKey) && index + 1 < entry.length; index += 1) {
				if (typeof entry[index] === "string" && entry[index + 1] !== null &&
						sensitivePair(entry[index], entry[index + 1])) return true;
			}
			return entry.some((item) => walk(item, depth + 1, parentKey));
		}
		if (typeof entry === "string") return sensitiveText(entry);
		if (!entry || typeof entry !== "object") return false;
		if (Object.hasOwn(entry, "value") && entry.value !== null &&
				[entry.name, entry.key].some((key) => typeof key === "string" &&
					!safeSource(entry.value) && sensitivePair(key, entry.value))) return true;
		return Object.entries(entry).some(([key, item]) => {
			if (item === null) return false;
			if (typeof item !== "object") {
				return (!safeSource(item) && sensitivePair(key, item)) ||
					(typeof item === "string" && walk(item, depth + 1, key));
			}
			if (isSensitiveKey(key) && Object.keys(item).length > 0 &&
					!safeSchema(item)) return true;
			return walk(item, depth + 1, key);
		});
	};
	return walk(parsed, 0);
}

function sensitiveQuery(value) {
	for (const match of value.matchAll(/[?&#]([^=&#\s]{1,256})=([^&#\s]{0,2048})/gu)) {
		let key;
		let assigned;
		try {
			key = decodeURIComponent(match[1]);
			assigned = decodeURIComponent(match[2]);
		} catch {
			return true;
		}
		if (sensitivePair(key, assigned)) return true;
	}
	return false;
}

function sensitiveAssignment(value) {
	for (const match of value.matchAll(
		/(?:^|[(/?&,;:{\s])["']?([A-Za-z_][A-Za-z0-9_.\[\]-]{0,127})["']?\s*(?:=|:)\s*("""|''')/gmu,
	)) {
		const start = (match.index ?? 0) + match[0].length;
		const end = value.indexOf(match[2], start);
		if (end < 0 || sensitivePair(match[1], value.slice(start, end))) return true;
	}
	const assignments = value.matchAll(
		/(?:^|[(/?&,;:{\s])["']?([A-Za-z_][A-Za-z0-9_.\[\]-]{0,127}(?:[ \t]+[A-Za-z][A-Za-z0-9_.\[\]-]{0,63}){0,3})["']?\s*(?:=|:)\s*(?:"""([^"\r]{0,2048})"""|'''([^'\r]{0,2048})'''|"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s,;&}\r\n]+))/gmu,
	);
	for (const match of assignments) {
		const assigned = match.slice(2).find((entry) => entry !== undefined) ?? "";
		const matchIndex = match.index ?? 0;
		const line = value.slice(matchIndex).split(/\r?\n/u, 1)[0].trim();
		if (match[1].replace(/[^A-Za-z0-9]/gu, "").toLowerCase().endsWith("authorization")) {
			if (/^[^=]{0,128}:\s*/u.test(line) || safeAuthorization(assigned)) continue;
			return true;
		}
		if (isSensitiveKey(match[1]) && /:\s*must\s+(?:never\s+be\s+logged|not\s+be\s+(?:logged|stored)|(?:come|be\s+read)\s+from\s+process\.env(?:\.[A-Z][A-Z0-9_]{0,127}|\[["'][A-Z][A-Z0-9_]{0,127}["']\]))\.?$/iu.test(line)) continue;
		const contextPrefix = value.slice(Math.max(0, matchIndex - 512), matchIndex);
		if (SAFE_TYPE_WORDS.has(assigned.trim().toLowerCase()) &&
				/\b(?:type|interface)\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s*=)?[^{}]{0,256}\{[^}]*$/u
					.test(contextPrefix)) continue;
		if (safeSource(assigned)) continue;
		if (sensitivePair(match[1], assigned)) return true;
	}
	return false;
}

function sensitiveStructure(value) {
	for (const pattern of [
		/<([A-Za-z_][A-Za-z0-9_.-]{0,127})>([^<]{1,2048})<\/\1>/gu,
		/\[\s*["']([^"']+)["']\s*\]\s*=\s*["']([^"']*)["']/gu,
		/\[\s*`([^`]+)`\s*\]\s*=\s*`([^`]*)`/gu,
		/\[\s*["']([^"']+)["']\s*\]\s*:\s*["']([^"']*)["']/gu,
		/\[\s*\[\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']\s*\]\s*\]/gu,
		/\.set\(\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']\s*\)/gu,
		/\b(?:new\s+)?Headers\s*\(\s*\[\s*\[\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']/gu,
		/\b(?:os\.Setenv|System\.setProperty|[A-Za-z_$][A-Za-z0-9_$]*\.(?:put|Add|Set|setHeader|append|insert))\(\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']\s*\)/gu,
	]) for (const match of value.matchAll(pattern)) {
		if (sensitivePair(match[1], match[2])) return true;
	}
	return false;
}

function sensitiveCli(value) {
	for (const match of value.matchAll(
		/(?:^|\s)--([A-Za-z][A-Za-z0-9_.-]{0,127})(?:=|\s+)(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s\r\n]+))/gmu,
	)) {
		if (sensitivePair(match[1], match[2] ?? match[3] ?? match[4] ?? "")) return true;
	}
	return false;
}

function sensitiveAuthorization(value) {
	for (const match of value.matchAll(/\b(?:Proxy-)?Authorization\s*:\s*([^\r\n]+)/gimu)) {
		if (!safeAuthorization(match[1])) return true;
	}
	for (const match of value.matchAll(
		/\b(?:Bearer|Basic)\s+(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s,;\r\n]+))/gimu,
	)) {
		const assigned = (match[1] ?? match[2] ?? match[3] ?? "").trim().toLowerCase();
		if (assigned !== "" && !SAFE_AUTHORIZATION_WORDS.has(assigned)) return true;
	}
	return false;
}

function safeAuthorization(value) {
	const parts = String(value).trim().toLowerCase().split(/\s+/u);
	return (parts.length === 1 && SAFE_AUTHORIZATION_WORDS.has(parts[0])) ||
		(parts.length === 2 && /^(?:apikey|basic|bearer|digest)$/u.test(parts[0]) &&
			SAFE_AUTHORIZATION_WORDS.has(parts[1]));
}

function sensitiveUri(value) {
	for (const match of value.matchAll(/\b[a-z][a-z0-9+.-]*:\/\/[^:\s/@]+:([^@\s/]+)@/giu)) {
		let assigned;
		try { assigned = decodeURIComponent(match[1]).trim().toLowerCase(); }
		catch { return true; }
		if (assigned !== "" && !ALLOWED_SENSITIVE_PLACEHOLDERS.has(assigned)) return true;
	}
	return false;
}

function sensitiveText(value) {
	return sensitiveQuery(value) || sensitiveCli(value) ||
		sensitiveAuthorization(value) || sensitiveUri(value) ||
		sensitiveAssignment(value) || sensitiveStructure(value) ||
		SENSITIVE_PATTERNS.some((pattern) => pattern.test(value));
}

function scanSensitive(bytes) {
	const value = safeText(bytes);
	if (value === null) return null;
	const unicodeDecoded = value.replace(/\\u([a-f0-9]{4})/giu, (_match, hex) =>
		String.fromCharCode(Number.parseInt(hex, 16)));
	const variants = [value, unicodeDecoded];
	let percentDecoded = unicodeDecoded;
	for (let round = 0; round < 4; round += 1) {
		try {
			const next = decodeURIComponent(percentDecoded);
			if (next === percentDecoded) break;
			variants.push(next);
			percentDecoded = next;
		} catch { break; }
	}
	const incompletePercent = /%[a-f0-9]{2}/iu.test(percentDecoded);
	for (const variant of [...variants]) {
		const noFormat = variant.replace(/\p{Cf}/gu, "");
		if (noFormat !== variant) variants.push(noFormat);
	}
	return incompletePercent || variants.some((variant) => {
		const jsonScan = scanJson(variant);
		return jsonScan === true || (jsonScan === null && sensitiveText(variant));
	});
}

function diagArtifact(path, bytes, limit, supplied) {
	if (!supplied) {
		return { retention: "UNAVAILABLE", path: null, byteLength: null, sha256: null };
	}
	if (bytes.byteLength > limit) {
		return { retention: "WITHHELD_OVERSIZE", path: null, byteLength: null, sha256: null };
	}
	const sensitive = scanSensitive(bytes);
	if (sensitive === null) {
		return { retention: "WITHHELD_UNSCANNABLE", path: null, byteLength: null, sha256: null };
	}
	if (sensitive) {
		return { retention: "WITHHELD_SENSITIVE", path: null, byteLength: null, sha256: null };
	}
	return {
		retention: "RETAINED_SAFE_BOUNDED",
		path,
		byteLength: bytes.byteLength,
		sha256: bytesDigest(bytes),
	};
}

function onlyKeys(value, required, optional = []) {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const keys = Object.keys(value);
	return required.every((key) => keys.includes(key)) && keys.every((key) => required.includes(key) || optional.includes(key));
}

function boundedString(value, maximum = 2 * 1024 * 1024) {
	return typeof value === "string" && Buffer.byteLength(value, "utf8") <= maximum;
}

function safeTokenCount(value) {
	return Number.isSafeInteger(value) && value >= 0;
}

function closedSummary(value) {
	return boundedString(value) ||
		(Array.isArray(value) && value.length <= 256 && value.every((entry) => boundedString(entry)));
}

function closedCliEvent(event) {
	if (event.type === "thread.started") {
		return onlyKeys(event, ["type", "thread_id", "model"]) &&
			boundedString(event.thread_id, 128) && boundedString(event.model, 128);
	}
	if (event.type === "turn.started") {
		return onlyKeys(event, ["type", "model"]) && boundedString(event.model, 128);
	}
	if (event.type === "turn.completed") {
		return onlyKeys(event, ["type", "model"], ["usage"]) && boundedString(event.model, 128) &&
			(event.usage === undefined || (onlyKeys(event.usage, [], ["input_tokens", "cached_input_tokens", "output_tokens"]) &&
				Object.values(event.usage).every(safeTokenCount)));
	}
	if (event.type === "item.started" || event.type === "item.completed") {
		if (!onlyKeys(event, ["type", "item"]) || !ALLOWED_ITEM_TYPES.has(event.item?.type)) return false;
		if (event.item.type === "agent_message") {
			return onlyKeys(event.item, ["type", "text"], ["model"]) && boundedString(event.item.text) &&
				(event.item.model === undefined || boundedString(event.item.model, 128));
		}
		return onlyKeys(event.item, ["type"], ["text", "summary", "model"]) &&
			(event.item.text === undefined || boundedString(event.item.text)) &&
			(event.item.summary === undefined || closedSummary(event.item.summary)) &&
			(event.item.model === undefined || boundedString(event.item.model, 128));
	}
	return false;
}

function classifyEvents(events) {
	let toolCallEventCount = 0;
	let eventContractRecognized = true;
	for (const event of events) {
		if (TOOL_EVENT_TYPES.has(event?.type)) {
			toolCallEventCount += 1;
			continue;
		}
		if (!ALLOWED_EVENT_TYPES.has(event?.type)) {
			eventContractRecognized = false;
			continue;
		}
		if (!closedCliEvent(event)) eventContractRecognized = false;
		if (event.type === "item.started" || event.type === "item.completed") {
			if (TOOL_ITEM_TYPES.has(event?.item?.type)) {
				toolCallEventCount += 1;
			} else if (!ALLOWED_ITEM_TYPES.has(event?.item?.type)) {
				eventContractRecognized = false;
			}
		}
	}
	const lifecycle = events.filter((event) => ALLOWED_EVENT_TYPES.has(event?.type));
	const threadIndexes = lifecycle.flatMap((event, index) => event.type === "thread.started" ? [index] : []);
	const turnIndexes = lifecycle.flatMap((event, index) => event.type === "turn.started" ? [index] : []);
	const completedIndexes = lifecycle.flatMap((event, index) => event.type === "turn.completed" ? [index] : []);
	const lifecycleComplete = threadIndexes.length === 1 && threadIndexes[0] === 0 &&
		turnIndexes.length <= 1 && (turnIndexes.length === 0 || turnIndexes[0] === 1) &&
		completedIndexes.length === 1 && completedIndexes[0] === lifecycle.length - 1 &&
		lifecycle.slice(1, -1).every((event) => event.type !== "thread.started" && event.type !== "turn.completed");
	return { toolCallEventCount, eventContractRecognized, lifecycleComplete };
}

export async function analyzeOpenAiTerraCliResult(input) {
	const jsonlSupplied = input.jsonlBytes instanceof Uint8Array;
	const stderrSupplied = input.stderrBytes instanceof Uint8Array;
	const lastSupplied = input.outputLastMessageBytes instanceof Uint8Array;
	const jsonlBytes = Buffer.from(input.jsonlBytes ?? []);
	const stderrBytes = Buffer.from(input.stderrBytes ?? []);
	const lastBytes = Buffer.from(input.outputLastMessageBytes ?? []);
	const reasons = [];
	const signal = input.signal === null || input.signal === undefined
		? null
		: /^SIG[A-Z0-9]+$/u.test(input.signal) ? input.signal : null;
	if (input.signal !== null && input.signal !== undefined && signal === null) {
		reasons.push("OPENAI_TERRA_CLI_SIGNAL_INVALID");
	}
	const sizeLimitExceeded = jsonlBytes.byteLength > DIAGNOSTIC_LIMITS.jsonl ||
		stderrBytes.byteLength > DIAGNOSTIC_LIMITS.stderr ||
		lastBytes.byteLength > DIAGNOSTIC_LIMITS.outputLastMessage;
	const scans = [jsonlBytes, stderrBytes, lastBytes].map(scanSensitive);
	const utf8Scannable = scans.every((value) => value !== null);
	const sensitiveDetected = scans.some((value) => value === true);
	const sensitiveMaterialAbsent = utf8Scannable && !sensitiveDetected;
	if (sizeLimitExceeded) reasons.push("OPENAI_TERRA_DIAGNOSTIC_SIZE_LIMIT_EXCEEDED");
	if (sensitiveDetected) reasons.push("OPENAI_TERRA_SENSITIVE_MATERIAL_DETECTED");
	if (!utf8Scannable) reasons.push("OPENAI_TERRA_ARTIFACT_UTF8_INVALID");
	if (input.timedOut === true) reasons.push("OPENAI_TERRA_TIMEOUT");
	if (input.exitCode !== 0) {
		const stderr = safeText(stderrBytes) ?? "";
		if (/quota/iu.test(stderr)) reasons.push("OPENAI_TERRA_QUOTA_UNAVAILABLE");
		else if (/service unavailable|temporarily unavailable|503/iu.test(stderr)) reasons.push("OPENAI_TERRA_SERVICE_UNAVAILABLE");
		else reasons.push("OPENAI_TERRA_CLI_NONZERO_EXIT");
	}
	const jsonl = safeText(jsonlBytes);
	const events = [];
	let jsonlParsed = false;
	if (!jsonl || jsonlBytes.byteLength === 0) reasons.push("OPENAI_TERRA_JSONL_INCOMPLETE");
	else {
		try {
			for (const line of jsonl.trimEnd().split("\n")) {
				events.push(parseIndependentReviewJsonBytes(Buffer.from(line, "utf8"), "OpenAI Terra JSONL event", DIAGNOSTIC_LIMITS.jsonl));
			}
			jsonlParsed = true;
		} catch { reasons.push("OPENAI_TERRA_JSONL_INVALID"); }
	}
	const { toolCallEventCount, eventContractRecognized, lifecycleComplete } = classifyEvents(events);
	if (!lifecycleComplete) reasons.push("OPENAI_TERRA_JSONL_INCOMPLETE");
	if (toolCallEventCount > 0) reasons.push("OPENAI_TERRA_TOOL_EVENT_FORBIDDEN");
	if (!eventContractRecognized) reasons.push("OPENAI_TERRA_EVENT_CONTRACT_UNRECOGNIZED");
	const sessionIds = [...new Set(events.filter((event) => event?.type === "thread.started").map((event) => event.thread_id).filter(Boolean))];
	if (sessionIds.length !== 1) reasons.push("OPENAI_TERRA_SESSION_ID_NOT_PROVED");
	const models = [...new Set(events.flatMap((event) => [event?.model, event?.item?.model]).filter(Boolean))];
	if (models.length !== 1 || models[0] !== input.requestedModel) reasons.push("OPENAI_TERRA_ACTUAL_MODEL_NOT_PROVED");
	const messages = events.filter((event) => event?.type === "item.completed" && event?.item?.type === "agent_message").map((event) => event.item.text);
	const lastText = safeText(lastBytes);
	const finalMessageMatched = messages.length === 1 && lastText !== null && messages[0] === lastText;
	if (!finalMessageMatched) reasons.push("OPENAI_TERRA_FINAL_MESSAGE_MISMATCH");
	let outputJsonParsed = false;
	if (lastText !== null) {
		try {
			JSON.parse(lastText);
			outputJsonParsed = true;
		} catch {
			outputJsonParsed = false;
		}
	}
	const outputValidation = await validateIndependentModelReviewOutputArtifact({
		rawModelOutput: lastBytes,
		outputSchemaBytes: input.outputSchemaBytes,
		expectedOutputSchemaSha256: input.expectedOutputSchemaSha256,
	});
	const output = outputValidation.output;
	const outputSchemaValidated = outputJsonParsed &&
		!outputValidation.reasonCodes.includes("INDEPENDENT_REVIEW_SCHEMA_BYTES_MISMATCH") &&
		!outputValidation.reasonCodes.includes("INDEPENDENT_REVIEW_SCHEMA_INVALID") &&
		!outputValidation.reasonCodes.includes("INDEPENDENT_REVIEW_SCHEMA_INSTANCE_INVALID");
	if (!outputValidation.ok) reasons.push(output === null ? "OPENAI_TERRA_OUTPUT_INVALID" : "OPENAI_TERRA_OUTPUT_SCHEMA_INVALID");
	const derivationsAllowed = sensitiveMaterialAbsent && !sizeLimitExceeded;
	const diagnostic = {
		schemaVersion: "openai-terra-cli-diagnostic.v1",
		status: reasons.length === 0 ? "PROVED" : "BLOCKED",
		reasonCodes: [...new Set(reasons)].sort(),
		receiptEligible: reasons.length === 0,
		execution: {
			exitCode: Number.isInteger(input.exitCode) ? input.exitCode : null,
			signal,
			timedOut: input.timedOut === true,
		},
		actualModel: derivationsAllowed && models.length === 1 && models[0] === input.requestedModel ? models[0] : null,
		reviewerSessionId: derivationsAllowed && sessionIds.length === 1 && /^[A-Za-z0-9_-]{8,128}$/u.test(sessionIds[0]) ? sessionIds[0] : null,
		toolCallEventCount,
		validation: {
			jsonlParsed,
			eventContractRecognized,
			finalMessageMatched,
			outputUtf8Valid: lastText !== null,
			outputJsonParsed,
			outputSchemaValidated,
			outputSemanticValidated: outputValidation.ok,
			sensitiveMaterialAbsent,
		},
		artifacts: {
			jsonl: diagArtifact("jsonl-events.jsonl", jsonlBytes, DIAGNOSTIC_LIMITS.jsonl, jsonlSupplied),
			stderr: diagArtifact("stderr.log", stderrBytes, DIAGNOSTIC_LIMITS.stderr, stderrSupplied),
			outputLastMessage: diagArtifact("output-last-message.json", lastBytes, DIAGNOSTIC_LIMITS.outputLastMessage, lastSupplied),
		},
		diagnosticSha256: `sha256:${"0".repeat(64)}`,
	};
	diagnostic.diagnosticSha256 = selfDigest(diagnostic, "diagnosticSha256");
	return diagnostic;
}

export async function validateOpenAiTerraDiagnostic({
	diagnostic,
	diagnosticSchemaBytes,
	expectedDiagnosticSchemaSha256,
}) {
	const schemaValidation = await validateIndependentReviewSchemaInstance({
		schemaBytes: diagnosticSchemaBytes,
		expectedSchemaSha256: expectedDiagnosticSchemaSha256,
		instance: diagnostic,
		label: "OpenAI Terra CLI Diagnostic Schema",
	});
	const reasons = [...schemaValidation.reasonCodes];
	const proved = diagnostic?.status === "PROVED" && diagnostic?.reasonCodes?.length === 0;
	const provedSemantics = diagnostic?.execution?.exitCode === 0 && diagnostic?.execution?.signal === null &&
		diagnostic?.execution?.timedOut === false && diagnostic?.actualModel === "gpt-5.6-terra" &&
		/^.{8,128}$/u.test(diagnostic?.reviewerSessionId ?? "") && diagnostic?.toolCallEventCount === 0 &&
		Object.values(diagnostic?.validation ?? {}).every((value) => value === true) &&
		Object.values(diagnostic?.artifacts ?? {}).every((artifact) => artifact?.retention === "RETAINED_SAFE_BOUNDED");
	if (!SHA256.test(diagnostic?.diagnosticSha256 ?? "") ||
			selfDigest(diagnostic, "diagnosticSha256") !== diagnostic?.diagnosticSha256 ||
			diagnostic?.receiptEligible !== proved || (proved && !provedSemantics)) {
		reasons.push("OPENAI_TERRA_DIAGNOSTIC_INVALID");
	}
	return result(reasons.length === 0, reasons);
}

export async function persistOpenAiTerraDiagnostic({
	diagnostic,
	diagnosticSchemaBytes,
	expectedDiagnosticSchemaSha256,
	artifactBytes,
	writeArtifact,
	readArtifact,
	diagnosticPath = "openai-terra-cli-diagnostic.json",
}) {
	const validation = await validateOpenAiTerraDiagnostic({
		diagnostic,
		diagnosticSchemaBytes,
		expectedDiagnosticSchemaSha256,
	});
	if (!validation.ok || typeof writeArtifact !== "function" || typeof readArtifact !== "function" ||
			!SAFE_PATH.test(diagnosticPath)) {
		throw new TypeError("A closed Terra diagnostic and trusted Artifact store are required.");
	}
	let retainedArtifactCount = 0;
	for (const key of ["jsonl", "stderr", "outputLastMessage"]) {
		const descriptor = diagnostic.artifacts[key];
		if (descriptor.retention !== "RETAINED_SAFE_BOUNDED") continue;
		const bytes = Buffer.from(artifactBytes?.[key] ?? []);
		if (scanSensitive(bytes) !== false || descriptor.byteLength !== bytes.byteLength ||
				descriptor.sha256 !== bytesDigest(bytes)) {
			throw new TypeError("Terra diagnostic Artifact bytes are stale or sensitive.");
		}
		await writeArtifact(descriptor.path, bytes);
		const reread = Buffer.from(await readArtifact(descriptor.path));
		if (!reread.equals(bytes) || descriptor.sha256 !== bytesDigest(reread)) {
			throw new TypeError("Terra diagnostic Artifact readback failed.");
		}
		retainedArtifactCount += 1;
	}
	const diagnosticBytes = Buffer.from(canonicalize(diagnostic), "utf8");
	await writeArtifact(diagnosticPath, diagnosticBytes);
	const diagnosticReadback = Buffer.from(await readArtifact(diagnosticPath));
	if (!diagnosticReadback.equals(diagnosticBytes) || bytesDigest(diagnosticReadback) !== bytesDigest(diagnosticBytes)) {
		throw new TypeError("Terra diagnostic readback failed.");
	}
	return {
		diagnosticPath,
		diagnosticByteLength: diagnosticBytes.byteLength,
		diagnosticSha256: bytesDigest(diagnosticBytes),
		retainedArtifactCount,
	};
}

function isolationIssues(isolation) {
	const reasons = [];
	if (!exactKeys(isolation, ["mode", "apiDeclaredTools", "toolCallEventCount", "probes"]) ||
			!["API_NO_TOOLS", "OS_ENFORCED_TARGET_READ_ONLY"].includes(isolation?.mode) ||
			isolation?.toolCallEventCount !== 0 || !exactKeys(isolation?.probes, REQUIRED_OS_PROBES)) {
		return ["OPENAI_TERRA_ISOLATION_NOT_PROVED"];
	}
	if (isolation.mode === "API_NO_TOOLS") {
		if (!Array.isArray(isolation.apiDeclaredTools) || isolation.apiDeclaredTools.length !== 0) reasons.push("OPENAI_TERRA_API_NO_TOOLS_NOT_PROVED");
	} else if (isolation.apiDeclaredTools !== null) reasons.push("OPENAI_TERRA_OS_READ_ONLY_NOT_PROVED");
	if (REQUIRED_OS_PROBES.some((key) => isolation.probes[key] !== true)) reasons.push("OPENAI_TERRA_OS_READ_ONLY_NOT_PROVED");
	return reasons;
}

export async function validateOpenAiTerraRuntimeEvidence({ evidence, expected, artifacts }) {
	const reasons = ["OPENAI_TERRA_RUNTIME_AUTHORITY_REQUIRED"];
	if (!exactKeys(evidence, ["schemaVersion", "evidenceId", "status", "reasonCodes", "cli", "reviewer", "execution", "source", "bindings", "isolation", "artifacts", "validation", "repositoryUnchangedBeforeAfter", "evidenceSha256"]) ||
			!exactKeys(evidence?.reviewer, ["provider", "requestedModel", "actualModel", "reasoningEffort", "reviewerSessionId", "implementationModel", "reviewerIndependentOfImplementation", "implementationParticipation"]) ||
			!exactKeys(evidence?.execution, ["ephemeral", "userConfigLoaded", "projectRulesLoaded", "implementationConversationImported", "implementationConclusionsProvided", "attemptCount", "exitCode", "signal", "timedOut", "startedAt", "finishedAt"]) ||
			!exactKeys(evidence?.source, RUNTIME_SOURCE_KEYS) ||
			!exactKeys(evidence?.bindings, RUNTIME_BINDING_KEYS) ||
			!exactKeys(evidence?.artifacts, ["jsonl", "stderr", "outputLastMessage", "diagnostic"]) ||
			!exactKeys(evidence?.validation, ["jsonlParsed", "eventContractRecognized", "finalMessageMatched", "outputUtf8Valid", "outputJsonParsed", "outputSchemaValidated", "outputSemanticValidated", "sensitiveMaterialAbsent"]) ||
			!exactKeys(evidence?.repositoryUnchangedBeforeAfter, ["beforeSha256", "afterSha256", "unchanged"]) ||
			evidence.schemaVersion !== "openai-terra-runtime-transport-evidence.v1" ||
			evidence.status !== "PROVED" || !Array.isArray(evidence.reasonCodes) || evidence.reasonCodes.length !== 0 ||
			!SHA256.test(evidence.evidenceSha256 ?? "") || selfDigest(evidence, "evidenceSha256") !== evidence.evidenceSha256) reasons.push("OPENAI_TERRA_RUNTIME_EVIDENCE_INVALID");
	if (validateOpenAiTerraConfig(expected?.config).ok !== true ||
			canonicalize(evidence?.cli) !== canonicalize(expected?.config?.cli) ||
			evidence?.reviewer?.provider !== "openai" || evidence?.reviewer?.requestedModel !== "gpt-5.6-terra" ||
			evidence?.reviewer?.actualModel !== "gpt-5.6-terra" || evidence?.reviewer?.reasoningEffort !== "high" ||
			evidence?.reviewer?.implementationModel !== "gpt-5.6-sol" || evidence?.reviewer?.reviewerIndependentOfImplementation !== true ||
			evidence?.reviewer?.implementationParticipation !== false || !/^.{8,128}$/u.test(evidence?.reviewer?.reviewerSessionId ?? "")) reasons.push("OPENAI_TERRA_MODEL_IDENTITY_NOT_PROVED");
	if (evidence?.execution?.ephemeral !== true || evidence?.execution?.userConfigLoaded !== false ||
			evidence?.execution?.projectRulesLoaded !== false || evidence?.execution?.implementationConversationImported !== false ||
			evidence?.execution?.implementationConclusionsProvided !== false || evidence?.execution?.attemptCount !== 1 ||
			evidence?.execution?.exitCode !== 0 || evidence?.execution?.signal !== null || evidence?.execution?.timedOut !== false) reasons.push("OPENAI_TERRA_EXECUTION_NOT_PROVED");
	if (RUNTIME_SOURCE_KEYS.some((key) => evidence?.source?.[key] !== expected?.[key])) reasons.push("OPENAI_TERRA_SCOPE_BINDING_MISMATCH");
	if (RUNTIME_BINDING_KEYS.some((key) => evidence?.bindings?.[key] !==
		(key === "configSha256" ? expected?.config?.configSha256 : expected?.[key]))) {
		reasons.push("OPENAI_TERRA_ARTIFACT_BINDING_MISMATCH");
	}
	reasons.push(...isolationIssues(evidence?.isolation));
	if (evidence?.repositoryUnchangedBeforeAfter?.unchanged !== true || evidence?.repositoryUnchangedBeforeAfter?.beforeSha256 !== evidence?.repositoryUnchangedBeforeAfter?.afterSha256) reasons.push("OPENAI_TERRA_REPOSITORY_CHANGED");
	if (!validArtifact(evidence?.artifacts?.jsonl, artifacts.jsonl) || !validArtifact(evidence?.artifacts?.stderr, artifacts.stderr) || !validArtifact(evidence?.artifacts?.outputLastMessage, artifacts.outputLastMessage) || !validArtifact(evidence?.artifacts?.diagnostic, artifacts.diagnostic)) reasons.push("OPENAI_TERRA_OUTPUT_EVIDENCE_INCOMPLETE");
	const analysis = await analyzeOpenAiTerraCliResult({ requestedModel: "gpt-5.6-terra", exitCode: evidence?.execution?.exitCode, signal: evidence?.execution?.signal, timedOut: evidence?.execution?.timedOut, jsonlBytes: artifacts.jsonl, stderrBytes: artifacts.stderr, outputLastMessageBytes: artifacts.outputLastMessage, outputSchemaBytes: artifacts.outputSchema, expectedOutputSchemaSha256: expected.outputSchemaSha256 });
	if (!analysis.receiptEligible || analysis.actualModel !== evidence?.reviewer?.actualModel || analysis.reviewerSessionId !== evidence?.reviewer?.reviewerSessionId || analysis.toolCallEventCount !== evidence?.isolation?.toolCallEventCount) reasons.push("OPENAI_TERRA_OUTPUT_EVIDENCE_INCOMPLETE");
	try {
		const recorded = parseIndependentReviewJsonBytes(artifacts.diagnostic, "Persisted Terra diagnostic");
		if (canonicalize(recorded) !== canonicalize(analysis)) reasons.push("OPENAI_TERRA_DIAGNOSTIC_RUNTIME_MISMATCH");
	} catch {
		reasons.push("OPENAI_TERRA_DIAGNOSTIC_RUNTIME_MISMATCH");
	}
	if (Object.values(evidence?.validation ?? {}).some((value) => value !== true)) reasons.push("OPENAI_TERRA_VALIDATION_NOT_PROVED");
	return result(false, reasons, { status: "INCONCLUSIVE" });
}

function receiptDigest(receipt) { return selfDigest(receipt, "receiptSha256"); }

export async function validateOpenAiTerraReceipt({ receipt, receiptSchemaBytes }) {
	const reasons = ["OPENAI_TERRA_RECEIPT_RUNTIME_AUTHORITY_REQUIRED"];
	const schemaValidation = receiptSchemaBytes instanceof Uint8Array
		? await validateIndependentReviewSchemaInstance({
			schemaBytes: receiptSchemaBytes,
			expectedSchemaSha256: bytesDigest(receiptSchemaBytes),
			instance: receipt,
			label: "OpenAI Terra Receipt Schema",
		})
		: { ok: false };
	if (!schemaValidation.ok || !SHA256.test(receipt?.receiptSha256 ?? "") ||
			receiptDigest(receipt) !== receipt?.receiptSha256) reasons.push("OPENAI_TERRA_RECEIPT_INVALID");
	if (receipt?.reviewer?.requestedModel !== "gpt-5.6-terra" ||
			receipt?.reviewer?.actualModel !== "gpt-5.6-terra" ||
			receipt?.reviewer?.implementationModel !== "gpt-5.6-sol") {
		reasons.push("OPENAI_TERRA_RECEIPT_MODEL_MISMATCH");
	}
	if (receipt?.humanIndependentReviewSatisfied !== false || receipt?.humanReviewClaim !== false ||
			receipt?.governanceEffect !== "NONE" || receipt?.p1B11StatusChanged !== false ||
			receipt?.profileApproved !== false || receipt?.o02O03AuthorizedOrStarted !== false ||
			receipt?.historicalK3EvidenceAccepted !== false) {
		reasons.push("OPENAI_TERRA_RECEIPT_GOVERNANCE_CLAIM_FORBIDDEN");
	}
	if (!DECISIONS.has(receipt?.decision) ||
			receipt?.conclusion !== (receipt?.decision === "CLEAR"
				? "MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION"
				: receipt?.decision)) reasons.push("OPENAI_TERRA_RECEIPT_DECISION_MISMATCH");
	if (receipt?.decision === "CLEAR" && receipt?.findings?.some((finding) =>
		finding.status === "OPEN" && BLOCKING_SEVERITIES.has(finding.severity))) {
		reasons.push("OPENAI_TERRA_UNRESOLVED_BLOCKING_FINDING");
	}
	return result(false, reasons, { status: "INCONCLUSIVE" });
}
