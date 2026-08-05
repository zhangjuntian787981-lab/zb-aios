import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import {
	OPENAI_TERRA_CORE_REVIEW_PATHS,
	OPENAI_TERRA_MAX_MODEL_VISIBLE_BYTES,
	analyzeOpenAiTerraCliResult,
	buildOpenAiTerraCliArguments as cliArgs,
	openAiTerraDigests as digest,
	persistOpenAiTerraDiagnostic as saveD,
	validateOpenAiTerraConfig as checkConfig,
	validateOpenAiTerraDiagnostic as checkD,
	validateOpenAiTerraReceipt as checkReceipt,
	validateOpenAiTerraReviewSubject as checkSubject,
	validateOpenAiTerraRuntimeEvidence as checkR,
} from "../lib/openai-terra-independent-review.mjs";
import {
	buildOpenAiTerraReviewSubjectFromGit as buildSubject,
	encodeOpenAiTerraReviewSubject as encodeSubject,
	parseOpenAiTerraReviewSubject as parseSubject,
} from "../scripts/build-openai-terra-review-material.mjs";
import {
	finalizeOpenAiTerraInvocationDiagnostic as finalizeDiag,
	runOpenAiTerraIndependentReview as runReview,
} from "../scripts/run-openai-terra-independent-review.mjs";

const BASE = "340b8900dda62fa57ee185b9a43cfe472e7eaed7";
const CORE_FREEZE = "ab95c7aff586279062c7698749fdbc0e38e955d1";
const SOURCE = "5fec0823663d8f1ecfb828469c0e6c7890b84ac5";
const PARENT = "956b4bd2e3e16c607b45957ed17d135ff0491604";
const TREE = "bb027bfee3492785f777e606efac9f4773af0b75";
const SHA = (character) => `sha256:${character.repeat(64)}`;
const IR = "implementation/governance/independent-review/";
const GS = "implementation/governance/schemas/";
const buf = (...args) => Buffer.from(...args);
const EMPTY = Buffer.alloc(0);
const { deepEqual, equal, match, ok, rejects, throws } = assert;
const clone = globalThis.structuredClone;
const json = JSON.stringify;
const sha = (bytes) =>
	`sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const repoUrl = new URL("../", import.meta.url);
const repoFs = fileURLToPath(repoUrl);
const gitBytes = (args) => buf(execFileSync("/usr/bin/git", [
	"--no-replace-objects", "-C", repoFs, ...args,
], { maxBuffer: 32 * 1024 * 1024 }));
const readJson = (path) =>
	JSON.parse(readFileSync(new URL(path, repoUrl), "utf8"));
const O_SCHEMA = readFileSync(new URL(
	`${GS}independent-model-review-output.v2.schema.json`,
	repoUrl,
));
const O_SHA = sha(O_SCHEMA);
const O_BINDING = Object.freeze({
	outputSchemaBytes: O_SCHEMA,
	expectedOutputSchemaSha256: O_SHA,
});
const D_SCHEMA = readFileSync(new URL(
	`${GS}openai-terra-cli-diagnostic.v1.schema.json`,
	repoUrl,
));
const D_SHA = sha(D_SCHEMA);
const cases = [];
const test = (name, execute) => cases.push({ name, execute });
const OS_PROBE_KEYS = [
	"createFileDenied", "modifyFileDenied", "deleteFileDenied", "moveRenameDenied",
	"applyPatchDenied", "readOutsideBundleDenied", "gitCommitDenied", "gitTagDenied",
	"gitPushNotAttempted", "networkToolUnavailable", "d1SitesGovernanceWriteUnavailable",
	"credentialsUnavailableToReviewer",
];
const TOOL_EVENTS = [
	"exec_command_begin", "exec_command_end", "patch_apply_begin", "patch_apply_updated",
	"patch_apply_end", "web_search_begin", "web_search_end", "mcp_tool_call_begin",
	"mcp_tool_call_end", "dynamic_tool_call_request", "dynamic_tool_call_response",
];
const TOOL_ITEMS = [
	"tool_call", "command_execution", "file_change", "web_search", "mcp_tool_call",
	"dynamic_tool_call",
];
const VALIDATION_KEYS = [
	"jsonlParsed", "eventContractRecognized", "finalMessageMatched", "outputUtf8Valid",
	"outputJsonParsed", "outputSchemaValidated", "outputSemanticValidated", "sensitiveMaterialAbsent",
];
const allTrue = (keys) => Object.fromEntries(keys.map((key) => [key, true]));
function cfg() {
	return clone(readJson(
		`${IR}openai-codex-terra.v1.json`,
	));
}

function artifact(path, bytes) {
	return {
		path,
		byteLength: bytes.byteLength,
		sha256: sha(bytes),
	};
}

function section(kind, path, bytes, extra = {}) {
	return {
		descriptor: {
			kind, path, gitMode: kind === "PROVIDER_NEUTRAL_REVIEW_BUNDLE" ? null : "100644",
			byteLength: bytes.byteLength, sha256: sha(bytes), ...extra,
		},
		bytes,
	};
}

function iso(mode = "OS_ENFORCED_TARGET_READ_ONLY") {
	return {
		mode,
		apiDeclaredTools: mode === "API_NO_TOOLS" ? [] : null,
		toolCallEventCount: 0,
		probes: Object.fromEntries(OS_PROBE_KEYS.map((key) => [key, true])),
	};
}

function out(decision = "CLEAR") {
	return {
		schemaVersion: "independent-model-review-output.v2",
		reviewSummary: "Scoped provider-neutral core review.",
		findings: [],
		decision,
	};
}

function events(last, extraEvents = []) {
	return buf([
		{ type: "thread.started", thread_id: "terra-session-001", model: "gpt-5.6-terra" },
		...extraEvents,
		{ type: "item.completed", item: { type: "agent_message", text: last.toString("utf8") } },
		{ type: "turn.completed", model: "gpt-5.6-terra" },
	].map(json).join("\n") + "\n", "utf8");
}

function analyze(overrides = {}) {
	const last = overrides.outputLastMessageBytes ?? buf(json(out()), "utf8");
	return analyzeOpenAiTerraCliResult({
		...O_BINDING,
		requestedModel: "gpt-5.6-terra", exitCode: 0, signal: null, timedOut: false,
		jsonlBytes: events(last), stderrBytes: EMPTY, outputLastMessageBytes: last,
		...overrides,
	});
}

function provedDiag(jsonl, last) {
	const diagnostic = {
		schemaVersion: "openai-terra-cli-diagnostic.v1",
		status: "PROVED", reasonCodes: [], receiptEligible: true,
		execution: { exitCode: 0, signal: null, timedOut: false },
		actualModel: "gpt-5.6-terra", reviewerSessionId: "terra-session-001", toolCallEventCount: 0,
		validation: allTrue(VALIDATION_KEYS),
		artifacts: {
			jsonl: { retention: "RETAINED_SAFE_BOUNDED", ...artifact("jsonl-events.jsonl", jsonl) },
			stderr: { retention: "RETAINED_SAFE_BOUNDED", ...artifact("stderr.log", EMPTY) },
			outputLastMessage: { retention: "RETAINED_SAFE_BOUNDED", ...artifact("output-last-message.json", last) },
		},
		diagnosticSha256: SHA("0"),
	};
	diagnostic.diagnosticSha256 = digest.self(diagnostic, "diagnosticSha256");
	return buf(digest.canonicalize(diagnostic), "utf8");
}

function rt(overrides = {}, decision = "CLEAR") {
	const last = buf(json(out(decision)), "utf8");
	const jsonl = events(last);
	const diagnosticBytes = provedDiag(jsonl, last);
	const evidence = {
		schemaVersion: "openai-terra-runtime-transport-evidence.v1",
		evidenceId: "otre_openai_terra_fixture_001",
		status: "PROVED",
		reasonCodes: [],
		cli: clone(cfg().cli),
		reviewer: {
			provider: "openai",
			requestedModel: "gpt-5.6-terra",
			actualModel: "gpt-5.6-terra",
			reasoningEffort: "high",
			reviewerSessionId: "terra-session-001",
			implementationModel: "gpt-5.6-sol",
			reviewerIndependentOfImplementation: true,
			implementationParticipation: false,
		},
		execution: {
			ephemeral: true,
			userConfigLoaded: false,
			projectRulesLoaded: false,
			implementationConversationImported: false,
			implementationConclusionsProvided: false,
			attemptCount: 1,
			exitCode: 0,
			signal: null,
			timedOut: false,
			startedAt: "2026-08-05T00:00:00.000Z",
			finishedAt: "2026-08-05T00:01:00.000Z",
		},
		source: {
			coverageBase: BASE,
			coreFreezeCommit: CORE_FREEZE,
			sourceCommit: SOURCE,
			sourceParent: PARENT,
			sourceTree: TREE,
			fullPatchByteLength: 123,
			fullPatchSha256: SHA("a"),
			reviewPathSetSha256: SHA("2"),
		},
		bindings: {
			reviewSubjectSha256: SHA("3"),
			reviewSubjectByteLength: 500000,
			reviewBundleSha256: SHA("b"),
			reviewerPromptSha256: SHA("4"),
			authorizationPromptByteLength: 16491,
			authorizationPromptSha256: "sha256:a7e5d4b8334ae0cac5a6d9c0bf90c40dc9150c4a1bad1be1e2c1675c6facceaf",
			configSha256: cfg().configSha256,
			policySha256: SHA("a"),
			subjectSchemaSha256: SHA("5"),
			outputSchemaSha256: O_SHA,
			evidenceSchemaSha256: SHA("6"),
			diagnosticSchemaSha256: D_SHA,
			receiptSchemaSha256: SHA("7"),
			testEvidenceSetSha256: SHA("8"),
		},
		isolation: iso(),
		artifacts: {
			jsonl: artifact("jsonl-events.jsonl", jsonl),
			stderr: artifact("stderr.log", EMPTY),
			outputLastMessage: artifact("output-last-message.json", last),
			diagnostic: artifact("openai-terra-cli-diagnostic.json", diagnosticBytes),
		},
		validation: allTrue(VALIDATION_KEYS),
		repositoryUnchangedBeforeAfter: {
			beforeSha256: SHA("9"),
			afterSha256: SHA("9"),
			unchanged: true,
		},
		evidenceSha256: SHA("0"),
	};
	Object.assign(evidence, overrides);
	evidence.evidenceSha256 = digest.self(evidence, "evidenceSha256");
	return { evidence, jsonl, last, diagnosticBytes };
}

function rtIn({ evidence, jsonl, last, diagnosticBytes }) {
	return {
		runtimeExpected: {
			config: cfg(),
			...evidence.source,
			...evidence.bindings,
		},
		runtimeArtifacts: {
			jsonl,
			stderr: EMPTY,
			outputLastMessage: last,
			diagnostic: diagnosticBytes,
			outputSchema: O_SCHEMA,
		},
	};
}

test("the fixed core scope is the exact 22-path provider-neutral set", () => {
	equal(OPENAI_TERRA_CORE_REVIEW_PATHS.length, 22);
	equal(new Set(OPENAI_TERRA_CORE_REVIEW_PATHS).size, 22);
	deepEqual(OPENAI_TERRA_CORE_REVIEW_PATHS, [...OPENAI_TERRA_CORE_REVIEW_PATHS].sort());
	equal(OPENAI_TERRA_MAX_MODEL_VISIBLE_BYTES, 650 * 1024);
});

test("Terra config is closed, self-hashed, distinct, single-attempt and fail-closed", () => {
	deepEqual(checkConfig(cfg()), { ok: true, reasonCodes: [] });
	for (const mutate of [
		(value) => (value.reviewer.requestedModel = "gpt-5.6-sol"),
		(value) => (value.implementation.model = "gpt-5.6-terra"),
		(value) => (value.reviewer.reasoningEffort = "ultra"),
		(value) => (value.reviewer.maximumFormalAttempts = 2),
		(value) => (value.reviewer.fallbackPolicy = "AUTOMATIC"),
		(value) => (value.authorizationPrompt.byteLength = 1),
		(value) => (value.authorizationPrompt.sha256 = SHA("d")),
		(value) => value.reviewer.extra = true,
	]) {
		const invalid = clone(cfg());
		mutate(invalid);
		invalid.configSha256 = digest.self(invalid, "configSha256");
		equal(checkConfig(invalid).ok, false);
	}
});

test("Config, Subject, Runtime Evidence and Receipt schemas are closed and compile", async () => {
	const ajv = new Ajv2020({ allErrors: true, strict: true });
	const outputSchema = readJson(`${GS}independent-model-review-output.v2.schema.json`);
	ajv.addSchema(outputSchema);
	const schemas = [
		`${GS}openai-codex-terra-config.v1.schema.json`,
		`${GS}openai-terra-scoped-review-subject.v1.schema.json`,
		`${GS}openai-terra-runtime-transport-evidence.v1.schema.json`,
		`${GS}openai-terra-cli-diagnostic.v1.schema.json`,
		`${GS}independent-model-review-receipt.v10.schema.json`,
	].map(readJson);
	for (const schema of schemas) equal(typeof ajv.compile(schema), "function");

	const frozenConfig = readJson(`${IR}openai-codex-terra.v1.json`);
	deepEqual(frozenConfig, cfg());
	equal(ajv.getSchema(schemas[0].$id)(frozenConfig), true);
	equal(ajv.getSchema(schemas[0].$id)({ ...frozenConfig, ready: true }), false);

	const { evidence } = rt();
	const validateRuntime = ajv.getSchema(schemas[2].$id);
	equal(validateRuntime(evidence), true, json(validateRuntime.errors));
	equal(schemas[4].properties.governanceEffect.const, "NONE");
	equal(schemas[4].properties.humanIndependentReviewSatisfied.const, false);
});

test("CLI arguments pin fresh Terra execution and reject inherited or ambiguous invocation", () => {
	const args = cliArgs({
		config: cfg(),
		outputSchemaPath: "/review/output.schema.json",
		outputLastMessagePath: "/dev/fd/3",
	});
	deepEqual(args, [
		"exec", "--model", "gpt-5.6-terra", "--ephemeral", "--ignore-user-config",
		"--ignore-rules", "--skip-git-repo-check", "--sandbox", "read-only",
		"--ask-for-approval", "never", "--config", 'model_reasoning_effort="high"',
		"--output-schema", "/review/output.schema.json", "--json",
		"--output-last-message", "/dev/fd/3", "-",
	]);
});

test("runtime evidence remains authority-unproved and rejects identity, session, scope, output and repository drift", async () => {
	const runtime = rt();
	const { evidence } = runtime;
	const { runtimeExpected: expected, runtimeArtifacts: artifacts } = rtIn(runtime);
	const selfConsistent = await checkR({ evidence, expected, artifacts });
	equal(selfConsistent.ok, false);
	equal(selfConsistent.status, "INCONCLUSIVE");
	ok(selfConsistent.reasonCodes.includes("OPENAI_TERRA_RUNTIME_AUTHORITY_REQUIRED"));
	for (const mutate of [
		(value) => (value.reviewer.actualModel = "gpt-5.6-sol"),
		(value) => (value.reviewer.implementationParticipation = true),
		(value) => (value.reviewer.reviewerSessionId = "old-session"),
		(value) => (value.execution.ephemeral = false),
		(value) => (value.execution.userConfigLoaded = true),
		(value) => (value.execution.projectRulesLoaded = true),
		(value) => (value.execution.implementationConversationImported = true),
		(value) => (value.execution.implementationConclusionsProvided = true),
		(value) => (value.source.sourceCommit = "d".repeat(40)),
		(value) => (value.source.sourceTree = "d".repeat(40)),
		(value) => (value.bindings.reviewSubjectSha256 = SHA("d")),
		(value) => (value.bindings.reviewerPromptSha256 = SHA("d")),
		(value) => (value.bindings.evidenceSchemaSha256 = SHA("d")),
		(value) => (value.repositoryUnchangedBeforeAfter.unchanged = false),
		(value) => (value.execution.attemptCount = 2),
		(value) => (value.extra = true),
	]) {
		const invalid = clone(evidence);
		mutate(invalid);
		invalid.evidenceSha256 = digest.self(invalid, "evidenceSha256");
		equal((await checkR({ evidence: invalid, expected, artifacts })).ok, false);
	}
	const mismatch = rt();
	const diagnostic = JSON.parse(mismatch.diagnosticBytes.toString("utf8"));
	diagnostic.reviewerSessionId = "different-session";
	diagnostic.diagnosticSha256 = digest.self(diagnostic, "diagnosticSha256");
	mismatch.diagnosticBytes = buf(digest.canonicalize(diagnostic));
	mismatch.evidence.artifacts.diagnostic = artifact("openai-terra-cli-diagnostic.json", mismatch.diagnosticBytes);
	mismatch.evidence.evidenceSha256 = digest.self(mismatch.evidence, "evidenceSha256");
	const mismatchInputs = rtIn(mismatch);
	const mismatchResult = await checkR({
		evidence: mismatch.evidence,
		expected: mismatchInputs.runtimeExpected,
		artifacts: mismatchInputs.runtimeArtifacts,
	});
	ok(mismatchResult.reasonCodes.includes("OPENAI_TERRA_DIAGNOSTIC_RUNTIME_MISMATCH"));
});

test("API no-tools and OS read-only modes fail closed on tools, file, network or governance capability", async () => {
	const cases = [
		["API_NO_TOOLS", (value) => value.apiDeclaredTools.push("shell")],
		["OS_ENFORCED_TARGET_READ_ONLY", (value) => (value.probes.createFileDenied = false)],
		["OS_ENFORCED_TARGET_READ_ONLY", (value) => (value.probes.readOutsideBundleDenied = false)],
		["OS_ENFORCED_TARGET_READ_ONLY", (value) => (value.probes.networkToolUnavailable = false)],
		["OS_ENFORCED_TARGET_READ_ONLY", (value) => (value.probes.d1SitesGovernanceWriteUnavailable = false)],
		["OS_ENFORCED_TARGET_READ_ONLY", (value) => (value.probes.gitPushNotAttempted = false)],
	];
	for (const [mode, mutate] of cases) {
		const runtime = rt();
		const { evidence } = runtime;
		evidence.isolation = iso(mode);
		mutate(evidence.isolation);
		evidence.evidenceSha256 = digest.self(evidence, "evidenceSha256");
		const result = await checkR({
			evidence,
			expected: rtIn(runtime).runtimeExpected,
			artifacts: rtIn(runtime).runtimeArtifacts,
		});
		equal(result.ok, false);
		match(result.reasonCodes.join(" "), /ISOLATION|TOOLS|READ_ONLY/u);
	}
});

test("CLI analysis preserves diagnostics for every bounded failure without a Receipt", async () => {
	const cases = [
		{ exitCode: 1, stderr: "service unavailable", code: "OPENAI_TERRA_SERVICE_UNAVAILABLE" },
		{ exitCode: 1, stderr: "quota unavailable", code: "OPENAI_TERRA_QUOTA_UNAVAILABLE" },
		{ exitCode: null, timedOut: true, stderr: "", code: "OPENAI_TERRA_TIMEOUT" },
		{ exitCode: 0, jsonl: "", stderr: "", code: "OPENAI_TERRA_JSONL_INCOMPLETE" },
	];
	for (const item of cases) {
		const result = await analyze({
			exitCode: item.exitCode,
			timedOut: item.timedOut ?? false,
			jsonlBytes: buf(item.jsonl ?? "", "utf8"),
			stderrBytes: buf(item.stderr, "utf8"),
			outputLastMessageBytes: EMPTY,
		});
		equal(result.receiptEligible, false);
		ok(result.reasonCodes.includes(item.code));
		equal(result.artifacts.stderr.retention, "RETAINED_SAFE_BOUNDED");
		match(result.artifacts.stderr.sha256, /^sha256:[a-f0-9]{64}$/u);
		deepEqual(Object.keys(result).sort(), [
			"actualModel", "artifacts", "diagnosticSha256", "execution",
			"reasonCodes", "receiptEligible", "reviewerSessionId", "schemaVersion",
			"status", "toolCallEventCount", "validation",
		]);
		equal(
			result.diagnosticSha256,
			digest.self(result, "diagnosticSha256"),
		);
		equal((await checkD({
			diagnostic: result,
			diagnosticSchemaBytes: D_SCHEMA,
			expectedDiagnosticSchemaSha256: D_SHA,
		})).ok, true);
	}
	for (const [bytes, code] of [
		[buf("{", "utf8"), "OPENAI_TERRA_OUTPUT_INVALID"],
		[buf([0xff, 0xfe]), "OPENAI_TERRA_OUTPUT_INVALID"],
		[buf(json({ ...out(), extra: true }), "utf8"), "OPENAI_TERRA_OUTPUT_SCHEMA_INVALID"],
	]) {
		const result = await analyze({
			jsonlBytes: buf(`${json({ type: "thread.started", thread_id: "terra-session-001", model: "gpt-5.6-terra" })}\n`, "utf8"),
			outputLastMessageBytes: bytes,
		});
		equal(result.receiptEligible, false);
		ok(result.reasonCodes.includes(code));
	}
	const sensitive = await analyze({
		exitCode: 1,
		jsonlBytes: EMPTY, stderrBytes: buf("Authorization: Bearer abcdefghijklmnop"),
		outputLastMessageBytes: EMPTY,
	});
	ok(sensitive.reasonCodes.includes("OPENAI_TERRA_SENSITIVE_MATERIAL_DETECTED"));
	equal(sensitive.receiptEligible, false);
	equal(sensitive.artifacts.stderr.retention, "WITHHELD_SENSITIVE");
	deepEqual(sensitive.artifacts.stderr, {
		retention: "WITHHELD_SENSITIVE", path: null, byteLength: null, sha256: null,
	});
	equal(json(sensitive).includes("abcdefghijklmnop"), false);
	const secret = "live-secret";
	const assignments = (keys, separator = "=") => keys.map((key) => `${key}${separator}${secret}`);
	for (const value of [
		...["Authorization: Basic", "Authorization: Bearer", "Bearer"].map((key) => `${key} ${secret}`),
		"Authorization: Bearer x", 'Authorization: Bearer "x"',
		`Authorization: ApiKey ${secret}-abcdefghijklmnop`,
		`Proxy-Authorization: Digest ${secret}-abcdefghijklmnop`,
		`Authorization = "ApiKey ${secret}-abcdefghijklmnop"`,
		`proxyAuthorization = "Digest ${secret}-abcdefghijklmnop"`,
		`authorization="Token ${secret}-abcdefghijklmnop"`,
		json({ Authorization: `ApiKey ${secret}-abcdefghijklmnop` }),
		`Ocp-Apim-Subscription-Key: ${secret}-abcdefghijklmnop`,
		`X-Auth-Key: ${secret}-abcdefghijklmnop`,
		...["Cookie", "Set-Cookie"].map((key) => `${key}: session=${secret}`),
		"sk-proj-1234567890abcdefghijklmnop",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
		"person\\u0040example.com",
		...assignments(["X-API-Key", "Api-Key"], ": "),
		...["api_key", "apiKey", "openaiApiKey", "vendor_api_key", "password"]
			.map((key) => json({ [key]: secret })),
		...assignments(["OPENAI_API_KEY", "VENDOR_API_KEY", "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "PRIVATE_KEY"]),
		...assignments(["OPENAI_API_KEY", "client_secret", "apiKey", "openaiApiKey", "sessionToken", "credentials[sessionToken]"], ": "),
		json({ credentials: { githubToken: secret } }),
		...assignments(["access_token", "api%5Fkey", "apiKey", "openaiApiKey", "githubToken", "session_token",
			"AWS_SECRET_ACCESS_KEY", "privateKey", "signingKey", "credential", "credentials[sessionToken]",
			"credentials%5BsessionToken%5D"]).map((query) => `https://example.invalid/?${query}`),
		...["api-key", "token", "github-token"].flatMap((key) =>
			[`--${key} ${secret}`, `--${key}=${secret}`]),
		json(["apiKey", secret]), `https://x.invalid/?api%25255Fkey=${secret}`,
		`{"api\\u200bKey":"${secret}"}`,
		...["tokens", "apiKeys"].map((key) => json({ [key]: [secret] })),
		`http://admin:${secret}@127.0.0.1/private`, `postgres://admin:${secret}@db:5432/app`,
		...["string", "null"].map((value) => `DATABASE_PASSWORD=${value}`),
		...["token", "undefined"].map((value) => `API_KEY=${value}`),
		'{"password":"null"}',
		"http://admin:null@127.0.0.1/private",
		`https://app.invalid/callback#access_token=${secret}`,
		`https://x.invalid/?api%25252525255Fkey=${secret}`,
		'{"apiKey":"live-secret","apiKey":"REDACTED"}',
		json({ error: `request failed with API_KEY=${secret}` }),
		json({ error: `nested clientSecret: ${secret}` }),
		`//registry.npmjs.org/:_authToken=${secret}`,
		json({ auths: { "registry.invalid": { auth: secret } } }),
		`API key: ${secret}`, json({ description: `API key: ${secret}` }),
		`Secret access key: ${secret}`, `AWS Secret Access Key: ${secret}`,
		`api\u2060Key=${secret}`, `api\u200eKey=${secret}`,
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot-a-real-key",
		`<apiKey>${secret}</apiKey>`,
		json({ name: "apiKey", value: secret }),
		json({ key: "password", value: secret }),
		json({ headers: [{ name: "x-api-key", value: secret }] }),
		json(["x-api-key", secret, "content-type", "application/json"]),
		json(["apiKey", secret, { source: "env" }]),
		`process.env["API_KEY"]="${secret}"`, `headers["X-API-Key"]="${secret}"`,
		`headers.set("X-API-Key","${secret}")`, `new Headers([["X-API-Key","${secret}"]])`,
		`const headers = { ["apiKey"]: "${secret}-abcdefghijklmnop" };`,
		`dict(apiKey="${secret}-abcdefghijklmnop")`,
		`apiKey = """${secret}-abcdefghijklmnop"""`,
		`apiKey = '''${secret}-abcdefghijklmnop'''`,
		`apiKey = """\n${secret}-abcdefghijklmnop\n"""`,
		`apiKey = '''\n${secret}-abcdefghijklmnop\n'''`,
		`apiKey = """${"x".repeat(2100)}${secret}-abcdefghijklmnop"""`,
		`apiKey = '''${"x".repeat(250 * 1024)}${secret}-abcdefghijklmnop'''`,
		`AccountKey=${secret}-abcdefghijklmnop`, `SharedAccessKey=${secret}-abcdefghijklmnop`,
		`SharedAccessSignature=${secret}-abcdefghijklmnop`,
		`headers[\`apiKey\`] = \`${secret}-abcdefghijklmnop\``,
		...["os.Setenv", "System.setProperty", "headers.put", "headers.Add", "headers.Set",
			"headers.setHeader", "headers.append", "headers.insert"].map((method) =>
			`${method}("apiKey","${secret}-abcdefghijklmnop")`),
		`machine api.invalid login reviewer password ${secret}-abcdefghijklmnop`,
		...["sk_live_1234567890abcdefghijklmnop", "glpat-1234567890abcdefghijklmnop",
			"npm_1234567890abcdefghijklmnop", "ASIAIOSFODNN7EXAMPLE",
			"AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"],
		`localhost:5432:review:user:${secret}-abcdefghijklmnop`,
		...["new Map", "Object.fromEntries", "const x="].map((prefix) =>
			`${prefix}([["apiKey","${secret}-abcdefghijklmnop"]])`),
	]) {
		const rejected = await analyze({
			exitCode: 1,
			jsonlBytes: EMPTY, stderrBytes: buf(value, "utf8"),
			outputLastMessageBytes: EMPTY,
		});
		ok(rejected.reasonCodes.includes("OPENAI_TERRA_SENSITIVE_MATERIAL_DETECTED"));
		equal(json(rejected).includes(value), false);
		const writeSpy = new Map();
		await saveD({
			diagnostic: rejected,
			diagnosticSchemaBytes: D_SCHEMA,
			expectedDiagnosticSchemaSha256: D_SHA,
			artifactBytes: { jsonl: EMPTY, stderr: buf(value), outputLastMessage: EMPTY },
			writeArtifact: async (path, bytes) => writeSpy.set(path, buf(bytes)),
			readArtifact: async (path) => writeSpy.get(path),
		});
		equal([...writeSpy.values()].some((bytes) => bytes.includes(buf(value))), false);
	}
	for (const value of [
		"Authorization: Bearer <token>",
		"Authorization: REDACTED", "Proxy-Authorization: <token>",
		"Cookie: REDACTED",
		'{"api_key":"REDACTED"}',
		"type Config = { apiKey: string };",
		"interface Auth { token: string; }",
		"GITHUB_TOKEN must never be logged",
		"const config = { apiKey: process.env.API_KEY };",
		"type Config = {\n  apiKey: string;\n};",
		"interface Auth {\n  token: string;\n}",
		'const config = { apiKey: process.env["API_KEY"] };',
		'{"properties":{"apiKey":{"type":"string"}}}',
		'{"properties":{"apiKey":{"type":["string","null"],"description":"credential reference"}}}',
		'{"apiKey":"process.env.API_KEY"}',
		json({ required: ["apiKey", "baseUrl"], enum: ["token", "credential"] }),
		'const required = ["apiKey", "baseUrl"];',
		"API key: must never be logged",
		json({ description: "API key: must never be logged" }),
		"Secret access key: must come from process.env.AWS_SECRET_ACCESS_KEY",
		"Ocp-Apim-Subscription-Key: must never be logged",
	]) {
		const retained = await analyze({ stderrBytes: buf(value) });
		equal(retained.artifacts.stderr.retention, "RETAINED_SAFE_BOUNDED");
	}
	const sensitiveSession = await analyze({
		jsonlBytes: buf(events(buf(json(out()))).toString("utf8")
			.replaceAll("terra-session-001", "person@example.com")),
	});
	equal(sensitiveSession.artifacts.jsonl.retention, "WITHHELD_SENSITIVE");
	equal(sensitiveSession.reviewerSessionId, null);
	equal(json(sensitiveSession).includes("person@example.com"), false);
	const unsafeSignal = await analyze({ signal: "secret-value" });
	equal(unsafeSignal.execution.signal, null);
	ok(unsafeSignal.reasonCodes.includes("OPENAI_TERRA_CLI_SIGNAL_INVALID"));

	const persistedJsonl = EMPTY;
	const persistedStderr = buf("service unavailable", "utf8");
	const persistedOutput = EMPTY;
	const persistedDiagnostic = await analyze({
		exitCode: 1,
		jsonlBytes: persistedJsonl,
		stderrBytes: persistedStderr,
		outputLastMessageBytes: persistedOutput,
	});
	const artifactStore = new Map();
	const persisted = await saveD({
		diagnostic: persistedDiagnostic,
		diagnosticSchemaBytes: D_SCHEMA,
		expectedDiagnosticSchemaSha256: D_SHA,
		artifactBytes: {
			jsonl: persistedJsonl,
			stderr: persistedStderr,
			outputLastMessage: persistedOutput,
		},
		writeArtifact: async (path, bytes) => artifactStore.set(path, buf(bytes)),
		readArtifact: async (path) => artifactStore.get(path),
	});
	equal(persisted.retainedArtifactCount, 3);
	equal(artifactStore.get("stderr.log").toString("utf8"), "service unavailable");
	match(persisted.diagnosticSha256, /^sha256:[a-f0-9]{64}$/u);
	equal(
		sha(artifactStore.get(persisted.diagnosticPath)),
		persisted.diagnosticSha256,
	);
	const finalized = await finalizeDiag({
		subjectBytes: EMPTY,
		subjectSchemaBytes: EMPTY,
	});
	equal(finalized.formalAttemptCount, 1);
	equal(finalized.receiptIssued, false);
	deepEqual(finalized.reasonCodes, ["OPENAI_TERRA_TRUSTED_CONTEXT_INVALID"]);

	await rejects(
		saveD({
			diagnostic: persistedDiagnostic,
			diagnosticSchemaBytes: D_SCHEMA,
			expectedDiagnosticSchemaSha256: D_SHA,
			artifactBytes: {
				jsonl: persistedJsonl,
				stderr: persistedStderr,
				outputLastMessage: persistedOutput,
			},
			writeArtifact: async (path, bytes) => artifactStore.set(path, buf(bytes)),
			readArtifact: async (path) => path === "stderr.log"
				? buf("tampered", "utf8")
				: artifactStore.get(path),
		}),
		/readback/u,
	);

	const sensitiveStore = new Map();
	await saveD({
		diagnostic: sensitive,
		diagnosticSchemaBytes: D_SCHEMA,
		expectedDiagnosticSchemaSha256: D_SHA,
		artifactBytes: {
			jsonl: EMPTY,
			stderr: buf("Authorization: Bearer abcdefghijklmnop", "utf8"),
			outputLastMessage: EMPTY,
		},
		writeArtifact: async (path, bytes) => sensitiveStore.set(path, buf(bytes)),
		readArtifact: async (path) => sensitiveStore.get(path),
	});
	equal(
		[...sensitiveStore.values()].some((bytes) => bytes.includes(buf("abcdefghijklmnop", "utf8"))),
		false,
	);

	const forgedProved = clone(persistedDiagnostic);
	forgedProved.status = "PROVED";
	forgedProved.reasonCodes = [];
	forgedProved.receiptEligible = true;
	forgedProved.diagnosticSha256 = digest.self(forgedProved, "diagnosticSha256");
	equal((await checkD({
		diagnostic: forgedProved,
		diagnosticSchemaBytes: D_SCHEMA,
		expectedDiagnosticSchemaSha256: D_SHA,
	})).ok, false);

	const unscannable = await analyze({
		exitCode: 1,
		jsonlBytes: EMPTY, stderrBytes: buf([0xff]),
		outputLastMessageBytes: EMPTY,
	});
	ok(unscannable.reasonCodes.includes("OPENAI_TERRA_ARTIFACT_UTF8_INVALID"));
	equal(unscannable.artifacts.stderr.retention, "WITHHELD_UNSCANNABLE");
	equal(unscannable.validation.sensitiveMaterialAbsent, false);
});

test("a complete bounded mock output is eligible only with one session, one model and no tools", async () => {
	const { jsonl, last } = rt();
	const result = await analyzeOpenAiTerraCliResult({
		...O_BINDING,
		requestedModel: "gpt-5.6-terra", exitCode: 0, signal: null, timedOut: false,
		jsonlBytes: jsonl, stderrBytes: EMPTY, outputLastMessageBytes: last,
	});
	equal(result.receiptEligible, true);
	equal(result.actualModel, "gpt-5.6-terra");
	equal(result.reviewerSessionId, "terra-session-001");
	equal(result.toolCallEventCount, 0);
});

test("tool events, model drift, missing session and final-message mismatch are rejected", async () => {
	const last = buf(json(out()), "utf8");
	for (const event of [
		...TOOL_EVENTS.map((type) => ({ type })),
		...TOOL_ITEMS.map((type) => ({ type: "item.completed", item: { type } })),
	]) {
		const result = await analyze({ jsonlBytes: events(last, [event]) });
		equal(result.receiptEligible, false);
		ok(result.reasonCodes.includes("OPENAI_TERRA_TOOL_EVENT_FORBIDDEN"));
		ok(result.toolCallEventCount > 0);
	}
	const unknown = await analyze({
		jsonlBytes: events(last, [{ type: "future.protocol.event" }]),
	});
	ok(unknown.reasonCodes.includes("OPENAI_TERRA_EVENT_CONTRACT_UNRECOGNIZED"));
	equal(unknown.toolCallEventCount, 0);
	for (const event of [
		{ type: "thread.started", thread_id: "terra-session-001", model: "gpt-5.6-terra", tools: [] },
		{ type: "item.completed", item: { type: "agent_message", text: "safe", tool_call: {} } },
		{ type: "item.completed", item: { type: "agent_message", text: "safe", command: "true" } },
		{ type: "item.completed", item: { type: "reasoning", summary: { tool_call: { name: "shell" } } } },
		{ type: "turn.completed", model: "gpt-5.6-terra", usage: { input_tokens: { tool_call: { name: "shell" } } } },
	]) {
		const rejected = await analyze({ jsonlBytes: events(last, [event]) });
		equal(rejected.receiptEligible, false);
		ok(rejected.reasonCodes.includes("OPENAI_TERRA_EVENT_CONTRACT_UNRECOGNIZED"));
	}
	for (const jsonlBytes of [
		events(last).subarray(0, events(last).lastIndexOf("{")),
		buf('{"type":"exec_command_begin","type":"thread.started","thread_id":"terra-session-001","model":"gpt-5.6-terra"}\n' +
			`${json({ type: "item.completed", item: { type: "agent_message", text: last.toString("utf8") } })}\n` +
			`${json({ type: "turn.completed", model: "gpt-5.6-terra" })}\n`),
	]) {
		const rejected = await analyze({ jsonlBytes });
		equal(rejected.receiptEligible, false);
		ok(rejected.reasonCodes.includes("OPENAI_TERRA_JSONL_INCOMPLETE") ||
			rejected.reasonCodes.includes("OPENAI_TERRA_JSONL_INVALID"));
	}
	equal((await analyze({ outputLastMessageBytes: buf("{}") })).receiptEligible, false);
});

test("caller-authored runtime evidence cannot authorize a Terra Receipt", async () => {
	const callerAuthored = await checkReceipt({
		receiptSchemaBytes: readFileSync(new URL(`${GS}independent-model-review-receipt.v10.schema.json`, repoUrl)),
		receipt: { reviewer: { requestedModel: "gpt-5.6-terra", actualModel: "gpt-5.6-terra", implementationModel: "gpt-5.6-sol" } },
	});
	equal(callerAuthored.ok, false);
	equal(callerAuthored.status, "INCONCLUSIVE");
	ok(callerAuthored.reasonCodes.includes("OPENAI_TERRA_RECEIPT_RUNTIME_AUTHORITY_REQUIRED"));
	const runnerModule = await import("../scripts/run-openai-terra-independent-review.mjs");
	equal(Object.keys(runnerModule).some((name) => /mint|register|issue.*receipt/iu.test(name)), false);
});

test("formal runner cannot be enabled by caller-authored scope or isolation booleans", async () => {
	let calls = 0;
	const blocked = await runReview({
		config: cfg(),
		preflight: { scopeProved: true, isolationProved: false },
		invokeCli: async () => { calls += 1; throw new Error("must not run"); },
	});
	equal(blocked.status, "BLOCKED");
	deepEqual(blocked.reasonCodes, ["OPENAI_TERRA_ISOLATION_NOT_PROVED"]);
	equal(calls, 0);

	const stillBlocked = await runReview({
		config: cfg(),
		preflight: { scopeProved: true, isolationProved: true },
		invokeCli: async () => {
			calls += 1;
			throw new Error("caller-authored proof must not launch Terra");
		},
	});
	equal(stillBlocked.status, "BLOCKED");
	deepEqual(stillBlocked.reasonCodes, ["OPENAI_TERRA_ISOLATION_NOT_PROVED"]);
	equal(calls, 0);
});

test("the real Git builder and Subject validator bind the frozen commit scope end to end", async () => {
	if (process.env.INDEPENDENT_REVIEW_NETWORK_MODE === "DENY_ALL_OFFLINE_ALTERNATIVES") {
		equal(process.env.INDEPENDENT_REVIEW_NETWORK_MODE, "DENY_ALL_OFFLINE_ALTERNATIVES");
		return;
	}
	const sourceCommit = gitBytes(["rev-parse", "HEAD"]).toString("utf8").trim();
	const sourceParent = gitBytes(["rev-parse", "HEAD^"]).toString("utf8").trim();
	const sourceTree = gitBytes(["rev-parse", "HEAD^{tree}"]).toString("utf8").trim();
	const evidenceRoot = await mkdtemp(join(tmpdir(), "openai-terra-builder-test-"));
	try {
		const subject = await buildSubject({
			repoPath: repoFs,
			coverageBase: BASE,
			coreFreezeCommit: CORE_FREEZE,
			sourceCommit,
			sourceParent,
			generatedAt: "2026-08-05T00:00:00.000Z",
			bundleId: "imrb_openai_terra_git_roundtrip_001",
			testEvidenceRoot: evidenceRoot,
		});
		const subjectSchemaBytes = gitBytes(["cat-file", "blob", `${sourceCommit}:${cfg().schemas.subject}`]);
		const validation = await checkSubject({
			subjectBytes: subject.bytes,
			subjectSchemaBytes,
			expectedSubjectSchemaSha256: sha(subjectSchemaBytes),
		});
		equal(validation.ok, true, validation.reasonCodes.join(","));
		equal(validation.parsed.manifest.source.sourceCommit, sourceCommit);
		equal(validation.parsed.manifest.source.sourceParent, sourceParent);
		equal(validation.parsed.manifest.source.sourceTree, sourceTree);
		equal(validation.reviewBundle.reviewedPaths.length, 41);
		equal(validation.reviewBundle.reviewedPaths.some((path) => /(?:kimi|moonshot|k3)/iu.test(path)), false);
		for (const entry of validation.parsed.sections.filter(({ descriptor }) =>
			descriptor.kind === "GIT_BLOB" || descriptor.kind === "USER_AUTHORIZATION_PROMPT")) {
			equal(entry.descriptor.sha256, sha(gitBytes(["cat-file", "blob", `${sourceCommit}:${entry.descriptor.path}`])));
		}
		const patchBytes = gitBytes(["diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", BASE, sourceCommit, "--"]);
		equal(validation.parsed.manifest.source.fullPatchSha256, sha(patchBytes));
		const tampered = buf(subject.bytes);
		tampered[tampered.length - 1] ^= 1;
		equal((await checkSubject({
			subjectBytes: tampered,
			subjectSchemaBytes,
			expectedSubjectSchemaSha256: sha(subjectSchemaBytes),
		})).ok, false);
		await rejects(buildSubject({
			repoPath: repoFs,
			coverageBase: BASE,
			coreFreezeCommit: CORE_FREEZE,
			sourceCommit,
			sourceParent: BASE,
			generatedAt: "2026-08-05T00:00:00.000Z",
			bundleId: "imrb_openai_terra_wrong_parent_001",
			testEvidenceRoot: evidenceRoot,
		}), /Source parent binding is stale/u);
	} finally {
		await rm(evidenceRoot, { recursive: true, force: true });
	}
});

test("scoped subject contains exact current bytes once and excludes K3 evidence bodies", () => {
	const sourceBytes = buf("export const reviewed = true;\n", "utf8");
	const promptPath = `${IR}openai-terra-authorization-prompt.v1.txt`;
	const promptBytes = readFileSync(new URL(promptPath, repoUrl));
	const reviewedPaths = [promptPath, "lib/reviewed.mjs"].sort();
	const sourceRecord = section("GIT_BLOB", "lib/reviewed.mjs", sourceBytes);
	const promptRecord = section("USER_AUTHORIZATION_PROMPT", promptPath, promptBytes);
	const { descriptor: sourceDescriptor } = sourceRecord;
	const { descriptor: promptDescriptor } = promptRecord;
	const reviewBundleValue = {
		reviewedPaths,
		sourceSubjects: [
			{ path: promptDescriptor.path, gitMode: "100644", blobSha256: promptDescriptor.sha256 },
			{ path: sourceDescriptor.path, gitMode: "100644", blobSha256: sourceDescriptor.sha256 },
		].sort(({ path: left }, { path: right }) => left.localeCompare(right)),
		source: { changedPathsDigest: digest.value(reviewedPaths) },
	};
	const reviewBundleBytes = buf(digest.canonicalize(reviewBundleValue), "utf8");
	const reviewBundleRecord = section(
		"PROVIDER_NEUTRAL_REVIEW_BUNDLE", "bundle/review-bundle.v2.json", reviewBundleBytes, {
		bundleId: "imrb_openai_terra_fixture_001",
		bundleSha256: SHA("b"),
		},
	);
	const { descriptor: reviewBundleDescriptor } = reviewBundleRecord;
	const historyReferences = [];
	const built = encodeSubject({
		manifest: {
			schemaVersion: "openai-terra-scoped-review-subject.v1",
			format: "LENGTH_PREFIXED_UTF8_SECTIONS_V1",
			claimBoundary: "CORE_SUBJECT_ONLY_NOT_FULL_REPOSITORY_CLEARANCE",
			source: {
				coverageBase: BASE,
				coreFreezeCommit: CORE_FREEZE,
				sourceCommit: SOURCE,
				sourceParent: PARENT,
				sourceTree: TREE,
				fullPatchByteLength: 123,
				fullPatchSha256: SHA("a"),
			},
			authorizationPrompt: promptDescriptor,
			reviewBundle: reviewBundleDescriptor,
			historyReferences,
			historyReferenceSetSha256: digest.value(historyReferences),
			duplicatePathPolicy: "EACH_REVIEWED_GIT_PATH_EXACTLY_ONCE",
			recursiveK3EvidencePolicy: "REFERENCE_ONLY_NO_MODEL_VISIBLE_BYTES",
		},
		sections: [sourceRecord, promptRecord, reviewBundleRecord],
	});
	const parsed = parseSubject(built.bytes);
	deepEqual(parsed.reviewBundle.reviewedPaths, reviewedPaths);
	equal(new Set(parsed.reviewBundle.reviewedPaths).size, parsed.reviewBundle.reviewedPaths.length);
	equal(parsed.sections.length, parsed.reviewBundle.reviewedPaths.length + 1);
	equal(built.bytes.byteLength <= OPENAI_TERRA_MAX_MODEL_VISIBLE_BYTES, true);
	equal(parsed.manifest.historyReferences.every((entry) => entry.modelVisibleBytes === false), true);
	deepEqual(parsed.manifest.historyReferences, []);
	equal(parsed.sections.some((section) => /kimi-k3.*evidence/iu.test(section.path)), false);

	const recursive = clone(parsed.manifest);
	recursive.historyReferences.push({
		path: "implementation/governance/independent-review/evidence/kimi-history.json",
		commit: SOURCE,
		tree: TREE,
		gitMode: "100644",
		byteLength: 99,
		sha256: SHA("c"),
		historicalDecision: "INCONCLUSIVE",
		governanceEffect: "NONE",
		modelVisibleBytes: true,
	});
	recursive.historyReferenceSetSha256 = digest.value(recursive.historyReferences);
	throws(() => encodeSubject({
		manifest: recursive,
		sections: [sourceRecord, promptRecord, reviewBundleRecord],
	}), /coverage closure/iu);

	throws(() => encodeSubject({
		manifest: parsed.manifest,
		sections: [
			{ descriptor: sourceDescriptor, bytes: buf("tampered", "utf8") },
			{ descriptor: promptDescriptor, bytes: promptBytes },
			{ descriptor: reviewBundleDescriptor, bytes: reviewBundleBytes },
		],
	}), /stale/iu);
});

export async function runOpenAiTerraIndependentReviewCases() {
	for (const { name, execute } of cases) {
		try {
			await execute();
		} catch (error) {
			error.message = `${name}: ${error.message}`;
			throw error;
		}
	}
	return cases.map(({ name }) => name);
}
