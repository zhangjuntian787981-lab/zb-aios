import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  link,
  mkdir,
  open,
  readFile,
  unlink,
} from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

const EFFECT_KEY = /^effect_[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ROUTE_ID =
  /^mrt_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROVIDER_ID = /^c14-mock-[a-z0-9-]+$/;
const MODEL_REF = /^synthetic:\/\/c14\/models\/[a-z0-9-]+$/;
const REFERENCE = /^(?:synthetic|fixture|test|policy):\/\/\S+$/;

export class C14SyntheticModelProviderError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C14SyntheticModelProviderError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C14SyntheticModelProviderError(code, message);
}

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function exactKeys(value, keys, field) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) {
    fail("INVALID_PROVIDER_REQUEST", `${field} is not closed.`);
  }
}

function validateRequest(request) {
  exactKeys(
    request,
    [
      "tenantId",
      "routeId",
      "effectKey",
      "providerId",
      "modelRef",
      "modelVersion",
      "inputRef",
      "inputSha256",
      "maxOutputTokens",
    ],
    "provider request",
  );
  if (
    !SYNTHETIC_TENANT_ID.test(request.tenantId ?? "") ||
    !ROUTE_ID.test(request.routeId ?? "") ||
    !EFFECT_KEY.test(request.effectKey ?? "") ||
    !PROVIDER_ID.test(request.providerId ?? "") ||
    !MODEL_REF.test(request.modelRef ?? "") ||
    typeof request.modelVersion !== "string" ||
    request.modelVersion.length === 0 ||
    request.modelVersion.length > 128 ||
    !REFERENCE.test(request.inputRef ?? "") ||
    !SHA256.test(request.inputSha256 ?? "") ||
    !Number.isSafeInteger(request.maxOutputTokens) ||
    request.maxOutputTokens < 1
  ) {
    fail("INVALID_PROVIDER_REQUEST", "Provider request is invalid.");
  }
}

function buildReceipt(request, failed) {
  const outcome = failed.has(request.providerId) ? "FAILED" : "SUCCEEDED";
  const responseRef =
    outcome === "SUCCEEDED"
      ? `test://c14/provider-results/${request.effectKey.slice(7, 23)}`
      : null;
  const inputTokens =
    outcome === "SUCCEEDED"
      ? Math.max(
          1,
          Math.min(
            256,
            Number.parseInt(request.inputSha256.slice(-4), 16) % 257,
          ),
        )
      : 0;
  const outputTokens =
    outcome === "SUCCEEDED"
      ? Math.min(64, request.maxOutputTokens)
      : 0;
  return Object.freeze({
    trustSource: "C14_C0_MOCK_PROVIDER_RECEIPT",
    effectKey: request.effectKey,
    providerId: request.providerId,
    modelRef: request.modelRef,
    modelVersion: request.modelVersion,
    outcome,
    responseRef,
    responseSha256:
      responseRef === null
        ? null
        : digest(
            JSON.stringify([
              request.effectKey,
              responseRef,
              inputTokens,
              outputTokens,
            ]),
          ),
    inputTokens,
    outputTokens,
    providerRequestId: `mock-${request.effectKey.slice(7, 31)}`,
  });
}

function validateStoredRecord(record) {
  exactKeys(record, ["request", "receipt"], "stored provider record");
  validateRequest(record.request);
  const receipt = record.receipt;
  exactKeys(
    receipt,
    [
      "trustSource",
      "effectKey",
      "providerId",
      "modelRef",
      "modelVersion",
      "outcome",
      "responseRef",
      "responseSha256",
      "inputTokens",
      "outputTokens",
      "providerRequestId",
    ],
    "stored provider receipt",
  );
  const failed = new Set(
    receipt.outcome === "FAILED" ? [record.request.providerId] : [],
  );
  const expected = buildReceipt(record.request, failed);
  if (
    digest(JSON.stringify(receipt)) !==
      digest(JSON.stringify(expected))
  ) {
    fail(
      "PROVIDER_RECEIPT_UNVERIFIED",
      "Stored provider receipt is inconsistent.",
    );
  }
  return Object.freeze({
    request: Object.freeze(structuredClone(record.request)),
    receipt: expected,
  });
}

export function createMemoryC14ModelReceiptStore() {
  const records = new Map();
  return Object.freeze({
    async putIfAbsent(record) {
      const key = record.request.effectKey;
      const existing = records.get(key);
      if (existing) return structuredClone(existing);
      records.set(key, structuredClone(record));
      return null;
    },
    async getByEffectKey(effectKey) {
      return structuredClone(records.get(effectKey) ?? null);
    },
  });
}

export function createFileC14ModelReceiptStore({ rootDir }) {
  if (
    typeof rootDir !== "string" ||
    !isAbsolute(rootDir) ||
    resolve(rootDir) === "/"
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "Provider receipt root must be a dedicated absolute directory.",
    );
  }
  const resolvedRoot = resolve(rootDir);

  async function prepareRoot() {
    await mkdir(resolvedRoot, { recursive: true, mode: 0o700 });
    const stat = await lstat(resolvedRoot);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail(
        "INVALID_CONFIGURATION",
        "Provider receipt root is not a dedicated directory.",
      );
    }
  }

  function recordPath(effectKey) {
    if (!EFFECT_KEY.test(effectKey ?? "")) {
      fail("INVALID_PROVIDER_REQUEST", "Provider effect key is invalid.");
    }
    return join(resolvedRoot, `${effectKey}.json`);
  }

  async function readRecord(path) {
    try {
      return validateStoredRecord(
        JSON.parse(await readFile(path, "utf8")),
      );
    } catch (error) {
      if (error instanceof C14SyntheticModelProviderError) throw error;
      if (error?.code === "ENOENT") return null;
      fail(
        "PROVIDER_RECEIPT_UNVERIFIED",
        "Stored provider receipt cannot be read.",
      );
    }
  }

  return Object.freeze({
    async putIfAbsent(record) {
      await prepareRoot();
      const finalPath = recordPath(record.request.effectKey);
      const temporaryPath = join(
        resolvedRoot,
        `.${record.request.effectKey}.${randomUUID()}.tmp`,
      );
      let temporary;
      try {
        temporary = await open(temporaryPath, "wx", 0o600);
        await temporary.writeFile(JSON.stringify(record), "utf8");
        await temporary.sync();
        await temporary.close();
        temporary = null;
        try {
          await link(temporaryPath, finalPath);
          const directory = await open(resolvedRoot, "r");
          try {
            await directory.sync();
          } finally {
            await directory.close();
          }
          return null;
        } catch (error) {
          if (error?.code !== "EEXIST") throw error;
          return await readRecord(finalPath);
        }
      } finally {
        if (temporary) await temporary.close().catch(() => {});
        await unlink(temporaryPath).catch((error) => {
          if (error?.code !== "ENOENT") throw error;
        });
      }
    },
    async getByEffectKey(effectKey) {
      await prepareRoot();
      return readRecord(recordPath(effectKey));
    },
  });
}

export function createC14SyntheticModelProvider({
  failedProviderIds = [],
  receiptStore = createMemoryC14ModelReceiptStore(),
} = {}) {
  if (
    !Array.isArray(failedProviderIds) ||
    failedProviderIds.some((value) => !PROVIDER_ID.test(value)) ||
    typeof receiptStore?.putIfAbsent !== "function" ||
    typeof receiptStore?.getByEffectKey !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "Provider configuration is invalid.");
  }
  const calls = [];
  const failed = new Set(failedProviderIds);

  return Object.freeze({
    calls,
    async invoke(request) {
      validateRequest(request);
      const existing = await receiptStore.getByEffectKey(
        request.effectKey,
      );
      if (existing) {
        const verified = validateStoredRecord(existing);
        if (
          digest(JSON.stringify(verified.request)) !==
          digest(JSON.stringify(request))
        ) {
          fail(
            "PROVIDER_EFFECT_CONFLICT",
            "Provider effect key has different content.",
          );
        }
        return structuredClone(verified.receipt);
      }

      const record = Object.freeze({
        request: Object.freeze(structuredClone(request)),
        receipt: buildReceipt(request, failed),
      });
      const raced = await receiptStore.putIfAbsent(record);
      if (raced) {
        const verified = validateStoredRecord(raced);
        if (
          digest(JSON.stringify(verified.request)) !==
          digest(JSON.stringify(request))
        ) {
          fail(
            "PROVIDER_EFFECT_CONFLICT",
            "Provider effect key has different content.",
          );
        }
        return structuredClone(verified.receipt);
      }
      calls.push(structuredClone(request));
      return structuredClone(record.receipt);
    },
  });
}
