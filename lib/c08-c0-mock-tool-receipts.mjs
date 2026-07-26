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

const UUID_V7 =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const TENANT_ID = new RegExp(`^stn_${UUID_V7}$`);
const RUN_ID = new RegExp(`^run_${UUID_V7}$`);
const TOOL_CALL_ID = new RegExp(`^tcl_${UUID_V7}$`);
const EFFECT_KEY = /^effect_[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RECEIPT_ID = /^mrc_[0-9a-f]{64}$/;
const OUTCOMES = new Set(["SUCCEEDED", "FAILED"]);

export class C08MockToolReceiptError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C08MockToolReceiptError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C08MockToolReceiptError(code, message);
}

function exactKeys(value, keys, field) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) {
    fail("INVALID_MOCK_RECEIPT", `${field} is not closed.`);
  }
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("INVALID_MOCK_RECEIPT", "Mock receipt value is invalid.");
}

function sha256(value) {
  return `sha256:${createHash("sha256")
    .update(typeof value === "string" ? value : canonicalize(value))
    .digest("hex")}`;
}

function validateEffect(effect) {
  exactKeys(
    effect,
    [
      "tenantId",
      "runId",
      "toolCallId",
      "effectKey",
      "requestHash",
      "operationRef",
      "operationVersion",
      "outcome",
    ],
    "Mock effect",
  );
  if (
    !TENANT_ID.test(effect.tenantId ?? "") ||
    !RUN_ID.test(effect.runId ?? "") ||
    !TOOL_CALL_ID.test(effect.toolCallId ?? "") ||
    !EFFECT_KEY.test(effect.effectKey ?? "") ||
    !SHA256.test(effect.requestHash ?? "") ||
    typeof effect.operationRef !== "string" ||
    !effect.operationRef.startsWith("synthetic://") ||
    typeof effect.operationVersion !== "string" ||
    !effect.operationVersion ||
    !OUTCOMES.has(effect.outcome)
  ) {
    fail("INVALID_MOCK_RECEIPT", "Mock effect is invalid.");
  }
}

function buildRecord(effect) {
  const frozenEffect = structuredClone(effect);
  const receiptId = `mrc_${sha256(frozenEffect).slice(7)}`;
  const receiptRef = `test://c08/c0-mock-receipts/${receiptId}`;
  const receipt = Object.freeze({
    trustSource: "VERIFIED_C0_MOCK_TOOL_RECEIPT",
    receiptId,
    tenantId: effect.tenantId,
    runId: effect.runId,
    toolCallId: effect.toolCallId,
    effectKey: effect.effectKey,
    requestHash: effect.requestHash,
    operationRef: effect.operationRef,
    operationVersion: effect.operationVersion,
    outcome: effect.outcome,
    receiptRef,
    receiptHash: sha256({
      receiptId,
      tenantId: effect.tenantId,
      runId: effect.runId,
      toolCallId: effect.toolCallId,
      effectKey: effect.effectKey,
      requestHash: effect.requestHash,
      operationRef: effect.operationRef,
      operationVersion: effect.operationVersion,
      outcome: effect.outcome,
      receiptRef,
    }),
  });
  return Object.freeze({
    effect: Object.freeze(frozenEffect),
    receipt,
  });
}

function validateStoredRecord(value) {
  validateEffect(value?.effect);
  const expected = buildRecord(value.effect);
  if (sha256(value) !== sha256(expected)) {
    fail(
      "TOOL_RECEIPT_UNVERIFIED",
      "Stored Mock receipt is inconsistent.",
    );
  }
  return expected;
}

export function createMemoryC08MockReceiptStore() {
  const records = new Map();
  return Object.freeze({
    async putIfAbsent(record) {
      const existing = records.get(record.effect.effectKey);
      if (existing) return structuredClone(existing);
      records.set(record.effect.effectKey, structuredClone(record));
      return null;
    },
    async getByEffectKey(effectKey) {
      return structuredClone(records.get(effectKey) ?? null);
    },
  });
}

export function createFileC08MockReceiptStore({ rootDir }) {
  if (
    typeof rootDir !== "string" ||
    !isAbsolute(rootDir) ||
    resolve(rootDir) === "/"
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "Mock receipt root must be a dedicated absolute directory.",
    );
  }
  const resolvedRoot = resolve(rootDir);

  async function prepareRoot() {
    await mkdir(resolvedRoot, { recursive: true, mode: 0o700 });
    const stat = await lstat(resolvedRoot);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail(
        "INVALID_CONFIGURATION",
        "Mock receipt root is not a dedicated directory.",
      );
    }
  }

  function recordPath(effectKey) {
    if (!EFFECT_KEY.test(effectKey ?? "")) {
      fail("INVALID_MOCK_RECEIPT", "Mock effect key is invalid.");
    }
    return join(resolvedRoot, `${effectKey}.json`);
  }

  async function readRecord(path) {
    try {
      return validateStoredRecord(
        JSON.parse(await readFile(path, "utf8")),
      );
    } catch (error) {
      if (error instanceof C08MockToolReceiptError) throw error;
      if (error?.code === "ENOENT") return null;
      fail(
        "TOOL_RECEIPT_UNVERIFIED",
        "Stored Mock receipt cannot be read.",
      );
    }
  }

  return Object.freeze({
    async putIfAbsent(record) {
      await prepareRoot();
      const finalPath = recordPath(record.effect.effectKey);
      const temporaryPath = join(
        resolvedRoot,
        `.${record.effect.effectKey}.${process.pid}.${randomUUID()}.tmp`,
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

export function createC08C0MockToolReceipts({
  store = createMemoryC08MockReceiptStore(),
} = {}) {
  if (
    typeof store?.putIfAbsent !== "function" ||
    typeof store?.getByEffectKey !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "Mock receipt Store is incomplete.");
  }

  const executor = Object.freeze({
    async accept(effect) {
      validateEffect(effect);
      const record = buildRecord(effect);
      const existing = await store.putIfAbsent(record);
      if (existing) {
        const verified = validateStoredRecord(existing);
        if (sha256(verified.effect) !== sha256(record.effect)) {
          fail(
            "EFFECT_CONFLICT",
            "Mock effect key was reused with different content.",
          );
        }
        return Object.freeze({
          receiptId: verified.receipt.receiptId,
          duplicate: true,
        });
      }
      return Object.freeze({
        receiptId: record.receipt.receiptId,
        duplicate: false,
      });
    },
  });

  const verifier = Object.freeze({
    async resolve(query) {
      exactKeys(
        query,
        [
          "receiptId",
          "tenantId",
          "runId",
          "toolCallId",
          "effectKey",
          "requestHash",
          "operationRef",
          "operationVersion",
        ],
        "Mock receipt query",
      );
      if (
        !RECEIPT_ID.test(query.receiptId ?? "") ||
        !EFFECT_KEY.test(query.effectKey ?? "")
      ) {
        fail("TOOL_RECEIPT_UNVERIFIED", "Mock receipt is not verified.");
      }
      const stored = await store.getByEffectKey(query.effectKey);
      const receipt = stored
        ? validateStoredRecord(stored).receipt
        : null;
      if (
        !receipt ||
        receipt.receiptId !== query.receiptId ||
        receipt.tenantId !== query.tenantId ||
        receipt.runId !== query.runId ||
        receipt.toolCallId !== query.toolCallId ||
        receipt.effectKey !== query.effectKey ||
        receipt.requestHash !== query.requestHash ||
        receipt.operationRef !== query.operationRef ||
        receipt.operationVersion !== query.operationVersion
      ) {
        fail("TOOL_RECEIPT_UNVERIFIED", "Mock receipt is not verified.");
      }
      return receipt;
    },
  });

  return Object.freeze({ executor, verifier });
}
