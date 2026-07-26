import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  C08MockToolReceiptError,
  createC08C0MockToolReceipts,
  createFileC08MockReceiptStore,
} from "../lib/c08-c0-mock-tool-receipts.mjs";

const EFFECT = Object.freeze({
  tenantId: "stn_018f0000-0000-7000-8000-000000000010",
  runId: "run_018f0000-0000-7000-8000-000000000019",
  toolCallId: "tcl_018f0000-0000-7000-8000-000000000020",
  effectKey:
    "effect_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  requestHash:
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  operationRef: "synthetic://c08/tools/catalog-read",
  operationVersion: "tool-1",
  outcome: "SUCCEEDED",
});

test("C0 Mock receipts bind one effect to one server-verifiable receipt", async () => {
  const mock = createC08C0MockToolReceipts();
  const first = await mock.executor.accept(EFFECT);
  const retry = await mock.executor.accept(EFFECT);
  assert.equal(first.duplicate, false);
  assert.deepEqual(retry, { receiptId: first.receiptId, duplicate: true });

  const receipt = await mock.verifier.resolve({
    receiptId: first.receiptId,
    tenantId: EFFECT.tenantId,
    runId: EFFECT.runId,
    toolCallId: EFFECT.toolCallId,
    effectKey: EFFECT.effectKey,
    requestHash: EFFECT.requestHash,
    operationRef: EFFECT.operationRef,
    operationVersion: EFFECT.operationVersion,
  });
  assert.equal(receipt.trustSource, "VERIFIED_C0_MOCK_TOOL_RECEIPT");
  assert.equal(receipt.outcome, "SUCCEEDED");
  assert.match(receipt.receiptHash, /^sha256:[0-9a-f]{64}$/);
});

test("forged, cross-Tenant and wrong-effect Mock receipts fail closed", async () => {
  const mock = createC08C0MockToolReceipts();
  const { receiptId } = await mock.executor.accept(EFFECT);
  for (const query of [
    {
      receiptId:
        "mrc_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      tenantId: EFFECT.tenantId,
      runId: EFFECT.runId,
      toolCallId: EFFECT.toolCallId,
      effectKey: EFFECT.effectKey,
      requestHash: EFFECT.requestHash,
      operationRef: EFFECT.operationRef,
      operationVersion: EFFECT.operationVersion,
    },
    {
      receiptId,
      tenantId:
        "stn_018f0000-0000-7000-8000-000000000011",
      runId: EFFECT.runId,
      toolCallId: EFFECT.toolCallId,
      effectKey: EFFECT.effectKey,
      requestHash: EFFECT.requestHash,
      operationRef: EFFECT.operationRef,
      operationVersion: EFFECT.operationVersion,
    },
    {
      receiptId,
      tenantId: EFFECT.tenantId,
      runId: EFFECT.runId,
      toolCallId: EFFECT.toolCallId,
      effectKey:
        "effect_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      requestHash: EFFECT.requestHash,
      operationRef: EFFECT.operationRef,
      operationVersion: EFFECT.operationVersion,
    },
  ]) {
    await assert.rejects(
      mock.verifier.resolve(query),
      (error) =>
        error instanceof C08MockToolReceiptError &&
        error.code === "TOOL_RECEIPT_UNVERIFIED",
    );
  }
});

test("a new Mock process reuses the durable effect receipt", async (t) => {
  const rootDir = await mkdtemp(join(tmpdir(), "c08-mock-receipts-"));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  const firstProcess = createC08C0MockToolReceipts({
    store: createFileC08MockReceiptStore({ rootDir }),
  });
  const accepted = await firstProcess.executor.accept(EFFECT);
  assert.equal(accepted.duplicate, false);

  const restartedProcess = createC08C0MockToolReceipts({
    store: createFileC08MockReceiptStore({ rootDir }),
  });
  assert.deepEqual(await restartedProcess.executor.accept(EFFECT), {
    receiptId: accepted.receiptId,
    duplicate: true,
  });
  await assert.rejects(
    restartedProcess.executor.accept({
      ...EFFECT,
      outcome: "FAILED",
    }),
    (error) =>
      error instanceof C08MockToolReceiptError &&
      error.code === "EFFECT_CONFLICT",
  );
});
