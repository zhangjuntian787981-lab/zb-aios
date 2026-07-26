import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  C14SyntheticModelProviderError,
  createC14SyntheticModelProvider,
  createFileC14ModelReceiptStore,
} from "../lib/c14-synthetic-model-provider.mjs";

const REQUEST = Object.freeze({
  tenantId: "stn_018f0000-0000-7000-8000-000000000011",
  routeId: "mrt_018f0000-0000-7000-8000-000000000101",
  effectKey:
    "effect_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  providerId: "c14-mock-cloud-eu",
  modelRef: "synthetic://c14/models/cloud-eu-quality",
  modelVersion: "1.0.0",
  inputRef: "synthetic://c14/inputs/public-summary",
  inputSha256:
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  maxOutputTokens: 512,
});

test("C14 file receipt survives provider restart without a second effect", async (t) => {
  const rootDir = await mkdtemp(join(tmpdir(), "c14-provider-"));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  const first = createC14SyntheticModelProvider({
    receiptStore: createFileC14ModelReceiptStore({ rootDir }),
  });
  const receipt = await first.invoke(REQUEST);
  assert.equal(first.calls.length, 1);

  const restarted = createC14SyntheticModelProvider({
    receiptStore: createFileC14ModelReceiptStore({ rootDir }),
  });
  assert.deepEqual(await restarted.invoke(REQUEST), receipt);
  assert.equal(restarted.calls.length, 0);
  await assert.rejects(
    restarted.invoke({
      ...REQUEST,
      modelVersion: "2.0.0",
    }),
    (error) =>
      error instanceof C14SyntheticModelProviderError &&
      error.code === "PROVIDER_EFFECT_CONFLICT",
  );
});

test("concurrent C14 provider processes persist one effect", async (t) => {
  const rootDir = await mkdtemp(join(tmpdir(), "c14-provider-race-"));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  const first = createC14SyntheticModelProvider({
    receiptStore: createFileC14ModelReceiptStore({ rootDir }),
  });
  const second = createC14SyntheticModelProvider({
    receiptStore: createFileC14ModelReceiptStore({ rootDir }),
  });
  const [left, right] = await Promise.all([
    first.invoke(REQUEST),
    second.invoke(REQUEST),
  ]);
  assert.deepEqual(left, right);
  assert.equal(first.calls.length + second.calls.length, 1);
});
