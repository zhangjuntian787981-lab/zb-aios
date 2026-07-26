import { createHash } from "node:crypto";

function digest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function createC14SyntheticModelProvider({
  failedProviderIds = [],
} = {}) {
  const receipts = new Map();
  const calls = [];
  const failed = new Set(failedProviderIds);

  return Object.freeze({
    calls,
    async invoke(request) {
      const existing = receipts.get(request.effectKey);
      if (existing) return structuredClone(existing);
      calls.push(structuredClone(request));
      const outcome = failed.has(request.providerId)
        ? "FAILED"
        : "SUCCEEDED";
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
                Number.parseInt(request.inputSha256.slice(-4), 16) %
                  257,
              ),
            )
          : 0;
      const outputTokens =
        outcome === "SUCCEEDED"
          ? Math.min(64, request.maxOutputTokens)
          : 0;
      const receipt = Object.freeze({
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
      receipts.set(request.effectKey, receipt);
      return structuredClone(receipt);
    },
  });
}
