import {
  humanDecisionSha256,
} from "./human-decision-workflow.mjs";

export class C15SyntheticEffectAdapterError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C15SyntheticEffectAdapterError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C15SyntheticEffectAdapterError(code, message);
}

function validate(effect) {
  if (
    effect?.tenantKind !== "SYNTHETIC" ||
    effect?.operationId !== "SYNTHETIC_PREVIEW_EFFECT" ||
    effect?.externalEffectCount !== 0 ||
    typeof effect?.effectKey !== "string" ||
    typeof effect?.artifactSha256 !== "string" ||
    typeof effect?.expectedReadbackSha256 !== "string"
  ) {
    fail(
      "SYNTHETIC_BOUNDARY_VIOLATION",
      "C15 adapter accepts only a C0 Synthetic effect.",
    );
  }
}

function appliedBody(effect) {
  return {
    schemaVersion: "c15-synthetic-readback.v1",
    tenantId: effect.tenantId,
    effectKey: effect.effectKey,
    artifactSha256: effect.artifactSha256,
    state: "APPLIED",
  };
}

export function createC15SyntheticEffectAdapter({
  mismatchEffectKeys = new Set(),
  compensationFailureEffectKeys = new Set(),
} = {}) {
  const applied = new Map();
  const compensated = new Set();
  const commitCounts = new Map();

  return Object.freeze({
    async commit(effect) {
      validate(effect);
      if (!applied.has(effect.effectKey)) {
        const body = appliedBody(effect);
        applied.set(effect.effectKey, {
          ...body,
          readbackSha256: humanDecisionSha256(body),
        });
        commitCounts.set(
          effect.effectKey,
          (commitCounts.get(effect.effectKey) ?? 0) + 1,
        );
      }
      return Object.freeze({
        schemaVersion: "c15-synthetic-commit-receipt.v1",
        tenantId: effect.tenantId,
        effectKey: effect.effectKey,
        operationId: effect.operationId,
        committed: true,
        externalEffectCount: 0,
      });
    },

    async readback(effect) {
      validate(effect);
      const value = applied.get(effect.effectKey);
      if (!value || compensated.has(effect.effectKey)) {
        fail("READBACK_NOT_FOUND", "Synthetic effect was not found.");
      }
      return Object.freeze({
        schemaVersion: "c15-synthetic-readback-receipt.v1",
        tenantId: effect.tenantId,
        effectKey: effect.effectKey,
        readbackSha256: mismatchEffectKeys.has(effect.effectKey)
          ? humanDecisionSha256({
              ...appliedBody(effect),
              state: "MISMATCH",
            })
          : value.readbackSha256,
        externalEffectCount: 0,
      });
    },

    async compensate(effect) {
      validate(effect);
      if (compensationFailureEffectKeys.has(effect.effectKey)) {
        fail("COMPENSATION_FAILED", "Synthetic compensation failed.");
      }
      compensated.add(effect.effectKey);
      return Object.freeze({
        schemaVersion: "c15-synthetic-compensation-receipt.v1",
        tenantId: effect.tenantId,
        effectKey: effect.effectKey,
        compensated: true,
        externalEffectCount: 0,
      });
    },

    snapshot() {
      return Object.freeze({
        networkRequestCount: 0,
        enterpriseCredentialCount: 0,
        externalEffectCount: 0,
        appliedEffectKeys: Object.freeze([...applied.keys()].sort()),
        compensatedEffectKeys: Object.freeze([...compensated].sort()),
        commitCounts: Object.freeze(
          Object.fromEntries(
            [...commitCounts.entries()].sort(([left], [right]) =>
              left < right ? -1 : left > right ? 1 : 0,
            ),
          ),
        ),
      });
    },
  });
}
