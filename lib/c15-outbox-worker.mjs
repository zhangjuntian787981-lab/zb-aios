import {
  createC15EffectOutcomeAuditIntent,
} from "./human-decision-workflow.mjs";

export class C15OutboxWorkerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C15OutboxWorkerError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C15OutboxWorkerError(code, message);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

export function createC15EffectOutboxWorker({
  store,
  adapter,
  workerId,
  leaseDurationSeconds = 30,
  retryDelaySeconds = 1,
  clock = () => new Date().toISOString(),
  idFactory,
}) {
  if (
    typeof store?.claimEffects !== "function" ||
    typeof store?.completeEffect !== "function" ||
    typeof store?.failEffect !== "function" ||
    typeof adapter?.commit !== "function" ||
    typeof adapter?.readback !== "function" ||
    typeof adapter?.compensate !== "function" ||
    typeof workerId !== "string" ||
    !workerId
  ) {
    fail("INVALID_CONFIGURATION", "C15 effect worker is invalid.");
  }

  return Object.freeze({
    async runOnce(scope) {
      const claimed = await store.claimEffects(scope, {
        workerId,
        limit: 1,
        leaseDurationSeconds,
      });
      if (claimed.length === 0) return null;
      const item = claimed[0];
      const effect = deepFreeze(structuredClone(item.effect));
      try {
        const commitReceipt = await adapter.commit(effect);
        const readbackReceipt = await adapter.readback(effect);
        let terminalStatus = "SUCCEEDED";
        let compensationReceipt = null;
        if (
          readbackReceipt.readbackSha256 !==
          effect.expectedReadbackSha256
        ) {
          try {
            compensationReceipt = await adapter.compensate(effect);
            terminalStatus = "COMPENSATED";
          } catch (error) {
            compensationReceipt = {
              schemaVersion: "c15-compensation-failure.v1",
              tenantId: effect.tenantId,
              effectKey: effect.effectKey,
              errorCode: error?.code ?? "COMPENSATION_FAILED",
              externalEffectCount: 0,
            };
            terminalStatus = "COMPENSATION_FAILED";
          }
        }
        const occurredAt = clock();
        const auditIntent = createC15EffectOutcomeAuditIntent({
          effect,
          terminalStatus,
          identityBinding: effect.executionIdentity,
          authorization: effect.executionAuthorization,
          correlationId: scope.correlationId,
          occurredAt,
          ...(idFactory ? { idFactory } : {}),
        });
        return await store.completeEffect(scope, {
          effectId: item.effectId,
          workerId,
          leaseVersion: item.leaseVersion,
          terminalStatus,
          commitReceipt,
          readbackReceipt,
          compensationReceipt,
          auditIntent,
        });
      } catch (error) {
        await store.failEffect(scope, {
          effectId: item.effectId,
          workerId,
          leaseVersion: item.leaseVersion,
          retryDelaySeconds,
          errorCode: error?.code ?? "SYNTHETIC_EFFECT_FAILED",
        });
        throw error;
      }
    },
  });
}

export function createC15AuditOutboxWorker({
  store,
  c18Publisher,
  workerId,
  leaseDurationSeconds = 30,
  retryDelaySeconds = 1,
}) {
  if (
    typeof store?.claimAudit !== "function" ||
    typeof store?.completeAudit !== "function" ||
    typeof store?.failAudit !== "function" ||
    typeof c18Publisher?.publish !== "function" ||
    typeof workerId !== "string" ||
    !workerId
  ) {
    fail("INVALID_CONFIGURATION", "C15 audit worker is invalid.");
  }

  return Object.freeze({
    async runOnce(scope) {
      const claimed = await store.claimAudit(scope, {
        workerId,
        limit: 1,
        leaseDurationSeconds,
      });
      if (claimed.length === 0) return null;
      const item = claimed[0];
      try {
        const ack = await c18Publisher.publish(item.intent);
        if (ack?.intentId !== item.intentId) {
          fail(
            "AUDIT_ACK_MISMATCH",
            "C18 publisher ACK did not match the C15 intent.",
          );
        }
        return await store.completeAudit(scope, {
          intentId: item.intentId,
          workerId,
          leaseVersion: item.leaseVersion,
          ackIntentId: ack.intentId,
        });
      } catch (error) {
        await store.failAudit(scope, {
          intentId: item.intentId,
          workerId,
          leaseVersion: item.leaseVersion,
          retryDelaySeconds,
          errorCode: error?.code ?? "AUDIT_PUBLISH_FAILED",
        });
        throw error;
      }
    },
  });
}
