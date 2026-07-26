export class C16OutboxWorkerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C16OutboxWorkerError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C16OutboxWorkerError(code, message);
}

export function createC16AuditOutboxWorker({
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
    fail("INVALID_CONFIGURATION", "C16 audit worker is invalid.");
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
            "C18 publisher ACK did not match the C16 intent.",
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
          errorCode:
            typeof error?.code === "string" &&
            /^[A-Z][A-Z0-9_]{0,63}$/.test(error.code)
              ? error.code
              : "AUDIT_PUBLISH_FAILED",
        });
        throw error;
      }
    },
  });
}
