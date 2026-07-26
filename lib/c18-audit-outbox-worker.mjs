function fail(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function exactRequest(request) {
  const fields = [
    "workerId",
    "now",
    "leaseExpiresAt",
    "retryAt",
    "limit",
  ];
  if (
    !request ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).sort().join("\u0000") !==
      [...fields].sort().join("\u0000")
  ) {
    fail("INVALID_INPUT", "C18 Outbox Worker request is invalid.");
  }
}

export function createC18AuditOutboxWorker({ store, publisher }) {
  if (
    typeof store?.claimOutbox !== "function" ||
    typeof store?.completeOutbox !== "function" ||
    typeof store?.failOutbox !== "function" ||
    typeof publisher?.publish !== "function"
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C18 Outbox Worker dependencies are invalid.",
    );
  }

  async function runOnce(scope, request) {
    exactRequest(request);
    const claims = await store.claimOutbox(scope, {
      workerId: request.workerId,
      now: request.now,
      leaseExpiresAt: request.leaseExpiresAt,
      limit: request.limit,
    });
    const publishedEventIds = [];
    const requeuedEventIds = [];

    for (const claim of claims) {
      try {
        const acknowledgement = await publisher.publish({
          eventId: claim.eventId,
          event: claim.event,
        });
        if (acknowledgement?.eventId !== claim.eventId) {
          fail(
            "PUBLISH_ACK_INVALID",
            "Publisher acknowledgement does not match the AuditEvent.",
          );
        }
      } catch {
        await store.failOutbox(scope, {
          eventId: claim.eventId,
          workerId: request.workerId,
          leaseVersion: claim.leaseVersion,
          now: request.now,
          retryAt: request.retryAt,
          errorCode: "PUBLISH_FAILED",
        });
        requeuedEventIds.push(claim.eventId);
        continue;
      }

      await store.completeOutbox(scope, {
        eventId: claim.eventId,
        workerId: request.workerId,
        leaseVersion: claim.leaseVersion,
        now: request.now,
      });
      publishedEventIds.push(claim.eventId);
    }

    return Object.freeze({
      claimed: claims.length,
      published: publishedEventIds.length,
      requeued: requeuedEventIds.length,
      publishedEventIds: Object.freeze(publishedEventIds),
      requeuedEventIds: Object.freeze(requeuedEventIds),
    });
  }

  return Object.freeze({ runOnce });
}
