import {
  assertAuditIntentMetadataOnly,
  humanDecisionSha256,
} from "./human-decision-workflow.mjs";

const C18_EVENT_ID =
  /^aev_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;

export class C15C18AuditPublisherError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C15C18AuditPublisherError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C15C18AuditPublisherError(code, message);
}

export function createC15C18AuditPublisher({
  auditEvidenceService,
  resolveBinding,
}) {
  if (
    typeof auditEvidenceService?.append !== "function" ||
    typeof resolveBinding !== "function"
  ) {
    fail("INVALID_CONFIGURATION", "C15 C18 publisher is invalid.");
  }

  return Object.freeze({
    async publish(intent) {
      const metadata = structuredClone(intent);
      delete metadata.intentSha256;
      delete metadata.createdAt;
      assertAuditIntentMetadataOnly(metadata);
      if (
        (intent.intentSha256 !== undefined &&
          intent.intentSha256 !== humanDecisionSha256(metadata)) ||
        (intent.createdAt !== undefined &&
          intent.createdAt !== metadata.occurredAt)
      ) {
        fail(
          "C15_INTENT_INVALID",
          "C15 Audit Intent persistence binding is invalid.",
        );
      }
      const binding = await resolveBinding(metadata);
      if (
        !binding ||
        typeof binding !== "object" ||
        Array.isArray(binding) ||
        Object.keys(binding).sort().join("\u0000") !==
          [
            "evidenceBundleRef",
            "serverContext",
            "sessionToken",
          ].sort().join("\u0000") ||
        binding.serverContext?.tenantId !== metadata.tenantId ||
        binding.serverContext?.workloadActorPrincipalId !==
          metadata.workloadActorPrincipalId ||
        typeof binding.sessionToken !== "string" ||
        !binding.sessionToken ||
        typeof binding.evidenceBundleRef !== "string" ||
        !binding.evidenceBundleRef
      ) {
        fail(
          "C18_BINDING_INVALID",
          "C15 Audit Intent has no registered C18 binding.",
        );
      }
      const event = await auditEvidenceService.append(
        binding.serverContext,
        {
          sessionToken: binding.sessionToken,
          delegationId: metadata.leafDelegationId,
          idempotencyKey: metadata.intentId,
          correlationId: metadata.correlationId,
          evidenceBundleRef: binding.evidenceBundleRef,
        },
      );
      if (
        event?.tenantId !== metadata.tenantId ||
        !C18_EVENT_ID.test(event?.eventId ?? "") ||
        !SHA256.test(event?.eventHash ?? "") ||
        !SHA256.test(event?.payloadSha256 ?? "") ||
        typeof event?.duplicate !== "boolean"
      ) {
        fail(
          "C18_ACK_INVALID",
          "C18 returned an invalid persistence acknowledgement.",
        );
      }
      return Object.freeze({
        schemaVersion: "c15-c18-audit-ack.v1",
        tenantId: metadata.tenantId,
        intentId: metadata.intentId,
        c18CommandReceiptKey: metadata.intentId,
        c18EventId: event.eventId,
        c18EventHash: event.eventHash,
        c18PayloadSha256: event.payloadSha256,
        duplicate: event.duplicate,
      });
    },
  });
}
