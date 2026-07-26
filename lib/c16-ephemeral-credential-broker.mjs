import { randomBytes, timingSafeEqual } from "node:crypto";

const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const OPERATION_ID =
  /^synthetic\.(?:approval\.status|erp\.order|bi\.metric)\.get$/;
const SYNTHETIC_TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class C16CredentialBrokerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "C16CredentialBrokerError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C16CredentialBrokerError(code, message);
}

function canonicalInstant(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) ||
    new Date(value).toISOString() !== value
  ) {
    fail("INVALID_CONFIGURATION", "C16 broker clock is invalid.");
  }
  return value;
}

function validateScope(scope) {
  if (
    !scope ||
    typeof scope !== "object" ||
    Array.isArray(scope) ||
    Object.getPrototypeOf(scope) !== Object.prototype ||
    Object.keys(scope).length !== 4 ||
    !SYNTHETIC_TENANT_ID.test(scope.tenantId ?? "") ||
    !OPERATION_ID.test(scope.operationId ?? "") ||
    typeof scope.callId !== "string" ||
    !/^tcl_[0-9a-f-]{36}$/.test(scope.callId) ||
    typeof scope.audience !== "string" ||
    !/^[a-z0-9][a-z0-9-]{0,63}$/.test(scope.audience)
  ) {
    fail(
      "CREDENTIAL_SCOPE_MISMATCH",
      "C16 credential scope is invalid.",
    );
  }
}

function sameText(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

export function createC16EphemeralCredentialBroker({
  clock = () => new Date().toISOString(),
  idFactory,
  ttlSeconds = 15,
}) {
  if (
    typeof clock !== "function" ||
    typeof idFactory !== "function" ||
    !Number.isSafeInteger(ttlSeconds) ||
    ttlSeconds < 1 ||
    ttlSeconds > 30
  ) {
    fail("INVALID_CONFIGURATION", "C16 broker configuration is invalid.");
  }
  const capabilities = new Map();
  let issuedCapabilityCount = 0;

  return Object.freeze({
    issue(scope) {
      validateScope(scope);
      const id = idFactory();
      if (!UUID_V7.test(id)) {
        fail("INVALID_CONFIGURATION", "C16 broker ID is invalid.");
      }
      const issuedAt = canonicalInstant(clock());
      const expiresAt = new Date(
        new Date(issuedAt).getTime() + ttlSeconds * 1000,
      ).toISOString();
      const capability = Object.freeze({
        schemaVersion: "c16-synthetic-opaque-capability.v1",
        capabilityId: `cap_${id}`,
        opaque: randomBytes(32).toString("hex"),
        tenantId: scope.tenantId,
        operationId: scope.operationId,
        callId: scope.callId,
        audience: scope.audience,
        issuedAt,
        expiresAt,
      });
      capabilities.set(capability.capabilityId, {
        capability,
        state: "ACTIVE",
      });
      issuedCapabilityCount += 1;
      return capability;
    },

    assertUsable(capability, expectedScope) {
      validateScope(expectedScope);
      const record = capabilities.get(capability?.capabilityId);
      if (
        !record ||
        capability?.schemaVersion !==
          "c16-synthetic-opaque-capability.v1" ||
        !sameText(record.capability.opaque, capability?.opaque)
      ) {
        fail("INVALID_CREDENTIAL", "C16 capability is invalid.");
      }
      if (record.state !== "ACTIVE") {
        fail("CREDENTIAL_REVOKED", "C16 capability is revoked.");
      }
      const current = new Date(canonicalInstant(clock())).getTime();
      if (current >= new Date(record.capability.expiresAt).getTime()) {
        fail("CREDENTIAL_EXPIRED", "C16 capability expired.");
      }
      for (const field of [
        "tenantId",
        "operationId",
        "callId",
        "audience",
      ]) {
        if (
          record.capability[field] !== expectedScope[field] ||
          capability[field] !== expectedScope[field]
        ) {
          fail(
            "CREDENTIAL_SCOPE_MISMATCH",
            "C16 capability scope changed.",
          );
        }
      }
      return true;
    },

    revoke(capability) {
      const record = capabilities.get(capability?.capabilityId);
      if (
        !record ||
        !sameText(record.capability.opaque, capability?.opaque)
      ) {
        fail("INVALID_CREDENTIAL", "C16 capability is invalid.");
      }
      record.state = "REVOKED";
    },

    snapshot() {
      let activeCapabilityCount = 0;
      let revokedCapabilityCount = 0;
      for (const record of capabilities.values()) {
        if (record.state === "ACTIVE") activeCapabilityCount += 1;
        if (record.state === "REVOKED") revokedCapabilityCount += 1;
      }
      return Object.freeze({
        issuedCapabilityCount,
        activeCapabilityCount,
        revokedCapabilityCount,
      });
    },
  });
}
