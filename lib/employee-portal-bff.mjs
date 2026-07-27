const SYNTHETIC_TENANT =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REFERENCE =
  /^(?:evidence|quarantine|synthetic):\/\/[A-Za-z0-9][A-Za-z0-9._~:/-]*$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RESOURCE_ID = /^c01-[a-z0-9-]{1,123}$/;
const READ_FIELDS = Object.freeze({
  PORTAL_HOME_VIEW: Object.freeze(["panelRef", "status"]),
  THREAD_VIEW: Object.freeze([
    "threadRef",
    "titleRef",
    "status",
    "ownerPrincipalId",
  ]),
  RUN_VIEW: Object.freeze([
    "runRef",
    "status",
    "streamRef",
    "ownerPrincipalId",
  ]),
  FILE_STATUS_VIEW: Object.freeze([
    "fileRef",
    "status",
    "quarantineRef",
    "contentSha256",
    "ownerPrincipalId",
  ]),
  RESOURCE_DIRECTORY_VIEW: Object.freeze([
    "resourceRef",
    "resourceType",
    "titleRef",
    "evidenceRef",
  ]),
  AGENT_SKILL_DIRECTORY_VIEW: Object.freeze([
    "resourceRef",
    "resourceType",
    "titleRef",
    "releaseChannel",
    "contentSha256",
    "evidenceRef",
  ]),
  MEMORY_VIEW: Object.freeze([
    "memoryRef",
    "status",
    "contentSha256",
    "ownerPrincipalId",
  ]),
  APPROVAL_VIEW: Object.freeze([
    "approvalRef",
    "status",
    "artifactRef",
    "artifactSha256",
    "ownerPrincipalId",
  ]),
  CITATION_VIEW: Object.freeze([
    "evidenceRef",
    "resourceRef",
    "locatorRef",
    "titleRef",
    "status",
    "reasonCode",
    "ownerPrincipalId",
  ]),
});
const PRIVATE_READS = new Set([
  "THREAD_VIEW",
  "RUN_VIEW",
  "FILE_STATUS_VIEW",
  "MEMORY_VIEW",
  "APPROVAL_VIEW",
  "CITATION_VIEW",
]);
const WRITE_STATUSES = Object.freeze({
  THREAD_CREATE: "CREATED",
  CHAT_SUBMIT: "ACCEPTED",
  FILE_QUARANTINE_REQUEST: "QUARANTINED",
  MEMORY_CONFIRM: "RECORDED",
  APPROVAL_DECIDE: "RECORDED",
});
const STREAM_EVENT_TYPES = new Set([
  "RUN_STATUS",
  "CONTENT_DELTA_REF",
  "CITATION_REF",
  "COMPLETED",
  "FAILED",
]);
const TERMINAL_STREAM_EVENT_TYPES = new Set(["COMPLETED", "FAILED"]);
const CITATION_UNAVAILABLE_REASONS = new Set([
  "EVIDENCE_NOT_FOUND",
  "EVIDENCE_MISMATCH",
  "SOURCE_NOT_CURRENT",
  "ACCESS_DENIED",
  "DEPENDENCY_UNAVAILABLE",
]);
const DEFAULT_STREAM_TIMEOUT_MS = 30_000;

export class EmployeePortalBffError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "EmployeePortalBffError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new EmployeePortalBffError(code, message);
}

function clone(value) {
  return structuredClone(value);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return value;
  }
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function exactKeys(value, allowed, field) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== allowed.length ||
    Object.keys(value).some((key) => !allowed.includes(key))
  ) {
    fail("INVALID_INPUT", `${field} has an invalid shape.`);
  }
}

function nonEmpty(value, field, max = 256) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > max
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function reference(value, field) {
  nonEmpty(value, field, 1024);
  if (!REFERENCE.test(value)) {
    fail("SYNTHETIC_BOUNDARY_VIOLATION", `${field} is not Synthetic.`);
  }
}

function validateContext(context) {
  exactKeys(
    context,
    [
      "synthetic",
      "routeTrustSource",
      "tenantId",
      "workloadTrustSource",
      "workloadActorPrincipalId",
    ],
    "serverContext",
  );
  if (
    context.synthetic !== true ||
    context.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR" ||
    context.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT" ||
    !SYNTHETIC_TENANT.test(context.tenantId) ||
    typeof context.workloadActorPrincipalId !== "string" ||
    context.workloadActorPrincipalId.length < 1
  ) {
    fail("UNTRUSTED_ROUTE", "C01 requires a trusted Synthetic route.");
  }
}

function validateCommonRequest(request) {
  nonEmpty(request.sessionToken, "sessionToken", 4096);
  nonEmpty(request.delegationId, "delegationId", 128);
  nonEmpty(request.correlationId, "correlationId", 128);
  if (!RESOURCE_ID.test(request.resourceId ?? "")) {
    fail("INVALID_INPUT", "resourceId is invalid.");
  }
}

function validateReadRequest(request) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "correlationId",
      "operationId",
      "resourceId",
    ],
    "request",
  );
  validateCommonRequest(request);
  if (!Object.hasOwn(READ_FIELDS, request.operationId)) {
    fail("OPERATION_NOT_ALLOWED", "C01 read operation is not allowed.");
  }
}

function validateStreamRequest(request) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "correlationId",
      "operationId",
      "resourceId",
    ],
    "request",
  );
  validateCommonRequest(request);
  if (request.operationId !== "RUN_STREAM_VIEW") {
    fail("OPERATION_NOT_ALLOWED", "C01 stream operation is not allowed.");
  }
}

function validateAbortSignal(value, field) {
  if (
    value !== undefined &&
    (typeof value?.aborted !== "boolean" ||
      typeof value?.addEventListener !== "function" ||
      typeof value?.removeEventListener !== "function")
  ) {
    fail("INVALID_INPUT", `${field} is invalid.`);
  }
}

function validateStreamControl(value) {
  if (value === undefined) {
    return Object.freeze({
      cancelSignal: undefined,
      disconnectSignal: undefined,
    });
  }
  exactKeys(
    value,
    ["cancelSignal", "disconnectSignal"],
    "streamControl",
  );
  validateAbortSignal(value.cancelSignal, "streamControl.cancelSignal");
  validateAbortSignal(
    value.disconnectSignal,
    "streamControl.disconnectSignal",
  );
  return value;
}

function validateMutationRequest(request) {
  exactKeys(
    request,
    [
      "sessionToken",
      "delegationId",
      "correlationId",
      "idempotencyKey",
      "operationId",
      "resourceId",
      "expectedVersion",
      "commandRef",
      "commandSha256",
    ],
    "request",
  );
  validateCommonRequest(request);
  nonEmpty(request.idempotencyKey, "idempotencyKey", 128);
  if (!Object.hasOwn(WRITE_STATUSES, request.operationId)) {
    fail("OPERATION_NOT_ALLOWED", "C01 write operation is not allowed.");
  }
  if (
    !Number.isSafeInteger(request.expectedVersion) ||
    request.expectedVersion < 1
  ) {
    fail("INVALID_INPUT", "expectedVersion is invalid.");
  }
  reference(request.commandRef, "commandRef");
  if (!SHA256.test(request.commandSha256 ?? "")) {
    fail("INVALID_INPUT", "commandSha256 is invalid.");
  }
}

function createStreamLifecycle(control, timeoutMs) {
  const controller = new AbortController();
  const stop = (code, message) => {
    if (!controller.signal.aborted) {
      controller.abort(new EmployeePortalBffError(code, message));
    }
  };
  const onCancel = () =>
    stop("STREAM_CANCELLED", "C01 stream was cancelled.");
  const onDisconnect = () =>
    stop(
      "CLIENT_DISCONNECTED",
      "C01 stream client disconnected.",
    );

  control.cancelSignal?.addEventListener("abort", onCancel, {
    once: true,
  });
  control.disconnectSignal?.addEventListener(
    "abort",
    onDisconnect,
    { once: true },
  );
  if (control.cancelSignal?.aborted) onCancel();
  if (control.disconnectSignal?.aborted) onDisconnect();

  const timeout = setTimeout(
    () =>
      stop(
        "STREAM_TIMEOUT",
        "C01 stream exceeded the server timeout.",
      ),
    timeoutMs,
  );
  timeout.unref?.();
  const aborted = new Promise((_, reject) => {
    if (controller.signal.aborted) {
      reject(controller.signal.reason);
      return;
    }
    controller.signal.addEventListener(
      "abort",
      () => reject(controller.signal.reason),
      { once: true },
    );
  });

  return Object.freeze({
    signal: controller.signal,
    aborted,
    stop,
    dispose() {
      clearTimeout(timeout);
      control.cancelSignal?.removeEventListener(
        "abort",
        onCancel,
      );
      control.disconnectSignal?.removeEventListener(
        "abort",
        onDisconnect,
      );
    },
  });
}

async function authorize(authorizer, context, request, mode) {
  const operationId = `C01_${request.operationId}`;
  const surface = mode === "READ" ? "READ" : "MANAGE";
  let result;
  try {
    result = await authorizer.enforce(
      context,
      {
        sessionToken: request.sessionToken,
        delegationId: request.delegationId,
        correlationId: request.correlationId,
        resourceId: request.resourceId,
      },
      {
        operationId,
        surface,
        path: "employee-portal",
        mode,
      },
    );
  } catch {
    fail("ACCESS_DENIED", "C01 authorization failed closed.");
  }
  exactKeys(
    result,
    [
      "trustSource",
      "tenantId",
      "humanPrincipalId",
      "workloadActorPrincipalId",
      "decisionId",
      "evidenceRef",
      "policyVersion",
      "resourceId",
      "operationId",
    ],
    "authorization",
  );
  if (
    result.trustSource !== "C06_BOUND_DECISION_EVIDENCE" ||
    result.tenantId !== context.tenantId ||
    result.workloadActorPrincipalId !==
      context.workloadActorPrincipalId ||
    result.resourceId !== request.resourceId ||
    result.operationId !== operationId
  ) {
    fail("ACCESS_DENIED", "C01 authorization is unbound.");
  }
  for (const field of [
    "humanPrincipalId",
    "decisionId",
    "evidenceRef",
    "policyVersion",
  ]) {
    nonEmpty(result[field], `authorization.${field}`, 1024);
  }
  reference(result.evidenceRef, "authorization.evidenceRef");
  return deepFreeze({
    tenantId: result.tenantId,
    humanPrincipalId: result.humanPrincipalId,
    workloadActorPrincipalId: result.workloadActorPrincipalId,
    decisionId: result.decisionId,
    evidenceRef: result.evidenceRef,
    policyVersion: result.policyVersion,
    correlationId: request.correlationId,
  });
}

function validateItem(item, operationId, scope) {
  exactKeys(item, READ_FIELDS[operationId], "view.item");
  for (const [field, value] of Object.entries(item)) {
    if (field.endsWith("Ref")) {
      reference(value, `view.item.${field}`);
    } else if (field.endsWith("Sha256")) {
      if (!SHA256.test(value ?? "")) {
        fail("CORE_RESULT_INVALID", `view.item.${field} is invalid.`);
      }
    } else {
      nonEmpty(value, `view.item.${field}`, 256);
    }
  }
  if (
    PRIVATE_READS.has(operationId) &&
    item.ownerPrincipalId !== scope.humanPrincipalId
  ) {
    fail("CORE_RESULT_INVALID", "C01 private view is cross-user.");
  }
  if (
    operationId === "FILE_STATUS_VIEW" &&
    (item.status !== "QUARANTINED" ||
      !item.quarantineRef.startsWith(
        `quarantine://c10/${scope.tenantId}/`,
      ))
  ) {
    fail("CORE_RESULT_INVALID", "C01 file view is not quarantined.");
  }
  if (operationId === "CITATION_VIEW") {
    const available =
      item.status === "AVAILABLE" &&
      item.reasonCode === "CURRENT_AUTHORIZED_SOURCE" &&
      item.evidenceRef.startsWith("evidence://c11/") &&
      item.resourceRef.startsWith("synthetic://c10/") &&
      item.locatorRef.startsWith("synthetic://c10/") &&
      item.titleRef.startsWith("synthetic://c10/");
    const unavailable =
      item.status === "UNAVAILABLE" &&
      CITATION_UNAVAILABLE_REASONS.has(item.reasonCode) &&
      item.evidenceRef.startsWith("evidence://c11/") &&
      item.resourceRef.startsWith(
        "synthetic://c01/citation-unavailable/",
      ) &&
      item.locatorRef.startsWith(
        "synthetic://c01/citation-unavailable/",
      ) &&
      item.titleRef.startsWith(
        "synthetic://c01/citation-unavailable/",
      );
    if (!available && !unavailable) {
      fail(
        "CORE_RESULT_INVALID",
        "C01 citation availability is invalid.",
      );
    }
  }
}

function validateView(value, scope, request) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "tenantId",
      "operationId",
      "resourceId",
      "resourceVersion",
      "items",
      "evidenceRefs",
    ],
    "view",
  );
  if (
    value.schemaVersion !== "c01-portal-view.v1" ||
    value.tenantId !== scope.tenantId ||
    value.operationId !== request.operationId ||
    value.resourceId !== request.resourceId ||
    !Number.isSafeInteger(value.resourceVersion) ||
    value.resourceVersion < 1 ||
    !Array.isArray(value.items) ||
    !Array.isArray(value.evidenceRefs) ||
    value.evidenceRefs.length < 1
  ) {
    fail("CORE_RESULT_INVALID", "C01 Core view is unbound.");
  }
  value.items.forEach((item) =>
    validateItem(item, request.operationId, scope),
  );
  value.evidenceRefs.forEach((item) =>
    reference(item, "view.evidenceRef"),
  );
}

function validateMutationReceipt(value, scope, request) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "tenantId",
      "operationId",
      "resourceId",
      "resourceVersion",
      "commandRef",
      "commandSha256",
      "status",
      "resultRef",
      "ownerPrincipalId",
      "evidenceRefs",
      "auditRef",
    ],
    "receipt",
  );
  if (
    value.schemaVersion !== "c01-portal-mutation-receipt.v1" ||
    value.tenantId !== scope.tenantId ||
    value.operationId !== request.operationId ||
    value.resourceId !== request.resourceId ||
    value.resourceVersion !== request.expectedVersion + 1 ||
    value.commandRef !== request.commandRef ||
    value.commandSha256 !== request.commandSha256 ||
    value.status !== WRITE_STATUSES[request.operationId] ||
    value.ownerPrincipalId !== scope.humanPrincipalId ||
    !Array.isArray(value.evidenceRefs) ||
    value.evidenceRefs.length < 1 ||
    !/^evidence:\/\/c18\//.test(value.auditRef ?? "")
  ) {
    fail("CORE_RESULT_INVALID", "C01 Core receipt is unbound.");
  }
  reference(value.resultRef, "receipt.resultRef");
  reference(value.auditRef, "receipt.auditRef");
  value.evidenceRefs.forEach((item) =>
    reference(item, "receipt.evidenceRef"),
  );
  if (
    request.operationId === "FILE_QUARANTINE_REQUEST" &&
    !value.resultRef.startsWith(
      `quarantine://c10/${scope.tenantId}/`,
    )
  ) {
    fail("CORE_RESULT_INVALID", "C01 file did not enter quarantine.");
  }
}

function validateStreamEvent(value, scope, request, sequence) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "tenantId",
      "resourceId",
      "sequence",
      "eventType",
      "dataRef",
      "evidenceRefs",
      "ownerPrincipalId",
    ],
    "stream.event",
  );
  if (
    value.schemaVersion !== "c01-portal-stream-event.v1" ||
    value.tenantId !== scope.tenantId ||
    value.resourceId !== request.resourceId ||
    value.sequence !== sequence ||
    !STREAM_EVENT_TYPES.has(value.eventType) ||
    value.ownerPrincipalId !== scope.humanPrincipalId ||
    !Array.isArray(value.evidenceRefs) ||
    value.evidenceRefs.length < 1
  ) {
    fail("CORE_RESULT_INVALID", "C01 stream event is unbound.");
  }
  reference(value.dataRef, "stream.dataRef");
  value.evidenceRefs.forEach((item) =>
    reference(item, "stream.evidenceRef"),
  );
}

export function createEmployeePortalBff({
  authorizer,
  corePort,
  streamTimeoutMs = DEFAULT_STREAM_TIMEOUT_MS,
}) {
  if (
    typeof authorizer?.enforce !== "function" ||
    typeof corePort?.read !== "function" ||
    typeof corePort?.mutate !== "function" ||
    typeof corePort?.stream !== "function" ||
    !Number.isSafeInteger(streamTimeoutMs) ||
    streamTimeoutMs < 1
  ) {
    fail("INVALID_CONFIGURATION", "C01 dependencies are incomplete.");
  }

  return Object.freeze({
    async read(serverContext, originalRequest) {
      const context = deepFreeze(clone(serverContext));
      const request = deepFreeze(clone(originalRequest));
      validateContext(context);
      validateReadRequest(request);
      const scope = await authorize(authorizer, context, request, "READ");
      let view;
      try {
        view = await corePort.read(scope, {
          operationId: request.operationId,
          resourceId: request.resourceId,
        });
      } catch {
        fail("CORE_UNAVAILABLE", "C01 Core read failed closed.");
      }
      validateView(view, scope, request);
      return deepFreeze({
        ...clone(view),
        authorityOwner: "PRODUCT_CORE",
        authorizationEvidenceRef: scope.evidenceRef,
      });
    },

    async mutate(serverContext, originalRequest) {
      const context = deepFreeze(clone(serverContext));
      const request = deepFreeze(clone(originalRequest));
      validateContext(context);
      validateMutationRequest(request);
      const scope = await authorize(
        authorizer,
        context,
        request,
        "WRITE",
      );
      let receipt;
      try {
        receipt = await corePort.mutate(scope, {
          idempotencyKey: request.idempotencyKey,
          operationId: request.operationId,
          resourceId: request.resourceId,
          expectedVersion: request.expectedVersion,
          commandRef: request.commandRef,
          commandSha256: request.commandSha256,
        });
      } catch {
        fail("CORE_UNAVAILABLE", "C01 Core mutation failed closed.");
      }
      validateMutationReceipt(receipt, scope, request);
      return deepFreeze({
        ...clone(receipt),
        authorityOwner: "PRODUCT_CORE",
        authorizationEvidenceRef: scope.evidenceRef,
      });
    },

    async *stream(
      serverContext,
      originalRequest,
      originalStreamControl,
    ) {
      const context = deepFreeze(clone(serverContext));
      const request = deepFreeze(clone(originalRequest));
      const streamControl = validateStreamControl(
        originalStreamControl,
      );
      validateContext(context);
      validateStreamRequest(request);
      const scope = await authorize(authorizer, context, request, "READ");
      const lifecycle = createStreamLifecycle(
        streamControl,
        streamTimeoutMs,
      );
      let source;
      let iterator;
      let sourceEnded = false;
      try {
        source = corePort.stream(scope, {
          operationId: request.operationId,
          resourceId: request.resourceId,
        }, {
          signal: lifecycle.signal,
        });
        if (!source?.[Symbol.asyncIterator]) {
          fail("CORE_UNAVAILABLE", "C01 Core stream is unavailable.");
        }
        iterator = source[Symbol.asyncIterator]();
      } catch {
        lifecycle.dispose();
        fail("CORE_UNAVAILABLE", "C01 Core stream failed closed.");
      }
      let sequence = 1;
      try {
        while (true) {
          if (lifecycle.signal.aborted) {
            throw lifecycle.signal.reason;
          }
          const result = await Promise.race([
            iterator.next(),
            lifecycle.aborted,
          ]);
          if (lifecycle.signal.aborted) {
            throw lifecycle.signal.reason;
          }
          if (result.done) {
            sourceEnded = true;
            fail(
              "CORE_RESULT_INVALID",
              "C01 Core stream ended without a terminal result.",
            );
          }
          const event = result.value;
          validateStreamEvent(event, scope, request, sequence);
          sequence += 1;
          const projected = deepFreeze({
            ...clone(event),
            authorityOwner: "PRODUCT_CORE",
            authorizationEvidenceRef: scope.evidenceRef,
          });
          if (TERMINAL_STREAM_EVENT_TYPES.has(event.eventType)) {
            if (lifecycle.signal.aborted) {
              throw lifecycle.signal.reason;
            }
            const end = await Promise.race([
              iterator.next(),
              lifecycle.aborted,
            ]);
            if (lifecycle.signal.aborted) {
              throw lifecycle.signal.reason;
            }
            if (!end.done) {
              fail(
                "CORE_RESULT_INVALID",
                "C01 Core stream continued after its terminal result.",
              );
            }
            sourceEnded = true;
            yield projected;
            return;
          }
          yield projected;
        }
      } catch (error) {
        if (error instanceof EmployeePortalBffError) throw error;
        fail("CORE_UNAVAILABLE", "C01 Core stream failed closed.");
      } finally {
        lifecycle.dispose();
        if (!sourceEnded && !lifecycle.signal.aborted) {
          lifecycle.stop(
            "STREAM_CANCELLED",
            "C01 stream consumer stopped reading.",
          );
        }
        if (!sourceEnded && typeof iterator?.return === "function") {
          void iterator.return().catch(() => {});
        }
      }
    },
  });
}
