import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";
import { observabilitySha256 } from "./c19-observability.mjs";

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const TENANT_ID =
  /^stn_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TASK_REF =
  /^tsk_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const IDEMPOTENCY_PREFIX = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,79}$/;
const EXPECTED_BINDING_SHA256 =
  "sha256:d3d24cc827e22ce6409d8942f916fa05357f9c7616461a45c42024c2024a8e21";
const MANIFEST_ALGORITHM =
  "SHA256_UTF8_SORTED_PATH_NUL_FILE_SHA256_HEX_LF";
const ERROR_CODE = Object.freeze({
  "c14.model.route": "MODEL_ROUTE_REJECTED",
  "c16.tool.execute": "TOOL_EXECUTION_REJECTED",
  "c18.audit.append": "AUDIT_REJECTED",
  "c19.usage.settle": "USAGE_SETTLEMENT_REJECTED",
});

export class C19UpstreamEmitterError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "C19UpstreamEmitterError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new C19UpstreamEmitterError(code, message);
}

function plainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactKeys(value, keys, label) {
  if (
    !plainObject(value) ||
    Object.keys(value).length !== keys.length ||
    Object.keys(value).some((key) => !keys.includes(key))
  ) {
    fail("INVALID_INPUT", `${label} is not closed.`);
  }
}

function fileSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function safeArtifactPath(rootDir, path) {
  const absolute = resolve(rootDir, path);
  const fromRoot = relative(rootDir, absolute);
  if (
    fromRoot === "" ||
    fromRoot === ".." ||
    fromRoot.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) ||
    isAbsolute(fromRoot)
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C19 upstream artifact path escapes the repository root.",
    );
  }
  return absolute;
}

function artifactMap(document) {
  const artifacts = new Map();
  for (const artifact of document.artifacts) {
    const common = ["module", "verificationType", "path", "sha256"];
    const keys = {
      FILE_SHA256: common,
      MANIFEST_SHA256: [...common, "manifestSha256"],
      EVIDENCE_ARTIFACT_LIST: [...common, "projectionSha256"],
    }[artifact.verificationType];
    if (!keys) {
      fail(
        "INVALID_CONFIGURATION",
        "C19 upstream artifact binding is invalid.",
      );
    }
    exactKeys(artifact, keys, "upstream artifact");
    if (
      !["C14", "C16", "C18", "C19"].includes(artifact.module) ||
      ![
        "FILE_SHA256",
        "MANIFEST_SHA256",
        "EVIDENCE_ARTIFACT_LIST",
      ].includes(
        artifact.verificationType,
      ) ||
      typeof artifact.path !== "string" ||
      artifact.path.length < 3 ||
      !SHA256.test(artifact.sha256 ?? "") ||
      (artifact.verificationType === "MANIFEST_SHA256" &&
        !SHA256.test(artifact.manifestSha256 ?? "")) ||
      (artifact.verificationType === "EVIDENCE_ARTIFACT_LIST" &&
        !SHA256.test(artifact.projectionSha256 ?? "")) ||
      artifacts.has(artifact.module)
    ) {
      fail(
        "INVALID_CONFIGURATION",
        "C19 upstream artifact binding is invalid.",
      );
    }
    artifacts.set(artifact.module, structuredClone(artifact));
  }
  if (
    artifacts.size !== 4 ||
    !["C14", "C16", "C18", "C19"].every((module) =>
      artifacts.has(module),
    )
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C19 upstream artifact bindings are incomplete.",
    );
  }
  return artifacts;
}

function projectionArtifactSha256(artifact) {
  if (artifact.verificationType === "MANIFEST_SHA256") {
    return artifact.manifestSha256;
  }
  if (artifact.verificationType === "EVIDENCE_ARTIFACT_LIST") {
    return artifact.projectionSha256;
  }
  return artifact.sha256;
}

function validateTenantBinding(value, artifacts) {
  exactKeys(
    value,
    [
      "tenantId",
      "identityContextRef",
      "idempotencyPrefix",
      "taskRef",
      "model",
      "tool",
      "audit",
    ],
    "upstream Tenant binding",
  );
  exactKeys(
    value.model,
    [
      "upstreamTaskRef",
      "planRef",
      "receiptRef",
      "resourceRef",
      "expectedProjection",
    ],
    "model binding",
  );
  exactKeys(
    value.tool,
    ["planRef", "receiptRef", "resourceRef", "expectedProjection"],
    "Tool binding",
  );
  exactKeys(
    value.audit,
    ["bundleRef", "expectedProjection"],
    "audit binding",
  );
  if (
    !TENANT_ID.test(value.tenantId ?? "") ||
    !TASK_REF.test(value.taskRef ?? "") ||
    typeof value.identityContextRef !== "string" ||
    !value.identityContextRef.startsWith("fixture://") ||
    !IDEMPOTENCY_PREFIX.test(value.idempotencyPrefix ?? "") ||
    !value.model.upstreamTaskRef?.startsWith("synthetic://c14/") ||
    !value.model.planRef?.startsWith("fixture://") ||
    !value.model.receiptRef?.startsWith("fixture://") ||
    !value.model.resourceRef?.startsWith("model://") ||
    !value.tool.planRef?.startsWith("fixture://") ||
    !value.tool.receiptRef?.startsWith("fixture://") ||
    !value.tool.resourceRef?.startsWith("tool://") ||
    !value.audit.bundleRef?.startsWith("fixture://") ||
    !plainObject(value.model.expectedProjection) ||
    !plainObject(value.tool.expectedProjection) ||
    !plainObject(value.audit.expectedProjection) ||
    value.model.expectedProjection.sourceModule !== "C14" ||
    value.tool.expectedProjection.sourceModule !== "C16" ||
    value.audit.expectedProjection.sourceModule !== "C18" ||
    value.model.expectedProjection.sourceArtifactSha256 !==
      projectionArtifactSha256(artifacts.get("C14")) ||
    value.tool.expectedProjection.sourceArtifactSha256 !==
      projectionArtifactSha256(artifacts.get("C16")) ||
    value.audit.expectedProjection.sourceArtifactSha256 !==
      projectionArtifactSha256(artifacts.get("C18"))
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C19 upstream Tenant binding is invalid.",
    );
  }
  return structuredClone(value);
}

async function manifestSha256(evidence, rootDir, readArtifact) {
  const source = evidence?.source_artifacts;
  if (
    source?.algorithm !== MANIFEST_ALGORITHM ||
    !Array.isArray(source.paths) ||
    source.paths.length < 1 ||
    source.paths.some((path) => typeof path !== "string")
  ) {
    fail(
      "UPSTREAM_ARTIFACT_MISMATCH",
      "Upstream source manifest is invalid.",
    );
  }
  const rows = [];
  for (const path of [...source.paths].sort()) {
    const bytes = await readArtifact(safeArtifactPath(rootDir, path));
    rows.push(`${path}\u0000${fileSha256(bytes).slice(7)}\n`);
  }
  return fileSha256(rows.join(""));
}

function assertC19CatalogBinding(document, binding) {
  const tenant = document?.tenants?.find(
    (candidate) => candidate.tenantId === binding.tenantId,
  );
  const modelPlan = tenant?.plans?.find(
    (plan) => plan.planRef === binding.model.planRef,
  );
  const toolPlan = tenant?.plans?.find(
    (plan) => plan.planRef === binding.tool.planRef,
  );
  const modelReceipt = tenant?.receipts?.find(
    (receipt) => receipt.receiptRef === binding.model.receiptRef,
  );
  const toolReceipt = tenant?.receipts?.find(
    (receipt) => receipt.receiptRef === binding.tool.receiptRef,
  );
  const modelProjectionSha256 = observabilitySha256(
    binding.model.expectedProjection,
  );
  const toolProjectionSha256 = observabilitySha256(
    binding.tool.expectedProjection,
  );
  const auditProjectionSha256 = observabilitySha256(
    binding.audit.expectedProjection,
  );
  if (
    modelPlan?.taskRef !== binding.taskRef ||
    modelPlan?.resourceRef !== binding.model.resourceRef ||
    modelPlan?.sourceEvidenceSha256 !== modelProjectionSha256 ||
    modelPlan?.auditEvidenceSha256 !== auditProjectionSha256 ||
    modelReceipt?.planRef !== binding.model.planRef ||
    modelReceipt?.quantity !==
      binding.model.expectedProjection.usage?.totalTokens ||
    modelReceipt?.supplierCostMicros !==
      binding.model.expectedProjection.supplierCostMicros ||
    toolPlan?.taskRef !== binding.taskRef ||
    toolPlan?.resourceRef !== binding.tool.resourceRef ||
    toolPlan?.sourceEvidenceSha256 !== toolProjectionSha256 ||
    toolPlan?.auditEvidenceSha256 !== auditProjectionSha256 ||
    toolReceipt?.planRef !== binding.tool.planRef ||
    toolReceipt?.quantity !== 1 ||
    toolReceipt?.supplierCostMicros !== 0
  ) {
    fail(
      "C19_SETTLEMENT_BINDING_MISMATCH",
      "C19 settlement catalog is not bound to upstream evidence.",
    );
  }
}

export function createC19UpstreamBindingCatalog(
  document,
  { rootDir, readArtifact = readFile } = {},
) {
  exactKeys(
    document,
    ["schemaVersion", "phase", "artifacts", "tenants"],
    "upstream binding catalog",
  );
  if (
    document.schemaVersion !==
      "c19-upstream-artifact-bindings.v1" ||
    document.phase !== "P1_SYNTHETIC_ONLY" ||
    observabilitySha256(document) !== EXPECTED_BINDING_SHA256 ||
    !Array.isArray(document.artifacts) ||
    !Array.isArray(document.tenants) ||
    document.tenants.length !== 1 ||
    typeof rootDir !== "string" ||
    !isAbsolute(rootDir) ||
    typeof readArtifact !== "function"
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C19 upstream binding catalog is invalid.",
    );
  }
  const artifacts = artifactMap(document);
  const tenants = new Map();
  for (const raw of document.tenants) {
    const tenant = validateTenantBinding(raw, artifacts);
    if (tenants.has(tenant.tenantId)) {
      fail(
        "INVALID_CONFIGURATION",
        "C19 upstream Tenant binding is duplicated.",
      );
    }
    tenants.set(tenant.tenantId, tenant);
  }

  async function verifyArtifacts() {
    for (const artifact of artifacts.values()) {
      const path = safeArtifactPath(rootDir, artifact.path);
      const bytes = await readArtifact(path);
      if (fileSha256(bytes) !== artifact.sha256) {
        fail(
          "UPSTREAM_ARTIFACT_MISMATCH",
          `${artifact.module} artifact digest changed.`,
        );
      }
      if (artifact.verificationType === "MANIFEST_SHA256") {
        let evidence;
        try {
          evidence = JSON.parse(bytes.toString("utf8"));
        } catch {
          fail(
            "UPSTREAM_ARTIFACT_MISMATCH",
            `${artifact.module} evidence is not JSON.`,
          );
        }
        const actualManifest = await manifestSha256(
          evidence,
          rootDir,
          readArtifact,
        );
        if (
          evidence.source_artifacts.manifest_sha256 !==
            artifact.manifestSha256 ||
          actualManifest !== artifact.manifestSha256
        ) {
          fail(
            "UPSTREAM_ARTIFACT_MISMATCH",
            `${artifact.module} source manifest changed.`,
          );
        }
      }
      if (
        artifact.verificationType ===
        "EVIDENCE_ARTIFACT_LIST"
      ) {
        let evidence;
        try {
          evidence = JSON.parse(bytes.toString("utf8"));
        } catch {
          fail(
            "UPSTREAM_ARTIFACT_MISMATCH",
            `${artifact.module} evidence is not JSON.`,
          );
        }
        if (
          !Array.isArray(evidence.artifacts) ||
          evidence.artifacts.length < 1
        ) {
          fail(
            "UPSTREAM_ARTIFACT_MISMATCH",
            `${artifact.module} artifact list is invalid.`,
          );
        }
        const seen = new Set();
        let projectionFound = false;
        for (const row of evidence.artifacts) {
          if (
            !plainObject(row) ||
            Object.keys(row).length !== 2 ||
            typeof row.path !== "string" ||
            !SHA256.test(row.sha256 ?? "") ||
            seen.has(row.path)
          ) {
            fail(
              "UPSTREAM_ARTIFACT_MISMATCH",
              `${artifact.module} artifact list is invalid.`,
            );
          }
          seen.add(row.path);
          const artifactBytes = await readArtifact(
            safeArtifactPath(rootDir, row.path),
          );
          if (fileSha256(artifactBytes) !== row.sha256) {
            fail(
              "UPSTREAM_ARTIFACT_MISMATCH",
              `${artifact.module} source artifact changed.`,
            );
          }
          if (
            row.path === "lib/model-gateway.mjs" &&
            row.sha256 === artifact.projectionSha256
          ) {
            projectionFound = true;
          }
        }
        if (!projectionFound) {
          fail(
            "UPSTREAM_ARTIFACT_MISMATCH",
            `${artifact.module} projection artifact is missing.`,
          );
        }
      }
    }
    const c19 = artifacts.get("C19");
    const c19Document = JSON.parse(
      (
        await readArtifact(safeArtifactPath(rootDir, c19.path))
      ).toString("utf8"),
    );
    for (const binding of tenants.values()) {
      assertC19CatalogBinding(c19Document, binding);
    }
    return true;
  }

  return Object.freeze({
    verifyArtifacts,
    resolveTenant(tenantId) {
      const value = tenants.get(tenantId);
      if (!value) {
        fail(
          "SYNTHETIC_FIXTURE_MISMATCH",
          "No frozen C19 upstream binding exists for this Tenant.",
        );
      }
      return structuredClone(value);
    },
    assertProjection(tenantId, kind, projection) {
      const binding = tenants.get(tenantId);
      const expected = binding?.[kind]?.expectedProjection;
      if (
        !expected ||
        observabilitySha256(projection) !==
          observabilitySha256(expected)
      ) {
        fail(
          "UPSTREAM_EVIDENCE_MISMATCH",
          `${kind} output does not match frozen C19 evidence.`,
        );
      }
      return observabilitySha256(projection);
    },
    artifactProjectionSha256(module) {
      return projectionArtifactSha256(artifacts.get(module));
    },
  });
}

function validateServerContext(value) {
  exactKeys(
    value,
    [
      "synthetic",
      "routeTrustSource",
      "tenantId",
      "workloadTrustSource",
      "workloadActorPrincipalId",
    ],
    "upstream server context",
  );
  if (
    value.synthetic !== true ||
    value.routeTrustSource !== "VERIFIED_ROUTE_DESCRIPTOR" ||
    value.workloadTrustSource !== "VERIFIED_WORKLOAD_CONTEXT" ||
    !TENANT_ID.test(value.tenantId ?? "") ||
    typeof value.workloadActorPrincipalId !== "string" ||
    value.workloadActorPrincipalId.length < 3
  ) {
    fail("INVALID_INPUT", "Upstream server context is invalid.");
  }
}

function validateRunRequest(value) {
  exactKeys(
    value,
    [
      "traceparent",
      "tracestate",
      "sessionToken",
      "delegationId",
      "correlationId",
      "idempotencyPrefix",
      "model",
      "tool",
    ],
    "upstream run request",
  );
  exactKeys(
    value.model,
    ["taskRef", "inputRef", "inputSha256"],
    "upstream model request",
  );
  exactKeys(
    value.tool,
    ["operationId", "params"],
    "upstream Tool request",
  );
  if (
    !IDEMPOTENCY_PREFIX.test(value.idempotencyPrefix ?? "") ||
    typeof value.sessionToken !== "string" ||
    value.sessionToken.length < 1 ||
    typeof value.delegationId !== "string" ||
    value.delegationId.length < 1 ||
    typeof value.correlationId !== "string" ||
    value.correlationId.length < 1 ||
    typeof value.traceparent !== "string" ||
    (value.tracestate !== null &&
      typeof value.tracestate !== "string") ||
    typeof value.model.taskRef !== "string" ||
    typeof value.model.inputRef !== "string" ||
    !SHA256.test(value.model.inputSha256 ?? "") ||
    typeof value.tool.operationId !== "string" ||
    !plainObject(value.tool.params)
  ) {
    fail("INVALID_INPUT", "Upstream run request is invalid.");
  }
}

function duration(started, monotonicClock) {
  const ended = monotonicClock();
  if (
    typeof started !== "number" ||
    !Number.isFinite(started) ||
    typeof ended !== "number" ||
    !Number.isFinite(ended) ||
    ended < started
  ) {
    fail("INVALID_CONFIGURATION", "Monotonic clock is invalid.");
  }
  return Math.floor(ended - started);
}

export function createC19SyntheticUpstreamEmitter({
  modelGateway,
  toolGateway,
  auditEvidenceService,
  observabilityService,
  bindingCatalog,
  monotonicClock = () => performance.now(),
}) {
  if (
    typeof modelGateway?.route !== "function" ||
    typeof toolGateway?.confirm !== "function" ||
    typeof toolGateway?.execute !== "function" ||
    typeof auditEvidenceService?.append !== "function" ||
    typeof observabilityService?.reserve !== "function" ||
    typeof observabilityService?.release !== "function" ||
    typeof observabilityService?.settle !== "function" ||
    typeof observabilityService?.recordSignal !== "function" ||
    typeof bindingCatalog?.verifyArtifacts !== "function" ||
    typeof bindingCatalog?.resolveTenant !== "function" ||
    typeof bindingCatalog?.assertProjection !== "function" ||
    typeof bindingCatalog?.artifactProjectionSha256 !== "function" ||
    typeof monotonicClock !== "function"
  ) {
    fail(
      "INVALID_CONFIGURATION",
      "C19 upstream emitter dependencies are incomplete.",
    );
  }

  async function run(serverContext, request) {
    validateServerContext(serverContext);
    validateRunRequest(request);
    await bindingCatalog.verifyArtifacts();
    const binding = bindingCatalog.resolveTenant(
      serverContext.tenantId,
    );
    if (
      request.idempotencyPrefix !== binding.idempotencyPrefix ||
      request.model.taskRef !== binding.model.upstreamTaskRef ||
      request.tool.operationId !==
        binding.tool.expectedProjection.operationId
    ) {
      fail(
        "SYNTHETIC_FIXTURE_MISMATCH",
        "Upstream request is outside the frozen C19 binding.",
      );
    }
    const c19Context = Object.freeze({
      synthetic: true,
      routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
      tenantId: serverContext.tenantId,
      identityContextRef: binding.identityContextRef,
    });
    let traceContext = {
      traceparent: request.traceparent,
      tracestate: request.tracestate,
    };
    const modelReservation = await observabilityService.reserve(
      c19Context,
      {
        idempotencyKey:
          `${request.idempotencyPrefix}-reserve-model`,
        planRef: binding.model.planRef,
        ...traceContext,
      },
    );
    traceContext = modelReservation.traceContext;
    const pending = new Map([["model", modelReservation]]);
    let toolReservation;
    try {
      toolReservation = await observabilityService.reserve(
        c19Context,
        {
          idempotencyKey:
            `${request.idempotencyPrefix}-reserve-tool`,
          planRef: binding.tool.planRef,
          ...traceContext,
        },
      );
    } catch (error) {
      try {
        await observabilityService.release(c19Context, {
          idempotencyKey:
            `${request.idempotencyPrefix}-release-model`,
          reservationId:
            modelReservation.reservation.reservationId,
          ...traceContext,
        });
      } catch {
        throw new C19UpstreamEmitterError(
          "QUOTA_RELEASE_FAILED",
          "C19 could not release a partial reservation.",
          { cause: error },
        );
      }
      throw error;
    }
    traceContext = toolReservation.traceContext;
    pending.set("tool", toolReservation);

    async function observed(
      operation,
      work,
      project,
      projectionKind,
    ) {
      const started = monotonicClock();
      try {
        const output = await work();
        const projection = project(output);
        bindingCatalog.assertProjection(
          serverContext.tenantId,
          projectionKind,
          projection,
        );
        const recorded = await observabilityService.recordSignal(
          c19Context,
          {
            idempotencyKey:
              `${request.idempotencyPrefix}-${projectionKind}-ok`,
            ...traceContext,
            signalType: "SPAN",
            operation,
            taskRef: binding.taskRef,
            status: "OK",
            durationMs: duration(started, monotonicClock),
            errorCode: null,
          },
        );
        traceContext = recorded.traceContext;
        return { output, projection };
      } catch (error) {
        try {
          const recorded = await observabilityService.recordSignal(
            c19Context,
            {
              idempotencyKey:
                `${request.idempotencyPrefix}-${projectionKind}-error`,
              ...traceContext,
              signalType: "SPAN",
              operation,
              taskRef: binding.taskRef,
              status: "ERROR",
              durationMs: duration(started, monotonicClock),
              errorCode: ERROR_CODE[operation],
            },
          );
          traceContext = recorded.traceContext;
        } catch {
          // Preserve the upstream or evidence failure.
        }
        throw error;
      }
    }

    const settlementStarted = monotonicClock();
    let modelSettlement;
    let toolSettlement;
    let model;
    let tool;
    let audit;

    async function releasePending() {
      let firstFailure;
      for (const [kind, reservation] of pending) {
        try {
          await observabilityService.release(c19Context, {
            idempotencyKey:
              `${request.idempotencyPrefix}-release-${kind}`,
            reservationId: reservation.reservation.reservationId,
            ...traceContext,
          });
          pending.delete(kind);
        } catch (error) {
          firstFailure ??= error;
        }
      }
      if (firstFailure) throw firstFailure;
    }

    try {
      model = await observed(
        "c14.model.route",
        () =>
          modelGateway.route(serverContext, {
            sessionToken: request.sessionToken,
            delegationId: request.delegationId,
            idempotencyKey: `${request.idempotencyPrefix}-c14`,
            correlationId: request.correlationId,
            taskRef: request.model.taskRef,
            inputRef: request.model.inputRef,
            inputSha256: request.model.inputSha256,
          }),
        (result) => ({
          sourceModule: "C14",
          sourceArtifactSha256:
            bindingCatalog.artifactProjectionSha256("C14"),
          catalogSha256: result.route.catalogSha256,
          selectedModel: structuredClone(result.route.selectedModel),
          usage: structuredClone(result.route.usage),
          supplierRateVersion: result.route.rateVersion,
          supplierCostMicros: result.route.costMicrousd,
        }),
        "model",
      );
      tool = await observed(
        "c16.tool.execute",
        async () => {
          const common = {
            sessionToken: request.sessionToken,
            delegationId: request.delegationId,
            correlationId: request.correlationId,
            operationId: request.tool.operationId,
          };
          const confirmation = await toolGateway.confirm(
            serverContext,
            {
              ...common,
              idempotencyKey:
                `${request.idempotencyPrefix}-c16-confirm`,
              params: request.tool.params,
            },
          );
          const result = await toolGateway.execute(serverContext, {
            ...common,
            idempotencyKey:
              `${request.idempotencyPrefix}-c16-execute`,
            confirmationId: confirmation.confirmationId,
            confirmationSha256: confirmation.confirmationSha256,
            expectedParamSha256: confirmation.normalizedParamSha256,
          });
          return { confirmation, result };
        },
        ({ confirmation, result }) => ({
          sourceModule: "C16",
          sourceArtifactSha256:
            bindingCatalog.artifactProjectionSha256("C16"),
          catalogSha256: confirmation.catalogSha256,
          operationId: result.operationId,
          adapterVersion: confirmation.adapterVersion,
          resultSha256: result.receipt.resultSha256,
          receiptSha256: result.receipt.receiptSha256,
          networkRequestCount: result.receipt.networkRequestCount,
          externalEffectCount: result.receipt.externalEffectCount,
        }),
        "tool",
      );
      audit = await observed(
        "c18.audit.append",
        () =>
          auditEvidenceService.append(serverContext, {
            sessionToken: request.sessionToken,
            delegationId: request.delegationId,
            idempotencyKey: `${request.idempotencyPrefix}-c18`,
            correlationId: request.correlationId,
            evidenceBundleRef: binding.audit.bundleRef,
          }),
        (result) => ({
          sourceModule: "C18",
          sourceArtifactSha256:
            bindingCatalog.artifactProjectionSha256("C18"),
          eventId: result.eventId,
          eventHash: result.eventHash,
          payloadSha256: result.payloadSha256,
          provenanceSha256: result.provenanceSha256,
        }),
        "audit",
      );
      const settlementWrapperParent = { ...traceContext };
      modelSettlement = await observabilityService.settle(
        c19Context,
        {
          idempotencyKey:
            `${request.idempotencyPrefix}-settle-model`,
          reservationId:
            modelReservation.reservation.reservationId,
          receiptRef: binding.model.receiptRef,
          ...traceContext,
        },
      );
      pending.delete("model");
      toolSettlement = await observabilityService.settle(
        c19Context,
        {
          idempotencyKey:
            `${request.idempotencyPrefix}-settle-tool`,
          reservationId:
            toolReservation.reservation.reservationId,
          receiptRef: binding.tool.receiptRef,
          ...traceContext,
        },
      );
      pending.delete("tool");
      const recorded = await observabilityService.recordSignal(
        c19Context,
        {
          idempotencyKey:
            `${request.idempotencyPrefix}-settlement-ok`,
          ...settlementWrapperParent,
          signalType: "SPAN",
          operation: "c19.usage.settle",
          taskRef: binding.taskRef,
          status: "OK",
          durationMs: duration(
            settlementStarted,
            monotonicClock,
          ),
          errorCode: null,
        },
      );
      traceContext = recorded.traceContext;
    } catch (error) {
      let releaseFailure;
      try {
        await releasePending();
      } catch (cleanupError) {
        releaseFailure = cleanupError;
      }
      try {
        const recorded = await observabilityService.recordSignal(
          c19Context,
          {
            idempotencyKey:
              `${request.idempotencyPrefix}-settlement-error`,
            ...traceContext,
            signalType: "SPAN",
            operation: "c19.usage.settle",
            taskRef: binding.taskRef,
            status: "ERROR",
            durationMs: duration(
              settlementStarted,
              monotonicClock,
            ),
            errorCode: ERROR_CODE["c19.usage.settle"],
          },
        );
        traceContext = recorded.traceContext;
      } catch {
        // Preserve the settlement failure.
      }
      if (releaseFailure) {
        throw new C19UpstreamEmitterError(
          "QUOTA_RELEASE_FAILED",
          "C19 could not release a failed upstream reservation.",
          { cause: error },
        );
      }
      throw error;
    }

    return Object.freeze({
      model: model.output,
      tool: tool.output,
      audit: audit.output,
      projections: Object.freeze({
        model: Object.freeze(model.projection),
        tool: Object.freeze(tool.projection),
        audit: Object.freeze(audit.projection),
      }),
      settlements: Object.freeze({
        model: modelSettlement,
        tool: toolSettlement,
      }),
      traceContext: Object.freeze({ ...traceContext }),
    });
  }

  return Object.freeze({ run });
}
