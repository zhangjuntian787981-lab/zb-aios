import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const MODULE_OPERATIONS = Object.freeze({
  portal: "getPortalBootstrap",
  core: "createTask",
  model: "createModelResponse",
  tool: "prepareToolCall",
  connector: "validateConnectorTemplate",
  audit: "appendAuditEvent",
});

const HTTP_METHODS = new Set([
  "get",
  "post",
  "put",
  "patch",
  "delete",
  "options",
  "head",
  "trace",
]);

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function nonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function validDateTime(value) {
  return nonEmptyString(value) && !Number.isNaN(Date.parse(value));
}

function validSemanticVersion(value) {
  return (
    typeof value === "string" &&
    /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/.test(
      value,
    )
  );
}

function result(errors) {
  return { valid: errors.length === 0, errors };
}

function rootUrl(value) {
  if (value instanceof URL) return value;
  const absolute = path.resolve(value);
  return pathToFileURL(`${absolute}${path.sep}`);
}

async function readJson(base, relativePath) {
  return JSON.parse(await readFile(new URL(relativePath, base), "utf8"));
}

export function createJsonSchemaValidators(schemas) {
  const names = ["taskEnvelope", "problemDetails", "cloudEvent"];
  if (
    !isRecord(schemas) ||
    names.some((name) => !isRecord(schemas[name]))
  ) {
    throw new Error("F03 JSON Schema 集合不完整");
  }
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const compiled = Object.fromEntries(
    names.map((name) => [name, ajv.compile(schemas[name])]),
  );

  return Object.freeze({
    validate(name, value) {
      const validator = compiled[name];
      if (!validator) {
        throw new Error(`未知的 F03 JSON Schema: ${String(name)}`);
      }
      const valid = validator(value);
      return {
        valid,
        errors: valid
          ? []
          : (validator.errors ?? []).map(
              ({ instancePath, keyword, message, params }) => ({
                instancePath,
                keyword,
                message,
                params: structuredClone(params),
              }),
            ),
      };
    },
  });
}

export async function loadContractLab(
  root = new URL("../implementation/p0/f03/", import.meta.url),
) {
  const base = rootUrl(root);
  const contracts = {};
  for (const moduleName of Object.keys(MODULE_OPERATIONS)) {
    contracts[moduleName] = await readJson(
      base,
      `contracts/${moduleName}.openapi.v1.json`,
    );
  }

  return {
    contracts,
    schemas: {
      taskEnvelope: await readJson(
        base,
        "schemas/canonical-task-envelope.v1.schema.json",
      ),
      problemDetails: await readJson(
        base,
        "schemas/problem-details.v1.schema.json",
      ),
      cloudEvent: await readJson(
        base,
        "schemas/cloud-event.v1.schema.json",
      ),
    },
    samples: {
      taskEnvelope: await readJson(
        base,
        "samples/task-envelope.valid.json",
      ),
      problemDetails: await readJson(
        base,
        "samples/problem-details.valid.json",
      ),
      cloudEvent: await readJson(base, "samples/cloud-event.valid.json"),
      mockCore: await readJson(base, "samples/mock-core-create-task.json"),
    },
    negatives: {
      taskEnvelope: await readJson(
        base,
        "negative/task-envelope.invalid.json",
      ),
      problemDetails: await readJson(
        base,
        "negative/problem-details.secret-leak.invalid.json",
      ),
      cloudEvent: await readJson(
        base,
        "negative/cloud-event.invalid.json",
      ),
      breakingContract: await readJson(
        base,
        "negative/core-breaking.openapi.v2.json",
      ),
    },
    compatibility: await readJson(base, "compatibility-matrix.v1.json"),
    deprecation: await readJson(base, "deprecation-matrix.v1.json"),
  };
}

export function validateTaskEnvelope(value) {
  const errors = [];
  if (!isRecord(value)) return result(["TaskEnvelope 必须是对象"]);

  if (value.envelope_version !== "1.0.0") {
    errors.push("envelope_version 必须是 1.0.0");
  }
  for (const key of ["task_id", "correlation_id", "operation_id"]) {
    if (!nonEmptyString(value[key])) errors.push(`${key} 不能为空`);
  }
  if (!validDateTime(value.created_at)) {
    errors.push("created_at 必须是有效的 RFC 3339 时间");
  }
  if (!isRecord(value.payload)) errors.push("payload 必须是对象");
  if (
    !Array.isArray(value.evidence_refs) ||
    !value.evidence_refs.every(nonEmptyString)
  ) {
    errors.push("evidence_refs 必须是字符串数组");
  }

  const tenant = value.tenant_context;
  if (!isRecord(tenant)) {
    errors.push("tenant_context 必须是对象");
  } else {
    if (!nonEmptyString(tenant.tenant_id)) {
      errors.push("tenant_context.tenant_id 不能为空");
    }
    if (!["SYNTHETIC", "ENTERPRISE"].includes(tenant.tenant_kind)) {
      errors.push("tenant_context.tenant_kind 非法");
    }
    if (
      !["VERIFIED_SERVER_CONTEXT", "SYNTHETIC_FIXTURE"].includes(
        tenant.trust_source,
      )
    ) {
      errors.push("tenant_context.trust_source 非法");
    }
  }

  const principal = value.principal_context;
  if (!isRecord(principal)) {
    errors.push("principal_context 必须是对象");
  } else {
    if (!nonEmptyString(principal.principal_id)) {
      errors.push("principal_context.principal_id 不能为空");
    }
    if (!["HUMAN", "AGENT", "SERVICE"].includes(principal.principal_kind)) {
      errors.push("principal_context.principal_kind 非法");
    }
    if (
      ![
        "VERIFIED_SESSION",
        "SERVICE_IDENTITY",
        "SYNTHETIC_FIXTURE",
      ].includes(principal.trust_source)
    ) {
      errors.push("principal_context.trust_source 非法");
    }
  }

  const authorization = value.authorization_context;
  if (!isRecord(authorization)) {
    errors.push("authorization_context 必须是对象");
  } else if (
    !["NOT_EVALUATED", "ALLOWED", "DENIED"].includes(authorization.status)
  ) {
    errors.push("authorization_context.status 非法");
  }

  return result(errors);
}

function hasSensitiveProblemContent(value) {
  const forbiddenKeys = new Set([
    "stack",
    "stacktrace",
    "stack_trace",
    "exception",
    "password",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
  ]);
  const sensitiveValue =
    /\b(?:Bearer\s+[A-Za-z0-9._-]{8,}|sk-[A-Za-z0-9_-]{8,}|password\s*[=:]|secret\s*[=:]|Traceback \(most recent call last\)|at [\w$.]+ \([^)]*:\d+:\d+\))/i;

  function visit(item) {
    if (typeof item === "string") return sensitiveValue.test(item);
    if (Array.isArray(item)) return item.some(visit);
    if (!isRecord(item)) return false;
    return Object.entries(item).some(
      ([key, child]) => forbiddenKeys.has(key.toLowerCase()) || visit(child),
    );
  }

  return visit(value);
}

export function validateProblemDetails(value) {
  const errors = [];
  if (!isRecord(value)) return result(["Problem Details 必须是对象"]);
  if (!nonEmptyString(value.type)) errors.push("type 不能为空");
  if (!nonEmptyString(value.title)) errors.push("title 不能为空");
  if (
    !Number.isInteger(value.status) ||
    value.status < 400 ||
    value.status > 599
  ) {
    errors.push("status 必须是 400 到 599 的整数");
  }
  if (value.detail !== undefined && !nonEmptyString(value.detail)) {
    errors.push("detail 如存在必须是非空字符串");
  }
  if (value.instance !== undefined && !nonEmptyString(value.instance)) {
    errors.push("instance 如存在必须是非空字符串");
  }
  if (hasSensitiveProblemContent(value)) {
    errors.push("Problem Details 不得包含敏感信息或堆栈");
  }
  return result(errors);
}

export function validateCloudEvent(value) {
  const errors = [];
  if (!isRecord(value)) return result(["CloudEvent 必须是对象"]);
  if (value.specversion !== "1.0") errors.push("specversion 必须是 1.0");
  for (const key of ["id", "source", "type"]) {
    if (!nonEmptyString(value[key])) errors.push(`${key} 不能为空`);
  }
  if (!validDateTime(value.time)) errors.push("time 必须是有效时间");
  if (value.datacontenttype !== "application/json") {
    errors.push("datacontenttype 必须是 application/json");
  }
  if (!isRecord(value.data)) errors.push("data 必须是对象");
  if (!["SYNTHETIC", "ENTERPRISE"].includes(value.tenantkind)) {
    errors.push("tenantkind 非法");
  }
  if (!nonEmptyString(value.correlationid)) {
    errors.push("correlationid 不能为空");
  }
  if (typeof value.synthetic !== "boolean") {
    errors.push("synthetic 必须是布尔值");
  }
  return result(errors);
}

function operations(document) {
  const found = [];
  if (!isRecord(document.paths)) return found;
  for (const [pathName, pathItem] of Object.entries(document.paths)) {
    if (!isRecord(pathItem)) continue;
    for (const [method, operation] of Object.entries(pathItem)) {
      if (HTTP_METHODS.has(method) && isRecord(operation)) {
        found.push({ pathName, method, operation });
      }
    }
  }
  return found;
}

export function validateOpenApiContract(moduleName, document) {
  const errors = [];
  if (!isRecord(document)) return result([`${moduleName}: 契约必须是对象`]);
  if (document.openapi !== "3.1.2") {
    errors.push(`${moduleName}: openapi 必须是 3.1.2`);
  }
  if (!isRecord(document.info) || !nonEmptyString(document.info.version)) {
    errors.push(`${moduleName}: info.version 不能为空`);
  }
  if (document["x-module"] !== moduleName) {
    errors.push(`${moduleName}: x-module 不匹配`);
  }
  const boundary = document["x-f03-boundary"];
  if (
    !isRecord(boundary) ||
    boundary.schema_valid_does_not_imply_authorized !== true ||
    boundary.mock_does_not_imply_enterprise_connected !== true
  ) {
    errors.push(`${moduleName}: 缺少 F03 安全边界声明`);
  }
  if (
    !Array.isArray(document.servers) ||
    document.servers.length !== 1 ||
    !/^https:\/\/mock\.invalid(?:\/|$)/.test(document.servers[0]?.url ?? "")
  ) {
    errors.push(`${moduleName}: P0 契约只能声明 mock.invalid Server`);
  }

  const found = operations(document);
  if (found.length === 0) errors.push(`${moduleName}: 至少需要一个操作`);
  const operationIds = new Set();
  for (const { pathName, method, operation } of found) {
    if (!nonEmptyString(operation.operationId)) {
      errors.push(`${moduleName}: ${method.toUpperCase()} ${pathName} 缺少 operationId`);
    } else if (operationIds.has(operation.operationId)) {
      errors.push(`${moduleName}: operationId 重复`);
    } else {
      operationIds.add(operation.operationId);
    }
    if (!isRecord(operation.responses)) {
      errors.push(`${moduleName}: ${operation.operationId} 缺少 responses`);
    }
  }
  if (!operationIds.has(MODULE_OPERATIONS[moduleName])) {
    errors.push(`${moduleName}: 缺少冻结操作 ${MODULE_OPERATIONS[moduleName]}`);
  }
  if (!isRecord(document.components?.schemas)) {
    errors.push(`${moduleName}: 缺少 components.schemas`);
  }
  return result(errors);
}

export function validateContractLab(lab) {
  const errors = [];
  const moduleNames = Object.keys(MODULE_OPERATIONS);

  for (const moduleName of moduleNames) {
    const contractResult = validateOpenApiContract(
      moduleName,
      lab.contracts?.[moduleName],
    );
    errors.push(...contractResult.errors);
  }

  for (const [name, validation] of [
    ["TaskEnvelope", validateTaskEnvelope(lab.samples?.taskEnvelope)],
    ["Problem Details", validateProblemDetails(lab.samples?.problemDetails)],
    ["CloudEvent", validateCloudEvent(lab.samples?.cloudEvent)],
  ]) {
    errors.push(...validation.errors.map((error) => `${name}: ${error}`));
  }

  const matrixModules = new Set(
    lab.compatibility?.contracts?.map((entry) => entry.module) ?? [],
  );
  const deprecationModules = new Set(
    lab.deprecation?.contracts?.map((entry) => entry.module) ?? [],
  );
  for (const moduleName of moduleNames) {
    if (!matrixModules.has(moduleName)) {
      errors.push(`兼容矩阵缺少 ${moduleName}`);
    }
    if (!deprecationModules.has(moduleName)) {
      errors.push(`废弃矩阵缺少 ${moduleName}`);
    }
  }
  const deprecationValidation = validateDeprecationMatrix(lab.deprecation);
  errors.push(
    ...deprecationValidation.errors.map(
      ({ code, module }) =>
        `废弃矩阵 ${module ?? "unknown"}: ${code}`,
    ),
  );
  return result(errors);
}

export function validateDeprecationMatrix(document) {
  const errors = [];
  const add = (code, module = null) => errors.push({ code, module });
  if (
    !isRecord(document) ||
    !Number.isSafeInteger(document.minimum_notice_days) ||
    document.minimum_notice_days < 90 ||
    !Array.isArray(document.contracts)
  ) {
    add("INVALID_DEPRECATION_MATRIX");
    return result(errors);
  }
  const modules = new Set();
  for (const contract of document.contracts) {
    const moduleName = contract?.module ?? null;
    if (!isRecord(contract) || !nonEmptyString(moduleName)) {
      add("INVALID_CONTRACT", moduleName);
      continue;
    }
    if (modules.has(moduleName)) {
      add("DUPLICATE_MODULE", moduleName);
    }
    modules.add(moduleName);
    if (!validSemanticVersion(contract.version)) {
      add("INVALID_VERSION", moduleName);
    }
    if (!["ACTIVE", "DEPRECATED"].includes(contract.status)) {
      add("INVALID_STATUS", moduleName);
      continue;
    }
    if (contract.status === "ACTIVE") {
      if (
        contract.deprecated_at !== null ||
        contract.remove_not_before !== null
      ) {
        add("ACTIVE_WITH_DEPRECATION", moduleName);
      }
      continue;
    }
    if (!nonEmptyString(contract.replacement_contract)) {
      add("MISSING_REPLACEMENT", moduleName);
    }
    if (!validDateTime(contract.deprecated_at)) {
      add("INVALID_DEPRECATION_DATE", moduleName);
    }
    if (!validDateTime(contract.remove_not_before)) {
      add("INVALID_REMOVAL_DATE", moduleName);
    }
    if (
      validDateTime(contract.deprecated_at) &&
      validDateTime(contract.remove_not_before)
    ) {
      const noticeMs =
        Date.parse(contract.remove_not_before) -
        Date.parse(contract.deprecated_at);
      if (
        noticeMs <
        document.minimum_notice_days * 24 * 60 * 60 * 1000
      ) {
        add("NOTICE_TOO_SHORT", moduleName);
      }
    }
  }
  return result(errors);
}

export function createMockResponse(moduleName, operationId, request = {}) {
  if (MODULE_OPERATIONS[moduleName] !== operationId) {
    throw new Error(`未知的 F03 Mock 操作: ${moduleName}.${operationId}`);
  }
  const requestReference = nonEmptyString(request.task_id)
    ? request.task_id
    : "no-task-reference";
  return {
    mock_id: `mock_${moduleName}_${operationId}_${requestReference}`,
    module: moduleName,
    operation_id: operationId,
    request_reference: requestReference,
    contract_status: "SCHEMA_VALID",
    authorization_status: "NOT_EVALUATED",
    connection_status: "MOCK_ONLY",
    synthetic: true,
    outcome: "SYNTHETIC_CONTRACT_RESPONSE",
  };
}

function breaking(code, location, message) {
  return { code, location, message };
}

function compareSchema(previous, next, location, changes) {
  if (!isRecord(previous) || !isRecord(next)) return;
  if (
    previous.type !== undefined &&
    next.type !== undefined &&
    JSON.stringify(previous.type) !== JSON.stringify(next.type)
  ) {
    changes.push(
      breaking("TYPE_CHANGED", location, `${location} 的 type 已改变`),
    );
  }
  if (
    previous.$ref !== undefined &&
    next.$ref !== undefined &&
    previous.$ref !== next.$ref
  ) {
    changes.push(
      breaking("REFERENCE_CHANGED", location, `${location} 的 $ref 已改变`),
    );
  }
  if (Array.isArray(previous.enum) && Array.isArray(next.enum)) {
    for (const value of previous.enum) {
      if (!next.enum.some((item) => Object.is(item, value))) {
        changes.push(
          breaking(
            "ENUM_VALUE_REMOVED",
            location,
            `${location} 移除了枚举值 ${String(value)}`,
          ),
        );
      }
    }
  }
  if (
    previous.additionalProperties !== false &&
    next.additionalProperties === false
  ) {
    changes.push(
      breaking(
        "ADDITIONAL_PROPERTIES_RESTRICTED",
        location,
        `${location} 禁止了额外属性`,
      ),
    );
  }

  const previousRequired = new Set(previous.required ?? []);
  for (const required of next.required ?? []) {
    if (!previousRequired.has(required)) {
      changes.push(
        breaking(
          "REQUIRED_PROPERTY_ADDED",
          `${location}.${required}`,
          `${location} 新增必填属性 ${required}`,
        ),
      );
    }
  }

  const previousProperties = previous.properties ?? {};
  const nextProperties = next.properties ?? {};
  for (const [propertyName, propertySchema] of Object.entries(
    previousProperties,
  )) {
    const childLocation = `${location}.${propertyName}`;
    if (!(propertyName in nextProperties)) {
      changes.push(
        breaking(
          "PROPERTY_REMOVED",
          childLocation,
          `${childLocation} 已移除`,
        ),
      );
    } else {
      compareSchema(
        propertySchema,
        nextProperties[propertyName],
        childLocation,
        changes,
      );
    }
  }
}

export function findBreakingChanges(previous, next) {
  const changes = [];
  const previousPaths = previous?.paths ?? {};
  const nextPaths = next?.paths ?? {};

  for (const [pathName, previousPath] of Object.entries(previousPaths)) {
    const nextPath = nextPaths[pathName];
    if (!isRecord(nextPath)) {
      changes.push(
        breaking("PATH_REMOVED", pathName, `路径 ${pathName} 已移除`),
      );
      continue;
    }
    for (const [method, previousOperation] of Object.entries(previousPath)) {
      if (!HTTP_METHODS.has(method) || !isRecord(previousOperation)) continue;
      const nextOperation = nextPath[method];
      const location = `${method.toUpperCase()} ${pathName}`;
      if (!isRecord(nextOperation)) {
        changes.push(
          breaking("OPERATION_REMOVED", location, `${location} 已移除`),
        );
        continue;
      }
      for (const responseCode of Object.keys(
        previousOperation.responses ?? {},
      )) {
        if (!(responseCode in (nextOperation.responses ?? {}))) {
          changes.push(
            breaking(
              "RESPONSE_REMOVED",
              `${location} ${responseCode}`,
              `${location} 移除了响应 ${responseCode}`,
            ),
          );
        }
      }
    }
  }

  const previousSchemas = previous?.components?.schemas ?? {};
  const nextSchemas = next?.components?.schemas ?? {};
  for (const [schemaName, previousSchema] of Object.entries(previousSchemas)) {
    if (!isRecord(nextSchemas[schemaName])) {
      changes.push(
        breaking(
          "SCHEMA_REMOVED",
          schemaName,
          `Schema ${schemaName} 已移除`,
        ),
      );
    } else {
      compareSchema(
        previousSchema,
        nextSchemas[schemaName],
        `components.schemas.${schemaName}`,
        changes,
      );
    }
  }
  return changes;
}

async function readJsonArgument(value) {
  return JSON.parse(await readFile(path.resolve(value), "utf8"));
}

async function main(args = process.argv.slice(2)) {
  if (args[0] === "breaking") {
    if (args.length !== 3) {
      process.stdout.write(
        `${JSON.stringify({
          status: "INVALID_ARGUMENTS",
          usage: "breaking <previous> <candidate>",
        })}\n`,
      );
      process.exitCode = 2;
      return;
    }
    const [previous, candidate] = await Promise.all([
      readJsonArgument(args[1]),
      readJsonArgument(args[2]),
    ]);
    const changes = findBreakingChanges(previous, candidate);
    process.stdout.write(
      `${JSON.stringify({
        status:
          changes.length === 0 ? "COMPATIBLE" : "BREAKING_CHANGE",
        changes,
      })}\n`,
    );
    process.exitCode = changes.length === 0 ? 0 : 1;
    return;
  }
  const lab = await loadContractLab();
  const validation = validateContractLab(lab);
  const knownBreakingChanges = findBreakingChanges(
    lab.contracts.core,
    lab.negatives.breakingContract,
  );
  const summary = {
    status:
      validation.valid && knownBreakingChanges.length > 0 ? "PASS" : "FAIL",
    frozen_contracts: Object.keys(lab.contracts).length,
    validation_errors: validation.errors,
    detected_negative_breaking_changes: knownBreakingChanges.map(
      (item) => item.code,
    ),
    boundaries: {
      schema_valid_means_authorized: false,
      mock_means_enterprise_connected: false,
    },
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (summary.status !== "PASS") process.exitCode = 1;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  await main();
}
