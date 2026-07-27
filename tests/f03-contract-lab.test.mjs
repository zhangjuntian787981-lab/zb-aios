import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  createJsonSchemaValidators,
  createMockResponse,
  findBreakingChanges,
  loadContractLab,
  validateCloudEvent,
  validateContractLab,
  validateDeprecationMatrix,
  validateProblemDetails,
  validateTaskEnvelope,
} from "../scripts/f03-contract-lab.mjs";

const labRoot = new URL("../implementation/p0/f03/", import.meta.url);
const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const schemaCases = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f03/schema-validation-cases.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const packageDocument = JSON.parse(
  await readFile(new URL("../package.json", import.meta.url), "utf8"),
);
const breakingCases = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f03/breaking-mutation-cases.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const frozenDigests = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f03/frozen-contract-digests.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const deprecationCases = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f03/deprecation-validation-cases.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

function mutatedSample(source, fixture) {
  const value = structuredClone(source);
  let parent = value;
  for (const segment of fixture.path.slice(0, -1)) {
    parent = parent[segment];
  }
  const key = fixture.path.at(-1);
  if (fixture.operation === "remove") {
    delete parent[key];
  } else {
    parent[key] = structuredClone(fixture.value);
  }
  return value;
}

function breakingBase() {
  return {
    openapi: "3.1.2",
    paths: {
      "/v1/tasks": {
        post: {
          operationId: "createTask",
          responses: {
            "202": { description: "accepted" },
            default: { description: "problem" },
          },
        },
      },
    },
    components: {
      schemas: {
        Task: {
          type: "object",
          required: ["task_id"],
          properties: {
            task_id: { type: "string" },
            note: { type: "string" },
            state: { type: "string", enum: ["OPEN", "CLOSED"] },
            linked: { $ref: "#/components/schemas/Linked" },
          },
        },
        Linked: {
          type: "object",
          properties: { id: { type: "string" } },
        },
      },
    },
  };
}

function breakingMutation(kind) {
  const next = structuredClone(breakingBase());
  if (kind === "PATH_REMOVED") delete next.paths["/v1/tasks"];
  if (kind === "OPERATION_REMOVED") delete next.paths["/v1/tasks"].post;
  if (kind === "RESPONSE_REMOVED") {
    delete next.paths["/v1/tasks"].post.responses["202"];
  }
  if (kind === "PROPERTY_REMOVED") {
    delete next.components.schemas.Task.properties.note;
  }
  if (kind === "REQUIRED_PROPERTY_ADDED") {
    next.components.schemas.Task.required.push("note");
  }
  if (kind === "TYPE_CHANGED") {
    next.components.schemas.Task.properties.note.type = "number";
  }
  if (kind === "ENUM_VALUE_REMOVED") {
    next.components.schemas.Task.properties.state.enum = ["OPEN"];
  }
  if (kind === "REFERENCE_CHANGED") {
    next.components.schemas.Task.properties.linked.$ref =
      "#/components/schemas/Replacement";
  }
  return next;
}

test("F03 freezes six minimal OpenAPI 3.1.2 module contracts", async () => {
  const lab = await loadContractLab(labRoot);
  const result = validateContractLab(lab);

  assert.equal(result.valid, true, result.errors.join("\n"));
  assert.deepEqual(
    Object.keys(lab.contracts).sort(),
    ["audit", "connector", "core", "model", "portal", "tool"],
  );
  for (const contract of Object.values(lab.contracts)) {
    assert.equal(contract.openapi, "3.1.2");
  }
});

test("canonical TaskEnvelope, Problem Details and CloudEvent samples validate", async () => {
  const lab = await loadContractLab(labRoot);

  assert.deepEqual(validateTaskEnvelope(lab.samples.taskEnvelope), {
    valid: true,
    errors: [],
  });
  assert.deepEqual(validateProblemDetails(lab.samples.problemDetails), {
    valid: true,
    errors: [],
  });
  assert.deepEqual(validateCloudEvent(lab.samples.cloudEvent), {
    valid: true,
    errors: [],
  });
});

test("fixed Ajv JSON Schema 2020-12 validates positives and every used keyword negative", async () => {
  const lab = await loadContractLab(labRoot);
  const validators = createJsonSchemaValidators(lab.schemas);
  assert.equal(packageDocument.devDependencies.ajv, "8.20.0");
  assert.equal(packageDocument.devDependencies["ajv-formats"], "2.1.1");
  assert.deepEqual(schemaCases.validator, {
    draft: "2020-12",
    ajv: "8.20.0",
    ajvFormats: "2.1.1",
    strict: true,
  });

  for (const name of ["taskEnvelope", "problemDetails", "cloudEvent"]) {
    assert.deepEqual(validators.validate(name, lab.samples[name]), {
      valid: true,
      errors: [],
    });
  }
  for (const fixture of schemaCases.cases) {
    const validation = validators.validate(
      fixture.schema,
      mutatedSample(lab.samples[fixture.schema], fixture),
    );
    assert.equal(validation.valid, false, fixture.id);
    assert.equal(
      validation.errors.some(
        ({ keyword }) => keyword === fixture.expectedKeyword,
      ),
      true,
      fixture.id,
    );
  }
});

test("negative fixtures fail without accepting leaked stacks or secrets", async () => {
  const lab = await loadContractLab(labRoot);

  assert.equal(
    validateTaskEnvelope(lab.negatives.taskEnvelope).valid,
    false,
  );
  const problemResult = validateProblemDetails(lab.negatives.problemDetails);
  assert.equal(problemResult.valid, false);
  assert.match(problemResult.errors.join("\n"), /敏感|堆栈/);
  assert.equal(validateCloudEvent(lab.negatives.cloudEvent).valid, false);
});

test("mock responses are pure and never claim authorization or enterprise access", () => {
  const request = {
    task_id: "tsk_01j00000000000000000000000",
    operation_id: "createTask",
  };
  const before = structuredClone(request);
  const first = createMockResponse("core", "createTask", request);
  const second = createMockResponse("core", "createTask", request);

  assert.deepEqual(request, before);
  assert.deepEqual(first, second);
  assert.equal(first.contract_status, "SCHEMA_VALID");
  assert.equal(first.authorization_status, "NOT_EVALUATED");
  assert.equal(first.connection_status, "MOCK_ONLY");
  assert.equal(first.synthetic, true);
});

test("breaking-change check blocks removals and new required fields", () => {
  const previous = {
    openapi: "3.1.2",
    paths: {
      "/v1/tasks": {
        post: {
          operationId: "createTask",
          responses: { "202": { description: "accepted" } },
        },
      },
    },
    components: {
      schemas: {
        Task: {
          type: "object",
          required: ["task_id"],
          properties: {
            task_id: { type: "string" },
            note: { type: "string" },
          },
        },
      },
    },
  };
  const additive = structuredClone(previous);
  additive.components.schemas.Task.properties.label = { type: "string" };
  assert.deepEqual(findBreakingChanges(previous, additive), []);

  const next = structuredClone(previous);
  delete next.paths["/v1/tasks"];
  next.components.schemas.Task.required.push("note");
  const breaking = findBreakingChanges(previous, next);

  assert.ok(breaking.some((item) => item.code === "PATH_REMOVED"));
  assert.ok(
    breaking.some((item) => item.code === "REQUIRED_PROPERTY_ADDED"),
  );
});

test("breaking-change matrix detects every frozen mutation category", () => {
  for (const fixture of breakingCases.cases) {
    const changes = findBreakingChanges(
      breakingBase(),
      breakingMutation(fixture.mutation),
    );
    assert.equal(
      changes.some(({ code }) => code === fixture.expectedCode),
      true,
      fixture.id,
    );
  }
});

test("frozen v1 contracts keep their exact SHA-256", async () => {
  for (const contract of frozenDigests.contracts) {
    const contents = await readFile(
      new URL(`../${contract.path}`, import.meta.url),
    );
    assert.equal(
      `sha256:${createHash("sha256").update(contents).digest("hex")}`,
      contract.sha256,
      contract.path,
    );
  }
});

test("breaking CLI exits non-zero for a breaking candidate and zero for an identical contract", () => {
  const script = "scripts/f03-contract-lab.mjs";
  const current =
    "implementation/p0/f03/contracts/core.openapi.v1.json";
  const breaking =
    "implementation/p0/f03/negative/core-breaking.openapi.v2.json";
  const rejected = spawnSync(
    process.execPath,
    [script, "breaking", current, breaking],
    { cwd: repositoryRoot, encoding: "utf8" },
  );
  assert.equal(rejected.status, 1);
  assert.equal(JSON.parse(rejected.stdout).status, "BREAKING_CHANGE");

  const accepted = spawnSync(
    process.execPath,
    [script, "breaking", current, current],
    { cwd: repositoryRoot, encoding: "utf8" },
  );
  assert.equal(accepted.status, 0);
  assert.equal(JSON.parse(accepted.stdout).status, "COMPATIBLE");
});

test("deprecation lifecycle validates replacement, dates, semantic version, and 90-day notice", async () => {
  const lab = await loadContractLab(labRoot);
  assert.deepEqual(validateDeprecationMatrix(lab.deprecation), {
    valid: true,
    errors: [],
  });
  for (const fixture of deprecationCases.cases) {
    const validation = validateDeprecationMatrix({
      matrix_version: "validation-only",
      minimum_notice_days: deprecationCases.minimumNoticeDays,
      breaking_change_policy: "MAJOR_VERSION_ONLY",
      removal_requirements: [],
      contracts: [fixture.contract],
    });
    assert.equal(validation.valid, fixture.expectedValid, fixture.id);
    assert.equal(
      fixture.expectedCode === null ||
        validation.errors.some(
          ({ code }) => code === fixture.expectedCode,
        ),
      true,
      fixture.id,
    );
  }
});

test("compatibility and deprecation matrices cover every frozen contract", async () => {
  const lab = await loadContractLab(labRoot);
  const modules = new Set(Object.keys(lab.contracts));
  const matrixModules = new Set(
    lab.compatibility.contracts.map((entry) => entry.module),
  );

  assert.deepEqual(matrixModules, modules);
  assert.equal(lab.compatibility.openapi_version, "3.1.2");
  assert.equal(lab.deprecation.breaking_change_policy, "MAJOR_VERSION_ONLY");
  assert.ok(lab.deprecation.minimum_notice_days >= 90);
  assert.ok(
    lab.deprecation.contracts.every((entry) => entry.status === "ACTIVE"),
  );
  for (const entry of lab.compatibility.contracts) {
    const response = createMockResponse(
      entry.module,
      entry.operation_id,
      lab.samples.taskEnvelope,
    );
    assert.equal(response.authorization_status, "NOT_EVALUATED");
    assert.equal(response.connection_status, "MOCK_ONLY");
  }

  const knownBreaking = findBreakingChanges(
    lab.contracts.core,
    lab.negatives.breakingContract,
  );
  assert.ok(knownBreaking.some((entry) => entry.code === "PATH_REMOVED"));
});
