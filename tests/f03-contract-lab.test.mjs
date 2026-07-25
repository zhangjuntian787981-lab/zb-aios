import assert from "node:assert/strict";
import test from "node:test";
import {
  createMockResponse,
  findBreakingChanges,
  loadContractLab,
  validateCloudEvent,
  validateContractLab,
  validateProblemDetails,
  validateTaskEnvelope,
} from "../scripts/f03-contract-lab.mjs";

const labRoot = new URL("../implementation/p0/f03/", import.meta.url);

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
