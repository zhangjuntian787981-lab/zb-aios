import assert from "node:assert/strict";
import test from "node:test";
import {
  createTenantGovernanceShell,
} from "../lib/tenant-governance-shell.mjs";

test("the replaceable management shell delegates authority to C02 BFF", async () => {
  const calls = [];
  const shell = createTenantGovernanceShell({
    bffClient: {
      async read(request) {
        calls.push(["read", request]);
        return {
          authorityOwner: "PRODUCT_CORE",
          authorizationEvidenceRef: "evidence://c06/decision/shell-1",
          allowedActions: [
            "TENANT_CONFIG_VIEW",
            "TENANT_CONFIG_CHANGE",
          ],
          operationId: "TENANT_CONFIG_VIEW",
          items: [],
        };
      },
      async mutate(request) {
        calls.push(["mutate", request]);
        return {
          authorityOwner: "PRODUCT_CORE",
          authorizationEvidenceRef: "evidence://c06/decision/shell-2",
          operationId: "TENANT_CONFIG_CHANGE",
          status: "COMMITTED",
          auditRef: "evidence://c18/event/shell-2",
        };
      },
    },
  });

  const pages = shell.listPages();
  assert.equal(pages.length, 9);
  assert.equal(
    pages.find(({ readOperationId }) =>
      readOperationId === "AUDIT_VIEW"
    ).writeOperationId,
    null,
  );
  assert.equal(
    pages.some(({ readOperationId }) =>
      readOperationId.includes("PRIVATE")
    ),
    false,
  );

  const readRequest = { operationId: "TENANT_CONFIG_VIEW" };
  const view = await shell.load(readRequest);
  assert.deepEqual(shell.allowedActions(view), [
    "TENANT_CONFIG_VIEW",
    "TENANT_CONFIG_CHANGE",
  ]);

  const mutationRequest = { operationId: "TENANT_CONFIG_CHANGE" };
  const receipt = await shell.submit(mutationRequest);
  assert.equal(receipt.status, "COMMITTED");
  assert.deepEqual(calls, [
    ["read", readRequest],
    ["mutate", mutationRequest],
  ]);
  assert.equal(Object.isFrozen(shell), true);
});

test("the shell cannot invent a private action from local UI state", () => {
  const shell = createTenantGovernanceShell({
    bffClient: {
      async read() {
        throw new Error("not used");
      },
      async mutate() {
        throw new Error("not used");
      },
    },
  });

  assert.throws(
    () =>
      shell.allowedActions({
        authorityOwner: "PRODUCT_CORE",
        authorizationEvidenceRef:
          "evidence://c06/decision/counterfeit",
        allowedActions: ["PRIVATE_MEMORY_VIEW"],
      }),
    (error) => error.code === "UNTRUSTED_BFF_RESPONSE",
  );
});
