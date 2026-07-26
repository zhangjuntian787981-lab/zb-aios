import assert from "node:assert/strict";
import test from "node:test";
import {
  createEmployeePortalShell,
} from "../lib/employee-portal-shell.mjs";

const VIEW = Object.freeze({
  schemaVersion: "c01-portal-view.v1",
  tenantId: "stn_018f0000-0000-7000-8000-000000000010",
  operationId: "PORTAL_HOME_VIEW",
  resourceId: "c01-portal-home-demo",
  resourceVersion: 1,
  items: [
    {
      panelRef: "synthetic://c01/panel/home",
      status: "ACTIVE",
    },
  ],
  evidenceRefs: ["evidence://c01/home/demo"],
  authorityOwner: "PRODUCT_CORE",
  authorizationEvidenceRef: "evidence://c06/decision/c01-demo",
});

test("both portal renderers depend on the same replaceable BFF contract", async () => {
  const calls = [];
  const bffClient = {
    async read(request) {
      calls.push(["read", request]);
      return VIEW;
    },
    async mutate(request) {
      calls.push(["mutate", request]);
      return {
        schemaVersion: "c01-portal-mutation-receipt.v1",
        tenantId: VIEW.tenantId,
        operationId: "CHAT_SUBMIT",
        resourceId: "c01-thread-demo",
        resourceVersion: 2,
        commandRef: "synthetic://c01/command/chat-demo",
        commandSha256:
          "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        status: "ACCEPTED",
        resultRef: "synthetic://c08/run/demo",
        ownerPrincipalId:
          "prn_018f0000-0000-7000-8000-000000000001",
        evidenceRefs: ["evidence://c08/run/demo"],
        auditRef: "evidence://c18/event/chat-demo",
        authorityOwner: "PRODUCT_CORE",
        authorizationEvidenceRef:
          "evidence://c06/decision/c01-demo",
      };
    },
    async *stream(request) {
      calls.push(["stream", request]);
      yield {
        schemaVersion: "c01-portal-stream-event.v1",
        tenantId: VIEW.tenantId,
        resourceId: "c01-run-demo",
        sequence: 1,
        eventType: "COMPLETED",
        dataRef: "synthetic://c08/run/demo/result",
        evidenceRefs: ["evidence://c08/run/demo"],
        ownerPrincipalId:
          "prn_018f0000-0000-7000-8000-000000000001",
        authorityOwner: "PRODUCT_CORE",
        authorizationEvidenceRef:
          "evidence://c06/decision/c01-demo",
      };
    },
  };

  for (const renderer of ["LIBRECHAT_ADAPTER", "MINIMAL_REPLACEMENT"]) {
    const shell = createEmployeePortalShell({ renderer, bffClient });
    assert.deepEqual(
      shell.listSurfaces().map(({ surfaceId }) => surfaceId),
      [
        "home",
        "threads",
        "runs",
        "files",
        "resources",
        "agent-skills",
        "memory",
        "approvals",
        "citations",
      ],
    );
    assert.equal((await shell.load({ renderer })).authorityOwner, "PRODUCT_CORE");
    assert.equal(
      (await shell.submit({ renderer })).authorityOwner,
      "PRODUCT_CORE",
    );
    const events = [];
    for await (const event of shell.stream({ renderer })) {
      events.push(event);
    }
    assert.equal(events.length, 1);
    assert.equal(shell.renderer, renderer);
  }
  assert.equal(calls.length, 6);
});

test("the portal shell rejects local or unbound authority", async () => {
  const shell = createEmployeePortalShell({
    renderer: "MINIMAL_REPLACEMENT",
    bffClient: {
      async read() {
        return {
          ...VIEW,
          authorityOwner: "PORTAL_LOCAL_STATE",
        };
      },
      async mutate() {
        throw new Error("not used");
      },
      async *stream() {
        throw new Error("not used");
      },
    },
  });

  await assert.rejects(
    shell.load({}),
    (error) => error.code === "UNTRUSTED_BFF_RESPONSE",
  );
});
