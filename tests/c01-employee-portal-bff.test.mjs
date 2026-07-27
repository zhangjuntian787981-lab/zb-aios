import assert from "node:assert/strict";
import test from "node:test";
import {
  createEmployeePortalBff,
} from "../lib/employee-portal-bff.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const OTHER_TENANT =
  "stn_018f0000-0000-7000-8000-000000000099";
const HUMAN =
  "prn_018f0000-0000-7000-8000-000000000001";
const OTHER_HUMAN =
  "prn_018f0000-0000-7000-8000-000000000099";
const WORKLOAD =
  "prn_018f0000-0000-7000-8000-000000000002";

function context(overrides = {}) {
  return {
    synthetic: true,
    routeTrustSource: "VERIFIED_ROUTE_DESCRIPTOR",
    tenantId: TENANT,
    workloadTrustSource: "VERIFIED_WORKLOAD_CONTEXT",
    workloadActorPrincipalId: WORKLOAD,
    ...overrides,
  };
}

function readRequest(overrides = {}) {
  return {
    sessionToken: "synthetic-session",
    delegationId: "synthetic-delegation",
    correlationId: "corr-c01-read-1",
    operationId: "THREAD_VIEW",
    resourceId: "c01-thread-demo",
    ...overrides,
  };
}

function mutationRequest(overrides = {}) {
  return {
    sessionToken: "synthetic-session",
    delegationId: "synthetic-delegation",
    correlationId: "corr-c01-write-1",
    idempotencyKey: "idem-c01-write-1",
    operationId: "FILE_QUARANTINE_REQUEST",
    resourceId: "c01-file-demo",
    expectedVersion: 1,
    commandRef: "synthetic://c01/command/file-demo",
    commandSha256:
      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    ...overrides,
  };
}

function streamRequest(overrides = {}) {
  return readRequest({
    correlationId: "corr-c01-stream-1",
    operationId: "RUN_STREAM_VIEW",
    resourceId: "c01-run-demo",
    ...overrides,
  });
}

function authorization(serverContext, input, descriptor, overrides = {}) {
  return {
    trustSource: "C06_BOUND_DECISION_EVIDENCE",
    tenantId: serverContext.tenantId,
    humanPrincipalId: HUMAN,
    workloadActorPrincipalId:
      serverContext.workloadActorPrincipalId,
    decisionId: "dec-c01-1",
    evidenceRef: "evidence://c06/decision/c01-1",
    policyVersion: "c06-policy-1",
    resourceId: input.resourceId,
    operationId: descriptor.operationId,
    ...overrides,
  };
}

function authorizedBff(corePort, authorizationOverrides = {}) {
  return createEmployeePortalBff({
    authorizer: {
      async enforce(serverContext, input, descriptor) {
        return authorization(
          serverContext,
          input,
          descriptor,
          authorizationOverrides,
        );
      },
    },
    corePort,
  });
}

test("an authorized synthetic employee sees only their private Core view", async () => {
  const bff = authorizedBff({
    async read(scope, command) {
      return {
        schemaVersion: "c01-portal-view.v1",
        tenantId: scope.tenantId,
        operationId: command.operationId,
        resourceId: command.resourceId,
        resourceVersion: 1,
        items: [
          {
            threadRef: "synthetic://c08/thread/demo",
            titleRef: "synthetic://c08/title/demo",
            status: "ACTIVE",
            ownerPrincipalId: HUMAN,
          },
        ],
        evidenceRefs: ["evidence://c08/thread/demo"],
      };
    },
    async mutate() {
      throw new Error("not used");
    },
    async *stream() {
      throw new Error("not used");
    },
  });

  const result = await bff.read(context(), readRequest());

  assert.equal(result.authorityOwner, "PRODUCT_CORE");
  assert.equal(result.tenantId, TENANT);
  assert.equal(result.items[0].ownerPrincipalId, HUMAN);
  assert.equal(
    result.authorizationEvidenceRef,
    "evidence://c06/decision/c01-1",
  );
  assert.equal(Object.isFrozen(result), true);
});

test("every frozen portal view is projected only through the Core seam", async () => {
  const cases = [
    [
      "PORTAL_HOME_VIEW",
      { panelRef: "synthetic://c01/panel/home", status: "ACTIVE" },
    ],
    [
      "THREAD_VIEW",
      {
        threadRef: "synthetic://c08/thread/demo",
        titleRef: "synthetic://c08/title/demo",
        status: "ACTIVE",
        ownerPrincipalId: HUMAN,
      },
    ],
    [
      "RUN_VIEW",
      {
        runRef: "synthetic://c08/run/demo",
        status: "RUNNING",
        streamRef: "synthetic://c01/stream/demo",
        ownerPrincipalId: HUMAN,
      },
    ],
    [
      "FILE_STATUS_VIEW",
      {
        fileRef: "synthetic://c10/file/demo",
        status: "QUARANTINED",
        quarantineRef:
          `quarantine://c10/${TENANT}/file-demo/1/${"1".repeat(64)}`,
        contentSha256: `sha256:${"1".repeat(64)}`,
        ownerPrincipalId: HUMAN,
      },
    ],
    [
      "RESOURCE_DIRECTORY_VIEW",
      {
        resourceRef: "synthetic://c11/resource/demo",
        resourceType: "KNOWLEDGE",
        titleRef: "synthetic://c11/title/demo",
        evidenceRef: "evidence://c11/resource/demo",
      },
    ],
    [
      "AGENT_SKILL_DIRECTORY_VIEW",
      {
        resourceRef: "synthetic://c13/skill/demo",
        resourceType: "SKILL",
        titleRef: "synthetic://c13/title/demo",
        releaseChannel: "PILOT",
        contentSha256: `sha256:${"2".repeat(64)}`,
        evidenceRef: "evidence://c13/skill/demo",
      },
    ],
    [
      "MEMORY_VIEW",
      {
        memoryRef: "synthetic://c09/memory/demo",
        status: "CONFIRMED",
        contentSha256: `sha256:${"3".repeat(64)}`,
        ownerPrincipalId: HUMAN,
      },
    ],
    [
      "APPROVAL_VIEW",
      {
        approvalRef: "synthetic://c15/approval/demo",
        status: "PENDING",
        artifactRef: "synthetic://c08/artifact/demo",
        artifactSha256: `sha256:${"4".repeat(64)}`,
        ownerPrincipalId: HUMAN,
      },
    ],
    [
      "CITATION_VIEW",
      {
        evidenceRef: "evidence://c11/citation/demo",
        resourceRef: "synthetic://c10/resource/demo",
        locatorRef: "synthetic://c10/locator/demo",
        titleRef: "synthetic://c10/title/demo",
        status: "AVAILABLE",
        reasonCode: "CURRENT_AUTHORIZED_SOURCE",
        ownerPrincipalId: HUMAN,
      },
    ],
  ];
  const bff = authorizedBff({
    async read(scope, command) {
      return {
        schemaVersion: "c01-portal-view.v1",
        tenantId: scope.tenantId,
        operationId: command.operationId,
        resourceId: command.resourceId,
        resourceVersion: 1,
        items: [
          cases.find(([operationId]) =>
            operationId === command.operationId
          )[1],
        ],
        evidenceRefs: ["evidence://c01/view/demo"],
      };
    },
    async mutate() {
      throw new Error("not used");
    },
    async *stream() {
      throw new Error("not used");
    },
  });

  for (const [operationId, item] of cases) {
    const result = await bff.read(
      context(),
      readRequest({
        operationId,
        resourceId:
          `c01-view-${operationId.toLowerCase().replaceAll("_", "-")}`,
      }),
    );
    assert.deepEqual(result.items, [item]);
  }
});

test("file status view rejects non-quarantined or cross-Tenant references", async () => {
  for (const item of [
    {
      fileRef: "synthetic://c10/file/demo",
      status: "READY",
      quarantineRef:
        `quarantine://c10/${TENANT}/file-demo/1/${"1".repeat(64)}`,
      contentSha256: `sha256:${"1".repeat(64)}`,
      ownerPrincipalId: HUMAN,
    },
    {
      fileRef: "synthetic://c10/file/demo",
      status: "QUARANTINED",
      quarantineRef:
        `quarantine://c10/${OTHER_TENANT}/file-demo/1/${"1".repeat(64)}`,
      contentSha256: `sha256:${"1".repeat(64)}`,
      ownerPrincipalId: HUMAN,
    },
  ]) {
    const bff = authorizedBff({
      async read(scope, command) {
        return {
          schemaVersion: "c01-portal-view.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: 1,
          items: [item],
          evidenceRefs: ["evidence://c10/quarantine/file-demo"],
        };
      },
      async mutate() {
        throw new Error("not used");
      },
      async *stream() {
        throw new Error("not used");
      },
    });

    await assert.rejects(
      bff.read(
        context(),
        readRequest({
          operationId: "FILE_STATUS_VIEW",
          resourceId: "c01-file-demo",
        }),
      ),
      (error) => error.code === "CORE_RESULT_INVALID",
    );
  }
});

test("cross-user or cross-Tenant evidence fails before private data is returned", async () => {
  let coreCalls = 0;
  const privateView = {
    schemaVersion: "c01-portal-view.v1",
    tenantId: TENANT,
    operationId: "THREAD_VIEW",
    resourceId: "c01-thread-demo",
    resourceVersion: 1,
    items: [
      {
        threadRef: "synthetic://c08/thread/demo",
        titleRef: "synthetic://c08/title/demo",
        status: "ACTIVE",
        ownerPrincipalId: OTHER_HUMAN,
      },
    ],
    evidenceRefs: ["evidence://c08/thread/demo"],
  };
  const corePort = {
    async read() {
      coreCalls += 1;
      return privateView;
    },
    async mutate() {
      throw new Error("not used");
    },
    async *stream() {
      throw new Error("not used");
    },
  };
  const crossUser = authorizedBff(corePort);
  await assert.rejects(
    crossUser.read(context(), readRequest()),
    (error) => error.code === "CORE_RESULT_INVALID",
  );
  const crossTenant = authorizedBff(corePort, {
    tenantId: OTHER_TENANT,
  });
  await assert.rejects(
    crossTenant.read(context(), readRequest()),
    (error) => error.code === "ACCESS_DENIED",
  );
  assert.equal(coreCalls, 1);
});

test("bypassing the portal UI still authorizes before Product Core", async () => {
  let coreCalls = 0;
  const bff = createEmployeePortalBff({
    authorizer: {
      async enforce() {
        throw new Error("denied");
      },
    },
    corePort: {
      async read() {
        coreCalls += 1;
      },
      async mutate() {
        coreCalls += 1;
      },
      async *stream() {
        coreCalls += 1;
      },
    },
  });

  await assert.rejects(
    bff.read(context(), readRequest()),
    (error) => error.code === "ACCESS_DENIED",
  );
  await assert.rejects(
    bff.mutate(context(), mutationRequest()),
    (error) => error.code === "ACCESS_DENIED",
  );
  assert.equal(coreCalls, 0);
});

test("the portal cannot accept raw file bytes and only returns quarantine state", async () => {
  let coreCalls = 0;
  const bff = authorizedBff({
    async read() {
      throw new Error("not used");
    },
    async mutate(scope, command) {
      coreCalls += 1;
      return {
        schemaVersion: "c01-portal-mutation-receipt.v1",
        tenantId: scope.tenantId,
        operationId: command.operationId,
        resourceId: command.resourceId,
        resourceVersion: 2,
        commandRef: command.commandRef,
        commandSha256: command.commandSha256,
        status: "QUARANTINED",
        resultRef:
          `quarantine://c10/${scope.tenantId}/file-demo/1/` +
          "1".repeat(64),
        ownerPrincipalId: HUMAN,
        evidenceRefs: ["evidence://c10/quarantine/file-demo"],
        auditRef: "evidence://c18/event/file-demo",
      };
    },
    async *stream() {
      throw new Error("not used");
    },
  });

  await assert.rejects(
    bff.mutate(
      context(),
      mutationRequest({ bytes: "not-allowed" }),
    ),
    (error) => error.code === "INVALID_INPUT",
  );
  assert.equal(coreCalls, 0);

  const result = await bff.mutate(context(), mutationRequest());
  assert.equal(coreCalls, 1);
  assert.equal(result.status, "QUARANTINED");
  assert.match(result.resultRef, /^quarantine:\/\/c10\//);
  assert.equal(result.auditRef, "evidence://c18/event/file-demo");
});

test("the frozen command catalog accepts only its operation-specific receipt status", async () => {
  const cases = [
    ["THREAD_CREATE", "CREATED", "synthetic://c08/thread/demo"],
    ["CHAT_SUBMIT", "ACCEPTED", "synthetic://c08/run/demo"],
    [
      "FILE_QUARANTINE_REQUEST",
      "QUARANTINED",
      `quarantine://c10/${TENANT}/file-demo/1/${"1".repeat(64)}`,
    ],
    ["MEMORY_CONFIRM", "RECORDED", "synthetic://c09/memory/demo"],
    [
      "APPROVAL_DECIDE",
      "RECORDED",
      "evidence://c15/decision/demo",
    ],
  ];
  const bff = authorizedBff({
    async read() {
      throw new Error("not used");
    },
    async mutate(scope, command) {
      const [, status, resultRef] = cases.find(
        ([operationId]) => operationId === command.operationId,
      );
      return {
        schemaVersion: "c01-portal-mutation-receipt.v1",
        tenantId: scope.tenantId,
        operationId: command.operationId,
        resourceId: command.resourceId,
        resourceVersion: command.expectedVersion + 1,
        commandRef: command.commandRef,
        commandSha256: command.commandSha256,
        status,
        resultRef,
        ownerPrincipalId: HUMAN,
        evidenceRefs: ["evidence://c01/command/demo"],
        auditRef: "evidence://c18/event/command-demo",
      };
    },
    async *stream() {
      throw new Error("not used");
    },
  });

  for (const [operationId, status] of cases) {
    const result = await bff.mutate(
      context(),
      mutationRequest({
        operationId,
        resourceId:
          `c01-command-${operationId.toLowerCase().replaceAll("_", "-")}`,
      }),
    );
    assert.equal(result.status, status);
  }
});

test("portal mutation receipts remain bound to command, version, and C18 audit", async () => {
  const bff = authorizedBff({
    async read() {
      throw new Error("not used");
    },
    async mutate(scope, command) {
      return {
        schemaVersion: "c01-portal-mutation-receipt.v1",
        tenantId: scope.tenantId,
        operationId: command.operationId,
        resourceId: command.resourceId,
        resourceVersion: 99,
        commandRef: command.commandRef,
        commandSha256: command.commandSha256,
        status: "QUARANTINED",
        resultRef: "synthetic://c01/not-quarantined",
        ownerPrincipalId: HUMAN,
        evidenceRefs: ["evidence://c10/quarantine/file-demo"],
        auditRef: "synthetic://c01/not-audit",
      };
    },
    async *stream() {
      throw new Error("not used");
    },
  });

  await assert.rejects(
    bff.mutate(context(), mutationRequest()),
    (error) => error.code === "CORE_RESULT_INVALID",
  );
});

test("cross-Tenant or cross-user mutation receipts fail closed", async () => {
  for (const overrides of [
    { tenantId: OTHER_TENANT },
    { ownerPrincipalId: OTHER_HUMAN },
  ]) {
    const bff = authorizedBff({
      async read() {
        throw new Error("not used");
      },
      async mutate(scope, command) {
        return {
          schemaVersion: "c01-portal-mutation-receipt.v1",
          tenantId: scope.tenantId,
          operationId: command.operationId,
          resourceId: command.resourceId,
          resourceVersion: command.expectedVersion + 1,
          commandRef: command.commandRef,
          commandSha256: command.commandSha256,
          status: "QUARANTINED",
          resultRef:
            `quarantine://c10/${scope.tenantId}/file-demo/1/` +
            "1".repeat(64),
          ownerPrincipalId: HUMAN,
          evidenceRefs: ["evidence://c10/quarantine/file-demo"],
          auditRef: "evidence://c18/event/file-demo",
          ...overrides,
        };
      },
      async *stream() {
        throw new Error("not used");
      },
    });

    await assert.rejects(
      bff.mutate(context(), mutationRequest()),
      (error) => error.code === "CORE_RESULT_INVALID",
    );
  }
});

test("stream events are Tenant-, owner-, run-, and sequence-bound", async () => {
  const bff = authorizedBff({
    async read() {
      throw new Error("not used");
    },
    async mutate() {
      throw new Error("not used");
    },
    async *stream(scope, command) {
      yield {
        schemaVersion: "c01-portal-stream-event.v1",
        tenantId: scope.tenantId,
        resourceId: command.resourceId,
        sequence: 1,
        eventType: "RUN_STATUS",
        dataRef: "synthetic://c08/run/demo/status/1",
        evidenceRefs: ["evidence://c08/run/demo/1"],
        ownerPrincipalId: HUMAN,
      };
      yield {
        schemaVersion: "c01-portal-stream-event.v1",
        tenantId: scope.tenantId,
        resourceId: command.resourceId,
        sequence: 2,
        eventType: "COMPLETED",
        dataRef: "synthetic://c08/run/demo/result",
        evidenceRefs: ["evidence://c08/run/demo/2"],
        ownerPrincipalId: HUMAN,
      };
    },
  });
  const request = readRequest({
    operationId: "RUN_STREAM_VIEW",
    resourceId: "c01-run-demo",
  });

  const events = [];
  for await (const event of bff.stream(context(), request)) {
    events.push(event);
  }
  assert.deepEqual(
    events.map(({ sequence }) => sequence),
    [1, 2],
  );
  assert.equal(events[0].authorityOwner, "PRODUCT_CORE");
});

test("cross-Tenant or cross-user stream events are never yielded", async () => {
  for (const overrides of [
    { tenantId: OTHER_TENANT },
    { ownerPrincipalId: OTHER_HUMAN },
  ]) {
    const bff = authorizedBff({
      async read() {
        throw new Error("not used");
      },
      async mutate() {
        throw new Error("not used");
      },
      async *stream(scope, command) {
        yield {
          schemaVersion: "c01-portal-stream-event.v1",
          tenantId: scope.tenantId,
          resourceId: command.resourceId,
          sequence: 1,
          eventType: "RUN_STATUS",
          dataRef: "synthetic://c08/run/demo/status/1",
          evidenceRefs: ["evidence://c08/run/demo/1"],
          ownerPrincipalId: HUMAN,
          ...overrides,
        };
      },
    });
    const events = [];

    await assert.rejects(
      async () => {
        for await (const event of bff.stream(
          context(),
          readRequest({
            operationId: "RUN_STREAM_VIEW",
            resourceId: "c01-run-demo",
          }),
        )) {
          events.push(event);
        }
      },
      (error) => error.code === "CORE_RESULT_INVALID",
    );
    assert.deepEqual(events, []);
  }
});

test("cancel, timeout, and disconnect stop the stream without later side effects or fake success", async (t) => {
  const cases = [
    {
      name: "explicit cancellation",
      expectedCode: "STREAM_CANCELLED",
      trigger({ cancelController }) {
        cancelController.abort();
      },
    },
    {
      name: "server timeout",
      expectedCode: "STREAM_TIMEOUT",
      trigger() {},
    },
    {
      name: "client disconnect",
      expectedCode: "CLIENT_DISCONNECTED",
      trigger({ disconnectController }) {
        disconnectController.abort();
      },
    },
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const sideEffects = [];
      const cancelController = new AbortController();
      const disconnectController = new AbortController();
      let downstreamSignal;
      const bff = createEmployeePortalBff({
        authorizer: {
          async enforce(serverContext, input, descriptor) {
            return authorization(serverContext, input, descriptor);
          },
        },
        corePort: {
          async read() {
            throw new Error("not used");
          },
          async mutate() {
            throw new Error("not used");
          },
          async *stream(scope, command, { signal }) {
            downstreamSignal = signal;
            yield {
              schemaVersion: "c01-portal-stream-event.v1",
              tenantId: scope.tenantId,
              resourceId: command.resourceId,
              sequence: 1,
              eventType: "RUN_STATUS",
              dataRef: "synthetic://c08/run/demo/status/1",
              evidenceRefs: ["evidence://c08/run/demo/1"],
              ownerPrincipalId: HUMAN,
            };
            await new Promise((resolve, reject) => {
              const timer = setTimeout(() => {
                sideEffects.push("TOOL_OR_CONNECTOR_EFFECT");
                resolve();
              }, 80);
              signal.addEventListener(
                "abort",
                () => {
                  clearTimeout(timer);
                  reject(signal.reason);
                },
                { once: true },
              );
            });
            yield {
              schemaVersion: "c01-portal-stream-event.v1",
              tenantId: scope.tenantId,
              resourceId: command.resourceId,
              sequence: 2,
              eventType: "COMPLETED",
              dataRef: "synthetic://c08/run/demo/result",
              evidenceRefs: ["evidence://c08/run/demo/2"],
              ownerPrincipalId: HUMAN,
            };
          },
        },
        streamTimeoutMs: 20,
      });
      const stream = bff.stream(context(), streamRequest(), {
        cancelSignal: cancelController.signal,
        disconnectSignal: disconnectController.signal,
      });

      const first = await stream.next();
      assert.equal(first.value.eventType, "RUN_STATUS");
      scenario.trigger({ cancelController, disconnectController });
      await assert.rejects(
        stream.next(),
        (error) => error.code === scenario.expectedCode,
      );
      assert.equal(downstreamSignal.aborted, true);

      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.deepEqual(sideEffects, []);
    });
  }
});

test("a stream ending without a terminal result fails closed", async () => {
  const bff = authorizedBff({
    async read() {
      throw new Error("not used");
    },
    async mutate() {
      throw new Error("not used");
    },
    async *stream(scope, command) {
      yield {
        schemaVersion: "c01-portal-stream-event.v1",
        tenantId: scope.tenantId,
        resourceId: command.resourceId,
        sequence: 1,
        eventType: "RUN_STATUS",
        dataRef: "synthetic://c08/run/demo/status/1",
        evidenceRefs: ["evidence://c08/run/demo/1"],
        ownerPrincipalId: HUMAN,
      };
    },
  });
  const events = [];

  await assert.rejects(
    async () => {
      for await (const event of bff.stream(
        context(),
        streamRequest(),
      )) {
        events.push(event);
      }
    },
    (error) => error.code === "CORE_RESULT_INVALID",
  );
  assert.deepEqual(
    events.map(({ eventType }) => eventType),
    ["RUN_STATUS"],
  );
});

test("a terminal result followed by another event is never released as success", async () => {
  const bff = authorizedBff({
    async read() {
      throw new Error("not used");
    },
    async mutate() {
      throw new Error("not used");
    },
    async *stream(scope, command) {
      for (const [sequence, eventType] of [
        [1, "COMPLETED"],
        [2, "CONTENT_DELTA_REF"],
      ]) {
        yield {
          schemaVersion: "c01-portal-stream-event.v1",
          tenantId: scope.tenantId,
          resourceId: command.resourceId,
          sequence,
          eventType,
          dataRef: `synthetic://c08/run/demo/event/${sequence}`,
          evidenceRefs: [
            `evidence://c08/run/demo/event/${sequence}`,
          ],
          ownerPrincipalId: HUMAN,
        };
      }
    },
  });

  await assert.rejects(
    bff.stream(context(), streamRequest()).next(),
    (error) => error.code === "CORE_RESULT_INVALID",
  );
});
