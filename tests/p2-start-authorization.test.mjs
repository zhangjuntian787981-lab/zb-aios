import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  createMemoryJournal,
  createProjectControl,
} from "../lib/project-control.mjs";
import {
  createP2ExecutionBaselineVerifier,
  p2AcceptanceDigests,
} from "../lib/p2-acceptance-receipt-validator.mjs";
import { evaluateP2StartAuthorization } from "../lib/p2-start-authorization.mjs";

const profileEventSchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/p2-acceptance-profile-approved.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const startEventSchema = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/schemas/p2-work-package-start-authorized.v1.schema.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const ajv = new Ajv2020({
  strict: true,
  allErrors: true,
  validateFormats: true,
});
addFormats(ajv);
const validateProfileEvent = ajv.compile(profileEventSchema);
const validateStartEvent = ajv.compile(startEventSchema);

const digest = (character) => `sha256:${character.repeat(64)}`;
const manifest = JSON.parse(
  await readFile(
    new URL(
      "../implementation/governance/work-package-manifest.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const policy = {
  protectedWorkPackages: ["O02", "O03"],
  profile: {
    path: "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
    schemaVersion: "p2-acceptance-profile.v2",
    sha256: digest("a"),
  },
  receiptSchema: {
    path: "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
    version: "p2-acceptance-receipt.v2",
    sha256: digest("b"),
  },
  validator: {
    path: "lib/p2-acceptance-receipt-validator.mjs",
    version: "p2-acceptance-validator.v2",
    sha256: digest("c"),
  },
};
const executionBaselineDescriptor = {
  schemaVersion: "p2-execution-baseline.v1",
  sourceCommit: "1".repeat(40),
  acceptanceProfile: {
    path: policy.profile.path,
    sha256: policy.profile.sha256,
  },
  receiptSchema: {
    path: policy.receiptSchema.path,
    version: policy.receiptSchema.version,
    sha256: policy.receiptSchema.sha256,
  },
  semanticValidator: {
    path: policy.validator.path,
    version: policy.validator.version,
    sha256: policy.validator.sha256,
  },
  fixtures: [
    {
      name: "p2-start-authorization-contract",
      path: "tests/p2-start-authorization.test.mjs",
      sha256: digest("4"),
    },
  ],
  toolLocks: [
    {
      name: "ajv",
      version: "8.20.0",
      digest: digest("5"),
    },
  ],
};
const executionBaselineDigest = p2AcceptanceDigests.executionBaseline(
  executionBaselineDescriptor,
);
const verifyP2ExecutionBaseline = createP2ExecutionBaselineVerifier({
  resolveExecutionBaseline: async (candidateDigest) =>
    candidateDigest === executionBaselineDigest
      ? executionBaselineDescriptor
      : null,
});

function profileApproval({
  revision = 65,
  approvalId = "p2pa_profile_01",
  baselineDigest = executionBaselineDigest,
  profileSha256 = policy.profile.sha256,
  supersedes = null,
} = {}) {
  const createdAt = `2026-07-28T03:00:${String(revision % 60).padStart(2, "0")}.000Z`;
  return {
    id: `event-profile-${revision}`,
    revision,
    type: "P2_ACCEPTANCE_PROFILE_APPROVED",
    actorId: "external_product_owner",
    createdAt,
    payload: {
      profile_approval_id: approvalId,
      profile_path: policy.profile.path,
      profile_sha256: profileSha256,
      profile_schema_version: policy.profile.schemaVersion,
      receipt_schema_path: policy.receiptSchema.path,
      receipt_schema_sha256: policy.receiptSchema.sha256,
      receipt_schema_version: policy.receiptSchema.version,
      validator_path: policy.validator.path,
      validator_sha256: policy.validator.sha256,
      validator_version: policy.validator.version,
      execution_baseline_digest: baselineDigest,
      source_commit: "1".repeat(40),
      approved_by: "external_product_owner",
      approved_at: createdAt,
      source_revision: revision - 1,
      supersedes,
    },
  };
}

function startAuthorization({
  revision = 66,
  authorizationId = "p2wpa_o02_start_01",
  workPackageId = "O02",
  profileApprovalId = "p2pa_profile_01",
  profileSha256 = policy.profile.sha256,
  baselineDigest = executionBaselineDigest,
  status = "AUTHORIZED",
  revokesAuthorizationId = null,
} = {}) {
  const createdAt = `2026-07-28T04:00:${String(revision % 60).padStart(2, "0")}.000Z`;
  return {
    id: `event-start-${revision}`,
    revision,
    type: "P2_WORK_PACKAGE_START_AUTHORIZED",
    actorId: "external_product_owner",
    createdAt,
    payload: {
      authorization_id: authorizationId,
      work_package_id: workPackageId,
      profile_approval_id: profileApprovalId,
      profile_sha256: profileSha256,
      execution_baseline_digest: baselineDigest,
      authorization_status: status,
      revokes_authorization_id: revokesAuthorizationId,
      recorded_by: "external_product_owner",
      recorded_at: createdAt,
      source_revision: revision - 1,
    },
  };
}

test("fixed P2 D1 event payloads compile and forbid finalReleaseDigest", () => {
  const profilePayload = profileApproval().payload;
  assert.equal(
    validateProfileEvent(profilePayload),
    true,
    ajv.errorsText(validateProfileEvent.errors),
  );
  const startPayload = startAuthorization().payload;
  assert.equal(
    validateStartEvent(startPayload),
    true,
    ajv.errorsText(validateStartEvent.errors),
  );

  assert.equal(
    validateStartEvent({
      ...startPayload,
      final_release_digest: digest("f"),
    }),
    false,
  );
  assert.equal(
    validateStartEvent({
      ...startPayload,
      authorization_status: "REVOKED",
      revokes_authorization_id: null,
    }),
    false,
  );
});

test("Profile approval verifier reproduces every execution-baseline binding", async () => {
  assert.equal(
    await verifyP2ExecutionBaseline({
      executionBaselineDigest,
      sourceCommit: executionBaselineDescriptor.sourceCommit,
      policy,
    }),
    true,
  );
  assert.equal(
    await verifyP2ExecutionBaseline({
      executionBaselineDigest,
      sourceCommit: "2".repeat(40),
      policy,
    }),
    false,
  );
  assert.equal(
    await verifyP2ExecutionBaseline({
      executionBaselineDigest,
      sourceCommit: executionBaselineDescriptor.sourceCommit,
      policy: {
        ...policy,
        validator: {
          ...policy.validator,
          sha256: digest("f"),
        },
      },
    }),
    false,
  );
});

test("O02 and O03 deny by default while unrelated work packages need no P2 authorization", () => {
  const o02 = evaluateP2StartAuthorization({
    workPackageId: "O02",
    governanceEvents: [],
    policy,
  });
  assert.equal(o02.required, true);
  assert.equal(o02.authorized, false);
  assert.deepEqual(o02.reasonCodes, ["P2_PROFILE_NOT_APPROVED"]);

  const o01 = evaluateP2StartAuthorization({
    workPackageId: "O01",
    governanceEvents: [],
    policy,
  });
  assert.equal(o01.required, false);
  assert.equal(o01.authorized, true);
  assert.deepEqual(o01.reasonCodes, []);

  const incompletePolicy = {
    ...policy,
    protectedWorkPackages: ["O02"],
  };
  for (const workPackageId of ["O02", "O03"]) {
    const denied = evaluateP2StartAuthorization({
      workPackageId,
      governanceEvents: [],
      policy: incompletePolicy,
    });
    assert.equal(denied.authorized, false);
    assert.deepEqual(denied.reasonCodes, ["P2_START_POLICY_INVALID"]);
  }
});

test("only an exact current Profile and execution-baseline authorization permits start", () => {
  const approved = profileApproval();
  const profileOnly = evaluateP2StartAuthorization({
    workPackageId: "O02",
    governanceEvents: [approved],
    policy,
  });
  assert.equal(profileOnly.authorized, false);
  assert.deepEqual(profileOnly.reasonCodes, [
    "P2_START_AUTHORIZATION_MISSING",
  ]);

  const exact = evaluateP2StartAuthorization({
    workPackageId: "O02",
    governanceEvents: [approved, startAuthorization()],
    policy,
  });
  assert.equal(exact.authorized, true);
  assert.equal(exact.executionBaselineDigest, executionBaselineDigest);

  const wrongBaseline = evaluateP2StartAuthorization({
    workPackageId: "O02",
    governanceEvents: [
      approved,
      startAuthorization({ baselineDigest: digest("e") }),
    ],
    policy,
  });
  assert.equal(wrongBaseline.authorized, false);
  assert.deepEqual(wrongBaseline.reasonCodes, [
    "P2_START_AUTHORIZATION_STALE",
  ]);
});

test("latest revocation, malformed event or superseding Profile fails closed", () => {
  const approved = profileApproval();
  const authorized = startAuthorization();
  const revoked = startAuthorization({
    revision: 67,
    authorizationId: "p2wpa_o02_revoke_01",
    status: "REVOKED",
    revokesAuthorizationId: authorized.payload.authorization_id,
  });
  const afterRevocation = evaluateP2StartAuthorization({
    workPackageId: "O02",
    governanceEvents: [approved, authorized, revoked],
    policy,
  });
  assert.equal(afterRevocation.authorized, false);
  assert.deepEqual(afterRevocation.reasonCodes, [
    "P2_START_AUTHORIZATION_REVOKED",
  ]);

  const malformed = structuredClone(authorized);
  malformed.revision = 68;
  malformed.payload.source_revision = 10;
  const afterMalformed = evaluateP2StartAuthorization({
    workPackageId: "O02",
    governanceEvents: [approved, authorized, malformed],
    policy,
  });
  assert.equal(afterMalformed.authorized, false);
  assert.deepEqual(afterMalformed.reasonCodes, [
    "P2_GOVERNANCE_EVENT_INVALID",
  ]);

  const duplicateAuthorization = startAuthorization({
    revision: 67,
    authorizationId: "p2wpa_o02_start_02",
  });
  const afterDuplicateAuthorization = evaluateP2StartAuthorization({
    workPackageId: "O02",
    governanceEvents: [approved, authorized, duplicateAuthorization],
    policy,
  });
  assert.equal(afterDuplicateAuthorization.authorized, false);
  assert.deepEqual(afterDuplicateAuthorization.reasonCodes, [
    "P2_GOVERNANCE_EVENT_INVALID",
  ]);

  const superseding = profileApproval({
    revision: 67,
    approvalId: "p2pa_profile_02",
    baselineDigest: digest("e"),
    supersedes: approved.payload.profile_approval_id,
  });
  const afterSupersession = evaluateP2StartAuthorization({
    workPackageId: "O02",
    governanceEvents: [approved, authorized, superseding],
    policy,
  });
  assert.equal(afterSupersession.authorized, false);
  assert.deepEqual(afterSupersession.reasonCodes, [
    "P2_START_AUTHORIZATION_STALE",
  ]);
});

function structurallyReadyP2Events() {
  const definitions = manifest.work_packages.filter(({ phase }) =>
    ["P0", "P1"].includes(phase),
  );
  const packageEvents = definitions.map((definition, index) => ({
    id: `historical-${definition.id.toLowerCase()}`,
    type: "WORK_PACKAGE_RECORDED",
    actorId: "external_product_owner",
    createdAt: `2026-07-27T00:${String(index).padStart(2, "0")}:00.000Z`,
    payload: {
      workPackageId: definition.id,
      implementationStatus: "IMPLEMENTED",
      verificationStatus: "VERIFIED",
      evidenceRefs: [`evidence/${definition.id}.json`],
      evidenceHashes: [digest(String((index % 6) + 1))],
      note: `historical ${definition.id}`,
    },
  }));
  const scope = (phase) =>
    definitions
      .filter((definition) => definition.phase === phase)
      .map((definition) => {
        const index = definitions.indexOf(definition);
        return {
        work_package_id: definition.id,
        applicability: definition.applicability,
        implementation_status: "IMPLEMENTED",
        verification_status: "VERIFIED",
        evidence_refs: [`evidence/${definition.id}.json`],
        evidence_hashes: [digest(String((index % 6) + 1))],
        };
      });
  const gateEvents = ["G0", "G1"].flatMap((gateId, index) => {
    const phase = `P${index}`;
    const gateScope = scope(phase);
    const packageHash = digest(index === 0 ? "a" : "b");
    return [
      {
        id: `historical-${gateId.toLowerCase()}-submission-event`,
        type: "GATE_SUBMITTED",
        actorId: "external_product_owner",
        createdAt: `2026-07-27T01:0${index}:00.000Z`,
        payload: {
          gate_id: gateId,
          submission_id: `historical-${gateId.toLowerCase()}-submission`,
          package_hash: packageHash,
          submitted_at: `2026-07-27T01:0${index}:00.000Z`,
          submitted_by: "external_product_owner",
          source_revision: packageEvents.length + index * 2,
          work_package_scope: gateScope,
          evidence_refs: gateScope.flatMap(
            ({ evidence_refs }) => evidence_refs,
          ),
          supersedes: null,
        },
      },
      {
        id: `historical-${gateId.toLowerCase()}-decision-event`,
        type: "GATE_DECIDED",
        actorId: "external_product_owner",
        createdAt: `2026-07-27T01:0${index}:30.000Z`,
        payload: {
          decision_id: `historical-${gateId.toLowerCase()}-decision`,
          submission_id: `historical-${gateId.toLowerCase()}-submission`,
          package_hash: packageHash,
          decision: "APPROVE",
          decided_by: "external_product_owner",
          decided_at: `2026-07-27T01:0${index}:30.000Z`,
          accepted_exclusions: [],
          evidence_refs: [`evidence/${gateId}.json`],
        },
      },
    ];
  });
  return [...packageEvents, ...gateEvents];
}

test("project-control keeps structural readiness separate and rejects direct O02 start without D1 authorization", async () => {
  const events = structurallyReadyP2Events();
  const journal = createMemoryJournal(events);
  const control = createProjectControl({
    manifest,
    journal,
    p2StartPolicy: policy,
  });
  const before = await control.snapshot();
  const o02 = before.workPackages.find(({ id }) => id === "O02");
  assert.equal(before.phaseEntry.P2, true);
  assert.equal(o02.structuralReady, true);
  assert.deepEqual(o02.structuralBlockers, []);
  assert.equal(o02.allowedToStart, false);
  assert.deepEqual(o02.startAuthorization.reasonCodes, [
    "P2_PROFILE_NOT_APPROVED",
  ]);

  await assert.rejects(
    control.execute(
      {
        actorId: "external_product_owner",
        roles: ["PRODUCT_OWNER"],
      },
      {
        kind: "RECORD_WORK_PACKAGE",
        workPackageId: "O02",
        implementationStatus: "IN_PROGRESS",
        verificationStatus: "NOT_VERIFIED",
        evidenceRefs: [],
        evidenceHashes: [],
        note: "must remain blocked",
        expectedRevision: before.revision,
        idempotencyKey: "blocked-o02-without-p2-authorization",
      },
    ),
    (error) => error.code === "EXECUTION_NOT_AUTHORIZED",
  );
  const after = await control.snapshot();
  assert.equal(after.revision, before.revision);
  assert.equal(after.events.length, before.events.length);
});

test("project-control accepts exact authorization but never lets O03 bypass O02", async () => {
  const structuralEvents = structurallyReadyP2Events();
  const profileRevision = structuralEvents.length + 1;
  const profile = profileApproval({ revision: profileRevision });
  const o02Authorization = startAuthorization({
    revision: profileRevision + 1,
  });
  const o03Authorization = startAuthorization({
    revision: profileRevision + 2,
    authorizationId: "p2wpa_o03_start_01",
    workPackageId: "O03",
  });
  const control = createProjectControl({
    manifest,
    journal: createMemoryJournal([
      ...structuralEvents,
      profile,
      o02Authorization,
      o03Authorization,
    ]),
    p2StartPolicy: policy,
  });
  const before = await control.snapshot();
  const o02 = before.workPackages.find(({ id }) => id === "O02");
  const o03 = before.workPackages.find(({ id }) => id === "O03");
  assert.equal(o02.allowedToStart, true);
  assert.equal(o02.startAuthorization.executionStatus, "AUTHORIZED");
  assert.equal(o03.startAuthorization.executionStatus, "AUTHORIZED");
  assert.equal(o03.structuralReady, false);
  assert.equal(o03.allowedToStart, false);
  assert.deepEqual(o03.structuralBlockers, ["O02"]);

  const started = await control.execute(
    {
      actorId: "external_product_owner",
      roles: ["PRODUCT_OWNER"],
    },
    {
      kind: "RECORD_WORK_PACKAGE",
      workPackageId: "O02",
      implementationStatus: "IN_PROGRESS",
      verificationStatus: "NOT_VERIFIED",
      evidenceRefs: [],
      evidenceHashes: [],
      note: "authorized local contract test",
      expectedRevision: before.revision,
      idempotencyKey: "authorized-o02-start",
    },
  );
  assert.equal(started.revision, before.revision + 1);

  await assert.rejects(
    control.execute(
      {
        actorId: "external_product_owner",
        roles: ["PRODUCT_OWNER"],
      },
      {
        kind: "RECORD_WORK_PACKAGE",
        workPackageId: "O03",
        implementationStatus: "IN_PROGRESS",
        verificationStatus: "NOT_VERIFIED",
        evidenceRefs: [],
        evidenceHashes: [],
        note: "must not bypass O02",
        expectedRevision: started.revision,
        idempotencyKey: "blocked-o03-dependency",
      },
    ),
    (error) => error.code === "DEPENDENCY_BLOCKED",
  );
});

test("project-control appends the fixed Profile approval contract with CAS and exact idempotency", async () => {
  const structuralEvents = structurallyReadyP2Events();
  let id = 0;
  const control = createProjectControl({
    manifest,
    journal: createMemoryJournal(structuralEvents),
    p2StartPolicy: policy,
    verifyP2ExecutionBaseline,
    clock: () => "2026-07-28T05:00:00.000Z",
    idFactory: () => `local-p2-id-${++id}`,
  });
  const before = await control.snapshot();
  const command = {
    kind: "APPROVE_P2_ACCEPTANCE_PROFILE",
    profilePath: policy.profile.path,
    profileSha256: policy.profile.sha256,
    profileSchemaVersion: policy.profile.schemaVersion,
    receiptSchemaPath: policy.receiptSchema.path,
    receiptSchemaSha256: policy.receiptSchema.sha256,
    receiptSchemaVersion: policy.receiptSchema.version,
    validatorPath: policy.validator.path,
    validatorSha256: policy.validator.sha256,
    validatorVersion: policy.validator.version,
    executionBaselineDigest,
    sourceCommit: "1".repeat(40),
    supersedes: null,
    expectedRevision: before.revision,
    idempotencyKey: "approve-p2-profile-local-test",
  };
  const approved = await control.execute(
    {
      actorId: "external_product_owner",
      roles: ["PRODUCT_OWNER"],
    },
    command,
  );
  assert.equal(approved.revision, before.revision + 1);
  assert.equal(
    approved.output.profileApproval.execution_baseline_digest,
    executionBaselineDigest,
  );
  assert.equal(
    approved.output.profileApproval.source_revision,
    before.revision,
  );
  assert.equal(
    validateProfileEvent(approved.output.profileApproval),
    true,
    ajv.errorsText(validateProfileEvent.errors),
  );

  const replay = await control.execute(
    {
      actorId: "external_product_owner",
      roles: ["PRODUCT_OWNER"],
    },
    command,
  );
  assert.equal(replay.duplicate, true);
  assert.equal(replay.eventId, approved.eventId);
  assert.equal((await control.snapshot()).revision, approved.revision);

  await assert.rejects(
    control.execute(
      {
        actorId: "external_product_owner",
        roles: ["PRODUCT_OWNER"],
      },
      {
        ...command,
        executionBaselineDigest: digest("e"),
      },
    ),
    (error) => error.code === "IDEMPOTENCY_CONFLICT",
  );
});

test("project-control rejects a Profile approval without a reproduced execution baseline", async () => {
  const structuralEvents = structurallyReadyP2Events();
  const control = createProjectControl({
    manifest,
    journal: createMemoryJournal(structuralEvents),
    p2StartPolicy: policy,
  });
  const before = await control.snapshot();

  await assert.rejects(
    control.execute(
      {
        actorId: "external_product_owner",
        roles: ["PRODUCT_OWNER"],
      },
      {
        kind: "APPROVE_P2_ACCEPTANCE_PROFILE",
        profilePath: policy.profile.path,
        profileSha256: policy.profile.sha256,
        profileSchemaVersion: policy.profile.schemaVersion,
        receiptSchemaPath: policy.receiptSchema.path,
        receiptSchemaSha256: policy.receiptSchema.sha256,
        receiptSchemaVersion: policy.receiptSchema.version,
        validatorPath: policy.validator.path,
        validatorSha256: policy.validator.sha256,
        validatorVersion: policy.validator.version,
        executionBaselineDigest,
        sourceCommit: executionBaselineDescriptor.sourceCommit,
        supersedes: null,
        expectedRevision: before.revision,
        idempotencyKey: "reject-unverified-p2-execution-baseline",
      },
    ),
    (error) => error.code === "P2_EXECUTION_BASELINE_UNVERIFIED",
  );
  assert.equal((await control.snapshot()).revision, before.revision);
});

test("project-control authorizes and revokes start through one fixed append-only event contract", async () => {
  const structuralEvents = structurallyReadyP2Events();
  let id = 0;
  const control = createProjectControl({
    manifest,
    journal: createMemoryJournal(structuralEvents),
    p2StartPolicy: policy,
    verifyP2ExecutionBaseline,
    clock: () => "2026-07-28T06:00:00.000Z",
    idFactory: () => `local-auth-id-${++id}`,
  });
  const initial = await control.snapshot();
  const profileReceipt = await control.execute(
    {
      actorId: "external_product_owner",
      roles: ["PRODUCT_OWNER"],
    },
    {
      kind: "APPROVE_P2_ACCEPTANCE_PROFILE",
      profilePath: policy.profile.path,
      profileSha256: policy.profile.sha256,
      profileSchemaVersion: policy.profile.schemaVersion,
      receiptSchemaPath: policy.receiptSchema.path,
      receiptSchemaSha256: policy.receiptSchema.sha256,
      receiptSchemaVersion: policy.receiptSchema.version,
      validatorPath: policy.validator.path,
      validatorSha256: policy.validator.sha256,
      validatorVersion: policy.validator.version,
      executionBaselineDigest,
      sourceCommit: "1".repeat(40),
      supersedes: null,
      expectedRevision: initial.revision,
      idempotencyKey: "approve-p2-profile-before-start",
    },
  );
  const profileApprovalId =
    profileReceipt.output.profileApproval.profile_approval_id;
  const authorizationReceipt = await control.execute(
    {
      actorId: "external_product_owner",
      roles: ["PRODUCT_OWNER"],
    },
    {
      kind: "AUTHORIZE_P2_WORK_PACKAGE_START",
      workPackageId: "O02",
      profileApprovalId,
      executionBaselineDigest,
      expectedRevision: profileReceipt.revision,
      idempotencyKey: "authorize-o02-local-test",
    },
  );
  assert.equal(
    authorizationReceipt.output.startAuthorization.authorization_status,
    "AUTHORIZED",
  );
  assert.equal(
    authorizationReceipt.output.startAuthorization.source_revision,
    profileReceipt.revision,
  );
  assert.equal(
    validateStartEvent(authorizationReceipt.output.startAuthorization),
    true,
    ajv.errorsText(validateStartEvent.errors),
  );
  assert.equal(
    Object.hasOwn(
      authorizationReceipt.output.startAuthorization,
      "final_release_digest",
    ),
    false,
  );
  assert.equal(
    (await control.snapshot()).workPackages.find(({ id }) => id === "O02")
      .allowedToStart,
    true,
  );

  await assert.rejects(
    control.execute(
      {
        actorId: "external_product_owner",
        roles: ["PRODUCT_OWNER"],
      },
      {
        kind: "AUTHORIZE_P2_WORK_PACKAGE_START",
        workPackageId: "O02",
        profileApprovalId,
        executionBaselineDigest,
        finalReleaseDigest: digest("f"),
        expectedRevision: authorizationReceipt.revision,
        idempotencyKey: "reject-final-release-at-start",
      },
    ),
    (error) => error.code === "INVALID_COMMAND",
  );

  const revoked = await control.execute(
    {
      actorId: "external_product_owner",
      roles: ["PRODUCT_OWNER"],
    },
    {
      kind: "REVOKE_P2_WORK_PACKAGE_START_AUTHORIZATION",
      workPackageId: "O02",
      profileApprovalId,
      executionBaselineDigest,
      revokesAuthorizationId:
        authorizationReceipt.output.startAuthorization.authorization_id,
      expectedRevision: authorizationReceipt.revision,
      idempotencyKey: "revoke-o02-local-test",
    },
  );
  assert.equal(
    revoked.output.startAuthorization.authorization_status,
    "REVOKED",
  );
  assert.equal(
    (await control.snapshot()).workPackages.find(({ id }) => id === "O02")
      .startAuthorization.executionStatus,
    "REVOKED",
  );

  const afterRevocation = await control.snapshot();
  await assert.rejects(
    control.execute(
      {
        actorId: "external_product_owner",
        roles: ["PRODUCT_OWNER"],
      },
      {
        kind: "RECORD_WORK_PACKAGE",
        workPackageId: "O02",
        implementationStatus: "IN_PROGRESS",
        verificationStatus: "NOT_VERIFIED",
        evidenceRefs: [],
        evidenceHashes: [],
        note: "revoked authorization must fail closed",
        expectedRevision: afterRevocation.revision,
        idempotencyKey: "start-o02-after-revocation",
      },
    ),
    (error) => error.code === "EXECUTION_NOT_AUTHORIZED",
  );
  const afterDeniedProgress = await control.snapshot();
  assert.equal(afterDeniedProgress.revision, afterRevocation.revision);
  assert.equal(
    afterDeniedProgress.workPackages.find(({ id }) => id === "O02")
      .implementationStatus,
    "NOT_STARTED",
  );
});
