import { createHash } from "node:crypto";
import {
  buildSyntheticPolicyTuples,
  hashSyntheticPolicyTuples,
} from "./authorization-facade.mjs";

const SURFACES = Object.freeze([
  "READ",
  "RETRIEVE",
  "DOWNLOAD",
  "MANAGE",
  "TOOL_CALL",
  "SANDBOX_RUN",
]);
const UUID_V7 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINCIPAL_ID = new RegExp(`^prn_${UUID_V7.source.slice(1, -1)}$`);
const POLICY_RELEASE_ID = new RegExp(
  `^azr_${UUID_V7.source.slice(1, -1)}$`,
);
const TENANT_ID = new RegExp(`^stn_${UUID_V7.source.slice(1, -1)}$`);
const OPENFGA_ID = /^[ABCDEFGHJKMNPQRSTVWXYZ0-9]{26}$/;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const CASE_COUNT = 30;
const FORBIDDEN_PRINCIPAL_FIELDS = Object.freeze([
  "humanPrincipalId",
  "workloadActorPrincipalId",
  "unauthorizedHumanPrincipalId",
  "principalIds",
  "principalIdsByFixtureRef",
]);

export class OpenFgaPolicyVerifierError extends Error {
  constructor(code) {
    super(code);
    this.name = "OpenFgaPolicyVerifierError";
    this.code = code;
  }
}

function fail(code) {
  throw new OpenFgaPolicyVerifierError(code);
}

function canonicalize(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("POLICY_VERIFICATION_INVALID_INPUT");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
      .join(",")}}`;
  }
  fail("POLICY_VERIFICATION_INVALID_INPUT");
}

function sha256(value) {
  return `sha256:${createHash("sha256")
    .update(typeof value === "string" ? value : canonicalize(value))
    .digest("hex")}`;
}

function resourceId(fixtureId, surface) {
  return `${fixtureId}--${surface.toLowerCase().replaceAll("_", "-")}`;
}

function validateCandidate(candidate, template) {
  if (
    !candidate ||
    typeof candidate !== "object" ||
    Array.isArray(candidate) ||
    FORBIDDEN_PRINCIPAL_FIELDS.some((field) =>
      Object.hasOwn(candidate, field),
    ) ||
    !POLICY_RELEASE_ID.test(candidate.policyReleaseId ?? "") ||
    !TENANT_ID.test(candidate.tenantId ?? "") ||
    candidate.tenantKind !== "SYNTHETIC" ||
    typeof candidate.fixtureId !== "string" ||
    candidate.fixtureId.length === 0 ||
    candidate.fixtureId.length > 128 ||
    candidate.templateRef !== template.template_ref ||
    candidate.templateSequence !== template.sequence ||
    candidate.bundleSha256 !== template.bundle_sha256 ||
    candidate.modelSha256 !== template.modelSha256 ||
    !OPENFGA_ID.test(candidate.openFgaStoreId ?? "") ||
    !OPENFGA_ID.test(candidate.authorizationModelId ?? "") ||
    (candidate.tupleBundleSha256 !== undefined &&
      !SHA256.test(candidate.tupleBundleSha256))
  ) {
    fail("POLICY_VERIFICATION_INVALID_INPUT");
  }
}

function validatePrincipals(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some(
      (key) =>
        ![
          "principalIdsByFixtureRef",
          "unauthorizedHumanPrincipalId",
          "trustSource",
        ].includes(key),
    ) ||
    value.trustSource !== "VERIFIED_SYNTHETIC_PRINCIPAL_MAPPING" ||
    !value.principalIdsByFixtureRef ||
    typeof value.principalIdsByFixtureRef !== "object" ||
    Array.isArray(value.principalIdsByFixtureRef) ||
    Object.keys(value.principalIdsByFixtureRef).length < 2 ||
    Object.values(value.principalIdsByFixtureRef).some(
      (principalId) => !PRINCIPAL_ID.test(principalId),
    ) ||
    !PRINCIPAL_ID.test(value.unauthorizedHumanPrincipalId ?? "") ||
    Object.values(value.principalIdsByFixtureRef).includes(
      value.unauthorizedHumanPrincipalId,
    )
  ) {
    fail("POLICY_VERIFICATION_PRINCIPALS_UNVERIFIED");
  }
  return value;
}

function checkCases({
  policyCatalog,
  candidate,
  humanPrincipalId,
  workloadActorPrincipalId,
  unauthorizedHumanPrincipalId,
}) {
  return SURFACES.flatMap((surface, index) => {
    const operation = policyCatalog.operation(surface);
    const wrongPurpose = policyCatalog.operation(
      SURFACES[(index + 1) % SURFACES.length],
    ).purpose_ref;
    const object =
      `${operation.resource_type}:${resourceId(candidate.fixtureId, surface)}`;
    return [
      {
        caseId: `${surface}:HUMAN_ALLOW`,
        expected: true,
        tupleKey: {
          user: `human:${humanPrincipalId}`,
          relation: operation.human_relation,
          object,
        },
      },
      {
        caseId: `${surface}:ACTOR_ALLOW`,
        expected: true,
        tupleKey: {
          user: `workload:${workloadActorPrincipalId}`,
          relation: operation.actor_relation,
          object,
        },
      },
      {
        caseId: `${surface}:PURPOSE_ALLOW`,
        expected: true,
        tupleKey: {
          user: `purpose_scope:${sha256(operation.purpose_ref).slice(7)}`,
          relation: operation.purpose_relation,
          object,
        },
      },
      {
        caseId: `${surface}:UNAUTHORIZED_HUMAN_DENY`,
        expected: false,
        tupleKey: {
          user: `human:${unauthorizedHumanPrincipalId}`,
          relation: operation.human_relation,
          object,
        },
      },
      {
        caseId: `${surface}:WRONG_PURPOSE_DENY`,
        expected: false,
        tupleKey: {
          user: `purpose_scope:${sha256(wrongPurpose).slice(7)}`,
          relation: operation.purpose_relation,
          object,
        },
      },
    ];
  });
}

export function createOpenFgaPolicyVerifier({
  policyCatalog,
  pdpFactory,
  resolvePrincipalIds,
}) {
  if (
    !policyCatalog?.template ||
    !policyCatalog?.operation ||
    typeof pdpFactory !== "function" ||
    typeof resolvePrincipalIds !== "function"
  ) {
    fail("POLICY_VERIFICATION_INVALID_CONFIGURATION");
  }

  async function evaluateProjection(candidate) {
    const template = policyCatalog.template(candidate?.templateRef);
    validateCandidate(candidate, template);

    let principals;
    try {
      principals = validatePrincipals(
        await resolvePrincipalIds({
          tenantId: candidate.tenantId,
          fixtureId: candidate.fixtureId,
        }),
      );
    } catch (error) {
      if (error instanceof OpenFgaPolicyVerifierError) throw error;
      fail("POLICY_VERIFICATION_PRINCIPALS_UNVERIFIED");
    }

    let pdp;
    try {
      pdp = pdpFactory({
        storeId: candidate.openFgaStoreId,
        authorizationModelId: candidate.authorizationModelId,
      });
    } catch {
      fail("POLICY_VERIFICATION_UNAVAILABLE");
    }
    if (
      !pdp?.check ||
      !pdp?.readAuthorizationModel ||
      !pdp?.readAllTuples
    ) {
      fail("POLICY_VERIFICATION_UNAVAILABLE");
    }

    let tupleKeys;
    try {
      tupleKeys = buildSyntheticPolicyTuples({
        catalog: policyCatalog,
        templateRef: candidate.templateRef,
        fixtureId: candidate.fixtureId,
        principalIdsByFixtureRef: principals.principalIdsByFixtureRef,
      });
    } catch {
      fail("POLICY_VERIFICATION_PRINCIPALS_UNVERIFIED");
    }
    const humanRef =
      `fixture://${candidate.fixtureId}/principals/ava`;
    const actorRef =
      `fixture://${candidate.fixtureId}/principals/assistant-agent`;
    const humanPrincipalId =
      principals.principalIdsByFixtureRef[humanRef];
    const workloadActorPrincipalId =
      principals.principalIdsByFixtureRef[actorRef];
    if (
      !PRINCIPAL_ID.test(humanPrincipalId ?? "") ||
      !PRINCIPAL_ID.test(workloadActorPrincipalId ?? "") ||
      humanPrincipalId === workloadActorPrincipalId
    ) {
      fail("POLICY_VERIFICATION_PRINCIPALS_UNVERIFIED");
    }
    const expectedTupleBundleSha256 = hashSyntheticPolicyTuples(tupleKeys);
    let modelReadback;
    let tupleReadback;
    try {
      [modelReadback, tupleReadback] = await Promise.all([
        pdp.readAuthorizationModel({
          authorizationModelId: candidate.authorizationModelId,
        }),
        pdp.readAllTuples({
          authorizationModelId: candidate.authorizationModelId,
        }),
      ]);
    } catch {
      fail("POLICY_VERIFICATION_UNAVAILABLE");
    }
    if (
      modelReadback?.storeId !== candidate.openFgaStoreId ||
      modelReadback?.authorizationModelId !==
        candidate.authorizationModelId ||
      tupleReadback?.storeId !== candidate.openFgaStoreId ||
      tupleReadback?.authorizationModelId !==
        candidate.authorizationModelId ||
      tupleReadback?.consistency !== "HIGHER_CONSISTENCY" ||
      !Array.isArray(tupleReadback?.tupleKeys)
    ) {
      fail("POLICY_VERIFICATION_INVALID_RESPONSE");
    }
    let actualTupleBundleSha256;
    try {
      actualTupleBundleSha256 = hashSyntheticPolicyTuples(
        tupleReadback.tupleKeys,
      );
    } catch {
      fail("POLICY_VERIFICATION_PROJECTION_MISMATCH");
    }
    const actualModelSha256 = sha256(modelReadback.model);
    if (
      canonicalize(modelReadback.model) !== canonicalize(template.model) ||
      actualModelSha256 !== template.modelSha256 ||
      actualTupleBundleSha256 !== expectedTupleBundleSha256 ||
      (candidate.tupleBundleSha256 !== undefined &&
        candidate.tupleBundleSha256 !== actualTupleBundleSha256)
    ) {
      fail("POLICY_VERIFICATION_PROJECTION_MISMATCH");
    }
    const tupleBundleSha256 = actualTupleBundleSha256;
    const results = [];
    for (const fixture of checkCases({
      policyCatalog,
      candidate,
      humanPrincipalId,
      workloadActorPrincipalId,
      unauthorizedHumanPrincipalId:
        principals.unauthorizedHumanPrincipalId,
    })) {
      let response;
      try {
        response = await pdp.check({
          authorizationModelId: candidate.authorizationModelId,
          tupleKey: fixture.tupleKey,
        });
      } catch {
        fail("POLICY_VERIFICATION_UNAVAILABLE");
      }
      if (
        typeof response?.allowed !== "boolean" ||
        response.storeId !== candidate.openFgaStoreId ||
        response.authorizationModelId !==
          candidate.authorizationModelId ||
        response.consistency !== "HIGHER_CONSISTENCY"
      ) {
        fail("POLICY_VERIFICATION_INVALID_RESPONSE");
      }
      results.push({
        caseId: fixture.caseId,
        expected: fixture.expected,
        allowed: response.allowed,
        passed: response.allowed === fixture.expected,
      });
    }

    const fixturePassCount = results.filter(({ passed }) => passed).length;
    const fixtureFailCount = CASE_COUNT - fixturePassCount;
    const reportPayload = {
      schemaVersion: "1.0.0",
      policyReleaseId: candidate.policyReleaseId,
      tenantId: candidate.tenantId,
      fixtureId: candidate.fixtureId,
      templateRef: candidate.templateRef,
      templateSequence: candidate.templateSequence,
      bundleSha256: candidate.bundleSha256,
      tupleBundleSha256,
      modelSha256: actualModelSha256,
      openFgaStoreId: candidate.openFgaStoreId,
      authorizationModelId: candidate.authorizationModelId,
      consistency: "HIGHER_CONSISTENCY",
      results,
    };
    return Object.freeze({
      passed: fixtureFailCount === 0,
      fixturePassCount,
      fixtureFailCount,
      fixtureReportSha256: sha256(reportPayload),
      policyBundleSha256: candidate.bundleSha256,
      tupleBundleSha256,
      modelSha256: actualModelSha256,
      openFgaStoreId: candidate.openFgaStoreId,
      authorizationModelId: candidate.authorizationModelId,
      templateRef: candidate.templateRef,
    });
  }

  async function verifyPolicyRelease(release) {
    if (
      !SHA256.test(release?.fixtureReportSha256 ?? "") ||
      release?.fixturePassCount !== CASE_COUNT ||
      release?.fixtureFailCount !== 0
    ) {
      fail("POLICY_VERIFICATION_INVALID_INPUT");
    }
    const replay = await evaluateProjection(release);
    return Object.freeze({
      ...replay,
      passed:
        replay.passed &&
        replay.fixtureReportSha256 === release.fixtureReportSha256 &&
        replay.fixturePassCount === release.fixturePassCount &&
        replay.fixtureFailCount === release.fixtureFailCount &&
        replay.policyBundleSha256 === release.bundleSha256 &&
        replay.tupleBundleSha256 === release.tupleBundleSha256 &&
        replay.modelSha256 === release.modelSha256 &&
        replay.openFgaStoreId === release.openFgaStoreId &&
        replay.authorizationModelId === release.authorizationModelId &&
        replay.templateRef === release.templateRef,
    });
  }

  return Object.freeze({ evaluateProjection, verifyPolicyRelease });
}
