import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  buildSyntheticPolicyTuples,
  createSyntheticAuthorizationCatalog,
} from "../lib/authorization-facade.mjs";
import {
  OpenFgaPolicyVerifierError,
  createOpenFgaPolicyVerifier,
} from "../lib/openfga-policy-verifier.mjs";

const TENANT_ID = "stn_018f0000-0000-7000-8000-000000000010";
const FIXTURE_ID = "synthetic-tenant-northstar-fasteners";
const RELEASE_ID = "azr_018f0000-0000-7000-8000-000000000020";
const STORE_ID = "01J00000000000000000000000";
const MODEL_ID = "01J00000000000000000000001";
const HUMAN_ID = "prn_018f0000-0000-7000-8000-000000000001";
const ACTOR_ID = "prn_018f0000-0000-7000-8000-000000000002";
const OUTSIDER_ID = "prn_018f0000-0000-7000-8000-000000000099";
const TEMPLATE_REF = "fixture://c06/policy-release/baseline-v1";

async function load(path) {
  return JSON.parse(
    await readFile(new URL(`../${path}`, import.meta.url), "utf8"),
  );
}

const model = await load(
  "implementation/p1/c06/openfga/authorization-model.v1.json",
);
const policyCatalog = createSyntheticAuthorizationCatalog({
  policyCatalog: await load(
    "implementation/p1/c06/synthetic-policy-catalog.v1.json",
  ),
  protectedOperations: await load(
    "implementation/p1/c06/protected-operations.v1.json",
  ),
  fixtures: await load(
    "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
  ),
  model,
});
const template = policyCatalog.template(TEMPLATE_REF);
const principalIdsByFixtureRef = {
  [`fixture://${FIXTURE_ID}/principals/ava`]: HUMAN_ID,
  [`fixture://${FIXTURE_ID}/principals/assistant-agent`]: ACTOR_ID,
  [`fixture://${FIXTURE_ID}/principals/noah`]:
    "prn_018f0000-0000-7000-8000-000000000003",
};
const tupleKeys = buildSyntheticPolicyTuples({
  catalog: policyCatalog,
  templateRef: TEMPLATE_REF,
  fixtureId: FIXTURE_ID,
  principalIdsByFixtureRef,
});
const tupleSet = new Set(
  tupleKeys.map(
    ({ user, relation, object }) => `${user}|${relation}|${object}`,
  ),
);
const candidate = {
  policyReleaseId: RELEASE_ID,
  tenantId: TENANT_ID,
  tenantKind: "SYNTHETIC",
  fixtureId: FIXTURE_ID,
  templateRef: TEMPLATE_REF,
  templateSequence: template.sequence,
  bundleSha256: template.bundle_sha256,
  modelSha256: template.modelSha256,
  openFgaStoreId: STORE_ID,
  authorizationModelId: MODEL_ID,
};

function createHarness({
  responseOverride,
  modelOverride,
  tupleKeysOverride,
} = {}) {
  const checks = [];
  const verifier = createOpenFgaPolicyVerifier({
    policyCatalog,
    pdpFactory({ storeId, authorizationModelId }) {
      return {
        async readAuthorizationModel({ authorizationModelId: requestedModelId }) {
          return {
            storeId,
            authorizationModelId: requestedModelId,
            model: modelOverride ?? model,
          };
        },
        async readAllTuples({ authorizationModelId: requestedModelId }) {
          return {
            storeId,
            authorizationModelId: requestedModelId,
            consistency: "HIGHER_CONSISTENCY",
            tupleKeys: tupleKeysOverride ?? tupleKeys,
          };
        },
        async check({ authorizationModelId: requestedModelId, tupleKey }) {
          checks.push(tupleKey);
          if (responseOverride) {
            return responseOverride({
              storeId,
              authorizationModelId,
              requestedModelId,
              tupleKey,
            });
          }
          return {
            allowed: tupleSet.has(
              `${tupleKey.user}|${tupleKey.relation}|${tupleKey.object}`,
            ),
            storeId,
            authorizationModelId: requestedModelId,
            consistency: "HIGHER_CONSISTENCY",
          };
        },
      };
    },
    async resolvePrincipalIds(input) {
      assert.deepEqual(input, {
        tenantId: TENANT_ID,
        fixtureId: FIXTURE_ID,
      });
      return {
        principalIdsByFixtureRef,
        unauthorizedHumanPrincipalId: OUTSIDER_ID,
        trustSource: "VERIFIED_SYNTHETIC_PRINCIPAL_MAPPING",
      };
    },
  });
  return { verifier, checks };
}

test("evaluateProjection runs exactly 30 deterministic five-case fixtures", async () => {
  const { verifier, checks } = createHarness();
  const first = await verifier.evaluateProjection(candidate);
  const second = await verifier.evaluateProjection(candidate);

  assert.equal(checks.length, 60);
  assert.equal(first.passed, true);
  assert.equal(first.fixturePassCount, 30);
  assert.equal(first.fixtureFailCount, 0);
  assert.match(first.fixtureReportSha256, /^sha256:[a-f0-9]{64}$/);
  assert.equal(
    first.tupleBundleSha256,
    "sha256:303d1010fabf45f5149303fa53731380c0aa21f3ec8255726422e3dbee1ac689",
  );
  assert.equal(first.fixtureReportSha256, second.fixtureReportSha256);
  for (const surface of [
    "read",
    "retrieve",
    "download",
    "manage",
    "tool-call",
    "sandbox-run",
  ]) {
    assert.equal(
      checks.filter(({ object }) => object.endsWith(`--${surface}`)).length,
      10,
    );
  }
});

test("verifyPolicyRelease reruns and binds the stored report hash", async () => {
  const { verifier } = createHarness();
  const report = await verifier.evaluateProjection(candidate);
  const release = {
    ...candidate,
    tupleBundleSha256: report.tupleBundleSha256,
    fixtureReportSha256: report.fixtureReportSha256,
    fixturePassCount: 30,
    fixtureFailCount: 0,
  };

  assert.equal((await verifier.verifyPolicyRelease(release)).passed, true);
  assert.equal(
    (
      await verifier.verifyPolicyRelease({
        ...release,
        fixtureReportSha256: `sha256:${"f".repeat(64)}`,
      })
    ).passed,
    false,
  );
});

test("principal mapping cannot be supplied by the release candidate", async () => {
  const { verifier, checks } = createHarness();

  await assert.rejects(
    verifier.evaluateProjection({
      ...candidate,
      humanPrincipalId: OUTSIDER_ID,
    }),
    (error) =>
      error instanceof OpenFgaPolicyVerifierError &&
      error.code === "POLICY_VERIFICATION_INVALID_INPUT",
  );
  assert.equal(checks.length, 0);
});

test("a mismatched PDP response fails closed before a report is produced", async () => {
  const { verifier } = createHarness({
    responseOverride({ authorizationModelId }) {
      return {
        allowed: true,
        storeId: "01J00000000000000000000009",
        authorizationModelId,
        consistency: "HIGHER_CONSISTENCY",
      };
    },
  });

  await assert.rejects(
    verifier.evaluateProjection(candidate),
    (error) =>
      error instanceof OpenFgaPolicyVerifierError &&
      error.code === "POLICY_VERIFICATION_INVALID_RESPONSE",
  );
});

test("an extra stored tuple or changed remote model blocks projection", async () => {
  const extraTuple = {
    user: `human:${OUTSIDER_ID}`,
    relation: "human_can_read",
    object: `protected_resource:${FIXTURE_ID}--read`,
  };
  await assert.rejects(
    createHarness({
      tupleKeysOverride: [...tupleKeys, extraTuple],
    }).verifier.evaluateProjection(candidate),
    { code: "POLICY_VERIFICATION_PROJECTION_MISMATCH" },
  );
  await assert.rejects(
    createHarness({
      modelOverride: {
        ...model,
        type_definitions: [...model.type_definitions, { type: "unapproved" }],
      },
    }).verifier.evaluateProjection(candidate),
    { code: "POLICY_VERIFICATION_PROJECTION_MISMATCH" },
  );
  await assert.rejects(
    createHarness({
      tupleKeysOverride: tupleKeys.slice(1),
    }).verifier.evaluateProjection(candidate),
    { code: "POLICY_VERIFICATION_PROJECTION_MISMATCH" },
  );
  await assert.rejects(
    createHarness({
      tupleKeysOverride: [tupleKeys[0], ...tupleKeys],
    }).verifier.evaluateProjection(candidate),
    { code: "POLICY_VERIFICATION_PROJECTION_MISMATCH" },
  );
});
