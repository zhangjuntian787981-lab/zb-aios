import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { sha256ProjectValue } from "../lib/project-control.mjs";

const PREPARATION_PATH =
  "implementation/governance/reference-review/p2-profile-backfill-preparation.v1.json";
const RESEARCH_PATH =
  "implementation/governance/reference-review/p2-profile-backfill-official-research.v1.md";
const ADR_PATH = "docs/adr/0009-p1-reference-backfill-preparation.md";
const INSPECTED_SOURCE_COMMIT =
  "817ab47674dd7a312aeaf386063acdec559a7fa1";
const INSPECTED_SOURCE_TREE =
  "141bd74abf86b7c16b08062f1ef10a49b010f6b0";

const sha256 = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

const readText = (path) =>
  readFile(new URL(`../${path}`, import.meta.url), "utf8");

const readJson = async (path) => JSON.parse(await readText(path));

const gitShow = (commit, path) =>
  execFileSync("/usr/bin/git", ["show", `${commit}:${path}`]);

const gitTree = (commit) =>
  execFileSync("/usr/bin/git", ["rev-parse", `${commit}^{tree}`], {
    encoding: "utf8",
  }).trim();

const withoutSelfHash = (value) => {
  const copy = structuredClone(value);
  delete copy.preparationSha256;
  return copy;
};

test("Profile backfill preparation fixes the exact retrospective reference set", async () => {
  const preparation = await readJson(PREPARATION_PATH);

  assert.equal(
    preparation.schemaVersion,
    "p2-profile-reference-backfill-preparation.v1",
  );
  assert.equal(preparation.status, "GIT_FROZEN_INPUT_ONLY");
  assert.equal(preparation.reviewMode, "RETROSPECTIVE_BACKFILL");
  assert.equal(preparation.dataBoundary, "P1_SYNTHETIC_ONLY");
  assert.deepEqual(preparation.inspectedSource, {
    commit: INSPECTED_SOURCE_COMMIT,
    tree: INSPECTED_SOURCE_TREE,
  });
  assert.equal(gitTree(INSPECTED_SOURCE_COMMIT), INSPECTED_SOURCE_TREE);

  assert.deepEqual(
    preparation.references.map(
      ({ workPackageId, referenceId, decision }) => ({
        workPackageId,
        referenceId,
        decision,
      }),
    ),
    [
      {
        workPackageId: "C04",
        referenceId: "R09.KEYCLOAK",
        decision: "ADOPT",
      },
      {
        workPackageId: "C06",
        referenceId: "R11.OPENFGA",
        decision: "ADOPT",
      },
      {
        workPackageId: "C07",
        referenceId: "R12.PGVECTOR",
        decision: "ADOPT",
      },
      {
        workPackageId: "C07",
        referenceId: "R12.POSTGRESQL_RLS",
        decision: "ADOPT",
      },
    ],
  );
});

test("each proposed ADOPT is pinned to exact existing P1 bytes and remains non-production", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const byReference = new Map(
    preparation.references.map((reference) => [
      reference.referenceId,
      reference,
    ]),
  );

  const expected = {
    "R09.KEYCLOAK": {
      version: "26.7.0",
      artifactDigest:
        "sha256:f771df0aa1e4820f57d56f7d6d015beb6415487b43f8de7e5a6d48f8a7fe118a",
      evidencePath: "implementation/p1/c04/c04-verification-evidence.v1.json",
      evidenceFreezeCommit: "93772e891ab032ac6ea88bd6dec5847a2c748420",
      evidenceSha256:
        "sha256:554df39362987342eaab88b5146b04a70bc3db8b566a81c6af5b1866816063de",
    },
    "R11.OPENFGA": {
      version: "v1.18.1",
      artifactDigest:
        "sha256:d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94",
      evidencePath: "implementation/p1/c06/c06-verification-evidence.v3.json",
      evidenceFreezeCommit: "9aab0cb19d14848dfd837729dd7df07828043258",
      evidenceSha256:
        "sha256:b80fe8d28b8c4b2ea8caa33f6685af0ab1c00b7f127b736600cd5e82feef83de",
    },
    "R12.PGVECTOR": {
      version: "0.8.5",
      artifactDigest:
        "sha256:6f88a5cbdde31666f4b6c1a6b75c51dcbeffe58f9a7d2b26e502d5a6e5e14d44",
      evidencePath: "implementation/p1/c07/c07-verification-evidence.v1.json",
      evidenceFreezeCommit: "23d400e7b56512975ecc2d0f1189322414e75de3",
      evidenceSha256:
        "sha256:0d9b53b93966859a91fc3f7a8cf73d0ded84d3760cd5d46c3d3696e4424ceeb3",
    },
    "R12.POSTGRESQL_RLS": {
      version: "17.10",
      artifactDigest: null,
      evidencePath: "implementation/p1/c07/c07-verification-evidence.v1.json",
      evidenceFreezeCommit: "23d400e7b56512975ecc2d0f1189322414e75de3",
      evidenceSha256:
        "sha256:0d9b53b93966859a91fc3f7a8cf73d0ded84d3760cd5d46c3d3696e4424ceeb3",
    },
  };

  for (const [referenceId, binding] of Object.entries(expected)) {
    const reference = byReference.get(referenceId);
    assert.ok(reference, referenceId);
    assert.equal(reference.exactVersion.version, binding.version);
    assert.equal(
      reference.exactVersion.artifactDigest,
      binding.artifactDigest,
    );
    assert.equal(reference.verification.scope, "P1_SYNTHETIC_ONLY");
    assert.equal(reference.verification.productionStatus, "NOT_VERIFIED");
    assert.equal(reference.productionAdoptionClaim, false);
    assert.equal(reference.futureReceiptRequired, true);
    assert.equal(reference.verification.evidence.path, binding.evidencePath);
    assert.equal(
      reference.verification.evidence.freezeCommit,
      binding.evidenceFreezeCommit,
    );
    assert.equal(
      reference.verification.evidence.sha256,
      binding.evidenceSha256,
    );
    assert.equal(
      sha256(gitShow(binding.evidenceFreezeCommit, binding.evidencePath)),
      binding.evidenceSha256,
    );
    assert.ok(reference.adoptedScope.length > 0);
    assert.ok(reference.deferredProductionScope.length > 0);
  }
});

test("every implementation binding is frozen before the inspected source and every source is official", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const officialRoots = new Map([
    [
      "R09.KEYCLOAK",
      [
        "https://github.com/keycloak/keycloak",
        "https://www.keycloak.org",
      ],
    ],
    [
      "R11.OPENFGA",
      [
        "https://github.com/openfga/openfga",
        "https://openfga.dev",
      ],
    ],
    [
      "R12.PGVECTOR",
      ["https://github.com/pgvector/pgvector"],
    ],
    [
      "R12.POSTGRESQL_RLS",
      ["https://www.postgresql.org"],
    ],
  ]);

  for (const reference of preparation.references) {
    for (const binding of reference.implementationBindings) {
      assert.equal(
        sha256(gitShow(binding.freezeCommit, binding.path)),
        binding.sha256,
        `${reference.referenceId}:${binding.path}`,
      );
      execFileSync("/usr/bin/git", [
        "merge-base",
        "--is-ancestor",
        binding.freezeCommit,
        INSPECTED_SOURCE_COMMIT,
      ]);
    }

    for (const source of reference.officialSources) {
      assert.ok(
        officialRoots
          .get(reference.referenceId)
          .some(
            (root) =>
              source.uri === root || source.uri.startsWith(`${root}/`),
          ),
        `${reference.referenceId}:${source.uri}`,
      );
      assert.ok(source.reviewedSections.length > 0, source.uri);
    }
  }
});

test("the preparation binds official research and a candidate ADR without claiming a Receipt", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const research = await readText(RESEARCH_PATH);
  const adr = await readText(ADR_PATH);

  for (const inputName of ["referenceCatalog", "referencePolicy"]) {
    const input = preparation.trustInputs[inputName];
    const bytes = await readText(input.path);
    assert.equal(input.fileSha256, sha256(Buffer.from(bytes)));
    assert.equal(
      input.canonicalSha256,
      await sha256ProjectValue(JSON.parse(bytes)),
    );
  }

  assert.equal(
    preparation.trustInputs.officialResearch.path,
    RESEARCH_PATH,
  );
  assert.equal(
    preparation.trustInputs.officialResearch.sha256,
    sha256(Buffer.from(research)),
  );
  assert.equal(preparation.trustInputs.architectureDecision.path, ADR_PATH);
  assert.equal(
    preparation.trustInputs.architectureDecision.sha256,
    sha256(Buffer.from(adr)),
  );

  assert.match(adr, /状态：Candidate/);
  assert.match(adr, /Keycloak 26\.7\.0/);
  assert.match(adr, /OpenFGA v1\.18\.1/);
  assert.match(adr, /PostgreSQL 17\.10/);
  assert.match(adr, /pgvector 0\.8\.5/);
  assert.match(adr, /RETROSPECTIVE_BACKFILL/);
  assert.match(adr, /does not claim production adoption/i);
  assert.match(adr, /does not create D1, Gate, Profile, or start-authorization state/i);

  assert.equal(preparation.futureReceiptBinding.profileSha256, "PENDING");
  assert.equal(
    preparation.futureReceiptBinding.executionBaselineDigest,
    "PENDING",
  );
  assert.equal(preparation.futureReceiptBinding.formalReceiptCreated, false);
  assert.equal(preparation.futureReceiptBinding.formalBundleCreated, false);
  assert.equal(preparation.futureReceiptBinding.freezeAttestationCreated, false);
});

test("the preparation is self-hashed and cannot authorize governance", async () => {
  const preparation = await readJson(PREPARATION_PATH);

  assert.equal(
    await sha256ProjectValue(withoutSelfHash(preparation)),
    preparation.preparationSha256,
  );
  assert.deepEqual(preparation.governanceBoundary, {
    createsSecondStateTruth: false,
    d1Written: false,
    workPackageStatusChanged: false,
    gateStatusChanged: false,
    manifestChanged: false,
    profileApproved: false,
    startAuthorized: false,
    profileReadinessEffect: "NONE",
  });

  const tampered = structuredClone(preparation);
  tampered.references[0].productionAdoptionClaim = true;
  assert.notEqual(
    await sha256ProjectValue(withoutSelfHash(tampered)),
    preparation.preparationSha256,
  );
});
