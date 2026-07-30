import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { sha256ProjectValue } from "../lib/project-control.mjs";

const PREPARATION_PATH =
  "implementation/governance/reference-review/o02-reference-review-preparation.v1.json";
const RESEARCH_PATH =
  "implementation/governance/reference-review/o02-official-reference-research.v1.md";
const ADR_PATH = "docs/adr/0010-o02-reference-review-preparation.md";
const INSPECTED_SOURCE_COMMIT =
  "0cd6813f3fec4a07e61cd19d679e6e00713358a3";
const INSPECTED_SOURCE_TREE =
  "f324263ff688836c132c38a7cb82933bec19f245";

const sha256 = (bytes) =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;

const readText = (path) =>
  readFile(new URL(`../${path}`, import.meta.url), "utf8");

const readJson = async (path) => JSON.parse(await readText(path));

const withoutSelfHash = (value) => {
  const copy = structuredClone(value);
  delete copy.preparationSha256;
  return copy;
};

test("O02 preparation fixes the complete candidate set without selecting a tool lock", async () => {
  const preparation = await readJson(PREPARATION_PATH);

  assert.equal(
    preparation.schemaVersion,
    "o02-reference-review-preparation.v1",
  );
  assert.equal(preparation.status, "GIT_FROZEN_INPUT_ONLY");
  assert.equal(preparation.reviewMode, "PROSPECTIVE");
  assert.equal(preparation.workPackageId, "O02");
  assert.deepEqual(preparation.inspectedSource, {
    commit: INSPECTED_SOURCE_COMMIT,
    tree: INSPECTED_SOURCE_TREE,
  });
  assert.equal(
    execFileSync("/usr/bin/git", [
      "rev-parse",
      `${INSPECTED_SOURCE_COMMIT}^{tree}`,
    ], { encoding: "utf8" }).trim(),
    INSPECTED_SOURCE_TREE,
  );

  assert.deepEqual(
    preparation.references.map(
      ({ referenceId, decision, productionAdoptionClaim }) => ({
        referenceId,
        decision,
        productionAdoptionClaim,
      }),
    ),
    [
      {
        referenceId: "R26.EXTERNAL_SECRETS_OPERATOR",
        decision: "DEFER",
        productionAdoptionClaim: false,
      },
      {
        referenceId: "R26.OPENBAO",
        decision: "DEFER",
        productionAdoptionClaim: false,
      },
      {
        referenceId: "R26.SPIRE",
        decision: "DEFER",
        productionAdoptionClaim: false,
      },
    ],
  );

  assert.deepEqual(preparation.toolLockAssessments, [
    {
      domain: "O02_SECRETS_SYSTEM",
      selection: "UNSELECTED_BLOCKS_EVIDENCE",
      preferredPocCandidate: "R26.OPENBAO",
      rejectedPrimaryStoreCandidate: "R26.EXTERNAL_SECRETS_OPERATOR",
    },
    {
      domain: "O02_WORKLOAD_IDENTITY",
      selection: "UNSELECTED_BLOCKS_EVIDENCE",
      conditionalPocCandidate: "R26.SPIRE",
      alternativeReferenceReviewRequired:
        "KUBERNETES_PROJECTED_SERVICE_ACCOUNT_TOKEN",
    },
  ]);
});

test("O02 preparation pins researched releases but keeps every decision deferred", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const byReference = new Map(
    preparation.references.map((reference) => [
      reference.referenceId,
      reference,
    ]),
  );

  assert.deepEqual(byReference.get("R26.OPENBAO").exactVersion, {
    version: "v2.6.1",
    releaseCommit: "ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f",
    linuxAmd64TarSha256:
      "sha256:ca8d836eb3a5c80407e45e762300b64e7138c419e78826955f2e4ba4ce6d8a6b",
    linuxArm64TarSha256:
      "sha256:a74aa73b80000a4340a90edbf27726c0fb0a4537970eab6e1a7e0e211d117b75",
  });
  assert.deepEqual(byReference.get("R26.SPIRE").exactVersion, {
    version: "v1.15.2",
    releaseCommit: "e78e2eeca03a8a420bfe1b23b6eaf3db0db78630",
    linuxAmd64MuslTarSha256:
      "sha256:3874d07ffeb6640bafb9fe6a538de06151f155d5ed2f8e8a51f138d2f51b8105",
    linuxArm64MuslTarSha256:
      "sha256:92e782b285c50c62cdf37fdfa8917ea68fa57685b3bf99d03db36da4095678fa",
  });
  assert.deepEqual(
    byReference.get("R26.EXTERNAL_SECRETS_OPERATOR").exactVersion,
    {
      version: "v2.8.0",
      releaseCommit: "2e0f135f739eff1543b0a86cbedf9331756432d5",
      chartVersion: "helm-chart-2.8.0",
      chartCommit: "6f1eed573faac17c3272c576cfd419a5b40db25d",
      imageDigest:
        "sha256:24c0dd3699e0988520afd2218612758cd97d1f702757b5b4fcf89adaa33ef679",
    },
  );

  for (const reference of preparation.references) {
    assert.equal(reference.decision, "DEFER");
    assert.equal(reference.productionAdoptionClaim, false);
    assert.equal(reference.futureReceiptRequired, true);
    assert.ok(reference.reReviewTrigger.length > 0);
    assert.ok(reference.blockedBy.length > 0);
    assert.ok(reference.officialSources.length > 0);
    for (const source of reference.officialSources) {
      assert.ok(source.reviewedSections.length > 0, source.uri);
    }
  }
});

test("O02 preparation binds exact catalog, policy, profile, research and candidate ADR bytes", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const jsonInputs = [
    "referenceCatalog",
    "referencePolicy",
    "candidateProfile",
  ];

  for (const inputName of jsonInputs) {
    const input = preparation.trustInputs[inputName];
    const bytes = await readText(input.path);
    assert.equal(input.fileSha256, sha256(Buffer.from(bytes)));
    assert.equal(
      input.canonicalSha256,
      await sha256ProjectValue(JSON.parse(bytes)),
    );
  }

  for (const inputName of ["officialResearch", "architectureDecision"]) {
    const input = preparation.trustInputs[inputName];
    const bytes = await readText(input.path);
    assert.equal(input.sha256, sha256(Buffer.from(bytes)));
  }

  assert.equal(
    preparation.trustInputs.officialResearch.path,
    RESEARCH_PATH,
  );
  const adr = await readText(ADR_PATH);
  assert.match(adr, /状态：Candidate/);
  assert.match(adr, /OpenBao v2\.6\.1/);
  assert.match(adr, /SPIRE v1\.15\.2/);
  assert.match(adr, /ESO v2\.8\.0/);
  assert.match(adr, /does not create a formal Reference Review Receipt/i);
  assert.match(adr, /does not authorize or start O02/i);
});

test("O02 sources stay on exact official roots and the artifact has no governance effect", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  const roots = new Map([
    [
      "R26.EXTERNAL_SECRETS_OPERATOR",
      [
        "https://external-secrets.io",
        "https://github.com/external-secrets/external-secrets",
      ],
    ],
    [
      "R26.OPENBAO",
      ["https://openbao.org", "https://github.com/openbao/openbao"],
    ],
    [
      "R26.SPIRE",
      ["https://spiffe.io", "https://github.com/spiffe/spire"],
    ],
  ]);

  for (const reference of preparation.references) {
    for (const source of reference.officialSources) {
      assert.ok(
        roots
          .get(reference.referenceId)
          .some(
            (root) =>
              source.uri === root || source.uri.startsWith(`${root}/`),
          ),
        `${reference.referenceId}:${source.uri}`,
      );
    }
  }

  assert.deepEqual(preparation.formalArtifacts, {
    receiptsFrozen: false,
    bundleFrozen: false,
    freezeAttestationFrozen: false,
    pocResultsFrozen: false,
  });
  assert.deepEqual(preparation.governanceEffect, {
    d1EventCreated: false,
    profileApproved: false,
    startAuthorized: false,
    workPackageStarted: false,
    workPackageStatusChanged: false,
  });
});

test("O02 preparation self-hash covers the complete closed input", async () => {
  const preparation = await readJson(PREPARATION_PATH);
  assert.equal(
    preparation.preparationSha256,
    await sha256ProjectValue(withoutSelfHash(preparation)),
  );
});
