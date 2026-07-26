import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  C08SyntheticReferenceError,
  createC08SyntheticReferenceCatalog,
} from "../lib/c08-synthetic-reference-catalog.mjs";

const TENANT =
  "stn_018f0000-0000-7000-8000-000000000010";
const data = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p1/c08/synthetic-reference-catalog.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);

test("C08 Synthetic references require an exact Tenant catalog entry", () => {
  const catalog = createC08SyntheticReferenceCatalog(data);
  assert.deepEqual(Object.keys(catalog), [
    "verify",
    "authorizationResources",
  ]);
  assert.deepEqual(
    catalog.verify({
      tenantId: TENANT,
      kind: "MODEL",
      ref: "synthetic://c08/models/assistant",
      version: "model-1",
      sha256:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      asOf: null,
    }),
    {
      kind: "MODEL",
      ref: "synthetic://c08/models/assistant",
      version: "model-1",
      sha256:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      asOf: null,
      fixtureSourcePackage: "C08",
      intendedOwnerPackage: "C14",
      dependencyStatus: "PENDING_DEPENDENT_PACKAGE",
    },
  );
  assert.deepEqual(catalog.authorizationResources(TENANT), {
    READ: "synthetic-tenant-northstar-fasteners--read",
    MANAGE: "synthetic-tenant-northstar-fasteners--manage",
    TOOL_CALL: "synthetic-tenant-northstar-fasteners--tool-call",
  });
  for (const [tenantId, fixtureId] of [
    [
      "stn_018f0000-0000-7000-8000-000000000010",
      "synthetic-tenant-northstar-fasteners",
    ],
    [
      "stn_018f0000-0000-7000-8000-000000000011",
      "synthetic-tenant-blue-harbor-tools",
    ],
    [
      "stn_018f0000-0000-7000-8000-000000000012",
      "synthetic-tenant-cedar-field-components",
    ],
  ]) {
    assert.deepEqual(catalog.authorizationResources(tenantId), {
      READ: `${fixtureId}--read`,
      MANAGE: `${fixtureId}--manage`,
      TOOL_CALL: `${fixtureId}--tool-call`,
    });
    assert.equal(
      catalog.verify({
        tenantId,
        kind: "MODEL",
        ref: "synthetic://c08/models/assistant",
        version: "model-1",
        sha256:
          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        asOf: null,
      }).intendedOwnerPackage,
      "C14",
    );
    assert.equal(
      catalog.verify({
        tenantId,
        kind: "PURPOSE",
        ref: "policy://c08/purpose/analyze-order",
        version: null,
        sha256: null,
        asOf: null,
      }).intendedOwnerPackage,
      "C08",
    );
  }
});

test("a plausible Synthetic URI cannot self-assert provenance", () => {
  const catalog = createC08SyntheticReferenceCatalog(data);
  for (const query of [
    {
      tenantId: TENANT,
      kind: "GOAL",
      ref: "synthetic://c08/goals/not-frozen",
      version: null,
      sha256: null,
      asOf: null,
    },
    {
      tenantId:
        "stn_018f0000-0000-7000-8000-000000000013",
      kind: "MODEL",
      ref: "synthetic://c08/models/assistant",
      version: "model-1",
      sha256:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      asOf: null,
    },
    {
      tenantId: TENANT,
      kind: "MODEL",
      ref: "synthetic://c08/models/assistant",
      version: "forged",
      sha256:
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      asOf: null,
    },
  ]) {
    assert.throws(
      () => catalog.verify(query),
      (error) =>
        error instanceof C08SyntheticReferenceError &&
        error.code === "SYNTHETIC_REFERENCE_UNVERIFIED",
    );
  }
});

test("Tenant-scoped data references cannot cross Synthetic Tenants", () => {
  const catalog = createC08SyntheticReferenceCatalog(data);
  const references = [
    {
      tenantId: "stn_018f0000-0000-7000-8000-000000000010",
      ref: "evidence://c08/knowledge/synthetic-handbook",
      sha256:
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    },
    {
      tenantId: "stn_018f0000-0000-7000-8000-000000000011",
      ref: "evidence://c08/tenants/blue-harbor-tools/knowledge/synthetic-handbook",
      sha256:
        "sha256:5555555555555555555555555555555555555555555555555555555555555555",
    },
    {
      tenantId: "stn_018f0000-0000-7000-8000-000000000012",
      ref: "evidence://c08/tenants/cedar-field-components/knowledge/synthetic-handbook",
      sha256:
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  ];
  for (const [index, reference] of references.entries()) {
    const query = {
      tenantId: reference.tenantId,
      kind: "KNOWLEDGE",
      ref: reference.ref,
      version: "knowledge-1",
      sha256: reference.sha256,
      asOf: "2026-07-26T09:59:00.000Z",
    };
    assert.equal(catalog.verify(query).ref, reference.ref);
    assert.throws(
      () =>
        catalog.verify({
          ...query,
          tenantId: references[(index + 1) % references.length].tenantId,
        }),
      (error) =>
        error instanceof C08SyntheticReferenceError &&
        error.code === "SYNTHETIC_REFERENCE_UNVERIFIED",
    );
  }
});

test("the catalog rejects a resource mapping detached from its fixture", () => {
  const tampered = structuredClone(data);
  tampered.tenants[0].authorizationResources.MANAGE =
    "synthetic-tenant-blue-harbor-tools--manage";
  assert.throws(
    () => createC08SyntheticReferenceCatalog(tampered),
    (error) =>
      error instanceof C08SyntheticReferenceError &&
      error.code === "INVALID_REFERENCE_CATALOG",
  );
});
