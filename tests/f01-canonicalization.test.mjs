import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  canonicalizeProjectJson,
  sha256ProjectValue,
} from "../lib/project-control.mjs";

const cases = JSON.parse(
  await readFile(
    new URL(
      "../implementation/p0/f01/canonicalization-cases.v1.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const workerPath = fileURLToPath(
  new URL("../scripts/f01-canonical-worker.mjs", import.meta.url),
);

test("F01 freezes one canonical UTF-8 byte sequence for equivalent JSON", async () => {
  for (const fixture of cases.cases) {
    const canonicalValues = fixture.equivalentInputs.map((value) =>
      canonicalizeProjectJson(value),
    );
    assert.deepEqual(
      new Set(canonicalValues),
      new Set([fixture.expectedCanonicalJson]),
      fixture.id,
    );
    assert.equal(
      Buffer.from(canonicalValues[0], "utf8").toString("hex"),
      fixture.expectedUtf8Hex,
      fixture.id,
    );
    assert.equal(
      await sha256ProjectValue(fixture.equivalentInputs[0]),
      fixture.expectedSha256,
      fixture.id,
    );
  }

  assert.notEqual(
    canonicalizeProjectJson(cases.arrayOrderControl.left),
    canonicalizeProjectJson(cases.arrayOrderControl.right),
  );
});

test("F01 reconciles the same canonical bytes and SHA-256 in three processes", () => {
  const input = JSON.stringify(cases.cases[1].equivalentInputs[0]);
  const receipts = Array.from({ length: 3 }, () =>
    JSON.parse(
      execFileSync(process.execPath, [workerPath], {
        input,
        encoding: "utf8",
      }),
    ),
  );

  assert.equal(new Set(receipts.map(({ pid }) => pid)).size, 3);
  assert.equal(
    new Set(receipts.map(({ canonicalUtf8Hex }) => canonicalUtf8Hex)).size,
    1,
  );
  assert.equal(
    new Set(
      receipts.map(({ canonicalBytesSha256 }) => canonicalBytesSha256),
    ).size,
    1,
  );
  assert.deepEqual(
    new Set(receipts.map(({ nodeVersion }) => nodeVersion)),
    new Set([process.version]),
  );
  assert.deepEqual(
    new Set(receipts.map(({ platform }) => platform)),
    new Set([process.platform]),
  );
  assert.deepEqual(
    new Set(receipts.map(({ architecture }) => architecture)),
    new Set([process.arch]),
  );
  assert.equal(
    receipts[0].canonicalUtf8Hex,
    cases.cases[1].expectedUtf8Hex,
  );
  assert.equal(
    receipts[0].canonicalBytesSha256,
    cases.cases[1].expectedSha256,
  );
});
