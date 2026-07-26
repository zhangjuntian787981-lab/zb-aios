import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const SOURCE_PATHS = [
  "../lib/c17-connector-sdk.mjs",
  "../lib/c17-mock-lab.mjs",
  "../lib/c17-time.mjs",
  "../implementation/p1/c17/README.md",
  "../implementation/p1/c17/compatibility-matrix.v1.json",
  "../implementation/p1/c17/connector-templates.v1.json",
  "../implementation/p1/c17/synthetic-connector-fixtures.v1.json",
  "../implementation/p1/c17/verification-matrix.v1.json",
  "../scripts/run-c17-tests.sh",
];
const ENTERPRISE_MARKER = /中宝|\b(?:Zhongbao|U9|OA)\b/i;
const CONNECTOR_INSTANCE_MARKER = /\bconnectorInstance\b/i;

test("enterprise marker probes cover Chinese and capitalization variants", () => {
  assert.match("中宝", ENTERPRISE_MARKER);
  assert.match("ConnectorInstance", CONNECTOR_INSTANCE_MARKER);
});

test("C17 source and fixtures contain no live network or enterprise material", async () => {
  const texts = await Promise.all(
    SOURCE_PATHS.map((path) =>
      readFile(new URL(path, import.meta.url), "utf8"),
    ),
  );
  const combined = texts.join("\n");
  assert.doesNotMatch(combined, /https?:\/\//i);
  assert.doesNotMatch(combined, /\bfetch\s*\(/);
  assert.doesNotMatch(
    combined,
    /node:(?:http|https|net|tls)|from\s+["'](?:undici|axios)/,
  );
  assert.doesNotMatch(
    combined,
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  );
  assert.doesNotMatch(combined, /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/);
  assert.doesNotMatch(combined, ENTERPRISE_MARKER);
  assert.doesNotMatch(combined, CONNECTOR_INSTANCE_MARKER);

  const c17Files = await readdir(
    new URL("../implementation/p1/c17/", import.meta.url),
  );
  assert.equal(c17Files.some((name) => name.endsWith(".sql")), false);
});
