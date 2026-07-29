import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const research = await readFile(
  new URL(
    "../implementation/p0/f03/p0-b07-official-reference-research.v1.md",
    import.meta.url,
  ),
  "utf8",
);

const adr = await readFile(
  new URL("../docs/adr/0007-f03-contract-reference-decisions.md", import.meta.url),
  "utf8",
);

test("F03 reference research is source-bounded and has no governance effect", () => {
  assert.match(research, /查询日期：2026-07-30/);
  assert.match(research, /仅官方标准正文、官方仓库、官方发布、官方安全资料/);
  assert.match(research, /状态：`RESEARCH_INPUT_ONLY`/);
  assert.match(research, /治理效力：`NONE`/);
  assert.match(research, /数据边界：`P0_SYNTHETIC_ONLY`/);
  assert.match(research, /不能冒充 P0-B07 的 F03 托管阻断证据/);
});

test("F03 decision ADR fixes adopted references and exact implementation pins", () => {
  for (const adopted of [
    "JSON Schema 2020-12",
    "OpenAPI 3.1.2",
    "CloudEvents 1.0.2 Core + JSON Format",
    "RFC 9457",
    "Ajv 8.20.0",
    "ajv-formats 2.1.1",
    "GitHub Actions",
  ]) {
    assert.match(adr, new RegExp(adopted.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }

  assert.match(adr, /11d5960a326750d5838078e36cf38b85af677262/);
  assert.match(adr, /49933ea5288caeca8642d1e84afbd3f7d6820020/);
  assert.match(adr, /eight-category mutation strategy[\s\S]*`ADAPT`/);
});

test("F03 decision ADR records deferred and inapplicable candidates without production claims", () => {
  assert.match(adr, /CloudEvents HTTP Binding[\s\S]*`DEFER`/);
  assert.match(adr, /Pact JS[\s\S]*`DEFER`/);
  assert.match(adr, /WireMock[\s\S]*`NOT_APPLICABLE`/);
  assert.match(adr, /Schemathesis[\s\S]*`DEFER`/);
  assert.match(adr, /Testcontainers for Node\.js[\s\S]*`NOT_APPLICABLE`/);
  assert.match(adr, /does not claim production adoption/i);
  assert.match(adr, /does not close P0-B07/i);
  assert.match(adr, /does not create D1, Gate, Profile, or start-authorization state/i);
});
