import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const port = 43127;

async function renderFromProductionServer(path = "/") {
  const child = spawn(
    process.execPath,
    [
      "node_modules/wrangler/bin/wrangler.js",
      "dev",
      "--config",
      "dist/server/wrangler.json",
      "--port",
      String(port),
    ],
    {
      cwd: new URL("../", import.meta.url),
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let output = "";
  child.stdout.on("data", (chunk) => {
    output += chunk;
  });
  child.stderr.on("data", (chunk) => {
    output += chunk;
  });

  try {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (child.exitCode !== null) {
        throw new Error(`Production server exited early:\n${output}`);
      }
      try {
        const response = await fetch(`http://127.0.0.1:${port}${path}`, {
          headers: { accept: "text/html" },
        });
        if (response.ok) {
          return response;
        }
      } catch {
        // The server is still starting.
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Production server did not become ready:\n${output}`);
  } finally {
    child.kill("SIGTERM");
    if (child.exitCode === null) {
      await Promise.race([
        once(child, "exit"),
        new Promise((resolve) => setTimeout(resolve, 2_000)),
      ]);
    }
  }
}

test("server-renders the real project progress center", async () => {
  const response = await renderFromProductionServer();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>多企业 AI 平台产品进度中心<\/title>/i);
  assert.match(html, /正在读取真实任务状态/);
  assert.doesNotMatch(html, /Your site is taking shape|codex-preview/i);
  assert.doesNotMatch(html, /react-loading-skeleton/i);
});

test("progress API exposes a deny-first O02 and O03 start boundary", async () => {
  const response = await renderFromProductionServer("/api/progress");
  assert.equal(response.status, 200);

  const data = await response.json();
  for (const workPackageId of ["O02", "O03"]) {
    const task = data.tasks.find((item) => item.id === workPackageId);
    assert.ok(task, workPackageId);
    assert.equal(typeof task.structuralReady, "boolean");
    assert.ok(Array.isArray(task.structuralBlockers));
    assert.equal(task.startAuthorization.required, true);
    assert.equal(task.startAuthorization.authorized, false);
    assert.equal(task.allowedToStart, false);
    assert.ok(task.startAuthorization.reasonCodes.length > 0);
    assert.equal(
      Object.hasOwn(task.startAuthorization, "finalReleaseDigest"),
      false,
    );
  }
});

test("removes the starter and keeps truthful progress rules in source", async () => {
  const [page, layout, api, schema, manifest, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/progress/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(
      new URL(
        "../implementation/governance/work-package-manifest.v1.json",
        import.meta.url,
      ),
      "utf8",
    ),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /计划完成、代码实现、证据验证和阶段批准分开计算/);
  assert.match(page, /37 个真实工作包/);
  assert.match(page, /G0—G3 放行状态/);
  assert.match(page, /P0-P2 只使用合成数据/);
  assert.match(page, /你不是目标企业员工/);
  assert.match(page, /当前不是实时数据/);
  assert.match(page, /企业 Connector 接入状态/);
  assert.match(page, /setFormIdempotencyKey\(uniqueKey\(\)\)/);
  assert.match(page, /idempotencyKey: formIdempotencyKey/);
  assert.match(page, /action: "submit_gate"/);
  assert.match(page, /action: "decide_gate"/);
  assert.match(page, /action: "validate_human_baseline"/);
  assert.match(page, /F04 安全人工基线/);
  assert.match(page, /我确认这 10 条人工基线/);
  assert.match(page, /本决定将永久绑定冻结包/);
  assert.match(page, /decideGate\(gate, "APPROVE"\)/);
  assert.match(page, /decideGate\(gate, "RETURN"\)/);
  assert.match(page, /decideGate\(gate, "HOLD"\)/);
  assert.match(page, /not_started: \["in_progress"\]/);
  assert.match(page, /implemented: \["verified"\]/);
  assert.match(page, /structuralReady: boolean/);
  assert.match(page, /structuralBlockers: string\[\]/);
  assert.match(page, /type StartAuthorization = \{/);
  assert.match(page, /startAuthorization: StartAuthorization/);
  assert.match(page, /task\.allowedToStart !== true/);
  assert.match(page, /task\.structuralReady !== true/);
  assert.match(page, /task\.startAuthorization\?\.authorized !== true/);
  assert.match(page, /结构前置/);
  assert.match(page, /P2 Profile 与启动授权/);
  assert.match(page, /状态缺失，拒绝启动/);
  assert.doesNotMatch(page, /approve_p2_acceptance_profile/);
  assert.doesNotMatch(page, /authorize_p2_work_package_start/);
  assert.match(layout, /多企业 AI 平台产品进度中心/);
  assert.match(layout, /favicon\.svg/);
  assert.match(api, /manifest\.project_id/);
  assert.match(api, /createProjectControl/);
  assert.match(api, /verifyFrozenEvidence/);
  assert.match(api, /governanceIssues: snapshot\.evidenceValidationIssues/);
  assert.match(api, /snapshot\.workPackages/);
  assert.match(api, /snapshot\.phaseEntry\.P3/);
  assert.match(api, /PROJECT_OWNER_EMAIL/);
  assert.match(api, /isProductOwner/);
  assert.match(api, /mutationAuthorized: isProductOwner/);
  assert.match(api, /expectedRevision/);
  assert.match(api, /payload\.action === "submit_gate"/);
  assert.match(api, /payload\.action === "decide_gate"/);
  assert.match(api, /payload\.action === "validate_human_baseline"/);
  assert.match(api, /HUMAN_BASELINE_CANDIDATE_HASH/);
  assert.match(api, /expectedPackageHash: packageHash/);
  assert.match(api, /allowedDecisions = \["APPROVE", "RETURN", "HOLD"\]/);
  assert.match(api, /sha256:\[a-f0-9\]\{64\}/);
  assert.match(api, /enterprise-authorization:/);
  assert.match(api, /idempotencyKey/);
  assert.match(api, /nextIndex > currentIndex \+ 1/);
  assert.match(manifest, /"manifest_version": "1\.0\.0"/);
  assert.match(manifest, /"id": "F01"/);
  assert.match(manifest, /"id": "T08"/);
  assert.match(schema, /task_events_idempotency_idx/);
  assert.match(schema, /governance_events_project_revision_idx/);
  assert.match(schema, /governance_events_project_idempotency_idx/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);

  await access(new URL("../public/favicon.ico", import.meta.url));
  await assert.rejects(
    access(new URL("app/_sites-preview/SkeletonPreview.tsx", root)),
  );
});
