import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const port = 43127;

async function renderFromProductionServer() {
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
        const response = await fetch(`http://127.0.0.1:${port}/`, {
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

test("removes the starter and keeps truthful progress rules in source", async () => {
  const [page, layout, api, schema, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/api/progress/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /进度只计算“已验收”的任务/);
  assert.match(page, /P0-P2 只使用合成数据/);
  assert.match(page, /你不是目标企业员工/);
  assert.match(page, /当前不是实时数据/);
  assert.match(page, /企业 Connector 接入状态/);
  assert.match(page, /setFormIdempotencyKey\(uniqueKey\(\)\)/);
  assert.match(page, /idempotencyKey: formIdempotencyKey/);
  assert.match(
    page,
    /not_started: \[\s*"in_progress",\s*"awaiting_confirmation"/,
  );
  assert.match(layout, /多企业 AI 平台产品进度中心/);
  assert.match(layout, /favicon\.svg/);
  assert.match(api, /SCOPE_VERSION = "v4\.0-GENERIC-PRODUCT-P3-ONBOARDING"/);
  assert.match(api, /外部产品所有者与单一阶段审批/);
  assert.match(api, /P0-P2 零企业内部资料/);
  assert.match(api, /公开企业信息预收集规则/);
  assert.match(api, /通用租户、身份与数据边界/);
  assert.match(api, /v4-p0-08-technical-gates/);
  assert.match(api, /v4-p0-09-stage-approval/);
  assert.match(api, /v4-p2-01-product-hardening/);
  assert.match(api, /v4-p2-02-stage-approval/);
  assert.match(api, /v4-p3-02-stage-approval/);
  assert.match(api, /product-model-v4\.0/);
  assert.match(api, /PROJECT_OWNER_EMAIL/);
  assert.match(api, /isProductOwner/);
  assert.match(api, /mutationAuthorized: isProductOwner/);
  assert.match(api, /canStartPhase/);
  assert.match(api, /canAdvanceConnector/);
  assert.match(api, /nextStatus === "accepted"/);
  assert.match(api, /标记为已验收前，必须确认并填写证据/);
  assert.match(api, /接入阶段向前升级前，必须确认并填写验收证据/);
  assert.match(api, /enterprise-authorization:/);
  assert.match(api, /accepted: \[\]/);
  assert.match(api, /isDuplicateEvent/);
  assert.match(api, /idempotencyKey/);
  assert.match(api, /nextIndex > currentIndex \+ 1/);
  assert.match(schema, /task_events_idempotency_idx/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);

  await access(new URL("../public/favicon.ico", import.meta.url));
  await assert.rejects(
    access(new URL("app/_sites-preview/SkeletonPreview.tsx", root)),
  );
});
