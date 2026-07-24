import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const CONFIRMED = "CONFIRMED";
const VERIFIED = "VERIFIED";

function requireArray(value, label) {
  if (!Array.isArray(value)) {
    throw new Error(`${label} 必须是数组。`);
  }
  return value;
}

function hasEvidence(gate) {
  return (
    Array.isArray(gate?.evidence_refs) &&
    gate.evidence_refs.some(
      (reference) => typeof reference === "string" && reference.trim(),
    )
  );
}

export function evaluateP0(baseline) {
  if (baseline?.phase !== "P0") {
    throw new Error("阶段门文件必须明确标记 phase=P0。");
  }

  const connectors = requireArray(baseline.connectors, "connectors");
  const decisionGates = requireArray(
    baseline.decision_gates,
    "decision_gates",
  );
  const technicalGates = requireArray(
    baseline.technical_gates,
    "technical_gates",
  );

  const securityIssues = [];
  for (const connector of connectors) {
    if (connector.stage !== "C0") {
      securityIssues.push(`${connector.system} 当前必须保持 C0。`);
    }
    if (connector.enabled) {
      securityIssues.push(`${connector.system} 当前不得启用。`);
    }
    if (connector.credentials_present) {
      securityIssues.push(`${connector.system} 当前不得保存生产凭据。`);
    }
    if (connector.outbound_network) {
      securityIssues.push(`${connector.system} 当前不得开放生产出站网络。`);
    }
  }

  if (baseline.source_modes?.real_read_enabled) {
    securityIssues.push("P0 当前不得启用 REAL_READ。");
  }
  if (baseline.p1?.allowed) {
    securityIssues.push("P0 阶段门通过前不得把 P1 标记为允许启动。");
  }

  const missingDecisions = decisionGates
    .filter((gate) => gate.status !== CONFIRMED || !hasEvidence(gate))
    .map((gate) => ({ id: gate.id, label: gate.label, status: gate.status }));
  const missingTechnicalEvidence = technicalGates
    .filter((gate) => gate.status !== VERIFIED || !hasEvidence(gate))
    .map((gate) => ({ id: gate.id, label: gate.label, status: gate.status }));
  const finalDecisionReady =
    baseline.final_decision?.status === "GO" &&
    typeof baseline.final_decision?.decided_by === "string" &&
    baseline.final_decision.decided_by.trim() &&
    typeof baseline.final_decision?.decided_at === "string" &&
    baseline.final_decision.decided_at.trim() &&
    hasEvidence(baseline.final_decision);

  let status = "READY";
  if (securityIssues.length > 0) {
    status = "BLOCKED";
  } else if (
    missingDecisions.length > 0 ||
    missingTechnicalEvidence.length > 0 ||
    !finalDecisionReady
  ) {
    status = "NOT_READY";
  }

  return {
    status,
    phase: "P0",
    scopeVersion: baseline.scope_version,
    p1Allowed: status === "READY",
    securityIssues,
    missingDecisions,
    missingTechnicalEvidence,
    finalDecision: baseline.final_decision?.status ?? "NOT_DECIDED",
  };
}

export async function loadBaseline(path) {
  const text = await readFile(path, "utf8");
  return JSON.parse(text);
}

function printHuman(result) {
  console.log(`P0 阶段门：${result.status}`);
  console.log(`范围版本：${result.scopeVersion}`);
  console.log(`是否允许进入 P1：${result.p1Allowed ? "是" : "否"}`);

  if (result.securityIssues.length > 0) {
    console.log("\n安全阻断：");
    for (const issue of result.securityIssues) console.log(`- ${issue}`);
  }
  if (result.missingDecisions.length > 0) {
    console.log("\n等待公司确认：");
    for (const gate of result.missingDecisions) {
      console.log(`- ${gate.label}（${gate.status}）`);
    }
  }
  if (result.missingTechnicalEvidence.length > 0) {
    console.log("\n等待技术证据：");
    for (const gate of result.missingTechnicalEvidence) {
      console.log(`- ${gate.label}（${gate.status}）`);
    }
  }
  if (result.finalDecision !== "GO") {
    console.log(`\n最终 Go/No-Go：${result.finalDecision}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const strict = args.includes("--strict");
  const path =
    args.find((arg) => !arg.startsWith("--")) ??
    "implementation/p0/baseline.json";
  const result = evaluateP0(await loadBaseline(path));
  printHuman(result);

  if (strict && result.status !== "READY") {
    process.exitCode = result.status === "BLOCKED" ? 3 : 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
