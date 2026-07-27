import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { createFrozenEvidenceVerifier } from "../lib/frozen-evidence.mjs";
import {
  createMemoryJournal,
  createProjectControl,
} from "../lib/project-control.mjs";

const defaultManifestPath = new URL(
  "../implementation/governance/work-package-manifest.v1.json",
  import.meta.url,
);
const defaultJournalPath = new URL(
  "../implementation/governance/governance-events.v1.json",
  import.meta.url,
);
const defaultP0EvidenceIndexPath = new URL(
  "../implementation/governance/p0-frozen-evidence-index.v1.json",
  import.meta.url,
);
const defaultP1EvidenceIndexPath = new URL(
  "../implementation/governance/p1-d1-evidence-bindings.revision-64.v1.json",
  import.meta.url,
);

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} 必须是数组。`);
  return value;
}

function hasEvidence(record) {
  return (
    Array.isArray(record?.evidence_refs) &&
    record.evidence_refs.some(
      (reference) => typeof reference === "string" && reference.trim(),
    )
  );
}

function securityIssuesFor(baseline) {
  const issues = [];
  for (const connector of requireArray(baseline.connectors, "connectors")) {
    if (connector.stage !== "C0") {
      issues.push(`${connector.system} 在 P3 前必须保持 C0。`);
    }
    if (connector.enabled) {
      issues.push(`${connector.system} 在 P3 前不得启用。`);
    }
    if (connector.credentials_present) {
      issues.push(`${connector.system} 在 P3 前不得保存生产凭据。`);
    }
    if (connector.outbound_network) {
      issues.push(`${connector.system} 在 P3 前不得开放出站网络。`);
    }
  }
  if (baseline.source_modes?.approved_snapshot_enabled) {
    issues.push("P0—P2 不得启用企业快照。");
  }
  if (baseline.source_modes?.real_read_enabled) {
    issues.push("P0—P2 不得启用真实企业读取。");
  }
  if (baseline.enterprise_boundary?.information_present) {
    issues.push("P0—P2 不得保存企业内部资料。");
  }
  if (baseline.enterprise_boundary?.enterprise_users_present) {
    issues.push("P0—P2 不得导入真实企业用户。");
  }
  if (baseline.enterprise_boundary?.enterprise_credentials_present) {
    issues.push("P0—P2 不得保存企业凭据。");
  }
  if (baseline.enterprise_boundary?.enterprise_network_access) {
    issues.push("P0—P2 不得开放企业网络访问。");
  }
  if (baseline.p1?.allowed) {
    issues.push("G0 批准前不得把 P1 标记为允许启动。");
  }
  return issues;
}

export function evaluateP0(baseline, governanceSnapshot) {
  if (baseline?.phase !== "P0") {
    throw new Error("安全边界文件必须明确标记 phase=P0。");
  }
  const securityIssues = securityIssuesFor(baseline);
  const approvalAuthority = baseline.approval_authority;
  const authorityReady =
    approvalAuthority?.status === "ACTIVE" &&
    approvalAuthority?.product_owner_id === "external_product_owner" &&
    approvalAuthority?.authority_basis ===
      "USER_DEFINED_PRODUCT_GOVERNANCE" &&
    approvalAuthority?.does_not_grant_enterprise_data_access === true &&
    hasEvidence(approvalAuthority);
  const g0 = governanceSnapshot.gates.find(({ id }) => id === "G0");
  if (!g0) throw new Error("治理快照缺少 G0。");

  const status =
    securityIssues.length > 0
      ? "BLOCKED"
      : authorityReady && g0.status === "APPROVED"
        ? "READY"
        : "NOT_READY";
  return {
    status,
    phase: "P0",
    scopeVersion: `manifest-${governanceSnapshot.manifestVersion}`,
    p1Allowed: status === "READY" && governanceSnapshot.phaseEntry.P1,
    securityIssues,
    authorityReady,
    gateStatus: g0.status,
    missingWorkPackages: g0.missingWorkPackages,
    unresolvedApplicability: g0.unresolvedApplicability,
    verifiedWorkPackages: governanceSnapshot.workPackages
      .filter(
        ({ phase, verificationStatus }) =>
          phase === "P0" && verificationStatus === "VERIFIED",
      )
      .map(({ id }) => id),
  };
}

export async function loadJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

export async function loadGovernanceSnapshot(
  manifestPath = defaultManifestPath,
  journalPath = defaultJournalPath,
  p0EvidenceIndexPath = defaultP0EvidenceIndexPath,
  p1EvidenceIndexPath = defaultP1EvidenceIndexPath,
) {
  const [manifest, events, p0EvidenceIndex, p1EvidenceIndex] = await Promise.all([
    loadJson(manifestPath),
    loadJson(journalPath),
    loadJson(p0EvidenceIndexPath),
    loadJson(p1EvidenceIndexPath),
  ]);
  const verifyFrozenEvidence = createFrozenEvidenceVerifier({
    schemaVersion: "frozen-evidence-catalog.v1",
    records: [
      ...p0EvidenceIndex.records,
      ...p1EvidenceIndex.records,
    ],
  });
  const control = createProjectControl({
    manifest,
    journal: createMemoryJournal(events),
    verifyFrozenEvidence,
  });
  return control.snapshot();
}

function printHuman(result) {
  console.log(`P0 阶段门：${result.status}`);
  console.log(`范围版本：${result.scopeVersion}`);
  console.log(`G0 状态：${result.gateStatus}`);
  console.log(`是否允许进入 P1：${result.p1Allowed ? "是" : "否"}`);
  console.log(
    `P0 已验证：${result.verifiedWorkPackages.join("、") || "无"}`,
  );
  if (result.missingWorkPackages.length > 0) {
    console.log(`P0 尚缺：${result.missingWorkPackages.join("、")}`);
  }
  if (result.securityIssues.length > 0) {
    console.log("\n安全阻断：");
    for (const issue of result.securityIssues) console.log(`- ${issue}`);
  }
  if (!result.authorityReady) {
    console.log("\n外部产品所有者的唯一阶段审批权尚未形成有效证据。");
  }
}

async function main() {
  const args = process.argv.slice(2);
  const strict = args.includes("--strict");
  const baselinePath =
    args.find((arg) => !arg.startsWith("--")) ??
    "implementation/p0/baseline.json";
  const [baseline, governanceSnapshot] = await Promise.all([
    loadJson(baselinePath),
    loadGovernanceSnapshot(),
  ]);
  const result = evaluateP0(baseline, governanceSnapshot);
  printHuman(result);
  if (strict && result.status !== "READY") {
    process.exitCode = result.status === "BLOCKED" ? 3 : 2;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await main();
}
