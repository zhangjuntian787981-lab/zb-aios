import { env } from "cloudflare:workers";
import { createD1GovernanceJournal } from "../../../../db/governance-journal";
import manifest from "../../../../implementation/governance/work-package-manifest.v1.json";
import { createG0StaleAuditGet } from "../../../../lib/g0-stale-audit-projection.mjs";
import { createProjectControl } from "../../../../lib/project-control.mjs";
import { isProductOwner } from "../../../../scripts/project-policy.mjs";

export const dynamic = "force-dynamic";

function configuredProductOwner() {
  return (env as unknown as { PROJECT_OWNER_EMAIL?: string })
    .PROJECT_OWNER_EMAIL;
}

async function loadOnlineD1AuditInput() {
  const onlineJournal = createD1GovernanceJournal();
  const journalState = await onlineJournal.load(manifest.project_id);
  const capturedState = structuredClone(journalState);
  const capturedJournal = {
    async load(projectId: string) {
      if (projectId !== manifest.project_id) {
        throw new Error("Unexpected governance project.");
      }
      return structuredClone(capturedState);
    },
    async append() {
      throw new Error("G0 stale audit is read-only.");
    },
  };
  const control = createProjectControl({
    manifest,
    journal: capturedJournal,
  });
  return {
    journalState: capturedState,
    snapshot: await control.snapshot(),
  };
}

export const GET = createG0StaleAuditGet({
  configuredProductOwner,
  isProductOwner,
  loadAuditInput: loadOnlineD1AuditInput,
  clock: () => new Date().toISOString(),
});
