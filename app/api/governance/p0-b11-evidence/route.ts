import { env } from "cloudflare:workers";
import { createD1GovernanceJournal } from "../../../../db/governance-journal";
import p0EvidenceIndex from "../../../../implementation/governance/p0-frozen-evidence-index.v1.json";
import manifest from "../../../../implementation/governance/work-package-manifest.v1.json";
import { createP0B11EvidenceGet } from "../../../../lib/p0-b11-evidence-projection.mjs";
import { isProductOwner } from "../../../../scripts/project-policy.mjs";

export const dynamic = "force-dynamic";

function configuredProductOwner() {
  return (env as unknown as { PROJECT_OWNER_EMAIL?: string })
    .PROJECT_OWNER_EMAIL;
}

async function loadJournalState() {
  const onlineJournal = createD1GovernanceJournal();
  return onlineJournal.load(manifest.project_id);
}

export const GET = createP0B11EvidenceGet({
  configuredProductOwner,
  isProductOwner,
  loadJournalState,
  catalog: p0EvidenceIndex,
  manifest,
  clock: () => new Date().toISOString(),
});
