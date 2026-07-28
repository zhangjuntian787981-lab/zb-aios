import { env } from "cloudflare:workers";
import { createD1GovernanceJournal } from "../../../../db/governance-journal";
import manifest from "../../../../implementation/governance/work-package-manifest.v1.json";
import { createP2ReadinessGet } from "../../../../lib/p2-readiness-projection.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "../../../../lib/p2-start-authorization.mjs";
import { createProjectControl } from "../../../../lib/project-control.mjs";
import { isProductOwner } from "../../../../scripts/project-policy.mjs";

export const dynamic = "force-dynamic";

function configuredProductOwner() {
  return (env as unknown as { PROJECT_OWNER_EMAIL?: string })
    .PROJECT_OWNER_EMAIL;
}

async function loadOnlineD1Snapshot() {
  const control = createProjectControl({
    manifest,
    journal: createD1GovernanceJournal(),
    p2StartPolicy: P2_V2_CANDIDATE_START_POLICY,
  });
  return control.snapshot();
}

export const GET = createP2ReadinessGet({
  configuredProductOwner,
  isProductOwner,
  loadSnapshot: loadOnlineD1Snapshot,
  clock: () => new Date().toISOString(),
});
