import { env } from "cloudflare:workers";
import { createD1GovernanceJournal } from "../../../../db/governance-journal";
import p0EvidenceIndex from "../../../../implementation/governance/p0-frozen-evidence-index.v1.json";
import p1EvidenceBindings from "../../../../implementation/governance/p1-d1-evidence-bindings.revision-64.v1.json";
import manifest from "../../../../implementation/governance/work-package-manifest.v1.json";
import { createFrozenEvidenceVerifier } from "../../../../lib/frozen-evidence.mjs";
import { createG0DecisionHandlers } from "../../../../lib/g0-decision.mjs";
import { P2_V2_CANDIDATE_START_POLICY } from "../../../../lib/p2-start-authorization.mjs";
import { createProjectControl } from "../../../../lib/project-control.mjs";
import { isProductOwner } from "../../../../scripts/project-policy.mjs";

export const dynamic = "force-dynamic";

const verifyFrozenEvidence = createFrozenEvidenceVerifier({
  schemaVersion: "frozen-evidence-catalog.v1",
  records: [
    ...p0EvidenceIndex.records,
    ...p1EvidenceBindings.records,
  ],
});

function configuredProductOwner() {
  return (env as unknown as { PROJECT_OWNER_EMAIL?: string })
    .PROJECT_OWNER_EMAIL;
}

async function createRuntime({
  readOnly,
}: {
  readOnly: boolean;
}) {
  const onlineJournal = createD1GovernanceJournal();
  if (!readOnly) {
    return {
      control: createProjectControl({
        manifest,
        journal: onlineJournal,
        verifyFrozenEvidence,
        p2StartPolicy: P2_V2_CANDIDATE_START_POLICY,
      }),
    };
  }

  const capturedState = await onlineJournal.load(manifest.project_id);
  const capturedJournal = {
    async load(projectId: string) {
      if (projectId !== manifest.project_id) {
        throw new Error("Unexpected governance project.");
      }
      return structuredClone(capturedState);
    },
    async append() {
      throw new Error("G0 Decision preview is read-only.");
    },
  };
  return {
    control: createProjectControl({
      manifest,
      journal: capturedJournal,
      verifyFrozenEvidence,
      p2StartPolicy: P2_V2_CANDIDATE_START_POLICY,
    }),
  };
}

const handlers = createG0DecisionHandlers({
  configuredProductOwner,
  isProductOwner,
  createRuntime,
  clock: () => new Date().toISOString(),
});

export const GET = handlers.GET;
export const POST = handlers.POST;
