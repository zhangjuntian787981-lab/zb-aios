import { env } from "cloudflare:workers";
import { createD1GovernanceJournal } from "../../../../db/governance-journal";
import p0EvidenceIndex from "../../../../implementation/governance/p0-frozen-evidence-index.v1.json";
import manifest from "../../../../implementation/governance/work-package-manifest.v1.json";
import { createFrozenEvidenceVerifier } from "../../../../lib/frozen-evidence.mjs";
import {
  G0_REMEDIATION_BUILD_BINDING,
  createG0RemediationHandlers,
} from "../../../../lib/g0-remediation.mjs";
import { createProjectControl } from "../../../../lib/project-control.mjs";
import { isProductOwner } from "../../../../scripts/project-policy.mjs";

export const dynamic = "force-dynamic";

const verifyFrozenEvidence =
  createFrozenEvidenceVerifier(p0EvidenceIndex);

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
      journal: onlineJournal,
      control: createProjectControl({
        manifest,
        journal: onlineJournal,
        verifyFrozenEvidence,
      }),
    };
  }
  const capturedState = await onlineJournal.load(manifest.project_id);
  const capturedJournal = {
    async load(projectId: string) {
      if (projectId !== manifest.project_id && projectId !== undefined) {
        throw new Error("Unexpected governance project.");
      }
      return structuredClone(capturedState);
    },
    async append() {
      throw new Error("G0 remediation preview is read-only.");
    },
  };
  return {
    journal: capturedJournal,
    control: createProjectControl({
      manifest,
      journal: capturedJournal,
      verifyFrozenEvidence,
    }),
  };
}

const handlers = createG0RemediationHandlers({
  configuredProductOwner,
  isProductOwner,
  createRuntime,
  manifest,
  catalog: p0EvidenceIndex,
  buildBinding: G0_REMEDIATION_BUILD_BINDING,
});

export const GET = handlers.GET;
export const POST = handlers.POST;
