import { validateIndependentReviewSchemaInstance } from "./independent-model-review.mjs";

export const INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS = Object.freeze({
  activePolicy: Object.freeze({
    path: "implementation/governance/schemas/independent-review-policy.v2.active.schema.json",
    sha256:
      "sha256:b49e48d7c75371142468e9b92395586e26c884d5872dfba9cfc4801db4360162",
  }),
  targetedRemediationEvidence: Object.freeze({
    path: "implementation/governance/schemas/targeted-remediation-model-review-evidence.v1.schema.json",
    sha256:
      "sha256:e364821feb41faad8e2b6e2b355bbfb8d0841a8549c0df7e867e1de8cd272738",
  }),
});

export function validateActiveIndependentReviewPolicy({ policy, schemaBytes }) {
  return validateIndependentReviewSchemaInstance({
    schemaBytes,
    expectedSchemaSha256: INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS.activePolicy.sha256,
    instance: policy,
    label: "Active independent review Policy v2 Schema",
  });
}

export function validateTargetedRemediationModelReviewEvidence({
  evidence,
  schemaBytes,
}) {
  return validateIndependentReviewSchemaInstance({
    schemaBytes,
    expectedSchemaSha256:
      INDEPENDENT_REVIEW_ARTIFACT_SCHEMAS.targetedRemediationEvidence.sha256,
    instance: evidence,
    label: "Targeted remediation model review Evidence Schema",
  });
}
