function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

export const P2_LEGACY_WORKER_ATTESTATION_PIN_POLICY = deepFreeze({
  schemaVersion: "p2-worker-attestation-pin-policy.v1",
  canonicalization: "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785",
  attestationPath:
    "implementation/p2/attestations/p2-execution-baseline-attestation.48a4e4.v1.json",
  attestationSha256:
    "sha256:46fe858b866f16a97c9a9e0d10dc604412feceed85e03201da7ed75c7a85f298",
  attestationId: "p2eba_48a4e4eac1f2_e6282c301d6e",
  predicateType:
    "urn:multi-enterprise-ai-platform:p2-execution-baseline-attestation:v1",
  source: {
    commit: "48a4e4eac1f2fc2404d21ca5ab9a2d014a0e20e5",
    tree: "49b9fab6215fe985352473edfc46bd068302d61e",
    objectType: "commit",
  },
  executionBaseline: {
    recipePath:
      "implementation/p2/acceptance/p2-execution-baseline-recipe.v1.json",
    recipeSha256:
      "sha256:43289d9784888585ad427b723370e89debc3a67bf14e424b4bfb41e101bc37ef",
    digest:
      "sha256:e6282c301d6eb05cace8361f5974143897db59c3770d4c8856211f0635599bee",
  },
  subjects: [
    {
      kind: "PROFILE",
      name: "p2-acceptance-profile-v2-candidate",
      path:
        "implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json",
      version: "p2-acceptance-profile.v2",
      sha256:
        "sha256:90a9741d6ae39012458f073523da0c7b4dc8e4eef53ea759b32d6640e6aaef32",
    },
    {
      kind: "SCHEMA",
      name: "p2-acceptance-receipt-v2-schema",
      path:
        "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
      version: "p2-acceptance-receipt.v2",
      sha256:
        "sha256:f995310688c620b24c42b058fb6305b00876e0dfa0b8a755f41f827bfcb700bf",
    },
    {
      kind: "VALIDATOR",
      name: "p2-acceptance-receipt-semantic-validator",
      path: "lib/p2-acceptance-receipt-validator.mjs",
      version: "p2-acceptance-validator.v2",
      sha256:
        "sha256:ae2b169b81f7769dfa952d0393b770e7a547f378989ab25a75ef62276f349200",
    },
    {
      kind: "FIXTURE",
      name: "c06-synthetic-authorization-fixtures",
      path:
        "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
      version: "c06-authorization-fixtures-v1",
      sha256:
        "sha256:2c46d1c46eafaf5aebbfe7382cd16a9138a1c2cf142ca581ae101b254ebda130",
    },
    {
      kind: "TOOL_LOCK",
      name: "npm-package-lock",
      path: "package-lock.json",
      version: "3",
      sha256:
        "sha256:6d5832c95b23aa8386d5a6f69e51d6346666d6abe233ab766154c74beec83c86",
    },
  ],
  buildVerification: {
    method: "BUILD_TIME_LOCAL_GIT_OBJECT_READ",
    builderId:
      "multi-enterprise-ai-platform/p2-execution-baseline-attestation-builder",
    builderVersion: "1.0.0",
    result: "VERIFIED",
  },
});

export const P2_PROFILE_V2_WORKER_ATTESTATION_PIN_POLICY = deepFreeze({
  schemaVersion: "p2-worker-attestation-pin-policy.v1",
  canonicalization: "PROJECT_CANONICAL_JSON_V1_NOT_RFC8785",
  attestationPath:
    "implementation/p2/attestations/p2-execution-baseline-attestation.bc718b.v1.json",
  attestationSha256:
    "sha256:83f63243386d179cf3facc59e24eb7bcbcfb7e7960f42d8d38c7d83aef787220",
  attestationId: "p2eba_bc718bc1a069_36cfdf3f36d5",
  predicateType:
    "urn:multi-enterprise-ai-platform:p2-execution-baseline-attestation:v1",
  source: {
    commit: "bc718bc1a069deaa388b9a00e0135c8e9427dd91",
    tree: "2fa1d5a511215a78ce324b61c585a4d4bb9697e0",
    objectType: "commit",
  },
  executionBaseline: {
    recipePath:
      "implementation/p2/acceptance/p2-execution-baseline-recipe.profile-v2.v1.json",
    recipeSha256:
      "sha256:fa35085d2d18131920d932b3321fd77bc370c1d44cfb927feb91c34604c0c89e",
    digest:
      "sha256:36cfdf3f36d5a4f8bbafe519a6edfdc0fe1cfc86a31cf14252daf70a47973aec",
  },
  subjects: [
    {
      kind: "PROFILE",
      name: "p2-acceptance-profile-v2",
      path: "implementation/p2/acceptance/p2-acceptance-profile.v2.json",
      version: "p2-acceptance-profile.v2",
      sha256:
        "sha256:ed6836e5e212a95b66dd386e8bfbe1cf6aa5f37c1b281cfb0514e9aa9f7213f5",
    },
    {
      kind: "SCHEMA",
      name: "p2-acceptance-receipt-v2-schema",
      path: "implementation/p2/acceptance/p2-acceptance-receipt.v2.schema.json",
      version: "p2-acceptance-receipt.v2",
      sha256:
        "sha256:f995310688c620b24c42b058fb6305b00876e0dfa0b8a755f41f827bfcb700bf",
    },
    {
      kind: "VALIDATOR",
      name: "p2-acceptance-receipt-semantic-validator",
      path: "lib/p2-acceptance-receipt-validator.mjs",
      version: "p2-acceptance-validator.v2",
      sha256:
        "sha256:ff8da36988ace70213e58368b8b3894677e732e0c0e262f87ba8824fac6347a7",
    },
    {
      kind: "FIXTURE",
      name: "c06-synthetic-authorization-fixtures",
      path: "implementation/p1/c06/synthetic-authorization-fixtures.v1.json",
      version: "c06-authorization-fixtures-v1",
      sha256:
        "sha256:2c46d1c46eafaf5aebbfe7382cd16a9138a1c2cf142ca581ae101b254ebda130",
    },
    {
      kind: "TOOL_LOCK",
      name: "npm-package-lock",
      path: "package-lock.json",
      version: "3",
      sha256:
        "sha256:8a7e27bd052d9f6fa1371cc23c153ca40a5a6299a31bdc321169b4ebf68abdcf",
    },
  ],
  buildVerification: {
    method: "BUILD_TIME_LOCAL_GIT_OBJECT_READ",
    builderId:
      "multi-enterprise-ai-platform/p2-execution-baseline-attestation-builder",
    builderVersion: "1.0.0",
    result: "VERIFIED",
  },
});

export const P2_WORKER_ATTESTATION_PIN_POLICY =
  P2_PROFILE_V2_WORKER_ATTESTATION_PIN_POLICY;
