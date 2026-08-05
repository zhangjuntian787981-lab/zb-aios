#!/usr/bin/env node

import {
  analyzeOpenAiTerraCliResult,
  openAiTerraDigests,
  persistOpenAiTerraDiagnostic,
  validateOpenAiTerraConfig,
  validateOpenAiTerraReviewSubject,
} from "../lib/openai-terra-independent-review.mjs";

function blocked(reasonCode, formalAttemptCount = 0) {
  return {
    status: "BLOCKED",
    reasonCodes: [reasonCode],
    formalAttemptCount,
    receiptIssued: false,
  };
}

export async function runOpenAiTerraIndependentReview({
  config,
}) {
  if (!validateOpenAiTerraConfig(config).ok) {
    return blocked("OPENAI_TERRA_CONFIG_INVALID");
  }
  return blocked("OPENAI_TERRA_ISOLATION_NOT_PROVED");
}

export async function finalizeOpenAiTerraInvocationDiagnostic(input) {
  let subject;
  try {
    subject = await validateOpenAiTerraReviewSubject({
      subjectBytes: input.subjectBytes,
      subjectSchemaBytes: input.subjectSchemaBytes,
      expectedSubjectSchemaSha256: openAiTerraDigests.bytes(input.subjectSchemaBytes),
    });
  } catch {
    return blocked("OPENAI_TERRA_TRUSTED_CONTEXT_INVALID", 1);
  }
  const sections = new Map(subject.parsed?.sections.map((entry) => [entry.descriptor.path, entry.descriptor.sha256]));
  if (!subject.ok || sections.get(subject.config?.schemas.output) !== openAiTerraDigests.bytes(input.outputSchemaBytes) ||
      sections.get(subject.config?.schemas.diagnostic) !== openAiTerraDigests.bytes(input.diagnosticSchemaBytes)) {
    return blocked("OPENAI_TERRA_TRUSTED_CONTEXT_INVALID", 1);
  }
  const diagnostic = await analyzeOpenAiTerraCliResult({
    ...input.cliResult,
    requestedModel: subject.config.reviewer.requestedModel,
    outputSchemaBytes: input.outputSchemaBytes,
    expectedOutputSchemaSha256: openAiTerraDigests.bytes(input.outputSchemaBytes),
  });
  try {
    const persistence = await persistOpenAiTerraDiagnostic({
      diagnostic,
      diagnosticSchemaBytes: input.diagnosticSchemaBytes,
      expectedDiagnosticSchemaSha256: openAiTerraDigests.bytes(input.diagnosticSchemaBytes),
      artifactBytes: input.artifactBytes,
      writeArtifact: input.writeArtifact,
      readArtifact: input.readArtifact,
    });
    return {
      status: diagnostic.status,
      reasonCodes: diagnostic.reasonCodes,
      formalAttemptCount: 1,
      receiptIssued: false,
      diagnostic,
      persistence,
    };
  } catch {
    return {
      status: "BLOCKED",
      reasonCodes: ["OPENAI_TERRA_DIAGNOSTIC_PERSISTENCE_FAILED"],
      formalAttemptCount: 1,
      receiptIssued: false,
      diagnostic,
      persistence: null,
    };
  }
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  process.stdout.write(`${JSON.stringify(blocked("OPENAI_TERRA_ISOLATION_NOT_PROVED"))}\n`);
  process.exitCode = 2;
}
