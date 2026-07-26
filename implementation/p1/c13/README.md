# C13 Skill Registry

## Outcome

C13 implements a P1, Synthetic-only Skill Release registry with immutable content hashes and an explicit governance path:

```text
SUBMITTED
  → STATIC_PASSED
  → EVALUATED
  → APPROVED
  → PILOT
  → STABLE
```

A release can then be withdrawn, or a channel can be rolled back to a previously published eligible release. A new Run receives a Skill only when the requested semantic version and SHA-256 exactly match the approved, non-withdrawn release currently selected by the requested channel.

The historical F04 candidate remains unchanged at
`PENDING_HUMAN_VALIDATION`. A separate append-only governance reference
binds the external Product Owner's validation to the exact candidate
SHA-256 and the approved G0 package SHA-256. No external event ID or time
was supplied, so G1 archival is explicitly pending. All four checked-in
releases still return `BLOCKED`: the human baseline is validated, but
there are zero reported case results. No checked-in release can be
approved or published.

## Public module seams

- `validateSkillManifest` checks the closed P1 Manifest.
- `canonicalSkillManifestSha256` hashes deterministic canonical JSON for this closed JSON subset.
- `createSkillRegistry` exposes `execute` and `resolveForRun`.
- `createMemorySkillRegistryStore` supports deterministic unit and concurrency tests.
- `createPostgresSkillRegistryStore` uses signed C07 transaction scope, SERIALIZABLE commands, idempotent receipts, CAS, FORCE RLS, and recovery after an uncertain commit acknowledgement.
- `createC13C06Authorizer` adapts the real C06 Authorization Facade.
- `createC13SyntheticSkillCatalog` binds the three F02 Tenants to source-review and F04 evaluation evidence.
- `evaluation-report.v1.schema.json` closes the runtime report contract
  and binds Tenant, Skill, release digest, frozen suite, human decision,
  report artifact, case count and per-case evidence.
- `synthetic-evaluation-reports.v1.json` contains four reproducible
  zero-result `BLOCKED` reports.
- `run-c13-evaluation.mjs` checks every artifact hash and recomputes the
  frozen F04 decision with the built-in deterministic gate.
- Catalog construction requires the actual report-bundle bytes, verifies
  their SHA-256, and binds every embedded evaluation field one-to-one to
  its report. The verifier also hashes the exact human-baseline candidate
  approved by the governance reference.
- The Registry and frozen catalog independently recompute F04 precedence:
  a complete zero-tolerance failure is `BLOCKED`, an ordinary threshold
  failure is `FAIL`, and only a complete report satisfying the case,
  category and overall thresholds is `PASS`.

The OpenAPI contract is `skill-registry.openapi.v1.json`; the closed
schemas are `skill-manifest.v1.schema.json` and
`evaluation-report.v1.schema.json`.

## Manifest

The only P1 fields are:

```json
{
  "schemaVersion": "1.0.0",
  "name": "analyze-synthetic-order",
  "version": "1.0.0",
  "description": "Analyze a fictitious order with cited synthetic evidence.",
  "instructions": "Use only the supplied Synthetic evidence. Return a concise finding and cite each source.",
  "allowedTools": ["catalog.read"],
  "executionMode": "INSTRUCTIONS_ONLY"
}
```

There is no script field. `executionMode` has one value. `allowedTools` is advisory metadata and never grants runtime permission; C06/C16 must authorize the actual operation again.

## Persistence and concurrency

Migration order is fixed:

1. `0019_skill_registry.sql`
2. `0020_skill_registry_runtime_roles.sql`

The four C13 tables are:

- `skill_release`: immutable content plus CAS-governed lifecycle state.
- `skill_channel`: `PILOT`/`STABLE` pointer with an independent generation.
- `skill_event`: append-only evidence.
- `command_receipt`: append-only idempotency recovery record.

`aios_c13_runtime` is `NOLOGIN`, `NOSUPERUSER`, `NOBYPASSRLS`, cannot delete, cannot update events or receipts, and cannot issue C07 scope signatures. The Store rejects a login that combines C13 runtime and C07 scope-signing roles.

After `static_report`, the frozen suite binding, or
`evaluation_report` is first written, PostgreSQL rejects every later
attempt to replace it, including updates made during otherwise valid
state transitions.

## Run resolution rules

Resolution fails closed when:

- the F04 human-decision or evaluation-report binding differs;
- no release is published on the channel;
- static check or evaluation has not passed;
- explicit approval is absent;
- the semantic version or digest differs;
- the release is withdrawn;
- Tenant, C05 identity, C06 authorization, or C07 scope binding differs.

Existing Runs should persist the returned `releaseId`, semantic version, and `contentSha256` in their C08 Run Manifest. Withdrawal blocks new resolution; it does not rewrite historical Run evidence.

## Verification

Run only the C13 suite:

```sh
sh scripts/run-c13-tests.sh
```

The PostgreSQL scripts create isolated local PostgreSQL 17 clusters under guarded `/tmp/c13-*.XXXXXX` paths, require pgvector because C07 does, and delete only those temporary clusters after a clean shutdown.

`tests/c13-synthetic-skill-catalog.test.mjs` recomputes the F04 gate
outcome from the frozen suite, gate configuration, validated governance
reference and empty case results. It must remain `BLOCKED`. Every
successful lifecycle fixture contains all ten case results and is
explicitly marked `TEST_ONLY`; it is state-machine evidence, not product
evaluation evidence.

`promptfoo` was not verified or claimed. The checked-in executable uses
the same frozen F04 gate function as the P0 package and labels itself
`FROZEN_GATE_EQUIVALENCE_ONLY`. Claiming promptfoo execution without
machine evidence is a no-go.

## Deliberate boundaries

- All data and references are Synthetic. Enterprise sources and adapters remain disabled until P3.
- C13 does not execute Skills, tools, Python, shell, JavaScript, or arbitrary code.
- The external Product Owner decision is recorded only as a local,
  hash-bound governance reference. Its external event ID and timestamp
  remain unknown and pending G1 archival.
- Real `.github/CODEOWNERS` rules and hashable deterministic source-review
  artifacts exist. Repository branch protection and human pull-request
  approval are still `NOT_VERIFIED`.
- C06 authorization uses a distinct protected resource for submit,
  static check, evaluate, approve, publish, withdraw, rollback and
  resolve. Every lifecycle event stores the current operation,
  decision/evidence refs and purpose.
- OCI packaging, SBOM, artifact signing, signature verification, and provenance are O03 work in P2. Their absence is not disguised as a P1 capability.
- This package does not modify the governance Manifest, progress dashboard, or any other work package.
