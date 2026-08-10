# ADR 0022: Activate Independent Review Policy v2 for P0–P2

- Status: Accepted
- Date: 2026-08-10
- Scope: P0–P2 synthetic-data preproduction review

## Context

ADR 0008 required a second human reviewer for protected source review. ADR 0011
recorded a candidate model-only alternative but retained scope-only human-review
exceptions and explicitly did not activate the Policy. The Product Owner has now
decided that every P0–P2 code, Schema, specification, test, and governance-artifact
scope may use independent model review while it remains synthetic-only and has no
production effect.

The completed targeted remediation review may conclude only
`MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION`. It is not a human review, GitHub human
approval, Gate Decision, Profile Approval, work-package status event, or start
authorization.

## Decision

Activate `independent-review-policy.v2` prospectively from the Git commit that
adds the active Policy artifact.

- P0, P1, and P2 require independent model review and do not require a second
  human independent reviewer.
- `humanIndependentReviewRequired` and
  `humanIndependentReviewSatisfied` remain `false`.
- Identity, authorization, Tenant isolation, D1/Gate/Profile/start-authorization
  code, sandbox/network code, Secrets, enterprise-connector code, and
  deployment/rollback/writeback code are eligible for model review only while
  they remain P0–P2 synthetic preproduction artifacts. This eligibility grants
  the model no authority to execute those capabilities.
- P3, real enterprise onboarding, real enterprise data, real credentials, real
  users, and production still require a real second human reviewer. Model review
  cannot substitute at those boundaries.
- A model result cannot create GitHub Human Approve, write D1, decide a Gate,
  approve a Profile, authorize O02/O03, merge, push, deploy, or change a Project
  Work Package.

This decision narrowly supersedes ADR 0008 and the high-risk-scope exception in
ADR 0011/ADR 0021 for P0–P2 synthetic preproduction review only. It does not
alter their historical bytes or their P3, real-data, credential, user, or
production boundaries.

## Historical and governance boundary

The activation is prospective. It does not reclassify or overwrite any event
before the activation commit. In particular,
`INCONCLUSIVE_INDEPENDENT_HUMAN_REVIEWER_MISSING` and
`INCONCLUSIVE_INDEPENDENT_REVIEWER_MISSING` remain append-only historical facts.

This ADR does not change P1-B11, D1, any Gate, the P2 Profile, the Manifest, or
any work-package status. D1 remains the only state truth for work packages,
GateSubmission, GateDecision, Profile Approval, and O02/O03 start authorization.
Git remains evidence truth only.

This ADR does not configure a GitHub Required Check or Ruleset and does not
authorize P3 or production.
