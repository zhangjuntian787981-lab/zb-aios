# ADR 0019: Kimi K3 Chat response sensitive-material contract

- Status: Candidate
- Date: 2026-08-02
- Supersedes for future K3 calls: ADR 0018 runtime candidate
- Historical effect: none

## Context

The V6 Kimi K3 call returned HTTP 200, but the trusted runtime classified its
64,674-byte decoded response as `KIMI_K3_RESPONSE_CREDENTIAL_ECHOED` before
provider and canonical Schema validation. The response body was intentionally
not persisted, so its exact triggering text is not recoverable. Neither an
actual credential echo nor a false positive is proved by that attempt; its
result remains `INCONCLUSIVE` and no Receipt exists.

The V6 scanner treated ordinary security-review vocabulary and actual secret
values as the same condition. That behavior was fail closed, but it could not
produce a useful independent review result when a model discussed credential
handling as part of its review.

## Decision

Future formal K3 reviews use the additive V7 contract:

1. The transport layer checks the active credential and its deterministic
   Base64, Base64URL, hexadecimal and bounded Unicode representations exactly.
2. Token Estimate retains the historical strict response scanner.
3. Chat responses are parsed and validated in this order: provider protocol,
   provider MFJS Schema, canonical output Schema, canonical semantics, then
   high-confidence sensitive-material classification.
4. Security vocabulary, reserved example addresses and explicit redaction
   placeholders are not credentials.
5. A matching active credential remains
   `KIMI_K3_RESPONSE_CREDENTIAL_ECHOED`.
6. Other high-confidence values use
   `KIMI_K3_RESPONSE_SENSITIVE_MATERIAL_DETECTED`.
7. A response containing such a value is never persisted. Diagnostic v4 keeps
   only bounded metadata, byte length, SHA-256 and the actual validation
   progress established while the bytes were held in memory.
8. Runtime Manifest v5 and Receipt v9 bind the exact V7 runtime bytes. A
   Receipt is issued only for a fully validated successful response.

## Consequences

- V6 diagnostics, Runtime Manifest v4, Receipt v8, ADR 0018 and all failed
  attempt evidence remain byte-identical historical records.
- V7 cannot fall back to V6, another model, another endpoint, retries or
  segmented review.
- A K3 CLEAR Receipt is model-only preproduction evidence. It is not a human
  review, D1 event, Gate decision, Profile Approval, work-package status change
  or O02/O03 authorization.
