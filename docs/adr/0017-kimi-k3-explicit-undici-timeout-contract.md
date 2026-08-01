# ADR 0017: Explicit Undici timeout contract for Kimi K3

## Status

Candidate. This decision is append-only and applies only to future Kimi K3
independent-review attempts. It does not reinterpret or replace historical
attempt evidence.

## Context

The preceding formal attempt completed Token Estimate, then reached the Kimi K3
Chat transport exactly once but received no HTTP response after approximately
305 seconds. That duration is highly consistent with Undici's default header
timeout, but the historical evidence did not preserve the underlying transport
error code. The historical root cause therefore remains high-confidence rather
than proven.

The formal runner previously used Node's global `fetch` without a frozen client
timeout contract. Its runtime dependency manifest also did not identify the
HTTP client implementation as a critical direct dependency.

## Decision

Future Kimi K3 attempts use the repository-pinned `undici@7.24.8` package for
both `fetch` and a per-request `Agent` dispatcher. The root `package.json`, lock
entry, package bytes, entry point, complete dependency tree, and executable
runtime modules are bound by append-only Runtime Manifest v3.

The application remains the authoritative total deadline:

- Token Estimate application deadline: 120,000 ms;
- Chat Completion application deadline: 600,000 ms;
- Undici `connectTimeout`: 610,000 ms;
- Undici `headersTimeout`: 610,000 ms;
- Undici `bodyTimeout`: 610,000 ms;
- dispatcher guard above the maximum application deadline: 10,000 ms.

Thus the application abort must occur before the client connect/header/body
timeout. All three client values are finite and non-zero. Formal requests
always pass a per-request dispatcher explicitly and never read, replace,
mutate, or route traffic through Undici's global dispatcher. Package-internal
global initialization is outside this contract. There is no automatic retry,
redirect, model fallback, segmented review, or alternate endpoint.

Each request owns one dispatcher and attempts to close it exactly once within
the remaining application deadline. Response classification always completes
before dispatcher cleanup is allowed to affect the outcome. An HTTP, metadata,
body, Schema, semantic, timeout, or other already-bound failure keeps its
original classification. Only a response that would otherwise succeed becomes
`POST_RESPONSE_CLEANUP` with
`KIMI_K3_TRANSPORT_DISPATCHER_CLOSE_FAILED` when close fails or exhausts the
remaining deadline.

V5 uses append-only Token Estimate and Chat Diagnostic Evidence v3 to bind that
cleanup failure, the complete safe application-layer response bytes, their
digest, and the validation progress that had already succeeded. V4 and earlier
contracts continue to use their historical diagnostic Schema versions. A
cleanup failure never issues Token Estimate Evidence, Transport Evidence, or a
Review Receipt. The formal launcher is one-shot and exits after the diagnostic
result is persisted and read back or rejected.

Receipt v7 binds Runtime Manifest v3. Runtime Manifest v2, Receipt v6, ADR 0016,
and all prior evidence remain byte-exact historical contracts and cannot be
used as fallback for this candidate.

## Consequences

This change can only make a future independent-model review transport
deterministic and auditable. It does not grant model review clearance, human
review, D1 authority, Gate or Profile approval, work-package authorization, or
deployment authority.
