# ADR 0018: Extended bounded Kimi K3 Chat deadline

## Status

Candidate. This append-only decision applies only to future K3 V6 review
attempts. It does not reinterpret ADR 0017, V5 attempts, or historical
diagnostic evidence.

## Context

The first V5 formal request completed Token Estimate and then made exactly one
Kimi K3 Chat request. No HTTP response arrived before the authoritative
600,000 ms application deadline, so the attempt correctly ended with
`KIMI_K3_TRANSPORT_TIMEOUT` and no Review Receipt. The exact 600-second stop
proves the local deadline was reached; it does not prove whether the provider
would later have returned a valid response.

The frozen request used 412,408 estimated input tokens with
`reasoning_effort=max`. A longer but finite deadline is therefore required to
distinguish the local deadline from a provider failure without changing the
model, material, endpoint, response limit, context proof, budget, or one-shot
policy.

## Decision

K3 V6 keeps Token Estimate bounded at 120,000 ms and changes only the Chat
Completion application deadline to 1,800,000 ms. The per-request Undici Agent
uses finite `connectTimeout`, `headersTimeout`, and `bodyTimeout` values of
1,810,000 ms. The 10,000 ms guard preserves application-deadline precedence.

The transport implementation enforces separate maximums: callers cannot use
the Chat extension for Token Estimate, and values above either maximum fail
before dispatcher creation or network access. The formal composition root
passes the Chat deadline explicitly. Dispatcher cleanup remains bounded by the
remaining application deadline and cannot overwrite an already classified
HTTP, metadata, body, Schema, semantic, or timeout failure.

V6 retains one Token Estimate, at most one conditional Chat Completion, no
retry, no redirect, no fallback, no segmented review, and no alternate
endpoint. Diagnostic Evidence v3 and Transport Evidence v4 remain sufficient;
Receipt v8 binds Runtime Manifest v4 and the exact V6 runtime bytes.

## Consequences

One future formal attempt may hold a process, socket, and in-memory credential
for up to 30 minutes. External execution supervision must therefore allow the
bounded attempt to finish and persist its diagnostic result. The longer bound
does not establish model success, independent-review clearance, human review,
or any D1, Gate, Profile, work-package, or deployment authority.
