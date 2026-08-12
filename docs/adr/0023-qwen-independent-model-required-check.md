# ADR 0023: Use a fixed Qwen snapshot for the independent-model-review Check

- Status: Accepted
- Date: 2026-08-13
- Scope: P0–P2 synthetic-data preproduction Required Check

## Context

ADR 0022 activated a provider-neutral model-only review policy for P0–P2. The
first Required Check implementation requested `gpt-5.6-terra` through
`openai/codex-action`, but the OpenAI API billing prerequisite is not currently
available. The Product Owner permits a paid domestic-model API while preserving
the same model-only, preproduction-only conclusion and failure boundary.

Alibaba Cloud Model Studio exposes an OpenAI-compatible Responses endpoint.
`qwen3.7-max-2026-05-20` is a fixed, text-only flagship snapshot with a context
window suitable for the bounded review. A fixed snapshot avoids the silent
model drift of the `qwen3.7-max` alias.

The compatible Responses endpoint processes only its documented parameters and
does not document OpenAI `text.format` or `json_schema`. The Check therefore
must not treat API-side structured-output enforcement as proven. The reviewer
is instructed to return JSON, and the existing provider-neutral output Schema
and semantic validator remain the fail-closed authority after the call.

## Decision

The `independent-model-review` workflow requests exactly:

- provider: `ALIBABA_CLOUD_MODEL_STUDIO`;
- region: `CHINA_BEIJING`;
- model: `qwen3.7-max-2026-05-20`;
- Responses endpoint:
  `https://dashscope.aliyuncs.com/compatible-mode/v1/responses`; and
- repository secret: `DASHSCOPE_API_KEY` from the general Model Studio
  pay-as-you-go service.

The workflow continues to use the pinned official `openai/codex-action` only as
the read-only invocation adapter. It does not use a Coding Plan key, create a
new model transport, or trust unvalidated model text. Missing credentials,
provider incompatibility, malformed output, Schema failure, `BLOCKED`,
`INCONCLUSIVE`, or any OPEN HIGH/CRITICAL finding fails the Check.

An external run is not accepted as positive governance evidence until the
exact-head workflow succeeds and its Check identity and result are read back.
An unsuccessful compatibility run is only a failed control and cannot be
reported as model review CLEAR.

## Governance boundary

This decision changes only the requested provider configuration for the P0–P2
Required Check. It does not alter the active Policy, frozen Review Evidence,
historical Terra/Kimi evidence, P1-B11, D1, a Gate, the Profile, O02/O03, P3,
production, or `humanIndependentReviewSatisfied=false`.
