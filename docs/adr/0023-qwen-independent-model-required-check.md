# ADR 0023: Run the model Required Check through fixed Qwen Code

- Status: Accepted
- Date: 2026-08-13
- Scope: P0–P2 synthetic-data preproduction Required Check

## Context

ADR 0022 activated a provider-neutral model-only review policy for P0–P2. The
Product Owner permits Alibaba Cloud Model Studio for the hosted
`independent-model-review` Check while retaining the same preproduction-only
conclusion and fail-closed output validation.

The official Qwen Code Action runs Qwen Code with `--yolo` and writes temporary
`.qwen` and `qwen-artifacts` files on its disposable runner. Settings are not an
OS read-root sandbox, so this decision does not claim formal read-root
confinement. The accepted assurance boundary is instead
`PLATFORM_TCB_PROMPT_BOUND_MODEL_REVIEW`: the parent workflow deterministically
assembles exact Git-object bytes into the prompt, and the reviewer has zero
executable tool calls.

## Decision

The workflow fixes:

- `QwenLM/qwen-code-action@132374a450dd882f728d117fdafc64201e81abff`
  (the official `v0.1.1` release commit);
- Qwen Code CLI `0.21.10`;
- provider `ALIBABA_CLOUD_MODEL_STUDIO` and region `CHINA_BEIJING`;
- model `qwen3.7-max-2026-05-20`;
- workspace Base URL
  `https://ws-lkkcajn7d1l4okvo.cn-beijing.maas.aliyuncs.com/compatible-mode/v1`;
- repository secret `DASHSCOPE_API_KEY` from the general Model Studio
  pay-as-you-go service; and
- `upload_artifacts=false`, debug disabled, and GitHub `contents: read` only.

The parent workflow reads only committed Git objects at the exact pull-request
head and tree. Its bounded prompt includes the Required Check implementation,
active Policy, frozen remediation Evidence, closed output Schema, Ruleset
candidate, and P1-B11 preparation boundary. Every byte is described by path,
Git mode, length, and SHA-256; the complete content section is capped at 96 KiB.
The model output must echo the exact head, tree, model, Policy digest, Evidence
digest, content digest, assurance level, and `toolCalls=0` in `reviewSummary`.

Qwen Code settings set `model.maxToolCalls=0`, disable startup context, hooks,
memory, telemetry, MCP, skills, Computer Use, Web Search, tool search, and every
known core side-effect tool. Explicit `deny` rules are evaluated before YOLO.
In Qwen Code 0.21.10 the run budget is checked before dispatch: the first tool
attempt aborts with exit 55 and the tool is not executed. This is a
zero-execution contract, not a claim that tool schemas are hidden from the
model. Action-created temporary files may exist on the disposable runner, but
they are not uploaded or committed and tracked Git bytes must remain unchanged.

The Action summary is written to a runner-temporary file and passed to the
existing provider-neutral output Schema and semantic validator; they remain the
fail-closed authority. API-side structured-output enforcement must not be treated as proven.
An authoritative terminal output contract is appended after all untrusted review material.
It requires exactly one JSON object: the first non-whitespace byte must be `{`
and the last non-whitespace byte must be `}`. Markdown code fences, explanations,
prefixes, and suffixes are forbidden. Only the closed Schema fields may appear,
and `reviewSummary` must start exactly with the material binding summary. The
first exact-head run returned a fenced JSON object and was therefore rejected;
that failed Check is not treated as a valid `CLEAR` result.
Malformed output, `BLOCKED`,
`INCONCLUSIVE`, an OPEN HIGH/CRITICAL finding, wrong Git binding, wrong model or
provider, changed Policy/Evidence bytes, changed material, a tool attempt, or
an overclaim fails the Check.

## Governance boundary

Success means only `MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION` for P0–P2 with
`humanIndependentReviewSatisfied=false` and `governanceEffect=NONE`.
It does not alter the active Policy, frozen Review Evidence, historical Terra/Kimi
evidence, P1-B11, D1, a Gate, the Profile, O02/O03, P3, production, or any
human-review fact. The model Check is not a GitHub human approval.
