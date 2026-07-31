# Moonshot Kimi K3 transport contract v3 research

- Query date: 2026-08-01
- Authority boundary: Moonshot/Kimi official API documentation and official API platform homepage only.
- Candidate use: preproduction, read-only independent-model review; no governance authority.

## Fixed findings

| Contract fact | Official source | Frozen interpretation |
| --- | --- | --- |
| Model ID and context | https://platform.kimi.ai/docs/models | `kimi-k3`; official model list describes a 1M-token context window. The local contract uses the exact fixed value `1048576` tokens and still requires an official Token Estimate before a call. |
| Chat endpoint and K3 parameters | https://platform.kimi.ai/docs/api/chat | `POST https://api.moonshot.ai/v1/chat/completions`; K3 always reasons; top-level `reasoning_effort=max`; `tool_choice=none`; no `thinking` field; `max_completion_tokens=32768`. |
| Token Estimate | https://platform.kimi.ai/docs/api/estimate | `POST https://api.moonshot.ai/v1/tokenizers/estimate-token-count`; exact `model` and `messages` are estimated. Non-message model-visible input is therefore bound separately and covered by a fixed conservative reserve. |
| Structured Output | https://platform.kimi.ai/docs/guide/response_format | `response_format.type=json_schema`, `json_schema.strict=true`; K3 is documented as supporting Structured Output. Local Schema and semantic validation remain mandatory. |
| Price | https://platform.kimi.ai/ | K3 cache hit input USD 0.30/MTok, cache-miss input USD 3.00/MTok, output USD 15.00/MTok. The budget calculation uses cache-miss input and maximum output. |

## Failure-closed interpretation

Bytes are transport resource ceilings, not Token estimates. The official Token
Estimate covers the exact formal `messages`. Every other model-visible request
field is canonicalized and hash-bound, limited to 16,384 UTF-8 bytes, and
covered by an unadjustable 65,536-token reserve. Admission requires:

`estimatedMessageInputTokens + 65536 + 32768 + 8192 <= 1048576`

No estimate, mismatch, over-budget result, non-`kimi-k3` response, non-`stop`
finish reason, schema failure, semantic failure, fallback, segmentation, or
retry may produce a review Receipt.
