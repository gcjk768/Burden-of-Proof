# Feedback on Nebius Token Factory, NVIDIA Nemotron and Nebius AI Cloud

Notes collected while building Burden of Proof, for the hackathon feedback submission. Each item says
whether we saw it first-hand or learned it from documentation and other builders.

Status on 2 Oct 2026: no live inference call has been made yet. The build environment's network
policy blocks the Token Factory hosts, and live smoke tests (`bop doctor --live`) are scheduled for
the first session with a key.

## What worked well

- **The public model catalog** (`/api/public/models_info`) needs no key and lists model IDs, status,
  context length and prices per flavor. It let us validate model IDs and price the budget before the
  first call. *(Documentation and third-party dumps; first-hand check pending.)*
- **OpenAI compatibility** means the official OpenAI Python SDK works unchanged, including `extra_body`
  for Nemotron's `chat_template_kwargs`. *(Confirmed against the SDK; endpoint check pending.)*
- **Sandboxes share the inference key and host.** `contree-sdk` reads `NEBIUS_API_KEY` and
  `NEBIUS_PROJECT_ID` and defaults to `https://api.tokenfactory.nebius.com/sandboxes`, so one key covers
  both inference and code execution. *(First-hand, from the package source.)*
- **`contree-client` ships an in-memory test double** (`contree_client.testing`), which makes the
  sandbox runner testable without network access. *(First-hand.)*

## What was frustrating or unclear

- **Model ID casing is inconsistent in Nebius's own cookbook.** The Nemotron 3 Nano quickstart uses
  `nvidia/nvidia-nemotron-3-nano-30b-a3b`, but the catalog ID is `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`,
  and IDs are case-sensitive. *(Documentation.)*
- **Thinking is on by default and eats the output budget.** Hidden reasoning tokens count against
  `max_tokens`, so structured replies are silently truncated unless thinking is switched off. Other
  builders measured 8 percent valid JSON from Lightning with thinking on. A prominent note on the
  structured-output page, or thinking off by default whenever `response_format` is set, would save
  every team the same debugging. *(Reported by other builders; to be measured first-hand.)*
- **Two switches for "thinking off".** Other builders report that `chat_template_kwargs.enable_thinking`
  alone has not always produced zero reasoning tokens, and that adding `reasoning_effort: "none"` did.
  One documented, enforced switch, and a `reasoning_tokens` count that is always present in `usage`,
  would make this verifiable. We send both and log any thinking-off call that still reasons.
  *(Reported by other builders; to be measured first-hand.)*
- **The reasoning field moves.** One builder saw reasoning in `reasoning_content` on 18 Sep and inside
  `content` on 27 Sep 2026 for the same model. We read both. *(Reported by other builders.)*
- **The catalog does not advertise JSON mode for Nemotron**, although `json_schema` works with thinking
  off. *(Third-party.)*
- **Regional hosts are easy to get wrong.** Super and Ultra examples use the us-central1 host, and one
  builder reports that calling Ultra on the wrong host returns a 404 that reads like a bad model name.
  A clearer error ("model served in another region") would help. *(Third-party.)*
- **Only the low-level Sandboxes client can turn the network off.** `contree-sdk`'s high-level `run()`
  has no networking option; we use `contree-client` for that one switch. *(First-hand.)*
- **Serverless AI jobs do not report exit codes** and the minimum timeout differs between the CLI
  reference (1 hour) and the quickstart (15 minutes). *(Documentation.)*
- **Ultra availability.** The catalog listed Nemotron 3 Ultra with status "error" on 12 and 14 Sep 2026.
  We built an automatic fallback to Super because of it. *(Third-party catalog snapshots.)*

## NVIDIA Nemotron

- Lightning at the same price as Nano with four times the context is a clear upgrade for high-volume
  triage. *(Catalog.)*
- The Qwen3-Coder tool-call format can leak into plain text when a server does not parse it; we added
  a parser for `<tool_call><function=...>` blocks. *(Model cards and vLLM issues.)*
