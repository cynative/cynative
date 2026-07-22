# LLM provider guides

Cynative talks to LLMs through the embedded [Bifrost](https://github.com/maximhq/bifrost) SDK and supports Bifrost's chat-capable providers, listed below. Pick the one you want to use and follow its guide for the env vars and YAML shape.

> The "Bifrost … provider source" links in these guides point to Bifrost's `main` branch; Cynative embeds the exact version pinned in [`go.mod`](../../go.mod) (`github.com/maximhq/bifrost/core`), so check there if you need the precise version a field or behavior shipped in.

## Quick start (the 30-second path)

```bash
export CYNATIVE_LLM_PROVIDER=openai           # provider id from the table below
export CYNATIVE_LLM_MODEL=gpt-5               # model id
export OPENAI_API_KEY=sk-...                  # canonical env var (provider-specific; see table)
cynative -p "..."
```

No `~/.cynative/config.yaml` is needed for the simple path. Write YAML only when you need fields the env-var surface doesn't cover.

## Provider catalog

| Provider id    | Canonical env var                  | Guide |
|----------------|------------------------------------|-------|
| `openai`       | `OPENAI_API_KEY`                   | [openai.md](openai.md) |
| `anthropic`    | `ANTHROPIC_API_KEY`                | [anthropic.md](anthropic.md) |
| `azure`        | `AZURE_OPENAI_API_KEY`             | [azure.md](azure.md) |
| `bedrock`      | (AWS credential chain)             | [bedrock.md](bedrock.md) |
| `bedrock_mantle` | (AWS credential chain or `api_key`) | [bedrock_mantle.md](bedrock_mantle.md) |
| `vertex`       | (none — needs project_id + region) | [vertex.md](vertex.md) |
| `gemini`       | `GEMINI_API_KEY`                   | [gemini.md](gemini.md) |
| `cohere`       | `COHERE_API_KEY`                   | [cohere.md](cohere.md) |
| `mistral`      | `MISTRAL_API_KEY`                  | [mistral.md](mistral.md) |
| `groq`         | `GROQ_API_KEY`                     | [groq.md](groq.md) |
| `perplexity`   | `PERPLEXITY_API_KEY`               | [perplexity.md](perplexity.md) |
| `cerebras`     | `CEREBRAS_API_KEY`                 | [cerebras.md](cerebras.md) |
| `openrouter`   | `OPENROUTER_API_KEY`               | [openrouter.md](openrouter.md) |
| `xai`          | `XAI_API_KEY`                      | [xai.md](xai.md) |
| `huggingface`  | `HUGGINGFACE_API_KEY`              | [huggingface.md](huggingface.md) |
| `nebius`       | `NEBIUS_API_KEY`                   | [nebius.md](nebius.md) |
| `parasail`     | `PARASAIL_API_KEY`                 | [parasail.md](parasail.md) |
| `fireworks`    | `FIREWORKS_API_KEY`                | [fireworks.md](fireworks.md) |
| `replicate`    | `REPLICATE_API_TOKEN`              | [replicate.md](replicate.md) |
| `deepseek`     | `DEEPSEEK_API_KEY`                 | [deepseek.md](deepseek.md) |
| `sarvam`       | `SARVAM_API_KEY`                   | [sarvam.md](sarvam.md) |
| `wafer`        | `WAFER_API_KEY`                    | [wafer.md](wafer.md) |
| `opencode-go`  | `OPENCODE_API_KEY`                 | [opencode-go.md](opencode-go.md) |
| `opencode-zen` | `OPENCODE_API_KEY`                 | [opencode-zen.md](opencode-zen.md) |
| `ollama`       | (none — local endpoint)            | [ollama.md](ollama.md) |
| `vllm`         | (none — local endpoint)            | [vllm.md](vllm.md) |
| `sgl`          | (none — local endpoint)            | [sgl.md](sgl.md) |

## Shared YAML reference

Every guide uses the same flat `llm:` schema:

```yaml
llm:
  provider: <provider-id>          # required
  model: <model-id>                # required
  api_key: env.YOUR_KEY            # optional; falls back to the canonical env var
  reasoning_effort: high           # optional; none | minimal | low | medium | high
  reasoning_max_tokens: 2048       # optional; reasoning/thinking token budget
  network_config:                  # any field on schemas.NetworkConfig
    base_url: https://...                          # optional
    default_request_timeout_in_seconds: 60         # optional; integer seconds
    max_retries: 3                                 # optional; default 3 (0 disables retries)
    extra_headers:                                 # optional
      x-custom: value
    insecure_skip_verify: false                    # optional
  openai_config: {...}             # top-level squashed provider config
  azure: {...}                     # per-provider key config alias (azure/vertex/bedrock/bedrock_mantle/vllm/ollama/sgl/replicate)
  keys: [...]                      # advanced: multi-key load balancing
```

Reasoning keys are optional and provider-portable: providers without reasoning support ignore them, though a model that doesn't support reasoning may still reject the parameter upstream on providers that forward it for every model (e.g. OpenAI-style APIs). `reasoning_effort` maps to the provider's native effort knob (coerced to the nearest supported level where needed); `reasoning_max_tokens` sets an explicit thinking budget (Anthropic-style providers use it directly; OpenAI-style providers convert it to an estimated effort). Gemini additionally validates an explicit budget against a per-model range at request time. Setting `reasoning_effort: none` together with `reasoning_max_tokens` is rejected at config validation.

### Environment variables

Every **config field** is settable via a `CYNATIVE_*` env var; **maps and slices need YAML**. In practice that means a YAML file is required only for map/slice fields — e.g. `network_config.extra_headers` (map), `keys[]` (slice), and `keys[].aliases` (map) — plus a handful of other Bifrost map/slice fields (e.g. `network_config.beta_header_overrides`). Everything else, including all identity selectors, is env-bindable.

Selectors and common aliases:

- `CYNATIVE_LLM_PROVIDER`, `CYNATIVE_LLM_MODEL` (both required)
- `CYNATIVE_LLM_API_KEY` (or the provider's canonical var, e.g. `OPENAI_API_KEY`)
- `CYNATIVE_LLM_NETWORK_CONFIG_BASE_URL`, `CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS` (integer seconds), `CYNATIVE_LLM_NETWORK_CONFIG_MAX_RETRIES`, `CYNATIVE_LLM_NETWORK_CONFIG_INSECURE_SKIP_VERIFY` (`extra_headers` is a map — set it in YAML, it has no env form)
- `CYNATIVE_LLM_REASONING_EFFORT` (`none|minimal|low|medium|high`), `CYNATIVE_LLM_REASONING_MAX_TOKENS`

Provider-specific (nested) identity fields:

- **Azure:** `CYNATIVE_LLM_AZURE_ENDPOINT`
- **Vertex:** `CYNATIVE_LLM_VERTEX_PROJECT_ID`, `CYNATIVE_LLM_VERTEX_REGION`
- **Bedrock:** `CYNATIVE_LLM_BEDROCK_REGION`
- **Bedrock Mantle:** `CYNATIVE_LLM_BEDROCK_MANTLE_REGION`
- **vLLM / SGL:** `CYNATIVE_LLM_VLLM_URL`, `CYNATIVE_LLM_VLLM_MODEL_NAME`, `CYNATIVE_LLM_SGL_URL`

Any nested Bifrost field is reachable by upper-snake-casing its JSON path: `CYNATIVE_LLM_<PATH>` (e.g. `CYNATIVE_LLM_NETWORK_CONFIG_MAX_CONNS_PER_HOST`, `CYNATIVE_LLM_OPENAI_CONFIG_DISABLE_STORE`).

## Prompt caching

cynative always marks the stable prefix of every request with ephemeral cache
breakpoints — the tool schemas, the system prompt, and the last two conversation
turns. **Anthropic-family providers** (anthropic, bedrock, vertex) cache that
prefix and bill cached reads at a large discount. Every other provider's Bifrost
converter strips or ignores the markers, and the ones that auto-cache server-side
(OpenAI, Gemini) keep doing so regardless. There is **no
configuration** — it is on for all providers and inert where unsupported.

The cache window is Anthropic's default five-minute ephemeral TTL, so back-to-back
calls (e.g. `--auto-approve` runs) benefit most; long human-approval pauses
between tool calls may let the cache expire and re-pay the write.

## Troubleshooting

**Request timeouts.** Non-streaming LLM calls default to a **300s** per-request
timeout — cynative's default, replacing Bifrost's 30s, which is too short for the
long, reasoning-heavy completions a research run makes. Override it with
`llm.network_config.default_request_timeout_in_seconds` (an integer number of
seconds, e.g. `60`) or the env var
`CYNATIVE_LLM_NETWORK_CONFIG_DEFAULT_REQUEST_TIMEOUT_IN_SECONDS`. On a timeout the
underlying error comes from Bifrost and mentions
`default_request_timeout_in_seconds`, `network_config`, and a "Providers >
Provider Name > Network Config" UI — that wording is Bifrost's (it even hard-codes
"30 seconds" regardless of the effective timeout); cynative has no such UI, and
the knob you want is `network_config.default_request_timeout_in_seconds` above.

**Rate limits and transient errors.** LLM calls retry retryable failures (HTTP
429/500/502/503/504, provider errors recognized as rate limits, and network
errors) up to **3** times with exponential backoff (500ms initial, 5s max):
cynative's default, replacing Bifrost's 0 retries, under which a single
rate-limit blip fails the whole turn (and a `-p` run outright). Request
timeouts are not retried. Override the count with
`llm.network_config.max_retries` (an integer; `0` disables retries, negative
is rejected) or the env var `CYNATIVE_LLM_NETWORK_CONFIG_MAX_RETRIES`, and
tune the backoff with `network_config.retry_backoff_initial` /
`retry_backoff_max` (durations, e.g. `500ms`). A run that still ends with
"rate limited / out of quota (HTTP 429)" exhausted its retries: check the
provider account's quota and billing, or retry later.
