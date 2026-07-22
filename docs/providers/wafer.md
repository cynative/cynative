# Wafer

**Bifrost provider id:** `wafer`

## Quick start

```bash
export WAFER_API_KEY=wfr_...
export CYNATIVE_LLM_PROVIDER=wafer
export CYNATIVE_LLM_MODEL=GLM-5.2
cynative -p "..."
```

## YAML

```yaml
llm:
  provider: wafer
  model: GLM-5.2
  api_key: env.WAFER_API_KEY
```

Wafer serves open-weight models (GLM, Kimi, Qwen, DeepSeek, MiniMax) over an
OpenAI-compatible API at `https://pass.wafer.ai/v1` (overridable via
`network_config.base_url`); the models page below lists the current ids.

## Authentication

Get a key (format `wfr_...`) from <https://app.wafer.ai/>.

## Links

- Wafer site: <https://www.wafer.ai/>
- Wafer models: <https://app.wafer.ai/models>
- Bifrost Wafer provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/wafer>
