# Runway

**Bifrost provider id:** `runway`
**Cynative chat-loop support:** ❌ not chat-capable

Bifrost exposes Runway for video generation. Cynative's agent loop
sends only chat-completion requests, so this provider cannot be used
through cynative today.

If a future cynative release adds a media-output capability, this guide
will gain a YAML + env-var example. For now: set `CYNATIVE_LLM_PROVIDER`
to one of the chat-capable providers listed in
[the provider index](README.md).

## Links

- Runway docs: <https://docs.dev.runwayml.com/>
- Bifrost Runway provider source: <https://github.com/maximhq/bifrost/tree/main/core/providers/runway>
