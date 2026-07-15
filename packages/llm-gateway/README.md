# `@harness/llm-gateway`

Proxy verso Anthropic/OpenAI-compatibile: i client si autenticano con il
loro **device token** (verificato via introspezione sul control plane), il
gateway inietta le credenziali del provider — che così non risiedono mai sui
client. Revoca e kill switch si propagano all'inferenza entro il TTL della
cache di introspezione.

- Solo gli endpoint di inferenza sono inoltrabili (allowlist per path): il
  device token non dà accesso al resto dell'API del provider.
- Rate limit per device, timeout upstream configurabile
  (`UPSTREAM_TIMEOUT_MS`), body della richiesta inoltrato in streaming (mai
  bufferizzato per intero).
- mTLS opzionale: un device legato a un certificato deve presentarlo anche
  qui, non solo sul control plane.

```bash
CONTROL_PLANE_URL=http://localhost:8787 GATEWAY_TOKEN=gwt_... \
ANTHROPIC_API_KEY=sk-ant-... node dist/cli.js
```

Vedi la [guida operativa](../../docs/guida-operativa.md#3-gateway-llm) per
la configurazione completa.
