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

## Credenziale del provider: API key **oppure** account/sessione (OAuth)

L'accesso al provider **non** è legato esclusivamente a una API key metered. Per
ogni provider il gateway accetta una di queste fonti (precedenza
`*_AUTH_TOKEN_FILE` > `*_AUTH_TOKEN` > `*_API_KEY`):

| Fonte | Variabili | Header verso l'upstream | Fatturazione |
| --- | --- | --- | --- |
| API key | `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | Anthropic: `x-api-key`; OpenAI: `Authorization: Bearer` | credito API a token |
| Token account/sessione (OAuth) | `*_AUTH_TOKEN` | `Authorization: Bearer` (mai `x-api-key`) | abbonamento dell'account |
| Token da file rotante | `*_AUTH_TOKEN_FILE` | come sopra, riletto a ogni richiesta | abbonamento dell'account |

- **Configurazione.** Ottieni il token di sessione dal login ufficiale del
  provider e passalo via `*_AUTH_TOKEN` o, meglio, scrivilo in un file indicato
  da `*_AUTH_TOKEN_FILE`. Per Anthropic imposta anche l'header beta richiesto dal
  flusso OAuth con `ANTHROPIC_AUTH_BETA` (unito a quello del client, es. prompt
  caching). Il device token del client resta invariato: la sostituzione della
  credenziale è trasparente lato agente.
- **Rotazione / fallback.** Con `*_AUTH_TOKEN_FILE` il gateway rilegge il token
  quando cambia l'mtime del file, così un processo esterno (che rinnova la
  sessione OAuth) può aggiornarlo senza riavviare il gateway. Se nessuna
  credenziale è disponibile il gateway risponde **503** senza inoltrare. Puoi
  configurare API key su un provider e OAuth sull'altro.
- **Limiti.** Con un token di sessione valgono i limiti/quote dell'account (non
  quelli dell'API a consumo) e i termini d'uso del provider per quel canale. Il
  gateway non implementa il flusso OAuth interattivo né il refresh: ottenere e
  rinnovare il token è responsabilità dell'operatore (statico, o scritto nel file
  da uno script/servizio esterno).
- **Verificato dal vivo (importante).** Il gateway inoltra correttamente un token
  OAuth come `Authorization: Bearer` (mai `x-api-key`), ma **Anthropic rifiuta con
  `401 "OAuth access token is invalid"` un token di abbonamento** (generato con
  `claude setup-token`) presentato da un gateway di terze parti: quel token è
  **vincolato al client ufficiale** e non è onorato su `/v1/messages` da terzi.
  Di conseguenza, la modalità OAuth **non** permette oggi di usare l'abbonamento
  Anthropic al posto dei crediti API. È utile invece verso provider/gateway che
  accettano esplicitamente un bearer OAuth (es. gateway aziendali/self-hosted, o
  provider OpenAI-compatibili che emettono token di sessione). OpenAI non offre
  alcun percorso OAuth per l'API. In pratica: per Anthropic e OpenAI resta
  necessaria una **API key**; la modalità OAuth è per canali che la supportano.

Vedi la [guida operativa](../../docs/guida-operativa.md#3-gateway-llm) per
la configurazione completa.
