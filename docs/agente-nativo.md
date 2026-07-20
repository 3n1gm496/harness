# Agente nativo (`@harness/agent-core`)

Fino a questo punto Harness era **un harness che governa un agente altrui**:
l'unico agente reale era `@harness/fleet-extension`, un adapter attorno al
coding agent di terze parti PI. `@harness/agent-core` chiude il cerchio:
Harness ha ora **un agente proprio**, LLM-driven, governato dalla stessa policy
firmata che governa qualunque altro adapter.

## Cosa contiene

- **Loop reason-act-observe** (`agent.ts`): assembla il prompt, chiama il
  modello via gateway, esegue i tool che il modello richiede e reinietta i
  risultati, iterando fino a fine turno. Anti-loop (`maxIterations`), usage
  aggregato, eventi strutturati per la UI, streaming opzionale.
- **Client LLM** (`llm.ts`): parla la Messages API **solo attraverso il
  gateway** (`@harness/llm-gateway`). Presenta il device token come
  `x-api-key`; le credenziali del provider non toccano mai il client.
  Non-streaming (deterministico) e streaming SSE.
- **Runtime di tool nativi** (`tools/`): `read_file`, `write_file`,
  `edit_file`, `list_dir`, `grep`, `glob`, `bash`. In-process, zero dipendenze
  esterne (grep/glob in Node puro; bash con kill del process-group su
  timeout/abort e cap sull'output).
- **Gestione del contesto** (`context.ts`): stima dei token e compaction del
  prefisso più vecchio in una sintesi generata dal modello, con taglio a un
  turno utente "pulito" — non spezza mai una coppia `tool_use`/`tool_result`.
- **Adapter di enforcement** (`adapter.ts`): implementa il contratto neutro
  `AgentAdapter` di `@harness/enforcement-core` lato host. È lo specchio del
  `PiAdapter`, ma qui agente e host coincidono.

## Come la governance resta identica

Ogni `tool_use` del modello attraversa, **in quest'ordine**:

1. **Gate di enforcement** (`gateToolCall`): kill switch, sandbox obbligatoria,
   allowlist/denylist dei tool, policy bash (per il tool `bash`), policy dei
   percorsi. Una call negata **non viene eseguita**: al modello torna un
   `tool_result` d'errore con la motivazione, così può correggersi.
2. **Esecuzione** del tool nativo.
3. **Redaction** del risultato (`rewriteResult`): i segreti vengono redatti
   prima di tornare al modello.

L'audit è prodotto dagli stessi handler del motore (`policy_decision`,
`tool_result`, `user_bash`, …) e spedito al control plane. In breve: **stessa
policy firmata, stesso audit, stesso fail-closed** di PI — ma l'agente è nostro.

## Uso

```sh
# elenca i tool nativi
harness-agent-native tools

# esecuzione singola (one-shot)
HARNESS_GATEWAY_URL=https://gateway.interno harness-agent-native \
  --model claude-sonnet-5 -p "Aggiungi un test per parseBashCommand"

# sessione interattiva
HARNESS_GATEWAY_URL=https://gateway.interno harness-agent-native
```

Il device dev'essere arruolato (`harness-agent enroll …`): l'agente carica la
configurazione firmata, avvia i loop di sync/flush dell'audit e — se la policy
lo richiede — rifiuta di partire fuori dall'ambiente contenuto sanzionato
(stessa barriera sandbox di `harness-agent run`).

Config via flag o ambiente:

| Flag | Ambiente | Default |
| --- | --- | --- |
| `--gateway <url>` | `HARNESS_GATEWAY_URL` | — (obbligatorio) |
| `--model <id>` | `HARNESS_MODEL` | `claude-sonnet-5` |
| `--cwd <dir>` | — | directory corrente |

## Multi-provider

L'agente lavora sempre sui tipi neutri; un `WireProvider` traduce da/verso il
formato del provider. Sono supportati **Anthropic** (Messages,
`/anthropic/v1/messages`) e **OpenAI** (Chat Completions,
`/openai/v1/chat/completions`, con traduzione di `tool_calls`/ruolo `tool`).
Si sceglie con `provider` nel client (`--` la CLI usa Anthropic di default).
Aggiungere un terzo provider = implementare l'interfaccia, senza toccare il loop.

## Sub-agenti (tool `task`)

Con `subAgents` abilitato (la CLI lo attiva), l'agente espone il tool `task`:
delega un sotto-compito a un **agente figlio** con contesto isolato ma lo
**stesso** motore di enforcement (stessa policy, stesso audit, stesso
fail-closed). Il padre riceve solo il risultato finale. La profondità di
annidamento è limitata (`maxDepth`, default 2) per evitare ricorsione.

## Conteggio dei token

La decisione di compaction usa il conteggio **esatto** del provider
(`count_tokens`, Anthropic) quando disponibile; la chiamata avviene solo quando
la stima euristica (~4 caratteri/token) si avvicina al budget (80%), per non
aggiungere un round-trip a ogni turno. Un provider senza `count_tokens`
(OpenAI) ricade in modo trasparente sulla stima.

## Prompt caching

Con `promptCache` attivo (la CLI lo abilita) il client marca il **prefisso
stabile** della richiesta — system + ultimo tool — con `cache_control: ephemeral`
e invia l'header beta. Poiché ogni turno del loop condivide lo stesso system e
gli stessi tool, i loro token di input vengono **riusati** invece che
rifatturati. OpenAI (cache automatica) ignora l'hint in modo trasparente.

## Demo live

`npm run example:native-agent` avvia l'agente nativo contro il **gateway reale**
(`@harness/llm-gateway`) su HTTP vero, con upstream del provider e introspezione
del control plane simulati. La demo (che è anche un gate CI, con asserzioni)
mostra: compito multi-step su file veri, `rm -rf /` bloccato dall'enforcement,
segreto `.env` redatto, delega a un sotto-agente, e la prova che le **credenziali
del provider non lasciano mai il gateway** (l'upstream vede la API key iniettata,
non il device token). Vedi `examples/README.md`.

### Smoke contro un provider reale

`npm run smoke:live-provider` esegue lo stesso stack (control plane + gateway
reale + agente) ma contro l'**API vera** del provider, per validare streaming,
tool-use, `count_tokens` e l'autenticazione end-to-end (API key **o** OAuth).
Consuma una piccola quantità di token. Config via ambiente:

```bash
# Anthropic con API key:
ANTHROPIC_API_KEY=sk-ant-... npm run smoke:live-provider
# Anthropic con token di account/sessione (OAuth):
ANTHROPIC_AUTH_TOKEN=... ANTHROPIC_AUTH_BETA=oauth-2025-04-20 npm run smoke:live-provider
# OpenAI:
HARNESS_LIVE_PROVIDER=openai OPENAI_API_KEY=sk-... npm run smoke:live-provider
```

Variabili: `HARNESS_LIVE_PROVIDER` (anthropic|openai), `HARNESS_LIVE_MODEL`
(default `claude-haiku-4-5-20251001` / `gpt-4o-mini`).
