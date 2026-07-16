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

## Limiti noti / evoluzioni

- Un solo provider di wire (Anthropic Messages, via gateway). Un secondo
  provider (OpenAI) si aggiunge con un traduttore in `llm.ts`, senza toccare i
  tipi interni né il loop.
- Nessun sub-agente/delega: il loop è a singolo agente. La struttura degli
  eventi e dell'adapter è già pronta a ospitarli.
- La stima dei token per la compaction è euristica (~4 caratteri/token): con
  `count_tokens` del gateway diventerebbe esatta.
