# `@harness/enforcement-core`

Motore di enforcement **agent-agnostic**: applica policy (allow/deny sui
tool, allowlist bash argv-aware, filesystem limitato alla workspace),
redaction dei segreti, sandbox obbligatoria e audit tamper-evident a
qualunque coding agent, senza conoscerne l'API nativa. Il motore parla solo
con un contratto neutro, [`AgentAdapter`](src/adapter.ts): integrare un
nuovo agente significa scrivere un adapter che lo traduce, senza toccare una
riga del motore.

Zero dipendenze runtime esterne: solo i built-in di Node e `@harness/shared`.

## Perché un adapter

Il motore non sa cosa sia PI, Claude Code, o qualunque altro agente. Sa solo
che, a un certo punto della sessione, qualcuno gli dirà "sta per succedere
una tool call", "sta per partire un comando shell", "la sessione è finita" —
e lui risponderà con una decisione (`allow`/`deny`) o una riscrittura del
risultato. L'adapter è il pezzo di codice specifico dell'agente che:

1. ascolta gli eventi nativi dell'agente (nel formato che l'agente espone);
2. li traduce nei tipi neutri del motore (`ToolCall`, `ToolResult`,
   `ShellCommand`, `HostSession`, …);
3. registra gli handler del motore (`adapter.onToolCall`, ecc. — è l'adapter
   che *implementa* l'interfaccia `AgentAdapter`, il motore la *chiama*);
4. applica la decisione del motore nel modo che l'agente nativo si aspetta
   (bloccare la tool call, sostituire l'output, …).

`@harness/fleet-extension` è l'adapter per PI — vale la pena leggerlo
(`packages/fleet-extension/src/pi-adapter.ts`) come riferimento reale, oltre
all'esempio sotto.

## Il contratto: `AgentAdapter`

```ts
export interface AgentAdapter {
	onSessionStart(handler: (session: HostSession) => void | Promise<void>): void;
	onToolCall(handler: (call: ToolCall, session: HostSession) => Gate | Promise<Gate>): void;
	onToolResult(handler: (result: ToolResult, session: HostSession) => ResultRewrite | Promise<ResultRewrite>): void;
	onShellCommand(handler: (command: ShellCommand, session: HostSession) => Gate | Promise<Gate>): void;
	onSessionEnd(handler: () => void | Promise<void>): void;
}
```

Il motore **chiama** questi cinque metodi una volta ciascuno (con
`attachEnforcement`/`bootstrapEnforcement`, sotto) per registrare i propri
handler. L'adapter implementa l'interfaccia e **invoca** l'handler
registrato ogni volta che l'evento corrispondente accade nell'agente nativo,
poi usa il valore ritornato:

- `Gate = { allow: true } | { allow: false; reason: string }` — se
  `allow: false`, l'adapter deve impedire l'esecuzione (della tool call o del
  comando shell) e mostrare/propagare `reason` così com'è: è già il messaggio
  pronto per l'utente.
- `ResultRewrite = { content: OutputBlock[] } | undefined` — se presente,
  l'adapter sostituisce il contenuto del risultato del tool con quello
  fornito (tipicamente dopo redaction di segreti); se `undefined`, nessuna
  modifica.

Tutti gli handler possono essere `async`: attendili prima di lasciare che
l'agente prosegua — sono barriere sincrone dal punto di vista dell'agente,
anche se l'implementazione è asincrona.

## Scrivere un adapter, passo per passo

1. **Implementa `AgentAdapter`.** Nella forma più semplice, ogni `on*` salva
   l'handler in un campo privato:

   ```ts
   class MyAgentAdapter implements AgentAdapter {
   	#toolCall?: (call: ToolCall, session: HostSession) => Gate | Promise<Gate>;
   	onToolCall(handler) { this.#toolCall = handler; }
   	// … idem per onSessionStart, onToolResult, onShellCommand, onSessionEnd
   }
   ```

2. **Aggancia gli eventi nativi dell'agente** ai punti in cui l'handler
   registrato va invocato. Nell'adapter PI, questo significa iscriversi alla
   Extension API di PI (`pi.on(...)`); per un agente diverso, sarà qualunque
   meccanismo di hook/plugin quell'agente esponga.

3. **Traduci i tipi.** L'agente nativo avrà la sua rappresentazione di "tool
   call" o "comando shell": mappala sui tipi neutri (`ToolCall`,
   `ShellCommand`, …) prima di invocare l'handler, e il risultato (`Gate`,
   `ResultRewrite`) va tradotto indietro nel formato che l'agente nativo si
   aspetta per bloccare/riscrivere.

4. **Collega il motore con `attachEnforcement` o `bootstrapEnforcement`:**

   ```ts
   import { attachEnforcement, bootstrapEnforcement } from "@harness/enforcement-core";

   // Se hai già uno FleetState (config caricata, es. in un test):
   attachEnforcement(adapter, state);

   // Nel percorso reale (produzione): carica l'identità del device da
   // ~/.harness/agent.json (o HARNESS_AGENT_CONFIG), scarica/verifica il
   // bundle firmato, aggancia il motore, avvia i loop di sync/flush audit.
   // Se il device non è arruolato, registra invece handler fail-closed
   // (blocco totale) senza lanciare: l'agente parte ma resta inibito finché
   // non arruolato.
   await bootstrapEnforcement(adapter);
   ```

5. **Verifica con l'esempio.** [`examples/mock-agent/run.mjs`](../../examples/mock-agent/run.mjs)
   è un adapter minimo per un agente finto (non PI): arruola un device reale
   su un control plane in-process, scarica la policy firmata, aggancia il
   motore ed emette una sequenza di azioni (tool call consentite/negate,
   comando shell pericoloso, redaction di un segreto). Eseguilo con
   `npm run example:mock-agent` dalla radice del repo — se funziona lì,
   il tuo adapter è sulla buona strada.

## Cosa il motore fa per te

Una volta agganciato, il motore (non l'adapter) si occupa di: risolvere la
policy effettiva (org → gruppo → device), verificare il kill switch a ogni
livello, valutare i comandi bash con un tokenizzatore argv-aware (blocca
eval inline, redirezioni pericolose, ecc.), limitare il filesystem alla
workspace (via `realpath`, symlink inclusi), applicare la redaction dei
segreti sui risultati dei tool, imporre la sandbox obbligatoria (se
richiesta dalla policy e il marker non è presente, ogni tool call è negata),
e tracciare ogni decisione nell'audit (in batch, verso il control plane).
L'adapter non implementa nessuna di queste politiche: le riceve già decise.

## Vedi anche

- [`docs/threat-model.md`](../../docs/threat-model.md) — cosa il motore
  garantisce e cosa no (la sandbox è il vero confine, non la policy sui tool).
- [`packages/fleet-extension`](../fleet-extension) — l'adapter PI, come
  riferimento completo per un'integrazione reale.
- [Guida operativa](../../docs/guida-operativa.md) — comportamento a runtime
  lato client (sync, fail-closed, kill switch).
