# Esempi

## `mock-agent` — enforcement end-to-end senza PI

Dimostra che il motore di enforcement (`@harness/enforcement-core`) è
**agent-agnostic**: un "coding agent" finto viene arruolato in un control plane
reale, scarica la policy firmata e ogni sua azione passa dallo stesso motore che
userebbe PI. Qui PI non esiste — è solo un altro `AgentAdapter`.

```bash
npm run example:mock-agent
```

Cosa fa lo script (`mock-agent/run.mjs`):

1. avvia un control plane in-process (data dir temporanea);
2. arruola un device via l'endpoint HTTP `/api/enroll`, come farebbe l'agent-client;
3. `FleetState` scarica e verifica il **bundle firmato** dal control plane;
4. `attachEnforcement` aggancia il motore all'adapter mock;
5. l'agente finto emette una sequenza di azioni (tool call, comandi shell,
   un risultato con un segreto) e vediamo le decisioni: **allow / deny /
   redaction**;
6. l'audit prodotto viene letto dal control plane.

Output atteso (estratto):

```
▶ Sequenza di azioni dell'agente:

  ✓ allow  read src/app.ts
  ✗ deny   read /etc/passwd (fuori workspace)
  ✗ deny   bash: rm -rf /
  ✓ allow  shell utente: ls -la | sort
  ✗ deny   shell utente: node -e (eval inline)

  ✎ redaction  .env → "TOKEN=«REDATTO:github-token» fine"
```

Per aggiungere il supporto a un altro coding agent basta scrivere un nuovo
adapter che implementa `AgentAdapter` (come fa `@harness/fleet-extension` per
PI): il motore non cambia.

## `native-agent` — demo LIVE dell'agente nativo end-to-end

Dimostra l'agente **nativo** di Harness (`@harness/agent-core`) contro il
**gateway reale** (`@harness/llm-gateway`), su HTTP vero. Nessun mock del nostro
codice: si simulano solo l'upstream del provider e l'introspezione del control
plane.

```bash
npm run example:native-agent
```

Catena esercitata:

```
Agent → LlmClient → HTTP → GATEWAY REALE
                              → introspezione del device token (CP finto)
                              → upstream provider finto (con API key iniettata)
```

Cosa dimostra lo script (`native-agent/run.mjs`), con asserzioni (è anche un
gate CI):

1. l'agente guida un compito multi-step su file veri (`read_file` → `edit_file`
   → `bash`);
2. l'enforcement **blocca `rm -rf /` prima dell'esecuzione**;
3. la **redaction** nasconde un segreto letto da `.env`;
4. la **delega a un sotto-agente** (`task`) sotto lo stesso enforcement, con
   attività annidata indentata;
5. le **credenziali del provider non lasciano mai il gateway**: l'upstream vede
   la API key iniettata, non il device token (che viene introspezionato).
