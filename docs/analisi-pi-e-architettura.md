# Analisi di PI Coding Agent e architettura dell'harness aziendale

Data analisi: 2026-07-09 — repository analizzato: [earendil-works/pi](https://github.com/earendil-works/pi) @ v0.80.3 (licenza MIT)

## 1. Cos'è PI e com'è fatto il repository

PI è un "agent harness" minimale ed estensibile, sviluppato in TypeScript come monorepo npm workspaces. I pacchetti:

| Pacchetto | Ruolo |
|---|---|
| `@earendil-works/pi-ai` | API LLM unificata multi-provider (Anthropic, OpenAI, Google, ecc. — 15+ provider), con discovery automatica dei modelli e switch a metà sessione |
| `@earendil-works/pi-agent-core` | Runtime agentico: loop di tool calling, gestione stato, transport astratto |
| `@earendil-works/pi-coding-agent` | Il coding agent vero e proprio: CLI, tool built-in (read, bash, edit, write, grep, find, ls), sessioni, estensioni, skills |
| `@earendil-works/pi-tui` | Libreria TUI con rendering differenziale |
| `@earendil-works/pi-orchestrator` | Orchestratore multi-agente (sperimentale) |

### Filosofia: "primitives over features"

PI omette deliberatamente MCP, sub-agenti, popup di permessi, plan mode e sandbox. In cambio espone primitive potenti con cui costruirli. Per il nostro caso d'uso questo è un vantaggio: non dobbiamo aggirare un sistema di permessi esistente, ne costruiamo uno nostro esattamente come serve.

### Le quattro modalità operative

1. **Interactive**: TUI per uso diretto da terminale.
2. **Print/JSON** (`-p`, `--mode json`): one-shot non interattivo.
3. **RPC** (`--mode rpc`): protocollo JSONL su stdin/stdout per embedding in altre applicazioni — comandi `prompt`, `steer`, `follow_up`, eventi streammati.
4. **SDK**: `createAgentSession()` da `@earendil-works/pi-coding-agent` — embedding in-process Node.js con controllo totale (`ResourceLoader` custom, tool filtrati, `SessionManager.inMemory()`, ecc.).

Per un client aziendale gestito, **SDK e RPC sono i punti di integrazione giusti**: permettono di costruire il nostro wrapper senza forkare PI.

### Sistema di configurazione

- Globale: `~/.pi/agent/settings.json`; progetto: `.pi/settings.json` (il progetto sovrascrive il globale, merge profondo degli oggetti).
- Copre modello/provider di default, thinking level, compaction, retry, proxy HTTP, sessioni, e soprattutto **`packages`/`extensions`/`skills`/`prompts`**: le risorse caricate all'avvio, installabili da npm o git.
- **Project trust**: le risorse locali al progetto (`.pi/`) vengono caricate solo se la directory è fidata (`trust.json`, `defaultProjectTrust`). È una guardia sul *caricamento* di configurazione, non una sandbox.

### Extension API: il gancio chiave per policy centralizzate

Le estensioni sono moduli TypeScript caricati all'avvio. Gli hook rilevanti per un sistema di controllo:

- **`tool_call`** — scatta *prima* dell'esecuzione di ogni tool; può **bloccare** (`{ block: true, reason }`) o **mutare l'input** (es. riscrivere il comando bash). È il punto di enforcement per un policy engine.
- **`tool_result`** — middleware sul risultato (redaction di segreti, truncation, audit).
- **`user_bash`** — può sostituire completamente il backend di esecuzione bash (es. redirigerlo in una sandbox/VM remota).
- **`project_trust`** — un'estensione può *possedere* la decisione di trust (es. forzare sempre "never" da policy centrale).
- `registerTool`, `registerCommand`, `registerFlag`, `pi.setActiveTools()` — per aggiungere/limitare le capacità esposte al modello.

### Postura di sicurezza dichiarata da PI

Punto critico da capire bene (da `SECURITY.md` e `docs/security.md`):

- **Nessuna sandbox integrata, by design.** PI gira con i permessi dell'utente OS che lo lancia. Il boundary di sicurezza è l'account utente: tutto ciò che è scrivibile da quell'utente (home, dotfiles, `~/.pi`, workspace) è considerato *dentro* il perimetro di fiducia.
- La prompt injection da file del repository (`AGENTS.md`, commenti, ecc.) è dichiarata **non prevenibile** e fuori scope.
- L'isolamento reale deve venire dall'OS o da container/VM. PI documenta tre pattern in `docs/containerization.md`: estensione **Gondolin** (micro-VM Linux locale in cui vengono instradati i tool built-in, mentre `pi` e le credenziali restano sull'host), **Docker** (tutto il processo in container), **OpenShell** (sandbox policy-controlled con gateway, che può tenere le API key fuori dalla sandbox iniettandole a livello di gateway di inferenza).
- **Supply chain**: molto curata — dipendenze pinnate a versione esatta, `npm-shrinkwrap.json` pubblicato, `--ignore-scripts` ovunque, `min-release-age=2`, audit CI schedulato, allowlist esplicita per i lifecycle script.
- **Telemetria/rete all'avvio**: ping di install a `https://pi.dev/api/report-install` e check versione a `https://pi.dev/api/latest-version`. Disattivabili con `PI_OFFLINE=1` / `--offline` / `PI_SKIP_VERSION_CHECK=1` — **da disattivare nei deployment aziendali**.

### Valutazione di idoneità

| Requisito | Copertura di PI | Gap da colmare |
|---|---|---|
| Base harness embeddabile | ✅ SDK + RPC + estensioni | — |
| Licenza compatibile | ✅ MIT | — |
| Config gestita centralmente | ⚠️ Solo file locali con merge globale/progetto | Control plane + distribuzione config firmata |
| Permessi/policy sui tool | ❌ Assenti by design | Policy engine come estensione (hook `tool_call`) |
| Sandbox / isolamento | ❌ Assente by design | Container/micro-VM (pattern Gondolin/Docker già documentati) |
| Gestione credenziali LLM | ⚠️ API key locali (`auth-storage`) | LLM gateway centrale: le chiavi non vanno sui client |
| Audit e osservabilità | ⚠️ Sessioni locali JSONL | Audit log centralizzato via estensione |
| Identità e RBAC | ❌ | Control plane (OIDC/mTLS per device) |

Conclusione: **PI è una buona base** proprio perché è un harness neutro con hook bloccanti su ogni esecuzione di tool. Tutto ciò che manca per l'enterprise va costruito *attorno*, non *dentro*: non serve un fork, servono un'estensione "fleet" e una piattaforma di controllo.

---

## 2. Architettura proposta

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│  CLIENT (workstation/VM)    │  mTLS/  │  CONTROL PLANE (piattaforma  │
│                             │  OIDC   │  amministrativa)             │
│  ┌───────────────────────┐  │◄───────►│                              │
│  │ Harness wrapper       │  │         │  • API config & policy      │
│  │  (SDK createAgent-    │  │         │  • UI amministrativa (RBAC) │
│  │   Session / RPC)      │  │         │  • Registry pacchetti/skill │
│  │  ┌─────────────────┐  │  │         │  • Audit ingest + SIEM      │
│  │  │ Estensione FLEET │  │  │         │  • Firma config (JWS)      │
│  │  │ • policy engine  │  │  │         │  • Rollout / kill switch    │
│  │  │ • audit shipper  │  │  │         └──────────────┬───────────────┘
│  │  │ • config sync    │  │  │                        │
│  │  └─────────────────┘  │  │         ┌──────────────▼───────────────┐
│  │  PI coding agent      │  │────────►│  LLM GATEWAY                 │
│  └───────────────────────┘  │ inferenza│  • credenziali provider     │
│  Esecuzione tool in sandbox │         │  • rate limit / budget      │
│  (container / micro-VM)     │         │  • logging prompt/response  │
└─────────────────────────────┘         └──────────────────────────────┘
```

### 2.1 Client agent

Wrapper sottile attorno a PI (via SDK se il client è Node, via RPC se il wrapper è in altro linguaggio), distribuito come pacchetto interno. Non si forka PI: lo si pinna a versione esatta e si aggiorna in modo controllato dal control plane.

**Estensione "fleet"** (il cuore, ~caricata sempre, non disattivabile dall'utente):

- **Policy engine su `tool_call`**: valuta ogni chiamata tool contro la policy ricevuta dal control plane — allowlist/denylist di comandi bash (parsati, non regex naive), path consentiti (workspace only), blocco di rete/credenziali, limiti dimensione. Default **deny** per ciò che non è classificato; le decisioni "ask" possono essere inoltrate a un approvatore.
- **`tool_result` / redaction**: scrubbing di pattern segreti (token, chiavi) prima che rientrino nel contesto del modello e nei log.
- **Config sync**: pull periodico della configurazione dal control plane. Il bundle di config è **firmato** (JWS/cosign): il client verifica la firma con una chiave pubblica pinnata prima di applicarlo. Cache locale firmata per funzionare offline; TTL oltre il quale l'agent degrada a policy restrittiva o si ferma (kill switch implicito).
- **Audit shipper**: ogni tool call (input, esito, decisione di policy), cambio modello e sessione viene spedito al control plane in formato strutturato, con buffering locale.
- **Lockdown della configurazione locale**: `project_trust` forzato a `never` (o gestito da policy), `PI_OFFLINE=1`, disabilitazione di `/settings` e dell'installazione pacchetti arbitrari; i pacchetti/skill arrivano solo dal registry interno approvato.

**Isolamento di esecuzione** (obbligatorio: PI non ha sandbox):
- Opzione A (consigliata): tutto il processo in **container** non privilegiato con solo il workspace montato, filesystem root read-only, egress limitato a control plane + LLM gateway.
- Opzione B: pattern **Gondolin** — PI sull'host, tool instradati in micro-VM (utile dove Docker non è disponibile sui client).

### 2.2 Control plane (piattaforma amministrativa)

- **Modello dati**: organizzazione → gruppi/team → device/utente; config e policy per livello con ereditarietà e override (ricalca il modello globale→progetto di PI, ma risolto lato server: il client riceve una config già *appiattita* e firmata).
- **API**: CRUD config/policy, enrollment device (bootstrap con token monouso → certificato mTLS o device credential OIDC), heartbeat/inventory (versione agent, versione config applicata), ingest audit.
- **UI amministrativa**: editing policy con validazione, diff e versioning delle config, rollout graduale (canary → gruppi → tutti), rollback, kill switch per device/gruppo/globale, dashboard di audit.
- **RBAC + audit amministrativo**: chi ha cambiato quale policy, quando; approvazione a 4 occhi per policy sensibili.
- **Registry interno** di estensioni/skill/prompt approvati (PI li carica via `packages` in settings): niente npm pubblico sui client.

### 2.3 LLM Gateway

Le API key dei provider **non devono mai risiedere sui client**. Il gateway:
- espone endpoint Anthropic/OpenAI-compatibili (PI supporta provider custom/baseUrl, vedi `docs/custom-provider.md`);
- autentica il device (mTLS/OIDC), applica rate limit e budget per team;
- logga prompt/response per audit e DLP;
- centralizza la rotazione delle credenziali provider.

### 2.4 Principi di sicurezza (riepilogo)

1. **Zero trust verso il contenuto**: prompt injection non è prevenibile (lo dice PI stesso) → l'unico contenimento affidabile è la sandbox + policy default-deny + egress control.
2. **Zero segreti sul client**: inferenza via gateway; l'unico credential sul client è l'identità device.
3. **Config come artefatto firmato e versionato**: il client applica solo config con firma valida; ogni applicazione è tracciata.
4. **Supply chain**: PI pinnato a versione esatta, shrinkwrap, `--ignore-scripts`, mirror npm interno; si eredita e si estende l'hardening già presente nel monorepo di PI.
5. **Auditabilità completa**: ogni azione dell'agente è ricostruibile dal log centrale (le sessioni JSONL di PI aiutano, ma la fonte autoritativa è l'audit shipper).
6. **Fail closed**: config scaduta, firma invalida o control plane irraggiungibile oltre soglia → policy restrittiva o stop.

### 2.5 Roadmap suggerita

1. **PoC** (settimane 1–3): wrapper SDK + estensione fleet con policy statica da file firmato locale; sandbox Docker; gateway LLM minimo (proxy con key server-side).
2. **Control plane MVP** (settimane 4–8): API config/policy + enrollment + UI base; config sync firmato; audit ingest.
3. **Hardening** (settimane 9–12): rollout graduale, kill switch, redaction, registry interno pacchetti, integrazione SIEM, pen test.
4. **Scala**: RBAC avanzato, approvazioni interattive ("ask" → approvatore umano), budget/quota per team, aggiornamento automatico controllato dell'agent.

---

## 3. Rischi e punti di attenzione

- **Progetto giovane e in rapida evoluzione** (v0.80.x, release frequenti): pinnare la versione e testare gli upgrade in canary; l'Extension API può cambiare.
- Le **estensioni girano in-process** con i permessi del processo PI: l'estensione fleet è essa stessa codice fidato critico — firma del pacchetto e review obbligatoria.
- L'hook `tool_call` intercetta i tool dell'agente ma **non ciò che un comando bash consentito fa a valle** (es. `bash -c` che scarica ed esegue): il vero enforcement di rete/filesystem sta nella sandbox, la policy sui tool è defense-in-depth, non il boundary.
- **Nuove versioni di PI possono introdurre nuovi tool o comportamenti**: la policy deve essere default-deny sui tool sconosciuti (`pi.setActiveTools()` con allowlist esplicita).
