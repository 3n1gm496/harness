# Changelog

Tutte le modifiche rilevanti di questo progetto sono documentate qui. Il
formato segue [Keep a Changelog](https://keepachangelog.com/it/1.1.0/); i
pacchetti sono privati (uso interno) e non seguono ancora Semantic
Versioning pubblico — la versione `0.1.0` copre l'intero sviluppo fino a oggi.

## [Unreleased]

### Added

- **Agente nativo `@harness/agent-core`**: Harness non è più solo un harness che
  governa un agente di terze parti (PI) — ha ora un **agente proprio**,
  LLM-driven, di prim'ordine. Loop reason-act-observe; client LLM che parla la
  Messages API **solo via gateway** (device token come `x-api-key`, credenziali
  del provider mai sul client), non-streaming e streaming SSE; runtime di tool
  nativi in-process e zero-dep (`read_file`, `write_file`, `edit_file`,
  `list_dir`, `grep`, `glob`, `bash` con kill del process-group e cap output);
  gestione del contesto con compaction che non spezza mai le coppie
  `tool_use`/`tool_result`; CLI `harness-agent-native` (one-shot e interattiva).
  Ogni azione dell'agente attraversa lo **stesso** motore di
  `@harness/enforcement-core` di qualunque adapter (gate → esecuzione →
  redaction → audit): stessa policy firmata, stesso fail-closed, stesso audit.
  Un `AgentAdapter` nativo tiene il motore identico a com'è per PI. 36 test,
  inclusa una verifica end-to-end su HTTP reale (server-gateway finto in
  streaming SSE che guida un `edit_file` sotto enforcement). La `defaultPolicy`
  ora elenca anche i nomi dei tool nativi. Vedi `docs/agente-nativo.md`.
- **Agente nativo — multi-provider, sub-agenti, token esatti**: astrazione
  `WireProvider` con provider **Anthropic** e **OpenAI** (Chat Completions:
  traduzione della cronologia neutra ↔ `tool_calls`/ruolo `tool`, streaming SSE
  con accumulo dei tool_calls frammentati e usage via `stream_options`); tool
  **`task`** per delegare a un agente **figlio** con contesto isolato ma stesso
  enforcement/audit e profondità limitata (`maxDepth`); **conteggio token
  esatto** via `count_tokens` (Anthropic), chiamato solo vicino al budget con
  fallback trasparente alla stima per i provider che non lo espongono. La
  `defaultPolicy` elenca anche `task`. 48 test nel package.
  **Caveat verificato dal vivo:** un token di abbonamento Anthropic
  (`claude setup-token`) presentato dal gateway riceve `401 "OAuth access token
  is invalid"` (è vincolato al client ufficiale); la modalità OAuth non permette
  quindi di usare l'abbonamento Anthropic al posto dei crediti API — resta utile
  verso provider/gateway che accettano un bearer OAuth. Lo stack inoltra e
  gestisce l'errore correttamente (401 non ritentato).
- **Agente nativo — eventi annidati, prompt caching, demo live**: gli
  `AgentEvent` portano `depth` (l'attività dei sotto-agenti è inoltrata e
  indentabile); **prompt caching** Anthropic opt-in (`cache_control` su
  system+ultimo tool, header beta, riuso dei token del prefisso tra i turni);
  **demo live** `npm run example:native-agent` — agente reale contro il
  **gateway reale** su HTTP, con asserzioni (compito multi-step, `rm -rf`
  bloccato, `.env` redatto, delega, credenziali del provider confinate nel
  gateway), aggiunta come gate CI. 52 test nel package.

- **Gateway: credenziale provider via account/sessione (OAuth), non solo API
  key.** Per ciascun provider il gateway accetta una API key metered
  (`*_API_KEY`) **oppure** un token di account/sessione (`*_AUTH_TOKEN` o
  `*_AUTH_TOKEN_FILE`) inviato come `Authorization: Bearer` (mai `x-api-key`),
  così l'accesso può usare un abbonamento invece del credito API. Con il file il
  token è riletto a ogni richiesta (cache per mtime) per la rotazione esterna
  senza riavvio; `ANTHROPIC_AUTH_BETA` unisce l'header beta OAuth a quello del
  client; senza credenziale il gateway risponde 503. Documentato in
  `packages/llm-gateway/README.md` e nella guida operativa.

### Fixed (review pre-release agente nativo)

- **A1** — gestione del contesto robusta anche senza `count_tokens` (OpenAI):
  budget di default più prudente (100k) e margine di sicurezza (×1.3) sulla stima
  euristica, così la compaction scatta prima di superare la finestra.
- **A2** — il tool `bash` non eredita più l'intero `process.env`: env allowlist
  (PATH/HOME/LANG/…) con passthrough opt-in (`HARNESS_BASH_ENV_PASSTHROUGH`),
  chiudendo l'esposizione di segreti d'ambiente ai comandi guidati dal modello.
- **A3** — retry/backoff sul client LLM (429/5xx/overloaded/timeout/rete, con
  `Retry-After` e jitter): un errore transitorio non fa più fallire il turno.
- **A4** — niente più doppio evento di testo dei sotto-agenti (un solo
  `assistant_text` per turno, marcato con la profondità).
- **A5** — CLI dell'agente nativo con sottocomandi `run`/`repl`; il prompt
  posizionale non ingloba più i valori dei flag (es. l'URL del gateway).
- **A6** — i tool `write_file`/`edit_file` rimuovono il file temporaneo (best
  effort) se il rename fallisce.

### Security

- **Chiusi due bypass del motore di policy bash** (config di default):
  riconoscimento dei flag "attaccati" (`node --eval=…`, `python3 -c'…'`, cluster
  di short flag) che sfuggivano a un match esatto — un percorso di esecuzione
  arbitraria; decodifica ANSI-C (`$'\x62…'`) nel tokenizer; wrapper mancanti
  (`command`/`time`/`sudo`/…). Corpus di test avversariale dedicato.
- **Redazione dei segreti `KEY=VALUE` non quotati** (`cat .env`/`printenv`), che
  nessun pattern catturava prima.
- **Sessioni UI revocabili**: revocare l'admin token che ha aperto una sessione
  la invalida subito (prima restava valida fino a 12h). Sessioni ora persistite
  (Postgres), durevoli e condivise multi-istanza; CSRF sul logout; CSP con
  `frame-ancestors 'none'` + `X-Frame-Options: DENY`; `X-Forwarded-Proto` fidato
  solo dietro `HARNESS_TRUST_PROXY`; confronto CSRF a tempo costante.
- **Fail-closed** garantito nel motore di enforcement anche su eccezione
  inattesa; validazione della chiave di firma del device all'enrollment;
  `verifyJwt` richiede `exp`; nessun leak del messaggio d'eccezione interno
  nelle risposte HTTP; guard ReDoS (input limitato) sulle regex admin;
  enforcement dei path esteso a chiavi annidate/array.

### Added

- Rete di sicurezza a livello processo (`uncaughtException`/`unhandledRejection`)
  nei CLI di control plane e gateway.
- Rate limit a **finestra scorrevole** (niente burst 2× al confine) ovunque, con
  eviction LRU sull'overflow in memoria; rate limit del gateway condivisibile
  multi-istanza via `DATABASE_URL`.
- CI resa un gate reale: audit supply-chain bloccanti, `mock-agent` con `assert`,
  load-test eseguito, coverage per-pacchetto, coerenza pin PI ↔ shim dei tipi.
- Deploy: healthcheck e limiti di risorse per tutti i servizi del compose.

### Added

- Motore di enforcement **agent-agnostic** (`@harness/enforcement-core`) con
  contratto neutro `AgentAdapter`; PI è un adapter come un altro
  (`@harness/fleet-extension`), dimostrato da un esempio end-to-end senza PI
  (`examples/mock-agent`).
- Control plane con API dichiarativa, RBAC (admin/operator/viewer), kill
  switch (globale/gruppo/device), rotazione della chiave di firma in tre fasi
  senza re-enrollment, audit tamper-evident (catena di hash) con export di un
  anchor firmato verso storage WORM esterno.
- Storage pluggable: file locale (default, zero dipendenze) o Postgres
  normalizzato con scritture mirate, sincronizzazione incrementale
  (LISTEN/NOTIFY) e migrazioni di schema versionate.
- Retention: eliminazione device, pruning automatico dei token
  amministrativi scaduti, comando `harness-cp prune` per audit/changelog
  (con genesis-tracking per non rompere la tamper-evidence).
- Rate limit condiviso multi-istanza sull'enrollment (Postgres) e per device
  sul gateway LLM.
- Gateway LLM (Anthropic/OpenAI-compatibile) con introspezione dei device
  token, credenziali provider mai esposte ai client, body in streaming e
  timeout upstream configurabile.
- Autenticazione admin via OIDC/JWT oltre ai token statici; binding dei
  device al certificato client mTLS su control plane e gateway.
- Provenance crittografica dell'audit dei device (firma Ed25519 propria del
  device sui batch, generata all'enrollment).
- UI amministrativa: dashboard di flotta, paginazione/ricerca/filtro
  server-side dei device, editor di policy con diff e validazione, gestione
  token/chiavi di firma.
- Metriche Prometheus di flotta (`harness_fleet_devices{state}`,
  `harness_fleet_kill_switch`, `harness_fleet_config_version`) oltre alle
  metriche HTTP standard.
- Osservabilità: logger strutturato, `/readyz` con sonda di readiness reale.
- Test: suite unitaria/integrazione estesa (incluso backend Postgres live e
  mTLS), test UI in un browser reale (`playwright-core`), load-test
  committato (`scripts/load-test.mjs`).
- CI: build, lint (Biome), suite completa, coverage con soglia minima,
  esempio end-to-end, validazione di `docker-compose.yml`, build delle
  immagini Docker.
- Deploy: Docker Compose one-command (Postgres + control plane + UI, con
  auto-seeding), Dockerfile del client con sandbox obbligatoria.
- Documentazione: modello di minaccia, guida operativa, questo changelog,
  guida "scrivere un adapter" per `@harness/enforcement-core`.

### Changed

- `ControlPlaneService` non è più una facciata delegante: i chiamanti usano
  direttamente i sotto-servizi di dominio (`service.auth`, `service.devices`,
  `service.groups`, `service.org`, `service.signingKeys`, `service.auditLog`).
- `@harness/agent-client` dipende direttamente da `@harness/enforcement-core`
  invece che da `@harness/fleet-extension` (che resta solo per lanciare `pi`).
- Indice O(1) token→device in memoria (`authenticateDevice`/
  `introspectDeviceToken` non scandiscono più linearmente la flotta).
- UI amministrativa: sessione server-side (cookie httpOnly+Secure+SameSite,
  CSRF token, logout) al posto del bearer token in `localStorage`; JS/CSS
  esternalizzati (`app.js`/`app.css`) e nessun `onclick=` inline, così la CSP
  scende a `default-src 'self'` senza `'unsafe-inline'`. Il bearer token
  resta invariato per API/CLI.
- `Store.save()` in file-mode con un backend Postgres attivo throttla la
  riscrittura del file locale (cache di bootstrap, non fonte di verità)
  invece di riscrivere l'intero blob a ogni mutazione — elimina
  l'amplificazione di scrittura dell'heartbeat di flotte grandi.

### Fixed

- Trust-on-first-use del binding certificato disabilitato di default
  (richiede l'opt-in esplicito `allowCertTofu`).
- Rimozione della facciata duplicata e di un private class member morto in
  un test di `enforcement-core` (rilievi Biome, non solo soppressi).
- `deploy/Dockerfile.backend`: `/shared` ora creata e di proprietà
  dell'utente non-root `node` (senza, il seeding falliva con `EACCES` su un
  named volume montato da Docker come root).
