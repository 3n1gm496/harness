# Guida operativa

Come mettere in funzione la piattaforma e arruolare i client gestiti.

## 1. Build

```bash
npm ci --ignore-scripts
npm run build
npm test
```

Requisiti: Node.js ≥ 22. Nessuna dipendenza runtime esterna: i pacchetti usano solo i built-in di Node (superficie di supply chain minima).

### Avvio one-command (Docker)

L'intero backend (Postgres + control plane con auto-seeding) parte con un solo comando; le credenziali iniziali sono stampate nei log del servizio `control-plane`:

```bash
docker compose -f deploy/docker-compose.yml up --build
# Gateway LLM opzionale (profilo `gateway`, richiede una chiave provider):
ANTHROPIC_API_KEY=sk-... docker compose -f deploy/docker-compose.yml --profile gateway up --build
```

La KEK nel compose è un valore di **sviluppo**: in produzione forniscila da un secret manager.

## 2. Control plane

```bash
# Prima inizializzazione: genera la coppia di chiavi Ed25519 di firma dei
# bundle e il primo token amministrativo (mostrato una sola volta).
node packages/control-plane/dist/cli.js init --data-dir .data/control-plane

# In alternativa, seeding idempotente (admin se assente + token di
# enrollment + token gateway, output JSON) — comodo per sviluppo e CI:
node packages/control-plane/dist/cli.js seed --data-dir .data/control-plane

# Avvio del server (default porta 8787)
node packages/control-plane/dist/cli.js serve --data-dir .data/control-plane
```

La UI amministrativa è su `http://localhost:8787/`. Accedi con il token generato da `init`. Da lì puoi:

- vedere i device (ultimo contatto, versione config applicata) e sospenderli/revocarli;
- creare gruppi e attivare kill switch per device, gruppo o **globale**;
- modificare la policy dell'organizzazione (override JSON sul default default-deny);
- generare token di enrollment monouso;
- consultare l'audit per device e l'audit amministrativo.

Ruoli: `admin` (tutto), `operator` (kill switch, enrollment), `viewer` (sola lettura). Nuovi token si creano con `POST /api/admin/admin-tokens` (`ttlDays`, default 90: **i token amministrativi scadono**); si elencano con `GET /api/admin/admin-tokens` e si revocano con `DELETE /api/admin/admin-tokens/:id` — la revoca dell'ultimo admin attivo è rifiutata.

### TLS

Imposta `HARNESS_TLS_CERT_FILE` e `HARNESS_TLS_KEY_FILE` (PEM) per servire HTTPS con HSTS direttamente da control plane e gateway; in alternativa termina TLS su un reverse proxy. Senza TLS il server avvisa all'avvio. Le richieste sono loggate in JSON strutturato (`method`, `path`, `status`, `durationMs`).

### Osservabilità

Control plane e gateway espongono:

- `GET /healthz` — liveness (il processo risponde);
- `GET /readyz` — readiness **reale**: sul control plane verifica la connettività del backend (con Postgres: una query sul changelog) e la presenza di una chiave di firma attiva; sul gateway la raggiungibilità del control plane. Risponde 503 se non pronto — da usare come readiness probe di Kubernetes/compose;
- `GET /metrics` — formato Prometheus: `harness_http_requests_total{method,status}`, `harness_http_request_duration_seconds` (histogram), richieste in-flight, `harness_up`; sul gateway `harness_gateway_requests_total{provider,status}` e durata upstream.

Il livello di log si controlla con `HARNESS_LOG_LEVEL` (`debug|info|warn|error`, default `info`); l'output è una riga JSON per evento, pronto per qualunque collector.

### Audit tamper-evident

I log di audit (per device e amministrativo) sono catene di hash: ogni riga incorpora l'hash della precedente, quindi modifiche o cancellazioni retroattive rompono la catena in modo rilevabile.

```bash
harness-cp verify-audit --data-dir .data/control-plane              # audit amministrativo
harness-cp verify-audit --device dev_...                            # audit di un device
# oppure via API: GET /api/admin/audit/verify?deviceId=...
```

Per la **non-ripudiabilità completa**, esporta periodicamente un anchor firmato delle teste delle catene e archivialo su storage WORM esterno (S3 object-lock, ecc.):

```bash
harness-cp export-audit-anchor --data-dir .data/control-plane > anchor-$(date +%s).jws
# oppure via API: GET /api/admin/audit/anchor
```

L'anchor è un JWS firmato dal control plane: chi verifica in seguito ne controlla la firma (chiave in `trustedPublicKeys`) e confronta le teste ancorate con le catene correnti, scoprendo qualunque troncamento o manomissione anche da parte di chi ha accesso in scrittura ai file di audit.

### Autenticazione admin via OIDC/JWT

Oltre ai token statici `adm_...`, il control plane accetta JWT firmati dal vostro provider OIDC. Abilitalo via ambiente:

```bash
HARNESS_OIDC_ISSUER=https://sso.azienda.it \
HARNESS_OIDC_AUDIENCE=harness-control-plane \
HARNESS_OIDC_KEYS_FILE=/etc/harness/oidc-keys.json \   # [{ "kid": "...", "alg": "RS256", "publicKeyPem": "..." }]
HARNESS_OIDC_ROLE_CLAIM=harness_role \                  # claim → admin|operator|viewer (default "harness_role")
node packages/control-plane/dist/cli.js serve
```

Sono verificati firma (RS256/ES256), issuer, audience e scadenza; il claim di ruolo mappa sul ruolo RBAC. Così l'accesso amministrativo passa dall'IdP aziendale (MFA, offboarding automatico) invece che da segreti condivisi.

### Rotazione della chiave di firma dei bundle

Senza re-enrollment dei device, in tre fasi:

```bash
# 1. add — nuova chiave fidata ma non ancora firmante (i device la apprendono dai bundle)
curl -X POST .../api/admin/signing-keys -H "authorization: Bearer $ADMIN"
#    → attendi un ciclo di sync dei device (default 60 s, con margine)
# 2. promote — la nuova chiave diventa firmante (i device la fidano già)
curl -X POST .../api/admin/signing-keys/$KEY_ID/promote -H "authorization: Bearer $ADMIN"
# 3. retire — ritira la vecchia chiave
curl -X DELETE .../api/admin/signing-keys/$OLD_KEY_ID -H "authorization: Bearer $ADMIN"
```

I client verificano i bundle contro l'insieme di chiavi fidate e aggiornano il pin da `trustedPublicKeys`; saltare le attese (o promuovere prima che i device apprendano la nuova chiave) manda fail-closed i device non ancora sincronizzati.

### Binding mTLS dei device

Per legare un device al suo certificato client (un token rubato senza chiave privata diventa inutile): servi il control plane in TLS (`HARNESS_TLS_*`) e arruola presentando il certificato client, oppure passa `certFingerprint` (SHA-256 hex) nel body di enrollment. Da quel momento le richieste `/api/device/*` di quel device richiedono il certificato combaciante.

Il binding **dopo** l'enrollment (`POST /api/device/bind-cert`, trust-on-first-use) è **disabilitato di default**: un token rubato non deve poter legare un certificato arbitrario prima che lo faccia il device legittimo. Con `requireDeviceCert=true` è vietato sempre (il binding va fatto solo all'enrollment); con `requireDeviceCert=false` va abilitato esplicitamente con `PUT /api/admin/org { "allowCertTofu": true }` se serve per un flusso operativo specifico.

### Storage Postgres (flotte grandi)

Il default è il file store locale (zero dipendenze, singola istanza). Per alta disponibilità/scala, imposta `DATABASE_URL`: lo stato è **normalizzato** (una riga per entità — org, gruppi, device, token, chiavi) con **scritture mirate** (niente riscrittura del blob), e l'**audit è centralizzato** nel DB (`cp_audit_events` con testa di catena per-stream serializzata via lock di riga). Più istanze condividono lo stesso DB: convergono via reload periodico, le scritture sono row-level (niente conflitti globali), l'audit è unico e non frammentato. Richiede la dipendenza opzionale `pg` e `HARNESS_SIGNING_KEK` (obbligatoria: le chiavi private sono cifrate a riposo anche nel DB). L'heartbeat dei device (`lastSeenAt`) è persistito con throttling (≤ ogni 30s per device).

```bash
DATABASE_URL=postgresql://user:pass@db:5432/harness node packages/control-plane/dist/cli.js serve
```

## 3. Gateway LLM

Le API key dei provider stanno **solo** sul gateway, mai sui client.

```bash
# Dalla UI o via API: POST /api/admin/gateway-tokens → token gateway
CONTROL_PLANE_URL=http://localhost:8787 \
GATEWAY_TOKEN=gwt_... \
ANTHROPIC_API_KEY=sk-ant-... \
node packages/llm-gateway/dist/cli.js
```

I client chiamano `http://gateway:8788/anthropic/v1/messages` autenticandosi con il **device token**; il gateway lo verifica via introspezione sul control plane (revoca e kill switch si propagano entro il TTL di cache, 60 s), applica il rate limit per device e inoltra la richiesta con la chiave provider iniettata.

Per instradare PI attraverso il gateway, configura nei `piSettings` del gruppo un provider custom con `baseUrl` puntata al gateway (vedi `docs/custom-provider.md` di PI).

## 4. Client gestito

```bash
# Nella UI: genera un token di enrollment per il gruppo del device.
harness-agent enroll --url https://cp.azienda.it --token enr_... --name workstation-42

harness-agent status   # stato e versione config
harness-agent sync     # scarica il bundle firmato e applica i settings PI gestiti
harness-agent run      # sync + avvio di pi con l'estensione fleet caricata
```

L'enrollment scrive `~/.harness/agent.json` (0600) con l'identità del device e la **chiave pubblica di firma pinnata**. Da quel momento il client applica solo bundle firmati con quella chiave.

Il device token **ruota automaticamente** ogni 30 giorni (`rotateAfterDays` in agent.json) a ogni `sync`/`run`, o su richiesta con `harness-agent rotate-token`; il vecchio token smette immediatamente di valere su control plane e gateway.

### Comportamento a runtime (motore di enforcement)

L'enforcement vive in `@harness/enforcement-core`, **agent-agnostic**: definisce un contratto neutro `AgentAdapter` e non conosce PI. `@harness/fleet-extension` è l'adapter che traduce la Extension API di PI sulle primitive neutre; integrare un altro coding agent significa scrivere un adapter analogo, senza toccare il motore (dimostrazione funzionante: `npm run example:mock-agent`).

- ogni `tool_call` dell'agente è valutata contro la policy: default **deny** sui tool sconosciuti, allowlist bash per segmenti di comando, filesystem limitato alla workspace;
- i comandi `!` dell'utente seguono la stessa policy bash;
- i segreti nei risultati dei tool vengono redatti prima di rientrare nel contesto del modello;
- ogni decisione è tracciata e spedita in batch al control plane;
- la config si risincronizza ogni 60 s; se il bundle scade senza rinnovo (control plane irraggiungibile oltre il TTL, default 60 min) l'agente degrada a **fail-closed** e si blocca;
- kill switch: attivato dalla UI, blocca l'agente al sync successivo (e immediatamente sul gateway LLM).

### Sandbox (obbligatoria in produzione)

PI non ha sandbox propria: la policy sui tool è defense-in-depth, il confine di sicurezza è il container. Usa `deploy/Dockerfile.agent`:

```bash
docker build -t harness-agent -f deploy/Dockerfile.agent .
docker run --rm -it \
  -v "$PWD:/workspace" \
  -v harness-agent-home:/home/node \
  harness-agent run
```

Linee guida: montare solo la workspace necessaria, usare un volume dedicato per `/home/node`, limitare l'egress di rete del container a control plane e gateway (network policy/firewall), nessuna API key provider nell'ambiente del container.

I container girano come utente non-root: l'immagine backend crea `/data` di proprietà di `node` e la dichiara `VOLUME`, così un named volume vi si monta con i permessi corretti. Un `.dockerignore` esclude `node_modules`, `dist` e `.tsbuildinfo` dell'host dal contesto di build (immagini più snelle, nessun binario nativo host-specific).

## 5. Operazioni di sicurezza

| Scenario | Azione |
|---|---|
| Incidente su un device | UI → device → **sospendi** (kill switch): tool bloccati al sync successivo, inferenza bloccata entro 60 s |
| Device revocato | Al primo sync dopo la revoca (risposta 401/403) il client scarta subito bundle e cache e degrada a fail-closed, senza attendere la scadenza |
| Incidente diffuso | Kill switch **globale** dalla testata della UI |
| Device compromesso/dismesso | UI → device → **revoca**: il token smette di funzionare su config, audit e gateway |
| Rotazione chiave di firma | Procedura a tre fasi senza re-enrollment: `POST /signing-keys` (add) → attendi un sync → `POST /signing-keys/:id/promote` → `DELETE /signing-keys/:oldId` (retire) |
| Custodia della KEK | `HARNESS_SIGNING_KEK` va conservata in un secret manager/KMS: senza non si aprono le chiavi di firma. La rotazione della KEK richiede oggi un re-seal manuale (decifra con la vecchia, ri-cifra con la nuova) — automatizzarla è un follow-up |
| Sicurezza elevata per un team | Gruppo con `policyOverride` restrittiva + `requireDeviceCert=true` (mTLS all'enroll, no TOFU) |
| Verifica di una policy | `GET /api/admin/devices/:id/effective-policy` mostra la policy esattamente come la vedrà il client |
| Non-ripudiabilità audit | Esporta periodicamente l'anchor (`export-audit-anchor`) su WORM esterno; verifica con `verify-audit` |

Nota: `export-audit-anchor` e `verify-audit` da CLI operano con identità admin implicita (chi accede al data dir è già admin-equivalente).

## 6. Limiti noti (da leggere)

- Il parsing dei comandi bash è conservativo ma approssimato: non è un sostituto della sandbox. Un comando consentito può fare a valle cose che la policy non vede (incluse le redirezioni `>` verso percorsi arbitrari); il contenimento di rete/filesystem spetta al container.
- I percorsi vengono risolti con `realpath` (i symlink che escono dalla workspace sono negati), ma race TOCTOU tra verifica ed esecuzione restano possibili: anche qui il confine è la sandbox.
- Il gateway inoltra solo gli endpoint di inferenza (`/v1/messages`, `/v1/chat/completions`, …): il device token non dà accesso al resto dell'API del provider.
- La prompt injection da contenuti del repository non è prevenibile a livello di harness (posizione esplicita anche di PI): default-deny + sandbox + audit sono le mitigazioni.
- Lo shim dei tipi dell'Extension API (`packages/fleet-extension/src/pi-types.ts`) è allineato a PI v0.80.x: quando si aggiorna la versione pinnata di PI sui client, riverificarlo.
- Lo storage a file JSON (default) è per singola istanza; per multi-istanza/HA usa il backend Postgres normalizzato (`DATABASE_URL`). In file mode va eseguita **una sola istanza** per data dir.
- La UI amministrativa conserva il token in `localStorage` e usa script inline (CSP `unsafe-inline`): accettabile dietro rete interna/VPN; per esposizione più ampia prevedere una sessione server-side.
