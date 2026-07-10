# Guida operativa

Come mettere in funzione la piattaforma e arruolare i client gestiti.

## 1. Build

```bash
npm ci --ignore-scripts
npm run build
npm test
```

Requisiti: Node.js ≥ 22. Nessuna dipendenza runtime esterna: i pacchetti usano solo i built-in di Node (superficie di supply chain minima).

## 2. Control plane

```bash
# Prima inizializzazione: genera la coppia di chiavi Ed25519 di firma dei
# bundle e il primo token amministrativo (mostrato una sola volta).
node packages/control-plane/dist/cli.js init --data-dir .data/control-plane

# Avvio del server (default porta 8787)
node packages/control-plane/dist/cli.js serve --data-dir .data/control-plane
```

La UI amministrativa è su `http://localhost:8787/`. Accedi con il token generato da `init`. Da lì puoi:

- vedere i device (ultimo contatto, versione config applicata) e sospenderli/revocarli;
- creare gruppi e attivare kill switch per device, gruppo o **globale**;
- modificare la policy dell'organizzazione (override JSON sul default default-deny);
- generare token di enrollment monouso;
- consultare l'audit per device e l'audit amministrativo.

Ruoli: `admin` (tutto), `operator` (kill switch, enrollment), `viewer` (sola lettura). Nuovi token si creano con `POST /api/admin/admin-tokens`.

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

### Comportamento a runtime (estensione fleet)

- ogni `tool_call` di PI è valutata contro la policy: default **deny** sui tool sconosciuti, allowlist bash per segmenti di comando, filesystem limitato alla workspace;
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

## 5. Operazioni di sicurezza

| Scenario | Azione |
|---|---|
| Incidente su un device | UI → device → **sospendi** (kill switch): tool bloccati al sync successivo, inferenza bloccata entro 60 s |
| Device revocato | Al primo sync dopo la revoca (risposta 401/403) il client scarta subito bundle e cache e degrada a fail-closed, senza attendere la scadenza |
| Incidente diffuso | Kill switch **globale** dalla testata della UI |
| Device compromesso/dismesso | UI → device → **revoca**: il token smette di funzionare su config, audit e gateway |
| Rotazione chiave di firma | Genera nuove chiavi in `keys/`, ridistribuisci la pubblica ri-arruolando i device (la chiave è pinnata per-device) |
| Policy più restrittiva per un team | Gruppo dedicato con `policyOverride` (es. `{"bash": {"mode": "deny-all"}}`) |
| Verifica di una policy | `GET /api/admin/devices/:id/effective-policy` mostra la policy esattamente come la vedrà il client |

## 6. Limiti noti (da leggere)

- Il parsing dei comandi bash è conservativo ma approssimato: non è un sostituto della sandbox. Un comando consentito può fare a valle cose che la policy non vede (incluse le redirezioni `>` verso percorsi arbitrari); il contenimento di rete/filesystem spetta al container.
- I percorsi vengono risolti con `realpath` (i symlink che escono dalla workspace sono negati), ma race TOCTOU tra verifica ed esecuzione restano possibili: anche qui il confine è la sandbox.
- Il gateway inoltra solo gli endpoint di inferenza (`/v1/messages`, `/v1/chat/completions`, …): il device token non dà accesso al resto dell'API del provider.
- La prompt injection da contenuti del repository non è prevenibile a livello di harness (posizione esplicita anche di PI): default-deny + sandbox + audit sono le mitigazioni.
- Lo shim dei tipi dell'Extension API (`packages/fleet-extension/src/pi-types.ts`) è allineato a PI v0.80.x: quando si aggiorna la versione pinnata di PI sui client, riverificarlo.
- Lo storage del control plane è su file JSON con scritture atomiche: adatto a flotte piccole/medie e a PoC; l'interfaccia (`Store`) è pensata per migrare a Postgres senza toccare la logica. Va eseguita **una sola istanza** del server per data dir (nessun lock multi-processo).
- La UI amministrativa conserva il token in `localStorage` e usa script inline (CSP `unsafe-inline`): accettabile dietro rete interna/VPN; per esposizione più ampia prevedere una sessione server-side.
