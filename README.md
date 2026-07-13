# Harness

Harness AI aziendale con un **motore di enforcement agent-agnostic** e una piattaforma amministrativa per la gestione centralizzata di configurazioni e policy sui client, pensato per ambienti di produzione. Il motore non dipende da un coding agent specifico: [PI Coding Agent](https://pi.dev/) è **uno degli adapter** (vedi `examples/mock-agent` per un agente non-PI che usa lo stesso motore).

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│  CLIENT (sandbox Docker)    │  HTTPS  │  CONTROL PLANE               │
│  agente + adapter +         │◄───────►│  policy · config firmata     │
│  @harness/enforcement-core  │         │  kill switch · audit · RBAC  │
│  enforcement · redaction    │         │  UI · /metrics · /readyz     │
└──────────────┬──────────────┘         └──────────────┬───────────────┘
               │ inferenza (device token)              │ introspezione
               ▼                                       ▼
        ┌────────────────────────────────────────────────┐
        │  LLM GATEWAY — credenziali provider solo qui   │
        └────────────────────────────────────────────────┘
```

## Pacchetti

| Pacchetto | Ruolo |
|---|---|
| [`@harness/shared`](packages/shared) | Tipi, firma Ed25519 dei bundle di config, policy engine default-deny, redaction, logger e metriche Prometheus |
| [`@harness/enforcement-core`](packages/enforcement-core) | Motore di enforcement **agent-agnostic**: contratto neutro `AgentAdapter`, sync della config firmata (fail-closed, anti-rollback), audit, sandbox |
| [`@harness/control-plane`](packages/control-plane) | Piattaforma amministrativa: API (router dichiarativo), storage (file o Postgres normalizzato), RBAC, kill switch, audit, UI web, osservabilità |
| [`@harness/fleet-extension`](packages/fleet-extension) | **Adapter PI**: traduce la Extension API di PI sulle primitive neutre del core (integrare un altro agente = scrivere un adapter analogo) |
| [`@harness/llm-gateway`](packages/llm-gateway) | Proxy Anthropic/OpenAI-compatibile: le API key dei provider non toccano mai i client |
| [`@harness/agent-client`](packages/agent-client) | CLI del client gestito: enrollment, sync, avvio di `pi` con l'adapter fleet |

## Proprietà di sicurezza

- **Sandbox obbligatoria (confine reale)**: PI non ha sandbox propria; il confine di sicurezza è l'isolamento OS. La policy di default rifiuta l'esecuzione fuori dall'ambiente contenuto sanzionato (marker in `deploy/Dockerfile.agent`). Vedi il [modello di minaccia](docs/threat-model.md).
- **Config firmata, fail-closed e anti-rollback**: i client applicano solo bundle firmati Ed25519 con chiave pinnata; bundle scaduto/invalido ⇒ agente bloccato; una `configVersion` inferiore a quella già vista viene rifiutata (niente downgrade del kill switch).
- **Default-deny + analizzatore bash argv-aware**: tool sconosciuti negati, filesystem limitato alla workspace (con `realpath`), e un tokenizer shell che blocca gli eval inline (`node -e`, `python -c`, `awk system()`, `find -exec`, wrapper). Difesa in profondità, non confine anti-esecuzione.
- **Zero segreti sui client**: inferenza via gateway con introspezione dei device token; revoca e kill switch si propagano anche all'inferenza.
- **Audit completo e tamper-evident**: ogni decisione di policy, redaction e comando utente è tracciata e centralizzata in log a catena di hash (manomissioni sempre rilevabili, `harness-cp verify-audit`); audit amministrativo separato per le modifiche di config.
- **Ciclo di vita dei segreti**: token amministrativi con scadenza e revoca, rotazione automatica dei device token ogni 30 giorni, TLS nativo con HSTS su control plane e gateway.
- **Identità forte**: autenticazione admin via **OIDC/JWT** (RS256/ES256) oltre ai token statici; binding dei device al **certificato client mTLS** applicato sia sul control plane sia sul **gateway LLM** (un token rubato è inutile senza la chiave privata).
- **Chiavi private cifrate a riposo**: le chiavi di firma sono sigillate con envelope encryption AES-256-GCM (KEK da `HARNESS_SIGNING_KEK`, obbligatoria con Postgres) — mai in chiaro su disco o in database.
- **Rotazione della chiave di firma senza re-enrollment**: procedura a tre fasi (add → promote → retire) con cross-firma; le chiavi valide viaggiano nei bundle e i client le apprendono prima del cambio.
- **Non-ripudiabilità dell'audit**: export di un **anchor firmato** con le teste delle catene, ancorabile su storage WORM esterno.
- **Supply chain minima**: zero dipendenze runtime esterne nel core (solo built-in Node); Postgres è un backend di stato **opzionale** per flotte grandi (`DATABASE_URL`, locking ottimistico). Install con `--ignore-scripts`, CI con audit.
- **Sandbox obbligatoria**: PI non ha sandbox propria; il client va eseguito in container (`deploy/Dockerfile.agent`). La policy sui tool è defense-in-depth, non il confine di sicurezza.

## Quick start

**Un comando (Docker):** Postgres + control plane + UI su http://localhost:8787, con auto-seeding delle credenziali (stampate nei log):

```bash
docker compose -f deploy/docker-compose.yml up --build
# Gateway LLM opzionale (richiede una chiave provider):
ANTHROPIC_API_KEY=sk-... docker compose -f deploy/docker-compose.yml --profile gateway up --build
```

**Esempio end-to-end senza PI** — un agente finto arruolato che passa dal motore di enforcement (dimostra il disaccoppiamento):

```bash
npm run example:mock-agent
```

**Sviluppo locale:**

```bash
npm ci --ignore-scripts && npm run build && npm test
npm run test:pg          # test inclusi gli adapter Postgres (Postgres effimero via Docker)

# Control plane + UI su http://localhost:8787
node packages/control-plane/dist/cli.js init      # file store locale
node packages/control-plane/dist/cli.js seed      # oppure: bootstrap admin + enroll + gateway token
node packages/control-plane/dist/cli.js serve

# Client (dalla UI o da `seed`: genera un token di enrollment)
node packages/agent-client/dist/cli.js enroll --url http://localhost:8787 --token enr_...
node packages/agent-client/dist/cli.js run
```

Osservabilità: `GET /metrics` (Prometheus) e `GET /readyz` (readiness reale) su control plane e gateway.

## Documentazione

- [Modello di minaccia](docs/threat-model.md) — avversari, confini di fiducia, garanzie e non-garanzie
- [Analisi di PI e architettura](docs/analisi-pi-e-architettura.md)
- [Guida operativa](docs/guida-operativa.md) — deploy, enrollment, operazioni di sicurezza, limiti noti
