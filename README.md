# Harness

Harness AI aziendale basato su [PI Coding Agent](https://pi.dev/), con piattaforma amministrativa per la gestione centralizzata di configurazioni e policy sui client, pensato per ambienti di produzione.

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│  CLIENT (sandbox Docker)    │  HTTPS  │  CONTROL PLANE               │
│  pi + @harness/fleet-ext    │◄───────►│  policy · config firmata     │
│  policy enforcement         │         │  kill switch · audit · RBAC  │
│  redaction · audit shipper  │         │  UI amministrativa           │
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
| [`@harness/shared`](packages/shared) | Tipi, firma Ed25519 dei bundle di config, policy engine default-deny, redaction dei segreti |
| [`@harness/control-plane`](packages/control-plane) | Piattaforma amministrativa: API, storage, RBAC, kill switch, audit, UI web |
| [`@harness/fleet-extension`](packages/fleet-extension) | Estensione PI caricata su ogni client: enforcement su `tool_call`, redaction su `tool_result`, config sync fail-closed, audit |
| [`@harness/llm-gateway`](packages/llm-gateway) | Proxy Anthropic/OpenAI-compatibile: le API key dei provider non toccano mai i client |
| [`@harness/agent-client`](packages/agent-client) | CLI del client gestito: enrollment, sync, avvio di `pi` con l'estensione fleet |

## Proprietà di sicurezza

- **Config firmata e fail-closed**: i client applicano solo bundle firmati Ed25519 con chiave pinnata all'enrollment; bundle scaduto o firma invalida ⇒ agente bloccato.
- **Default-deny**: tool sconosciuti negati, bash in allowlist per segmenti, filesystem limitato alla workspace.
- **Zero segreti sui client**: inferenza via gateway con introspezione dei device token; revoca e kill switch si propagano anche all'inferenza.
- **Audit completo e tamper-evident**: ogni decisione di policy, redaction e comando utente è tracciata e centralizzata in log a catena di hash (manomissioni sempre rilevabili, `harness-cp verify-audit`); audit amministrativo separato per le modifiche di config.
- **Ciclo di vita dei segreti**: token amministrativi con scadenza e revoca, rotazione automatica dei device token ogni 30 giorni, TLS nativo con HSTS su control plane e gateway.
- **Supply chain minima**: zero dipendenze runtime esterne (solo built-in Node), install con `--ignore-scripts`, CI con audit.
- **Sandbox obbligatoria**: PI non ha sandbox propria; il client va eseguito in container (`deploy/Dockerfile.agent`). La policy sui tool è defense-in-depth, non il confine di sicurezza.

## Quick start

```bash
npm ci --ignore-scripts && npm run build && npm test

# Control plane + UI su http://localhost:8787
node packages/control-plane/dist/cli.js init
node packages/control-plane/dist/cli.js serve

# Client (dalla UI: genera un token di enrollment)
node packages/agent-client/dist/cli.js enroll --url http://localhost:8787 --token enr_...
node packages/agent-client/dist/cli.js run
```

## Documentazione

- [Analisi di PI e architettura](docs/analisi-pi-e-architettura.md)
- [Guida operativa](docs/guida-operativa.md) — deploy, enrollment, operazioni di sicurezza, limiti noti
