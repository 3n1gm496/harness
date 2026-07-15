# Changelog

Tutte le modifiche rilevanti di questo progetto sono documentate qui. Il
formato segue [Keep a Changelog](https://keepachangelog.com/it/1.1.0/); i
pacchetti sono privati (uso interno) e non seguono ancora Semantic
Versioning pubblico — la versione `0.1.0` copre l'intero sviluppo fino a oggi.

## [Unreleased]

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

### Fixed

- Trust-on-first-use del binding certificato disabilitato di default
  (richiede l'opt-in esplicito `allowCertTofu`).
- Rimozione della facciata duplicata e di un private class member morto in
  un test di `enforcement-core` (rilievi Biome, non solo soppressi).
