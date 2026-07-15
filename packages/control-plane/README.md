# `@harness/control-plane`

Piattaforma amministrativa: enrollment dei device, config firmata per
gruppo/org, kill switch, RBAC (admin/operator/viewer), audit tamper-evident
centralizzato, UI web, osservabilità (`/metrics`, `/readyz`).

- **API** dichiarativa (`src/routes.ts` + `src/http-router.ts`): tabella di
  route con autenticazione risolta prima dell'handler.
- **Servizi di dominio** (`src/services/`): `AuthService`, `DeviceService`,
  `GroupService`, `OrgService`, `SigningKeyService`, `AuditService` —
  `ControlPlaneService` (`src/service.ts`) li compone, senza logica propria.
- **Storage pluggable** (`src/store.ts`, `src/state-store.ts`): file locale
  (default, zero dipendenze) o Postgres normalizzato con scritture mirate,
  sincronizzazione incrementale (LISTEN/NOTIFY) e migrazioni di schema
  versionate (`src/pg-migrations.ts`).
- **UI** amministrativa a file singolo (`public/index.html`, zero build
  frontend): dashboard, paginazione/ricerca/filtro server-side, editor di
  policy con diff e validazione.
- **CLI** (`src/cli.ts`, bin `harness-cp`): `init`, `serve`, `seed`,
  `verify-audit`, `export-audit-anchor`, `rekey`, `prune`.

```bash
node dist/cli.js init      # bootstrap: chiavi + primo token admin
node dist/cli.js serve     # avvia il server (UI su /, API su /api/*)
```

Vedi la [guida operativa](../../docs/guida-operativa.md) per deploy,
enrollment, retention e operazioni di sicurezza, e il
[modello di minaccia](../../docs/threat-model.md) per garanzie/confini.
