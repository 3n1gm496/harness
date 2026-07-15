# `@harness/shared`

Fondamenta condivise dagli altri pacchetti, senza dipendenze runtime
esterne (solo built-in di Node):

- **Firma/verifica** dei bundle di configurazione e dei token (Ed25519,
  JWS-like compatto) — `signing.ts`.
- **Policy engine** default-deny: risoluzione org → gruppo → device,
  allowlist bash argv-aware, limiti filesystem — `policy.ts`, `defaults.ts`,
  `bash-parse.ts`.
- **Redaction** dei segreti nei risultati dei tool — `redaction.ts`.
- **Envelope encryption** (AES-256-GCM) delle chiavi di firma a riposo —
  `keystore.ts`.
- **Audit tamper-evident**: hash chain con genesis configurabile (per
  verificare un segmento residuo dopo il pruning) — `audit-chain.ts`.
- **JWT/JWKS** per l'autenticazione admin via OIDC — `jwt.ts`.
- Logger strutturato e registro di metriche Prometheus — `logger.ts`,
  `metrics.ts`.

Consumato da tutti gli altri pacchetti del monorepo; non ha un proprio
eseguibile. Vedi il [README della radice](../../README.md) per l'architettura
complessiva.
