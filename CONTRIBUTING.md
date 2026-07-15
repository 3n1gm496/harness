# Contribuire

Repository privato, uso interno (vedi [LICENSE](LICENSE)). Questa guida
copre come costruire, testare e proporre modifiche.

## Setup

```bash
npm ci --ignore-scripts
npm run build
npm test
npm run lint
```

Requisiti: Node.js ≥ 22. `npm ci --ignore-scripts` evita di eseguire gli
script di lifecycle delle dipendenze (igiene di supply chain di base).

Per esercitare anche l'adapter Postgres (altrimenti i suoi test si
auto-saltano):

```bash
npm run test:pg   # Postgres effimero via Docker, oppure imposta HARNESS_TEST_PG_URL
```

## Struttura del monorepo

Workspace npm sotto `packages/*`; ogni pacchetto ha un proprio `README.md`
con lo scopo specifico. Punto di partenza: [`README.md`](README.md) (tabella
pacchetti, architettura, quick start) e [`docs/guida-operativa.md`](docs/guida-operativa.md)
(deploy, operazioni di sicurezza, limiti noti).

## Stile del codice

- **Tab** per l'indentazione, **doppi apici** per le stringhe — non è una
  preferenza personale, è quello che [Biome](https://biomejs.dev/) impone
  (`biome.json` in radice). `npm run lint` verifica, `npm run lint:fix`
  applica i fix sicuri, `npm run format` riformatta soltanto.
- Commenti solo dove il *perché* non è ovvio dal codice (un vincolo nascosto,
  un invariante, un workaround) — non per spiegare *cosa* fa il codice.
- I commenti e i messaggi di commit di questo repository sono
  prevalentemente in italiano: mantieni la coerenza nelle aree che tocchi.
- Zero dipendenze runtime esterne nel core (`@harness/shared`,
  `@harness/enforcement-core`): solo i built-in di Node. `pg` è una
  dipendenza opzionale del control plane, non del core.

## Test

- `node:test` ovunque (nessun runner esterno, incluso per il test UI in
  browser: `playwright-core`, non `@playwright/test`).
- I test che richiedono un backend esterno (Postgres, un Chromium
  eseguibile) si auto-saltano quando quel backend non è disponibile
  (`{ skip: !PG_URL }` / `{ skip: !chromiumPath }`) — non renderli falliti
  di default, non renderli silenziosamente sempre saltati in CI.
- Un bug fix richiede un test che lo avrebbe colto; una feature richiede un
  test che ne verifichi il comportamento osservabile (risposta HTTP, stato
  persistito), non l'implementazione interna.

## Prima di proporre una modifica

```bash
npm run build && npm run lint && npm test
```

Per modifiche a `packages/control-plane/public/index.html`, verifica anche
visivamente: il test `packages/control-plane/src/test/ui.test.ts` copre i
flussi principali, ma un controllo manuale (`node packages/control-plane/dist/cli.js serve`
+ browser) resta utile per cambi di layout/interazione.

## Commit e PR

- Messaggi di commit descrittivi: cosa cambia e perché, non solo cosa.
- Non introdurre segreti (chiavi, token) nei commit — nemmeno in file di
  esempio o fixture di test; usa placeholder chiaramente non validi.
- Le modifiche a superfici di sicurezza (autenticazione, policy default,
  crittografia) vanno accompagnate da un aggiornamento del
  [modello di minaccia](docs/threat-model.md) se cambiano garanzie o confini
  di fiducia.
