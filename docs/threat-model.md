# Modello di minaccia

Questo documento definisce, senza ambiguità, **contro chi e cosa** l'harness
protegge, quali sono i confini di fiducia e quali garanzie ogni componente
offre — e, altrettanto importante, quali **non** offre. Va letto prima di
mettere il sistema in produzione: molti controlli sono difesa in profondità,
non barriere assolute, e trattarli come tali è pericoloso.

## Confine di fiducia primario

**Il confine di sicurezza reale è l'isolamento del sistema operativo (la
sandbox): container non privilegiato, micro-VM o sandbox policy-controlled.**
Tutto ciò che l'harness fa a livello applicativo (policy sui tool, allowlist
bash, redaction) è **difesa in profondità dentro** quel confine, non il confine
stesso.

Per questo la sandbox è **obbligatoria**: la policy di default
(`sandbox.required = true`) fa sì che l'agente si rifiuti di operare se non
rileva il marker dell'ambiente contenuto sanzionato (vedi P0.1 e
`deploy/Dockerfile.agent`).

## Avversari nel modello (in scope)

| Avversario | Descrizione | Mitigazioni |
|---|---|---|
| **Agente / LLM ostile o prompt-injected** | Il modello, indotto da contenuti di repo non fidati (`AGENTS.md`, commenti, output di build), tenta di eseguire azioni non volute. | Sandbox (confine); policy default-deny su tool/bash/path; analizzatore bash che blocca gli eval inline; redaction; audit. |
| **Repository non fidato** | File del progetto che tentano prompt injection o percorsi/symlink malevoli. | `realpath` sui path, workspace-only, project-trust `never` imposto. |
| **Rete / MITM tra client e piattaforma** | Intercettazione o manomissione del traffico di config/audit/inferenza. | TLS+HSTS; bundle firmati Ed25519 con chiave pinnata; anti-rollback monotòno; mTLS opzionale del device. |
| **Furto del solo token del device** | Un token device esfiltrato (senza la chiave privata del certificato). | Binding mTLS: control plane **e** gateway LLM richiedono il certificato legato; revoca e kill switch. |
| **Manomissione dei log di audit a posteriori** | Chi ha accesso in scrittura ai file di audit prova ad alterarli. | Hash chain per-stream; anchor firmato ancorabile su WORM esterno. |
| **Amministratore malintenzionato o compromesso** | Un admin che abusa dei privilegi. | RBAC (admin/operator/viewer); token con scadenza e revoca; audit amministrativo separato; OIDC con MFA/offboarding dall'IdP. |

## Fuori dal modello (out of scope)

Questi attori/scenari **non** sono contrastati dal design e non vanno
considerati coperti:

- **Utente/endpoint fisicamente ostile con privilegi locali.** Chi controlla la
  macchina client come root può: non caricare l'estensione fleet, usare `pi`
  direttamente, leggere il token da `~/.harness/agent.json`, o **falsificare il
  marker della sandbox**. Il marker è una barriera contro esecuzioni
  *accidentali* non sandboxate, non contro un attore locale privilegiato. La
  mitigazione operativa è non dare all'utente privilegi di root nell'host che
  esegue il container, e usare immagini/sandbox gestite centralmente.
- **Onestà dell'audit prodotto dal client.** Le decisioni di policy e i comandi
  sono generati e spediti dal client: un client modificato può ometterli o
  falsificarli. L'audit documenta un client **cooperante**; la hash chain
  garantisce solo che *la piattaforma* non alteri i log dopo la ricezione.
- **Contenuti malevoli prodotti dal modello** (output testuale dannoso): fuori
  scope, come per qualsiasi coding-agent.
- **Compromissione del control plane, del gateway o della loro infrastruttura**
  host (fuori dallo scope applicativo: spetta all'hardening infrastrutturale).
- **Sicurezza delle dipendenze upstream di PI** oltre l'hardening di supply
  chain già adottato.

## Garanzie e non-garanzie per componente

### Estensione fleet (client)
- **Garantisce**: applicazione della policy firmata a ogni `tool_call`/`user_bash`
  entro il processo PI; fail-closed su config assente/scaduta/rollback o sandbox
  assente; redaction dei segreti nei risultati.
- **Non garantisce**: contenimento dell'esecuzione. Un comando consentito
  (`node file.js`, `npm test`, `make`) esegue codice arbitrario del repo: lo
  contiene **solo** la sandbox. L'analizzatore bash chiude i bypass *banali*
  (`node -e`, `awk system()`, `find -exec`, wrapper), non l'esecuzione in sé.

### Policy engine / analizzatore bash
- **Garantisce**: default-deny sui tool sconosciuti; blocco degli eval inline e
  dei costrutti di esecuzione indiretta; workspace-only con risoluzione dei
  symlink.
- **Non garantisce**: che un interprete consentito non esegua codice; che il
  parsing copra ogni sintassi shell (in ambiguità → deny). Non è un confine
  anti-esecuzione.

### Control plane
- **Garantisce**: distribuzione di config firmate e versionate; RBAC; kill
  switch a tre livelli; audit tamper-evident; introspezione con binding mTLS.
- **Non garantisce**: comportamento onesto di un client compromesso; sicurezza
  se l'host è compromesso.

### Gateway LLM
- **Garantisce**: le API key dei provider restano server-side; autenticazione
  del device con introspezione **e** binding mTLS; rate limit per device (a
  finestra scorrevole); allowlist degli endpoint di inferenza.
- **Nota sul rate limit multi-istanza**: il conteggio è condiviso tra le istanze
  del gateway solo se è configurato `DATABASE_URL` (stessa `cp_rate_buckets` del
  control plane). Senza, il limite è **per-istanza**: con N istanze la soglia
  effettiva è N× quella dichiarata. Un deploy scalato orizzontalmente deve
  impostare `DATABASE_URL` (o accettare esplicitamente il limite per-istanza).
- **Non garantisce**: protezione se il device token **e** la chiave privata del
  certificato sono entrambi compromessi.

## Requisiti di deployment (non opzionali)

1. Eseguire il client **solo** dentro l'immagine/sandbox ufficiale
   (`deploy/Dockerfile.agent`), con egress ristretto a control plane e gateway.
2. Non concedere privilegi di root nell'host agli utenti che eseguono i client.
3. Impostare `HARNESS_SIGNING_KEK` (obbligatoria con Postgres) e servire tutto in
   TLS.
4. Usare mTLS per i device ad alto rischio (binding all'enrollment, non TOFU).
5. Esportare periodicamente l'anchor di audit su storage WORM esterno.
6. **Far eseguire un penetration test esterno** prima del rilascio: nessuna
   autovalutazione sostituisce un red team indipendente.
