# `@harness/agent-client`

CLI del client gestito (bin `harness-agent`): arruola il device sul control
plane, sincronizza la configurazione firmata e lancia l'agente con il motore
di enforcement agganciato.

```bash
harness-agent enroll --url https://cp.azienda.it --token enr_... --name workstation-42
harness-agent status   # stato e versione config
harness-agent sync     # scarica il bundle firmato e applica i settings gestiti
harness-agent run      # sync + avvio di pi con l'estensione fleet caricata
```

Dipende direttamente da `@harness/enforcement-core` (agent-agnostic):
`@harness/fleet-extension` (l'adapter PI) è solo una devDependency, risolta
a runtime dal solo comando `run` — `enroll`/`sync`/`status`/`rotate-token`
non la richiedono affatto.

L'enrollment scrive `~/.harness/agent.json` (0600) con l'identità del device
e la chiave pubblica di firma pinnata; il device token ruota automaticamente
ogni 30 giorni. Vedi la
[guida operativa](../../docs/guida-operativa.md#4-client-gestito) per il
comportamento a runtime completo.
