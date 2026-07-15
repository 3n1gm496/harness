# `@harness/fleet-extension`

Adapter [PI Coding Agent](https://pi.dev/) per `@harness/enforcement-core`:
traduce la Extension API di PI (`pi.on(...)`) sulle primitive neutre del
motore (`AgentAdapter`). È l'unico pacchetto che conosce PI — tutta la
logica di policy, redaction, audit e sandbox vive nel motore, agent-agnostic.

```ts
export default async function fleetExtension(pi: ExtensionAPI): Promise<void> {
	await bootstrapEnforcement(new PiAdapter(pi));
}
```

Caricata su ogni client gestito con `pi -e <percorso>/dist/index.js`
(`@harness/agent-client run` la risolve e la passa a `pi` automaticamente).

Per integrare un coding agent diverso da PI, non serve toccare questo
pacchetto: si scrive un adapter analogo per il motore. Vedi la guida
["scrivere un adapter"](../enforcement-core/README.md) in
`@harness/enforcement-core`, con `examples/mock-agent` come riferimento
concreto di un adapter per un agente che non è PI.

Lo shim dei tipi della Extension API (`src/pi-types.ts`) è allineato a una
versione pinnata di PI (`ARG PI_CODING_AGENT_VERSION` in
`deploy/Dockerfile.agent`): quando si aggiorna quella versione, riverificare
lo shim prima del rollout.
