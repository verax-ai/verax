# @verax-ai/inventory

The declared roster document a Verax body serves and a Verax galaxy draws:
which agents exist, which group each belongs to, when each last ran, and
which pulses the roster does not name. This package carries the types and one
strict parser, and nothing else, so a body can read the document without
pulling in the galaxy's three.js and React.

Part of [Verax](https://github.com/verax-ai/verax) by
[VERAX Teknoloji](https://verax-ai.com). What the code carries and what stays
unproven is stated in
[`docs/STATUS.md`](https://github.com/verax-ai/verax/blob/main/docs/STATUS.md).

## Install

```sh
npm install @verax-ai/inventory
```

Node 22.6 or newer. No dependencies.

## Use

```js
import { parseInventory } from "@verax-ai/inventory";

const parsed = parseInventory(JSON.parse(text));
if (parsed.ok) {
  console.log(parsed.value.agents.length, "agents from", parsed.value.source);
} else {
  console.error(parsed.reason);
}
```

`parseInventory` is strict: a single broken field fails the whole document,
and nothing half-filled is returned. The document looks like this:

```json
{
  "takenAtMs": 1757980800000,
  "source": "cron-scan",
  "groups": [{ "id": "billing", "label": "Billing" }],
  "agents": [
    {
      "id": "invoice-bot",
      "label": "Invoice bot",
      "groupId": "billing",
      "kind": "cron",
      "lastRunMs": 1757980000000,
      "state": "live"
    }
  ],
  "orphans": []
}
```

An agent's `state` is one of `live`, `stale`, `failed`, `unmonitored`,
`retired` or `unknown`, and `lastRunMs` is `null` when the source does not
know. An orphan is a pulse the roster does not name: the record and the fact
have come apart.

## License

Apache-2.0.
