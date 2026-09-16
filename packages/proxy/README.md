# @verax-ai/proxy

The decision proxy behind Verax. Every tool call goes through a policy that
denies what it does not name, leaves a signed decision record before the
call runs, and an effect row after it did. The records live in a ledger on
local disk, and `explain` reads that ledger back and reports what it finds,
including a record whose effect does not match it.

Part of [Verax](https://github.com/verax-ai/verax) by
[VERAX Teknoloji](https://verax-ai.com). Most callers want
[`@verax-ai/body`](https://www.npmjs.com/package/@verax-ai/body), the MCP
server built on this package. What the code carries and what stays unproven
is stated in
[`docs/STATUS.md`](https://github.com/verax-ai/verax/blob/main/docs/STATUS.md).

## Install

```sh
npm install @verax-ai/proxy
```

Node 22.6 or newer. Decision records use the Cedulon record format
(`@cedulon/core`, `@cedulon/audit`).

## Use

```js
import { createProxy, loadPolicy, FileLedger, explain } from "@verax-ai/proxy";
```

- `loadPolicy` reads a policy file. `policy/default.json` in this package is
  the one the body starts from.
- `createProxy` wraps tool functions: each call is decided and recorded, then
  run or refused.
- `FileLedger` and `MemoryLedger` hold the records, one `FileLedger` per
  directory.
- `explain` reads a ledger and reports the chain, its signatures and its
  findings.
- `approvePending`, `reconcile` and `parseCardCsv` are what the body's
  `approve` and `reconcile` commands call.

The exports map is the whole public surface; deep imports are not in it.

## License

Apache-2.0.
