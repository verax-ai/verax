# Security

## Reporting a vulnerability

Email <security@verax-ai.com>. Please do not open a public issue for something
that is exploitable; everything else is welcome in the tracker.

Useful in a report: the commit you tested, the platform and Node version,
what you did, and what you expected instead. A failing command is worth
more than a paragraph.

There is no PGP key for this address.

## What you can expect

Reports are handled under coordinated disclosure: 90 days from the first
acknowledged receipt, or until a fix is published, whichever comes first.
There is no rota and no bounty. The mailbox is read; silence after an
acknowledgement is a bug in the process, not a policy.

## Scope

In scope: the packages under `@verax-ai/*` once they exist as more than
stubs, the panel once it serves a ledger, and the decision-record path
that wraps Cedulon.

Out of scope: a compromise of the operating system that hosts the body.
That limit is stated in `docs/THREAT_MODEL.md`.
