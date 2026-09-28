# Security

## Reporting a vulnerability

Email <security@verax-ai.com>, or use GitHub's private vulnerability
reporting on this repository. Please do not open a public issue for
something that is exploitable; everything else is welcome in the tracker.

Useful in a report: the commit you tested, the platform and Node version,
what you did, and what you expected instead. A failing command is worth
more than a paragraph.

There is no PGP key for this address.

## What you can expect

Reports are handled under coordinated disclosure: 90 days from the first
acknowledged receipt, or until a fix is published, whichever comes first.
There is no rota. The one bounty is below. The mailbox is read; silence
after an acknowledgement is a bug in the process, not a policy.

## Break it, and we pay

Each valid report gets USD 100 and the reporter's name in the release notes
and in this file, unless you ask to stay anonymous. The budget is USD 500
in total. When it is spent, the offer ends and this section says so.

A report is valid when, against Verax 0.4.0 or later installed with
`verax install` as the README describes and running the default policy, a
user who is not an administrator (the account the agent runs as) can do one
of these:

- get the gate to allow a call that its policy refuses;
- run a tool call that leaves no decision record;
- change the service's code, keys or ledger.

Not covered: anything that needs an administrator or root account; an
elevated terminal the operator leaves open to the agent; local mode
(`verax init --local`), which is not a boundary; `verax desktop`, which is
not in 0.4.0; denial of service; and the issues already listed as known in
the release notes of the version you tested.

Report privately, with steps that reproduce on a clean machine. The first
valid report of an issue is the one that counts. Payment is arranged with
you once the issue is confirmed.

### Thanks

No valid report yet.

## Scope

In scope: the published packages under `@verax-ai/*` and the
decision-record path that wraps Cedulon. The panel is in scope once it
ships.

Out of scope: a compromise of the operating system that hosts the body.
That limit is stated in `docs/THREAT_MODEL.md`.
