# Contributing to Verax

Thank you for looking. Verax is the body an agent asks before it acts: an MCP
server that gates tool calls and keeps a signed ledger on the machine it runs
on. Start with [See it run](README.md#see-it-run) and
[docs/STATUS.md](docs/STATUS.md), which says what is released, what is not,
and what stays unproven.

## Security reports first

Do not open a public issue for something that is exploitable. Use
[SECURITY.md](SECURITY.md): email or GitHub's private vulnerability reporting.
A valid report of a way for the agent's account to get a refused call allowed,
run a call with no decision record, or change the service's code, keys or
ledger is paid as described there.

## Set up

Node 22.6 or newer.

```sh
npm ci
npm test            # guards, typecheck, build, unit and cost suites, panel
npm run pack:smoke  # pack the three packages and install them elsewhere
```

`npm test` runs, in order: `guard:crlf`, `guard:claims`, `build:dist`, `build`
(the TypeScript check), `test:unit`, and the panel's tests. CI runs the suite
as a non-root user on Linux and again on Windows; a pull request is expected
to pass the same suite locally first.

## What helps most

- **A run on a platform we have not checked.** [docs/PLATFORMS.md](docs/PLATFORMS.md)
  lists only the CI runners. If you try `npx @verax-ai/body demo`, then
  `verax init --local`, `verax serve`, one tool call and `verax verify` on
  another platform, open a *Platform report* issue with what you ran and
  what it printed.
- **A verifier that is not ours.** The ledger can be read back without the
  body ([Read the ledger back without us](README.md#read-the-ledger-back-without-us)).
  A second implementation in another language is the strongest check of that
  claim.
- **A failing command.** A bug report with the command, the output and the
  version (`verax --version`) is worth more than a paragraph.
- **Documentation that does not match what the program does.** Quote the
  sentence and the output that contradicts it.

## Pull requests

- One change per pull request, with a test that fails before it and passes
  after it. Say in the description which test that is.
- If the change moves a row of [docs/STATUS.md](docs/STATUS.md) (something
  becomes released, or a limit goes away), update that row in the same
  pull request.
- `guard:claims` rejects a short list of certainty phrases in `README.md` and
  `docs/`. Say what the code does and what it does not; STATUS states what is
  unproven.
- Match the surrounding code. Comments explain why, not what.
- Commit messages say what changed and why, in plain sentences.

Releases are cut from the Actions tab by a maintainer; nothing is published
on push.

## License

Apache-2.0. Contributions are accepted under the same license.
