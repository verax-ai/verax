# Remote approval — design, partly built, not released

Status: not in a release. The door's listener, the passkey sign-in, the list
of what is waiting, the approval, halt and enrolment with a pairing code are
in the tree, off unless `VERAX_OPERATOR_DOOR` names an origin. The install
flag and the page are not built.

The capability matrix says there is no remote approver, and on a released
install that is true: a held call is approved with `verax approve` at the
machine. This document says what is already there, what stops it from being
used away from the machine, and what would have to be built.

## What exists

- `POST /api/approve` resolves a held call over HTTP for a session that
  carries `verax:approve`. It takes the `ref` and the `requestHash` the
  operator was looking at; if what is waiting is no longer that request the
  answer is `409 stale` and nothing is approved.
- `GET /api/approve/challenge?ref=…` answers a WebAuthn challenge that is the
  hash of a document bound to that one defer record. Once an operator is
  registered, an approval without a valid assertion over that challenge is
  refused, so a stolen session token does not approve, and an assertion made
  for one request does not fit another.
- The approver written into the signed record is the session's subject, not
  the machine's login name, and `verax verify` checks the assertion again
  against the operator's public key without asking the body.
- The body accepts a bind off loopback only with `VERAX_TLS_TERMINATED=1`,
  and the passkey relying party is read from `VERAX_RP_ID` and
  `VERAX_RP_ORIGINS`.
- The panel has the approve ceremony: it asks for the passkey and posts the
  assertion with the approval.
- `verax operator enroll` prints an eight-digit pairing code that lasts five
  minutes and five attempts; the passkey is created on the device that types
  it.

## What stops it

1. **An installed body is in local mode.** `verax install` sets the service
   up with `VERAX_JWKS_FILE`. In local mode the body does not honour
   `verax:approve` or `verax:audit` over HTTP at all
   (`local-mode-operator-scope`), because whoever can read the key file can
   mint those scopes; and `VERAX_JWKS_FILE` needs a loopback bind.
2. **There is no operator sign-in in a release.** The only thing that turns a
   passkey into a `verax:approve` session is the development issuer, which
   refuses `NODE_ENV=production`. `verax desktop`, which supervises that
   issuer with the body and the panel, answers `desktop-not-released`.
3. **A phone cannot reach it.** The released paths listen on loopback, and
   the launcher's relying party is `localhost`. WebAuthn does not take an IP
   address as a relying party and wants HTTPS anywhere but `localhost`.

So the signature, the binding to the request and the record are built. What
is missing is a way to sign in as the operator on an installed body, and a
way to reach that from another device.

## Proposal

1. **An operator door in the service.** The installed service gains a second
   listener, off by default, that serves only the operator's paths: the
   passkey sign-in, the list of what is waiting, the approve challenge and
   the approval, and halt. It never serves `/mcp`. It is turned on with
   `verax install --operator-door <https origin>`, which records that origin
   as the relying party and nothing else.
2. **Sign-in is a passkey and nothing else.** The door issues a short
   session (minutes, one device) after a WebAuthn assertion from a credential
   in `operator-credentials.json`. There is no password and no recovery
   link. The session is a random value the running body remembers and
   nothing else: no key on disk signs one, so nothing the agent's local
   issuer key signs is ever a session, and local mode's refusal of operator
   scopes stays as it is. A restart of the body ends every session.
3. **Enrolment stays at the machine.** A credential is added only with a
   pairing code from an elevated `verax operator enroll`, as today. A phone
   cannot enrol itself, and the agent's account cannot ask for a code. The
   door takes the code on `POST /api/enroll/options` and `POST /api/enroll`,
   and those two are the only paths open before an operator exists.
   A code buys one enrolment, five wrong tries end it wherever they arrive,
   and enrolling opens no session. The door reads the new credential itself:
   made for its challenge, its origin and its relying party, with the user
   verified, a key it can verify with, and no byte of the authenticator data
   left unexplained.
4. **Each approval still needs its own assertion.** The session lets the
   operator see what is waiting. Approving one request asks the passkey again
   over that request's challenge. The screen shows what the CLI shows: tool,
   payee, amount, currency, reference, and the start of the request hash.
5. **Reaching it is the operator's own endpoint.** The door listens on
   loopback. The operator puts their own TLS endpoint in front of it (a
   reverse proxy on the host, or a tunnel) and names that origin at install. Verax does not run a relay: an approval
   summary names payees and amounts, and a relay of ours would see every one.
6. **No notification in the first step.** The phone learns of a held call
   when the operator opens the page. A push would be a new outbound path from
   the body and gets its own design.

## What this does not do

- It does not approve without a person. There is still no auto-approve path;
  a budget an operator signs once is a separate design
  (`spend-mandate.md`, not written).
- It does not hide the summaries from whoever terminates TLS. With a tunnel
  that ends at the provider, the provider can read them. An operator who
  minds runs the endpoint on the host.
- It does not protect against the administrator of the host, who can read
  the body's memory, add a credential, or approve from the CLI.
- It does not reach a body that is off or cut from the network. The call
  stays held.
- It does not limit connections or request rate. A sign-in body nobody has
  vouched for is at most 16 KiB, at most 32 are read at once, and one that
  takes longer than five seconds is dropped. A caller who keeps those 32
  busy can still delay a sign-in; a limit on that belongs at the operator's
  TLS endpoint.
- It does not check what kind of device holds a passkey. Enrolment asks for
  no attestation and refuses an answer that carries one; the pairing code
  from the machine is what vouches for the device.
- It does not keep a pairing code open against a caller who can reach the
  door. Five wrong tries end the code, the operator asks for another, and a
  caller who keeps guessing can keep enrolment from happening. Nobody is
  enrolled that way; a limit on it belongs at the operator's TLS endpoint.
- It does not make a lost phone harmless by itself: the passkey's own user
  verification is what stands between a thief and an approval, and
  `verax operator` needs a way to remove one credential.

## What it would change in the claims

- STATUS, "Operator approval": "no remote approver" becomes "a remote
  approval needs the operator door, an enrolled passkey and an assertion per
  request".
- The site's capability card says there is no remote approval, and the first
  animated episode shows one on a phone. Both would be true together.

## Tests it would need

- An installed body with the door off answers nothing on the door's port,
  and `local-mode-operator-scope` still refuses a `verax:approve` token
  signed by the local issuer key.
- A session from the door reads the waiting list and cannot approve without
  an assertion; an assertion for request A does not approve request B; a
  replayed assertion is refused.
- The door refuses `/mcp` and every path outside its list.
- An origin other than the one named at install fails the WebAuthn origin
  check.
- A pairing code is refused after five wrong attempts and after five minutes,
  and enrolment over the door without a code is refused.
- The agent's account cannot read the door's session key or the credentials
  file on any of the three platforms (install-e2e).
- `verax verify` checks an approval made through the door with no body
  running, and names the approver.
- A red-team round on the door before it is released: it is the first
  listener meant to face a network.
