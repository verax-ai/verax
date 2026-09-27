# F27 fixes

## R15-3 desktop passkey sign-in

`verax desktop` now names browser-facing origins as `http://localhost:<port>`: the issuer URL, the panel URL, the redirect URI, and the body audience (so the token `aud` and `VERAX_AUDIENCE` agree). Sockets, readiness lines, `/healthz`, and the panel proxy stay on `127.0.0.1`. The dev issuer gets `VERAX_RP_ID=localhost` and `VERAX_RP_ORIGINS` set to the issuer origin (where `/authorize` and `/enroll` call WebAuthn) unless those are already set. The body gets `VERAX_ALLOWED_ORIGINS` including `http://localhost:<panelPort>`. Vite preview still binds `127.0.0.1` and lists `localhost` in `preview.allowedHosts`.

## R19-2 successful effect recorded as `:threw`

The tool call and the effect-row write are separate. If the tool returns and the effect write throws, the proxy does not append `<tool>:threw`, leaves the in-flight mark, and answers `effect-unrecorded:<ref>`. A tool that itself throws is unchanged.

## R18-2 add-file beside node.exe

For a Windows executable, `trustTargets` judges the immediate parent with the object mask, so add-file and add-subdirectory count. Ancestors above that parent keep the ancestor mask. Directories, including the Verax code directories, are unchanged.

## R17-2 Windows approval path

Docs and the Windows lines from `successText`, `unreadableSentence` (approve), and the approve help name the panel with a passkey first. An elevated CLI `approve` remains a fallback from a separate administrator account.

## R16-9 witness checkpoint signature

The existing PEM mismatch case stays. A second case carries the listen key's PEM and a COSE signature from another key; it is refused with `witness-key-mismatch` and no checkpoint row.
