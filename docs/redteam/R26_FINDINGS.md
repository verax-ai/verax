# R26 findings

Round R26 read the five areas merged to main after 0.4.8 and not yet released: the key custody check and the stale lock rule (#160, #164), the downstream `tools` list (#157), the unknown policy key refusal (#169), automatic anchoring with `--require-anchored` (#158), and signed start rows (#159). Each area was attacked at least four ways on a Windows host. Eleven findings, none high: six medium, five low. Thirty-eight other attacks held. Ten findings are fixed on main and one is answered by an option.

| id | severity | description | status |
| --- | --- | --- | --- |
| R26-1 | medium | A lock naming this pid with a start time in the future, or one that is not a finite number, was read as this process's own. After a clock step backwards the body answered `ledger-locked` and `verax unlock` answered `still-running`: the dead end #164 was merged to end. | fixed (#173) |
| R26-2 | medium | Two containers on one volume both run the body as PID 1. The second read the first one's lock as its own leftover, told the operator to run `verax unlock`, and unlock removed the lock of a running body. Proven by simulating the second PID namespace; Docker was not used. | fixed (#173) |
| R26-3 | medium | A `spend` block on a rule whose tool is not `spend` loaded without a word. It set no cap and stayed out of the policy hash; `dailyMax` inside it loaded although #169 refuses that key on the spend rule. | fixed (#176) |
| R26-4 | medium | `verax reconcile --channel card` took statement descriptors from the stored document for every rule. With R26-3, a card line was matched to an approved spend through a descriptor the policy hash did not cover. | fixed (#176) |
| R26-5 | low | `--require-anchored` counts the grace from the end the checkpoint itself states. A checkpoint signed with a window ending in 2100 and no receipt was exempt for good. Needs the witness key. | fixed (#175) |
| R26-6 | low | `verax verify` dropped an option it did not know. `--require-anchord` printed `VERIFIED` and exited 0 over a checkpoint with no receipt. | fixed (#172) |
| R26-7 | medium | With `v`, `prevStartHash` and `sig` removed from every row, `starts.jsonl` reads as a file from before signing: a three-day gap rewritten to one second verifies with exit 0. The output does say `unsigned (not verified)`. No key is needed. | option (#183) |
| R26-8 | low | The 64 KiB bound on a downstream tool counted UTF-16 units of three fields. A 180 KB description was attached and republished; megabytes in `outputSchema` or `title` were never measured. | fixed (#174) |
| R26-9 | medium | The MCP client ran a child's own `outputSchema` on the child's own result inside the body. A backtracking `pattern` held the body's event loop past the call's timeout: 7.9 s at 31 characters, about twice that per further character. | fixed (#177) |
| R26-10 | low | `key-custody` is `ok` for a record key the user owns but has denied itself; one `icacls /remove:d` or `chmod` gives read back. | fixed (#184) |
| R26-11 | low | A transparency service that answered JSON `null` made `registerCheckpoint` throw a TypeError; `verax anchor` ended on an exception. | fixed (#172) |

## Fixes

- R26-1, R26-2: a held lock is touched every 2 seconds and records that beat (`beatMs`) in the lock file. The body, `verax unlock` and `verax doctor` watch such a lock for five beats. One that moves is held, whatever pid it names; only a change is read, never a time. One that does not move is then judged by its pid and start time as before, and is stale only when that says so too. A start time that has not come yet, or one that is not a finite number, no longer counts as a live holder. A lock from 0.4.8 or earlier records no beat and is judged by its pid alone.
- R26-3: the parser refuses the block with `policy-rule-spend-not-spend-tool:<id>`. A snapshot already on disk is still read.
- R26-4: descriptors come from the parsed spend rule (`Policy.descriptorsByPayee`), so what decides a match is what the hash covers.
- R26-5: a window that ends more than a minute after the reader's clock is named `checkpoint-window-in-future <hash>`.
- R26-6: an option `verify` does not know is named and refused with exit 1; a second directory is refused too.
- R26-7: a stripped row cannot be told from one written before signing, so the default is unchanged: the file is counted, named `unsigned (not verified)`, and verifies. `verax verify --require-signed-starts` refuses it for a reader who knows the ledger was written signed: each unsigned row is `start-row-unsigned`, a ledger with no start row is `start-rows-missing`.
- R26-8: the bound is the UTF-8 byte length of the whole entry as the MCP client parsed it. A field the MCP tool shape does not know is dropped before the count and is not kept.
- R26-9: `tools/list` and `tools/call` are sent as plain requests, so no schema a child sends is compiled or run in the body. The same call returns in a few milliseconds.
- R26-10: when the open is refused, `doctor` reads who owns the file: the uid on POSIX, the owner SID on Windows. A key this user owns is a `fail`, an owner that cannot be read is a warning, and only a key the user neither opens nor owns is `ok`.
- R26-11: a `null` answer is refused as `wrong-receipt`, like `[]` and `{}`.
- Outside the round's five areas, in a released one: a top-level `egress` list with no rule carrying `egress: true` loaded and restricted nothing. The parser refuses a list beside an unmarked `message.send` rule with `policy-rule-egress-unmarked:<id>`, and a list no rule is marked for with `policy-egress-unused`; a snapshot already on disk is still read (#180).
- Beside the eleven, noted while fixing R26-8: the bound on a downstream tool was applied after the child's answer had been read and parsed. Measured afterwards: over HTTP nothing bounded one message (a 50 MiB `tools/call` answer was accepted); over stdio the MCP client's own 10 MiB read buffer already cut the child, without a name. One message is now at most 10 MiB on either transport and a larger one is `downstream-message-too-large` (#185).

Each fix carries the attack as a test under `tests/attack-r26-*.test.ts` that failed on main before the change.

## Found at the gate

- The first version of the lock fix judged a beating lock by movement alone. A live body whose event loop was held for more than five beats then lost its lock to `verax unlock`, which the pid check used to refuse. Stillness is now only the first half of the test.
- A still lock under a live pid is either a frozen body or a dead one whose pid another process now has. Nothing on disk tells them apart, and on main the second case could only be ended by deleting the lock by hand. `verax unlock` refuses it as `still-running` and names it `lock-not-beating`; `verax doctor` warns; `verax unlock --force` removes it and writes `reason: "not-beating"` to `unlocks.jsonl`. `--force` does not remove a lock that moves.
- The R26-9 test required a timer tick during the call. A call that now answers in 2 ms leaves no tick to count; the tick is still required when the call lasts.
- The first version of the `egress` fix asked only that some rule be marked. A list beside a marked `memory.get` rule and an unmarked `message.send` rule still loaded, and `message.send` still reached any host. The unmarked rule is now named and refused.
- With the list case closed, a `message.send` rule without the mark in a document with no list still reached any host, against the description the tool publishes. The mark is now required on that rule (`policy-rule-egress-unmarked:<id>`); a marked rule with no list reaches no host.
- Three existing tests wrote a lock naming their own pid by hand and expected it to be held. A first rule that called every such lock stale broke them; the rule was dropped, and the future start time is what decides.
- The first version of `--require-signed-starts` left a line that cannot be read as a warning. History replaced by one such line, with the body's next signed start chained on it, passed under the flag. The line is now `start-row-unreadable` and the ledger does not verify.
- The first version of the R26-10 fix compared the Windows owner with the user's own SID only. A key owned by a group the user's token holds enabled read as someone else's, and `key-custody` stayed `ok`. The owner is now held against the user and those groups, and output that names no owner or no user is unknown rather than someone else's.
- The first version of the message bound restarted its count at every empty line whenever the content type contained `text/event-stream`. An HTTP 500 labelled that way, and a JSON answer with that name in a content-type parameter, are read whole by the client: with empty lines inside them, 12 MiB passed. The count now restarts only for a successful answer whose media type is exactly `text/event-stream`.

## Open

Nothing from this round is open.

## Known limits

- A body in another container that is frozen for longer than five beats can still lose its lock to an operator there running `verax unlock` under a pid that reads as dead or as the caller's own. Its next append stops with `ledger-lost-lock`.
- Deciding that a lock is stale takes about 10 seconds. A live one is seen within a beat.
- The witness's listen file and the unreleased desktop launcher do not use the beat.
- Not exercised in this round: a Linux boot id, a real PID namespace, a stdio child, a running `verax witness` process, POSIX file modes.
