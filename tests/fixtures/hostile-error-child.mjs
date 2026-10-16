#!/usr/bin/env node
// Fixture stdio MCP child that answers `initialize` with a JSON-RPC error whose
// message carries terminal controls, bidi and combining code points. Written
// with String.fromCodePoint so the source stays ASCII.

const cp = (...points) => String.fromCodePoint(...points);
const HOSTILE =
  `boom${cp(0x1b)}]0;pwned${cp(0x07)}${cp(0x1b)}[2J${cp(0x9b)}2J${cp(0x202e)}KO${cp(0x338)}${cp(0xfe0f)}` +
  `${cp(0x0d)}${cp(0x0a)}listening 127.0.0.1:1`;

let buffered = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffered += chunk;
  let newline;
  while ((newline = buffered.indexOf("\n")) !== -1) {
    const line = buffered.slice(0, newline).trim();
    buffered = buffered.slice(newline + 1);
    if (line === "") continue;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      continue;
    }
    if (msg.id === undefined) continue;
    process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: HOSTILE } })}\n`);
  }
});
