/**
 * The one page the operator door serves: its markup, its stylesheet and its
 * script, each a string the door hands out under its own path.
 *
 * The door sends them under a policy that runs no inline script and applies
 * no inline style, so the markup carries neither. The script writes every
 * value the door gives it as text, and keeps the session token in a variable
 * of its own: nothing a later page could read, and gone on reload.
 *
 * What a held call says comes from the agent. The terminal escapes every
 * control and format character before it prints one; the script escapes the
 * same class, read from the same place, and gives each value its own
 * direction, so text that runs right to left cannot rearrange what is beside it.
 */
import { TERMINAL_CONTROL_CLASS } from "@verax-ai/proxy";

export const DOOR_HTML: string = `<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Verax operator door</title>
<link rel="stylesheet" href="/door.css">
<script src="/door.js" defer></script>
</head>
<body>
<main data-test="door">
  <header class="top">
    <h1>Verax</h1>
    <p class="dim">Operator door</p>
  </header>

  <p data-test="notice" class="notice" role="status" aria-live="polite" hidden></p>

  <section data-test="screen-loading">
    <p class="dim">Asking the door.</p>
  </section>

  <section data-test="screen-enroll" hidden>
    <h2>Add this device</h2>
    <p>Run <code>verax operator enroll</code> at the machine. It prints an 8-digit code that is good for five minutes.</p>
    <label for="enroll-code">Pairing code</label>
    <input id="enroll-code" data-test="enroll-code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="8" spellcheck="false">
    <button type="button" data-test="enroll-submit" class="primary">Enrol a passkey on this device</button>
    <button type="button" data-test="goto-signin" class="plain" hidden>Back to sign-in</button>
  </section>

  <section data-test="screen-signin" hidden>
    <h2>Sign in</h2>
    <p>Signing in shows what is waiting. Each approval asks the passkey again.</p>
    <button type="button" data-test="signin" class="primary">Sign in with a passkey</button>
    <button type="button" data-test="goto-enroll" class="plain">Add a device with a pairing code</button>
  </section>

  <section data-test="screen-main" hidden>
    <div class="bar">
      <p class="dim">Signed in as <strong data-test="session-sub"></strong> until <span data-test="session-expires"></span></p>
      <button type="button" data-test="signout" class="plain">Sign out</button>
    </div>

    <div class="card">
      <p class="state"><span class="label">Body</span><strong data-test="halt-state" data-halted="false">Running</strong></p>
      <p data-test="halt-since" class="dim" hidden></p>
      <button type="button" data-test="halt" class="danger">Stop the body</button>
      <button type="button" data-test="resume" class="primary" hidden>Resume with passkey</button>
    </div>

    <div class="bar">
      <h2>Waiting <span data-test="waiting-count" class="count">0</span></h2>
      <button type="button" data-test="refresh" class="plain">Refresh</button>
    </div>
    <p data-test="waiting-empty" class="dim">Nothing is waiting.</p>
    <ul data-test="waiting-list" class="waiting"></ul>
  </section>
</main>
</body>
</html>
`;

export const DOOR_CSS: string = `:root {
  --paper: #f6f5f1;
  --card: #ffffff;
  --ink: #16181d;
  --dim: #5b616e;
  --line: #d9d7cf;
  --go: #0b5cad;
  --go-ink: #ffffff;
  --stop: #b3261e;
  --ok: #17643a;
  --ok-paper: #e5f3ea;
  --bad-paper: #fbe9e7;
}
@media (prefers-color-scheme: dark) {
  :root {
    --paper: #101216;
    --card: #191c22;
    --ink: #eceef2;
    --dim: #9aa1ae;
    --line: #2c313a;
    --go: #7db7f5;
    --go-ink: #0b1420;
    --stop: #f28b82;
    --ok: #81c995;
    --ok-paper: #14261b;
    --bad-paper: #2d1614;
  }
}
[hidden] { display: none !important; }
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 34rem; margin: 0 auto; padding: 20px 16px 48px; }
h1 { font-size: 1.25rem; margin: 0; letter-spacing: 0.02em; }
h2 { font-size: 1.1rem; margin: 0; }
p { margin: 0; }
section > * + * { margin-top: 14px; }
.top { display: flex; align-items: baseline; gap: 10px; margin-bottom: 18px; }
.dim { color: var(--dim); font-size: 0.9rem; }
.label { color: var(--dim); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; }
code, pre, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85rem; }
/* Arguments and identifiers: one character after another, left to right, whatever script they are in. */
pre, .mono { direction: ltr; unicode-bidi: bidi-override; }
/* Every other value keeps its own direction to itself. */
bdi, [data-test="session-sub"], [data-test="session-expires"] { unicode-bidi: isolate; }
.notice { padding: 12px 14px; border-radius: 8px; border: 1px solid var(--line); margin-bottom: 16px; overflow-wrap: anywhere; }
.notice[data-kind="ok"] { background: var(--ok-paper); border-color: var(--ok); }
.notice[data-kind="error"] { background: var(--bad-paper); border-color: var(--stop); }
label { display: block; font-size: 0.9rem; color: var(--dim); }
input {
  display: block; width: 100%; min-height: 52px; margin-top: 6px; padding: 8px 12px;
  font: 1.6rem/1.2 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: 0.3em;
  color: var(--ink); background: var(--card); border: 1px solid var(--line); border-radius: 8px;
}
button {
  display: block; width: 100%; min-height: 48px; padding: 10px 16px;
  font: inherit; font-weight: 600; border-radius: 8px; border: 1px solid var(--line);
  background: var(--card); color: var(--ink); cursor: pointer;
}
button:disabled { opacity: 0.5; cursor: default; }
button:focus-visible, input:focus-visible { outline: 3px solid var(--go); outline-offset: 2px; }
button.primary { background: var(--go); border-color: var(--go); color: var(--go-ink); }
button.danger { background: transparent; border-color: var(--stop); color: var(--stop); }
button.plain { width: auto; min-height: 44px; font-weight: 500; white-space: nowrap; flex: none; }
.bar { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.card, .waiting li { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 16px; }
.card > * + *, .waiting li > * + * { margin-top: 12px; }
.state { display: flex; align-items: baseline; gap: 10px; font-size: 1.15rem; }
[data-halted="true"] { color: var(--stop); }
[data-halted="false"] { color: var(--ok); }
.count { display: inline-block; min-width: 1.6em; padding: 0 0.4em; text-align: center; border: 1px solid var(--line); border-radius: 999px; font-size: 0.9rem; }
.waiting { list-style: none; margin: 14px 0 0; padding: 0; }
.waiting li + li { margin-top: 14px; }
.spend .amount { font-size: 1.9rem; font-weight: 700; line-height: 1.15; overflow-wrap: anywhere; }
.spend .amount small { font-size: 0.8rem; font-weight: 400; color: var(--dim); }
.spend .payee { font-size: 1.35rem; font-weight: 600; overflow-wrap: anywhere; }
.field { display: grid; grid-template-columns: 6.5rem 1fr; gap: 8px; align-items: baseline; }
.field > :last-child, pre { overflow-wrap: anywhere; white-space: pre-wrap; min-width: 0; }
pre { margin: 0; padding: 10px 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--paper); max-height: 16rem; overflow: auto; }
.confirm { border-top: 1px solid var(--line); padding-top: 12px; }
.confirm > * + * { margin-top: 10px; }
.confirm p { font-weight: 600; overflow-wrap: anywhere; }
`;

const SCRIPT: string = String.raw`(function () {
  "use strict";

  // The session. Held here and nowhere else; a reload ends it.
  var token = null;
  var expiryTimer = null;
  var operatorKnown = false;
  var unsupported = false;
  var busy = false;

  var SCREENS = ["loading", "enroll", "signin", "main"];
  var TEXT = {
    "enrolled": "This device is enrolled. Sign in to go on.",
    "signed-in": "Signed in.",
    "signed-out": "Signed out.",
    "approved": "Approved.",
    "halted": "The body is stopped.",
    "halted-unsigned": "The body is stopped. The stop carries no passkey signature.",
    "resumed": "The body is running again.",
    "session-ended": "The session ended. Sign in again.",
    "code-format": "The code is 8 digits.",
    "pairing-refused": "That code was not accepted. Ask for a new one at the machine.",
    "enroll-refused": "The door did not accept this passkey.",
    "signin-refused": "The door did not accept this sign-in.",
    "cloned-authenticator": "This passkey answered with an older counter than the door has seen. It was refused.",
    "no-operator": "Nobody is enrolled yet. Add this device with a pairing code.",
    "passkey-unsupported": "This browser has no passkeys. Open the door in one that does.",
    "passkey-cancelled": "The passkey prompt was dismissed. Nothing was sent.",
    "passkey-failed": "The passkey did not answer.",
    "stale": "That request changed since it was listed. The list is fresh now; nothing was approved.",
    "unknown-ref": "That request is no longer waiting. Nothing was approved.",
    "approve-halted": "The body is stopped. Nothing is approved while it is.",
    "resume-signature-required": "A resume needs the passkey.",
    "origin-not-allowed": "This page was opened under a name the door does not answer for.",
    "busy": "The door is busy. Try again in a few seconds.",
    "network": "The door did not answer.",
    "fault": "Something went wrong on this page. Reload it."
  };

  function Refusal(code, body) {
    this.code = code;
    this.body = body || {};
  }

  function at(name, root) {
    return (root || document).querySelector('[data-test="' + name + '"]');
  }

  /**
   * The page's own words as text, and each value among them in an element of
   * its own direction: letters that run right to left stay inside the value
   * and move nothing beside it.
   */
  function fill(el, parts) {
    while (el.firstChild) el.removeChild(el.firstChild);
    for (var i = 0; i < parts.length; i += 1) {
      if (typeof parts[i] === "string") {
        el.appendChild(document.createTextNode(parts[i]));
      } else {
        var value = document.createElement("bdi");
        value.textContent = parts[i].value;
        el.appendChild(value);
      }
    }
    return el;
  }

  function show(name) {
    SCREENS.forEach(function (screen) {
      at("screen-" + screen).hidden = screen !== name;
    });
  }

  function hush() {
    var notice = at("notice");
    notice.hidden = true;
    notice.textContent = "";
    ["data-kind", "data-code", "data-reason", "data-allow-ref"].forEach(function (name) {
      notice.removeAttribute(name);
    });
  }

  function say(kind, code, more) {
    var notice = at("notice");
    hush();
    // The page's own sentence where it has one. A word of the door's it does not know is shown as a value.
    var parts = [Object.prototype.hasOwnProperty.call(TEXT, code) ? TEXT[code] : { value: plain(code) }];
    if (more && typeof more.reason === "string" && more.reason !== "") {
      notice.setAttribute("data-reason", more.reason);
      parts.push(" (", { value: plain(more.reason) }, ")");
    }
    if (more && typeof more.allowRef === "string") notice.setAttribute("data-allow-ref", more.allowRef);
    notice.setAttribute("data-kind", kind);
    notice.setAttribute("data-code", code);
    fill(notice, parts);
    notice.hidden = false;
  }

  function lock(on) {
    var buttons = document.querySelectorAll("button");
    for (var i = 0; i < buttons.length; i += 1) buttons[i].disabled = on;
    if (!on && unsupported) {
      at("signin").disabled = true;
      at("enroll-submit").disabled = true;
    }
  }

  // The class the terminal escapes in a held call. A character from it is shown as
  // its escape, one per UTF-16 unit, which is also how JSON would write it.
  var CONTROL = new RegExp("[" + "@@CONTROL_CLASS@@" + "]", "gu");

  function plain(text, keepLineBreaks) {
    return String(text).replace(CONTROL, function (ch) {
      if (keepLineBreaks && ch === "\n") return ch;
      var out = "";
      for (var i = 0; i < ch.length; i += 1) out += "\\u" + ("000" + ch.charCodeAt(i).toString(16)).slice(-4);
      return out;
    });
  }

  function clock(ms) {
    if (typeof ms !== "number" || !isFinite(ms)) return "—";
    return new Date(ms).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
  }

  // ---- the door ----

  function call(method, path, body, withSession) {
    var headers = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (withSession && token !== null) headers["authorization"] = "Bearer " + token;
    var options = {
      method: method,
      headers: headers,
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer"
    };
    if (body !== undefined) options.body = JSON.stringify(body);
    return fetch(path, options).then(
      function (res) {
        return res.text().then(function (text) {
          var parsed = null;
          try {
            parsed = text === "" ? null : JSON.parse(text);
          } catch (err) {
            parsed = null;
          }
          return { ok: res.ok, status: res.status, body: parsed !== null && typeof parsed === "object" ? parsed : {} };
        });
      },
      function () {
        throw new Refusal("network");
      }
    );
  }

  /** The answer's body, or the door's refusal by its own word for it. */
  function need(res) {
    if (res.ok) return res.body;
    var word = typeof res.body.error === "string" && res.body.error !== "" ? res.body.error : "http-" + res.status;
    if (token !== null && (res.status === 401 || word === "no-operator")) throw new Refusal("session-ended");
    throw new Refusal(word, res.body);
  }

  // ---- passkeys: base64url on the wire, bytes for the browser ----

  function toBytes(value) {
    var padded = String(value).replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) padded += "=";
    var binary = atob(padded);
    var out = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  }

  function toText(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function descriptors(list) {
    var out = [];
    if (!Array.isArray(list)) return out;
    for (var i = 0; i < list.length; i += 1) {
      if (list[i] && typeof list[i].id === "string") out.push({ type: "public-key", id: toBytes(list[i].id) });
    }
    return out;
  }

  function ceremony(make) {
    return Promise.resolve()
      .then(make)
      .then(
        function (made) {
          if (!made) throw new Refusal("passkey-failed");
          return made;
        },
        function (err) {
          var name = err && err.name;
          throw new Refusal(name === "NotAllowedError" || name === "AbortError" ? "passkey-cancelled" : "passkey-failed");
        }
      );
  }

  function assertion(options) {
    return ceremony(function () {
      return navigator.credentials.get({
        publicKey: {
          challenge: toBytes(options.challenge),
          rpId: options.rpId,
          allowCredentials: descriptors(options.allowCredentials),
          userVerification: "required",
          timeout: 60000
        }
      });
    }).then(function (made) {
      var id = toText(made.rawId);
      return {
        id: id,
        rawId: id,
        type: made.type,
        response: {
          clientDataJSON: toText(made.response.clientDataJSON),
          authenticatorData: toText(made.response.authenticatorData),
          signature: toText(made.response.signature)
        },
        clientExtensionResults: made.getClientExtensionResults()
      };
    });
  }

  // ---- what is drawn ----

  function piece(tag, test, text, className) {
    var el = document.createElement(tag);
    if (test) el.setAttribute("data-test", test);
    if (className) el.className = className;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  /** A value in an element of its own direction: what runs right to left in it stays in it. */
  function field(label, test, text, mono) {
    var wrap = piece("div", null, undefined, "field");
    wrap.appendChild(piece("span", null, label, "label"));
    wrap.appendChild(piece("bdi", test, text, mono ? "mono" : ""));
    return wrap;
  }

  function word(value) {
    return value === null || value === undefined ? "" : String(value);
  }

  /** A value from the door, as it is put on the screen. */
  function shown(value) {
    return plain(word(value));
  }

  /** A sentence with values in it, each value apart from the words around it. */
  function sentence(parts) {
    return fill(document.createElement("p"), parts);
  }

  function drawRow(row) {
    var item = piece("li", "waiting-row");
    item.setAttribute("data-ref", word(row.ref));
    var spend = row.spend && typeof row.spend === "object" ? row.spend : null;
    var asked = ["Approve ", { value: shown(row.tool) }, "?"];
    if (spend) {
      var amountText = typeof spend.amountMinor === "number" ? String(spend.amountMinor) : "unreadable";
      var box = piece("div", null, undefined, "spend");
      var amount = piece("p", null, undefined, "amount");
      amount.appendChild(piece("bdi", "row-amount", amountText));
      amount.appendChild(document.createTextNode(" "));
      amount.appendChild(piece("bdi", "row-currency", shown(spend.currency)));
      amount.appendChild(document.createTextNode(" "));
      amount.appendChild(piece("small", null, "minor units"));
      box.appendChild(amount);
      var payee = piece("p", null, undefined, "payee");
      payee.appendChild(piece("span", null, "to ", "label"));
      payee.appendChild(piece("bdi", "row-payee", shown(spend.payee)));
      box.appendChild(payee);
      box.appendChild(field("Reference", "row-reference", shown(spend.reference), false));
      item.appendChild(box);
      asked = [
        "Approve ",
        { value: amountText },
        " ",
        { value: shown(spend.currency) },
        " (minor units) to ",
        { value: shown(spend.payee) },
        "?"
      ];
    }
    item.appendChild(field("Tool", "row-tool", shown(row.tool), true));
    item.appendChild(field("Agent", "row-agent", shown(row.agent), false));
    item.appendChild(field("Rule", "row-rule", row.rule === null || row.rule === undefined ? "—" : shown(row.rule), false));
    var held = "";
    try {
      held = JSON.stringify(row.args, null, 2);
    } catch (err) {
      held = "";
    }
    // The line breaks are the layout's own: JSON has already escaped any inside a value.
    item.appendChild(piece("pre", "row-args", held === undefined ? "" : plain(held, true)));
    item.appendChild(field("Held as", "row-ref", shown(row.ref), true));
    item.appendChild(field("Request", "row-hash", shown(row.requestHash), true));
    item.appendChild(field("Expires", "row-expires", clock(row.expiresAtMs), false));

    var open = piece("button", "approve", "Approve", "primary");
    open.type = "button";
    var panel = piece("div", "approve-panel", undefined, "confirm");
    panel.hidden = true;
    panel.appendChild(sentence(asked));
    var confirm = piece("button", "approve-confirm", "Approve with passkey", "primary");
    confirm.type = "button";
    var cancel = piece("button", "approve-cancel", "Cancel", "plain");
    cancel.type = "button";
    panel.appendChild(confirm);
    panel.appendChild(cancel);
    open.addEventListener("click", function () {
      panel.hidden = false;
      open.hidden = true;
    });
    cancel.addEventListener("click", function () {
      panel.hidden = true;
      open.hidden = false;
    });
    confirm.addEventListener("click", run(function () {
      return approve(row);
    }));
    item.appendChild(open);
    item.appendChild(panel);
    return item;
  }

  function drawWaiting(rows) {
    var list = at("waiting-list");
    while (list.firstChild) list.removeChild(list.firstChild);
    for (var i = 0; i < rows.length; i += 1) {
      if (rows[i] && typeof rows[i] === "object") list.appendChild(drawRow(rows[i]));
    }
    at("waiting-count").textContent = String(list.children.length);
    at("waiting-empty").hidden = list.children.length !== 0;
  }

  function drawHalt(state) {
    var halted = state.halted === true;
    var mark = at("halt-state");
    mark.setAttribute("data-halted", halted ? "true" : "false");
    mark.textContent = halted ? "Stopped" : "Running";
    at("halt").hidden = halted;
    at("resume").hidden = !halted;
    var since = at("halt-since");
    if (halted && state.since && typeof state.since === "object") {
      fill(since, ["Stopped by ", { value: shown(state.since.by) }, ", " + clock(state.since.atMs)]);
      since.hidden = false;
    } else {
      since.textContent = "";
      since.hidden = true;
    }
  }

  // ---- the session ----

  function endSession() {
    token = null;
    clearTimeout(expiryTimer);
    at("session-sub").textContent = "";
    at("session-expires").textContent = "";
    drawWaiting([]);
    show("signin");
  }

  function beginSession(session) {
    token = session.token;
    at("session-sub").textContent = shown(session.sub);
    at("session-expires").textContent = clock(session.expiresAtMs);
    clearTimeout(expiryTimer);
    // The door's clock decides when a session ends. This timer only saves a
    // tap when the two clocks agree; when they do not, the next call finds out.
    var left = session.expiresAtMs - Date.now();
    if (typeof left === "number" && left > 0 && left < 15 * 60 * 1000) {
      expiryTimer = setTimeout(function () {
        if (token === null) return;
        endSession();
        say("error", "session-ended");
      }, left);
    }
  }

  function load() {
    return call("GET", "/api/halt", undefined, true)
      .then(function (res) {
        drawHalt(need(res));
        return call("GET", "/api/waiting", undefined, true);
      })
      .then(function (res) {
        var listed = need(res);
        drawWaiting(Array.isArray(listed.waiting) ? listed.waiting : []);
      });
  }

  /** After something was done: a list that cannot be fetched must not hide that it was. */
  function loadAfter() {
    return load().catch(function (err) {
      if (err instanceof Refusal && err.code === "session-ended") throw err;
    });
  }

  // ---- what the buttons do ----

  function enroll() {
    var input = at("enroll-code");
    var code = input.value.trim();
    if (!/^[0-9]{8}$/.test(code)) return Promise.reject(new Refusal("code-format"));
    return call("POST", "/api/enroll/options", { code: code })
      .then(function (res) {
        var options = need(res);
        return ceremony(function () {
          return navigator.credentials.create({
            publicKey: {
              challenge: toBytes(options.challenge),
              rp: options.rp,
              user: { id: toBytes(options.user.id), name: options.user.name, displayName: options.user.displayName },
              pubKeyCredParams: options.pubKeyCredParams,
              authenticatorSelection: options.authenticatorSelection,
              attestation: options.attestation,
              excludeCredentials: descriptors(options.excludeCredentials),
              timeout: options.timeout
            }
          });
        });
      })
      .then(function (made) {
        var id = toText(made.rawId);
        return call("POST", "/api/enroll", {
          code: code,
          response: {
            id: id,
            rawId: id,
            type: made.type,
            response: {
              clientDataJSON: toText(made.response.clientDataJSON),
              attestationObject: toText(made.response.attestationObject)
            }
          }
        });
      })
      .then(function (res) {
        need(res);
        input.value = "";
        operatorKnown = true;
        show("signin");
        say("ok", "enrolled");
      });
  }

  function signIn() {
    return call("POST", "/api/signin/options")
      .then(function (res) {
        return assertion(need(res));
      })
      .then(function (signed) {
        return call("POST", "/api/signin", { assertion: signed });
      })
      .then(function (res) {
        beginSession(need(res));
        show("main");
        return load();
      })
      .then(function () {
        say("ok", "signed-in");
      });
  }

  function signOut() {
    return call("POST", "/api/signout", undefined, true)
      .catch(function () {
        return null;
      })
      .then(function () {
        endSession();
        say("ok", "signed-out");
      });
  }

  function approve(row) {
    var done = null;
    return call("GET", "/api/approve/challenge?ref=" + encodeURIComponent(word(row.ref)), undefined, true)
      .then(function (res) {
        return assertion(need(res));
      })
      .then(function (signed) {
        // The request hash that was on the screen: if something else is waiting now, the door says so.
        return call("POST", "/api/approve", { ref: row.ref, requestHash: row.requestHash, assertion: signed }, true);
      })
      .then(function (res) {
        done = need(res);
        return loadAfter();
      })
      .then(function () {
        say("ok", "approved", { allowRef: word(done.allowRef) });
      });
  }

  function halt() {
    // Stopping is the safe direction. A passkey that does not answer does not keep the body running.
    return call("GET", "/api/halt/challenge", undefined, true)
      .then(function (res) {
        return assertion(need(res));
      })
      .then(
        function (signed) {
          return { assertion: signed };
        },
        function (err) {
          if (err instanceof Refusal && err.code === "session-ended") throw err;
          return {};
        }
      )
      .then(function (sent) {
        return call("POST", "/api/halt", sent, true).then(function (res) {
          var state = need(res);
          drawHalt(state);
          say("ok", sent.assertion && !state.signatureRefused ? "halted" : "halted-unsigned");
        });
      });
  }

  function resume() {
    return call("GET", "/api/resume/challenge", undefined, true)
      .then(function (res) {
        return assertion(need(res));
      })
      .then(function (signed) {
        return call("POST", "/api/resume", { assertion: signed }, true);
      })
      .then(function (res) {
        drawHalt(need(res));
        say("ok", "resumed");
      });
  }

  /** One thing at a time, every button shut while it runs, and whatever went wrong said by its code. */
  function run(action) {
    return function () {
      if (busy) return;
      busy = true;
      lock(true);
      hush();
      Promise.resolve()
        .then(action)
        .catch(function (err) {
          var refusal = err instanceof Refusal ? err : new Refusal("fault");
          var after = Promise.resolve();
          if (refusal.code === "session-ended") {
            endSession();
          } else if (refusal.code === "no-operator") {
            operatorKnown = false;
            at("goto-signin").hidden = true;
            show("enroll");
          } else if (token !== null && (refusal.code === "stale" || refusal.code === "unknown-ref")) {
            after = load().catch(function (again) {
              if (again instanceof Refusal && again.code === "session-ended") {
                endSession();
                refusal = again;
              }
            });
          }
          return after.then(function () {
            say("error", refusal.code, refusal.code === "enroll-refused" ? { reason: refusal.body.reason } : null);
          });
        })
        .then(function () {
          busy = false;
          lock(false);
        });
    };
  }

  function start() {
    at("enroll-submit").addEventListener("click", run(enroll));
    at("enroll-code").addEventListener("keydown", function (event) {
      if (event.key === "Enter") at("enroll-submit").click();
    });
    at("signin").addEventListener("click", run(signIn));
    at("signout").addEventListener("click", run(signOut));
    at("refresh").addEventListener("click", run(load));
    at("halt").addEventListener("click", run(halt));
    at("resume").addEventListener("click", run(resume));
    at("goto-enroll").addEventListener("click", function () {
      hush();
      at("goto-signin").hidden = !operatorKnown;
      show("enroll");
    });
    at("goto-signin").addEventListener("click", function () {
      hush();
      show("signin");
    });

    if (!window.PublicKeyCredential || !navigator.credentials) {
      unsupported = true;
      lock(false);
      show("signin");
      say("error", "passkey-unsupported");
      return;
    }
    // Whether anyone is enrolled decides the first screen. The challenge this
    // returns is not kept: a sign-in asks for its own.
    call("POST", "/api/signin/options").then(
      function (res) {
        if (res.ok) {
          operatorKnown = true;
          show("signin");
          return;
        }
        if (res.body.error === "no-operator") {
          operatorKnown = false;
          at("goto-signin").hidden = true;
          show("enroll");
          return;
        }
        show("signin");
        say("error", typeof res.body.error === "string" && res.body.error !== "" ? res.body.error : "http-" + res.status);
      },
      function (err) {
        show("signin");
        say("error", err instanceof Refusal ? err.code : "fault");
      }
    );
  }

  start();
})();
`;

export const DOOR_JS: string = SCRIPT.replace('"@@CONTROL_CLASS@@"', () => JSON.stringify(TERMINAL_CONTROL_CLASS));
