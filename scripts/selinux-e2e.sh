#!/usr/bin/env bash
# SELinux end-to-end gate for verax install.
#
# Run this on a RHEL-family virtual machine with SELinux enforcing, as a user
# who can sudo:
#   bash scripts/selinux-e2e.sh <commit-sha>
#
# CI cannot run it: containers have no SELinux.
#
# Mirrors .github/workflows/install-e2e.yml (linux job), then records SELinux evidence.
# A tarball Node under /usr/local/lib is lib_t. Install must refuse that (exit 78)
# before anything is created. The printed semanage + restorecon remedy is applied
# next; the full install, a reinstall, and uninstall then run. The fcontext rule
# is removed on the way out so the VM is left as found.
set -uo pipefail
COMMIT="${1:?commit sha}"
VER=22.20.0
log() { printf '\n=== %s\n' "$*"; }
fail=0
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }

log "host"
cat /etc/os-release | grep -E '^(PRETTY_NAME|VERSION_ID)='
uname -srm
echo "getenforce: $(getenforce)"
sestatus | grep -E 'SELinux status|Current mode|Loaded policy'
test "$(getenforce)" = "Enforcing" || { echo "FAIL  SELinux is not enforcing; this run proves nothing"; exit 2; }

log "tools"
sudo dnf -y -q install git tar xz policycoreutils-python-utils audit >/dev/null 2>&1 || true
arch="$(uname -m)"; case "$arch" in x86_64) a=x64;; aarch64) a=arm64;; esac
name="node-v${VER}-linux-${a}.tar.xz"
curl -fsSL "https://nodejs.org/dist/v${VER}/SHASUMS256.txt" -o /tmp/SHASUMS256.txt
curl -fsSL "https://nodejs.org/dist/v${VER}/${name}" -o "/tmp/${name}"
(cd /tmp && grep " ${name}$" SHASUMS256.txt | sha256sum -c -) || exit 3
sudo mkdir -p /usr/local/lib/nodejs
sudo tar -C /usr/local/lib/nodejs -xJf "/tmp/${name}"
sudo chown -R root:root /usr/local/lib/nodejs && sudo chmod -R go-w /usr/local/lib/nodejs
export VERAX_NODE="/usr/local/lib/nodejs/node-v${VER}-linux-${a}/bin/node"
export PATH="$(dirname "$VERAX_NODE"):$PATH"
echo "node $(node -v) at $(command -v node)"

log "source at $COMMIT"
rm -rf ~/verax && git clone -q https://github.com/verax-ai/verax.git ~/verax && cd ~/verax && git checkout -q "$COMMIT"
git log --oneline -1
npm ci --silent >/dev/null 2>&1 && npm run build:dist >/dev/null 2>&1 || { echo "FAIL build"; exit 4; }
dir=/tmp/verax-tarballs
sudo rm -rf "$dir"
mkdir -p "$dir"
for p in inventory proxy body; do npm pack -w "@verax-ai/$p" --pack-destination "$dir" >/dev/null; done
sudo chown -R root:root "$dir"; sudo chmod -R a-w,u+rX "$dir"
export VERAX_TARBALLS="$dir"
NODE_REAL="$(readlink -f "$VERAX_NODE")"
fcontext_added=0
cleanup_label() {
  if [ "${fcontext_added:-0}" != 1 ]; then
    return 0
  fi
  echo "restore file context: semanage fcontext -d $NODE_REAL"
  sudo semanage fcontext -d "$NODE_REAL" || true
  sudo restorecon -v "$NODE_REAL" || true
  fcontext_added=0
}
trap cleanup_label EXIT

log "install refuses a lib_t Node"
refuse_log=/tmp/verax-selinux-refuse.txt
sudo -E env "PATH=$PATH" "$VERAX_NODE" packages/body/dist/cli.js install --from-tarballs "$VERAX_TARBALLS" --port 8801 >"$refuse_log" 2>&1
refuse_code=$?
echo "refuse exit=$refuse_code"
cat "$refuse_log"
check "lib_t Node is refused with exit 78" "test $refuse_code -eq 78"
check "refusal names lib_t" "grep -F 'labelled lib_t' '$refuse_log'"
check "refusal prints the semanage remedy" "grep -F \"semanage fcontext -a -t bin_t '$NODE_REAL'\" '$refuse_log'"
check "refused install left no unit" "! test -e /etc/systemd/system/verax.service"
check "refused install left no code dir" "! test -e /opt/verax"

log "label Node bin_t"
if ! sudo semanage fcontext -l >/dev/null 2>&1; then
  sudo dnf -y install policycoreutils-python-utils
fi
sudo semanage fcontext -a -t bin_t "$NODE_REAL" || { echo "FAIL  semanage fcontext"; exit 5; }
fcontext_added=1
sudo restorecon -v "$NODE_REAL" || { echo "FAIL  restorecon"; exit 5; }

sudo ausearch --input-logs -m avc -ts recent </dev/null >/dev/null 2>&1; start_ts="$(date '+%m/%d/%Y %H:%M:%S')"

log "install (sudo, as the invoking user $(id -un))"
sudo -E env "PATH=$PATH" "$VERAX_NODE" packages/body/dist/cli.js install --from-tarballs "$VERAX_TARBALLS" --port 8801
install_code=$?
echo "install exit=$install_code"
check "install exits 0 under SELinux enforcing" "test $install_code -eq 0"
sleep 3
check "service answers /healthz" "curl -fsS http://127.0.0.1:8801/healthz >/dev/null"
systemctl is-active verax; systemctl show verax -p User,ActiveState,SubState | tr '\n' ' '; echo
log "SELinux labels"
ls -Zd /opt/verax /var/lib/verax 2>&1
ps -eZ | grep -E 'node|verax' | grep -v grep | head -3
check "non-admin cannot read the signing key" "! cat /var/lib/verax/keys/record.private.pem >/dev/null 2>&1"
check "non-admin cannot write the approval queue" "! (echo x >> /var/lib/verax/approval-commands.jsonl) 2>/dev/null"
check "non-admin cannot change the installed code" "! touch /opt/verax/probe-write 2>/dev/null"
node --input-type=module -e '
  import { readFileSync } from "node:fs";
  const token = readFileSync(process.env.HOME + "/.verax/agent.token", "utf8").trim();
  const res = await fetch("http://127.0.0.1:8801/mcp", { method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer " + token },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }) });
  process.exit(res.status === 200 ? 0 : 1);'
check "agent token works through the service" "test $? -eq 0"
node packages/body/dist/cli.js approve probe-ref >/dev/null 2>&1; ac=$?
check "approve without admin refuses with 77" "test $ac -eq 77"

log "SELinux denials since install"
sudo ausearch --input-logs -m avc,user_avc -ts "$start_ts" </dev/null 2>/dev/null | grep -E 'avc:' | head -20 || true
denials=$(sudo ausearch --input-logs -m avc,user_avc -ts "$start_ts" </dev/null 2>/dev/null | grep -c 'avc:.*denied' || true)
echo "AVC denials: $denials"
check "no SELinux AVC denials" "test ${denials:-0} -eq 0"
log "service journal (last 15)"
sudo journalctl -u verax --no-pager -n 15 2>&1 | tail -15

log "uninstall"
sudo -E env "PATH=$PATH" "$VERAX_NODE" packages/body/dist/cli.js uninstall; uc=$?
check "uninstall exits 0" "test $uc -eq 0"
check "service unit removed" "! test -e /etc/systemd/system/verax.service"
echo "verax account after uninstall: $(id verax 2>&1 || true)"
check "verax account is gone" "! id verax >/dev/null 2>&1"
check "verax group is gone" "! getent group verax >/dev/null 2>&1"

log "reinstall after uninstall"
sudo -E env "PATH=$PATH" "$VERAX_NODE" packages/body/dist/cli.js install --from-tarballs "$VERAX_TARBALLS" --port 8801
reinstall_code=$?
echo "reinstall exit=$reinstall_code"
check "reinstall exits 0" "test $reinstall_code -eq 0"
sleep 3
check "reinstall answers /healthz" "curl -fsS http://127.0.0.1:8801/healthz >/dev/null"
sudo -E env "PATH=$PATH" "$VERAX_NODE" packages/body/dist/cli.js uninstall; uc2=$?
check "second uninstall exits 0" "test $uc2 -eq 0"
check "service unit removed after reinstall" "! test -e /etc/systemd/system/verax.service"
check "verax account is gone after reinstall" "! id verax >/dev/null 2>&1"

log "RESULT"
if [ $fail -eq 0 ]; then echo "ALL PASS on $(grep PRETTY_NAME /etc/os-release | cut -d= -f2) with SELinux $(getenforce)"; else echo "SOME CHECKS FAILED"; fi
exit $fail
