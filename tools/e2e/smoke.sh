#!/usr/bin/env bash
# tools/e2e/smoke.sh — end-to-end gate for the trojan protocol.
#
# Builds ./cmd/caddy, starts it with a trojan listener wrapper, and drives a
# real trojan handshake against it:
#
#   1. correct password  -> the tunnel must forward the request to the target
#                            and the target must log the hit;
#   2. wrong password    -> the connection must be closed without an answer and
#                            the target must not be hit at all.
#
# The password is generated at run time: the Caddyfile and the client must
# always agree on it.
#
# Usage: tools/e2e/smoke.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
cd "$SCRIPT_DIR/../.."

BIN="${BIN:-./dist/e2e-caddy}"
WORK="$(mktemp -d)"
export WORK
PASS="$(python3 -c "import secrets,string;print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(16)))")"
MARKER="hello-from-target"

cleanup() {
  [ -n "${CADDY_PID:-}" ] && kill "$CADDY_PID" 2>/dev/null || true
  [ -n "${TARGET_PID:-}" ] && kill "$TARGET_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  [ "${KEEP_WORK:-0}" = "1" ] || rm -rf "$WORK"
}
trap cleanup EXIT

# Print the server log before leaving: without it a failure is unreadable.
fail() {
  echo "e2e: $*" >&2
  [ -f "$WORK/caddy.log" ] && { echo "--- caddy log ---" >&2; cat "$WORK/caddy.log" >&2; }
  [ -f "$WORK/target.log" ] && { echo "--- target hits ---" >&2; cat "$WORK/target.log" >&2; }
  exit 1
}

free_port() {
  python3 -c "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()"
}

TROJAN_PORT="$(free_port)"
TARGET_PORT="$(free_port)"
while [ "$TROJAN_PORT" = "$TARGET_PORT" ]; do TARGET_PORT="$(free_port)"; done

echo "=== e2e: building caddy ==="
mkdir -p "$(dirname "$BIN")"
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  echo "e2e: reusing $BIN"
else
  CGO_ENABLED=0 go build -trimpath -tags "malloc_syscall" -o "$BIN" ./cmd/caddy
fi

cat > "$WORK/Caddyfile" <<EOF
{
	admin off
	auto_https off
	servers :${TROJAN_PORT} {
		listener_wrappers {
			trojan
		}
	}
	trojan {
		no_proxy
		users ${PASS}
	}
}

:${TROJAN_PORT} {
	respond "decoy-page"
}
EOF

echo "=== e2e: starting target server on 127.0.0.1:${TARGET_PORT} ==="
TARGET_PORT="$TARGET_PORT" MARKER="$MARKER" python3 -c "
import http.server, os, socketserver

port = int(os.environ['TARGET_PORT'])
marker = os.environ['MARKER']
hits = os.path.join(os.environ['WORK'], 'hits.log') if 'WORK' in os.environ else '/dev/null'

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(hits, 'a') as f:
            f.write('HIT %s\n' % self.path)
        body = marker.encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('127.0.0.1', port), Handler).serve_forever()
" &
TARGET_PID=$!

echo "=== e2e: starting caddy on 127.0.0.1:${TROJAN_PORT} ==="
"$BIN" run --config "$WORK/Caddyfile" > "$WORK/caddy.log" 2>&1 &
CADDY_PID=$!

# Wait for the trojan listener to accept connections.
ready=0
for _ in $(seq 1 50); do
  if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', ${TROJAN_PORT})) == 0 else 1)
"; then ready=1; break; fi
  sleep 0.2
done
if [ "$ready" != 1 ]; then
  fail "caddy did not start listening"
fi

echo "=== e2e: correct password must be forwarded ==="
set +e
OUT="$(python3 tools/e2e/trojan_client.py "$PASS" 127.0.0.1 "$TROJAN_PORT" 127.0.0.1 "$TARGET_PORT" 2>&1)"
RC=$?
set -e
echo "$OUT" | tail -3
if [ "$RC" != 0 ]; then
  fail "expected the tunnel to answer, client exit=$RC"
fi
case "$OUT" in
  *"$MARKER"*) echo "e2e: response came from the upstream target" ;;
  *) fail "response did not come from the upstream target" ;;
esac
if ! grep -q HIT "$WORK/hits.log" 2>/dev/null; then
  fail "target server recorded no request"
fi
HITS_BEFORE="$(grep -c HIT "$WORK/hits.log")"

echo "=== e2e: wrong password must be rejected ==="
set +e
python3 tools/e2e/trojan_client.py "definitely-not-the-password" 127.0.0.1 "$TROJAN_PORT" 127.0.0.1 "$TARGET_PORT" > "$WORK/wrong.out" 2>&1
WRONG_RC=$?
set -e
if [ "$WRONG_RC" = 0 ]; then
  cat "$WORK/wrong.out" >&2
  fail "wrong password was accepted"
fi
HITS_AFTER="$(grep -c HIT "$WORK/hits.log")"
if [ "$HITS_BEFORE" != "$HITS_AFTER" ]; then
  fail "wrong password still reached the target"
fi

echo "=== e2e: PASS (correct password forwarded, wrong password rejected) ==="
