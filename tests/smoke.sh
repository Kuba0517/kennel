#!/usr/bin/env bash
set -u

KENNEL="$(cd "$(dirname "$0")/.." && pwd)/target/debug/kennel"
[ -x "$KENNEL" ] || { echo "build first: cargo build"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
echo "hello" > allowed.txt

pass=0 fail=0
check() { # check <desc> <expected:0|nonzero> <cmd...>
    local desc="$1" expected="$2"; shift 2
    "$@" >/dev/null 2>&1
    local rc=$?
    if { [ "$expected" = 0 ] && [ $rc -eq 0 ]; } || { [ "$expected" = nonzero ] && [ $rc -ne 0 ]; }; then
        echo "PASS: $desc"; pass=$((pass+1))
    else
        echo "FAIL: $desc (exit=$rc, expected $expected)"; fail=$((fail+1))
    fi
}

check "reads file in cwd"                0       "$KENNEL" -- cat allowed.txt
check "writes file in cwd"               0       "$KENNEL" -- touch created.txt
check "blocks reading ~/.ssh"            nonzero "$KENNEL" -- ls "$HOME/.ssh"
check "blocks writing to \$HOME"         nonzero "$KENNEL" -- touch "$HOME/kennel-pwned"
check "blocks reading other dirs in ~"   nonzero "$KENNEL" -- ls "$HOME/Documents"
check "proxy allows a listed domain"     0       "$KENNEL" --allow-domain example.com -- curl -sf --max-time 10 https://example.com
check "proxy blocks other domains"       nonzero "$KENNEL" --allow-domain example.com -- curl -sf --max-time 10 https://example.org
check "proxy blocks other ports"         nonzero "$KENNEL" --allow-domain example.com -- curl -sf --max-time 5 http://example.com:8080
check "blocks connections around proxy"  nonzero "$KENNEL" -- python3 -c 'import socket; socket.create_connection(("1.1.1.1", 443), 5)'
check "blocks UDP"                       nonzero "$KENNEL" -- python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM)'
check "blocks DNS"                       nonzero "$KENNEL" -- getent hosts example.com
check "--net ports allows TCP 443"       0       "$KENNEL" --net ports -- curl -s --max-time 10 https://example.com
check "--net ports blocks other ports"   nonzero "$KENNEL" --net ports -- curl -s --max-time 5 http://example.com:8080
check "--no-network blocks TCP 443"      nonzero "$KENNEL" --no-network -- curl -s --max-time 5 https://example.com
check "--allow-bind runs a dev server"   0       "$KENNEL" --allow-bind 8765 -- bash -c 'cd "$TMPDIR"; python3 -m http.server 8765 --bind 127.0.0.1 >/dev/null 2>&1 & s=$!; sleep 1; curl -sf -o /dev/null http://localhost:8765/; r=$?; kill $s; exit $r'
git init -q .
check "undoes a planted git hook"        nonzero bash -c "\"$KENNEL\" -- bash -c 'echo evil > .git/hooks/pre-commit' 2>/dev/null; [ -e .git/hooks/pre-commit ]"
check "undoes core.hooksPath"            nonzero bash -c "\"$KENNEL\" -- git config core.hooksPath /tmp/x 2>/dev/null; git config --get core.hooksPath"
check "child processes stay confined"    nonzero "$KENNEL" -- bash -c "cat $HOME/.ssh/* 2>/dev/null || exit 1"
check "drops secrets from the environment" nonzero env KENNEL_TEST_SECRET=x "$KENNEL" -- bash -c '[ -n "${KENNEL_TEST_SECRET:-}" ]'
check "--env passes a variable through"  0       env KENNEL_TEST_SECRET=x "$KENNEL" --env KENNEL_TEST_SECRET -- bash -c '[ -n "${KENNEL_TEST_SECRET:-}" ]'
check "closes inherited fds"             nonzero bash -c "exec 9</etc/hostname; \"$KENNEL\" -- bash -c 'cat <&9'"
check "blocks signals to outside"        nonzero bash -c "sleep 30 & p=\$!; \"$KENNEL\" -- kill -0 \$p; r=\$?; kill \$p; exit \$r"
check "blocks writing to /tmp"           nonzero "$KENNEL" -- touch /tmp/kennel-pwned
check "TMPDIR is writable"               0       "$KENNEL" -- bash -c 'touch "$TMPDIR/x"'
check "blocks unix sockets"              nonzero "$KENNEL" -- python3 -c 'import socket; socket.socket(socket.AF_UNIX)'
check "allows socketpair"                0       "$KENNEL" -- python3 -c 'import socket; socket.socketpair()'
check "blocks io_uring"                  nonzero "$KENNEL" -- python3 -c 'import ctypes; b=ctypes.create_string_buffer(120); exit(ctypes.CDLL(None).syscall(425, 1, b) < 0)'
check "--allow-unix allows unix sockets" 0       "$KENNEL" --allow-unix -- python3 -c 'import socket; socket.socket(socket.AF_UNIX)'
printf '[fs]\nread_write = ["~"]\n' > .kennel.toml
check "refuses unapproved .kennel.toml"  nonzero "$KENNEL" -- true
rm .kennel.toml
(cd "$HOME" && "$KENNEL" -- true) >/dev/null 2>&1 && { echo "FAIL: home-dir guard"; fail=$((fail+1)); } || { echo "PASS: refuses to run with cwd=\$HOME"; pass=$((pass+1)); }

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
