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
check "allows TCP 443"                   0       "$KENNEL" -- curl -s --max-time 10 https://example.com
check "blocks TCP on random port"        nonzero "$KENNEL" -- curl -s --max-time 5 http://example.com:8080
check "--no-network blocks TCP 443"      nonzero "$KENNEL" --no-network -- curl -s --max-time 5 https://example.com
check "child processes stay confined"    nonzero "$KENNEL" -- bash -c "cat $HOME/.ssh/* 2>/dev/null || exit 1"
check "drops secrets from the environment" nonzero env KENNEL_TEST_SECRET=x "$KENNEL" -- bash -c '[ -n "${KENNEL_TEST_SECRET:-}" ]'
check "--env passes a variable through"  0       env KENNEL_TEST_SECRET=x "$KENNEL" --env KENNEL_TEST_SECRET -- bash -c '[ -n "${KENNEL_TEST_SECRET:-}" ]'
check "closes inherited fds"             nonzero bash -c "exec 9</etc/hostname; \"$KENNEL\" -- bash -c 'cat <&9'"
check "blocks signals to outside"        nonzero bash -c "sleep 30 & p=\$!; \"$KENNEL\" -- kill -0 \$p; r=\$?; kill \$p; exit \$r"
check "blocks writing to /tmp"           nonzero "$KENNEL" -- touch /tmp/kennel-pwned
check "TMPDIR is writable"               0       "$KENNEL" -- bash -c 'touch "$TMPDIR/x"'
printf '[fs]\nread_write = ["~"]\n' > .kennel.toml
check "refuses unapproved .kennel.toml"  nonzero "$KENNEL" -- true
rm .kennel.toml
(cd "$HOME" && "$KENNEL" -- true) >/dev/null 2>&1 && { echo "FAIL: home-dir guard"; fail=$((fail+1)); } || { echo "PASS: refuses to run with cwd=\$HOME"; pass=$((pass+1)); }

echo
echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
