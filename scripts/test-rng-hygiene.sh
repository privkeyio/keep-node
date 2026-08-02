#!/usr/bin/env bash
# Self-test for check-rng-hygiene.sh.
#
# A guard nobody tests is a guard that quietly stops guarding. Seven bypasses of
# this script were found by hand; five were fixed and four more survived into a
# later revision, because nothing asserted that a known bypass still fails. Each
# case below is one of those, and each runs against a positive control so a
# scanner that silently stopped scanning cannot pass this file.
#
# Probe files are staged into a throwaway GIT_INDEX_FILE, never the real index:
# check-rng-hygiene.sh enumerates work via `git ls-files`, which honours that
# variable, so the working tree and the developer's staged changes are untouched.
set -uo pipefail

cd "$(dirname "$0")/.."
GUARD=scripts/check-rng-hygiene.sh
[ -x "$GUARD" ] || { echo "FAIL: $GUARD not found or not executable"; exit 1; }

TMPDIR_T=$(mktemp -d)
cleanup() { rm -rf "$TMPDIR_T"; rm -f "${PROBE:-}"; }
trap cleanup EXIT

fails=0
PROBE=""

# run_probe <filename> <content> <expect: pass|fail> <description>
run_probe() {
    local name="$1" content="$2" expect="$3" desc="$4"
    PROBE="$name"
    printf '%s' "$content" > "$name"

    cp .git/index "$TMPDIR_T/index" 2>/dev/null || : > "$TMPDIR_T/index"
    GIT_INDEX_FILE="$TMPDIR_T/index" git add "$name" 2>/dev/null

    local rc=0
    GIT_INDEX_FILE="$TMPDIR_T/index" "$GUARD" >/dev/null 2>&1 || rc=$?

    rm -f "$name"; PROBE=""

    if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
        echo "  BYPASS: $desc"
        fails=$((fails + 1))
    elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
        echo "  FALSE POSITIVE: $desc"
        fails=$((fails + 1))
    else
        echo "  ok: $desc"
    fi
}

echo "== the guard rejects what it is supposed to reject =="

run_probe probe_plain.nix 'let x = "/dev/urandom"; in x
' fail "plain /dev/urandom (positive control: if this passes, nothing below means anything)"

run_probe probe_concat.nix 'let src = "/dev/" + "urandom"; in src
' fail "nix string concatenation splitting the token"

run_probe probe_concat2.nix 'let src = "/dev/" ++ "urandom"; in src
' fail "nix list-concat spelling of the same split"

run_probe probe_indirect.sh 'd=urandom
head -c 32 /dev/$d > /tmp/k
' fail "shell variable indirection building the device path"

run_probe probe_brace.sh 'd=urandom
head -c 32 /dev/${d} > /tmp/k
' fail "brace-expanded indirection"

run_probe probe_ext.bash 'head -c 32 /dev/urandom > /tmp/k
' fail ".bash extension is scanned, not skipped by the extension gate"

run_probe probe_shebang '#!/usr/bin/env bash
head -c 32 /dev/urandom > /tmp/k
' fail "extensionless file with a shell shebang is scanned"

run_probe probe_pyshebang '#!/usr/bin/env python3
open("/dev/urandom", "rb").read(32)
' fail "extensionless python file is scanned"

run_probe probe_hash_string.sh 'printf "#x"
pass=$(head -c 32 /dev/urandom)
' fail "a # inside a string does not start a comment and hide the read"

run_probe probe_marker_string.sh 'msg="#rng-hygiene: ok"
pass="/dev/urandom"
' fail "an opt-out marker inside a string literal does not exempt the line"

run_probe probe_random.sh 'k=$RANDOM
' fail "bash \$RANDOM"

echo "== the guard accepts what it is supposed to accept =="

run_probe probe_good.sh 'head -c 32 /dev/random > /tmp/k
' pass "/dev/random is the sanctioned source"

run_probe probe_marked.sh '# rng-hygiene: ok - retry jitter, not key material
sleep "0.$RANDOM"
' pass "a real opt-out comment on the preceding line still works"

echo
if [ "$fails" -ne 0 ]; then
    echo "FAIL: $fails case(s) did not behave as required"
    exit 1
fi
echo "OK: check-rng-hygiene.sh rejects every known bypass and accepts sanctioned use"
