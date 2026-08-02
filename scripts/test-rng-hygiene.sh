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

cd "$(dirname "$0")/.." || { echo "FAIL: cannot cd to the repo root"; exit 1; }
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

    # The probe must exist on disk, not just in the index: the guard's shebang
    # sweep reads bytes with `head`. So this does write into the working tree,
    # briefly, and removes the file on every path including the EXIT trap.
    # Refuse rather than clobber if the name is already taken.
    if [ -e "$name" ]; then
        echo "  HARNESS BROKEN: $name already exists; refusing to overwrite a real file"
        fails=$((fails + 1))
        return
    fi
    PROBE="$name"
    printf '%s' "$content" > "$name"

    # Build the temp index from HEAD rather than copying .git/index. The copy
    # depended on that file existing and being current, which is not guaranteed
    # under every checkout, and an empty index made the guard abort with "no
    # sources found" for every case: the reject cases then passed for entirely
    # the wrong reason while the accept cases failed.
    rm -f "$TMPDIR_T/index"
    GIT_INDEX_FILE="$TMPDIR_T/index" git read-tree HEAD 2>/dev/null
    GIT_INDEX_FILE="$TMPDIR_T/index" git add -f "$name" 2>/dev/null

    local staged
    staged=$(GIT_INDEX_FILE="$TMPDIR_T/index" git ls-files | wc -l)
    if [ "$staged" -lt 10 ]; then
        echo "  HARNESS BROKEN: only $staged file(s) staged; the guard would scan almost nothing"
        fails=$((fails + 1))
        rm -f "$name"; PROBE=""
        return
    fi

    local rc=0 out
    out=$(GIT_INDEX_FILE="$TMPDIR_T/index" "$GUARD" 2>&1) || rc=$?

    rm -f "$name"; PROBE=""

    if [ "$expect" = fail ]; then
        if [ "$rc" -eq 0 ]; then
            echo "  BYPASS: $desc"
            fails=$((fails + 1))
        elif ! printf '%s' "$out" | grep -qF "$name"; then
            # The guard failed, but not because of this probe. Without this the
            # test would credit an unrelated abort as a successful detection.
            echo "  WRONG REASON: $desc (guard failed without naming $name)"
            fails=$((fails + 1))
        else
            echo "  ok: $desc"
        fi
    else
        if [ "$rc" -ne 0 ]; then
            echo "  FALSE POSITIVE: $desc"
            printf '%s\n' "$out" | sed 's/^/      /' | head -4
            fails=$((fails + 1))
        else
            echo "  ok: $desc"
        fi
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

# One line on purpose. Split across two, the second line is caught whatever the
# comment splitter does, so the probe would pass even against the naive
# index($0, "#") this case exists to rule out.
run_probe probe_hash_string.sh 'printf "#x"; pass=$(head -c 32 /dev/urandom)
' fail "a # inside a string does not start a comment and hide a read on the same line"

run_probe probe_marker_string.sh 'msg="#rng-hygiene: ok"; pass="/dev/urandom"
' fail "an opt-out marker inside a string literal does not exempt the same line"

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
