#!/usr/bin/env bash
# Fail if the appliance can generate key material from an entropy source that
# might not be ready.
#
# Motivated by the COLDCARD firmware disclosure (Block, 2026-07):
# https://engineering.block.xyz/blog/predictable-rng-fallback-and-32-bit-reseed-in-coldcard-firmware
# A guard that checked only whether a macro was *defined* -- not whether it was
# *enabled* -- silently bound wallet seed generation to a non-cryptographic
# fallback PRNG. Nothing crashed, nothing logged, and the firmware shipped that
# way for years. The lesson is not "use a CSPRNG"; every codebase already
# intends to. The lesson is that a degraded RNG path must not be able to succeed
# quietly, and that only a mechanical check keeps it that way.
#
# The shape that bug takes in an appliance image:
#
#   1. /dev/urandom never blocks. Read before the kernel CRNG is initialised it
#      returns output anyway, with nothing but a kernel log line to say so. This
#      box generates the LUKS passphrase for the vault volume on the FIRST boot
#      of a freshly imaged disk, before any seed file exists, which is precisely
#      the window where that matters. /dev/random on Linux >= 5.6 blocks only
#      until the CRNG is up and never afterwards, so it is strictly better here
#      at no cost. Rule 1 requires it.
#   2. $RANDOM is bash's seeded PRNG. Fine for retry jitter, never for a key.
#      Rule 2 requires an explicit marker.
#
# Deliberate non-crypto randomness is allowed with an inline opt-out on the same
# line or in the comment block directly above:
#
#     sleep $(( 10 + RANDOM % 5 ))   # rng-hygiene: ok - retry jitter
#
# This guard fails CLOSED. A scanner error, a run outside a git work tree, or an
# empty file list is reported as a failure rather than silently passing: a guard
# that prints "OK" when it scanned nothing is worse than no guard, because it
# gets trusted.
#
# Scope: TRACKED Nix, shell, and Python under nixos/ and the repo root. tests/
# is excluded -- test fixtures are deterministic on purpose, and a VM test that
# reads /dev/urandom is not provisioning a real box.
#
# What this does NOT cover: it is a grep, so it catches the source, not what the
# value becomes. It cannot see into the keep binaries the appliance runs (those
# have their own guard in the keep repo), into nixpkgs, or into systemd's own
# seeding. And "reads /dev/random" is not proof the CRNG had real entropy behind
# it on a given piece of hardware, only that the read waited for the kernel to
# say it was ready.
#
# Portable to BSD awk. Run from anywhere; exits non-zero with the offending lines.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

status=0
fail() { printf '\n\033[31mFAIL\033[0m %s\n' "$1"; status=1; }

OPT_OUT='rng-hygiene: ok'
# This script is a .sh file and its rules name the very tokens they ban, so it
# would report itself. Excluded by path rather than by opt-out markers, which
# would blunt the markers' signal. Caught only after committing: run untracked,
# `git ls-files` did not list it and it passed locally while failing in CI.
# The self-test carries the same banned tokens as probe fixtures, so it hits
# this identically. Both are excluded by path.
SELF='scripts/check-rng-hygiene.sh
scripts/test-rng-hygiene.sh'

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  printf '\n\033[31mFAIL\033[0m not inside a git work tree; this guard scans tracked files only\n'
  exit 1
}

# Extension list plus a shebang sweep. An extension gate alone is a bypass: the
# same read in `scripts/x.bash`, or in an extensionless hook, was simply never
# scanned. Anything tracked that declares itself a shell or python program gets
# scanned whatever it is called.
list_sources() {
  {
    git ls-files '*.nix' '*.sh' '*.bash' '*.py' 'justfile'
    git ls-files | while IFS= read -r f; do
      case "$f" in
        *.nix|*.sh|*.bash|*.py|justfile) continue ;;
      esac
      [ -f "$f" ] || continue
      case "$(head -c 80 "$f" 2>/dev/null | head -n 1)" in
        '#!'*sh|'#!'*sh\ *|'#!'*python*|'#!'*bash*) printf '%s\n' "$f" ;;
      esac
    done
  } | sort -u \
    | grep -vE '^tests/' \
    | grep -vxF "$SELF"
}

SOURCES=$(list_sources)
if [ -z "$SOURCES" ]; then
  printf '\n\033[31mFAIL\033[0m no sources found to scan; the file list is broken\n'
  exit 1
fi

# Emit "file:line:code" for live code lines, dropping `#` comments (Nix, shell
# and Python all use them) and honouring the opt-out marker. String literals are
# left intact: the values this guard cares about -- a device path like
# "/dev/urandom" -- live inside them.
preprocess() {
  local f rc out
  rc=0
  for f in $SOURCES; do
    out=$(awk -v fname="$f" -v optout="$OPT_OUT" '
      function trim(s) { sub(/^[ \t]*/, "", s); sub(/[ \t]*$/, "", s); return s }

      # Split a line into code and comment, honouring quoting. A naive
      # index($0, "#") splits `''${#pass}` and, worse, treats a `#` inside a
      # string as a comment start -- which let `printf "#x"; pass=/dev/urandom`
      # hide the read, and let an opt-out marker inside a string literal exempt
      # a line with no comment a reviewer could see.
      function split_line(s,   i, c, n, q, out) {
        out = ""; cmt = ""; q = ""
        n = length(s)
        for (i = 1; i <= n; i++) {
          c = substr(s, i, 1)
          if (q != "") {
            if (c == "\\") { out = out c substr(s, i + 1, 1); i++; continue }
            if (c == q) q = ""
            out = out c
            continue
          }
          if (c == "\"" || c == "'"'"'") { q = c; out = out c; continue }
          if (c == "#") { cmt = substr(s, i); return out }
          out = out c
        }
        return out
      }

      BEGIN { blockopt = 0; prose = 0 }
      {
        raw = $0
        code = trim(split_line(raw))

        # Nix option documentation is prose, not code. Without this, a
        # description mentioning /dev/urandom is a finding, and the only way to
        # silence it is a marker that renders as literal text in the rendered
        # option docs.
        if (prose) {
          if (raw ~ /(\x27\x27;|\x27\x27[ \t]*$)/) prose = 0
          next
        }
        if (code ~ /(description|example|longDescription)[ \t]*=[ \t]*\x27\x27/ && code !~ /\x27\x27.*\x27\x27[ \t]*;/) {
          prose = 1
          next
        }

        # A blank line ends the comment block, so a marker cannot carry across
        # unrelated lines to exempt something far below it.
        if (code == "" && cmt == "") { blockopt = 0; next }
        if (code == "") { blockopt = (index(cmt, optout) ? 1 : blockopt); next }
        if (index(cmt, optout) || blockopt) { blockopt = 0; next }
        blockopt = 0
        printf "%s:%d:%s\n", fname, FNR, code
      }
    ' "$f") || rc=2
    [ -n "$out" ] && printf '%s\n' "$out"
  done
  return "$rc"
}

CODE=$(preprocess) || {
  printf '\n\033[31mFAIL\033[0m the scanner itself failed; refusing to report a clean tree\n'
  exit 1
}
if [ -z "$CODE" ]; then
  printf '\n\033[31mFAIL\033[0m preprocessor produced no code lines; the guard scanned nothing\n'
  exit 1
fi

# Called from the CALLER, never from inside the command substitution: an `exit`
# in a substitution terminates only the subshell, so `x=$(scan ...) ` would have
# swallowed the failure and reported a clean tree. That is the fail-open shape
# this guard exists to reject.
scanner_died() {
  printf '\n\033[31mFAIL\033[0m the scanner itself failed; refusing to report a clean tree\n' >&2
  exit 1
}

# Splitting the token across a concatenation hid it from a line regex:
# `src = "/dev/" + "urandom"` and `"/dev/" ++ "urandom"` both read the same file
# at runtime. Collapse quote-adjacent concatenation before matching so the rules
# see the string the program actually builds. Reported against the raw line, so
# the output still shows what the author wrote.
normalise() {
  sed -E 's/"[ \t]*\+\+?[ \t]*"//g; s/"[ \t]*"//g; s/\x27[ \t]*\+\+?[ \t]*\x27//g'
}

scan() { # $1 = ERE
  printf '%s\n' "$CODE" | awk -v pat="$1" '{
    raw = $0
    line = $0; sub(/^[^:]*:[0-9]+:/, "", line)
    norm = line
    gsub(/"[ \t]*\+\+?[ \t]*"/, "", norm)
    gsub(/"[ \t]*"/, "", norm)
    if (line ~ pat || norm ~ pat) print raw
  }'
}

report() { # $1 = findings, $2 = headline, $3.. = hints
  [ -z "$1" ] && return 0
  fail "$2"
  printf '%s\n' "$1" | sed 's/^/  /'
  shift 2
  for hint in "$@"; do echo "  → $hint"; done
}

# ------------------------------------------ 1. no non-blocking entropy read ----
urandom_bad=$(scan '/dev/urandom') || scanner_died
report "$urandom_bad" "reads /dev/urandom, which never waits for the kernel CRNG:" \
  'use /dev/random. On Linux >= 5.6 it blocks only until the CRNG is initialised' \
  'and never afterwards, which is the guarantee a first-boot appliance needs.' \
  "Mark a deliberate non-key-material read: # $OPT_OUT - <reason>"

# ----------------------------------- 1b. no device path built at runtime ----
# `d=urandom; head -c 32 /dev/$d` reads the banned device while matching no
# literal. A dynamic /dev/ path is rare enough in this repo that requiring the
# marker on it costs nothing, and it closes the indirection route into rule 1.
dyndev_bad=$(scan '/dev/[$"\x27]|/dev/\$\{') || scanner_died
report "$dyndev_bad" "builds a /dev path at runtime, so rule 1 cannot see which device is read:" \
  'name the device literally, or mark it if the indirection is deliberate.' \
  "Mark it: # $OPT_OUT - <reason>"

# ------------------------------------------------- 2. no bash seeded PRNG ----
bashrandom_bad=$(scan '(^|[^a-zA-Z0-9_])RANDOM([^a-zA-Z0-9_]|$)') || scanner_died
report "$bashrandom_bad" "uses bash \$RANDOM, a seeded PRNG:" \
  'fine for retry jitter, never for key material.' \
  "Mark the jitter case: # $OPT_OUT - <reason>"

# ------------------ 3. the bootstrap passphrase draw keeps both its guarantees --
# The repo-specific invariant, and the one rule that has to check for something
# being PRESENT rather than absent. Rule 1 only bans /dev/urandom; on its own,
# replacing the whole draw with `date +%s | sha256sum` leaves CI green.
#
# Pinned structurally, not by error message: an earlier version grepped for the
# text "refusing to format", so deleting the check while leaving the words in a
# comment passed.
if [ ! -f nixos/frost-gate.nix ]; then
  fail "nixos/frost-gate.nix not found; rule 3 cannot run (was the module moved?)"
else
  if ! grep -qE 'head -c 32 /dev/random' nixos/frost-gate.nix; then
    fail "the LUKS bootstrap passphrase no longer reads 32 bytes from /dev/random:"
    echo "  → this is the only key material this repo mints itself. It must come from"
    echo "    the source that waits for the kernel CRNG, not from a derived value."
  fi
  if ! grep -qE '\-eq 44' nixos/frost-gate.nix; then
    fail "nixos/frost-gate.nix no longer length-checks the LUKS bootstrap passphrase:"
    echo "  → a short entropy read must abort provisioning, not format the volume"
    echo "    under a truncated passphrase. base64 of 32 bytes is exactly 44 chars."
  fi
fi

if [ "$status" -eq 0 ]; then
  echo "RNG hygiene: OK (no /dev/urandom, no bash \$RANDOM outside marked jitter, bootstrap passphrase drawn from /dev/random and length-checked)"
fi
exit "$status"
