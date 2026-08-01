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

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  printf '\n\033[31mFAIL\033[0m not inside a git work tree; this guard scans tracked files only\n'
  exit 1
}

list_sources() {
  git ls-files '*.nix' '*.sh' '*.py' 'justfile' \
    | grep -vE '^tests/'
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
      BEGIN { blockopt = 0 }
      {
        line = trim($0)
        p = index($0, "#")
        code = (p > 0) ? trim(substr($0, 1, p - 1)) : line
        cmt  = (p > 0) ? substr($0, p) : ""

        if (code == "") { if (index(cmt, optout)) blockopt = 1; next }
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

scanner_died() {
  printf '\n\033[31mFAIL\033[0m the scanner itself failed; refusing to report a clean tree\n' >&2
  exit 1
}

scan() { # $1 = ERE
  printf '%s\n' "$CODE" | awk -v pat="$1" '{
    line = $0; sub(/^[^:]*:[0-9]+:/, "", line)
    if (line ~ pat) print $0
  }' || scanner_died
}

report() { # $1 = findings, $2 = headline, $3.. = hints
  [ -z "$1" ] && return 0
  fail "$2"
  printf '%s\n' "$1" | sed 's/^/  /'
  shift 2
  for hint in "$@"; do echo "  → $hint"; done
}

# ------------------------------------------ 1. no non-blocking entropy read ----
urandom_bad=$(scan '/dev/urandom')
report "$urandom_bad" "reads /dev/urandom, which never waits for the kernel CRNG:" \
  'use /dev/random. On Linux >= 5.6 it blocks only until the CRNG is initialised' \
  'and never afterwards, which is the guarantee a first-boot appliance needs.' \
  "Mark a deliberate non-key-material read: # $OPT_OUT - <reason>"

# ------------------------------------------------- 2. no bash seeded PRNG ----
bashrandom_bad=$(scan '(^|[^a-zA-Z0-9_])RANDOM([^a-zA-Z0-9_]|$)')
report "$bashrandom_bad" "uses bash \$RANDOM, a seeded PRNG:" \
  'fine for retry jitter, never for key material.' \
  "Mark the jitter case: # $OPT_OUT - <reason>"

# ------------------------------ 3. the bootstrap passphrase stays length-checked --
# The one repo-specific invariant. `head -c 32 /dev/random | base64` exits 0 with
# a short string if the read is truncated, which would luksFormat the vault
# volume under a truncated passphrase and carry on. The check is what makes that
# loud, so it is pinned rather than trusted to survive editing.
if [ -f nixos/frost-gate.nix ]; then
  if ! grep -q 'refusing to format' nixos/frost-gate.nix; then
    fail "nixos/frost-gate.nix no longer length-checks the LUKS bootstrap passphrase:"
    echo "  → a short entropy read must abort provisioning, not format the volume"
    echo "    under a truncated passphrase. See the comment above the read."
  fi
else
  fail "nixos/frost-gate.nix not found; rule 3 cannot run (was the module moved?)"
fi

if [ "$status" -eq 0 ]; then
  echo "RNG hygiene: OK (no /dev/urandom, no bash \$RANDOM outside marked jitter, bootstrap passphrase length-checked)"
fi
exit "$status"
