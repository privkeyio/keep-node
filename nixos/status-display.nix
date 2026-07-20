# A read-only, Keep-branded status screen on the physical console. It paints what the node is doing ,
# vault state, service health, and (opt-in) mesh facts , onto a virtual terminal, and accepts nothing
# back.
#
# The problem it solves: an installed node boots to a bare kernel log dump followed by a `keepnode
# login:` prompt where every account is password-locked. An operator standing in front of the box
# therefore learns NOTHING about why the vault did not unlock or why the mesh did not form. The only
# diagnostic channel is SSH over the mesh , which means you need working SSH to diagnose why SSH might
# not be working. That is the gap: the one moment the operator has physical presence is the one moment
# the appliance tells them the least.
#
# Scope fence: physical console access grants NOTHING today, and it must continue to grant nothing.
# This display accepts NO input, reaches NO shell, and confers NO privilege. It does not touch the
# FROST threshold model, adds no password path, opens no listening port, and introduces no network-
# reachable daemon. It is a one-way pane of glass: information flows out to the operator's eyes and
# nothing flows back in. Anything that would make the console actionable belongs in a different module
# with a different threat model.
#
# Backward compatibility: off by default. Enabling it is an explicit operator decision, and leaving it
# off changes nothing whatsoever for existing deployments.
#
# The module is two halves that must stay two halves. The COLLECTOR runs as root on a timer, probes the
# node, and publishes one JSON snapshot under /run. The RENDERER runs unprivileged, reads that snapshot,
# and paints it. Nothing but a file crosses between them, so the thing holding the terminal has no
# privilege to lose and the thing holding the privilege has no terminal to be attacked through.
#
# The single most important line in this file is `StandardInput = "null"` on the renderer. The renderer
# holds NO file descriptor on the keyboard: not `tty`, not `tty-force`. There is therefore no read path
# to escape from, no line discipline to poke, and no "press a key" affordance to find. That is what
# makes "physical console grants nothing" a structural property rather than a promise about how
# carefully the script parses input , it parses no input at all.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.statusDisplay;

  # Probe targets are read out of the config of OTHER modules, every one of which is optional and may
  # not even be imported on a given node. `x.y or default` tolerates a missing attribute at any level
  # of the path, so a minimal node that imports neither frost-gate nor vault-replication still
  # evaluates -- and reports those subsystems as absent rather than as broken.
  gateEnabled = config.keepNode.frostGate.enable or false;
  gateDataDir = config.keepNode.frostGate.dataDir or "/var/lib/vaultwarden";
  gateMapper = config.keepNode.frostGate.mapperName or "keep-vault";
  meshEnabled = config.keepNode.mesh.enable or false;
  meshInterface = config.keepNode.mesh.interface or "";
  replRole = config.keepNode.vaultReplication.role or null;

  statusDir = "/run/keep-node-status";
  statusFile = "${statusDir}/status.json";

  brand = import ./lib/brand.nix { inherit lib; };

  ttyPath = "/dev/tty${toString cfg.tty}";
  gettyUnit = "getty@tty${toString cfg.tty}.service";

  # The account the renderer runs as. It exists only to be a uid that owns a terminal and can read one
  # world-readable file, which is exactly the amount of authority the console is allowed to represent.
  renderUser = "keep-status";

  # Static config, so it survives the staleness blanking below: this line is not a collected fact, and
  # it is precisely what an operator standing at a screen full of `??` needs in order to go fix it.
  sshCommand =
    if (config.keepNode.adminAccess.enable or false) then
      "ssh keepadmin@${config.networking.hostName}"
    else
      "admin SSH not configured on this node";

  # Appended only on the widest tier, and only when it FITS (see build_frame). Truncating a reassurance
  # mid-word is worse than not showing it: the longest static command text plus the older, wordier note
  # came to 79 columns against the 78 a two_col left field gets at w=80, so the note lost its closing
  # paren and read as an unterminated aside. The command itself is the part that must survive at every
  # width, so the note is both shorter than that budget and dropped whole rather than cut.
  sshNote = " (key-only; no console login)";

  shellList = xs: lib.concatMapStringsSep " " lib.escapeShellArg xs;

  collector = pkgs.writeShellScriptBin "keep-node-status-collect" ''
    set -euo pipefail

    # Operator-supplied strings (paths, interface and mapper names, the node label) are bound to shell
    # VARIABLES via escapeShellArg and only ever referenced as "$var". A variable's contents are never
    # re-scanned for command substitution, so no config value can execute as root here -- the same
    # discipline as nixos/admin-access.nix's key check.
    probe_timeout=${toString cfg.probeTimeoutSeconds}
    dir=${lib.escapeShellArg statusDir}
    node_label=${lib.escapeShellArg cfg.nodeLabel}
    vault_dir=${lib.escapeShellArg gateDataDir}
    vault_mapper=${lib.escapeShellArg "/dev/mapper/${gateMapper}"}
    mesh_iface=${lib.escapeShellArg (if meshEnabled then meshInterface else "")}
    repl_role=${lib.escapeShellArg (if replRole == null then "" else replRole)}

    # EVERY output variable is pre-initialised. The invariant this module lives or dies by is that the
    # write block at the bottom is reached on every run: a collector that exits early leaves the
    # PREVIOUS snapshot in place, and a renderer then paints stale numbers with nothing on the glass
    # admitting why. "unknown" is the honest default for a probe that never got to run.
    vault_state=unknown
    gate_state=unknown
    svc_vaultwarden=unknown
    svc_mesh=unknown
    svc_wisp=unknown
    anti_lockout=unknown
    anti_lockout_at_json=null
    repl_lag_check=unknown
    mesh_up=false
    mesh_addr=""
    lag_json=null

    is_uint() {
      case "''${1:-}" in
        "" | *[!0-9]*) return 1 ;;
        *) return 0 ;;
      esac
    }

    # Every probe runs under a wall-clock timeout: one wedged systemctl or findmnt must not stall the
    # round, because a stalled round ages the snapshot and would eventually mark the WHOLE screen STALE
    # when in truth a single subsystem is hung.
    run() {
      ${pkgs.coreutils}/bin/timeout "$probe_timeout" "$@"
    }

    # The three-way unit state. Conflating these is the single most damaging thing this collector could
    # do, because most probe targets belong to OPTIONAL modules and on a minimal node legitimately do
    # not exist:
    #   LoadState=not-found (or masked) -> "n/a"     the owning module is off; this is normal
    #   probe timed out / returned nothing -> "unknown"   we could not tell
    #   otherwise -> the real ActiveState
    # An absent unit must NEVER render as "failed": that sends an operator chasing a subsystem the node
    # was never configured to run.
    #
    # ONE systemctl call, parsed as KEY=value rather than with --value, because `systemctl show` does
    # not promise to echo multiple --property requests back in the order they were asked. Sets `load`
    # and `active` for the two wrappers below, each of which owns only its final mapping -- the shared
    # probe is identical for both and duplicating it invites the two readings to drift apart.
    unit_load_active() {
      local out
      load=""
      active=""
      out="$(run ${pkgs.systemd}/bin/systemctl show --property=LoadState --property=ActiveState -- "$1" 2>/dev/null || true)"
      load="$(printf '%s\n' "$out" | ${pkgs.gnused}/bin/sed -n 's/^LoadState=//p' || true)"
      active="$(printf '%s\n' "$out" | ${pkgs.gnused}/bin/sed -n 's/^ActiveState=//p' || true)"
    }

    unit_state() {
      local load active
      unit_load_active "$1"
      case "$load" in
        "") echo unknown ;;
        not-found | masked) echo "n/a" ;;
        *)
          if [ -z "$active" ]; then echo unknown; else echo "$active"; fi
          ;;
      esac
    }

    # Timer-driven Type=oneshot units WITHOUT RemainAfterExit report nothing on success: the unit falls
    # back to "inactive" the moment the run ends, so ActiveState carries a fail signal but no pass
    # signal. Read through unit_state above, "inactive" maps to warn and a perfectly healthy node shows
    # a permanent amber row -- the cry-wolf failure the staleSeconds assertion exists to prevent,
    # arriving by another door. nixos/vault-replication.nix:628 states the contract for such a unit:
    # `systemctl is-failed keep-node-vault-lag-check` IS the monitoring signal. So: failed -> "failed",
    # anything else -> "ok". The three-way discipline is unchanged -- an absent unit is still "n/a" and
    # never "failed", and a probe that did not return is still "unknown".
    check_unit_state() {
      local load active
      unit_load_active "$1"
      case "$load" in
        "") echo unknown ;;
        not-found | masked) echo "n/a" ;;
        *)
          case "$active" in
            "") echo unknown ;;
            failed) echo failed ;;
            *) echo ok ;;
          esac
          ;;
      esac
    }

    # WHEN the anti-lockout backstop last actually ran. keep-node-admin-key-check is Type=oneshot +
    # RemainAfterExit with NO timer anywhere in the tree: it runs once at boot and LATCHES "active"
    # forever. A key deleted after boot -- named at nixos/admin-access.nix:158 as precisely the
    # scenario the backstop exists for -- never re-triggers it, so the row would paint a green
    # ANTI-LOCKOUT ok on a node whose admin SSH is already gone.
    #
    # That is worse than ordinary staleness because this display's contract trains the operator to
    # trust it: every other field blanks to "??" the moment it stops being current, so a non-"??"
    # value reads as "known right now". A boot-latched verdict wearing live-data clothing is exactly
    # the failure this feature exists to prevent, so the age of the verdict is carried alongside it
    # and rendered ("active (checked 41d ago)") rather than left implied.
    #
    # --timestamp=unix yields "@<epoch>"; a never-activated unit yields "@0" or an empty value, both
    # of which fall through to "" and simply omit the age rather than claiming a bogus one.
    unit_active_since() {
      local ts
      ts="$(run ${pkgs.systemd}/bin/systemctl show --timestamp=unix --property=ActiveEnterTimestamp --value -- "$1" 2>/dev/null || true)"
      ts="''${ts#@}"
      if is_uint "$ts" && [ "$ts" -gt 0 ]; then printf '%s' "$ts"; fi
    }

    now="$(run ${pkgs.coreutils}/bin/date +%s 2>/dev/null || echo unknown)"
    is_uint "$now" || now=0

    # Type=oneshot + RemainAfterExit units (the anti-lockout check at nixos/admin-access.nix:170-171,
    # the frost gate) LATCH "active" after a successful run and "failed" after a bad one -- that is the
    # intended reading, not a liveness claim. The frost gate's "activating" means an unlock is genuinely
    # in flight. keep-node-vault-lag-check does NOT latch and so must not be read this way.
    gate_state="$(unit_state keep-node-frost-gate.service || echo unknown)"
    svc_vaultwarden="$(unit_state vaultwarden.service || echo unknown)"
    svc_mesh="$(unit_state keep-node-mesh.service || echo unknown)"
    svc_wisp="$(unit_state wisp.service || echo unknown)"
    anti_lockout="$(unit_state keep-node-admin-key-check.service || echo unknown)"
    anti_lockout_at="$(unit_active_since keep-node-admin-key-check.service || true)"
    if is_uint "$anti_lockout_at"; then
      anti_lockout_at_json="$anti_lockout_at"
    fi
    repl_lag_check="$(check_unit_state keep-node-vault-lag-check.service || echo unknown)"

    ${
      if !gateEnabled then
        ''
          # No gate configured, so there is no encrypted volume whose state could be reported. "n/a",
          # not "locked": a node that was never gated is not a node whose vault failed to open.
          vault_state="n/a"
        ''
      else
        ''
          # Mirrors the fail-closed mount guard in nixos/frost-gate.nix:118-123. A dataDir backed by a
          # source that is NOT our mapper is the plaintext-exposure case the gate itself refuses to
          # proceed on, so it gets its own alarm state and is never folded into "locked" or "unlocked".
          if src="$(run ${pkgs.util-linux}/bin/findmnt -no SOURCE -- "$vault_dir" 2>/dev/null)"; then
            findmnt_rc=0
          else
            findmnt_rc=$?
            src=""
          fi
          if [ "$findmnt_rc" -gt 1 ]; then
            # Exit 1 is findmnt's ordinary "no match" (not a mountpoint). Anything above it, including
            # timeout's 124, means the probe itself failed and we genuinely do not know.
            vault_state=unknown
          elif [ -z "$src" ]; then
            vault_state=locked
          elif [ "$src" = "$vault_mapper" ]; then
            vault_state=unlocked
          else
            vault_state=wrong-device
          fi
        ''
    }

    ${lib.optionalString meshEnabled ''
      # tun devices sit at "state UNKNOWN" even when carrying traffic, so operational state is read
      # from the IFF_UP flag inside <...> rather than from the state word, which would read every
      # healthy mesh interface as down.
      if link="$(run ${pkgs.iproute2}/bin/ip -o link show dev "$mesh_iface" 2>/dev/null)"; then
        flags="$(printf '%s' "$link" | ${pkgs.gnused}/bin/sed -n 's/.*<\([^>]*\)>.*/\1/p' || true)"
        case ",$flags," in
          *,UP,*) mesh_up=true ;;
          *) mesh_up=false ;;
        esac
      fi
    ''}

    ${lib.optionalString (meshEnabled && cfg.showMeshAddress) ''
      # awk (not `head`) consumes the whole stream: under `set -o pipefail` a SIGPIPE'd producer would
      # be reported as a failed probe on a perfectly healthy interface.
      mesh_addr="$(run ${pkgs.iproute2}/bin/ip -o -4 addr show dev "$mesh_iface" 2>/dev/null | ${pkgs.gawk}/bin/awk 'NR==1{split($4,a,"/"); print a[1]}' || true)"
    ''}

    ${lib.optionalString (replRole == "standby") ''
      # keep-node-vault-lag-check logs exactly one line per run; its unit state is the pass/fail signal
      # and this recovers the NUMBER behind it so the screen can show how far behind the standby is.
      lag_line="$(run ${pkgs.systemd}/bin/journalctl -u keep-node-vault-lag-check.service -n 50 -o cat --no-pager 2>/dev/null | ${pkgs.gawk}/bin/awk '/^vault replication lag: /{ l = $0 } END { print l }' || true)"
      lag="$(printf '%s' "$lag_line" | ${pkgs.gnused}/bin/sed -n 's/^vault replication lag: \([0-9][0-9]*\)s .*/\1/p' || true)"
      if is_uint "$lag"; then
        lag_json="$lag"
      fi
    ''}

    # Atomic publish: same-directory temp, mode set BEFORE any content exists, then rename. The
    # world-readable window therefore never holds a half-written file, and a reader either sees the
    # previous snapshot or the new one -- never a torn one.
    tmp="$dir/.status.json.$$"
    trap 'rm -f "$tmp"' EXIT
    # The `|| : >` fallback keeps a broken/unavailable `install` from being the one thing that stops a
    # snapshot from ever being published. Plain redirection creates the file at 0644 under this unit's
    # UMask=0022, so the fallback lands on the same mode rather than a laxer one.
    ${pkgs.coreutils}/bin/install -m 0644 /dev/null "$tmp" || : > "$tmp"

    # Schema 1 field vocabularies. Every unit field carries a raw systemd ActiveState ("active",
    # "inactive", "failed", ...) plus "n/a" and "unknown" -- EXCEPT replication.lag_check, which carries
    # a verdict: "ok" | "failed" | "n/a" | "unknown" (see check_unit_state above; its unit's ActiveState
    # is not a pass/fail signal). The schema stays at 1 because nothing has shipped, so no consumer of
    # an older vocabulary exists to keep working.
    #
    # Emitted through jq rather than concatenated by hand: a probe result containing a quote or a
    # backslash cannot produce unparseable output, and the renderer's only input stays machine-readable
    # no matter what the probes returned. --argjson values are all either a validated unsigned integer
    # or the literal null/true/false, so they cannot inject structure either.
    if ! ${pkgs.jq}/bin/jq -n \
      --argjson schema 1 \
      --argjson generated_at "$now" \
      --arg node "$node_label" \
      --arg vault_state "$vault_state" \
      --arg gate_state "$gate_state" \
      --arg svc_vaultwarden "$svc_vaultwarden" \
      --arg svc_mesh "$svc_mesh" \
      --arg svc_wisp "$svc_wisp" \
      --arg mesh_iface "$mesh_iface" \
      --argjson mesh_up "$mesh_up" \
      --arg mesh_addr "$mesh_addr" \
      --arg repl_role "$repl_role" \
      --arg repl_lag_check "$repl_lag_check" \
      --argjson repl_lag "$lag_json" \
      --arg anti_lockout "$anti_lockout" \
      --argjson anti_lockout_checked_at "$anti_lockout_at_json" \
      '{
         schema: $schema,
         generated_at: $generated_at,
         node: $node,
         vault: { state: $vault_state, gate: $gate_state },
         services: { vaultwarden: $svc_vaultwarden, mesh: $svc_mesh, wisp: $svc_wisp },
         mesh: {
           interface: (if $mesh_iface == "" then null else $mesh_iface end),
           up: $mesh_up,
           address: (if $mesh_addr == "" then null else $mesh_addr end)
         },
         replication: {
           role: (if $repl_role == "" then null else $repl_role end),
           lag_check: $repl_lag_check,
           lag_seconds: $repl_lag
         },
         anti_lockout: $anti_lockout,
         anti_lockout_checked_at: $anti_lockout_checked_at
       }' > "$tmp"; then
      # Last-ditch: even a broken jq must leave PARSEABLE json, so the renderer can BANNER a collector
      # fault instead of falling over on a truncated file and showing nothing at all. `error` is a
      # real degrade reason in the renderer (read_status), not decoration: generated_at here is
      # CURRENT, so staleness would never fire and without that read the frame would look entirely
      # normal -- hostname painted, every row "unknown", no banner at all.
      printf '{"schema":1,"generated_at":%s,"node":null,"error":"collector-emit-failed"}\n' "$now" > "$tmp"
    fi

    ${pkgs.coreutils}/bin/mv -f "$tmp" "$dir/status.json"
    trap - EXIT
  '';

  # ONE jq call per repaint, emitting a FIXED, ORDERED, newline-separated value list that a fixed
  # sequence of `read -r` consumes into named variables. No eval, no source, no dynamic variable names:
  # the snapshot cannot introduce a name, only fill a slot that already exists. `s` additionally folds
  # control characters to spaces so that no single value can ever span two lines and shift every
  # subsequent field into the wrong variable.
  jqProgram = ''
    def s: if . == null then "" else tostring end | gsub("[[:cntrl:]]"; " ");
    [ (.schema | s),
      (.generated_at | s),
      (.node | s),
      (.vault.state | s),
      (.vault.gate | s),
      (.services.vaultwarden | s),
      (.services.mesh | s),
      (.services.wisp | s),
      (.mesh.interface | s),
      (.mesh.up | s),
      (.mesh.address | s),
      (.replication.role | s),
      (.replication.lag_check | s),
      (.replication.lag_seconds | s),
      (.anti_lockout | s),
      (.anti_lockout_checked_at | s),
      (.error | s),
      "."
    ] | .[]
  '';

  renderer = pkgs.writeShellScriptBin "keep-node-status-render" ''
    set -euo pipefail

    # Same discipline as the collector: every operator-supplied string is bound to a shell VARIABLE via
    # escapeShellArg and only ever referenced as "$var", so no config value is ever re-scanned as code.
    status_file=${lib.escapeShellArg statusFile}
    stale_seconds=${toString cfg.staleSeconds}
    repaint_seconds=${toString cfg.repaintSeconds}
    node_label=${lib.escapeShellArg cfg.nodeLabel}
    host_name=${lib.escapeShellArg config.networking.hostName}
    ssh_command=${lib.escapeShellArg sshCommand}
    ssh_note=${lib.escapeShellArg sshNote}
    show_mesh_link=${if meshEnabled then "1" else "0"}
    show_mesh_addr=${if cfg.showMeshAddress then "1" else "0"}
    show_repl=${if replRole != null then "1" else "0"}

    mark_unicode=(${shellList brand.markUnicode})
    mark_ascii=(${shellList brand.markAscii})
    wordmark=${lib.escapeShellArg brand.wordmark}
    wordmark_ascii=${lib.escapeShellArg brand.wordmarkAscii}

    # --once renders exactly ONE frame to stdout and exits 0. It is not a parallel implementation: it
    # runs build_frame(), the same function the loop runs, and differs only in that it does not wrap the
    # frame in cursor-positioning control codes (there is no terminal to position on). The VM test
    # asserts real frame CONTENT through this path, so content and loop output cannot drift apart.
    once=0
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --once)
          once=1
          shift
          ;;
        --status-file)
          if [ "$#" -lt 2 ]; then
            echo "keep-node-status-render: --status-file needs a path" >&2
            exit 2
          fi
          status_file="$2"
          shift 2
          ;;
        *)
          echo "usage: keep-node-status-render [--once] [--status-file PATH]" >&2
          exit 2
          ;;
      esac
    done

    is_uint() {
      case "''${1:-}" in
        "" | *[!0-9]*) return 1 ;;
        *) return 0 ;;
      esac
    }

    # EVERY value taken from the snapshot passes through here before it reaches the screen. tr in the C
    # locale keeps only 0x20-0x7E, so an ESC, a CSI, an OSC title-set, a CR or a stray newline are gone
    # before any of them can reach the terminal's parser; the caller then hard-truncates to the field
    # width so a long value cannot push the layout apart either. The collector is trusted and this is
    # still done: it is the difference between "the screen is safe because the producer behaves" and
    # "the screen is safe regardless of what the producer emits".
    clean() {
      printf '%s' "''${1:-}" | LC_ALL=C ${pkgs.coreutils}/bin/tr -cd '[:print:]'
    }

    # Bound a snapshot-derived string to $1 characters. clean() sanitises CONTENT; this sanitises
    # LENGTH, which the banner no longer does for itself since it word-wraps instead of hard-cutting.
    # Callers that put a snapshot value into a banner must clip it, or one oversized field can grow the
    # header past the whole screen.
    clip() {
      local n=$1 s=''${2:-}
      if [ "''${#s}" -le "$n" ]; then
        printf '%s' "$s"
      else
        printf '%s...' "''${s:0:$n}"
      fi
    }

    repeat_char() {
      local n=$1 c=$2 out=""
      while [ "''${#out}" -lt "$n" ]; do
        out="$out$c"
      done
      printf '%s' "''${out:0:$n}"
    }

    # Capability detection runs per repaint, not once at startup: a serial console can be attached to a
    # box that has been up for months, and the frame after that must already be in the right alphabet.
    detect_caps() {
      ascii=0
      color=1
      case "''${TERM:-}" in
        "" | dumb | unknown)
          # No terminfo worth trusting: drop to the lowest common denominator on both axes.
          ascii=1
          color=0
          ;;
        vt100* | vt102* | vt220* | vt320*)
          ascii=1
          ;;
      esac
      case "''${LC_ALL:-''${LC_CTYPE:-''${LANG:-}}}" in
        *UTF-8* | *utf-8* | *UTF8* | *utf8*) : ;;
        # Not a UTF-8 locale: the block-glyph mark would arrive as mojibake, so use brand.markAscii.
        *) ascii=1 ;;
      esac
      if [ -n "''${NO_COLOR:-}" ]; then color=0; fi
      if [ "''${KEEPNODE_STATUS_ASCII:-0}" != 0 ]; then ascii=1; fi
      if [ "''${KEEPNODE_STATUS_NOCOLOR:-0}" != 0 ]; then color=0; fi
    }

    detect_geometry() {
      local size=""
      term_cols=""
      term_rows=""
      # stty is asked first because it reads the real kernel window size, where `tput cols` may only
      # know terminfo's static 80x24. It is pointed at fd 1, NOT at the renderer's own fd 0: fd 0 is
      # /dev/null (StandardInput=null) and knows nothing about any terminal. The `0<&1` is a redirection
      # scoped to this one command -- it duplicates the ALREADY-OPEN, write-only terminal descriptor
      # onto fd 0 for the lifetime of the stty process alone. It opens nothing, grants no read access
      # (a dup shares the original's O_WRONLY access mode, so a read would fail with EBADF), and leaves
      # the renderer's own fd 0 still on /dev/null. The no-input property is untouched.
      if size="$(${pkgs.coreutils}/bin/stty size 0<&1 2>/dev/null)"; then
        term_rows="''${size%% *}"
        term_cols="''${size##* }"
      fi
      if ! is_uint "$term_cols"; then
        term_cols="$(${pkgs.ncurses}/bin/tput cols 2>/dev/null || true)"
      fi
      if ! is_uint "$term_rows"; then
        term_rows="$(${pkgs.ncurses}/bin/tput lines 2>/dev/null || true)"
      fi
      if [ -n "''${KEEPNODE_STATUS_WIDTH:-}" ]; then term_cols="$KEEPNODE_STATUS_WIDTH"; fi
      if [ -n "''${KEEPNODE_STATUS_ROWS:-}" ]; then term_rows="$KEEPNODE_STATUS_ROWS"; fi
      is_uint "$term_cols" || term_cols=80
      is_uint "$term_rows" || term_rows=24

      # Clamped to [40,100] and CENTRED. A 4K VT reports 240 columns and a status pane stretched across
      # all of them reads as broken furniture rather than as an instrument: the eye cannot associate a
      # label on the far left with a value on the far right.
      if [ "$term_cols" -lt 40 ]; then
        w=40
      elif [ "$term_cols" -gt 100 ]; then
        w=100
      else
        w="$term_cols"
      fi
      pad_n=$(( (term_cols - w) / 2 ))
      if [ "$pad_n" -lt 0 ]; then pad_n=0; fi
      pad="$(repeat_char "$pad_n" ' ')"

      # Three layout tiers. Narrow does not reflow into columns; it keeps ONE LINE PER ITEM and spends
      # its remaining budget on the value, because a wrapped status line is a misread status line.
      if [ "$w" -ge 80 ]; then
        tier=full
        labelw=16
      elif [ "$w" -ge 60 ]; then
        tier=plain
        labelw=14
      else
        tier=narrow
        # 12, not 10: 12 is the longest label this screen uses, so no tier ever cuts a label mid-word.
        # A truncated label is a guessing game ("VAULTWARDE"), and the value is what the extra columns
        # would have bought -- values are already truncated last and are the part that carries news.
        labelw=12
      fi
    }

    colorize() {
      if [ "$color" -eq 1 ]; then
        printf -v _c '\033[1;%sm%s\033[0m' "$1" "$2"
      else
        _c="$2"
      fi
    }

    # Triple-coded: GLYPH + WORD + COLOUR, so the reading survives colourblindness, a monochrome LCD, a
    # serial capture and a photograph. Colour is never the only carrier of a state.
    #
    # `n/a` (a module that is switched off -- entirely normal) and `unknown`/`failed` (we could not tell
    # / it broke) get DIFFERENT glyphs. Collapsing them is how an operator ends up chasing a subsystem
    # this node was never configured to run.
    #
    # U+00D7 MULTIPLICATION SIGN for fail, deliberately NOT U+2715: U+2715 is absent from the Linux
    # console fonts (CP437, Lat2-Terminus16) and paints as an empty box -- an alarm state that renders
    # as nothing at all is worse than no alarm state.
    glyph_for() {
      case "''${1:-}" in
        ok)
          code=32
          if [ "$ascii" -eq 1 ]; then glyph="[ ok ]"; else glyph="●"; fi
          ;;
        warn)
          code=33
          if [ "$ascii" -eq 1 ]; then glyph="[warn]"; else glyph="▲"; fi
          ;;
        fail)
          code=31
          if [ "$ascii" -eq 1 ]; then glyph="[FAIL]"; else glyph="×"; fi
          ;;
        na)
          code=90
          if [ "$ascii" -eq 1 ]; then glyph="[ -- ]"; else glyph="·"; fi
          ;;
        *)
          code=90
          if [ "$ascii" -eq 1 ]; then glyph="[ ?? ]"; else glyph="○"; fi
          ;;
      esac
      if [ "$ascii" -eq 1 ]; then gw=6; else gw=1; fi
    }

    # Both mappers fall through to `unknown` for anything they do not recognise, which is what makes the
    # staleness blanking below a one-liner: set every collected value to "??" and every state reads
    # unknown automatically, with no second code path to keep in sync.
    unit_status() {
      case "''${1:-}" in
        active) echo ok ;;
        activating | reloading | deactivating) echo warn ;;
        failed) echo fail ;;
        inactive) echo warn ;;
        "n/a") echo na ;;
        *) echo unknown ;;
      esac
    }

    # replication.lag_check is a VERDICT, not an ActiveState: its unit is a timer-driven oneshot whose
    # success latches nothing, so the collector resolves it against `is-failed` (the contract stated at
    # nixos/vault-replication.nix:628) and emits ok/failed rather than active/inactive. Feeding it to
    # unit_status would paint a healthy standby amber forever.
    check_status() {
      case "''${1:-}" in
        ok) echo ok ;;
        failed) echo fail ;;
        "n/a") echo na ;;
        *) echo unknown ;;
      esac
    }

    vault_status() {
      case "''${1:-}" in
        unlocked) echo ok ;;
        locked) echo warn ;;
        wrong-device) echo fail ;;
        "n/a") echo na ;;
        *) echo unknown ;;
      esac
    }

    fmt_time() {
      if is_uint "''${1:-}" && [ "$1" -gt 0 ]; then
        ${pkgs.coreutils}/bin/date -u -d "@$1" +'%Y-%m-%d %H:%M:%SZ' 2>/dev/null || printf 'unknown'
      else
        printf 'unknown'
      fi
    }

    # Coarse, single-unit age. Deliberately imprecise: the reader needs "is this verdict minutes or
    # months old", and a wider string would be the first thing truncated out of a narrow value column.
    fmt_age() {
      local secs=''${1:-0}
      if [ "$secs" -lt 60 ]; then
        printf '%ds' "$secs"
      elif [ "$secs" -lt 3600 ]; then
        printf '%dm' $(( secs / 60 ))
      elif [ "$secs" -lt 86400 ]; then
        printf '%dh' $(( secs / 3600 ))
      else
        printf '%dd' $(( secs / 86400 ))
      fi
    }

    read_status() {
      local json line_count gen mtime
      degraded=0
      degrade_reason=""
      last_ts=unknown

      now="$(${pkgs.coreutils}/bin/date +%s 2>/dev/null || echo 0)"
      is_uint "$now" || now=0

      v_schema=""
      v_generated=""
      v_node=""
      v_vault=""
      v_gate=""
      v_vw=""
      v_mesh=""
      v_wisp=""
      v_iface=""
      v_up=""
      v_addr=""
      v_role=""
      v_lagchk=""
      v_lag=""
      v_al=""
      v_al_at=""
      v_error=""

      if [ ! -r "$status_file" ]; then
        degraded=1
        degrade_reason="NO STATUS SNAPSHOT - COLLECTOR HAS NOT RUN"
        return 0
      fi

      mtime="$(${pkgs.coreutils}/bin/stat -c %Y -- "$status_file" 2>/dev/null || true)"
      is_uint "$mtime" || mtime=0

      if ! json="$(${pkgs.jq}/bin/jq -r ${lib.escapeShellArg jqProgram} < "$status_file" 2>/dev/null)"; then
        degraded=1
        degrade_reason="STATUS SNAPSHOT UNREADABLE - MALFORMED JSON"
        last_ts="$(fmt_time "$mtime")"
        return 0
      fi
      # A short list means the filter did not produce the shape this reader expects. Reading it anyway
      # would silently slide every field into the wrong slot, which is the one failure that looks
      # completely plausible on screen. The LAST element is a "." sentinel purely so that a trailing
      # EMPTY field cannot be eaten by command substitution's newline stripping and fake a short list.
      line_count="$(printf '%s\n' "$json" | ${pkgs.coreutils}/bin/wc -l)"
      if [ "$line_count" -ne 18 ]; then
        degraded=1
        degrade_reason="STATUS SNAPSHOT UNREADABLE - UNEXPECTED SHAPE"
        last_ts="$(fmt_time "$mtime")"
        return 0
      fi

      {
        read -r v_schema
        read -r v_generated
        read -r v_node
        read -r v_vault
        read -r v_gate
        read -r v_vw
        read -r v_mesh
        read -r v_wisp
        read -r v_iface
        read -r v_up
        read -r v_addr
        read -r v_role
        read -r v_lagchk
        read -r v_lag
        read -r v_al
        read -r v_al_at
        read -r v_error
      } <<< "$json"

      if [ "$v_schema" != "1" ]; then
        degraded=1
        # Bounded before it reaches the banner. clean() strips control bytes but not LENGTH, and the
        # banner word-wraps rather than hard-cutting, so an unbounded snapshot value would grow the
        # header without limit -- and `head` is the one array the row-budget fitter never trades away,
        # so a long enough value pushes every status row and the SSH line off the screen.
        degrade_reason="STATUS SCHEMA $(clip 24 "$(clean "$v_schema")") UNSUPPORTED - EXPECTED 1"
        last_ts="$(fmt_time "$mtime")"
        return 0
      fi

      # The collector's own emergency payload (its jq emit failed) carries `error` and a CURRENT
      # generated_at, so staleness can never catch it. Read here it becomes a banner; unread it was a
      # perfectly normal-looking frame with every row "unknown" and nothing on the glass admitting a
      # fault -- the exact "plausible but wrong" screen this module refuses to show.
      if [ -n "$v_error" ]; then
        degraded=1
        degrade_reason="COLLECTOR FAULT - $(clip 60 "$(clean "$v_error")")"
        last_ts="$(fmt_time "$mtime")"
        return 0
      fi

      # age = now - MIN(mtime, generated_at). The minimum is the pessimistic reading and the correct
      # one: mtime alone trusts a collector that keeps touching the file while re-emitting a cached
      # payload, and generated_at alone trusts a clock. Either one being old is enough to be old.
      gen="$v_generated"
      is_uint "$gen" || gen=0
      oldest="$mtime"
      if [ "$gen" -lt "$oldest" ]; then oldest="$gen"; fi
      age=$(( now - oldest ))
      if [ "$age" -lt 0 ]; then age=0; fi
      last_ts="$(fmt_time "$oldest")"

      if [ "$age" -gt "$stale_seconds" ]; then
        degraded=1
        degrade_reason="STALE - DATA ''${age}s OLD (LIMIT ''${stale_seconds}s)"
      fi
    }

    # Banner text WRAPS on whitespace; it is never sliced mid-sentence. A hard cut to w-6 (34 columns at
    # the narrow tier) turned "VALUES BELOW ARE NOT KNOWN AND SHOW AS ??" -- 41 characters -- into
    # "...AND SHO", losing the very "??" the sentence exists to explain, and truncated a long
    # "STALE - DATA <n>s OLD (LIMIT <n>s)" into an unbalanced open paren. That is the same
    # cut-mid-token failure already fixed in the SSH footer, which drops its note whole rather than
    # slicing; a banner cannot be dropped (it is the alarm), so it wraps instead.
    #
    # Banners live in `head`, which the row-budget fitter never trades away, so an extra wrapped line
    # costs a body row on a very short screen rather than the alarm itself.
    add_banner() {
      local bcode=$1 inner text word cur bannerMaxLines=6
      shift
      inner=$(( w - 6 ))
      if [ "$inner" -lt 1 ]; then inner=1; fi
      colorize "$bcode" "$(repeat_char "$w" '!')"
      head+=("$_c")
      # Hard ceiling on wrapped lines. Callers clip their snapshot values, so this should never bind;
      # it is the backstop that keeps a missed clip from costing the operator the whole screen rather
      # than a few words. `head` is never traded away by the row-budget fitter, so an unbounded banner
      # pushes every status row AND the SSH line off the glass -- strictly worse than a cut sentence.
      local emitted=0
      for text in "$@"; do
        text="$(clean "$text")"
        # `set -f` for the word split: clean() permits `*` and `?`, and an unguarded split would let a
        # degrade reason glob against the working directory and paint filenames into the alarm.
        set -f
        cur=""
        for word in $text; do
          if [ "$emitted" -ge "$bannerMaxLines" ]; then break; fi
          if [ -z "$cur" ]; then
            cur="$word"
          elif [ $(( ''${#cur} + 1 + ''${#word} )) -le "$inner" ]; then
            cur="$cur $word"
          else
            printf -v line '!! %-*s !!' "$inner" "''${cur:0:$inner}"
            colorize "$bcode" "$line"
            head+=("$_c")
            emitted=$(( emitted + 1 ))
            cur="$word"
          fi
        done
        set +f
        if [ "$emitted" -ge "$bannerMaxLines" ]; then cur=""; fi
        # A single token longer than the whole banner is the one case still hard-cut: there is no
        # whitespace to break it at, and it carries no sentence to leave half-finished.
        if [ -n "$cur" ]; then
          printf -v line '!! %-*s !!' "$inner" "''${cur:0:$inner}"
          colorize "$bcode" "$line"
          head+=("$_c")
        fi
      done
      colorize "$bcode" "$(repeat_char "$w" '!')"
      head+=("$_c")
    }

    add_item() {
      local st=$1 label=$2 value=$3 valw rest
      glyph_for "$st"
      valw=$(( w - 3 - gw - labelw ))
      if [ "$valw" -lt 1 ]; then valw=1; fi
      value="$(clean "$value")"
      if [ -z "$value" ]; then value=unknown; fi
      printf -v rest ' %-*s %s' "$labelw" "''${label:0:$labelw}" "''${value:0:$valw}"
      colorize "$code" "$glyph"
      body+=(" $_c$rest")
    }

    two_col() {
      local left right space
      left="$(clean "$1")"
      right="$(clean "$2")"
      space=$(( w - 2 - ''${#right} ))
      if [ "$space" -lt 1 ]; then space=1; fi
      printf -v line ' %-*s %s' "$space" "''${left:0:$space}" "$right"
      printf '%s' "''${line:0:$w}"
    }

    build_frame() {
      local i n budget kept sep al_value al_age al_valw al_uptime al_long al_short
      detect_caps
      detect_geometry
      read_status

      # THE staleness rule. Every collected value is REPLACED by "??" -- not dimmed, not greyed, not
      # kept as a last-known reading. A greyed-out "UNLOCKED" is still read as "unlocked" by someone
      # glancing at the screen from across the room, and the whole point of this display is what it
      # tells that person. Only the last-known TIMESTAMP (in the footer) and the SSH line survive, being
      # static config rather than collected facts. The node label is NOT among them -- it is collected,
      # so it blanks with everything else and a stale screen cannot tell you which box you are looking
      # at. The SSH line is what identifies the node then.
      if [ "$degraded" -eq 1 ]; then
        v_node="??"
        v_vault="??"
        v_gate="??"
        v_vw="??"
        v_mesh="??"
        v_wisp="??"
        v_iface="??"
        v_up="??"
        v_addr="??"
        v_role="??"
        v_lagchk="??"
        v_lag="??"
        v_al="??"
        v_al_at="??"
      fi

      brandl=()
      head=()
      body=()
      foot=()

      if [ "$ascii" -eq 1 ]; then
        for i in "''${mark_ascii[@]}"; do brandl+=("  $i"); done
        brandl+=("" "  $wordmark_ascii" "")
      else
        for i in "''${mark_unicode[@]}"; do brandl+=("  $i"); done
        brandl+=("" "  $wordmark" "")
      fi

      sep="$(repeat_char "$w" '-')"
      if [ "$tier" = full ]; then head+=("$sep"); fi
      # Minutes, not seconds. The header clock is part of the frame comparison key, so a ticking seconds
      # field would make every frame differ from the last and turn the diff-repaint below into an
      # unconditional 1 Hz full repaint. Sub-minute liveness is the heartbeat's job.
      # The node label is a COLLECTED value, so it blanks to ?? with everything else when the snapshot
      # goes stale. The static hostname stays reachable in the SSH line at the foot of the frame, and
      # that pair -- "I cannot tell you anything" plus "here is how to come and find out" -- is what the
      # operator actually needs. The empty case is the collector's own emergency fallback payload, which
      # carries no label at all.
      if [ "$degraded" -eq 0 ] && [ -z "$v_node" ]; then v_node="$host_name"; fi
      now_hm="$(${pkgs.coreutils}/bin/date -u +'%H:%MZ' 2>/dev/null || printf "unknown")"
      head+=("$(two_col "NODE  $v_node" "$now_hm")")
      if [ "$tier" = full ]; then head+=("$sep"); fi

      # Banner precedence. nixos/admin-access.nix:198 writes its KEEP NODE ANTI-LOCKOUT message straight
      # to /dev/console -- this very VT -- and a 1 Hz repaint erases it inside a second. Losing that
      # message means an operator never learns the node is unreachable until they try to reach it, so it
      # is re-raised here as the most visually dominant element on the screen, above the fold, and it is
      # placed in `head` where the row-budget fitter can never drop or scroll it.
      #
      # When the snapshot is degraded the anti-lockout field is "??" and no claim is made either way:
      # the staleness banner is already saying that nothing on the screen is known.
      if [ "$degraded" -eq 0 ] && [ "$v_al" = "failed" ]; then
        add_banner 31 "ANTI-LOCKOUT TRIPPED: NO ADMIN SSH KEY" "REMOTE ACCESS IS IMPOSSIBLE - PROVISION A KEY"
      fi
      if [ "$degraded" -eq 1 ]; then
        add_banner 31 "$degrade_reason" "VALUES BELOW ARE NOT KNOWN AND SHOW AS ??"
      fi

      add_item "$(vault_status "$v_vault")" VAULT "$v_vault"
      add_item "$(unit_status "$v_gate")" GATE "$v_gate"
      add_item "$(unit_status "$v_vw")" VAULTWARDEN "$v_vw"
      add_item "$(unit_status "$v_mesh")" MESH "$v_mesh"
      add_item "$(unit_status "$v_wisp")" WISP "$v_wisp"
      if [ "$show_mesh_link" = 1 ]; then
        case "$v_up" in
          true) add_item ok "MESH LINK" "up ($v_iface)" ;;
          false) add_item warn "MESH LINK" "down ($v_iface)" ;;
          *) add_item unknown "MESH LINK" "$v_up" ;;
        esac
      fi
      # The `degraded` arm has to come FIRST in each of these. Without it a blanked "??" is a non-empty
      # string / a non-integer and would fall into the healthy branch or the "unknown" branch, painting
      # a green dot next to an unknown address, or the word "unknown" where the frame has just promised
      # that every collected value reads "??".
      if [ "$show_mesh_addr" = 1 ]; then
        if [ "$degraded" -eq 1 ]; then
          add_item unknown "MESH ADDR" "$v_addr"
        elif [ -n "$v_addr" ]; then
          add_item ok "MESH ADDR" "$v_addr"
        else
          add_item unknown "MESH ADDR" unknown
        fi
      fi
      if [ "$show_repl" = 1 ]; then
        if is_uint "$v_lag"; then
          add_item "$(check_status "$v_lagchk")" REPLICATION "$v_role lag ''${v_lag}s"
        else
          add_item "$(check_status "$v_lagchk")" REPLICATION "$v_role $v_lagchk"
        fi
      fi
      # The anti-lockout verdict is BOOT-LATCHED (Type=oneshot + RemainAfterExit, no timer), so unlike
      # every other row it can be arbitrarily old while the snapshot carrying it is perfectly fresh.
      # Showing the bare word would be a green dot asserting "no lockout" about a node whose key was
      # deleted weeks ago. The age is therefore part of the value, not metadata.
      #
      # Two forms, longest-that-fits, then dropped whole -- the SSH footer's discipline. Slicing this
      # is what produces "active (checked 41d" with an open paren, and the ascii tier's six-column
      # glyph leaves as little as 19 columns for the value at the narrow tier.
      al_value="$v_al"
      # Clamped to uptime, not just to "not in the future". ActiveEnterTimestamp is CLOCK_REALTIME at
      # activation, so on a box with no RTC (or with NTP landing late) the clock jumps FORWARD after
      # boot and a check that ran seconds ago computes as decades. The unit cannot have activated
      # before this boot, so an age exceeding uptime is impossible and the age is dropped rather than
      # shown -- a fabricated reading on the one row added to stop fabricated readings would be the
      # worst possible place to have one.
      # KEEPNODE_STATUS_UPTIME is a test seam, like KEEPNODE_STATUS_WIDTH/ASCII/NOCOLOR above. A long
      # age is only PHYSICALLY possible on a long-lived node, so a VM three minutes into its life
      # cannot produce the "checked 41d ago" string whose width behaviour needs testing. Overriding the
      # plausibility bound is the only way to exercise that path; systemd never sets this, and the worst
      # a wrong value can do is mis-display an age -- it gates no security property.
      al_uptime="''${KEEPNODE_STATUS_UPTIME:-}"
      if [ -z "$al_uptime" ] && [ -r /proc/uptime ]; then
        al_uptime="$(${pkgs.coreutils}/bin/cut -d' ' -f1 /proc/uptime 2>/dev/null || true)"
        al_uptime="''${al_uptime%%.*}"
      fi
      if [ "$degraded" -eq 0 ] && is_uint "$v_al_at" && [ "$v_al_at" -gt 0 ] && [ "$now" -ge "$v_al_at" ] &&
        { ! is_uint "$al_uptime" || [ $(( now - v_al_at )) -le "$al_uptime" ]; }; then
        al_age="$(fmt_age $(( now - v_al_at )))"
        al_valw=$(( w - 3 - labelw ))
        if [ "$ascii" -eq 1 ]; then al_valw=$(( al_valw - 6 )); else al_valw=$(( al_valw - 1 )); fi
        # Measured off the candidate strings themselves rather than off hand-counted widths, so the
        # fit test cannot drift away from the text it is meant to be measuring.
        al_long="$v_al (checked $al_age ago)"
        al_short="$v_al ($al_age ago)"
        if [ "''${#al_long}" -le "$al_valw" ]; then
          al_value="$al_long"
        elif [ "''${#al_short}" -le "$al_valw" ]; then
          al_value="$al_short"
        fi
      fi
      add_item "$(unit_status "$v_al")" "ANTI-LOCKOUT" "$al_value"

      if [ "$tier" = full ]; then foot+=("$sep"); fi
      # two_col gives its left field w-2 columns. The note is appended only if the WHOLE line fits in
      # that budget, so a long hostname (up to 63 chars in "ssh keepadmin@<host>") drops the note
      # instead of having it sliced mid-token. The command may still be hard-truncated at 40 columns,
      # but it carries no punctuation that can be left unbalanced.
      ssh_line="SSH   $ssh_command"
      if [ "$tier" = full ] && [ $(( ''${#ssh_line} + ''${#ssh_note} )) -le $(( w - 2 )) ]; then
        ssh_line="$ssh_line$ssh_note"
      fi
      foot+=("$(two_col "$ssh_line" "")")
      # The heartbeat placeholder. \001 is not survivable through clean(), so no collected value can
      # ever introduce a second one and move the cursor target.
      foot+=(" "$'\001'" last update: $last_ts")

      # Row budget. Decoration goes first, then items from the end; the header (which carries the
      # banners) and the footer are never traded away.
      all=()
      if [ $(( ''${#brandl[@]} + ''${#head[@]} + ''${#body[@]} + ''${#foot[@]} )) -le "$term_rows" ] &&
        [ "$tier" != narrow ]; then
        all+=("''${brandl[@]}")
      fi
      all+=("''${head[@]}")
      budget=$(( term_rows - ''${#all[@]} - ''${#foot[@]} ))
      if [ "$budget" -lt 0 ]; then budget=0; fi
      n=''${#body[@]}
      if [ "$n" -gt "$budget" ]; then n="$budget"; fi
      i=0
      while [ "$i" -lt "$n" ]; do
        all+=("''${body[$i]}")
        i=$(( i + 1 ))
      done
      if [ "$n" -lt "''${#body[@]}" ] && [ "$n" -gt 0 ]; then
        kept=$(( ''${#body[@]} - n + 1 ))
        all[$(( ''${#all[@]} - 1 ))]=" ... $kept more items (screen too short)"
      fi
      all+=("''${foot[@]}")
      if [ "''${#all[@]}" -gt "$term_rows" ]; then
        all=("''${all[@]:0:$term_rows}")
      fi

      # ONE variable holding the WHOLE frame. Emitting line by line tears visibly: the collector's next
      # snapshot can land mid-frame and the screen shows half of one reading and half of another.
      frame_tpl=""
      for i in "''${!all[@]}"; do
        if [ "$i" -gt 0 ]; then frame_tpl="$frame_tpl"$'\n'; fi
        frame_tpl="$frame_tpl$pad''${all[$i]}"
      done
    }

    # Where the heartbeat cell sits, in 1-based screen coordinates, derived from the assembled template.
    # Everything to its left on that line is ASCII spaces, so a byte offset is a column offset.
    locate_heartbeat() {
      local pre nls lastline
      hb_row=0
      hb_col=0
      case "$frame_tpl" in
        *$'\001'*) : ;;
        *) return 0 ;;
      esac
      pre="''${frame_tpl%%$'\001'*}"
      nls="''${pre//[!$'\n']/}"
      hb_row=$(( ''${#nls} + 1 ))
      lastline="''${pre##*$'\n'}"
      hb_col=$(( ''${#lastline} + 1 ))
    }

    hb_chars='-\|/'
    hb_i=0

    heartbeat_char() {
      hb="''${hb_chars:$(( hb_i % 4 )):1}"
      hb_i=$(( hb_i + 1 ))
    }

    if [ "$once" -eq 1 ]; then
      build_frame
      heartbeat_char
      frame="''${frame_tpl/$'\001'/$hb}"
      # printf '%s', NEVER printf "$frame": a node label or hostname containing %s or %n would otherwise
      # be interpreted as a conversion and corrupt (or crash) the output.
      printf '%s\n' "$frame"
      exit 0
    fi

    # Console blanking would hide the one screen this feature exists to show, on exactly the timescale
    # an unattended appliance is left alone for.
    ${pkgs.util-linux}/bin/setterm --blank 0 --powersave off 2>/dev/null || true
    printf '\033[?25l'

    # A frozen renderer cannot draw its own staleness banner -- the banner is painted by the thing that
    # died. The rotating heartbeat is the only cue that survives that failure, and this trap covers the
    # case where the process at least gets to exit: it leaves an explicit statement on the glass instead
    # of a plausible-looking last frame that nobody can date.
    on_exit() {
      local msg bar
      bar="$(repeat_char "''${w:-80}" '!')"
      printf '\033[H\033[J\033[?25h'
      printf '%s\n' "$bar"
      printf -v msg '!! %-*s !!' $(( ''${w:-80} - 6 )) "KEEP NODE STATUS DISPLAY STOPPED - NO DATA IS SHOWN"
      printf '%s\n' "''${msg:0:''${w:-80}}"
      printf '%s\n' "$bar"
    }
    # EXIT alone carries the painting; INT/TERM only convert the signal into an ordinary exit. Trapping
    # on_exit for all three would run it TWICE on a systemctl stop -- once for the signal and once for
    # the exit it causes -- leaving two stacked STOPPED banners on the terminal.
    trap on_exit EXIT
    trap 'exit 143' INT TERM

    prev_key=""
    last_full=0
    while :; do
      build_frame
      locate_heartbeat
      heartbeat_char

      # Serial efficiency: at 9600 baud a full 24x80 frame is about 2.5 seconds of wire time, so a 1 Hz
      # unconditional repaint would never finish one before starting the next. The comparison key is the
      # template, heartbeat placeholder and all, so the heartbeat's own rotation does not count as a
      # change; when nothing else moved, only the single heartbeat cell is rewritten. The forced full
      # repaint at most once per 60s is how a line garbled by kernel output heals itself.
      if [ "$frame_tpl" != "$prev_key" ] || [ $(( now - last_full )) -ge 60 ] || [ "$hb_row" -eq 0 ]; then
        # ESC[H + per-line ESC[K, then ESC[J. NEVER ESC[2J: clearing the whole screen before redrawing
        # it shows a black flash on every repaint, which at 1 Hz is a strobing screen.
        out=$'\033[H'
        for i in "''${!all[@]}"; do
          if [ "$i" -gt 0 ]; then out="$out"$'\r\n'; fi
          out="$out$pad''${all[$i]}"$'\033[K'
        done
        # Substituting into the assembled string rather than re-rendering keeps the emitted frame
        # byte-identical to the one the key was computed from.
        out="''${out/$'\001'/$hb}"$'\033[J'
        printf '%s' "$out"
        prev_key="$frame_tpl"
        last_full="$now"
      else
        printf '\033[%d;%dH%s' "$hb_row" "$hb_col" "$hb"
      fi

      ${pkgs.coreutils}/bin/sleep "$repaint_seconds"
    done
  '';
in
{
  options.keepNode.statusDisplay = {
    enable = lib.mkEnableOption "the read-only Keep status screen on the physical console";

    backend = lib.mkOption {
      type = lib.types.enum [ "console" ];
      default = "console";
      description = ''
        How the status screen is painted. Only `console` , writing frames directly to a Linux virtual
        terminal , is implemented, and it is the only value the enum currently accepts.

        A Wayland kiosk (`cage` running `foot`) was evaluated and REJECTED. `foot` binds
        `ctrl+shift+n` to spawning `$SHELL`, which would hand a shell to anyone standing at the box and
        blow straight through the "console grants nothing" fence this module is built around. Beyond
        that single binding, a compositor adds a seat and a keyboard input consumer to an appliance
        that deliberately has neither, which is a large new attack surface bought for a nicer font.

        The option is an enum rather than a bare implementation detail so that a future framebuffer or
        DRM backend arrives as an added enum value rather than as a breaking rename of this option.
      '';
    };

    tty = lib.mkOption {
      type = lib.types.ints.between 1 12;
      default = 1;
      example = 3;
      description = ''
        Which Linux virtual terminal the status screen owns. Defaults to tty1 because that is the VT
        the machine shows on boot, and so the only one an operator with a monitor plugged in will
        actually see without knowing to press Alt+F-something. Move it to a free VT when something else
        needs tty1 (for example the bring-up autologin console from `keepNode.debugAccess`).
      '';
    };

    refreshSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 5;
      description = ''
        How often the collector re-samples node state and rewrites its status snapshot. This is the
        rate at which the displayed FACTS can change; the repaint cadence below only controls how
        quickly a new snapshot reaches the glass. Lower values cost more probing of the services being
        sampled, so keep this comfortably above the time a full collection round takes.
      '';
    };

    repaintSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 1;
      description = ''
        How often the renderer redraws the screen from the latest collector snapshot. Painting is
        cheap and touches nothing but the VT, so this runs faster than collection: it keeps the clock
        and the staleness banner honest even when the collector has stopped producing snapshots.
      '';
    };

    staleSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 20;
      description = ''
        How old the collector's snapshot may be before the screen is marked STALE. Past this age the
        renderer stops presenting the numbers as current, because a frozen-but-plausible screen is
        worse than an obviously broken one , it invites an operator to make decisions from data that
        stopped tracking reality minutes ago. Should be several multiples of `refreshSeconds` so
        ordinary collection jitter never trips it.
      '';
    };

    probeTimeoutSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 2;
      description = ''
        Per-probe wall-clock timeout inside the collector. A single wedged probe must not be able to
        stall a whole collection round, because a stalled round ages the snapshot and would eventually
        show STALE for the entire screen when in fact one subsystem is hung. Keep it well under
        `refreshSeconds` so that even several slow probes fit inside one round.
      '';
    };

    showMeshAddress = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Show this node's mesh address on the status screen. Off by default: a mesh address is topology
        intelligence, and this screen renders it to whoever is physically standing in front of the box
        , which includes anyone who should not be learning the shape of the private network. Turn it
        on when the console is in a trusted location and the address genuinely helps bring-up.
      '';
    };

    nodeLabel = lib.mkOption {
      type = lib.types.str;
      default = config.networking.hostName;
      defaultText = lib.literalExpression "config.networking.hostName";
      example = "vault-rack-3";
      description = ''
        The human-facing name shown in the status screen header. Defaults to the system hostname,
        which is what an operator already correlates with the box. Override it when the hostname is an
        opaque identifier and a physical label (rack position, site name) is what the person standing
        in front of the machine actually needs to match against.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # nixos/debug-access.nix:19 sets services.getty.autologinUser = "root", which claims tty1.
        # Two owners, one VT: the status renderer and the autologin getty would fight over the same
        # terminal and the operator loses the bring-up console they turned debugAccess on to get.
        assertion = !(cfg.tty == 1 && (config.keepNode.debugAccess.enable or false));
        message = "keepNode.statusDisplay.tty is 1 but keepNode.debugAccess.enable is true: debug-access sets services.getty.autologinUser = \"root\", which claims tty1, so the status renderer and the autologin getty would contend for the same virtual terminal and the bring-up console would be lost. Disable keepNode.debugAccess (production), or move keepNode.statusDisplay.tty to a free VT such as 2 (bring-up).";
      }
      {
        # Staleness must trigger LATER than the collector produces snapshots. At or below the
        # collection cadence, every snapshot is already stale by the time it is painted, so the screen
        # reads STALE permanently , which trains the operator to ignore the one banner that matters.
        # A multiple of at least 3x leaves room for ordinary collection jitter.
        assertion = cfg.staleSeconds > cfg.refreshSeconds;
        message = "keepNode.statusDisplay.staleSeconds (${toString cfg.staleSeconds}) must be greater than refreshSeconds (${toString cfg.refreshSeconds}): staleness that triggers at or below the collector cadence marks every freshly-collected snapshot STALE, so the banner is permanently lit and the operator learns to ignore it. Set staleSeconds to at least 3x refreshSeconds (e.g. ${
          toString (3 * cfg.refreshSeconds)
        }).";
      }
      {
        # The renderer is what draws the STALE banner, so it must repaint at least once within the
        # staleness window. Otherwise a healthy-looking frozen screen persists for a full repaint
        # period after the collector has already died, with nothing on the glass admitting it.
        assertion = cfg.repaintSeconds < cfg.staleSeconds;
        message = "keepNode.statusDisplay.repaintSeconds (${toString cfg.repaintSeconds}) must be less than staleSeconds (${toString cfg.staleSeconds}): the renderer draws the STALE banner, so if it repaints less often than the staleness window it keeps showing a healthy-looking frozen screen for a full repaint period after the collector dies. Lower repaintSeconds below staleSeconds (the default 1 is fine).";
      }
      {
        # The mesh address has nothing to read when the mesh module is off. It would render a
        # permanent "n/a", which on a status screen looks like a FAULT rather than a disabled feature,
        # and sends the operator chasing a mesh problem that does not exist.
        assertion = cfg.showMeshAddress -> (config.keepNode.mesh.enable or false);
        message = "keepNode.statusDisplay.showMeshAddress is true but keepNode.mesh.enable is false: there is no mesh to report on, so the field would render a permanent \"n/a\" that reads as a fault and sends the operator chasing a non-existent mesh problem. Enable keepNode.mesh, or leave showMeshAddress off.";
      }
    ];

    systemd.services.keep-node-status-collect = {
      description = "Collect the Keep node status snapshot for the console display";
      # One eager run at boot so the first frame the renderer paints is real rather than a missing-file
      # placeholder; the timer takes over from there. NOTHING may `require` this unit: it is a reporting
      # side-channel, and boot must never be able to block on it.
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      serviceConfig = {
        # NOT RemainAfterExit: this repeats on a timer, and a unit that stays "active" after its run
        # would make every subsequent trigger a no-op.
        Type = "oneshot";
        ExecStart = lib.getExe collector;
        RuntimeDirectory = "keep-node-status";
        RuntimeDirectoryMode = "0755";
        # The snapshot must outlive each oneshot run, otherwise systemd removes the directory the
        # instant the collector exits and the renderer reads a file that exists for milliseconds
        # per cycle.
        RuntimeDirectoryPreserve = "yes";
        UMask = "0022";
        # Sandboxing mirrors nixos/mesh.nix:440-468. This unit runs as root only because it reads
        # unit state and the vault gate's device mapping; it needs no capability at all, writes
        # exactly one directory, and must not be a lever if anything it shells out to misbehaves.
        # No PrivateNetwork: `ip` must observe the HOST network namespace or every mesh fact it
        # reports would describe an empty private netns instead of the real interface.
        NoNewPrivileges = true;
        CapabilityBoundingSet = [ ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        # The collector cannot use PrivateNetwork (see above), so the socket families it may open are
        # narrowed instead. Its baseline needs are AF_UNIX (systemctl and journalctl talk to PID 1 and
        # the journal over unix sockets) and AF_NETLINK (how ip(8) actually asks the kernel about
        # links and addresses -- without it every mesh fact reads as unknown).
        #
        # Nothing else is admitted: no probe here talks to a network, so this root unit cannot open an
        # internet socket at all.
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
        ];
        SystemCallFilter = [ "@system-service" ];
        SystemCallArchitectures = "native";
        RestrictNamespaces = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        MemoryDenyWriteExecute = true;
      };
    };

    systemd.timers.keep-node-status-collect = {
      description = "Re-collect the Keep node status snapshot";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "5s";
        # OnUnitInactiveSec, NOT OnUnitActiveSec: the interval is measured from the END of the previous
        # run, so a collection round that runs long simply delays the next one instead of stacking a
        # second collector on top of a still-running first.
        OnUnitInactiveSec = "${toString cfg.refreshSeconds}s";
        AccuracySec = "1s";
        Unit = "keep-node-status-collect.service";
      };
    };

    # Writing users.users directly is normally something this tree avoids, but this account is owned by
    # nothing else: it exists solely so the process holding a terminal is not root. It has no password
    # (`!` is unmatchable, so `su` and every PAM password path refuse it), no shell, and no home, so
    # there is nothing to log into even if a login path to it were somehow found.
    users.users.${renderUser} = {
      isSystemUser = true;
      group = renderUser;
      description = "Keep node console status renderer";
      shell = "${pkgs.shadow}/bin/nologin";
      hashedPassword = "!";
      home = "/var/empty";
      createHome = false;
    };
    users.groups.${renderUser} = { };

    systemd.services.keep-node-status-render = {
      description = "Paint the Keep node status screen on ${ttyPath}";
      wantedBy = [ "multi-user.target" ];
      after = [ "keep-node-status-collect.service" ];
      # Belt and braces alongside the getty/autovt disabling below: even if something re-enables the
      # getty for this VT, systemd will not run both owners on the same terminal at once.
      conflicts = [ gettyUnit ];
      # NO start rate limit. With systemd's defaults (StartLimitBurst=5 in StartLimitIntervalSec=10s)
      # and RestartSec=2 below, a renderer that fails fast burns its five attempts in about ten
      # seconds and is then given up on PERMANENTLY -- the 209/STDOUT device-cgroup bug this module
      # already hit once looked exactly like that.
      #
      # There is no recovery from that state at the console. getty@ and autovt@ for this VT are
      # `enable = false`, which NixOS implements as a /dev/null symlink -- i.e. MASKED -- so
      # `systemctl start getty@tty1` refuses and the operator is left with a permanently dead terminal
      # on the one screen this feature exists to provide. Retrying forever is strictly better: the
      # failure is loud in the journal either way, and a transient cause (a device that appears late,
      # a VT briefly held by something else) heals itself instead of latching.
      #
      # This is a [Unit] directive, not [Service]: putting it in serviceConfig silently does nothing.
      unitConfig.StartLimitIntervalSec = 0;
      # tput needs a terminfo name, and setterm's blanking controls are linux-console specific.
      environment = {
        TERM = "linux";
        LANG = "C.UTF-8";
      };
      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe renderer}";
        Restart = "always";
        RestartSec = 2;

        User = renderUser;
        Group = renderUser;

        # THE security property of this module. The renderer holds NO descriptor on the keyboard --
        # not "tty", not "tty-force", which would both give it fd 0 on the console. With no read path
        # there is nothing to escape from: no shell-out, no pager, no "press any key". Everything else
        # in this block is defence in depth around a process that already cannot be talked to.
        StandardInput = "null";
        StandardOutput = "tty";
        # Diagnostics go to the journal, never to the terminal: a stray warning painted onto the VT
        # would corrupt the frame and, worse, would be the one line on screen with no timestamp.
        StandardError = "journal";
        TTYPath = ttyPath;
        TTYReset = true;
        TTYVHangup = true;
        TTYVTDisallocate = true;

        # Deliberately NOT PrivateDevices: that substitutes a private /dev and fights TTYPath and
        # TTYVTDisallocate, which need the real VT.
        #
        # DevicePolicy=closed narrows the unit to the standard pseudo-devices (/dev/null, zero, full,
        # random, urandom). That set does NOT include a virtual terminal: /dev/tty1 is an ordinary
        # character device, so opening it for StandardOutput=tty is refused by the device cgroup with
        # EPERM and the unit dies at step STDOUT (209/STDOUT) in a restart loop -- the screen never
        # paints at all. The terminal is opened with this unit's cgroup already applied, so the policy
        # very much does reach it.
        #
        # DeviceAllow re-admits exactly the one VT this module owns, and nothing else: it names the
        # configured tty path rather than the whole `char-tty` class, so enabling the display on tty3
        # does not also hand the renderer tty1..tty12.
        #
        # `rw` IS THE MINIMUM -- do not "harden" it to `w`. The read bit is NOT for StandardOutput:
        # that open is O_WRONLY and `w` alone satisfies it. It is required because TTYVHangup and
        # TTYReset below reopen the terminal O_RDWR|O_NOCTTY in the child, after the cgroup has been
        # attached, in order to issue their ioctls. Dropping to `w` reintroduces the 209/STDOUT
        # restart loop. The renderer process itself still never holds a readable descriptor on the VT
        # (StandardInput=null; asserted mechanically in tests/status-display.nix), so this bit costs
        # nothing against the no-input property -- it is a device-cgroup permission, not an open fd.
        DevicePolicy = "closed";
        DeviceAllow = [ "${ttyPath} rw" ];
        # A screen painter has no business on any network, in any direction.
        PrivateNetwork = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        NoNewPrivileges = true;
        CapabilityBoundingSet = [ ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        SystemCallFilter = [ "@system-service" ];
        SystemCallArchitectures = "native";
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        UMask = "0077";
      };
    };

    # Displacing the getty is not cosmetic: two processes writing one VT interleave their output, and
    # the login prompt would be repainted over once per second anyway. Both units must go.
    #
    # autovt@ is the one that is easy to miss. logind instantiates it on demand, so leaving it enabled
    # means the moment anyone presses Alt+F<n> (or anything calls chvt) a fresh getty is spawned onto
    # the terminal the renderer already owns, and the two race for the device.
    systemd.services."getty@tty${toString cfg.tty}".enable = false;
    systemd.services."autovt@tty${toString cfg.tty}".enable = false;

    # Kernel messages above KERN_ERR would otherwise scribble across the frame. mkDefault, NOT mkForce:
    # an operator debugging a boot problem must still be able to raise the level, and the cost of doing
    # so is only a garbled frame that the next repaint (or the 60s forced full repaint) cleans up.
    boot.consoleLogLevel = lib.mkDefault 3;

    # tty2-6 keep their gettys ON PURPOSE. Every account on the node is password-locked, so those
    # prompts grant exactly nothing to someone at the keyboard, and `keepNode.debugAccess` uses them
    # during bring-up. Taking them away would remove a bring-up affordance while adding no security.
  };
}
