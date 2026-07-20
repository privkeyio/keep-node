# The read-only console status screen, on a booted machine. Everything here needs a real kernel VT, a
# real systemd, and real units to probe, which is why none of it can be an eval check: the collector's
# probes, the renderer's ownership of tty1, and the getty displacement only mean anything once something
# has actually booted.
#
# The load-bearing assertion is the STALE one. This display's entire justification is that it must never
# show a plausible-but-frozen reading, so the test stops the collector, waits past staleSeconds, and
# proves BOTH that the banner lights AND that no healthy value survived anywhere on the glass. Then it
# restarts the collector and proves recovery, because a STALE banner that is simply always-on would pass
# the first half of that and be worthless.
#
# Screen content is read from /dev/vcs1 -- the kernel's live character cells for tty1 -- not from OCR.
# That is exact: it is the bytes the VT actually holds. OCR against the box-drawing brand mark is flaky
# and asserting on it would be theatre.
#
# Run: nix build .#checks.x86_64-linux.status-display
{
  nvpnPackage,
  vaultRsaKeyFixture,
  ...
}:
let
  statusFile = "/run/keep-node-status/status.json";

  # Cadences fast enough that the staleness window is tens of seconds rather than minutes, but NOT as
  # tight as they could be on real hardware. A collection round spawns a good number of short-lived
  # probes, and on two contending VMs those rounds were measured taking up to 25s of wall clock (against
  # ~2s of CPU) -- so with staleSeconds down at 6 the snapshot was legitimately stale the instant it was
  # written and the screen read STALE permanently. That is the module's assertion documentation being
  # exactly right about wanting several multiples of refreshSeconds; it just needs more headroom under a
  # loaded hypervisor than on the appliance. Still satisfies both module assertions:
  # staleSeconds (30) > refreshSeconds (5), and repaintSeconds (1) < staleSeconds (30).
  display = {
    enable = true;
    refreshSeconds = 5;
    staleSeconds = 30;
    repaintSeconds = 1;
  };

  # Generous, because the bound is one collection round on a contended host, not the product's cadence.
  slow = 120;
in
{
  name = "keep-node-status-display";

  # The plain node: no mesh, no wisp, no replication. Their units are therefore genuinely NOT PRESENT,
  # which is what makes this the right place to prove absent-unit -> "n/a" rather than "failed".
  nodes.box =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
      keepNode.statusDisplay = display;
      environment.systemPackages = [
        pkgs.jq
        pkgs.kbd
      ];
    };

  # A second node purely to execute the REPLICATION row and the collector's lag_seconds journal parsing,
  # neither of which any test has ever run. Both are gated on vaultReplication.role, so they need a node
  # that has one. meshReplication (and therefore keepNode.mesh) is required because the lag-check unit
  # lives inside that block -- but no mesh has to actually FORM: the test writes the heartbeat file the
  # active would have pushed and runs the check directly, which is enough to make it log the line the
  # collector parses. Standing up real litestream replication between two VMs to observe one screen row
  # would be disproportionate, and tests/mesh-replication.nix already covers that transport.
  nodes.standby =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
      keepNode.statusDisplay = display;
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
      };
      keepNode.vaultReplication = {
        # Test-only anti-pattern (exactly what rsaKeyFile warns against): a Nix-store path leaves the key world-readable in /nix/store. Safe only because this is an ephemeral per-build fixture, never a real cluster signing key; a real deploy must pass an out-of-band path.
        rsaKeyFile = "${vaultRsaKeyFixture}/rsa_key.pem";
        role = "standby";
        meshReplication.enable = true;
      };
      environment.systemPackages = [ pkgs.jq ];
    };

  testScript =
    { nodes, ... }:
    let
      render = nodes.box.systemd.services.keep-node-status-render.serviceConfig.ExecStart;
      renderStandby = nodes.standby.systemd.services.keep-node-status-render.serviceConfig.ExecStart;
      replicaDir = nodes.standby.keepNode.vaultReplication.litestream.replicaDir;
    in
    ''
      start_all()

      for node in [box, standby]:
          node.wait_for_unit("multi-user.target")
          node.wait_for_unit("keep-node-status-render.service")

      # The renderer must be genuinely RUNNING, not crash-looping. wait_for_unit alone does not catch
      # that: a unit with Restart=always is "active" for a moment on every respawn. DevicePolicy=closed
      # once refused the manager's own open() of /dev/tty1 (EPERM at step STDOUT, 209/STDOUT) and the
      # only symptom was a restart counter climbing behind a blank screen. Comparing NRestarts across a
      # few seconds tolerates one benign restart during boot but fails a loop.
      for node in [box, standby]:
          node.succeed("systemctl show -p NRestarts --value keep-node-status-render.service > /tmp/n1")
      box.sleep(5)
      for node in [box, standby]:
          node.succeed("systemctl show -p NRestarts --value keep-node-status-render.service > /tmp/n2")
          node.succeed("cmp /tmp/n1 /tmp/n2")
          node.succeed("systemctl is-active --quiet keep-node-status-render.service")

      # ---------------------------------------------------------------------------------------------
      # The collector at runtime. Nothing in CI has ever exercised it; its only prior verification was a
      # throwaway harness. The snapshot must EXIST, be world-readable (the renderer runs as an
      # unprivileged user and can read nothing else), parse as JSON, and declare the schema the renderer
      # is built against.
      # ---------------------------------------------------------------------------------------------
      box.wait_for_file("${statusFile}")

      box.succeed("stat -c %a ${statusFile} > /tmp/mode")
      box.succeed("grep -qx 644 /tmp/mode")

      # jq -e exits non-zero on a false/null result, so this IS the assertion -- no pipe into grep, which
      # under the driver's `set -o pipefail` could never have passed anyway.
      box.succeed("jq -e '.schema == 1' ${statusFile} >/dev/null")
      box.succeed("jq -e 'has(\"generated_at\") and has(\"vault\") and has(\"services\")' ${statusFile} >/dev/null")

      # ---------------------------------------------------------------------------------------------
      # Absent unit -> "n/a", never "failed". This node runs neither mesh nor wisp, so those units do not
      # exist at all. Reporting a non-existent subsystem as failed is the single most damaging lie this
      # screen could tell: it sends an operator chasing a service the node was never configured to run.
      # ---------------------------------------------------------------------------------------------
      for field in ["mesh", "wisp"]:
          box.succeed(f"jq -r '.services.{field}' ${statusFile} > /tmp/svc")
          box.succeed("grep -qx 'n/a' /tmp/svc")
          box.fail("grep -qx 'failed' /tmp/svc")

      # ---------------------------------------------------------------------------------------------
      # Can we read the real screen? /dev/vcs1 is the kernel's live character-cell buffer for tty1. Under
      # some headless configurations the kernel binds dummycon and this device is absent. This first
      # read only proves it is READABLE -- vcs1 always returns a full screen of cells, so a non-empty
      # result says nothing about content. The grep for painted text just below is the real proof, and
      # every screen assertion in this test goes through the same device.
      # ---------------------------------------------------------------------------------------------
      box.wait_until_succeeds("cat /dev/vcs1 > /tmp/screen_probe; test -s /tmp/screen_probe", timeout=${toString slow})
      print("=== /dev/vcs1 initial contents ===")
      print(box.succeed("cat /tmp/screen_probe"))

      def screen(path):
          """Snapshot tty1's live character cells to a file inside the VM."""
          box.succeed(f"cat /dev/vcs1 > {path}")

      # The renderer paints the frame from the top of the screen, so a HEALTHY, non-stale frame must be
      # visibly present before the stale test can prove it was REPLACED rather than merely absent. Both
      # halves are waited on together so that one slow collection round early on is tolerated rather than
      # latched as a failure.
      box.wait_until_succeeds(
          "cat /dev/vcs1 > /tmp/screen_healthy; "
          "grep -q 'VAULT' /tmp/screen_healthy && ! grep -q 'STALE' /tmp/screen_healthy",
          timeout=${toString slow},
      )
      box.succeed("grep -q 'ANTI-LOCKOUT' /tmp/screen_healthy")

      # ---------------------------------------------------------------------------------------------
      # THE staleness property. Stop the collector and let the snapshot age past staleSeconds. Two
      # separate things must hold, and the second is the one that matters: the banner lights, AND every
      # collected value is REPLACED by "??". A greyed-out or last-known "unlocked" left on the glass is
      # still read as "unlocked" by someone glancing across the room.
      # ---------------------------------------------------------------------------------------------
      box.succeed("systemctl stop keep-node-status-collect.timer")
      box.succeed("systemctl stop keep-node-status-collect.service")

      box.wait_until_succeeds("cat /dev/vcs1 > /tmp/screen_stale; grep -q 'STALE' /tmp/screen_stale", timeout=${toString slow})

      # No healthy reading survived anywhere on the screen. This is the assertion the whole feature
      # exists to satisfy.
      box.fail("grep -qE '(unlocked|active|RUNNING)' /tmp/screen_stale")
      box.succeed("grep -q '??' /tmp/screen_stale")

      # The static config lines are NOT collected facts and must survive: they are what the operator
      # standing at a screen full of ?? needs in order to go and fix it.
      box.succeed("grep -q 'SSH' /tmp/screen_stale")

      # ---------------------------------------------------------------------------------------------
      # Recovery. Without this, a STALE banner that was simply always-on would have passed everything
      # above.
      # ---------------------------------------------------------------------------------------------
      box.succeed("systemctl start keep-node-status-collect.timer")
      box.succeed("systemctl start keep-node-status-collect.service")
      box.wait_until_succeeds("cat /dev/vcs1 > /tmp/screen_recovered; grep -q 'VAULT' /tmp/screen_recovered", timeout=${toString slow})
      box.wait_until_succeeds("cat /dev/vcs1 > /tmp/screen_recovered; ! grep -q 'STALE' /tmp/screen_recovered", timeout=${toString slow})

      # ---------------------------------------------------------------------------------------------
      # Degraded state propagates. A service going down must reach the glass within a couple of collector
      # cycles, otherwise the screen is decorative.
      # ---------------------------------------------------------------------------------------------
      box.wait_until_succeeds("jq -e '.services.vaultwarden == \"active\"' ${statusFile} >/dev/null", timeout=${toString slow})
      box.succeed("systemctl stop vaultwarden.service")
      box.wait_until_succeeds("jq -e '.services.vaultwarden == \"inactive\"' ${statusFile} >/dev/null", timeout=${toString slow})
      box.wait_until_succeeds("cat /dev/vcs1 > /tmp/screen_degraded; grep -q 'inactive' /tmp/screen_degraded", timeout=${toString slow})
      box.succeed("systemctl start vaultwarden.service")

      # ---------------------------------------------------------------------------------------------
      # The no-input guarantee, checked MECHANICALLY rather than by reading the unit file. StandardInput
      # = "null" is the single line that makes "physical console grants nothing" structural: with fd 0 on
      # /dev/null there is no read path to escape from, no line discipline to poke, no "press any key".
      # ---------------------------------------------------------------------------------------------
      pid = box.succeed("systemctl show -p MainPID --value keep-node-status-render.service").strip()
      assert pid.isdigit() and int(pid) > 0, f"renderer has no MainPID: {pid!r}"
      box.succeed(f"readlink /proc/{pid}/fd/0 > /tmp/fd0")
      box.succeed("grep -qx /dev/null /tmp/fd0")

      # The account holding the terminal cannot be logged into even if a path to it were found: no
      # password (`!` is unmatchable) and a nologin shell.
      #
      # `su -s /bin/sh keep-status` is NOT a test of this and was wrong here first time round: the driver
      # runs as root, so su skips authentication altogether, and -s overrides the very nologin shell that
      # is doing the work. That command succeeds for ANY account on the box and asserts nothing. The two
      # properties are checked directly instead.
      box.succeed("getent passwd keep-status > /tmp/pw")
      box.succeed("grep -q ':[^:]*/nologin$' /tmp/pw")

      # `!` cannot be produced by any hash function, so no supplied password can ever match it. This is
      # what closes every PAM password path to the account, su included.
      box.succeed("getent shadow keep-status > /tmp/shadow_ent")
      box.succeed("cut -d: -f2 /tmp/shadow_ent > /tmp/hash")
      box.succeed("grep -qx '!' /tmp/hash")

      # And with the account's OWN shell (no -s override), even root's passwordless su gets no session.
      box.fail("su keep-status -c true")

      # ---------------------------------------------------------------------------------------------
      # The getty is displaced AND does not come back. autovt@ is the easy one to miss: logind
      # instantiates it on demand, so with it left enabled the moment anything calls chvt a fresh getty
      # is spawned onto the terminal the renderer already owns and the two race for the device. Only a
      # booted machine can show this.
      # ---------------------------------------------------------------------------------------------
      box.fail("systemctl is-active --quiet getty@tty1.service")

      box.succeed("chvt 1")
      box.sleep(5)
      box.fail("systemctl is-active --quiet getty@tty1.service")
      box.fail("systemctl is-active --quiet autovt@tty1.service")

      # The renderer survived the VT switch and still owns the screen.
      box.succeed("systemctl is-active --quiet keep-node-status-render.service")
      box.wait_until_succeeds("cat /dev/vcs1 > /tmp/screen_postchvt; grep -q 'VAULT' /tmp/screen_postchvt", timeout=${toString slow})
      box.fail("grep -qi 'login:' /tmp/screen_postchvt")

      # tty2 keeps its getty on purpose (every account is password-locked, so it grants nothing, and
      # debugAccess uses it during bring-up). Displacing tty1 must not have taken the others with it.
      box.succeed("systemctl cat getty@tty2.service >/dev/null")

      # ---------------------------------------------------------------------------------------------
      # Escape injection, end to end. The collector is trusted and the renderer sanitises anyway: the
      # difference between "the screen is safe because the producer behaves" and "the screen is safe
      # whatever the producer emits". The fixture carries a REAL ESC byte, not the text "\\033".
      # ---------------------------------------------------------------------------------------------
      # The fixture is built BY jq from a shell string holding a real ESC, so the file is VALID JSON that
      # encodes the escape as . A raw ESC byte written straight into the file would instead be
      # illegal JSON (control characters below 0x20 may not appear unescaped in a JSON string): jq would
      # reject the whole snapshot and the renderer would blank to ?? via the malformed-JSON path, which
      # tests the wrong thing entirely and never exercises the sanitiser at all.
      box.succeed(
          "jq -n --argjson generated_at \"$(date +%s)\" "
          "--arg node \"$(printf 'AAA\\033[2JBBB')\" "
          "'{schema:1, generated_at:$generated_at, node:$node, "
          "vault:{state:\"unlocked\",gate:\"active\"}, "
          "services:{vaultwarden:\"active\",mesh:\"n/a\",wisp:\"n/a\"}, "
          "mesh:{interface:null,up:false,address:null,peers:null}, "
          "replication:{role:null,lag_check:\"n/a\",lag_seconds:null}, "
          "anti_lockout:\"active\"}' > /tmp/evil.json"
      )

      # Vacuity guards on the fixture itself. It must parse...
      box.succeed("jq -e . /tmp/evil.json >/dev/null")
      # ...must carry no raw ESC on disk (it is -encoded)...
      box.succeed("LC_ALL=C tr -cd '\\033' < /tmp/evil.json > /tmp/file_esc")
      box.succeed("test ! -s /tmp/file_esc")
      # ...and must nonetheless DECODE to a value containing a real ESC byte, which is what actually
      # reaches the renderer's variable. Without this check a fixture that quietly lost its escape would
      # make the assertion below pass while proving nothing.
      box.succeed("jq -r '.node' /tmp/evil.json > /tmp/node_raw")
      box.succeed("LC_ALL=C tr -cd '\\033' < /tmp/node_raw > /tmp/node_esc")
      box.succeed("test -s /tmp/node_esc")

      box.succeed(
          "KEEPNODE_STATUS_WIDTH=80 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux LANG=C.UTF-8 "
          "${render} --once --status-file /tmp/evil.json > /tmp/frame_evil"
      )
      # Not one ESC byte reaches the glass.
      box.succeed("LC_ALL=C tr -cd '\\033' < /tmp/frame_evil > /tmp/frame_esc")
      box.succeed("test ! -s /tmp/frame_esc")

      # The frame is otherwise HEALTHY (so this is the sanitiser's doing, not the blanking path) and the
      # payload around the escape survived as inert text: the clear-screen sequence was defanged into
      # characters, not obeyed and not silently swallowed whole.
      box.fail("grep -q 'STALE' /tmp/frame_evil")
      box.succeed("grep -q 'AAA' /tmp/frame_evil")
      box.succeed("grep -q 'BBB' /tmp/frame_evil")
      box.succeed("grep -qF '[2J' /tmp/frame_evil")

      # ---------------------------------------------------------------------------------------------
      # Degradation tiers, through the --once path (the SAME build_frame the loop runs).
      # ---------------------------------------------------------------------------------------------

      # ASCII tier: not one byte >= 0x80. This is the fallback for serial consoles, vt100 and non-UTF-8
      # locales, where the block-glyph brand mark would arrive as mojibake.
      box.succeed(
          "KEEPNODE_STATUS_WIDTH=80 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${render} --once --status-file /tmp/evil.json > /tmp/frame_ascii"
      )
      box.succeed("LC_ALL=C tr -d '\\000-\\177' < /tmp/frame_ascii > /tmp/frame_high")
      box.succeed("test ! -s /tmp/frame_high")

      # No-colour tier: no ESC[ sequences at all, for a monochrome LCD, a serial capture or a photograph.
      # State is triple-coded (glyph + word + colour) precisely so it survives this.
      box.succeed("LC_ALL=C tr -cd '\\033' < /tmp/frame_ascii > /tmp/ascii_esc")
      box.succeed("test ! -s /tmp/ascii_esc")

      # Width budget at every tier. 80 is the tier the SSH footer used to overflow by exactly one column,
      # which cut its closing paren off mid-token.
      for width in [40, 60, 80, 100]:
          box.succeed(
              f"KEEPNODE_STATUS_WIDTH={width} KEEPNODE_STATUS_NOCOLOR=1 TERM=linux LANG=C.UTF-8 "
              f"${render} --once --status-file /tmp/evil.json > /tmp/frame_{width}"
          )
          box.succeed(
              f"awk -v w={width} 'length($0) > w {{ print \"OVERWIDE \" length($0) \": \" $0; bad=1 }} "
              f"END {{ exit bad }}' /tmp/frame_{width}"
          )

      # The full tier carries the SSH note, and it must be INTACT -- balanced parens, not a mid-word cut.
      box.succeed("grep -q 'no console login)' /tmp/frame_80")
      box.succeed("grep -q 'no console login)' /tmp/frame_100")

      # ---------------------------------------------------------------------------------------------
      # The REPLICATION row, which has never been rendered, and the collector's lag_seconds journal
      # parsing, which has never been exercised. Both are gated on vaultReplication.role.
      # ---------------------------------------------------------------------------------------------
      standby.wait_for_file("${statusFile}")
      standby.succeed("jq -e '.replication.role == \"standby\"' ${statusFile} >/dev/null")

      # Stand in for the heartbeat the active would have pushed into replicaDir, then run the check so it
      # logs the one line the collector's journal parse is looking for.
      standby.succeed("install -d -o vaultwarden -g vaultwarden -m 0700 ${replicaDir}")
      standby.succeed("date +%s > ${replicaDir}/.push-heartbeat")
      standby.succeed("chown vaultwarden:vaultwarden ${replicaDir}/.push-heartbeat")
      standby.succeed("systemctl start keep-node-vault-lag-check.service")

      # The unit logged a lag line...
      standby.succeed("journalctl -u keep-node-vault-lag-check.service -o cat --no-pager > /tmp/lag_log")
      standby.succeed("grep -q '^vault replication lag: ' /tmp/lag_log")

      # ...and the collector recovered the NUMBER behind it into the snapshot. This is the parse that has
      # never run before.
      standby.wait_until_succeeds("jq -e '.replication.lag_seconds != null' ${statusFile} >/dev/null", timeout=${toString slow})
      standby.succeed("jq -e '.replication.lag_seconds >= 0' ${statusFile} >/dev/null")

      # A HEALTHY standby must read OK. keep-node-vault-lag-check is Type=oneshot with NO
      # RemainAfterExit, so a SUCCESSFUL run leaves the unit "inactive" and its ActiveState carries no
      # pass signal at all; nixos/vault-replication.nix:628 states that `systemctl is-failed` is the
      # monitoring signal instead. Reading it as a raw ActiveState painted a permanent amber
      # REPLICATION row on a healthy node, which is the cry-wolf failure this must never regress into.
      #
      # The heartbeat is RE-STAMPED on every attempt rather than written once: it goes stale after
      # maxLagSeconds (90s), so a single fixture stamp would make this a race against the 30s timer on a
      # contended builder. Each attempt refreshes the stamp, runs the check, and then waits one
      # collector round (refreshSeconds=5) for the verdict to reach the snapshot.
      def restamp_and_check(extra):
          standby.wait_until_succeeds(
              "date +%s > ${replicaDir}/.push-heartbeat && "
              "chown vaultwarden:vaultwarden ${replicaDir}/.push-heartbeat && "
              "systemctl start keep-node-vault-lag-check.service && "
              "sleep 7 && " + extra,
              timeout=${toString slow},
          )

      restamp_and_check("jq -e '.replication.lag_check == \"ok\"' ${statusFile} >/dev/null")

      # Non-vacuity guard on the assertion above: it only proves anything if the unit really is sitting
      # at the non-latched "inactive" that used to render amber. If systemd ever started latching this
      # unit "active", the ok verdict would be trivially true and this row would stop testing the bug.
      standby.succeed("systemctl show -p ActiveState --value keep-node-vault-lag-check.service > /tmp/lagstate")
      print("=== observed lag-check ActiveState ===")
      print(standby.succeed("cat /tmp/lagstate"))
      standby.succeed("grep -qx 'inactive' /tmp/lagstate")

      # ...and the OK state reaches the RENDERED row, not just the JSON. Asserted through --once in the
      # ascii/no-colour tier so the verdict is plain text ("[ ok ]") rather than a colour code or a
      # console-mapped glyph byte that reading /dev/vcs1 would make brittle to grep for.
      restamp_and_check(
          "KEEPNODE_STATUS_WIDTH=80 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${renderStandby} --once --status-file ${statusFile} > /tmp/frame_repl && "
          "grep -qE '\\[ ok \\] +REPLICATION' /tmp/frame_repl"
      )
      print("=== rendered standby frame ===")
      print(standby.succeed("cat /tmp/frame_repl"))
      standby.fail("grep -qE '\\[warn\\] +REPLICATION' /tmp/frame_repl")

      # And the row actually reaches the glass, with the lag rendered into it.
      # Wait on the LAG text, not on the word REPLICATION: the row is painted either way (it reads
      # "standby <lag_check>" when no lag number is available), so waiting on the label alone matches a
      # frame rendered before the heartbeat existed and proves nothing about the parse.
      standby.wait_until_succeeds(
          "cat /dev/vcs1 > /tmp/screen_repl; grep -qE 'standby lag [0-9]+s' /tmp/screen_repl",
          timeout=${toString slow},
      )
      standby.succeed("grep -q 'REPLICATION' /tmp/screen_repl")
    '';
}
