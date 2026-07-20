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
      # The anti-lockout verdict carries its own AGE. keep-node-admin-key-check is Type=oneshot +
      # RemainAfterExit with no timer anywhere in the tree: it runs once at boot and latches "active"
      # forever, so a key deleted after boot never re-triggers it. Without the age beside it, the row
      # paints a green "ok" on a node whose admin SSH is already gone -- and on a display where every
      # other field blanks to ?? the moment it stops being current, a non-?? value reads as "true right
      # now". The age is what stops the row from wearing live-data clothing.
      #
      # keepNode.adminAccess is OFF on these nodes, so the unit is genuinely absent here. That is worth
      # asserting in its own right: the field must be null rather than fabricating an age for a check
      # that never ran.
      box.succeed("jq -e 'has(\"anti_lockout_checked_at\")' ${statusFile} >/dev/null")
      box.succeed("jq -e '.anti_lockout == \"n/a\" and .anti_lockout_checked_at == null' ${statusFile} >/dev/null")
      box.succeed(
          "KEEPNODE_STATUS_WIDTH=80 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${render} --once --status-file ${statusFile} > /tmp/frame_al_absent"
      )
      # No timestamp, no age claim -- and specifically no "checked 0s ago", which would be a lie about
      # a check that has never run.
      box.fail("grep -q 'checked' /tmp/frame_al_absent")

      # The rendering of a REAL, old verdict, driven from a fixture so the age is exact rather than
      # whatever the VM's uptime happens to be. 41 days is chosen to be unmistakably not-now.
      box.succeed(
          "jq -n --argjson generated_at \"$(date +%s)\" "
          "--argjson checked_at \"$(( $(date +%s) - 41 * 86400 ))\" "
          "'{schema:1, generated_at:$generated_at, node:\"agetest\", "
          "vault:{state:\"unlocked\",gate:\"active\"}, "
          "services:{vaultwarden:\"active\",mesh:\"n/a\",wisp:\"n/a\"}, "
          "mesh:{interface:null,up:false,address:null,peers:null}, "
          "replication:{role:null,lag_check:\"n/a\",lag_seconds:null}, "
          "anti_lockout:\"active\", anti_lockout_checked_at:$checked_at}' > /tmp/al_old.json"
      )
      # KEEPNODE_STATUS_UPTIME: the renderer refuses to show an age exceeding this boot's uptime, since
      # the unit cannot have activated before the machine started. A 41-day age is therefore physically
      # impossible on a VM minutes into its life, and without this seam the fixture exercises the clamp
      # instead of the width behaviour it exists to test. The clamp itself is asserted separately below.
      box.succeed(
          "KEEPNODE_STATUS_UPTIME=9999999 "
          "KEEPNODE_STATUS_WIDTH=80 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${render} --once --status-file /tmp/al_old.json > /tmp/frame_al_old"
      )
      print("=== frame with a 41-day-old anti-lockout verdict ===")
      print(box.succeed("cat /tmp/frame_al_old"))
      # The frame is otherwise healthy, so the age is the row's doing and not the staleness blanking.
      box.fail("grep -q 'STALE' /tmp/frame_al_old")
      box.succeed("grep -qE '\\[ ok \\] +ANTI-LOCKOUT +active \\(checked 41d ago\\)' /tmp/frame_al_old")

      # The age must be DROPPED WHOLE when it does not fit, never sliced into an unbalanced paren --
      # the SSH footer's discipline. At w=40 in the ascii tier the value column is 19 columns, which
      # fits the short form but not the long one.
      box.succeed(
          "KEEPNODE_STATUS_UPTIME=9999999 "
          "KEEPNODE_STATUS_WIDTH=40 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${render} --once --status-file /tmp/al_old.json > /tmp/frame_al_narrow"
      )
      print("=== narrow-tier anti-lockout age ===")
      print(box.succeed("cat /tmp/frame_al_narrow"))
      box.succeed(
          "awk -v w=40 'length($0) > w { print \"OVERWIDE \" length($0) \": \" $0; bad=1 } "
          "END { exit bad }' /tmp/frame_al_narrow"
      )
      # Positive assertion FIRST. The three negative checks below all pass vacuously if the age feature
      # broke entirely or the fixture aged past staleSeconds -- v_al_at blanks, no parenthetical is
      # emitted, and "no half-written parenthetical" becomes trivially true. This pins the short form
      # that is supposed to survive here, which is the actual "drop whole, do not slice" property.
      box.succeed("grep -qF 'active (41d ago)' /tmp/frame_al_narrow")
      # Whatever form survived, it is not a half-written parenthetical.
      box.fail("grep -qE '\\((checked )?41d( ago)?$' /tmp/frame_al_narrow")
      box.fail("grep -q '(checked$' /tmp/frame_al_narrow")

      # ---------------------------------------------------------------------------------------------
      # The uptime clamp. ActiveEnterTimestamp is CLOCK_REALTIME at activation, so a box with no RTC
      # (or with NTP landing after boot) jumps the clock forward and a check that ran seconds ago
      # computes as decades. The unit cannot have activated before this boot, so an age exceeding
      # uptime is impossible and must be DROPPED rather than painted -- a fabricated reading on the one
      # row added to stop fabricated readings is the worst possible place to have one.
      #
      # Same 41-day fixture, real /proc/uptime this time (VM is minutes old), so the age is impossible.
      box.succeed(
          "KEEPNODE_STATUS_WIDTH=80 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${render} --once --status-file /tmp/al_old.json > /tmp/frame_al_skew"
      )
      print("=== impossible age (exceeds uptime) must be dropped ===")
      print(box.succeed("cat /tmp/frame_al_skew"))
      # The row still renders and still reads healthy -- only the implausible AGE is withheld.
      box.succeed("grep -qE '\\[ ok \\] +ANTI-LOCKOUT +active *$' /tmp/frame_al_skew")
      box.fail("grep -q '41d' /tmp/frame_al_skew")
      box.fail("grep -q 'checked' /tmp/frame_al_skew")

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
      # ActiveState=failed, end to end. Until now NO unit in this test was ever driven to `failed`, so
      # the collector's unit_state -> "failed" mapping, the renderer's unit_status -> `fail`, and the
      # `fail` glyph itself were entirely unexercised -- despite state mapping being the exact bug class
      # that already regressed here once (a non-latching oneshot read as a raw ActiveState painted a
      # healthy node permanently amber).
      #
      # A runtime drop-in under /run replaces a PROBED unit's ExecStart with a command that exits 1.
      # It has to be a probed unit: the collector asks about a fixed list of unit names, so a standalone
      # fixture unit would fail invisibly and prove nothing. `Restart=no` is part of the fixture -- with
      # the packaged restart policy left in place the unit sits in "activating" (auto-restart) instead
      # of settling at "failed", which is a different state and not the one under test.
      box.succeed("mkdir -p /run/systemd/system/vaultwarden.service.d")
      box.succeed(
          "printf '[Service]\\nExecStart=\\nExecStart=/bin/sh -c \"exit 1\"\\nRestart=no\\n' "
          "> /run/systemd/system/vaultwarden.service.d/99-fail-fixture.conf"
      )
      box.succeed("systemctl daemon-reload")
      box.succeed("systemctl restart vaultwarden.service || true")
      box.wait_until_succeeds("systemctl is-failed --quiet vaultwarden.service", timeout=${toString slow})

      # The collector maps it to "failed" -- and specifically NOT to "n/a", which is the mapping an
      # absent unit gets and would quietly hide a genuinely broken service.
      box.wait_until_succeeds("jq -e '.services.vaultwarden == \"failed\"' ${statusFile} >/dev/null", timeout=${toString slow})
      box.succeed("jq -r '.services.vaultwarden' ${statusFile} > /tmp/svc_failed")
      box.fail("grep -qx 'n/a' /tmp/svc_failed")

      # ...and the renderer turns that into the `fail` glyph on the row. Read through --once in the
      # ascii tier so the assertion is on plain text ("[FAIL]") rather than on the U+00D7 byte, which
      # reading /dev/vcs1 would make brittle. The frame must be otherwise healthy, so this is the state
      # mapping's doing and not the staleness blanking painting everything unknown.
      box.succeed(
          "KEEPNODE_STATUS_WIDTH=80 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${render} --once --status-file ${statusFile} > /tmp/frame_failed"
      )
      print("=== frame with a failed unit ===")
      print(box.succeed("cat /tmp/frame_failed"))
      box.fail("grep -q 'STALE' /tmp/frame_failed")
      box.succeed("grep -qE '\\[FAIL\\] +VAULTWARDEN' /tmp/frame_failed")
      box.fail("grep -qE '\\[ -- \\] +VAULTWARDEN' /tmp/frame_failed")

      # Restore, and prove the fail state was not sticky -- a `fail` glyph that never clears is as
      # useless as one that never lights.
      box.succeed("rm -f /run/systemd/system/vaultwarden.service.d/99-fail-fixture.conf")
      box.succeed("systemctl daemon-reload")
      box.succeed("systemctl reset-failed vaultwarden.service")
      box.succeed("systemctl restart vaultwarden.service")
      box.wait_until_succeeds("jq -e '.services.vaultwarden == \"active\"' ${statusFile} >/dev/null", timeout=${toString slow})

      # ---------------------------------------------------------------------------------------------
      # The no-input guarantee, checked MECHANICALLY rather than by reading the unit file. StandardInput
      # = "null" is the single line that makes "physical console grants nothing" structural: with fd 0 on
      # /dev/null there is no read path to escape from, no line discipline to poke, no "press any key".
      # ---------------------------------------------------------------------------------------------
      pid = box.succeed("systemctl show -p MainPID --value keep-node-status-render.service").strip()
      assert pid.isdigit() and int(pid) > 0, f"renderer has no MainPID: {pid!r}"
      box.succeed(f"readlink /proc/{pid}/fd/0 > /tmp/fd0")
      box.succeed("grep -qx /dev/null /tmp/fd0")

      # The TIOCSTI question, VERIFIED rather than inferred. TIOCSTI ("push this byte back into the
      # terminal's input queue") is the classic way a process holding a VT fabricates keystrokes for
      # whatever reads that terminal next. The kernel requires a descriptor open for READING to issue
      # it. The security review concluded by reading the unit file that the renderer holds no such
      # descriptor; that conclusion is asserted here against the running process instead.
      #
      # Two independent properties, because either one alone leaves a gap:
      #   1. NO descriptor on the VT is open in a readable mode. Not just fd 0: fd 1 is the terminal
      #      (StandardOutput=tty), and this proves the manager opened it O_WRONLY rather than O_RDWR.
      #      Access mode is the low two bits of the octal `flags:` field in fdinfo (0=RDONLY, 1=WRONLY,
      #      2=RDWR), so a readable VT fd is anything whose accmode is not 1.
      #   2. The process has NO controlling terminal, i.e. field 7 (tty_nr) of /proc/PID/stat is 0.
      #      Without one there is no /dev/tty to reopen -- which is how a process that was given only a
      #      write-only fd could otherwise get a fresh read-write one back.
      vt = "/dev/tty1"
      fds = box.succeed(f"ls /proc/{pid}/fd").split()
      assert fds, f"renderer {pid} has no open descriptors at all"
      saw_vt = False
      for fd in fds:
          # Target and flags in ONE round trip, both tolerant of the fd vanishing. The renderer runs
          # command substitutions every repaintSeconds, each transiently opening a pipe fd, so an entry
          # present in the `ls` above can be gone by the time a separate driver round trip reaches it.
          # An unguarded awk exits 2 there and fails the test on a race rather than on a defect.
          probe = box.succeed(
              f"readlink /proc/{pid}/fd/{fd} 2>/dev/null || true; echo '|'; "
              f"awk '/^flags:/{{print $2}}' /proc/{pid}/fdinfo/{fd} 2>/dev/null || true"
          )
          target, _, flags = probe.partition("|")
          target, flags = target.strip(), flags.strip()
          if not target or not flags:
              continue
          accmode = int(flags, 8) & 3
          print(f"fd {fd} -> {target} flags={flags} accmode={accmode}")
          if target == vt:
              saw_vt = True
              assert accmode == 1, (
                  f"renderer fd {fd} is open on {vt} in a READABLE mode (accmode={accmode}, "
                  f"flags={flags}): TIOCSTI keystroke injection into this VT becomes possible, and "
                  f"'the console accepts no input' stops being a structural property"
              )
          assert not (target == "/dev/tty"), f"renderer fd {fd} is on /dev/tty (a controlling terminal)"

      # Non-vacuity: if the renderer held NO descriptor on the VT at all, the loop above would pass
      # while proving nothing. It must hold one (that is how it paints) -- just never a readable one.
      assert saw_vt, f"renderer holds no descriptor on {vt}; the fd-mode assertion above was vacuous"

      # No controlling terminal. comm (field 2) can itself contain spaces and parens, so fields are
      # counted from the LAST ')' -- after which stat's field 3 (state) is index 0, making tty_nr
      # (field 7) index 4.
      stat_line = box.succeed(f"cat /proc/{pid}/stat")
      tty_nr = int(stat_line[stat_line.rindex(")") + 1:].split()[4])
      assert tty_nr == 0, (
          f"renderer has a controlling terminal (tty_nr={tty_nr}); it could reopen /dev/tty read-write "
          f"and regain exactly the read path StandardInput=null exists to deny"
      )

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
      # debugAccess uses it during bring-up). Displacing tty1 must not have taken the others with it,
      # and Alt+F2 is the ONLY console recovery path if the renderer dies -- tty1 has no getty left to
      # fall back to.
      #
      # `systemctl cat getty@tty2.service` was the previous check and proved nothing: cat succeeds on
      # any template unit regardless of enablement, and for a MASKED instance it happily prints the
      # /dev/null symlink target. LoadState is the property that actually distinguishes them, because
      # NixOS implements `enable = false` for a unit as exactly that /dev/null symlink, which systemd
      # reports as "masked". So the two VTs must disagree here, and that disagreement is the assertion.
      box.succeed("systemctl show -p LoadState --value getty@tty1.service > /tmp/getty1_load")
      box.succeed("systemctl show -p LoadState --value getty@tty2.service > /tmp/getty2_load")
      print("=== getty LoadState: tty1 / tty2 ===")
      print(box.succeed("cat /tmp/getty1_load /tmp/getty2_load"))
      box.succeed("grep -qx 'masked' /tmp/getty1_load")
      box.fail("grep -qx 'masked' /tmp/getty2_load")
      box.succeed("grep -qx 'loaded' /tmp/getty2_load")

      # And the same for autovt@, the one that is easy to miss: logind instantiates it on demand, so if
      # tty2's were masked too, Alt+F2 would silently produce nothing at the keyboard.
      box.succeed("systemctl show -p LoadState --value autovt@tty1.service > /tmp/autovt1_load")
      box.succeed("systemctl show -p LoadState --value autovt@tty2.service > /tmp/autovt2_load")
      box.succeed("grep -qx 'masked' /tmp/autovt1_load")
      box.fail("grep -qx 'masked' /tmp/autovt2_load")

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
      # The DEGRADED paths, through --once --status-file. Only the timer-driven STALE path had ever been
      # covered; the missing-file, malformed-JSON, wrong-schema and collector-fault paths were all
      # unexercised, even though each one is a distinct banner and each one is what stands between the
      # operator and a plausible-looking frame full of numbers that are not true.
      #
      # Every one of them must satisfy the SAME two properties as the STALE path: the banner names the
      # reason, and every collected value is blanked to "??".
      # ---------------------------------------------------------------------------------------------
      def degraded_frame(name, setup, expect, width=80):
          if setup:
              box.succeed(setup)
          box.succeed(
              f"KEEPNODE_STATUS_WIDTH={width} KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 "
              f"TERM=linux ${render} --once --status-file /tmp/deg_{name}.json > /tmp/frame_deg_{name}"
          )
          print(f"=== degraded frame: {name} ===")
          print(box.succeed(f"cat /tmp/frame_deg_{name}"))
          # The banner names the reason...
          box.succeed(f"grep -qF '{expect}' /tmp/frame_deg_{name}")
          # ...and nothing collected survived. The unlocked/active greps are the ones that matter: a
          # last-known reading left on the glass is read as current by anyone glancing at it.
          box.succeed(f"grep -q '??' /tmp/frame_deg_{name}")
          box.fail(f"grep -qE '(unlocked|active)' /tmp/frame_deg_{name}")
          # The static SSH line is not a collected fact and must survive -- it is how the operator
          # standing at a screen full of ?? gets to a shell to fix it.
          box.succeed(f"grep -q 'SSH' /tmp/frame_deg_{name}")

      # 1. No snapshot at all: the collector has never run, or /run was wiped.
      box.succeed("rm -f /tmp/deg_missing.json")
      degraded_frame("missing", None, "NO STATUS SNAPSHOT")

      # 2. Unparseable bytes where JSON should be (a truncated write, a half-written file).
      degraded_frame("malformed", "printf 'this is not json{' > /tmp/deg_malformed.json", "MALFORMED JSON")

      # 3. A snapshot from a FUTURE schema. Parsing it against schema 1's field vocabulary would slide
      #    values into the wrong rows, which is the failure mode that looks entirely plausible.
      degraded_frame(
          "schema",
          "jq -n --argjson generated_at \"$(date +%s)\" "
          "'{schema:2, generated_at:$generated_at, node:\"future\"}' > /tmp/deg_schema.json",
          "UNSUPPORTED",
      )

      # 4. The collector's OWN emit failure. This is the subtle one: the fallback payload carries a
      #    CURRENT generated_at, so staleness can never fire on it, and until the renderer read `.error`
      #    the result was a completely normal-looking frame -- hostname painted, every row "unknown",
      #    no banner anywhere. The comment in the collector claimed a fault was reported; nothing read
      #    the field.
      degraded_frame(
          "collector",
          "jq -n --argjson generated_at \"$(date +%s)\" "
          "'{schema:1, generated_at:$generated_at, node:null, error:\"collector-emit-failed\"}' "
          "> /tmp/deg_collector.json",
          "COLLECTOR FAULT",
      )

      # Non-vacuity for the collector-fault case specifically: prove the snapshot is NOT stale, so the
      # banner above came from reading .error and not from the age check firing by luck.
      box.succeed("jq -e '(now - .generated_at) < 5' /tmp/deg_collector.json >/dev/null")

      # ---------------------------------------------------------------------------------------------
      # Banner text WRAPS, never slices. At w=40 the inner width is 34 and the notice is 41 characters,
      # so a hard cut produced "...AND SHO" -- dropping the very "??" the sentence exists to explain.
      # Asserted at the narrowest tier, which is the only one where it bites.
      # ---------------------------------------------------------------------------------------------
      box.succeed(
          "KEEPNODE_STATUS_WIDTH=40 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${render} --once --status-file /tmp/deg_malformed.json > /tmp/frame_banner40"
      )
      print("=== narrow-tier banner wrap ===")
      print(box.succeed("cat /tmp/frame_banner40"))
      # Still inside the width budget after wrapping...
      box.succeed(
          "awk -v w=40 'length($0) > w { print \"OVERWIDE \" length($0) \": \" $0; bad=1 } "
          "END { exit bad }' /tmp/frame_banner40"
      )
      # ...the sentence survived WHOLE across the wrap, including its trailing ?? ...
      box.succeed("grep -q 'SHOW AS ??' /tmp/frame_banner40")
      # ...and no line ends mid-word on the word the old hard cut split.
      box.fail("grep -q 'AND SHO *!!' /tmp/frame_banner40")

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

      # ---------------------------------------------------------------------------------------------
      # The OTHER half of the verdict mapping: check_unit_state -> "failed" -> check_status -> `fail`.
      # Everything above only ever drove this unit through its healthy "inactive" state, so the failing
      # branch of the non-latching-oneshot reading had never executed. That branch is the whole reason
      # this unit is read via `is-failed` semantics instead of as a raw ActiveState, so leaving it
      # untested left the interesting half of the fix unguarded.
      #
      # Same runtime drop-in technique as the vaultwarden fixture on box: replace ExecStart with a
      # command that exits 1 and let the unit settle at failed.
      standby.succeed("mkdir -p /run/systemd/system/keep-node-vault-lag-check.service.d")
      standby.succeed(
          "printf '[Service]\\nExecStart=\\nExecStart=/bin/sh -c \"exit 1\"\\n' "
          "> /run/systemd/system/keep-node-vault-lag-check.service.d/99-fail-fixture.conf"
      )
      standby.succeed("systemctl daemon-reload")
      standby.succeed("systemctl start keep-node-vault-lag-check.service || true")
      standby.wait_until_succeeds("systemctl is-failed --quiet keep-node-vault-lag-check.service", timeout=${toString slow})

      # The collector emits the VERDICT vocabulary here ("failed"), not a raw ActiveState.
      standby.wait_until_succeeds("jq -e '.replication.lag_check == \"failed\"' ${statusFile} >/dev/null", timeout=${toString slow})

      standby.succeed(
          "KEEPNODE_STATUS_WIDTH=80 KEEPNODE_STATUS_ASCII=1 KEEPNODE_STATUS_NOCOLOR=1 TERM=linux "
          "${renderStandby} --once --status-file ${statusFile} > /tmp/frame_repl_failed"
      )
      print("=== standby frame with a failed lag check ===")
      print(standby.succeed("cat /tmp/frame_repl_failed"))
      standby.fail("grep -q 'STALE' /tmp/frame_repl_failed")
      standby.succeed("grep -qE '\\[FAIL\\] +REPLICATION' /tmp/frame_repl_failed")
      # Not amber and not "absent": those are the two mappings this row must never collapse into.
      standby.fail("grep -qE '\\[warn\\] +REPLICATION' /tmp/frame_repl_failed")
      standby.fail("grep -qE '\\[ -- \\] +REPLICATION' /tmp/frame_repl_failed")

      standby.succeed("rm -f /run/systemd/system/keep-node-vault-lag-check.service.d/99-fail-fixture.conf")
      standby.succeed("systemctl daemon-reload")
      standby.succeed("systemctl reset-failed keep-node-vault-lag-check.service")
    '';
}
