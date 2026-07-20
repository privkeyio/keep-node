# The keep-node brand mark: a pure typographic asset, no config, no options, no pkgs.
#
# Everything the box prints to a console -- the boot status display, the installer MOTD -- draws a
# framed block underneath this mark. The frame is sized from `markWidth`, so if the mark's lines are
# not all EXACTLY that many terminal columns wide, every border below it is ragged and the whole
# display looks broken on the one screen an operator actually looks at during bring-up. That is the
# invariant this file exists to hold, and `checks.brand-shapes` in flake.nix enforces it.
#
# Measuring it is the hard part. Nix has no codepoint-aware length: `lib.stringLength "█▀█"` is 9
# (bytes), and `lib.stringToCharacters` splits bytes too. So byte equality across lines is necessary
# but NOT sufficient -- a genuinely ragged unicode mark passes a byte check whenever the raggedness
# happens to be byte-balanced (one dropped 3-byte block plus three added spaces, say). `displayWidth`
# below therefore counts real columns: it folds each known wide glyph down to a single ASCII byte and
# then requires every remaining byte to be printable ASCII. An unrecognised multibyte glyph leaves a
# non-ASCII byte behind and yields `null`, which callers must treat as a failure -- the measurement
# refuses to guess rather than silently returning a byte count.
#
# `markAscii` is the fallback for serial consoles, vt100, and any terminal not in a UTF-8 locale,
# where the block glyphs render as mojibake or question marks. It must be the same line count and the
# same column width as the unicode mark so a renderer can swap one for the other without resizing.
{ lib }:
let
  # Printable ASCII (0x20-0x7E) as single bytes. Used both to prove the fallback mark is transport
  # safe and, in displayWidth, to prove nothing unmeasured is left in a string.
  printableAscii = lib.stringToCharacters " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

  # Every non-ASCII glyph this file is allowed to contain, each occupying exactly one column.
  wideGlyphs = [
    "█"
    "▀"
    "▄"
    "·"
  ];

  indentOf = n: lib.concatStrings (lib.replicate n " ");
in
rec {
  isPrintableAscii = s: lib.replaceStrings printableAscii (map (_: "") printableAscii) s == "";

  # Terminal columns, or null if the string holds a glyph this file cannot measure.
  displayWidth =
    s:
    let
      folded = lib.replaceStrings wideGlyphs (map (_: "#") wideGlyphs) s;
    in
    if isPrintableAscii folded then lib.stringLength folded else null;

  # Declared, not derived: flake.nix checks the mark against this number, so deriving it from the
  # mark itself would make that check vacuous.
  markWidth = 18;

  markUnicode = [
    "█▄▀  █▀▀  █▀▀  █▀█"
    "██   █▀   █▀   █▀▀"
    "█▀▄  █▄▄  █▄▄  █  "
  ];

  markAscii = [
    "| /  |--  |--  |-\\"
    "|<   |-   |-   |-/"
    "| \\  |__  |__  |  "
  ];

  wordmark = "k e e p · n o d e";
  wordmarkAscii = "k e e p . n o d e";

  block =
    {
      ascii ? false,
      indent ? 2,
    }:
    let
      pad = indentOf indent;
      lines = (if ascii then markAscii else markUnicode) ++ [
        ""
        (if ascii then wordmarkAscii else wordmark)
      ];
    in
    lib.concatStringsSep "\n" (map (l: if l == "" then "" else pad + l) lines);
}
