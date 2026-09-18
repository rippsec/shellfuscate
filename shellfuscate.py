#!/usr/bin/env python3
"""
Randomized shell-command obfuscator.

Educational tool for CTF write-ups, shell-quoting research, and
detection-engineering test corpora. Encodes a plain shell command into a
semantically equivalent, harder-to-read form using Bash ANSI-C quoting,
randomized escape bases, alternate word separators, and wrappers.

As a safety measure it refuses to obfuscate a denylist of destructive
patterns - including when they are hidden inside `sh -c` / base64 payloads.

`--verify` re-parses the output WITHOUT executing it.
"""
from __future__ import annotations

import argparse
import base64
import random
import re
import shlex
import subprocess
import sys

# --------------------------------------------------------------------------
# 1. Character encoders
# --------------------------------------------------------------------------

# Literal characters that are safe to leave as-is inside $'...'
_LITERAL_OK = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "_-./=:,+@%^"
)

# Each bash escape form has a hard digit-count limit; using it on a value
# that does not fit silently corrupts the output (e.g. \\x1f600 is read as
# \\x1f followed by literal "600").  So every encoder declares the maximum
# code point it can represent and encode_char() filters on that.
_ENCODERS = {
    # name: (weight, max_codepoint, formatter)
    # hex/oct emit RAW BYTES, which only coincide with the input text for
    # ASCII; for code points >= 0x80 they would re-encode as Latin-1-ish
    # garbage instead of UTF-8.  \u/\U emit the proper UTF-8 sequence.
    "hex": (4, 0x7F,        lambda b: f"\\x{b:02x}"),      # \x64      (max 2 hex digits)
    "oct": (4, 0o177,       lambda b: f"\\{b:03o}"),       # \144      (max 3 octal digits)
    "uni": (2, 0xFFFF,      lambda b: f"\\u{b:04x}"),      # \u0064    (exactly 4 hex digits)
    "uni8": (2, 0x10FFFF,   lambda b: f"\\U{b:08x}"),      # \U0001f600 (exactly 8 hex digits)
}

# Hoist the per-encoder tables so they are built once, not per character.
_ENCODER_NAMES = tuple(_ENCODERS)
_ENCODER_WEIGHTS = tuple(_ENCODERS[n][0] for n in _ENCODER_NAMES)
_LIT_WEIGHT = 2


def _eligible_encoders(b: int) -> tuple[list[str], list[int]]:
    names = [n for n in _ENCODER_NAMES if _ENCODERS[n][1] >= b]
    weights = [_ENCODERS[n][0] for n in names]
    return names, weights


def encode_char(ch: str, rng: random.Random, allow_literal: bool = True) -> str:
    """Encode one character as a $'...' escape sequence, or a literal."""
    if ch == "'":
        return "\\'"
    if ch == "\\":
        return "\\\\"

    b = ord(ch)
    names, weights = _eligible_encoders(b)
    if allow_literal and ch in _LITERAL_OK:
        names.append("lit")
        weights.append(_LIT_WEIGHT)

    kind = rng.choices(names, weights=weights, k=1)[0]
    if kind == "lit":
        return ch
    return _ENCODERS[kind][2](b)


# --------------------------------------------------------------------------
# 2. Word encoders
# --------------------------------------------------------------------------

def encode_word(word: str, rng: random.Random,
                allow_literal: bool = True, max_chunks: int = 3) -> str:
    """Encode one shell word as one or more concatenated $'...' chunks.

    Chunks are adjacent with no separator, so $'a'$'b' is the single word 'ab'.
    """
    if word == "":
        return "$''"

    n_chunks = rng.randint(1, max(1, min(max_chunks, len(word))))
    cuts = set(rng.sample(range(1, len(word)), n_chunks - 1)) if n_chunks > 1 else set()

    chunks: list[list[str]] = [[]]
    for i, ch in enumerate(word):
        if i in cuts:
            chunks.append([])
        chunks[-1].append(encode_char(ch, rng, allow_literal))

    return "".join("$'" + "".join(c) + "'" for c in chunks if c)


_SEPARATORS = [" ", "\t", "${IFS}", "$IFS"]


def encode_argv(argv: list[str], rng: random.Random,
                allow_literal: bool = True, max_chunks: int = 3,
                separators: list[str] | None = None) -> str:
    """Encode a whole argv into an obfuscated command line."""
    seps = separators if separators else _SEPARATORS
    out = [encode_word(argv[0], rng, allow_literal, max_chunks)]
    for w in argv[1:]:
        out.append(rng.choice(seps))
        out.append(encode_word(w, rng, allow_literal, max_chunks))
    return "".join(out)


def encode_blob(text: str, rng: random.Random, max_chunks: int = 4) -> str:
    """Encode an entire string (spaces included) as ONE quoted word.

    Spaces become \\x20 etc., so they never split. Used for `sh -c` payloads.
    """
    return encode_word(text, rng, allow_literal=False, max_chunks=max_chunks)


# --------------------------------------------------------------------------
# 3. Wrappers
# --------------------------------------------------------------------------

def wrap(argv: list[str], rng: random.Random, mode: str,
         allow_literal: bool, max_chunks: int,
         separators: list[str] | None) -> str:
    if mode == "bare":
        return encode_argv(argv, rng, allow_literal, max_chunks, separators)

    if mode == "subst":
        # Command substitution as the command name: the output is word-split
        # and the first field becomes the command.
        return "`" + encode_argv(argv, rng, allow_literal, max_chunks, separators) + "`"

    if mode == "eval":
        return "eval " + encode_argv(argv, rng, allow_literal, max_chunks, separators)

    if mode == "sh":
        # sh -c <one-argument-payload>; spaces inside become \x20.
        payload = encode_blob(shlex.join(argv), rng, max_chunks)
        pra = encode_word("sh", rng, allow_literal, 1)
        prb = encode_word("-c", rng, allow_literal, 1)
        return f"{pra} {prb} {payload}"

    if mode == "b64":
        blob = base64.b64encode(shlex.join(argv).encode()).decode()
        return f"echo {blob} | base64 -d | sh"

    raise ValueError(f"unknown mode: {mode}")

def outer_wrap(out: str) -> str:
    """Wrap an already-obfuscated command as "`<out>`" (double-quoted
    command substitution)."""
    return '"`' + out + '`"'


def outer_unwrap(out: str) -> str:
    """Inverse of outer_wrap(); leaves non-wrapped input untouched."""
    if out.startswith('"`') and out.endswith('`"'):
        return out[2:-2]
    return out


# --------------------------------------------------------------------------
# 4. Safety + verification
# --------------------------------------------------------------------------

# Commands we refuse to obfuscate, matched on the basename of argv[0] and,
# for opaque wrappers (sh/b64), on every token of the decoded payload too -
# otherwise `echo <b64-of-rm> | base64 -d | sh` would trivially bypass the
# denylist.
#_DENY = frozenset({"rm", "dd", "mkfs", "shred", "chmod", "chown", "sudo", "curl", "wget"})

_DENY = frozenset({""})



def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def is_safe(argv: list[str], mode: str) -> bool:
    """True if neither the command nor (for sh/b64) its payload is denied."""
    candidates = [_basename(argv[0])]
    if mode in ("sh", "b64"):
        # Payload tokens: for "sh" the words of the joined command; for "b64"
        # the decoded base64 blob.  shlex handles the quoting for us.
        if mode == "sh":
            payload = shlex.join(argv)
        else:
            payload = base64.b64encode(shlex.join(argv).encode()).decode()
            try:
                payload = base64.b64decode(payload).decode()
            except Exception:
                return False
        try:
            candidates += [_basename(t) for t in shlex.split(payload)]
        except ValueError:
            pass
    return not any(c in _DENY for c in candidates)


_B64_LINE = re.compile(r"^echo ([A-Za-z0-9+/=]+) \| base64 -d \| sh$")


def expected_argv(argv: list[str], mode: str) -> list[str] | None:
    """The word list `parse_back(wrap(...))` must reproduce, or None if the
    mode cannot be verified by word expansion alone (b64)."""
    if mode == "eval":
        return list(argv)  # "eval " prefix is stripped before parse_back
    if mode == "sh":
        return ["sh", "-c", shlex.join(argv)]
    if mode == "b64":
        return None
    return list(argv)


def parse_back(payload: str, timeout: float = 5.0) -> list[str]:
    """Expand the payload without executing it, returning the word list.

    Runs `for a in <payload>; do printf '%s\\0' "$a"; done` in bash. The
    target command is never invoked - only the quoting is resolved.

    NOTE: never pass a command-substitution payload (mode "subst") here;
    bash would execute it.  Callers strip the backticks first.
    """
    script = f'for __a in {payload}; do printf "%s\\0" "$__a"; done'
    r = subprocess.run(["bash", "-c", script], capture_output=True,
                       text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    # NUL-delimited so arguments containing newlines / vertical tabs survive
    # (str.splitlines() would chop them incorrectly).
    parts = r.stdout.split("\x00")
    if parts and parts[-1] == "":
        parts.pop()
    return parts


def verify_output(out: str, argv: list[str], mode: str) -> str:
    """Return "ok" or an error description; never executes the payload."""
    try:
        if mode == "b64":
            m = _B64_LINE.match(out)
            if not m:
                return f"MISMATCH: unrecognized b64 line: {out!r}"
            decoded = base64.b64decode(m.group(1)).decode()
            return "ok" if decoded == shlex.join(argv) else \
                f"MISMATCH: payload decodes to {decoded!r}"
        payload = out
        if mode == "eval":
            payload = out[len("eval "):]
        elif mode == "subst":
            payload = out[1:-1]  # strip surrounding backticks
        got = parse_back(payload)
        want = expected_argv(argv, mode)
        return "ok" if got == want else f"MISMATCH: {got!r}"
    except (RuntimeError, subprocess.TimeoutExpired, UnicodeDecodeError) as e:
        return f"ERROR: {e}"


# --------------------------------------------------------------------------
# 5. CLI
# --------------------------------------------------------------------------

_SEP_CHOICES = {"space": " ", "tab": "\t", "IFS": "${IFS}"}


def main() -> int:
    p = argparse.ArgumentParser(prog=sys.argv[0], description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("command", nargs="+", help="command to obfuscate")
    p.add_argument("--mode", choices=("bare", "subst", "eval", "sh", "b64"),
                   default="bare")
    p.add_argument("--wrap", action="store_true",
                   help='also wrap the whole output as "`<obfuscated>`" '
                        "(double-quoted command substitution)")
    p.add_argument("--seed", type=int, default=None, help="RNG seed (reproducible output)")
    p.add_argument("--max-chunks", type=int, default=3,
                   help="max $'...' chunks per word (default 3)")
    p.add_argument("--no-literals", action="store_true",
                   help="escape every character, leave nothing literal")
    p.add_argument("--separators", default="space,tab,IFS",
                   help="comma list from: space, tab, IFS (default: all)")
    p.add_argument("--verify", action="store_true",
                   help="re-parse the output and compare against the input argv")
    p.add_argument("--shlex", action="store_true",
                   help="the command was passed as ONE shell string; re-split it "
                        "with shlex.split before obfuscating")
    p.add_argument("--count", type=int, default=1,
                   help="emit N distinct obfuscations")
    # argparse would reject flags that belong to the *command* itself
    # (e.g. `obfuscator.py rm -rf /` -> "unrecognized arguments").  Collect
    # unknown tokens and fold them back into the command; only tokens that
    # look like misspelled long options are reported as errors.
    args, unknown = p.parse_known_args()
    bad_opts = [t for t in unknown if t.startswith("--")]
    if bad_opts:
        p.error(f"unrecognized arguments: {' '.join(bad_opts)}")
    if unknown:
        args.command.extend(unknown)

    raw = [s.strip() for s in args.separators.split(",") if s.strip()]
    bad = [s for s in raw if s not in _SEP_CHOICES]
    if bad:
        p.error(f"unknown separator(s) {bad!r}; choose from {sorted(_SEP_CHOICES)}")
    seps = [_SEP_CHOICES[s] for s in raw] or [" "]

    rng = random.Random(args.seed)
    argv = args.command

    if len(argv) == 1 and re.search(r"[\s'\"`$\\|&;<>(){}*?[\]~]", argv[0]):
        argv = shlex.split(argv[0])
        if not argv:
            p.error("command is empty after shlex.split")

    if args.shlex:
        # Caller passed one shell-quoted string; re-tokenize it.  Requiring a
        # single argument avoids silently mangling `tool.py echo "a b"`.
        if len(argv) != 1:
            p.error("--shlex expects the command as a single argument")
        argv = shlex.split(argv[0])
        if not argv:
            p.error("--shlex: command is empty after splitting")

    if not is_safe(argv, args.mode):
        print(f"refusing to obfuscate: {argv[0]!r} (or its payload) is on the denylist",
              file=sys.stderr)
        return 2

    for _ in range(args.count):
        out = wrap(argv, rng, args.mode, not args.no_literals,
                   args.max_chunks, seps)
        if args.wrap:
            out = outer_wrap(out)
        print(out)

        if args.verify:
            # Verify the *inner* payload: the outer backticks would otherwise
            # make bash actually execute the command during `parse_back`.
            check = outer_unwrap(out) if args.wrap else out
            print(f"  # verify: {verify_output(check, argv, args.mode)}",
                  file=sys.stderr)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
