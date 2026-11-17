#!/usr/bin/env python3
"""A tiny scripted Symbolon bot: answers "!ping" with "pong" and "!echo TEXT" with TEXT.

It does NOT link any Symbolon code: it just runs `symbolon bot-run` and talks to
it over pipes, so any language works the same way:

  * the bot's STDOUT is one tab-separated record per group event:
        kind <TAB> who <TAB> seq <TAB> text
    kind is msg | edit | del | roster | receipt | exists. Tabs, newlines and
    backslashes inside `text` are escaped (\\t \\n \\\\), so one event is always
    exactly one line and a message can never forge a second record.
  * every line you write to its STDIN is posted to the group VERBATIM (it is
    never treated as a command unless you pass --commands).

Usage:
  echo_bot.py [--symbolon PATH] -- bot-run --id BOT.enc --pass-file PASS \
      --state-dir DIR --invite HEX --trust CREATORKEY --bind 0.0.0.0:7001 \
      --peer KEY=HOST:PORT ... --format tsv

SECURITY: message text is UNTRUSTED input from other group members. This bot
only compares and echoes it; never pass it to a shell, eval, or a file path.
"""
import argparse
import subprocess
import sys

MAX_REPLY = 500  # never echo an unbounded amount of someone else's text


def unescape(text: str) -> str:
    """Undo the tsv escaping (\\t \\n \\r \\\\)."""
    out, i = [], 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            out.append({"t": "\t", "n": "\n", "r": "\r", "\\": "\\"}.get(text[i + 1], text[i + 1]))
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def reply_for(text: str):
    """The whole 'brain': return a reply string or None."""
    if text.strip() == "!ping":
        return "pong"
    if text.startswith("!echo "):
        return text[len("!echo "):][:MAX_REPLY]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--symbolon", default="symbolon", help="path to the symbolon binary")
    ap.add_argument("botargs", nargs=argparse.REMAINDER, help="-- bot-run ARGS...")
    ns = ap.parse_args()
    args = [a for a in ns.botargs if a != "--"] if ns.botargs[:1] == ["--"] else ns.botargs
    if not args or args[0] != "bot-run":
        ap.error("after -- give the bot-run command line")
    if "--format" not in args:
        args += ["--format", "tsv"]

    proc = subprocess.Popen([ns.symbolon] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            text=True, bufsize=1)
    for line in proc.stdout:
        parts = line.rstrip("\n").split("\t", 3)
        if len(parts) != 4 or parts[0] != "msg":
            continue
        _kind, who, seq, text = parts
        answer = reply_for(unescape(text))
        if answer is not None:
            proc.stdin.write(answer.replace("\n", " ") + "\n")  # one post per line
            proc.stdin.flush()
    return proc.wait()


if __name__ == "__main__":
    sys.exit(main())
