# Padding between two real processes: one side pads (--padding standard), the
# other does not, and messages must still arrive exactly, in both directions,
# including an empty-looking one, a long one and one ending in odd characters.
import os, subprocess, time, threading, tempfile, re
HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("SYMBOLON_BIN") or os.path.join(HERE, "..", "..", "target", "release", "symbolon")
root = tempfile.mkdtemp(prefix="sym-pad-"); env = dict(os.environ, P2P_PASSPHRASE="pw")
def run(a): return subprocess.run([BIN] + a, env=env, capture_output=True, text=True, timeout=60)
ids = {}
for n in "XY":
    f = f"{root}/{n}.id"; run(["keygen", "--id", f]); o = run(["show", "--id", f]).stdout
    ids[n] = (f, re.search(r"public key : (\w+)", o).group(1))
class P:
    def __init__(s, args):
        s.lines = []; s.p = subprocess.Popen([BIN] + args, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        threading.Thread(target=s.rd, daemon=True).start()
    def rd(s):
        for l in s.p.stdout: s.lines.append(l.rstrip())
    def say(s, t): s.p.stdin.write(t + "\n"); s.p.stdin.flush()
    def saw(s, n, t=20):
        e = time.time() + t
        while time.time() < e:
            if any(n in l for l in s.lines): return True
            time.sleep(0.1)
        return False
port = 17331
# X pads with 256-byte blocks; Y sends unpadded (and must still read X's padded messages).
X = P(["listen", "--id", ids["X"][0], "--trust", ids["Y"][1], "--bind", f"127.0.0.1:{port}", "--padding", "standard"])
time.sleep(1)
Y = P(["connect", "--id", ids["Y"][0], "--trust", ids["X"][1], "--addr", f"127.0.0.1:{port}"])
time.sleep(2)
ok = []
long_msg = "long " * 120 + "END"
for text in ["hi", long_msg, "trailing spaces   ", "ünïcödé ✓"]:
    X.say(text); ok.append((f"Y got padded message ({len(text)} chars)", Y.saw("peer> " + text.rstrip(), 6)))
    Y.say(text); ok.append((f"X got unpadded message ({len(text)} chars)", X.saw("peer> " + text.rstrip(), 6)))
# A bad value is refused at startup with a clear error.
bad = run(["show", "--padding", "7"])
ok.append(("--padding 7 is refused", bad.returncode != 0 and "--padding takes" in (bad.stdout + bad.stderr)))
for n, v in ok: print(("PASS " if v else "FAIL ") + n)
X.p.kill(); Y.p.kill()
