import os
HERE = os.path.dirname(os.path.abspath(__file__))
import subprocess, os, sys, time, threading, tempfile, re
BIN = os.environ.get("SYMBOLON_BIN") or os.path.join(HERE, "..", "..", "target", "release", "symbolon")
root = tempfile.mkdtemp(prefix="sym-e2e-")
env = dict(os.environ, P2P_PASSPHRASE="pw")
def run(args, **kw):
    return subprocess.run([BIN]+args, env=env, capture_output=True, text=True, timeout=60, **kw)

nodes = {}
for n in "ABC":
    idf = f"{root}/{n}.id"
    run(["keygen","--id",idf])
    out = run(["show","--id",idf]).stdout
    fp = re.search(r"fingerprint: (\w+)", out).group(1)
    pk = re.search(r"public key : (\w+)", out).group(1)
    nodes[n] = dict(id=idf, fp=fp, pk=pk, state=f"{root}/{n}-state", port=17100+ord(n)-65)
print({n:(v['fp'][:6]) for n,v in nodes.items()})

r = run(["group-new","--id",nodes["A"]["id"],"--state-dir",nodes["A"]["state"],"--members",nodes["B"]["pk"]+","+nodes["C"]["pk"]])
print(r.stdout, r.stderr)
invite = re.search(r"invite     : (\w+)", r.stdout).group(1)
gid = re.search(r"group id   : (\w+)", r.stdout).group(1)

class Node:
    def __init__(self, n, first=True):
        d = nodes[n]; self.name=n; self.lines=[]; self.lock=threading.Lock()
        args = ["group-run","--id",d["id"],"--state-dir",d["state"],"--bind",f"127.0.0.1:{d['port']}"]
        args += (["--invite",invite,"--trust",nodes["A"]["pk"]] if first else ["--group",gid])
        for m,o in nodes.items():
            if m!=n: args += ["--peer", f"{o['pk']}=127.0.0.1:{o['port']}"]
        self.p = subprocess.Popen([BIN]+args, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        threading.Thread(target=self._rd, daemon=True).start()
    def _rd(self):
        for l in self.p.stdout:
            with self.lock: self.lines.append(l.rstrip())
    def say(self, t): self.p.stdin.write(t+"\n"); self.p.stdin.flush()
    def saw(self, needle, timeout=15):
        end=time.time()+timeout
        while time.time()<end:
            with self.lock:
                if any(needle in l for l in self.lines): return True
            time.sleep(0.1)
        return False
    def dump(self):
        with self.lock: return "\n".join(self.lines)
    def stop(self):
        try: self.p.stdin.close()
        except: pass
        try: self.p.wait(timeout=5)
        except: self.p.kill()

A,B,C = Node("A"),Node("B"),Node("C")
ok=True
def check(c, msg):
    global ok
    print(("PASS " if c else "FAIL ")+msg); ok = ok and c

# wait for mesh: each should show 2 connected
time.sleep(1); 
for n in (A,B,C): n.say("/members")
time.sleep(6)
for n in (A,B,C): n.say("/state")
time.sleep(1)
A.say("hello from A"); B.say("hello from B"); C.say("hello from C")
for n,others in ((A,("hello from B","hello from C")),(B,("hello from A","hello from C")),(C,("hello from A","hello from B"))):
    for o in others:
        check(n.saw(o), f"{n.name} received '{o}'")

# C goes away; A posts; C returns and catches up
C.stop(); time.sleep(1)
A.say("posted while C was away")
time.sleep(1)
C = Node("C", first=False)
check(C.saw("posted while C was away", 25), "restarted C caught up on a message posted while it was down")
# C's own earlier message survived the restart (persisted)
C.say("/history"); time.sleep(1)
check(any(l.strip().endswith("#1] hello from C") for l in C.dump().splitlines()), "C's own saved history survived restart (shown by /history)")
B.say("/history"); time.sleep(1)

# edit and delete propagate
A.say("typo mesage"); time.sleep(0.5)
A.say("/history"); time.sleep(0.5)
seqs = re.findall(r"#(\d+)[^\]]*\] typo mesage", A.dump())
if seqs:
    A.say(f"/edit {seqs[-1]} typo message fixed")
    check(B.saw("typo message fixed"), "edit propagated to B")
for n in (A,B,C): n.stop()
print("\n--- A output ---\n"+A.dump()[-1500:])
print("\nALL OK" if ok else "\nSOME FAILED")
sys.exit(0 if ok else 1)
