import os
HERE = os.path.dirname(os.path.abspath(__file__))
import subprocess, os, sys, time, threading, tempfile, re
BIN = os.environ.get("SYMBOLON_BIN") or os.path.join(HERE, "..", "..", "target", "release", "symbolon")
root=tempfile.mkdtemp(prefix="sym-late-"); env=dict(os.environ,P2P_PASSPHRASE="pw")
def run(a): return subprocess.run([BIN]+a,env=env,capture_output=True,text=True,timeout=60)
nodes={}
for n in "ABC":
    f=f"{root}/{n}.id"; run(["keygen","--id",f]); o=run(["show","--id",f]).stdout
    nodes[n]=dict(id=f,pk=re.search(r"public key : (\w+)",o).group(1),state=f"{root}/{n}-st",port=17600+ord(n)-65)
r=run(["group-new","--id",nodes["A"]["id"],"--state-dir",nodes["A"]["state"],"--members",nodes["B"]["pk"]])
invite=re.search(r"invite     : (\w+)",r.stdout).group(1); gid=re.search(r"group id   : (\w+)",r.stdout).group(1)
class Node:
    def __init__(s,n,peers,first=True):
        d=nodes[n]; s.name=n; s.lines=[]
        a=["group-run","--id",d["id"],"--state-dir",d["state"],"--bind",f"127.0.0.1:{d['port']}"]
        a+=(["--invite",invite,"--trust",nodes["A"]["pk"]] if first else ["--group",gid])
        for m in peers: a+=["--peer",f"{nodes[m]['pk']}=127.0.0.1:{nodes[m]['port']}"]
        s.p=subprocess.Popen([BIN]+a,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        threading.Thread(target=s.rd,daemon=True).start()
    def rd(s):
        for l in s.p.stdout: s.lines.append(l.rstrip())
    def say(s,t): s.p.stdin.write(t+"\n"); s.p.stdin.flush()
    def saw(s,n,t=20):
        e=time.time()+t
        while time.time()<e:
            if any(n in l for l in s.lines): return True
            time.sleep(0.1)
        return False
res=[]
A=Node("A",["B"]); B=Node("B",["A"]); time.sleep(4)
A.say("early message"); res.append(("B got early message",B.saw("early message")))
# A adds C after the fact, and tells A and B where C is
A.say(f"/add {nodes['C']['pk']}"); res.append(("B learns C was added (roster changed: 3 members)",B.saw("roster changed: 3 members")))
A.say(f"/peer {nodes['C']['pk']}=127.0.0.1:{nodes['C']['port']}"); B.say(f"/peer {nodes['C']['pk']}=127.0.0.1:{nodes['C']['port']}")
C=Node("C",["A","B"]); time.sleep(8)
C.say("/members"); time.sleep(1)
res.append(("C synced roster: sees 3 members incl. itself",sum(1 for l in C.lines if "tier=" in l)>=3))
C.say("hello, I joined late"); res.append(("A got C's message",A.saw("hello, I joined late"))); res.append(("B got C's message",B.saw("hello, I joined late")))
A.say("welcome C"); res.append(("C got A's message",C.saw("welcome C")))
for n,v in res: print(("PASS " if v else "FAIL ")+n)
if not all(v for _,v in res): print("--C--\n"+"\n".join(C.lines[-25:]))
for x in (A,B,C): x.p.kill()
