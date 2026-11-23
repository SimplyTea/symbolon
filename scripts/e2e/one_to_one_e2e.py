import os
HERE = os.path.dirname(os.path.abspath(__file__))
import subprocess, os, time, threading, tempfile, re, sys
BIN = os.environ.get("SYMBOLON_BIN") or os.path.join(HERE, "..", "..", "target", "release", "symbolon")
root=tempfile.mkdtemp(prefix="sym-11-"); env=dict(os.environ,P2P_PASSPHRASE="pw")
def run(a): return subprocess.run([BIN]+a,env=env,capture_output=True,text=True,timeout=60)
ids={}
for n in "XY":
    f=f"{root}/{n}.id"; run(["keygen","--id",f]); o=run(["show","--id",f]).stdout
    ids[n]=(f,re.search(r"public key : (\w+)",o).group(1))
class P:
    def __init__(s,args):
        s.lines=[];s.p=subprocess.Popen([BIN]+args,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
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
port=17301
X=P(["listen","--id",ids["X"][0],"--trust",ids["Y"][1],"--bind",f"127.0.0.1:{port}"])
time.sleep(1)
Y=P(["connect","--id",ids["Y"][0],"--trust",ids["X"][1],"--addr",f"127.0.0.1:{port}"])
time.sleep(2)
Y.say("one"); ok=[]
ok.append(("X got 'one'",X.saw("peer> one")))
# kill Y hard, X notices (EOF), Y restarts as a NEW process (fresh session) -> not a resume.
# Instead test the true resume: cut the TCP link without killing either process, using tcpkill-like: restart X's side? Not possible;
# so here we only verify X (listener) survives Y's death and accepts a new peer process.
Y.p.kill(); time.sleep(1.5)
ok.append(("X reports reconnecting", X.saw("reconnecting")))
Y2=P(["connect","--id",ids["Y"][0],"--trust",ids["X"][1],"--addr",f"127.0.0.1:{port}"])
time.sleep(3)
Y2.say("after restart from Y2"); ok.append(("X got post-restart message", X.saw("peer> after restart from Y2",6))); X.say("reply from X"); ok.append(("Y2 got X reply", Y2.saw("peer> reply from X",6)))
print("\n".join(X.lines[-8:]))
print("\n-- Y2 --\n"+"\n".join(Y2.lines[-6:]))
for n,v in ok: print(("PASS " if v else "FAIL ")+n)
X.p.kill();Y2.p.kill()
