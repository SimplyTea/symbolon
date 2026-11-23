import os
HERE = os.path.dirname(os.path.abspath(__file__))
import socket, threading, subprocess, os, time, tempfile, re
BIN = os.environ.get("SYMBOLON_BIN") or os.path.join(HERE, "..", "..", "target", "release", "symbolon")
root=tempfile.mkdtemp(prefix="sym-resume-"); env=dict(os.environ,P2P_PASSPHRASE="pw")
def run(a): return subprocess.run([BIN]+a,env=env,capture_output=True,text=True,timeout=60)
ids={}
for n in "XY":
    f=f"{root}/{n}.id"; run(["keygen","--id",f]); o=run(["show","--id",f]).stdout
    ids[n]=(f,re.search(r"public key : (\w+)",o).group(1))
XPORT,PPORT=17401,17402
class Proxy:
    def __init__(s):
        s.up=True; s.conns=[]; s.ls=socket.socket(); s.ls.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.ls.bind(("127.0.0.1",PPORT)); s.ls.listen(); threading.Thread(target=s.acc,daemon=True).start()
    def acc(s):
        while True:
            c,_=s.ls.accept()
            if not s.up: c.close(); continue
            try: u=socket.create_connection(("127.0.0.1",XPORT))
            except Exception: c.close(); continue
            s.conns+= [c,u]
            for a,b in ((c,u),(u,c)): threading.Thread(target=s.pipe,args=(a,b),daemon=True).start()
    def pipe(s,a,b):
        try:
            while True:
                d=a.recv(4096)
                if not d: break
                b.sendall(d)
        except Exception: pass
        for x in (a,b):
            try: x.close()
            except: pass
    def cut(s):
        s.up=False
        for c in s.conns:
            try: c.shutdown(socket.SHUT_RDWR)
            except: pass
        s.conns=[]
    def restore(s): s.up=True
class P:
    def __init__(s,args):
        s.lines=[];s.p=subprocess.Popen([BIN]+args,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
        threading.Thread(target=s.rd,daemon=True).start()
    def rd(s):
        for l in s.p.stdout: s.lines.append(l.rstrip())
    def say(s,t): s.p.stdin.write(t+"\n"); s.p.stdin.flush()
    def saw(s,n,t=25):
        e=time.time()+t
        while time.time()<e:
            if any(n in l for l in s.lines): return True
            time.sleep(0.1)
        return False
px=Proxy()
X=P(["listen","--id",ids["X"][0],"--trust",ids["Y"][1],"--bind",f"127.0.0.1:{XPORT}"]); time.sleep(1)
Y=P(["connect","--id",ids["Y"][0],"--trust",ids["X"][1],"--addr",f"127.0.0.1:{PPORT}"]); time.sleep(2)
res=[]
print("--Y--");print("\n".join(Y.lines[-12:]));print("--X--");print("\n".join(X.lines[-12:]))
Y.say("before cut"); res.append(("X got 'before cut'",X.saw("peer> before cut")))
px.cut(); time.sleep(0.5)
Y.say("sent during outage"); X.say("X talks during outage")
time.sleep(2); px.restore()
res.append(("Y reconnected & resumed same session",Y.saw("same session resumed",30)))
res.append(("X got message sent during outage",X.saw("peer> sent during outage",15)))
res.append(("Y got X's message from during outage",Y.saw("peer> X talks during outage",15)))
print("--Y--");print("\n".join(Y.lines[-12:]));print("--X--");print("\n".join(X.lines[-12:]))
try: Y.say("after resume")
except Exception as e: print("Y stdin dead",e)
res.append(("X got 'after resume'",X.saw("peer> after resume")))
for n,v in res: print(("PASS " if v else "FAIL ")+n)
X.p.kill();Y.p.kill()
