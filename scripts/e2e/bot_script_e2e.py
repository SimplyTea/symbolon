import os
HERE = os.path.dirname(os.path.abspath(__file__))
import subprocess, os, time, threading, tempfile, re, stat
BIN = os.environ.get("SYMBOLON_BIN") or os.path.join(HERE, "..", "..", "target", "release", "symbolon")
root = tempfile.mkdtemp(prefix="sym-bot-")
env = dict(os.environ, P2P_PASSPHRASE="pw")
def run(args, e=env):
    return subprocess.run([BIN]+args, env=e, capture_output=True, text=True, timeout=60)
ok=True
def check(c,m):
    global ok; print(("PASS " if c else "FAIL ")+m); ok=ok and c

people={}
for n in "AB":
    f=f"{root}/{n}.id"; run(["keygen","--id",f])
    o=run(["show","--id",f]).stdout
    people[n]=dict(id=f,fp=re.search(r"fingerprint: (\w+)",o).group(1),pk=re.search(r"public key : (\w+)",o).group(1),state=f"{root}/{n}-st",port=17300+ord(n)-65)
# bot identity via bot-new with a pass file (no env passphrase)
pf=f"{root}/pass"; open(pf,"w").write("botpw\n"); os.chmod(pf,0o644)
bid=f"{root}/X.id"
r=run(["bot-new","--id",bid,"--pass-file",pf],e=dict(os.environ)); 
check("readable by others" in r.stderr, "pass-file with loose mode is refused")
os.chmod(pf,0o600)
r=run(["bot-new","--id",bid,"--pass-file",pf],e=dict(os.environ))
check("/addbot" in r.stdout, "bot-new prints the /addbot line")
r2=run(["bot-new"],e=dict(os.environ)); check("needs --id" in r2.stderr,"bot-new requires --id")
xpk=re.search(r"public key : (\w+)",r.stdout).group(1)
xfp=re.search(r"fingerprint: (\w+)",r.stdout).group(1)
xport=17399; xstate=f"{root}/X-st"

r=run(["group-new","--id",people["A"]["id"],"--state-dir",people["A"]["state"],"--members",people["B"]["pk"]])
invite=re.search(r"invite     : (\w+)",r.stdout).group(1)

class P:
    def __init__(s,args,e=env):
        s.out=[];s.err=[];s.l=threading.Lock()
        cmd=[BIN]+args
        if args and args[0]=="__SCRIPT__": cmd=["python3",os.path.join(HERE, "..", "echo_bot.py"),"--symbolon",BIN,"--"]+args[1:]
        s.p=subprocess.Popen(cmd,env=e,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        threading.Thread(target=s._r,args=(s.p.stdout,s.out),daemon=True).start()
        threading.Thread(target=s._r,args=(s.p.stderr,s.err),daemon=True).start()
    def _r(s,f,buf):
        for l in f:
            with s.l: buf.append(l.rstrip("\n"))
    def say(s,t): s.p.stdin.write(t+"\n"); s.p.stdin.flush()
    def saw(s,needle,timeout=15,err=False):
        end=time.time()+timeout
        while time.time()<end:
            with s.l:
                if any(needle in l for l in (s.err if err else s.out)): return True
            time.sleep(0.1)
        return False
    def stop(s):
        try:s.p.stdin.close()
        except:pass
        try:s.p.wait(timeout=5)
        except:s.p.kill()

def person(n,first=True):
    d=people[n]
    a=["group-run","--id",d["id"],"--state-dir",d["state"],"--bind",f"127.0.0.1:{d['port']}"]
    a+=(["--invite",invite,"--trust",people["A"]["pk"]] if first else [])
    o=people["B" if n=="A" else "A"]
    a+=["--peer",f"{o['pk']}=127.0.0.1:{o['port']}"]
    return P(a)
A=person("A"); B=person("B")
time.sleep(3)

# governance rules over the CLI
B.say(f"/addbot {xpk}"); check(B.saw("addbot failed"),"plain member cannot /addbot")
A.say(f"/addbot {xpk} owner"); check(A.saw("addbot failed"),"bot cannot be added to a managing tier")
A.say(f"/addbot {xpk}"); check(A.saw("added bot"),"owner adds the bot")
time.sleep(1)
A.say("/members"); check(A.saw("[bot, sponsor"),"/members marks the bot with its sponsor")
A.say("/bots"); check(A.saw("sponsor="),"/bots lists it")
B.say("/bots"); check(B.saw("tier=bot"),"B learned about the bot through roster sync")
for n in (A,B): n.say(f"/peer {xpk}=127.0.0.1:{xport}")

penv=dict(os.environ)
bot=P(["__SCRIPT__","bot-run","--id",bid,"--pass-file",pf,"--state-dir",xstate,"--bind",f"127.0.0.1:{xport}",
       "--invite",invite,"--trust",people["A"]["pk"],"--format","tsv",
       "--peer",f"{people['A']['pk']}=127.0.0.1:{people['A']['port']}",
       "--peer",f"{people['B']['pk']}=127.0.0.1:{people['B']['port']}"],e=penv)
time.sleep(6)
A.say("!ping"); check(A.saw("pong",20),"A sees the scripted bot answer !ping with pong")
check(B.saw("pong",20),"B sees it too")
A.say("!echo hello\\there <&;|$(x)>"); check(A.saw("hello",20) and A.saw("$(x)",10),"!echo repeats text verbatim (no shell/eval of it)")
A.say("just chatting"); time.sleep(2)
with A.l: n=sum(1 for l in A.out if "pong" in l)
check(n==1,"bot stays quiet for ordinary messages and answers once (pongs seen: %d)"%n)
for n_ in (bot,A,B): n_.stop()
print("SCRIPT ALL OK" if ok else "SCRIPT SOME FAILED")
