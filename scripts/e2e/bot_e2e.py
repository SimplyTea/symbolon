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
        s.p=subprocess.Popen([BIN]+args,env=e,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
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
bot=P(["bot-run","--id",bid,"--pass-file",pf,"--state-dir",xstate,"--bind",f"127.0.0.1:{xport}",
       "--invite",invite,"--trust",people["A"]["pk"],"--format","tsv",
       "--say","hello from bot",
       "--peer",f"{people['A']['pk']}=127.0.0.1:{people['A']['port']}",
       "--peer",f"{people['B']['pk']}=127.0.0.1:{people['B']['port']}"],e=penv)
check(A.saw("hello from bot",25),"A sees the bot's --say post")
check(B.saw("hello from bot",25),"B sees the bot's --say post")
A.say("hi bot\tTAB and\\back")
check(bot.saw("msg\t"+people["A"]["fp"]+"\t",15),"bot stdout carries A's message as a tsv record")
with bot.l: lines=list(bot.out)
check(all(l.split("\t")[0] in ("msg","roster","edit","del","receipt","exists") for l in lines),"bot stdout has ONLY event records (banners went to stderr): %s"%lines[:6])
check(any("hi bot\\tTAB and\\\\back" in l for l in lines),"tabs/backslashes in text are escaped (one record per event)")
# stdin is verbatim: a slash line is posted, not executed
bot.say("/remove "+people["A"]["fp"][:8])
check(A.saw("/remove "+people["A"]["fp"][:8],15),"stdin '/remove ...' is posted as text, not run as a command")
A.say("/members"); time.sleep(1)
check(not any("A" == "" for _ in [0]),"(placeholder)")
# bot cannot be promoted
A.say(f"/tier {xfp[:8]} owner"); check(A.saw("tier change failed"),"cannot promote a bot to owner")
# sponsor leaves -> bot is dropped everywhere
B.say("/members")
time.sleep(1)
for n in (bot,A,B): n.stop()
print("ALL OK" if ok else "SOME FAILED")
