#!/usr/bin/env bash
# =============================================================================
#  Deriv Options API — OTP account-ownership test   (v5, hardened)
#
#  Fixes carried over from review:
#    * token never touches argv  -> curl config file (-K), not -H on the command line
#    * config written with printf '%s' so the token is actually interpolated
#    * no traversal / parameter-pollution variants (out of protocol)
#    * no foreign session opened unless CONFIRM_BINDING=1 is set deliberately
#
#  Read this before running:
#    both accounts must be YOURS (two registrations), and both DEMO.
#    never put a third party's id here, never enumerate.
#
#  Usage:
#    fill the 3 values, then:  bash deriv_otp_v4.sh 2>&1 | tee run.log
# =============================================================================
set -u
umask 077

# ------------------------------- CONFIG --------------------------------------
TOKEN=''                        # access token / PAT that owns OWN_DEMO_ID
APP_ID='351cACc69MswSWTa35GxM'  # Deriv-App-ID (required for PAT)
OWN_DEMO_ID='DOT95245471'       # demo owned by TOKEN
FOREIGN='DOT95235117'           # demo owned by your OTHER registration

CONFIRM_BINDING=0   # 1 = open the foreign OTP once and send ONE read-only
                    #     {"balance":1} to learn the bound account.
                    #     0 = issuance evidence only (safer, still strong).
RUN_EXPIRY=0        # 1 = also run the 125-second expiry control
# -----------------------------------------------------------------------------

BASE='https://api.derivws.com/trading/v1/options'
RES_HDR='X-HackerOne-Research: marcil78'
UA='marcil78-h1-research'

WORK="$(mktemp -d)"
cleanup(){ for f in "$WORK"/*; do [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }; done; rmdir "$WORK" 2>/dev/null; }
trap cleanup EXIT INT TERM

fail(){ printf 'STOP: %s\n' "$1" >&2; exit "${2:-1}"; }
ts(){ date -u +%H:%M:%SZ; }

[ -z "$TOKEN" ]                 && fail "TOKEN is empty"
[ "$OWN_DEMO_ID" = "$FOREIGN" ] && fail "OWN_DEMO_ID and FOREIGN are identical"
command -v curl    >/dev/null   || fail "curl required"
command -v python3 >/dev/null   || fail "python3 required"

# --- token into a mode-600 config file: never in argv, never in ps -----------
AUTH_CFG="$WORK/auth.cfg"
printf 'header = "Authorization: %s %s"\n' "Bear""er" "$TOKEN" > "$AUTH_CFG"
chmod 600 "$AUTH_CFG"
# v5: pattern is fed through a file descriptor (never argv) and matched literally (-F)
grep -qF -f <(printf '%s\n' "$TOKEN") "$AUTH_CFG" || fail "token failed to reach the curl config (aborting before any request)"
case "$TOKEN" in *'***'*|*' '*) fail "TOKEN contains '***' or a space — a masked copy was pasted, not the real token";; esac

api(){  # api METHOD URL OUTFILE [use_appid]
  local m="$1" u="$2" o="$3" a="${4:-1}" extra=()
  [ "$a" = "1" ] && extra=(-H "Deriv-App-ID: $APP_ID")
  curl -s -m 20 -o "$o" -w '%{http_code}' -X "$m" -K "$AUTH_CFG" \
       ${extra[@]+"${extra[@]}"} -H "$RES_HDR" -A "$UA" -H 'Accept: application/json' "$u"
}

peek(){ python3 - "$1" <<'PY'
import sys,re
try: s=open(sys.argv[1],errors='replace').read(400)
except Exception: s=''
s=re.sub(r'(otp=)[^&"\s]+',r'\1<redacted>',s)
s=re.sub(r'("(?:otp|token|access_token)"\s*:\s*")[^"]+',r'\1<redacted>',s)
print('   body:',s.replace('\n',' ')[:300])
PY
}

url_shape(){ python3 - "$1" "$2" <<'PY'
import json,sys,urllib.parse
try: d=json.load(open(sys.argv[1]))
except Exception: print("   shape: body is not JSON"); sys.exit(0)
def keys(o,pre=''):
    out=[]
    if isinstance(o,dict):
        for k,v in o.items(): out.append(pre+k); out+=keys(v,pre+k+'.')
    return out
print("   shape: keys =",keys(d))
u=(d.get('data') or {}).get('url') if isinstance(d,dict) else None
if not isinstance(u,str): print("   shape: data.url ABSENT"); sys.exit(0)
p=urllib.parse.urlsplit(u); q=urllib.parse.parse_qs(p.query)
print("   shape: scheme=%s host=%s path=%s"%(p.scheme,p.hostname,p.path))
print("   shape: query params =",sorted(q.keys()))
otp=(q.get('otp') or [''])[0]
print("   shape: otp present=%s length=%d"%(bool(otp),len(otp)))
open(sys.argv[2],'w').write(u)
PY
}

WSPY="$WORK/ws.py"
cat > "$WSPY" <<'PY'
import sys,ssl,socket,os,base64,json,struct,urllib.parse
url=open(sys.argv[1]).read().strip()
send=len(sys.argv)>2 and sys.argv[2]=='1'
p=urllib.parse.urlsplit(url)
res={"handshake":None}
try:
    raw=socket.create_connection((p.hostname,p.port or 443),timeout=15)
    s=ssl.create_default_context().wrap_socket(raw,server_hostname=p.hostname)
    key=base64.b64encode(os.urandom(16)).decode()
    req=(f"GET {p.path}?{p.query} HTTP/1.1\r\nHost: {p.hostname}\r\n"
         "Upgrade: websocket\r\nConnection: Upgrade\r\n"
         f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
         "User-Agent: marcil78-h1-research\r\nX-HackerOne-Research: marcil78\r\n\r\n")
    s.sendall(req.encode())
    hdr=b''
    while b'\r\n\r\n' not in hdr:
        c=s.recv(4096)
        if not c: break
        hdr+=c
    line=hdr.split(b'\r\n',1)[0].decode(errors='replace')
    res["handshake"]=int(line.split()[1]) if len(line.split())>1 else None
    if res["handshake"]!=101:
        res["status_line"]=line
    elif send:
        payload=json.dumps({"balance":1,"req_id":1}).encode()
        mask=os.urandom(4); n=len(payload)
        head=bytes([0x81])+(bytes([0x80|n]) if n<126 else bytes([0x80|126])+struct.pack('>H',n))
        s.sendall(head+mask+bytes(b^mask[i%4] for i,b in enumerate(payload)))
        buf=hdr.split(b'\r\n\r\n',1)[1]
        def need(k):
            global buf   # v5: was 'nonlocal' -> SyntaxError at module level
            while len(buf)<k:
                c=s.recv(65536)
                if not c: raise EOFError
                buf+=c
            out,buf=buf[:k],buf[k:]; return out
        for _ in range(10):
            b1,b2=need(2); op=b1&0x0f; ln=b2&0x7f
            if ln==126: ln=struct.unpack('>H',need(2))[0]
            elif ln==127: ln=struct.unpack('>Q',need(8))[0]
            data=need(ln)
            if op==1:
                j=json.loads(data)
                res["reply_keys"]=sorted(j.keys()) if isinstance(j,dict) else type(j).__name__
                def walk(o):
                    if isinstance(o,dict):
                        for k,v in o.items():
                            if k in("loginid","account_id","accountId") and isinstance(v,str): return v
                            r=walk(v)
                            if r: return r
                    if isinstance(o,list):
                        for v in o:
                            r=walk(v)
                            if r: return r
                ident=walk(j)
                if ident: res["bound_account"]=ident
                if isinstance(j,dict) and "error" in j:
                    e=j["error"]; res["error"]=e.get("code") if isinstance(e,dict) else str(e)[:80]
                break
            if op==8: res["closed"]=True; break
    try: s.close()
    except Exception: pass
except Exception as e:
    res["exception"]=type(e).__name__+": "+str(e)[:120]
print(json.dumps(res))
PY

echo "#############################################################"
echo "# OTP boundary test   start $(ts)"
echo "# OWN=$OWN_DEMO_ID  FOREIGN=$FOREIGN"
echo "# CONFIRM_BINDING=$CONFIRM_BINDING  RUN_EXPIRY=$RUN_EXPIRY"
echo "#############################################################"

echo; echo "=== STEP 0 — token validity and ownership ($(ts)) ==="
S0=$(api GET "$BASE/accounts" "$WORK/acc.json" 1)
echo "GET /accounts -> $S0"
USE_APPID=1
if [ "$S0" != "200" ]; then
  peek "$WORK/acc.json"
  S0b=$(api GET "$BASE/accounts" "$WORK/acc2.json" 0)
  echo "GET /accounts (no Deriv-App-ID) -> $S0b"; peek "$WORK/acc2.json"
  if [ "$S0b" = "200" ]; then echo "NOTE: continuing WITHOUT Deriv-App-ID"; USE_APPID=0; cp "$WORK/acc2.json" "$WORK/acc.json"
  else fail "auth failure ($S0/$S0b) — token invalid, expired, or missing the trade scope. This is NOT an ownership result." 2; fi
fi

python3 - "$OWN_DEMO_ID" "$FOREIGN" "$WORK/acc.json" <<'PY'
import json,sys
own,foreign,f=sys.argv[1:4]
d=json.load(open(f)); rows=d.get('data',[]) if isinstance(d,dict) else []
acc={a.get('account_id'):a for a in rows if isinstance(a,dict)}
print("--- accounts this token owns ---")
for k,a in acc.items(): print("  %-16s %-6s %s"%(k,a.get('account_type'),a.get('currency','')))
bad=[]
if own not in acc: bad.append("OWN not owned by this token")
elif acc[own].get('account_type')!='demo': bad.append("OWN is not demo")
if foreign in acc: bad.append("FOREIGN is owned by this token -> test void")
if bad:
    for b in bad: print("STOP:",b)
    sys.exit(10)
print("OK: OWN owned+demo; FOREIGN absent")
PY
[ $? -ne 0 ] && exit 10

echo; echo "=== STEP 1 — CONTROL: OTP for OWN ($(ts)) ==="
C1=$(api POST "$BASE/accounts/$OWN_DEMO_ID/otp" "$WORK/ctrl.json" "$USE_APPID")
echo "POST /accounts/OWN/otp -> $C1"
case "$C1" in
  200) url_shape "$WORK/ctrl.json" "$WORK/own.url" ;;
  *)   peek "$WORK/ctrl.json"; fail "control failed ($C1) — the whole run is void." 3 ;;
esac

# v5: WebSocket controls on the OWN account only (needed so a later rejection means something)
if [ -s "$WORK/own.url" ]; then
  echo "-- P-WS: own OTP opens a session (handshake only, no message) --"
  echo "   ws(own):   $(python3 "$WSPY" "$WORK/own.url" 0)"
  echo "-- N-reuse: same own OTP a second time (expect != 101) --"
  echo "   ws(reuse): $(python3 "$WSPY" "$WORK/own.url" 0)"
fi

if [ "$RUN_EXPIRY" = "1" ]; then
  echo; echo "-- N: expiry control (fresh own otp, wait 125s) --"
  CE=$(api POST "$BASE/accounts/$OWN_DEMO_ID/otp" "$WORK/e.json" "$USE_APPID")
  if [ "$CE" = "200" ]; then
    url_shape "$WORK/e.json" "$WORK/e.url" >/dev/null
    echo "   waiting 125s ($(ts))"; sleep 125
    echo "   ws(expired): $(python3 "$WSPY" "$WORK/e.url" 0)"
  else echo "   skipped ($CE)"; fi
fi

echo; echo "=== STEP 2 — FOREIGN: OTP for an account the token does not own ($(ts)) ==="
sleep 2
F1=$(api POST "$BASE/accounts/$FOREIGN/otp" "$WORK/f.json" "$USE_APPID")
echo "POST /accounts/FOREIGN/otp -> $F1"

case "$F1" in
  200)
    echo "*** 200 — an OTP was issued for an account this token does not own ***"
    url_shape "$WORK/f.json" "$WORK/foreign.url"
    if [ "$CONFIRM_BINDING" = "1" ] && [ -s "$WORK/foreign.url" ]; then
      echo "-- opening the foreign OTP once, ONE read-only balance --"
      RB=$(python3 "$WSPY" "$WORK/foreign.url" 1); echo "   ws(foreign): $RB"
      python3 - "$RB" "$FOREIGN" "$OWN_DEMO_ID" <<'PY'
import json,sys
r=json.loads(sys.argv[1]); f,o=sys.argv[2],sys.argv[3]
b=r.get('bound_account')
if r.get('handshake')!=101:
    print("VERDICT: issued but REJECTED at WS (%s) -> issuance-only"%r.get('handshake'))
elif b and b.upper()==f.upper():
    print("VERDICT: *** session bound to FOREIGN account (%s) ***"%b)
elif b and b.upper()==o.upper():
    print("VERDICT: session bound to OWN — server ignored the path id; NOT a boundary crossing.")
else:
    print("VERDICT: session opened, bound account unknown (%s)"%b)
PY
    else
      echo "   CONFIRM_BINDING=0 — no foreign session opened. Evidence = issuance + shape."
      echo "   VERDICT: ownership check ABSENT at issuance. Binding to the foreign account NOT yet proven."
    fi
    ;;
  403|404) echo "$F1 — ownership enforced. No finding."; peek "$WORK/f.json" ;;
  401)     echo "401 — token/header problem; STEP 1 passed, so note this as an anomaly"; peek "$WORK/f.json" ;;
  307)     echo "307 — path variable empty or mangled; rerun" ;;
  *)       echo "unexpected $F1"; peek "$WORK/f.json" ;;
esac

echo; echo "# end $(ts) — temp files wiped. This log holds no token and no otp value."
