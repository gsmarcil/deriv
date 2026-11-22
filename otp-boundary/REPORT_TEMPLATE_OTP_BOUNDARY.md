<!--
Fill ONLY from run.log of deriv_otp_v7.sh. Delete this comment before submitting.
Submit only if the VERDICT line says CRITICAL (session bound to FOREIGN).
- Issuance-only 200 (WS rejected or CONFIRM_BINDING=0)  -> rewrite as Low/Informative or do not submit.
- 200 but session bound to OWN account                  -> NOT a vulnerability, do not submit.
- 403/404 everywhere                                     -> no finding.
Never paste an OTP value, a token, or any third-party account id.
-->

# Broken Object Level Authorization in Options API `/accounts/{accountId}/otp` allows opening a trading WebSocket session on another user's account

**Asset:** `api.derivws.com` (Options REST + WebSocket API)
**Weakness:** CWE-639 Authorization Bypass Through User-Controlled Key (OWASP API1:2023 BOLA)
**Severity (proposed, pending triage):** Critical — see CVSS section
**Researcher header used on every request:** `X-HackerOne-Research: marcil78`

## Summary

`POST /trading/v1/options/accounts/{accountId}/otp` returns a one-time WebSocket URL (`data.url`, `?otp=`) for the `accountId` in the path without checking that this account belongs to the bearer token. Using the returned URL opens a WebSocket session bound to the **foreign** account (`<bound_account from log>`), not to the token's own account.

An attacker who knows or obtains a victim's account id (shown in UI, statements, support chats, referral/affiliate flows, screenshots) can therefore act on the victim's Options account with the attacker's own token.

## Test setup (both accounts owned by the researcher)

| Role | Account | Owner | Type |
|---|---|---|---|
| Attacker token (PAT) | `<OWN_DEMO_ID>` | Registration A (researcher) | demo |
| Victim | `<FOREIGN>` | Registration B (researcher) | demo |

`GET /trading/v1/options/accounts` with token A returns `<list from STEP 0>`; `<FOREIGN>` is **not** in that list (verified by the script before any test request).

No third-party account was touched. No trade, transfer, or write was performed. The only WebSocket message sent on the foreign session was a single read-only `{"balance":1}`.

## Steps to reproduce

1. Create two separate Deriv registrations (A, B), each with a demo Options account. Note B's account id.
2. With A's PAT:
   ```
   GET https://api.derivws.com/trading/v1/options/accounts
   Authorization: Bearer <PAT_A>
   Deriv-App-ID: <app_id>
   ```
   Confirm B's account id is absent.
3. Positive control (own account):
   ```
   POST https://api.derivws.com/trading/v1/options/accounts/<A_account>/otp
   ```
   → `<C1>`; `data.url` = `wss://<host><path>?otp=<redacted>`.
4. Attack (foreign account, same token):
   ```
   POST https://api.derivws.com/trading/v1/options/accounts/<B_account>/otp
   ```
   → **`<F1>`**, same response shape as step 3.
5. Open the returned `data.url` and send `{"balance":1}`.
   → handshake `<101>`, response account identifier = **`<B_account>`**.

## Evidence

**Run log (token and OTP values are never printed by the script):**
```
<paste run.log here>
```

**Shape comparison**

| Field | Own (control) | Foreign (attack) |
|---|---|---|
| HTTP status | `<C1>` | `<F1>` |
| Response keys | `<…>` | `<…>` |
| WS host / path | `<…>` | `<…>` |
| `otp` length / charset | `<…>` | `<…>` |
| WS handshake | `<101>` | `<101>` |
| Bound account in WS reply | `<OWN>` | `<FOREIGN>` |

## Controls (show the server validates OTPs, so the result is not an artefact)

| Control | Expected | Observed |
|---|---|---|
| P1 own account OTP opens session | 101, bound to own | `<…>` |
| N1 same OTP reused | rejected | `<…>` |
| N2 bogus OTP | rejected | `<…>` |
| N3 demo OTP on `/ws/real` path | rejected | `<…>` |
| N4 OTP used after 125 s | rejected | `<…>` |
| Foreign id variants (case, encoding, traversal) | `<only if relevant>` | `<…>` |

## Impact

- **Account takeover of the Options trading session**: the attacker's token yields a fully authenticated WebSocket session on the victim's account. Through that session the WebSocket API exposes `<list the capabilities documented for the Options WS: balance, portfolio, profit table, buy/sell contracts…>`.
- **Financial impact on real accounts**: an attacker can open/close contracts on the victim's real-money account, draining balance through deliberately losing trades, or read the victim's trading history and balance.
- **Only prerequisite is the victim's account id**, which is not a secret (visible in the UI, statements, screenshots shared in support/social channels).

Researcher limits: impact was demonstrated on a **demo** account owned by the researcher, with a single read-only call. Real-account behaviour was **not** tested to avoid touching funds; it is inferred because the same endpoint serves both account types (`<confirm the path/segment from log>`). Happy to test a real account of my own if the team authorises it.

## CVSS (proposed, final value to be confirmed after triage)

- CVSS 3.1: `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = **8.1** (High)
  - If real-money trading on the victim's account is confirmed via the foreign session, argue `S:C` (`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` = **9.6**) only if the triager agrees the impact crosses the authorization scope of the attacker's account.
- CVSS 4.0: `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- Adjust down to `C:L/I:N` if the foreign session is read-only, or to Low/Informative if the OTP is issued but rejected at the WebSocket.

## Remediation

1. In the OTP handler, resolve `accountId` against the account list of the authenticated principal; return `404` (not `403`, to avoid id enumeration) when it is not owned.
2. Bind the OTP server-side to `(principal_id, account_id)` and re-check the pair on WebSocket handshake.
3. Apply the same ownership check to every `/accounts/{accountId}/…` route; add a regression test with two principals.
4. Audit logs for OTPs issued where `accountId` ∉ principal's accounts to detect past abuse.
