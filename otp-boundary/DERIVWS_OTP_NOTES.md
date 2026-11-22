# DerivWS OTP account binding probe v7 (v6 + fixes)

## Safety and scope

- Two demo accounts from two registrations **owned by the researcher** only. No enumeration or account ID guessing.
- Only `GET /accounts`, `POST /accounts/{accountId}/otp`, WebSocket `balance` (read-only) and optional expiry control. **No purchases or orders.**
- Token A must be authorized for the configured `OWN_DEMO_ID`. The configured `FOREIGN` account must be owned by the second registration and not be among A's accounts.
- `APP_ID` must be a **new Deriv API** app ID supporting PAT, not a legacy App ID. `trade` scope is required even for account listing / OTP.
- The second PAT (`TOKEN_B_FILE`) is optional for the probe to run, **but required for automatic independent ownership verification**. If absent, ownership of B is user asserted and the finding should not be called fully verified without supporting evidence.
- `CONFIRM_BINDING=1` authorizes one read-only `balance` query over the B OTP if and only if A's token unexpectedly obtains a valid OTP for B. Default is 0.
- Files containing tokens and OTP URLs are temporary and removed on exit; `shred` is best effort and cannot guarantee secure erasure on SSD/COW filesystems. Do not upload terminal captures with secrets.

## Launch

The script prompts for token A silently if no `TOKEN_A_FILE` is supplied.

```bash
bash deriv_otp_v7.sh
```

For fully corroborated two-account evidence, save both PATs in local files with permissions `0600` and use paths (not credential strings) in the environment:

```bash
chmod 600 /private/token-a /private/token-b
TOKEN_A_FILE=/private/token-a TOKEN_B_FILE=/private/token-b CONFIRM_BINDING=1 bash deriv_otp_v7.sh | tee deriv_otp_v6_run.log
```

To use a different registered Deriv API App ID, add `APP_ID='YOUR_REGISTERED_APP_ID'` to the environment; `APP_ID_B` may be set separately if necessary. App IDs are not access tokens. Set `RUN_EXPIRY=1` only if you want the optional 125-second expiry control.

## Interpretation

- A positive A control must fetch its own demo account, issue an OTP, open WebSocket, and get read-only balance returning A's login ID. If not, no B inference is valid.
- For Token A and B-account ID: `401`, `403`, or `404` means the attempted cross-account issuance was rejected **in this test**. A `200` without a well-formed `data.url` is not issuance proof.
- A `200` with a valid `wss://api.derivws.com/trading/v1/options/ws/demo?otp=...` URL is an **issuance anomaly**, not necessarily account data access.
- `101` alone does not establish access. With `CONFIRM_BINDING=1`, a read-only balance response with B's account ID, together with independently verified B ownership, establishes a cross-account read.
- Do **not** automatically label this Critical: severity must be assessed from actually demonstrated capabilities and scope, not from untested trading privileges.

## Local checks completed

- `bash -n` PASS; all embedded Python snippets compile.
- A fake offline API returning `200` without `data.url` for A's own OTP causes the script to stop (exit 5), not claim an OTP was issued.
- OTP URL validation cases: valid WSS 1/1, missing URL rejected, external host rejected, real channel rejected, empty OTP rejected, duplicate OTP rejected (6/6).
- No valid Deriv PAT was available in this session; **no authenticated live result claimed**.
