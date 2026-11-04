# Zi.Care Security Self-Assessment — Run Guide (SEC-FORM-001 v1.1)

Authorized self-assessment of your own Zi.Care HIS for the BPJS bridging form.

- **App tests (1.x):** run against **STAGING** `https://dev-rsmpm3308.zicare.id:4334`.
- **Server tests (2.x):** run on **PRODUCTION** `https://rsmpm3308.zicare.id:3443`.
- Never put passwords in the document or in this chat. Use env vars.
- Screenshot every result for the **Eviden** column.

| Point | Tool | Where |
|-------|------|-------|
| 1.1 XSS | OWASP ZAP (+ manual) | staging |
| 1.2 SQL Injection | sqlmap (+ ZAP) | staging |
| 1.3 CAPTCHA / delay | `app_auth_test.py` | staging |
| 1.4 Lock-out 3x | `app_auth_test.py --yes-lock` | staging |
| 1.5 Gagal login msg | `app_auth_test.py` | staging |
| 1.6 Msg tidak bedakan | `app_auth_test.py` | staging |
| 1.7 Password complexity | manual (see below) | staging |
| 1.8 Menu per role | `app_auth_test.py` | staging |
| 1.9 Broken access ctrl | `app_auth_test.py` | staging |
| 1.10 Vulnerable libs | retire.js | staging |
| 2.1–2.5 Server | `server-check.sh` | production |

---

## A. Prepare (once)

```bash
cd ../security-selftest-zicare           # you are here
python3 -m venv venv
source venv/bin/activate
pip install requests
```

Install external tools:
```bash
brew install nmap                        # ports (2.2)
brew install testssl                     # TLS (2.3), or use nmap ssl-enum-ciphers
npm install -g retire                    # vulnerable JS libs (1.10)
# ZAP: download from https://www.zaproxy.org/download/  (desktop app)
# sqlmap: brew install sqlmap
```

---

## B. App login tests — points 1.3, 1.5, 1.6, 1.8, 1.9  (safe, no lock)

```bash
export ZC_BASE='https://dev-rsmpm3308.zicare.id:4334'
export ZC_DOKTER_USER='anita020495'
read -s ZC_DOKTER_PASS; export ZC_DOKTER_PASS      # type password, hidden
export ZC_PERAWAT_USER='anonim'
read -s ZC_PERAWAT_PASS; export ZC_PERAWAT_PASS

python3 app_auth_test.py --only 1.5,1.6,1.3,1.8,1.9 | tee app-safe-$(date +%Y%m%d).log
```
The script **refuses to run if `ZC_BASE` points at production**.

Expected from the code review: 1.3 NOT PASS, 1.5 PASS (but wording "Invalid credentials." not "Gagal Login"), 1.6 PASS, 1.8 and 1.9 NOT PASS. Confirm with the real output.

---

## C. Lock-out test — point 1.4  (WARNING: locks the account)

This sends 3 wrong passwords for `anita020495`, then the correct one. It will
**lock that account on staging**. An admin must unlock it afterward
(set `is_lockedout` / reset `failed_password_att`, or the User menu).

```bash
python3 app_auth_test.py --only 1.4 --yes-lock | tee app-1.4-$(date +%Y%m%d).log
```
Run this **last**, because afterward `anita020495` can't log in until unlocked.

---

## D. Point 1.7 — password complexity (manual, 2 minutes)

Log in to staging as `anita020495`, open **Ubah Password**, and try to save each
weak password below. Screenshot the result. **PASS** only if all are rejected.

| Try | Should be |
|-----|-----------|
| `12345`           | rejected (too short) |
| `abcdefgh`        | rejected (no upper/number/symbol) |
| `Password1`       | rejected (no symbol) |
| `Passw0rd!`       | accepted (8+, upper, lower, number, symbol) |

From the code review the app does **not** enforce this, so expect **NOT PASS**.
Set the password back when done.

---

## E. Point 1.10 — vulnerable libraries (retire.js)

```bash
retire --outputformat text --outputpath retire-$(date +%Y%m%d).txt \
  --jspath /dev/null  # see note
```
Simplest: point retire.js at the live site with the browser extension, OR scan
the repo's JS folder locally:
```bash
retire --path ../zicare_v1/public/assets/js --outputformat text \
  | tee retire-$(date +%Y%m%d).log
```
Expect findings: jQuery 1.11.1, Bootstrap 3.2.0, jQuery UI 1.10.4, axios 0.16.2
⇒ **NOT PASS**. Screenshot the list of CVEs.

---

## F. Points 1.1 (XSS) & 1.2 (SQLi) — OWASP ZAP + sqlmap

Zi.Care is a Vue SPA that posts JSON, so the spider alone misses forms. Use an
authenticated scan.

**ZAP (1.1 XSS, also flags SQLi):**
1. Start ZAP desktop. Set browser proxy to `127.0.0.1:8080`, import ZAP CA cert.
2. Log in to staging through the proxied browser so ZAP records the session.
3. In ZAP: right-click the staging site → **Spider** then **AJAX Spider**.
4. Right-click the site → **Active Scan** (scope = staging host only).
5. Report → HTML. Screenshot the XSS and SQLi alerts (or "no alerts") for 1.1/1.2.

**sqlmap (1.2 SQLi, targeted):** capture one authenticated POST (e.g. a search
or billing filter) with the browser dev-tools "Copy as cURL", save the raw
request to `req.txt`, then:
```bash
sqlmap -r req.txt --batch --level 2 --risk 1 --dbms mysql --threads 2
```
Keep `--risk 1` so it does not run data-changing payloads. Run on staging only.
Screenshot the "is/is not injectable" result.

> The code review found ~490 queries built with `sprintf` from raw request
> input (e.g. `BillingController.php:277`) and ~7,400 `v-html` uses. Automated
> scans will likely confirm NOT PASS for both.

---

## G. Server tests — points 2.1 – 2.5 (production)

SSH into `rsmpm3308.zicare.id`, copy `server-check.sh` over (or paste it), then:
```bash
bash server-check.sh | tee server-check-$(date +%Y%m%d).log
```
It only **reads** config (firewall rules, versions, TLS directives) — it changes
nothing. Firewall and version reads need `sudo`.

From your laptop, add the external views:
```bash
nmap -Pn -p- rsmpm3308.zicare.id                          # 2.2
nmap --script ssl-enum-ciphers -p 3443 rsmpm3308.zicare.id # 2.3
testssl.sh rsmpm3308.zicare.id:3443                        # 2.3 (nicer report)
```

**Do not enable or edit firewall rules during the assessment** — a wrong rule
can lock you out of SSH. Collect evidence first; apply fixes in a separate,
planned change.

---

## H. Fill the form

For each point paste PASS / NOT PASS into the **Checklist** column and attach the
matching screenshot/log as **Eviden**. For NOT PASS items, note the planned fix
and target date so BPJS sees a remediation path.
