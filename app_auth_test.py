#!/usr/bin/env python3
"""
Zi.Care Security Self-Assessment - APP / login checks (points 1.3 - 1.9).

Authorized self-assessment of your OWN Zi.Care HIS for the BPJS SEC-FORM-001.
Run against STAGING, never production: the lock-out test (1.4) will lock the
test accounts, and an admin must unlock them afterwards.

Read-only except:
  - 1.4 sends wrong passwords on purpose -> locks the account under test.
  - 1.7 (optional, --test-pw) changes the test user's password and sets it back.

NO passwords on the command line. Pass them as environment variables:
    export ZC_BASE='https://dev-rsauas3174.zicare.id:4334'
    export ZC_DOKTER_USER='anita020495'   ; export ZC_DOKTER_PASS='...'
    export ZC_PERAWAT_USER='anonim'       ; export ZC_PERAWAT_PASS='...'
Then:
    python3 app_auth_test.py --only 1.5,1.6            # safe, no lock
    python3 app_auth_test.py --only 1.3,1.4            # LOCKS dokter account
    python3 app_auth_test.py --only 1.8,1.9            # needs both users

Requires: pip install requests
"""
import os, re, sys, json, time, argparse, urllib3

try:
    import requests
except ImportError:
    sys.exit("pip install requests   (run inside a venv)")

urllib3.disable_warnings()  # staging may use a self-signed cert

def load_dotenv(path=None):
    """Minimal .env loader (no dependency). Existing env vars win."""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key, val = key.strip(), val.strip().strip('"').strip("'")
            os.environ.setdefault(key, val)

load_dotenv()

BASE = os.environ.get("ZC_BASE", "").rstrip("/")
VERIFY = os.environ.get("ZC_VERIFY", "0") == "1"   # set ZC_VERIFY=1 to enforce cert
TOKEN_RE_K = re.compile(r"key:\s*[`'\"]([^`'\"]+)[`'\"]")
TOKEN_RE_V = re.compile(r"value:\s*[`'\"]([^`'\"]+)[`'\"]")

results = []
def record(point, name, verdict, detail):
    results.append((point, name, verdict, detail))
    mark = {"PASS": "PASS    ", "NOT PASS": "NOT PASS", "INFO": "INFO    ",
            "MANUAL": "MANUAL  "}.get(verdict, verdict)
    print(f"  [{mark}] {point} {name}\n            {detail}", flush=True)

def progress(msg):
    print(f"  ... {msg}", flush=True)

def new_session():
    s = requests.Session()
    s.verify = VERIFY
    s.headers.update({"X-Requested-With": "XMLHttpRequest",
                      "Content-Type": "application/json",
                      # server/WAF drops requests without a browser User-Agent
                      "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                                     "Chrome/124.0 Safari/537.36")})
    return s

def get_token(s):
    """Load /login and pull the CSRF token the signin form uses."""
    r = s.get(f"{BASE}/login", timeout=30)
    k = TOKEN_RE_K.search(r.text)
    v = TOKEN_RE_V.search(r.text)
    if not (k and v):
        raise RuntimeError("could not parse CSRF token from /login page")
    return k.group(1), v.group(1)

def signin(s, user, pw, token):
    """One login attempt. Returns (result, error, next_token)."""
    k, v = token
    r = s.post(f"{BASE}/login/signin",
               data=json.dumps({"user_guid": user, "user_password": pw,
                                "key": k, "value": v}),
               timeout=30)
    try:
        j = r.json()
    except ValueError:
        return "failed", f"<non-JSON HTTP {r.status_code}>", token
    nxt = (j.get("token") or {})
    next_token = (nxt.get("key"), nxt.get("value")) if nxt else token
    return j.get("result", "failed"), (j.get("error") or ""), next_token

# --------------------------------------------------------------------------
def t_1_5(duser, dpass):
    """1.5  'Gagal Login' warning appears on wrong credentials."""
    s = new_session()
    tok = get_token(s)
    res, err, _ = signin(s, duser, "definitely_wrong_pw_123", tok)
    ok = res == "failed" and bool(err)
    record("1.5", "Pesan warning gagal login",
           "PASS" if ok else "NOT PASS",
           f'message shown = "{err}"  (NOTE: form wants the literal text '
           f'"Gagal Login"; Zi.Care currently returns "{err}")')

def t_1_6(duser):
    """1.6  Same message for wrong-username vs wrong-password (no user enum)."""
    s = new_session()
    _, err_baduser, _ = signin(s, "no_such_user_zzz_999", "whatever_pw", get_token(s))
    s2 = new_session()
    _, err_badpass, _ = signin(s2, duser, "definitely_wrong_pw_123", get_token(s2))
    same = err_baduser.strip() == err_badpass.strip() and err_baduser != ""
    record("1.6", "Pesan tidak bedakan user/pass salah",
           "PASS" if same else "NOT PASS",
           f'wrong-user="{err_baduser}"  |  wrong-pass="{err_badpass}"')

def t_1_3(duser):
    """1.3  CAPTCHA or delay / rate-limit on repeated failed logins."""
    s = new_session()
    tok = get_token(s)
    page = s.get(f"{BASE}/login", timeout=30).text.lower()
    has_captcha = any(x in page for x in ("captcha", "g-recaptcha", "hcaptcha"))
    #~~ bomb with a DIFFERENT random username each time -> hits the user-not-found
    #~~ path (per-IP throttle), so the account-lockout (1.4) does not short-circuit
    #~~ the timing. This also mirrors a real "random username" bombing attack.
    import random
    times = []
    for i in range(6):
        guid = "nouser_%d_%d" % (random.randint(100000, 999999), i)
        t0 = time.time()
        res, err, tok = signin(s, guid, "wrong_pw", tok)
        times.append(time.time() - t0)
        if "too many" in err.lower() or "captcha" in err.lower():
            break
    #~~ per-IP delay should grow across attempts (cap ~8s)
    grew = len(times) >= 4 and (times[-1] - times[0]) > 1.0
    verdict = "PASS" if (has_captcha or grew) else "NOT PASS"
    record("1.3", "CAPTCHA / delay / rate-limit",
           verdict,
           f"captcha_on_page={has_captcha}  response_times={[round(t,2) for t in times]}  "
           f"(bombed random usernames; rising times => per-IP delay works)")

def t_1_4(duser, dpass):
    """1.4  Temporary lock-out after 3 wrong attempts.  WARNING: locks account."""
    s = new_session()
    tok = get_token(s)
    msgs = []
    for i in range(3):
        res, err, tok = signin(s, duser, f"wrong_pw_lock_{i}", tok)
        msgs.append(err)
    # now try the CORRECT password; if locked, it must be refused
    res, err, tok = signin(s, duser, dpass, tok)
    locked = res == "failed" and ("lock" in err.lower() or "terkunci" in err.lower())
    record("1.4", "Lock-out setelah 3x gagal",
           "PASS" if locked else "NOT PASS",
           f'after 3 fails, correct-password result="{res}" msg="{err}"  '
           f'(Zi.Care default locks only after >5 fails and lock is PERMANENT, '
           f'not temporary => expect NOT PASS). ACCOUNT "{duser}" IS NOW LOCKED ON STAGING.')

ADMIN_PROBES = [
    # path , why it should be blocked for a non-admin (perawat)
    ("/user",                      "user management page"),
    ("/configuration",             "system configuration page"),
    ("/user/getUsers",             "list all users (admin data)"),
]
def t_1_8_1_9(puser, ppass, duser):
    """1.8 menu-by-role + 1.9 broken access control."""
    # --- anonymous: protected endpoints must redirect to login / 302 ---
    s_anon = new_session()
    anon_open = []
    for path, _why in ADMIN_PROBES:
        try:
            r = s_anon.get(f"{BASE}{path}", timeout=30, allow_redirects=False)
            body = (r.text or "")[:200].lower()
            # open = 200 with real content and not bounced to login
            if r.status_code == 200 and "login" not in r.url.lower() and "sign in" not in body:
                anon_open.append(f"{path}(HTTP200)")
        except Exception as e:
            anon_open.append(f"{path}(err:{e})")
    record("1.9", "Broken access control (anonymous)",
           "NOT PASS" if anon_open else "PASS",
           f"endpoints reachable WITHOUT login: {anon_open or 'none'}")

    # --- perawat logged in: admin-only URLs must be blocked ---
    if not (puser and ppass):
        record("1.8", "Menu per role (perawat -> admin URL)", "MANUAL",
               "set ZC_PERAWAT_USER / ZC_PERAWAT_PASS to run automatically")
        return
    s = new_session()
    res, err, tok = signin(s, puser, ppass, get_token(s))
    if res != "ok":
        record("1.8", "Menu per role", "INFO",
               f'could not log in as perawat "{puser}": {err}')
        return
    reachable = []
    for path, why in ADMIN_PROBES:
        r = s.get(f"{BASE}{path}", timeout=30, allow_redirects=False)
        body = (r.text or "")[:300].lower()
        blocked = (r.status_code in (301, 302, 401, 403)
                   or "login" in r.url.lower()
                   or "tidak memiliki akses" in body or "forbidden" in body)
        if not blocked and r.status_code == 200:
            reachable.append(f"{path} [{why}] HTTP{r.status_code}")
    record("1.8", "Menu per role (perawat akses URL admin)",
           "NOT PASS" if reachable else "PASS",
           f"admin URLs reachable as perawat: {reachable or 'none (all blocked)'}")

# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="1.5,1.6,1.3,1.8,1.9",
                    help="comma list of points; 1.4 excluded by default (locks account)")
    ap.add_argument("--yes-lock", action="store_true",
                    help="required to actually run 1.4 (it locks the dokter account)")
    args = ap.parse_args()

    if not BASE:
        sys.exit("set ZC_BASE first (staging URL)")
    # production is rsmpm3308.zicare.id:3443 ; staging is dev-rsmpm3308...:4334
    if ":3443" in BASE or ("rsmpm3308" in BASE and "dev-" not in BASE):
        sys.exit("REFUSING: ZC_BASE looks like PRODUCTION (:3443). Use the dev/staging URL only.")

    duser = os.environ.get("ZC_DOKTER_USER", "")
    dpass = os.environ.get("ZC_DOKTER_PASS", "")
    puser = os.environ.get("ZC_PERAWAT_USER", "")
    ppass = os.environ.get("ZC_PERAWAT_PASS", "")
    want = [x.strip() for x in args.only.split(",") if x.strip()]

    print(f"Target: {BASE}   (cert verify={VERIFY})", flush=True)
    print("  NOTE: server responds ~10s per login, so each point takes a while.\n",
          flush=True)
    if "1.5" in want:
        progress("1.5 running (1 login attempt)...");           t_1_5(duser, dpass)
    if "1.6" in want:
        progress("1.6 running (2 login attempts)...");          t_1_6(duser)
    if "1.3" in want:
        progress("1.3 running (up to 6 login attempts, ~60s)..."); t_1_3(duser)
    if "1.8" in want or "1.9" in want:
        progress("1.8/1.9 running (login + admin URL probes)..."); t_1_8_1_9(puser, ppass, duser)
    if "1.4" in want:
        if args.yes_lock:
            t_1_4(duser, dpass)
        else:
            record("1.4", "Lock-out", "INFO",
                   "skipped. Re-run with --only 1.4 --yes-lock to run (LOCKS the account).")

    print("\n---- SUMMARY (for SEC-FORM-001 'Checklist' column) ----")
    for p, n, v, _ in sorted(results):
        print(f"  {p:4} {v:8}  {n}")
    print("\nScreenshot this run for the 'Eviden' column. 1.1, 1.2, 1.7, 1.10 are "
          "covered in README.md (ZAP / sqlmap / retire.js).")

if __name__ == "__main__":
    main()
