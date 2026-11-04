#!/usr/bin/env python3
"""
Zi.Care Security Self-Assessment - point 1.2 (SQL Injection), automated,
multiple endpoints, no browser needed.

Logs in to STAGING by itself, captures the session cookie, then for each target
endpoint: (a) runs a manual differential probe on the `search` param, and
(b) runs sqlmap. Targets are raw-concat `search` sinks found in code review.

Account: uses ZC_PERAWAT_USER / ZC_PERAWAT_PASS (fallback to ZC_DOKTER_*).
Reads config from .env. STAGING only (refuses :3443 production).
sqlmap runs with --risk 1 --level 2 (no data-changing payloads).

Usage:
    python3 sqli_test.py --probe          # fast manual differential, all targets
    python3 sqli_test.py                   # probe + sqlmap, all targets
    python3 sqli_test.py --only config     # one target by key
"""
import os, re, sys, json, glob, shlex, subprocess, urllib3

try:
    import requests
except ImportError:
    sys.exit("pip install requests  (inside venv)")

urllib3.disable_warnings()

def load_dotenv(path=None):
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            s = raw.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

load_dotenv()

BASE = os.environ.get("ZC_BASE", "").rstrip("/")
USER = os.environ.get("ZC_PERAWAT_USER") or os.environ.get("ZC_DOKTER_USER", "")
PASS = os.environ.get("ZC_PERAWAT_PASS") or os.environ.get("ZC_DOKTER_PASS", "")
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_RE_K = re.compile(r"key:\s*[`'\"]([^`'\"]+)[`'\"]")
TOKEN_RE_V = re.compile(r"value:\s*[`'\"]([^`'\"]+)[`'\"]")

# raw-concat `search` sinks (code review). {search} is the injection value.
def body_config(v):  return {"search": v, "is_house": False}
def body_stok(v):    return {"search": v, "object_category": [], "item_type": "",
                             "item_type_ids": [], "depo_id": "", "object_id": "",
                             "company_ids": [], "company_id": "", "pager": None,
                             "warehouse_variant_key": None, "only_active": False,
                             "per_batch": False}
def body_object(v):  return {"search": v, "per_company": True, "include_expired": False,
                             "include_zero": True, "item_category_ids": [], "item_type_ids": [],
                             "depo_ids": [], "company_ids": [], "object_ids": [],
                             "near_minimum": False, "exclude_object": [], "per_batch": False,
                             "per_depo": False, "drug_class": [], "sub_item_types": [],
                             "drug_type": [], "column_adds": []}

# patient NAME search (already hardened with $this->db->escapeString); expect PASS.
# Real body the UI sends to /api/pasien/search; `filter` holds the name words.
def body_pasien_nama(v):
    import datetime
    return {"poli_id": "ALL", "disposition": "registration",
            "the_day": datetime.date.today().isoformat(),
            "start": 1, "page": 1, "length": 50, "filter": [v],
            "start_date": "", "end_date": "", "start_schedule": "", "end_schedule": "",
            "time_from": None, "time_to": None, "max_change_date": ""}

# (key, path, body(payload)->dict, result_key, injected_param_name|None)
# pfield=None -> let sqlmap test all JSON params (needed for array/name field)
TARGETS = [
    ("pasien_nama", "/api/pasien/search",              body_pasien_nama, "pasien", None),
    ("config",      "/master/searchMasterConfigOption", body_config,      "sys_options", "search"),
    ("stok",        "/master/searchMasterStok",         body_stok,        None, "search"),
    ("object",      "/masterdata/searchStockObject",    body_object,      None, "search"),
]

def die(m): sys.exit("ERROR: " + m)

def login():
    s = requests.Session()
    s.verify = os.environ.get("ZC_VERIFY", "0") == "1"
    s.headers.update({"User-Agent": UA, "X-Requested-With": "XMLHttpRequest",
                      "Content-Type": "application/json"})
    r = s.get(f"{BASE}/login", timeout=30)
    k = TOKEN_RE_K.search(r.text); v = TOKEN_RE_V.search(r.text)
    if not (k and v):
        die("cannot parse CSRF token from /login")
    r = s.post(f"{BASE}/login/signin",
               data=json.dumps({"user_guid": USER, "user_password": PASS,
                                "key": k.group(1), "value": v.group(1)}), timeout=30)
    j = r.json()
    if j.get("result") != "ok":
        die(f"login failed for '{USER}': {j.get('error')}")
    cookies = "; ".join(f"{c.name}={c.value}" for c in s.cookies)
    if not cookies:
        die("login ok but no session cookie captured")
    return s, cookies

def rows_of(resp, key):
    try:
        j = resp.json()
    except ValueError:
        return -1
    if key and isinstance(j.get("data"), dict):
        return len(j["data"].get(key, []))
    if key:
        return len(j.get(key, []))
    if isinstance(j.get("person"), dict) and isinstance(j["person"].get("data"), list):
        return len(j["person"]["data"])
    d = j.get("data", j)
    for kk in ("records", "rows", "result", "stock", "sys_options", "data"):
        if isinstance(d, dict) and isinstance(d.get(kk), list):
            return len(d[kk])
    return -1

def probe(s, name, path, mkbody, key):
    cases = {"baseline": "zzz", "single_quote": "zzz'",
             "or_true": "zzz%' OR '1'='1", "comment": "zzz'-- -"}
    print(f"\n  [{name}] {path}", flush=True)
    out = {}
    for cname, val in cases.items():
        r = s.post(f"{BASE}{path}", data=json.dumps(mkbody(val)), timeout=30)
        out[cname] = (r.status_code, len(r.text), rows_of(r, key))
        print(f"     {cname:13} http={r.status_code} len={len(r.text):6} "
              f"rows={out[cname][2]}  payload={val!r}", flush=True)
    base = out["baseline"]
    # endpoints build  CALL SelectPaging('...filter...')  by string concat, so an
    # un-escaped single quote breaks the SQL -> HTTP 500. No 500 on a quote payload
    # => the quote is escaped => no error-based/quote-breakout injection.
    verdict = "LIKELY SAFE (no SQL error on quote; confirm blind with sqlmap)"
    if base[0] >= 500:
        verdict = "INCONCLUSIVE (baseline HTTP 500 - request body missing fields, not a finding)"
    elif out["single_quote"][0] >= 500 or out["comment"][0] >= 500:
        verdict = "NOT PASS (quote payload -> SQL error / HTTP 500)"
    elif base[2] >= 0 and out["or_true"][2] > base[2]:
        verdict = "NOT PASS (OR '1'='1' returns more rows -> injectable)"
    elif base[0] != 200:
        verdict = f"INCONCLUSIVE (baseline HTTP {base[0]}; check account/access)"
    print(f"     -> probe verdict: {verdict}", flush=True)
    return verdict, base[0]

def default_sqlmap():
    hits = glob.glob("/opt/homebrew/Cellar/sqlmap/*/libexec/sqlmap.py")
    return f"/usr/bin/python3 {sorted(hits)[-1]}" if hits else "sqlmap"

def run_sqlmap(name, path, mkbody, cookies, pfield):
    host = BASE.split("://", 1)[1]
    body = json.dumps(mkbody("zzz*"))          # * = injection marker
    req_file = os.path.join(HERE, f"sqli-req-{name}.txt")
    req = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
           f"Accept: application/json\r\nX-Requested-With: XMLHttpRequest\r\n"
           f"Content-Type: application/json\r\nCookie: {cookies}\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}")
    with open(req_file, "w", encoding="utf-8") as fh:
        fh.write(req)
    sqlmap = os.environ.get("SQLMAP") or default_sqlmap()
    cmd = shlex.split(sqlmap) + ["-r", req_file, "--batch", "--level", "2",
                                 "--risk", "1", "--dbms", "mysql", "--threads", "2",
                                 "--force-ssl"]
    if pfield:
        cmd += ["-p", pfield]
    print(f"\n  [{name}] sqlmap -> {path}  (param {pfield or 'all JSON'})")
    return subprocess.call(cmd)

def main():
    if not BASE:
        die("set ZC_BASE in .env")
    if ":3443" in BASE or ("rsmpm3308" in BASE and "dev-" not in BASE):
        die("ZC_BASE looks like PRODUCTION (:3443). Staging only.")
    if not (USER and PASS):
        die("set ZC_PERAWAT_USER/PASS (or ZC_DOKTER_*) in .env")

    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]
    targets = [t for t in TARGETS if not only or t[0] == only]

    print(f"Target base: {BASE}   account: {USER}")
    print("  logging in...")
    s, cookies = login()
    print("  login ok\n  == MANUAL DIFFERENTIAL PROBE ==", flush=True)
    verdicts = {}
    base_http = {}
    for name, path, mk, key, pfield in targets:
        verdicts[name], base_http[name] = probe(s, name, path, mk, key)

    if "--probe" not in sys.argv:
        print("\n  == SQLMAP ==", flush=True)
        for name, path, mk, key, pfield in targets:
            if base_http[name] >= 500:
                print(f"\n  [{name}] skip sqlmap (baseline HTTP {base_http[name]} "
                      f"- fix request body first)", flush=True)
                continue
            run_sqlmap(name, path, mk, cookies, pfield)

    print("\n---- SUMMARY (probe) ----")
    for name in verdicts:
        print(f"  {name:8} {verdicts[name]}")
    print("PASS 1.2 if every endpoint is LIKELY SAFE in probe AND sqlmap says "
          "'not injectable'. INCONCLUSIVE = retest with a different account/endpoint.")

if __name__ == "__main__":
    main()
