#!/usr/bin/env python3
"""
Zi.Care Security Self-Assessment - point 2.4 (Tidak menggunakan library yang vulnerable), automated.

Scans the JavaScript the app ships with retire.js, shows progress per target, then prints one summary
table: every finding retire reports and whether the shipped file carries the fix. A backported fix is
counted only when its marker is found in the scanned file itself, never assumed. Libraries retire cannot
identify (axios 0.3x, lodash, crypto-js, SheetJS) are checked by their version string.

Targets:
  default    gjs.js, rebuilt from the gjs collection in app/controllers/ControllerBase.php (one compact
             file, no vendor duplicates), plus pdf.js that dflip loads on demand
  --served   every <script> the login page of ZC_LOCAL_BASE (default http://localhost:8080) loads

Usage:
    python3 retire_test.py                 # gjs.js
    python3 retire_test.py --served        # what the browser loads
    python3 retire_test.py --exploit       # also run lib-check/run.sh (headless Chrome, before vs after)
    python3 retire_test.py --no-rebuild    # scan gjs.js as it is

App root: ZC_APP_ROOT (default ../zicare_v1). Output: retire-test-<time>.log and .json next to this script.
"""
import os, re, sys, json, time, shutil, argparse, subprocess, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

def load_dotenv(path=None):
    path = path or os.path.join(HERE, ".env")
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
APP = os.path.abspath(os.environ.get("ZC_APP_ROOT", os.path.join(HERE, "..", "zicare_v1")))
PUBLIC = os.path.join(APP, "public")
LOCAL_BASE = os.environ.get("ZC_LOCAL_BASE", "http://localhost:8080").rstrip("/")
CACHE = os.path.join(HERE, ".retire-cache")
LIBCHECK = os.path.join(HERE, "lib-check")
ON_DEMAND = ["assets/js/vendor/dflip/js/libs/pdf.min.js"]   # loaded by dflip when a PDF opens

# Backported fixes: (component, finding) -> (what, any of these must be in the file, none of these may be,
# key in lib-check/result-*.json)
PATCHED = {
    ("jquery", "CVE-2019-11358"): ("extend() skips __proto__ (backport of 3.4.0)",
                                   ['name === "__proto__"'], [], "CVE-2019-11358"),
    ("jquery", "CVE-2020-11022"): ("no self-closing tag expansion (backport of 3.5.0)",
                                   [], ['replace( rxhtmlTag, "<$1></$2>" )'], "CVE-2020-11022"),
    ("jquery", "CVE-2020-11023"): ("<option> not wrapped in <select> (backport of 3.5.0)",
                                   [], ["option: [ 1, \"<select multiple='multiple'>\""], "CVE-2020-11023"),
    ("jquery", "CVE-2015-9251"): ("cross-domain response never run as script (backport of 3.0.0)",
                                  ["s.contents.script = false"], [], "CVE-2015-9251"),
    ("jquery", "issue-11974"): ("parseHTML() builds in a detached document (backport of 3.0.0)",
                                ['createHTMLDocument( "" )'], [], "jQuery-11974"),
    ("bootstrap", "CVE-2024-6485"): ("button loading/reset text set as text, not HTML",
                                     ['is("input")?"val":"text"', "is('input') ? 'val' : 'text'"], [], "CVE-2024-6485"),
}

# No fix exists in the major line: kept as a documented risk exception.
ACCEPTED = {
    ("bootstrap", "CVE-2025-1647"): "no public 3.x fix; sanitizer on, html popover only in form-verification-ok.vue.js:660",
    ("vue", "CVE-2024-9506"): "no Vue 2 fix; ReDoS needs untrusted templates compiled at runtime, app compiles none",
}

def ver(s):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])

def first(pat, text):
    m = re.search(pat, text)
    return m.group(1) if m else None

def xlsx_version(text):
    found = [v for v in re.findall(r'\.version="(\d+\.\d+\.\d+)"', text) if v.startswith("0.")]
    return max(found, key=ver) if found else None

def cryptojs_version(text):
    m = re.search(r"C_algo\.PBKDF2 = Base\.extend\(\{.{0,600}?hasher: (SHA\d+).{0,80}?iterations: (\d+)", text, re.S)
    if not m:
        return None
    return "<4.2.0" if (m.group(1) == "SHA1" and m.group(2) == "1") else ">=4.2.0"

# Libraries retire.js does not identify in these builds: version string read from the file.
EXTRA = [
    dict(lib="axios", path="assets/js/vendor/axios/axios.min.js", find=lambda t: first(r'"(0\.\d+\.\d+)"', t),
         fixed="0.30.2", ids="CVE-2023-45857, CVE-2025-27152, CVE-2025-58754", sev="high"),
    dict(lib="lodash", path="assets/js/vendor/lodash/lodash.min.js", retire="lodash",
         find=lambda t: first(r'VERSION="(\d+\.\d+\.\d+)"', t) or first(r'"(4\.\d+\.\d+)"', t),
         fixed="4.18.1", ids="CVE-2019-10744, CVE-2020-8203, CVE-2021-23337, CVE-2025-13465, CVE-2026-4800", sev="high"),
    dict(lib="crypto-js", path="assets/js/vendor/crypto-js/crypto-js.js", find=cryptojs_version,
         fixed="4.2.0", ids="CVE-2023-46233", sev="critical"),
    dict(lib="xlsx (SheetJS)", path="assets/js/vendor/sheetjs/xlsx.full.min.js", find=xlsx_version,
         fixed="0.20.2", ids="CVE-2023-30533, CVE-2024-22363", sev="high"),
    dict(lib="pdf.js (dflip)", path="assets/js/vendor/dflip/js/libs/pdf.min.js",
         find=lambda t: first(r'version="(\d+\.\d+\.\d+)"', t) or first(r"pdfjsVersion\s*=\s*['\"](\d+\.\d+\.\d+)", t),
         fixed="4.2.67", ids="CVE-2024-4367", sev="high",
         # 4.x does not fit dflip: the advised mitigation, eval-compiled glyphs off by default
         mitigation=("f.isEvalSupported===undefined?false:f.isEvalSupported",
                     "isEvalSupported defaults to false: glyphs drawn without eval (advised mitigation)")),
]

TTY = sys.stdout.isatty()
COL = {"FIXED": "32", "PATCHED": "32", "CLEAN": "32", "ACCEPTED": "33", "EOL": "33", "OPEN": "31", "UNKNOWN": "33"}

def paint(s, status):
    return f"\033[{COL.get(status, '0')}m{s}\033[0m" if TTY and status in COL else s

class Tee:
    def __init__(self, path):
        self.fh = open(path, "w", encoding="utf-8")
    def __call__(self, s="", end="\n"):
        print(s, end=end, flush=True)
        self.fh.write(re.sub(r"\033\[[0-9;]*m", "", s.lstrip("\r")) + end)
        self.fh.flush()
    def progress(self, s):
        # a live counter on a terminal only; the log keeps the final line
        if TTY:
            print("\r" + s, end="", flush=True)

def die(m):
    sys.exit("ERROR: " + m)

def gjs_sources():
    src = open(os.path.join(APP, "app/controllers/ControllerBase.php"), encoding="utf-8").read()
    block = re.search(r"collection\('gjs'\)(.*?)->join\(", src, re.S)
    if not block:
        die("gjs collection not found in ControllerBase.php")
    lines = [l for l in block.group(1).splitlines() if not l.strip().startswith("//")]
    return re.findall(r"addJs\('([^']+)'", "\n".join(lines))

def rebuild_gjs(log):
    files = gjs_sources()
    out = os.path.join(PUBLIC, "assets/js/gjs.js")
    with open(out, "wb") as fh:
        for i, f in enumerate(files, 1):
            log.progress(f"      joining {i:3}/{len(files)} {f[-60:]:<60}")
            with open(os.path.join(PUBLIC, f), "rb") as src:
                fh.write(src.read())
            fh.write(b"\n;\n")
    log(f"\r      joined {len(files)} files -> public/assets/js/gjs.js ({os.path.getsize(out) / 1e6:.1f} MB)" + " " * 30)
    return out

OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

def fetch(url):
    try:
        with OPENER.open(url, timeout=60) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        # /login answers "302 Not Found" with no Location and the page as body: a browser shows it, so do we
        if e.code in (301, 302, 303) and not e.headers.get("Location"):
            return e.read()
        raise

def download_served(log):
    page = fetch(LOCAL_BASE + "/").decode("utf-8", "replace")
    srcs = [re.sub(r"\?.*$", "", s) for s in re.findall(r'<script[^>]+src="([^"]+)"', page)]
    srcs = [s for s in srcs if s.startswith("/")] + ["/" + p for p in ON_DEMAND]
    folder = os.path.join(HERE, "served-js-" + time.strftime("%Y%m%d"))
    shutil.rmtree(folder, ignore_errors=True)
    os.makedirs(folder)
    targets, failed = [], []
    for i, s in enumerate(srcs, 1):
        log.progress(f"      download {i:3}/{len(srcs)} {s[-60:]:<60}")
        try:
            body = fetch(LOCAL_BASE + s)
        except urllib.error.URLError as e:
            failed.append(f"{s} ({getattr(e, 'code', e)})")
            continue
        dest = os.path.join(folder, s.strip("/").replace("/", "_"))
        with open(dest, "wb") as fh:
            fh.write(body)
        targets.append((s.lstrip("/"), dest))
    log(f"\r      downloaded {len(targets)}/{len(srcs)} scripts from {LOCAL_BASE} -> {os.path.basename(folder)}/" + " " * 30)
    for f in failed:
        log(f"      ! not downloaded: {f}")
    return targets

def retire_scan(path):
    r = subprocess.run(["retire", "--path", path, "--outputformat", "json", "--cachedir", CACHE, "-v"],
                       capture_output=True, text=True)
    if r.returncode not in (0, 13):
        die(f"retire failed on {path}: {r.stderr.strip()[:300]}")
    data = json.loads(r.stdout or "{}").get("data", [])
    return [res for f in data for res in f.get("results", [])]

def finding_ids(v):
    ids = v.get("identifiers", {})
    out = list(ids.get("CVE") or [])
    if not out and ids.get("issue"):
        out = ["issue-" + str(ids["issue"])]
    if not out and ids.get("retid"):
        out = ["retid-" + str(ids["retid"])]
    return out or [ids.get("summary", "?")[:30]]

def classify(comp, vuln, text, exploit):
    summary = vuln.get("identifiers", {}).get("summary", "")
    if "end-of-life" in summary.lower():
        return "EOL", "major line out of support: list it in the risk exception", ""
    ids = finding_ids(vuln)
    if all((comp, i) in ACCEPTED for i in ids):
        return "ACCEPTED", ACCEPTED[(comp, ids[0])], ""
    notes, proof = [], []
    for i in ids:
        p = PATCHED.get((comp, i))
        if not p:
            return "OPEN", summary[:90], ""
        what, has, lacks, key = p
        if (has and not any(h in text for h in has)) or any(l in text for l in lacks):
            return "OPEN", f"{i}: backport marker missing in this file", ""
        notes.append(what)
        if exploit:
            old, new = exploit[0].get(key), exploit[1].get(key)
            if new == "VULNERABLE":
                return "OPEN", f"{i}: exploit still runs", "EXPLOITABLE"
            proof.append("blocked, was exploitable" if old == "VULNERABLE" else "PoC n/a in Chrome")
    return "PATCHED", "; ".join(notes), ", ".join(sorted(set(proof)))

def run_exploit(log):
    for f in ("jquery.js", "vendor/bootstrap/bootstrap.min.js"):
        shutil.copy(os.path.join(PUBLIC, "assets/js", f), os.path.join(LIBCHECK, "new", os.path.basename(f)))
    log("      lib-check/new <- current jquery.js, bootstrap.min.js; lib-check/old = before the patch")
    r = subprocess.run(["bash", os.path.join(LIBCHECK, "run.sh")], capture_output=True, text=True, timeout=180)
    try:
        old = json.load(open(os.path.join(LIBCHECK, "result-old.json")))
        new = json.load(open(os.path.join(LIBCHECK, "result-new.json")))
    except (OSError, ValueError):
        die("lib-check/run.sh gave no result: " + (r.stderr or r.stdout)[-300:])
    keys = [k for k in new if k.startswith(("CVE", "jQuery"))]
    log(f"      {'check':16} {'before':12} after")
    for k in keys:
        log(f"      {k:16} {paint(f'{old.get(k):12}', 'OPEN' if old.get(k) == 'VULNERABLE' else 'CLEAN')} "
            f"{paint(new.get(k), 'OPEN' if new.get(k) == 'VULNERABLE' else 'CLEAN')}")
    return old, new

def table(log, rows):
    heads = ["#", "Library", "Version", "Finding", "Sev", "Status", "Evidence"]
    cells = [[str(i), r["lib"], r["version"], r["finding"], r["sev"], r["status"],
              (r["note"] + (f" | exploit {r['exploit']}" if r["exploit"] else ""))[:110]]
             for i, r in enumerate(rows, 1)]
    w = [max(len(h), *(len(c[j]) for c in cells)) for j, h in enumerate(heads)]
    line = "+" + "+".join("-" * (x + 2) for x in w) + "+"
    log(line)
    log("| " + " | ".join(h.ljust(w[j]) for j, h in enumerate(heads)) + " |")
    log(line)
    for c in cells:
        log("| " + " | ".join(paint(v.ljust(w[j]), c[5]) if j == 5 else v.ljust(w[j]) for j, v in enumerate(c)) + " |")
    log(line)

def main():
    ap = argparse.ArgumentParser(description="BPJS 2.4 vulnerable JS library check")
    ap.add_argument("--served", action="store_true", help="scan what the login page loads instead of gjs.js")
    ap.add_argument("--exploit", action="store_true", help="also run lib-check/run.sh (headless Chrome)")
    ap.add_argument("--no-rebuild", action="store_true", help="scan gjs.js without rebuilding it")
    a = ap.parse_args()
    if not shutil.which("retire"):
        die("retire not found: npm install -g retire")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log = Tee(os.path.join(HERE, f"retire-test-{stamp}.log"))
    t0 = time.time()
    out = subprocess.run(["retire", "--version"], capture_output=True, text=True).stdout.strip()
    log(f"BPJS 2.4 - vulnerable JS libraries    retire {out}    app {APP}")
    log(f"mode: {'served (' + LOCAL_BASE + ')' if a.served else 'gjs.js'}    {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    steps = 4 if a.exploit else 3
    log(f"[1/{steps}] targets")
    if a.served:
        targets = download_served(log)
    else:
        gjs = os.path.join(PUBLIC, "assets/js/gjs.js")
        if not a.no_rebuild:
            gjs = rebuild_gjs(log)
        targets = [("assets/js/gjs.js", gjs)] + [(p, os.path.join(PUBLIC, p)) for p in ON_DEMAND
                                                 if os.path.isfile(os.path.join(PUBLIC, p))]
        for name, _ in targets[1:]:
            log(f"      + {name} (loaded on demand)")

    exploit = None
    if a.exploit:
        log(f"\n[2/{steps}] exploit test (lib-check, headless Chrome)")
        exploit = run_exploit(log)

    log(f"\n[{steps - 1}/{steps}] retire scan")
    rows, seen = [], set()
    for i, (name, path) in enumerate(targets, 1):
        log(f"      [{i:3}/{len(targets)}] {name[-58:]:<58} ", end="")
        t = time.time()
        results = retire_scan(path)
        text = open(path, encoding="utf-8", errors="replace").read() if results else ""
        found = []
        for res in results:
            comp, version = res["component"], res["version"]
            found.append(f"{comp} {version}")
            if (comp, version) in seen:
                continue
            seen.add((comp, version))
            vulns = res.get("vulnerabilities", [])
            if not vulns:
                rows.append(dict(lib=comp, version=version, finding="-", sev="-", status="CLEAN",
                                 note="no known vulnerability", exploit="", file=name))
            for v in vulns:
                status, note, proof = classify(comp, v, text, exploit)
                rows.append(dict(lib=comp, version=version, finding=", ".join(finding_ids(v)), sev=v.get("severity", "?"),
                                 status=status, note=note, exploit=proof, file=name))
        log(f"{', '.join(found) or 'no library identified'}  ({time.time() - t:.1f}s)")

    log(f"\n[{steps}/{steps}] libraries retire cannot identify (version string)")
    for e in EXTRA:
        if e.get("retire") in {c for c, _ in seen}:
            log(f"      {e['lib']:16} identified by retire above")
            continue
        src = os.path.join(PUBLIC, e["path"])
        try:
            text = fetch(LOCAL_BASE + "/" + e["path"]).decode("utf-8", "replace") if a.served else \
                (open(src, encoding="utf-8", errors="replace").read() if os.path.isfile(src) else "")
        except urllib.error.URLError:
            text = ""
        v = e["find"](text) if text else None
        if v is None:
            status, note = "UNKNOWN", "version not found: check by hand"
        elif v.startswith(("<", ">")):
            status = "OPEN" if v.startswith("<") else "FIXED"
            note = f"PBKDF2 defaults show {v}" + (f", fixed in {e['fixed']}" if status == "OPEN" else "")
        else:
            status = "OPEN" if ver(v) < ver(e["fixed"]) else "FIXED"
            note = f"fixed in {e['fixed']}"
            if status == "OPEN" and e.get("mitigation") and e["mitigation"][0] in text:
                status, note = "PATCHED", e["mitigation"][1]
        log(f"      {e['lib']:16} {v or '?':10} {paint(status, status)}")
        rows.append(dict(lib=e["lib"], version=v or "?", finding=e["ids"] if status != "FIXED" else "-",
                         sev=e["sev"] if status != "FIXED" else "-", status=status, note=note, exploit="", file=e["path"]))

    order = {"OPEN": 0, "UNKNOWN": 1, "ACCEPTED": 2, "EOL": 3, "PATCHED": 4, "FIXED": 5, "CLEAN": 6}
    rows.sort(key=lambda r: (order[r["status"]], r["lib"]))
    log("\n---- SUMMARY ----")
    table(log, rows)
    count = {s: sum(r["status"] == s for r in rows) for s in order}
    log("  " + "   ".join(paint(f"{s} {n}", s) for s, n in count.items() if n))
    if count["OPEN"] or count["UNKNOWN"]:
        verdict, st = f"FAIL 2.4: {count['OPEN']} open, {count['UNKNOWN']} unknown finding(s)", "OPEN"
    elif count["ACCEPTED"] or count["EOL"]:
        verdict, st = "PASS 2.4 with documented exceptions (ACCEPTED / EOL rows go in the risk exception)", "ACCEPTED"
    else:
        verdict, st = "PASS 2.4", "CLEAN"
    log("  " + paint(verdict, st))
    report = os.path.join(HERE, f"retire-test-{stamp}.json")
    json.dump(dict(mode="served" if a.served else "gjs", app=APP, retire=out, verdict=verdict, rows=rows,
                   exploit=dict(before=exploit[0], after=exploit[1]) if exploit else None), open(report, "w"), indent=2)
    log(f"  log: retire-test-{stamp}.log   json: retire-test-{stamp}.json   ({time.time() - t0:.0f}s)")
    sys.exit(1 if st == "OPEN" else 0)

if __name__ == "__main__":
    main()
