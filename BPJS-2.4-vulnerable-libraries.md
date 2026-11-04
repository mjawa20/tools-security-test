# BPJS 2.4 — No vulnerable libraries in use

Self-assessment SEC-FORM-001, point 2.4: *"Tidak menggunakan library yang vulnerable, misalnya bootstrap, jQuery, dan sebagainya."*
(Do not use vulnerable libraries, such as Bootstrap, jQuery, and so on.)

| | |
|---|---|
| Application | Zi.Care HIS (`zicare_v1`, branch `rc/prime`) |
| Test date | 2026-10-30 |
| Status | **PASS with documented risk exceptions** (0 OPEN findings) |
| Main evidence | `retire-test-20261030-135919.log` / `.json`, `lib-check/evidence-old.png`, `lib-check/evidence-new.png` |

---

## 1. Summary

The application's JavaScript libraries are loaded through the `gjs` collection in `app/controllers/ControllerBase.php`
(74 files). The initial scan found vulnerable versions of jQuery, Bootstrap, axios, moment.js, Vue, lodash, crypto-js and
pdf.js (dflip).

The fixes avoid major-version upgrades, so the application keeps working as before:

- **Upgrade within the same major line** when a safe version exists.
- **Backport the official fixes** into the library file when the major line is end-of-life and has no safe version
  (jQuery 1.11.1, Bootstrap 3.4.1). The library's version string is **left unchanged**, so scanners still report the real version.
- **Official mitigation** when an upgrade is not compatible (pdf.js inside dflip).
- **Risk exception** for findings that have no public fix.

## 2. Library changes

| Library | Before | After | Fix |
|---|---|---|---|
| axios | 0.16.2 | 0.34.0 | upgrade (0.x) |
| moment.js | 2.24.0 | 2.31.0 | upgrade (2.x) |
| vue | 2.6.10 | 2.7.16 | upgrade (2.x), new file `vue.v2.7.16.min.js` |
| bootstrap | 3.2.0 | 3.4.1 + patch | upgrade (3.x) + CVE-2024-6485 patch |
| jquery | 1.11.1 | 1.11.1 + backports | 5 fixes backported from jQuery 3.x |
| lodash | 4.17.4 | 4.18.1 | upgrade (4.x) |
| crypto-js | 4.0.0 | 4.2.0 | upgrade (4.x) |
| pdf.js (dflip) | 1.9.426 | 1.9.426 + mitigation | `isEvalSupported = false` (official CVE-2024-4367 mitigation) |

### jQuery 1.11.1 backports (`public/assets/js/jquery.js`)

| CVE / issue | Fix | From |
|---|---|---|
| CVE-2019-11358 | `extend()` skips the `__proto__` key (prototype pollution) | jQuery 3.4.0 |
| CVE-2020-11022 | no self-closing tag expansion in `html()` / `buildFragment` | jQuery 3.5.0 |
| CVE-2020-11023 | `<option>` no longer wrapped in `<select>` | jQuery 3.5.0 |
| CVE-2015-9251 | cross-domain responses are never auto-executed as script | jQuery 3.0.0 |
| issue #11974 | `parseHTML()` without a context builds in a detached document | jQuery 3.0.0 |

### Bootstrap 3.4.1 patch

CVE-2024-6485: the button plugin sets `data-loading-text` and the reset text as **text**, not HTML
(`vendor/bootstrap/bootstrap.js`, `vendor/bootstrap/bootstrap.min.js`).

### pdf.js 1.9.426 mitigation (dflip)

CVE-2024-4367: font glyphs are no longer compiled with `new Function`, so a crafted FontMatrix in a malicious PDF cannot run
script. The `isEvalSupported` default is changed to `false` in `libs/pdf.js` and `libs/pdf.min.js`, and set explicitly in
`dflip.js`. pdf.js 4.x (the fixed version) is not compatible with dflip.

### Changed files (`zicare_v1`)

```
app/controllers/ControllerBase.php                      # gjs: vue.v2.6.10.min.js -> vue.v2.7.16.min.js
public/assets/js/jquery.js                              # backports
public/assets/js/vue.v2.7.16.min.js                     # new
public/assets/js/vendor/axios/axios.min.js
public/assets/js/vendor/bootstrap/bootstrap.js
public/assets/js/vendor/bootstrap/bootstrap.min.js
public/assets/js/vendor/momentjs/moment-with-locales.min.js
public/assets/js/vendor/lodash/lodash.min.js
public/assets/js/vendor/crypto-js/crypto-js.js
public/assets/js/vendor/dflip/js/dflip.js
public/assets/js/vendor/dflip/js/libs/pdf.js
public/assets/js/vendor/dflip/js/libs/pdf.min.js
```

Commit: `e77b578c23` (jQuery, Bootstrap, axios, moment, Vue). The lodash, crypto-js and pdf.js changes follow in the next commit.

## 3. Regression checks

| Library | Check | Result |
|---|---|---|
| jquery | search app code for `html()` / `append()` calls with non-void self-closing tags | none found |
| lodash | old vs new API, 14 common calls, compiling all 11 `_.template` calls in the app, RIS URL template, grouper `_.unset` | identical |
| crypto-js | the app only uses passphrase `AES.decrypt` (EvpKDF, unchanged); decrypting the 3 ag-grid/amcharts license keys in `zicare.js` | identical |
| pdf.js | rendering a test PDF with eval on vs off, on both the FontFace path and the glyph path (Safari/iOS) | identical pixel hash |
| axios | APIs the app uses (`CancelToken`, `isCancel`, `all`, `spread`, interceptors, `withCredentials`) | all present in 0.34.0 |

Recommended manual browser checks: menu, modals, dropdowns, tooltips, datetimepicker, main Vue pages, saving forms and uploads
(axios), kardeks / medical instructions / radiology image links (lodash templates), ag-grid and amcharts without a license
watermark (crypto-js), medical record file flipbook (pdf.js).

## 4. How to run the test

From `security-selftest-zicare/`:

```bash
python3 retire_test.py              # scan gjs.js (rebuilt from the gjs collection) + pdf.js
python3 retire_test.py --exploit    # + before/after exploit test in headless Chrome
python3 retire_test.py --served     # cross-check: every script the login page loads (localhost:8080)
python3 retire_test.py --no-rebuild # scan gjs.js as it is
```

Script steps:

1. **targets** — rebuilds `gjs.js` from the `gjs` collection (warmup.sh does not build it because of `join(false)`).
2. **exploit test** (`--exploit`) — `lib-check/run.sh` runs each CVE payload against the libraries before the patch
   (`lib-check/old`) and after (`lib-check/new`). A check is `VULNERABLE` only when the payload actually executes.
3. **retire scan** — Retire.js against the public vulnerability database.
4. **libraries Retire.js cannot identify** — version read from the file content (axios, lodash, crypto-js, SheetJS, pdf.js).

Statuses in the summary table:

| Status | Meaning |
|---|---|
| CLEAN / FIXED | version is not vulnerable |
| PATCHED | fix is in place; its marker is checked in the file itself, never assumed |
| ACCEPTED | no public fix yet, listed as a risk exception |
| EOL | major line no longer supported by the vendor, listed as a risk exception |
| OPEN | still vulnerable — test FAILS (exit code 1) |

Output: `retire-test-<time>.log` and `retire-test-<time>.json`.

## 5. Results

### Exploit test (headless Chrome)

| Check | Before | After |
|---|---|---|
| CVE-2019-11358 prototype pollution | VULNERABLE | safe |
| CVE-2020-11022 `html()` XSS | VULNERABLE | safe |
| CVE-2020-11023 `<option>` XSS | safe* | safe |
| jQuery #11974 `parseHTML` XSS | VULNERABLE | safe |
| CVE-2015-9251 cross-domain script | VULNERABLE | safe |
| CVE-2024-6485 Bootstrap button XSS | VULNERABLE | safe |

\* The public CVE-2020-11023 PoC no longer executes in modern Chrome, even against the old library; the fix is shown by the code change.

### retire_test.py summary

| # | Library | Version | Finding | Sev | Status |
|---|---|---|---|---|---|
| 1 | bootstrap | 3.4.1 | CVE-2025-1647 | medium | ACCEPTED |
| 2 | vue | 2.7.16 | CVE-2024-9506 | low | ACCEPTED |
| 3 | bootstrap | 3.4.1 | end-of-life | low | EOL |
| 4 | jquery | 1.11.1 | end-of-life | low | EOL |
| 5 | bootstrap | 3.4.1 | CVE-2024-6485 | medium | PATCHED |
| 6 | jquery | 1.11.1 | CVE-2015-9251 | medium | PATCHED |
| 7 | jquery | 1.11.1 | issue #11974 | medium | PATCHED |
| 8 | jquery | 1.11.1 | CVE-2019-11358 | medium | PATCHED |
| 9 | jquery | 1.11.1 | CVE-2020-11023 | medium | PATCHED |
| 10 | pdf.js (dflip) | 1.9.426 | CVE-2024-4367 | high | PATCHED |
| 11 | axios | 0.34.0 | - | - | FIXED |
| 12 | crypto-js | 4.2.0 | - | - | FIXED |
| 13 | xlsx (SheetJS) | 0.20.3 | - | - | FIXED |
| 14 | lodash | 4.18.1 | - | - | CLEAN |
| 15 | moment.js | 2.31.0 | - | - | CLEAN |

**ACCEPTED 2 · EOL 2 · PATCHED 6 · FIXED 3 · CLEAN 2 → PASS 2.4 with documented risk exceptions.**

## 6. Risk exceptions

1. **Bootstrap 3.4.1 — CVE-2025-1647 (medium).** No fixed release exists for Bootstrap 3. Bootstrap's built-in HTML
   sanitizer stays on, and a popover with `html: true` is used on only one internal screen
   (`component/form/form-verification-ok.vue.js:660`, operating room schedule).
2. **Vue 2.7.16 — CVE-2024-9506 (low, ReDoS).** No fix exists for Vue 2. It can only be exploited when the application
   compiles templates from user input at runtime, which it does not do.
3. **jQuery 1.x and Bootstrap 3.x — end-of-life.** Every known CVE in both libraries is closed by an official backported fix
   and proven by the exploit test. Migration to the current major versions (jQuery 3, Bootstrap 5, Vue 3) is planned for a
   later release.

## 7. Tools used

| Tool | Purpose |
|---|---|
| Retire.js 6.1.0 (RetireJS / OWASP) | Scans the JavaScript libraries (`gjs.js`, 74 libraries) against the public vulnerability database (CVE / GitHub Advisory) |
| retire_test.py (Zi.Care internal script, Python 3.15.2) | Automates the scan, checks versions of libraries Retire.js cannot identify, verifies patch markers, prints the summary table |
| Google Chrome 156.0.8078.74 (Google LLC, headless) | Runs CVE exploit payloads before/after the fix; verifies PDF rendering after the pdf.js mitigation |
| Node.js v24.18.0 (OpenJS Foundation) | Retire.js runtime; old vs new compatibility checks (lodash, crypto-js) |

## 8. Rollback

```bash
# in zicare_v1: restore every library to its pre-fix state
git revert e77b578c23                                   # jQuery, Bootstrap, axios, moment, Vue
git checkout HEAD -- public/assets/js/vendor/lodash public/assets/js/vendor/crypto-js public/assets/js/vendor/dflip
```

## 9. Notes

- `gjs.js` is gitignored and **not loaded by the browser** (the `gjs` collection uses `join(false)`, so every library is
  loaded as its own file). `retire_test.py` rebuilds it only as a single scan target.
- Retire.js matches **versions**, not fixes. That is why jQuery 1.11.1 and Bootstrap 3.4.1 still appear in a raw Retire.js
  report; the PATCHED status is proven by the markers in the files and by the exploit test.
- Retire.js does not identify some libraries (axios 0.3x, crypto-js, SheetJS, minified pdf.js). Without the extra version
  check they looked "clean" while they were vulnerable (lodash 4.17.4, crypto-js 4.0.0, pdf.js 1.9.426).
