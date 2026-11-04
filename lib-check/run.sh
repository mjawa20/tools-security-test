#!/bin/bash
# BPJS 2.4 evidence: runs each exploit in headless Chrome against old/ (before the patch) and new/ (served now).
# Refresh the libs first:
#   git -C ../../zicare_v1 show e77b578c23^:public/assets/js/jquery.js > old/jquery.js   (and bootstrap.min.js)
#   cp ../../zicare_v1/public/assets/js/jquery.js ../../zicare_v1/public/assets/js/vendor/bootstrap/bootstrap.min.js new/
cd "$(dirname "$0")"
CH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
python3 -I evil_server.py 8765 >/dev/null 2>&1 & E=$!
python3 -I -m http.server 8766 --bind localhost --directory . >/dev/null 2>&1 & W=$!
trap 'kill $E $W' EXIT
python3 -c "import time; time.sleep(1)"
for v in old new; do
  echo "== $v"
  "$CH" --headless=new --disable-gpu --no-first-run --user-data-dir="$(mktemp -d)" --virtual-time-budget=6000 \
    --dump-dom "http://localhost:8766/$v.html" 2>/dev/null \
    | python3 -c "import sys,re,html; m=re.search(r'<pre id=\"result\">(.*?)</pre>', sys.stdin.read(), re.S); print(html.unescape(m.group(1)) if m else 'NO RESULT')" \
    | tee "result-$v.json"
done
