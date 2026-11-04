#!/usr/bin/env bash
#
# Zi.Care Security Self-Assessment - SERVER checks (points 2.1 - 2.5)
# Read-only. Does NOT change firewall, packages, or config.
# Run ON the production server (SSH in first).
#
# Usage:
#   bash server-check.sh | tee server-check-$(date +%Y%m%d).log
#
# Some checks need sudo (firewall rules). You will be prompted.
# Nothing here writes to disk except the log you redirect yourself.

set -u
line() { printf '\n================ %s ================\n' "$1"; }
note() { printf '  [i] %s\n' "$1"; }

printf 'Zi.Care server self-check  |  host=%s  |  date=%s\n' "$(hostname)" "$(date '+%Y-%m-%d %H:%M:%S')"

# ---------------------------------------------------------------------------
line "STEP 0  Server identity"
cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION)=' || true
printf 'kernel: %s\n' "$(uname -r)"
printf 'whoami: %s\n' "$(whoami)"
note "Is the app in Docker? Listing containers:"
docker ps --format '{{.Names}}  {{.Image}}  {{.Ports}}' 2>/dev/null || note "docker not present / no permission"
note "Web-facing processes:"
ps -eo comm 2>/dev/null | grep -E 'nginx|apache2|httpd|php-fpm|haproxy|traefik' | sort -u || true

# ---------------------------------------------------------------------------
line "2.1  Antivirus installed"
if command -v clamscan >/dev/null 2>&1; then
  clamscan --version
  systemctl is-active clamav-daemon 2>/dev/null   && note "clamav-daemon active"
  systemctl is-active clamav-freshclam 2>/dev/null && note "freshclam (signature updater) active"
  note "Signature DB date:"; ls -l /var/lib/clamav/*.cvd /var/lib/clamav/*.cld 2>/dev/null | head
else
  note "ClamAV NOT found. Checking other AV/EDR vendors:"
  ls -d /opt/* 2>/dev/null | grep -iE 'eset|sophos|trend|crowdstrike|sentinel|wazuh|bitdefender|falcon' \
    || note ">>> NO antivirus detected -> point 2.1 likely NOT PASS"
fi

# ---------------------------------------------------------------------------
line "2.2  Firewall active, inbound HTTPS only"
note "Firewall status (reads rules only, changes nothing):"
if command -v ufw >/dev/null 2>&1; then
  sudo ufw status verbose 2>/dev/null || note "need sudo for ufw"
elif command -v firewall-cmd >/dev/null 2>&1; then
  sudo firewall-cmd --list-all 2>/dev/null || note "need sudo for firewalld"
else
  note "iptables INPUT chain:"; sudo iptables -S INPUT 2>/dev/null | head -40 || note "need sudo for iptables"
fi
note "Ports this server is LISTENING on (excluding localhost):"
sudo ss -tlnp 2>/dev/null | awk 'NR==1 || ($4 !~ /127.0.0.1/ && $4 !~ /::1/)'
note ">>> From OUTSIDE the server, also run:  nmap -Pn -p- rsmpm3308.zicare.id"
note ">>> PASS = only the HTTPS app port (3443, plus 80->443 redirect) reachable from internet."

# ---------------------------------------------------------------------------
line "2.3  TLS >= 1.2  (configured)"
note "nginx TLS directives found in config:"
sudo grep -rnE 'ssl_protocols|ssl_ciphers' /etc/nginx/ 2>/dev/null \
  || note "none in /etc/nginx (may be in Docker container or a proxy)"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q nginx; then
  note "nginx container TLS directives:"
  docker exec "$(docker ps --format '{{.Names}}' | grep nginx | head -1)" \
    sh -c 'grep -rnE "ssl_protocols|ssl_ciphers" /etc/nginx/ 2>/dev/null' || true
fi
note ">>> From your laptop confirm with: testssl.sh rsmpm3308.zicare.id:3443"
note ">>> or:  nmap --script ssl-enum-ciphers -p 3443 rsmpm3308.zicare.id"
note ">>> PASS = TLSv1.0 and TLSv1.1 disabled, TLSv1.2 enabled."

# ---------------------------------------------------------------------------
line "2.4  Web server version"
nginx -v 2>&1 || true
apache2 -v 2>/dev/null || httpd -v 2>/dev/null || true
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q nginx; then
  docker exec "$(docker ps --format '{{.Names}}' | grep nginx | head -1)" nginx -v 2>&1 || true
fi
note "server_tokens setting (should be 'off' so version is hidden):"
sudo grep -rn 'server_tokens' /etc/nginx/ 2>/dev/null || note "not set -> version exposed"
note ">>> Check version against https://nginx.org/en/security_advisories.html"

# ---------------------------------------------------------------------------
line "2.5  Language / framework version"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qi phalcon; then
  C="$(docker ps --format '{{.Names}}' | grep -i phalcon | head -1)"
  docker exec "$C" php -v 2>&1 | head -1
  docker exec "$C" php -r 'echo "Phalcon: ".(extension_loaded("phalcon")?phpversion("phalcon"):"not loaded")."\n";' 2>/dev/null
  docker exec "$C" php -i 2>/dev/null | grep -E '^(expose_php|display_errors)'
else
  php -v 2>&1 | head -1
  php -r 'echo "Phalcon: ".(extension_loaded("phalcon")?phpversion("phalcon"):"not loaded")."\n";' 2>/dev/null
  php -i 2>/dev/null | grep -E '^(expose_php|display_errors)'
fi
note "X-Powered-By header exposed? (empty = good):"
curl -skI https://rsmpm3308.zicare.id:3443/login | grep -i 'x-powered-by' || note "  (no X-Powered-By header - good)"
note ">>> PHP 7.2 / 7.3 and Phalcon 3.x are END OF LIFE -> point 2.5 NOT PASS."

line "DONE"
printf 'Screenshot each section for the "Eviden" column of SEC-FORM-001.\n'
