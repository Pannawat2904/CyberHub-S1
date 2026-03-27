#!/usr/bin/env bash
# =============================================================================
# CyberHub-S1 — Comprehensive Security Test Script
# Covers: Code, Server, Web, API, Dependency, Container
# =============================================================================
set -euo pipefail

# ─── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Configuration ─────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/security-report-$(date +%Y%m%d-%H%M%S).txt"
TARGET_HOST="cyberhub-s1.com"        # Must match Caddyfile
TARGET_HTTP="http://${TARGET_HOST}"
TARGET_HTTPS="https://${TARGET_HOST}"
ADMIN_URL="http://127.0.0.1:8080"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

# ─── Helpers ───────────────────────────────────────────────────────────────────
log() {
    local level="$1" category="$2" id="$3"
    shift 3
    local msg="$*"
    local line="[${level}] [${category}] ${id}: ${msg}"

    echo "$line" >> "$REPORT_FILE"

    case "$level" in
        PASS) echo -e "${GREEN}[PASS]${RESET} [${category}] ${id}: ${msg}" ;;
        FAIL) echo -e "${RED}[FAIL]${RESET} [${category}] ${id}: ${msg}" ;;
        WARN) echo -e "${YELLOW}[WARN]${RESET} [${category}] ${id}: ${msg}" ;;
        SKIP) echo -e "${CYAN}[SKIP]${RESET} [${category}] ${id}: ${msg}" ;;
        INFO) echo -e "       [${category}] ${id}: ${msg}" ;;
    esac

    case "$level" in
        PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
        FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
        WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
        SKIP) SKIP_COUNT=$((SKIP_COUNT + 1)) ;;
    esac
}

section() {
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  $1${RESET}"
    echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
    echo "# $1" >> "$REPORT_FILE"
}

check_command() {
    command -v "$1" &>/dev/null
}

stack_running() {
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'CyberHub'
}

dns_configured() {
    grep -q "${TARGET_HOST}" /etc/hosts 2>/dev/null
}

# ─── Header ────────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "║     CyberHub-S1  Security Assessment Tool        ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo "Report will be saved to: ${REPORT_FILE}"
echo ""

{
    echo "CyberHub-S1 Security Assessment"
    echo "Date: $(date)"
    echo "Host: $(hostname)"
    echo "================================"
} >> "$REPORT_FILE"

cd "$SCRIPT_DIR"

# =============================================================================
# SECTION 1: CODE — Static Analysis (no Docker required)
# =============================================================================
section "1. CODE — Static Analysis"

# C-01: Real credentials in .env
echo "--- C-01: Credentials in .env ---" >> "$REPORT_FILE"
if [[ -f .env ]]; then
    REAL_CREDS=$(grep -vE '^(#|[[:space:]]*$)' .env \
        | grep -vE '=(modified|<.*>|)$' \
        | grep -E '(PASSWORD|PASS|SECRET|TOKEN|KEY)\s*=' \
        | grep -vE '=\$\{' || true)
    if [[ -n "$REAL_CREDS" ]]; then
        log FAIL CODE C-01 "Real credentials found in .env (plaintext passwords present)"
        echo "  Detail: $(echo "$REAL_CREDS" | sed 's/=.*/=[REDACTED]/')" | tee -a "$REPORT_FILE"
    else
        log PASS CODE C-01 ".env contains no plaintext credential values"
    fi
else
    log PASS CODE C-01 ".env file does not exist (not deployed)"
fi

# C-02: Credentials in git history
echo "--- C-02: Credentials in git history ---" >> "$REPORT_FILE"
HIST_CREDS=$(git log --all -p --no-merges 2>/dev/null \
    | grep -E '^\+(.*PASSWORD|.*PASS|.*SECRET|.*TOKEN)\s*=' \
    | grep -vE '=(modified|<|=|\s*$|\$\{)' \
    | grep -v '^+++' || true)
if [[ -n "$HIST_CREDS" ]]; then
    log FAIL CODE C-02 "Plaintext credentials found in git history — rotate immediately"
    echo "  Detail: $(echo "$HIST_CREDS" | head -5 | sed 's/=.*/=[REDACTED]/')" | tee -a "$REPORT_FILE"
else
    log PASS CODE C-02 "No plaintext credentials found in git history"
fi

# C-03: .env tracked by git (despite .gitignore)
echo "--- C-03: .env tracked by git ---" >> "$REPORT_FILE"
TRACKED=$(git ls-files --error-unmatch .env 2>&1 || true)
HIST_ENV=$(git log --all --oneline -- '.env' 2>/dev/null | head -1 || true)
if git ls-files --error-unmatch .env &>/dev/null; then
    log FAIL CODE C-03 ".env is currently tracked by git — credentials are in repository"
elif [[ -n "$HIST_ENV" ]]; then
    log FAIL CODE C-03 ".env was historically committed to git (commit: ${HIST_ENV}) — git history contains credentials"
else
    log PASS CODE C-03 ".env has never been tracked by git"
fi

# C-04: Password reuse
echo "--- C-04: Password reuse ---" >> "$REPORT_FILE"
if [[ -f .env ]]; then
    DB_PASS=$(grep '^DATABASE_PASSWORD=' .env | cut -d= -f2- | tr -d '\r')
    ADMIN_PASS=$(grep '^ADMIN_PASS=' .env | cut -d= -f2- | tr -d '\r')
    if [[ -n "$DB_PASS" && -n "$ADMIN_PASS" && "$DB_PASS" == "$ADMIN_PASS" ]]; then
        log FAIL CODE C-04 "DATABASE_PASSWORD and ADMIN_PASS are identical — password reuse"
    elif [[ -z "$DB_PASS" || -z "$ADMIN_PASS" ]]; then
        log WARN CODE C-04 "Could not compare passwords (.env values empty or not set)"
    else
        log PASS CODE C-04 "DATABASE_PASSWORD and ADMIN_PASS are different"
    fi
else
    log SKIP CODE C-04 ".env not present — cannot check password reuse"
fi

# C-05: Unofficial / unversioned Docker images
echo "--- C-05: Docker image provenance & version pinning ---" >> "$REPORT_FILE"
COMPOSE_FILES="docker-compose.yaml app.yaml db.yaml proxy.yaml admin.yaml"
while IFS= read -r img; do
    [[ -z "$img" ]] && continue
    # Check unofficial namespace
    if echo "$img" | grep -qE '^[a-z0-9_-]+/[a-z0-9_-]'; then
        user=$(echo "$img" | cut -d/ -f1)
        if [[ "$user" != "library" ]]; then
            log WARN CODE C-05 "Non-official image: ${img} (namespace: ${user}) — verify trust chain"
        fi
    fi
    # Check :latest or no tag
    if echo "$img" | grep -qE ':latest$' || ! echo "$img" | grep -q ':'; then
        log FAIL CODE C-05 "Image '${img}' uses :latest or has no version tag — no reproducibility/pinning"
    else
        log PASS CODE C-05 "Image '${img}' has explicit version tag"
    fi
done < <(grep -h 'image:' $COMPOSE_FILES 2>/dev/null | awk '{print $2}' | sort -u)

# C-06: Uncommitted port exposure in app.yaml / db.yaml
echo "--- C-06: Port exposure in committed YAML ---" >> "$REPORT_FILE"
COMMITTED_APP_PORTS=$(git show HEAD:app.yaml 2>/dev/null | grep -A3 'ports:' | grep -E ':\d+' || true)
COMMITTED_DB_PORTS=$(git show HEAD:db.yaml 2>/dev/null | grep -A3 'ports:' | grep -E ':\d+' || true)
if [[ -n "$COMMITTED_APP_PORTS" ]]; then
    log FAIL CODE C-06 "app.yaml (committed HEAD) exposes Strapi port directly: ${COMMITTED_APP_PORTS//[[:space:]]/ }"
else
    log PASS CODE C-06 "app.yaml (committed HEAD) does not expose Strapi port directly"
fi
if [[ -n "$COMMITTED_DB_PORTS" ]]; then
    log FAIL CODE C-06 "db.yaml (committed HEAD) exposes PostgreSQL port directly: ${COMMITTED_DB_PORTS//[[:space:]]/ }"
else
    log PASS CODE C-06 "db.yaml (committed HEAD) does not expose PostgreSQL port directly"
fi
# Also check working tree
WORKING_APP_PORTS=$(grep -A3 'ports:' app.yaml 2>/dev/null | grep -E ':\d+' || true)
WORKING_DB_PORTS=$(grep -A3 'ports:' db.yaml 2>/dev/null | grep -E ':\d+' || true)
if [[ -n "$WORKING_APP_PORTS" ]]; then
    log WARN CODE C-06 "app.yaml (working tree) still exposes Strapi port — uncommitted fix not deployed"
fi
if [[ -n "$WORKING_DB_PORTS" ]]; then
    log WARN CODE C-06 "db.yaml (working tree) still exposes PostgreSQL port — uncommitted fix not deployed"
fi

# C-07: Domain mismatch
echo "--- C-07: Domain consistency ---" >> "$REPORT_FILE"
CADDYFILE_DOMAIN=$(grep -E '^\S+\s*\{' Caddyfile 2>/dev/null | awk '{print $1}' | head -1 || true)
README_DOMAIN=$(grep -oE 'cyberhub-s1\.[a-z]+' README.md 2>/dev/null | head -1 || true)
if [[ -z "$CADDYFILE_DOMAIN" ]]; then
    log WARN CODE C-07 "Could not parse domain from Caddyfile"
elif [[ "$CADDYFILE_DOMAIN" != "$README_DOMAIN" ]]; then
    log FAIL CODE C-07 "Domain mismatch: Caddyfile uses '${CADDYFILE_DOMAIN}', README references '${README_DOMAIN}'"
else
    log PASS CODE C-07 "Domain is consistent across Caddyfile and README (${CADDYFILE_DOMAIN})"
fi

# C-08: Typo in env.simple
echo "--- C-08: env.simple key correctness ---" >> "$REPORT_FILE"
if grep -q 'AMDIN_EMAIL' env.simple 2>/dev/null; then
    log FAIL CODE C-08 "Typo 'AMDIN_EMAIL' in env.simple — should be 'ADMIN_EMAIL' (causes misconfigured deployments)"
else
    log PASS CODE C-08 "No typo found in env.simple"
fi

# =============================================================================
# SECTION 2: SERVER — Port & Network Exposure
# =============================================================================
section "2. SERVER — Port & Network Exposure"

if ! stack_running; then
    log SKIP SERVER S-01 "Stack not running — start with 'docker compose up -d' for server tests"
    log SKIP SERVER S-02 "Stack not running"
    log SKIP SERVER S-03 "Stack not running"
else
    # S-01: Port scan
    echo "--- S-01: Open ports on localhost ---" >> "$REPORT_FILE"
    if check_command nmap; then
        echo "  Running nmap port scan (this may take a moment)..." | tee -a "$REPORT_FILE"
        NMAP_OUT=$(nmap -T4 -p 80,443,1337,5432,8040,8080 127.0.0.1 2>/dev/null || true)
        echo "$NMAP_OUT" >> "$REPORT_FILE"

        for port_check in "80/open" "443/open"; do
            port="${port_check%/*}"; expected="${port_check#*/}"
            actual=$(echo "$NMAP_OUT" | grep "^${port}/tcp" | awk '{print $2}' || true)
            if [[ "$actual" == "$expected" ]]; then
                log PASS SERVER S-01 "Port ${port} is ${expected} (expected)"
            else
                log WARN SERVER S-01 "Port ${port} state: '${actual}' (expected: ${expected})"
            fi
        done
        for port in 1337 5432 8040; do
            actual=$(echo "$NMAP_OUT" | grep "^${port}/tcp" | awk '{print $2}' || true)
            if [[ "$actual" == "open" ]]; then
                log FAIL SERVER S-01 "Port ${port} is OPEN on host — service bypasses reverse proxy"
            else
                log PASS SERVER S-01 "Port ${port} is not exposed on host (state: ${actual:-closed/filtered})"
            fi
        done
    else
        log SKIP SERVER S-01 "nmap not installed — install with: sudo apt install nmap"
    fi

    # S-02: pgAdmin external exposure
    echo "--- S-02: pgAdmin external interface binding ---" >> "$REPORT_FILE"
    HOST_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}' || true)
    if [[ -n "$HOST_IP" ]]; then
        EXT_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
            "http://${HOST_IP}:8080" 2>/dev/null || true)
        EXT_CODE="${EXT_CODE:-000}"
        if [[ "$EXT_CODE" != "000" ]]; then
            log FAIL SERVER S-02 "pgAdmin reachable on external interface ${HOST_IP}:8080 (HTTP ${EXT_CODE})"
        else
            log PASS SERVER S-02 "pgAdmin NOT reachable on external interface ${HOST_IP}:8080"
        fi
    else
        log WARN SERVER S-02 "Could not determine external IP — skipping external pgAdmin check"
    fi
    LOC_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:8080" 2>/dev/null || true)
    LOC_CODE="${LOC_CODE:-000}"
    if [[ "$LOC_CODE" =~ ^[23] ]]; then
        log PASS SERVER S-02 "pgAdmin accessible on localhost (127.0.0.1:8080) as expected"
    else
        log WARN SERVER S-02 "pgAdmin returned HTTP ${LOC_CODE} on 127.0.0.1:8080 — may not be running"
    fi

    # S-03: Direct internal service access
    echo "--- S-03: Direct access to internal services ---" >> "$REPORT_FILE"
    STRAPI_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:1337" 2>/dev/null || true)
    STRAPI_CODE="${STRAPI_CODE:-000}"
    if [[ "$STRAPI_CODE" == "000" ]]; then
        log PASS SERVER S-03 "Strapi port 1337 NOT accessible from host"
    else
        log FAIL SERVER S-03 "Strapi port 1337 is accessible from host (HTTP ${STRAPI_CODE}) — bypasses Caddy"
    fi

    APP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "http://127.0.0.1:8040" 2>/dev/null || true)
    APP_CODE="${APP_CODE:-000}"
    if [[ "$APP_CODE" == "000" ]]; then
        log PASS SERVER S-03 "Strapi APP_PORT 8040 NOT accessible from host"
    else
        log FAIL SERVER S-03 "Strapi APP_PORT 8040 is accessible from host (HTTP ${APP_CODE}) — bypasses Caddy"
    fi

    if timeout 3 bash -c 'echo "" > /dev/tcp/127.0.0.1/5432' 2>/dev/null; then
        log FAIL SERVER S-03 "PostgreSQL port 5432 is accessible from host — database directly reachable"
    else
        log PASS SERVER S-03 "PostgreSQL port 5432 NOT accessible from host"
    fi
fi

# =============================================================================
# SECTION 3: WEB — HTTP / TLS / Headers
# =============================================================================
section "3. WEB — HTTP / TLS / Headers"

if ! stack_running; then
    log SKIP WEB "W-01~W-07" "Stack not running — start with 'docker compose up -d' for web tests"
elif ! dns_configured; then
    log SKIP WEB "W-01~W-07" "DNS not configured — run: echo '127.0.0.1 ${TARGET_HOST}' | sudo tee -a /etc/hosts"
else
    # W-01: HTTP to HTTPS redirect
    echo "--- W-01: HTTP to HTTPS redirect ---" >> "$REPORT_FILE"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "${TARGET_HTTP}" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "301" || "$HTTP_CODE" == "302" ]]; then
        LOCATION=$(curl -sI --max-time 5 "${TARGET_HTTP}" 2>/dev/null \
            | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
        if echo "$LOCATION" | grep -qi 'https://'; then
            log PASS WEB W-01 "HTTP redirects to HTTPS (${HTTP_CODE} → ${LOCATION})"
        else
            log FAIL WEB W-01 "HTTP redirects but NOT to HTTPS (location: ${LOCATION})"
        fi
    elif [[ "$HTTP_CODE" == "000" ]]; then
        log WARN WEB W-01 "Cannot reach ${TARGET_HTTP} — check if stack is up and DNS is set"
    else
        log FAIL WEB W-01 "HTTP does not redirect (status ${HTTP_CODE}) — content served over plain HTTP"
    fi

    # W-02: TLS certificate
    echo "--- W-02: TLS certificate ---" >> "$REPORT_FILE"
    TLS_INFO=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:443 \
        -servername "${TARGET_HOST}" 2>/dev/null || true)
    if [[ -n "$TLS_INFO" ]]; then
        ISSUER=$(echo "$TLS_INFO" | openssl x509 -noout -issuer 2>/dev/null || true)
        SUBJECT=$(echo "$TLS_INFO" | openssl x509 -noout -subject 2>/dev/null || true)
        EXPIRY=$(echo "$TLS_INFO" | openssl x509 -noout -enddate 2>/dev/null || true)
        log INFO WEB W-02 "Issuer: ${ISSUER}"
        log INFO WEB W-02 "Subject: ${SUBJECT}"
        log INFO WEB W-02 "Expiry: ${EXPIRY}"
        if echo "$ISSUER" | grep -qi 'caddy\|local\|self\|testing'; then
            log FAIL WEB W-02 "TLS certificate is self-signed (tls internal) — not trusted by browsers"
        else
            log PASS WEB W-02 "TLS certificate signed by external CA"
        fi
        # TLS version check
        for tls_flag in tls1 tls1_1; do
            TLS_RESULT=$(echo | timeout 3 openssl s_client -connect 127.0.0.1:443 \
                -"${tls_flag}" 2>&1 | grep -iE 'CONNECTED|error|handshake failure' | head -1 || true)
            if echo "$TLS_RESULT" | grep -qi 'CONNECTED'; then
                log FAIL WEB W-02 "${tls_flag} is accepted — legacy TLS version should be disabled"
            else
                log PASS WEB W-02 "${tls_flag} is rejected (${TLS_RESULT:-no response})"
            fi
        done
    else
        log WARN WEB W-02 "Could not connect to TLS on 443 — Caddy may not be running"
    fi

    # W-03: Security headers
    echo "--- W-03: Security headers ---" >> "$REPORT_FILE"
    RESP_HEADERS=$(curl -skI --max-time 5 "${TARGET_HTTPS}" 2>/dev/null || true)
    declare -A REQUIRED_HEADERS=(
        ["strict-transport-security"]="HSTS"
        ["content-security-policy"]="CSP"
        ["x-frame-options"]="Clickjacking protection"
        ["x-content-type-options"]="MIME sniffing protection"
        ["referrer-policy"]="Referrer Policy"
        ["permissions-policy"]="Permissions Policy"
    )
    for header in "${!REQUIRED_HEADERS[@]}"; do
        label="${REQUIRED_HEADERS[$header]}"
        if echo "$RESP_HEADERS" | grep -qi "^${header}:"; then
            val=$(echo "$RESP_HEADERS" | grep -i "^${header}:" | tr -d '\r' | head -1)
            log PASS WEB W-03 "${label} header present: ${val}"
        else
            log FAIL WEB W-03 "${label} (${header}) header MISSING"
        fi
    done

    # W-04: Information disclosure in headers
    echo "--- W-04: Server info disclosure ---" >> "$REPORT_FILE"
    SERVER_HDR=$(echo "$RESP_HEADERS" | grep -i '^server:' | tr -d '\r' || true)
    POWERED_HDR=$(echo "$RESP_HEADERS" | grep -i '^x-powered-by:' | tr -d '\r' || true)
    if [[ -n "$SERVER_HDR" ]]; then
        log WARN WEB W-04 "Server header exposes software version: ${SERVER_HDR}"
    else
        log PASS WEB W-04 "No Server header in response"
    fi
    if [[ -n "$POWERED_HDR" ]]; then
        log WARN WEB W-04 "X-Powered-By header exposes stack info: ${POWERED_HDR}"
    else
        log PASS WEB W-04 "No X-Powered-By header in response"
    fi

    # W-05: CORS
    echo "--- W-05: CORS configuration ---" >> "$REPORT_FILE"
    CORS_RESP=$(curl -sk --max-time 5 \
        -H "Origin: https://evil.com" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: Authorization,Content-Type" \
        -X OPTIONS "${TARGET_HTTPS}/api/" 2>/dev/null || true)
    ACAO=$(echo "$CORS_RESP" | grep -i 'access-control-allow-origin' | tr -d '\r' || true)
    if echo "$ACAO" | grep -q '\*'; then
        log FAIL WEB W-05 "Wildcard CORS (Access-Control-Allow-Origin: *) — all origins permitted"
    elif echo "$ACAO" | grep -qi 'evil.com'; then
        log FAIL WEB W-05 "Arbitrary origin reflected in ACAO header — CORS misconfiguration"
    elif [[ -z "$ACAO" ]]; then
        log PASS WEB W-05 "No wildcard CORS headers on /api/ (may use application-level CORS)"
    else
        log PASS WEB W-05 "CORS restricted: ${ACAO}"
    fi

    # W-06: Cookie security flags
    echo "--- W-06: Cookie security flags ---" >> "$REPORT_FILE"
    COOKIES=$(curl -skI --max-time 5 "${TARGET_HTTPS}/admin" 2>/dev/null \
        | grep -i '^set-cookie:' | tr -d '\r' || true)
    if [[ -z "$COOKIES" ]]; then
        log INFO WEB W-06 "No Set-Cookie headers on /admin (may require POST auth)"
    else
        while IFS= read -r cookie_line; do
            [[ -z "$cookie_line" ]] && continue
            COOKIE_NAME=$(echo "$cookie_line" | grep -o 'Set-Cookie: [^=]*' | awk '{print $2}' || echo "unknown")
            if ! echo "$cookie_line" | grep -qi 'httponly'; then
                log FAIL WEB W-06 "Cookie missing HttpOnly flag: ${cookie_line:0:80}"
            else
                log PASS WEB W-06 "Cookie has HttpOnly flag: ${COOKIE_NAME}"
            fi
            if ! echo "$cookie_line" | grep -qi 'secure'; then
                log FAIL WEB W-06 "Cookie missing Secure flag: ${cookie_line:0:80}"
            else
                log PASS WEB W-06 "Cookie has Secure flag: ${COOKIE_NAME}"
            fi
            if ! echo "$cookie_line" | grep -qi 'samesite'; then
                log WARN WEB W-06 "Cookie missing SameSite attribute: ${COOKIE_NAME}"
            else
                log PASS WEB W-06 "Cookie has SameSite attribute: ${COOKIE_NAME}"
            fi
        done <<< "$COOKIES"
    fi

    # W-07: Rate limiting
    echo "--- W-07: Rate limiting ---" >> "$REPORT_FILE"
    echo "  Testing rate limiting (30 rapid requests)..." | tee -a "$REPORT_FILE"
    THROTTLED=0
    for i in $(seq 1 30); do
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 2 \
            "${TARGET_HTTPS}/admin" 2>/dev/null || echo "000")
        [[ "$CODE" == "429" ]] && ((THROTTLED++))
    done
    if [[ "$THROTTLED" -gt 0 ]]; then
        log PASS WEB W-07 "Rate limiting active (${THROTTLED}/30 requests returned 429)"
    else
        log FAIL WEB W-07 "No rate limiting — 30 rapid requests to /admin all accepted (brute force unprotected)"
    fi
fi

# =============================================================================
# SECTION 4: API — Strapi Endpoint Security
# =============================================================================
section "4. API — Strapi Endpoint Security"

if ! stack_running; then
    log SKIP API "A-01~A-06" "Stack not running — start with 'docker compose up -d' for API tests"
elif ! dns_configured; then
    log SKIP API "A-01~A-06" "DNS not configured — run: echo '127.0.0.1 ${TARGET_HOST}' | sudo tee -a /etc/hosts"
else
    # A-01: Content-type builder without auth
    echo "--- A-01: Unauthenticated API access ---" >> "$REPORT_FILE"
    CTB_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        "${TARGET_HTTPS}/api/content-type-builder/content-types" 2>/dev/null || echo "000")
    CTB_RESP=$(curl -sk --max-time 5 \
        "${TARGET_HTTPS}/api/content-type-builder/content-types" 2>/dev/null || true)
    if echo "$CTB_RESP" | grep -qi '"data":\['; then
        log FAIL API A-01 "Content-type builder accessible without authentication (HTTP ${CTB_CODE})"
    else
        log PASS API A-01 "Content-type builder requires authentication (HTTP ${CTB_CODE})"
    fi

    # A-02: Admin registration endpoint
    echo "--- A-02: Admin registration endpoint ---" >> "$REPORT_FILE"
    REG_BODY='{"firstname":"Pentest","lastname":"User","email":"pentest@evil.com","password":"Pentest1234!"}'
    REG_RESP=$(curl -sk --max-time 5 -X POST \
        -H "Content-Type: application/json" \
        -d "$REG_BODY" \
        "${TARGET_HTTPS}/admin/register-admin" 2>/dev/null || true)
    REG_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -X POST \
        -H "Content-Type: application/json" \
        -d "$REG_BODY" \
        "${TARGET_HTTPS}/admin/register-admin" 2>/dev/null || echo "000")
    if echo "$REG_RESP" | grep -qi '"token"'; then
        log FAIL API A-02 "Admin registration SUCCEEDED — endpoint is open, unauthorized admin created"
    else
        log PASS API A-02 "Admin registration blocked (HTTP ${REG_CODE})"
    fi

    # A-03: User enumeration
    echo "--- A-03: User enumeration ---" >> "$REPORT_FILE"
    EXISTING_EMAIL=$(grep '^ADMIN_EMAIL=' .env 2>/dev/null | cut -d= -f2- | tr -d '\r' || echo "admin@example.com")
    FAKE_EMAIL="ghost_$(date +%s)@nowhere.invalid"
    RESP_EXISTING=$(curl -sk --max-time 5 -X POST \
        -H "Content-Type: application/json" \
        -d "{\"identifier\":\"${EXISTING_EMAIL}\",\"password\":\"WrongPwd!\"}" \
        "${TARGET_HTTPS}/api/auth/local" 2>/dev/null || true)
    RESP_FAKE=$(curl -sk --max-time 5 -X POST \
        -H "Content-Type: application/json" \
        -d "{\"identifier\":\"${FAKE_EMAIL}\",\"password\":\"WrongPwd!\"}" \
        "${TARGET_HTTPS}/api/auth/local" 2>/dev/null || true)
    MSG_EXISTING=$(echo "$RESP_EXISTING" | grep -o '"message":"[^"]*"' | head -1 || true)
    MSG_FAKE=$(echo "$RESP_FAKE" | grep -o '"message":"[^"]*"' | head -1 || true)
    if [[ "$MSG_EXISTING" != "$MSG_FAKE" && -n "$MSG_EXISTING" && -n "$MSG_FAKE" ]]; then
        log FAIL API A-03 "User enumeration possible — different error messages for valid vs invalid email"
        log INFO API A-03 "  Existing: ${MSG_EXISTING} | Fake: ${MSG_FAKE}"
    else
        log PASS API A-03 "Error messages identical for valid/invalid email (no user enumeration)"
    fi

    # A-04: GraphQL introspection
    echo "--- A-04: GraphQL introspection ---" >> "$REPORT_FILE"
    GQL_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        -X POST -H "Content-Type: application/json" \
        -d '{"query":"{ __schema { types { name } } }"}' \
        "${TARGET_HTTPS}/graphql" 2>/dev/null || echo "000")
    GQL_RESP=$(curl -sk --max-time 5 -X POST \
        -H "Content-Type: application/json" \
        -d '{"query":"{ __schema { types { name } } }"}' \
        "${TARGET_HTTPS}/graphql" 2>/dev/null || true)
    if echo "$GQL_RESP" | grep -q '"__schema"'; then
        log FAIL API A-04 "GraphQL introspection enabled — full schema exposed to unauthenticated users"
    elif [[ "$GQL_CODE" == "404" ]]; then
        log PASS API A-04 "GraphQL endpoint not found (HTTP 404) — plugin not installed or disabled"
    else
        log INFO API A-04 "GraphQL returned HTTP ${GQL_CODE} — review manually"
    fi

    # A-05: Injection in API filter params
    echo "--- A-05: Injection in API parameters ---" >> "$REPORT_FILE"
    declare -a PAYLOADS=(
        "filters[name][\$eq]=test' OR '1'='1"
        "filters[id][\$ne]=0"
        "filters[password][\$ne]=invalid"
    )
    for payload in "${PAYLOADS[@]}"; do
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
            -G --data-urlencode "$payload" \
            "${TARGET_HTTPS}/api/users" 2>/dev/null || echo "000")
        if [[ "$CODE" == "500" ]]; then
            log FAIL API A-05 "Server error (500) on injection payload — possible unhandled injection: ${payload:0:50}"
        elif [[ "$CODE" == "400" || "$CODE" == "403" || "$CODE" == "401" ]]; then
            log PASS API A-05 "Injection payload rejected (HTTP ${CODE}): ${payload:0:50}"
        else
            log INFO API A-05 "Injection payload returned HTTP ${CODE}: ${payload:0:50}"
        fi
    done

    # A-06: Mass assignment / role escalation on register
    echo "--- A-06: Mass assignment on user registration ---" >> "$REPORT_FILE"
    MASS_BODY='{"username":"pentest_escalate","email":"pentest_esc@evil.com","password":"Test1234!","role":"admin","confirmed":true}'
    MASS_RESP=$(curl -sk --max-time 5 -X POST \
        -H "Content-Type: application/json" \
        -d "$MASS_BODY" \
        "${TARGET_HTTPS}/api/auth/local/register" 2>/dev/null || true)
    MASS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -X POST \
        -H "Content-Type: application/json" \
        -d "$MASS_BODY" \
        "${TARGET_HTTPS}/api/auth/local/register" 2>/dev/null || echo "000")
    ROLE_IN_RESP=$(echo "$MASS_RESP" | grep -o '"type":"[^"]*"' | head -1 || true)
    if echo "$ROLE_IN_RESP" | grep -qi '"type":"admin"'; then
        log FAIL API A-06 "Mass assignment succeeded — registered user got admin role"
    elif echo "$MASS_RESP" | grep -qi '"jwt"'; then
        log WARN API A-06 "Registration succeeded (HTTP ${MASS_CODE}) — verify role assignment is not admin"
        log INFO API A-06 "  Role in response: ${ROLE_IN_RESP}"
    else
        log PASS API A-06 "Public registration with elevated role correctly rejected (HTTP ${MASS_CODE})"
    fi
fi

# =============================================================================
# SECTION 5: DEPENDENCY — Image CVE Scanning
# =============================================================================
section "5. DEPENDENCY — Docker Image CVE Scanning"

if ! check_command docker; then
    log SKIP DEP "D-01~D-03" "Docker not available"
else
    IMAGES=("prawee/strapi:latest" "postgres:16" "caddy:latest" "dpage/pgadmin4")

    # D-01: Trivy CVE scan
    echo "--- D-01: CVE scan with Trivy ---" >> "$REPORT_FILE"
    TRIVY_CMD=""
    if check_command trivy; then
        TRIVY_CMD="trivy image --severity HIGH,CRITICAL --no-progress --quiet"
    elif docker image inspect aquasec/trivy &>/dev/null 2>&1; then
        TRIVY_CMD="docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image --severity HIGH,CRITICAL --no-progress --quiet"
    fi

    if [[ -n "$TRIVY_CMD" ]]; then
        for img in "${IMAGES[@]}"; do
            echo "  Scanning ${img}..." | tee -a "$REPORT_FILE"
            SCAN_OUT=$($TRIVY_CMD "$img" 2>/dev/null || true)
            CRITICAL_COUNT=$(echo "$SCAN_OUT" | grep -c 'CRITICAL' || true)
            HIGH_COUNT=$(echo "$SCAN_OUT" | grep -c 'HIGH' || true)
            echo "$SCAN_OUT" >> "$REPORT_FILE"
            if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
                log FAIL DEP D-01 "${img}: ${CRITICAL_COUNT} CRITICAL CVEs found"
            elif [[ "$HIGH_COUNT" -gt 0 ]]; then
                log WARN DEP D-01 "${img}: ${HIGH_COUNT} HIGH CVEs found (no CRITICAL)"
            else
                log PASS DEP D-01 "${img}: No HIGH/CRITICAL CVEs found"
            fi
        done
    else
        log SKIP DEP D-01 "Trivy not installed. Install: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
        log INFO DEP D-01 "Alternative: docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image prawee/strapi:latest"
    fi

    # D-02: Image digest pinning
    echo "--- D-02: Image digest pinning ---" >> "$REPORT_FILE"
    for img in "${IMAGES[@]}"; do
        DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$img" 2>/dev/null || true)
        # Check if compose file references the image with a digest
        IMG_BASE="${img%%:*}"
        PINNED=$(grep -r "$IMG_BASE@sha256" docker-compose.yaml app.yaml db.yaml proxy.yaml admin.yaml 2>/dev/null || true)
        if [[ -n "$PINNED" ]]; then
            log PASS DEP D-02 "${img} is digest-pinned in compose file"
        else
            log FAIL DEP D-02 "${img} NOT digest-pinned — supply chain risk (current digest: ${DIGEST:-unknown})"
        fi
    done

    # D-03: Image staleness
    echo "--- D-03: Image build date ---" >> "$REPORT_FILE"
    for img in "${IMAGES[@]}"; do
        BUILD_DATE=$(docker inspect --format='{{.Created}}' "$img" 2>/dev/null | cut -c1-10 || true)
        if [[ -n "$BUILD_DATE" ]]; then
            EPOCH_BUILD=$(date -d "$BUILD_DATE" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "$BUILD_DATE" +%s 2>/dev/null || echo 0)
            DAYS_OLD=$(( ($(date +%s) - EPOCH_BUILD) / 86400 ))
            if [[ "$DAYS_OLD" -gt 180 ]]; then
                log FAIL DEP D-03 "${img} built ${BUILD_DATE} (${DAYS_OLD} days ago) — likely has unpatched CVEs"
            elif [[ "$DAYS_OLD" -gt 90 ]]; then
                log WARN DEP D-03 "${img} built ${BUILD_DATE} (${DAYS_OLD} days ago) — consider updating"
            else
                log PASS DEP D-03 "${img} built ${BUILD_DATE} (${DAYS_OLD} days ago) — recently updated"
            fi
        else
            log SKIP DEP D-03 "${img} not pulled locally — cannot check build date"
        fi
    done
fi

# =============================================================================
# SECTION 6: CONTAINER — Runtime Security
# =============================================================================
section "6. CONTAINER — Runtime Security"

if ! stack_running; then
    log SKIP CONTAINER "CO-01~CO-07" "Stack not running — start with 'docker compose up -d' for container tests"
else
    CONTAINERS=("CyberHub-App" "CyberHub-Database" "CyberHub-Caddy")
    # Include CyberHub-Admin if running
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'CyberHub-Admin' \
        && CONTAINERS+=("CyberHub-Admin") || true

    # CO-01: Running as root
    echo "--- CO-01: Container user (root check) ---" >> "$REPORT_FILE"
    for c in "${CONTAINERS[@]}"; do
        USER_INFO=$(docker exec "$c" id 2>/dev/null || true)
        if [[ -z "$USER_INFO" ]]; then
            log SKIP CONTAINER CO-01 "${c}: exec failed — container may not accept shell"
        elif echo "$USER_INFO" | grep -q 'uid=0'; then
            log FAIL CONTAINER CO-01 "${c} running as root (${USER_INFO%%)*})"
        else
            log PASS CONTAINER CO-01 "${c} running as non-root (${USER_INFO%%)*})"
        fi
    done

    # CO-02: no-new-privileges
    echo "--- CO-02: no-new-privileges ---" >> "$REPORT_FILE"
    for c in "${CONTAINERS[@]}"; do
        SEC_OPT=$(docker inspect --format='{{.HostConfig.SecurityOpt}}' "$c" 2>/dev/null || true)
        if echo "$SEC_OPT" | grep -q 'no-new-privileges'; then
            log PASS CONTAINER CO-02 "${c}: no-new-privileges is set"
        else
            log FAIL CONTAINER CO-02 "${c}: no-new-privileges NOT set — setuid binaries can escalate"
        fi
    done

    # CO-03: Read-only root filesystem
    echo "--- CO-03: Read-only root filesystem ---" >> "$REPORT_FILE"
    for c in "${CONTAINERS[@]}"; do
        RO=$(docker inspect --format='{{.HostConfig.ReadonlyRootfs}}' "$c" 2>/dev/null || true)
        if [[ "$RO" == "true" ]]; then
            log PASS CONTAINER CO-03 "${c}: root filesystem is read-only"
        else
            log FAIL CONTAINER CO-03 "${c}: root filesystem is writable — malware could persist to disk"
        fi
    done

    # CO-04: Dangerous capabilities / privileged
    echo "--- CO-04: Linux capabilities & privileged mode ---" >> "$REPORT_FILE"
    DANGEROUS="SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|DAC_OVERRIDE|CAP_SYS_ADMIN"
    for c in "${CONTAINERS[@]}"; do
        PRIV=$(docker inspect --format='{{.HostConfig.Privileged}}' "$c" 2>/dev/null || true)
        CAPS=$(docker inspect --format='{{.HostConfig.CapAdd}}' "$c" 2>/dev/null || true)
        if [[ "$PRIV" == "true" ]]; then
            log FAIL CONTAINER CO-04 "${c}: running in PRIVILEGED mode — full host access"
        else
            log PASS CONTAINER CO-04 "${c}: not running in privileged mode"
        fi
        if echo "$CAPS" | grep -qE "$DANGEROUS"; then
            log FAIL CONTAINER CO-04 "${c}: dangerous capability added: ${CAPS}"
        else
            log PASS CONTAINER CO-04 "${c}: no dangerous capabilities added (${CAPS:-[]})"
        fi
    done

    # CO-05: Network segmentation
    echo "--- CO-05: Network isolation ---" >> "$REPORT_FILE"
    for c in "${CONTAINERS[@]}"; do
        NETS=$(docker inspect --format='{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c" 2>/dev/null || true)
        if echo "$NETS" | grep -wq 'bridge'; then
            log FAIL CONTAINER CO-05 "${c} is on the default 'bridge' network — bypasses cyberhub-network isolation"
        elif echo "$NETS" | grep -q 'cyberhub'; then
            log PASS CONTAINER CO-05 "${c} is on cyberhub-network only"
        else
            log WARN CONTAINER CO-05 "${c} network: '${NETS}' — verify isolation"
        fi
    done

    # CO-06: Sensitive host volume mounts
    echo "--- CO-06: Volume mount security ---" >> "$REPORT_FILE"
    SENSITIVE='\(/etc\|/proc\|/sys\|/dev\|/root\|/var/run/docker\.sock\)'
    for c in "${CONTAINERS[@]}"; do
        MOUNTS=$(docker inspect --format='{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' "$c" 2>/dev/null || true)
        SENSITIVE_FOUND=$(echo "$MOUNTS" | grep -E "$SENSITIVE" || true)
        if [[ -n "$SENSITIVE_FOUND" ]]; then
            log FAIL CONTAINER CO-06 "${c}: sensitive host path mounted: ${SENSITIVE_FOUND}"
        else
            log PASS CONTAINER CO-06 "${c}: no sensitive host paths mounted"
        fi
    done

    # CO-07: Caddy TLS certificate persistence
    echo "--- CO-07: Caddy TLS volume persistence ---" >> "$REPORT_FILE"
    CADDY_MOUNTS=$(docker inspect --format='{{range .Mounts}}{{.Destination}}{{"\n"}}{{end}}' \
        CyberHub-Caddy 2>/dev/null || true)
    if echo "$CADDY_MOUNTS" | grep -q '/data'; then
        log PASS CONTAINER CO-07 "Caddy /data volume is persistent — TLS certificates survive restarts"
    else
        log FAIL CONTAINER CO-07 "Caddy /data NOT mounted — TLS certificates lost on container restart (Let's Encrypt rate limit risk)"
    fi
    if echo "$CADDY_MOUNTS" | grep -q '/config'; then
        log PASS CONTAINER CO-07 "Caddy /config volume is persistent"
    else
        log WARN CONTAINER CO-07 "Caddy /config NOT mounted — Caddy config not persistent across restarts"
    fi
fi

# =============================================================================
# SECTION 7: SUMMARY
# =============================================================================
section "7. SUMMARY"

TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))

echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  CyberHub-S1 Security Assessment — Results${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "  Date:     $(date)"
echo -e "  Report:   ${REPORT_FILE}"
echo ""
echo -e "  Total checks : ${TOTAL}"
echo -e "  ${GREEN}PASS${RESET}         : ${PASS_COUNT}"
echo -e "  ${RED}FAIL${RESET}         : ${FAIL_COUNT}"
echo -e "  ${YELLOW}WARN${RESET}         : ${WARN_COUNT}"
echo -e "  ${CYAN}SKIP${RESET}         : ${SKIP_COUNT}"
echo ""

SNAPSHOT=$(cat "$REPORT_FILE")

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo -e "${BOLD}${RED}  ── FAILURES ──${RESET}"
    echo "$SNAPSHOT" | grep '^\[FAIL\]' | while IFS= read -r line; do
        echo -e "  ${RED}${line}${RESET}"
    done
    echo ""
fi

if [[ "$WARN_COUNT" -gt 0 ]]; then
    echo -e "${BOLD}${YELLOW}  ── WARNINGS ──${RESET}"
    echo "$SNAPSHOT" | grep '^\[WARN\]' | while IFS= read -r line; do
        echo -e "  ${YELLOW}${line}${RESET}"
    done
    echo ""
fi

echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "  Full report saved to: ${BOLD}${REPORT_FILE}${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""

# Write summary to report file (SNAPSHOT already captured above)
{
    echo ""
    echo "==============================="
    echo "SUMMARY"
    echo "Total: ${TOTAL} | PASS: ${PASS_COUNT} | FAIL: ${FAIL_COUNT} | WARN: ${WARN_COUNT} | SKIP: ${SKIP_COUNT}"
    echo ""
    echo "FAILURES:"
    echo "$SNAPSHOT" | grep '^\[FAIL\]' || echo "  (none)"
    echo ""
    echo "WARNINGS:"
    echo "$SNAPSHOT" | grep '^\[WARN\]' || echo "  (none)"
} >> "$REPORT_FILE"

# Exit with error code if any failures found
[[ "$FAIL_COUNT" -gt 0 ]] && exit 1 || exit 0
