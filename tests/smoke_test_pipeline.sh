#!/usr/bin/env bash
# smoke_test_pipeline.sh — end-to-end: sample logs → Fluentbit → Loki
# Run from any directory. Requires: docker, curl, python3.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/docker"
DATA_RAW="$PROJECT_ROOT/data/raw"
LOKI_URL="http://localhost:3100"

PASS=0
FAIL=0

# ── Helpers ──────────────────────────────────────────────────────────────────

ok()   { echo "  ✓ PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ FAIL: $*"; FAIL=$((FAIL + 1)); }

wait_for_url() {
    local url="$1" max_secs="$2" i
    for i in $(seq 1 "$max_secs"); do
        if curl -sf "$url" > /dev/null 2>&1; then return 0; fi
        sleep 1
        printf "."
    done
    echo ""
    return 1
}

# Query Loki for a given source label; retries up to $3 times with 5s gap.
# Returns 0 and prints entry count if data found; 1 if not.
query_loki_source() {
    local source="$1" max_retries="${2:-3}" attempt count response
    local start end
    # 24-hour window covers both historical log timestamps and ingestion-time records
    start=$(( $(date +%s) - 86400 ))000000000
    end=$(date +%s)000000000

    for attempt in $(seq 1 "$max_retries"); do
        response=$(curl -sf "$LOKI_URL/loki/api/v1/query_range" \
            -G \
            --data-urlencode "query={source=\"$source\"}" \
            -d "start=$start" \
            -d "end=$end" \
            -d "limit=10" 2>/dev/null) || true

        count=$(echo "$response" | python3 - <<'EOF'
import sys, json
try:
    d = json.load(sys.stdin)
    results = d.get("data", {}).get("result", [])
    total = sum(len(r.get("values", [])) for r in results)
    print(total)
except Exception:
    print(0)
EOF
)
        if [[ "${count:-0}" -gt 0 ]]; then
            echo "$count"
            return 0
        fi
        [[ $attempt -lt $max_retries ]] && sleep 5
    done
    echo "0"
    return 1
}

# ── Main ─────────────────────────────────────────────────────────────────────

echo "================================================================"
echo " Smoke Test: sample logs → Fluentbit → Loki"
echo "================================================================"
echo ""

# ── Step 1: Stage sample files ───────────────────────────────────────────────
echo "[1/4] Staging sample files into data/raw/ ..."

for pair in \
    "nginx_sample.log:nginx_access.log" \
    "auth_sample.log:auth.log" \
    "pfsense_sample.csv:pfsense.csv"
do
    src="${pair%%:*}"
    dst="${pair##*:}"
    if [[ ! -f "$DATA_RAW/$src" ]]; then
        echo "  ERROR: $DATA_RAW/$src not found"
        exit 1
    fi
    cp "$DATA_RAW/$src" "$DATA_RAW/$dst"
    echo "  → $src → data/raw/$dst"
done

# ── Step 2: Start stack ───────────────────────────────────────────────────────
echo ""
echo "[2/4] Starting docker compose stack (clean containers, keep volumes) ..."
cd "$DOCKER_DIR"
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d
echo "  → containers starting"

# ── Step 3: Wait for Loki ─────────────────────────────────────────────────────
echo ""
echo "[3/4] Waiting for Loki /ready (max 60s) ..."
printf "  "
if wait_for_url "$LOKI_URL/ready" 60; then
    echo "  → Loki ready"
else
    echo ""
    echo "  ERROR: Loki did not become ready within 60s"
    echo "  Debug: docker logs loki --tail 20"
    exit 1
fi

# ── Step 4: Wait for Fluentbit flush ─────────────────────────────────────────
echo ""
echo "[4/4] Waiting 20s for Fluentbit to process and flush logs ..."
sleep 20
echo "  → done waiting"

# ── Assertions ────────────────────────────────────────────────────────────────
echo ""
echo "----------------------------------------------------------------"
echo " Querying Loki (up to 3 retries per source, 5s apart)"
echo "----------------------------------------------------------------"

for source in nginx auth firewall; do
    printf "  source=%-10s ... " "$source"
    count=$(query_loki_source "$source" 3) && found=true || found=false
    if $found && [[ "${count:-0}" -gt 0 ]]; then
        ok "source=$source — $count entries in Loki"
    else
        fail "source=$source — 0 entries found"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "================================================================"
if [[ $FAIL -eq 0 ]]; then
    echo " PASS — all $PASS sources verified in Loki"
    echo "================================================================"
    exit 0
else
    echo " FAIL — $FAIL of $((PASS + FAIL)) sources missing data"
    echo "================================================================"
    echo ""
    echo "Fluentbit logs (last 40 lines):"
    docker logs fluentbit --tail 40 2>&1 | sed 's/^/  /'
    exit 1
fi
