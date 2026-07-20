#!/usr/bin/env bash
# telego SYN limiter — telemt two-tier scheme (iOS lane + generic lane) in DOCKER-USER.
# Usage: sudo ./synlimit.sh <port> [apply|clear]   (default: apply)
set -euo pipefail

PORT="${1:?usage: $0 <port> [apply|clear]}"
ACTION="${2:-apply}"

# --- telemt defaults ---
GEN_RATE="48/minute"    # 48 SYN / 60s  (~0.8/sec)  -- Android/desktop lane
GEN_BURST=1
IOS_RATE="12/second"    # 12 SYN / 1s                -- iOS lane
IOS_BURST=24
IOS_LEN_V4=64           # iOS SYN total packet length
IOS_LEN_V6=84
IOS_TTL=65              # match ttl/hoplimit < 65
HT_EXPIRE=60000         # hashlimit htable entry expiry (ms)
HT_SIZE=32768           # hashlimit htable size
CHAIN="DOCKER-USER"
TAG="telego-syn-${PORT}"

have_chain() { "$1" -L "$CHAIN" -n >/dev/null 2>&1; }

clear_family() {
  local ipt="$1"
  have_chain "$ipt" || return 0
  while :; do
    local n
    n=$("$ipt" -L "$CHAIN" --line-numbers -n 2>/dev/null | awk -v t="$TAG" '$0 ~ t {print $1; exit}')
    [ -n "${n:-}" ] || break
    "$ipt" -D "$CHAIN" "$n"
  done
}

apply_family() {
  local ipt="$1" len="$2" ttlmatch="$3" ios_tag="$4" gen_tag="$5"
  have_chain "$ipt" || { echo "[$ipt] no $CHAIN chain, skipping"; return 0; }
  # order (top->bottom): ios-accept, ios-reject, generic-accept, generic-reject
  "$ipt" -I "$CHAIN" 1 -p tcp --dport "$PORT" --syn \
    -m length --length "$len" $ttlmatch "$IOS_TTL" \
    -m hashlimit --hashlimit-mode srcip --hashlimit-name "$ios_tag" \
    --hashlimit-upto "$IOS_RATE" --hashlimit-burst "$IOS_BURST" \
    --hashlimit-htable-expire "$HT_EXPIRE" --hashlimit-htable-size "$HT_SIZE" \
    -m comment --comment "$TAG" -j ACCEPT
  "$ipt" -I "$CHAIN" 2 -p tcp --dport "$PORT" --syn \
    -m length --length "$len" $ttlmatch "$IOS_TTL" \
    -m comment --comment "$TAG" -j REJECT --reject-with tcp-reset
  "$ipt" -I "$CHAIN" 3 -p tcp --dport "$PORT" --syn \
    -m hashlimit --hashlimit-mode srcip --hashlimit-name "$gen_tag" \
    --hashlimit-upto "$GEN_RATE" --hashlimit-burst "$GEN_BURST" \
    --hashlimit-htable-expire "$HT_EXPIRE" --hashlimit-htable-size "$HT_SIZE" \
    -m comment --comment "$TAG" -j ACCEPT
  "$ipt" -I "$CHAIN" 4 -p tcp --dport "$PORT" --syn \
    -m comment --comment "$TAG" -j REJECT --reject-with tcp-reset
  echo "[$ipt] applied two-tier SYN limit on port $PORT"
}

case "$ACTION" in
  apply)
    clear_family iptables;  clear_family ip6tables
    apply_family iptables  "$IOS_LEN_V4" "-m ttl --ttl-lt" "tgs_i4_${PORT}" "tgs_g4_${PORT}"
    apply_family ip6tables "$IOS_LEN_V6" "-m hl --hl-lt"   "tgs_i6_${PORT}" "tgs_g6_${PORT}"
    ;;
  clear)
    clear_family iptables;  clear_family ip6tables
    echo "cleared telego SYN limit rules for port $PORT"
    ;;
  *) echo "unknown action: $ACTION (use apply|clear)"; exit 1 ;;
esac

echo "--- iptables $CHAIN ---";  iptables  -L "$CHAIN" -n -v --line-numbers | grep -E "Chain|$TAG" || true
echo "--- ip6tables $CHAIN ---"; ip6tables -L "$CHAIN" -n -v --line-numbers 2>/dev/null | grep -E "Chain|$TAG" || true
