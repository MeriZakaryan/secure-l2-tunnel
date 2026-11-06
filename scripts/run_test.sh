#!/usr/bin/env bash
# End-to-end test: builds the topology, starts both devices and the MITM,
# transfers a 5 MB random file PC1 -> PC2 and compares SHA-256 hashes.
#
# Usage: sudo ./scripts/run_test.sh <inplace|udp> <forward|flip|replay|hs-tamper>
#        sudo ./scripts/run_test.sh all        # every combination, one result line each
set -uo pipefail
cd "$(dirname "$0")/.."

MODE=${1:-inplace}
ATTACK=${2:-forward}
LOG=logs

if [[ $EUID -ne 0 ]]; then echo "Run as root: sudo $0 $*"; exit 1; fi

# ---- "all": run every combination and print only the result lines ----
if [[ $MODE == all ]]; then
    for m in inplace udp; do
        for a in forward flip replay hs-tamper; do
            "$0" "$m" "$a" | tail -n 1
        done
    done
    exit 0
fi

case $MODE in inplace|udp) ;; *) echo "Unknown mode: $MODE"; exit 1 ;; esac
case $ATTACK in
    forward)   MITM_ARGS=() ;;
    flip)      MITM_ARGS=(-m flip -n 100) ;;
    replay)    MITM_ARGS=(-m replay -n 50) ;;
    hs-tamper) MITM_ARGS=(-m hs-tamper) ;;
    *) echo "Unknown attack: $ATTACK"; exit 1 ;;
esac

for b in device mitm sender receiver; do
    [[ -x $b ]] || { echo "Missing ./$b: run 'make' first"; exit 1; }
done
[[ -f keys/dev1_priv.pem && -f keys/dev2_priv.pem ]] || { echo "Missing keys: run ./scripts/genkeys.sh first"; exit 1; }

mkdir -p "$LOG"
rm -f "$LOG"/*.log "$LOG/out.bin"
./scripts/setup.sh > /dev/null
[[ -f $LOG/test.bin ]] || head -c 5M /dev/urandom > "$LOG/test.bin"

# ---- Start MITM, Device2, Device1 in the background ----
PIDS=()
stop_all() {
    for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
    wait "${PIDS[@]}" 2>/dev/null
    PIDS=()
}
trap stop_all EXIT

# stdbuf -oL: line-buffered output, so the logs can be read while the programs run
ip netns exec mitm stdbuf -oL ./mitm "${MITM_ARGS[@]}" mitm-left mitm-right > "$LOG/mitm.log" 2>&1 &
PIDS+=($!)
ip netns exec dev2 stdbuf -oL ./device -m "$MODE" 2 dev2-lan dev2-wan > "$LOG/dev2.log" 2>&1 &
PIDS+=($!)
ip netns exec dev1 stdbuf -oL ./device -m "$MODE" 1 dev1-lan dev1-wan > "$LOG/dev1.log" 2>&1 &
PIDS+=($!)

session_up() {
    grep -q "Secure session established" "$LOG/dev1.log" &&
    grep -q "Secure session established" "$LOG/dev2.log"
}
for _ in $(seq 1 10); do session_up && break; sleep 0.5; done

RESULT="[$MODE / $ATTACK]"

# ---- Handshake attack: success means NO session was established ----
if [[ $ATTACK == hs-tamper ]]; then
    sleep 3
    stop_all
    if ! session_up && grep -q "signature INVALID" "$LOG/dev1.log"; then
        echo "$RESULT PASS: tampered handshake rejected, no session established"
        exit 0
    fi
    echo "$RESULT FAIL: expected the handshake to be rejected"
    exit 1
fi

if ! session_up; then
    echo "$RESULT FAIL: no secure session (see $LOG/dev1.log and $LOG/dev2.log)"
    exit 1
fi

# ---- File transfer ----
ip netns exec pc2 ./receiver 5000 "$LOG/out.bin" > "$LOG/receiver.log" 2>&1 &
RPID=$!
sleep 0.5
timeout 60 ip netns exec pc1 ./sender 10.20.20.2 5000 "$LOG/test.bin" > "$LOG/sender.log" 2>&1
SENDER_RC=$?
[[ $SENDER_RC -ne 0 ]] && kill "$RPID" 2>/dev/null     # sender failed: don't wait forever
wait "$RPID" 2>/dev/null
stop_all                                               # devices print their statistics

# ---- Results ----
H1=$(sha256sum < "$LOG/test.bin" | cut -d' ' -f1)
H2=$([[ -f $LOG/out.bin ]] && sha256sum < "$LOG/out.bin" | cut -d' ' -f1)
echo "Device1: $(grep Stopped "$LOG/dev1.log")"
echo "MITM:    $(grep Stopped "$LOG/mitm.log")"
echo "Device2: $(grep Stopped "$LOG/dev2.log")"
echo "sha256 sent:     $H1"
echo "sha256 received: $H2"
DETECTED="auth_fail=$(grep -c 'AUTH FAIL' "$LOG/dev2.log"), replay=$(grep -c 'REPLAY' "$LOG/dev2.log")"

if [[ -n $H2 && $H1 == "$H2" ]]; then
    echo "$RESULT PASS: file identical ($DETECTED)"
else
    echo "$RESULT FAIL: file differs or missing ($DETECTED)"
    exit 1
fi