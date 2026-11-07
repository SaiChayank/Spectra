#!/usr/bin/env bash
# Live-capture sizing rig (Phase B, docs/34 B.2 item 6).  MUST BE RUN BY A HUMAN WITH SUDO: it creates a veth pair, runs
# `spectra serve` as root (raw sockets) against it and replays a pcap with tcpreplay.  Nothing here has been run by the agent.
#
#   sudo scripts/bench_perf.sh <pcap> [rates...]        # rates in packets/s, default "1000 10000 50000 topspeed"
#
# Needs: ip (iproute2), tcpreplay, curl, jq, a venv with Spectra installed (`spectra` on PATH or SPECTRA_BIN=...).
# Per rate it records packets offered/received/queued/dropped (from /api/metrics), wall time, flows seen, and the server's
# CPU seconds and peak RSS (from /proc).  Publish the machine spec next to the numbers (lscpu, free -h, kernel).
set -euo pipefail
PCAP="${1:?usage: $0 <pcap> [rates...]}"; shift || true
RATES=("${@:-1000 10000 50000 topspeed}")
read -r -a RATES <<<"${RATES[*]}"
SPECTRA="${SPECTRA_BIN:-spectra}"
PORT="${PORT:-8899}"
DATA="$(mktemp -d)"; export SPECTRA_DATA_DIR="$DATA" SPECTRA_MODEL_PATH="$DATA/model.joblib"
A=veth-sp0; B=veth-sp1
cleanup() { [[ -n "${SRV:-}" ]] && kill "$SRV" 2>/dev/null || true; ip link del "$A" 2>/dev/null || true; rm -rf "$DATA"; }
trap cleanup EXIT
ip link add "$A" type veth peer name "$B"; ip link set "$A" up; ip link set "$B" up
"$SPECTRA" serve --port "$PORT" >"$DATA/server.log" 2>&1 & SRV=$!
for _ in $(seq 60); do curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null && break; sleep 1; done
PW="$(grep '^password=' "$DATA/admin_bootstrap.txt" | cut -d= -f2)"
JAR="$DATA/jar"; curl -sf -c "$JAR" -H 'content-type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$PW\"}" "http://127.0.0.1:$PORT/api/auth/login" >/dev/null
metric() { curl -sf -b "$JAR" "http://127.0.0.1:$PORT/api/metrics" | awk -v k="$1" '$1==k {print $2}'; }
echo "machine: $(lscpu | awk -F: '/Model name/ {gsub(/^ +/,"",$2); print $2}'), $(nproc) cpus, $(free -g | awk '/Mem/ {print $2}') GB RAM, kernel $(uname -r)"
printf '%-10s %12s %12s %12s %12s %9s %9s\n' rate offered received dropped flows cpu_s rss_mb
for r in "${RATES[@]}"; do
  curl -sf -b "$JAR" -X POST -H 'content-type: application/json' -d "{\"mode\":\"live\",\"iface\":\"$A\"}" \
    "http://127.0.0.1:$PORT/api/capture/start" >/dev/null
  sleep 2
  cpu0=$(awk '{print $14+$15}' /proc/$SRV/stat)
  if [[ "$r" == topspeed ]]; then tcpreplay --topspeed -i "$B" "$PCAP" >"$DATA/replay.txt" 2>&1
  else tcpreplay --pps="$r" -i "$B" "$PCAP" >"$DATA/replay.txt" 2>&1; fi
  sleep 3
  cpu1=$(awk '{print $14+$15}' /proc/$SRV/stat)
  offered=$(awk '/Successful packets/ {print $3}' "$DATA/replay.txt")
  rss=$(awk '/VmHWM/ {print int($2/1024)}' /proc/$SRV/status)
  printf '%-10s %12s %12s %12s %12s %9s %9s\n' "$r" "${offered:-?}" "$(metric spectra_queue_packets_received)" \
    "$(metric spectra_queue_packets_dropped)" "$(metric spectra_flows_total)" "$(( (cpu1-cpu0) / $(getconf CLK_TCK) ))" "$rss"
  curl -sf -b "$JAR" -X POST "http://127.0.0.1:$PORT/api/capture/stop" >/dev/null
done
