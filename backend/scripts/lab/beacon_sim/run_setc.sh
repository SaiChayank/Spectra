#!/usr/bin/env bash
# Set C (ci/prereg/e22.json H1).  usage: run_setc.sh <run-id> [duration_s]   e.g. run_setc.sh setc-$(date -u +%Y%m%dT%H%MZ)
set -euo pipefail
cd "$(dirname "$0")"
RUN_ID=$1 DURATION_S=${2:-57600}
export OUT_DIR="$HOME/Projects/Spectra_bench_data/setc/$RUN_ID" DURATION_S
[ ! -e "$OUT_DIR" ] || { echo "$OUT_DIR exists"; exit 1; }
docker build -q -t spectra-setb-sim:latest . >/dev/null
mkdir -p "$OUT_DIR" && chmod 777 "$OUT_DIR"  # containers run without DAC_OVERRIDE
python3 - "$RUN_ID" "$(docker image inspect -f '{{.Id}}' spectra-setb-sim:latest)" \
  "$(git rev-parse HEAD)" <<'P' > "$OUT_DIR/manifest.json"
import json, os, sys, datetime
import simsched
m = simsched.build_manifest_setc(duration_s=int(os.environ["DURATION_S"]))
m.update(run_id=sys.argv[1], image_id=sys.argv[2], git_commit=sys.argv[3],
         start_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
print(json.dumps(m, indent=1))
P
RUN_ID=$RUN_ID docker compose -f docker-compose.setc.yml up -d
