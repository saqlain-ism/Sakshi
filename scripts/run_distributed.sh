#!/usr/bin/env bash
# Runs every participant as a separate process on its own port, without Docker.
# Same code paths as docker-compose: real network calls between services.
#
#   ./scripts/run_distributed.sh        then open http://localhost:8000
#   (Ctrl+C stops everything)
set -euo pipefail
cd "$(dirname "$0")/.."

export NETWORK_SEED="${NETWORK_SEED:-sakshi-demo-network}" ADMIN_TOKEN="${ADMIN_TOKEN:-demo-admin-token}"
export REGISTRY_HOST=http://127.0.0.1:8101 GATEWAY_HOST=http://127.0.0.1:8102 LEDGER_HOST=http://127.0.0.1:8103 \
       ISSUER_HOST=http://127.0.0.1:8104 BAP_HOST=http://127.0.0.1:8105 BPP_KIRANA_HOST=http://127.0.0.1:8106 \
       BPP_BAZAAR_HOST=http://127.0.0.1:8107 BPP_LOCAL_HOST=http://127.0.0.1:8108 \
       CONSOLE_HOST=http://127.0.0.1:8000 ATTACKERS_HOST=http://127.0.0.1:8000
export PYTHONPATH="${PWD}/src${PYTHONPATH:+:$PYTHONPATH}"

pids=()
start() {  # role port [extra env...]
  local role=$1 port=$2; shift 2
  env SAKSHI_ROLE="$role" "$@" python -m uvicorn sakshi_network.app:create_app --factory \
      --host 127.0.0.1 --port "$port" --log-level warning &
  pids+=($!)
}
trap 'kill "${pids[@]}" 2>/dev/null' EXIT INT TERM

start registry 8101
start gateway 8102
start ledger 8103
start issuer 8104
start bap 8105
start bpp 8106 BPP_NAME=kirana
start bpp 8107 BPP_NAME=bazaar
start bpp 8108 BPP_NAME=local
sources=$(printf 'http://127.0.0.1:%s,' 8101 8102 8103 8104 8105 8106 8107 8108)
start console 8000 EVENT_SOURCES="${sources%,}"

echo "Sakshi is starting as 9 separate services. Dashboard: http://localhost:8000"
wait
