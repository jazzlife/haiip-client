#!/usr/bin/env bash
set -u -o pipefail

if (( EUID != 0 )); then
  echo "root 권한으로 실행해야 합니다." >&2
  exit 64
fi

server=${1:-}
username=${2:-}
duration=${3:-180}

if [[ ! $server =~ ^hai-ip[1-8]\.haion\.net$ ]]; then
  echo "서버는 hai-ip1.haion.net부터 hai-ip8.haion.net만 사용할 수 있습니다." >&2
  exit 64
fi
if [[ -z $username ]]; then
  echo "사용자명을 지정해야 합니다." >&2
  exit 64
fi
if [[ ! $duration =~ ^[0-9]+$ ]] || (( duration < 30 || duration > 1800 )); then
  echo "검증 시간은 30~1800초여야 합니다." >&2
  exit 64
fi

base_dir=/var/log/haiip-probe
run_dir="$base_dir/$(date -u +%Y%m%dT%H%M%SZ)-${server%%.*}"
umask 077
mkdir -p "$run_dir"
ln -sfn "$run_dir" "$base_dir/latest"
exec >>"$run_dir/run.log" 2>&1

printf 'started_at=%s\nserver=%s\nusername=%s\nduration_seconds=%s\n' \
  "$(date -Is)" "$server" "$username" "$duration"

if systemctl is-active --quiet haiip-client.service; then
  echo "refusing_to_run=haiip-client.service is active"
  exit 65
fi
if pgrep -x pppd >/dev/null || pgrep -x pptp >/dev/null; then
  echo "refusing_to_run=an existing PPTP session is active"
  exit 65
fi

if [[ ! -r /etc/haiip/client.env ]]; then
  echo "missing=/etc/haiip/client.env"
  exit 66
fi
if [[ ! -x /usr/local/bin/haiip ]]; then
  echo "missing=/usr/local/bin/haiip"
  exit 66
fi
if ! command -v tcpdump >/dev/null || ! command -v ip >/dev/null; then
  echo "missing=required network diagnostic command"
  exit 66
fi

set -a
# shellcheck disable=SC1091
. /etc/haiip/client.env
set +a
if [[ -z ${HAIIP_PASSWORD:-} ]]; then
  echo "missing=HAIIP_PASSWORD"
  exit 66
fi

printf '[network_before]\n'
ip -brief addr
ip route show

capture_pid=''
client_pid=''
client_log="$run_dir/client.log"
capture_log="$run_dir/capture.log"
finish() {
  status=$?
  if [[ -n $client_pid ]] && kill -0 "$client_pid" 2>/dev/null; then
    kill -TERM "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  if [[ -n $capture_pid ]] && kill -0 "$capture_pid" 2>/dev/null; then
    kill -TERM "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
  fi
  printf '[network_after]\n'
  ip -brief addr
  ip route show
  if [[ -f $client_log ]]; then
    printf '[client_events]\n'
    grep -E 'PPTP|GRE|PPP|LCP|CHAP|IPCP|Hai-IP|error' "$client_log" || true
  fi
  if [[ -f "$run_dir/session.pcap" ]]; then
    tcpdump -nn -vv -r "$run_dir/session.pcap" >"$run_dir/decoded.pcap.txt" 2>&1 || true
  fi
  printf 'finished_at=%s\nexit_status=%s\n' "$(date -Is)" "$status"
}
trap finish EXIT

tcpdump -U -ni any -s 0 -w "$run_dir/session.pcap" 'tcp port 1723 or proto 47' >"$capture_log" 2>&1 &
capture_pid=$!
sleep 1
if ! kill -0 "$capture_pid" 2>/dev/null; then
  echo "capture_start_failed"
  exit 67
fi

RUST_LOG=debug /usr/local/bin/haiip connect \
  --server "$server" \
  --username "$username" \
  --password-env HAIIP_PASSWORD \
  --tun-name haiip0 \
  --mtu 1400 >"$client_log" 2>&1 &
client_pid=$!

deadline=$((SECONDS + duration))
while kill -0 "$client_pid" 2>/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "result=duration_reached"
    kill -TERM "$client_pid"
    break
  fi
  sleep 1
done

set +e
wait "$client_pid"
client_status=$?
set -e
client_pid=''
printf 'client_exit_status=%s\n' "$client_status"
exit "$client_status"
