#!/usr/bin/env bash
set -euo pipefail

readonly INSTALL_DIR='/etc/haiip'
readonly UNIT_FILE='/etc/systemd/system/haiip-client.service'
readonly BINARY_FILE='/usr/local/bin/haiip'

if (( EUID != 0 )); then
  exec sudo -- "$0" "$@"
fi

if (($#)); then
  echo '사용법: sudo ./scripts/uninstall.sh' >&2
  exit 64
fi

systemctl disable --now haiip-client.service >/dev/null 2>&1 || true
rm -f "$UNIT_FILE" "$BINARY_FILE"
rm -rf "$INSTALL_DIR"
systemctl daemon-reload

echo 'Hai-IP 서비스와 로컬 인증 정보를 삭제했습니다.'
