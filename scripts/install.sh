#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_SERVER='auto'
readonly INSTALL_DIR='/etc/haiip'
readonly ENV_FILE="$INSTALL_DIR/client.env"
readonly UNIT_FILE='/etc/systemd/system/haiip-client.service'
readonly BINARY_FILE='/usr/local/bin/haiip'

usage() {
  cat <<'EOF'
사용법: sudo ./scripts/install.sh --username <아이디@VPN번호> --password <비밀번호> [--server auto|hai-ip1.haion.net]
EOF
}

fail() {
  echo "설치 실패: $1" >&2
  exit 1
}

require_root() {
  if (( EUID != 0 )); then
    exec sudo -- "$0" "$@"
  fi
}

escape_environment_value() {
  local value=$1
  [[ $value != *$'\n'* && $value != *$'\r'* ]] || fail '사용자명과 비밀번호에는 줄바꿈을 사용할 수 없습니다.'
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

find_cargo() {
  if [[ -x /usr/local/bin/cargo ]]; then
    printf '%s' /usr/local/bin/cargo
    return
  fi
  command -v cargo
}

build_project() {
  local cargo_bin=$1
  local project_dir=$2
  if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]] && command -v runuser >/dev/null; then
    runuser -u "$SUDO_USER" -- "$cargo_bin" build --release --manifest-path "$project_dir/Cargo.toml" --quiet
    return
  fi
  "$cargo_bin" build --release --manifest-path "$project_dir/Cargo.toml" --quiet
}

main() {
  if [[ ${1:-} == '-h' || ${1:-} == '--help' ]]; then
    usage
    exit 0
  fi
  require_root "$@"

  local username=''
  local password=''
  local server=$DEFAULT_SERVER
  while (($#)); do
    case $1 in
      --username)
        (($# >= 2)) || fail '--username 값이 필요합니다.'
        username=$2
        shift 2
        ;;
      --password)
        (($# >= 2)) || fail '--password 값이 필요합니다.'
        password=$2
        shift 2
        ;;
      --server)
        (($# >= 2)) || fail '--server 값이 필요합니다.'
        server=$2
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "알 수 없는 인자입니다: $1"
        ;;
    esac
  done

  [[ -n $username ]] || fail '--username 값이 필요합니다.'
  [[ -n $password ]] || fail '--password 값이 필요합니다.'
  [[ $server == auto || $server =~ ^hai-ip[1-8]\.haion\.net$ ]] || fail '서버는 auto 또는 hai-ip1.haion.net부터 hai-ip8.haion.net만 사용할 수 있습니다.'
  local cargo_bin
  cargo_bin=$(find_cargo) || fail 'Rust Cargo가 필요합니다.'
  command -v systemctl >/dev/null || fail 'systemd 기반 Linux가 필요합니다.'

  local project_dir
  project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
  [[ -f $project_dir/Cargo.toml ]] || fail '프로젝트 루트를 찾지 못했습니다.'

  build_project "$cargo_bin" "$project_dir"

  install -d -o root -g root -m 700 "$INSTALL_DIR"
  umask 077
  {
    printf 'HAIIP_SERVER=%s\n' "$(escape_environment_value "$server")"
    printf 'HAIIP_USERNAME=%s\n' "$(escape_environment_value "$username")"
    printf 'HAIIP_PASSWORD=%s\n' "$(escape_environment_value "$password")"
  } >"$ENV_FILE"
  chown root:root "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  install -o root -g root -m 750 "$project_dir/target/release/haiip" "$BINARY_FILE"
  install -o root -g root -m 644 "$project_dir/systemd/haiip-client.service" "$UNIT_FILE"
  systemctl daemon-reload
  systemctl enable haiip-client.service >/dev/null
  systemctl restart haiip-client.service
  sleep 2
  systemctl is-active --quiet haiip-client.service || fail '서비스를 시작하지 못했습니다. journalctl -u haiip-client.service를 확인하십시오.'

  echo "Hai-IP 서비스 설치 및 시작 완료: $server"
}

main "$@"
