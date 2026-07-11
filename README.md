# Hai-IP Client

기존 `pptp-linux`, `pppd`, NetworkManager를 실행하지 않고 PPTP/PPP를 직접 처리하는 Linux용 Rust 클라이언트입니다.

현재 PPTP 제어 연결, Enhanced GRE, LCP, MS-CHAPv2 상호 인증, IPCP, Linux TUN 및 양방향 LCP keepalive를 직접 구현합니다. Hai-IP의 GRE 초기 패킷 손실과 서버 생존 확인 방식에 맞춘 호환 계층을 포함합니다. 기본 경로 변경은 아직 수행하지 않으며 `haiip0` point-to-point 인터페이스만 구성합니다.

## 빌드와 확인

Rust stable이 필요합니다.

```bash
cargo build
cargo test --all
cargo clippy --all-targets --all-features -- -D warnings
```

## 실행

전체 연결은 raw GRE와 TUN 때문에 `CAP_NET_RAW`, `CAP_NET_ADMIN`이 필요합니다. 기본 실행은 사용자명과 숨김 비밀번호를 직접 입력받으며, 인증 정보를 명령행이나 설정 파일에 기록하지 않습니다.

```bash
cargo run -- connect --server hai-ip4.haion.net --port 1723 --control-only
sudo cargo run -- connect --server hai-ip4.haion.net
cargo run -- inspect
cargo run -- capture-info
```

## systemd 서비스 등록

인증 정보는 서버의 root 전용 환경 파일에만 직접 입력합니다. 저장소에는 빈 예제만 포함되며 실제 환경 파일은 Git 추적 대상이 아닙니다.

```bash
sudo install -d -m 700 /etc/haiip
sudo install -o root -g root -m 600 systemd/client.env.example /etc/haiip/client.env
sudoedit /etc/haiip/client.env
# HAIIP_USERNAME=여기에_사용자명_입력
# HAIIP_PASSWORD=여기에_비밀번호_입력

sudo install -o root -g root -m 644 systemd/haiip-client.service /etc/systemd/system/haiip-client.service
sudo systemctl daemon-reload
sudo systemctl enable --now haiip-client.service
```

제공된 unit은 `HAIIP_USERNAME`과 `HAIIP_PASSWORD`를 `/etc/haiip/client.env`에서만 읽고, 실패 시 60초 뒤 재접속합니다. capability 범위는 네트워크 관리와 raw socket으로 제한합니다.

## 보안 주의

PPTP 및 MS-CHAPv2는 현대적인 VPN 프로토콜보다 보안상 약합니다. 이 프로젝트는 Hai-IP 호환 목적이며 신뢰할 수 없는 네트워크를 위한 범용 신규 설계로 권장하지 않습니다. 인증 정보와 패킷 캡처를 저장소에 커밋하지 마십시오.

설계 근거와 구현 범위는 [프로토콜 흐름](docs/protocol-flow.md), [패킷 형식](docs/packet-formats.md)을 참고하십시오.
