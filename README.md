# Hai-IP Client

> [!IMPORTANT]
> ## 바로 시작
>
> ```bash
> sudo ./scripts/install.sh --username '<사용자명>' --password '<비밀번호>'
> ```
>
> 삭제할 때는 아래 한 명령만 실행합니다.
>
> ```bash
> sudo ./scripts/uninstall.sh
> ```

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
sudo cargo run -- connect
cargo run -- inspect
cargo run -- capture-info
```

## 한 단계 설치와 삭제

Rust stable이 설치된 Linux에서 아래 한 명령으로 빌드·환경 파일 생성·서비스 등록·시작이 끝납니다.

```bash
sudo ./scripts/install.sh --username '<사용자명>' --password '<비밀번호>'
```

기본값은 `auto`이며 연결 가능한 Hai-IP 서버를 자동 선택합니다. 특정 서버를 지정하려면 다음처럼 실행합니다.

```bash
sudo ./scripts/install.sh --username '<사용자명>' --password '<비밀번호>' --server hai-ip4.haion.net
```

삭제는 한 명령입니다.

```bash
sudo ./scripts/uninstall.sh
```

설치 스크립트는 사용자명·비밀번호·서버를 `/etc/haiip/client.env`에만 기록하고 `root:root`, `0600` 권한을 적용합니다. 이 파일은 Git에 포함되지 않습니다. 제공된 unit은 이 환경 파일에서만 계정을 읽고, 실패 시 60초 뒤 재접속합니다.

## 보안 주의

PPTP 및 MS-CHAPv2는 현대적인 VPN 프로토콜보다 보안상 약합니다. 이 프로젝트는 Hai-IP 호환 목적이며 신뢰할 수 없는 네트워크를 위한 범용 신규 설계로 권장하지 않습니다. 인증 정보와 패킷 캡처를 저장소에 커밋하지 마십시오.

`haiip about`에서 기능과 계정 처리 방식을 확인할 수 있습니다. 설계 근거와 구현 범위는 [프로토콜 흐름](docs/protocol-flow.md), [패킷 형식](docs/packet-formats.md)을 참고하십시오.
