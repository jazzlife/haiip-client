# Hai-IP Client

> [!IMPORTANT]
> ```bash
> sudo ./scripts/install.sh --username '<아이디@VPN번호>' --password '<비밀번호>'
> sudo ./scripts/uninstall.sh
> ```

기존 `pptp-linux`, `pppd`, NetworkManager를 실행하지 않고 PPTP/PPP를 직접 처리하는 Linux용 Rust 클라이언트입니다.

현재 PPTP 제어 연결, Enhanced GRE, LCP, MS-CHAPv2 상호 인증, IPCP, Linux TUN 및 LCP keepalive를 직접 구현합니다. Hai-IP의 서버별 접속 상태 차이를 고려해 자동 서버 선택과 순차 전환을 제공하며, 인증 정보는 저장소와 명령 실행 로그에 남기지 않는 운영 구성을 지향합니다.

## 동작 원리

클라이언트는 TCP/1723의 PPTP 제어 채널을 수립한 뒤 Outgoing-Call 절차를 수행하고, raw GRE 소켓으로 PPP 프레임을 교환합니다. LCP 협상에서 MS-CHAPv2 인증 방식을 확인하고, 상호 인증 성공 후 IPCP를 통해 할당된 IPv4 주소를 `haiip0` TUN 인터페이스에 구성합니다. 서버가 전송하는 LCP Echo-Request에는 RFC 1661 형식의 Echo-Reply를 반환하며, IPv4 GRE payload에는 PPTP Enhanced GRE ACK를 별도로 반환합니다.

`--server auto`가 기본값입니다. 이 모드에서는 `hai-ip1.haion.net`부터 `hai-ip8.haion.net`까지를 무작위 순서로 시도합니다. 제어 협상·인증·IPCP 중 하나라도 실패하면 사용자의 개입 없이 다음 후보로 전환합니다. 이미 연결된 세션이 종료된 경우에도 같은 후보 목록을 다시 순회하므로, 특정 서버의 일시적인 세션 제한이나 상태 불량에 고정되지 않습니다. 특정 서버를 고정해야 하는 운영 환경에서는 `--server hai-ipN.haion.net`을 명시할 수 있습니다.

시스템 기본 경로는 변경하지 않습니다. 대신 Hai-IP가 할당한 주소에서 시작하는 응답 트래픽만 `haiip0` 전용 라우팅 테이블로 보내므로, 기존 관리 경로와 PPTP 전송 경로를 보존하면서 공인 주소로 들어온 SSH 같은 연결에 정상 응답합니다.

## 빌드와 확인

Rust stable이 필요합니다.

```bash
cargo build
cargo test --all
cargo clippy --all-targets --all-features -- -D warnings
```

## 실행

전체 연결에는 raw GRE와 TUN을 위한 `CAP_NET_RAW`, `CAP_NET_ADMIN` 권한이 필요합니다. 사용자명은 Hai-IP **아이디와 VPN 번호를 `아이디@VPN번호` 형식으로 결합한 값**입니다. 대화형 실행은 이 사용자명과 숨김 비밀번호를 직접 입력받습니다.

```bash
cargo run -- connect --server hai-ip4.haion.net --port 1723 --control-only
sudo cargo run -- connect
cargo run -- inspect
cargo run -- capture-info
haiip about
```

## 한 단계 설치와 삭제

Rust stable이 설치된 Linux에서 아래 한 명령으로 빌드·환경 파일 생성·서비스 등록·시작이 끝납니다.

```bash
sudo ./scripts/install.sh --username '<아이디@VPN번호>' --password '<비밀번호>'
```

기본값은 `auto`이며 연결 가능한 Hai-IP 서버를 자동 선택합니다. 특정 서버를 지정하려면 다음처럼 실행합니다.

```bash
sudo ./scripts/install.sh --username '<아이디@VPN번호>' --password '<비밀번호>' --server hai-ip4.haion.net
```

삭제는 한 명령입니다.

```bash
sudo ./scripts/uninstall.sh
```

설치 스크립트는 release 빌드, 바이너리 배치, systemd unit 등록, 환경 파일 생성, 서비스 재시작을 내부에서 처리합니다. 사용자명·비밀번호·서버 선택값은 `/etc/haiip/client.env`에만 기록하고 `root:root`, `0600` 권한을 적용합니다. 이 파일은 Git 추적 대상이 아니며 저장소에 포함되지 않습니다. 제공된 unit은 환경 파일에서만 계정을 읽고, 프로세스가 모든 후보에서 실패한 경우 60초 후 다시 시도합니다.

## 운영과 관찰

서비스 상태는 다음 명령으로 확인합니다.

```bash
sudo systemctl status haiip-client.service
sudo journalctl -u haiip-client.service -f
```

로그에는 선택된 서버, PPTP 제어 협상, LCP/MS-CHAPv2/IPCP 상태, TUN 생성과 서버 전환 사유가 남습니다. 비밀번호는 로그에 기록되지 않습니다. 패킷 단위 검증이 필요할 때는 `haiip capture-info`가 출력하는 tcpdump 필터를 사용할 수 있습니다.

`scripts/remote_haiip_probe.sh`는 운영 서비스와 분리된 진단 도구입니다. 활성 서비스나 기존 `pppd`/`pptp` 세션이 있는 경우 실행을 거부하고, 별도 로그와 pcap을 남겨 원격 접속 단절 이후에도 연결 과정을 분석할 수 있게 합니다.

## 보안 주의

PPTP 및 MS-CHAPv2는 현대적인 VPN 프로토콜보다 보안상 약합니다. 이 프로젝트는 Hai-IP 호환 목적이며, 신뢰할 수 없는 네트워크를 위한 범용 신규 VPN 설계로 권장하지 않습니다. 설치 명령의 비밀번호 인자는 셸 이력과 프로세스 인자 노출 가능성이 있으므로, 사용 후 해당 이력을 적절히 관리하십시오. 인증 정보·환경 파일·패킷 캡처는 저장소에 커밋하지 마십시오.

`haiip about`에서 기능과 계정 처리 방식을 확인할 수 있습니다. 설계 근거와 구현 범위는 [프로토콜 흐름](docs/protocol-flow.md), [패킷 형식](docs/packet-formats.md)을 참고하십시오.
