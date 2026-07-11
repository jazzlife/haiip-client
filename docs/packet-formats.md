# 패킷 형식

모든 다중 바이트 PPTP 필드는 RFC 2637에 따라 network byte order(big-endian)입니다. 코드는 구조체 메모리를 전송하지 않고 필드별로 직렬화하여 padding과 호스트 endian 의존성을 제거합니다.

## 공통 PPTP 제어 헤더

| Offset | 크기 | 필드 | 검증 |
|---:|---:|---|---|
| 0 | 2 | Length | 헤더 포함 전체 길이, 실제 프레임 길이와 일치 |
| 2 | 2 | PPTP Message Type | Control은 `1` |
| 4 | 4 | Magic Cookie | `0x1a2b3c4d` |
| 8 | 2 | Control Message Type | RFC 2637 section 2 코드 |
| 10 | 2 | Reserved0 | 반드시 `0` |

현재 제어 메시지 최대 길이는 RFC에 정의된 메시지를 충분히 포함하는 512바이트로 제한합니다. 선언 길이가 12보다 작거나 상한보다 크면 나머지를 할당하기 전에 거부합니다. 알 수 없는 제어 타입과 비영(非零) 예약 필드 역시 거부합니다.

## 지원 메시지와 정확한 길이

| 코드 | 메시지 | 길이 |
|---:|---|---:|
| 1 | Start-Control-Connection-Request | 156 |
| 2 | Start-Control-Connection-Reply | 156 |
| 3 | Stop-Control-Connection-Request | 16 |
| 4 | Stop-Control-Connection-Reply | 16 |
| 5 | Echo-Request | 16 |
| 6 | Echo-Reply | 20 |
| 7 | Outgoing-Call-Request | 168 |
| 8 | Outgoing-Call-Reply | 32 |
| 12 | Call-Clear-Request | 16 |
| 13 | Call-Disconnect-Notify | 148 |
| 15 | Set-Link-Info | 24 |

Start Request는 version `0x0100`, async+synchronous framing bits `3`, analog+digital bearer bits `3`, PNS maximum channels `0`을 보냅니다. 고정 문자열은 NUL로 나머지를 채우며 필드 크기를 넘기지 않습니다. Outgoing Request의 phone number length는 64 이하인지 검사합니다. Call ID와 Peer Call ID는 이름이 다른 별도 필드로 유지합니다.

## Enhanced GRE (후속 마일스톤)

RFC 2637 section 4.1의 PPTP GRE는 일반 RFC 1701 헤더와 다른 고정 bit 의미를 사용합니다. 기본 단어에는 C=0, R=0, K=1, S는 sequence 존재 여부, recursion=0, A는 ack 존재 여부, flags=0, version=1, protocol type=`0x880b`가 들어갑니다. 이어 Payload Length, Call ID, 선택적 Sequence Number, 선택적 Acknowledgement Number가 network order로 위치합니다. ACK만 있는 패킷은 payload length 0이며 S가 설정되지 않을 수 있습니다.

수신 IP raw socket이 IPv4 헤더를 포함하는지는 Linux 소켓 API 동작을 실제 Linux 테스트로 고정하고, IPv4 IHL/total length/protocol/source를 검증한 뒤 GRE를 넘깁니다. sequence 비교는 단순 정수 대소가 아니라 32비트 wrap-around 순환 비교를 사용합니다.

## PPP over GRE (후속 마일스톤)

PPTP의 GRE payload는 PPP 패킷을 운반합니다. RFC 2637 section 4는 PPP 프레임의 trailing FCS를 전송하지 않는다고 규정합니다. RFC 1661의 Address `0xff`, Control `0x03`, 1~2바이트 Protocol을 처리하되 협상된 ACFC/PFC에 따라 생략을 허용합니다. RFC 1662의 `0x7e` flag와 octet escape를 GRE payload에 항상 있다고 가정하지 않으며 async HDLC 입력 모드와 분리합니다.

중요 프로토콜 값은 IPv4 `0x0021`, IPCP `0x8021`, LCP `0xc021`, CHAP `0xc223`, CCP `0x80fd`, IPv6CP `0x8057`입니다. LCP가 Opened 되기 전 인증/NCP를 진행하지 않고, IPCP Opened 전 IPv4 payload를 TUN에 전달하지 않습니다.
