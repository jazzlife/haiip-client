# 프로토콜 흐름

## 규범 자료

- [RFC 2637](https://www.rfc-editor.org/rfc/rfc2637): PPTP 제어 연결, Outgoing Call, Enhanced GRE
- [RFC 1661](https://www.rfc-editor.org/rfc/rfc1661): PPP 캡슐화와 LCP 상태 머신
- [RFC 1994](https://www.rfc-editor.org/rfc/rfc1994): PPP CHAP
- [RFC 2759](https://www.rfc-editor.org/rfc/rfc2759): MS-CHAPv2 계산과 공개 테스트 벡터
- [RFC 1332](https://www.rfc-editor.org/rfc/rfc1332): IPCP
- [RFC 1662](https://www.rfc-editor.org/rfc/rfc1662): HDLC-like framing. PPTP GRE payload에 그대로 적용한다고 가정하지 않는다.
- [Linux TUN/TAP 문서](https://docs.kernel.org/networking/tuntap.html): `/dev/net/tun`, `IFF_TUN`, `IFF_NO_PI`
- Linux UAPI 헤더 `include/uapi/linux/if_tun.h`, `if_ppp.h`, `if_ether.h`: 이후 TUN/PPP 경계 구현의 공식 기준

RFC 2637은 Informational 문서이며 알려진 errata가 있다. 구현 시 RFC Editor errata와 비식별 패킷 캡처를 함께 대조한다. 기존 GPL 구현은 동작 비교에만 사용하고 코드를 복사하지 않는다.

## 전체 연결 순서

```text
DNS A 레코드 해석 및 세션 서버 IPv4 고정
  -> TCP server:1723
  -> Start-Control-Connection-Request / Reply
  -> Outgoing-Call-Request / Reply
  -> IP protocol 47 Enhanced GRE
  -> PPP LCP 양방향 Configure 협상
  -> CHAP MS-CHAPv2 Challenge / Response / Success 검증
  -> IPCP Configure-Nak의 주소 수락 후 Configure-Ack
  -> TUN 생성 및 IPv4/PPP 양방향 펌프
  -> 서버 host route 고정 후 split/default route 적용
```

종료는 새 라우트를 역순으로 제거하고, TUN을 닫고, Call-Clear 및 Stop-Control을 가능한 범위에서 교환한 뒤 TCP/raw socket을 닫는다. 프로세스가 추가한 객체만 제거하며 실행 중 외부에서 바뀐 라우트를 덮어쓰지 않는다.

## 현재 구현된 흐름

1. `tokio::net::lookup_host` 결과 중 IPv4 하나를 선택한다.
2. TCP 1723에 제한 시간 내 연결한다.
3. RFC 2637의 156바이트 Start-Control-Connection-Request를 전송한다.
4. TCP 분할/병합과 무관하게 선언 길이만큼 정확히 읽는다.
5. 길이, 메시지 종류, Magic Cookie, Control Type, 예약 필드를 검사한다.
6. 대기 중 PPTP Echo-Request가 오면 동일 Identifier로 성공 Echo-Reply를 즉시 보낸다.
7. Start-Control-Connection-Reply의 result=1과 version=0x0100을 확인한다.

현재 바이너리는 Outgoing Call, raw Enhanced GRE, LCP, MS-CHAPv2, IPCP와 TUN까지 연결합니다. 비밀번호는 환경 변수에서만 받고 NT Response 및 Challenge를 로그에 남기지 않습니다. 서버 Authenticator Response를 RFC 2759 방식으로 상수 시간 검증한 뒤에만 IPCP를 시작합니다.

## Hai-IP 관찰 흐름과 안정화 항목

2026-07-11 원격 Linux에서 기존 `pppd`의 실패를 재현했고 약 25초 뒤 `Peer not responding` 종료를 확인했습니다. 새 구현에서는 같은 서버와 계정으로 인증/IPCP/TUN까지 성공했습니다. 실제 캡처에서 서버가 LCP Configure-Request와 Configure-Ack를 같은 시각에 연속 전송할 때 GRE seq 1이 raw socket에서 누락되는 경우가 확인되었습니다. 협상 중 gap을 감지하면 LCP Configure-Request를 다시 보내 Ack를 회복합니다.

Hai-IP는 수신 Echo-Reply만으로 연결 생존 상태를 계속 갱신하지 않았습니다. 서버 요청에는 RFC 1661 Echo-Reply로 즉시 답하고, 별도의 클라이언트 Echo-Request도 주기적으로 보내 양방향 keepalive를 유지합니다. 클라이언트 Identifier는 서버의 낮은 증가값과 충돌하지 않도록 128 이상에서 시작합니다.

- 서버 LCP Echo-Request의 Identifier 보존
- Echo-Reply Magic Number와 GRE sequence/ack 갱신
- 제어 패킷이 IP 데이터에 밀리지 않는 우선순위 큐
- sequence gap의 제한 시간 버퍼링, 중복 제거, wrap-around
- TCP PPTP Echo와 PPP LCP Echo의 별도 타이머

실계정, Linux raw socket/TUN 권한 및 30분 관찰이 없으므로 실서버 세션 유지 완료를 주장하지 않습니다.
