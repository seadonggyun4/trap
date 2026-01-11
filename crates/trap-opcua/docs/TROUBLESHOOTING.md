# OPC UA Troubleshooting Guide

> trap-opcua 트러블슈팅 가이드

## 목차

- [진단 도구](#진단-도구)
- [연결 문제](#연결-문제)
- [인증 문제](#인증-문제)
- [읽기/쓰기 오류](#읽기쓰기-오류)
- [구독 문제](#구독-문제)
- [성능 문제](#성능-문제)
- [인증서 문제](#인증서-문제)
- [로그 분석](#로그-분석)

---

## 진단 도구

### 연결 테스트

```bash
# 네트워크 연결 확인
nc -zv <server-ip> 4840

# 또는 telnet 사용
telnet <server-ip> 4840
```

### OPC UA 전용 도구

1. **UaExpert** (Unified Automation)
   - 무료 OPC UA 클라이언트
   - 서버 브라우징, 읽기/쓰기 테스트
   - 다운로드: https://www.unified-automation.com/products/development-tools/uaexpert.html

2. **Prosys OPC UA Browser**
   - 크로스 플랫폼 지원
   - 다운로드: https://www.prosysopc.com/products/opc-ua-browser/

3. **opcua-client (Python)**
   ```bash
   pip install opcua
   python -c "
   from opcua import Client
   client = Client('opc.tcp://localhost:4840')
   client.connect()
   print('Connected!')
   client.disconnect()
   "
   ```

### 드라이버 상태 확인

```rust
// 연결 상태 확인
let is_connected = driver.is_connected();
println!("Connected: {}", is_connected);

// 세션 상태 확인
let session_state = driver.session_state().await;
println!("Session: {:?}", session_state);

// 헬스 체크
let health = driver.health_check().await;
println!("Health: {:?}", health);

// 통계 확인
let stats = driver.client_stats();
println!("Reads: {}, Errors: {}, Success Rate: {:.2}%",
    stats.reads(), stats.errors(), stats.success_rate() * 100.0);
```

---

## 연결 문제

### 문제: 연결 시간 초과 (Connection Timeout)

**증상:**
```
Error: Connection(Timeout { endpoint: "opc.tcp://192.168.1.100:4840", timeout_ms: 5000 })
```

**원인:**
- 네트워크 연결 불가
- 서버가 실행 중이지 않음
- 방화벽에서 포트 차단
- 잘못된 IP 주소 또는 포트

**해결책:**

1. 네트워크 연결 확인
```bash
# ping 테스트
ping 192.168.1.100

# 포트 확인
nc -zv 192.168.1.100 4840
```

2. 서버 상태 확인
```bash
# 서버 프로세스 확인 (서버 측에서)
netstat -an | grep 4840
```

3. 방화벽 규칙 확인
```bash
# Linux
sudo iptables -L -n | grep 4840

# Windows
netsh advfirewall firewall show rule name=all | findstr 4840
```

4. 타임아웃 증가
```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://192.168.1.100:4840")
    .request_timeout(Duration::from_secs(30))  // 30초로 증가
    .build()?;
```

### 문제: 연결 거부 (Connection Refused)

**증상:**
```
Error: Connection(Refused { endpoint: "opc.tcp://192.168.1.100:4840" })
```

**원인:**
- 서버가 실행 중이지 않음
- 서버가 다른 포트에서 수신 중
- 서버 최대 연결 수 초과

**해결책:**

1. 서버 상태 확인
2. 올바른 포트 확인 (GetEndpoints 사용)
3. 서버 최대 연결 수 확인

### 문제: 호스트 이름 해석 실패

**증상:**
```
Error: Connection(DnsLookupFailed { hostname: "plc-server.local" })
```

**해결책:**

1. DNS 확인
```bash
nslookup plc-server.local
```

2. /etc/hosts 파일에 항목 추가
```
192.168.1.100  plc-server.local
```

3. IP 주소 직접 사용

---

## 인증 문제

### 문제: 인증서 신뢰 실패

**증상:**
```
Error: Security(CertificateValidation { reason: "Certificate not trusted" })
```

**원인:**
- 서버 인증서가 신뢰되지 않음
- 클라이언트 인증서가 서버에서 신뢰되지 않음

**해결책:**

1. **개발 환경** - 자동 신뢰 활성화
```rust
let cert_config = CertificateConfig {
    trust_server_certs: true,  // 주의: 프로덕션에서는 false
    ..Default::default()
};
```

2. **프로덕션 환경** - 인증서 교환
   - 서버 인증서를 클라이언트의 trusted 폴더에 복사
   - 클라이언트 인증서를 서버의 trusted 폴더에 복사

```bash
# 인증서 위치 확인
ls /etc/trap/certs/trusted/
ls /etc/trap/certs/rejected/

# rejected에서 trusted로 이동
mv /etc/trap/certs/rejected/server.der /etc/trap/certs/trusted/
```

### 문제: 보안 모드 불일치

**증상:**
```
Error: Security(SecurityModeRejected { requested: SignAndEncrypt, available: [None, Sign] })
```

**원인:**
- 클라이언트가 요청한 보안 모드를 서버가 지원하지 않음

**해결책:**

1. 지원되는 엔드포인트 확인
```rust
// GetEndpoints로 확인
let endpoints = discover_endpoints("opc.tcp://server:4840").await?;
for ep in endpoints {
    println!("Security: {:?} + {:?}", ep.security_mode, ep.security_policy);
}
```

2. 지원되는 모드로 변경
```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://server:4840")
    .security_mode(SecurityMode::Sign)  // 서버가 지원하는 모드
    .security_policy(SecurityPolicy::Basic256Sha256)
    .build()?;
```

### 문제: 사용자 인증 실패

**증상:**
```
Error: Session(ActivationFailed { reason: "BadUserAccessDenied" })
```

**원인:**
- 잘못된 사용자명/비밀번호
- 사용자 계정 비활성화
- 권한 부족

**해결책:**

1. 자격 증명 확인
2. 서버 관리 도구에서 사용자 상태 확인
3. 익명 인증 테스트 (지원되는 경우)
```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://server:4840")
    .anonymous()
    .build()?;
```

---

## 읽기/쓰기 오류

### 문제: 노드 없음 (BadNodeIdUnknown)

**증상:**
```
Error: Operation(ReadFailed { node_id: "ns=2;s=InvalidNode", status: 0x80340000 })
```

**원인:**
- 잘못된 NodeId
- 노드가 삭제됨
- namespace 인덱스 오류

**해결책:**

1. NodeId 형식 확인
```rust
// 올바른 형식 예시
let numeric = NodeId::numeric(2, 1001);       // ns=2;i=1001
let string = NodeId::string(2, "Temp");        // ns=2;s=Temp
```

2. 브라우즈로 확인
```rust
let nodes = driver.browse().await?;
for node in nodes {
    println!("{} -> {}", node.name, node.address);
}
```

3. namespace 확인
```bash
# 서버의 namespace 목록 확인 (UaExpert 등 사용)
# 일반적으로:
# ns=0: OPC UA 표준
# ns=1: 서버 특정
# ns=2+: 사용자 정의
```

### 문제: 읽기 권한 없음 (BadNotReadable)

**증상:**
```
Error: Operation(ReadFailed { node_id: "ns=2;i=1001", status: 0x803A0000 })
```

**해결책:**

1. 사용자 권한 확인
2. 서버에서 노드 접근 권한 설정 확인
3. 다른 사용자로 테스트

### 문제: 쓰기 권한 없음 (BadNotWritable)

**증상:**
```
Error: Operation(NotWritable { node_id: "ns=2;i=1001" })
```

**해결책:**

1. 노드가 쓰기 가능한지 확인
2. 현재 사용자의 쓰기 권한 확인
3. 노드 속성 확인 (AccessLevel)

### 문제: 타입 불일치 (BadTypeMismatch)

**증상:**
```
Error: Operation(WriteFailed { reason: "BadTypeMismatch" })
```

**원인:**
- 쓰려는 값의 타입이 노드 타입과 일치하지 않음

**해결책:**

1. 노드 데이터 타입 확인
```rust
// 노드의 DataType 속성 읽기
let data_type = driver.read_attribute(node_id, AttributeId::DataType).await?;
```

2. 올바른 타입으로 값 변환
```rust
// Double 노드에 값 쓰기
driver.write(&address, Value::Float64(25.5)).await?;

// Int32 노드에 값 쓰기
driver.write(&address, Value::Int32(100)).await?;
```

---

## 구독 문제

### 문제: 구독 생성 실패

**증상:**
```
Error: Subscription(CreationFailed { reason: "Too many subscriptions" })
```

**원인:**
- 서버의 최대 구독 수 초과
- 리소스 부족

**해결책:**

1. 기존 구독 정리
```rust
// 모든 구독 해제
for sub_id in active_subscriptions {
    driver.unsubscribe(&sub_id).await?;
}
```

2. 구독 통합 (여러 노드를 하나의 구독에)
```rust
// 모든 노드를 하나의 구독으로
let all_addresses = vec![addr1, addr2, addr3, ...];
let subscription = driver.subscribe(&all_addresses).await?;
```

### 문제: 데이터 변경 알림 없음

**증상:**
- 구독이 생성되었지만 알림이 오지 않음

**원인:**
- 값이 변경되지 않음
- 데드밴드 설정으로 필터링됨
- 퍼블리싱 간격이 너무 김

**해결책:**

1. 퍼블리싱 간격 줄이기
```rust
let settings = SubscriptionSettings {
    publishing_interval: Duration::from_millis(100),  // 더 짧은 간격
    ..Default::default()
};
```

2. 데드밴드 확인/제거
```rust
// 데드밴드 없이 모든 변경 수신
let item_settings = MonitoredItemSettings {
    deadband: None,
    ..Default::default()
};
```

3. 값 변경 강제 (테스트용)
```rust
// 현재 값 읽고 다시 쓰기
let current = driver.read(&address).await?;
driver.write(&address, current).await?;
```

### 문제: 구독 타임아웃

**증상:**
```
Error: Subscription(Timeout { subscription_id: 1 })
```

**원인:**
- 네트워크 문제
- 서버 과부하
- keep-alive 실패

**해결책:**

1. lifetime_count 증가
```rust
let settings = SubscriptionSettings {
    lifetime_count: 120,     // 더 긴 수명
    keepalive_count: 20,
    ..Default::default()
};
```

2. 재연결 로직 추가
```rust
async fn maintain_subscription(driver: &mut OpcUaDriver) {
    loop {
        match driver.subscribe(&addresses).await {
            Ok(sub) => {
                // 알림 수신
                while let Some(data) = sub.receiver.recv().await {
                    process_data(data);
                }
            }
            Err(e) => {
                eprintln!("Subscription error: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                // 재연결 시도
                driver.reconnect().await.ok();
            }
        }
    }
}
```

---

## 성능 문제

### 문제: 느린 읽기 성능

**원인:**
- 개별 읽기 호출 과다
- 네트워크 지연
- 서버 과부하

**해결책:**

1. 배치 읽기 사용
```rust
// 나쁜 예: 개별 읽기
for addr in &addresses {
    let value = driver.read(addr).await?;  // N번의 네트워크 호출
}

// 좋은 예: 배치 읽기
let results = driver.read_batch(&addresses).await?;  // 1번의 네트워크 호출
```

2. 구독 사용 (폴링 대신)
```rust
// 나쁜 예: 주기적 폴링
loop {
    let values = driver.read_batch(&addresses).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// 좋은 예: 구독 사용
let subscription = driver.subscribe(&addresses).await?;
while let Some(data) = subscription.receiver.recv().await {
    // 변경된 값만 수신
}
```

### 문제: 메모리 사용량 증가

**원인:**
- 구독 알림 축적
- 미처리 메시지 누적

**해결책:**

1. 채널 용량 조정
```rust
let (tx, rx) = mpsc::channel(100);  // 적절한 버퍼 크기
```

2. 정기적인 정리
```rust
// 오래된 구독 정리
driver.cleanup_subscriptions().await;
```

### 문제: 높은 CPU 사용량

**원인:**
- 너무 짧은 폴링 간격
- 과도한 로깅

**해결책:**

1. 퍼블리싱 간격 조정
```rust
// 100ms -> 500ms로 변경
let settings = SubscriptionSettings {
    publishing_interval: Duration::from_millis(500),
    ..Default::default()
};
```

2. 로깅 레벨 조정
```bash
RUST_LOG=trap_opcua=warn cargo run
```

---

## 인증서 문제

### 문제: 인증서 만료

**증상:**
```
Error: Security(CertificateExpired { not_after: "2024-01-01T00:00:00Z" })
```

**해결책:**

1. 인증서 유효 기간 확인
```bash
openssl x509 -in client.der -inform DER -noout -dates
```

2. 새 인증서 생성
```bash
# 1년 유효한 새 인증서
openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout client.pem \
    -out client.der \
    -outform DER \
    -subj "/CN=TRAP-Gateway"
```

### 문제: 개인 키 로드 실패

**증상:**
```
Error: Security(InvalidPrivateKey { path: "/path/to/key.pem" })
```

**해결책:**

1. 키 형식 확인
```bash
openssl rsa -in client.pem -check
```

2. 암호화된 키인 경우 암호 제거
```bash
openssl rsa -in encrypted.pem -out client.pem
```

### 문제: 인증서 형식 오류

**증상:**
```
Error: Security(InvalidCertificate { path: "/path/to/cert.der" })
```

**해결책:**

1. 형식 확인 및 변환
```bash
# PEM에서 DER로
openssl x509 -in cert.pem -outform DER -out cert.der

# DER에서 PEM으로
openssl x509 -in cert.der -inform DER -out cert.pem
```

---

## 로그 분석

### 로그 레벨 설정

```bash
# 상세 디버그 로그
RUST_LOG=trap_opcua=debug cargo run

# 특정 모듈만
RUST_LOG=trap_opcua::client=debug,trap_opcua::driver=info cargo run

# 트레이스 레벨 (가장 상세)
RUST_LOG=trap_opcua=trace cargo run
```

### 주요 로그 패턴

#### 연결 성공
```
INFO trap_opcua::driver: OPC UA driver connected endpoint="opc.tcp://localhost:4840"
```

#### 연결 실패
```
ERROR trap_opcua::client: Connection failed error=Timeout { ... }
```

#### 읽기 오류
```
WARN trap_opcua::client: Read failed node_id="ns=2;i=1001" status=0x80340000
```

#### 구독 이벤트
```
INFO trap_opcua::subscription: Subscription created id=1 items=5
DEBUG trap_opcua::subscription: Data change notification item_id=1 value=25.5
```

### 구조화된 로깅 활용

```rust
// JSON 형식 로그
RUST_LOG=trap_opcua=info cargo run 2>&1 | jq .

// 필터링
RUST_LOG=trap_opcua=debug cargo run 2>&1 | grep "Connection"
```

---

## 지원 요청 시 필요 정보

문제 해결이 어려운 경우, 다음 정보를 수집하여 지원팀에 제출하세요:

1. **환경 정보**
   - trap-opcua 버전
   - Rust 버전
   - 운영체제

2. **설정 정보** (민감 정보 제거)
   - 엔드포인트 URL
   - 보안 모드/정책
   - 구독 설정

3. **로그**
   - DEBUG 레벨 로그
   - 에러 발생 시점 전후 로그

4. **재현 단계**
   - 문제 재현을 위한 단계별 설명
   - 최소 재현 코드 (가능한 경우)

```bash
# 환경 정보 수집 스크립트
echo "=== Environment ===" > diagnosis.txt
echo "OS: $(uname -a)" >> diagnosis.txt
echo "Rust: $(rustc --version)" >> diagnosis.txt
echo "trap-opcua: $(cargo pkgid -p trap-opcua)" >> diagnosis.txt
echo "" >> diagnosis.txt
echo "=== Logs ===" >> diagnosis.txt
RUST_LOG=trap_opcua=debug cargo run 2>&1 | tail -100 >> diagnosis.txt
```
