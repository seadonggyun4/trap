# OPC UA Security Configuration Guide

> trap-opcua 보안 설정 가이드

## 목차

- [개요](#개요)
- [보안 아키텍처](#보안-아키텍처)
- [인증서 관리](#인증서-관리)
- [보안 모드 설정](#보안-모드-설정)
- [사용자 인증](#사용자-인증)
- [권장 보안 구성](#권장-보안-구성)
- [보안 체크리스트](#보안-체크리스트)

---

## 개요

OPC UA는 산업용 통신을 위한 강력한 보안 기능을 제공합니다. trap-opcua는 OPC UA의 보안 기능을 완전히 지원하며, 다음 보안 요소를 구현합니다:

- **인증 (Authentication)**: 클라이언트/서버 신원 확인
- **인가 (Authorization)**: 접근 권한 관리
- **기밀성 (Confidentiality)**: 데이터 암호화
- **무결성 (Integrity)**: 데이터 변조 방지

### 보안 위협

| 위협 | 설명 | 대응책 |
|-----|------|--------|
| 도청 | 네트워크 트래픽 가로채기 | 암호화 (SignAndEncrypt) |
| 중간자 공격 | 통신 가로채기 및 변조 | 인증서 검증 |
| 스푸핑 | 위장 서버 연결 | 서버 인증서 검증 |
| 리플레이 | 이전 메시지 재전송 | 시퀀스 번호, 타임스탬프 |
| 무단 접근 | 권한 없는 데이터 접근 | 사용자 인증, 역할 기반 접근 |

---

## 보안 아키텍처

### OPC UA 보안 레이어

```
┌─────────────────────────────────────────────────────┐
│                  Application Layer                   │
│              (Read, Write, Subscribe)               │
├─────────────────────────────────────────────────────┤
│                 Session Layer                        │
│        (User Authentication, Session Keys)          │
├─────────────────────────────────────────────────────┤
│               Secure Channel Layer                   │
│     (Encryption, Signing, Certificate Exchange)     │
├─────────────────────────────────────────────────────┤
│                Transport Layer                       │
│             (TCP/IP, WebSocket)                     │
└─────────────────────────────────────────────────────┘
```

### 보안 흐름

```
클라이언트                                   서버
    │                                        │
    │──── 1. 서버 발견 (GetEndpoints) ─────→│
    │←─── 엔드포인트 목록 반환 ──────────────│
    │                                        │
    │──── 2. Secure Channel 생성 요청 ─────→│
    │     (클라이언트 인증서 + 논스)         │
    │←─── 서버 인증서 + 세션 키 ────────────│
    │                                        │
    │──── 3. 세션 생성 요청 ───────────────→│
    │     (사용자 자격 증명)                 │
    │←─── 세션 ID + 인증 토큰 ──────────────│
    │                                        │
    │──── 4. 세션 활성화 ──────────────────→│
    │←─── 활성화 완료 ─────────────────────│
    │                                        │
    │══════ 암호화된 통신 ═══════════════════│
```

---

## 인증서 관리

### 인증서 생성

#### 1. 자체 서명 인증서 생성

```bash
# OpenSSL을 사용한 인증서 생성

# 1. 개인 키 생성
openssl genrsa -out client.pem 2048

# 2. 인증서 서명 요청(CSR) 생성
openssl req -new -key client.pem -out client.csr \
    -subj "/C=KR/O=MyCompany/CN=TRAP-Gateway"

# 3. 자체 서명 인증서 생성
openssl x509 -req -days 365 -in client.csr \
    -signkey client.pem -out client.der \
    -outform DER

# 4. PEM 형식으로 변환 (선택)
openssl x509 -inform DER -in client.der -out client.crt
```

#### 2. OPC UA 요구사항을 충족하는 인증서

OPC UA 인증서는 다음 조건을 충족해야 합니다:

```bash
# OPC UA 호환 인증서 생성
cat > opcua-ext.cnf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = KR
O = MyCompany
CN = TRAP-Gateway

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
URI.1 = urn:MyCompany:TRAP-Gateway
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# 인증서 생성
openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout client.pem \
    -out client.der \
    -outform DER \
    -config opcua-ext.cnf
```

### 인증서 설정

```rust
use trap_opcua::{OpcUaConfig, CertificateConfig};

let cert_config = CertificateConfig {
    // 클라이언트 인증서 경로
    cert_path: PathBuf::from("/etc/trap/certs/client.der"),

    // 개인 키 경로
    private_key_path: PathBuf::from("/etc/trap/certs/client.pem"),

    // 서버 인증서 자동 신뢰 (개발용만 - 프로덕션에서는 false)
    trust_server_certs: false,

    // 신뢰할 인증서 디렉토리
    trusted_certs_dir: Some(PathBuf::from("/etc/trap/certs/trusted")),

    // 거부된 인증서 디렉토리
    rejected_certs_dir: Some(PathBuf::from("/etc/trap/certs/rejected")),
};

let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://server:4840")
    .certificate(cert_config)
    .build()?;
```

### 인증서 검증

인증서 검증 시 다음 항목을 확인합니다:

| 검증 항목 | 설명 |
|----------|------|
| 유효 기간 | 인증서가 만료되지 않았는지 |
| 서명 검증 | 인증서 서명이 유효한지 |
| 키 사용 | 적절한 keyUsage 확장 포함 |
| 확장 키 사용 | clientAuth 또는 serverAuth 포함 |
| 신뢰 체인 | 신뢰할 수 있는 CA에서 발급되었는지 |
| 폐기 상태 | 인증서가 폐기되지 않았는지 (CRL) |

---

## 보안 모드 설정

### SecurityMode

```rust
pub enum SecurityMode {
    /// 보안 없음 (개발/테스트 전용)
    None,

    /// 서명만 (무결성 보장)
    Sign,

    /// 서명 및 암호화 (권장)
    SignAndEncrypt,
}
```

### SecurityPolicy

```rust
pub enum SecurityPolicy {
    /// 보안 없음
    None,

    /// 레거시 (권장하지 않음)
    Basic128Rsa15,

    /// 레거시 (권장하지 않음)
    Basic256,

    /// 현재 권장
    Basic256Sha256,

    /// 최신 보안 (AES-256-CBC + SHA-256)
    Aes128Sha256RsaOaep,

    /// 최신 보안 (AES-256-CBC + SHA-256)
    Aes256Sha256RsaPss,
}
```

### 보안 수준별 권장 설정

#### 개발/테스트 환경

```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://localhost:4840")
    .security_mode(SecurityMode::None)
    .security_policy(SecurityPolicy::None)
    .build()?;
```

#### 내부 네트워크 (격리된 산업용 네트워크)

```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://192.168.100.10:4840")
    .security_mode(SecurityMode::Sign)
    .security_policy(SecurityPolicy::Basic256Sha256)
    .certificate(cert_config)
    .build()?;
```

#### 프로덕션 환경 (권장)

```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://plc.factory.local:4840")
    .security_mode(SecurityMode::SignAndEncrypt)
    .security_policy(SecurityPolicy::Aes256Sha256RsaPss)
    .certificate(cert_config)
    .build()?;
```

---

## 사용자 인증

### 인증 유형

#### 1. 익명 (Anonymous)

```rust
// 기본값 - 사용자 인증 없음
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://localhost:4840")
    .anonymous()
    .build()?;
```

#### 2. 사용자명/비밀번호

```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://localhost:4840")
    .username("operator", "P@ssw0rd!")
    .build()?;
```

**보안 주의사항:**
- 비밀번호를 코드에 하드코딩하지 마세요
- 환경 변수나 안전한 저장소 사용
- SignAndEncrypt 모드와 함께 사용

```rust
// 환경 변수에서 자격 증명 로드
let username = std::env::var("OPCUA_USERNAME")
    .expect("OPCUA_USERNAME not set");
let password = std::env::var("OPCUA_PASSWORD")
    .expect("OPCUA_PASSWORD not set");

let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://localhost:4840")
    .security_mode(SecurityMode::SignAndEncrypt)
    .security_policy(SecurityPolicy::Basic256Sha256)
    .username(&username, &password)
    .build()?;
```

#### 3. X.509 인증서

```rust
let config = OpcUaConfig::builder()
    .endpoint("opc.tcp://localhost:4840")
    .user_certificate(
        "/path/to/user.der",
        "/path/to/user.pem"
    )
    .build()?;
```

---

## 권장 보안 구성

### 시나리오 1: 격리된 산업용 네트워크

```yaml
# trap.yaml
opcua:
  endpoint: "opc.tcp://192.168.100.10:4840"
  security:
    mode: Sign
    policy: Basic256Sha256
  certificate:
    cert_path: "/etc/trap/certs/client.der"
    private_key_path: "/etc/trap/certs/client.pem"
    trust_server_certs: true  # 신뢰할 수 있는 내부 네트워크
  user:
    type: anonymous
```

### 시나리오 2: 인터넷 경유 연결

```yaml
# trap.yaml
opcua:
  endpoint: "opc.tcp://remote-plc.example.com:4840"
  security:
    mode: SignAndEncrypt
    policy: Aes256Sha256RsaPss
  certificate:
    cert_path: "/etc/trap/certs/client.der"
    private_key_path: "/etc/trap/certs/client.pem"
    trust_server_certs: false
    trusted_certs_dir: "/etc/trap/certs/trusted"
    rejected_certs_dir: "/etc/trap/certs/rejected"
  user:
    type: username
    username: "${OPCUA_USERNAME}"
    password: "${OPCUA_PASSWORD}"
```

### 시나리오 3: 고보안 요구사항

```yaml
# trap.yaml
opcua:
  endpoint: "opc.tcp://critical-plc.factory.local:4840"
  security:
    mode: SignAndEncrypt
    policy: Aes256Sha256RsaPss
  certificate:
    cert_path: "/etc/trap/certs/client.der"
    private_key_path: "/etc/trap/certs/client.pem"
    trust_server_certs: false
    trusted_certs_dir: "/etc/trap/certs/trusted"
    rejected_certs_dir: "/etc/trap/certs/rejected"
    crl_check: true
    crl_path: "/etc/trap/certs/crl"
  user:
    type: certificate
    cert_path: "/etc/trap/certs/user.der"
    private_key_path: "/etc/trap/certs/user.pem"
  session:
    timeout_seconds: 600  # 10분
    max_keep_alive: 30
```

---

## 보안 체크리스트

### 배포 전 체크리스트

#### 인증서

- [ ] 자체 서명이 아닌 CA 발급 인증서 사용 (프로덕션)
- [ ] 인증서 유효 기간 확인 (최소 1년 권장)
- [ ] 적절한 키 길이 사용 (최소 2048비트 RSA)
- [ ] OPC UA 필수 확장 포함 (keyUsage, extendedKeyUsage)
- [ ] 인증서 폐기 확인 프로세스 설정

#### 보안 모드

- [ ] SecurityMode.None 사용하지 않음 (프로덕션)
- [ ] 레거시 정책 사용하지 않음 (Basic128Rsa15, Basic256)
- [ ] 최신 보안 정책 사용 (Basic256Sha256 이상)

#### 사용자 인증

- [ ] 익명 접근 비활성화 (가능한 경우)
- [ ] 강력한 비밀번호 정책 적용
- [ ] 비밀번호 환경 변수 또는 비밀 관리자 사용
- [ ] 불필요한 사용자 계정 제거

#### 네트워크

- [ ] 방화벽에서 OPC UA 포트 (4840) 접근 제한
- [ ] 불필요한 네트워크 노출 방지
- [ ] VPN 또는 전용선 사용 (인터넷 경유 시)

#### 모니터링

- [ ] 연결 시도 로깅 활성화
- [ ] 실패한 인증 시도 알림 설정
- [ ] 비정상 트래픽 패턴 모니터링

### 정기 점검 항목

| 점검 항목 | 주기 | 설명 |
|----------|------|------|
| 인증서 만료 | 월간 | 만료 30일 전 갱신 |
| 비밀번호 변경 | 분기 | 정기 비밀번호 교체 |
| 접근 로그 검토 | 주간 | 비정상 접근 패턴 확인 |
| 보안 업데이트 | 월간 | 라이브러리 보안 패치 |
| 정책 검토 | 연간 | 보안 정책 재평가 |

---

## 문제 해결

### 일반적인 보안 오류

#### "BadCertificateUntrusted"

서버가 클라이언트 인증서를 신뢰하지 않습니다.

**해결책:**
1. 서버의 신뢰할 인증서 폴더에 클라이언트 인증서 추가
2. 또는 서버에서 자동 신뢰 옵션 활성화 (개발용만)

#### "BadSecurityModeRejected"

요청한 보안 모드가 서버에서 지원되지 않습니다.

**해결책:**
1. `GetEndpoints`로 지원되는 보안 모드 확인
2. 서버가 지원하는 모드로 변경

#### "BadUserAccessDenied"

사용자 인증 실패.

**해결책:**
1. 사용자명/비밀번호 확인
2. 사용자 계정이 활성화되어 있는지 확인
3. 필요한 권한이 있는지 확인

---

## 참고 자료

- [OPC UA Security Analysis](https://opcfoundation.org/security/)
- [ICS-CERT OPC UA Security Advisory](https://www.cisa.gov/uscert/ics)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
