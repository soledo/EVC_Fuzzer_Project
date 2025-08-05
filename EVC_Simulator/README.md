# EVC 시뮬레이터

EVC 퍼징 프로젝트의 **테스트 대상** 역할을 하는 EVSE(Electric Vehicle Supply Equipment) 시뮬레이터입니다. 실제 충전소의 통신 프로토콜을 구현하여, 퍼저가 테스트할 수 있는 표준적인 V2G 서비스를 제공합니다.

## 개요

EVC_Simulator는 다음 역할을 수행합니다:
- **EVSE 에뮬레이션**: Supply Equipment Communications Controller (SECC) 역할
- **V2G 프로토콜 구현**: DIN 70121 및 ISO 15118 표준 지원
- **퍼징 대상**: EVC_Fuzzer의 테스트 타겟으로 동작

## 구성 요소

### 주요 파일
- `EVSE.py` - 충전소 에뮬레이터 메인 실행 파일
- `XMLBuilder.py` - 표준 V2G XML 메시지 구성 도구

### 의존성 (shared/ 디렉토리)
- `EXIProcessor.py` - EXI 인코딩/디코딩 처리
- `EmulatorEnum.py` - 프로토콜 상태 및 모드 정의
- `NMAPScanner.py` - 네트워크 스캐닝 기능
- `external_libs/` - HomePlugPWN, RISE-V2G 등 외부 라이브러리

## EVSE 시뮬레이터 기능

### 지원 프로토콜 스택

#### Layer 1: 물리 신호 (하드웨어 구성 시)
- J1772 Control Pilot (CP) 신호 생성
- Proximity Pilot (PP) 신호 처리
- GPIO 기반 릴레이 제어 (Raspberry Pi)

#### Layer 2: HomePlug Green PHY
- SLAC (Signal Level Attenuation Characterization) 프로토콜
- Association 및 Key Management
- 사용자 정의 Scapy 레이어 활용

#### Layer 3: 네트워크
- IPv6 link-local 주소 지정
- UDP SECC Discovery Protocol 응답
- TCP V2G 메시징 서버

#### Layer 4: V2G 애플리케이션
- DIN 70121 메시지 처리 (완전 지원)
- ISO 15118-2:2010 메시지 (부분 지원)
- EXI (Efficient XML Interchange) 인코딩/디코딩

### 지원되는 V2G 메시지

#### DIN 70121 (완전 구현)
1. **SupportedAppProtocolRes** - 지원 프로토콜 응답
2. **SessionSetupRes** - 세션 설정 응답
3. **ServiceDiscoveryRes** - 서비스 발견 응답
4. **ServicePaymentSelectionRes** - 결제 서비스 선택 응답
5. **ContractAuthenticationRes** - 계약 인증 응답
6. **ChargeParameterDiscoveryRes** - 충전 파라미터 발견 응답
7. **CableCheckRes** - 케이블 확인 응답
8. **PreChargeRes** - 사전 충전 응답
9. **PowerDeliveryRes** - 전력 전송 응답
10. **CurrentDemandRes** - 전류 요구 응답
11. **WeldingDetectionRes** - 용접 감지 응답
12. **SessionStopRes** - 세션 중지 응답

## 사용법

### 기본 실행

```bash
# 기본 설정으로 EVSE 시뮬레이터 실행
sudo python3 EVSE.py

# 특정 네트워크 인터페이스 지정
sudo python3 EVSE.py --interface eth1

# 가상 네트워크 인터페이스에서 실행 (테스팅용)
sudo python3 EVSE.py --interface veth-evse
```

### 명령행 옵션

```bash
# 도움말 보기
python3 EVSE.py --help

# 주요 옵션들:

# 네트워크 인터페이스 지정
python3 EVSE.py --interface eth1

# 실행 모드 설정
python3 EVSE.py --mode 0  # 0: 완전 대화 (기본)
python3 EVSE.py --mode 1  # 1: 대화 중단
python3 EVSE.py --mode 2  # 2: 포트 스캔

# 네트워크 주소 설정
python3 EVSE.py --source-mac 00:1e:c0:f2:6c:a0
python3 EVSE.py --source-ip fe80::21e:c0ff:fef2:6ca0
python3 EVSE.py --source-port 25565

# 프로토콜 선택
python3 EVSE.py --protocol DIN     # DIN 70121 (기본)
python3 EVSE.py --protocol ISO-2   # ISO 15118-2
python3 EVSE.py --protocol ISO-20  # ISO 15118-20

# HomePlug Green PHY 설정
python3 EVSE.py --NID "\\x9c\\xb0\\xb2\\xbb\\xf5\\x6c\\x0e"
python3 EVSE.py --NMK "\\x48\\xfe\\x56\\x02\\xdb\\xac\\xcd\\xe5\\x1e\\xda\\xdc\\x3e\\x08\\x1a\\x52\\xd1"

# NMAP 스캔 설정 (모드 2에서 사용)
python3 EVSE.py --nmap-mac <target_mac>
python3 EVSE.py --nmap-ip <target_ip>
python3 EVSE.py --nmap-ports "80,443,1000-2000"

# 하드웨어 테스트 옵션
python3 EVSE.py --modified-cordset  # 수정된 코드셋 사용 시
```

### 퍼징 테스트와의 연동

EVC_Simulator는 EVC_Fuzzer의 테스트 대상으로 설계되었습니다:

```bash
# 터미널 1: EVSE 시뮬레이터 (테스트 대상)
cd EVC_Simulator
sudo python3 EVSE.py --interface veth-evse

# 터미널 2: 퍼저 실행 (별도 터미널)
cd ../EVC_Fuzzer
sudo python3 unified_fuzzer.py --state state1 --interface veth-pev
```

## 동작 과정

### 1. 초기화 단계
- 네트워크 인터페이스 설정
- EXI 디코더 서버 자동 시작
- IPv6 link-local 주소 구성

### 2. SLAC 협상 처리
```
PEV → EVSE: CM_SLAC_PARM.REQ
EVSE → PEV: CM_SLAC_PARM.CNF
... (SLAC 프로토콜 완료)
```

### 3. SECC Discovery 응답
```
PEV → Multicast: SECCDiscoveryReq (UDP)
EVSE → PEV: SECCDiscoveryRes (UDP 포트 15118)
```

### 4. V2G Communication Session
```
PEV → EVSE: SupportedAppProtocolReq (TCP 포트 61851)
EVSE → PEV: SupportedAppProtocolRes
PEV → EVSE: SessionSetupReq  
EVSE → PEV: SessionSetupRes
... (충전 세션 진행)
```

## 설정 요구사항

### 네트워크 설정
- IPv6 활성화 필수
- Link-local 주소 자동 할당 또는 수동 설정
- Raw socket 접근을 위한 root 권한

### 소프트웨어 의존성

#### 1. 시스템 의존성 설치:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-11-jdk python3-pip

# 설치 확인
java -version
python3 --version
```

#### 2. Python 패키지 설치:
```bash
# sudo 권한으로 실행하므로 시스템 전역 설치 필요
sudo pip3 install -r ../requirements.txt
```

**중요**: Java는 EXI 인코딩/디코딩을 위해 **필수**입니다. EVSE 시뮬레이터가 시작할 때 자동으로 Java EXI 서버를 실행합니다.

### 하드웨어 설정 (옵션)
물리적 하드웨어 테스팅을 위한 Raspberry Pi 구성:
- GPIO 핀 설정 (릴레이 제어)
- I2C 인터페이스 활성화
- Devolo Green PHY 평가 보드 연결

## 로그 및 디버깅

### 실행 로그
시뮬레이터는 다음 정보를 출력합니다:
- 현재 프로토콜 상태
- 수신된 요청 메시지
- 전송하는 응답 메시지
- SLAC 협상 진행 상황
- TCP 연결 상태

### 디버그 모드
```bash
# 상세 디버그 정보 출력
export V2G_DEBUG=1
sudo python3 EVSE.py --interface eth1
```

### 네트워크 트래픽 모니터링
```bash
# V2G TCP 트래픽 캡처
sudo tcpdump -i eth1 'tcp port 61851'

# HomePlug 트래픽 캡처  
sudo tcpdump -i eth1 'ether proto 0x88e1'
```

## 알려진 제한사항

1. **TLS 미지원**: 현재 평문 TCP 통신만 지원
2. **Plug and Charge 미구현**: PKI 인증 기능 없음
3. **ISO 15118-20 미지원**: 최신 표준 미구현
4. **단일 세션**: 동시 다중 PEV 연결 미지원

## 확장 및 개발

### 새로운 메시지 추가
1. `XMLBuilder.py`에 메시지 구성 메서드 추가
2. `EVSE.py`에 메시지 처리 로직 구현
3. 상태 전환 로직 업데이트

### 커스터마이징
- 충전 파라미터 수정
- 에러 응답 시뮬레이션
- 특정 취약점 테스트를 위한 비정상 동작 구현

## 문제 해결

### 일반적인 문제

1. **권한 거부**:
   ```bash
   sudo python3 EVSE.py --interface eth1
   ```

2. **IPv6 비활성화**:
   ```bash
   sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
   ```

3. **EXI 디코더 오류**:
   ```bash
   cd ../shared/java_decoder
   java -jar V2Gdecoder-jar-with-dependencies.jar -w
   ```

4. **포트 충돌**:
   ```bash
   # 61851 포트 사용 중인 프로세스 확인
   sudo lsof -i :61851
   ```

상세한 문제 해결은 [../docs/TROUBLESHOOTING.md](../docs/TROUBLESHOOTING.md)를 참조하세요.

## 관련 문서

- [프로젝트 루트 README](../README.md) - 전체 프로젝트 개요
- [EVC_Fuzzer README](../EVC_Fuzzer/README.md) - 퍼징 도구 (이 시뮬레이터를 테스트함)
- [설치 가이드](../INSTALLATION.md) - 상세 설치 방법
- [테스팅 가이드](../TESTING.md) - 다양한 테스트 시나리오
- [문제 해결](../docs/TROUBLESHOOTING.md) - 일반적인 문제 해결

## 라이선스 및 인정

이 시뮬레이터는 다음 오픈소스 프로젝트를 기반으로 합니다:
- [AcCCS](https://github.com/IdahoLabResearch/AcCCS) - 원본 Access Capabilities for CCS 프로젝트
- [RISE-V2G](https://github.com/SwitchEV/RISE-V2G) - V2G 프로토콜 참조 구현
- [V2Gdecoder](https://github.com/FlUxIuS/V2Gdecoder) - EXI 인코딩/디코딩
- [HomePlugPWN](https://github.com/FlUxIuS/HomePlugPWN) - HomePlug 프로토콜 레이어

### 저작권 고지
```
MIT License

Copyright (c) 2023 Idaho National Laboratory Research Projects
```

원본 EVSE 시뮬레이터는 Idaho National Laboratory의 AcCCS 프로젝트에서 개발되었으며, 이 프로젝트에서는 퍼징 테스트 환경에 맞게 수정 및 확장하였습니다.