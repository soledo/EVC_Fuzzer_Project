# EVC Fuzzer - 통합 V2G 프로토콜 퍼저

ISO 15118 및 DIN 70121 프로토콜을 사용하여 전기차 통신 제어기(EVCC)와 공급 장비 통신 제어기(SECC) 구현을 테스트하기 위한 종합적인 퍼징 도구입니다.

## 개요

EVC Fuzzer가 **통합 아키텍처로 업데이트**되어 모든 상태별 퍼징 기능을 단일 매개변수화된 도구로 통합했습니다. 이는 각 프로토콜 상태마다 별도 파일을 유지하던 기존 방식을 대체합니다.

### 🆕 최신 업데이트 (2025.09.10)

**듀얼 퍼징 모드 및 상태 머신 관리 시스템 추가**:
- **새로운 기능**: `--fuzzing-mode` 파라미터로 독립/준수 모드 선택
- **Independent Mode**: 상태 독립적 퍼징 (EVSE 시뮬레이터 환경용)
- **Compliant Mode**: V2G 상태 머신 순서 준수 퍼징 (실제 충전기 환경용)
- **상태 머신 관리**: 상태 간 의존성 및 응답 검증 시스템 구현
- **향상된 크래시 감지**: 타임아웃, RST 패킷, EXI 디코딩 실패 구분

**프로토콜 지원 현황**:
- **EXI 처리**: DIN, ISO-2, ISO-20 프로토콜별 EXI 인코딩/디코딩 지원
- **XML 메시지 생성**: 현재 DIN 70121만 지원 (XML 템플릿 제한)
- **완전한 프로토콜별 퍼징을 위해서는 추가 개발 필요**

자세한 변경사항은 [CHANGELOG.md](../CHANGELOG.md)를 참조하세요.

### 주요 기능

- **통합 아키텍처**: 단일 `unified_fuzzer.py`가 11개의 개별 상태별 퍼저를 대체
- **상태 기반 퍼징**: 특정 V2G 프로토콜 상태 타겟팅 (state1-state11)
- **듀얼 퍼징 모드**: 독립적/준수 모드로 다양한 환경 지원
- **상태 머신 관리**: V2G 프로토콜 순서 및 의존성 검증
- **설정 가능한 변이**: 4가지 변이 알고리즘 (플립, 랜덤값, 삭제, 삽입)
- **고급 크래시 감지**: 타임아웃, RST, EXI 디코딩 실패 구분
- **재시작 기능**: 중단된 퍼징 세션을 위한 상태 유지
- **포괄적인 보고**: 재현 데이터와 통계 분석을 포함한 상세 보고서

## 빠른 시작

### 사전 요구사항

1. **시스템 의존성 설치**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install openjdk-11-jdk python3-pip
   
   # 설치 확인
   java -version
   python3 --version
   ```

2. **Python 패키지 설치**:
   ```bash
   # sudo 권한으로 실행하므로 시스템 전역 설치 필요
   sudo pip3 install -r ../requirements.txt
   # 또는 개별 설치:
   # sudo pip3 install scapy tqdm smbus requests colorama
   ```

**중요**: Java는 EXI 인코딩/디코딩을 위해 **필수**입니다. 퍼저가 시작할 때 자동으로 별도의 Java EXI 서버를 실행합니다.

3. **네트워크 환경 설정** (로컬 테스트용 가상 네트워크):
   ```bash
   # 가상 이더넷 페어 생성
   sudo ip link add veth-pev type veth peer name veth-evse
   sudo ip link set veth-pev up
   sudo ip link set veth-evse up
   ```

### 완전한 퍼징 데모 워크플로우

퍼징 테스트를 위해서는 **2개의 터미널**만 필요합니다:

#### 터미널 1: EVSE 시뮬레이터 (타겟)
```bash
cd ../EVC_Simulator
sudo python3 EVSE.py --interface veth-evse
```
*참고: EVSE가 시작되면 자동으로 자체 EXI 디코더 서버를 실행합니다*

#### 터미널 2: 통합 퍼저 (공격자)
```bash
cd ../EVC_Fuzzer

# 사용 가능한 상태 목록 확인
python3 unified_fuzzer.py --list-states

# 기본 퍼징 실행 (독립 모드)
sudo python3 unified_fuzzer.py --state state1 --interface veth-pev --iterations-per-element 50

# 상태 머신 준수 모드 (실제 충전기 환경용)
sudo python3 unified_fuzzer.py --state state5 --fuzzing-mode compliant --interface veth-pev --iterations-per-element 50
```
*참고: 퍼저도 시작될 때 자동으로 자체 EXI 디코더 서버를 실행합니다*

### 기본 사용법 (간단한 테스트)

위의 완전한 설정 후:

1. **사용 가능한 상태 목록 보기**:
   ```bash
   python3 unified_fuzzer.py --list-states
   ```

2. **퍼징 실행**:
   ```bash
   # 기본 설정으로 퍼징 (EVSE가 같은 네트워크에서 실행 중이어야 함)
   sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 100
   
   # 가상 네트워크 설정으로 퍼징
   sudo python3 unified_fuzzer.py --state state3 --interface veth-pev --iterations-per-element 50
   ```

3. **도움말 보기**:
   ```bash
   python3 unified_fuzzer.py --help
   ```

## 사용 가능한 퍼징 상태

| 상태    | 대상 프로토콜 단계 | 설명 |
|---------|-------------------|------|
| state1  | SupportedAppProtocol | SupportedAppProtocolRequest 퍼징 |
| state2  | SessionSetup | SessionSetupRequest 퍼징 |
| state3  | ServiceDiscovery | ServiceDiscoveryRequest 퍼징 |
| state4  | ServicePaymentSelection | ServicePaymentSelectionRequest 퍼징 |
| state5  | ContractAuthentication | ContractAuthenticationRequest 퍼징 |
| state6  | ChargeParameterDiscovery | ChargeParameterDiscoveryRequest 퍼징 |
| state7  | CableCheck | CableCheckRequest 퍼징 |
| state8  | PreCharge | PreChargeRequest 퍼징 |
| state9  | PowerDelivery | PowerDeliveryRequest 퍼징 |
| state10 | CurrentDemand | CurrentDemandRequest 퍼징 |
| state11 | SessionStop | SessionStopRequest 퍼징 |

## 명령행 옵션

```
사용법: unified_fuzzer.py [-h] [--state {state1,...,state11}] [--list-states]
                         [-M MODE] [-I INTERFACE] [--source-mac SOURCE_MAC]
                         [--source-ip SOURCE_IP] [--source-port SOURCE_PORT]
                         [-p PROTOCOL] [--iterations-per-element ITERATIONS]
                         [--verbose] [--fuzzing-mode {independent,compliant}]

EVC 테스팅을 위한 통합 V2G 프로토콜 퍼저

선택적 인수:
  -h, --help            도움말 메시지를 표시하고 종료
  --state               퍼징할 V2G 프로토콜 상태
  --list-states         사용 가능한 모든 퍼징 상태 목록 표시 후 종료
  -M, --mode            에뮬레이터 모드 (0=전체, 1=정지, 2=포트스캔)
  -I, --interface       이더넷 인터페이스 (기본값: eth1)
  --source-mac          소스 MAC 주소 (기본값: 00:1e:c0:f2:6c:a1)
  --source-ip           소스 IP 주소 (기본값: fe80::21e:c0ff:fef2:6ca1)
  --source-port         소스 포트 (기본값: 랜덤)
  -p, --protocol        프로토콜 (DIN, ISO-2, ISO-20, 기본값: DIN)
  --iterations-per-element  요소별 퍼징 반복 횟수 (기본값: 1000)
  --verbose             상세 출력 (XML 및 변이 정보 표시)
  --fuzzing-mode        퍼징 모드: independent (독립) 또는 compliant (준수) (기본값: independent)
```

## 사용 예제

### 기본 퍼징
```bash
# 요소당 50회 반복으로 SupportedAppProtocol 상태 퍼징
sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 50
```

### 고급 퍼징
```bash
# 사용자 정의 네트워크 구성으로 ServiceDiscovery 퍼징
sudo python3 unified_fuzzer.py \
  --state state3 \
  --interface veth-pev \
  --source-ip fe80::2 \
  --source-mac 52:9f:ad:fc:c6:5e \
  --iterations-per-element 100
```

### 퍼징 모드별 사용
```bash
# 독립 모드 (기본값) - 시뮬레이터 환경용
sudo python3 unified_fuzzer.py --state state5 --fuzzing-mode independent --iterations-per-element 50

# 준수 모드 - 실제 충전기 환경용 (상태 순서 준수)
sudo python3 unified_fuzzer.py --state state5 --fuzzing-mode compliant --iterations-per-element 50

# 상세 로깅 포함
sudo python3 unified_fuzzer.py --state state3 --verbose --iterations-per-element 25
```

### 프로토콜별 퍼징 (제한사항 있음)
```bash
# 프로토콜 파라미터 - EXI 처리에만 영향, XML 템플릿은 여전히 DIN
sudo python3 unified_fuzzer.py --state state2 --protocol ISO-2 --iterations-per-element 75
```
**참고**: 현재 XML 메시지 생성은 DIN 70121만 지원합니다. 완전한 프로토콜별 퍼징을 위해서는 XMLFormat.py의 프로토콜별 구현이 필요합니다.

## 출력 및 보고

퍼징 결과는 **`fuzzing_reports/` 디렉토리**에 자동으로 저장됩니다.

### 📊 리포팅 시스템 개요

통합 퍼저는 향상된 리포팅 시스템을 제공합니다:
- **실시간 메트릭 수집**: 응답 시간, 성공률, 오류율 추적
- **포괄적인 통계 분석**: 변이 함수 효과성, 요소별 취약점 분석
- **구조화된 JSON 출력**: 자동화된 분석 및 시각화 가능

**상세한 리포팅 시스템 문서는 [REPORTING_SYSTEM.md](../REPORTING_SYSTEM.md)를 참조하세요.**

### 퍼징 상태 파일
- `fuzzing_reports/fuzzing_state_[state].json`: 재시작 기능을 위한 현재 진행 상황 저장
- 성공적으로 완료되면 자동으로 제거됨

### 퍼징 리포트 파일
- `fuzzing_reports/fuzzing_report_[state].json`: 종합적인 퍼징 분석 결과
- 포함 내용:
  - 세션 메타데이터 (시간, 대상 상태, 설명)
  - 성능 메트릭 (응답률, 오류율, 크래시율)
  - 상세 통계 (변이 함수별, 요소별, 응답 시간)
  - 크래시 상세 정보 (재현 데이터 포함)

### 보고서 구조 예제
```json
{
  "target_state": "state2",
  "state_name": "SessionSetup",
  "description": "Fuzzes the SessionSetupRequest",
  "session_start_time": 1755592925.678,
  "session_duration": 17.203,
  "total_attempts": 100,
  "total_crashes": 0,
  "metrics": {
    "correct_response_rate": 1.0,
    "incorrect_response_rate": 99.0,
    "non_error_fuzz_rate": 99.0,
    "crash_rate": 0.0
  },
  "comprehensive_data": {
    "vulnerability_candidates_count": 99,
    "mutation_function_stats": {
      "random_deletion": 28,
      "value_flip": 24,
      "random_insertion": 25,
      "random_value": 22
    },
    "response_time_stats": {
      "average": 0.074,
      "min": 0.040,
      "max": 0.324
    }
  }
}
```

## 통합 퍼저 아키텍처

이 프로젝트는 **통합 퍼저 아키텍처**를 사용합니다:

### 통합 퍼저 (`unified_fuzzer.py`)
- **모든 V2G 상태를 하나의 도구로 처리**
- 매개변수를 통한 상태 선택 (`--state state1`)
- 일관된 인터페이스와 보고 시스템
- 중앙화된 설정 관리
- 깔끔한 코드 유지보수

### 사용 예제
```bash
# 다양한 상태 퍼징
sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 100
sudo python3 unified_fuzzer.py --state state3 --iterations-per-element 50
sudo python3 unified_fuzzer.py --state state10 --iterations-per-element 200
```

## 아키텍처 세부사항

### 상태 구성
퍼저는 중앙화된 `STATE_CONFIG` 딕셔너리를 사용하여 다음을 정의합니다:
- 각 상태별 대상 XML 요소
- 메시지 전제조건 (대기할 응답)
- XML 생성 메서드
- 상태별 설명

### 변이 알고리즘
1. **값 뒤집기 (value_flip)**: 대상 문자열 내 두 문자의 위치를 교환
2. **랜덤 값 (random_value)**: 임의 위치의 문자를 랜덤 문자로 교체
3. **랜덤 삭제 (random_deletion)**: 임의 위치의 문자를 제거
4. **랜덤 삽입 (random_insertion)**: 임의 위치에 랜덤 문자를 삽입

### 크래시 감지 기준
- **네트워크 크래시**: 2초 타임아웃, TCP RST 패킷 수신
- **프로토콜 크래시**: EXI 디코딩 실패, 예외 발생
- **비정상 응답**: 예상되지 않은 응답 코드 (취약점 후보)

### 듀얼 퍼징 모드
- **Independent Mode**: 상태 순서 무시, 직접 접근 (시뮬레이터용)
- **Compliant Mode**: V2G 상태 머신 순서 준수 (실제 충전기용)

### 네트워크 스택
- **Layer 1**: J1772 제어/근접 파일럿 신호
- **Layer 2**: HomePlug Green PHY (SLAC 프로토콜)
- **Layer 3**: IPv6 링크-로컬 네트워킹
- **Layer 4**: EXI 인코딩을 사용한 V2G TCP 메시징

## 문제 해결

### 일반적인 문제

1. **권한 거부됨**:
   ```bash
   # 네트워크 인터페이스 접근을 위해 sudo로 실행
   sudo python3 unified_fuzzer.py --state state1
   ```

2. **EXI 디코더가 실행되지 않음**:
   ```bash
   # 먼저 디코더 서버를 시작
   cd ../shared/java_decoder
   java -jar V2Gdecoder-jar-with-dependencies.jar -w
   ```

3. **네트워크 인터페이스 문제**:
   ```bash
   # 사용 가능한 인터페이스 확인
   ip link show
   
   # 올바른 인터페이스 이름 사용
   python3 unified_fuzzer.py --state state1 -I eth0  # 또는 사용자의 인터페이스
   ```

4. **import 오류**:
   ```bash
   # EVC_Fuzzer 디렉토리에 있는지 확인
   cd /path/to/EVC_Fuzzing_Project/EVC_Fuzzer
   python3 unified_fuzzer.py --list-states
   ```

### 디버그 정보
퍼저는 다음을 포함한 상세한 출력을 제공합니다:
- 상태 초기화 메시지
- 각 반복에 대한 변이 세부사항
- 네트워크 패킷 정보
- 크래시 감지 및 로깅

### 네트워크 요구사항
- **IPv6 링크-로컬 네트워킹**: V2G 프로토콜은 IPv6를 사용합니다
- **원시 소켓 접근**: 퍼저는 sudo 권한이 필요합니다
- **전용 네트워크 인터페이스**: 퍼저와 타겟 간 통신용
- **HomePlug 레이어**: SLAC 프로토콜을 위한 커스텀 Scapy 레이어

## 기여하기

퍼저를 수정할 때:
1. 새로운 상태에 대해 `STATE_CONFIG` 딕셔너리 업데이트
2. `--list-states`로 구성 검증 테스트
3. 커밋 전 기본 기능 테스트 실행
4. 중요한 변경사항에 대해 이 README 업데이트

## 보안 참고사항

이 퍼저는 **방어적 보안 테스팅 전용**으로 설계되었습니다. 다음 용도로 사용해야 합니다:
- EV 충전 인프라의 견고성 테스트
- V2G 구현의 취약점 식별
- 프로토콜 준수성 검증

**중요**: 이 도구를 악의적인 목적이나 소유하지 않거나 명시적인 테스트 허가가 없는 시스템에 대해 사용하지 마십시오. 주로 **EVC_Simulator의 EVSE.py**를 대상으로 한 테스팅 환경에서 사용하도록 설계되었습니다.

## 관련 문서

- [프로젝트 루트 README](../README.md) - 전체 프로젝트 개요
- [EVC_Simulator README](../EVC_Simulator/README.md) - EVSE 시뮬레이터 (테스트 대상)
- [설치 가이드](../INSTALLATION.md) - 상세 설치 방법
- [테스팅 가이드](../TESTING.md) - 다양한 테스트 시나리오
- [문제 해결](../docs/TROUBLESHOOTING.md) - 일반적인 문제 해결