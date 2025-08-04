# EVC Fuzzer - 통합 V2G 프로토콜 퍼저

ISO 15118 및 DIN 70121 프로토콜을 사용하여 전기차 통신 제어기(EVCC)와 공급 장비 통신 제어기(SECC) 구현을 테스트하기 위한 종합적인 퍼징 도구입니다.

## 개요

EVC Fuzzer가 **통합 아키텍처로 업데이트**되어 모든 상태별 퍼징 기능을 단일 매개변수화된 도구로 통합했습니다. 이는 각 프로토콜 상태마다 별도 파일을 유지하던 기존 방식을 대체합니다.

### 주요 기능

- **통합 아키텍처**: 단일 `unified_fuzzer.py`가 10개의 개별 상태별 퍼저를 대체
- **상태 기반 퍼징**: 특정 V2G 프로토콜 상태 타겟팅 (state1-state10)
- **설정 가능한 변이**: 다중 변이 알고리즘 (플립, 랜덤, 삭제, 삽입)
- **크래시 감지**: 타겟 크래시 자동 감지 및 로깅
- **재시작 기능**: 중단된 퍼징 세션을 위한 상태 유지
- **포괄적인 보고**: 재현 데이터와 함께 상세한 크래시 보고서

## 빠른 시작

### 사전 요구사항

1. **의존성 설치**:
   ```bash
   pip install scapy tqdm smbus requests
   ```

2. **네트워크 환경 설정** (로컬 테스트용 가상 네트워크):
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
cd /home/donghyuk/EVC_Fuzzing_Project/EVC_Fuzzer

# 사용 가능한 상태 목록 확인
python3 unified_fuzzer.py --list-states

# 퍼징 실행 (예: state1 퍼징)
sudo python3 unified_fuzzer.py --state state1 --interface veth-pev --iterations-per-element 50
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
| state5  | ChargeParameterDiscovery | ChargeParameterDiscoveryRequest 퍼징 |
| state6  | CableCheck | CableCheckRequest 퍼징 |
| state7  | PreCharge | PreChargeRequest 퍼징 |
| state8  | PowerDelivery | PowerDeliveryRequest 퍼징 |
| state9  | CurrentDemand | CurrentDemandRequest 퍼징 |
| state10 | WeldingDetection | WeldingDetectionRequest 퍼징 |

## 명령행 옵션

```
사용법: unified_fuzzer.py [-h] [--state {state1,...,state10}] [--list-states]
                         [-M MODE] [-I INTERFACE] [--source-mac SOURCE_MAC]
                         [--source-ip SOURCE_IP] [--source-port SOURCE_PORT]
                         [-p PROTOCOL] [--iterations-per-element ITERATIONS]

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

### 프로토콜별 퍼징
```bash
# 기본 DIN 대신 ISO-2 프로토콜 사용
sudo python3 unified_fuzzer.py --state state2 --protocol ISO-2 --iterations-per-element 75
```

## 출력 및 보고

### 퍼징 상태 파일
- `fuzzing_state_[state].json`: 재시작 기능을 위한 현재 진행 상황 저장
- 성공적으로 완료되면 자동으로 제거됨

### 크래시 보고서
- `fuzzing_report_[state].json`: 종합적인 크래시 분석
- 포함 내용:
  - 총 시도 횟수 및 크래시 횟수
  - 상세한 크래시 정보
  - 재현 데이터 (변이된 XML, 값)
  - 사용된 변이 함수

### 보고서 구조 예제
```json
{
  "target_state": "state1",
  "state_name": "SupportedAppProtocol",
  "description": "SupportedAppProtocolRequest 퍼징",
  "total_attempts": 500,
  "total_crashes": 3,
  "crash_details": [
    {
      "state": "state1",
      "element": "ProtocolNamespace",
      "iteration": 42,
      "mutated_value": "corrupted_value",
      "fuzzed_xml": "<xml>...</xml>",
      "mutation_function": "random_insertion"
    }
  ]
}
```

## 레거시 퍼저에서 마이그레이션

통합 퍼저는 다음의 더 이상 사용되지 않는 파일들을 대체합니다:
- `state1_fuzz.py` → `unified_fuzzer.py --state state1`
- `state2_fuzz.py` → `unified_fuzzer.py --state state2`
- ... (state3-state10도 동일)

### 마이그레이션 예제
```bash
# 기존 방식 (더 이상 사용하지 않음)
sudo python3 state1_fuzz.py --iterations-per-element 100

# 새로운 방식 (권장)
sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 100
```

## 아키텍처 세부사항

### 상태 구성
퍼저는 중앙화된 `STATE_CONFIG` 딕셔너리를 사용하여 다음을 정의합니다:
- 각 상태별 대상 XML 요소
- 메시지 전제조건 (대기할 응답)
- XML 생성 메서드
- 상태별 설명

### 변이 알고리즘
1. **값 뒤집기**: 대상 문자열 내 문자들을 교환
2. **랜덤 값**: 랜덤 문자를 새로운 문자로 교체
3. **랜덤 삭제**: 랜덤 문자를 제거
4. **랜덤 삽입**: 랜덤 위치에 랜덤 문자를 삽입

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

이 도구를 악의적인 목적이나 소유하지 않거나 명시적인 테스트 허가가 없는 시스템에 대해 사용하지 마십시오.