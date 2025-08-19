# V2G 프로토콜 퍼징 대상 분석

## 퍼징 대상 요약

EVC 퍼저는 **10개의 V2G 프로토콜 상태**와 **총 20개의 XML 요소**를 대상으로 퍼징을 수행할 수 있습니다.

## 상태별 퍼징 대상 상세

### 1. State1: SupportedAppProtocol
- **대상 요소 수**: 5개
- **퍼징 요소**:
  - `ProtocolNamespace`
  - `VersionNumberMajor`
  - `VersionNumberMinor`
  - `SchemaID`
  - `Priority`

### 2. State2: SessionSetup
- **대상 요소 수**: 1개
- **퍼징 요소**:
  - `V2G_Message/Body/SessionSetupReq/EVCCID`

### 3. State3: ServiceDiscovery
- **대상 요소 수**: 2개
- **퍼징 요소**:
  - `V2G_Message/Body/ServiceDiscoveryReq/ServiceScope`
  - `V2G_Message/Body/ServiceDiscoveryReq/ServiceCategory`

### 4. State4: ServicePaymentSelection
- **대상 요소 수**: 2개
- **퍼징 요소**:
  - `V2G_Message/Body/ServicePaymentSelectionReq/SelectedPaymentOption`
  - `V2G_Message/Body/ServicePaymentSelectionReq/SelectedServiceList/SelectedService/ServiceID`

### 5. State5: ChargeParameterDiscovery
- **대상 요소 수**: 2개
- **퍼징 요소**:
  - `V2G_Message/Body/ChargeParameterDiscoveryReq/RequestedEnergyTransferMode`
  - `V2G_Message/Body/ChargeParameterDiscoveryReq/EVChargeParameter/DepartureTime`

### 6. State6: CableCheck
- **대상 요소 수**: 2개
- **퍼징 요소**:
  - `V2G_Message/Body/CableCheckReq/DC_EVStatus/EVReady`
  - `V2G_Message/Body/CableCheckReq/DC_EVStatus/EVCabinConditioning`

### 7. State7: PreCharge
- **대상 요소 수**: 2개
- **퍼징 요소**:
  - `V2G_Message/Body/PreChargeReq/DC_EVStatus/EVReady`
  - `V2G_Message/Body/PreChargeReq/EVTargetVoltage/Value`

### 8. State8: PowerDelivery
- **대상 요소 수**: 2개
- **퍼징 요소**:
  - `V2G_Message/Body/PowerDeliveryReq/ChargeProgress`
  - `V2G_Message/Body/PowerDeliveryReq/DC_EVPowerDeliveryParameter/DC_EVStatus/EVReady`

### 9. State9: CurrentDemand
- **대상 요소 수**: 2개
- **퍼징 요소**:
  - `V2G_Message/Body/CurrentDemandReq/DC_EVStatus/EVReady`
  - `V2G_Message/Body/CurrentDemandReq/EVTargetCurrent/Value`

### 10. State10: WeldingDetection
- **대상 요소 수**: 2개
- **퍼징 요소**:
  - `V2G_Message/Body/WeldingDetectionReq/DC_EVStatus/EVReady`
  - `V2G_Message/Body/WeldingDetectionReq/DC_EVStatus/EVCabinConditioning`

## 퍼징 규모 계산

### 기본 계산식
- **총 상태 수**: 10개
- **총 요소 수**: 20개
- **변조 기법 수**: 4개 (value_flip, random_value, random_deletion, random_insertion)

### 테스트 케이스 계산 (기본 100회 반복 기준)
```
각 요소당 테스트 케이스 = 100회 반복
각 상태별 총 테스트 케이스 = 요소 수 × 100회

상태별 테스트 케이스:
- State1: 5개 요소 × 100 = 500 테스트
- State2: 1개 요소 × 100 = 100 테스트
- State3: 2개 요소 × 100 = 200 테스트
- State4: 2개 요소 × 100 = 200 테스트
- State5: 2개 요소 × 100 = 200 테스트
- State6: 2개 요소 × 100 = 200 테스트
- State7: 2개 요소 × 100 = 200 테스트
- State8: 2개 요소 × 100 = 200 테스트
- State9: 2개 요소 × 100 = 200 테스트
- State10: 2개 요소 × 100 = 200 테스트

전체 합계: 2,000 테스트 케이스
```

### 사용자 정의 반복 횟수
퍼저는 `--iterations-per-element` 매개변수로 반복 횟수를 조정할 수 있습니다:

```bash
# 요소당 50회 반복 → 총 1,000 테스트 케이스
sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 50

# 요소당 1000회 반복 → 총 20,000 테스트 케이스
sudo python3 unified_fuzzer.py --state state9 --iterations-per-element 1000
```

## 요소 유형별 분류

### 1. 프로토콜 메타데이터 (5개)
- `ProtocolNamespace`
- `VersionNumberMajor`
- `VersionNumberMinor`
- `SchemaID`
- `Priority`

### 2. 식별자 및 설정 (3개)
- `EVCCID`
- `ServiceScope`
- `ServiceCategory`
- `SelectedPaymentOption`
- `ServiceID`

### 3. 충전 파라미터 (4개)
- `RequestedEnergyTransferMode`
- `DepartureTime`
- `ChargeProgress`
- `EVTargetVoltage/Value`
- `EVTargetCurrent/Value`

### 4. 상태 플래그 (8개)
- `EVReady` (6회 반복 - 여러 상태에서 사용)
- `EVCabinConditioning` (2회)

## 확장 가능성

### 현재 미포함 요소들
V2G 프로토콜에는 더 많은 요소들이 있지만, 현재 퍼저는 핵심적이고 취약할 가능성이 높은 요소들만 선별하여 타겟팅하고 있습니다.

### 추가 가능한 대상
1. **복합 데이터 구조**: 중첩된 XML 구조
2. **바이너리 데이터**: 인증서, 키 데이터
3. **배열 요소**: 서비스 목록, 스케줄 배열
4. **선택적 요소**: 조건부로 포함되는 요소들

## 퍼징 전략 권장사항

### 포괄적 테스트
```bash
# 모든 상태를 순차적으로 테스트
for state in state1 state2 state3 state4 state5 state6 state7 state8 state9 state10; do
    sudo python3 unified_fuzzer.py --state $state --iterations-per-element 100
done
```

### 집중적 테스트
가장 복잡한 상태들을 높은 반복 횟수로 테스트:
```bash
# State1 (5개 요소) - 가장 많은 대상
sudo python3 unified_fuzzer.py --state state1 --iterations-per-element 500

# State5 (충전 파라미터) - 복잡한 로직
sudo python3 unified_fuzzer.py --state state5 --iterations-per-element 300
```

## 결론

EVC 퍼저는 **10개 상태 × 20개 요소 = 총 20개의 고유 퍼징 대상**을 제공하며, 반복 횟수에 따라 수백에서 수만 개의 테스트 케이스를 생성할 수 있는 포괄적인 V2G 프로토콜 퍼징 도구입니다.