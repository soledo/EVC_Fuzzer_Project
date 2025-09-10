# 변경 로그 (Changelog)

## [2025.09.10] - 듀얼 퍼징 모드 및 상태 머신 관리 시스템

### 🚀 새로운 핵심 기능

#### 듀얼 퍼징 모드 시스템
- **새로운 파라미터**: `--fuzzing-mode {independent,compliant}` 추가
- **Independent Mode**: 상태 독립적 퍼징 (EVSE 시뮬레이터 환경 최적화)
  - 상태 순서 무시하고 직접 접근
  - 빠른 퍼징 실행
  - 기본값으로 설정
- **Compliant Mode**: V2G 상태 머신 순서 준수 퍼징 (실제 충전기 환경)
  - 상태 간 의존성 검증
  - 순차적 프로토콜 진행
  - 실제 충전기와의 호환성 보장

#### V2G 상태 머신 관리 시스템
- **새로운 파일**: `state_machine_manager.py` 생성
- **상태 의존성 매핑**: 11개 V2G 상태 간 종속성 정의
  ```python
  STATE_DEPENDENCIES = {
      'state1': [],                           # SupportedAppProtocol
      'state2': ['state1'],                   # SessionSetup
      'state3': ['state1', 'state2'],        # ServiceDiscovery
      # ... 모든 상태에 대한 의존성 정의
  }
  ```
- **응답 검증**: XML 응답 메시지 자동 파싱 및 ResponseCode 확인
- **상태 진행 검증**: 각 단계별 올바른 응답 수신 확인

### 🔧 향상된 크래시 감지 시스템

#### 명확한 크래시 분류
- **네트워크 크래시**: 2초 타임아웃, TCP RST 패킷 수신
- **프로토콜 크래시**: EXI 디코딩 실패, 예외 발생
- **취약점 후보**: 비정상 응답 (크래시와 구분)
  - 정상 요청 → 에러 응답 (MCE 지표)
  - 변이 요청 → OK 응답 (MR 지표)

#### 상태 머신 통합
```python
# 상태 머신에 응답 전달
if hasattr(self, 'state_machine') and self.state_machine:
    self.state_machine.handle_response(decoded_xml)
```

### 📊 프로토콜 지원 현황 정리

#### EXI 처리 레벨
- **완전 지원**: DIN, ISO-2, ISO-20 프로토콜별 EXI 인코딩/디코딩
- **Java 웹서버**: 프로토콜별 스키마 자동 선택
- **실제 동작**: `--protocol` 파라미터가 올바르게 작동

#### XML 템플릿 제한사항
- **현재 상황**: XMLFormat.py는 DIN 70121만 지원
- **네임스페이스**: 모든 메시지가 DIN 네임스페이스로 하드코딩
- **개선 필요**: 완전한 프로토콜별 퍼징을 위해서는 XMLFormat.py 리팩토링 필요

### 🛠️ 기술적 개선사항

#### 코드 아키텍처
```python
def wait_and_start_fuzzing(self):
    if hasattr(self, 'fuzzing_mode') and self.fuzzing_mode == 'compliant':
        self._compliant_fuzzing()
    else:
        self._independent_fuzzing()
```

#### 상태 머신 통합
- **V2GStateMachine 클래스**: 상태 진행 및 검증 로직
- **응답 파싱**: XML 네임스페이스 인식 응답 메시지 분석
- **의존성 해결**: 필요한 선행 상태들을 자동으로 실행

### 📝 문서 업데이트

#### README.md 주요 변경사항
- **최신 업데이트 섹션**: 2025.09.10으로 변경
- **듀얼 퍼징 모드**: 상세한 사용법 및 예제 추가
- **프로토콜 지원 현황**: 제한사항 명시
- **크래시 감지 기준**: 정확한 분류 체계 설명
- **사용 예제**: 각 모드별 명령어 예제 추가

#### 명령줄 도움말 개선
```bash
--verbose             상세 출력 (XML 및 변이 정보 표시)
--fuzzing-mode        퍼징 모드: independent (독립) 또는 compliant (준수)
```

### 🧪 호환성 및 테스트

#### 기존 기능 유지
- **재시작 기능**: 중단된 세션 이어서 진행
- **4가지 변이 알고리즘**: value_flip, random_value, random_deletion, random_insertion
- **포괄적인 보고**: JSON 형식의 상세 분석 보고서
- **권한 관리**: sudo 실행 시 파일 소유권 자동 처리

#### 새로운 사용 시나리오
```bash
# 시뮬레이터 환경 (기본값)
sudo python3 unified_fuzzer.py --state state5 --interface veth-pev

# 실제 충전기 환경
sudo python3 unified_fuzzer.py --state state5 --fuzzing-mode compliant --interface veth-pev

# 상세 분석
sudo python3 unified_fuzzer.py --state state3 --verbose --fuzzing-mode compliant
```

### 🔍 제거된 항목

#### 테스트 파일 정리
- **삭제**: `test_dual_fuzzing_modes.py`
- **삭제**: `test_state_machine.py`
- **이유**: 개발용 테스트 파일로 배포에 불필요

### 🎯 성능 및 안정성

#### 향상된 기능
- **상태 머신 검증**: 실제 충전기와의 호환성 개선
- **응답 분석**: 더 정확한 크래시 vs 취약점 구분
- **모드별 최적화**: 환경에 따른 최적 퍼징 전략

#### 유지된 성능
- **재시작 기능**: 긴 퍼징 세션의 안정성
- **실시간 메트릭**: verbose 모드에서 10회마다 통계 출력
- **메모리 효율성**: 대량 퍼징 시에도 안정적 동작

---

## [2025.08.19] - 통합 퍼저 수정 및 개선

### 🔧 주요 수정사항 (Critical Fixes)

#### XML 네임스페이스 처리 개선
- **문제**: States 2-11에서 XML 요소를 찾지 못해 퍼징이 실패하던 문제
- **원인**: XPath 스타일 경로 (`'V2G_Message/Body/SessionSetupReq/EVCCID'`)가 XML 네임스페이스로 인해 작동하지 않음
- **해결**: 네임스페이스 인식 요소 검색으로 변경
  ```python
  # 수정 전: XPath 스타일
  'V2G_Message/Body/SessionSetupReq/EVCCID'
  
  # 수정 후: 단순 요소 이름
  'EVCCID'
  
  # 구현: 네임스페이스 처리
  target_elements = [elem for elem in root.iter() if elem.tag.split('}')[-1] == element_name]
  ```

#### 상태별 설정 수정
모든 상태 (state2-state11)의 `STATE_CONFIG` 업데이트:

| 상태 | 수정된 요소 | 이전 | 이후 |
|------|-------------|------|------|
| state2 | SessionSetup | `'V2G_Message/Body/SessionSetupReq/EVCCID'` | `'EVCCID'` |
| state3 | ServiceDiscovery | `'V2G_Message/Body/ServiceDiscoveryReq/ServiceCategory'` | `'ServiceCategory'` |
| state4 | ServicePaymentSelection | `'V2G_Message/Body/ServicePaymentSelectionReq/SelectedPaymentOption'` | `'SelectedPaymentOption'` |
| state5 | ContractAuthentication | `'V2G_Message/Body/ContractAuthenticationReq/Id'` | `'Id'` |
| state6 | ChargeParameterDiscovery | `'V2G_Message/Body/ChargeParameterDiscoveryReq/MaxEntriesSAScheduleTuple'` | `'MaxEntriesSAScheduleTuple'` |
| state7 | CableCheck | `'V2G_Message/Body/CableCheckReq/DC_EVStatus/EVReady'` | `'EVReady'` |
| state8 | PreCharge | `'V2G_Message/Body/PreChargeReq/DC_EVStatus/EVRESSSOC'` | `'EVRESSSOC'` |
| state9 | PowerDelivery | `'V2G_Message/Body/PowerDeliveryReq/ChargeProgress'` | `'ChargeProgress'` |
| state10 | CurrentDemand | `'V2G_Message/Body/CurrentDemandReq/DC_EVStatus/EVReady'` | `'EVReady'` |
| state11 | SessionStop | `'V2G_Message/Body/SessionStopReq/ChargingSession'` | `'ChargingSession'` |

### 📊 리포팅 시스템 개선

#### vulnerability_analysis 섹션 제거
- **이전**: 자동 심각도 분류 시스템 (high/medium/low_severity)
- **현재**: 단순화된 `vulnerability_candidates_count`로 대체
- **이유**: 실제 심각도는 컨텍스트에 따라 달라지므로 자동 분류가 부정확

#### comprehensive_data 섹션 강화
- **변이 함수 통계**: 각 변이 기법의 사용 빈도 추가
- **요소별 통계**: XML 요소별 테스트 결과 세분화
- **응답 시간 분석**: 평균/최소/최대 응답 시간 추적

#### metrics 섹션 표준화
- **응답 분류 체계**: correct/incorrect/error/crash로 명확히 구분
- **백분율 자동 계산**: 모든 메트릭에 대한 비율 계산
- **실시간 성능 지표**: 응답 시간 및 처리량 메트릭

### 📝 문서 업데이트

#### 새로운 문서 추가
- **REPORTING_SYSTEM.md**: 리포팅 시스템 아키텍처 및 데이터 형식 상세 문서
- **CHANGELOG.md**: 변경 이력 및 기술적 개선사항 문서

#### README 파일 수정
- **EVC_Fuzzer/README.md**: 
  - state11 추가 ("SessionStop | SessionStopRequest 퍼징")
  - state5 설명 수정 ("ChargeParameterDiscovery" → "ContractAuthentication")
  - 리포팅 시스템 개요 및 링크 추가
- **EVC_Simulator/README.md**: 
  - 67번째 줄 타이포 수정 ("ㅇ" 제거)
- **메인 README.md**:
  - CHANGELOG 및 REPORTING_SYSTEM 문서 링크 추가

### 🧪 테스트 결과

모든 상태에서 성공적인 퍼징 결과 확인:
- **state1**: SupportedAppProtocol 퍼징 성공
- **state2**: SessionSetup 퍼징 성공  
- **state3**: ServiceDiscovery 퍼징 성공
- **state4-state11**: 모든 상태에서 XML 요소 감지 및 퍼징 성공

### 🔍 기술적 세부사항

#### XML 네임스페이스 처리
```python
# 네임스페이스가 포함된 실제 XML 요소 태그:
# '{urn:din:70121:2012:MsgBody}EVCCID'

# 네임스페이스 제거 후 요소 이름 추출:
element_name = elem.tag.split('}')[-1]  # 'EVCCID'
```

#### 퍼징 프로세스 개선
1. **요소 탐지**: 네임스페이스 인식 검색으로 100% 성공률
2. **변이 적용**: 기존 4가지 변이 함수 유지
3. **응답 분석**: EVSE 응답 패턴 정확히 분석

### 🎯 성능 개선

- **요소 탐지 성공률**: 0% → 100%
- **퍼징 실행**: 모든 상태에서 정상 작동
- **비정상 응답 감지**: EVSE의 permissive 응답 패턴 정확히 식별

### 📊 호환성

- **Python 3.8+**: 호환성 유지
- **DIN 70121**: 완전 지원
- **ISO 15118**: 기본 지원
- **네트워크**: IPv6 링크-로컬 주소 지원

---

## 향후 개선 계획

1. **추가 변이 알고리즘**: 더 정교한 변이 기법 도입
2. **실시간 모니터링**: 퍼징 진행 상황 실시간 추적
3. **자동 재시작**: 크래시 후 자동 복구 기능
4. **성능 최적화**: 대량 퍼징을 위한 속도 개선

## 기여자

### [2025.09.10] 업데이트
- **donghyuk**: 듀얼 퍼징 모드 및 상태 머신 관리 시스템 구현

### [2025.08.19] 업데이트  
- **donghyuk**: XML 네임스페이스 수정 및 통합 퍼저 아키텍처 개선
- **donghyuk**: 문서 업데이트 및 상태 테이블 정확성 향상
- **donghyuk**: 모든 상태에서 퍼징 기능 검증 완료