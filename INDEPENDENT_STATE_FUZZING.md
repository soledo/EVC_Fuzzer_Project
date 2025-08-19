# Independent State Fuzzing Guide

독립적인 상태 퍼징을 위한 사용 가이드입니다. 각 V2G 프로토콜 상태를 완전히 독립적으로 테스트할 수 있습니다.

## 🎯 문제 해결

기존 상태머신 퍼징에서 발생하는 문제:
- **상태 간 연결 상태 오염**: state1 퍼징 후 연결이 불안정해져 state2가 실패
- **불완전한 정리**: 네트워크 상태가 완전히 초기화되지 않음
- **프로세스 잔여**: 이전 상태의 프로세스가 남아있어 간섭

## 🔧 해결방안

### 1. 독립적인 상태 퍼저 (`independent_state_fuzzer.py`)

각 상태 테스트 전에 완전한 환경 초기화:
- **프로세스 정리**: 기존 퍼저 프로세스 강제 종료
- **네트워크 초기화**: ARP 캐시 클리어, 인터페이스 재시작
- **충분한 대기시간**: 상태 간 10초 대기 (조정 가능)

### 2. 강화된 기존 퍼저

`unified_fuzzer.py`의 상태 간 정리 로직 강화:
- **스레드 강제 종료**: 모든 네트워크 스레드 완전 정리
- **가비지 컬렉션**: 메모리 정리 강화
- **확장된 대기시간**: 3초 → 10초

## 🚀 사용법

### 기본 사용법

```bash
# 모든 상태를 독립적으로 테스트 (100 iterations per element)
sudo python3 independent_state_fuzzer.py --iterations 100

# 특정 상태들만 테스트
sudo python3 independent_state_fuzzer.py --states state1 state2 state3 --iterations 50

# 빠른 테스트 (짧은 대기시간)
sudo python3 independent_state_fuzzer.py --iterations 10 --cleanup-delay 5

# 특정 인터페이스 사용
sudo python3 independent_state_fuzzer.py --interface veth-pev --iterations 200
```

### 테스트 실행

```bash
# 간단한 테스트 (state1, state2, state3만 2 iterations)
sudo python3 test_independent_states.py

# 사용 가능한 상태 목록 확인
python3 independent_state_fuzzer.py --list-states
```

### 기존 퍼저와 비교

```bash
# 기존 방식 (연속 실행, 상태 간 오염 가능)
sudo python3 EVC_Fuzzer/unified_fuzzer.py --state all --iterations-per-element 50

# 새로운 방식 (완전 독립 실행)
sudo python3 independent_state_fuzzer.py --iterations 50
```

## 📊 결과 분석

### 결과 파일 위치

```
independent_fuzzing_results/
├── independent_fuzzing_report.json    # 전체 요약 보고서
├── state1_output.txt                  # 각 상태별 상세 출력
├── state2_output.txt
└── ...
```

### 보고서 내용

1. **요약 정보**
   - 전체 실행 시간
   - 성공/실패 상태 수
   - 성공률

2. **상태별 결과**
   - 실행 시간
   - 성공/실패 여부
   - 오류 메시지 (실패 시)

3. **상세 출력**
   - 각 상태별 퍼징 과정
   - 발견된 취약점
   - 네트워크 통신 로그

## ⚙️ 설정 옵션

### 명령줄 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--states` | 테스트할 특정 상태들 | 모든 상태 |
| `--iterations` | 요소당 퍼징 반복 수 | 100 |
| `--interface` | 네트워크 인터페이스 | 자동 감지 |
| `--cleanup-delay` | 상태 간 정리 대기시간 | 10초 |
| `--list-states` | 사용 가능한 상태 목록 표시 | - |

### 환경별 권장 설정

**빠른 테스트**
```bash
sudo python3 independent_state_fuzzer.py --iterations 5 --cleanup-delay 5
```

**표준 테스트**
```bash
sudo python3 independent_state_fuzzer.py --iterations 100 --cleanup-delay 10
```

**심화 테스트**
```bash
sudo python3 independent_state_fuzzer.py --iterations 500 --cleanup-delay 15
```

**특정 상태 집중 테스트**
```bash
sudo python3 independent_state_fuzzer.py --states state1 state6 state10 --iterations 1000
```

## 🔍 문제 해결

### 일반적인 문제

1. **권한 오류**
   ```
   ❌ This script requires root privileges
   ```
   **해결**: `sudo`로 실행

2. **인터페이스 오류**
   ```
   WARNING: Interface detection failed
   ```
   **해결**: `--interface` 옵션으로 명시적 지정

3. **시간 초과**
   ```
   ⏰ State timeout after 600s
   ```
   **해결**: `--cleanup-delay` 증가 또는 네트워크 환경 점검

### 로그 확인

```bash
# 특정 상태의 상세 로그 확인
cat independent_fuzzing_results/state1_output.txt

# 전체 요약 보고서 확인
cat independent_fuzzing_results/independent_fuzzing_report.json | jq '.'
```

## 📈 성능 최적화

### 병렬 실행 (권장하지 않음)

독립성을 보장하기 위해 순차 실행을 권장하지만, 필요시 수동으로 병렬 실행 가능:

```bash
# 터미널 1
sudo python3 independent_state_fuzzer.py --states state1 state4 state7 --iterations 100

# 터미널 2  
sudo python3 independent_state_fuzzer.py --states state2 state5 state8 --iterations 100

# 터미널 3
sudo python3 independent_state_fuzzer.py --states state3 state6 state9 --iterations 100
```

### 리소스 모니터링

```bash
# 실행 중 시스템 리소스 모니터링
watch -n 1 'ps aux | grep fuzzer'
watch -n 1 'netstat -tuln | grep :15118'
```

## 🧪 테스트 예제

### 예제 1: 빠른 검증

```bash
# 3개 상태만 빠르게 테스트
sudo python3 test_independent_states.py
```

### 예제 2: 특정 문제 상태 집중 분석

```bash
# 문제가 있었던 상태들만 집중 테스트
sudo python3 independent_state_fuzzer.py --states state1 state2 --iterations 500 --cleanup-delay 20
```

### 예제 3: 전체 프로토콜 검증

```bash
# 모든 상태를 충분한 반복으로 테스트
sudo python3 independent_state_fuzzer.py --iterations 300 --cleanup-delay 15
```

## 📋 체크리스트

퍼징 실행 전 확인사항:

- [ ] Root 권한으로 실행
- [ ] 네트워크 인터페이스 확인
- [ ] 충분한 디스크 공간 (결과 파일용)
- [ ] 시뮬레이터/대상 시스템 준비
- [ ] 방화벽/보안 소프트웨어 설정 확인

실행 후 확인사항:

- [ ] 결과 파일 생성 확인
- [ ] 성공률 점검
- [ ] 오류 로그 분석
- [ ] 발견된 취약점 검토