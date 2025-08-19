# 퍼징 리포팅 시스템 문서

## 개요

EVC Fuzzer의 리포팅 시스템은 퍼징 테스트 결과를 체계적으로 수집, 분석, 저장하는 종합적인 데이터 관리 시스템입니다. 이 문서는 리포팅 시스템의 아키텍처, 데이터 형식, 그리고 최근 개선사항을 설명합니다.

## 📊 리포팅 시스템 아키텍처

### 1. 데이터 수집 계층

퍼징 프로세스 중 실시간으로 데이터를 수집:

```python
# 퍼징 실행 중 데이터 수집
for iteration in range(iterations_per_element):
    # 변이 적용
    mutated_value, mutation_function = mutate_value(original_value)
    
    # 응답 분석
    response_time = end_time - start_time
    response_type = analyze_response(response)
    
    # 데이터 기록
    record_test_result(element, iteration, response_type, response_time)
```

### 2. 데이터 분석 계층

수집된 데이터를 다차원적으로 분석:

- **응답 분류**: 정상/비정상/오류/크래시
- **통계 계산**: 응답률, 성공률, 크래시율
- **패턴 식별**: 취약점 후보 식별

### 3. 데이터 저장 계층

JSON 형식으로 구조화된 리포트 생성 및 저장

## 📁 리포트 파일 구조

### 파일 명명 규칙

```
fuzzing_reports/
├── fuzzing_report_state1.json    # 완료된 퍼징 리포트
├── fuzzing_report_state2.json
├── ...
├── fuzzing_state_state1.json     # 진행 중 상태 파일 (임시)
└── fuzzing_state_state2.json
```

- **`fuzzing_report_*.json`**: 완료된 퍼징 세션의 최종 리포트
- **`fuzzing_state_*.json`**: 재시작 기능을 위한 진행 상태 (완료 시 삭제)

## 📝 JSON 리포트 형식

### 최상위 구조

```json
{
    "target_state": "state2",
    "state_name": "SessionSetup",
    "description": "Fuzzes the SessionSetupRequest",
    "session_start_time": 1755592925.6788976,
    "session_duration": 17.203054428100586,
    "elements_tested": ["EVCCID"],
    "total_attempts": 100,
    "total_crashes": 0,
    "crash_details": [],
    "metrics": {...},
    "comprehensive_data": {...}
}
```

### 필드 설명

#### 기본 메타데이터

| 필드 | 타입 | 설명 |
|------|------|------|
| `target_state` | string | 퍼징 대상 상태 식별자 (state1-state11) |
| `state_name` | string | V2G 프로토콜 상태 이름 |
| `description` | string | 퍼징 작업 설명 |
| `session_start_time` | float | 세션 시작 시간 (Unix timestamp) |
| `session_duration` | float | 총 실행 시간 (초) |
| `elements_tested` | array | 테스트된 XML 요소 목록 |
| `total_attempts` | int | 총 퍼징 시도 횟수 |
| `total_crashes` | int | 감지된 크래시 횟수 |

#### metrics 섹션

실시간 성능 메트릭과 응답 분석:

```json
"metrics": {
    "total_messages_sent": 100,
    "correct_responses": 1,
    "incorrect_responses": 99,
    "valid_request_errors": 0,
    "non_error_fuzzes": 99,
    "crashes": 0,
    "correct_response_rate": 1.0,
    "incorrect_response_rate": 99.0,
    "valid_request_error_rate": 0.0,
    "non_error_fuzz_rate": 99.0,
    "crash_rate": 0.0
}
```

| 메트릭 | 설명 | 계산 방법 |
|--------|------|-----------|
| `correct_responses` | 정상 응답 수 | 기대 응답과 일치하는 경우 |
| `incorrect_responses` | 비정상 응답 수 | 오류 없이 잘못된 응답 |
| `valid_request_errors` | 유효한 요청 오류 | 프로토콜 오류 응답 |
| `non_error_fuzzes` | 오류 없는 퍼즈 | 크래시 없이 처리된 변이 |
| `*_rate` | 백분율 | (해당 수 / 전체) * 100 |

#### comprehensive_data 섹션

상세한 통계 및 분석 데이터:

```json
"comprehensive_data": {
    "total_test_results": 100,
    "normal_test_results_count": 1,
    "vulnerability_candidates_count": 99,
    "mutation_function_stats": {
        "original_value": 1,
        "random_deletion": 28,
        "value_flip": 24,
        "random_insertion": 25,
        "random_value": 22
    },
    "element_stats": {
        "EVCCID": {
            "total_tests": 100,
            "vulnerability_candidates": 99,
            "crashes": 0
        }
    },
    "response_time_stats": {
        "count": 100,
        "average": 0.07382434368133545,
        "min": 0.03968191146850586,
        "max": 0.32361602783203125
    }
}
```

##### mutation_function_stats
각 변이 함수의 사용 빈도:

| 변이 함수 | 설명 |
|-----------|------|
| `original_value` | 변이 없는 원본 값 |
| `random_deletion` | 랜덤 문자 삭제 |
| `value_flip` | 문자 위치 교환 |
| `random_insertion` | 랜덤 문자 삽입 |
| `random_value` | 랜덤 문자 대체 |

##### element_stats
각 XML 요소별 테스트 통계:

| 필드 | 설명 |
|------|------|
| `total_tests` | 해당 요소 총 테스트 횟수 |
| `vulnerability_candidates` | 잠재적 취약점 발견 수 |
| `crashes` | 크래시 유발 횟수 |

##### response_time_stats
응답 시간 통계 (초 단위):

| 필드 | 설명 |
|------|------|
| `count` | 측정된 응답 수 |
| `average` | 평균 응답 시간 |
| `min` | 최소 응답 시간 |
| `max` | 최대 응답 시간 |

#### crash_details 섹션

크래시 발생 시 상세 정보:

```json
"crash_details": [
    {
        "state": "state2",
        "element": "EVCCID",
        "iteration": 42,
        "mutated_value": "corrupted_value",
        "fuzzed_xml": "<complete XML content>",
        "mutation_function": "random_insertion",
        "timestamp": 1755592942.123,
        "response_time": 0.5234
    }
]
```

## 🔄 리포팅 시스템 개선사항

### 기존 시스템 (vulnerability_analysis 포함)

```python
# 이전 버전 - 제거된 기능
"vulnerability_analysis": {
    "high_severity": [],
    "medium_severity": [],
    "low_severity": [],
    "analysis_summary": "..."
}
```

### 현재 시스템 (개선된 버전)

1. **vulnerability_analysis 섹션 제거**
   - 불필요한 자동 심각도 분류 제거
   - 대신 `vulnerability_candidates_count`로 단순화

2. **comprehensive_data 섹션 강화**
   - 변이 함수 통계 추가
   - 요소별 상세 통계
   - 응답 시간 분석

3. **metrics 섹션 표준화**
   - 명확한 응답 분류 체계
   - 백분율 계산 자동화
   - 실시간 성능 지표

## 📈 데이터 활용 방법

### 1. 취약점 식별

```python
# vulnerability_candidates_count가 높은 상태 찾기
if report["comprehensive_data"]["vulnerability_candidates_count"] > 50:
    print(f"State {state} shows potential vulnerabilities")
```

### 2. 성능 분석

```python
# 응답 시간 이상 탐지
avg_time = report["comprehensive_data"]["response_time_stats"]["average"]
max_time = report["comprehensive_data"]["response_time_stats"]["max"]
if max_time > avg_time * 10:
    print("Potential DoS vulnerability detected")
```

### 3. 변이 효과성 평가

```python
# 가장 효과적인 변이 함수 식별
mutation_stats = report["comprehensive_data"]["mutation_function_stats"]
most_effective = max(mutation_stats, key=mutation_stats.get)
```

## 🔍 리포트 해석 가이드

### 정상 동작 지표
- `correct_response_rate` > 95%: 시스템이 안정적
- `response_time_stats["average"]` < 0.1초: 정상 성능

### 이상 징후 지표
- `non_error_fuzz_rate` > 90%: EVSE가 너무 관대함 (보안 위험)
- `crash_rate` > 0: 크래시 취약점 존재
- `response_time_stats["max"]` > 1초: 잠재적 DoS 취약점

### 취약점 우선순위

1. **크래시 (최고 우선순위)**
   - `crash_details` 배열 확인
   - 재현 가능한 크래시는 즉시 패치 필요

2. **비정상 응답 (중간 우선순위)**
   - `incorrect_responses` 높음
   - 프로토콜 구현 오류 가능성

3. **성능 이상 (낮은 우선순위)**
   - `response_time_stats` 이상치
   - 최적화 필요

## 📊 통계 집계 예제

### 전체 퍼징 캠페인 요약

```python
import json
import glob

def summarize_campaign():
    total_stats = {
        "states_tested": 0,
        "total_messages": 0,
        "total_crashes": 0,
        "total_vulnerabilities": 0,
        "avg_response_time": []
    }
    
    for report_file in glob.glob("fuzzing_reports/fuzzing_report_*.json"):
        with open(report_file) as f:
            report = json.load(f)
            
        total_stats["states_tested"] += 1
        total_stats["total_messages"] += report["total_attempts"]
        total_stats["total_crashes"] += report["total_crashes"]
        total_stats["total_vulnerabilities"] += report["comprehensive_data"]["vulnerability_candidates_count"]
        total_stats["avg_response_time"].append(report["comprehensive_data"]["response_time_stats"]["average"])
    
    # 평균 계산
    total_stats["overall_avg_response"] = sum(total_stats["avg_response_time"]) / len(total_stats["avg_response_time"])
    
    return total_stats
```

## 🛠️ 커스터마이징

### 새로운 메트릭 추가

```python
# unified_fuzzer.py에서 수정
def generate_report(self):
    # 기존 메트릭...
    
    # 커스텀 메트릭 추가
    self.report_data["custom_metrics"] = {
        "your_metric": calculated_value,
        "another_metric": another_value
    }
```

### 리포트 형식 변경

```python
# CSV 내보내기 추가
def export_to_csv(report_data):
    import csv
    
    with open('report.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['State', 'Tests', 'Crashes', 'Vulnerabilities'])
        writer.writerow([
            report_data['state_name'],
            report_data['total_attempts'],
            report_data['total_crashes'],
            report_data['comprehensive_data']['vulnerability_candidates_count']
        ])
```

## 📋 체크리스트

퍼징 리포트 검토 시 확인사항:

- [ ] 모든 상태(state1-state11)의 리포트 파일 존재
- [ ] 각 리포트의 `total_attempts` >= 설정된 반복 횟수
- [ ] `crash_details` 배열에 재현 가능한 데이터 포함
- [ ] `response_time_stats` 이상치 확인
- [ ] `vulnerability_candidates_count` > 0인 상태 검토
- [ ] `mutation_function_stats` 균형 확인

## 🔗 관련 문서

- [CHANGELOG.md](CHANGELOG.md) - 리포팅 시스템 변경 이력
- [EVC_Fuzzer/README.md](EVC_Fuzzer/README.md) - 퍼저 사용법
- [unified_fuzzer.py](EVC_Fuzzer/unified_fuzzer.py) - 리포팅 구현 코드