# V2G 프로토콜 퍼저 변조 기법 문서

## 개요
이 문서는 EVC 퍼징 프로젝트에서 사용되는 4가지 핵심 변조 기법(Mutation Techniques)에 대해 설명합니다. 각 기법은 V2G 프로토콜 메시지의 XML 요소 값을 체계적으로 변조하여 타겟 시스템의 취약점을 발견하는 데 사용됩니다.

## 변조 기법 상세 분석

### 1. Value Flip (값 뒤집기)
**함수명**: `value_flip(self, value)`

#### 동작 방식
- 문자열 내에서 무작위로 2개의 문자 위치를 선택하여 서로 교환
- 최소 2개 이상의 문자가 있어야 동작
- 문자열의 구조는 유지하면서 순서만 변경

#### 코드 구현
```python
def value_flip(self, value):
    if len(value) < 2:
        return value
    idx1, idx2 = random.sample(range(len(value)), 2)
    value_list = list(value)
    value_list[idx1], value_list[idx2] = value_list[idx2], value_list[idx1]
    return ''.join(value_list)
```

#### 예시
- 입력: `"urn:iso:15118:2:2013:MsgDef"`
- 가능한 출력: `"urn:iso:15118:2:2013:MsgDef"` → `"urn:iso:15118:2:2013:MsgDef"`
  - 예: 3번째 'n'과 15번째 '2' 교환 → `"ur2:iso:15118:n:2013:MsgDef"`

#### 장점
- 원본 길이 유지로 버퍼 오버플로우 회피
- 형식 검증 로직을 부분적으로 통과 가능
- 타입 체크 우회 가능성

#### 타겟 취약점
- 문자열 파싱 로직의 순서 의존성
- 불완전한 입력 검증
- 패턴 매칭 알고리즘의 취약점

---

### 2. Random Value (랜덤 치환)
**함수명**: `random_value(self, value)`

#### 동작 방식
- 문자열 내 무작위 위치의 한 문자를 ASCII 인쇄 가능 문자(33-126)로 교체
- 원본 문자열 길이 유지
- ASCII 범위: `!` (33) ~ `~` (126)

#### 코드 구현
```python
def random_value(self, value):
    if len(value) == 0:
        return value
    idx = random.randrange(len(value))
    new_char = chr(random.randint(33, 126))
    value_list = list(value)
    value_list[idx] = new_char
    return ''.join(value_list)
```

#### 예시
- 입력: `"NO_ERROR"`
- 가능한 출력: 
  - 2번째 위치에 '@' 삽입 → `"N@_ERROR"`
  - 5번째 위치에 '}' 삽입 → `"NO_ER}OR"`

#### 장점
- 특수 문자 주입으로 인젝션 취약점 탐지
- XML 파서의 특수 문자 처리 테스트
- 인코딩 관련 문제 발견

#### 타겟 취약점
- SQL/XML 인젝션
- 특수 문자 이스케이프 누락
- 문자 인코딩 처리 오류
- 정규식 패턴 매칭 취약점

---

### 3. Random Deletion (랜덤 삭제)
**함수명**: `random_deletion(self, value)`

#### 동작 방식
- 문자열에서 무작위로 한 문자를 삭제
- 문자열 길이가 1 감소
- 빈 문자열은 그대로 반환

#### 코드 구현
```python
def random_deletion(self, value):
    if len(value) == 0:
        return value
    idx = random.randrange(len(value))
    value_list = list(value)
    del value_list[idx]
    return ''.join(value_list)
```

#### 예시
- 입력: `"ExternalPayment"`
- 가능한 출력:
  - 8번째 'P' 삭제 → `"Externalayment"`
  - 첫 번째 'E' 삭제 → `"xternalPayment"`

#### 장점
- 필수 문자 누락 시 처리 테스트
- 최소 길이 검증 로직 테스트
- 경계 조건 검사

#### 타겟 취약점
- 길이 검증 누락
- Null 포인터 역참조
- 배열 경계 검사 오류
- 파싱 로직의 off-by-one 에러

---

### 4. Random Insertion (랜덤 삽입)
**함수명**: `random_insertion(self, value)`

#### 동작 방식
- 문자열의 무작위 위치에 영숫자(a-z, A-Z, 0-9) 한 문자 삽입
- 문자열 길이가 1 증가
- 문자열 시작, 중간, 끝 어디든 삽입 가능

#### 코드 구현
```python
def random_insertion(self, value):
    if len(value) == 0:
        return value
    
    insert_idx = random.randrange(len(value)+1)
    random_char = random.choice(string.ascii_letters + string.digits)
    value_list = list(value)
    value_list.insert(insert_idx, random_char)
    return ''.join(value_list)
```

#### 예시
- 입력: `"true"`
- 가능한 출력:
  - 시작에 'X' 삽입 → `"Xtrue"`
  - 중간에 '7' 삽입 → `"tr7ue"`
  - 끝에 'z' 삽입 → `"truez"`

#### 장점
- 버퍼 오버플로우 취약점 탐지
- 최대 길이 제한 테스트
- 메모리 할당 오류 발견

#### 타겟 취약점
- 버퍼 오버플로우
- 힙 오버플로우
- 스택 오버플로우
- 동적 메모리 관리 오류

---

## 변조 기법 적용 전략

### 적용 프로세스
1. **요소 선택**: STATE_CONFIG에 정의된 각 상태별 변조 대상 요소 선택
2. **반복 실행**: 각 요소당 설정된 반복 횟수만큼 변조 수행
3. **함수 순환**: 4가지 변조 함수를 순차적으로 적용
4. **결과 모니터링**: 타겟 시스템의 응답 또는 크래시 감지

### 변조 함수 선택 로직
```python
mutation_funcs = [
    self.value_flip,
    self.random_value,
    self.random_deletion,
    self.random_insertion
]

for iteration in range(iterations_per_element):
    mutation_func = mutation_funcs[iteration % len(mutation_funcs)]
    mutated_value = mutation_func(original_value)
```

### 효과성 분석

#### 커버리지
- **구조적 변조**: Value Flip
- **문자 수준 변조**: Random Value
- **길이 감소**: Random Deletion
- **길이 증가**: Random Insertion

#### 취약점 탐지 능력
| 변조 기법 | 주요 탐지 대상 | 효과성 |
|-----------|----------------|---------|
| Value Flip | 파싱 로직, 순서 의존성 | 중간 |
| Random Value | 인젝션, 특수 문자 처리 | 높음 |
| Random Deletion | 경계 검사, 최소 길이 | 중간 |
| Random Insertion | 버퍼 오버플로우, 메모리 관리 | 높음 |

---

## 실제 적용 예시

### State1: SupportedAppProtocol 퍼징
```python
elements_to_modify = [
    "ProtocolNamespace",    # "urn:iso:15118:2:2013:MsgDef"
    "VersionNumberMajor",   # "2"
    "VersionNumberMinor",   # "0"
    "SchemaID",            # "1"
    "Priority"             # "1"
]
```

각 요소에 대해:
- 100회 반복 시 각 변조 함수가 25회씩 적용
- 총 500개의 변조된 메시지 생성 (5개 요소 × 100회)

### 크래시 유발 시나리오

1. **ProtocolNamespace 변조**
   - Random Deletion으로 ':' 제거 → 네임스페이스 파싱 실패
   - Random Value로 특수 문자 삽입 → XML 파서 오류

2. **VersionNumberMajor 변조**
   - Random Insertion으로 문자 추가 → 정수 변환 실패
   - Value Flip으로 숫자 순서 변경 → 버전 검증 실패

---

## 개선 제안

### 추가 가능한 변조 기법
1. **Boundary Values**: 최대/최소값 테스트
2. **Format String**: 포맷 문자열 취약점 탐지
3. **Unicode Injection**: 유니코드 문자 주입
4. **Null Byte Injection**: Null 바이트 삽입
5. **XML Entity Expansion**: XXE 공격 시뮬레이션

### 지능형 변조 전략
- 컨텍스트 인식 변조 (데이터 타입별 특화)
- 학습 기반 변조 (이전 크래시 패턴 학습)
- 조합 변조 (여러 기법 동시 적용)

---

## 참고사항

- 모든 변조는 XML 문자열 수준에서 수행 후 EXI로 인코딩
- 크래시 발생 시 정확한 재현을 위해 변조된 XML 전체 저장
- 각 변조 기법의 효과는 타겟 시스템의 구현에 따라 다름
- 실제 취약점 발견 시 책임감 있는 공개 원칙 준수 필요