# EVC 퍼징 프로젝트

ISO 15118 및 DIN 70121 프로토콜을 사용하는 전기차 통신 제어기(EVCC)와 공급 장비 통신 제어기(SECC) 구현을 위한 종합적인 테스팅 및 퍼징 프레임워크입니다.

## 개요

이 프로젝트는 전기차 충전 인프라의 보안 테스팅과 프로토콜 검증을 위한 도구를 제공합니다:

- **EVC_Simulator**: EVSE(충전소) 에뮬레이터 - 퍼징 테스트의 대상 역할
- **EVC_Fuzzer**: V2G 프로토콜의 취약점 발견을 위한 고급 퍼징 프레임워크

### 주요 기능

- **EVSE 에뮬레이션**: DIN 70121 및 ISO 15118 프로토콜을 지원하는 충전소 시뮬레이션
- **통합 퍼징 프레임워크**: 10개 V2G 프로토콜 상태를 대상으로 하는 상태 기반 퍼징
- **다양한 테스트 환경**: 가상 네트워크, VM 간 통신, 물리적 분산 테스팅 지원
- **포괄적인 취약점 탐지**: 크래시 감지, 로깅, 재현 가능한 테스트 케이스 생성
- **Raspberry Pi 하드웨어 지원**: 물리 계층 J1772 신호 에뮬레이션

## 빠른 시작

### 사전 요구사항

- Linux 기반 OS (Ubuntu 20.04/22.04, Debian 11/12, 또는 Raspberry Pi OS)
- Python 3.8 이상
- Java 8 이상 (EXI 인코더/디코더용)
- IPv6 지원 네트워크 인터페이스

### 설치

1. 저장소 복제:
   ```bash
   git clone --recurse-submodules <repository-url>
   cd EVC_Fuzzing_Project
   ```

2. 의존성 설치:
   ```bash
   pip install -r requirements.txt
   ```

3. 자세한 설치 방법은 [INSTALLATION.md](INSTALLATION.md)를 참조하세요

### 기본 사용법

#### 단일 호스트 테스팅 (가상 네트워크)

1. 가상 네트워크 인터페이스 생성:
   ```bash
   sudo ip link add veth-pev type veth peer name veth-evse
   sudo ip link set veth-pev up
   sudo ip link set veth-evse up
   ```

2. 터미널 1 - EVSE 시뮬레이터 시작 (테스트 대상):
   ```bash
   cd EVC_Simulator
   sudo python3 EVSE.py --interface veth-evse
   ```

3. 터미널 2 - 통합 퍼저 실행 (테스트 도구):
   ```bash
   cd EVC_Fuzzer
   sudo python3 unified_fuzzer.py --state state1 --interface veth-pev --iterations-per-element 100
   ```

더 많은 테스팅 시나리오는 [TESTING.md](TESTING.md)를 참조하세요

## 프로젝트 구조

```
EVC_Fuzzing_Project/
├── EVC_Simulator/          # EVSE 시뮬레이터 (테스트 대상)
│   ├── EVSE.py            # 충전소 에뮬레이터 (메인)
│   └── XMLBuilder.py      # 정상 V2G 메시지 구성
├── EVC_Fuzzer/            # 퍼징 프레임워크 (테스트 도구)
│   ├── unified_fuzzer.py  # 통합 퍼징 엔진 (메인)
│   ├── state*_fuzz.py     # 개별 상태별 퍼저들 (레거시)
│   └── XMLFormat.py       # 변조된 메시지 생성
├── shared/                # 공유 리소스
│   ├── EXIProcessor.py    # EXI 인코딩/디코딩
│   ├── EmulatorEnum.py    # 공통 상수 정의
│   ├── NMAPScanner.py     # 네트워크 스캐닝
│   ├── external_libs/     # 서드파티 의존성
│   └── java_decoder/      # Java EXI 디코더
└── docs/                  # 추가 문서
```

## 테스트된 환경

### 완전 테스트됨
- Ubuntu 22.04 LTS (x86_64)
- Raspberry Pi OS (Bullseye) on RPi 4
- Debian 11 (Bullseye)

### 부분적으로 테스트됨
- Ubuntu 20.04 LTS
- Debian 12 (Bookworm)

## 문서

- [INSTALLATION.md](INSTALLATION.md) - 자세한 설치 방법
- [TESTING.md](TESTING.md) - 테스팅 시나리오 및 가이드
- [EVC_Simulator/README.md](EVC_Simulator/README.md) - 시뮬레이터 세부사항
- [EVC_Fuzzer/README.md](EVC_Fuzzer/README.md) - 퍼저 문서

## 아키텍처 개요

### 퍼징 테스트 구조
- **Target (타겟)**: EVC_Simulator의 EVSE.py가 실제 충전소 역할
- **Fuzzer (퍼저)**: EVC_Fuzzer가 악의적인 전기차 역할로 EVSE 공격
- **Protocol Stack**: HomePlug Green PHY → IPv6 → V2G over TCP

### 하드웨어 지원
- **소프트웨어 전용**: 가상 네트워크 인터페이스를 통한 프로토콜 테스팅
- **하드웨어**: Raspberry Pi + Devolo Green PHY 보드를 통한 물리 계층 테스팅

## 보안 주의사항

이 도구는 **방어적 보안 테스팅 전용**으로 설계되었습니다. 다음 용도로 사용하세요:
- 전기차 충전 인프라의 견고성 테스트
- V2G 구현의 취약점 식별
- 프로토콜 준수성 검증

소유하지 않거나 명시적 허가가 없는 시스템에서는 이 도구를 사용하지 마세요.

## 기여하기

기여할 때:
1. 기존 코드 규칙을 따르세요
2. 지원되는 플랫폼 중 최소 하나에서 변경사항을 테스트하세요
3. 필요에 따라 문서를 업데이트하세요
4. 명확한 설명과 함께 풀 리퀘스트를 제출하세요

## 라이선스

[여기에 라이선스를 명시하세요]

## 지원

문제 및 질문사항:
- [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) 확인
- 기존 이슈 검토
- 자세한 설명과 함께 새 이슈 생성

## 감사의 말

이 프로젝트는 다음을 기반으로 합니다:
- [AcCCS](https://github.com/IdahoLabResearch/AcCCS) - Idaho National Laboratory의 원본 Access Capabilities for CCS 프로젝트
- [HomePlugPWN](https://github.com/FlUxIuS/HomePlugPWN) - HomePlug 프로토콜 레이어
- [V2Gdecoder](https://github.com/FlUxIuS/V2Gdecoder) - EXI 인코딩/디코딩
- [RISE-V2G](https://github.com/SwitchEV/RISE-V2G) - V2G 레퍼런스 구현

### 저작권 고지
```
Copyright 2023, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED
```

EVC_Simulator는 Idaho National Laboratory의 AcCCS 프로젝트를 기반으로 하며, 퍼징 테스트 환경에 맞게 수정 및 확장되었습니다.