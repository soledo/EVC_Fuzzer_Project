#!/usr/bin/env python3

"""
자동화된 State 1-11 퍼징 실행기
각 상태별로 EVSE 재시작 없이 연속 실행
"""

import subprocess
import time
import sys
import os
import json
from datetime import datetime

def run_single_state(state_id, iterations=10, interface="veth-pev"):
    """단일 상태 실행"""
    print(f"\n{'='*80}")
    print(f"🎯 EXECUTING STATE: {state_id}")
    print(f"{'='*80}")
    
    cmd = [
        'python3', 
        'EVC_Fuzzer/unified_fuzzer.py',
        '--state', state_id,
        '--interface', interface,
        '--iterations-per-element', str(iterations)
    ]
    
    start_time = time.time()
    success = False
    error_msg = None
    
    try:
        print(f"🚀 Command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,   # 1분 타임아웃 (빠른 실패 감지)
            cwd='/home/donghyuk/EVC_Fuzzing_Project'
        )
        
        execution_time = time.time() - start_time
        
        # 성공 조건: "completed successfully" 메시지 포함
        if "completed successfully" in result.stdout:
            print(f"✅ {state_id}: SUCCESS ({execution_time:.1f}s)")
            success = True
        else:
            print(f"❌ {state_id}: FAILED ({execution_time:.1f}s)")
            print(f"Return code: {result.returncode}")
            if result.stderr:
                error_msg = result.stderr[-200:]  # 마지막 200자
                print(f"Error: {error_msg}")
            
    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        print(f"⏰ {state_id}: TIMEOUT ({execution_time:.1f}s)")
        error_msg = "Timeout"
        
    except Exception as e:
        execution_time = time.time() - start_time
        print(f"💥 {state_id}: ERROR ({execution_time:.1f}s) - {e}")
        error_msg = str(e)
    
    return {
        'state': state_id,
        'success': success,
        'execution_time': execution_time,
        'error': error_msg,
        'timestamp': datetime.now().isoformat()
    }

def check_evse_running():
    """EVSE가 실행 중인지 확인"""
    try:
        result = subprocess.run(['pgrep', '-f', 'EVSE.py'], capture_output=True)
        return result.returncode == 0
    except:
        return False

def main():
    print("🎯 자동화된 State 1-11 퍼징 테스트")
    print("=" * 60)
    
    # 권한 확인
    if os.geteuid() != 0:
        print("❌ 이 스크립트는 root 권한이 필요합니다.")
        print("실행: sudo python3 run_all_states.py")
        sys.exit(1)
    
    # EVSE 실행 확인
    if not check_evse_running():
        print("❌ EVSE가 실행되지 않았습니다.")
        print("먼저 다른 터미널에서 실행하세요:")
        print("cd EVC_Simulator && sudo python3 EVSE.py --interface veth-evse")
        sys.exit(1)
    
    print("✅ EVSE 실행 확인됨")
    
    # State 설정
    states = [f"state{i}" for i in range(1, 12)]  # state1 ~ state11
    iterations = 10  # 각 상태별 반복 횟수
    
    print(f"📋 테스트할 상태: {', '.join(states)}")
    print(f"🔢 각 상태별 반복: {iterations}회")
    print(f"⏰ 시작 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 결과 저장
    results = []
    successful_states = []
    failed_states = []
    
    start_total = time.time()
    
    for i, state_id in enumerate(states, 1):
        print(f"\n📍 진행률: {i}/{len(states)} 상태")
        
        # 상태 실행
        result = run_single_state(state_id, iterations)
        results.append(result)
        
        if result['success']:
            successful_states.append(state_id)
        else:
            failed_states.append(state_id)
        
        # 상태 간 대기 (EVSE가 안정화되도록)
        if i < len(states):  # 마지막 상태가 아니면
            print(f"⏳ 다음 상태 준비를 위해 3초 대기...")
            time.sleep(3)
    
    total_time = time.time() - start_total
    
    # 최종 결과 출력
    print(f"\n{'='*80}")
    print(f"🎯 전체 퍼징 테스트 완료")
    print(f"{'='*80}")
    print(f"📊 총 실행 시간: {total_time:.1f}초 ({total_time/60:.1f}분)")
    print(f"✅ 성공: {len(successful_states)}/{len(states)} ({len(successful_states)/len(states)*100:.1f}%)")
    print(f"❌ 실패: {len(failed_states)}/{len(states)} ({len(failed_states)/len(states)*100:.1f}%)")
    
    if successful_states:
        print(f"\n✅ 성공한 상태: {', '.join(successful_states)}")
    
    if failed_states:
        print(f"\n❌ 실패한 상태: {', '.join(failed_states)}")
    
    # 결과를 JSON 파일로 저장
    report = {
        'summary': {
            'total_states': len(states),
            'successful_states': len(successful_states),
            'failed_states': len(failed_states),
            'success_rate': (len(successful_states) / len(states)) * 100,
            'total_execution_time': total_time,
            'iterations_per_state': iterations,
            'timestamp': datetime.now().isoformat()
        },
        'successful_states': successful_states,
        'failed_states': failed_states,
        'detailed_results': results
    }
    
    report_file = f'EVC_Fuzzer/fuzzing_reports/all_states_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=4)
    
    # 권한 수정
    sudo_user = os.environ.get('SUDO_USER')
    if sudo_user:
        try:
            import pwd
            pw_record = pwd.getpwnam(sudo_user)
            os.chown(report_file, pw_record.pw_uid, pw_record.pw_gid)
        except:
            pass
    
    print(f"\n📄 상세 보고서 저장: {report_file}")
    
    # 개별 상태 보고서 확인 안내
    print(f"\n📊 개별 상태 결과는 여기서 확인:")
    print(f"ls -la EVC_Fuzzer/fuzzing_reports/fuzzing_report_state*.json")

if __name__ == "__main__":
    main()