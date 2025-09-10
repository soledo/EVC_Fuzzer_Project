#!/usr/bin/env python3
"""
V2G State Machine Manager
Manages sequential V2G protocol states and transitions for proper fuzzing
"""

import time
import xml.etree.ElementTree as ET
from threading import Event
from XMLFormat import PacketHandler
from EXIProcessor import EXIProcessor
import binascii

class V2GStateMachine:
    """V2G 프로토콜 상태 머신 관리"""
    
    # 상태 의존성 정의 (올바른 순서)
    STATE_DEPENDENCIES = {
        'state1': [],                           # SupportedAppProtocol (첫 상태)
        'state2': ['state1'],                   # SessionSetup (SupportedAppProtocol 완료 후)
        'state3': ['state1', 'state2'],        # ServiceDiscovery (SessionSetup 완료 후)
        'state4': ['state1', 'state2', 'state3'], # ServicePaymentSelection (ServiceDiscovery 완료 후)
        'state5': ['state1', 'state2', 'state3', 'state4'], # ContractAuthentication
        'state6': ['state1', 'state2', 'state3', 'state4', 'state5'], # ChargeParameterDiscovery
        'state7': ['state1', 'state2', 'state3', 'state4', 'state5', 'state6'], # CableCheck
        'state8': ['state1', 'state2', 'state3', 'state4', 'state5', 'state6', 'state7'], # PreCharge
        'state9': ['state1', 'state2', 'state3', 'state4', 'state5', 'state6', 'state7', 'state8'], # PowerDelivery
        'state10': ['state1', 'state2', 'state3', 'state4', 'state5', 'state6', 'state7', 'state8', 'state9'], # CurrentDemand
        'state11': ['state1', 'state2', 'state3', 'state4', 'state5', 'state6', 'state7', 'state8', 'state9', 'state10'] # SessionStop
    }
    
    # 각 상태별 기대 응답 메시지
    EXPECTED_RESPONSES = {
        'state1': 'supportedAppProtocolRes',
        'state2': 'sessionSetupRes', 
        'state3': 'serviceDiscoveryRes',
        'state4': 'servicePaymentSelectionRes',
        'state5': 'contractAuthenticationRes',
        'state6': 'chargeParameterDiscoveryRes',
        'state7': 'cableCheckRes',
        'state8': 'preChargeRes',
        'state9': 'powerDeliveryRes',
        'state10': 'currentDemandRes',
        'state11': 'sessionStopRes'
    }
    
    # 응답 메시지 타입 식별을 위한 XML 태그 매핑
    RESPONSE_TAG_MAPPING = {
        'supportedAppProtocolRes': 'supportedAppProtocolRes',
        'sessionSetupRes': 'SessionSetupRes',
        'serviceDiscoveryRes': 'ServiceDiscoveryRes',
        'servicePaymentSelectionRes': 'ServicePaymentSelectionRes',
        'contractAuthenticationRes': 'ContractAuthenticationRes',
        'chargeParameterDiscoveryRes': 'ChargeParameterDiscoveryRes',
        'cableCheckRes': 'CableCheckRes',
        'preChargeRes': 'PreChargeRes',
        'powerDeliveryRes': 'PowerDeliveryRes',
        'currentDemandRes': 'CurrentDemandRes',
        'sessionStopRes': 'SessionStopRes'
    }
    
    def __init__(self, fuzzer_instance):
        self.fuzzer = fuzzer_instance
        self.completed_states = set()
        self.current_waiting_for = None
        self.response_received = Event()
        self.last_response_type = None
        
    def reach_target_state(self, target_state):
        """타겟 상태에 도달하기 위해 필요한 모든 이전 상태들을 순차 실행"""
        print(f"🎯 Target state: {target_state}")
        
        # 필요한 선행 상태들 확인
        required_states = self.STATE_DEPENDENCIES.get(target_state, [])
        missing_states = [state for state in required_states if state not in self.completed_states]
        
        if not missing_states:
            print(f"✅ All prerequisites completed for {target_state}")
            return True
            
        print(f"📋 Need to complete states: {missing_states}")
        
        # 누락된 상태들을 순차적으로 실행
        for state in missing_states:
            print(f"\n🚀 Executing {state} to reach {target_state}")
            
            if not self.execute_normal_state(state):
                print(f"❌ Failed to complete {state}")
                return False
                
            # 완료된 상태로 표시
            self.completed_states.add(state)
            print(f"✅ {state} completed successfully")
        
        return True
    
    def execute_normal_state(self, state_name):
        """특정 상태의 정상 메시지를 전송하고 올바른 응답을 기다림"""
        from EVC_Fuzzer.unified_fuzzer import STATE_CONFIG
        
        state_config = STATE_CONFIG.get(state_name)
        if not state_config:
            print(f"❌ State config not found for {state_name}")
            return False
            
        print(f"📤 Sending normal {state_config['name']} message")
        
        # 정상 XML 메시지 생성
        handler = PacketHandler()
        xml_method_func = getattr(handler, state_config['xml_method'], None)
        if not xml_method_func:
            print(f"❌ XML method {state_config['xml_method']} not found")
            return False
            
        xml_method_func()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        
        # EXI 인코딩 및 전송
        exi_payload = self.fuzzer.exi.encode(xml_string)
        if not exi_payload:
            print(f"❌ Failed to encode XML to EXI")
            return False
            
        exi_payload_bytes = binascii.unhexlify(exi_payload)
        packet = self.fuzzer.buildV2G(exi_payload_bytes)
        
        # 응답 대기 설정
        expected_response = self.EXPECTED_RESPONSES.get(state_name)
        if expected_response:
            self.current_waiting_for = expected_response
            self.response_received.clear()
            
        # 패킷 전송
        from scapy.all import sendp
        sendp(packet, iface=self.fuzzer.iface, verbose=0)
        tcp_payload_length = len(bytes(packet.payload))
        self.fuzzer.seq += tcp_payload_length
        
        # 응답 대기
        if expected_response:
            print(f"⏳ Waiting for {expected_response} response...")
            success = self.response_received.wait(timeout=10)  # 10초 대기
            
            if not success:
                print(f"⏰ Timeout waiting for {expected_response}")
                return False
                
            if self.last_response_type != expected_response:
                print(f"❌ Expected {expected_response}, got {self.last_response_type}")
                return False
                
            print(f"✅ Received expected {expected_response}")
        
        return True
    
    def handle_response(self, decoded_xml):
        """응답 메시지를 파싱하여 타입을 확인하고 대기 중인 응답과 매칭"""
        if not decoded_xml or not self.current_waiting_for:
            return
            
        try:
            # XML 파싱
            root = ET.fromstring(decoded_xml)
            
            # 응답 타입 식별
            response_type = self.identify_response_type(root)
            self.last_response_type = response_type
            
            print(f"📨 Received response: {response_type}")
            
            # 대기 중인 응답과 일치하는지 확인
            if response_type == self.current_waiting_for:
                # ResponseCode 확인
                if self.is_successful_response(root):
                    print(f"✅ {response_type} with success code")
                    self.response_received.set()
                else:
                    print(f"⚠️  {response_type} with error code")
                    # 에러 응답도 일단 진행 (퍼징 목적)
                    self.response_received.set()
            else:
                print(f"❌ Expected {self.current_waiting_for}, got {response_type}")
                
        except Exception as e:
            print(f"❌ Error parsing response: {e}")
    
    def identify_response_type(self, root):
        """XML root에서 응답 타입을 식별"""
        # 네임스페이스를 제거한 태그 이름으로 식별
        tag_name = root.tag.split('}')[-1] if '}' in root.tag else root.tag
        
        # SupportedAppProtocol은 다른 스키마 사용
        if tag_name == 'supportedAppProtocolRes':
            return 'supportedAppProtocolRes'
            
        # V2G 메시지의 경우 Body 내부에서 실제 메시지 타입 찾기
        if tag_name == 'V2G_Message':
            body = root.find('.//{*}Body')
            if body is not None:
                for child in body:
                    child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                    # Res로 끝나는 태그 찾기
                    if child_tag.endswith('Res'):
                        # 매핑 테이블에서 해당하는 응답 타입 찾기
                        for response_key, xml_tag in self.RESPONSE_TAG_MAPPING.items():
                            if child_tag == xml_tag:
                                return response_key
        
        return f"UNKNOWN_{tag_name}"
    
    def is_successful_response(self, root):
        """응답 메시지의 ResponseCode가 성공인지 확인"""
        try:
            # ResponseCode 엘리먼트 찾기
            response_code_elem = root.find('.//{*}ResponseCode')
            if response_code_elem is not None:
                response_code = response_code_elem.text
                # OK로 시작하는 코드를 성공으로 간주
                return response_code and response_code.startswith('OK')
            return False
        except:
            return False
    
    def reset(self):
        """상태 머신 초기화"""
        self.completed_states.clear()
        self.current_waiting_for = None
        self.last_response_type = None
        self.response_received.clear()