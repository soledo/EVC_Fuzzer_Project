    """
    SessionSetupRequest 메시지를 가지고 퍼징을 수행하는 코드입니다. 
    타겟 상태머신 : Wait for SessionSetupRequest
    """

import sys, os
sys.path.append("../shared/external_libs/HomePlugPWN")
sys.path.append("../shared/external_libs/V2GInjector/core")
sys.path.append("../shared")

from threading import Thread, Event
import binascii
from scapy.all import *
from layers.SECC import *
from layers.V2G import *
from layerscapy.HomePlugGP import *
from EXIProcessor import EXIProcessor
from EmulatorEnum import *
from XMLFormat import PacketHandler
import xml.etree.ElementTree as ET
import os.path
import random
import argparse
import time
import string
import json
import threading  # threading.Lock()을 사용하기 위해 추가

class PEV:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = args.interface[0] if args.interface else "eth1"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:1e:c0:f2:6c:a1"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::21e:c0ff:fef2:6ca1"
        self.sourcePort = args.source_port[0] if args.source_port else random.randint(1025, 65534)
        self.protocol = Protocol(args.protocol[0]) if args.protocol else Protocol.DIN
        self.iterations_per_element = args.iterations_per_element

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None

        self.exi = EXIProcessor(self.protocol)
        self.slac = _SLACHandler(self)
        self.xml = PacketHandler()
        self.iterations_per_element = args.iterations_per_element
        self.tcp = _TCPHandler(self, self.iterations_per_element)

        self.I2C_ADDR = 0x20
        self.CONTROL_REG = 0x9
        self.PEV_CP1 = 0b10
        self.PEV_CP2 = 0b100
        self.PEV_PP = 0b10000
        self.ALL_OFF = 0b0

    def start(self):
        self.toggleProximity()
        self.doSLAC()
        self.doTCP()
        if not self.tcp.finishedNMAP:
            self.start()

    def doTCP(self):
        self.tcp.start()
        print("INFO (PEV) : Done TCP")

    def doSLAC(self):
        self.slac.start()
        self.slac.sniffThread.join()

    def closeProximity(self):
        self.setState(PEVState.B)

    def openProximity(self):
        self.setState(PEVState.A)

    def setState(self, state: PEVState):
        if state == PEVState.A:
            pass
        elif state == PEVState.B:
            pass
        elif state == PEVState.C:
            pass

    def toggleProximity(self, t: int = 5):
        self.openProximity()
        time.sleep(t)
        self.closeProximity()


# 이 클래스는 레벨 2 SLAC 프로토콜 통신과 SECC 요청을 처리합니다
class _SLACHandler:
    def __init__(self, pev: PEV):
        self.pev = pev
        self.iface = self.pev.iface
        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.runID = os.urandom(8)

        self.timeSinceLastPkt = time.time()
        self.timeout = 8  # 메시지 타임아웃 시간
        self.stop = False

    # SLAC 프로세스를 시작하고 중지합니다
    def start(self):
        self.runID = os.urandom(8)
        self.stop = False

        self.sniffThread = AsyncSniffer(iface=self.iface, prn=self.handlePacket, stop_filter=self.stopSniff)
        self.sniffThread.start()

        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborSolicitation
        )
        self.neighborSolicitationThread.start()

        sendp(self.buildSlacParmReq(), iface=self.iface, verbose=0)

    # 타임아웃을 확인하고 SLAC 프로세스를 재시작합니다
    def checkForTimeout(self):
        while not self.stop:
            if time.time() - self.timeSinceLastPkt > self.timeout:
                sendp(self.buildSlacParmReq(), iface=self.iface, verbose=0)
                self.timeSinceLastPkt = time.time()
            time.sleep(1)

    # SLAC 매치가 완료되면 스니핑을 중지합니다
    def stopSniff(self, pkt):
        if pkt.haslayer("SECC_ResponseMessage"):
            self.pev.destinationIP = pkt[SECC_ResponseMessage].TargetAddress
            self.pev.destinationPort = pkt[SECC_ResponseMessage].TargetPort
            if self.neighborSolicitationThread.running:
                self.neighborSolicitationThread.stop()
            return True
        return False

    # 수신된 패킷을 처리합니다
    def handlePacket(self, pkt):
        if pkt[Ether].type != 0x88E1 or pkt[Ether].src == self.sourceMAC:
            return

        if hasattr(pkt[1][2], "RunID") and pkt[1][2].RunID != self.runID:
            return

        if pkt.haslayer("CM_SLAC_PARM_CNF"):
            self.destinationMAC = pkt[Ether].src
            self.pev.destinationMAC = pkt[Ether].src
            self.numSounds = pkt[CM_SLAC_PARM_CNF].NumberMSounds
            self.numRemainingSounds = self.numSounds
            startSoundsPkts = [self.buildStartAttenCharInd() for _ in range(3)]
            soundPkts = [self.buildMNBCSoundInd() for _ in range(self.numSounds)]
            sendp(startSoundsPkts, iface=self.iface, verbose=0, inter=0.05)
            sendp(soundPkts, iface=self.iface, verbose=0, inter=0.05)
            return

        if pkt.haslayer("CM_ATTEN_CHAR_IND"):
            sendp(self.buildAttenCharRes(), iface=self.iface, verbose=0)
            self.timeSinceLastPkt = time.time()
            sendp(self.buildSlacMatchReq(), iface=self.iface, verbose=0)
            self.timeSinceLastPkt = time.time()
            return

        if pkt.haslayer("CM_SLAC_MATCH_CNF"):
            self.NID = pkt[CM_SLAC_MATCH_CNF].VariableField.NetworkID
            self.NMK = pkt[CM_SLAC_MATCH_CNF].VariableField.NMK
            sendp(self.buildSetKeyReq(), iface=self.iface, verbose=0)
            self.stop = True
            Thread(target=self.sendSECCRequest).start()
            return

    # SECC 요청을 보냅니다
    def sendSECCRequest(self):
        time.sleep(3)
        sendp(self.buildSECCRequest(), iface=self.iface, verbose=0)

    # SLAC 파라미터 요청 패킷을 생성합니다
    def buildSlacParmReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SLAC_PARM_REQ()
        homePlugLayer.RunID = self.runID

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    # 시작 ATTEN_CHAR_IND 패킷을 생성합니다
    def buildStartAttenCharInd(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_START_ATTEN_CHAR_IND()
        homePlugLayer.NumberOfSounds = self.numSounds
        homePlugLayer.TimeOut = 0x06
        homePlugLayer.ResponseType = 0x01
        homePlugLayer.ForwardingSTA = self.sourceMAC
        homePlugLayer.RunID = self.runID

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    # MNBC_SOUND_IND 패킷을 생성합니다
    def buildMNBCSoundInd(self):
        self.numRemainingSounds -= 1

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "ff:ff:ff:ff:ff:ff"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_MNBC_SOUND_IND()
        homePlugLayer.Countdown = self.numRemainingSounds
        homePlugLayer.RunID = self.runID
        homePlugLayer.RandomValue = os.urandom(16)

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    # ATTEN_CHAR_RSP 패킷을 생성합니다
    def buildAttenCharRes(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_ATTEN_CHAR_RSP()
        homePlugLayer.SourceAdress = self.sourceMAC
        homePlugLayer.RunID = self.runID
        homePlugLayer.Result = 0x00

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    # SLAC 매치 요청 패킷을 생성합니다
    def buildSlacMatchReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SLAC_MATCH_REQ()
        homePlugLayer.MatchVariableFieldLen = 0x3E00

        slacVars = SLAC_varfield()
        slacVars.EVMAC = self.sourceMAC
        slacVars.EVSEMAC = self.destinationMAC
        slacVars.RunID = self.runID

        homePlugLayer.VariableField = slacVars

        pkt = ethLayer / homePlugAVLayer / homePlugLayer
        return pkt

    # SET_KEY_REQ 패킷을 생성합니다
    def buildSetKeyReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "00:b0:52:00:00:01"

        homePlugAVLayer = HomePlugAV()
        homePlugAVLayer.version = 0x01

        homePlugLayer = CM_SET_KEY_REQ()
        homePlugLayer.KeyType = 0x1
        homePlugLayer.MyNonce = 0xAAAAAAAA
        homePlugLayer.YourNonce = 0x00000000
        homePlugLayer.PID = 0x4
        homePlugLayer.NetworkID = self.NID
        homePlugLayer.NewEncKeySelect = 0x1
        homePlugLayer.NewKey = self.NMK

        responsePacket = ethLayer / homePlugAVLayer / homePlugLayer
        return responsePacket

    # SECC 요청 패킷을 생성합니다
    def buildSECCRequest(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "33:33:00:00:00:01"

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = "ff02::1"
        ipLayer.hlim = 255

        udpLayer = UDP()
        udpLayer.sport = self.pev.sourcePort
        udpLayer.dport = 15118

        seccLayer = SECC()
        seccLayer.SECCType = 0x9000
        seccLayer.PayloadLen = 2

        seccRequestLayer = SECC_RequestMessage()
        seccRequestLayer.SecurityProtocol = 16
        seccRequestLayer.TransportProtocol = 0

        responsePacket = ethLayer / ipLayer / udpLayer / seccLayer / seccRequestLayer
        return responsePacket

    # Neighbor Advertisement 패킷을 생성합니다
    def buildNeighborAdvertisement(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP
        ipLayer.plen = 32
        ipLayer.hlim = 255

        icmpLayer = ICMPv6ND_NA()
        icmpLayer.type = 136
        icmpLayer.R = 0
        icmpLayer.S = 1
        icmpLayer.tgt = self.sourceIP

        optLayer = ICMPv6NDOptDstLLAddr()
        optLayer.type = 2
        optLayer.len = 1
        optLayer.lladdr = self.sourceMAC

        responsePacket = ethLayer / ipLayer / icmpLayer / optLayer
        return responsePacket

    # Neighbor Solicitation에 응답을 보냅니다
    def sendNeighborSolicitation(self, pkt):
        self.destinationIP = pkt[IPv6].src
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)


class _TCPHandler:
    def __init__(self, pev: PEV, iterations_per_element):
        self.pev = pev
        self.iface = self.pev.iface

        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.sourcePort = self.pev.sourcePort

        self.destinationMAC = self.pev.destinationMAC
        self.destinationIP = self.pev.destinationIP
        self.destinationPort = self.pev.destinationPort

        self.seq = 10000  # 초기 시퀀스 번호
        self.ack = 0      # 초기 응답 번호

        self.exi = self.pev.exi
        self.xml = self.pev.xml
        self.msgList = {}

        self.stop = False
        self.startSniff = False
        self.finishedNMAP = False
        self.lastPort = 0

        self.scanner = None

        self.timeout = 5

        self.soc = 10

        self.response_received = Event()
        self.rst_received = False
        self.handshake_complete = Event()  # 핸드셰이크 완료 신호

        # 퍼징 매개변수
        self.iterations_per_element = iterations_per_element
        self.state_file = 'fuzzing_state.json'
        self.state = {}
        self.elements_to_modify = ["EVCCID"]

        # 크래시 추적 초기화
        self.crash_info = []  # 크래시 세부 정보를 저장할 리스트
        self.total_attempts = 0
        self.total_crashes = 0
        self.state_lock = threading.Lock()

        # 퍼징 시작 신호 이벤트
        self.fuzzing_ready = Event()

    # TCP 핸들러를 시작합니다
    def start(self):
        self.msgList = {}
        self.running = True
        self.prechargeCount = 0
        print("INFO (PEV) : Starting TCP")

        self.load_state()  # 기존 상태를 로드

        self.recvThread = AsyncSniffer(
            iface=self.iface,
            lfilter=lambda x: x.haslayer("TCP") and x[IPv6].src == self.destinationIP and x[IPv6].dst == self.sourceIP and x[TCP].sport == self.destinationPort and x[TCP].dport == self.sourcePort,
            prn=self.handlePacket,
            started_callback=self.setStartSniff,
        )
        self.recvThread.start()

        self.handshakeThread = Thread(target=self.handshake)
        self.handshakeThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborAdvertisement
        )
        self.neighborSolicitationThread.start()

        self.fuzzing_control_thread = Thread(target=self.wait_and_start_fuzzing)
        self.fuzzing_control_thread.start()

        while self.running:
            time.sleep(1)

    # 핸드셰이크 완료를 기다리고 퍼징을 시작합니다
    def wait_and_start_fuzzing(self):
        self.handshake_complete.wait()
        print("INFO (TCPHandler): Handshake complete")

        self.send_supported_app_protocol_request()

        print("INFO (TCPHandler): Waiting for SupportedAppProtocolResponse to start fuzzing...")
        fuzzing_ready = self.fuzzing_ready.wait(timeout=15)  # 최대 15초 대기

        if fuzzing_ready:
            print("INFO (TCPHandler): Fuzzing conditions met, starting fuzzing.")
            self.send_fuzzing_messages()
        else:
            print("WARNING (TCPHandler): Fuzzing conditions not met within timeout, not starting fuzzing.")

    # 스레드를 종료합니다
    def killThreads(self):
        if self.scanner is not None:
            self.scanner.stop()
        self.running = False
        if self.neighborSolicitationThread.running:
            self.neighborSolicitationThread.stop()
        if self.recvThread.running:
            if threading.current_thread() != self.recvThread.thread:
                self.recvThread.stop()
            else:
                threading.Thread(target=self.recvThread.stop).start()

    # FIN 패킷을 처리합니다
    def fin(self):
        self.running = False
        self.ack += 1

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.flags = "A"
        tcpLayer.seq = self.seq
        tcpLayer.ack = self.ack

        ack = ethLayer / ipLayer / tcpLayer

        sendp(ack, iface=self.iface, verbose=0)

        tcpLayer.flags = "FA"

        finAck = ethLayer / ipLayer / tcpLayer

        sendp(finAck, iface=self.iface, verbose=0)

    # 스니핑 시작을 표시합니다
    def setStartSniff(self):
        self.startSniff = True

    # 세션을 시작합니다
    def startSession(self):
        sendp(
            Ether(src=self.sourceMAC, dst=self.destinationMAC)
            / IPv6(src=self.sourceIP, dst=self.destinationIP)
            / TCP(
                sport=self.sourcePort,
                dport=self.destinationPort,
                flags="A",
                seq=self.seq,
                ack=self.ack
            ),
            iface=self.iface,
            verbose=0,
        )
        print("INFO (PEV): Sending ACK to complete the handshake")
        self.handshake_complete.set()

    # SupportedAppProtocolRequest를 보냅니다
    def send_supported_app_protocol_request(self):
        handler = PacketHandler()
        handler.SupportedAppProtocolRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                sendp(packet, iface=self.iface, verbose=0)
            except binascii.Error as e:
                pass
        else:
            pass

    # 퍼징 메시지를 보냅니다
    def send_fuzzing_messages(self):
        handler = PacketHandler()
        handler.SessionSetupRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')

        self.load_state()

        self.fuzz_payload(xml_string)

    # 수신된 패킷을 처리합니다
    def handlePacket(self, pkt):
        self.last_recv = pkt
        tcp_layer = pkt[TCP]

        if len(tcp_layer.payload) > 0:
            self.ack = tcp_layer.seq + len(tcp_layer.payload)
        else:
            self.ack = tcp_layer.seq + 1  # 페이로드가 없는 패킷의 경우

        if tcp_layer.flags & 0x04:  # RST 플래그 체크
            self.rst_received = True
            self.response_received.set()
            return

        if (tcp_layer.flags & 0x12) == 0x12:  # SYN과 ACK 플래그가 설정된 경우
            self.ack = tcp_layer.seq + 1  # 서버의 SYN을 응답
            self.seq += 1  # ACK를 보낸 후 시퀀스 번호 증가
            self.startSession()
            return

        if tcp_layer.flags & 0x01:  # FIN 플래그 체크
            self.fin()
            return

        self.response_received.set()

        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            v2g = V2GTP(data)
            payload = v2g.Payload
            data_hex = binascii.hexlify(payload).decode()
            try:
                xmlString = self.exi.decode(data_hex)
                root = ET.fromstring(xmlString)

                if root.text is None:
                    if "AppProtocol" in root.tag:
                        self.fuzzing_ready.set()
                        return
                else:
                    pass
            except Exception as e:
                pass
        else:
            pass

    # 페이로드를 퍼징합니다
    def fuzz_payload(self, xml_string):
        elements_to_modify = self.elements_to_modify

        current_element_index = self.state.get('current_element_index', 0)
        iteration_count = self.state.get('iterations', {})
        crash_info = self.state.get('crash_info', [])
        crash_inputs = self.state.get('crash_inputs', [])
        total_attempts = self.state.get('total_attempts', 0)
        total_crashes = self.state.get('total_crashes', 0)

        for idx in range(current_element_index, len(elements_to_modify)):
            element_name = elements_to_modify[idx]
            root = ET.fromstring(xml_string)

            found_element = False
            for elem in root.iter():
                local_tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if local_tag == element_name:
                    found_element = True
                    if not elem.text:
                        elem.text = "1"

                    mutated_value = elem.text

                    start_iteration = iteration_count.get(element_name, 0)

                    for iteration in range(start_iteration, self.iterations_per_element):
                        mutation_func = random.choice([self.value_flip, self.random_value, self.random_deletion, self.random_insertion])
                        mutated_value = mutation_func(mutated_value)

                        if not mutated_value:
                            mutated_value = elem.text

                        elem.text = mutated_value

                        fuzzed_xml = ET.tostring(root, encoding='unicode')

                        self.state['total_attempts'] += 1
                        total_attempts += 1

                        self.response_received.clear()
                        self.rst_received = False

                        exi_payload = self.exi.encode(fuzzed_xml)
                        if exi_payload is not None:
                            try:
                                exi_payload_bytes = binascii.unhexlify(exi_payload)
                                packet = self.buildV2G(exi_payload_bytes)
                                tcp_payload_length = len(bytes(packet[TCP].payload))
                                sendp(packet, iface=self.iface, verbose=0)
                                self.seq += tcp_payload_length
                            except binascii.Error as e:
                                continue
                        else:
                            continue

                        self.state['iterations'][element_name] = iteration + 1

                        self.save_state()

                        response = self.response_received.wait(timeout=2)

                        if not response or self.rst_received:
                            self.state['total_crashes'] += 1
                            total_crashes += 1

                            crash_detail = {
                                'element': element_name,
                                'iteration': iteration + 1,
                                'mutated_value': mutated_value,
                                'fuzzed_xml': fuzzed_xml
                            }
                            self.state['crash_inputs'].append(crash_detail)

                            self.save_state()
                            self.killThreads()
                            return

            if not found_element:
                continue

        if os.path.exists(self.state_file):
            os.remove(self.state_file)
        self.generate_report()

    # 보고서를 생성합니다
    def generate_report(self):
        report = {
            'total_attempts': self.state.get('total_attempts', 0),
            'total_crashes': self.state.get('total_crashes', 0),
            'crash_details': self.state.get('crash_inputs', [])
        }

        report_file = 'fuzzing_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)

    # 값을 뒤집습니다
    def value_flip(self, value):
        if len(value) < 2:
            return value
        idx1, idx2 = random.sample(range(len(value)), 2)
        value_list = list(value)
        value_list[idx1], value_list[idx2] = value_list[idx2], value_list[idx1]
        return ''.join(value_list)

    # 랜덤 값을 생성합니다
    def random_value(self, value):
        if len(value) == 0:
            return value
        idx = random.randrange(len(value))
        new_char = chr(random.randint(33, 126))
        value_list = list(value)
        value_list[idx] = new_char
        return ''.join(value_list)

    # 랜덤으로 삭제합니다
    def random_deletion(self, value):
        if len(value) == 0:
            return value
        idx = random.randrange(len(value))
        value_list = list(value)
        del value_list[idx]
        return ''.join(value_list)

    # 랜덤으로 삽입합니다
    def random_insertion(self, value):
        if len(value) == 0:
            return value

        insert_idx = random.randrange(len(value)+1)
        random_char = random.choice(string.ascii_letters + string.digits)
        value_list = list(value)
        value_list.insert(insert_idx, random_char)
        return ''.join(value_list)

    # V2G 패킷을 생성합니다
    def buildV2G(self, payload):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.seq = self.seq
        tcpLayer.ack = self.ack
        tcpLayer.flags = "PA"

        v2gLayer = V2GTP()
        v2gLayer.PayloadLen = len(payload)
        v2gLayer.Payload = payload

        tcpLayer.add_payload(v2gLayer)

        packet = ethLayer / ipLayer / tcpLayer

        return packet

    # 핸드셰이크를 수행합니다
    def handshake(self):
        while not self.startSniff:
            if not self.running:
                return
            time.sleep(0.1)

        self.destinationMAC = self.pev.destinationMAC
        self.destinationIP = self.pev.destinationIP
        self.destinationPort = self.pev.destinationPort

        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP

        tcpLayer = TCP()
        tcpLayer.sport = self.sourcePort
        tcpLayer.dport = self.destinationPort
        tcpLayer.flags = "S"
        tcpLayer.seq = self.seq

        synPacket = ethLayer / ipLayer / tcpLayer
        sendp(synPacket, iface=self.iface, verbose=0)

    # Neighbor Solicitation을 보냅니다
    def sendNeighborSolicitation(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "33:33:ff:00" + self.destinationIP[-7:-5] + ":" + self.destinationIP[-4:-2] + ":" + self.destinationIP[-2:]

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = "ff02::1:" + self.destinationIP[-9:]

        icmpLayer = ICMPv6ND_NS()
        icmpLayer.type = 135
        icmpLayer.tgt = self.destinationIP

        optLayer = ICMPv6NDOptDstLLAddr()
        optLayer.type = 1
        optLayer.len = 1
        optLayer.lladdr = self.sourceMAC

        pkt = ethLayer / ipLayer / icmpLayer / optLayer
        sendp(pkt, iface=self.iface, verbose=0)

    # Neighbor Advertisement 패킷을 생성합니다
    def buildNeighborAdvertisement(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = self.destinationMAC

        ipLayer = IPv6()
        ipLayer.src = self.sourceIP
        ipLayer.dst = self.destinationIP
        ipLayer.plen = 32
        ipLayer.hlim = 255

        icmpLayer = ICMPv6ND_NA()
        icmpLayer.type = 136
        icmpLayer.R = 0
        icmpLayer.S = 1
        icmpLayer.tgt = self.sourceIP

        optLayer = ICMPv6NDOptDstLLAddr()
        optLayer.type = 2
        optLayer.len = 1
        optLayer.lladdr = self.sourceMAC

        responsePacket = ethLayer / ipLayer / icmpLayer / optLayer
        return responsePacket

    # 상태를 로드합니다
    def load_state(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, 'r') as f:
                self.state = json.load(f)
        else:
            self.state = {
                'current_element_index': 0,
                'iterations': {},
                'crash_info': [],
                'total_attempts': 0,
                'total_crashes': 0,
                'crash_inputs': []
            }
            for element in self.elements_to_modify:
                self.state['iterations'][element] = 0

    # 상태를 저장합니다
    def save_state(self):
        with self.state_lock:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PEV emulator for AcCCS with Fuzzing")
    parser.add_argument(
        "-M",
        "--mode",
        nargs=1,
        type=int,
        help="Mode for emulator to run in: 0 for full conversation, 1 for stalling the conversation, 2 for portscanning (default: 0)",
    )
    parser.add_argument("-I", "--interface", nargs=1, help="Ethernet interface to send/receive packets on (default: eth1)")
    parser.add_argument("--source-mac", nargs=1, help="Source MAC address of packets (default: 00:1e:c0:f2:6c:a0)")
    parser.add_argument("--source-ip", nargs=1, help="Source IP address of packets (default: fe80::21e:c0ff:fef2:72f3)")
    parser.add_argument("--source-port", nargs=1, type=int, help="Source port of packets (default: random port)")
    parser.add_argument("-p", "--protocol", nargs=1, help="Protocol for EXI encoding/decoding: DIN, ISO-2, ISO-20 (default: DIN)")
    parser.add_argument('--iterations-per-element', type=int, default=1000, help='Number of fuzzing iterations per element (default: 1000)')
    args = parser.parse_args()

    pev = PEV(args)
    try:
        pev.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        pass
    finally:
        pev.setState(PEVState.A)
        del pev
