"""
CurrentDemandRequest 메시지를 가지고 퍼징을 수행하는 코드입니다. 
타겟 상태머신 : Wait for CurrentDemandRequest
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

        # i2c 제어 릴레이를 위한 상수 (원래 코드에 따라 주석 처리됨)
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
        # NMAP이 완료되지 않은 경우 연결을 재시도
        if not self.tcp.finishedNMAP:
            print("INFO (PEV) : Attempting to restart connection...")
            self.start()

    def doTCP(self):
        self.tcp.start()
        print("INFO (PEV) : Done TCP")

    def doSLAC(self):
        print("INFO (PEV) : Starting SLAC")
        self.slac.start()
        self.slac.sniffThread.join()
        print("INFO (PEV) : Done SLAC")

    def closeProximity(self):
        self.setState(PEVState.B)

    def openProximity(self):
        self.setState(PEVState.A)

    def setState(self, state: PEVState):
        if state == PEVState.A:
            print("INFO (PEV) : Going to state A")
        elif state == PEVState.B:
            print("INFO (PEV) : Going to state B")
        elif state == PEVState.C:
            print("INFO (PEV) : Going to state C")

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
        self.timeout = 8  # 메시지 타임아웃 시간 (초 단위)
        self.stop = False

    # SLAC 프로세스를 시작하고 중지합니다
    def start(self):
        self.runID = os.urandom(8)
        self.stop = False

        self.sniffThread = AsyncSniffer(iface=self.iface, prn=self.handlePacket, stop_filter=self.stopSniff)
        self.sniffThread.start()

        # 타임아웃을 확인하고 SLAC 프로세스를 재시작하는 스레드 시작
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborSolicitation
        )
        self.neighborSolicitationThread.start()

        # SLAC 프로세스를 시작하기 위해 SLAC 파라미터 요청 전송
        sendp(self.buildSlacParmReq(), iface=self.iface, verbose=0)

    # 타임아웃을 확인하고 SLAC 프로세스를 재시작합니다
    def checkForTimeout(self):
        while not self.stop:
            if time.time() - self.timeSinceLastPkt > self.timeout:
                print("INFO (PEV) : Timed out... Sending SLAC_PARM_REQ")
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

    def handlePacket(self, pkt):
        if pkt[Ether].type != 0x88E1 or pkt[Ether].src == self.sourceMAC:
            return

        if hasattr(pkt[1][2], "RunID") and pkt[1][2].RunID != self.runID:
            return

        if pkt.haslayer("CM_SLAC_PARM_CNF"):
            print("INFO (PEV) : Received SLAC_PARM_CNF")
            self.destinationMAC = pkt[Ether].src
            self.pev.destinationMAC = pkt[Ether].src
            self.numSounds = pkt[CM_SLAC_PARM_CNF].NumberMSounds
            self.numRemainingSounds = self.numSounds
            startSoundsPkts = [self.buildStartAttenCharInd() for _ in range(3)]
            soundPkts = [self.buildMNBCSoundInd() for _ in range(self.numSounds)]
            print("INFO (PEV) : Sending 3 START_ATTEN_CHAR_IND")
            sendp(startSoundsPkts, iface=self.iface, verbose=0, inter=0.05)
            print(f"INFO (PEV) : Sending {self.numSounds} MNBC_SOUND_IND")
            sendp(soundPkts, iface=self.iface, verbose=0, inter=0.05)
            return

        if pkt.haslayer("CM_ATTEN_CHAR_IND"):
            print("INFO (PEV) : Received ATTEN_CHAR_IND")
            print("INFO (PEV) : Sending ATTEN_CHAR_RES")
            sendp(self.buildAttenCharRes(), iface=self.iface, verbose=0)
            self.timeSinceLastPkt = time.time()
            print("INFO (PEV) : Sending SLAC_MATCH_REQ")
            sendp(self.buildSlacMatchReq(), iface=self.iface, verbose=0)
            self.timeSinceLastPkt = time.time()
            return

        if pkt.haslayer("CM_SLAC_MATCH_CNF"):
            print("INFO (PEV) : Received SLAC_MATCH_CNF")
            self.NID = pkt[CM_SLAC_MATCH_CNF].VariableField.NetworkID
            self.NMK = pkt[CM_SLAC_MATCH_CNF].VariableField.NMK
            print("INFO (PEV) : Sending SET_KEY_REQ")
            sendp(self.buildSetKeyReq(), iface=self.iface, verbose=0)
            self.stop = True
            Thread(target=self.sendSECCRequest).start()
            return

    def sendSECCRequest(self):
        time.sleep(3)
        print("INFO (PEV) : Sending SECC_RequestMessage")
        sendp(self.buildSECCRequest(), iface=self.iface, verbose=0)

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

    def buildSetKeyReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        ethLayer.dst = "00:b0:52:00:00:01"  # Some AtherosC MAC for whatever reason

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

        self.seq = 10000  # Initial sequence number for our side
        self.ack = 0      # Initial acknowledgment number

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
        self.handshake_complete = Event()  # Added to signal handshake completion

        # Fuzzing parameters
        self.iterations_per_element = iterations_per_element
        self.state_file = 'fuzzing_state.json'
        self.state = {}
        self.elements_to_modify = [
            "Body/CurrentDemandReq/DC_EVStatus/EVReady",
            "Body/CurrentDemandReq/DC_EVStatus/EVCabinConditioning",
            "Body/CurrentDemandReq/DC_EVStatus/EVRESSConditioning",
            "Body/CurrentDemandReq/DC_EVStatus/EVErrorCode",
            "Body/CurrentDemandReq/DC_EVStatus/EVRESSSOC",
            "Body/CurrentDemandReq/EVTargetCurrent/Multiplier",
            "Body/CurrentDemandReq/EVTargetCurrent/Unit",
            "Body/CurrentDemandReq/EVTargetCurrent/Value",
            "Body/CurrentDemandReq/EVMaximumVoltageLimit/Multiplier",
            "Body/CurrentDemandReq/EVMaximumVoltageLimit/Unit",
            "Body/CurrentDemandReq/EVMaximumVoltageLimit/Value",
            "Body/CurrentDemandReq/EVMaximumCurrentLimit/Multiplier",
            "Body/CurrentDemandReq/EVMaximumCurrentLimit/Unit",
            "Body/CurrentDemandReq/EVMaximumCurrentLimit/Value",
            "Body/CurrentDemandReq/BulkChargingComplete",
            "Body/CurrentDemandReq/ChargingComplete",
            "Body/CurrentDemandReq/RemainingTimeToFullSoC/Multiplier",
            "Body/CurrentDemandReq/RemainingTimeToFullSoC/Unit",
            "Body/CurrentDemandReq/RemainingTimeToFullSoC/Value",
            "Body/CurrentDemandReq/RemainingTimeToBulkSoC/Multiplier",
            "Body/CurrentDemandReq/RemainingTimeToBulkSoC/Unit",
            "Body/CurrentDemandReq/RemainingTimeToBulkSoC/Value",
            "Body/CurrentDemandReq/EVTargetVoltage/Multiplier",
            "Body/CurrentDemandReq/EVTargetVoltage/Unit",
            "Body/CurrentDemandReq/EVTargetVoltage/Value"
        ]
        # Initialize crash tracking
        self.crash_info = []  # List to store crash details
        self.total_attempts = 0
        self.total_crashes = 0
        self.state_lock = threading.Lock()

        # Event to signal when fuzzing can start
        self.supported_app_response_received = Event()
        self.session_setup_response_received = Event()
        self.service_discovery_response_received = Event()
        self.service_payment_selection_response_received = Event()  
        self.contract_authentication_response_received = Event()     
        self.charge_parameter_discovery_response_received = Event()
        self.cable_check_response_received = Event()
        self.pre_charge_response_received = Event()
        self.power_delivery_response_received = Event()

    # TCP 핸들러를 시작합니다
    def start(self):
        self.msgList = {}
        self.running = True
        self.prechargeCount = 0
        print("INFO (PEV) : Starting TCP")

        self.load_state()  # Load existing state before starting

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

    # SupportedAppProtocolRequest를 보냅니다
    def send_supported_app_protocol_request(self):
        print("INFO (TCPHandler): Sending SupportedAppProtocolRequest")
        handler = PacketHandler()
        handler.SupportedAppProtocolRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): SupportedAppProtocolRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for SupportedAppProtocolRequest")

    # SessionSetupRequest를 보냅니다
    def send_session_setup_request(self):
        print("INFO (TCPHandler): Sending SessionSetupRequest")
        handler = PacketHandler()
        handler.SessionSetupRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): SessionSetupRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for SessionSetupRequest")
        
    # ServiceDiscoveryRequest를 보냅니다
    def send_service_discovery_request(self):
        print("INFO (TCPHandler): Sending ServiceDiscoveryRequest")
        handler = PacketHandler()
        handler.ServiceDiscoveryRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): ServiceDiscoveryRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for ServiceDiscoveryRequest")

    # ServicePaymentSelectionRequest를 보냅니다
    def send_service_payment_selection_request(self):
        print("INFO (TCPHandler): Sending ServicePaymentSelectionRequest")
        handler = PacketHandler()
        handler.ServicePaymentSelectionRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): ServicePaymentSelectionRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for ServicePaymentSelectionRequest")

    # ContractAuthenticationRequest를 보냅니다
    def send_contract_authentication_request(self):
        print("INFO (TCPHandler): Sending ContractAuthenticationRequest")
        handler = PacketHandler()
        handler.ContractAuthenticationRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): ContractAuthenticationRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for ContractAuthenticationRequest")

    # ChargeParameterDiscoveryRequest를 보냅니다
    def send_charge_parameter_discovery_request(self):
        print("INFO (TCPHandler): Sending ChargeParameterDiscoveryRequest")
        handler = PacketHandler()
        handler.ChargeParameterDiscoveryRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): ChargeParameterDiscoveryRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for ChargeParameterDiscoveryRequest")
    
    # CableCheckRequest를 보냅니다
    def send_cable_check_request(self):
        print("INFO (TCPHandler): Sending CableCheckRequest")
        handler = PacketHandler()
        handler.CableCheckRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): CableCheckRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for CableCheckRequest")

    # PreChargeRequest를 보냅니다
    def send_pre_charge_request(self):
        print("INFO (TCPHandler): Sending PreChargeRequest")
        handler = PacketHandler()
        handler.PreChargeRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): PreChargeRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for PreChargeRequest")

    # PowerDeliveryRequest를 보냅니다
    def send_power_delivery_request(self):
        print("INFO (TCPHandler): Sending PowerDeliveryRequest")
        handler = PacketHandler()
        handler.PowerDeliveryRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')
        exi_payload = self.exi.encode(xml_string)
        if exi_payload is not None:
            try:
                exi_payload_bytes = binascii.unhexlify(exi_payload)
                packet = self.buildV2G(exi_payload_bytes)
                # Set seq and ack
                packet[TCP].seq = self.seq
                packet[TCP].ack = self.ack
                # Recalculate checksums
                del packet[TCP].chksum
                del packet[IPv6].plen
                # Calculate the actual TCP payload length
                tcp_payload_length = len(exi_payload_bytes) + 8
                sendp(packet, iface=self.iface, verbose=0)
                self.seq += tcp_payload_length  # Increment sequence number
                print("INFO (TCPHandler): PowerDeliveryRequest sent successfully")
            except binascii.Error as e:
                print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
        else:
            print("ERROR (TCPHandler): EXI encoding failed for PowerDeliveryRequest")

    # 핸드셰이크 완료를 기다리고 퍼징을 시작합니다
    def wait_and_start_fuzzing(self):
        # 핸드셰이크 완료를 기다림
        self.handshake_complete.wait()
        print("INFO (TCPHandler): Handshake complete")

        # SupportedAppProtocolRequest 전송
        self.send_supported_app_protocol_request()

        # SupportedAppProtocolResponse를 기다림
        print("INFO (TCPHandler): Waiting for SupportedAppProtocolResponse...")
        if self.supported_app_response_received.wait(timeout=15):
            print("INFO (TCPHandler): Received SupportedAppProtocolResponse")
            # SessionSetupRequest 전송
            self.send_session_setup_request()
            # SessionSetupResponse를 기다림
            print("INFO (TCPHandler): Waiting for SessionSetupResponse...")
            if self.session_setup_response_received.wait(timeout=15):
                print("INFO (TCPHandler): Received SessionSetupResponse")
                # ServiceDiscoveryRequest 전송
                self.send_service_discovery_request()
                # ServiceDiscoveryResponse를 기다림
                print("INFO (TCPHandler): Waiting for ServiceDiscoveryResponse...")
                if self.service_discovery_response_received.wait(timeout=15):
                    print("INFO (TCPHandler): Received ServiceDiscoveryResponse")
                    # ServicePaymentSelectionRequest 전송
                    self.send_service_payment_selection_request()
                    # ServicePaymentSelectionResponse를 기다림
                    print("INFO (TCPHandler): Waiting for ServicePaymentSelectionResponse...")
                    if self.service_payment_selection_response_received.wait(timeout=15):
                        print("INFO (TCPHandler): Received ServicePaymentSelectionResponse")
                        # ContractAuthenticationRequest 전송
                        self.send_contract_authentication_request()
                        # ContractAuthenticationResponse를 기다림
                        print("INFO (TCPHandler): Waiting for ContractAuthenticationResponse...")
                        if self.contract_authentication_response_received.wait(timeout=15):
                            print("INFO (TCPHandler): Received ContractAuthenticationResponse")
                            # ChargeParameterDiscoveryRequest 전송
                            self.send_charge_parameter_discovery_request()
                            # ChargeParameterDiscoveryResponse를 기다림
                            print("INFO (TCPHandler): Waiting for ChargeParameterDiscoveryResponse...")
                            if self.charge_parameter_discovery_response_received.wait(timeout=15):
                                print("INFO (TCPHandler): Received ChargeParameterDiscoveryResponse")
                                # CableCheckRequest 전송
                                self.send_cable_check_request()
                                # CableCheckResponse를 기다림
                                print("INFO (TCPHandler): Waiting for CableCheckResponse...")
                                if self.cable_check_response_received.wait(timeout=15):
                                    print("INFO (TCPHandler): Received CableCheckResponse")
                                    # PreChargeRequest 전송
                                    self.send_pre_charge_request()
                                    # PreChargeResponse를 기다림
                                    print("INFO (TCPHandler): Waiting for PreChargeResponse...")
                                    if self.pre_charge_response_received.wait(timeout=15):
                                        print("INFO (TCPHandler): Received PreChargeResponse")
                                        # PowerDeliveryRequest 전송
                                        self.send_power_delivery_request()
                                        # PowerDeliveryResponse를 기다림
                                        print("INFO (TCPHandler): Waiting for PowerDeliveryResponse...")
                                        if self.power_delivery_response_received.wait(timeout=15):
                                            print("INFO (TCPHandler): Received PowerDeliveryResponse, starting fuzzing.")
                                            # 이제 CurrentDemandRequest를 보내고 퍼징을 시작
                                            self.send_fuzzing_messages()
                                        else:
                                            print("WARNING (TCPHandler): PowerDeliveryResponse not received within timeout, not starting fuzzing.")
                                    else:
                                        print("WARNING (TCPHandler): PreChargeResponse not received within timeout, not proceeding.")
                                else:
                                    print("WARNING (TCPHandler): CableCheckResponse not received within timeout, not proceeding.")
                            else:
                                print("WARNING (TCPHandler): ChargeParameterDiscoveryResponse not received within timeout, not proceeding.")
                        else:
                            print("WARNING (TCPHandler): ContractAuthenticationResponse not received within timeout, not proceeding.")
                    else:
                        print("WARNING (TCPHandler): ServicePaymentSelectionResponse not received within timeout, not proceeding.")
                else:
                    print("WARNING (TCPHandler): ServiceDiscoveryResponse not received within timeout, not proceeding.")
            else:
                print("WARNING (TCPHandler): SessionSetupResponse not received within timeout, not proceeding.")
        else:
            print("WARNING (TCPHandler): SupportedAppProtocolResponse not received within timeout, not proceeding.")

    # 스레드를 종료합니다
    def killThreads(self):
        print("INFO (PEV) : Killing sniffing threads")
        if self.scanner is not None:
            self.scanner.stop()
        self.running = False
        if self.neighborSolicitationThread.running:
            self.neighborSolicitationThread.stop()
        if self.recvThread.running:
            if threading.current_thread() != self.recvThread.thread:
                self.recvThread.stop()
            else:
                # 스니퍼가 현재 스레드에서 실행 중인 경우 별도의 스레드에서 중지 요청
                threading.Thread(target=self.recvThread.stop).start()
    
    # XML 경로를 통해 요소를 찾습니다
    def find_element_by_path(self, root, path):
        elements = path.split('/')
        current_element = root
        for elem_name in elements:
            found = False
            print(f"Looking for element '{elem_name}' in:")
            for child in current_element:
                local_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                print(f" - {local_tag}")
                if local_tag == elem_name:
                    current_element = child
                    found = True
                    break
            if not found:
                print(f"Element '{elem_name}' not found.")
                return None
        return current_element

    def fin(self):
        print("INFO (PEV): Received FIN")
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

        print("INFO (PEV): Sending FINACK")

        sendp(finAck, iface=self.iface, verbose=0)

    def setStartSniff(self):
        self.startSniff = True

    def startSession(self):
        # 핸드셰이크 완료를 위해 ACK 전송
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
        ## self.seq += 1  # ACK 전송 후 시퀀스 번호 증가
        print("INFO (PEV): Sending ACK to complete the handshake")
        # 핸드셰이크 완료 신호 설정
        self.handshake_complete.set()

    # 퍼징 메시지를 보냅니다
    def send_fuzzing_messages(self):
        # 초기 XML 메시지 빌드 (CurrentDemandRequest 사용)
        handler = PacketHandler()
        handler.CurrentDemandRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')


        # 퍼징 상태 로드
        self.load_state()

        # 각 요소에 대해 퍼징 수행
        self.fuzz_payload(xml_string)

    # 수신된 패킷을 처리합니다
    def handlePacket(self, pkt):
        self.last_recv = pkt
        tcp_layer = pkt[TCP]

        # 시퀀스 및 응답 번호 업데이트
        if len(tcp_layer.payload) > 0:
            self.ack = tcp_layer.seq + len(tcp_layer.payload)
        else:
            self.ack = tcp_layer.seq + 1  # 페이로드가 없는 패킷의 경우

        # RST 플래그 확인
        if tcp_layer.flags & 0x04:  # RST 플래그
            print("INFO (PEV): Received RST")
            self.rst_received = True
            self.response_received.set()
            return

        # SYN-ACK 확인
        if (tcp_layer.flags & 0x12) == 0x12:  # SYN과 ACK 플래그가 설정된 경우
            print("INFO (PEV): Received SYN-ACK")
            self.ack = tcp_layer.seq + 1  # 서버의 SYN을 ACK
            self.seq += 1  # ACK 전송 후 시퀀스 번호 증가
            self.startSession()
            return

        # FIN 플래그 확인
        if tcp_layer.flags & 0x01:  # FIN 플래그
            self.fin()
            return

        # 어떤 패킷이든 응답을 받았음을 설정
        self.response_received.set()

        # V2GTP 레이어가 있는지 확인하고 처리
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            v2g = V2GTP(data)
            payload = v2g.Payload
            data_hex = binascii.hexlify(payload).decode()
            try:
                xmlString = self.exi.decode(data_hex)
                root = ET.fromstring(xmlString)
                # 네임스페이스 없이 로컬 태그 이름 추출
                local_tag = root.tag.split('}')[-1] if '}' in root.tag else root.tag

                if local_tag == "supportedAppProtocolRes":
                    print("INFO (TCPHandler): Received SupportedAppProtocolResponse")
                    self.supported_app_response_received.set()
                    return
                elif local_tag == "V2G_Message":
                    # V2G_Message 내부의 특정 메시지 찾기
                    body = root.find('.//{*}Body')
                    if body is not None:
                        # Body의 첫 번째 자식 메시지 가져오기
                        message = next(iter(body))
                        message_tag = message.tag.split('}')[-1] if '}' in message.tag else message.tag
                        print(f"INFO (TCPHandler): Received message inside V2G_Message: {message_tag}")

                        if message_tag == "SessionSetupRes":
                            print("INFO (TCPHandler): Received SessionSetupResponse")
                            self.session_setup_response_received.set()
                            return
                        elif message_tag == "ServiceDiscoveryRes":
                            print("INFO (TCPHandler): Received ServiceDiscoveryResponse")
                            self.service_discovery_response_received.set()
                            return
                        elif message_tag == "ServicePaymentSelectionRes":
                            print("INFO (TCPHandler): Received ServicePaymentSelectionResponse")
                            self.service_payment_selection_response_received.set()
                            return
                        elif message_tag == "ContractAuthenticationRes":
                            print("INFO (TCPHandler): Received ContractAuthenticationResponse")
                            self.contract_authentication_response_received.set()
                            return
                        elif message_tag == "ChargeParameterDiscoveryRes":
                            print("INFO (TCPHandler): Received ChargeParameterDiscoveryResponse")
                            self.charge_parameter_discovery_response_received.set()
                            return
                        elif message_tag == "CableCheckRes":
                            print("INFO (TCPHandler): Received CableCheckResponse")
                            self.cable_check_response_received.set()
                            return
                        elif message_tag == "PreChargeRes":
                            print("INFO (TCPHandler): Received PreChargeResponse")
                            self.pre_charge_response_received.set()
                            return
                        elif message_tag == "PowerDeliveryRes":
                            print("INFO (TCPHandler): Received PowerDeliveryResponse")
                            self.power_delivery_response_received.set()
                            return
                        else:
                            print(f"INFO (TCPHandler): Received unknown message inside V2G_Message: {message_tag}")
                    else:
                        print("WARNING (TCPHandler): Body element not found in V2G_Message")
                else:
                    print(f"INFO (TCPHandler): Received unknown message: {local_tag}")
            except Exception as e:
                print(f"ERROR (TCPHandler): Failed to decode or parse EXI payload: {e}")
                return
        else:
            print("WARNING: No Raw layer found in packet. Cannot extract data.")
            return

    # 페이로드를 퍼징합니다
    def fuzz_payload(self, xml_string):
        print("INFO (TCPHandler): Starting fuzz_payload method.")
        elements_to_modify = self.elements_to_modify

        # 퍼징할 요소의 시작 인덱스
        current_element_index = self.state.get('current_element_index', 0)
        iteration_count = self.state.get('iterations', {})
        total_attempts = self.state.get('total_attempts', 0)
        total_crashes = self.state.get('total_crashes', 0)

        for idx in range(current_element_index, len(elements_to_modify)):
            element_path = elements_to_modify[idx]
            # XML 파싱
            root = ET.fromstring(xml_string)

            # 요소 경로를 사용하여 요소 찾기
            elem = self.find_element_by_path(root, element_path)
            if elem is None:
                print(f"ERROR: Element '{element_path}' not found in the XML.")
                continue

            # 요소의 텍스트가 비어있으면 기본값 "1" 할당
            if not elem.text:
                elem.text = "1"  # 기본값 "1" 할당

            mutated_value = elem.text  # 초기 값

            start_iteration = iteration_count.get(element_path, 0)

            for iteration in range(start_iteration, self.iterations_per_element):
                # 네 가지 변이 함수 중 하나 랜덤 선택
                mutation_func = random.choice([self.value_flip, self.random_value, self.random_deletion, self.random_insertion])
                mutated_value = mutation_func(mutated_value)  # 선택한 변이 함수 적용

                # 변이된 값이 비어있으면 이전 값으로 복원
                if not mutated_value:
                    print(f"Mutated value became empty, reverting to previous value: {elem.text}")
                    mutated_value = elem.text  # 이전 값 복원

                elem.text = mutated_value

                # 변이된 XML 직렬화
                fuzzed_xml = ET.tostring(root, encoding='unicode')

                # 디버깅 메시지 출력
                print(f"\n{'=' * 40}")
                print(f"[{element_path}] Iteration {iteration+1}: Mutated using {mutation_func.__name__}")
                print(f"Mutated value: {mutated_value}")
                print(f"Fuzzed XML:\n{fuzzed_xml}")
                print(f"{'=' * 40}\n")

                # 총 시도 횟수 증가
                with self.state_lock:
                    self.state['total_attempts'] = total_attempts + 1
                    total_attempts += 1

                # 전송 전 응답 이벤트 클리어
                self.response_received.clear()
                self.rst_received = False

                # EXI 인코딩 및 전송
                exi_payload = self.exi.encode(fuzzed_xml)
                if exi_payload is not None:
                    try:
                        exi_payload_bytes = binascii.unhexlify(exi_payload)
                        packet = self.buildV2G(exi_payload_bytes)
                        # Set seq and ack
                        packet[TCP].seq = self.seq
                        packet[TCP].ack = self.ack
                        # Recalculate checksums
                        del packet[TCP].chksum
                        del packet[IPv6].plen
                        # Calculate the actual TCP payload length
                        tcp_payload_length = len(exi_payload_bytes) + 8  # V2GTP header is 8 bytes
                        sendp(packet, iface=self.iface, verbose=0)
                        self.seq += tcp_payload_length  # Increment sequence number
                    except binascii.Error as e:
                        print(f"ERROR (TCPHandler): Failed to unhexlify EXI payload: {e}")
                        continue
                else:
                    print("ERROR (TCPHandler): EXI encoding failed for fuzzed XML")
                    continue

                # 변이 횟수 업데이트
                with self.state_lock:
                    self.state['iterations'][element_path] = iteration + 1

                # 상태 저장
                self.save_state()

                # 응답 대기
                response = self.response_received.wait(timeout=2)  # 최대 2초 대기

                if not response or self.rst_received:
                    # 응답을 받지 못했거나 RST를 받았을 경우 크래시 기록
                    print("No response received or RST received, recording crash.")
                    # 크래시 횟수 증가
                    with self.state_lock:
                        self.state['total_crashes'] = total_crashes + 1
                        total_crashes += 1

                        # 크래시 세부 정보 기록
                        crash_detail = {
                            'element': element_path,
                            'iteration': iteration + 1,
                            'mutated_value': mutated_value,
                            'fuzzed_xml': fuzzed_xml
                        }
                        if 'crash_inputs' not in self.state:
                            self.state['crash_inputs'] = []
                        self.state['crash_inputs'].append(crash_detail)

                    # 상태 저장
                    self.save_state()
                    self.killThreads()
                    return

                # 다음 반복으로 진행

            # 해당 요소의 변이 횟수 리셋 및 다음 요소로 이동
            with self.state_lock:
                self.state['iterations'][element_path] = 0

            # 다음 요소로 이동
            with self.state_lock:
                self.state['current_element_index'] = idx + 1

        print("Fuzzing completed for all elements.")
        # 상태 파일 삭제 (퍼징 완료 후)
        if os.path.exists(self.state_file):
            os.remove(self.state_file)
        # 요약 보고서 생성
        self.generate_report()



    def generate_report(self):
        report = {
            'total_attempts': self.state.get('total_attempts', 0),
            'total_crashes': self.state.get('total_crashes', 0),
            'crash_details': self.state.get('crash_inputs', [])
        }

        report_file = 'fuzzing_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)

        print(f"\n{'=' * 40}")
        print("Fuzzing Summary Report")
        print(f"Total Attempts: {report['total_attempts']}")
        print(f"Total Crashes: {report['total_crashes']}")
        print(f"Crash Details saved in {report_file}")
        print(f"{'=' * 40}\n")


    # 값을 뒤집습니다
    def value_flip(self, value):
        if len(value) < 2:
            return value  # 두 글자 미만이면 교환 불가
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

        # 랜덤 삽입 위치 선택
        insert_idx = random.randrange(len(value)+1)

        # 삽입할 랜덤 문자 선택 (알파벳 및 숫자)
        random_char = random.choice(string.ascii_letters + string.digits)

        # 문자열을 리스트로 변환하고 문자 삽입
        value_list = list(value)
        value_list.insert(insert_idx, random_char)

        # 리스트를 다시 문자열로 변환
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
        print("INFO (PEV) : Sending SYN")
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
        print("INFO (PEV) : Sending Neighbor Solicitation")
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

    # Neighbor Solicitation에 응답을 보냅니다
    def sendNeighborAdvertisement(self, pkt):
        # if self.stop: exit()
        # if not (pkt.haslayer("ICMPv6ND_NS") and pkt[ICMPv6ND_NS].tgt == self.sourceIP): return
        self.destinationMAC = pkt[Ether].src
        self.destinationIP = pkt[IPv6].src
        # print("INFO (EVSE): Sending Neighor Advertisement")
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)

    def load_state(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, 'r') as f:
                self.state = json.load(f)
            print(f"Loaded fuzzing state from {self.state_file}")
        else:
            # Initialize state
            self.state = {
                'current_element_index': 0,
                'iterations': {},
                'crash_info': [],
                'total_attempts': 0,
                'total_crashes': 0,
                'crash_inputs': []
            }
            for element_path in self.elements_to_modify:
                self.state['iterations'][element_path] = 0

    def save_state(self):
        with self.state_lock:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=4)
            print(f"Saved fuzzing state to {self.state_file}")


if __name__ == "__main__":
    # 커맨드 라인 인수를 파싱합니다
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
        print("INFO (PEV) : Shutting down emulator")
    except Exception as e:
        print(e)
    finally:
        pev.setState(PEVState.A)
        del pev
