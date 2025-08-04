"""
PreChargeRequest 메시지를 가지고 퍼징을 수행하는 코드입니다. 
타겟 상태머신 : Wait for PreChargeRequest
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
import threading  # Added for threading.Lock()


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

        # Constants for i2c controlled relays (commented out as per your original code)
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
        # If NMAP is not done, restart connection
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


# This class handles the level 2 SLAC protocol communications and the SECC Request
class _SLACHandler:
    def __init__(self, pev: PEV):
        self.pev = pev
        self.iface = self.pev.iface
        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.runID = os.urandom(8)

        self.timeSinceLastPkt = time.time()
        self.timeout = 8  # How long to wait for a message to timeout
        self.stop = False

    # This method starts the slac process and will stop
    def start(self):
        self.runID = os.urandom(8)
        self.stop = False

        self.sniffThread = AsyncSniffer(iface=self.iface, prn=self.handlePacket, stop_filter=self.stopSniff)
        self.sniffThread.start()

        # Thread to determine if PEV timed out or SLAC error occurred and restart SLAC process
        self.timeoutThread = Thread(target=self.checkForTimeout)
        self.timeoutThread.start()

        self.neighborSolicitationThread = AsyncSniffer(
            iface=self.iface, lfilter=lambda x: x.haslayer("ICMPv6ND_NS") and x[ICMPv6ND_NS].tgt == self.sourceIP, prn=self.sendNeighborSolicitation
        )
        self.neighborSolicitationThread.start()

        # Start the SLAC process by sending SLAC Parameter Request
        sendp(self.buildSlacParmReq(), iface=self.iface, verbose=0)

    # The EVSE sometimes fails the SLAC process, so this automatically restarts it from the beginning
    def checkForTimeout(self):
        while not self.stop:
            if time.time() - self.timeSinceLastPkt > self.timeout:
                print("INFO (PEV) : Timed out... Sending SLAC_PARM_REQ")
                sendp(self.buildSlacParmReq(), iface=self.iface, verbose=0)
                self.timeSinceLastPkt = time.time()
            time.sleep(1)

    # Stop the thread when the SLAC match is done
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
            "Body/PreChargeReq/DC_EVStatus/EVReady",
            "Body/PreChargeReq/DC_EVStatus/EVErrorCode",
            "Body/PreChargeReq/DC_EVStatus/EVRESSSOC",
            "Body/PreChargeReq/EVTargetVoltage/Multiplier",
            "Body/PreChargeReq/EVTargetVoltage/Unit",
            "Body/PreChargeReq/EVTargetVoltage/Value",
            "Body/PreChargeReq/EVTargetCurrent/Multiplier",
            "Body/PreChargeReq/EVTargetCurrent/Unit",
            "Body/PreChargeReq/EVTargetCurrent/Value"
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

    def wait_and_start_fuzzing(self):
        # Wait for handshake to complete
        self.handshake_complete.wait()
        print("INFO (TCPHandler): Handshake complete")

        # Now send the SupportedAppProtocolRequest
        self.send_supported_app_protocol_request()

        # Wait for SupportedAppProtocolResponse
        print("INFO (TCPHandler): Waiting for SupportedAppProtocolResponse...")
        if self.supported_app_response_received.wait(timeout=15):
            print("INFO (TCPHandler): Received SupportedAppProtocolResponse")
            # Now send SessionSetupRequest
            self.send_session_setup_request()
            # Wait for SessionSetupResponse
            print("INFO (TCPHandler): Waiting for SessionSetupResponse...")
            if self.session_setup_response_received.wait(timeout=15):
                print("INFO (TCPHandler): Received SessionSetupResponse")
                # Now send ServiceDiscoveryRequest
                self.send_service_discovery_request()
                # Wait for ServiceDiscoveryResponse
                print("INFO (TCPHandler): Waiting for ServiceDiscoveryResponse...")
                if self.service_discovery_response_received.wait(timeout=15):
                    print("INFO (TCPHandler): Received ServiceDiscoveryResponse")
                    # Now send ServicePaymentSelectionRequest
                    self.send_service_payment_selection_request()
                    # Wait for ServicePaymentSelectionResponse
                    print("INFO (TCPHandler): Waiting for ServicePaymentSelectionResponse...")
                    if self.service_payment_selection_response_received.wait(timeout=15):
                        print("INFO (TCPHandler): Received ServicePaymentSelectionResponse")
                        # Now send ContractAuthenticationRequest
                        self.send_contract_authentication_request()
                        # Wait for ContractAuthenticationResponse
                        print("INFO (TCPHandler): Waiting for ContractAuthenticationResponse...")
                        if self.contract_authentication_response_received.wait(timeout=15):
                            print("INFO (TCPHandler): Received ContractAuthenticationResponse")
                            # Now send ChargeParameterDiscoveryRequest
                            self.send_charge_parameter_discovery_request()
                            # Wait for ChargeParameterDiscoveryResponse
                            print("INFO (TCPHandler): Waiting for ChargeParameterDiscoveryResponse...")
                            if self.charge_parameter_discovery_response_received.wait(timeout=15):
                                print("INFO (TCPHandler): Received ChargeParameterDiscoveryResponse")
                                # Now send CableCheckRequest
                                self.send_cable_check_request()
                                # Wait for CableCheckResponse
                                print("INFO (TCPHandler): Waiting for CableCheckResponse...")
                                if self.cable_check_response_received.wait(timeout=15):
                                    print("INFO (TCPHandler): Received CableCheckResponse, starting fuzzing.")
                                    # Now send PreChargeRequest and start fuzzing
                                    self.send_fuzzing_messages()
                                else:
                                    print("WARNING (TCPHandler): CableCheckResponse not received within timeout, not starting fuzzing.")
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
                # Schedule stopping the thread after it returns
                threading.Thread(target=self.recvThread.stop).start()
    
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
        # Send ACK to complete handshake
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
        ## self.seq += 1  # Increment our sequence number after sending the ACK
        print("INFO (PEV): Sending ACK to complete the handshake")
        # Signal that the handshake is complete
        self.handshake_complete.set()

    def send_fuzzing_messages(self):
        # Build the initial XML message
        handler = PacketHandler()
        handler.PreChargeRequest()
        xml_string = ET.tostring(handler.root, encoding='unicode')

        # Load fuzzing state
        self.load_state()

        # Fuzz each element
        self.fuzz_payload(xml_string)

    def handlePacket(self, pkt):
        self.last_recv = pkt
        tcp_layer = pkt[TCP]

        # Update sequence and acknowledgment numbers
        if len(tcp_layer.payload) > 0:
            self.ack = tcp_layer.seq + len(tcp_layer.payload)
        else:
            self.ack = tcp_layer.seq + 1  # For packets without payload

        # Check for RST flag
        if tcp_layer.flags & 0x04:  # RST flag
            print("INFO (PEV): Received RST")
            self.rst_received = True
            self.response_received.set()
            return

        # Check for SYN-ACK
        if (tcp_layer.flags & 0x12) == 0x12:  # SYN and ACK flags set
            print("INFO (PEV): Received SYN-ACK")
            self.ack = tcp_layer.seq + 1  # Acknowledge the server's SYN
            self.seq += 1  # Increment our sequence number after sending ACK
            self.startSession()
            return

        # Check for FIN flag
        if tcp_layer.flags & 0x01:  # FIN flag
            self.fin()
            return

        # For any packet, set response_received
        self.response_received.set()

        # Process V2GTP layer if present
    # Process the data
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            v2g = V2GTP(data)
            payload = v2g.Payload
            data_hex = binascii.hexlify(payload).decode()
            try:
                xmlString = self.exi.decode(data_hex)
                root = ET.fromstring(xmlString)
                # Extract local tag name without namespace
                local_tag = root.tag.split('}')[-1] if '}' in root.tag else root.tag

                if local_tag == "supportedAppProtocolRes":
                    print("INFO (TCPHandler): Received SupportedAppProtocolResponse")
                    self.supported_app_response_received.set()
                    return
                elif local_tag == "V2G_Message":
                    # Look for the specific message inside V2G_Message
                    body = root.find('.//{*}Body')
                    if body is not None:
                        # Get the first child of Body
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

    def fuzz_payload(self, xml_string):
        print("INFO (TCPHandler): Starting fuzz_payload method.")
        elements_to_modify = self.elements_to_modify

        # Starting index of element to fuzz
        current_element_index = self.state.get('current_element_index', 0)
        iteration_count = self.state.get('iterations', {})
        total_attempts = self.state.get('total_attempts', 0)
        total_crashes = self.state.get('total_crashes', 0)

        for idx in range(current_element_index, len(elements_to_modify)):
            element_path = elements_to_modify[idx]
            # Parse XML
            root = ET.fromstring(xml_string)

            # Find the element using the path
            elem = self.find_element_by_path(root, element_path)
            if elem is None:
                print(f"ERROR: Element '{element_path}' not found in the XML.")
                continue

            # Assign default value if empty
            if not elem.text:
                elem.text = "1"  # Assign default value "1"

            mutated_value = elem.text  # Initial value

            start_iteration = iteration_count.get(element_path, 0)

            for iteration in range(start_iteration, self.iterations_per_element):
                # Randomly select one of the four mutation functions
                mutation_func = random.choice([self.value_flip, self.random_value, self.random_deletion, self.random_insertion])
                mutated_value = mutation_func(mutated_value)  # Perform the randomly selected mutation

                # If mutated value is empty, revert to previous value
                if not mutated_value:
                    print(f"Mutated value became empty, reverting to previous value: {elem.text}")
                    mutated_value = elem.text  # Restore previous value

                elem.text = mutated_value

                # Serialize mutated XML
                fuzzed_xml = ET.tostring(root, encoding='unicode')

                # Debugging messages
                print(f"\n{'=' * 40}")
                print(f"[{element_path}] Iteration {iteration+1}: Mutated using {mutation_func.__name__}")
                print(f"Mutated value: {mutated_value}")
                print(f"Fuzzed XML:\n{fuzzed_xml}")
                print(f"{'=' * 40}\n")

                # Increment total attempts
                with self.state_lock:
                    self.state['total_attempts'] = total_attempts + 1
                    total_attempts += 1

                # Clear response_received event before sending
                self.response_received.clear()
                self.rst_received = False

                # EXI encoding and sending
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

                # Update iteration count
                with self.state_lock:
                    self.state['iterations'][element_path] = iteration + 1

                # Save state
                self.save_state()

                # Wait for response
                response = self.response_received.wait(timeout=2)  # Wait for up to 2 seconds

                if not response or self.rst_received:
                    # No response received or RST received
                    print("No response received or RST received, recording crash.")
                    # Increment crash count
                    with self.state_lock:
                        self.state['total_crashes'] = total_crashes + 1
                        total_crashes += 1

                        # Record the crashing input
                        crash_detail = {
                            'element': element_path,
                            'iteration': iteration + 1,
                            'mutated_value': mutated_value,
                            'fuzzed_xml': fuzzed_xml
                        }
                        if 'crash_inputs' not in self.state:
                            self.state['crash_inputs'] = []
                        self.state['crash_inputs'].append(crash_detail)

                    # Save state
                    self.save_state()
                    self.killThreads()
                    return

                # Proceed to next iteration

            # Reset iteration count for this element
            with self.state_lock:
                self.state['iterations'][element_path] = 0

            # Move to next element
            with self.state_lock:
                self.state['current_element_index'] = idx + 1

        print("Fuzzing completed for all elements.")
        # Remove state file if exists
        if os.path.exists(self.state_file):
            os.remove(self.state_file)
        # Generate summary report
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


    def value_flip(self, value):
        if len(value) < 2:
            return value  # Cannot swap if less than two characters
        idx1, idx2 = random.sample(range(len(value)), 2)
        value_list = list(value)
        value_list[idx1], value_list[idx2] = value_list[idx2], value_list[idx1]
        return ''.join(value_list)

    def random_value(self, value):
        if len(value) == 0:
            return value
        idx = random.randrange(len(value))
        new_char = chr(random.randint(33, 126))
        value_list = list(value)
        value_list[idx] = new_char
        return ''.join(value_list)

    def random_deletion(self, value):
        if len(value) == 0:
            return value
        idx = random.randrange(len(value))
        value_list = list(value)
        del value_list[idx]
        return ''.join(value_list)

    def random_insertion(self, value):
        if len(value) == 0:
            return value

        # Randomly select insertion position
        insert_idx = random.randrange(len(value)+1)

        # Randomly select character to insert (letters and digits)
        random_char = random.choice(string.ascii_letters + string.digits)

        # Convert string to list and insert
        value_list = list(value)
        value_list.insert(insert_idx, random_char)

        # Convert list back to string and return
        return ''.join(value_list)

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

    def sendNeighborAdvertisement(self, pkt):
        # if self.stop: exit()
        # if not (pkt.haslayer("ICMPv6ND_NS") and pkt[ICMPv6ND_NS].tgt == self.sourceIP): return
        self.destinationMAC = pkt[Ether].src
        self.destinationIP = pkt[IPv6].src
        # print("INFO (EVSE): Sending Neighor Advertisement")
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)

    def buildLeaveReq(self):
        ethLayer = Ether()
        ethLayer.src = self.sourceMAC
        # ethLayer.dst = self.destinationMAC
        ethLayer.dst = "bc:f2:af:f2:0a:7b"

        hpLayer = HomePlugAV(binascii.unhexlify(b"01340000000100000000000000000000000000000000000000000000000000000000000000000000000000000000"))

        pkt = ethLayer / hpLayer
        return pkt

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
    # Parse arguments from command line
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
