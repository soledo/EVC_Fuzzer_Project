#!/usr/bin/env python3

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
import threading

# V2G protocol state configuration
STATE_CONFIG = {
    'state1': {
        'name': 'SupportedAppProtocol',
        'description': 'Fuzzes the SupportedAppProtocolRequest',
        'elements_to_modify': ["ProtocolNamespace", "VersionNumberMajor", "VersionNumberMinor", "SchemaID", "Priority"],
        'wait_for_message': None,
        'xml_method': 'SupportedAppProtocolRequest'
    },
    'state2': {
        'name': 'SessionSetup', 
        'description': 'Fuzzes the SessionSetupRequest',
        'elements_to_modify': ['V2G_Message/Body/SessionSetupReq/EVCCID'],
        'wait_for_message': 'sessionSetupRes',
        'xml_method': 'SessionSetupRequest'
    },
    'state3': {
        'name': 'ServiceDiscovery',
        'description': 'Fuzzes the ServiceDiscoveryRequest',
        'elements_to_modify': ['V2G_Message/Body/ServiceDiscoveryReq/ServiceScope', 'V2G_Message/Body/ServiceDiscoveryReq/ServiceCategory'],
        'wait_for_message': 'sessionSetupRes',
        'xml_method': 'ServiceDiscoveryRequest'
    },
    'state4': {
        'name': 'ServicePaymentSelection',
        'description': 'Fuzzes the ServicePaymentSelectionRequest',
        'elements_to_modify': ['V2G_Message/Body/ServicePaymentSelectionReq/SelectedPaymentOption', 'V2G_Message/Body/ServicePaymentSelectionReq/SelectedServiceList/SelectedService/ServiceID'],
        'wait_for_message': 'serviceDiscoveryRes',
        'xml_method': 'ServicePaymentSelectionRequest'
    },
    'state5': {
        'name': 'ChargeParameterDiscovery',
        'description': 'Fuzzes the ChargeParameterDiscoveryRequest',
        'elements_to_modify': ['V2G_Message/Body/ChargeParameterDiscoveryReq/RequestedEnergyTransferMode', 'V2G_Message/Body/ChargeParameterDiscoveryReq/EVChargeParameter/DepartureTime'],
        'wait_for_message': 'servicePaymentSelectionRes',
        'xml_method': 'ChargeParameterDiscoveryRequest'
    },
    'state6': {
        'name': 'CableCheck',
        'description': 'Fuzzes the CableCheckRequest',
        'elements_to_modify': ['V2G_Message/Body/CableCheckReq/DC_EVStatus/EVReady', 'V2G_Message/Body/CableCheckReq/DC_EVStatus/EVCabinConditioning'],
        'wait_for_message': 'chargeParameterDiscoveryRes',
        'xml_method': 'CableCheckRequest'
    },
    'state7': {
        'name': 'PreCharge',
        'description': 'Fuzzes the PreChargeRequest',
        'elements_to_modify': ['V2G_Message/Body/PreChargeReq/DC_EVStatus/EVReady', 'V2G_Message/Body/PreChargeReq/EVTargetVoltage/Value'],
        'wait_for_message': 'cableCheckRes',
        'xml_method': 'PreChargeRequest'
    },
    'state8': {
        'name': 'PowerDelivery',
        'description': 'Fuzzes the PowerDeliveryRequest',
        'elements_to_modify': ['V2G_Message/Body/PowerDeliveryReq/ChargeProgress', 'V2G_Message/Body/PowerDeliveryReq/DC_EVPowerDeliveryParameter/DC_EVStatus/EVReady'],
        'wait_for_message': 'preChargeRes',
        'xml_method': 'PowerDeliveryRequest'
    },
    'state9': {
        'name': 'CurrentDemand',
        'description': 'Fuzzes the CurrentDemandRequest',
        'elements_to_modify': ['V2G_Message/Body/CurrentDemandReq/DC_EVStatus/EVReady', 'V2G_Message/Body/CurrentDemandReq/EVTargetCurrent/Value'],
        'wait_for_message': 'powerDeliveryRes',
        'xml_method': 'CurrentDemandRequest'
    },
    'state10': {
        'name': 'WeldingDetection',
        'description': 'Fuzzes the WeldingDetectionRequest',
        'elements_to_modify': ['V2G_Message/Body/WeldingDetectionReq/DC_EVStatus/EVReady', 'V2G_Message/Body/WeldingDetectionReq/DC_EVStatus/EVCabinConditioning'],
        'wait_for_message': 'currentDemandRes',
        'xml_method': 'WeldingDetectionRequest'
    }
}

class PEV:

    def __init__(self, args):
        self.mode = RunMode(args.mode[0]) if args.mode else RunMode.FULL
        self.iface = args.interface[0] if args.interface else "eth1"
        self.sourceMAC = args.source_mac[0] if args.source_mac else "00:1e:c0:f2:6c:a1"
        self.sourceIP = args.source_ip[0] if args.source_ip else "fe80::21e:c0ff:fef2:6ca1"
        self.sourcePort = args.source_port[0] if args.source_port else random.randint(1025, 65534)
        self.protocol = Protocol(args.protocol[0]) if args.protocol else Protocol.DIN
        self.iterations_per_element = args.iterations_per_element
        self.target_state = args.state

        self.destinationMAC = None
        self.destinationIP = None
        self.destinationPort = None

        self.exi = EXIProcessor(self.protocol)
        self.slac = _SLACHandler(self)
        self.xml = PacketHandler()
        self.tcp = _TCPHandler(self, self.iterations_per_element, self.target_state)

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


class _SLACHandler:
    def __init__(self, pev: PEV):
        self.pev = pev
        self.iface = self.pev.iface
        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.runID = os.urandom(8)

        self.timeSinceLastPkt = time.time()
        self.timeout = 8
        self.stop = False

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

    def checkForTimeout(self):
        while not self.stop:
            if time.time() - self.timeSinceLastPkt > self.timeout:
                print("INFO (PEV) : Timed out... Sending SLAC_PARM_REQ")
                sendp(self.buildSlacParmReq(), iface=self.iface, verbose=0)
                self.timeSinceLastPkt = time.time()
            time.sleep(1)

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
    def __init__(self, pev: PEV, iterations_per_element, target_state):
        self.pev = pev
        self.iface = self.pev.iface
        self.target_state = target_state

        self.sourceMAC = self.pev.sourceMAC
        self.sourceIP = self.pev.sourceIP
        self.sourcePort = self.pev.sourcePort

        self.destinationMAC = self.pev.destinationMAC
        self.destinationIP = self.pev.destinationIP
        self.destinationPort = self.pev.destinationPort

        self.seq = 10000
        self.ack = 0

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
        self.handshake_complete = Event()

        self.iterations_per_element = iterations_per_element
        
        # Create reports directory with proper permissions
        self.reports_dir = 'fuzzing_reports'
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Fix ownership if running as root
        if os.geteuid() == 0:  # Running as root
            # Get the user who invoked sudo
            sudo_user = os.environ.get('SUDO_USER')
            if sudo_user:
                import pwd
                import grp
                try:
                    pw_record = pwd.getpwnam(sudo_user)
                    user_uid = pw_record.pw_uid
                    user_gid = pw_record.pw_gid
                    os.chown(self.reports_dir, user_uid, user_gid)
                except:
                    pass  # If it fails, just continue
        
        self.state_file = os.path.join(self.reports_dir, f'fuzzing_state_{target_state}.json')
        self.state = {}
        
        # Store user info for file ownership fixing
        self.sudo_user = os.environ.get('SUDO_USER')
        self.user_uid = None
        self.user_gid = None
        if self.sudo_user and os.geteuid() == 0:
            try:
                import pwd
                pw_record = pwd.getpwnam(self.sudo_user)
                self.user_uid = pw_record.pw_uid
                self.user_gid = pw_record.pw_gid
            except:
                pass
        
        # Get state configuration
        if target_state in STATE_CONFIG:
            self.state_config = STATE_CONFIG[target_state]
            self.elements_to_modify = self.state_config['elements_to_modify']
        else:
            raise ValueError(f"Invalid target state: {target_state}. Available states: {list(STATE_CONFIG.keys())}")
        
        self.crash_info = []
        self.total_attempts = 0
        self.total_crashes = 0
        self.state_lock = threading.Lock()

        print(f"INFO (PEV): Initialized fuzzer for {self.state_config['name']} state")
        print(f"INFO (PEV): {self.state_config['description']}")
        print(f"INFO (PEV): Target elements: {self.elements_to_modify}")

    def start(self):
        self.msgList = {}
        self.running = True
        self.prechargeCount = 0
        print(f"INFO (PEV) : Starting TCP fuzzer for {self.target_state}")

        self.load_state()

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

        self.fuzzingThread = Thread(target=self.wait_and_start_fuzzing)
        self.fuzzingThread.start()

        while self.running:
            time.sleep(1)

    def wait_and_start_fuzzing(self):
        self.handshake_complete.wait()
        
        # Check if we need to wait for a specific message before fuzzing
        wait_for_message = self.state_config.get('wait_for_message')
        if wait_for_message:
            print(f"INFO (PEV): Waiting for {wait_for_message} message before starting fuzzing")
            # TODO: Implement message waiting logic based on state requirements
            # For now, we'll proceed directly to fuzzing
        
        self.send_fuzzing_messages()

    def send_fuzzing_messages(self):
        handler = PacketHandler()
        
        # Get the appropriate XML method based on state configuration
        xml_method = self.state_config.get('xml_method', 'SupportedAppProtocolRequest')
        xml_method_func = getattr(handler, xml_method, None)
        
        if xml_method_func is None:
            print(f"ERROR: XML method {xml_method} not found in PacketHandler")
            return
            
        xml_method_func()
        xml_string = ET.tostring(handler.root, encoding='unicode')

        self.load_state()
        self.fuzz_payload(xml_string)

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
                threading.Thread(target=self.recvThread.stop).start()

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
        self.seq += 1
        ack_number = self.ack + 1

        sendp(
            Ether(src=self.sourceMAC, dst=self.destinationMAC)
            / IPv6(src=self.sourceIP, dst=self.destinationIP)
            / TCP(sport=self.sourcePort, dport=self.destinationPort, flags="A", seq=self.seq, ack=ack_number),
            iface=self.iface,
            verbose=0,
        )
        self.ack = ack_number
        self.handshake_complete.set()

    def handlePacket(self, pkt):
        self.last_recv = pkt

        tcp_layer = pkt[TCP]
        payload_len = len(bytes(tcp_layer.payload))

        if payload_len > 0:
            self.ack = tcp_layer.seq + payload_len
        else:
            self.ack = tcp_layer.seq + 1

        if pkt[TCP].flags & 0x03F == 0x012:
            print("INFO (PEV) : Received SYNACK")
            self.ack = tcp_layer.seq + 1
            self.startSession()
        elif pkt[TCP].flags & 0x01:
            self.fin()

        self.response_received.set()

    def fuzz_payload(self, xml_string):
        elements_to_modify = self.elements_to_modify

        current_element_index = self.state.get('current_element_index', 0)
        iteration_count = self.state.get('iterations', {})
        crash_info = self.state.get('crash_info', [])
        crash_inputs = self.state.get('crash_inputs', [])
        total_attempts = self.state.get('total_attempts', 0)
        total_crashes = self.state.get('total_crashes', 0)

        print(f"INFO (PEV): Starting fuzzing for {self.target_state} - {self.state_config['name']}")

        for idx in range(current_element_index, len(elements_to_modify)):
            element_name = elements_to_modify[idx]
            root = ET.fromstring(xml_string)

            # Handle XPath-style element paths
            target_elements = []
            if '/' in element_name:
                # XPath-style element path
                path_parts = element_name.split('/')
                current_elements = [root]
                
                for part in path_parts:
                    next_elements = []
                    for elem in current_elements:
                        next_elements.extend(elem.findall(f".//{part}"))
                    current_elements = next_elements
                target_elements = current_elements
            else:
                # Simple element name
                target_elements = list(root.iter(element_name))

            if not target_elements:
                print(f"WARNING: Element {element_name} not found in XML")
                continue

            for elem in target_elements:
                if not elem.text:
                    elem.text = "1"

                mutated_value = elem.text
                start_iteration = iteration_count.get(element_name, 0)

                for iteration in range(start_iteration, self.iterations_per_element):
                    mutation_func = random.choice([self.value_flip, self.random_value, self.random_deletion, self.random_insertion])
                    mutated_value = mutation_func(mutated_value)

                    if not mutated_value:
                        print(f"Mutated value became empty, reverting to previous value: {elem.text}")
                        mutated_value = elem.text

                    elem.text = mutated_value
                    fuzzed_xml = ET.tostring(root, encoding='unicode')

                    print(f"\n{'=' * 50}")
                    print(f"[{self.target_state}] [{element_name}] Iteration {iteration+1}: Mutated using {mutation_func.__name__}")
                    print(f"Mutated value: {mutated_value}")
                    print(f"Fuzzed XML:\n{fuzzed_xml}")
                    print(f"{'=' * 50}\n")

                    self.state['total_attempts'] = total_attempts + 1
                    total_attempts += 1

                    self.response_received.clear()
                    self.rst_received = False

                    exi_payload = self.exi.encode(fuzzed_xml)
                    if exi_payload is not None:
                        exi_payload_bytes = binascii.unhexlify(exi_payload)
                        packet = self.buildV2G(exi_payload_bytes)
                        tcp_payload_length = len(bytes(packet[TCP].payload))
                        sendp(packet, iface=self.iface, verbose=0)
                        self.seq += tcp_payload_length

                    self.state['iterations'][element_name] = iteration + 1

                    response = self.response_received.wait(timeout=2)

                    if not response or self.rst_received:
                        print("No response received or RST received, recording crash.")
                        self.state['total_crashes'] = total_crashes + 1
                        total_crashes += 1

                        crash_detail = {
                            'state': self.target_state,
                            'element': element_name,
                            'iteration': iteration + 1,
                            'mutated_value': mutated_value,
                            'fuzzed_xml': fuzzed_xml,
                            'mutation_function': mutation_func.__name__
                        }
                        self.state['crash_inputs'].append(crash_detail)

                        self.save_state()
                        self.killThreads()
                        return

                self.state['iterations'][element_name] = 0
                self.state['current_element_index'] = idx + 1

        print(f"Fuzzing completed for all elements in {self.target_state} state.")
        if os.path.exists(self.state_file):
            os.remove(self.state_file)
        self.generate_report()

    def generate_report(self):
        report = {
            'target_state': self.target_state,
            'state_name': self.state_config['name'],
            'description': self.state_config['description'],
            'total_attempts': self.state.get('total_attempts', 0),
            'total_crashes': self.state.get('total_crashes', 0),
            'crash_details': self.state.get('crash_inputs', [])
        }

        report_file = os.path.join(self.reports_dir, f'fuzzing_report_{self.target_state}.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        # Fix file ownership
        if self.user_uid is not None and self.user_gid is not None:
            try:
                os.chown(report_file, self.user_uid, self.user_gid)
            except:
                pass

        print(f"\n{'=' * 50}")
        print(f"Fuzzing Summary Report for {self.target_state}")
        print(f"State: {report['state_name']}")
        print(f"Description: {report['description']}")
        print(f"Total Attempts: {report['total_attempts']}")
        print(f"Total Crashes: {report['total_crashes']}")
        print(f"Crash Details saved in {report_file}")
        print(f"{'=' * 50}\n")

    # Mutation functions
    def value_flip(self, value):
        if len(value) < 2:
            return value
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

        insert_idx = random.randrange(len(value)+1)
        random_char = random.choice(string.ascii_letters + string.digits)
        value_list = list(value)
        value_list.insert(insert_idx, random_char)
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

    def sendNeighborAdvertisement(self, pkt):
        self.destinationIP = pkt[IPv6].src
        sendp(self.buildNeighborAdvertisement(), iface=self.iface, verbose=0)

    def load_state(self):
        if os.path.exists(self.state_file):
            with open(self.state_file, 'r') as f:
                self.state = json.load(f)
            print(f"Loaded fuzzing state from {self.state_file}")
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

    def save_state(self):
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=4)
        
        # Fix file ownership
        if self.user_uid is not None and self.user_gid is not None:
            try:
                os.chown(self.state_file, self.user_uid, self.user_gid)
            except:
                pass
                
        print(f"Saved fuzzing state to {self.state_file}")


def list_states():
    """List all available fuzzing states"""
    print("Available fuzzing states:")
    print("=" * 60)
    for state_id, config in STATE_CONFIG.items():
        print(f"{state_id:10s} - {config['name']}")
        print(f"{'':12s} {config['description']}")
        print(f"{'':12s} Elements: {config['elements_to_modify']}")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unified V2G Protocol Fuzzer for EVC Testing", 
                                   formatter_class=argparse.RawDescriptionHelpFormatter,
                                   epilog="""
Examples:
  %(prog)s --state state1 --iterations-per-element 100
  %(prog)s --state state3 --interface eth1 --iterations-per-element 50
  %(prog)s --list-states
                                   """)
    
    parser.add_argument("--state", choices=list(STATE_CONFIG.keys()), 
                       help="Target V2G protocol state to fuzz")
    parser.add_argument("--list-states", action="store_true",
                       help="List all available fuzzing states and exit")
    parser.add_argument("-M", "--mode", nargs=1, type=int,
                       help="Mode for emulator to run in: 0 for full conversation, 1 for stalling the conversation, 2 for portscanning (default: 0)")
    parser.add_argument("-I", "--interface", nargs=1, 
                       help="Ethernet interface to send/receive packets on (default: eth1)")
    parser.add_argument("--source-mac", nargs=1, 
                       help="Source MAC address of packets (default: 00:1e:c0:f2:6c:a1)")
    parser.add_argument("--source-ip", nargs=1, 
                       help="Source IP address of packets (default: fe80::21e:c0ff:fef2:6ca1)")
    parser.add_argument("--source-port", nargs=1, type=int, 
                       help="Source port of packets (default: random port)")
    parser.add_argument("-p", "--protocol", nargs=1, 
                       help="Protocol for EXI encoding/decoding: DIN, ISO-2, ISO-20 (default: DIN)")
    parser.add_argument('--iterations-per-element', type=int, default=1000, 
                       help='Number of fuzzing iterations per element (default: 1000)')
    
    args = parser.parse_args()

    if args.list_states:
        list_states()
        sys.exit(0)

    if not args.state:
        print("ERROR: --state argument is required. Use --list-states to see available states.")
        parser.print_help()
        sys.exit(1)

    print(f"Starting Unified V2G Fuzzer for {args.state}")
    print(f"Target: {STATE_CONFIG[args.state]['name']}")
    print(f"Description: {STATE_CONFIG[args.state]['description']}")
    print(f"Iterations per element: {args.iterations_per_element}")
    print("=" * 60)

    pev = PEV(args)
    try:
        pev.start()
    except KeyboardInterrupt:
        print("INFO (PEV) : Shutting down emulator")
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        pev.setState(PEVState.A)
        del pev