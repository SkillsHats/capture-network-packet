#!/usr/bin/env python3

import json
import socket
from datetime import datetime
from typing import Any, Dict, NamedTuple, Optional, Tuple

import requests
from scapy.all import (
    ARP,
    ByteField,
    Ether,
    DNS,
    DNSQR,
    DNSRR,
    Dot1Q,
    STP,
    Dot3,
    IP,
    IPv6,
    ICMP,
    TCP,
    UDP,
    Raw,
    Packet,
)
from scapy.utils import hexdump


FLAGS = {
    'F': 'FIN',
    'S': 'SYN',
    'R': 'RST',
    'P': 'PSH',
    'A': 'ACK',
    'U': 'URG',
    'E': 'ECE',
    'C': 'CWR',
	'DF': 'DNT FRAG',
	'RA': 'RST, ACK',
	'FA': 'FIN, ACK',
	'PA': 'PSH, ACK',
	'NS': 'ECN-nonce',
	'SEC': 'SYN, ECE, CWR',
}



class ParsedPacket(NamedTuple):
    """ Temporary representation of a parsed packet ready to be sent
        to Meteorshark
    """

    timestamp: int
    size: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    app_protocol: Optional[
        str
    ] = None  # The highest level protocol included in the packet
    transport_protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_service: Optional[str] = None
    dst_service: Optional[str] = None
    flags: Optional[str] = None
    dns_record: Optional[Dict[str, Any]] = None
    payload: Optional[str] = None

    def to_api(self) -> Dict[str, Any]:
        """ Prepare packet for JSON formatting """
        return {
            "timestamp": self.timestamp,
            "srcIP": self.src_ip,
            "dstIP": self.dst_ip,
            "size": self.size,
            "ttl": self.ttl,
            "srcMAC": self.src_mac,
            "dstMAC": self.dst_mac,
            "L7protocol": self.app_protocol,
            "L4protocol": self.transport_protocol,
            "srcPort": self.src_port,
            "dstPort": self.dst_port,
            "src_service": self.src_service,
            "dst_service": self.dst_service,
            "dns_record": self.dns_record,
            "flags": self.flags,
            "payload": self.payload,
        }


def clean_payload(pkt: Packet) -> str:
    """ Clean up packet payload from Scapy output

    """
    return pkt.layers()[-1].summary()


def get_ips(pkt: Packet) -> Tuple[Optional[str], Optional[str]]:
    if pkt.haslayer(ARP):
        return (pkt[ARP].psrc, pkt[ARP].pdst)

    if pkt.haslayer(IP):
        return (pkt[IP].src, pkt[IP].dst)
    if pkt.haslayer(IPv6):
        return (pkt[IPv6].src, pkt[IPv6].dst)

    return (None, None)


def get_macs(pkt: Packet) -> Tuple[Optional[str], Optional[str]]:
    if pkt.haslayer(Ether):
        return (pkt[Ether].src, pkt[Ether].dst)
    return (None, None)


def get_ports(pkt: Packet) -> Tuple[Optional[str], Optional[str]]:
    if pkt.haslayer(TCP):
        return (pkt[TCP].sport, pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return (pkt[UDP].sport, pkt[UDP].dport)
    return (None, None)


def get_transport_protocol(pkt: Packet) -> Optional[str]:
    pass


def get_app_protocol(pkt: Packet) -> Optional[str]:
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    else:
        for layer in reversed(pkt.layers()):
            name = layer.__name__
            if name != "Raw":
                return name
    return pkt.lastlayer().__name__


def get_payload(pkt: Packet) -> Optional[str]:
    """ Get the payload of the packet as a string """
    return f"{pkt.payload!r}"


def get_size(pkt: Packet) -> int:
    """ Get Packet size in bytes
    """
    return len(pkt)


def get_ttl(pkt: Packet) -> Optional[int]:
    if IP in pkt:
        return pkt.ttl

    if IPv6 in pkt:
        return pkt.hlim

    for layer in reversed(pkt.layers()):
        ttl = getattr(pkt[layer.__name__], "ttl", None)
        if ttl:
            return ttl


def get_service(port: int) -> None:
    """ Get Service used by client to transmit data using port. 
    """
    try:
        return socket.getservbyport(port)
    except:
        return None


def get_flags(pkt: Packet) -> str:
    """ Get Generated Packets Flag as string
    """
    if pkt.haslayer(TCP):
        return FLAGS.get(pkt.sprintf('%TCP.flags%'))
    else:
        return FLAGS.get(pkt.sprintf('%IP.flags%'))


def get_dnsrr_record(pkt: Packet) -> Dict:
    """ Get DNSRR Record
    """
    record = {
        "rrname": pkt[DNSRR].rrname.decode("utf-8"),
        "type": pkt[DNSRR].type,
        "rclass": pkt[DNSRR].rclass,
        "ttl": pkt[DNSRR].ttl,
        "rdlen": pkt[DNSRR].rdlen,
        "rdata": pkt[DNSRR].rdata
    }
    return record


def get_dnsqr_record(pkt: Packet) -> Dict:
    """ Get DNSQR Record
    """
    record =  {
        "qname": pkt[DNSQR].qname.decode("utf-8"),
        "qtype": pkt[DNSQR].qtype,
        "qclass": pkt[DNSQR].qclass
    }
    return record


def get_dns_record(pkt: Packet) -> Dict:
    """ Get DNS Record
    """
    record = {
        "qr": pkt[DNS].qr,
        "opcode": pkt[DNS].opcode,
        "rcode": pkt[DNS].rcode,
        "qdcount": pkt[DNS].qdcount,
        "ancount": pkt[DNS].ancount,
        "nscount": pkt[DNS].nscount,
        "arcount": pkt[DNS].arcount,
    }
    return record


def get_dns_layer(pkt: Packet) -> Dict:
    """ Get DNS Layer packet
    """
    record = dict()

    if pkt.haslayer(DNS):
        dns_record = get_dns_record(pkt)
        record["dns"] = dns_record

        if pkt.haslayer(DNSQR):
            dnsqr_record = get_dnsqr_record(pkt)
            record["dns"]["dnsqr"] = dnsqr_record

        if pkt.haslayer(DNSRR):
            dnsrr_record = get_dnsrr_record(pkt)
            record["dns"]["dnsrr"] = dnsrr_record
    return record


def parse_raw(raw: str) -> str:
    """ Parse Raw payload Data
    """
    return hexdump(raw)


def parse_packet(pkt: Packet) -> ParsedPacket:
    """ Parse packet and convert data into the Dict.
    """

    src_ip, dst_ip = get_ips(pkt)
    src_mac, dst_mac = get_macs(pkt)
    src_port, dst_port = get_ports(pkt)

    return ParsedPacket(
        timestamp=int(datetime.now().timestamp()),
        src_ip=src_ip,
        dst_ip=dst_ip,
        app_protocol=get_app_protocol(pkt),
        size=get_size(pkt),
        ttl=get_ttl(pkt),
        src_mac=src_mac,
        dst_mac=dst_mac,
        transport_protocol=get_transport_protocol(pkt),
        src_port=src_port,
        dst_port=dst_port,
        src_service=get_service(src_port),
        dst_service=get_service(dst_port),
        flags=get_flags(pkt),
        dns_record=get_dns_layer(pkt),
        payload=get_payload(pkt),
    )


def upload_packet(url: str, packet: ParsedPacket):
    """ Get the Packet JSON and upload in a POST request to Meteorshark """
    headers = {"content-type": "application/json"}
    packet_data = packet.to_api()
    headers = {"content-type": "application/json"}
    requests.post(url, data=json.dumps(packet_data), headers=headers)

