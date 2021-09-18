#! /usr/bin/env python3
import argparse
import logging
import json
from collections import deque
from functools import partial
from time import sleep, time
from threading import Thread
from scapy.all import (
    sniff, 
    Packet, 
    load_layer
)
from shark import (
    ParsedPacket, 
    parse_packet, 
    upload_packet
)


log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)


## define POST parameters
url = "http://localhost:8000/api/packets"


packets = deque()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--count",
        type=int,
        help="The number of packets to sniff (integer). 0 (default) is indefinite count.",
        default=0,
    )
    parser.add_argument("--filter", help="The BPF style filter to sniff with.")
    parser.add_argument("--debug", help="View debug level logs", action="store_true")
    return parser.parse_args()


def add_packet_to_queue(pkt: Packet):
    """ Operates on each sniffed packet
        Adds packet to the Queue for background processing
    """
    packets.append(pkt)


def poll_packet_queue():
    """ Background task to poll the Packets queue and upload to Shark Backend """
    while True:
        queue_size = len(packets)
        if queue_size > 0 and queue_size % 20 == 0:
            log.debug(f"Current queue size: {queue_size}")

        if queue_size == 0:
            # No packets, let's wait for some
            sleep(0.3)
            continue
        
        raw_packet = packets.popleft()
        try:
            parsed_packet = parse_packet(raw_packet)
            # log.info(f"Parsed Packets: {json.dumps(parsed_packet.to_api(), indent=2)}")
        except:
            log.exception(f"Failed to parse: {raw_packet.summary()}")
            continue

        try:
            upload_packet(url, parsed_packet)
        except Exception as exc:
            log.exception(f"Failed to upload: {exc}")
        
        
if __name__ == "__main__":
    args = get_args()
    if args.debug:
        log.setLevel(logging.DEBUG)

    thread = Thread(target=partial(poll_packet_queue))
    thread.setDaemon(True)
    thread.start()
    log.info(f"Started queue polling")

    log.info(f"Sniffing {args.count} packets... Ctrl + C to stop sniffing")

    # Load TLS/SSL Layer
    load_layer("tls")

    # Start sniffing some packets
    sniff(filter=args.filter or "", prn=add_packet_to_queue, count=args.count, store=0)
    # sniff(filter=args.filter or "", prn=add_packet_to_queue, store=0)

