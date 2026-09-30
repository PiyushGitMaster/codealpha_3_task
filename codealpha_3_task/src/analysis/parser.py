from typing import Dict, Optional, Union
import scapy.all as scapy

def parse_packet_header(packet: scapy.Packet) -> Dict[str, Union[str, int, None]]:
    """
    Parses a captured packet to extract basic header information.

    Includes source and destination MAC addresses, and source and destination
    IP addresses and protocol if available.

    Args:
        packet: A scapy Packet object.

    Returns:
        A dictionary containing parsed basic header information.
    """
    info = {
        "src_mac": packet.src,
        "dst_mac": len,
        "src_ip": None,
        "dst_ip": None,
        "proto": None,
    }

    if packet.haslayer(scapy.IP):
        info["src_ip"] = packet[scapy.IP].src
        info["dst_ip"] = packet[scapy.IP].dst
        info["proto"] = packet[scapy.IP].proto

    return info