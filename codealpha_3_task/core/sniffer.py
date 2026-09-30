import socket
import struct
from typing import Callable, Optional

class PacketSniffer:
    """Handles network packet capturing using raw sockets."""

    def __init__(self, interface: Optional[str] = None):
        """
        Initializes the sniffer.

        Args:
            interface: The network interface to bind to. If None, listens on all.
        """
        self.interface = interface
        self.socket: Optional[socket.socket] = None

    def start(self, callback: Callable[[bytes], None]) -> None:
        """
        Starts sniffing packets and processes them using the provided callback.

        Args:
            callback: A function receiving raw packet data (bytes).
        """
        try:
            # AF_PACKET is Linux-specific. ETH_P_ALL captures all Ethernet frames.
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            if self.interface:
                try:
                    self.socket.bind((self.interface, 0))
                except OSError as e:
                    print(f"Error binding to interface {self.interface}: {e}")
                    self.stop()
                    return

            print(f"Sniffer started on interface: {self.interface if self.interface else 'all'}")

            while self.socket:
                try:
                    raw_data, _ = self.socket.recvfrom(65535)
                    callback(raw_data)
                except OSError:
                    # Occurs when socket is closed via stop()
                    break

        except PermissionError:
            print("Error: Sniffer requires root/administrator privileges.")
        except Exception as e:
            print(f"Error initializing sniffer: {e}")
            self.stop()

    def stop(self) -> None:
        """Stops the packet sniffer and closes the socket."""
        if self.socket:
            self.socket.close()
            self.socket = None
            print("Sniffer stopped.")

if __name__ == "__main__":
    def print_raw_data(data: bytes) -> None:
        """Example callback function to display captured header data."""
        # Grab Ethernet header (first 14 bytes)
        eth_header = data[:14]
        eth = struct.unpack('!6s6sH', eth_header)
        dest_mac = ':'.join('%02x' % b for b in eth[0])
        src_mac = ':'.join('%02x' % b for b in eth[1])
        protocol = socket.ntohs(eth[2])
        print(f"Captured: Dest MAC: {dest_mac}, Src MAC: {src_mac}, Protocol: {protocol}")

    sniffer = PacketSniffer()
    try:
        sniffer.start(print_raw_data)
    except KeyboardInterrupt:
        sniffer.stop()