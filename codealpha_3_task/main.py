import sys
import signal
from typing import NoReturn
from core.sniffer import PacketSniffer
from core.analyzer import PacketAnalyzer

class IntrusionDetectionSystem:
    """Orchestrates packet sniffing and analysis to detect intrusions."""

    def __init__(self, interface: str = None) -> None:
        """
        Initializes the IDS.

        Args:
            interface: The network interface to capture packets from.
        """
        self.sniffer = PacketSniffer(interface=interface)
        self.analyzer = PacketAnalyzer()

    def process_packet(self, packet_data: bytes) -> None:
        """
        Callback function to analyze captured packet data.

        Args:
            packet_data: Raw byte content of the captured packet.
        """
        # Focus analysis on payload, skipping standard header length roughly
        # This is basic; complex parsers would extract payload correctly per layer.
        payload = packet_data[14:]  # Assume Ethernet header size for simplicity
        self.analyzer.analyze_payload(payload)

    def start(self) -> None:
        """Starts the IDS."""
        print("Starting Basic NIDS...")
        self.sniffer.start(self.process_packet)

    def stop(self) -> None:
        """Stops the IDS."""
        print("Stopping Basic NIDS...")
        self.sniffer.stop()

def signal_handler(sig: int, frame: object) -> NoReturn:
    """Handles SIGINT/Ctrl+C for graceful shutdown."""
    print("\nInterrupt received.")
    ids.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Interface selection, default to None (all interfaces on Linux)
    # Require root privileges typically to bind raw socket.
    INTERFACE = None

    if len(sys.argv) > 1:
        INTERFACE = sys.argv[1]

    ids = IntrusionDetectionSystem(interface=INTERFACE)
    
    # Register signal handler for graceful interruption
    signal.signal(signal.SIGINT, signal_handler)

    ids.start()