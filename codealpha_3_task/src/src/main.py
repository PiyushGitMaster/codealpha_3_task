import sys
import argparse
from typing import NoReturn
from analysis.capturer import PacketCapturer
from analysis.parser import PacketParser

def main() -> NoReturn:
    """
    Main entry point for the network intrusion detection system script.
    Optimized for orchestrating packet capture and analysis.
    """
    parser = argparse.ArgumentParser(description="Basic Network Intrusion Detection System")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on (e.g., eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for continuous)")
    
    args = parser.parse_args()
    interface = args.interface
    packet_count = args.count

    print(f"Starting packet capture on interface: {interface if interface else 'default'}")
    print("Press Ctrl+C to stop.")

    packet_parser = PacketParser()
    capturer = PacketCapturer(interface=interface)

    def process_packet(raw_packet) -> None:
        """Callback function to process each captured packet."""
        parsed_data = packet_parser.parse(raw_packet)
        if parsed_data:
            print(parsed_data)

    try:
        capturer.start_capture(callback=process_packet, count=packet_count)
    except KeyboardInterrupt:
        print("\nStopping capture...")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred during capture: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()