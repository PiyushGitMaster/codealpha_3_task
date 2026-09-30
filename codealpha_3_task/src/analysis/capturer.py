from scapy.all import sniff
from typing import Callable, Optional

class PacketCapturer:
    """
    Manages network packet sniffing using the Scapy library.
    """

    def __init__(self, interface: Optional[str] = None):
        """
        Initializes the PacketCapturer.

        :param interface: The network interface to sniff on.
                          Defaults to None, which scapy resolves to the default interface.
        """
        self.interface = interface

    def start_capture(self, callback: Callable) -> None:
        """
        Starts sniffing packets and applies the callback function to each.

        :param callback: Function to process each captured packet.
        """
        try:
            # count=0 means continuous sniffing
            sniff(iface=self.interface, prn=callback, store=0)
        except PermissionError:
            print("Error: Permission denied. Packet sniffing requires root/administrator privileges.")
        except Exception as e:
            print(f"An unexpected error occurred during capture: {e}")