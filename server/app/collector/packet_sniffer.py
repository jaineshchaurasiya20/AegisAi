"""
AegisAI Packet Sniffer — scapy-based network packet capture.
Captures raw network packets and converts them to CICIDS2017-compatible flow features.
NOTE: Requires Administrator/root privileges for raw socket access.
"""
import asyncio
from typing import Dict, Any, Callable, Optional
from loguru import logger


class PacketSniffer:
    """
    Async-compatible packet sniffer wrapping scapy's sniff() function.
    Runs in a background thread to avoid blocking the FastAPI event loop.
    """

    def __init__(self, interface: str = "eth0", callback: Optional[Callable] = None):
        self.interface = interface
        self.callback = callback
        self._running = False
        self._packet_count = 0

    async def start(self):
        """Start packet capture in a background executor thread."""
        self._running = True
        loop = asyncio.get_event_loop()
        logger.info(f"PacketSniffer starting on interface: {self.interface}")
        logger.warning(
            "PacketSniffer requires Administrator/root privileges. "
            "Ensure the process is run with elevated permissions."
        )
        try:
            await loop.run_in_executor(None, self._sniff_blocking)
        except PermissionError:
            logger.error(
                "Insufficient privileges for packet capture. "
                "Run the server with Administrator/sudo privileges."
            )
        except Exception as e:
            logger.error(f"Packet sniffer error: {e}")

    def _sniff_blocking(self):
        """Blocking scapy sniff — runs in thread pool."""
        try:
            from scapy.all import sniff, IP, TCP, UDP
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except ImportError:
            logger.warning("scapy not installed. Packet sniffer disabled.")
        except Exception as e:
            logger.error(f"scapy sniff error: {e}")

    def _process_packet(self, packet):
        """Process individual packet and extract basic flow features."""
        self._packet_count += 1
        try:
            from scapy.all import IP, TCP, UDP
            if IP in packet:
                features: Dict[str, Any] = {
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "protocol": packet[IP].proto,
                    "packet_len": len(packet),
                    "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0),
                    "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0),
                }
                if self.callback:
                    self.callback(features)
        except Exception:
            pass

    def stop(self):
        self._running = False
        logger.info(f"PacketSniffer stopped. Total packets captured: {self._packet_count}")
