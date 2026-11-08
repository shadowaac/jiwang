from typing import Iterator, Tuple, TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scapy.packet import Packet  # type: ignore
else:
    Packet = Any  # runtime fallback to avoid early scapy import


def format_hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
        lines.append(f"{i:08X}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


def packet_layers_iter(pkt: "Packet") -> Iterator["Packet"]:
    layer = pkt
    while layer:
        yield layer
        layer = layer.payload
        if layer is pkt or layer is None:
            break


def _inet_layers():
    from scapy.layers.inet import IP, TCP, UDP, ICMP  # lazy import
    return IP, TCP, UDP, ICMP


def _http_layers():
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse  # lazy import
        return HTTPRequest, HTTPResponse
    except Exception:
        return None, None


def guess_protocol(pkt: "Packet") -> str:
    try:
        IP, TCP, UDP, ICMP = _inet_layers()
        if ICMP in pkt:
            return "ICMP"
        if TCP in pkt:
            # HTTP detection heuristic
            HTTPRequest, HTTPResponse = _http_layers()
            if (HTTPRequest and pkt.haslayer(HTTPRequest)) or (HTTPResponse and pkt.haslayer(HTTPResponse)):
                return "HTTP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            if sport in (80, 8080, 8000) or dport in (80, 8080, 8000):
                return "HTTP"
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if IP in pkt:
            return "IP"
        return pkt.__class__.__name__
    except Exception:
        return "UNKNOWN"


def pkt_endpoints(pkt: "Packet") -> Tuple[str, str]:
    try:
        IP, TCP, UDP, _ICMP = _inet_layers()
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
        else:
            src = getattr(pkt, "src", "?")
            dst = getattr(pkt, "dst", "?")
        if TCP in pkt:
            src = f"{src}:{pkt[TCP].sport}"
            dst = f"{dst}:{pkt[TCP].dport}"
        elif UDP in pkt:
            src = f"{src}:{pkt[UDP].sport}"
            dst = f"{dst}:{pkt[UDP].dport}"
        return src, dst
    except Exception:
        return "?", "?"
