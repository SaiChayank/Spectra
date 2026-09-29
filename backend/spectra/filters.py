"""Pure-Python packet filtering with a tcpdump/BPF-style syntax.

scapy's native `filter=` argument needs libpcap, which is missing on many
Windows boxes. This module implements the useful subset in Python so filtering
works everywhere:

    host 10.0.0.5                 # either direction
    src host 10.0.0.5             # source only
    dst net 198.51.100.0/24
    port 443 / dst port 443
    portrange 8000-8100
    tcp / udp / icmp
    not port 53                   # negation
    tcp and port 443              # explicit combinators (whitespace = and)
    host 10.0.0.5 or host 10.0.0.6
"""

from __future__ import annotations

import ipaddress
from typing import Callable

from scapy.packet import Packet


class FilterError(ValueError):
    """Raised for an invalid filter expression."""


Predicate = Callable[[Packet], bool]

_COMBINATORS = {"and", "or"}
_KEYWORDS = {"host", "net", "port", "portrange", "tcp", "udp", "icmp",
             "src", "dst", "not", "and", "or"}


# -- packet accessors --------------------------------------------------------


def _ip_layer(pkt: Packet) -> tuple[str, str, int] | None:
    """Return (src_ip, dst_ip, proto) for IPv4/IPv6, else None."""
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    if pkt.haslayer(IP):
        ip = pkt[IP]
        return str(ip.src), str(ip.dst), int(ip.proto)
    if pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        nh = int(ip6.nh)
        return str(ip6.src), str(ip6.dst), nh
    return None


def _ports(pkt: Packet) -> tuple[int | None, int | None]:
    from scapy.layers.inet import TCP, UDP

    if pkt.haslayer(TCP):
        return int(pkt[TCP].sport), int(pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return int(pkt[UDP].sport), int(pkt[UDP].dport)
    return None, None


# -- tokenizer / parser ------------------------------------------------------

class _Token:
    __slots__ = ("kind", "value")

    def __init__(self, kind: str, value: str):
        self.kind = kind
        self.value = value

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.kind}:{self.value}"


def _tokenize(expr: str) -> list[_Token]:
    tokens: list[_Token] = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c in "()/":
            raise FilterError(f"unsupported character {c!r} in filter")
        j = i
        while j < n and not expr[j].isspace():
            j += 1
        word = expr[i:j]
        i = j
        low = word.lower()
        if low in _COMBINATORS:
            tokens.append(_Token("op", low))
        elif low == "not":
            tokens.append(_Token("not", low))
        elif low in ("tcp", "udp", "icmp"):
            tokens.append(_Token("proto", low))
        elif low in ("host", "net", "port", "portrange", "src", "dst"):
            tokens.append(_Token("kw", low))
        else:
            tokens.append(_Token("value", word))
    return tokens


class _Parser:
    """Recursive-descent parser: or < and < not < atom."""

    def __init__(self, tokens: list[_Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> _Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def next(self) -> _Token:
        tok = self.peek()
        if tok is None:
            raise FilterError("unexpected end of filter expression")
        self.pos += 1
        return tok

    def parse(self) -> Predicate:
        pred = self.parse_or()
        if self.peek() is not None:
            raise FilterError(f"unexpected token {self.peek().value!r}")
        return pred

    def parse_or(self) -> Predicate:
        left = self.parse_and()
        while self.peek() and self.peek().kind == "op" and self.peek().value == "or":
            self.next()
            right = self.parse_and()
            left = _or(left, right)
        return left

    def parse_and(self) -> Predicate:
        left = self.parse_not()
        while True:
            tok = self.peek()
            if tok is None:
                break
            if tok.kind == "op" and tok.value == "and":
                self.next()
                right = self.parse_not()
                left = _and(left, right)
            elif tok.kind in ("kw", "proto", "not"):
                # implicit AND between adjacent predicates
                right = self.parse_not()
                left = _and(left, right)
            else:
                break
        return left

    def parse_not(self) -> Predicate:
        if self.peek() and self.peek().kind == "not":
            self.next()
            return _not(self.parse_not())
        return self.parse_atom()

    def parse_atom(self) -> Predicate:
        tok = self.next()
        if tok.kind == "proto":
            return _proto_pred(tok.value)
        if tok.kind != "kw":
            raise FilterError(f"unexpected token {tok.value!r} in filter")
        kw = tok.value

        if kw in ("src", "dst"):
            direction = kw
            nxt = self.next()
            if nxt.kind == "proto":
                return _proto_pred(nxt.value, direction)  # e.g. `src tcp` (rare, accepted)
            if nxt.kind != "kw" or nxt.value not in ("host", "net", "port"):
                raise FilterError(f"expected host/net/port after '{kw}'")
            return self._address_pred(nxt.value, direction)
        return self._address_pred(kw, None)

    def _address_pred(self, kind: str, direction: str | None) -> Predicate:
        if kind == "tcp" or kind == "udp" or kind == "icmp":
            return _proto_pred(kind, direction)
        if kind == "host":
            addr = self.next().value
            _validate_ip(addr)
            return _host_pred(addr, direction)
        if kind == "net":
            net = self.next().value
            _validate_net(net)
            return _net_pred(net, direction)
        if kind == "port":
            raw = self.next().value
            port = _validate_port(raw)
            return _port_pred(port, port, direction)
        if kind == "portrange":
            raw = self.next().value
            if "-" not in raw:
                raise FilterError(f"portrange needs 'a-b', got {raw!r}")
            lo_s, hi_s = raw.split("-", 1)
            lo, hi = _validate_port(lo_s), _validate_port(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            return _port_pred(lo, hi, direction)
        raise FilterError(f"unsupported filter keyword {kind!r}")


def _validate_ip(addr: str) -> None:
    try:
        ipaddress.ip_address(addr)
    except ValueError as exc:
        raise FilterError(f"invalid IP address {addr!r}") from exc


def _validate_net(net: str) -> None:
    try:
        ipaddress.ip_network(net, strict=False)
    except ValueError as exc:
        raise FilterError(f"invalid network {net!r}") from exc


def _validate_port(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise FilterError(f"invalid port {raw!r}") from exc
    if not 0 <= port <= 65535:
        raise FilterError(f"port out of range: {port}")
    return port


# -- predicates --------------------------------------------------------------


def _and(a: Predicate, b: Predicate) -> Predicate:
    return lambda pkt: a(pkt) and b(pkt)


def _or(a: Predicate, b: Predicate) -> Predicate:
    return lambda pkt: a(pkt) or b(pkt)


def _not(a: Predicate) -> Predicate:
    return lambda pkt: not a(pkt)


def _proto_pred(proto: str, direction: str | None = None) -> Predicate:
    """`tcp` / `udp` / `icmp` matches; `direction` is accepted but not used
    (protocol direction is meaningless), so `src tcp` behaves like `tcp`."""
    if proto == "icmp":
        def icmp_pred(pkt: Packet) -> bool:
            from scapy.layers.inet import ICMP

            if pkt.haslayer(ICMP):
                return True
            info = _ip_layer(pkt)
            return info is not None and info[2] == 58  # ICMPv6

        return icmp_pred

    code = {"tcp": 6, "udp": 17}[proto]

    def pred(pkt: Packet) -> bool:
        info = _ip_layer(pkt)
        return info is not None and info[2] == code

    return pred


def _host_pred(addr: str, direction: str | None) -> Predicate:
    target = str(ipaddress.ip_address(addr))

    def pred(pkt: Packet) -> bool:
        info = _ip_layer(pkt)
        if info is None:
            return False
        src, dst, _ = info
        if direction == "src":
            return src == target
        if direction == "dst":
            return dst == target
        return src == target or dst == target

    return pred


def _net_pred(net: str, direction: str | None) -> Predicate:
    network = ipaddress.ip_network(net, strict=False)

    def pred(pkt: Packet) -> bool:
        info = _ip_layer(pkt)
        if info is None:
            return False
        src, dst, _ = info
        try:
            s_ok = ipaddress.ip_address(src) in network
            d_ok = ipaddress.ip_address(dst) in network
        except ValueError:
            return False
        if direction == "src":
            return s_ok
        if direction == "dst":
            return d_ok
        return s_ok or d_ok

    return pred


def _port_pred(lo: int, hi: int, direction: str | None) -> Predicate:
    def pred(pkt: Packet) -> bool:
        sport, dport = _ports(pkt)
        if sport is None and dport is None:
            return False

        def in_range(p: int | None) -> bool:
            return p is not None and lo <= p <= hi

        if direction == "src":
            return in_range(sport)
        if direction == "dst":
            return in_range(dport)
        return in_range(sport) or in_range(dport)

    return pred


def compile_filter(expr: str) -> Predicate:
    """Compile a filter expression into a packet predicate."""
    expr = (expr or "").strip()
    if not expr:
        return lambda pkt: True
    tokens = _tokenize(expr)
    if not tokens:
        return lambda pkt: True
    # `src 10.0.0.1` / `dst 192.168.0.0/24` shorthands
    tokens = _normalize(tokens)
    return _Parser(tokens).parse()


def _normalize(tokens: list[_Token]) -> list[_Token]:
    """Allow `src <ip>` shorthand by inserting the `host` keyword."""
    out: list[_Token] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.kind == "kw" and tok.value in ("src", "dst") and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            out.append(tok)
            if nxt.kind == "value":
                looks_like_net = "/" in nxt.value
                out.append(_Token("kw", "net" if looks_like_net else "host"))
                out.append(nxt)
                i += 2
                continue
            i += 1
            continue
        out.append(tok)
        i += 1
    return out


def packet_filter(expr: str) -> Callable[[Packet], bool]:
    """Alias for compile_filter (public API used by capture sources)."""
    return compile_filter(expr)
