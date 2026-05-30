#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║         CodeAlpha — Basic Network Sniffer                ║
║         Task 1 | Cyber Security Internship               ║
╚══════════════════════════════════════════════════════════╝
"""

import argparse
import datetime
import sys
import os
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
        ARP, Ether, Raw, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("[!] Scapy not found. Run: sudo apt install python3-scapy")
    sys.exit(1)

try:
    from colorama import Fore, Back, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Back = Style = _NoColor()

def c(text, color):
    return f"{color}{text}{Style.RESET_ALL}" if COLORS else text

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║   {Fore.GREEN}🔍  CodeAlpha Network Sniffer  {Fore.CYAN}                      ║
║   {Fore.YELLOW}Cyber Security Internship — Task 1          {Fore.CYAN}          ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

stats = defaultdict(int)
packet_count = 0
log_file = None

PROTO_COLORS = {
    "TCP":   Fore.GREEN,
    "UDP":   Fore.CYAN,
    "ICMP":  Fore.YELLOW,
    "DNS":   Fore.MAGENTA,
    "HTTP":  Fore.BLUE,
    "ARP":   Fore.WHITE,
    "OTHER": Fore.RED,
}

def proto_color(proto):
    return PROTO_COLORS.get(proto, Fore.WHITE)

def dissect_packet(pkt):
    info = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "proto":     "OTHER",
        "src_mac":   None,
        "dst_mac":   None,
        "src_ip":    None,
        "dst_ip":    None,
        "src_port":  None,
        "dst_port":  None,
        "flags":     None,
        "length":    len(pkt),
        "extra":     "",
        "payload":   None,
    }

    if pkt.haslayer(Ether):
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(ARP):
        info["proto"] = "ARP"
        arp = pkt[ARP]
        op = "REQUEST" if arp.op == 1 else "REPLY"
        info["src_ip"] = arp.psrc
        info["dst_ip"] = arp.pdst
        info["extra"]  = f"op={op} | hw_src={arp.hwsrc} → hw_dst={arp.hwdst}"
        return info

    if pkt.haslayer(IP):
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        info["src_ip"] = pkt[IPv6].src
        info["dst_ip"] = pkt[IPv6].dst

    if pkt.haslayer(TCP):
        info["proto"]    = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        flags = pkt[TCP].flags
        flag_str = ""
        flag_map = {0x01:"FIN", 0x02:"SYN", 0x04:"RST",
                    0x08:"PSH", 0x10:"ACK", 0x20:"URG"}
        for bit, name in flag_map.items():
            if flags & bit:
                flag_str += name + " "
        info["flags"] = flag_str.strip()

        if pkt.haslayer(HTTPRequest):
            info["proto"] = "HTTP"
            req = pkt[HTTPRequest]
            method = req.Method.decode(errors="ignore") if req.Method else "?"
            host   = req.Host.decode(errors="ignore")   if req.Host   else "?"
            path   = req.Path.decode(errors="ignore")   if req.Path   else "/"
            info["extra"] = f"{method} http://{host}{path}"
        elif pkt.haslayer(HTTPResponse):
            info["proto"] = "HTTP"
            resp = pkt[HTTPResponse]
            code = resp.Status_Code.decode(errors="ignore") if resp.Status_Code else "?"
            info["extra"] = f"HTTP Response {code}"

    elif pkt.haslayer(UDP):
        info["proto"]    = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport

        if pkt.haslayer(DNS):
            info["proto"] = "DNS"
            dns = pkt[DNS]
            if dns.qr == 0 and dns.haslayer(DNSQR):
                qname = dns[DNSQR].qname.decode(errors="ignore").rstrip(".")
                info["extra"] = f"Query → {qname}"
            elif dns.qr == 1 and dns.haslayer(DNSRR):
                rname = dns[DNSRR].rrname.decode(errors="ignore").rstrip(".")
                rdata = dns[DNSRR].rdata
                info["extra"] = f"Response ← {rname} = {rdata}"

    elif pkt.haslayer(ICMP):
        info["proto"] = "ICMP"
        icmp = pkt[ICMP]
        type_map = {0: "Echo Reply", 3: "Dest Unreachable",
                    8: "Echo Request", 11: "Time Exceeded"}
        info["extra"] = type_map.get(icmp.type, f"type={icmp.type} code={icmp.code}")

    if pkt.haslayer(Raw):
        raw = pkt[Raw].load
        try:
            decoded = raw.decode("utf-8", errors="replace")
        except Exception:
            decoded = repr(raw)
        info["payload"] = decoded[:80].replace("\n", "\\n").replace("\r", "")

    return info

SEPARATOR = c("─" * 68, Fore.WHITE + Style.DIM)

def display_packet(info, num):
    col = proto_color(info["proto"])
    header = (
        f"{c(f'[{num:>4}]', Fore.WHITE + Style.DIM)} "
        f"{c(info['timestamp'], Fore.WHITE)} "
        f"{c('[' + info['proto'].center(5) + ']', col + Style.BRIGHT)} "
        f"{c(str(info['length']) + 'B', Fore.WHITE + Style.DIM)}"
    )
    src = f"{info['src_ip'] or '?'}"
    dst = f"{info['dst_ip'] or '?'}"
    if info["src_port"]:
        src += f":{info['src_port']}"
        dst += f":{info['dst_port']}"
    flow = (
        f"  {c('SRC', Fore.YELLOW)} {c(src, Fore.WHITE)}  "
        f"{c('→', Fore.WHITE + Style.DIM)}  "
        f"{c('DST', Fore.YELLOW)} {c(dst, Fore.WHITE)}"
    )
    lines = [header, flow]
    if info["src_mac"]:
        lines.append(f"  {c('MAC', Fore.CYAN)} {info['src_mac']} → {info['dst_mac']}")
    if info["flags"]:
        lines.append(f"  {c('FLAGS', Fore.MAGENTA)} {info['flags']}")
    if info["extra"]:
        lines.append(f"  {c('INFO ', col)} {info['extra']}")
    if info["payload"]:
        lines.append(
            f"  {c('DATA ', Fore.RED + Style.DIM)} "
            f"{c(info['payload'], Fore.WHITE + Style.DIM)}"
        )
    output = "\n".join(lines)
    print(output)
    print(SEPARATOR)
    if log_file:
        import re
        ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
        log_file.write(ansi_escape.sub("", output) + "\n" + ("─" * 68) + "\n")

def print_stats():
    print(f"\n{c('═' * 68, Fore.CYAN)}")
    print(c("  📊  CAPTURE SUMMARY", Fore.CYAN + Style.BRIGHT))
    print(c('═' * 68, Fore.CYAN))
    print(f"  {'Total Packets':<20} {packet_count}")
    print()
    for proto, count in sorted(stats.items(), key=lambda x: -x[1]):
        bar = "█" * min(count, 40)
        print(f"  {c(proto, proto_color(proto)):<25} {count:>5}  {c(bar, proto_color(proto))}")
    print(c('═' * 68, Fore.CYAN))

def packet_callback(pkt):
    global packet_count
    packet_count += 1
    info = dissect_packet(pkt)
    stats[info["proto"]] += 1
    display_packet(info, packet_count)

def main():
    global log_file
    parser = argparse.ArgumentParser(description="CodeAlpha — Network Sniffer (Task 1)")
    parser.add_argument("-i", "--iface",  default=None)
    parser.add_argument("-c", "--count",  type=int, default=0)
    parser.add_argument("-f", "--filter", default=None)
    parser.add_argument("--log", default=None)
    args = parser.parse_args()

    if os.name != "nt" and os.geteuid() != 0:
        print(c("[!] Run as root/sudo.", Fore.RED))
        sys.exit(1)

    print(BANNER)
    if args.log:
        log_file = open(args.log, "w", encoding="utf-8")
        print(c(f"[+] Logging to: {args.log}", Fore.GREEN))

    print(f"  {c('Interface', Fore.YELLOW)} : {args.iface or 'all'}")
    print(f"  {c('Count    ', Fore.YELLOW)} : {args.count or 'unlimited'}")
    print(f"  {c('Filter   ', Fore.YELLOW)} : {args.filter or 'none'}")
    print(f"\n{c('[*] Starting capture... Press Ctrl+C to stop.', Fore.GREEN)}\n")
    print(SEPARATOR)

    try:
        sniff(iface=args.iface, count=args.count, filter=args.filter,
              prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print(c("\n[!] Capture stopped by user.", Fore.YELLOW))
    except PermissionError:
        print(c("[!] Permission denied. Try sudo.", Fore.RED))
        sys.exit(1)
    finally:
        print_stats()
        if log_file:
            log_file.close()

if __name__ == "__main__":
    main()

