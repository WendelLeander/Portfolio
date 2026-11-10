from scapy.all import sniff, Ether, IP, IPv6
from scapy.arch.windows import get_windows_if_list
import argparse
import time
import csv
from ipaddress import ip_address, IPv4Address, IPv6Address

def is_broadcast(dst_mac):
    """Check if an Ethernet MAC is broadcast"""
    return dst_mac.lower() == "ff:ff:ff:ff:ff:ff"

def is_multicast(dst):
    """
    Detect multicast frames or packets.
    dst can be:
    - Ethernet MAC address: "01:00:5e:xx:xx:xx"
    - IPv4 or IPv6 address: "224.0.0.251", "ff02::1"
    """
    try:
        if ":" in dst:  # MAC address
            first_octet = int(dst.split(":")[0], 16)
            return (first_octet & 1) == 1 and not is_broadcast(dst)
        else:  # IP address
            ip = ip_address(dst)
            return ip.is_multicast
    except ValueError:
        return False

def process_packet(pkt, counts):
    if not pkt.haslayer(Ether):
        return

    dst_mac = pkt[Ether].dst
    dst_ip = None
    if pkt.haslayer(IP):
        dst_ip = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        dst_ip = pkt[IPv6].dst

    if is_broadcast(dst_mac):
        counts['broadcast'] += 1
        print(f"[BROADCAST] {pkt.summary()}")
    elif is_multicast(dst_mac) or (dst_ip and is_multicast(dst_ip)):
        counts['multicast'] += 1
        print(f"[MULTICAST] {pkt.summary()}")
    else:
        counts['unicast'] += 1
        # Optional: uncomment if you want to see unicast too
        # print(f"[UNICAST] {pkt.summary()}")
    counts['total'] += 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=False, help="Interface name (e.g., 'Ethernet')", default=None)
    parser.add_argument("--pcap", required=False, help="Offline pcap file to analyze", default=None)
    parser.add_argument("--count", type=int, default=500, help="Packet capture limit")
    parser.add_argument("--timeout", type=int, default=30, help="Capture timeout (seconds)")
    args = parser.parse_args()

    counts = {'broadcast':0, 'multicast':0, 'unicast':0, 'total':0}

    print(f"{'Name':20} | {'Description':40} | {'GUID'}")
    print('-' * 100)
    for iface in get_windows_if_list():
        print(f"{iface['name'][:20]:20} | {iface['description'][:40]:40} | {iface['guid']}")

    if args.pcap:
        print(f"Reading PCAP file: {args.pcap}")
        sniff(offline=args.pcap, prn=lambda p: process_packet(p, counts))
    else:
        if not args.iface:
            print("No interface provided. Use --iface to specify (example: --iface Ethernet)")
            return
        print(f"Starting live capture on {args.iface} (count={args.count}, timeout={args.timeout}s)")
        sniff(iface=args.iface, prn=lambda p: process_packet(p, counts),
              count=args.count, timeout=args.timeout)

    # Output results
    total = counts['total']
    b = counts['broadcast']; m = counts['multicast']; u = counts['unicast']
    print("\nCapture Summary")
    print("----------------")
    print(f"Total frames: {total}")
    print(f"Broadcast: {b} ({(b/total*100) if total else 0:.2f}%)")
    print(f"Multicast: {m} ({(m/total*100) if total else 0:.2f}%)")
    print(f"Unicast:   {u} ({(u/total*100) if total else 0:.2f}%)")

    # Save CSV
    csvfile = f"bcast_multicast_summary_{int(time.time())}.csv"
    with open(csvfile, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["total", total])
        writer.writerow(["broadcast", b])
        writer.writerow(["multicast", m])
        writer.writerow(["unicast", u])
    print(f"Saved summary to {csvfile}")

if __name__ == "__main__":
    main()
