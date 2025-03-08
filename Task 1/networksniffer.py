import sys
from scapy.all import *

def handle_packet(packet, log):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")

def main(interface, verbose=False):
    logfile_name = f"sniffer_{interface}_log.txt"
    with open(logfile_name, 'w') as logfile:
        try:
            if verbose:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0, verbose=verbose)
            else:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python sniffer.py <interface> [verbose]")
        sys.exit(1)
    verbose = False
    if len(sys.argv) == 3 and sys.argv[2].lower() == "verbose":
        verbose = True
    main(sys.argv[1], verbose)