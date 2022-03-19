from sys import argv
import ipaddress
import dpkt


def detect_anomaly(packet_capture):
    """
    Process a dpkt packet capture to determine if any syn scan is detected. For every IP address address that are
    detected as suspicious. We define "suspicious" as having sent more than three times as many SYN packets as the
    number of SYN+ACK packets received.
    :param packet_capture: dpkt packet capture object for processing
    """

    # Keys are IP and vals are [num SYN sent, num SNY+ACK received]
    ips = {} 
    for ts, buf in packet_capture:
        try:
            eth = dpkt.ethernet.Ethernet(buf) 
        except dpkt.dpkt.NeedData: # malformed packet 
            continue

        ip = eth.data

        # TODO probably a better way to do this
        # Checking for ethernet and IP
        if type(eth).__name__ != "Ethernet" or type(ip).__name__ != "IP":
            continue

        # Checking for TCP 
        if dpkt.ip.get_ip_proto_name(ip.p) != "TCP":
            continue

        tcp = ip.data
        flags = dpkt.tcp.tcp_flags_to_str(tcp.flags).split(",")

        sa_counts_src = ips.get(ip.src) if ips.get(ip.src) else [0, 0]
        sa_counts_dst = ips.get(ip.dst) if ips.get(ip.dst) else [0, 0]

        syn =  "SYN" in flags 
        ack = "ACK" in flags
        
        # Update dict values if needed
        if syn and ack:
            sa_counts_dst[1] += 1
            ips[ip.dst] = sa_counts_dst
        elif syn:
            sa_counts_src[0] += 1
            ips[ip.src] = sa_counts_src


    # Checking relative amounts of SYN vs SYN+ACK
    for key, value in ips.items():
        num_syn = value[0]
        num_syn_ack =  value[1]

        if num_syn > 3 * num_syn_ack:
            print(ipaddress.IPv4Address(key))
 
# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: python detector.py capture.pcap')
        exit(-1)

    with open(argv[1], 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        detect_anomaly(pcap_obj)

