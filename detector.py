from sys import argv
import dpkt


def detect_anomaly(packet_capture):
    """
    Process a dpkt packet capture to determine if any syn scan is detected. For every IP address address that are
    detected as suspicious. We define "suspicious" as having sent more than three times as many SYN packets as the
    number of SYN+ACK packets received.
    :param packet_capture: dpkt packet capture object for processing
    """

    # implement your logic here and remove the print statement
    print('not implemented\n')


# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: python detector.py capture.pcap')
        exit(-1)

    with open(argv[1], 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        detect_anomaly(pcap_obj)

