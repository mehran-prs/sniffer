from scapy.all import sniff


def parser(packet):
    print(packet.show())
    input('next:')


if __name__ == '__main__':
    sniff(iface="wlp3s0", filter="tcp and udp", prn=parser)
