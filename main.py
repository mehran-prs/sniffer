from scapy.all import sniff
from extractor import Extractor

from Census import Census


def parser(packet):
    census.received(packet)


if __name__ == '__main__':
    e = Extractor(1)
    census = Census(e, [
        20,  # ftp
        21,  # fto
        22,  # ssh
        23,  # telnet
        25,  # SMTP
        53,  # DNS
        67,  # DHCP
        68,  # DHCP
        69,  # TFTP
        80,  # HTTP
        110,  # POP3
        143,  # IMAP
        443  # HTTPS
    ])

    sniff(iface="wlp3s0", filter="", prn=parser)
