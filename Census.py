import pygeoip
from scapy.all import conf, TCP_SERVICES, UDP_SERVICES
from scapy.layers.inet import IP


class Census:
    """Use This class to get calculate statics for packets."""

    gi = pygeoip.GeoIP('GeoIP.dat')
    gi6 = pygeoip.GeoIP('GeoIPv6.dat')
    local_ips = []
    valid_protos = ["udp", "tcp"]
    TCP_REVERSE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys())
    UDP_REVERSE = dict((UDP_SERVICES[k], k) for k in UDP_SERVICES.keys())

    for record in conf.route.routes:
        local_ips.append(record[4])

    def __init__(self, extractor, valid_ports):
        self.e = extractor
        self.tb = extractor.import_base_data()
        self.valid_ports = valid_ports

    def received(self, packet):
        """Add packet data to statics"""

        ip_layer = packet.getlayer(IP)

        if not ip_layer:
            return None

        ip = self.get_other_host_ip(ip_layer)

        # Some packet maybe don't have ip layer(layer2 packets),or
        # some is ont for tcp and udp,we reject theme
        if not ip or ip_layer.sprintf('%IP.proto%') not in Census.valid_protos:
            return None

        self.add_packet_to_stats(ip, ip_layer)

        if self.e.should_update():
            self.e.update(self.tb)

    def get_other_host_ip(self, iplayer):
        """Check if src is not in out local ips,this is other host ip, otherwise check if second ip is
            is not our ip and is not local ip, return second ip.
        """
        src = iplayer.src
        dst = iplayer.dst

        if self.should_stat_ip(src, iplayer.version == 4):
            return src

        if self.should_stat_ip(dst, iplayer.version == 4):
            return dst

        return None

    def should_stat_ip(self, ip, v4=True):
        """Check that should add this ip to stats or no(local and
         my ip don't need to be in stats)
         """

        return Census.ccode(ip, v4) and not (ip in self.local_ips)

    @classmethod
    def ccode(cls, ip, v4):
        return cls.gi.country_code_by_addr(ip) if v4 else cls.gi6.country_code_by_addr(ip)

    @classmethod
    def cname(cls, ip, v4):
        return cls.gi.country_name_by_addr(ip) if v4 else cls.gi6.country_name_by_addr(ip)

    def add_packet_to_stats(self, ip, ip_layer):

        c_code = self.ccode(ip, ip_layer.version == 4)

        # If country is not initialized, initialize now
        if c_code not in self.tb:
            self.init_country(c_code, ip, ip_layer.version == 4)

        c = self.tb[c_code]

        c['hits'] += 1

        # Set stats
        proto = ip_layer.sprintf('%IP.proto%')

        c[proto] += 1

        c['v' + str(ip_layer.version)] += 1
        c['len'] += ip_layer.len

        tcp_udp = ip_layer.getlayer(proto.upper())

        # If "src ip" is ip that should add to stats, packet are received.
        # if "dst ip" is ip that should add to stats, packet are sanded.
        if ip == ip_layer.src:
            port = tcp_udp.sport
            c['inp'] += 1
        else:
            port = tcp_udp.dport
            c['out'] += 1

        # Set Port
        if port in self.valid_ports:
            if port in c['ports']:
                c['ports'][port] += 1
            else:
                c['ports'][port] = 1

        # Add packet to ips stats:
        self.add_ip_stats(c_code, ip, ip_layer, port)

    def add_ip_stats(self, c_code, ip, ip_layer, port):
        c = self.tb[c_code]

        if ip not in c['ips']:
            self.init_ip_record(ip, c)

        ip_record = c['ips'][ip]

        ip_record['hits'] += 1
        ip_record['len'] += ip_layer.len

        if port in self.valid_ports:
            if port in ip_record['ports']:
                ip_record['ports'][port] += 1
            else:
                ip_record['ports'][port] = 1

    def init_country(self, c_code, ip, v4):
        self.tb[c_code] = {
            'name' : self.cname(ip, v4),
            'hits' : 0,
            'tcp'  : 0,
            'udp'  : 0,
            'v4'   : 0,
            'v6'   : 0,
            'len'  : 0,
            'inp'  : 0,
            'out'  : 0,
            'ports': {},
            'ips'  : {}
        }

    def init_ip_record(self, ip: str, country_data: dict) -> None:
        """
        Initialize new entry record in "ips" dict of country data

        :param ip: ip to enter in records of this country
        :param country_data: country data of self.tb
        """
        country_data['ips'][ip] = {
            'hits' : 0,
            'len'  : 0,
            'ports': {}
        }
