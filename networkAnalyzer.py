import scapy.data
from scapy.all import rdpcap
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether
from mac_vendor_lookup import MacLookup


class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.packets = rdpcap(self.pcap_path)


    def get_ips(self):
        """returns a list of ip addresses (strings) that appear in
        the pcap"""
        ips = set()
        for packet in self.packets:
            if "IP" in packet:
                ips.add(packet[IP].dst)
        return list(ips)


    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        macs = set()
        for packet in self.packets:
            eth_header = None
            if Ether in packet:
                eth_header = Ether
            elif "Ethernet" in packet:
                eth_header = "Ethernet"
            elif "cooked linux" in packet:
                eth_header = "cooked linux"
            for atr in ("dst", "src"):
                if Ether in packet:
                    macs.add(getattr(packet[eth_header], atr))
        return list(macs)


    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        for device in self.get_info():
            if mac == device["MAC"]:
                return device
        return None


    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        for device in self.get_info():
            if ip == device["IP"]:
                return device
        return None


    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        devices = set()
        for packet in self.packets:
            eth_header = None
            if Ether in packet:
                eth_header = Ether
            elif "Ethernet" in packet:
                eth_header = "Ethernet"
            elif "cooked linux" in packet:
                eth_header = "cooked linux"
            for atr in ("dst", "src"):
                if eth_header != None:
                    device = {"MAC": getattr(packet[eth_header], atr)}
                    if device["MAC"] == "ff:ff:ff:ff:ff:ff":
                        continue
                    if "IP" in packet:
                        device["IP"] = getattr(packet[IP], atr)
                    else:
                        device["IP"] = "UNKNOWN"
                    try:
                        device["VENDOR"] = MacLookup().lookup(device["MAC"])
                    except KeyError:
                        device["VENDOR"] = "UNKNOWN"
                    devices.add(frozenset(device.items()))
        return [dict(d) for d in devices]


    def __repr__(self):
        return "NetworkAnalayzer_for_pcap_at: " + str(self.pcap_path)


    def __str__(self):
        return self.__repr__()

    def guess_os(self, device_info):
        seqs = []
        sum_ttl = 0
        num = 0
        for packet in self.packets:
            if IP in packet:
                if packet[IP].src == device_info["IP"]:
                    ttl = packet[IP].ttl
                    num += 1
        if num == 0:
            return ["windows", "linux", "macOS", "unix"] # no info
        ttl_avg = sum_ttl / num
        if ttl_avg > 128:
            return ["unix"] # like solaris and BSD
        if ttl_avg > 64:
            return ["windows"] # modern windows
        if ttl_avg > 32:
            return ["linux", "unix", "macOS"]
        return ["windows"] # old windows versions like windows 95

if __name__ == "__main__":
    analyzer = AnalyzeNetwork("./example.pcapng")
    print(analyzer.get_macs())
    print(analyzer.get_ips())
    print(analyzer.get_info())