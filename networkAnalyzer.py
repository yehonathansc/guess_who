import scapy.data
from scapy.all import rdpcap
from scapy.layers.inet import IP, ICMP
from scapy.layers.http import *
from scapy.layers.l2 import Ether
from mac_vendor_lookup import MacLookup
from scapy.plist import PacketList
from scapy.utils import PcapReader
import pickle

# Load
def load_or_parse_pcap(file_path: str) -> PacketList:
    pickle_path = file_path + ".pkl"
    if os.path.exists(pickle_path):
        try:
            with open(pickle_path, "rb") as f:
                return pickle.load(f)
        except (IOError, pickle.UnpicklingError, EOFError) as e:
            print(f"Error reading pickle file: {e}")

    print(f"Pickle not found Parsing...")

    # Read the PCAP file (this is the slow step)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Original PCAP file not found at: {file_path}")

    packets = rdpcap(file_path)

    # Save the result to a pickle file for next time
    try:
        with open(pickle_path, "wb") as f:
            print(f"Saving parsed packets to '{pickle_path}' for faster future access.")
            # Use HIGHEST_PROTOCOL for maximum speed/efficiency
            pickle.dump(list(packets), f, protocol=pickle.HIGHEST_PROTOCOL)
    except IOError as e:
        print(f"Warning: Could not save pickle file: {e}")

    return packets

class AnalyzeNetwork:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.packets = load_or_parse_pcap(self.pcap_path)
        self.cache_file_path = "mac_cache.pkl"
        if os.path.exists(self.cache_file):
            with open(self.cache_file, "rb") as f:
                self.mac_cache = pickle.load(f)
        else:
            self.mac_cache = {}

    def save_cache(self):
        with open(self.cache_file, "wb") as f:
            pickle.dump(self.mac_vendors, f, protocol=pickle.HIGHEST_PROTOCOL)

    def get_vendor(self, mac):
        """Looks up vendor with multi-level caching (memory then disk)."""
        if mac in self.mac_vendors:
            return self.mac_vendors[mac]

        # If not in memory, do the expensive lookup
        try:
            vendor = self.mac_lookup.lookup(mac)
        except Exception:
            vendor = "UNKNOWN"

        # Update memory cache
        self.mac_vendors[mac] = vendor
        return vendor


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
            if "Ether" in packet:
                eth_header = Ether
            elif "Ethernet" in packet:
                eth_header = "Ethernet"
            elif "cooked linux" in packet:
                eth_header = "cooked linux"
            for atr in ("dst", "src"):
                if "Ether" in packet:
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
            if packet.haslayer(HTTPRequest):
                print("http req packet:")
                packet.show()
                packet.summary()
            elif packet.haslayer(HTTPResponse):
                print("http req packet:")
                packet.show()
                packet.summary()
            eth_header = None
            if "Ether" in packet:
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
                        device["IP"] = getattr(packet["IP"], atr)
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
            if "IP" in packet:
                if packet["IP"].src == device_info["IP"]:
                    sum_ttl += packet[IP].ttl
                    num += 1
        if num == 0:
            return ["windows", "windows_old", "linux", "macOS", "unix"] # no info
        ttl_avg = sum_ttl / num
        print(ttl_avg, sum_ttl, num)
        if ttl_avg > 128:
            return ["unix"] # like solaris and BSD
        if ttl_avg > 64:
            return ["windows"] # modern windows
        if ttl_avg > 32:
            return ["linux", "unix", "macOS"]
        return ["windows_old"] # old windows versions like windows 95

if __name__ == "__main__":
    print("pcap-00.pcapng:")
    analyzer = AnalyzeNetwork("pcap-00.pcapng")
    for device in analyzer.get_info():
        print(device)
        print(analyzer.guess_os(device))
    print("pcap-01.pcapng:")
    analyzer = AnalyzeNetwork("pcap-01.pcapng")
    for device in analyzer.get_info():
        print(device)
        print(analyzer.guess_os(device))
    print("pcap-02.pcapng:")
    analyzer = AnalyzeNetwork("pcap-02.pcapng")
    for device in analyzer.get_info():
        print(device)
        print(analyzer.guess_os(device))
    print("pcap-03.pcapng:")
    analyzer = AnalyzeNetwork("pcap-03.pcapng")
    print("loaded")
    for device in analyzer.get_info():
        print(device)
        print(analyzer.guess_os(device))