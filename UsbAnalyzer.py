from time import sleep

from scapy.all import rdpcap
from scapy.layers.http import *
import pickle
import turtle


def char_to_int(c):
    if c >= 128:
        return c-256
    return c



# Load
def load_or_parse_pcap(file_path: str):
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

class AnalyzeUSB:
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.pcap_path = pcap_path
        self.packets = load_or_parse_pcap(self.pcap_path)


    def __repr__(self):
        return "NetworkAnalayzer_for_pcap_at: " + str(self.pcap_path)


    def __str__(self):
        return self.__repr__()

    def draw(self):
        tu = turtle.Pen()
        tu.speed(0)
        for packet in self.packets:
            data = packet[Raw].load
            if len(data) == 32:
                hid = data[-5:]
                dx = char_to_int(hid[2])
                dy = char_to_int(hid[3])
                if hid[1] != 128:
                    tu.pendown()
                else:
                    tu.penup()
                tu.goto(tu.xcor()+dx, tu.ycor()-dy)
        sleep(1000)



if __name__ == "__main__":
    anyl = AnalyzeUSB("tablet.pcap")
    anyl.draw()